#include "ops/VaultRemote.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/query/cloud/Storage.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/RemoteDetach.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "rbac/permission/admin/Keys.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "storage/upstream/Names.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <pqxx/except>

#include <set>

namespace vh::ops::vault_remote {

namespace vault_remote_detail {

using Q = db::query::vault::RemoteAttach;
using DQ = db::query::vault::RemoteDetach;
namespace ra = vault::remote;
namespace rd = vault::remote::detach;
using VaultPerm = rbac::permission::admin::VaultPermissions;
using KeyPerm = rbac::permission::admin::keys::APIPermissions;
using SyncConfigPerm = rbac::permission::vault::sync::SyncConfigPermissions;

std::shared_ptr<vault::model::Vault> liveVault(const unsigned int vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw NotFound("no vault with ID " + std::to_string(vaultId));
    return vault;
}

bool canView(const Actor& actor, const std::shared_ptr<vault::model::Vault>& vault) {
    return rbac::resolver::Admin::has<VaultPerm>({.user = actor, .permission = VaultPerm::View, .vault = vault});
}

// What binding a bucket to the vault asks for, and the encryption-key Rotate permission.
void requireAttach(const Actor& actor, const std::shared_ptr<vault::model::Vault>& vault,
                   const std::optional<unsigned int> apiKeyId) {
    requireActor(actor);
    if (!rbac::resolver::Admin::has<VaultPerm>({.user = actor, .permission = VaultPerm::Edit, .vault = vault}))
        throw Denied("you do not have permission to edit vault " + vault->name);
    if (!rbac::resolver::Vault::has<SyncConfigPerm>(
            {.user = actor, .permission = SyncConfigPerm::Edit, .vault_id = vault->id}))
        throw Denied("you do not have permission to edit the sync configuration of vault " + vault->name);
    if (!actor->isSuperAdmin() && !actor->encryptionKeysPerms().canRotate())
        throw Denied("only super admins or users with the rotate encryption keys permission can attach or detach a "
                     "vault's remote storage");
    if (!apiKeyId) return;
    if (!db::query::vault::APIKey::getAPIKey(*apiKeyId)) throw NotFound("API key not found: " + std::to_string(*apiKeyId));
    if (!rbac::resolver::Admin::has<KeyPerm>({.user = actor, .permission = KeyPerm::Consume, .api_key_id = *apiKeyId}))
        throw Denied("you do not have permission to use api-key " + std::to_string(*apiKeyId) + " for this vault");
}

// A vault in managed storage is run by its switch (ops::cloud_storage), never by an operator's attach, detach, abort
// or access change.
void refuseManaged(const vault::model::Vault& vault) {
    if (db::query::cloud::CloudStorage::managed(vault.id))
        throw Refused("managed_storage", "vault '" + vault.name + "' is in managed storage: its switch decides where it "
                      "is stored (vh cloud storage enable|disable), and its access follows the account");
}

// A detach (or attach) that ended (done or aborted) says nothing more than the vault's type does.
bool unfinished(const std::optional<rd::Row>& row) {
    return row && row->state != rd::State::Done && row->state != rd::State::Aborted;
}

std::string summaryOf(const bool s3Vault, const std::optional<ra::Row>& row, const std::optional<rd::Row>& detach) {
    if (unfinished(detach)) return "detaching:" + std::string(rd::to_string(detach->state));
    if (row && row->state != ra::State::Done && row->state != ra::State::Aborted)
        return "attaching:" + std::string(ra::to_string(row->state));
    return s3Vault ? "attached" : "none";
}

Status statusOf(const vault::model::Vault& v) {
    const bool s3 = v.type == vault::model::VaultType::S3;
    Status s{.vault_id = v.id, .vault_name = v.name, .type = s3 ? "s3" : "local", .remote = {}, .attach = Q::get(v.id),
             .detach = DQ::get(v.id), .progress = std::nullopt, .items = {}, .detach_items = {},
             .access = std::nullopt};
    s.remote = summaryOf(s3, s.attach, s.detach);
    if (s3) s.access = storage::remote_access::state(v.id);
    if (s.detach) {
        const auto detachItems = DQ::items(v.id);
        for (const auto& it : detachItems) {
            if (it.kind == rd::ItemKind::Envelope) {
                ++s.detach_items.envelopes;
                if (it.hydrated) ++s.detach_items.envelopes_copied;
                continue;
            }
            if (it.state == rd::ItemState::Pending) ++s.detach_items.files_pending;
            else if (it.state == rd::ItemState::Failed) ++s.detach_items.files_failed;
            else ++s.detach_items.files_verified;
            if (it.hydrated) ++s.detach_items.files_fetched;
        }
        if (unfinished(s.detach) || !s.attach) s.progress = rd::progressOf(*s.detach, detachItems);
    }
    if (!s.attach) return s;
    const auto items = Q::items(v.id);
    if (!s.progress) s.progress = ra::progressOf(*s.attach, items);
    for (const auto& it : items) {
        if (it.state == ra::ItemState::Deleted || it.state == ra::ItemState::Stale) continue;
        switch (it.kind) {
        case ra::ItemKind::Content:
            if (it.state == ra::ItemState::Pending) ++s.items.files_pending;
            else if (it.state == ra::ItemState::Failed) ++s.items.files_failed;
            else ++s.items.files_sent;
            break;
        case ra::ItemKind::Envelope: ++s.items.envelopes; break;
        case ra::ItemKind::Metadata: ++s.items.metadata_objects; break;
        case ra::ItemKind::Orphan: ++s.items.orphans; break;
        }
    }
    return s;
}

nlohmann::json optTime(const std::optional<std::time_t>& t) { return t ? nlohmann::json(*t) : nlohmann::json(nullptr); }

template <class T>
nlohmann::json opt(const std::optional<T>& v) {
    return v ? nlohmann::json(*v) : nlohmann::json(nullptr);
}

// An engine refusal as the ops error a client acts on: its own code where the caller can do something about it.
[[noreturn]] void rethrow(const ra::Refusal& e, const std::string& vaultName) {
    const auto text = fmt::format("vault '{}' can't attach a remote now: {}", vaultName, e.what());
    const auto& code = e.code();
    if (code == "bucket_protected") throw Denied(e.what());
    if (code == "api_key_missing") throw NotFound(e.what());
    if (code == "bucket_in_use" || code == "not_local" || code == "vault_unavailable") throw Conflict(text);
    throw Refused(code, text);
}

}

std::string remoteSummary(const unsigned int vaultId, const bool s3Vault) {
    namespace d = vault_remote_detail;
    return d::summaryOf(s3Vault, d::Q::get(vaultId), d::DQ::get(vaultId));
}

std::vector<Status> status(const Actor& actor, const std::optional<unsigned int> vaultId) {
    namespace d = vault_remote_detail;
    requireActor(actor);
    std::vector<Status> out;
    if (vaultId) {
        const auto vault = d::liveVault(*vaultId);
        if (!d::canView(actor, vault)) throw Denied("you do not have permission to view vault " + vault->name);
        out.push_back(d::statusOf(*vault));
        return out;
    }
    std::set<unsigned int> withRow;
    for (const auto& [id, state] : d::Q::states()) withRow.insert(id);
    for (const auto& [id, state] : d::DQ::states()) withRow.insert(id);
    for (const auto& vault : db::query::vault::Vault::listLiveVaults())
        if (withRow.contains(vault->id) && d::canView(actor, vault)) out.push_back(d::statusOf(*vault));
    return out;
}

nlohmann::json toJson(const Status& s) {
    namespace d = vault_remote_detail;
    nlohmann::json attach = nullptr;
    if (s.attach) {
        const auto& a = *s.attach;
        attach = {{"state", std::string(vault::remote::to_string(a.state))},
                  {"origin", a.origin},
                  {"api_key_id", d::opt(a.api_key_id)},
                  {"bucket", a.bucket},
                  {"storage_tier", d::opt(a.storage_tier_id)},
                  {"manifest_publish", d::opt(a.manifest_publish)},
                  {"versioned", d::opt(a.versioned)},
                  {"started_at", a.started_at},
                  {"started_by", d::opt(a.started_by)},
                  {"attempts", a.attempts},
                  {"accept_unpriced", a.accept_unpriced},
                  {"verified_at", d::optTime(a.verified_at)},
                  {"cutover_at", d::optTime(a.cutover_at)},
                  {"done_at", d::optTime(a.done_at)},
                  {"aborted_at", d::optTime(a.aborted_at)},
                  {"abort_requested_at", d::optTime(a.abort_requested_at)},
                  {"rotation_queued", a.rotation_queued_at.has_value()},
                  {"estimate", a.estimate ? vault::remote::toJson(vault::remote::estimateFromJson(*a.estimate))
                                          : nlohmann::json(nullptr)},
                  {"usage", a.usage ? *a.usage : nlohmann::json(nullptr)},
                  {"first_pass", a.first_pass ? *a.first_pass : nlohmann::json(nullptr)},
                  {"last_error", d::opt(a.last_error)}};
    }
    nlohmann::json detach = nullptr;
    if (s.detach) {
        const auto& r = *s.detach;
        detach = {{"state", std::string(vault::remote::detach::to_string(r.state))},
                  {"mode", std::string(vault::remote::detach::to_string(r.mode))},
                  {"lost", r.lost ? *r.lost : nlohmann::json(nullptr)},
                  {"api_key_id", d::opt(r.api_key_id)},
                  {"bucket", r.bucket},
                  {"started_at", r.started_at},
                  {"started_by", d::opt(r.started_by)},
                  {"attempts", r.attempts},
                  {"verified_at", d::optTime(r.verified_at)},
                  {"cutover_at", d::optTime(r.cutover_at)},
                  {"done_at", d::optTime(r.done_at)},
                  {"aborted_at", d::optTime(r.aborted_at)},
                  {"abort_requested_at", d::optTime(r.abort_requested_at)},
                  {"estimate", r.estimate ? vault::remote::detach::toJson(vault::remote::detach::estimateFromJson(*r.estimate))
                                          : nlohmann::json(nullptr)},
                  {"items", {{"files_pending", s.detach_items.files_pending},
                             {"files_verified", s.detach_items.files_verified},
                             {"files_failed", s.detach_items.files_failed},
                             {"files_fetched", s.detach_items.files_fetched},
                             {"envelopes", s.detach_items.envelopes},
                             {"envelopes_copied", s.detach_items.envelopes_copied}}},
                  {"last_error", d::opt(r.last_error)}};
    }
    nlohmann::json access = nullptr;
    if (s.access)
        access = {{"mode", std::string(storage::remote_access::to_string(s.access->mode))},
                  {"reason", d::opt(s.access->reason)},
                  {"set_by", d::opt(s.access->set_by)},
                  {"set_at", d::optTime(s.access->set_at)}};
    return {{"vault_id", s.vault_id},
            {"vault_name", s.vault_name},
            {"type", s.type},
            {"remote", s.remote},
            {"access", access},
            {"attach", attach},
            {"detach", detach},
            {"progress", s.progress ? vault::remote::toJson(*s.progress) : nlohmann::json(nullptr)},
            {"items", {{"files_pending", s.items.files_pending}, {"files_sent", s.items.files_sent},
                       {"files_failed", s.items.files_failed}, {"envelopes", s.items.envelopes},
                       {"metadata_objects", s.items.metadata_objects}, {"orphans", s.items.orphans}}}};
}

Status attach(const Actor& actor, const AttachRequest& request) {
    namespace d = vault_remote_detail;
    namespace ra = vault::remote;
    requireActor(actor);
    const auto vault = d::liveVault(request.vault_id);
    if (request.api_key_id == 0) throw Invalid("an API key is required (--api-key)");
    if (request.bucket.empty()) throw Invalid("a bucket is required (--bucket)");
    d::requireAttach(actor, vault, request.api_key_id);
    d::refuseManaged(*vault);
    std::string why;
    if (!storage::upstream::validBucketName(request.bucket, why))
        throw Invalid("invalid bucket name '" + request.bucket + "': " + why);
    const auto key = db::query::vault::APIKey::getAPIKey(request.api_key_id);
    if (!key) throw NotFound("API key not found: " + std::to_string(request.api_key_id));
    const auto tier = storage::s3::provider::resolve(key->provider)->normalizeStorageTier(request.storage_tier);
    if (!tier.ok) throw Invalid(tier.error);

    if (vault->type != vault::model::VaultType::Local)
        throw Conflict("vault '" + vault->name + "' already has remote storage: only a local vault attaches a remote");
    if (const auto detaching = d::DQ::get(vault->id); d::unfinished(detaching))
        throw Conflict(fmt::format("vault '{}' has an unfinished remote detach ({}): abort or finish it first",
                                   vault->name, d::rd::to_string(detaching->state)));
    if (const auto existing = d::Q::get(vault->id); existing && existing->state != ra::State::Failed &&
                                                    existing->state != ra::State::Aborted)
        throw Conflict(fmt::format("vault '{}' already has a remote attach ({})", vault->name,
                                   ra::to_string(existing->state)));
    else if (existing && existing->state == ra::State::Failed &&
             (existing->api_key_id != std::optional<uint32_t>(request.api_key_id) || existing->bucket != request.bucket))
        throw Conflict(fmt::format("vault '{}' has a failed attach to bucket '{}': start it again with that API key and "
                                   "bucket to resume it, or abort it first (vh vault remote abort)", vault->name,
                                   existing->bucket));

    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vault->id) : nullptr;
    if (!engine) throw Conflict("vault '" + vault->name + "' is not loaded on this host");
    std::optional<ra::BucketCheck> check;
    try {
        ra::requireVaultReady(*engine);
        const auto controller = ra::controllerFor(vault->id, request.api_key_id, request.bucket);
        // The capability as the bucket answers now, and the proof that it holds nothing (spec 06 §7; precondition 4).
        check = ra::requireBucketUsable(vault->id, request.api_key_id, request.bucket, *controller, std::nullopt);
    } catch (const ra::Refusal& e) {
        d::rethrow(e, vault->name);
    }
    auth::stepup::require(auth::stepup::Family::Keys, "vault.remote.attach:" + std::to_string(vault->id));

    d::Q::Started started;
    try {
        started = d::Q::start({.vault_id = vault->id, .origin = "byos", .api_key_id = request.api_key_id,
                               .bucket = request.bucket, .storage_tier_id = tier.normalized_id,
                               .started_by = actor->id, .accept_unpriced = request.accept_unpriced});
    } catch (const pqxx::unique_violation&) {
        throw Conflict("bucket '" + request.bucket + "' was reserved by another attach meanwhile");
    }
    switch (started.outcome) {
    case d::Q::StartOutcome::Started:
    case d::Q::StartOutcome::Resumed:
        break;
    case d::Q::StartOutcome::BucketReserved:
        throw Conflict(fmt::format("bucket '{}' is already the storage of vault {} (or reserved by its attach) with "
                                   "this API key", request.bucket, started.reserved_by.value_or(0)));
    case d::Q::StartOutcome::BindingDiffers:
        throw Conflict("vault '" + vault->name + "' has a failed attach to another bucket: resume or abort it first");
    case d::Q::StartOutcome::Busy:
        throw Conflict("vault '" + vault->name + "' already has a remote attach");
    }
    const auto publish = check->probe.capability == sync::manifest::WriteCapability::Conditional ? "conditional" : "version_log";
    d::Q::setProbe(vault->id, std::string(publish), storage::s3::toJson(check->probe), check->versioned);

    const bool resumed = started.outcome == d::Q::StartOutcome::Resumed;
    vh::audit::record({.action = "vault.remote.attach", .outcome = vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(), .vault_id = vault->id,
                       .details = {{"api_key_id", static_cast<int64_t>(request.api_key_id)},
                                   {"publish", std::string(publish)},
                                   {"resumed", resumed},
                                   {"accept_unpriced", request.accept_unpriced}}},
                      fmt::format("[ops::vault_remote] {} {} attaching a remote to vault {} (API key {}, manifest "
                                  "publish {}); the vault stays local until the cutover",
                                  actor->name(), resumed ? "resumed" : "started", vault->id, request.api_key_id,
                                  publish));
    return d::statusOf(*vault);
}

Status detach(const Actor& actor, const DetachRequest& request) {
    namespace d = vault_remote_detail;
    requireActor(actor);
    const auto vault = d::liveVault(request.vault_id);
    d::requireAttach(actor, vault, std::nullopt);
    d::refuseManaged(*vault);
    if (vault->type != vault::model::VaultType::S3)
        throw Conflict("vault '" + vault->name + "' is a local vault: only an S3 vault detaches its remote");
    if (const auto existing = d::DQ::get(vault->id); existing && d::rd::running(existing->state))
        throw Conflict(fmt::format("vault '{}' already has a remote detach ({})", vault->name,
                                   d::rd::to_string(existing->state)));
    if (request.confirm != vault->name)
        throw Invalid("the confirmation must be the vault's name exactly ('" + vault->name + "')");

    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vault->id) : nullptr;
    if (!engine) throw Conflict("vault '" + vault->name + "' is not loaded on this host");
    try {
        d::rd::requireVaultReady(*engine);
    } catch (const vault::remote::Refusal& e) {
        const auto text = fmt::format("vault '{}' can't detach its remote now: {}", vault->name, e.what());
        if (e.code() == "not_s3" || e.code() == "vault_unavailable") throw Conflict(text);
        throw Refused(e.code(), text);
    }
    auth::stepup::require(auth::stepup::Family::Keys, "vault.remote.detach:" + std::to_string(vault->id));

    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    const auto started = d::DQ::start({.vault_id = vault->id,
                                       .api_key_id = s3 && s3->api_key_id ? std::make_optional(s3->api_key_id) : std::nullopt,
                                       .bucket = s3 ? s3->bucket : std::string{}, .started_by = actor->id});
    if (started.outcome == d::DQ::StartOutcome::Busy)
        throw Conflict("vault '" + vault->name + "' already has a remote detach");
    const bool resumed = started.outcome == d::DQ::StartOutcome::Resumed;
    vh::audit::record({.action = "vault.remote.detach", .outcome = vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(), .vault_id = vault->id,
                       .details = {{"bucket", s3 ? s3->bucket : std::string{}}, {"resumed", resumed}}},
                      fmt::format("[ops::vault_remote] {} {} detaching the remote of vault {}; the vault stays an S3 "
                                  "vault until every file is held and verified locally, and its bucket is left in place",
                                  actor->name(), resumed ? "resumed" : "started", vault->id));
    return d::statusOf(*vault);
}

Status setAccess(const Actor& actor, const AccessRequest& request) {
    namespace d = vault_remote_detail;
    requireActor(actor);
    const auto vault = d::liveVault(request.vault_id);
    d::requireAttach(actor, vault, std::nullopt);
    d::refuseManaged(*vault);
    if (vault->type != vault::model::VaultType::S3)
        throw Conflict("vault '" + vault->name + "' is a local vault: it has no remote storage whose access to set");
    if (request.reason && request.reason->size() > 500) throw Invalid("the reason is longer than 500 characters");
    (void)storage::remote_access::set(vault->id, request.mode, request.reason, "user:" + actor->name());
    return d::statusOf(*vault);
}

Status abort(const Actor& actor, const AbortRequest& request) {
    namespace d = vault_remote_detail;
    namespace ra = vault::remote;
    requireActor(actor);
    const auto vault = d::liveVault(request.vault_id);
    d::requireAttach(actor, vault, std::nullopt);
    d::refuseManaged(*vault);

    // A detach before its cutover is what runs on an S3 vault; an attach before its cutover on a local one.
    if (const auto detaching = d::DQ::get(vault->id); detaching && d::rd::beforeCutover(detaching->state)) {
        if (request.confirm != vault->name)
            throw Invalid("the confirmation must be the vault's name exactly ('" + vault->name + "')");
        auth::stepup::require(auth::stepup::Family::Keys, "vault.remote.abort:" + std::to_string(vault->id));
        if (!d::DQ::requestAbort(vault->id, actor->id))
            throw Conflict("vault '" + vault->name + "' cut over meanwhile: nothing was aborted");
        vh::audit::record({.action = "vault.remote.abort", .outcome = vh::audit::Outcome::Success, .actor_id = actor->id,
                           .actor = actor->name(), .vault_id = vault->id,
                           .details = {{"operation", "detach"},
                                       {"state", std::string(d::rd::to_string(detaching->state))}}},
                          fmt::format("[ops::vault_remote] {} asked to abort the remote detach of vault {} ({}); the "
                                      "vault stays an S3 vault", actor->name(), vault->id,
                                      d::rd::to_string(detaching->state)));
        return d::statusOf(*vault);
    }

    const auto row = d::Q::get(vault->id);
    if (!row || row->state == ra::State::Aborted)
        throw Conflict("vault '" + vault->name + "' has no remote attach or detach to abort");
    if (!ra::beforeCutover(row->state))
        throw Conflict("vault '" + vault->name + "' has cut over to its bucket: an attach is aborted before the cutover "
                       "only");
    if (request.confirm != vault->name)
        throw Invalid("the confirmation must be the vault's name exactly ('" + vault->name + "')");
    auth::stepup::require(auth::stepup::Family::Keys, "vault.remote.abort:" + std::to_string(vault->id));
    if (!d::Q::requestAbort(vault->id, actor->id))
        throw Conflict("vault '" + vault->name + "' cut over meanwhile: nothing was aborted");
    vh::audit::record({.action = "vault.remote.abort", .outcome = vh::audit::Outcome::Success, .actor_id = actor->id,
                       .actor = actor->name(), .vault_id = vault->id,
                       .details = {{"operation", "attach"}, {"state", std::string(ra::to_string(row->state))}}},
                      fmt::format("[ops::vault_remote] {} asked to abort the remote attach of vault {} ({}); the "
                                  "objects it recorded are deleted from the bucket, the vault was never changed",
                                  actor->name(), vault->id, ra::to_string(row->state)));
    return d::statusOf(*vault);
}

void attachForCloud(const unsigned int vaultId, const unsigned int apiKeyId, const std::string& bucket) {
    namespace d = vault_remote_detail;
    namespace ra = vault::remote;
    const auto vault = d::liveVault(vaultId);
    if (vault->type != vault::model::VaultType::Local)
        throw Conflict("vault '" + vault->name + "' already has remote storage");
    if (const auto detaching = d::DQ::get(vault->id); d::unfinished(detaching))
        throw Conflict("vault '" + vault->name + "' has an unfinished remote detach");
    const auto existing = d::Q::get(vault->id);
    if (existing && existing->state != ra::State::Failed && existing->state != ra::State::Aborted) return;   // runs
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vault->id) : nullptr;
    if (!engine) throw Conflict("vault '" + vault->name + "' is not loaded on this host");
    ra::requireManagedReady(vault->id, std::nullopt);   // the account key's grant: precondition 6
    ra::requireVaultReady(*engine);
    const auto controller = ra::controllerFor(vault->id, apiKeyId, bucket);
    const auto check = ra::requireBucketUsable(vault->id, apiKeyId, bucket, *controller, std::nullopt);
    d::Q::Started started;
    try {
        started = d::Q::start({.vault_id = vault->id, .origin = "cloud", .api_key_id = apiKeyId, .bucket = bucket,
                               .storage_tier_id = std::nullopt, .started_by = std::nullopt, .accept_unpriced = true});
    } catch (const pqxx::unique_violation&) {
        throw Conflict("bucket '" + bucket + "' was reserved by another attach meanwhile");
    }
    if (started.outcome != d::Q::StartOutcome::Started && started.outcome != d::Q::StartOutcome::Resumed)
        throw Conflict("vault '" + vault->name + "' can't start an attach to its managed bucket now");
    const auto publish = check.probe.capability == sync::manifest::WriteCapability::Conditional ? "conditional" : "version_log";
    d::Q::setProbe(vault->id, std::string(publish), storage::s3::toJson(check.probe), check.versioned);
    vh::audit::record({.action = "vault.remote.attach", .outcome = vh::audit::Outcome::Success, .actor_id = std::nullopt,
                       .actor = "system:cloud", .vault_id = vault->id,
                       .details = {{"api_key_id", static_cast<int64_t>(apiKeyId)}, {"publish", std::string(publish)},
                                   {"resumed", started.outcome == d::Q::StartOutcome::Resumed}, {"origin", "cloud"}}},
                      fmt::format("[ops::vault_remote] system:cloud started attaching vault {} to its managed bucket "
                                  "(manifest publish {}); the vault stays local until the cutover", vault->id, publish));
}

void detachForCloud(const unsigned int vaultId, const bool inPlace) {
    namespace d = vault_remote_detail;
    const auto vault = d::liveVault(vaultId);
    if (vault->type != vault::model::VaultType::S3) throw Conflict("vault '" + vault->name + "' is a local vault");
    if (const auto existing = d::DQ::get(vault->id); existing && d::rd::running(existing->state)) return;   // runs
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vault->id) : nullptr;
    if (!engine) throw Conflict("vault '" + vault->name + "' is not loaded on this host");
    d::rd::requireVaultReady(*engine);
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    const auto started = d::DQ::start({.vault_id = vault->id,
                                       .api_key_id = s3 && s3->api_key_id ? std::make_optional(s3->api_key_id) : std::nullopt,
                                       .bucket = s3 ? s3->bucket : std::string{}, .started_by = std::nullopt,
                                       .mode = inPlace ? d::rd::Mode::InPlace : d::rd::Mode::Hydrate});
    if (started.outcome == d::DQ::StartOutcome::Busy) throw Conflict("vault '" + vault->name + "' already has a remote detach");
    vh::audit::record({.action = "vault.remote.detach", .outcome = vh::audit::Outcome::Success, .actor_id = std::nullopt,
                       .actor = "system:cloud", .vault_id = vault->id,
                       .details = {{"bucket", s3 ? s3->bucket : std::string{}}, {"in_place", inPlace}, {"origin", "cloud"}}},
                      fmt::format("[ops::vault_remote] system:cloud started detaching vault {} from its managed bucket{}",
                                  vault->id, inPlace ? " in place (no request to the bucket)" : ""));
}

bool abortForCloud(const unsigned int vaultId) {
    namespace d = vault_remote_detail;
    const auto row = d::Q::get(vaultId);
    if (!row || !vault::remote::beforeCutover(row->state) || row->state == vault::remote::State::Aborted) return false;
    return d::Q::requestAbort(vaultId, std::nullopt);
}

}
