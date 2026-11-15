#include "ops/VaultRemote.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/RemoteAttach.hpp"
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
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <pqxx/except>

#include <set>

namespace vh::ops::vault_remote {

namespace vault_remote_detail {

using Q = db::query::vault::RemoteAttach;
namespace ra = vault::remote;
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

std::string summaryOf(const bool s3Vault, const std::optional<ra::Row>& row) {
    if (row && row->state != ra::State::Done && row->state != ra::State::Aborted)
        return "attaching:" + std::string(ra::to_string(row->state));
    return s3Vault ? "attached" : "none";
}

Status statusOf(const vault::model::Vault& v) {
    const bool s3 = v.type == vault::model::VaultType::S3;
    Status s{.vault_id = v.id, .vault_name = v.name, .type = s3 ? "s3" : "local", .remote = {}, .attach = Q::get(v.id),
             .progress = std::nullopt, .items = {}};
    s.remote = summaryOf(s3, s.attach);
    if (!s.attach) return s;
    const auto items = Q::items(v.id);
    s.progress = ra::progressOf(*s.attach, items);
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
    return vault_remote_detail::summaryOf(s3Vault, vault_remote_detail::Q::get(vaultId));
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
    return {{"vault_id", s.vault_id},
            {"vault_name", s.vault_name},
            {"type", s.type},
            {"remote", s.remote},
            {"attach", attach},
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
    std::string why;
    if (!storage::upstream::validBucketName(request.bucket, why))
        throw Invalid("invalid bucket name '" + request.bucket + "': " + why);
    const auto key = db::query::vault::APIKey::getAPIKey(request.api_key_id);
    if (!key) throw NotFound("API key not found: " + std::to_string(request.api_key_id));
    const auto tier = storage::s3::provider::resolve(key->provider)->normalizeStorageTier(request.storage_tier);
    if (!tier.ok) throw Invalid(tier.error);

    if (vault->type != vault::model::VaultType::Local)
        throw Conflict("vault '" + vault->name + "' already has remote storage: only a local vault attaches a remote");
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

Status abort(const Actor& actor, const AbortRequest& request) {
    namespace d = vault_remote_detail;
    namespace ra = vault::remote;
    requireActor(actor);
    const auto vault = d::liveVault(request.vault_id);
    d::requireAttach(actor, vault, std::nullopt);
    const auto row = d::Q::get(vault->id);
    if (!row || row->state == ra::State::Aborted) throw Conflict("vault '" + vault->name + "' has no remote attach to abort");
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
                       .details = {{"state", std::string(ra::to_string(row->state))}}},
                      fmt::format("[ops::vault_remote] {} asked to abort the remote attach of vault {} ({}); the "
                                  "objects it recorded are deleted from the bucket, the vault was never changed",
                                  actor->name(), vault->id, ra::to_string(row->state)));
    return d::statusOf(*vault);
}

}
