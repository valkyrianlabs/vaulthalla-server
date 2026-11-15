#include "ops/CloudStorage.hpp"

#include "audit/Trail.hpp"
#include "cloud/Storage.hpp"
#include "config/Registry.hpp"
#include "db/query/cloud/Link.hpp"
#include "db/query/cloud/RecoveryVault.hpp"
#include "db/query/cloud/Storage.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/Transactions.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/RemoteDetach.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/CloudKeys.hpp"
#include "ops/CloudRecovery.hpp"
#include "ops/Error.hpp"
#include "ops/RecoveryRecipients.hpp"
#include "ops/VaultRemote.hpp"
#include "ops/Vaults.hpp"
#include "rbac/permission/admin/Cloud.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/RemoteAccess.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/RemoteAttach.hpp"
#include "vault/RemoteDetach.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <vl/keykit/account_key.hpp>
#include <vl/keykit/vault_label.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>

namespace vh::ops::cloud_storage {

// Named, not anonymous: the unity build joins this file with others.
namespace cloud_storage_ops_detail {

using Row = db::query::cloud::VaultStorageRow;
using DB = db::query::cloud::CloudStorage;
namespace cs = vh::cloud::storage;
namespace ra = vault::remote;
namespace rd = vault::remote::detach;
using VaultPerm = rbac::permission::admin::VaultPermissions;
using json = nlohmann::json;

constexpr const char* kSystem = "system:cloud";
constexpr std::time_t kFastWindow = 5 * 60;      // fast polling after a switch or a handoff
constexpr std::time_t kFastInterval = 15;
constexpr std::time_t kKeyCheckInterval = 24 * 3600;
constexpr std::time_t kKeyCheckRetry = 3600;
constexpr std::time_t kEnrollBehindHealth = 24 * 3600;

std::atomic<bool> woken{false};
std::atomic<bool> keyCheckAsked{false};
std::mutex tickMutex;
std::mutex probeMutex;
std::optional<KeyProbe> keyProbe;

// The overview of the last successful fetch, in memory (the steps between fetches use it).
std::mutex cacheMutex;
std::optional<cs::Overview> cachedOverview;
std::time_t cachedAt = 0;

std::time_t now() { return std::time(nullptr); }

void audit(const std::string& action, const std::optional<uint32_t> vaultId, json details, const std::string& message,
           const ::vh::audit::Outcome outcome = ::vh::audit::Outcome::Success) {
    ::vh::audit::record({.action = action, .outcome = outcome, .actor_id = std::nullopt, .actor = kSystem,
                         .vault_id = vaultId, .details = std::move(details)},
                        "[CloudStorage] " + message);
}

void auditActor(const Actor& actor, const std::string& action, const std::optional<uint32_t> vaultId, json details,
                const std::string& message) {
    ::vh::audit::record({.action = action, .outcome = ::vh::audit::Outcome::Success, .actor_id = actor->id,
                         .actor = actor->name(), .vault_id = vaultId, .details = std::move(details)},
                        "[ops::cloud_storage] " + actor->name() + " " + message);
}

bool canView(const Actor& actor) { return actor->isSuperAdmin() || actor->cloudPerms().canView(); }

void requireView(const Actor& actor) {
    requireActor(actor);
    if (!canView(actor)) throw Denied("only super admins or users with the view cloud permission can see managed storage");
}

void requireStorage(const Actor& actor, const Channel channel) {
    requireActor(actor);
    if (channel == Channel::Agent)
        throw Denied("where a vault is stored is decided by a person, never an agent; run `vh cloud storage` yourself");
    if (!actor->isSuperAdmin() && !actor->cloudPerms().canManageStorage())
        throw Denied("only super admins or users with the cloud storage permission can change managed storage");
}

std::shared_ptr<vault::model::Vault> liveVault(const unsigned int vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw NotFound("no vault with ID " + std::to_string(vaultId));
    return vault;
}

void requireVaultEdit(const Actor& actor, const std::shared_ptr<vault::model::Vault>& vault) {
    if (!rbac::resolver::Admin::has<VaultPerm>({.user = actor, .permission = VaultPerm::Edit, .vault = vault}))
        throw Denied("you do not have permission to edit vault " + vault->name);
}

std::optional<ops::cloud_keys::PinnedKey> pinned() {
    try {
        return ops::cloud_keys::pinnedKey();
    } catch (const std::exception&) {
        return std::nullopt;   // tampered: nothing is wrapped to it, and nothing here runs
    }
}

std::string accountKeyState(const bool linked) {
    if (!linked) return "unlinked";
    try {
        return ops::cloud_keys::pinnedKey() ? "pinned" : "unconfirmed";
    } catch (const std::exception&) {
        return "tampered";
    }
}

bool storageAvailable(const std::optional<db::query::cloud::StorageAccountRow>& a) {
    return a && a->storage_access && *a->storage_access != "none";
}

std::string accessName(const storage::remote_access::Mode m) { return std::string(storage::remote_access::to_string(m)); }

std::string summaryOf(const Row& r) {
    const auto why = r.reason ? " (" + *r.reason + ")" : std::string();
    if (r.switch_state == "offered") return "offered: waiting for a person to accept";
    if (r.switch_state == "declined" && (r.state == "unregistered" || r.state == "off")) return "declined: stays local";
    if (r.state == "unregistered")
        return r.switch_state == "on" ? (r.reason == std::optional<std::string>("empty") ? "not stored yet: no files"
                                                                                         : "registering")
                                      : "local";
    if (r.state == "registered") return "registered";
    if (r.state == "waiting") return "waiting for its bucket" + why;
    if (r.state == "keyed")
        return r.reason == std::optional<std::string>("bucket_holds_this_vault")
                   ? "its bucket still holds this vault's earlier copy: restore it (`vh vault recover`) or have the "
                     "account holder delete the bucket"
                   : "bucket ready, starting the upload";
    if (r.state == "attaching") return "uploading";
    if (r.state == "active") {
        if (r.reason == std::optional<std::string>("ended_pending_confirmation"))
            return "the plan ended: waiting for an admin's confirmation (`vh cloud storage confirm-ended`) before it "
                   "becomes local; local copies only meanwhile";
        const auto mode = storage::remote_access::mode(r.vault_id);
        if (mode == storage::remote_access::Mode::ReadOnly) return "read-only: local changes kept" + why;
        if (mode == storage::remote_access::Mode::None) return "unavailable: local copies only" + why;
        return "backed up";
    }
    if (r.state == "detaching") return "making it local again" + why;
    if (r.state == "off") return "off";
    if (r.state == "moved") return "moved to another server: this copy no longer syncs";
    if (r.state == "ejected") return "uses its own storage (left managed storage)";
    if (r.state == "ended") return "local: managed storage ended";
    if (r.state == "failed") return "failed" + (r.last_error ? ": " + *r.last_error : why);
    return r.state;
}

VaultEntry entryOf(const vault::model::Vault& v, const std::optional<Row>& row) {
    VaultEntry e;
    e.vault_id = v.id;
    e.vault_name = v.name;
    e.vault_uid = v.uid ? vl::keykit::toBase32(*v.uid) : std::string{};
    try {
        e.local_bytes = DB::contentBytes(v.id);
    } catch (const std::exception&) {
    }
    if (v.type == vault::model::VaultType::S3) e.access = accessName(storage::remote_access::mode(v.id));
    if (!row) {
        const bool s3 = v.type == vault::model::VaultType::S3;
        e.storage = s3 ? "own" : "local";
        e.state = e.storage;
        e.summary = s3 ? "uses its own storage" : "local";
        e.progress = nullptr;
        e.lost = nullptr;
        return e;
    }
    const auto& r = *row;
    e.storage = r.state == "ejected" ? "own" : "managed";
    e.switch_state = r.switch_state;
    e.state = r.state;
    e.reason = r.reason;
    e.summary = summaryOf(r);
    e.key_state = r.key_state;
    e.key_access = r.key_access;
    e.retention_days = DB::desiredRetention(v.id);
    if (!e.retention_days) e.retention_days = r.retention_days;
    e.retention_sent = r.retention_sent;
    e.retention_pending = r.state == "active" && e.retention_days && e.retention_days != r.retention_sent;
    if (r.state == "active") {
        const auto enrolled = db::query::cloud::RecoveryVaults::get(v.id);
        e.recovery = !enrolled ? "none" : r.enroll_behind_since ? "behind" : "ready";
    }
    e.progress = nullptr;
    e.lost = nullptr;
    if (const auto d = db::query::vault::RemoteDetach::get(v.id); d && d->lost) e.lost = *d->lost;
    e.last_error = r.last_error;
    e.active_at = r.active_at;
    e.moved_at = r.moved_at;
    e.ejected_at = r.ejected_at;
    e.ended_at = r.ended_at;
    return e;
}

// The attach's or detach's progress, as vault.remote.status renders it (no permission check: the caller has view).
json progressOf(const uint32_t vaultId, const std::string& state) {
    if (state == "attaching") {
        if (const auto a = db::query::vault::RemoteAttach::get(vaultId))
            return ra::toJson(ra::progressOf(*a, db::query::vault::RemoteAttach::items(vaultId)));
    } else if (state == "detaching") {
        if (const auto d = db::query::vault::RemoteDetach::get(vaultId))
            return ra::toJson(rd::progressOf(*d, db::query::vault::RemoteDetach::items(vaultId)));
    }
    return nullptr;
}

void save(Row& r) { DB::update(r); }

// A step that failed for a reason that may pass: retried with a backoff (1 min doubling, at most 6 h).
void backoff(Row& r, const std::string& error) {
    r.attempts = std::min<uint32_t>(r.attempts + 1, 30);
    const auto wait = std::min<std::time_t>(60 * (std::time_t{1} << std::min<uint32_t>(r.attempts - 1, 9)), 6 * 3600);
    r.next_attempt_at = now() + wait;
    r.last_error = error;
    save(r);
}

void clearRetry(Row& r) {
    r.attempts = 0;
    r.next_attempt_at.reset();
    r.last_error.reset();
}

void fast() {
    try {
        DB::setFastUntil(now() + kFastWindow);
    } catch (const std::exception&) {
    }
    woken = true;
}

// ---- keys ----------------------------------------------------------------------------------------------------------------

vault::model::S3Provider providerOf(const std::string& provider) {
    // The cloud's provider names (storage.provider): b2 is Backblaze; anything else (the development provider, the fake)
    // is a generic S3 endpoint.
    return provider == "b2" ? vault::model::S3Provider::BackblazeB2 : vault::model::S3Provider::Other;
}

bool probeKey(const uint32_t apiKeyId, const std::string& bucket, std::string& error) {
    {
        std::scoped_lock lock(probeMutex);
        if (keyProbe && paths::testMode) return (*keyProbe)(apiKeyId, error);
    }
    if (paths::testMode) return true;
    const auto key = runtime::Deps::get().apiKeyManager->getAPIKey(apiKeyId);
    const auto [ok, msg] = storage::s3::Controller(key, bucket).validateAPICredentials();
    if (!ok) error = msg;
    return ok;
}

// The exchanged key stored like the server's other API keys (the secret sealed under ak_master), owned by the vault's
// owner and marked as the cloud's; a rotation writes it into the same row (the vaults bound to it keep their binding).
void storeKey(Row& r, cs::Credential& c, const std::string& provider) {
    const auto& keys = runtime::Deps::get().apiKeyManager;
    if (!keys) throw std::runtime_error("the API key manager is not available");
    std::string secret(reinterpret_cast<const char*>(c.secret.bytes().data()), c.secret.size());
    const auto region = c.region.empty() ? std::string("auto") : c.region;
    std::shared_ptr<vault::model::APIKey> existing;
    if (r.api_key_id) existing = db::query::vault::APIKey::getAPIKey(*r.api_key_id);
    if (existing) {
        existing->access_key = c.key_id;
        existing->secret_access_key = std::move(secret);
        existing->endpoint = c.s3_endpoint;
        existing->region = region;
        existing->provider = providerOf(provider);
        keys->updateAPIKey(existing);   // wipes the secret
    } else {
        const auto owner = DB::ownerOf(r.vault_id);
        if (!owner) throw std::runtime_error("the vault has no owner");
        auto key = std::make_shared<vault::model::APIKey>(*owner, "managed storage " + r.vault_uid, providerOf(provider),
                                                          c.key_id, std::move(secret), region, c.s3_endpoint);
        r.api_key_id = keys->addAPIKey(key);   // wipes the secret
    }
    vl::keykit::wipe(secret);
    DB::markKeyCloud(*r.api_key_id, c.access);
    r.key_id = c.key_id;
    r.key_state = "issued";
    r.key_access = c.access;
    r.bucket = c.bucket;
    r.bucket_id = c.bucket_id;
    r.s3_endpoint = c.s3_endpoint;
    r.region = c.region;
    save(r);
}

// Step 4 (and every rotation): a new sealed key, stored, probed, then acknowledged. A probe that fails leaves the key
// unacknowledged (the cloud revokes it) and is retried with a new key pair.
void exchangeKey(Row& r, const cs::Linked& link, const std::string& provider, const std::string& why) {
    auto c = cs::requestCredential(link, r.vault_uid);
    storeKey(r, c, provider);
    audit("cloud.storage.credential.issue", r.vault_id, {{"key_id", c.key_id}, {"access", c.access}, {"why", why}},
          fmt::format("bucket key {} ({}) for vault {} received sealed and stored ({})", c.key_id, c.access, r.vault_id, why));
    std::string error;
    if (!probeKey(*r.api_key_id, r.bucket.value_or(""), error))
        throw std::runtime_error("the bucket key didn't pass the probe: " + error);
    cs::acknowledge(link, c.key_id);
    r.key_state = "active";
    save(r);
    audit("cloud.storage.ack", r.vault_id, {{"key_id", c.key_id}}, fmt::format("bucket key {} acknowledged", c.key_id));
    // A vault already on its bucket picks the new key up (same API key row, new credentials).
    if (const auto& manager = runtime::Deps::get().storageManager) {
        const auto engine = manager->getEngine(r.vault_id);
        if (engine && engine->vault && engine->vault->type == vault::model::VaultType::S3) manager->reloadEngine(r.vault_id);
    }
}

// A key stored but never acknowledged (a crash after storing it): acknowledged now, or, when the cloud revoked it
// meanwhile, asked for again.
bool finishIssued(Row& r, const cs::Linked& link) {
    if (r.key_state != "issued" || !r.key_id) return true;
    try {
        std::string error;
        if (!r.api_key_id || !probeKey(*r.api_key_id, r.bucket.value_or(""), error)) return false;
        cs::acknowledge(link, *r.key_id);
        r.key_state = "active";
        save(r);
        return true;
    } catch (const cs::CallError& e) {
        if (e.status() == 409 || e.status() == 404) return false;   // revoked or replaced: a new one is asked for
        throw;
    }
}

void removeKey(Row& r) {
    if (r.api_key_id) {
        const auto id = *r.api_key_id;
        r.api_key_id.reset();
        try {
            if (db::query::vault::APIKey::listVaultsUsingKey(id).empty()) runtime::Deps::get().apiKeyManager->removeAPIKey(id);
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[CloudStorage] Vault {}: the bucket key {} wasn't removed: {}", r.vault_id, id, e.what());
        }
    }
    r.key_id.reset();
    r.key_state = "none";
    r.key_access.reset();
}

// ---- the label -------------------------------------------------------------------------------------------------------

std::string sealableName(const std::string& name) {
    std::string out;
    for (const unsigned char c : name)
        if (c >= 0x20 && c != 0x7f) out.push_back(static_cast<char>(c));
    if (out.empty()) out = "vault";
    while (out.size() > vl::keykit::label::kPaddedSize || !vl::keykit::label::isSealableName(out)) {
        out.pop_back();
        while (!out.empty() && (static_cast<unsigned char>(out.back()) & 0xC0) == 0x80) out.pop_back();
        if (!out.empty() && static_cast<unsigned char>(out.back()) >= 0xC0) out.pop_back();
        if (out.empty()) return "vault";
    }
    return out;
}

void sendLabel(Row& r, const cs::Linked& link, const vault::model::Vault& vault, const ops::cloud_keys::PinnedKey& pin) {
    if (!vault.uid) return;
    const auto statement = vl::keykit::account::parseStatement(pin.statement);
    const auto sealed = vl::keykit::label::seal(sealableName(vault.name), statement, *vault.uid);
    cs::putLabel(link, r.vault_uid, sealed);
    r.label_generation = pin.generation;
}

// ---- the gate ---------------------------------------------------------------------------------------------------------

storage::remote_access::Mode wantedAccess(const Row& r, const db::query::cloud::StorageAccountRow& account) {
    using storage::remote_access::Mode;
    if (r.state == "moved" || r.key_state == "none") return Mode::None;
    const auto a = account.storage_access.value_or("none");
    if (a == "none") return Mode::None;
    if (a == "read_delete" || r.key_access == std::optional<std::string>("read_delete")) return Mode::ReadOnly;
    return Mode::Full;
}

std::string accessCause(const Row& r, const db::query::cloud::StorageAccountRow& account) {
    if (r.state == "moved") return "moved to another server";
    if (r.key_state == "none") return "the account's service revoked this server's bucket key";
    if (account.cause && !account.cause->empty()) return "account " + *account.cause;
    return "account " + account.state.value_or("without a plan");
}

void applyGate(const Row& r, const db::query::cloud::StorageAccountRow& account) {
    const auto want = wantedAccess(r, account);
    if (storage::remote_access::mode(r.vault_id) == want) return;
    const auto cause = want == storage::remote_access::Mode::Full ? std::optional<std::string>() : accessCause(r, account);
    (void)storage::remote_access::set(r.vault_id, want, cause, kSystem);
    audit("cloud.storage.access", r.vault_id, {{"access", accessName(want)}, {"cause", cause.value_or("")}},
          fmt::format("vault {}: remote access {} ({})", r.vault_id, accessName(want), cause.value_or("full")));
}

// ---- the steps --------------------------------------------------------------------------------------------------------

struct Ctx {
    const cs::Linked& link;
    const cs::Overview& overview;
    std::time_t fetchedAt{};
    db::query::cloud::StorageAccountRow account;
    ops::cloud_keys::PinnedKey pin;
};

const cs::VaultStorage* cloudVault(const Ctx& ctx, const std::string& uid) {
    for (const auto& v : ctx.overview.vaults)
        if (v.vault_uid == uid) return &v;
    return nullptr;
}

uint32_t retentionFor(const Row& r) {
    if (const auto d = DB::desiredRetention(r.vault_id)) return *d;
    return r.retention_days.value_or(config::Registry::get().cloud.storage_default_retention_days);
}

void becomeOff(Row& r, const cs::Linked& link, const bool tellCloud) {
    if (tellCloud && r.registered_at) {
        try {
            (void)cs::setVault(link, r.vault_uid, false, std::nullopt);
        } catch (const cs::CallError& e) {
            if (e.status() != 404) throw;
        }
    }
    removeKey(r);
    r.state = "off";
    r.reason.reset();
    clearRetry(r);
    save(r);
    audit("cloud.storage.switch", r.vault_id, {{"switch", "off"}}, fmt::format("vault {} is off managed storage", r.vault_id));
}

void stepUnregistered(Row& r, const Ctx& ctx, const vault::model::Vault& vault) {
    if (r.switch_state != "on") return;
    // Open question 3: an empty vault isn't registered (a bucket per vault is the account's to spend).
    if (!DB::hasContent(r.vault_id)) {
        if (r.reason != std::optional<std::string>("empty")) {
            r.reason = "empty";
            save(r);
        }
        return;
    }
    try {
        (void)cs::registerVault(ctx.link, r.vault_uid, r.vault_id);
    } catch (const cs::CallError& e) {
        if (e.status() == 409) {
            r.state = "failed";
            r.reason = "registered_elsewhere";
            r.last_error = "another server of the account holds this vault";
            save(r);
            audit("cloud.storage.failed", r.vault_id, {{"reason", "registered_elsewhere"}},
                  fmt::format("vault {} is registered on the account by another server", r.vault_id),
                  ::vh::audit::Outcome::Failure);
            return;
        }
        throw;
    }
    sendLabel(r, ctx.link, vault, ctx.pin);
    r.state = "registered";
    r.reason.reset();
    r.registered_at = now();
    clearRetry(r);
    save(r);
    audit("cloud.storage.vault.register", r.vault_id, {{"label_generation", ctx.pin.generation}},
          fmt::format("vault {} registered with the account (sealed label, generation {})", r.vault_id, ctx.pin.generation));
    fast();
}

void stepRegistered(Row& r, const Ctx& ctx) {
    if (r.switch_state != "on") {
        becomeOff(r, ctx.link, true);
        return;
    }
    const auto days = retentionFor(r);
    const auto v = cs::setVault(ctx.link, r.vault_uid, true, days);
    r.retention_days = days;
    r.retention_sent = v.content_retention_days;
    r.state = "waiting";
    r.reason = v.reason;
    clearRetry(r);
    save(r);
    fast();
}

void stepWaiting(Row& r, const Ctx& ctx) {
    if (r.switch_state != "on") {
        becomeOff(r, ctx.link, true);
        return;
    }
    const auto* v = cloudVault(ctx, r.vault_uid);
    if (!v) return;   // registered a moment ago: the next fetch lists it
    if (!v->enabled || v->state == "off") {
        (void)cs::setVault(ctx.link, r.vault_uid, true, std::nullopt);
        fast();
        return;
    }
    if (v->state != "ready") {
        const auto reason = v->reason ? *v->reason : v->state;
        if (r.reason != std::optional<std::string>(reason)) {
            r.reason = reason;
            save(r);
        }
        return;
    }
    if (r.key_state == "issued" && !finishIssued(r, ctx.link)) r.key_state = "none";
    if (r.key_state != "active") {
        try {
            exchangeKey(r, ctx.link, ctx.overview.provider, "provisioned");
        } catch (const cs::CallError& e) {
            if (e.status() == 409 || e.status() == 402 || e.status() == 429) {
                r.reason = e.reason().empty() ? e.code() : e.reason();
                backoff(r, e.what());
                return;
            }
            throw;
        }
    }
    r.state = "keyed";
    r.reason.reset();
    r.ready_at = now();
    clearRetry(r);
    save(r);
    audit("cloud.storage.bucket.ready", r.vault_id, {{"bucket_id", r.bucket_id.value_or("")}},
          fmt::format("vault {}: its bucket is ready and this server holds its key", r.vault_id));
    fast();
}

void stepKeyed(Row& r, const Ctx& ctx) {
    if (r.switch_state != "on") {
        becomeOff(r, ctx.link, true);
        return;
    }
    if (!r.api_key_id || !r.bucket) {
        r.state = "waiting";
        save(r);
        return;
    }
    try {
        ops::vault_remote::attachForCloud(r.vault_id, *r.api_key_id, *r.bucket);
    } catch (const ra::Refusal& e) {
        r.reason = e.code();
        backoff(r, e.what());
        return;
    } catch (const Error& e) {
        r.reason = "attach_refused";
        backoff(r, e.what());
        return;
    }
    r.state = "attaching";
    r.reason.reset();
    clearRetry(r);
    save(r);
    fast();
}

void becomeActive(Row& r, const Ctx& ctx) {
    const auto key = db::query::vault::APIKey::getAPIKey(*r.api_key_id);
    if (key) {
        const auto id = storage::upstream::identityFor(*key, *r.bucket);
        DB::bindManagedBucket(r.vault_id, id.provider, id.account_ref.value_or("managed:" + r.bucket_id.value_or(*r.bucket)),
                              *r.bucket, r.region, *r.api_key_id, retentionFor(r));
    }
    r.state = "active";
    r.reason.reset();
    r.active_at = now();
    clearRetry(r);
    save(r);
    applyGate(r, ctx.account);
    audit("cloud.storage.attached", r.vault_id, {{"bucket_id", r.bucket_id.value_or("")}},
          fmt::format("vault {} is in managed storage", r.vault_id));
    fast();
}

void stepAttaching(Row& r, const Ctx& ctx) {
    const auto a = db::query::vault::RemoteAttach::get(r.vault_id);
    if (r.switch_state != "on") {
        if (a && ra::beforeCutover(a->state) && a->state != ra::State::Failed) {
            (void)ops::vault_remote::abortForCloud(r.vault_id);
            return;   // the attach service aborts it; the next step sees it aborted
        }
        if (!a || a->state == ra::State::Aborted || a->state == ra::State::Failed) {
            becomeOff(r, ctx.link, true);
            return;
        }
        // Cut over meanwhile: it is active, and the switch off detaches it.
    }
    if (!a) {
        r.state = "keyed";
        save(r);
        return;
    }
    switch (a->state) {
    case ra::State::Done: becomeActive(r, ctx); return;
    case ra::State::Failed:
        r.reason = "attach_failed";
        backoff(r, a->last_error.value_or("the attach failed"));
        r.state = "keyed";   // the next step starts it again (a failed attach resumes)
        save(r);
        return;
    case ra::State::Aborted: r.state = "keyed"; save(r); return;
    default: return;   // the attach service runs it
    }
}

void startDetach(Row& r, const bool inPlace, const std::string& why) {
    try {
        ops::vault_remote::detachForCloud(r.vault_id, inPlace);
    } catch (const ra::Refusal& e) {
        r.reason = e.code();
        backoff(r, e.what());
        return;
    } catch (const Error& e) {
        r.reason = "detach_refused";
        backoff(r, e.what());
        return;
    }
    r.state = "detaching";
    r.reason = why;
    clearRetry(r);
    save(r);
    audit("cloud.storage.detach", r.vault_id, {{"in_place", inPlace}, {"why", why}},
          fmt::format("vault {}: making it local again ({}{})", r.vault_id, why, inPlace ? ", in place" : ""));
    fast();
}

void ejectInPlace(Row& r, const Ctx& ctx) {
    // The customer's own credentials take over on the same bucket: the key becomes theirs, nothing moves.
    if (!DB::eject(r.vault_id)) return;
    if (storage::remote_access::mode(r.vault_id) != storage::remote_access::Mode::Full)
        (void)storage::remote_access::set(r.vault_id, storage::remote_access::Mode::Full, std::nullopt, kSystem);
    audit("cloud.storage.eject", r.vault_id, {{"bucket_id", r.bucket_id.value_or("")}},
          fmt::format("vault {} left managed storage in place: its bucket key is the customer's own now (BYOS)", r.vault_id));
    try {
        cs::reportEjected(ctx.link, r.vault_uid);
    } catch (const cs::CallError& e) {
        log::Registry::cloud()->warn("[CloudStorage] Vault {}: the ejection report wasn't accepted yet: {}", r.vault_id, e.what());
    }
}

void rotate(Row& r, const Ctx& ctx, const std::string& why) {
    exchangeKey(r, ctx.link, ctx.overview.provider, why);
    if (r.reason == std::optional<std::string>("rotation_requested")) r.reason.reset();
    save(r);
    audit("cloud.storage.rotate", r.vault_id, {{"why", why}, {"access", r.key_access.value_or("")}},
          fmt::format("vault {}: bucket key replaced ({})", r.vault_id, why));
}

void enroll(Row& r, const vault::model::Vault& vault) {
    const auto engine = runtime::Deps::get().storageManager ? runtime::Deps::get().storageManager->getEngine(vault.id) : nullptr;
    const auto current = engine && engine->encryptionManager ? engine->encryptionManager->get_key_version() : 0u;
    const auto enrolled = db::query::cloud::RecoveryVaults::get(vault.id);
    if (enrolled && r.enrolled_version && *r.enrolled_version >= current && !r.enroll_behind_since) return;
    const std::string reason = !enrolled ? "attached" : r.enroll_behind_since ? "behind" : "rotation";
    try {
        (void)ops::cloud_recovery::enrollAutomatic(vault.id, reason);
        r.enrolled_version = current;
        r.enroll_behind_since.reset();
        save(r);
    } catch (const std::exception& e) {
        if (!r.enroll_behind_since) r.enroll_behind_since = now();
        save(r);
        log::Registry::cloud()->warn("[CloudStorage] Vault {}: automatic recovery enrollment waits: {}", vault.id, e.what());
    }
}

std::time_t endedGrace() {
    return static_cast<std::time_t>(config::Registry::get().cloud.storage_ended_grace_hours) * 3600;
}

bool endedConfirmed(const db::query::cloud::StorageAccountRow& a) {
    if (a.state != std::optional<std::string>("ended")) return false;
    if (a.ended_confirmed_at) return true;
    return a.ended_seen_at && now() - *a.ended_seen_at >= endedGrace();
}

void stepActive(Row& r, const Ctx& ctx, const vault::model::Vault& vault) {
    const auto* v = cloudVault(ctx, r.vault_uid);
    // Gone from this deployment's view after it became active: another server restored it (the cloud moved the
    // replica). Only a fetch newer than the activation says so.
    if ((!v && r.active_at && ctx.fetchedAt > *r.active_at) || (v && v->moved_to)) {
        r.state = "moved";
        r.moved_at = now();
        r.reason = v && v->moved_to ? "restored on " + *v->moved_to : "restored on another server";
        save(r);
        applyGate(r, ctx.account);
        audit("cloud.storage.moved", r.vault_id, nlohmann::json::object(),
              fmt::format("vault {} was restored onto another server; this copy no longer syncs and its local data stays",
                          r.vault_id), ::vh::audit::Outcome::Info);
        return;
    }
    if (v && (v->state == "ejecting" || v->state == "ejected")) {
        ejectInPlace(r, ctx);
        return;
    }
    if (v && (v->state == "emptying" || v->state == "deleted") && ctx.account.state != std::optional<std::string>("ended")) {
        // The account's service is deleting this vault's bucket while the plan isn't (or no longer) ended: the end of an
        // earlier plan began it, or the account holder deleted the bucket in the portal with its confirmations. Nothing
        // is left to sync with, and waiting would leave the vault without access for good (the drill's finding: paying
        // again after `ended`), so it becomes local in place now, as at a confirmed end. Nothing local is deleted; what
        // only the bucket held is listed. While the plan is ended, the confirmation below decides.
        startDetach(r, true, "ended");
        return;
    }
    if (ctx.account.state == std::optional<std::string>("ended")) {
        // One report must not convert every vault: an admin confirms it, or the service keeps saying so for
        // cloud.storage.ended_grace_hours. Until then the vault stays attached with access none.
        if (endedConfirmed(ctx.account)) {
            startDetach(r, true, "ended");
        } else {
            applyGate(r, ctx.account);
            if (r.reason != std::optional<std::string>("ended_pending_confirmation")) {
                r.reason = "ended_pending_confirmation";
                save(r);
            }
        }
        return;
    }
    if (r.switch_state != "on") {
        if (storage::remote_access::allowsReads(storage::remote_access::mode(r.vault_id))) startDetach(r, false, "switched off");
        else if (r.reason != std::optional<std::string>("waiting_for_access")) {
            r.reason = "waiting_for_access";   // files only in the bucket can't be fetched while access is none
            save(r);
        }
        return;
    }
    if (v) {
        // The key as the cloud sees it: superseded (its access changed) asks again; none (revoked) closes the gate.
        if (v->key_state == "superseded" || r.reason == std::optional<std::string>("rotation_requested")) {
            if (v->key_state != "none") rotate(r, ctx, v->key_state == "superseded" ? "superseded" : "requested");
        } else if (v->key_state == "none" && r.key_state != "none") {
            r.key_state = "none";
            save(r);
            audit("cloud.storage.revoked", r.vault_id, nlohmann::json::object(),
                  fmt::format("vault {}: the account's service revoked this server's bucket key", r.vault_id),
                  ::vh::audit::Outcome::Info);
        } else if (r.key_state == "none" && (v->key_state == "active" || v->key_state == "none") &&
                   ctx.account.storage_access && *ctx.account.storage_access != "none") {
            // Access is back (paid again after a suspension): the cloud never reinstates a revoked key, so this server
            // asks for a new one. A step after the revocation was seen, so one stale view can't cause it.
            rotate(r, ctx, "access restored");
        } else if (v->key_state == "issued" && r.key_state == "issued") {
            if (!finishIssued(r, ctx.link)) rotate(r, ctx, "unacknowledged");
        }
        if (v->key_access && r.key_access != v->key_access && v->key_state == "active") {
            r.key_access = v->key_access;
            if (r.api_key_id) DB::markKeyCloud(*r.api_key_id, *v->key_access);
            save(r);
        }
        // Retention: what the vault's recovery policy asks for, until the cloud's view says it holds it.
        if (v->content_retention_days) r.retention_sent = v->content_retention_days;
        const auto want = retentionFor(r);
        if (r.retention_sent != std::optional<uint32_t>(want) && ctx.account.storage_access != std::optional<std::string>("none")) {
            const auto sent = cs::setVault(ctx.link, r.vault_uid, std::nullopt, want);
            r.retention_days = want;
            r.retention_sent = sent.content_retention_days;
            audit("cloud.storage.retention", r.vault_id, {{"days", want}},
                  fmt::format("vault {}: noncurrent retention {} day(s) sent", r.vault_id, want));
        }
        save(r);
    }
    applyGate(r, ctx.account);
    // The label follows the pinned generation (a rotation of the account key seals it anew).
    if (r.label_generation != std::optional<uint32_t>(ctx.pin.generation)) {
        sendLabel(r, ctx.link, vault, ctx.pin);
        save(r);
    }
    enroll(r, vault);
}

void stepDetaching(Row& r, const Ctx& ctx) {
    const auto d = db::query::vault::RemoteDetach::get(r.vault_id);
    if (!d) {
        r.state = r.reason == std::optional<std::string>("ended") ? "ended" : "active";
        save(r);
        return;
    }
    switch (d->state) {
    case rd::State::Done: {
        const auto why = r.reason.value_or("");
        if (why == "ended") {
            removeKey(r);
            r.state = "ended";
            r.ended_at = now();
            r.reason.reset();
            clearRetry(r);
            save(r);
            audit("cloud.storage.entitlement", r.vault_id, {{"state", "ended"}, {"lost", d->lost ? *d->lost : json(nullptr)}},
                  fmt::format("vault {} is local again: the plan ended (files held only in the bucket are listed as lost)",
                              r.vault_id));
            return;
        }
        if (why != "moved") {
            try {
                cs::reportDetached(ctx.link, r.vault_uid);
            } catch (const cs::CallError& e) {
                if (e.status() != 404) throw;
            }
        }
        becomeOff(r, ctx.link, why != "moved");
        return;
    }
    case rd::State::Failed:
        backoff(r, d->last_error.value_or("the detach failed"));
        startDetach(r, d->mode == rd::Mode::InPlace, r.reason.value_or("switched off"));
        return;
    default: return;
    }
}

void stepMoved(Row& r, const Ctx&) {
    // Kept read-only (open question 12): never deleted automatically. Switching it off keeps it as a local vault.
    if (r.switch_state != "on") startDetach(r, true, "moved");
}

void stepOff(Row& r) {
    if (r.switch_state != "on") return;
    r.state = r.registered_at ? "registered" : "unregistered";
    r.reason.reset();
    clearRetry(r);
    save(r);
    fast();
}

void stepVault(Row& r, const Ctx& ctx) {
    const auto vault = db::query::vault::Vault::getVault(r.vault_id);
    if (!vault) {
        DB::remove(r.vault_id);   // deleted: its bucket is the account holder's to delete in the portal
        return;
    }
    if (r.next_attempt_at && *r.next_attempt_at > now()) return;
    try {
        if (r.state == "unregistered") stepUnregistered(r, ctx, *vault);
        else if (r.state == "registered") stepRegistered(r, ctx);
        else if (r.state == "waiting") stepWaiting(r, ctx);
        else if (r.state == "keyed") stepKeyed(r, ctx);
        else if (r.state == "attaching") stepAttaching(r, ctx);
        else if (r.state == "active") stepActive(r, ctx, *vault);
        else if (r.state == "detaching") stepDetaching(r, ctx);
        else if (r.state == "moved") stepMoved(r, ctx);
        else if (r.state == "off") stepOff(r);
        else if (r.state == "failed" && r.switch_state == "on" && r.reason != std::optional<std::string>("registered_elsewhere"))
            stepOff(r);
    } catch (const cs::CallError& e) {
        // An unreachable cloud changes nothing: the step is retried.
        backoff(r, e.what());
    } catch (const std::exception& e) {
        // Anything else (a probe that failed, a database error) is this vault's: the others still step.
        log::Registry::cloud()->warn("[CloudStorage] Vault {}: {}", r.vault_id, e.what());
        try {
            backoff(r, e.what());
        } catch (const std::exception&) {
        }
    }
}

// The sweep (the hook is a sweep, not a call site): every live vault without a row gets one once storage is available.
// Local vaults created after storage became available on this link are switched on when the default says so; earlier
// ones are offered (open question 1). S3 vaults on their own storage get none.
void sweep(const db::query::cloud::StorageAccountRow& account) {
    if (!account.enabled_at) return;
    bool offered = false;
    for (const auto& c : DB::candidates()) {
        if (c.type != "local") continue;
        const bool on = account.new_vaults && c.after_enabled;
        Row r;
        r.vault_id = c.vault_id;
        r.vault_uid = c.vault_uid;
        r.switch_state = on ? "on" : "offered";
        r.switch_by = on ? "system:default" : "system:offer";
        r.state = "unregistered";
        r.retention_days = config::Registry::get().cloud.storage_default_retention_days;
        if (DB::insert(r) && !on) offered = true;
    }
    if (offered && !account.offer_open) DB::setOfferOpen(true);
}

// Replicated vaults (the join contract, 7): a vault the account holder removed from this server stops syncing; a
// former replica still named by the manifest's writers is dropped from them by this server's next publish (one change
// at a time). A former replica without a node id can't be matched to a writer: logged, nothing changes.
void stepReplicas(const Ctx& ctx) {
    const auto self = db::query::device::Devices::nodeId();
    for (const auto& v : ctx.overview.vaults) {
        if (v.replicas.empty() && v.former_replicas.empty() && !v.removed_reason) continue;
        const auto found = db::Transactions::exec("CloudStorage::vaultByUid", [&](pqxx::work& txn) {
            std::optional<unsigned int> id;
            const auto uid = vl::keykit::fromBase32(v.vault_uid);
            if (!uid) return id;
            const auto r = txn.exec("SELECT id FROM vault WHERE uid = $1::uuid", pqxx::params{crypto::id::toUuid(*uid)});
            if (!r.empty()) id = r[0][0].as<unsigned int>();
            return id;
        });
        if (!found) continue;
        if (v.removed_reason) {
            if (ops::vaults::stopSyncing(*found))
                audit("cloud.replica.removed", *found, {{"reason", *v.removed_reason}},
                      fmt::format("the account holder removed vault {} from this server ({}); it no longer syncs here",
                                  *found, *v.removed_reason),
                      ::vh::audit::Outcome::Info);
            continue;
        }
        const auto state = db::query::sync::Manifest::state(*found);
        if (state.writers_change || std::ranges::find(state.writers, self) == state.writers.end()) continue;
        for (const auto& f : v.former_replicas) {
            if (!f.node_id) {
                log::Registry::cloud()->warn("[CloudStorage] vault {}: former replica {} has no node id in Vaulthalla "
                                             "Cloud's answer; it can't be dropped from the manifest's writers",
                                             *found, f.deployment_id);
                continue;
            }
            if (*f.node_id == self || std::ranges::find(state.writers, *f.node_id) == state.writers.end()) continue;
            db::query::sync::Manifest::setWritersChange(
                *found, sync::manifest::WritersChange{sync::manifest::WritersChange::Kind::Remove, *f.node_id});
            audit("cloud.replica.drop", *found, {{"node", *f.node_id}, {"reason", f.reason.value_or("")}},
                  fmt::format("vault {}: {} is no longer a replica at Vaulthalla Cloud ({}); the next publish drops it "
                              "from the manifest's writers",
                              *found, f.name.empty() ? f.deployment_id : f.name, f.reason.value_or("removed")),
                  ::vh::audit::Outcome::Info);
            break;
        }
    }
}

std::optional<Row> rowFor(const unsigned int vaultId) { return DB::get(vaultId); }

Row requireRow(const std::shared_ptr<vault::model::Vault>& vault) {
    auto row = DB::get(vault->id);
    if (row) return *row;
    if (vault->type == vault::model::VaultType::S3)
        throw Conflict("vault '" + vault->name + "' uses its own storage (an S3 vault): managed storage is for local "
                       "vaults");
    if (!vault->uid) throw Conflict("vault '" + vault->name + "' has no uid");
    Row r;
    r.vault_id = vault->id;
    r.vault_uid = vl::keykit::toBase32(*vault->uid);
    r.switch_state = "off";
    r.switch_by = kSystem;
    r.retention_days = config::Registry::get().cloud.storage_default_retention_days;
    (void)DB::insert(r);
    return *DB::get(vault->id);
}

}

// ---- operations ---------------------------------------------------------------------------------------------------------

Status status(const Actor& actor) {
    namespace d = cloud_storage_ops_detail;
    d::requireView(actor);
    Status s;
    const auto link = db::query::cloud::Link::get();
    s.linked = link && link->status == "linked";
    s.account_key = d::accountKeyState(s.linked);
    const auto account = d::DB::account();
    if (account) {
        s.entitlement = account->state;
        s.plan = account->plan;
        s.quota_bytes = account->quota_bytes;
        s.used_bytes = account->used_bytes;
        s.usage_day = account->usage_day;
        s.storage_access = account->storage_access;
        s.cause = account->cause;
        s.new_vaults = account->new_vaults;
        s.offer_open = account->offer_open;
        s.billing = account->billing;
        s.ejection = account->ejection;
        s.fetched_at = account->fetched_at;
        s.fetch_error = account->fetch_error;
        if (account->state == std::optional<std::string>("ended") && account->ended_seen_at)
            s.ended = EndedPending{.since = *account->ended_seen_at,
                                   .converts_at = *account->ended_seen_at + d::endedGrace(),
                                   .confirmed_by = account->ended_confirmed_by};
    }
    s.available = s.linked && s.account_key == "pinned" && d::storageAvailable(account);
    std::map<unsigned int, d::Row> rows;
    for (auto& r : d::DB::list()) rows.emplace(r.vault_id, std::move(r));
    for (const auto& vault : db::query::vault::Vault::listLiveVaults()) {
        const auto it = rows.find(vault->id);
        auto e = d::entryOf(*vault, it == rows.end() ? std::nullopt : std::optional<d::Row>(it->second));
        if (it != rows.end()) e.progress = d::progressOf(vault->id, it->second.state);
        if (e.storage == "managed" && (e.state == "active" || e.state == "attaching" || e.state == "detaching"))
            s.managed_local_bytes += e.local_bytes;
        if (e.switch_state == std::optional<std::string>("offered")) s.offered.push_back(e);
        s.vaults.push_back(std::move(e));
    }
    if (!s.linked) s.next_step = "link this server to an account first (`vh cloud link`)";
    else if (s.account_key == "unconfirmed")
        s.next_step = "confirm the account recovery key's fingerprint (`vh cloud key confirm`): managed storage waits for it";
    else if (s.account_key == "tampered") s.next_step = "the pinned account key fails its check (`vh cloud key status`)";
    else if (s.ended && !s.ended->confirmed_by)
        s.next_step = "the plan ended: managed vaults become local in place when an admin confirms it (`vh cloud storage "
                      "confirm-ended`) or after the grace period";
    else if (!s.available) s.next_step = "the account has no storage plan (`vh cloud storage billing checkout`)";
    else if (!s.offered.empty())
        s.next_step = std::to_string(s.offered.size()) + " vault(s) wait for a decision (`vh cloud storage accept` or "
                      "`decline`)";
    return s;
}

VaultEntry setSwitch(const Actor& actor, const unsigned int vaultId, const bool on, const std::optional<std::string>& confirm,
                     const Channel channel) {
    namespace d = cloud_storage_ops_detail;
    d::requireStorage(actor, channel);
    const auto vault = d::liveVault(vaultId);
    d::requireVaultEdit(actor, vault);
    auto r = d::requireRow(vault);
    if (r.state == "ejected") throw Conflict("vault '" + vault->name + "' left managed storage: it uses its own storage now");
    if (on) {
        const auto link = db::query::cloud::Link::get();
        if (!link || link->status != "linked" || d::accountKeyState(true) != "pinned" ||
            !d::storageAvailable(d::DB::account()))
            throw Refused("managed_storage_unavailable",
                          "managed storage isn't available on this server (`vh cloud storage status` says why)");
        if (r.state == "moved")
            throw Conflict("vault '" + vault->name + "' was restored onto another server; this copy no longer syncs");
    } else {
        const bool hasBucket = r.state == "active" || r.state == "attaching" || r.state == "detaching" || r.state == "moved";
        if (hasBucket && confirm != std::optional<std::string>(vault->name))
            throw Invalid("switching managed storage off makes the vault local again; confirm with the vault's name ('" +
                          vault->name + "')");
    }
    const auto want = on ? "on" : "off";
    if (r.switch_state != want) {
        r.switch_state = want;
        r.switch_by = "user:" + actor->name();
        r.switch_at = std::time(nullptr);
        r.next_attempt_at.reset();
        d::save(r);
        d::auditActor(actor, "cloud.storage.switch", vault->id, {{"switch", want}},
                      fmt::format("switched managed storage {} for vault {}", want, vault->id));
        wake();
    }
    return d::entryOf(*vault, r);
}

OfferResult acceptOffer(const Actor& actor, const std::optional<std::vector<unsigned int>>& vaults, const Channel channel) {
    namespace d = cloud_storage_ops_detail;
    d::requireStorage(actor, channel);
    OfferResult out;
    for (auto r : d::DB::list()) {
        if (r.switch_state != "offered") continue;
        if (vaults && std::ranges::find(*vaults, r.vault_id) == vaults->end()) continue;
        const auto vault = db::query::vault::Vault::getVault(r.vault_id);
        if (!vault) continue;
        d::requireVaultEdit(actor, vault);
        r.switch_state = "on";
        r.switch_by = "user:" + actor->name();
        r.switch_at = std::time(nullptr);
        d::save(r);
        out.vaults.push_back(r.vault_id);
    }
    if (vaults)
        for (const auto id : *vaults)
            if (std::ranges::find(out.vaults, id) == out.vaults.end())
                throw NotFound("vault " + std::to_string(id) + " isn't offered for managed storage");
    const bool stillOffered = std::ranges::any_of(d::DB::list(), [](const d::Row& r) { return r.switch_state == "offered"; });
    if (!stillOffered) d::DB::setOfferOpen(false);
    out.offer_open = stillOffered;
    d::auditActor(actor, "cloud.storage.offer.accept", std::nullopt, {{"vaults", out.vaults}},
                  fmt::format("accepted managed storage for {} vault(s)", out.vaults.size()));
    wake();
    return out;
}

OfferResult declineOffer(const Actor& actor, const std::optional<std::vector<unsigned int>>& vaults, const Channel channel) {
    namespace d = cloud_storage_ops_detail;
    d::requireStorage(actor, channel);
    OfferResult out;
    for (auto r : d::DB::list()) {
        if (r.switch_state != "offered") continue;
        if (vaults && std::ranges::find(*vaults, r.vault_id) == vaults->end()) continue;
        r.switch_state = "declined";
        r.switch_by = "user:" + actor->name();
        r.switch_at = std::time(nullptr);
        d::save(r);
        out.vaults.push_back(r.vault_id);
    }
    const bool stillOffered = std::ranges::any_of(d::DB::list(), [](const d::Row& r) { return r.switch_state == "offered"; });
    if (!stillOffered) d::DB::setOfferOpen(false);
    out.offer_open = stillOffered;
    d::auditActor(actor, "cloud.storage.offer.decline", std::nullopt, {{"vaults", out.vaults}},
                  fmt::format("declined managed storage for {} vault(s)", out.vaults.size()));
    return out;
}

VaultEntry rotate(const Actor& actor, const unsigned int vaultId, const Channel channel) {
    namespace d = cloud_storage_ops_detail;
    d::requireStorage(actor, channel);
    const auto vault = d::liveVault(vaultId);
    d::requireVaultEdit(actor, vault);
    auto r = d::DB::get(vault->id);
    if (!r || r->state != "active") throw Conflict("vault '" + vault->name + "' isn't in managed storage");
    r->reason = "rotation_requested";
    r->next_attempt_at.reset();
    d::save(*r);
    d::auditActor(actor, "cloud.storage.rotate", vault->id, {{"requested", true}},
                  fmt::format("asked for a new bucket key for vault {}", vault->id));
    wake();
    return d::entryOf(*vault, *r);
}

EndedConfirmation confirmEnded(const Actor& actor, const Channel channel) {
    namespace d = cloud_storage_ops_detail;
    d::requireStorage(actor, channel);
    if (!d::DB::confirmEnded("user:" + actor->name()))
        throw Conflict("the account's service isn't reporting the plan ended; nothing to confirm");
    d::auditActor(actor, "cloud.storage.ended.confirm", std::nullopt, nlohmann::json::object(),
                  "confirmed that the plan ended: managed vaults become local in place");
    wake();
    const auto a = d::DB::account();
    return {.confirmed = true, .since = a ? a->ended_seen_at : std::nullopt,
            .vaults = static_cast<unsigned int>(std::ranges::count_if(d::DB::list(), [](const d::Row& r) {
                return r.state == "active";
            }))};
}

bool setNewVaultsDefault(const Actor& actor, const bool on, const Channel channel) {
    namespace d = cloud_storage_ops_detail;
    d::requireStorage(actor, channel);
    d::DB::setNewVaults(on);
    d::auditActor(actor, "cloud.storage.new_vaults", std::nullopt, {{"on", on}},
                  fmt::format("set new vaults to {} managed storage by default", on ? "use" : "not use"));
    return on;
}

Handoff billingHandoff(const Actor& actor, const std::string& kind, const std::optional<std::string>& plan,
                       const Channel channel) {
    namespace d = cloud_storage_ops_detail;
    requireActor(actor);
    if (channel == Channel::Agent) throw Denied("billing opens in a browser, for a person; never an agent");
    if (!actor->isSuperAdmin() && !actor->cloudPerms().canBilling())
        throw Denied("only super admins or users with the cloud billing permission can open billing");
    if (kind != "checkout" && kind != "portal") throw Invalid("kind is checkout or portal");
    if (plan && (plan->empty() || plan->size() > 64)) throw Invalid("the plan is 1 to 64 characters");
    const auto link = d::cs::linked();
    if (!link) throw Conflict("this server isn't linked to an account (`vh cloud link`)");
    try {
        const auto h = d::cs::billingHandoff(*link, kind, plan);
        d::fast();
        d::auditActor(actor, "cloud.storage.billing.handoff", std::nullopt, {{"kind", kind}},
                      "opened the account's billing (" + kind + ")");
        return {.kind = kind, .url = h.url, .expires_at = h.expires_at};
    } catch (const d::cs::CallError& e) {
        if (e.unreachable()) throw Refused("cloud_unreachable", e.what());
        throw Refused("cloud_refused", e.what());
    }
}

// ---- the engine ----------------------------------------------------------------------------------------------------------

TickResult tick(const bool force) {
    namespace d = cloud_storage_ops_detail;
    std::scoped_lock lock(d::tickMutex);
    TickResult out;
    try {
        const auto linkRow = db::query::cloud::Link::get();
        auto link = d::cs::linked();
        out.linked = link.has_value();
        if (!link || !linkRow) return out;

        // The account recovery key check (key-manager.md, "Fetch"), hosted here: daily, hourly after a failure, and at
        // once when asked.
        const bool asked = d::keyCheckAsked.exchange(false);
        const bool settled = linkRow->key_check == "ok" || linkRow->key_check == "none";
        const auto wait = settled ? d::kKeyCheckInterval : d::kKeyCheckRetry;
        if (asked || !linkRow->key_checked_at || d::now() - *linkRow->key_checked_at >= wait) {
            try {
                (void)ops::cloud_keys::check(asked ? "requested" : "scheduled");
            } catch (const std::exception& e) {
                log::Registry::vaulthalla()->warn("[CloudStorage] Account recovery key check failed: {}", e.what());
            }
        }
        const auto pin = d::pinned();
        out.pinned = pin.has_value();
        if (!pin) return out;   // nothing runs until a person confirmed the account key on this server

        auto account = d::DB::account();
        const auto poll = static_cast<std::time_t>(config::Registry::get().cloud.storage_poll_minutes) * 60;
        const bool fastNow = account && account->fast_until && *account->fast_until > d::now();
        const bool due = force || !account || !account->fetched_at ||
                         d::now() - *account->fetched_at >= (fastNow ? d::kFastInterval : poll);
        std::optional<d::cs::Overview> overview;
        std::time_t fetchedAt = 0;
        if (due) {
            try {
                auto ov = d::cs::overview(*link);
                nlohmann::json billing = nullptr;
                try {
                    billing = d::cs::billing(*link);
                } catch (const d::cs::CallError&) {
                }
                if (ov.ejection_portal) {
                    if (!ov.ejection.is_object()) ov.ejection = nlohmann::json::object();
                    ov.ejection["portal_url"] = *ov.ejection_portal;
                }
                d::DB::saveFetched({.state = ov.entitlement.state, .plan = ov.entitlement.plan,
                                    .quota_bytes = ov.entitlement.storage_quota_bytes,
                                    .storage_access = ov.entitlement.storage_access, .cause = ov.entitlement.cause,
                                    .used_bytes = ov.stored_bytes, .usage_day = ov.usage_date,
                                    .account_key_confirmed = ov.offline_copy_confirmed, .provider = ov.provider,
                                    .ejection = ov.ejection, .billing = billing});
                std::scoped_lock cache(d::cacheMutex);
                d::cachedOverview = ov;
                d::cachedAt = d::now();
                out.fetched = true;
            } catch (const d::cs::CallError& e) {
                d::DB::saveFetchError(e.what());
                out.error = e.what();
                return out;   // an unreachable cloud changes nothing
            }
            account = d::DB::account();
        }
        {
            std::scoped_lock cache(d::cacheMutex);
            if (d::cachedOverview) {
                overview = d::cachedOverview;
                fetchedAt = d::cachedAt;
            }
        }
        if (!overview || !account) return out;
        if (d::storageAvailable(account) && !account->enabled_at && d::DB::markEnabled()) {
            d::audit("cloud.storage.entitlement", std::nullopt, {{"state", account->state.value_or("")}},
                     "managed storage became available on this link");
            account = d::DB::account();
        }
        d::sweep(*account);
        const d::Ctx ctx{.link = *link, .overview = *overview, .fetchedAt = fetchedAt, .account = *account, .pin = *pin};
        try {
            d::stepReplicas(ctx);
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[CloudStorage] replica step failed: {}", e.what());
        }
        for (auto& r : d::DB::list()) {
            const auto before = r.state;
            d::stepVault(r, ctx);
            if (r.state != before) ++out.steps;
        }
    } catch (const std::exception& e) {
        out.error = e.what();
        log::Registry::cloud()->warn("[CloudStorage] Pass failed: {}", e.what());
    }
    return out;
}

std::optional<JoinedBucket> joinBucketKey(const Actor& actor, const std::string& vaultUid) {
    namespace d = cloud_storage_ops_detail;
    if (!actor) throw Denied("no caller");
    const auto link = d::cs::linked();
    if (!link) throw Conflict("this server isn't linked to Vaulthalla Cloud (vh cloud link)");
    try {
        const auto ov = d::cs::overview(*link);
        const auto v = std::ranges::find_if(ov.vaults, [&](const auto& x) { return x.vault_uid == vaultUid; });
        if (v == ov.vaults.end() || !v->bucket) return std::nullopt;
        auto c = d::cs::requestCredential(*link, vaultUid);
        const auto& keys = runtime::Deps::get().apiKeyManager;
        if (!keys) throw Conflict("the API key manager is not available");
        std::string secret(reinterpret_cast<const char*>(c.secret.bytes().data()), c.secret.size());
        auto key = std::make_shared<vault::model::APIKey>(actor->id, "managed storage " + vaultUid,
                                                          d::providerOf(ov.provider), c.key_id, std::move(secret),
                                                          c.region.empty() ? std::string("auto") : c.region,
                                                          c.s3_endpoint);
        vl::keykit::wipe(secret);
        JoinedBucket out{.api_key_id = keys->addAPIKey(key), .key_id = c.key_id, .access = c.access,
                         .bucket = c.bucket, .bucket_id = c.bucket_id, .s3_endpoint = c.s3_endpoint, .region = c.region};
        d::DB::markKeyCloud(out.api_key_id, c.access);
        std::string error;
        if (!d::probeKey(out.api_key_id, out.bucket, error))
            throw Conflict("the bucket key Vaulthalla Cloud issued for this server didn't pass the probe: " + error);
        d::cs::acknowledge(*link, c.key_id);
        d::audit("cloud.storage.credential.issue", std::nullopt, {{"key_id", c.key_id}, {"access", c.access}, {"why", "join"}},
                 fmt::format("bucket key {} ({}) for joined vault {} received sealed, stored and acknowledged", c.key_id,
                             c.access, vaultUid));
        return out;
    } catch (const d::cs::CallError& e) {
        if (e.reason() == "account_key_unconfirmed")
            throw Refused(e.reason(), "confirm the account recovery key on this server first (vh cloud key confirm)");
        if (e.code() == "no_such_vault" || e.reason() == "no_such_vault" || e.status() == 404)
            throw Refused("no_such_vault", "Vaulthalla Cloud doesn't count this server as a replica yet (approve the "
                                           "join first)");
        if (!e.reason().empty()) throw Refused(e.reason(), std::string("Vaulthalla Cloud refused the bucket key: ") + e.what());
        throw Conflict(std::string("Vaulthalla Cloud's bucket key exchange failed: ") + e.what());
    }
}

void adoptJoinedVault(const unsigned int vaultId, const std::string& vaultUid, const JoinedBucket& key) {
    namespace d = cloud_storage_ops_detail;
    d::Row r;
    r.vault_id = vaultId;
    r.vault_uid = vaultUid;
    r.switch_state = "on";
    r.switch_by = "system:join";
    r.state = "active";
    r.retention_days = config::Registry::get().cloud.storage_default_retention_days;
    (void)d::DB::insert(r);
    auto row = d::DB::get(vaultId);
    if (!row) return;
    row->api_key_id = key.api_key_id;
    row->key_id = key.key_id;
    row->key_state = "active";
    row->key_access = key.access;
    row->bucket = key.bucket;
    row->bucket_id = key.bucket_id;
    row->s3_endpoint = key.s3_endpoint;
    row->region = key.region;
    row->state = "active";
    row->active_at = d::now();
    d::save(*row);
    if (const auto k = db::query::vault::APIKey::getAPIKey(key.api_key_id)) {
        const auto id = storage::upstream::identityFor(*k, key.bucket);
        d::DB::bindManagedBucket(vaultId, id.provider, id.account_ref.value_or("managed:" + key.bucket_id), key.bucket,
                                 key.region.empty() ? std::nullopt : std::optional<std::string>(key.region),
                                 key.api_key_id, d::retentionFor(*row));
    }
    d::audit("cloud.storage.attached", vaultId, {{"bucket_id", key.bucket_id}, {"join", true}},
             fmt::format("joined vault {} is in managed storage on this server's own key", vaultId));
}

void refreshSoon() {
    namespace d = cloud_storage_ops_detail;
    {
        std::scoped_lock cache(d::cacheMutex);
        d::cachedOverview.reset();
    }
    if (d::DB::account()) d::DB::setFastUntil(d::now() + d::kFastWindow);
    wake();
}

bool reportLeft(const std::string& vaultUid, std::string& error) {
    namespace d = cloud_storage_ops_detail;
    const auto link = d::cs::linked();
    if (!link) return true;
    try {
        (void)d::cs::leaveReplica(*link, vaultUid);
        return true;
    } catch (const d::cs::CallError& e) {
        error = e.what();
        return false;
    }
}

std::string reportWriterRemoved(const std::string& vaultUid, const std::string& node) {
    namespace d = cloud_storage_ops_detail;
    const auto link = d::cs::linked();
    if (!link) return {};
    // Who the cloud lists with that node id, from a fresh answer (the cache may predate a join).
    std::optional<d::cs::VaultStorage::Replica> listed;
    bool former = false;
    try {
        const auto ov = d::cs::overview(*link);
        for (const auto& v : ov.vaults) {
            if (v.vault_uid != vaultUid) continue;
            for (const auto& r : v.replicas)
                if (r.node_id && *r.node_id == node) listed = r;
            for (const auto& r : v.former_replicas)
                if (r.node_id && *r.node_id == node) former = true;
        }
    } catch (const std::exception& e) {
        return fmt::format("Vaulthalla Cloud couldn't be asked whether it still lists {} ({}); if it does, the account "
                           "holder removes that server from the vault in the portal", node, e.what());
    }
    if (!listed)
        return former ? "Vaulthalla Cloud no longer lists it either"
                      : "Vaulthalla Cloud doesn't list it as a server of this vault";
    const auto name = listed->name.empty() ? listed->deployment_id : listed->name;
    std::string told;
    try {
        if (!d::cs::reportUnlisted(*link, vaultUid, node)) return "Vaulthalla Cloud no longer lists it either";
        told = "it was told, and shows it";
    } catch (const d::cs::CallError& e) {
        told = std::string("telling it failed: ") + e.what();
    }
    return fmt::format("Vaulthalla Cloud still lists '{}' as a server of this vault, and its storage key works, until the "
                       "account holder removes it from the vault in the portal ({})",
                       name, told);
}

bool removedAtCloud(const std::string& vaultUid) {
    namespace d = cloud_storage_ops_detail;
    const auto link = d::cs::linked();
    if (!link) return false;
    const auto removedIn = [&](const d::cs::Overview& ov) {
        return std::ranges::any_of(ov.vaults, [&](const auto& v) { return v.vault_uid == vaultUid && v.removed_reason; });
    };
    try {
        return removedIn(d::cs::overview(*link));
    } catch (const std::exception&) {
        std::lock_guard lock(d::cacheMutex);
        return d::cachedOverview && removedIn(*d::cachedOverview);   // the last poll's word, when the cloud can't answer
    }
}

nlohmann::json describeReplicas(const std::string& vaultUid, const nlohmann::json& manifest) {
    namespace d = cloud_storage_ops_detail;
    nlohmann::json out = manifest;
    std::optional<d::cs::VaultStorage> v;
    {
        std::lock_guard lock(d::cacheMutex);
        if (d::cachedOverview)
            for (const auto& e : d::cachedOverview->vaults)
                if (e.vault_uid == vaultUid) v = e;
    }
    out["cloud_only"] = nlohmann::json::array();
    if (!out.contains("replicas") || !out["replicas"].is_array()) return out;
    std::vector<std::string> writers;
    for (auto& r : out["replicas"]) {
        const auto node = r.value("node_id", "");
        writers.push_back(node);
        if (!v) {
            r["cloud"] = nullptr;   // not linked, not polled yet, or not a vault of the account at the cloud
            continue;
        }
        const auto match = [&](const auto& list) {
            return std::ranges::find_if(list, [&](const auto& x) { return x.node_id && *x.node_id == node; });
        };
        if (const auto it = match(v->replicas); it != v->replicas.end())
            r["cloud"] = it->unlisted_by ? "unlisted" : "listed";
        else if (match(v->former_replicas) != v->former_replicas.end())
            r["cloud"] = "former";
        else
            r["cloud"] = "not_listed";
    }
    // The other way round: a server the cloud lists that the manifest doesn't name (joining, or removed here: the
    // account holder removes it in the portal).
    if (v)
        for (const auto& r : v->replicas)
            if (r.node_id && std::ranges::find(writers, *r.node_id) == writers.end())
                out["cloud_only"].push_back({{"deployment_id", r.deployment_id}, {"name", r.name}, {"node_id", *r.node_id},
                                             {"unlisted_by", r.unlisted_by ? nlohmann::json(*r.unlisted_by) : nlohmann::json(nullptr)}});
    return out;
}

void wake() { cloud_storage_ops_detail::woken = true; }

bool takeWake() noexcept { return cloud_storage_ops_detail::woken.exchange(false); }

bool takeWakePeek() noexcept { return cloud_storage_ops_detail::woken.load(); }

void requestKeyCheck() {
    cloud_storage_ops_detail::keyCheckAsked = true;
    wake();
}

void installHooks() {
    namespace d = cloud_storage_ops_detail;
    vault::remote::setManagedHooks({
        .accountKeyGrant =
            [](const uint32_t vaultId) {
                try {
                    (void)ops::recovery_recipients::addAccountKeyForManagedVault(vaultId);
                } catch (const Refused& e) {
                    throw vault::remote::Refusal(e.code, e.what());
                } catch (const Error& e) {
                    throw vault::remote::Refusal("account_key_unconfirmed", e.what());
                }
            },
        .quotaPreflight =
            [](const uint32_t, const vault::remote::Estimate& estimate) {
                const auto a = d::DB::account();
                if (!a || !a->quota_bytes) return;
                const auto used = a->used_bytes.value_or(0);
                if (used + estimate.upload_bytes > *a->quota_bytes)
                    throw vault::remote::Refusal(
                        "over_quota", fmt::format("the vault's {} byte(s) don't fit in the {} byte(s) left of the "
                                                  "account's quota", estimate.upload_bytes,
                                                  *a->quota_bytes > used ? *a->quota_bytes - used : 0));
            },
    });
}

RestoreKey keyForRestore(const Actor& actor, const std::string& vaultUid, const unsigned int ownerId, const Channel channel) {
    namespace d = cloud_storage_ops_detail;
    d::requireStorage(actor, channel);
    const auto link = d::cs::linked();
    if (!link) throw Refused("managed_storage_unavailable", "this server isn't linked to an account (`vh cloud link`)");
    if (!d::pinned())
        throw Refused("managed_storage_unavailable", "confirm the account recovery key first (`vh cloud key confirm`)");
    d::cs::Credential c;
    std::string provider;
    try {
        // The cloud's view now: the restore's approval moved the vault here, so it is in this deployment's scope.
        const auto ov = d::cs::overview(*link);
        provider = ov.provider;
        c = d::cs::requestCredential(*link, vaultUid);
    } catch (const d::cs::CallError& e) {
        if (e.unreachable()) throw Refused("cloud_unreachable", e.what());
        throw Refused("cloud_refused", std::string(e.what()) + (e.reason().empty() ? "" : " [" + e.reason() + "]"));
    }
    const auto& keys = runtime::Deps::get().apiKeyManager;
    if (!keys) throw std::runtime_error("the API key manager is not available");
    std::string secret(reinterpret_cast<const char*>(c.secret.bytes().data()), c.secret.size());
    auto key = std::make_shared<vault::model::APIKey>(ownerId, "managed storage " + vaultUid, d::providerOf(provider), c.key_id,
                                                      std::move(secret), c.region.empty() ? std::string("auto") : c.region,
                                                      c.s3_endpoint);
    vl::keykit::wipe(secret);
    RestoreKey out{.vault_uid = vaultUid, .api_key_id = keys->addAPIKey(key), .key_id = c.key_id, .access = c.access,
                   .bucket = c.bucket, .bucket_id = c.bucket_id, .s3_endpoint = c.s3_endpoint, .region = c.region};
    d::DB::markKeyCloud(out.api_key_id, c.access);
    d::audit("cloud.storage.credential.issue", std::nullopt, {{"key_id", c.key_id}, {"access", c.access}, {"why", "restore"}},
             fmt::format("bucket key {} ({}) received sealed for restoring vault {}", c.key_id, c.access, vaultUid));
    std::string error;
    if (!d::probeKey(out.api_key_id, out.bucket, error)) {
        discardRestoreKey(out);
        throw Refused("key_probe_failed", "the bucket key didn't pass the probe: " + error);
    }
    return out;
}

void adoptRestored(const RestoreKey& key, const unsigned int vaultId) {
    namespace d = cloud_storage_ops_detail;
    const auto link = d::cs::linked();
    if (!link) throw Refused("managed_storage_unavailable", "this server is no longer linked to an account");
    d::Row r;
    if (const auto existing = d::DB::get(vaultId)) r = *existing;   // the service may have seen the new vault first
    r.vault_id = vaultId;
    r.vault_uid = key.vault_uid;
    r.switch_state = "on";
    r.switch_by = "restore";
    r.switch_at = d::now();
    r.api_key_id = key.api_key_id;
    r.key_id = key.key_id;
    r.key_access = key.access;
    r.key_state = "issued";
    r.bucket = key.bucket;
    r.bucket_id = key.bucket_id;
    r.s3_endpoint = key.s3_endpoint;
    r.region = key.region;
    r.registered_at = r.registered_at.value_or(d::now());
    r.ready_at = r.ready_at.value_or(d::now());
    if (!d::DB::insert(r)) d::DB::update(r);
    try {
        d::cs::acknowledge(*link, key.key_id);
    } catch (const d::cs::CallError& e) {
        // The vault is restored either way; the service asks for a new key when this one isn't acknowledged.
        log::Registry::cloud()->warn("[CloudStorage] Vault {}: the restore's bucket key wasn't acknowledged yet: {}", vaultId,
                                     e.what());
        r.state = "keyed";
        d::save(r);
        return;
    }
    r.key_state = "active";
    if (const auto k = db::query::vault::APIKey::getAPIKey(key.api_key_id)) {
        const auto id = storage::upstream::identityFor(*k, key.bucket);
        d::DB::bindManagedBucket(vaultId, id.provider, id.account_ref.value_or("managed:" + key.bucket_id), key.bucket,
                                 r.region, key.api_key_id, d::retentionFor(r));
    }
    r.state = "active";
    r.reason.reset();
    r.active_at = d::now();
    d::clearRetry(r);
    d::save(r);
    if (const auto account = d::DB::account()) d::applyGate(r, *account);
    d::audit("cloud.storage.restored", vaultId, {{"bucket_id", key.bucket_id}, {"key_id", key.key_id}},
             fmt::format("vault {} restored from its managed bucket and kept in managed storage", vaultId));
    d::fast();
}

void discardRestoreKey(const RestoreKey& key) noexcept {
    try {
        if (key.api_key_id && db::query::vault::APIKey::listVaultsUsingKey(key.api_key_id).empty())
            runtime::Deps::get().apiKeyManager->removeAPIKey(key.api_key_id);
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn("[CloudStorage] The restore's bucket key {} wasn't removed: {}", key.api_key_id, e.what());
    }
}

std::vector<std::string> unlinkBlockers() {
    namespace d = cloud_storage_ops_detail;
    std::vector<std::string> out;
    for (const auto& r : d::DB::list()) {
        if (r.state == "unregistered" || r.state == "off" || r.state == "moved" || r.state == "ejected" ||
            r.state == "ended" || r.state == "failed")
            continue;
        const auto v = db::query::vault::Vault::getVault(r.vault_id);
        out.push_back(v ? v->name : std::to_string(r.vault_id));
    }
    return out;
}

void onUnlinked() noexcept {
    namespace d = cloud_storage_ops_detail;
    try {
        for (auto r : d::DB::list()) {
            if (r.state == "active" || r.state == "detaching") {
                try {
                    (void)storage::remote_access::set(r.vault_id, storage::remote_access::Mode::None,
                                                      std::string("this server was unlinked"), d::kSystem);
                } catch (const std::exception&) {
                }
            }
            if (r.state != "off" && r.state != "ejected" && r.state != "ended" && r.state != "unregistered") {
                r.state = r.state == "active" || r.state == "detaching" || r.state == "moved" ? "moved" : "off";
                r.reason = "unlinked";
                r.key_state = "none";
                d::save(r);
            }
        }
        d::DB::clearAccount();
        std::scoped_lock cache(d::cacheMutex);
        d::cachedOverview.reset();
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn("[CloudStorage] After the unlink: {}", e.what());
    }
}

std::vector<HealthIssue> health() {
    namespace d = cloud_storage_ops_detail;
    std::vector<HealthIssue> out;
    const auto link = db::query::cloud::Link::get();
    if (!link || link->status != "linked") return out;
    const auto account = d::DB::account();
    const auto rows = d::DB::list();
    const bool managed = d::DB::anyManaged();
    const auto key = d::accountKeyState(true);
    if (key == "unconfirmed" && ((account && account->enabled_at) || !rows.empty() || d::storageAvailable(account)))
        out.push_back({.code = "cloud_account_key_unconfirmed", .severity = "degraded", .vault_id = std::nullopt,
                       .detail = "managed storage waits until a super admin confirms the account recovery key "
                                 "(`vh cloud key confirm`)"});
    if (account && account->state == std::optional<std::string>("ended") && !d::endedConfirmed(*account) &&
        std::ranges::any_of(rows, [](const d::Row& r) { return r.state == "active"; }))
        out.push_back({.code = "cloud_storage_ended_pending", .severity = "degraded", .vault_id = std::nullopt,
                       .detail = "the account's service reports the plan ended: managed vaults stay attached without "
                                 "access until an admin confirms it (`vh cloud storage confirm-ended`) or "
                                 "cloud.storage.ended_grace_hours pass"});
    for (const auto& r : rows) {
        if (r.state == "active" && r.enroll_behind_since && d::now() - *r.enroll_behind_since >= d::kEnrollBehindHealth)
            out.push_back({.code = "cloud_recovery_behind", .severity = "degraded", .vault_id = r.vault_id,
                           .detail = "the vault's automatic recovery enrollment has been failing for a day"});
        if (r.state == "moved")
            out.push_back({.code = "vault_cloud_moved", .severity = "degraded", .vault_id = r.vault_id,
                           .detail = "restored onto another server: this copy no longer syncs; keep it as a local vault "
                                     "(`vh cloud storage disable`) or delete it"});
        if (r.state == "failed")
            out.push_back({.code = "vault_cloud_failed", .severity = "degraded", .vault_id = r.vault_id,
                           .detail = r.last_error.value_or(r.reason.value_or("managed storage failed"))});
    }
    if (managed) {
        // What the cloud records of an offline copy of the account key (the key check reads it); the server can't see
        // the copy itself. Nothing is blocked by it.
        if (!link->offline_copy_at && link->key_check == std::optional<std::string>("ok"))
            out.push_back({.code = "cloud_account_key_no_offline_copy", .severity = "info", .vault_id = std::nullopt,
                           .detail = "no offline copy of the account recovery key is recorded: export it from Vaulthalla "
                                     "Desktop"});
    }
    return out;
}

void setKeyProbeForTesting(std::optional<KeyProbe> probe) {
    namespace d = cloud_storage_ops_detail;
    std::scoped_lock lock(d::probeMutex);
    d::keyProbe = std::move(probe);
}

// ---- JSON ----------------------------------------------------------------------------------------------------------------

nlohmann::json toJson(const VaultEntry& v) {
    const auto opt = [](const auto& x) { return x ? nlohmann::json(*x) : nlohmann::json(nullptr); };
    return {{"vault_id", v.vault_id},
            {"vault_name", v.vault_name},
            {"vault_uid", v.vault_uid},
            {"storage", v.storage},
            {"switch", opt(v.switch_state)},
            {"state", v.state},
            {"reason", opt(v.reason)},
            {"summary", v.summary},
            {"local_bytes", v.local_bytes},
            {"access", opt(v.access)},
            {"key_state", v.key_state},
            {"key_access", opt(v.key_access)},
            {"retention_days", opt(v.retention_days)},
            {"retention_sent", opt(v.retention_sent)},
            {"retention_pending", v.retention_pending},
            {"recovery", opt(v.recovery)},
            {"progress", v.progress},
            {"lost", v.lost},
            {"last_error", opt(v.last_error)},
            {"active_at", opt(v.active_at)},
            {"moved_at", opt(v.moved_at)},
            {"ejected_at", opt(v.ejected_at)},
            {"ended_at", opt(v.ended_at)}};
}

nlohmann::json toJson(const Status& s) {
    const auto opt = [](const auto& x) { return x ? nlohmann::json(*x) : nlohmann::json(nullptr); };
    auto vaults = nlohmann::json::array();
    for (const auto& v : s.vaults) vaults.push_back(toJson(v));
    auto offered = nlohmann::json::array();
    for (const auto& v : s.offered) offered.push_back(toJson(v));
    return {{"linked", s.linked},
            {"account_key", s.account_key},
            {"available", s.available},
            {"entitlement", opt(s.entitlement)},
            {"plan", opt(s.plan)},
            {"quota_bytes", opt(s.quota_bytes)},
            {"used_bytes", opt(s.used_bytes)},
            {"usage_day", opt(s.usage_day)},
            {"storage_access", opt(s.storage_access)},
            {"cause", opt(s.cause)},
            {"managed_local_bytes", s.managed_local_bytes},
            {"new_vaults", s.new_vaults},
            {"offer_open", s.offer_open},
            {"offered", offered},
            {"vaults", vaults},
            {"billing", s.billing},
            {"ejection", s.ejection},
            {"fetched_at", opt(s.fetched_at)},
            {"fetch_error", opt(s.fetch_error)},
            {"ended", s.ended ? nlohmann::json{{"since", s.ended->since}, {"converts_at", s.ended->converts_at},
                                               {"confirmed_by", opt(s.ended->confirmed_by)}}
                              : nlohmann::json(nullptr)},
            {"next_step", opt(s.next_step)}};
}

nlohmann::json toJson(const EndedConfirmation& e) {
    return {{"confirmed", e.confirmed}, {"since", e.since ? nlohmann::json(*e.since) : nlohmann::json(nullptr)},
            {"vaults", e.vaults}};
}

nlohmann::json toJson(const OfferResult& r) { return {{"vaults", r.vaults}, {"offer_open", r.offer_open}}; }

nlohmann::json toJson(const Handoff& h) {
    return {{"kind", h.kind}, {"url", h.url},
            {"expires_at", h.expires_at ? nlohmann::json(*h.expires_at) : nlohmann::json(nullptr)}};
}

}
