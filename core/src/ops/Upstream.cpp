#include "ops/Upstream.hpp"
#include "sync/events/Subscriptions.hpp"
#include "ops/UpstreamJson.hpp"

#include "db/query/upstream/Audit.hpp"
#include "db/query/upstream/Binding.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "db/query/upstream/Subscription.hpp"
#include "db/query/vault/APIKey.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/permission/admin/Upstream.hpp"
#include "rbac/permission/admin/keys/API.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Cleanup.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Inventory.hpp"
#include "storage/upstream/Lifecycle.hpp"
#include "storage/upstream/Provisioner.hpp"
#include "storage/upstream/model/Subscription.hpp"
#include "sync/model/RemoteManifest.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <map>
#include <set>

namespace vh::ops::upstream {

namespace {

using UpPerm = rbac::permission::admin::UpstreamPermissions;
using KeyPerm = rbac::permission::admin::keys::APIPermissions;
using BucketQuery = db::query::upstream::Bucket;
using BucketModel = storage::upstream::model::Bucket;
using storage::upstream::BucketIdentity;
using storage::upstream::BucketProtected;
namespace bmodel = storage::upstream::model;
namespace lifecycle = storage::upstream::lifecycle;
namespace provision = storage::upstream::provision;
namespace cleanupx = storage::upstream::cleanup;

const char* permName(const UpPerm p) {
    switch (p) {
    case UpPerm::View: return "admin.upstream.view";
    case UpPerm::Configure: return "admin.upstream.configure";
    case UpPerm::Provision: return "admin.upstream.provision";
    case UpPerm::Protect: return "admin.upstream.protect";
    case UpPerm::Unprotect: return "admin.upstream.unprotect";
    case UpPerm::Destroy: return "admin.upstream.destroy";
    default: return "admin.upstream";
    }
}

const char* keyPermName(const KeyPerm p) {
    switch (p) {
    case KeyPerm::View: return "view";
    case KeyPerm::Edit: return "edit";
    case KeyPerm::Consume: return "consume";
    default: return "use";
    }
}

void requireUpstream(const Actor& actor, const UpPerm p) {
    if (!rbac::resolver::Admin::has<UpPerm>({.user = actor, .permission = p}))
        throw Denied(std::string("this needs the ") + permName(p) + " permission");
}

api_keys::APIKeyPtr findKey(const KeyRef& ref) {
    api_keys::APIKeyPtr key;
    if (const auto* id = std::get_if<unsigned int>(&ref)) {
        if (*id == 0) throw Invalid("API key ID must be a positive integer");
        key = db::query::vault::APIKey::getAPIKey(*id);
        if (!key) throw NotFound("API key not found: " + std::to_string(*id));
    } else {
        key = db::query::vault::APIKey::getAPIKey(std::get<std::string>(ref));
        if (!key) throw NotFound("API key not found: " + std::get<std::string>(ref));
    }
    return key;
}

// The key (metadata) after both checks: the upstream permission and the key's own keys.api permission.
api_keys::APIKeyPtr authorize(const Actor& actor, const KeyRef& ref, const UpPerm up, const KeyPerm keyPerm) {
    requireActor(actor);
    requireUpstream(actor, up);
    auto key = findKey(ref);
    if (!rbac::resolver::Admin::has<KeyPerm>({.user = actor, .permission = keyPerm, .api_key_id = key->id}))
        throw Denied("you do not have permission to " + std::string(keyPermName(keyPerm)) + " API key '" + key->name + "'");
    return key;
}

api_keys::APIKeyPtr withSecrets(const api_keys::APIKeyPtr& key) {
    const auto& manager = runtime::Deps::get().apiKeyManager;
    if (!manager) throw std::runtime_error("the API key manager is not available");
    return manager->getAPIKey(key->id);
}

std::string unsupportedReason(const vault::model::APIKey& key) {
    if (!padmin::supportsAdmin(key)) return "provider administration supports AWS S3 and Cloudflare R2 keys only";
    if (!key.admin_enabled)
        return "API key '" + key.name + "' is not enabled for provider administration (vh upstream admin enable " +
               key.name + ")";
    return {};
}

std::unique_ptr<padmin::AdminClient> adminClient(const api_keys::APIKeyPtr& key) {
    if (const auto why = unsupportedReason(*key); !why.empty()) throw Invalid(why);
    auto client = padmin::adminFor(withSecrets(key));
    if (!client) throw Invalid("provider administration is not available for this API key");
    return client;
}

BucketIdentity identityOf(const api_keys::APIKeyPtr& key, const std::string& bucket) {
    if (bucket.empty()) throw Invalid("bucket name is required");
    try {
        return storage::upstream::resolvedIdentity(withSecrets(key), bucket);
    } catch (const Error&) {
        throw;
    } catch (const std::exception& e) {
        throw Invalid(std::string("can't resolve the provider account of this API key: ") + e.what());
    }
}

void auditRecord(const Actor& actor, const std::string& action, const BucketIdentity& id, const std::optional<uint32_t> keyId,
                 const std::optional<uint32_t> vaultId, const bmodel::AuditOutcome outcome, nlohmann::json detail = {}) {
    bmodel::AuditRecord r;
    if (actor) {
        r.user_id = actor->id;
        r.user_name = actor->name();
    }
    r.action = action;
    r.provider = id.provider;
    r.account_ref = id.account_ref.value_or("");
    r.bucket = id.bucket;
    r.api_key_id = keyId;
    r.vault_id = vaultId;
    r.outcome = outcome;
    r.detail_json = detail.is_object() ? detail.dump() : std::string("{}");
    db::query::upstream::Audit::appendNoThrow(r);
}

// Protected → Denied (with the lock's reason), audited as a refusal.
void requireUnprotected(const Actor& actor, const BucketIdentity& id, const std::string& action,
                        const std::optional<uint32_t> keyId) {
    if (!storage::upstream::guard::isProtected(id)) return;
    std::string reason;
    if (id.account_ref)
        if (const auto row = BucketQuery::getByIdentity(id.provider, *id.account_ref, id.bucket);
            row && row->protection_reason && !row->protection_reason->empty())
            reason = " (" + *row->protection_reason + ")";
    auditRecord(actor, action, id, keyId, std::nullopt, bmodel::AuditOutcome::Refused, {{"reason", "bucket protected"}});
    throw Denied("bucket '" + id.bucket + "' is protected" + reason + ": Vaulthalla will not touch it until it is unprotected");
}

// Adapter and primitive failures as ops refusals; anything else stays a fault.
template <typename Fn>
auto mapped(Fn&& fn) -> decltype(fn()) {
    try {
        return fn();
    } catch (const Error&) {
        throw;
    } catch (const BucketProtected& e) {
        throw Denied(e.what());
    } catch (const provision::ProvisionConflict& e) {
        throw Conflict(e.what());
    } catch (const provision::BucketMissing& e) {
        throw NotFound(e.what());
    } catch (const padmin::CapabilityMissing& e) {
        throw Invalid(e.what());
    } catch (const padmin::ProviderError& e) {
        if (e.accessDenied()) throw Denied(std::string("the provider refused: ") + e.what());
        if (e.notFound()) throw NotFound(e.what());
        throw;
    } catch (const std::invalid_argument& e) {
        throw Invalid(e.what());
    }
}

std::string eventsStateFor(const std::optional<uint32_t> vaultId) {
    if (!vaultId) return {};
    if (const auto sub = db::query::upstream::Subscription::getLiveForVault(*vaultId)) return bmodel::to_string(sub->state);
    return {};
}

BucketState stateOf(const std::optional<BucketModel>& row) {
    if (!row) return BucketState::Unmanaged;
    if (row->is_protected) return BucketState::Protected;
    if (row->ownership == bmodel::Ownership::Managed) return BucketState::Managed;
    if (row->ownership == bmodel::Ownership::Adopted) return BucketState::Adopted;
    return BucketState::Unmanaged;
}

BucketRow makeRow(const std::string& name, const std::optional<BucketModel>& row,
                  const std::vector<db::query::upstream::VaultBinding>& bindings, const std::optional<std::string>& region,
                  const bool listed) {
    BucketRow out;
    out.name = name;
    out.region = region;
    out.listed = listed;
    out.state = stateOf(row);
    out.ownership = row ? bmodel::to_string(row->ownership) : "unmanaged";
    out.provisioning_state = row ? bmodel::to_string(row->provisioning_state) : "none";
    if (row) {
        if (!out.region) out.region = row->region;
        out.is_protected = row->is_protected;
        out.protection_reason = row->protection_reason;
        out.protected_by = row->protected_by_name;
        out.protected_at = row->protected_at;
        out.vault_id = row->vault_id;
        out.last_seen_at = row->last_seen_at;
    }
    if (!out.vault_id) {
        for (const auto& b : bindings)
            if (!b.deleted) {
                out.vault_id = b.vault_id;
                out.vault_name = b.vault_name;
                break;
            }
        if (!out.vault_id && !bindings.empty()) {
            out.vault_id = bindings.front().vault_id;
            out.vault_name = bindings.front().vault_name;
        }
    } else {
        for (const auto& b : bindings)
            if (b.vault_id == *out.vault_id) out.vault_name = b.vault_name;
    }
    if (const auto ev = eventsStateFor(out.vault_id); !ev.empty()) out.events_state = ev;
    return out;
}

BucketRow rowFor(const BucketIdentity& id, const std::optional<std::string>& region = std::nullopt) {
    const auto row = id.account_ref ? BucketQuery::getByIdentity(id.provider, *id.account_ref, id.bucket) : std::nullopt;
    return makeRow(id.bucket, row, storage::upstream::bindingsFor(id), region, true);
}

std::vector<std::string> lifecycleFields(const vault::model::APIKey& key) {
    std::vector<std::string> out{"abort_incomplete_multipart_days", "expire_current_days"};
    if (key.provider == vault::model::S3Provider::AWS) out.emplace_back("expire_noncurrent_days");
    out.emplace_back("prefix");
    return out;
}

lifecycle::OwnedRuleChange toChange(const LifecyclePatch& p) {
    return {.abort_incomplete_multipart_days = p.abort_incomplete_multipart_days,
            .expire_current_days = p.expire_current_days,
            .expire_noncurrent_days = p.expire_noncurrent_days,
            .prefix = p.prefix,
            .clear = p.clear};
}

std::string destructiveText(const std::string& bucket, const std::optional<bmodel::Ownership>& ownership) {
    (void)ownership;
    return "This lifecycle rule makes the provider delete objects in bucket '" + bucket +
           "' automatically once they reach the configured age, including vault data that exists nowhere else. "
           "Accept to apply it.";
}

// Applies our lifecycle rule (GET-merge-PUT); returns whether anything was written.
bool applyLifecycle(padmin::AdminClient& admin, const vault::model::APIKey& key, const std::string& bucket,
                    const LifecyclePatch& patch) {
    const auto config = admin.inspect(bucket);
    if (!config.lifecycle_readable)
        throw Invalid("the lifecycle configuration of bucket '" + bucket + "' can't be read with this credential");
    const auto merged = lifecycle::mergeOwnedRule(config.lifecycle, toChange(patch),
                                                  key.provider == vault::model::S3Provider::AWS);
    if (merged.destructive && !patch.accept_destructive)
        throw NeedsConfirmation(DESTRUCTIVE_LIFECYCLE, destructiveText(bucket, std::nullopt));
    if (!merged.changed) return false;
    admin.putLifecycle(bucket, merged.rules);
    return true;
}

nlohmann::json patchJson(const LifecyclePatch& p) {
    nlohmann::json j = nlohmann::json::object();
    if (p.abort_incomplete_multipart_days) j["abort_incomplete_multipart_days"] = *p.abort_incomplete_multipart_days;
    if (p.expire_current_days) j["expire_current_days"] = *p.expire_current_days;
    if (p.expire_noncurrent_days) j["expire_noncurrent_days"] = *p.expire_noncurrent_days;
    if (p.prefix) j["prefix"] = *p.prefix;
    if (p.clear) j["clear"] = true;
    return j;
}

std::optional<std::string> headerValue(const std::unordered_map<std::string, std::string>& headers, std::string name) {
    std::ranges::transform(name, name.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    for (const auto& [k, v] : headers) {
        auto lower = k;
        std::ranges::transform(lower, lower.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == name) return v;
    }
    return std::nullopt;
}

std::string defaultRegion(const vault::model::APIKey& key) {
    auto region = key.region;
    if (key.provider == vault::model::S3Provider::AWS && (region.empty() || region == "auto")) return "us-east-1";
    if (key.provider == vault::model::S3Provider::CloudflareR2 && (region.empty() || region == "auto")) return {};
    return region;
}

std::optional<padmin::Capabilities> storedCapabilities(const vault::model::APIKey& key) {
    if (!key.admin_capabilities_json) return std::nullopt;
    try {
        return nlohmann::json::parse(*key.admin_capabilities_json).get<padmin::Capabilities>();
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

AdminStatus statusOf(const api_keys::APIKeyPtr& key, std::optional<padmin::Capabilities> caps = std::nullopt) {
    AdminStatus s;
    s.key = key;
    s.supported = padmin::supportsAdmin(*key);
    s.enabled = key->admin_enabled;
    s.has_provider_token = key->hasProviderToken();
    s.account_ref = padmin::staticAccountRef(*key);
    s.capabilities = caps ? std::move(caps) : storedCapabilities(*key);
    if (!s.supported) s.unsupported_reason = unsupportedReason(*key);
    return s;
}

bool authFailure(const padmin::ProviderError& e) {
    return e.code == "InvalidAccessKeyId" || e.code == "SignatureDoesNotMatch" || e.code == "InvalidClientTokenId" ||
           e.code == "AuthFailure" || e.http_status == 401;
}

std::string reportSummary(const AdmissionReport& r) {
    std::string out = "Adopt bucket '" + r.bucket.name + "' into a new vault? Nothing in it is deleted, overwritten or "
                      "converted. Scanned " + std::to_string(r.objects_scanned) + (r.truncated ? "+" : "") +
                      " objects (" + std::to_string(r.bytes_scanned) + " bytes)";
    if (r.sampled)
        out += "; of " + std::to_string(r.sampled) + " sampled, " + std::to_string(r.sampled_vaulthalla_encrypted) +
               " are Vaulthalla-encrypted and " + std::to_string(r.sampled_plaintext) +
               " are plain objects, which the vault will show as files as they are";
    out += ".";
    for (const auto& w : r.warnings) out += " " + w;
    return out;
}

}

// ---- strings -------------------------------------------------------------------------------------------------------

std::string to_string(const BucketState s) {
    switch (s) {
    case BucketState::Managed: return "managed";
    case BucketState::Adopted: return "adopted";
    case BucketState::Protected: return "protected";
    case BucketState::Unmanaged: break;
    }
    return "unmanaged";
}

BucketState bucketStateFromString(const std::string& s) {
    if (s == "managed") return BucketState::Managed;
    if (s == "adopted") return BucketState::Adopted;
    if (s == "unmanaged") return BucketState::Unmanaged;
    if (s == "protected") return BucketState::Protected;
    throw Invalid("bucket state must be managed, adopted, unmanaged or protected");
}

BucketMode bucketModeFromString(const std::string& s) {
    if (s.empty() || s == "existing") return BucketMode::Existing;
    if (s == "create") return BucketMode::Create;
    if (s == "adopt") return BucketMode::Adopt;
    throw Invalid("bucket mode must be existing, create or adopt");
}

// ---- administrative credentials ------------------------------------------------------------------------------------

AdminStatus enableAdmin(const Actor& actor, const KeyRef& ref, const AdminEnable& req) {
    auto key = authorize(actor, ref, UpPerm::Configure, KeyPerm::Edit);
    if (!padmin::supportsAdmin(*key)) throw Invalid(unsupportedReason(*key));
    const auto& manager = runtime::Deps::get().apiKeyManager;

    const bool newToken = req.provider_token && !req.provider_token->empty();
    if (newToken && key->provider != vault::model::S3Provider::CloudflareR2)
        throw Invalid("a provider token is only used by Cloudflare R2 keys (Queues and event notifications)");
    if (newToken && req.clear_provider_token) throw Invalid("give a provider token or clear it, not both");

    if (newToken) manager->setProviderToken(key->id, *req.provider_token);
    else if (req.clear_provider_token) manager->setProviderToken(key->id, std::nullopt);

    const auto full = manager->getAPIKey(key->id);
    padmin::Capabilities caps;
    std::string account;
    try {
        auto client = padmin::adminFor(full);
        if (!client) throw Invalid("provider administration is not available for this API key");
        const auto identity = client->identity();
        account = identity.account_ref;
        caps = client->probe();
        if (caps.identity.account_ref.empty()) caps.identity = identity;
        if (!caps.checked_at) caps.checked_at = std::time(nullptr);
    } catch (const padmin::ProviderError& e) {
        if (authFailure(e)) throw Invalid(std::string("the provider rejected this credential: ") + e.what());
        throw;
    }
    if (account.empty()) account = caps.identity.account_ref;
    if (account.empty()) throw Invalid("the provider did not report an account for this credential");

    manager->setAdmin(key->id, true, account, nlohmann::json(caps).dump(), caps.checked_at);
    auditRecord(actor, "admin.enable", {.provider = padmin::providerIdentity(key->provider), .account_ref = account, .bucket = ""},
                key->id, std::nullopt, bmodel::AuditOutcome::Ok,
                {{"provider_token", newToken ? "stored" : (req.clear_provider_token ? "cleared" : "unchanged")}});
    return statusOf(findKey(key->id), caps);
}

AdminStatus disableAdmin(const Actor& actor, const KeyRef& ref) {
    auto key = authorize(actor, ref, UpPerm::Configure, KeyPerm::Edit);
    if (const auto n = db::query::upstream::Subscription::countActiveUsingKey(key->id); n > 0)
        throw Conflict("API key '" + key->name + "' operates " + std::to_string(n) +
                       " event subscription(s); turn event-driven sync off for those vaults first");
    runtime::Deps::get().apiKeyManager->setAdmin(key->id, false, std::nullopt, std::nullopt, std::nullopt);
    auditRecord(actor, "admin.disable",
                {.provider = padmin::providerIdentity(key->provider), .account_ref = padmin::staticAccountRef(*key), .bucket = ""},
                key->id, std::nullopt, bmodel::AuditOutcome::Ok);
    return statusOf(findKey(key->id));
}

AdminStatus adminStatus(const Actor& actor, const KeyRef& ref, const bool probe) {
    if (!probe) return statusOf(authorize(actor, ref, UpPerm::View, KeyPerm::View));
    auto key = authorize(actor, ref, UpPerm::Configure, KeyPerm::Edit);
    auto client = adminClient(key);
    const auto caps = mapped([&] {
        auto c = client->probe();
        if (!c.checked_at) c.checked_at = std::time(nullptr);
        return c;
    });
    runtime::Deps::get().apiKeyManager->setAdmin(key->id, true,
                                                 caps.identity.account_ref.empty() ? std::nullopt
                                                                                   : std::make_optional(caps.identity.account_ref),
                                                 nlohmann::json(caps).dump(), caps.checked_at);
    return statusOf(findKey(key->id), caps);
}

// ---- inventory and locks -------------------------------------------------------------------------------------------

Inventory inventory(const Actor& actor, const KeyRef& ref, const InventoryQuery& query) {
    auto key = authorize(actor, ref, UpPerm::View, KeyPerm::View);
    auto client = adminClient(key);
    const auto provider = padmin::providerIdentity(key->provider);
    const auto account = mapped([&] { return storage::upstream::resolveAccount(withSecrets(key)); });
    const auto page = mapped([&] { return client->listBuckets(query.token, std::clamp(query.max, 1u, 1000u)); });

    std::vector<db::query::upstream::SeenBucket> seen;
    seen.reserve(page.buckets.size());
    for (const auto& b : page.buckets) seen.push_back({.bucket = b.name, .region = b.region});
    BucketQuery::recordSeen(provider, account, key->id, seen);

    std::map<std::string, BucketModel> known;
    for (auto& row : BucketQuery::listForAccount(provider, account)) known.emplace(row.bucket, row);

    const auto keep = [&](const BucketRow& row) {
        if (query.state && row.state != *query.state) return false;
        if (query.filter && !query.filter->empty() && row.name.find(*query.filter) == std::string::npos) return false;
        return true;
    };

    Inventory out;
    out.key = key;
    out.provider = provider;
    out.account_ref = account;
    out.next_token = page.next_token;
    std::set<std::string> listed;
    for (const auto& b : page.buckets) {
        listed.insert(b.name);
        const BucketIdentity id{.provider = provider, .account_ref = account, .bucket = b.name};
        const auto it = known.find(b.name);
        auto row = makeRow(b.name, it == known.end() ? std::nullopt : std::make_optional(it->second),
                           storage::upstream::bindingsFor(id), b.region, true);
        if (keep(row)) out.buckets.push_back(std::move(row));
    }
    // What Vaulthalla knows but the provider didn't list (deleted, or beyond this credential), on the last page.
    if (page.next_token.empty())
        for (const auto& [name, row] : known) {
            if (listed.contains(name)) continue;
            const BucketIdentity id{.provider = provider, .account_ref = account, .bucket = name};
            auto r = makeRow(name, row, storage::upstream::bindingsFor(id), std::nullopt, false);
            if (keep(r)) out.buckets.push_back(std::move(r));
        }
    return out;
}

BucketRow protect(const Actor& actor, const KeyRef& ref, const std::string& bucket, const std::string& reason) {
    auto key = authorize(actor, ref, UpPerm::Protect, KeyPerm::View);
    if (reason.empty()) throw Invalid("give a reason for the protection (it is shown to everyone who sees the bucket)");
    const auto id = identityOf(key, bucket);
    (void)BucketQuery::protect(id, std::nullopt, actor->id, actor->name(), reason);
    storage::upstream::guard::reload();
    sync::events::subscriptions::onBucketProtected(id);
    sync::events::subscriptions::invalidateCache();
    auditRecord(actor, "protect", id, key->id, std::nullopt, bmodel::AuditOutcome::Ok, {{"reason", reason}});
    log::Registry::audit()->info("[ops::upstream] {} protected bucket '{}' ({})", actor->name(), bucket, id.toString());
    return rowFor(id);
}

BucketRow unprotect(const Actor& actor, const KeyRef& ref, const std::string& bucket, const bool confirm) {
    auto key = authorize(actor, ref, UpPerm::Unprotect, KeyPerm::View);
    const auto id = identityOf(key, bucket);
    const auto current = BucketQuery::getByIdentity(id.provider, *id.account_ref, id.bucket);
    if (!current || !current->is_protected) return rowFor(id);
    if (!confirm)
        throw NeedsConfirmation(UNPROTECT_CONFIRM,
            "Unprotect bucket '" + bucket + "'? Vaulthalla may then inventory, configure, sync, adopt and (when explicitly "
            "asked) delete it again. It was protected" +
            (current->protected_by_name ? " by " + *current->protected_by_name : std::string{}) +
            (current->protection_reason ? ": " + *current->protection_reason : std::string{}) + ".");
    (void)BucketQuery::unprotect(id);
    storage::upstream::guard::reload();
    sync::events::subscriptions::onBucketUnprotected(id);
    sync::events::subscriptions::invalidateCache();
    auditRecord(actor, "unprotect", id, key->id, std::nullopt, bmodel::AuditOutcome::Ok,
                {{"previous_reason", current->protection_reason.value_or("")}});
    log::Registry::audit()->warn("[ops::upstream] {} unprotected bucket '{}' ({})", actor->name(), bucket, id.toString());
    return rowFor(id);
}

// ---- configuration -------------------------------------------------------------------------------------------------

Inspection inspect(const Actor& actor, const KeyRef& ref, const std::string& bucket) {
    auto key = authorize(actor, ref, UpPerm::View, KeyPerm::View);
    const auto id = identityOf(key, bucket);
    requireUnprotected(actor, id, "inspect", key->id);
    auto client = adminClient(key);
    Inspection out;
    out.config = mapped([&] { return client->inspect(bucket); });
    out.bucket = rowFor(id, out.config.region);
    out.supported_lifecycle_fields = lifecycleFields(*key);
    return out;
}

Inspection setLifecycle(const Actor& actor, const KeyRef& ref, const std::string& bucket, const LifecyclePatch& patch) {
    auto key = authorize(actor, ref, UpPerm::Configure, KeyPerm::Consume);
    const auto id = identityOf(key, bucket);
    requireUnprotected(actor, id, "lifecycle", key->id);
    const auto row = BucketQuery::getByIdentity(id.provider, *id.account_ref, id.bucket);
    if (!row || row->ownership == bmodel::Ownership::Unmanaged)
        throw Invalid("Vaulthalla manages lifecycle rules only on buckets it created or adopted; bucket '" + bucket +
                      "' is unmanaged");
    auto client = adminClient(key);
    const bool written = mapped([&] { return applyLifecycle(*client, *key, bucket, patch); });
    auditRecord(actor, "lifecycle.set", id, key->id, row->vault_id, bmodel::AuditOutcome::Ok,
                {{"patch", patchJson(patch)}, {"written", written}});
    Inspection out;
    out.config = mapped([&] { return client->inspect(bucket); });
    out.bucket = rowFor(id, out.config.region);
    out.supported_lifecycle_fields = lifecycleFields(*key);
    return out;
}

// ---- adoption and provisioning -------------------------------------------------------------------------------------

AdmissionReport adoptPreflight(const Actor& actor, const KeyRef& ref, const std::string& bucket,
                               const unsigned int maxObjects, const unsigned int sampleHeads) {
    auto key = authorize(actor, ref, UpPerm::Provision, KeyPerm::Consume);
    const auto id = identityOf(key, bucket);
    requireUnprotected(actor, id, "adopt.preflight", key->id);
    auto client = adminClient(key);
    const auto full = withSecrets(key);

    AdmissionReport r;
    const auto region = mapped([&] { return client->headBucket(bucket); });
    if (!region) throw NotFound("bucket '" + bucket + "' does not exist");
    r.bucket = rowFor(id, region);

    const auto limit = std::clamp(maxObjects, 1u, 100'000u);
    std::vector<std::string> sampleCandidates;
    std::string token;
    mapped([&] {
        do {
            const auto page = client->listObjects(bucket, token, 1000);
            for (const auto& o : page.objects) {
                if (r.objects_scanned >= limit) {
                    r.truncated = true;
                    return 0;
                }
                ++r.objects_scanned;
                r.bytes_scanned += o.size;
                if (sync::model::remote_manifest::isVaulthallaManifestKey(o.key)) {
                    r.has_vaulthalla_manifest = true;
                    continue;
                }
                if (r.sample_keys.size() < 10) r.sample_keys.push_back(o.key);
                if (sampleCandidates.size() < sampleHeads) sampleCandidates.push_back(o.key);
            }
            token = page.next_token;
        } while (!token.empty());
        return 0;
    });

    for (const auto& objectKey : sampleCandidates) {
        const auto head = mapped([&] { return provision::headObject(full, bucket, objectKey); });
        if (!head) continue;
        ++r.sampled;
        const auto flag = headerValue(*head, "x-amz-meta-vh-encrypted");
        if (flag && (*flag == "true" || *flag == "1")) ++r.sampled_vaulthalla_encrypted;
        else ++r.sampled_plaintext;
    }

    if (const auto config = mapped([&] { return client->inspect(bucket); }); true) {
        r.versioning = config.versioning;
        r.object_lock = config.object_lock;
        for (const auto& w : config.warnings) r.warnings.push_back(w);
    }

    for (const auto& b : storage::upstream::bindingsFor(id))
        r.blockers.push_back("already used by vault '" + b.vault_name + "' (ID " + std::to_string(b.vault_id) + ")" +
                             (b.deleted ? ", pending deletion" : ""));
    if (const auto row = BucketQuery::getByIdentity(id.provider, *id.account_ref, id.bucket);
        row && (row->provisioning_state == bmodel::ProvisioningState::Creating ||
                row->provisioning_state == bmodel::ProvisioningState::Configuring) && !row->vault_id)
        r.warnings.push_back("another provisioning attempt may be working on this bucket");
    if (r.has_vaulthalla_manifest)
        r.warnings.push_back("The bucket holds another Vaulthalla vault's index: objects that vault encrypted can only be "
                             "read with that vault's key.");
    if (r.truncated) r.warnings.push_back("Only the first " + std::to_string(limit) + " objects were scanned.");
    if (r.sampled_plaintext > 0 && r.sampled_vaulthalla_encrypted == 0) {
        r.recommended_encrypt_upstream = false;
        r.warnings.push_back("The bucket holds plain objects: keep upstream encryption off if other applications read them; "
                             "turn it on and new uploads are encrypted while existing objects stay as they are.");
    } else {
        r.recommended_encrypt_upstream = true;
    }
    return r;
}

ProvisionTicket beginProvision(const Actor& actor, const unsigned int apiKeyId, const std::string& vaultName,
                               const std::string& requestedBucket, const Provision& req) {
    ProvisionTicket ticket;
    ticket.mode = req.mode;
    ticket.bucket = requestedBucket;
    ticket.api_key_id = apiKeyId;
    if (req.mode == BucketMode::Existing) return ticket;

    auto key = authorize(actor, KeyRef{apiKeyId}, UpPerm::Provision, KeyPerm::Consume);
    auto client = adminClient(key);
    const bool aws = key->provider == vault::model::S3Provider::AWS;

    // Refuse what would fail later before anything exists upstream.
    if (req.lifecycle) {
        if (req.lifecycle->expire_noncurrent_days && *req.lifecycle->expire_noncurrent_days > 0 && !aws)
            throw Invalid("this provider has no object versions: noncurrent-version expiration is not supported");
        const auto preview = mapped([&] { return lifecycle::mergeOwnedRule({}, toChange(*req.lifecycle), aws); });
        if (preview.destructive && !req.lifecycle->accept_destructive)
            throw NeedsConfirmation(DESTRUCTIVE_LIFECYCLE, destructiveText(requestedBucket.empty() ? "(new)" : requestedBucket,
                                                                           std::nullopt));
    }

    if (req.mode == BucketMode::Create) {
        auto bucket = requestedBucket;
        if (bucket.empty() || req.generate_name)
            bucket = mapped([&] { return provision::generateBucketName(vaultName, *client); });
        const auto id = identityOf(key, bucket);
        requireUnprotected(actor, id, "bucket.create", key->id);
        const auto region = req.region && !req.region->empty() ? req.region : std::optional<std::string>(defaultRegion(*key));
        try {
            const auto lease = mapped([&] {
                return provision::createManaged(*client, id, region && !region->empty() ? region : std::nullopt, key->id);
            });
            ticket.bucket = bucket;
            ticket.upstream_bucket_id = lease.row.id;
            ticket.operation_token = lease.token;
            ticket.created = lease.created;
            auditRecord(actor, "bucket.create", id, key->id, std::nullopt, bmodel::AuditOutcome::Ok,
                        {{"region", region.value_or("")}, {"vault", vaultName}});
            return ticket;
        } catch (const Conflict& e) {
            auditRecord(actor, "bucket.create", id, key->id, std::nullopt, bmodel::AuditOutcome::Refused, {{"reason", e.what()}});
            throw;
        } catch (const std::exception& e) {
            auditRecord(actor, "bucket.create", id, key->id, std::nullopt, bmodel::AuditOutcome::Failed, {{"error", e.what()}});
            throw;
        }
    }

    // Adopt.
    if (requestedBucket.empty()) throw Invalid("name the bucket to adopt");
    const auto id = identityOf(key, requestedBucket);
    requireUnprotected(actor, id, "bucket.adopt", key->id);
    if (!req.accept_adoption) {
        const auto report = adoptPreflight(actor, KeyRef{apiKeyId}, requestedBucket);
        if (!report.blockers.empty()) throw Conflict("bucket '" + requestedBucket + "' can't be adopted: " + report.blockers.front());
        throw NeedsConfirmation(ADOPTION_CONFIRM, reportSummary(report));
    }
    const auto lease = mapped([&] { return provision::beginAdopt(*client, id, key->id); });
    ticket.upstream_bucket_id = lease.row.id;
    ticket.operation_token = lease.token;
    auditRecord(actor, "bucket.adopt", id, key->id, std::nullopt, bmodel::AuditOutcome::Ok, {{"vault", vaultName}});
    return ticket;
}

std::vector<std::string> finishProvision(const Actor& actor, const ProvisionTicket& ticket, const unsigned int vaultId,
                                         const Provision& req) {
    std::vector<std::string> warnings;
    if (!ticket.active()) return warnings;
    const auto row = BucketQuery::get(ticket.upstream_bucket_id);
    if (!row) {
        warnings.emplace_back("the bucket's provisioning record disappeared");
        return warnings;
    }
    const provision::Lease lease{.row = *row, .token = ticket.operation_token, .created = ticket.created};
    if (!provision::complete(lease, vaultId)) warnings.emplace_back("another provisioning attempt took the bucket over");

    const auto id = row->identity();
    if (req.lifecycle) {
        try {
            auto key = findKey(ticket.api_key_id);
            auto client = adminClient(key);
            (void)applyLifecycle(*client, *key, row->bucket, *req.lifecycle);
            auditRecord(actor, "lifecycle.set", id, ticket.api_key_id, vaultId, bmodel::AuditOutcome::Ok,
                        {{"patch", patchJson(*req.lifecycle)}});
        } catch (const std::exception& e) {
            warnings.push_back(std::string("the lifecycle rule was not applied: ") + e.what());
            auditRecord(actor, "lifecycle.set", id, ticket.api_key_id, vaultId, bmodel::AuditOutcome::Failed, {{"error", e.what()}});
        }
    }
    if (req.events)
        if (const auto w = detail::subscribeNewVault(actor, vaultId, req.events_prefix, ticket.mode == BucketMode::Adopt))
            warnings.push_back(*w);
    for (const auto& w : warnings)
        log::Registry::storage()->warn("[ops::upstream] vault {} on bucket '{}': {}", vaultId, row->bucket, w);
    return warnings;
}

void abortProvision(const ProvisionTicket& ticket, const std::string& reason) noexcept {
    if (!ticket.active()) return;
    try {
        const auto row = BucketQuery::get(ticket.upstream_bucket_id);
        if (!row) return;
        std::unique_ptr<padmin::AdminClient> client;
        try {
            if (const auto key = db::query::vault::APIKey::getAPIKey(ticket.api_key_id)) client = adminClient(key);
        } catch (const std::exception& e) {
            log::Registry::storage()->warn("[ops::upstream] no admin client to roll back '{}': {}", row->bucket, e.what());
        }
        provision::compensate(client.get(), {.row = *row, .token = ticket.operation_token, .created = ticket.created}, reason);
        auditRecord(nullptr, ticket.mode == BucketMode::Create ? "bucket.create.rollback" : "bucket.adopt.rollback",
                    row->identity(), ticket.api_key_id, std::nullopt, bmodel::AuditOutcome::Ok, {{"reason", reason}});
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[ops::upstream] rollback of bucket provisioning failed: {}", e.what());
    }
}

// ---- detach and cleanup --------------------------------------------------------------------------------------------

BucketRow detach(const Actor& actor, const KeyRef& ref, const std::string& bucket) {
    auto key = authorize(actor, ref, UpPerm::Destroy, KeyPerm::Consume);
    const auto id = identityOf(key, bucket);
    requireUnprotected(actor, id, "detach", key->id);
    const auto row = BucketQuery::getByIdentity(id.provider, *id.account_ref, id.bucket);
    if (!row || row->ownership == bmodel::Ownership::Unmanaged)
        throw Invalid("bucket '" + bucket + "' isn't managed or adopted by Vaulthalla");
    if (const auto bound = storage::upstream::bindingsFor(id); !bound.empty())
        throw Conflict("bucket '" + bucket + "' is still used by vault '" + bound.front().vault_name + "' (ID " +
                       std::to_string(bound.front().vault_id) + (bound.front().deleted ? ", pending deletion" : "") +
                       "); detach it after that vault is gone");
    if (!db::query::upstream::Subscription::listLiveForBucket(id.provider, *id.account_ref, id.bucket).empty())
        throw Conflict("bucket '" + bucket + "' still has a live event subscription; turn it off first");

    auto client = adminClient(key);
    bool lifecycleRemoved = false;
    try {
        LifecyclePatch clear;
        clear.clear = true;
        lifecycleRemoved = applyLifecycle(*client, *key, bucket, clear);
    } catch (const NeedsConfirmation&) {
        throw;
    } catch (const std::exception& e) {
        auditRecord(actor, "detach", id, key->id, std::nullopt, bmodel::AuditOutcome::Failed, {{"error", e.what()}});
        throw Invalid(std::string("our lifecycle rule could not be removed, nothing was changed: ") + e.what());
    }
    BucketQuery::setOwnership(row->id, bmodel::Ownership::Unmanaged, bmodel::ProvisioningState::Detached);
    auditRecord(actor, "detach", id, key->id, std::nullopt, bmodel::AuditOutcome::Ok,
                {{"previous_ownership", bmodel::to_string(row->ownership)}, {"lifecycle_rule_removed", lifecycleRemoved}});
    return rowFor(id);
}

namespace {

// Everything that forbids a cleanup (empty: allowed). Checked at preflight and again right before deleting.
std::vector<std::string> cleanupBlockers(const BucketIdentity& id, const std::optional<BucketModel>& row) {
    std::vector<std::string> out;
    if (!row || row->ownership != bmodel::Ownership::Managed || !row->created_by_vaulthalla)
        out.emplace_back("Vaulthalla only deletes buckets it created; this one is " +
                         std::string(row ? bmodel::to_string(row->ownership) : "unmanaged"));
    for (const auto& b : storage::upstream::bindingsFor(id))
        out.push_back("used by vault '" + b.vault_name + "' (ID " + std::to_string(b.vault_id) + ")" +
                      (b.deleted ? ", pending deletion: purge or restore it first" : ""));
    if (id.account_ref && !db::query::upstream::Subscription::listLiveForBucket(id.provider, *id.account_ref, id.bucket).empty())
        out.emplace_back("an event subscription is still live on this bucket");
    return out;
}

}

CleanupPlan cleanupPreflight(const Actor& actor, const KeyRef& ref, const std::string& bucket) {
    auto key = authorize(actor, ref, UpPerm::Destroy, KeyPerm::Consume);
    const auto id = identityOf(key, bucket);
    requireUnprotected(actor, id, "cleanup.preflight", key->id);
    const auto row = BucketQuery::getByIdentity(id.provider, *id.account_ref, id.bucket);

    CleanupPlan plan;
    plan.bucket = rowFor(id);
    plan.blockers = cleanupBlockers(id, row);
    if (!plan.blockers.empty()) return plan;   // nothing is listed for a bucket we may not delete

    auto client = adminClient(key);
    const auto config = mapped([&] { return client->inspect(bucket); });
    plan.versioning = config.versioning;
    plan.object_lock = config.object_lock;
    if (config.object_lock && *config.object_lock)
        plan.blockers.emplace_back("object lock is enabled: Vaulthalla never bypasses retention or legal holds");
    else if (!config.object_lock)
        plan.warnings.emplace_back("object lock could not be checked with this credential; locked objects would fail to delete");
    if (!plan.blockers.empty()) return plan;

    const auto counted = mapped([&] { return cleanupx::count(*client, bucket); });
    plan.objects = counted.objects;
    plan.versions = counted.versions;
    plan.delete_markers = counted.delete_markers;
    plan.bytes = counted.bytes;
    plan.truncated = counted.truncated;
    plan.sample_keys = counted.sample_keys;
    const auto issued = cleanupx::issueToken(id, counted, actor->id);
    plan.confirm_token = issued.token;
    plan.expires_at = issued.expires_at;
    auditRecord(actor, "cleanup.preflight", id, key->id, std::nullopt, bmodel::AuditOutcome::Ok,
                {{"objects", plan.objects}, {"versions", plan.versions}, {"delete_markers", plan.delete_markers},
                 {"bytes", plan.bytes}, {"truncated", plan.truncated}});
    return plan;
}

CleanupResult cleanup(const Actor& actor, const KeyRef& ref, const std::string& bucket, const std::string& confirmToken,
                      const bool deleteBucket) {
    auto key = authorize(actor, ref, UpPerm::Destroy, KeyPerm::Consume);
    const auto id = identityOf(key, bucket);
    requireUnprotected(actor, id, "cleanup", key->id);
    const auto seen = cleanupx::consumeToken(confirmToken, id, actor->id);
    if (!seen)
        throw NeedsConfirmation(CLEANUP_CONFIRM, "Run the cleanup preflight for bucket '" + bucket + "' and confirm what it "
                                "shows: this confirmation is missing, expired or for another bucket.");

    // Everything again, right before anything is deleted.
    const auto row = BucketQuery::getByIdentity(id.provider, *id.account_ref, id.bucket);
    if (const auto blockers = cleanupBlockers(id, row); !blockers.empty()) {
        auditRecord(actor, "cleanup", id, key->id, std::nullopt, bmodel::AuditOutcome::Refused, {{"blockers", blockers}});
        throw Conflict("bucket '" + bucket + "' can't be cleaned up: " + blockers.front());
    }
    auto client = adminClient(key);
    const auto now = mapped([&] { return cleanupx::count(*client, bucket); });
    if (!cleanupx::sameAs(*seen, now)) {
        auditRecord(actor, "cleanup", id, key->id, std::nullopt, bmodel::AuditOutcome::Refused,
                    {{"reason", "bucket changed since the preflight"}});
        throw NeedsConfirmation(CLEANUP_CONFIRM, "Bucket '" + bucket + "' changed since the preflight (" +
                                std::to_string(now.objects) + " objects, " + std::to_string(now.versions) +
                                " old versions now). Run the preflight again and confirm the new counts.");
    }
    requireUnprotected(actor, id, "cleanup", key->id);   // a lock set while counting still wins

    (void)BucketQuery::setProvisioningState(row->id, bmodel::ProvisioningState::Deleting, std::nullopt);
    const auto run = mapped([&] { return cleanupx::execute(*client, bucket, deleteBucket); });

    CleanupResult out;
    out.deleted = run.deleted;
    out.failed = run.failed;
    out.bucket_deleted = run.bucket_deleted;
    out.errors = run.errors;
    if (run.bucket_deleted) out.outcome = "deleted";
    else if (run.emptied && !deleteBucket) out.outcome = "emptied";
    else out.outcome = "partial";

    const bool done = out.outcome != "partial";
    (void)BucketQuery::setProvisioningState(row->id, run.bucket_deleted ? bmodel::ProvisioningState::Deleted
                                                                       : (done ? bmodel::ProvisioningState::Ready
                                                                               : bmodel::ProvisioningState::Failed),
                                            std::nullopt,
                                            done ? std::nullopt
                                                 : std::make_optional<std::string>("cleanup incomplete: " +
                                                                                    std::to_string(run.failed) + " failed"));
    auditRecord(actor, "cleanup", id, key->id, std::nullopt, done ? bmodel::AuditOutcome::Ok : bmodel::AuditOutcome::Partial,
                {{"outcome", out.outcome}, {"deleted", out.deleted}, {"failed", out.failed},
                 {"bucket_deleted", out.bucket_deleted}});
    log::Registry::audit()->warn("[ops::upstream] {} cleaned up bucket '{}': {} ({} deleted, {} failed)", actor->name(), bucket,
                                 out.outcome, out.deleted, out.failed);
    return out;
}

// ---- audit ---------------------------------------------------------------------------------------------------------

std::vector<AuditEntry> audit(const Actor& actor, const AuditQuery& query) {
    requireActor(actor);
    requireUpstream(actor, UpPerm::View);
    std::vector<AuditEntry> out;
    for (const auto& r : db::query::upstream::Audit::list(query.bucket, std::clamp(query.limit, 1u, 1000u)))
        out.push_back({.id = r.id, .at = r.at, .user_name = r.user_name, .action = r.action, .provider = r.provider,
                       .account_ref = r.account_ref, .bucket = r.bucket, .outcome = bmodel::to_string(r.outcome),
                       .api_key_id = r.api_key_id, .vault_id = r.vault_id, .detail_json = r.detail_json});
    return out;
}

}
