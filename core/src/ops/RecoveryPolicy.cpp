// ops::recovery policy, provider versioning and costs (.claude/context/recovery.md, "Provider versioning" and "Costs"):
// status, update, versioningDisclosure, suspendVersioning, costs. The only authorizing boundary for these; the
// primitives beneath (recovery::provider::policy, recovery::cost, db::query) never authorize.

#include "ops/Recovery.hpp"

#include "db/query/recovery/Generation.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "db/query/upstream/Audit.hpp"
#include "db/query/upstream/Bucket.hpp"
#include "db/query/vault/Key.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Stats.hpp"
#include "ops/Upstream.hpp"
#include "rbac/permission/admin/Upstream.hpp"
#include "rbac/permission/admin/keys/API.hpp"
#include "rbac/permission/vault/sync/Config.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "recovery/cost/Alerts.hpp"
#include "recovery/cost/Estimator.hpp"
#include "recovery/cost/Report.hpp"
#include "recovery/local/Versions.hpp"
#include "recovery/provider/Policy.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Inventory.hpp"
#include "storage/upstream/Lifecycle.hpp"
#include "storage/upstream/model/Audit.hpp"
#include "sync/model/RemoteManifest.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/except>

#include <algorithm>
#include <chrono>
#include <regex>
#include <unordered_set>

namespace vh::ops::recovery {

namespace {

namespace pol = vh::recovery::provider::policy;
namespace rcost = vh::recovery::cost;
namespace padmin = storage::s3::provider::admin;
namespace rq = db::query::recovery;
using PolUpPerm = rbac::permission::admin::UpstreamPermissions;
using PolKeyPerm = rbac::permission::admin::keys::APIPermissions;
using PolSyncPerm = rbac::permission::vault::sync::SyncConfigPermissions;
using PolOutcome = storage::upstream::model::AuditOutcome;

std::time_t polNow() { return std::time(nullptr); }

std::shared_ptr<vault::model::Vault> polRequireVault(const uint32_t vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    const auto& deps = runtime::Deps::get();
    const auto vault = deps.storageManager ? deps.storageManager->getVault(vaultId) : nullptr;
    if (!vault) throw NotFound("vault not found: " + std::to_string(vaultId));
    return vault;
}

void polRequireSync(const Actor& actor, const uint32_t vaultId, const PolSyncPerm perm, const std::string& vaultName) {
    if (rbac::resolver::Vault::has<PolSyncPerm>({.user = actor, .permission = perm, .vault_id = vaultId})) return;
    throw Denied(perm == PolSyncPerm::Edit
                     ? "changing the recovery settings of vault '" + vaultName + "' needs vault sync.config.edit"
                     : "you do not have permission to view the recovery settings of vault '" + vaultName + "'");
}

// costs and the disclosure: what reads the vault's sync settings, and its pricing statistics (stats.vault.pricing:
// the owner, or an admin role with view + view_stats on the vault).
void polRequireCosts(const Actor& actor, const uint32_t vaultId, const std::string& vaultName) {
    polRequireSync(actor, vaultId, PolSyncPerm::View, vaultName);
    if (!ops::stats::canViewVault(actor, vaultId))
        throw Denied("the recovery costs of vault '" + vaultName + "' are pricing statistics: they need the vault's owner, "
                     "or an admin role with view and view_stats on it");
}

// Adapter and primitive failures as ops refusals; anything else stays a fault.
template <typename Fn>
auto polMapped(Fn&& fn) -> decltype(fn()) {
    try {
        return fn();
    } catch (const Error&) {
        throw;
    } catch (const storage::upstream::BucketProtected& e) {
        throw Denied(e.what());
    } catch (const storage::upstream::lifecycle::UnmodeledOwnedRule& e) {
        throw Conflict(e.what());
    } catch (const padmin::CapabilityMissing& e) {
        throw Invalid(e.what());
    } catch (const padmin::ProviderError& e) {
        if (e.accessDenied()) throw Denied(std::string("the provider refused: ") + e.what());
        if (e.notFound()) throw NotFound(e.what());
        if (e.http_status == 409) throw Conflict(std::string("the provider refused: ") + e.what());
        throw;
    } catch (const std::invalid_argument& e) {
        throw Invalid(e.what());
    }
}

void polAudit(const Actor& actor, const std::string& action, const pol::VaultBucket& vb, const PolOutcome outcome,
              nlohmann::json detail = nlohmann::json::object()) {
    storage::upstream::model::AuditRecord r;
    if (actor) {
        r.user_id = actor->id;
        r.user_name = actor->name();
    }
    r.action = action;
    r.provider = vb.identity.provider;
    r.account_ref = vb.identity.account_ref.value_or("");
    r.bucket = vb.bucket;
    r.api_key_id = vb.api_key_id;
    r.vault_id = vb.vault_id;
    r.outcome = outcome;
    r.detail_json = detail.is_object() ? detail.dump() : std::string("{}");
    db::query::upstream::Audit::appendNoThrow(r);
}

// Why provider versioning can't be used with this vault's provider at all, without a request ("" = it can).
std::string polProviderGap(const pol::VaultBucket& vb) {
    if (!vb.key) return "the vault's API key no longer exists";
    if (vb.identity.provider == "cloudflare-r2") return padmin::kR2VersioningUnsupported;
    if (vb.identity.provider != "aws-s3") return "provider versioning is supported on AWS S3 buckets only";
    return {};
}

struct PolProvider {
    pol::VaultBucket vb;
    std::unique_ptr<padmin::AdminClient> admin;
};

// Provider changes: admin.upstream.configure + Consume on the vault's key, an administrative key, a provider that
// versions, and a bucket that isn't protected. Nothing is sent to the provider before all of that holds.
// changes = false: the disclosure (read-only, authorized like costs by the caller): no upstream/key bits.
PolProvider polAuthorizeProvider(const Actor& actor, const uint32_t vaultId, const std::string& action,
                                 const bool changes = true) {
    auto vb = pol::bucketForVault(vaultId);
    if (!vb) throw Invalid("provider versioning applies to S3 vaults only");
    if (changes && !rbac::resolver::Admin::has<PolUpPerm>({.user = actor, .permission = PolUpPerm::Configure}))
        throw Denied("provider versioning needs the admin.upstream.configure permission");
    if (!vb->key) throw Invalid("the vault's API key no longer exists");
    if (changes &&
        !rbac::resolver::Admin::has<PolKeyPerm>({.user = actor, .permission = PolKeyPerm::Consume, .api_key_id = vb->api_key_id}))
        throw Denied("you do not have permission to use the API key of this vault");
    if (const auto gap = polProviderGap(*vb); !gap.empty()) throw Invalid(gap);
    if (!padmin::supportsAdmin(*vb->key) || !vb->key->admin_enabled)
        throw Invalid("API key '" + vb->key->name + "' is not enabled for provider administration (vh upstream admin enable " +
                      vb->key->name + ")");
    if (vb->isProtected()) {
        polAudit(actor, action, *vb, PolOutcome::Refused, {{"reason", "bucket protected"}});
        std::string reason;
        if (vb->row && vb->row->protection_reason && !vb->row->protection_reason->empty())
            reason = " (" + *vb->row->protection_reason + ")";
        throw Denied("bucket '" + vb->bucket + "' is protected" + reason +
                     ": Vaulthalla will not touch it until it is unprotected");
    }
    const auto& manager = runtime::Deps::get().apiKeyManager;
    if (!manager) throw std::runtime_error("the API key manager is not available");
    auto admin = padmin::adminFor(manager->getAPIKey(vb->api_key_id));
    if (!admin) throw Invalid("provider administration is not available for this API key");
    if (!admin->supportsVersioning())
        throw Invalid(vb->identity.provider == "cloudflare-r2" ? std::string(padmin::kR2VersioningUnsupported)
                                                               : "this provider has no object versioning");
    return {.vb = std::move(*vb), .admin = std::move(admin)};
}

std::optional<vh::recovery::ProviderRetention> polRecordedRetention(const pol::VaultBucket& vb) {
    if (!vb.versioning) return std::nullopt;
    if (vb.versioning->retention_mode == "days" && vb.versioning->retention_days)
        return vh::recovery::ProviderRetention{.indefinite = false, .days = *vb.versioning->retention_days};
    if (vb.versioning->retention_mode == "indefinite") return vh::recovery::ProviderRetention{.indefinite = true, .days = 0};
    return std::nullopt;
}

// What history is kept now: Vaulthalla's retention, or, on a bucket that already keeps versions without one, all of it.
std::optional<vh::recovery::ProviderRetention> polCurrentRetention(const pol::VaultBucket& vb, const padmin::Versioning status) {
    if (const auto r = polRecordedRetention(vb)) return r;
    if (status == padmin::Versioning::Enabled || status == padmin::Versioning::Suspended)
        return vh::recovery::ProviderRetention{.indefinite = true, .days = 0};
    return std::nullopt;
}

bool polShortens(const std::optional<vh::recovery::ProviderRetention>& from, const vh::recovery::ProviderRetention& to) {
    if (!from || to.indefinite) return false;
    return from->indefinite || to.days < from->days;
}

// Local versioning: what in a change deletes retained local versions sooner ("" = nothing). Retention runs only while
// local versioning is on (db::Janitor, keep_last right after a capture): turning it off deletes nothing and keeps
// every version; turning it on (again) applies its limits to everything kept meanwhile. Tighter = a limit added where
// there was none (or none was applied because versioning was off), or lowered. A vault without retained local versions
// has no history to lose. The message says how much the next retention run would delete (one retention query; the
// part the previous limits would have deleted anyway is not counted).
std::string polLocalShortening(const uint32_t vaultId, const std::string& vaultName,
                               const vh::recovery::LocalVersioningPolicy& from, const vh::recovery::LocalVersioningPolicy& to) {
    if (!to.enabled) return {};
    std::vector<std::string> cuts;
    const auto limit = [&](const std::string& name, const auto& before, const auto& after) {
        if (!after) return;
        const bool applied = from.enabled && before;
        if (applied && *after >= *before) return;
        cuts.push_back(name + " " + (applied ? std::to_string(*before) : std::string(from.enabled ? "no limit" : "off")) +
                       " -> " + std::to_string(*after));
    };
    limit("keep_last", from.keep_last, to.keep_last);
    limit("max_age_days", from.max_age_days, to.max_age_days);
    limit("quota_bytes", from.quota_bytes, to.quota_bytes);
    if (cuts.empty()) return {};
    if (rq::Generation::usage(vaultId).versions.count == 0) return {};

    std::string cutText;
    for (const auto& c : cuts) cutText += (cutText.empty() ? "" : ", ") + c;
    std::string now;
    try {
        const auto t = polNow();
        const auto rule = [](const vh::recovery::LocalVersioningPolicy& p) {
            return rq::RetentionRule{.keep_last = p.keep_last, .max_age_days = p.max_age_days, .quota_bytes = p.quota_bytes};
        };
        std::unordered_set<int64_t> anyway;
        if (from.enabled)
            for (const auto& g : rq::Generation::listPrunable(vaultId, rule(from), t)) anyway.insert(g.id);
        uint64_t versions = 0, bytes = 0;
        for (const auto& g : rq::Generation::listPrunable(vaultId, rule(to), t))
            if (!anyway.contains(g.id)) {
                ++versions;
                bytes += g.size_bytes;
            }
        now = versions ? "The next retention run (within 15 minutes) permanently deletes " + std::to_string(versions) +
                             " local version(s) that exist now (" + std::to_string(bytes) + " bytes of file content)"
                       : "Nothing that exists now is deleted at once";
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[ops::recovery] vault {}: local versions a retention change deletes not counted: {}",
                                       vaultId, e.what());
        now = "Existing local versions may be deleted at the next retention run (within 15 minutes)";
    }
    return "This local versioning change for vault '" + vaultName + "' deletes retained history sooner (" + cutText +
           "). " + now + ", and from then on old versions are deleted sooner than before. Deleted versions can't be "
           "recovered. Accept to apply it.";
}

std::string polOptText(const std::optional<uint64_t>& v) { return v ? std::to_string(*v) : std::string("none"); }
std::string polOptText(const std::optional<unsigned int>& v) { return v ? std::to_string(*v) : std::string("none"); }

// What a policy write changes, field by field ("name before -> after"), for the audit log.
std::vector<std::string> polPolicyChanges(const rq::PolicyRow& a, const rq::PolicyRow& b) {
    std::vector<std::string> out;
    const auto diff = [&](const std::string& name, const std::string& x, const std::string& y) {
        if (x != y) out.push_back(name + " " + x + " -> " + y);
    };
    const auto alert = [](const rq::PolicyRow& r) {
        return r.cost_alert_monthly ? *r.cost_alert_monthly + " " + r.cost_alert_currency.value_or("") : std::string("none");
    };
    diff("mode", vh::recovery::to_string(a.mode), vh::recovery::to_string(b.mode));
    diff("snapshot_quota_bytes", polOptText(a.snapshot_quota_bytes), polOptText(b.snapshot_quota_bytes));
    diff("cost_alert_monthly", alert(a), alert(b));
    diff("local_versioning", a.local_versioning.enabled ? "on" : "off", b.local_versioning.enabled ? "on" : "off");
    diff("keep_last", polOptText(a.local_versioning.keep_last), polOptText(b.local_versioning.keep_last));
    diff("max_age_days", polOptText(a.local_versioning.max_age_days), polOptText(b.local_versioning.max_age_days));
    diff("quota_bytes", polOptText(a.local_versioning.quota_bytes), polOptText(b.local_versioning.quota_bytes));
    return out;
}

void polRecordCheck(const pol::VaultBucket& vb, const std::string& status, const std::optional<bool> mfa,
                    const std::optional<bool> lock) {
    if (!vb.row) return;
    try {
        db::query::upstream::Bucket::recordVersioningCheck(vb.row->id, status, mfa, lock);
    } catch (const std::exception& e) {
        log::Registry::storage()->warn("[ops::recovery] bucket '{}': versioning state not recorded: {}", vb.bucket, e.what());
    }
}

const std::regex& polMoneyPattern() {
    static const std::regex re(R"(^[0-9]{1,12}(\.[0-9]{1,8})?$)");
    return re;
}

std::string polRetentionText(const std::optional<vh::recovery::ProviderRetention>& r) {
    if (!r) return "none";
    return r->indefinite ? "kept indefinitely" : std::to_string(r->days) + " days";
}

void polFillProviderState(vh::recovery::Status& st, const pol::VaultBucket& vb, const vh::recovery::Mode mode,
                          const std::optional<pol::RetentionResult>& lifecycleView) {
    auto& p = st.provider;
    p.provider = vb.identity.provider;
    p.bucket = vb.bucket;
    if (vb.row && vb.row->region) p.region = vb.row->region;
    else if (vb.key && !vb.key->region.empty()) p.region = vb.key->region;
    if (const auto engine = std::dynamic_pointer_cast<storage::CloudEngine>(
            runtime::Deps::get().storageManager->getEngine(vb.vault_id)))
        if (const auto tier = engine->resolvedStorageTier()) p.storage_class = tier->id;
    p.unsupported_reason = polProviderGap(vb);
    p.supported = p.unsupported_reason.empty();
    p.bucket_state = vb.state();
    if (vb.versioning) {
        const auto& v = *vb.versioning;
        p.status = v.status.value_or("unknown");
        p.enabled_by_vaulthalla = v.enabled_by_vaulthalla;
        p.enabled_at = v.enabled_at;
        p.settles_at = v.settles_at;
        p.checked_at = v.checked_at;
        p.object_lock = v.object_lock;
        p.mfa_delete = v.mfa_delete;
        p.retention_mode = v.retention_mode;
        p.retention_days = v.retention_days;
    }
    const auto now = polNow();
    p.settled = p.status == "enabled" && (!p.settles_at || now >= *p.settles_at);
    if (lifecycleView) {
        p.foreign_noncurrent_rules = lifecycleView->foreign_rules;
        p.effective_noncurrent_days = lifecycleView->effective_days;
        for (const auto& w : lifecycleView->warnings) p.warnings.push_back(w);
    } else if (p.retention_mode == "days") {
        p.effective_noncurrent_days = p.retention_days;
    }

    if (!p.supported) return;
    if (p.status == "enabled" && !p.settled && p.settles_at)
        p.warnings.push_back("versioning was turned on recently and is still propagating: until " +
                             std::to_string(*p.settles_at) + " (epoch) the provider may not version every write");
    if ((p.status == "enabled" || p.status == "suspended") && mode != vh::recovery::Mode::ProviderVersioning)
        p.warnings.push_back("the bucket keeps object versions although this vault's recovery mode is " +
                             vh::recovery::to_string(mode) +
                             ": old versions still accrue storage costs (suspend versioning to stop new ones)");
    if (p.status == "suspended")
        p.warnings.emplace_back("versioning is suspended: existing versions are kept (and billed), new writes are not "
                                "versioned");
    if (p.object_lock && *p.object_lock)
        p.warnings.emplace_back("object lock is enabled on the bucket: versioning can't be suspended and locked versions "
                                "can't be removed before their retention ends");
    if (p.mfa_delete && *p.mfa_delete)
        p.warnings.emplace_back("MFA delete is enabled: Vaulthalla's lifecycle expirations still apply, but versions can "
                                "only be deleted by the root account with an MFA device");
    if (p.effective_noncurrent_days &&
        (p.retention_mode != "days" || !p.retention_days || *p.effective_noncurrent_days < *p.retention_days) &&
        lifecycleView && lifecycleView->foreign_whole_days &&
        *lifecycleView->foreign_whole_days == *p.effective_noncurrent_days)
        p.warnings.push_back("another application's lifecycle rule deletes noncurrent versions after " +
                             std::to_string(*p.effective_noncurrent_days) + " days, sooner than Vaulthalla's retention (" +
                             (p.retention_mode == "days" && p.retention_days ? std::to_string(*p.retention_days) + " days"
                                                                             : p.retention_mode) + ")");
}

}

// ---- status --------------------------------------------------------------------------------------------------------

namespace {

// The status after the caller's authorization (status needs sync.config.view; update and suspend report it back).
Status polBuildStatus(const Actor& actor, const uint32_t vaultId, const bool refreshProvider) {
    Status st;
    st.vault_id = vaultId;
    const auto policy = rq::Policy::get(vaultId);
    st.mode = policy.mode;
    st.snapshot_quota_bytes = policy.snapshot_quota_bytes;
    if (policy.cost_alert_monthly)
        st.cost_alert_monthly = vh::recovery::Money{.amount = *policy.cost_alert_monthly,
                                                    .currency = policy.cost_alert_currency.value_or("USD")};
    st.local_versioning = policy.local_versioning;

    const auto usage = rq::Generation::usage(vaultId);
    st.snapshots = usage.snapshots;
    st.versions = usage.versions;
    const auto backlog = rq::Generation::backlog(vaultId);
    st.backlog = {.pending_versions = backlog.pending, .pending_bytes = backlog.pending_bytes,
                  .oldest_pending_at = backlog.oldest_pending_at, .failing = backlog.failing,
                  .last_error = backlog.last_error};
    st.retained_key_versions = db::query::vault::Key::recoveryReferencedKeyVersions(vaultId);

    auto vb = pol::bucketForVault(vaultId);
    if (!vb) {
        st.provider.supported = false;
        st.provider.unsupported_reason = "provider versioning applies to S3 vaults only";
        return st;
    }

    std::optional<pol::RetentionResult> lifecycleView;
    if (refreshProvider && polProviderGap(*vb).empty()) {
        if (!rbac::resolver::Admin::has<PolUpPerm>({.user = actor, .permission = PolUpPerm::View}) ||
            !rbac::resolver::Admin::has<PolKeyPerm>({.user = actor, .permission = PolKeyPerm::View, .api_key_id = vb->api_key_id}))
            throw Denied("re-reading the bucket needs admin.upstream.view and view on the vault's API key");
        if (vb->isProtected()) {
            st.provider.warnings.emplace_back("the bucket is protected: its state was not re-read");
        } else if (!vb->key->admin_enabled) {
            st.provider.warnings.push_back("API key '" + vb->key->name + "' is not enabled for provider administration: "
                                           "the bucket's state can't be read");
        } else {
            auto admin = padmin::adminFor(runtime::Deps::get().apiKeyManager->getAPIKey(vb->api_key_id));
            if (admin) {
                const auto config = polMapped([&] { return admin->inspect(vb->bucket); });
                polRecordCheck(*vb, pol::to_string(config.versioning), config.mfa_delete, config.object_lock);
                if (config.lifecycle_readable) lifecycleView = pol::describeRetention(config.lifecycle);
                else st.provider.warnings.emplace_back("the bucket's lifecycle rules can't be read with this credential");
                vb = pol::bucketForVault(vaultId);
            }
        }
    }
    polFillProviderState(st, *vb, st.mode, lifecycleView);

    // Costs can't be estimated / the catalog isn't verified: worth knowing before (and after) turning versioning on.
    if (st.provider.supported && (st.mode == vh::recovery::Mode::ProviderVersioning || st.provider.status == "enabled" ||
                                  st.provider.status == "suspended")) {
        try {
            const auto report = rcost::reportForVault(vaultId, {}, polNow());
            if (!report.priced)
                st.provider.warnings.push_back("versioning costs can't be estimated: " +
                                               report.unpriced_reason.value_or("no price profile"));
            else if (!report.catalog.verified)
                st.provider.warnings.emplace_back("the price catalog's signature is not verified: cost figures are "
                                                  "unverified estimates");
        } catch (const std::exception& e) {
            st.provider.warnings.push_back(std::string("versioning costs could not be computed: ") + e.what());
        }
    }
    if (st.backlog.failing > 0)
        st.warnings.push_back(std::to_string(st.backlog.failing) + " local version(s) failed to upload to the provider" +
                              (st.backlog.last_error ? ": " + *st.backlog.last_error : std::string{}));
    for (const auto& w : st.provider.warnings) st.warnings.push_back(w);
    return st;
}

}

Status status(const Actor& actor, const uint32_t vaultId, const bool refreshProvider) {
    requireActor(actor);
    const auto vault = polRequireVault(vaultId);
    polRequireSync(actor, vaultId, PolSyncPerm::View, vault->name);
    return polBuildStatus(actor, vaultId, refreshProvider);
}

// ---- update --------------------------------------------------------------------------------------------------------

Status update(const Actor& actor, const uint32_t vaultId, const Update& req) {
    requireActor(actor);
    const auto vault = polRequireVault(vaultId);
    polRequireSync(actor, vaultId, PolSyncPerm::Edit, vault->name);

    auto row = rq::Policy::get(vaultId);
    const auto before = row;
    const auto previousMode = row.mode;
    const auto newMode = req.mode.value_or(row.mode);

    // ---- validation (nothing is changed until all of it passes) ----
    if (req.provider_retention && newMode != vh::recovery::Mode::ProviderVersioning)
        throw Invalid("a provider retention applies to provider versioning (mode provider_versioning)");
    if (req.provider_retention && !req.provider_retention->indefinite &&
        (req.provider_retention->days < 1 || req.provider_retention->days > 36500))
        throw Invalid("provider retention must be 1..36500 days or indefinite");
    if (req.cost_alert_monthly && !req.cost_alert_monthly->empty() &&
        !std::regex_match(*req.cost_alert_monthly, polMoneyPattern()))
        throw Invalid("the cost alert is a decimal amount (up to 12 integer and 8 fraction digits), e.g. 25.00");
    if (req.local_versioning) {
        const auto& lv = *req.local_versioning;   // 0 clears a limit
        if (lv.keep_last && *lv.keep_last > 10000) throw Invalid("local versioning keep_last must be 1..10000 (0 = no limit)");
        if (lv.max_age_days && *lv.max_age_days > 36500)
            throw Invalid("local versioning max_age_days must be 1..36500 (0 = no limit)");
    }
    auto nextLocal = row.local_versioning;
    if (req.local_versioning) {
        const auto& patch = *req.local_versioning;
        if (patch.enabled) nextLocal.enabled = *patch.enabled;
        if (patch.keep_last) nextLocal.keep_last = *patch.keep_last == 0 ? std::nullopt : patch.keep_last;
        if (patch.max_age_days) nextLocal.max_age_days = *patch.max_age_days == 0 ? std::nullopt : patch.max_age_days;
        if (patch.quota_bytes) nextLocal.quota_bytes = *patch.quota_bytes == 0 ? std::nullopt : patch.quota_bytes;
    }
    // Deleting local history sooner needs the same explicit acceptance as a shorter provider retention.
    const auto localCut = polLocalShortening(vaultId, vault->name, row.local_versioning, nextLocal);

    std::vector<std::string> warnings;
    std::optional<std::string> catalogCurrency;
    const bool entering = newMode == vh::recovery::Mode::ProviderVersioning &&
                          previousMode != vh::recovery::Mode::ProviderVersioning;
    const bool retentionChange = newMode == vh::recovery::Mode::ProviderVersioning && req.provider_retention.has_value();
    std::optional<std::string> providerRetentionSet;

    // With a provider change the provider's shortening question (below, before anything is sent) carries this one too,
    // so one acceptance never covers a consequence that wasn't shown.
    if (!(entering || retentionChange) && !localCut.empty() && !req.accept_retention_shortening)
        throw NeedsConfirmation(RETENTION_SHORTEN, localCut);

    if (entering || retentionChange) {
        auto ctx = polAuthorizeProvider(actor, vaultId, "recovery.versioning.enable");
        auto& vb = ctx.vb;
        const bool unmanaged = vb.state() == "unmanaged";
        if (unmanaged && !req.accept_adoption)
            throw NeedsConfirmation(BUCKET_ADOPTION,
                "Bucket '" + vb.bucket + "' isn't managed by Vaulthalla. Provider versioning changes the bucket's "
                "configuration, so Vaulthalla must adopt it first: an admission check lists and samples it (nothing in it "
                "is deleted, overwritten or converted), then the bucket is recorded as adopted for vault '" + vault->name +
                "'. Accept the adoption to continue (it needs admin.upstream.provision).");

        const auto target = req.provider_retention ? req.provider_retention : polRecordedRetention(vb);
        if (!target)
            throw Invalid("choose how long the provider keeps old versions: a retention of 30d, 90d, 365d (any 1..36500 "
                          "days) or indefinite");

        // One read of the bucket's versioning (the disclosure may be minutes old).
        const auto state = polMapped([&] { return ctx.admin->versioning(vb.bucket); });
        polRecordCheck(vb, pol::to_string(state.status), state.mfa_delete, std::nullopt);

        const auto now = polNow();
        const auto report = rcost::reportForVault(
            vaultId, {.retention = target, .foreign_noncurrent_days = std::nullopt,
                      .versioning_status = pol::to_string(state.status)}, now);
        catalogCurrency = report.currency;
        const pol::TokenBinding binding{.vault_id = vaultId, .bucket = vb.identity, .retention = target->str(),
                                        .actor_id = actor->id, .estimate_digest = rcost::pricingDigest(report)};
        if (!req.disclosure_token || !pol::verifyToken(*req.disclosure_token, binding, now))
            throw NeedsConfirmation(VERSIONING_DISCLOSURE,
                "Review the provider versioning cost disclosure for bucket '" + vb.bucket + "' with a retention of " +
                polRetentionText(target) + " (vh vault recovery disclosure) and confirm with its token: the token given "
                "is missing, expired, or was issued for another bucket, retention, price catalog or person.");
        if (!report.priced && !req.accept_unpriced)
            throw NeedsConfirmation(VERSIONING_UNPRICED,
                "Vaulthalla can't estimate what versioning will cost on bucket '" + vb.bucket + "' (" +
                report.unpriced_reason.value_or("no price profile") + "). Accept to enable it without an estimate.");
        const auto current = polCurrentRetention(vb, state.status);
        const bool providerCut = polShortens(current, *target);
        if ((providerCut || !localCut.empty()) && !req.accept_retention_shortening) {
            std::string text = providerCut
                ? "Shortening the retention of bucket '" + vb.bucket + "' from " + polRetentionText(current) + " to " +
                      polRetentionText(target) + " makes the provider permanently delete older noncurrent versions "
                      "sooner, including history that exists now. Accept to shorten it."
                : std::string{};
            if (!localCut.empty()) text += (text.empty() ? "" : " ") + localCut;
            throw NeedsConfirmation(RETENTION_SHORTEN, text);
        }

        if (unmanaged) {
            // The admission preflight (provision + key Consume), then the bucket is adopted for this vault.
            const auto admission = upstream::adoptPreflight(actor, upstream::KeyRef{vb.api_key_id}, vb.bucket);
            for (const auto& b : storage::upstream::bindingsFor(vb.identity))
                if (b.vault_id != vaultId)
                    throw Conflict("bucket '" + vb.bucket + "' can't be adopted: it is also used by vault '" + b.vault_name +
                                   "' (ID " + std::to_string(b.vault_id) + ")");
            if (admission.has_vaulthalla_manifest &&
                !(admission.manifest_vault_id && *admission.manifest_vault_id == vaultId) &&
                !db::query::sync::RemoteObjectIndex::getManifestETag(vaultId, sync::model::remote_manifest::INDEX_V1_KEY))
                throw Conflict("bucket '" + vb.bucket + "' can't be adopted: it holds another Vaulthalla vault's index");
            upstream::detail::adoptBoundBucket(actor, vb.api_key_id, vaultId, vb.bucket);
            for (const auto& w : admission.warnings) warnings.push_back(w);
            auto refreshed = pol::bucketForVault(vaultId);
            if (!refreshed || !refreshed->row) throw std::runtime_error("the adopted bucket's record is missing");
            vb = std::move(*refreshed);
        }
        if (!vb.row) throw Conflict("bucket '" + vb.bucket + "' has no Vaulthalla record; adopt it first");
        const auto rowId = vb.row->id;

        // Enable only when it isn't on already (never a second PutBucketVersioning), then read it back.
        bool put = false;
        pol::ReadBack readBack;
        if (state.status != padmin::Versioning::Enabled) {
            try {
                readBack = polMapped([&] { return pol::putAndConfirm(*ctx.admin, vb.bucket, padmin::Versioning::Enabled); });
            } catch (const std::exception& e) {
                polAudit(actor, "recovery.versioning.enable", vb, PolOutcome::Failed, {{"error", e.what()}});
                throw;
            }
            put = true;
            if (!readBack.confirmed)
                warnings.push_back("the provider accepted versioning for bucket '" + vb.bucket + "' but hasn't confirmed it "
                                   "after " + std::to_string(readBack.reads) + " read(s); it will show once it propagates");
        }
        const auto settles = polNow() + std::chrono::duration_cast<std::chrono::seconds>(pol::kPropagation).count();
        db::query::upstream::Bucket::recordVersioningEnabled(rowId, put ? std::make_optional(actor->id) : std::nullopt, put,
                                                             settles);
        if (state.mfa_delete) polRecordCheck(vb, "enabled", state.mfa_delete, std::nullopt);
        polAudit(actor, "recovery.versioning.enable", vb, PolOutcome::Ok,
                 {{"put", put}, {"confirmed", put ? readBack.confirmed : true}, {"reads", readBack.reads},
                  {"previous", pol::to_string(state.status)}, {"retention", target->str()},
                  {"priced", report.priced}, {"accepted_unpriced", !report.priced}});

        // Retention: Vaulthalla's lifecycle rule (+ the manifest-versions rule); every foreign rule stays as it was.
        try {
            const auto applied = polMapped([&] { return pol::applyRetention(*ctx.admin, vb.bucket, *target, true); });
            db::query::upstream::Bucket::recordRetention(rowId, target->indefinite ? "indefinite" : "days",
                                                         target->indefinite ? std::nullopt : std::make_optional(target->days),
                                                         actor->id);
            for (const auto& w : applied.warnings) warnings.push_back(w);
            if (applied.foreign_whole_days && (target->indefinite || *applied.foreign_whole_days < target->days))
                warnings.push_back("another application's lifecycle rule deletes noncurrent versions after " +
                                   std::to_string(*applied.foreign_whole_days) + " days, sooner than the retention chosen");
            providerRetentionSet = (current ? current->str() : std::string("unset")) + " -> " + target->str();
            polAudit(actor, "recovery.retention.set", vb, PolOutcome::Ok,
                     {{"retention", target->str()}, {"previous", current ? current->str() : std::string("unset")},
                      {"written", applied.written}, {"effective_days", applied.effective_days ? nlohmann::json(*applied.effective_days)
                                                                                          : nlohmann::json(nullptr)},
                      {"foreign_rules", applied.foreign_rules}});
        } catch (const std::exception& e) {
            polAudit(actor, "recovery.retention.set", vb, PolOutcome::Failed, {{"retention", target->str()}, {"error", e.what()}});
            throw;
        }
    }

    // ---- the vault's preference (never suspends anything; suspendVersioning does) ----
    row.vault_id = vaultId;
    row.mode = newMode;
    if (req.snapshot_quota_bytes)
        row.snapshot_quota_bytes = *req.snapshot_quota_bytes == 0 ? std::nullopt : req.snapshot_quota_bytes;
    if (req.cost_alert_monthly) {
        if (req.cost_alert_monthly->empty()) {
            row.cost_alert_monthly.reset();
            row.cost_alert_currency.reset();
        } else {
            row.cost_alert_monthly = *req.cost_alert_monthly;
            if (!catalogCurrency) {
                try {
                    catalogCurrency = rcost::reportForVault(vaultId, {}, polNow()).currency;
                } catch (const std::exception&) {
                }
            }
            row.cost_alert_currency = catalogCurrency.value_or(row.cost_alert_currency.value_or("USD"));
        }
    }
    row.local_versioning = nextLocal;
    row.updated_by = actor->id;
    try {
        rq::Policy::upsert(row);
    } catch (const pqxx::check_violation& e) {
        throw Invalid(std::string("the recovery settings are out of range: ") + e.what());
    }
    vh::recovery::local::invalidatePolicy(vaultId);   // the local versioning harness re-reads the policy

    // Every change, field by field (bucket-affecting steps are also in upstream_audit, above).
    auto changes = polPolicyChanges(before, row);
    if (providerRetentionSet) changes.push_back("provider retention " + *providerRetentionSet);
    if (!changes.empty()) {
        std::string text;
        for (const auto& c : changes) text += (text.empty() ? "" : ", ") + c;
        if (!localCut.empty())
            log::Registry::audit()->warn("[ops::recovery] {} changed the recovery settings of vault {} ('{}'): {} "
                                         "(accepted: local versions are deleted sooner)", actor->name(), vaultId,
                                         vault->name, text);
        else
            log::Registry::audit()->info("[ops::recovery] {} changed the recovery settings of vault {} ('{}'): {}",
                                         actor->name(), vaultId, vault->name, text);
    }

    auto st = polBuildStatus(actor, vaultId, false);
    for (auto& w : warnings) st.warnings.push_back(std::move(w));
    return st;
}

// ---- disclosure ----------------------------------------------------------------------------------------------------

Disclosure versioningDisclosure(const Actor& actor, const uint32_t vaultId,
                                const std::optional<ProviderRetention>& retention) {
    requireActor(actor);
    const auto vault = polRequireVault(vaultId);
    polRequireCosts(actor, vaultId, vault->name);
    if (retention && !retention->indefinite && (retention->days < 1 || retention->days > 36500))
        throw Invalid("provider retention must be 1..36500 days or indefinite");
    // Read-only: the enable re-checks admin.upstream.configure and the key; the token is bound to this person.
    auto ctx = polAuthorizeProvider(actor, vaultId, "recovery.disclosure", /*changes=*/false);
    const auto& vb = ctx.vb;

    // The one admin request: versioning, object lock, MFA delete and lifecycle in one inspect.
    const auto config = polMapped([&] { return ctx.admin->inspect(vb.bucket); });
    polRecordCheck(vb, pol::to_string(config.versioning), config.mfa_delete, config.object_lock);
    std::optional<pol::RetentionResult> described;
    if (config.lifecycle_readable) described = pol::describeRetention(config.lifecycle);

    const auto target = retention ? retention : polRecordedRetention(vb);
    const auto now = polNow();
    Disclosure d;
    d.report = rcost::reportForVault(
        vaultId, {.retention = target,
                  .foreign_noncurrent_days = described ? described->foreign_whole_days : std::nullopt,
                  .versioning_status = pol::to_string(config.versioning)}, now);
    rcost::noteAlert(d.report, now);

    auto& c = d.consequences;
    if (config.versioning == padmin::Versioning::Enabled)
        c.push_back("Bucket '" + vb.bucket + "' already keeps versions: Vaulthalla will not change that, only record it and "
                    "set the retention.");
    else
        c.push_back("Turning versioning on for bucket '" + vb.bucket + "' can't be undone: AWS can only suspend it later, "
                    "and versions that exist keep being billed until they expire or are deleted.");
    c.emplace_back("AWS takes up to 15 minutes before every write is versioned; until then Vaulthalla shows the bucket as "
                   "propagating and doesn't rely on versions for recovery.");
    if (!target)
        c.emplace_back("No retention chosen yet: choose one (30d, 90d, 365d or indefinite) to enable versioning.");
    else if (target->indefinite)
        c.emplace_back("Old versions are kept indefinitely: storage grows with every overwrite and delete until a retention "
                       "is set.");
    else
        c.push_back("The provider permanently deletes each old version " + std::to_string(target->days) +
                    " days after it stops being current (lifecycle rule '" +
                    std::string(storage::upstream::lifecycle::kOwnedRuleId) + "'); history older than that can't be "
                    "recovered.");
    c.emplace_back("Every old version is a full copy billed at the storage class rate; storage classes with a minimum "
                   "storage duration or object size bill at least that much per version.");
    c.push_back("Vaulthalla also expires old copies of its own index (" +
                std::string(storage::upstream::lifecycle::kManifestRulePrefix) + ", rule '" +
                std::string(storage::upstream::lifecycle::kManifestRuleId) + "') after 1 day.");
    if (described && !described->foreign_rules.empty())
        c.push_back("Other lifecycle rules on the bucket already expire noncurrent versions (" +
                    [&] {
                        std::string s;
                        for (const auto& r : described->foreign_rules) s += (s.empty() ? "" : ", ") + r;
                        return s;
                    }() + "); Vaulthalla keeps them unchanged, and the shortest one wins.");
    if (config.object_lock && *config.object_lock)
        c.emplace_back("Object lock is enabled on this bucket: versioning can never be suspended and locked versions can't "
                       "be removed early.");
    if (config.mfa_delete && *config.mfa_delete)
        c.emplace_back("MFA delete is enabled: only the root account with an MFA device can delete versions.");
    c.emplace_back("The figures are estimates computed on this host from the price catalog and this vault's own measured "
                   "usage, not an invoice: taxes, discounts and account-wide free tiers are not included.");

    d.required_acknowledgements.emplace_back(VERSIONING_DISCLOSURE);
    if (!d.report.priced) d.required_acknowledgements.emplace_back(VERSIONING_UNPRICED);
    if (vb.state() == "unmanaged") d.required_acknowledgements.emplace_back(BUCKET_ADOPTION);
    if (target && polShortens(polCurrentRetention(vb, config.versioning), *target))
        d.required_acknowledgements.emplace_back(RETENTION_SHORTEN);

    d.expires_at = now + std::chrono::duration_cast<std::chrono::seconds>(pol::kDisclosureLifetime).count();
    d.token = pol::issueToken({.vault_id = vaultId, .bucket = vb.identity, .retention = target ? target->str() : "unset",
                               .actor_id = actor->id, .estimate_digest = rcost::pricingDigest(d.report)},
                              d.expires_at);
    polAudit(actor, "recovery.disclosure", vb, PolOutcome::Ok,
             {{"retention", target ? target->str() : std::string("unset")}, {"priced", d.report.priced},
              {"versioning", pol::to_string(config.versioning)}});
    return d;
}

// ---- suspend -------------------------------------------------------------------------------------------------------

Status suspendVersioning(const Actor& actor, const uint32_t vaultId, const bool confirm) {
    requireActor(actor);
    const auto vault = polRequireVault(vaultId);
    polRequireSync(actor, vaultId, PolSyncPerm::Edit, vault->name);
    auto ctx = polAuthorizeProvider(actor, vaultId, "recovery.versioning.suspend");
    const auto& vb = ctx.vb;
    if (vb.state() == "unmanaged" || !vb.row)
        throw Invalid("Vaulthalla changes versioning only on buckets it manages or adopted; bucket '" + vb.bucket +
                      "' is unmanaged");
    if (!confirm)
        throw NeedsConfirmation(VERSIONING_SUSPEND,
            "Suspend versioning on bucket '" + vb.bucket + "'? New writes stop creating versions. Existing versions are "
            "kept (and billed) until the retention expires them; nothing is deleted.");

    const auto state = polMapped([&] { return ctx.admin->versioning(vb.bucket); });
    if (state.status == padmin::Versioning::Unversioned)
        throw Invalid("bucket '" + vb.bucket + "' has never been versioned: there is nothing to suspend");
    if (vb.versioning && vb.versioning->object_lock && *vb.versioning->object_lock)
        throw Conflict("bucket '" + vb.bucket + "' has object lock enabled: its versioning can't be suspended");
    pol::ReadBack readBack;
    bool put = false;
    if (state.status != padmin::Versioning::Suspended) {
        try {
            readBack = polMapped([&] { return pol::putAndConfirm(*ctx.admin, vb.bucket, padmin::Versioning::Suspended); });
        } catch (const std::exception& e) {
            polAudit(actor, "recovery.versioning.suspend", vb, PolOutcome::Failed, {{"error", e.what()}});
            throw;
        }
        put = true;
    }
    polRecordCheck(vb, put && !readBack.confirmed ? pol::to_string(readBack.state.status) : "suspended", state.mfa_delete,
                   std::nullopt);
    polAudit(actor, "recovery.versioning.suspend", vb, PolOutcome::Ok,
             {{"put", put}, {"confirmed", put ? readBack.confirmed : true}, {"previous", pol::to_string(state.status)}});
    log::Registry::audit()->warn("[ops::recovery] {} suspended versioning on bucket '{}' (vault {})", actor->name(), vb.bucket,
                                 vaultId);
    auto st = polBuildStatus(actor, vaultId, false);
    if (put && !readBack.confirmed)
        st.warnings.push_back("the provider accepted the suspension but hasn't confirmed it yet");
    return st;
}

// ---- costs ---------------------------------------------------------------------------------------------------------

CostReport costs(const Actor& actor, const uint32_t vaultId) {
    requireActor(actor);
    const auto vault = polRequireVault(vaultId);
    polRequireCosts(actor, vaultId, vault->name);
    const auto now = polNow();
    auto report = rcost::reportForVault(vaultId, {}, now);
    rcost::noteAlert(report, now);
    return report;
}

}
