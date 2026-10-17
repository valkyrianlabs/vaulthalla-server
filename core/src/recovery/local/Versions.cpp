#include "recovery/local/Versions.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/u8.hpp"
#include "db/query/recovery/Policy.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"
#include "recovery/provider/State.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/Vault.hpp"

#include <pqxx/except>
#include <pqxx/result>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <functional>
#include <mutex>
#include <stdexcept>
#include <unordered_map>

namespace vh::recovery::local {

namespace {

namespace rq = db::query::recovery;

// A safety net only: policy writers invalidate explicitly. Within the TTL the write path never reads the policy.
constexpr std::chrono::seconds kPolicyTtl{60};

struct CachedPolicy {
    LocalVersioningPolicy policy;
    std::chrono::steady_clock::time_point loaded;
};

std::mutex policyMutex;
std::unordered_map<uint32_t, CachedPolicy> policyCache;
// Bumped by every invalidation, so a load that raced with one never caches what it read.
uint64_t policyEpoch = 0;

std::atomic<uint64_t> retainedCount{0}, skippedCount{0}, failedCount{0}, policyLoadCount{0}, coalescedCount{0};

std::string vaultPathOf(const fs::model::File& f) {
    auto p = db::encoding::to_utf8_string(f.path.generic_u8string());
    if (p.empty() || p.front() != '/') p.insert(p.begin(), '/');
    return p;
}

// A delete reaches the bucket only when the vault's sync policy removes remote leftovers (mirror + keep_local);
// otherwise the object stays (or is fetched back) and there is nothing to keep in order upstream.
bool deletePropagatesUpstream(const storage::Engine& engine) {
    const auto* cloud = dynamic_cast<const storage::CloudEngine*>(&engine);
    if (!cloud) return false;
    const auto policy = cloud->remote_policy();
    return policy && policy->deleteRemoteLeftovers();
}

}

std::string to_string(const Reason r) {
    switch (r) {
    case Reason::Overwrite: return "overwrite";
    case Reason::Truncate: return "truncate";
    case Reason::Delete: return "delete";
    case Reason::Download: return "download";
    case Reason::Restore: return "restore";
    case Reason::Conflict: return "conflict";
    }
    return "overwrite";
}

Reason reasonFromString(const std::string& s) {
    for (const auto r : {Reason::Overwrite, Reason::Truncate, Reason::Delete, Reason::Download, Reason::Restore,
                         Reason::Conflict})
        if (to_string(r) == s) return r;
    throw std::invalid_argument("unknown local version reason '" + s + "'");
}

LocalVersioningPolicy versioningPolicy(const uint32_t vaultId) {
    const auto now = std::chrono::steady_clock::now();
    uint64_t epoch = 0;
    {
        std::scoped_lock lock(policyMutex);
        if (const auto it = policyCache.find(vaultId); it != policyCache.end() && now - it->second.loaded < kPolicyTtl)
            return it->second.policy;
        epoch = policyEpoch;
    }
    try {
        const auto row = db::query::recovery::Policy::get(vaultId);
        ++policyLoadCount;
        std::scoped_lock lock(policyMutex);
        if (epoch == policyEpoch) policyCache[vaultId] = {row.local_versioning, now};
        return row.local_versioning;
    } catch (const std::exception& e) {
        std::scoped_lock lock(policyMutex);
        if (const auto it = policyCache.find(vaultId); it != policyCache.end()) {
            log::Registry::storage()->warn("[LocalVersions] Vault {}: policy refresh failed ({}); using the cached one",
                                           vaultId, e.what());
            return it->second.policy;
        }
        log::Registry::storage()->warn("[LocalVersions] Vault {}: policy unavailable ({}); not versioning this write",
                                       vaultId, e.what());
        return {};
    }
}

void invalidatePolicy(const uint32_t vaultId) noexcept {
    std::scoped_lock lock(policyMutex);
    policyCache.erase(vaultId);
    ++policyEpoch;
}

void invalidateAllPolicies() noexcept {
    std::scoped_lock lock(policyMutex);
    policyCache.clear();
    ++policyEpoch;
}

}

namespace vh::recovery::local::versions {

namespace rq = db::query::recovery;

namespace {

std::function<void(pqxx::work&)>& attachHook() {
    static std::function<void(pqxx::work&)> hook;
    return hook;
}

}

void setAttachHookForTesting(std::function<void(pqxx::work&)> hook) { attachHook() = std::move(hook); }

Pending::Pending(Pending&& other) noexcept
    : vault_(std::move(other.vault_)), capture_(std::move(other.capture_)), generation_(std::move(other.generation_)),
      keepLast_(other.keepLast_), inserted_(other.inserted_), freedBlobs_(std::move(other.freedBlobs_)),
      coalesced_(other.coalesced_) {
    other.capture_.reset();
    other.inserted_.reset();
}

void Pending::attach(pqxx::work& txn) {
    if (!capture_ || inserted_) return;
    // Bookkeeping must never fail the content write it rides on: the rows go in under a savepoint, and a failure (the
    // reused blob was removed since retain(), a constraint, …) rolls back only them. The write commits; this
    // generation is not kept (logged and counted).
    txn.exec("SAVEPOINT vh_recovery_version");
    try {
        attachRows(txn);
        txn.exec("RELEASE SAVEPOINT vh_recovery_version");
    } catch (const pqxx::broken_connection&) {
        throw;   // the caller's transaction is gone with it
    } catch (const std::exception& e) {
        txn.exec("ROLLBACK TO SAVEPOINT vh_recovery_version");   // throws (failing the write) only if the txn is broken
        txn.exec("RELEASE SAVEPOINT vh_recovery_version");
        ++failedCount;
        log::Registry::storage()->error("[LocalVersions] Vault {}: the previous version of {} was not kept ({}); the "
                                        "write goes ahead", vault_.id, generation_.path, e.what());
        capture_->abort();
        capture_.reset();
        inserted_.reset();
        freedBlobs_.clear();
        coalesced_ = 0;
    }
}

void Pending::attachRows(pqxx::work& txn) {
    if (attachHook()) attachHook()(txn);
    generation_.blob_id = capture_->attach(txn);
    inserted_ = rq::Generation::insertLocalVersion(txn, generation_);

    // The key's backlog stays bounded: an autosave/append workload would otherwise queue a full blob per write, every
    // one replayed upstream. Older pending versions beyond the cap (keep_last, else kDefaultPendingCap) are skipped
    // ('coalesced'): not replayed, still local versions under the vault's retention (keep_last prunes them below).
    if (generation_.upstream_state == rq::UpstreamState::Pending && generation_.upstream_key) {
        const auto cap = keepLast_ && *keepLast_ > 0 ? *keepLast_ : kDefaultPendingCap;
        if (const auto coalesced = rq::Generation::coalescePending(txn, vault_.id, *generation_.upstream_key, cap);
            !coalesced.empty())
            coalesced_ = coalesced.size();
    }

    // keep_last per file, right here and bounded: only once the file has had more generations than it keeps (the
    // numbers only grow), and at most a page of the oldest unpinned ones. Retention catches up with the rest.
    if (!keepLast_ || !generation_.file_id || inserted_->version_number <= static_cast<int>(*keepLast_)) return;
    const auto res = txn.exec(R"SQL(
        SELECT id FROM (
            SELECT id, upstream_state, row_number() OVER (ORDER BY version_number DESC, id DESC) AS rn
            FROM file_versions WHERE file_id = $1 AND origin = 'version' AND snapshot_id IS NULL
        ) ranked
        WHERE rn > $2 AND upstream_state <> 'pending' ORDER BY id LIMIT 64
    )SQL", pqxx::params{*generation_.file_id, static_cast<int64_t>(*keepLast_)});
    std::vector<int64_t> ids;
    for (const auto row : res) ids.push_back(row[0].as<int64_t>());
    if (!ids.empty()) freedBlobs_ = rq::Generation::removeVersions(txn, vault_.id, ids);
}

void Pending::committed() noexcept {
    if (!capture_) return;
    capture_->committed();
    if (inserted_) ++retainedCount;
    if (coalesced_) {
        coalescedCount += coalesced_;
        log::Registry::storage()->info("[LocalVersions] Vault {}: {} older unsent version(s) of {} coalesced (the "
                                       "upstream backlog keeps the newest {})", vault_.id, coalesced_, generation_.path,
                                       keepLast_ && *keepLast_ > 0 ? *keepLast_ : kDefaultPendingCap);
        coalesced_ = 0;
    }
    if (!freedBlobs_.empty()) {
        static_cast<void>(store::removeBlobs(vault_, freedBlobs_));
        freedBlobs_.clear();
    }
}

void Pending::abort() noexcept {
    if (capture_) capture_->abort();
    inserted_.reset();
    coalesced_ = 0;
    freedBlobs_.clear();
}

std::optional<int64_t> Pending::versionId() const {
    return inserted_ ? std::make_optional(inserted_->id) : std::nullopt;
}

std::optional<int> Pending::versionNumber() const {
    return inserted_ ? std::make_optional(inserted_->version_number) : std::nullopt;
}

Pending retain(const storage::Engine& engine, const fs::model::File& prior, const Reason reason,
               const RetainOptions& options) {
    Pending p;
    if (!engine.vault || prior.id == 0) return p;
    const auto policy = versioningPolicy(engine.vault->id);
    if (!policy.enabled) return p;

    // An empty generation (or plaintext an older build left behind) has nothing a blob could hold: blobs are sealed
    // bytes only. A cloud file without local bytes is held by the provider.
    std::error_code ec;
    if (prior.encryption_iv.empty() || prior.backing_path.empty() ||
        !std::filesystem::is_regular_file(prior.backing_path, ec)) {
        ++skippedCount;
        return p;
    }

    const auto path = vaultPathOf(prior);
    try {
        p.vault_ = store::vaultRef(*engine.vault);
        p.capture_.emplace(store::captureLink(p.vault_, prior.backing_path,
                                              {.encryption_iv = prior.encryption_iv,
                                               .key_version = prior.encrypted_with_key_version,
                                               .plaintext_bytes = prior.size_bytes,
                                               .content_hash = prior.content_hash}));
    } catch (const std::exception& e) {
        ++failedCount;
        log::Registry::storage()->error("[LocalVersions] Vault {}: could not keep the previous version of {} ({}): {}",
                                        engine.vault->id, path, to_string(reason), e.what());
        return Pending{};
    }

    bool upstream = options.upstream && engine.type() == storage::StorageType::Cloud &&
                    reason != Reason::Download && reason != Reason::Conflict;
    if (upstream && reason == Reason::Delete) upstream = deletePropagatesUpstream(engine);

    auto& g = p.generation_;
    g.vault_id = engine.vault->id;
    g.file_id = prior.id;
    g.content_hash = prior.content_hash;
    g.size_bytes = prior.size_bytes;
    g.mime_type = prior.mime_type;
    g.path = path;
    g.mode = prior.mode;
    g.source_updated_at = prior.updated_at ? std::make_optional(prior.updated_at) : std::nullopt;
    g.created_by = options.actor;
    g.reason = to_string(reason);
    g.upstream_state = upstream ? rq::UpstreamState::Pending : rq::UpstreamState::None;
    if (upstream) g.upstream_key = path.substr(1);
    p.keepLast_ = policy.keep_last;
    return p;
}

// ---- retention ---------------------------------------------------------------------------------------------------------

RetentionReport applyRetention(const store::VaultRef& vault, const LocalVersioningPolicy& policy, const std::time_t now) {
    RetentionReport report;
    const rq::RetentionRule rule{.keep_last = policy.keep_last, .max_age_days = policy.max_age_days,
                                 .quota_bytes = policy.quota_bytes};
    const auto prunable = rq::Generation::listPrunable(vault.id, rule, now);
    constexpr std::size_t kChunk = 500;
    for (std::size_t i = 0; i < prunable.size(); i += kChunk) {
        std::vector<int64_t> ids, pending;
        for (auto k = i; k < std::min(prunable.size(), i + kChunk); ++k) {
            ids.push_back(prunable[k].id);
            if (prunable[k].upstream_state == rq::UpstreamState::Pending) pending.push_back(prunable[k].id);
        }
        // The version quota reaches unsent versions too: skipped visibly (reason 'quota', logged, reported) first.
        if (!pending.empty()) {
            report.pending_dropped += rq::Generation::markSkipped(pending, "quota");
            log::Registry::storage()->warn("[LocalVersions] Vault {}: the version quota removed {} version(s) not yet "
                                           "sent upstream; the provider will not get them", vault.id, pending.size());
        }
        const auto freed = rq::Generation::removeVersions(vault.id, ids);
        report.versions_removed += ids.size();
        report.blobs_removed += store::removeBlobs(vault, freed);
    }
    if (report.versions_removed)
        log::Registry::storage()->info("[LocalVersions] Vault {}: retention removed {} version(s), {} blob(s)", vault.id,
                                       report.versions_removed, report.blobs_removed);
    return report;
}

MaintenanceReport maintain(const std::time_t now, const bool sweepStores) {
    MaintenanceReport report;
    std::vector<std::shared_ptr<storage::Engine>> engines;
    try {
        if (const auto& manager = runtime::Deps::get().storageManager) engines = manager->getEngines();
    } catch (const std::exception& e) {
        report.errors.push_back(std::string("listing vaults: ") + e.what());
        return report;
    }

    for (const auto& engine : engines) {
        if (!engine || !engine->vault) continue;
        const auto vaultId = engine->vault->id;
        try {
            const auto ref = store::vaultRef(*engine->vault);
            ++report.vaults;

            invalidatePolicy(vaultId);   // maintenance reads it fresh; the write path refills the cache
            if (const auto policy = versioningPolicy(vaultId); policy.enabled) {
                const auto r = applyRetention(ref, policy, now);
                report.versions_removed += r.versions_removed;
                report.blobs_removed += r.blobs_removed;
                report.pending_dropped += r.pending_dropped;
            }

            // A bucket that keeps no history never gets the backlog replayed: only the latest content matters there.
            if (engine->type() == storage::StorageType::Cloud &&
                provider::bucketVersioningForVault(vaultId, now).status != "enabled") {
                for (int page = 0; page < 100; ++page) {
                    const auto pending = rq::Generation::listPending(vaultId, 1000);
                    if (pending.empty()) break;
                    std::vector<int64_t> ids;
                    for (const auto& g : pending) ids.push_back(g.id);
                    report.backlog_skipped += rq::Generation::markSkipped(ids);
                }
            }

            std::error_code ec;
            if (sweepStores && std::filesystem::is_directory(store::vaultDir(ref), ec)) {
                const auto s = store::sweep(ref);
                report.orphans_removed += s.orphans_removed;
                report.unreferenced_removed += s.unreferenced_removed;
                report.missing += s.missing.size();
                for (const auto& e : s.errors) report.errors.push_back("vault " + std::to_string(vaultId) + ": " + e);
            }
        } catch (const std::exception& e) {
            report.errors.push_back("vault " + std::to_string(vaultId) + ": " + e.what());
        }
    }

    for (const auto& e : report.errors) log::Registry::storage()->warn("[LocalVersions] Maintenance: {}", e);
    return report;
}

Counters counters() {
    return {.retained = retainedCount.load(), .skipped = skippedCount.load(), .failed = failedCount.load(),
            .policy_loads = policyLoadCount.load(), .coalesced = coalescedCount.load()};
}

}
