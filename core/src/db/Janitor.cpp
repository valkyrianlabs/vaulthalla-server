#include "db/Janitor.hpp"
#include "config/Registry.hpp"
#include "db/query/fs/ChangeLog.hpp"
#include "db/query/sync/Event.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/upstream/Inbox.hpp"
#include "db/query/upstream/WriteIntent.hpp"
#include "log/Registry.hpp"
#include "preview/cache/Maintenance.hpp"
#include "protocols/http/upload/Resumable.hpp"
#include "db/query/recovery/Plan.hpp"
#include "recovery/local/Snapshots.hpp"
#include "recovery/local/Versions.hpp"
#include "share/Manager.hpp"

#include <algorithm>
#include <ctime>
#include <utility>

using namespace vh::config;

namespace vh::db::janitor_impl {
// Derived preview artifacts are kept within caching.max_size_mb on a shorter cadence than the DB sweep.
constexpr std::chrono::minutes kDerivedCacheInterval{15};
// Finished upstream events (done/skipped) are kept this long for status and diagnostics (#96).
constexpr std::chrono::hours kUpstreamInboxRetention{24 * 7};

// File recovery: local version retention and the upstream backlog of buckets without history run with the derived
// cache cadence; the recovery store's orphan sweep (crashed captures) runs at startup and then daily.
constexpr std::chrono::hours kRecoveryStoreSweepInterval{24};

// Finished and expired restore plans are kept this long (resume, diagnostics).
constexpr std::chrono::hours kRecoveryPlanRetention{24 * 30};

// The filesystem change journal (fs.changes.list, migration 115): a cursor older than this, or more than this many
// revisions behind, is expired and its client enumerates again.
constexpr std::chrono::hours kFsChangeRetention{24 * 7};
constexpr uint64_t kFsChangeMaxRevisions = 1'000'000;

void maintainRecovery(const bool sweepStores) {
    // Snapshots left `creating` by a crash: at the first run after startup nothing of this process is in flight.
    static bool firstRun = true;
    const auto minAge = std::exchange(firstRun, false) ? std::chrono::seconds(0) : std::chrono::seconds(3600);
    if (sweepStores) {
        if (const auto n = vh::recovery::local::snapshots::cleanupInterrupted(minAge))
            log::Registry::vaulthalla()->warn("[DBSweeper] Recovery: {} interrupted snapshot(s) marked failed", n);
    }
    try {
        const auto now = std::time(nullptr);
        query::recovery::Plan::expire(now);
        query::recovery::Plan::purgeOlderThan(now - std::chrono::duration_cast<std::chrono::seconds>(kRecoveryPlanRetention).count());
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[DBSweeper] Recovery plan expiry failed: {}", e.what());
    }
    try {
        const auto r = vh::recovery::local::versions::maintain(std::time(nullptr), sweepStores);
        if (r.versions_removed || r.backlog_skipped || r.backlog_replayed || r.orphans_removed || r.unreferenced_removed)
            log::Registry::vaulthalla()->info(
                "[DBSweeper] Recovery: {} version(s) and {} blob(s) past retention, {} backlog version(s) skipped "
                "({} orphaned), {} orphaned backlog version(s) replayed, {} orphan blob(s) and {} unreferenced row(s) swept",
                r.versions_removed, r.blobs_removed, r.backlog_skipped, r.backlog_orphaned, r.backlog_replayed,
                r.orphans_removed, r.unreferenced_removed);
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[DBSweeper] Recovery maintenance failed: {}", e.what());
    }
}

// Best effort: a failure here never blocks the other sweeps.
void pruneFsChanges() {
    try {
        // Number what no client has asked for yet, so retention sees it (pending rows are never pruned).
        (void)query::fs::ChangeLog::sequence();
        if (const auto r = query::fs::ChangeLog::prune(kFsChangeRetention, kFsChangeMaxRevisions); r.removed > 0)
            log::Registry::vaulthalla()->info("[DBSweeper] Pruned {} filesystem change(s) through revision {}",
                                              r.removed, r.pruned_through);
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[DBSweeper] Filesystem change journal prune failed: {}", e.what());
    }
}

// Best effort: a failure here never blocks the other sweeps.
void sweepUpstreamEvents() {
    try {
        const auto events = query::upstream::Inbox::sweepFinished(kUpstreamInboxRetention);
        const auto intents = query::upstream::WriteIntent::sweepExpired();
        if (events > 0 || intents > 0)
            log::Registry::vaulthalla()->info("[DBSweeper] Removed {} finished upstream events and {} expired write intents",
                                              events, intents);
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[DBSweeper] Upstream event sweep failed: {}", e.what());
    }
}
}

vh::db::Janitor::Janitor()
    : AsyncService("DBSweeper"),
      sweep_interval_(Registry::get().services.db_sweeper.sweep_interval_minutes) {}

void vh::db::Janitor::runLoop() {
    auto nextDbSweep = std::chrono::steady_clock::now();
    auto nextRecoveryStoreSweep = nextDbSweep;
    while (!shouldStop()) {
        if (std::chrono::steady_clock::now() >= nextDbSweep) {
            try {
                query::sync::Event::purgeOld();
                query::auth::RefreshToken::purgeOldRevoked();
                const auto swept = vh::share::Manager{}.sweepStaleUploads();
                if (swept.failed > 0)
                    log::Registry::vaulthalla()->info("[DBSweeper] Marked {} stale share uploads failed", swept.failed);
                if (const auto expired = protocols::http::upload::resumable::Service::sweepExpired(); expired > 0)
                    log::Registry::vaulthalla()->info("[DBSweeper] Removed {} expired resumable upload session(s)", expired);
            } catch (const std::exception& e) {
                log::Registry::vaulthalla()->warn("[DBSweeper] Failed to run database cleanup: {}", e.what());
            }
            janitor_impl::sweepUpstreamEvents();
            janitor_impl::pruneFsChanges();
            nextDbSweep = std::chrono::steady_clock::now() + sweep_interval_;
        }

        try {
            (void)preview::cache::evictPeriodic();
        } catch (const std::exception& e) {
            log::Registry::vaulthalla()->warn("[DBSweeper] Derived artifact eviction failed: {}", e.what());
        }

        const bool sweepStores = std::chrono::steady_clock::now() >= nextRecoveryStoreSweep;
        janitor_impl::maintainRecovery(sweepStores);
        if (sweepStores) nextRecoveryStoreSweep = std::chrono::steady_clock::now() + janitor_impl::kRecoveryStoreSweepInterval;

        lazySleep(std::min<std::chrono::minutes>(sweep_interval_, janitor_impl::kDerivedCacheInterval));
    }
}
