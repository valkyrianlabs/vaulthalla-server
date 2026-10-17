#include "db/Janitor.hpp"
#include "config/Registry.hpp"
#include "db/query/sync/Event.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/upstream/Inbox.hpp"
#include "db/query/upstream/WriteIntent.hpp"
#include "log/Registry.hpp"
#include "preview/cache/Maintenance.hpp"
#include "recovery/local/Versions.hpp"
#include "share/Manager.hpp"

#include <algorithm>
#include <ctime>

using namespace vh::config;

namespace vh::db::janitor_impl {
// Derived preview artifacts are kept within caching.max_size_mb on a shorter cadence than the DB sweep.
constexpr std::chrono::minutes kDerivedCacheInterval{15};
// Finished upstream events (done/skipped) are kept this long for status and diagnostics (#96).
constexpr std::chrono::hours kUpstreamInboxRetention{24 * 7};

// File recovery: local version retention and the upstream backlog of buckets without history run with the derived
// cache cadence; the recovery store's orphan sweep (crashed captures) runs at startup and then daily.
constexpr std::chrono::hours kRecoveryStoreSweepInterval{24};

void maintainRecovery(const bool sweepStores) {
    try {
        const auto r = vh::recovery::local::versions::maintain(std::time(nullptr), sweepStores);
        if (r.versions_removed || r.backlog_skipped || r.orphans_removed || r.unreferenced_removed)
            log::Registry::vaulthalla()->info(
                "[DBSweeper] Recovery: {} version(s) and {} blob(s) past retention, {} backlog version(s) skipped, "
                "{} orphan blob(s) and {} unreferenced row(s) swept",
                r.versions_removed, r.blobs_removed, r.backlog_skipped, r.orphans_removed, r.unreferenced_removed);
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[DBSweeper] Recovery maintenance failed: {}", e.what());
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
            } catch (const std::exception& e) {
                log::Registry::vaulthalla()->warn("[DBSweeper] Failed to run database cleanup: {}", e.what());
            }
            janitor_impl::sweepUpstreamEvents();
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
