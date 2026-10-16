#include "db/Janitor.hpp"
#include "config/Registry.hpp"
#include "db/query/sync/Event.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/upstream/Inbox.hpp"
#include "db/query/upstream/WriteIntent.hpp"
#include "log/Registry.hpp"
#include "preview/cache/Maintenance.hpp"
#include "share/Manager.hpp"

#include <algorithm>

using namespace vh::config;

namespace vh::db::janitor_impl {
// Derived preview artifacts are kept within caching.max_size_mb on a shorter cadence than the DB sweep.
constexpr std::chrono::minutes kDerivedCacheInterval{15};
// Finished upstream events (done/skipped) are kept this long for status and diagnostics (#96).
constexpr std::chrono::hours kUpstreamInboxRetention{24 * 7};

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

        lazySleep(std::min<std::chrono::minutes>(sweep_interval_, janitor_impl::kDerivedCacheInterval));
    }
}
