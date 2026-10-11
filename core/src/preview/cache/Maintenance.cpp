#include "preview/cache/Maintenance.hpp"

#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "preview/cache/Store.hpp"
#include "runtime/Deps.hpp"
#include "stats/model/CacheStats.hpp"
#include "storage/Engine.hpp"
#include "storage/GcmFileReader.hpp"
#include "vault/model/Vault.hpp"

#include <chrono>
#include <exception>
#include <optional>

namespace vh::preview::cache {

void applyConfig() {
    const auto& preview = config::Registry::get().preview;
    storage::setDefaultIntegrityPolicy(preview.media.integrity == config::PreviewIntegrityMode::Strict
                                           ? storage::IntegrityPolicy::Strict
                                           : storage::IntegrityPolicy::Optimistic);
    switch (preview.media.remote) {
        case config::PreviewRemoteMode::Hydrate: storage::setDefaultRemotePolicy(storage::RemoteFetchPolicy::Hydrate); break;
        case config::PreviewRemoteMode::Ranged: storage::setDefaultRemotePolicy(storage::RemoteFetchPolicy::Ranged); break;
        case config::PreviewRemoteMode::Off: storage::setDefaultRemotePolicy(storage::RemoteFetchPolicy::Off); break;
    }
    Store::setFailureTtl(std::chrono::hours(preview.derive.failure_ttl_hours));
    // The preview cache's cap is configured, not measured: report it from boot instead of only after the first
    // periodic eviction (#160). Usage is filled in by Store::evict.
    if (const auto& stats = runtime::Deps::get().httpCacheStats)
        stats->set_capacity(static_cast<uint64_t>(config::Registry::get().caching.max_size_mb) << 20);
}

std::size_t sweepAtStartup(const std::vector<std::shared_ptr<storage::Engine>>& engines) {
    std::size_t total = 0;
    for (const auto& engine : engines) {
        if (!engine || !engine->vault) continue;
        try {
            const auto removed = Store::sweep(engine);
            total += removed;
            if (removed > 0)
                log::Registry::storage()->info("[DerivedStore] Startup sweep of vault {} removed {} stale cache entries",
                                               engine->vault->id, removed);
        } catch (const std::exception& e) {
            log::Registry::storage()->warn("[DerivedStore] Startup sweep of vault {} failed: {}", engine->vault->id,
                                           e.what());
        }
    }
    return total;
}

uint64_t evictPeriodic() {
    // Hits since the last round, so LRU eviction sees them.
    Store::flushTouches();
    const auto& caching = config::Registry::get().caching;
    const auto maxBytes = static_cast<uint64_t>(caching.max_size_mb) << 20;
    std::optional<std::chrono::seconds> maxIdle;
    if (caching.thumbnails.expiry_days > 0) maxIdle = std::chrono::days(caching.thumbnails.expiry_days);
    const auto freed = Store::evict(maxBytes, maxIdle);
    if (freed > 0)
        log::Registry::storage()->info("[DerivedStore] Evicted {} bytes of derived artifacts (cap {} MiB)", freed,
                                       caching.max_size_mb);
    return freed;
}

}
