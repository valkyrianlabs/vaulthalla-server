#pragma once

#include "concurrency/ThreadPool.hpp"
#include "log/Registry.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace vh::concurrency {

class ThreadPoolManager {
public:
    struct NamedThreadPoolSnapshot {
        std::string name;
        bool present = false;
        ThreadPool::Snapshot snapshot;
    };

    static ThreadPoolManager& instance() {
        static ThreadPoolManager instance;
        return instance;
    }

    // Startup sizing of the sync pools (config sync.worker_threads, sync.max_concurrent_passes); 0 picks the default.
    // (No member initializers: a default argument of the enclosing class can't use them; `{}` is all zeros.)
    struct Sizing {
        unsigned int syncWorkers;
        unsigned int syncPasses;
    };

    // sync.worker_threads: the workers that run a pass's operations (uploads, downloads, deletes, key-rotation
    // ranges). They wait on the network far more than they compute, so the default is one per CPU core (at least
    // kMinAutoSyncWorkers, at most kMaxAutoSyncWorkers); an explicit value is kept within 1..kMaxSyncWorkers.
    static constexpr unsigned int kMinAutoSyncWorkers = 4, kMaxAutoSyncWorkers = 64, kMaxSyncWorkers = 256;
    [[nodiscard]] static unsigned int syncWorkersFor(const unsigned int configured, const unsigned int cores) {
        if (configured > 0) return std::min(configured, kMaxSyncWorkers);
        return std::clamp(std::max(cores, 1u), kMinAutoSyncWorkers, kMaxAutoSyncWorkers);
    }

    // sync.max_concurrent_passes: passes (regular or scoped) that run at once, on a pool of their own. A pass only
    // waits on its operations, which run on the sync pool, so a pass can never occupy a worker one of its operations
    // (or another pass's) needs. Both used to share one pool: once every worker held a pass waiting on its
    // operations, the operations queued behind them never ran and sync hung for good.
    static constexpr unsigned int kDefaultSyncPasses = 4, kMaxSyncPasses = 64;
    [[nodiscard]] static unsigned int syncPassesFor(const unsigned int configured) {
        return configured > 0 ? std::min(configured, kMaxSyncPasses) : kDefaultSyncPasses;
    }

    void init(const Sizing& sizing = {}) {
        if (running_.exchange(true)) return; // already running

        const unsigned int cores = std::thread::hardware_concurrency();
        totalThreads_ = std::max(
            cores * RESERVE_FACTOR,
            8u // safety floor
        );

        // The general pools share max(cores x 3, 8) evenly, as they always have. The sync pool used to take one share
        // too (6 workers on 12 cores, running passes and their operations alike); it is sized on its own now.
        const unsigned int base = totalThreads_ / NUM_POOLS;
        const unsigned int rem  = totalThreads_ % NUM_POOLS;

        unsigned int fuseN  = base + (rem > 0 ? 1 : 0);
        unsigned int thumbN = base + (rem > 2 ? 1 : 0);
        unsigned int httpN  = base + (rem > 3 ? 1 : 0);
        unsigned int statsN = base + (rem > 4 ? 1 : 0);
        unsigned int s3N    = base + (rem > 5 ? 1 : 0);

        fuse_     = std::make_shared<ThreadPool>(fuseN);
        sync_     = std::make_shared<ThreadPool>(syncWorkersFor(sizing.syncWorkers, cores));
        syncPass_ = std::make_shared<ThreadPool>(syncPassesFor(sizing.syncPasses));
        thumb_    = std::make_shared<ThreadPool>(thumbN);
        http_     = std::make_shared<ThreadPool>(httpN);
        stats_    = std::make_shared<ThreadPool>(statsN);
        s3_       = std::make_shared<ThreadPool>(s3N);
    }

    // Every pool is asked to stop before any is joined, and all joins share one deadline, so shutdown waits for
    // the slowest in-flight task (bounded by `timeout`), never for the sum of the pools.
    void shutdown(const std::chrono::milliseconds timeout = std::chrono::seconds(3)) {
        if (!running_.exchange(false)) return;

        const auto pools = all();
        for (const auto& pool : pools) pool->requestStop();

        const auto deadline = std::chrono::steady_clock::now() + timeout;
        unsigned int detached = 0;
        for (const auto& pool : pools) detached += pool->join(deadline);

        if (detached)
            log::Registry::runtime()->warn("[ThreadPoolManager] {} worker(s) still running a task after {} ms; detached",
                                           detached, timeout.count());
        else log::Registry::runtime()->info("[ThreadPoolManager] Thread pools stopped.");
    }

    std::shared_ptr<ThreadPool>& fusePool() { return fuse_; }
    // A pass's operations (sync::Local::push, key rotation). Never a pass itself: see syncPassPool().
    std::shared_ptr<ThreadPool>& syncPool() { return sync_; }
    // Sync passes (sync::Controller), which wait on futures of syncPool() tasks.
    std::shared_ptr<ThreadPool>& syncPassPool() { return syncPass_; }
    std::shared_ptr<ThreadPool>& thumbPool() { return thumb_; }
    std::shared_ptr<ThreadPool>& httpPool() { return http_; }
    std::shared_ptr<ThreadPool>& statsPool() { return stats_; }
    std::shared_ptr<ThreadPool>& s3Pool() { return s3_; }

    [[nodiscard]] std::vector<NamedThreadPoolSnapshot> snapshotPools() const {
        return {
            namedSnapshot("fuse", fuse_),
            namedSnapshot("sync", sync_),
            namedSnapshot("sync_pass", syncPass_),
            namedSnapshot("thumb", thumb_),
            namedSnapshot("http", http_),
            namedSnapshot("stats", stats_),
            namedSnapshot("s3", s3_)
        };
    }

private:
    ThreadPoolManager() = default;
    ~ThreadPoolManager() { shutdown(); }

    static NamedThreadPoolSnapshot namedSnapshot(
        std::string name,
        const std::shared_ptr<ThreadPool>& pool
    ) {
        if (!pool) return {
            .name = std::move(name),
            .present = false,
            .snapshot = {}
        };
        return {
            .name = std::move(name),
            .present = true,
            .snapshot = pool->snapshot()
        };
    }

    // The general pools' shares: max(cores x RESERVE_FACTOR, 8) / NUM_POOLS each (the sync pool's former share is
    // left unused, so the other pools keep their sizes).
    static constexpr unsigned int RESERVE_FACTOR = 3, NUM_POOLS = 6;
    std::shared_ptr<ThreadPool> fuse_, sync_, syncPass_, thumb_, http_, stats_, s3_;
    std::atomic<bool> running_{false};
    unsigned int totalThreads_{0};

    [[nodiscard]] std::vector<std::shared_ptr<ThreadPool>> all() const {
        std::vector<std::shared_ptr<ThreadPool>> pools;
        for (const auto& pool : {fuse_, syncPass_, sync_, thumb_, http_, stats_, s3_})
            if (pool) pools.push_back(pool);
        return pools;
    }
};

} // namespace vh::concurrency
