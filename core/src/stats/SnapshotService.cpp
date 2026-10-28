#include "stats/SnapshotService.hpp"

#include "config/Registry.hpp"
#include "db/query/stats/DbStats.hpp"
#include "db/query/stats/MetricSamples.hpp"
#include "db/query/stats/OperationStats.hpp"
#include "db/query/stats/RetentionStats.hpp"
#include "db/query/stats/Snapshot.hpp"
#include "db/query/sync/Stats.hpp"
#include "db/query/vault/Activity.hpp"
#include "db/query/vault/Recovery.hpp"
#include "fs/cache/Registry.hpp"
#include "log/Registry.hpp"
#include "nlohmann/json.hpp"
#include "runtime/Deps.hpp"
#include "stats/model/CacheStats.hpp"
#include "stats/model/ConnectionStats.hpp"
#include "stats/model/DbStats.hpp"
#include "stats/model/FuseStats.hpp"
#include "stats/model/OperationStats.hpp"
#include "stats/model/RetentionStats.hpp"
#include "stats/model/StorageBackendStats.hpp"
#include "stats/model/ThreadPoolStats.hpp"
#include "stats/model/VaultActivity.hpp"
#include "stats/model/VaultRecovery.hpp"
#include "stats/model/VaultSyncHealth.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Capacity.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <limits>
#include <map>
#include <optional>
#include <string>

namespace vh::stats {

namespace {

std::uint64_t statsSnapshotServiceUnixTimestamp() {
    return static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

template <typename Func>
void snapshotServiceTry(const char* label, Func&& func) {
    try {
        func();
    } catch (const std::exception& e) {
        log::Registry::runtime()->warn("[StatsSnapshotService] {} snapshot failed: {}", label, e.what());
    }
}

std::chrono::seconds snapshotServiceSeconds(const std::uint32_t seconds) {
    return std::chrono::seconds(std::max<std::uint32_t>(1, seconds));
}

std::chrono::seconds snapshotObservationSeconds(const std::uint32_t seconds) {
    return std::chrono::seconds(std::clamp<std::uint32_t>(seconds, 1, 60));
}

template <typename T>
std::optional<double> optionalAsDouble(const std::optional<T>& value) {
    if (!value) return std::nullopt;
    return static_cast<double>(*value);
}

}

namespace detail {

struct DoubleWindowGauge {
    std::uint32_t count = 0;
    double min = 0.0;
    double max = 0.0;
    double sum = 0.0;
    double last = 0.0;

    void observe(const double value) {
        if (count == 0) {
            min = value;
            max = value;
        } else {
            min = std::min(min, value);
            max = std::max(max, value);
        }
        sum += value;
        last = value;
        ++count;
    }

    [[nodiscard]] double avg() const { return count == 0 ? 0.0 : sum / static_cast<double>(count); }
};

struct UIntWindowGauge {
    std::uint32_t count = 0;
    std::uint64_t min = 0;
    std::uint64_t max = 0;
    long double sum = 0.0L;
    std::uint64_t last = 0;

    void observe(const std::uint64_t value) {
        if (count == 0) {
            min = value;
            max = value;
        } else {
            min = std::min(min, value);
            max = std::max(max, value);
        }
        sum += static_cast<long double>(value);
        last = value;
        ++count;
    }

    [[nodiscard]] double avg() const { return count == 0 ? 0.0 : static_cast<double>(sum / static_cast<long double>(count)); }
};

struct ThreadPoolWindowStats {
    DoubleWindowGauge pressure;
    UIntWindowGauge queueDepth;
    UIntWindowGauge busyWorkers;
    UIntWindowGauge idleWorkers;
    std::uint32_t pressuredSamples = 0;
    std::uint32_t saturatedSamples = 0;
    std::string lastStatus = "unknown";

    void observe(const model::ThreadPoolSnapshot& pool) {
        pressure.observe(pool.pressureRatio);
        queueDepth.observe(pool.queueDepth);
        busyWorkers.observe(pool.busyWorkerCount);
        idleWorkers.observe(pool.idleWorkerCount);
        lastStatus = pool.status;
        if (pool.status == "pressured") ++pressuredSamples;
        if (pool.status == "saturated") ++saturatedSamples;
    }
};

struct CacheWindowStats {
    DoubleWindowGauge occupancy;
    UIntWindowGauge usedBytes;

    void observe(const model::CacheStatsSnapshot& stats) {
        const auto ratio = stats.capacity_bytes > 0
            ? static_cast<double>(stats.used_bytes) / static_cast<double>(stats.capacity_bytes)
            : 0.0;
        occupancy.observe(ratio);
        usedBytes.observe(stats.used_bytes);
    }
};

}

namespace {

std::string normalizeThreadPoolStatus(const std::string& status) {
    if (status == "healthy") return "normal";
    if (status == "idle" || status == "normal" || status == "pressured" || status == "saturated" || status == "degraded")
        return status;
    return "unknown";
}

model::ThreadPoolSnapshot aggregateThreadPoolSnapshot(const model::ThreadPoolManagerSnapshot& snapshot) {
    std::uint32_t busy = 0;
    for (const auto& pool : snapshot.pools) busy += pool.busyWorkerCount;

    return {
        .name = "__aggregate__",
        .queueDepth = snapshot.totalQueueDepth,
        .workerCount = snapshot.totalWorkerCount,
        .idleWorkerCount = snapshot.totalIdleWorkerCount,
        .busyWorkerCount = busy,
        .hasIdleWorker = snapshot.totalIdleWorkerCount > 0,
        .stopped = false,
        .pressureRatio = snapshot.maxPressureRatio,
        .status = normalizeThreadPoolStatus(snapshot.overallStatus)
    };
}

template <typename T>
std::uint64_t counterDelta(const T current, const T previous, bool& reset) {
    if (current < previous) {
        reset = true;
        return 0;
    }
    return static_cast<std::uint64_t>(current - previous);
}

std::map<std::string, model::FuseOpStatsSnapshot> fuseOpsByName(const model::FuseStatsSnapshot& snapshot) {
    std::map<std::string, model::FuseOpStatsSnapshot> out;
    for (const auto& op : snapshot.ops) out[op.op] = op;
    return out;
}

double readinessValue(const std::string& value) {
    if (value == "ready" || value == "healthy" || value == "success") return 1.0;
    if (value == "syncing" || value == "stale" || value == "warning") return 0.5;
    if (value == "disabled" || value == "unknown") return 0.0;
    return 0.0;
}

void addMetricSample(
    db::query::stats::SampleBatch& batch,
    const std::string& scope,
    const std::optional<std::uint32_t> vaultId,
    const std::string& metricKey,
    const std::string& seriesLabel,
    const std::string& unit,
    const std::string& snapshotType,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds,
    const std::optional<double> value,
    const std::string& seriesKey = "",
    const nlohmann::json& tags = nlohmann::json::object()
) {
    if (!value) return;
    batch.metrics.push_back({
        .scope = scope,
        .vaultId = vaultId,
        .metricKey = metricKey,
        .seriesKey = seriesKey,
        .seriesLabel = seriesLabel,
        .unit = unit,
        .snapshotType = snapshotType,
        .windowStart = windowStart,
        .windowEnd = windowEnd,
        .windowSeconds = windowSeconds,
        .sampleCount = 1,
        .valueMin = value,
        .valueAvg = value,
        .valueMax = value,
        .valueLast = value,
        .deltaValue = std::nullopt,
        .ratePerSecond = std::nullopt,
        .tags = tags.is_object() ? tags : nlohmann::json::object(),
    });
}

void addSystemMetric(
    db::query::stats::SampleBatch& batch,
    const std::string& metricKey,
    const std::string& seriesLabel,
    const std::string& unit,
    const std::string& snapshotType,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds,
    const std::optional<double> value,
    const std::string& seriesKey = "",
    const nlohmann::json& tags = nlohmann::json::object()
) {
    addMetricSample(
        batch,
        "system",
        std::nullopt,
        metricKey,
        seriesLabel,
        unit,
        snapshotType,
        windowStart,
        windowEnd,
        windowSeconds,
        value,
        seriesKey,
        tags
    );
}

void addVaultMetric(
    db::query::stats::SampleBatch& batch,
    const std::uint32_t vaultId,
    const std::string& metricKey,
    const std::string& seriesLabel,
    const std::string& unit,
    const std::string& snapshotType,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds,
    const std::optional<double> value,
    const std::string& seriesKey = "",
    const nlohmann::json& tags = nlohmann::json::object()
) {
    addMetricSample(
        batch,
        "vault",
        vaultId,
        metricKey,
        seriesLabel,
        unit,
        snapshotType,
        windowStart,
        windowEnd,
        windowSeconds,
        value,
        seriesKey,
        tags
    );
}

}

namespace detail {

struct RuntimeWindowAccumulator {
    bool active = false;
    std::uint64_t windowStartUnix = 0;
    std::chrono::steady_clock::time_point windowStartSteady{};
    std::map<std::string, ThreadPoolWindowStats> threadPools;
    std::map<std::string, CacheWindowStats> caches;
    std::optional<model::FuseStatsSnapshot> fuseBaseline;
    std::optional<model::CacheStatsSnapshot> fsCacheBaseline;
    std::optional<model::CacheStatsSnapshot> httpCacheBaseline;

    void begin(const std::chrono::steady_clock::time_point steadyNow) {
        active = true;
        windowStartSteady = steadyNow;
        windowStartUnix = statsSnapshotServiceUnixTimestamp();
        threadPools.clear();
        caches.clear();
        captureBaselines();
        observe();
    }

    void captureBaselines() {
        const auto& deps = runtime::Deps::get();
        fuseBaseline = deps.fuseStats ? std::optional<model::FuseStatsSnapshot>(deps.fuseStats->snapshot()) : std::nullopt;
        if (deps.fsCache) {
            const auto stats = deps.fsCache->stats();
            fsCacheBaseline = stats ? std::optional<model::CacheStatsSnapshot>(*stats) : std::nullopt;
        } else {
            fsCacheBaseline = std::nullopt;
        }
        httpCacheBaseline = deps.httpCacheStats
            ? std::optional<model::CacheStatsSnapshot>(deps.httpCacheStats->snapshot())
            : std::nullopt;
    }

    void observe() {
        const auto pools = model::ThreadPoolManagerSnapshot::snapshot();
        threadPools["__aggregate__"].observe(aggregateThreadPoolSnapshot(pools));
        for (const auto& pool : pools.pools) threadPools[pool.name].observe(pool);

        const auto& deps = runtime::Deps::get();
        if (deps.fsCache) {
            const auto stats = deps.fsCache->stats();
            if (stats) caches["fs"].observe(*stats);
        }
        if (deps.httpCacheStats) caches["http"].observe(deps.httpCacheStats->snapshot());
    }

    [[nodiscard]] std::uint32_t elapsedWindowSeconds(const std::chrono::steady_clock::time_point steadyNow) const {
        const auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(steadyNow - windowStartSteady).count();
        return static_cast<std::uint32_t>(std::max<long long>(1, elapsed));
    }

    void appendThreadPoolSamples(
        db::query::stats::SampleBatch& batch,
        const std::uint64_t windowEnd,
        const std::uint32_t windowSeconds
    ) const {
        for (const auto& [poolName, stats] : threadPools) {
            if (stats.pressure.count == 0) continue;
            batch.threadPools.push_back({
                .poolName = poolName,
                .windowStart = windowStartUnix,
                .windowEnd = windowEnd,
                .windowSeconds = windowSeconds,
                .sampleCount = stats.pressure.count,
                .pressureMin = stats.pressure.min,
                .pressureAvg = stats.pressure.avg(),
                .pressureMax = stats.pressure.max,
                .pressureLast = stats.pressure.last,
                .queueDepthMin = stats.queueDepth.min,
                .queueDepthAvg = stats.queueDepth.avg(),
                .queueDepthMax = stats.queueDepth.max,
                .queueDepthLast = stats.queueDepth.last,
                .busyWorkersMin = static_cast<std::uint32_t>(stats.busyWorkers.min),
                .busyWorkersAvg = stats.busyWorkers.avg(),
                .busyWorkersMax = static_cast<std::uint32_t>(stats.busyWorkers.max),
                .busyWorkersLast = static_cast<std::uint32_t>(stats.busyWorkers.last),
                .idleWorkersMin = static_cast<std::uint32_t>(stats.idleWorkers.min),
                .idleWorkersAvg = stats.idleWorkers.avg(),
                .idleWorkersMax = static_cast<std::uint32_t>(stats.idleWorkers.max),
                .idleWorkersLast = static_cast<std::uint32_t>(stats.idleWorkers.last),
                .pressuredSampleCount = stats.pressuredSamples,
                .saturatedSampleCount = stats.saturatedSamples,
                .queueDepthHighWater = stats.queueDepth.max,
                .pressureHighWater = stats.pressure.max,
                .lastStatus = normalizeThreadPoolStatus(stats.lastStatus),
            });
        }
    }

    void appendFuseSamples(
        db::query::stats::SampleBatch& batch,
        const std::uint64_t windowEnd,
        const std::uint32_t windowSeconds
    ) const {
        const auto& deps = runtime::Deps::get();
        if (!deps.fuseStats || !fuseBaseline) return;

        const auto current = deps.fuseStats->snapshot();
        const auto previousByOp = fuseOpsByName(*fuseBaseline);

        for (const auto& op : current.ops) {
            const auto previousIt = previousByOp.find(op.op);
            const model::FuseOpStatsSnapshot previous = previousIt == previousByOp.end()
                ? model::FuseOpStatsSnapshot{.op = op.op}
                : previousIt->second;

            bool reset = false;
            const auto countDelta = counterDelta(op.count, previous.count, reset);
            const auto successDelta = counterDelta(op.successes, previous.successes, reset);
            const auto errorDelta = counterDelta(op.errors, previous.errors, reset);
            const auto expectedErrorDelta = counterDelta(op.expectedErrors, previous.expectedErrors, reset);
            const auto alertableErrorDelta = counterDelta(op.alertableErrors, previous.alertableErrors, reset);
            const auto readBytesDelta = counterDelta(op.bytesRead, previous.bytesRead, reset);
            const auto writeBytesDelta = counterDelta(op.bytesWritten, previous.bytesWritten, reset);
            const auto totalUsDelta = counterDelta(op.totalUs, previous.totalUs, reset);

            const auto errorRate = !reset && countDelta > 0
                ? std::optional<double>(static_cast<double>(errorDelta) / static_cast<double>(countDelta))
                : std::nullopt;
            const auto expectedErrorRate = !reset && countDelta > 0
                ? std::optional<double>(static_cast<double>(expectedErrorDelta) / static_cast<double>(countDelta))
                : std::nullopt;
            const auto alertableErrorRate = !reset && countDelta > 0
                ? std::optional<double>(static_cast<double>(alertableErrorDelta) / static_cast<double>(countDelta))
                : std::nullopt;
            const auto avgLatencyMs = !reset && countDelta > 0
                ? std::optional<double>((static_cast<double>(totalUsDelta) / 1000.0) / static_cast<double>(countDelta))
                : std::nullopt;
            const auto maxLatencyMs = !reset && countDelta > 0
                ? std::optional<double>(op.maxMs)
                : std::nullopt;

            batch.fuseOps.push_back({
                .op = op.op,
                .windowStart = windowStartUnix,
                .windowEnd = windowEnd,
                .windowSeconds = windowSeconds,
                .countDelta = reset ? 0 : countDelta,
                .successDelta = reset ? 0 : successDelta,
                .errorDelta = reset ? 0 : errorDelta,
                .expectedErrorDelta = reset ? 0 : expectedErrorDelta,
                .alertableErrorDelta = reset ? 0 : alertableErrorDelta,
                .errorRate = errorRate,
                .expectedErrorRate = expectedErrorRate,
                .alertableErrorRate = alertableErrorRate,
                .readBytesDelta = reset ? 0 : readBytesDelta,
                .writeBytesDelta = reset ? 0 : writeBytesDelta,
                .avgLatencyMs = avgLatencyMs,
                .maxLatencyMs = maxLatencyMs,
                .counterReset = reset,
            });
        }
    }

    void appendCacheSample(
        db::query::stats::SampleBatch& batch,
        const std::string& source,
        const std::optional<model::CacheStatsSnapshot>& baseline,
        const model::CacheStatsSnapshot& current,
        const std::uint64_t windowEnd,
        const std::uint32_t windowSeconds
    ) const {
        const auto cacheIt = caches.find(source);
        const auto emptyCacheWindow = CacheWindowStats{};
        const auto& gauge = cacheIt == caches.end() ? emptyCacheWindow : cacheIt->second;

        bool reset = false;
        const auto previous = baseline.value_or(model::CacheStatsSnapshot{});
        const auto hitDelta = counterDelta(current.hits, previous.hits, reset);
        const auto missDelta = counterDelta(current.misses, previous.misses, reset);
        const auto evictionDelta = counterDelta(current.evictions, previous.evictions, reset);
        const auto insertDelta = counterDelta(current.inserts, previous.inserts, reset);
        const auto invalidationDelta = counterDelta(current.invalidations, previous.invalidations, reset);
        const auto bytesReadDelta = counterDelta(current.bytes_read, previous.bytes_read, reset);
        const auto bytesWrittenDelta = counterDelta(current.bytes_written, previous.bytes_written, reset);
        const auto opCountDelta = counterDelta(current.op_count, previous.op_count, reset);
        const auto opTotalUsDelta = counterDelta(current.op_total_us, previous.op_total_us, reset);

        const auto requests = hitDelta + missDelta;
        const auto hitRate = !reset && requests > 0
            ? std::optional<double>(static_cast<double>(hitDelta) / static_cast<double>(requests))
            : std::nullopt;
        const auto avgLatencyMs = !reset && opCountDelta > 0
            ? std::optional<double>((static_cast<double>(opTotalUsDelta) / 1000.0) / static_cast<double>(opCountDelta))
            : std::nullopt;
        const auto maxLatencyMs = !reset && opCountDelta > 0
            ? std::optional<double>(model::CacheStats::max_op_ms(current))
            : std::nullopt;

        batch.caches.push_back({
            .source = source,
            .windowStart = windowStartUnix,
            .windowEnd = windowEnd,
            .windowSeconds = windowSeconds,
            .sampleCount = gauge.occupancy.count,
            .hitDelta = reset ? 0 : hitDelta,
            .missDelta = reset ? 0 : missDelta,
            .evictionDelta = reset ? 0 : evictionDelta,
            .insertDelta = reset ? 0 : insertDelta,
            .invalidationDelta = reset ? 0 : invalidationDelta,
            .hitRate = hitRate,
            .bytesReadDelta = reset ? 0 : bytesReadDelta,
            .bytesWrittenDelta = reset ? 0 : bytesWrittenDelta,
            .occupancyMin = gauge.occupancy.min,
            .occupancyAvg = gauge.occupancy.avg(),
            .occupancyMax = gauge.occupancy.max,
            .occupancyLast = gauge.occupancy.last,
            .usedBytesMin = gauge.usedBytes.min,
            .usedBytesAvg = gauge.usedBytes.avg(),
            .usedBytesMax = gauge.usedBytes.max,
            .usedBytesLast = gauge.usedBytes.last,
            .opCountDelta = reset ? 0 : opCountDelta,
            .avgLatencyMs = avgLatencyMs,
            .maxLatencyMs = maxLatencyMs,
            .counterReset = reset,
        });
    }

    void appendCacheSamples(
        db::query::stats::SampleBatch& batch,
        const std::uint64_t windowEnd,
        const std::uint32_t windowSeconds
    ) const {
        const auto& deps = runtime::Deps::get();
        if (deps.fsCache) {
            const auto current = deps.fsCache->stats();
            if (current) appendCacheSample(batch, "fs", fsCacheBaseline, *current, windowEnd, windowSeconds);
        }
        if (deps.httpCacheStats) {
            appendCacheSample(batch, "http", httpCacheBaseline, deps.httpCacheStats->snapshot(), windowEnd, windowSeconds);
        }
    }

    db::query::stats::SampleBatch flush(const std::chrono::steady_clock::time_point steadyNow) {
        observe();

        db::query::stats::SampleBatch batch;
        const auto windowEnd = statsSnapshotServiceUnixTimestamp();
        const auto windowSeconds = elapsedWindowSeconds(steadyNow);

        appendThreadPoolSamples(batch, windowEnd, windowSeconds);
        appendFuseSamples(batch, windowEnd, windowSeconds);
        appendCacheSamples(batch, windowEnd, windowSeconds);

        active = false;
        return batch;
    }
};

}

namespace {

void addDbMetrics(
    db::query::stats::SampleBatch& batch,
    const model::DbStats& stats,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds
) {
    addSystemMetric(batch, "db_size_bytes", "Database size", "bytes", "system.db", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.dbSizeBytes));
    addSystemMetric(batch, "db_connections_total", "DB connections", "count", "system.db", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.connectionsTotal));
    addSystemMetric(batch, "db_connections_active", "DB active connections", "count", "system.db", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.connectionsActive));
    addSystemMetric(batch, "db_cache_hit_ratio", "DB cache hit rate", "ratio", "system.db", windowStart, windowEnd, windowSeconds, stats.cacheHitRatio);
    addSystemMetric(batch, "db_deadlocks_total", "DB deadlocks", "count", "system.db", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.deadlocks));
    addSystemMetric(batch, "db_temp_bytes_total", "DB temp bytes", "bytes", "system.db", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.tempBytes));
    addSystemMetric(batch, "db_oldest_transaction_age_seconds", "DB oldest transaction", "seconds", "system.db", windowStart, windowEnd, windowSeconds, optionalAsDouble(stats.oldestTransactionAgeSeconds));
    addSystemMetric(batch, "db_slow_queries", "DB slow queries", "count", "system.db", windowStart, windowEnd, windowSeconds, optionalAsDouble(stats.slowQueryCount));
    if (stats.connectionsMax && *stats.connectionsMax > 0) {
        addSystemMetric(
            batch,
            "db_connection_pressure",
            "DB connection pressure",
            "ratio",
            "system.db",
            windowStart,
            windowEnd,
            windowSeconds,
            static_cast<double>(stats.connectionsTotal) / static_cast<double>(*stats.connectionsMax)
        );
    }
}

void addOperationMetrics(
    db::query::stats::SampleBatch& batch,
    const model::OperationStats& stats,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds
) {
    addSystemMetric(batch, "operations_pending", "Queued operations", "count", "system.operations", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.pendingOperations));
    addSystemMetric(batch, "operations_in_progress", "In-progress operations", "count", "system.operations", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.inProgressOperations));
    addSystemMetric(batch, "operations_stalled", "Stalled operations", "count", "system.operations", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.stalledOperations + stats.stalledShareUploads));
    addSystemMetric(batch, "operations_failed_24h", "Failed operations 24h", "count", "system.operations", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.failedOperations24h + stats.failedShareUploads24h));
    addSystemMetric(batch, "share_uploads_active", "Active share uploads", "count", "system.operations", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.activeShareUploads));
    addSystemMetric(batch, "share_uploads_stalled", "Stalled share uploads", "count", "system.operations", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.stalledShareUploads));
    addSystemMetric(batch, "operations_oldest_pending_age_seconds", "Oldest pending operation", "seconds", "system.operations", windowStart, windowEnd, windowSeconds, optionalAsDouble(stats.oldestPendingOperationAgeSeconds));
    addSystemMetric(batch, "operations_oldest_active_age_seconds", "Oldest active operation", "seconds", "system.operations", windowStart, windowEnd, windowSeconds, optionalAsDouble(stats.oldestInProgressOperationAgeSeconds));
    if (stats.uploadBytesExpectedActive > 0) {
        addSystemMetric(
            batch,
            "share_upload_progress",
            "Share upload progress",
            "ratio",
            "system.operations",
            windowStart,
            windowEnd,
            windowSeconds,
            static_cast<double>(stats.uploadBytesReceivedActive) / static_cast<double>(stats.uploadBytesExpectedActive)
        );
    }
}

void addConnectionMetrics(
    db::query::stats::SampleBatch& batch,
    const model::ConnectionStats& stats,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds
) {
    addSystemMetric(batch, "connections_active_ws", "Active websocket sessions", "count", "system.connections", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.activeWsSessionsTotal));
    addSystemMetric(batch, "connections_human", "Human sessions", "count", "system.connections", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.activeHumanSessions));
    addSystemMetric(batch, "connections_share", "Share sessions", "count", "system.connections", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.activeShareSessions + stats.activeSharePendingSessions));
    addSystemMetric(batch, "connections_unauthenticated", "Unauthenticated sessions", "count", "system.connections", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.activeUnauthenticatedSessions));
    addSystemMetric(batch, "connections_oldest_session_age_seconds", "Oldest websocket session", "seconds", "system.connections", windowStart, windowEnd, windowSeconds, optionalAsDouble(stats.oldestSessionAgeSeconds));
    addSystemMetric(batch, "connections_oldest_unauthenticated_age_seconds", "Oldest unauthenticated session", "seconds", "system.connections", windowStart, windowEnd, windowSeconds, optionalAsDouble(stats.oldestUnauthenticatedSessionAgeSeconds));
}

void addStorageMetrics(
    db::query::stats::SampleBatch& batch,
    const model::StorageBackendStats& stats,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds
) {
    addSystemMetric(batch, "storage_vaults_total", "Vaults", "count", "system.storage", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.vaultCountTotal));
    addSystemMetric(batch, "storage_vaults_active", "Active vaults", "count", "system.storage", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.activeVaultCount));
    addSystemMetric(batch, "storage_vaults_degraded", "Degraded vaults", "count", "system.storage", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.degradedVaultCount));
    addSystemMetric(batch, "storage_vaults_error", "Error vaults", "count", "system.storage", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.errorVaultCount));

    for (const auto& vault : stats.vaults) {
        if (vault.vaultId == 0) continue;
        addVaultMetric(batch, vault.vaultId, "storage_free_space_bytes", "Free space", "bytes", "vault.storage", windowStart, windowEnd, windowSeconds, optionalAsDouble(vault.freeSpaceBytes));
        addVaultMetric(batch, vault.vaultId, "storage_vault_size_bytes", "Vault size", "bytes", "vault.storage", windowStart, windowEnd, windowSeconds, optionalAsDouble(vault.vaultSizeBytes));
        addVaultMetric(batch, vault.vaultId, "storage_cache_size_bytes", "Cache size", "bytes", "vault.storage", windowStart, windowEnd, windowSeconds, optionalAsDouble(vault.cacheSizeBytes));
        addVaultMetric(batch, vault.vaultId, "storage_backend_ready", "Storage backend ready", "ratio", "vault.storage", windowStart, windowEnd, windowSeconds, vault.backendStatus == "healthy" ? 1.0 : 0.0);
    }
}

void addRetentionMetrics(
    db::query::stats::SampleBatch& batch,
    const model::RetentionStats& stats,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds
) {
    const auto vaultId = stats.vaultId;
    auto add = [&](const std::string& key, const std::string& label, const std::string& unit, const std::optional<double> value) {
        if (vaultId) addVaultMetric(batch, *vaultId, key, label, unit, "vault.retention", windowStart, windowEnd, windowSeconds, value);
        else addSystemMetric(batch, key, label, unit, "system.retention", windowStart, windowEnd, windowSeconds, value);
    };

    add("retention_trash_count", "Trash count", "count", static_cast<double>(stats.trashedFilesCount));
    add("retention_trash_bytes", "Trash bytes", "bytes", static_cast<double>(stats.trashedBytesTotal));
    add("retention_trash_overdue_count", "Overdue trash", "count", static_cast<double>(stats.trashedFilesPastRetentionCount));
    add("retention_trash_overdue_bytes", "Overdue trash bytes", "bytes", static_cast<double>(stats.trashedBytesPastRetention));
    add("retention_sync_backlog", "Sync event backlog", "count", static_cast<double>(stats.syncEventsPastRetentionCount));
    add("retention_audit_backlog", "Audit backlog", "count", static_cast<double>(stats.auditLogEntriesPastRetentionCount));
    add("retention_share_access_events", "Share access events", "count", static_cast<double>(stats.shareAccessEventsTotal));
    add("retention_cache_expired", "Expired cache entries", "count", static_cast<double>(stats.cacheEntriesExpired));
    add("retention_cache_bytes", "Cache bytes", "bytes", static_cast<double>(stats.cacheBytesTotal));
    add("retention_oldest_trash_age_seconds", "Oldest trash age", "seconds", optionalAsDouble(stats.oldestTrashedAgeSeconds));
    add("retention_oldest_audit_age_seconds", "Oldest audit age", "seconds", optionalAsDouble(stats.oldestAuditLogAgeSeconds));
    add("retention_oldest_share_event_age_seconds", "Oldest share event age", "seconds", optionalAsDouble(stats.oldestShareAccessEventAgeSeconds));
}

void addVaultCapacityMetrics(
    db::query::stats::SampleBatch& batch,
    const std::uint32_t vaultId,
    const vault::model::Capacity& capacity,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds
) {
    addVaultMetric(batch, vaultId, "capacity_logical_size", "Logical size", "bytes", "vault.capacity", windowStart, windowEnd, windowSeconds, static_cast<double>(capacity.logical_size));
    addVaultMetric(batch, vaultId, "capacity_physical_size", "Physical size", "bytes", "vault.capacity", windowStart, windowEnd, windowSeconds, static_cast<double>(capacity.physical_size));
    addVaultMetric(batch, vaultId, "capacity_file_count", "Files", "count", "vault.capacity", windowStart, windowEnd, windowSeconds, static_cast<double>(capacity.file_count));
}

void addVaultSyncMetrics(
    db::query::stats::SampleBatch& batch,
    const model::VaultSyncHealth& stats,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds
) {
    const auto vaultId = stats.vaultId;
    addVaultMetric(batch, vaultId, "sync_health", "Sync health", "ratio", "vault.sync", windowStart, windowEnd, windowSeconds, readinessValue(model::to_string(stats.overallStatus)));
    addVaultMetric(batch, vaultId, "sync_active_runs", "Active sync runs", "count", "vault.sync", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.activeRunCount));
    addVaultMetric(batch, vaultId, "sync_stalled_runs", "Stalled sync runs", "count", "vault.sync", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.stalledRunCount));
    addVaultMetric(batch, vaultId, "sync_errors_24h", "Sync errors 24h", "count", "vault.sync", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.errorCount24h));
    addVaultMetric(batch, vaultId, "sync_failed_ops_24h", "Failed sync ops 24h", "count", "vault.sync", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.failedOps24h));
    addVaultMetric(batch, vaultId, "sync_bytes_24h", "Sync bytes 24h", "bytes", "vault.sync", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.bytesTotal24h));
    addVaultMetric(batch, vaultId, "sync_conflicts_open", "Open sync conflicts", "count", "vault.sync", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.conflictCountOpen));
    addVaultMetric(batch, vaultId, "sync_oldest_active_age_seconds", "Oldest active sync", "seconds", "vault.sync", windowStart, windowEnd, windowSeconds, optionalAsDouble(stats.oldestActiveAgeSeconds));
}

void addVaultActivityMetrics(
    db::query::stats::SampleBatch& batch,
    const std::uint32_t vaultId,
    const model::VaultActivity& stats,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds
) {
    const auto mutations = stats.uploads24h + stats.deletes24h + stats.renames24h + stats.moves24h + stats.copies24h + stats.restores24h;
    addVaultMetric(batch, vaultId, "activity_mutations_24h", "Mutations 24h", "count", "vault.activity", windowStart, windowEnd, windowSeconds, static_cast<double>(mutations));
    addVaultMetric(batch, vaultId, "activity_bytes_added_24h", "Bytes added 24h", "bytes", "vault.activity", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.bytesAdded24h));
    addVaultMetric(batch, vaultId, "activity_bytes_removed_24h", "Bytes removed 24h", "bytes", "vault.activity", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.bytesRemoved24h));
}

void addVaultRecoveryMetrics(
    db::query::stats::SampleBatch& batch,
    const model::VaultRecovery& stats,
    const std::uint64_t windowStart,
    const std::uint64_t windowEnd,
    const std::uint32_t windowSeconds
) {
    const auto vaultId = stats.vaultId;
    addVaultMetric(batch, vaultId, "recovery_backup_policy_present", "Backup policy present", "ratio", "vault.recovery", windowStart, windowEnd, windowSeconds, stats.backupPolicyPresent ? 1.0 : 0.0);
    addVaultMetric(batch, vaultId, "recovery_backup_enabled", "Backup enabled", "ratio", "vault.recovery", windowStart, windowEnd, windowSeconds, stats.backupEnabled ? 1.0 : 0.0);
    addVaultMetric(batch, vaultId, "recovery_readiness", "Recovery readiness", "ratio", "vault.recovery", windowStart, windowEnd, windowSeconds, readinessValue(stats.recoveryReadiness));
    addVaultMetric(batch, vaultId, "recovery_last_success_age_seconds", "Backup last success age", "seconds", "vault.recovery", windowStart, windowEnd, windowSeconds, optionalAsDouble(stats.lastSuccessAgeSeconds));
    addVaultMetric(batch, vaultId, "recovery_missed_backup_count", "Missed backups", "count", "vault.recovery", windowStart, windowEnd, windowSeconds, optionalAsDouble(stats.missedBackupCountEstimate));
    addVaultMetric(batch, vaultId, "recovery_retry_count", "Backup retries", "count", "vault.recovery", windowStart, windowEnd, windowSeconds, static_cast<double>(stats.retryCount));
}

}

SnapshotService::SnapshotService()
    : AsyncService("StatsSnapshotService") {}

void SnapshotService::runLoop() {
    using Clock = std::chrono::steady_clock;

    lastRuntimeCollection_ = Clock::time_point::min();
    lastVaultCollection_ = Clock::time_point::min();
    lastPurge_ = Clock::time_point::min();

    detail::RuntimeWindowAccumulator accumulator;

    while (!shouldStop()) {
        const auto& config = config::Registry::get().stats_snapshots;

        if (!config.enabled) {
            accumulator.active = false;
            lazySleep(std::chrono::seconds(60));
            continue;
        }

        const auto now = Clock::now();
        const auto runtimeInterval = std::chrono::seconds(60);
        const auto vaultInterval = snapshotServiceSeconds(config.vault_interval_seconds);
        const auto observeInterval = snapshotObservationSeconds(config.gauge_observation_interval_seconds);

        if (!accumulator.active) {
            accumulator.begin(now);
            lastRuntimeCollection_ = now;
        } else {
            accumulator.observe();
        }

        if (now - accumulator.windowStartSteady >= runtimeInterval) {
            collectRuntimeSnapshots(accumulator);
            accumulator.begin(Clock::now());
            lastRuntimeCollection_ = now;
        }

        if (lastVaultCollection_ == Clock::time_point::min() || now - lastVaultCollection_ >= vaultInterval) {
            collectVaultSnapshots();
            lastVaultCollection_ = now;
        }

        if (lastPurge_ == Clock::time_point::min() || now - lastPurge_ >= std::chrono::hours(24)) {
            purgeOldSnapshots();
            lastPurge_ = now;
        }

        const auto sleepFor = std::min<std::chrono::seconds>(observeInterval, std::chrono::seconds(60));
        lazySleep(sleepFor);
    }
}

void SnapshotService::collectRuntimeSnapshots(detail::RuntimeWindowAccumulator& accumulator) {
    auto& deps = runtime::Deps::get();
    auto batch = accumulator.flush(std::chrono::steady_clock::now());
    const auto windowStart = accumulator.windowStartUnix;
    const auto windowEnd = statsSnapshotServiceUnixTimestamp();
    const auto windowSeconds = std::max<std::uint32_t>(1, static_cast<std::uint32_t>(windowEnd > windowStart ? windowEnd - windowStart : 1));

    snapshotServiceTry("system.threadpools", [] {
        db::query::stats::Snapshot::insertSystem(
            "system.threadpools",
            nlohmann::json(model::ThreadPoolManagerSnapshot::snapshot())
        );
    });

    snapshotServiceTry("system.fuse", [&deps] {
        if (!deps.fuseStats) return;
        db::query::stats::Snapshot::insertSystem("system.fuse", nlohmann::json(deps.fuseStats->snapshot()));
    });

    snapshotServiceTry("system.cache", [&deps] {
        nlohmann::json payload = {
            {"checked_at", statsSnapshotServiceUnixTimestamp()},
        };

        if (deps.fsCache) {
            const auto fsStats = deps.fsCache->stats();
            payload["fs"] = fsStats ? nlohmann::json(*fsStats) : nlohmann::json(nullptr);
        }

        if (deps.httpCacheStats) {
            payload["http"] = nlohmann::json(*deps.httpCacheStats);
        }

        if (payload.contains("fs") || payload.contains("http"))
            db::query::stats::Snapshot::insertSystem("system.cache", payload);
    });

    snapshotServiceTry("system.db", [] {
        const auto stats = db::query::stats::DbStats::snapshot();
        if (stats) db::query::stats::Snapshot::insertSystem("system.db", nlohmann::json(*stats));
    });

    snapshotServiceTry("system.db typed", [&batch, windowStart, windowEnd, windowSeconds] {
        const auto stats = db::query::stats::DbStats::snapshot();
        if (stats) addDbMetrics(batch, *stats, windowStart, windowEnd, windowSeconds);
    });

    snapshotServiceTry("system.operations typed", [&batch, windowStart, windowEnd, windowSeconds] {
        const auto stats = db::query::stats::OperationStats::snapshot();
        if (stats) addOperationMetrics(batch, *stats, windowStart, windowEnd, windowSeconds);
    });

    snapshotServiceTry("system.connections typed", [&batch, windowStart, windowEnd, windowSeconds] {
        addConnectionMetrics(batch, model::ConnectionStats::snapshot(), windowStart, windowEnd, windowSeconds);
    });

    snapshotServiceTry("system.storage typed", [&batch, windowStart, windowEnd, windowSeconds] {
        addStorageMetrics(batch, model::StorageBackendStats::snapshot(), windowStart, windowEnd, windowSeconds);
    });

    snapshotServiceTry("system.retention typed", [&batch, windowStart, windowEnd, windowSeconds] {
        const auto stats = db::query::stats::RetentionStats::snapshot();
        if (stats) addRetentionMetrics(batch, *stats, windowStart, windowEnd, windowSeconds);
    });

    snapshotServiceTry("typed stats batch", [&batch] {
        db::query::stats::MetricSamples::insertBatch(batch);
    });
}

void SnapshotService::collectVaultSnapshots() {
    auto& deps = runtime::Deps::get();
    if (!deps.storageManager) return;

    db::query::stats::SampleBatch batch;
    const auto windowEnd = statsSnapshotServiceUnixTimestamp();
    const auto windowSeconds = std::max<std::uint32_t>(300, config::Registry::get().stats_snapshots.vault_interval_seconds);
    const auto windowStart = windowEnd > windowSeconds ? windowEnd - windowSeconds : windowEnd - 1;

    const auto engines = deps.storageManager->getEngines();
    for (const auto& engine : engines) {
        if (!engine || !engine->vault || engine->vault->id == 0) continue;
        const auto vaultId = engine->vault->id;

        snapshotServiceTry("vault.capacity", [vaultId, &batch, windowStart, windowEnd, windowSeconds] {
            const auto capacity = std::make_shared<vault::model::Capacity>(vaultId);
            db::query::stats::Snapshot::insertVault(vaultId, "vault.capacity", nlohmann::json(capacity));
            addVaultCapacityMetrics(batch, vaultId, *capacity, windowStart, windowEnd, windowSeconds);
        });

        snapshotServiceTry("vault.sync", [vaultId, &batch, windowStart, windowEnd, windowSeconds] {
            const auto stats = db::query::sync::Stats::getVaultSyncHealth(vaultId);
            if (stats) {
                db::query::stats::Snapshot::insertVault(vaultId, "vault.sync", nlohmann::json(*stats));
                addVaultSyncMetrics(batch, *stats, windowStart, windowEnd, windowSeconds);
            }
        });

        snapshotServiceTry("vault.activity", [vaultId, &batch, windowStart, windowEnd, windowSeconds] {
            const auto stats = db::query::vault::Activity::getVaultActivity(vaultId);
            if (stats) {
                db::query::stats::Snapshot::insertVault(vaultId, "vault.activity", nlohmann::json(*stats));
                addVaultActivityMetrics(batch, vaultId, *stats, windowStart, windowEnd, windowSeconds);
            }
        });

        snapshotServiceTry("vault.recovery typed", [vaultId, &batch, windowStart, windowEnd, windowSeconds] {
            const auto stats = db::query::vault::Recovery::getVaultRecovery(vaultId);
            if (stats) addVaultRecoveryMetrics(batch, *stats, windowStart, windowEnd, windowSeconds);
        });

        snapshotServiceTry("vault.retention typed", [vaultId, &batch, windowStart, windowEnd, windowSeconds] {
            const auto stats = db::query::stats::RetentionStats::snapshotForVault(vaultId);
            if (stats) addRetentionMetrics(batch, *stats, windowStart, windowEnd, windowSeconds);
        });

        snapshotServiceTry("vault.storage typed", [vaultId, &batch, windowStart, windowEnd, windowSeconds] {
            addStorageMetrics(batch, model::StorageBackendStats::snapshotForVault(vaultId), windowStart, windowEnd, windowSeconds);
        });
    }

    snapshotServiceTry("vault typed stats batch", [&batch] {
        db::query::stats::MetricSamples::insertBatch(batch);
    });
}

void SnapshotService::purgeOldSnapshots() {
    const auto snapshots = config::Registry::get().stats_snapshots;
    const auto retentionDays = snapshots.retention_days;
    snapshotServiceTry("stats_snapshot retention", [retentionDays] {
        db::query::stats::Snapshot::purgeOlderThan(retentionDays);
    });
    snapshotServiceTry("typed stats raw retention", [retentionDays] {
        db::query::stats::MetricSamples::purgeRawOlderThan(retentionDays);
    });
    // Each rollup tier has its own retention. 5-minute rollups used to be kept 365 days like the hourly ones, which made
    // them most of the database although the dashboard reads them only for windows up to 7 days.
    struct Tier {
        std::uint32_t resolutionSeconds;
        std::uint32_t days;
    };
    for (const Tier tier : {Tier{300, snapshots.rollup_5m_retention_days}, Tier{3600, snapshots.rollup_1h_retention_days}}) {
        snapshotServiceTry("typed stats rollup retention", [tier] {
            const auto purged = db::query::stats::MetricSamples::purgeRollupsOlderThan(tier.resolutionSeconds, tier.days);
            if (purged > 0)
                log::Registry::runtime()->info(
                    "[SnapshotService] Purged {} stats rollups of resolution {} s older than {} days",
                    purged, tier.resolutionSeconds, tier.days);
        });
    }
}

}
