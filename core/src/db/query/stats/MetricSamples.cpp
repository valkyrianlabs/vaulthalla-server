#include "db/query/stats/MetricSamples.hpp"

#include "db/Transactions.hpp"

#include <algorithm>
#include <map>
#include <pqxx/pqxx>

namespace vh::db::query::stats {

namespace {

struct RollupPoint {
    std::string scope = "system";
    std::optional<std::uint32_t> vaultId;
    std::string metricKey;
    std::string seriesKey;
    std::string seriesLabel;
    std::string unit = "unknown";
    std::string snapshotType;
    std::uint64_t windowEnd = 0;
    std::optional<double> valueMin;
    std::optional<double> valueAvg;
    std::optional<double> valueMax;
    std::optional<double> valueLast;
    std::optional<double> deltaValue;
    std::optional<double> ratePerSecond;
    std::uint32_t sourceSampleCount = 1;
};

std::optional<double> firstMetricValue(const MetricSample& sample) {
    if (sample.valueAvg) return sample.valueAvg;
    if (sample.valueLast) return sample.valueLast;
    if (sample.valueMax) return sample.valueMax;
    if (sample.valueMin) return sample.valueMin;
    return std::nullopt;
}

RollupPoint rollupFromMetricSample(const MetricSample& sample) {
    const auto fallback = firstMetricValue(sample);
    return {
        .scope = sample.scope,
        .vaultId = sample.vaultId,
        .metricKey = sample.metricKey,
        .seriesKey = sample.seriesKey,
        .seriesLabel = sample.seriesLabel,
        .unit = sample.unit,
        .snapshotType = sample.snapshotType,
        .windowEnd = sample.windowEnd,
        .valueMin = sample.valueMin ? sample.valueMin : fallback,
        .valueAvg = sample.valueAvg ? sample.valueAvg : fallback,
        .valueMax = sample.valueMax ? sample.valueMax : fallback,
        .valueLast = sample.valueLast ? sample.valueLast : fallback,
        .deltaValue = sample.deltaValue,
        .ratePerSecond = sample.ratePerSecond,
        .sourceSampleCount = std::max<std::uint32_t>(sample.sampleCount, 1),
    };
}

RollupPoint systemRollup(
    std::string metricKey,
    std::string seriesKey,
    std::string seriesLabel,
    std::string unit,
    std::string snapshotType,
    const std::uint64_t windowEnd,
    const std::optional<double> valueMin,
    const std::optional<double> valueAvg,
    const std::optional<double> valueMax,
    const std::optional<double> valueLast,
    const std::optional<double> deltaValue,
    const std::optional<double> ratePerSecond,
    const std::uint32_t sourceSampleCount
) {
    return {
        .scope = "system",
        .vaultId = std::nullopt,
        .metricKey = std::move(metricKey),
        .seriesKey = std::move(seriesKey),
        .seriesLabel = std::move(seriesLabel),
        .unit = std::move(unit),
        .snapshotType = std::move(snapshotType),
        .windowEnd = windowEnd,
        .valueMin = valueMin,
        .valueAvg = valueAvg,
        .valueMax = valueMax,
        .valueLast = valueLast,
        .deltaValue = deltaValue,
        .ratePerSecond = ratePerSecond,
        .sourceSampleCount = std::max<std::uint32_t>(sourceSampleCount, 1),
    };
}

std::string threadPoolLabel(const ThreadPoolSample& sample, const std::string& suffix) {
    if (sample.poolName == "__aggregate__") return "Aggregate " + suffix;
    return sample.poolName + " " + suffix;
}

void addThreadPoolRollups(std::vector<RollupPoint>& out, const ThreadPoolSample& sample) {
    const auto aggregate = sample.poolName == "__aggregate__";
    const auto pressureKey = aggregate ? "threadpool_pressure" : "threadpool_pool_pressure";
    const auto queueKey = aggregate ? "threadpool_queue_depth" : "threadpool_pool_queue_depth";
    const auto seriesKey = aggregate ? std::string{} : sample.poolName;

    out.push_back(systemRollup(
        pressureKey,
        seriesKey,
        threadPoolLabel(sample, "pressure"),
        "ratio",
        "system.threadpools",
        sample.windowEnd,
        sample.pressureMin,
        sample.pressureAvg,
        sample.pressureMax,
        sample.pressureLast,
        std::nullopt,
        std::nullopt,
        sample.sampleCount
    ));

    out.push_back(systemRollup(
        queueKey,
        seriesKey,
        threadPoolLabel(sample, "queue depth"),
        "count",
        "system.threadpools",
        sample.windowEnd,
        static_cast<double>(sample.queueDepthMin),
        sample.queueDepthAvg,
        static_cast<double>(sample.queueDepthMax),
        static_cast<double>(sample.queueDepthLast),
        std::nullopt,
        std::nullopt,
        sample.sampleCount
    ));
}

std::string cacheSourceLabel(const std::string& source) {
    return source == "http" ? "HTTP cache" : "FS cache";
}

void addCacheRollups(std::vector<RollupPoint>& out, const CacheSample& sample) {
    const auto label = cacheSourceLabel(sample.source);
    const auto prefix = sample.source == "http" ? "http_cache" : "fs_cache";

    out.push_back(systemRollup(
        prefix + std::string{"_hit_rate"},
        "",
        label + " hit rate",
        "ratio",
        "system.cache",
        sample.windowEnd,
        sample.hitRate,
        sample.hitRate,
        sample.hitRate,
        sample.hitRate,
        std::nullopt,
        std::nullopt,
        sample.sampleCount
    ));

    out.push_back(systemRollup(
        prefix + std::string{"_occupancy"},
        "",
        label + " occupancy",
        "ratio",
        "system.cache",
        sample.windowEnd,
        sample.occupancyMin,
        sample.occupancyAvg,
        sample.occupancyMax,
        sample.occupancyLast,
        std::nullopt,
        std::nullopt,
        sample.sampleCount
    ));

    out.push_back(systemRollup(
        prefix + std::string{"_used_bytes"},
        "",
        label + " used bytes",
        "bytes",
        "system.cache",
        sample.windowEnd,
        static_cast<double>(sample.usedBytesMin),
        sample.usedBytesAvg,
        static_cast<double>(sample.usedBytesMax),
        static_cast<double>(sample.usedBytesLast),
        std::nullopt,
        std::nullopt,
        sample.sampleCount
    ));
}

struct FuseAggregate {
    std::uint64_t windowEnd = 0;
    std::uint32_t windowSeconds = 60;
    std::uint64_t count = 0;
    std::uint64_t errors = 0;
    std::uint64_t expectedErrors = 0;
    std::uint64_t alertableErrors = 0;
    std::uint64_t readBytes = 0;
    std::uint64_t writeBytes = 0;
    double latencyWeightedMs = 0.0;
    double maxLatencyMs = 0.0;
    bool hasLatency = false;
};

void addFuseRollups(std::vector<RollupPoint>& out, const std::vector<FuseOpSample>& samples) {
    std::map<std::uint64_t, FuseAggregate> byWindow;

    for (const auto& sample : samples) {
        auto& aggregate = byWindow[sample.windowEnd];
        aggregate.windowEnd = sample.windowEnd;
        aggregate.windowSeconds = sample.windowSeconds;
        aggregate.count += sample.countDelta;
        aggregate.errors += sample.errorDelta;
        aggregate.expectedErrors += sample.expectedErrorDelta;
        aggregate.alertableErrors += sample.alertableErrorDelta;
        aggregate.readBytes += sample.readBytesDelta;
        aggregate.writeBytes += sample.writeBytesDelta;
        if (sample.avgLatencyMs && sample.countDelta > 0) {
            aggregate.latencyWeightedMs += *sample.avgLatencyMs * static_cast<double>(sample.countDelta);
            aggregate.hasLatency = true;
        }
        if (sample.maxLatencyMs) aggregate.maxLatencyMs = std::max(aggregate.maxLatencyMs, *sample.maxLatencyMs);
    }

    for (const auto& [_, aggregate] : byWindow) {
        const auto windowSeconds = std::max<std::uint32_t>(aggregate.windowSeconds, 1);
        const auto opsPerSecond = static_cast<double>(aggregate.count) / static_cast<double>(windowSeconds);
        const auto errorRate = aggregate.count > 0
            ? std::optional<double>(static_cast<double>(aggregate.errors) / static_cast<double>(aggregate.count))
            : std::nullopt;
        const auto expectedErrorRate = aggregate.count > 0
            ? std::optional<double>(static_cast<double>(aggregate.expectedErrors) / static_cast<double>(aggregate.count))
            : std::nullopt;
        const auto alertableErrorRate = aggregate.count > 0
            ? std::optional<double>(static_cast<double>(aggregate.alertableErrors) / static_cast<double>(aggregate.count))
            : std::nullopt;
        const auto avgLatencyMs = aggregate.hasLatency && aggregate.count > 0
            ? std::optional<double>(aggregate.latencyWeightedMs / static_cast<double>(aggregate.count))
            : std::nullopt;

        out.push_back(systemRollup(
            "fuse_ops_per_second",
            "",
            "FUSE ops/sec",
            "ops/s",
            "system.fuse",
            aggregate.windowEnd,
            opsPerSecond,
            opsPerSecond,
            opsPerSecond,
            opsPerSecond,
            static_cast<double>(aggregate.count),
            opsPerSecond,
            1
        ));

        out.push_back(systemRollup(
            "fuse_total_ops",
            "",
            "FUSE operations",
            "count",
            "system.fuse",
            aggregate.windowEnd,
            static_cast<double>(aggregate.count),
            static_cast<double>(aggregate.count),
            static_cast<double>(aggregate.count),
            static_cast<double>(aggregate.count),
            static_cast<double>(aggregate.count),
            opsPerSecond,
            1
        ));

        out.push_back(systemRollup(
            "fuse_error_rate",
            "",
            "FUSE alertable error rate",
            "ratio",
            "system.fuse",
            aggregate.windowEnd,
            alertableErrorRate,
            alertableErrorRate,
            alertableErrorRate,
            alertableErrorRate,
            std::nullopt,
            std::nullopt,
            1
        ));

        out.push_back(systemRollup(
            "fuse_raw_error_rate",
            "",
            "FUSE raw error rate",
            "ratio",
            "system.fuse",
            aggregate.windowEnd,
            errorRate,
            errorRate,
            errorRate,
            errorRate,
            std::nullopt,
            std::nullopt,
            1
        ));

        out.push_back(systemRollup(
            "fuse_expected_error_rate",
            "",
            "FUSE expected error rate",
            "ratio",
            "system.fuse",
            aggregate.windowEnd,
            expectedErrorRate,
            expectedErrorRate,
            expectedErrorRate,
            expectedErrorRate,
            std::nullopt,
            std::nullopt,
            1
        ));

        out.push_back(systemRollup(
            "fuse_latency_avg_ms",
            "",
            "FUSE latency",
            "ms",
            "system.fuse",
            aggregate.windowEnd,
            avgLatencyMs,
            avgLatencyMs,
            aggregate.hasLatency ? std::optional<double>(aggregate.maxLatencyMs) : std::nullopt,
            avgLatencyMs,
            std::nullopt,
            std::nullopt,
            1
        ));

        out.push_back(systemRollup(
            "fuse_read_bytes_per_second",
            "",
            "FUSE read bytes/sec",
            "bytes/s",
            "system.fuse",
            aggregate.windowEnd,
            static_cast<double>(aggregate.readBytes) / static_cast<double>(windowSeconds),
            static_cast<double>(aggregate.readBytes) / static_cast<double>(windowSeconds),
            static_cast<double>(aggregate.readBytes) / static_cast<double>(windowSeconds),
            static_cast<double>(aggregate.readBytes) / static_cast<double>(windowSeconds),
            static_cast<double>(aggregate.readBytes),
            static_cast<double>(aggregate.readBytes) / static_cast<double>(windowSeconds),
            1
        ));

        out.push_back(systemRollup(
            "fuse_write_bytes_per_second",
            "",
            "FUSE write bytes/sec",
            "bytes/s",
            "system.fuse",
            aggregate.windowEnd,
            static_cast<double>(aggregate.writeBytes) / static_cast<double>(windowSeconds),
            static_cast<double>(aggregate.writeBytes) / static_cast<double>(windowSeconds),
            static_cast<double>(aggregate.writeBytes) / static_cast<double>(windowSeconds),
            static_cast<double>(aggregate.writeBytes) / static_cast<double>(windowSeconds),
            static_cast<double>(aggregate.writeBytes),
            static_cast<double>(aggregate.writeBytes) / static_cast<double>(windowSeconds),
            1
        ));
    }
}

void insertMetricSample(pqxx::work& txn, const MetricSample& sample) {
    const auto tags = sample.tags.is_object() ? sample.tags.dump() : std::string{"{}"};
    txn.exec(pqxx::prepped{"stats_metric_sample.insert"}, pqxx::params{
        sample.scope,
        sample.vaultId,
        sample.metricKey,
        sample.seriesKey,
        sample.seriesLabel,
        sample.unit,
        sample.snapshotType,
        sample.windowStart,
        sample.windowEnd,
        sample.windowSeconds,
        sample.sampleCount,
        sample.valueMin,
        sample.valueAvg,
        sample.valueMax,
        sample.valueLast,
        sample.deltaValue,
        sample.ratePerSecond,
        tags
    });
}

void insertThreadPoolSample(pqxx::work& txn, const ThreadPoolSample& sample) {
    txn.exec(pqxx::prepped{"stats_threadpool_sample.upsert"}, pqxx::params{
        sample.poolName,
        sample.windowStart,
        sample.windowEnd,
        sample.windowSeconds,
        sample.sampleCount,
        sample.pressureMin,
        sample.pressureAvg,
        sample.pressureMax,
        sample.pressureLast,
        sample.queueDepthMin,
        sample.queueDepthAvg,
        sample.queueDepthMax,
        sample.queueDepthLast,
        sample.busyWorkersMin,
        sample.busyWorkersAvg,
        sample.busyWorkersMax,
        sample.busyWorkersLast,
        sample.idleWorkersMin,
        sample.idleWorkersAvg,
        sample.idleWorkersMax,
        sample.idleWorkersLast,
        sample.pressuredSampleCount,
        sample.saturatedSampleCount,
        sample.queueDepthHighWater,
        sample.pressureHighWater,
        sample.lastStatus
    });
}

void insertFuseOpSample(pqxx::work& txn, const FuseOpSample& sample) {
    txn.exec(pqxx::prepped{"stats_fuse_op_sample.upsert"}, pqxx::params{
        sample.op,
        sample.windowStart,
        sample.windowEnd,
        sample.windowSeconds,
        sample.countDelta,
        sample.successDelta,
        sample.errorDelta,
        sample.expectedErrorDelta,
        sample.alertableErrorDelta,
        sample.errorRate,
        sample.expectedErrorRate,
        sample.alertableErrorRate,
        sample.readBytesDelta,
        sample.writeBytesDelta,
        sample.avgLatencyMs,
        sample.maxLatencyMs,
        sample.counterReset
    });
}

void insertCacheSample(pqxx::work& txn, const CacheSample& sample) {
    txn.exec(pqxx::prepped{"stats_cache_sample.upsert"}, pqxx::params{
        sample.source,
        sample.windowStart,
        sample.windowEnd,
        sample.windowSeconds,
        sample.sampleCount,
        sample.hitDelta,
        sample.missDelta,
        sample.evictionDelta,
        sample.insertDelta,
        sample.invalidationDelta,
        sample.hitRate,
        sample.bytesReadDelta,
        sample.bytesWrittenDelta,
        sample.occupancyMin,
        sample.occupancyAvg,
        sample.occupancyMax,
        sample.occupancyLast,
        sample.usedBytesMin,
        sample.usedBytesAvg,
        sample.usedBytesMax,
        sample.usedBytesLast,
        sample.opCountDelta,
        sample.avgLatencyMs,
        sample.maxLatencyMs,
        sample.counterReset
    });
}

void upsertRollup(pqxx::work& txn, const RollupPoint& point, const std::uint32_t resolutionSeconds) {
    if (point.metricKey.empty() || point.seriesLabel.empty() || point.windowEnd == 0) return;

    if (point.scope == "vault" && point.vaultId) {
        txn.exec(pqxx::prepped{"stats_metric_rollup.upsert_vault"}, pqxx::params{
            *point.vaultId,
            point.metricKey,
            point.seriesKey,
            point.seriesLabel,
            point.unit,
            point.snapshotType,
            resolutionSeconds,
            point.windowEnd,
            point.valueMin,
            point.valueAvg,
            point.valueMax,
            point.valueLast,
            point.deltaValue,
            point.ratePerSecond,
            point.sourceSampleCount
        });
        return;
    }

    txn.exec(pqxx::prepped{"stats_metric_rollup.upsert_system"}, pqxx::params{
        point.metricKey,
        point.seriesKey,
        point.seriesLabel,
        point.unit,
        point.snapshotType,
        resolutionSeconds,
        point.windowEnd,
        point.valueMin,
        point.valueAvg,
        point.valueMax,
        point.valueLast,
        point.deltaValue,
        point.ratePerSecond,
        point.sourceSampleCount
    });
}

}

void MetricSamples::insertBatch(const SampleBatch& batch) {
    if (batch.empty()) return;

    Transactions::exec("MetricSamples::insertBatch", [&](pqxx::work& txn) {
        std::vector<RollupPoint> rollups;
        rollups.reserve(batch.metrics.size() + batch.threadPools.size() * 2 + batch.caches.size() * 3 + 10);

        for (const auto& sample : batch.metrics) {
            insertMetricSample(txn, sample);
            rollups.push_back(rollupFromMetricSample(sample));
        }

        for (const auto& sample : batch.threadPools) {
            insertThreadPoolSample(txn, sample);
            addThreadPoolRollups(rollups, sample);
        }

        for (const auto& sample : batch.fuseOps) {
            insertFuseOpSample(txn, sample);
        }
        addFuseRollups(rollups, batch.fuseOps);

        for (const auto& sample : batch.caches) {
            insertCacheSample(txn, sample);
            addCacheRollups(rollups, sample);
        }

        for (const auto& rollup : rollups) {
            upsertRollup(txn, rollup, 300);
            upsertRollup(txn, rollup, 3600);
        }
    });
}

void MetricSamples::purgeRawOlderThan(const std::uint32_t retentionDays) {
    Transactions::exec("MetricSamples::purgeRawOlderThan", [&](pqxx::work& txn) {
        const auto days = std::max<std::uint32_t>(1, retentionDays);
        txn.exec(pqxx::prepped{"stats_threadpool_sample.purge_older_than"}, pqxx::params{days});
        txn.exec(pqxx::prepped{"stats_fuse_op_sample.purge_older_than"}, pqxx::params{days});
        txn.exec(pqxx::prepped{"stats_cache_sample.purge_older_than"}, pqxx::params{days});
        txn.exec(pqxx::prepped{"stats_metric_sample.purge_older_than"}, pqxx::params{days});
    });
}

std::uint64_t MetricSamples::purgeRollupsOlderThan(const std::uint32_t resolutionSeconds,
                                                   const std::uint32_t retentionDays) {
    return Transactions::exec("MetricSamples::purgeRollupsOlderThan", [&](pqxx::work& txn) {
        const auto result = txn.exec(
            pqxx::prepped{"stats_samples.purge_rollups_older_than"},
            pqxx::params{resolutionSeconds, std::max<std::uint32_t>(1, retentionDays)}
        );
        return static_cast<std::uint64_t>(result.affected_rows());
    });
}

}
