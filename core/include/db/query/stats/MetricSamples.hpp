#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json.hpp>

namespace vh::db::query::stats {

struct MetricSample {
    std::string scope = "system";
    std::optional<std::uint32_t> vaultId;
    std::string metricKey;
    std::string seriesKey;
    std::string seriesLabel;
    std::string unit = "unknown";
    std::string snapshotType;
    std::uint64_t windowStart = 0;
    std::uint64_t windowEnd = 0;
    std::uint32_t windowSeconds = 60;
    std::uint32_t sampleCount = 1;
    std::optional<double> valueMin;
    std::optional<double> valueAvg;
    std::optional<double> valueMax;
    std::optional<double> valueLast;
    std::optional<double> deltaValue;
    std::optional<double> ratePerSecond;
    nlohmann::json tags;
};

struct ThreadPoolSample {
    std::string poolName;
    std::uint64_t windowStart = 0;
    std::uint64_t windowEnd = 0;
    std::uint32_t windowSeconds = 60;
    std::uint32_t sampleCount = 0;

    double pressureMin = 0.0;
    double pressureAvg = 0.0;
    double pressureMax = 0.0;
    double pressureLast = 0.0;

    std::uint64_t queueDepthMin = 0;
    double queueDepthAvg = 0.0;
    std::uint64_t queueDepthMax = 0;
    std::uint64_t queueDepthLast = 0;

    std::uint32_t busyWorkersMin = 0;
    double busyWorkersAvg = 0.0;
    std::uint32_t busyWorkersMax = 0;
    std::uint32_t busyWorkersLast = 0;

    std::uint32_t idleWorkersMin = 0;
    double idleWorkersAvg = 0.0;
    std::uint32_t idleWorkersMax = 0;
    std::uint32_t idleWorkersLast = 0;


    std::uint32_t pressuredSampleCount = 0;
    std::uint32_t saturatedSampleCount = 0;
    std::uint64_t queueDepthHighWater = 0;
    double pressureHighWater = 0.0;
    std::string lastStatus = "unknown";
};

struct FuseOpSample {
    std::string op;
    std::uint64_t windowStart = 0;
    std::uint64_t windowEnd = 0;
    std::uint32_t windowSeconds = 60;
    std::uint64_t countDelta = 0;
    std::uint64_t successDelta = 0;
    std::uint64_t errorDelta = 0;
    std::uint64_t expectedErrorDelta = 0;
    std::uint64_t alertableErrorDelta = 0;
    std::optional<double> errorRate;
    std::optional<double> expectedErrorRate;
    std::optional<double> alertableErrorRate;
    std::uint64_t readBytesDelta = 0;
    std::uint64_t writeBytesDelta = 0;
    std::optional<double> avgLatencyMs;
    std::optional<double> maxLatencyMs;
    bool counterReset = false;
};

struct CacheSample {
    std::string source;
    std::uint64_t windowStart = 0;
    std::uint64_t windowEnd = 0;
    std::uint32_t windowSeconds = 60;
    std::uint32_t sampleCount = 0;
    std::uint64_t hitDelta = 0;
    std::uint64_t missDelta = 0;
    std::uint64_t evictionDelta = 0;
    std::uint64_t insertDelta = 0;
    std::uint64_t invalidationDelta = 0;
    std::optional<double> hitRate;
    std::uint64_t bytesReadDelta = 0;
    std::uint64_t bytesWrittenDelta = 0;
    double occupancyMin = 0.0;
    double occupancyAvg = 0.0;
    double occupancyMax = 0.0;
    double occupancyLast = 0.0;
    std::uint64_t usedBytesMin = 0;
    double usedBytesAvg = 0.0;
    std::uint64_t usedBytesMax = 0;
    std::uint64_t usedBytesLast = 0;
    std::uint64_t opCountDelta = 0;
    std::optional<double> avgLatencyMs;
    std::optional<double> maxLatencyMs;
    bool counterReset = false;
};

struct SampleBatch {
    std::vector<MetricSample> metrics;
    std::vector<ThreadPoolSample> threadPools;
    std::vector<FuseOpSample> fuseOps;
    std::vector<CacheSample> caches;

    [[nodiscard]] bool empty() const {
        return metrics.empty() && threadPools.empty() && fuseOps.empty() && caches.empty();
    }
};

struct MetricSamples {
    static void insertBatch(const SampleBatch& batch);
    static void purgeRawOlderThan(std::uint32_t retentionDays);
    // Deletes the rollups of one tier (300 or 3600 seconds) that ended more than retentionDays (at least 1) ago, and
    // returns how many. Deleted rows don't shrink the table on disk; see docs/reference/configuration.md.
    static std::uint64_t purgeRollupsOlderThan(std::uint32_t resolutionSeconds, std::uint32_t retentionDays);
};

}
