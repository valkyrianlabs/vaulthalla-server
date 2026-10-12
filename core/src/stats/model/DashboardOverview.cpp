#include "stats/model/DashboardOverview.hpp"

#include "db/query/stats/DbStats.hpp"
#include "db/query/stats/OperationStats.hpp"
#include "db/query/stats/RetentionStats.hpp"
#include "db/query/stats/Snapshot.hpp"
#include "fs/cache/Registry.hpp"
#include "runtime/Deps.hpp"
#include "stats/model/CacheStats.hpp"
#include "stats/model/ConnectionStats.hpp"
#include "stats/model/DbStats.hpp"
#include "stats/model/FuseStats.hpp"
#include "stats/model/OperationStats.hpp"
#include "stats/model/RetentionStats.hpp"
#include "stats/model/StatsTrends.hpp"
#include "stats/model/StorageBackendStats.hpp"
#include "stats/model/SystemHealth.hpp"
#include "stats/model/ThreadPoolStats.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <exception>
#include <map>
#include <memory>
#include <nlohmann/json.hpp>
#include <unordered_map>
#include <utility>

namespace vh::stats::model {

namespace {

struct DashboardOverviewSectionDescriptor {
    std::string id;
    std::string title;
    std::string description;
    std::string href;
};

struct DashboardOverviewCardDescriptor {
    std::string id;
    std::string sectionId;
    std::string title;
    std::string description;
    std::string href;
    std::string variant;
    std::string size;
};

std::uint64_t dashboardOverviewUnixTimestamp() {
    return static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

template <typename T>
nlohmann::json dashboardOverviewNullable(const std::optional<T>& value) {
    return value ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

int dashboardOverviewSeverityRank(const std::string& severity) {
    if (severity == "error") return 5;
    if (severity == "warning") return 4;
    if (severity == "unknown") return 3;
    if (severity == "info") return 2;
    if (severity == "unavailable") return 1;
    return 0;
}

std::string dashboardOverviewWorstSeverity(const std::string& a, const std::string& b) {
    return dashboardOverviewSeverityRank(b) > dashboardOverviewSeverityRank(a) ? b : a;
}

std::string dashboardOverviewSeverityFromStatus(const std::string& status) {
    if (status == "healthy" || status == "idle" || status == "normal" || status == "ready") return "healthy";
    if (status == "info" || status == "syncing" || status == "success") return "info";
    if (status == "warning" || status == "degraded" || status == "pressured" || status == "stale") return "warning";
    if (status == "error" || status == "critical" || status == "saturated" || status == "failing" || status == "stalled" || status == "diverged" || status == "overdue") return "error";
    if (status == "unavailable" || status == "disabled") return "unavailable";
    return "unknown";
}

std::string dashboardOverviewFormatCount(const std::uint64_t value) {
    return std::to_string(value);
}

std::string dashboardOverviewFormatRatio(const double value) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%.2fx", value);
    return buffer;
}

std::string dashboardOverviewFormatPercent(const double ratio) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "%.1f%%", ratio * 100.0);
    return buffer;
}

std::string dashboardOverviewFormatBytes(const std::uint64_t value) {
    constexpr double kib = 1024.0;
    constexpr double mib = kib * 1024.0;
    constexpr double gib = mib * 1024.0;

    char buffer[48];
    if (value >= static_cast<std::uint64_t>(gib)) {
        std::snprintf(buffer, sizeof(buffer), "%.1f GiB", static_cast<double>(value) / gib);
    } else if (value >= static_cast<std::uint64_t>(mib)) {
        std::snprintf(buffer, sizeof(buffer), "%.1f MiB", static_cast<double>(value) / mib);
    } else if (value >= static_cast<std::uint64_t>(kib)) {
        std::snprintf(buffer, sizeof(buffer), "%.1f KiB", static_cast<double>(value) / kib);
    } else {
        std::snprintf(buffer, sizeof(buffer), "%llu B", static_cast<unsigned long long>(value));
    }
    return buffer;
}

std::string dashboardOverviewFormatDuration(const std::uint64_t seconds) {
    char buffer[48];
    if (seconds >= 86400) {
        std::snprintf(buffer, sizeof(buffer), "%llud", static_cast<unsigned long long>(seconds / 86400));
    } else if (seconds >= 3600) {
        std::snprintf(buffer, sizeof(buffer), "%lluh", static_cast<unsigned long long>(seconds / 3600));
    } else if (seconds >= 60) {
        std::snprintf(buffer, sizeof(buffer), "%llum", static_cast<unsigned long long>(seconds / 60));
    } else {
        std::snprintf(buffer, sizeof(buffer), "%llus", static_cast<unsigned long long>(seconds));
    }
    return buffer;
}

std::string dashboardOverviewFormatMillis(const double ms) {
    char buffer[48];
    std::snprintf(buffer, sizeof(buffer), "%.1f ms", ms);
    return buffer;
}

std::string dashboardOverviewFormatOptionalDuration(const std::optional<std::uint64_t>& seconds) {
    return seconds ? dashboardOverviewFormatDuration(*seconds) : "none";
}

std::uint64_t dashboardOverviewMapCount(const std::map<std::string, std::uint64_t>& values, const std::string& key) {
    const auto it = values.find(key);
    return it == values.end() ? 0 : it->second;
}

std::optional<double> dashboardOverviewOptionalDouble(const std::optional<std::uint64_t>& value) {
    return value ? std::optional<double>(static_cast<double>(*value)) : std::nullopt;
}

void dashboardOverviewAddMetric(
    DashboardCardSummary& card,
    std::string key,
    std::string label,
    std::string value,
    std::string tone = "unknown",
    std::optional<double> numericValue = std::nullopt,
    std::optional<std::string> unit = std::nullopt
) {
    DashboardMetricSummary metric;
    metric.key = std::move(key);
    metric.label = std::move(label);
    metric.value = std::move(value);
    metric.unit = std::move(unit);
    metric.tone = std::move(tone);
    metric.numericValue = numericValue;
    card.metrics.push_back(std::move(metric));
}

void dashboardOverviewAddIssue(
    DashboardCardSummary& card,
    std::string code,
    std::string severity,
    std::string message,
    std::optional<std::string> metricKey = std::nullopt
) {
    DashboardIssueSummary issue{
        .code = std::move(code),
        .severity = std::move(severity),
        .message = std::move(message),
        .href = card.href,
        .metricKey = std::move(metricKey),
    };

    if (issue.severity == "error") card.errors.push_back(std::move(issue));
    else card.warnings.push_back(std::move(issue));
}

std::string dashboardOverviewTrendTone(const std::string& key) {
    if (key.find("error") != std::string::npos || key.find("queue") != std::string::npos) return "warning";
    if (key.find("cache_hit") != std::string::npos || key.find("hit_rate") != std::string::npos) return "healthy";
    if (key.find("pressure") != std::string::npos) return "info";
    return "info";
}

DashboardGraphSeries dashboardOverviewGraphSeriesFromTrend(const StatsTrendSeries& source,
                                                           const std::size_t maxPoints = kDashboardOverviewMaxPointsPerSeries) {
    DashboardGraphSeries series;
    series.key = source.key;
    series.label = source.label;
    series.unit = source.unit;
    series.tone = dashboardOverviewTrendTone(source.key);

    const auto start = source.points.size() > maxPoints ? source.points.size() - maxPoints : 0;
    series.points.reserve(source.points.size() - start);
    for (std::size_t i = start; i < source.points.size(); ++i) {
        series.points.push_back({
            .createdAt = source.points[i].createdAt,
            .value = source.points[i].value,
        });
    }

    return series;
}

bool dashboardOverviewTrendBelongsToCard(const std::string& cardId, const std::string& key) {
    if (cardId == "system.threadpools")
        return key == "threadpool_pressure" || key.rfind("threadpool_pool_pressure:", 0) == 0;
    if (cardId == "system.fuse")
        return key == "fuse_error_rate" || key == "fuse_ops_per_second" || key == "fuse_latency_avg_ms";
    // The FS metadata cache has no byte cap, so its occupancy series carries no information.
    if (cardId == "system.fs_cache") return key == "fs_cache_hit_rate";
    if (cardId == "system.http_cache") return key == "http_cache_hit_rate" || key == "http_cache_occupancy";
    if (cardId == "system.db")
        return key == "db_cache_hit_ratio" || key == "db_connection_pressure" || key == "db_size_bytes";
    if (cardId == "system.operations")
        return key == "operations_pending" || key == "operations_in_progress" || key == "operations_stalled";
    if (cardId == "system.trends")
        return key == "threadpool_pressure" || key == "fuse_error_rate" || key == "fuse_ops_per_second"
            || key == "fs_cache_hit_rate" || key == "http_cache_hit_rate" || key == "db_cache_hit_ratio"
            || key == "operations_pending" || key == "operations_in_progress" || key == "operations_stalled";
    return false;
}

int dashboardOverviewTrendPriority(const std::string& cardId, const std::string& key) {
    if (cardId == "system.threadpools") {
        if (key == "threadpool_pressure") return 0;
        if (key.rfind("threadpool_pool_pressure:", 0) == 0) return 1;
    }
    if (cardId == "system.fuse") {
        if (key == "fuse_error_rate") return 0;
        if (key == "fuse_ops_per_second") return 1;
        if (key == "fuse_latency_avg_ms") return 2;
    }
    if (cardId == "system.db") {
        if (key == "db_cache_hit_ratio") return 0;
        if (key == "db_connection_pressure") return 1;
        if (key == "db_size_bytes") return 2;
    }
    if (cardId == "system.operations") {
        if (key == "operations_pending") return 0;
        if (key == "operations_in_progress") return 1;
        if (key == "operations_stalled") return 2;
    }
    return 10;
}

void dashboardOverviewAttachTrendSeries(
    std::vector<DashboardCardSummary>& cards,
    const std::shared_ptr<StatsTrends>& trends
) {
    if (!trends) return;

    for (auto& card : cards) {
        if (card.variant != "visual" && card.variant != "graph" && card.id != "system.trends") continue;

        std::vector<const StatsTrendSeries*> selected;
        for (const auto& series : trends->series) {
            if (!dashboardOverviewTrendBelongsToCard(card.id, series.key)) continue;
            if (series.points.size() < 2) continue;
            selected.push_back(&series);
        }

        std::sort(selected.begin(), selected.end(), [&card](const auto* a, const auto* b) {
            const auto priorityA = dashboardOverviewTrendPriority(card.id, a->key);
            const auto priorityB = dashboardOverviewTrendPriority(card.id, b->key);
            if (priorityA != priorityB) return priorityA < priorityB;
            return a->key < b->key;
        });

        // The console draws at most three series per card; sending every pool's series made up most of the ~80 KB
        // overview (#160).
        const auto maxSeries = std::min<std::size_t>(selected.size(), kDashboardOverviewMaxSeriesPerCard);
        card.series.reserve(maxSeries);
        for (std::size_t i = 0; i < maxSeries; ++i) {
            card.series.push_back(dashboardOverviewGraphSeriesFromTrend(*selected[i]));
        }
    }
}

DashboardCardSummary dashboardOverviewBaseCard(const DashboardOverviewCardDescriptor& descriptor) {
    DashboardCardSummary card;
    card.id = descriptor.id;
    card.sectionId = descriptor.sectionId;
    card.title = descriptor.title;
    card.description = descriptor.description;
    card.href = descriptor.href;
    card.variant = descriptor.variant;
    card.size = descriptor.size;
    card.checkedAt = dashboardOverviewUnixTimestamp();
    return card;
}

DashboardCardSummary dashboardOverviewUnavailableCard(
    const DashboardOverviewCardDescriptor& descriptor,
    const std::string& reason
) {
    auto card = dashboardOverviewBaseCard(descriptor);
    card.available = false;
    card.severity = "unavailable";
    card.unavailableReason = reason;
    card.summary = reason;
    return card;
}

std::vector<DashboardOverviewSectionDescriptor> dashboardOverviewSectionDescriptors() {
    return {
        {"runtime", "Runtime", "Runtime services, worker pressure, and connected sessions.", "/health/runtime"},
        {"filesystem", "Filesystem", "FUSE activity and preview cache readiness.", "/health/filesystem"},
        {"storage", "Storage", "Backing providers, database health, and cleanup pressure.", "/health/storage"},
        {"operations", "Operations", "Queued work, active transfers, and stuck-operation pressure.", "/health/activity#operation-queue"},
        {"cost_control", "Cost Control", "S3 price budgets, projected spend, catalog health, and override activity.", "/cost"},
        {"trends", "Trends", "Historical samples for live telemetry surfaces.", "/health/activity#trends"},
    };
}

std::vector<DashboardOverviewCardDescriptor> dashboardOverviewCardDescriptors() {
    return {
        {"system.health", "runtime", "System Health", "Core runtime, protocol, dependency, FUSE, and shell readiness.", "/health/runtime#system-health", "hero", "3x2"},
        {"system.threadpools", "runtime", "Thread Pools", "Runtime worker pressure across FUSE, sync, thumbnails, HTTP, and stats.", "/health/runtime#thread-pools", "visual", "2x1"},
        {"system.connections", "runtime", "Connection Health", "Websocket session mix and unauthenticated buildup.", "/health/runtime#connections", "visual", "2x1"},
        {"system.fuse", "filesystem", "FUSE Filesystem", "Live filesystem operation volume, errors, latency, and open handles.", "/health/filesystem#fuse", "visual", "2x1"},
        {"system.fs_cache", "filesystem", "FS Cache", "Filesystem cache hit rate, usage, and churn.", "/health/filesystem#fs-cache", "visual", "2x1"},
        {"system.http_cache", "filesystem", "HTTP Preview Cache", "Preview cache hit rate, usage, and churn.", "/health/filesystem#http-cache", "visual", "2x1"},
        {"system.storage", "storage", "Storage Backend", "Local and S3 vault backend configuration and free-space posture.", "/health/storage#storage-backend", "visual", "2x1"},
        {"system.db", "storage", "Database Health", "Database connectivity, connection pressure, cache hit ratio, and table size.", "/health/storage#database", "visual", "2x1"},
        {"system.retention", "storage", "Retention / Cleanup", "Trash, audit, sync, share, and cache cleanup backlog.", "/health/storage#retention", "visual", "2x1"},
        {"system.operations", "operations", "Operation Queue", "Pending, active, failed, and stalled filesystem/share work.", "/health/activity#operation-queue", "visual", "2x2"},
        {"system.pricing_budget", "cost_control", "S3 Price Budget Overview", "Active S3 price budget policies, current spend, projected spend, and budget blocks.", "/cost#spend", "tiles", "2x1"},
        {"system.pricing_providers", "cost_control", "Provider Spend", "AWS S3 and Cloudflare R2 committed and projected budget pressure.", "/cost#spend", "tiles", "2x1"},
        {"system.pricing_vaults", "cost_control", "Vault Spend", "Top vault spend and projected overage pressure.", "/cost#spend", "tiles", "2x1"},
        {"system.pricing_alerts", "cost_control", "Budget Alerts", "Active budget warnings, critical events, and acknowledgement backlog.", "/cost#budget-alerts", "tiles", "2x1"},
        {"system.pricing_catalog", "cost_control", "Catalog Health", "Pricing catalog verification, stale catalog, and unsupported-provider events.", "/cost#budget-alerts", "tiles", "2x1"},
        {"system.pricing_overrides", "cost_control", "Recent Blocks and Overrides", "Blocked syncs and single-run override request decisions.", "/cost#overrides", "tiles", "2x1"},
        {"system.trends", "trends", "Trends", "Recently collected stats snapshot series.", "/health/activity#trends", "visual", "2x1"},
    };
}

DashboardCardSummary dashboardOverviewBuildSystemHealth(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto health = SystemHealth::snapshot();
    const auto status = health.overallStatusString();

    card.checkedAt = health.summary.checkedAt;
    card.severity = dashboardOverviewSeverityFromStatus(status);
    if (status == "healthy" && health.shell.adminUidBound && !*health.shell.adminUidBound) {
        card.severity = "info";
        card.summary = "Core runtime is healthy. CLI shell admin binding is not configured.";
    } else {
        card.summary = card.severity == "healthy" ? "Runtime services and dependencies are healthy." : "Runtime health needs attention.";
    }

    dashboardOverviewAddMetric(card, "services", "Services", std::to_string(health.summary.servicesReady) + "/" + std::to_string(health.summary.servicesTotal), card.severity);
    dashboardOverviewAddMetric(card, "protocols", "Protocols", std::to_string(health.summary.protocolsReady) + "/" + std::to_string(health.summary.protocolsTotal), health.summary.protocolsReady == health.summary.protocolsTotal ? "healthy" : "warning");
    dashboardOverviewAddMetric(card, "deps", "Deps", std::to_string(health.summary.depsReady) + "/" + std::to_string(health.summary.depsTotal), health.summary.depsReady == health.summary.depsTotal ? "healthy" : "warning");
    dashboardOverviewAddMetric(
        card,
        "shell_admin_uid",
        "CLI Shell",
        !health.shell.adminUidBound ? "unknown" : *health.shell.adminUidBound ? "bound" : "setup",
        !health.shell.adminUidBound ? "unknown" : *health.shell.adminUidBound ? "healthy" : "info"
    );

    if (status != "healthy") {
        const auto severity = card.severity == "error" ? "error" : "warning";
        dashboardOverviewAddIssue(card, "system.health.unhealthy", severity, "System health is " + status + ".");
    }
    if (!health.deps.fuseSession && health.deps.fuseMount != "disabled") dashboardOverviewAddIssue(card, "system.health.fuse_missing", "warning", "FUSE session is not present.", "fuse");

    return card;
}

DashboardCardSummary dashboardOverviewBuildThreadPools(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = ThreadPoolManagerSnapshot::snapshot();
    card.checkedAt = stats.checkedAt;
    card.severity = dashboardOverviewSeverityFromStatus(stats.overallStatus);
    card.summary = stats.overallStatus == "healthy" ? "Runtime workers are available." : "Runtime worker pressure needs attention.";

    const auto poolCount = static_cast<std::uint64_t>(stats.pools.size());
    std::uint64_t stoppedPoolCount = 0;
    std::uint64_t degradedPoolCount = 0;
    for (const auto& pool : stats.pools) {
        if (pool.stopped) ++stoppedPoolCount;
        if (pool.status != "healthy" && pool.status != "idle" && pool.status != "normal" && pool.status != "ready") ++degradedPoolCount;
    }
    const auto nonBusyWorkers = static_cast<std::uint64_t>(stats.totalIdleWorkerCount);
    const auto busyWorkers =
        stats.totalWorkerCount > nonBusyWorkers ? static_cast<std::uint64_t>(stats.totalWorkerCount) - nonBusyWorkers : 0;

    dashboardOverviewAddMetric(card, "workers", "Workers", dashboardOverviewFormatCount(stats.totalWorkerCount), card.severity, static_cast<double>(stats.totalWorkerCount));
    dashboardOverviewAddMetric(card, "queue", "Queue", dashboardOverviewFormatCount(stats.totalQueueDepth), stats.totalQueueDepth == 0 ? "healthy" : "warning", static_cast<double>(stats.totalQueueDepth));
    dashboardOverviewAddMetric(card, "pressure", "Max Pressure", dashboardOverviewFormatRatio(stats.maxPressureRatio), card.severity, stats.maxPressureRatio);
    dashboardOverviewAddMetric(card, "pools", "Pools", dashboardOverviewFormatCount(poolCount), "info", static_cast<double>(poolCount));
    dashboardOverviewAddMetric(card, "busy", "Busy", dashboardOverviewFormatCount(busyWorkers), busyWorkers == 0 ? "healthy" : "info", static_cast<double>(busyWorkers));
    dashboardOverviewAddMetric(card, "idle", "Idle", dashboardOverviewFormatCount(stats.totalIdleWorkerCount), "info", static_cast<double>(stats.totalIdleWorkerCount));
    dashboardOverviewAddMetric(card, "pressured", "Pressured", dashboardOverviewFormatCount(stats.pressuredPoolCount), stats.pressuredPoolCount == 0 ? "healthy" : "warning", static_cast<double>(stats.pressuredPoolCount));
    dashboardOverviewAddMetric(card, "saturated", "Saturated", dashboardOverviewFormatCount(stats.saturatedPoolCount), stats.saturatedPoolCount == 0 ? "healthy" : "error", static_cast<double>(stats.saturatedPoolCount));
    dashboardOverviewAddMetric(card, "stopped", "Stopped", dashboardOverviewFormatCount(stoppedPoolCount), stoppedPoolCount == 0 ? "healthy" : "error", static_cast<double>(stoppedPoolCount));
    dashboardOverviewAddMetric(card, "degraded", "Degraded", dashboardOverviewFormatCount(degradedPoolCount), degradedPoolCount == 0 ? "healthy" : "warning", static_cast<double>(degradedPoolCount));

    if (stats.overallStatus == "pressured") {
        dashboardOverviewAddIssue(card, "system.threadpools.pressured", "warning", std::to_string(stats.pressuredPoolCount) + " thread pool(s) are pressured.", "pressure");
    } else if (stats.overallStatus == "saturated") {
        dashboardOverviewAddIssue(card, "system.threadpools.saturated", "error", std::to_string(stats.saturatedPoolCount) + " thread pool(s) are saturated.", "pressure");
    } else if (stats.overallStatus == "degraded") {
        dashboardOverviewAddIssue(card, "system.threadpools.degraded", "error", "One or more thread pools are degraded.", "workers");
    }

    return card;
}

DashboardCardSummary dashboardOverviewBuildConnections(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = ConnectionStats::snapshot();
    card.checkedAt = stats.checkedAt;
    card.severity = dashboardOverviewSeverityFromStatus(stats.status);
    card.summary = stats.status == "healthy" ? "Connected sessions look normal." : "Connection mix needs attention.";

    dashboardOverviewAddMetric(card, "sessions", "Sessions", dashboardOverviewFormatCount(stats.activeWsSessionsTotal), card.severity, static_cast<double>(stats.activeWsSessionsTotal));
    dashboardOverviewAddMetric(card, "human", "Human", dashboardOverviewFormatCount(stats.activeHumanSessions), "info", static_cast<double>(stats.activeHumanSessions));
    dashboardOverviewAddMetric(card, "share", "Share", dashboardOverviewFormatCount(stats.activeShareSessions), "info", static_cast<double>(stats.activeShareSessions));
    dashboardOverviewAddMetric(card, "share_pending", "Share Pending", dashboardOverviewFormatCount(stats.activeSharePendingSessions), stats.activeSharePendingSessions == 0 ? "healthy" : "warning", static_cast<double>(stats.activeSharePendingSessions));
    dashboardOverviewAddMetric(card, "unauthenticated", "Unauth", dashboardOverviewFormatCount(stats.activeUnauthenticatedSessions), stats.activeUnauthenticatedSessions == 0 ? "healthy" : "warning", static_cast<double>(stats.activeUnauthenticatedSessions));
    dashboardOverviewAddMetric(card, "oldest_session", "Oldest", dashboardOverviewFormatOptionalDuration(stats.oldestSessionAgeSeconds), "info", dashboardOverviewOptionalDouble(stats.oldestSessionAgeSeconds), "seconds");
    dashboardOverviewAddMetric(card, "oldest_unauth", "Oldest Unauth", dashboardOverviewFormatOptionalDuration(stats.oldestUnauthenticatedSessionAgeSeconds), stats.oldestUnauthenticatedSessionAgeSeconds ? "warning" : "healthy", dashboardOverviewOptionalDouble(stats.oldestUnauthenticatedSessionAgeSeconds), "seconds");
    dashboardOverviewAddMetric(card, "idle_timeout", "Idle Timeout", dashboardOverviewFormatDuration(stats.idleTimeoutMinutes * 60), "info", static_cast<double>(stats.idleTimeoutMinutes * 60), "seconds");
    dashboardOverviewAddMetric(card, "unauth_timeout", "Unauth Timeout", dashboardOverviewFormatDuration(stats.unauthenticatedTimeoutSeconds), "info", static_cast<double>(stats.unauthenticatedTimeoutSeconds), "seconds");
    dashboardOverviewAddMetric(card, "sweep_interval", "Sweep", dashboardOverviewFormatDuration(stats.sweepIntervalSeconds), "info", static_cast<double>(stats.sweepIntervalSeconds), "seconds");
    dashboardOverviewAddMetric(card, "opened_24h", "Opened 24h", stats.connectionsOpened24h ? dashboardOverviewFormatCount(*stats.connectionsOpened24h) : "unknown", "info", dashboardOverviewOptionalDouble(stats.connectionsOpened24h));
    dashboardOverviewAddMetric(card, "closed_24h", "Closed 24h", stats.connectionsClosed24h ? dashboardOverviewFormatCount(*stats.connectionsClosed24h) : "unknown", "info", dashboardOverviewOptionalDouble(stats.connectionsClosed24h));
    dashboardOverviewAddMetric(card, "errors_24h", "Errors 24h", stats.connectionErrors24h ? dashboardOverviewFormatCount(*stats.connectionErrors24h) : "unknown", dashboard_tone::zeroIsHealthy(stats.connectionErrors24h), dashboardOverviewOptionalDouble(stats.connectionErrors24h));
    dashboardOverviewAddMetric(card, "swept_24h", "Swept 24h", stats.sessionsSwept24h ? dashboardOverviewFormatCount(*stats.sessionsSwept24h) : "unknown", "info", dashboardOverviewOptionalDouble(stats.sessionsSwept24h));

    if (stats.status == "warning") {
        dashboardOverviewAddIssue(card, "system.connections.unauthenticated", "warning", "Unauthenticated websocket sessions are active.", "unauthenticated");
    } else if (stats.status == "critical") {
        dashboardOverviewAddIssue(card, "system.connections.unauthenticated_critical", "error", "Unauthenticated websocket sessions are accumulating.", "unauthenticated");
    } else if (stats.status == "unknown") {
        dashboardOverviewAddIssue(card, "system.connections.unknown", "warning", "Session manager state is unavailable.");
    }

    return card;
}

DashboardCardSummary dashboardOverviewBuildFuse(const DashboardOverviewCardDescriptor& descriptor) {
    const auto statsPtr = runtime::Deps::get().fuseStats;
    if (!statsPtr) return dashboardOverviewUnavailableCard(descriptor, "FUSE stats are not initialized.");

    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = statsPtr->snapshot();
    card.checkedAt = stats.checkedAt;

    if (stats.totalOps == 0) card.severity = "info";
    else if (stats.alertableErrorRate > 0.10) card.severity = "error";
    else if (stats.alertableErrorRate > 0.02) card.severity = "warning";
    else if (stats.totalErrors > 0) card.severity = "info";
    else card.severity = "healthy";

    card.summary = stats.totalOps == 0 ? "No FUSE traffic has been observed yet." : "FUSE operation telemetry is live.";
    std::uint64_t activeOpTypes = 0;
    double avgLatencyMs = 0.0;
    double maxLatencyMs = 0.0;
    std::uint64_t totalLatencyUs = 0;
    for (const auto& op : stats.ops) {
        if (op.count > 0) ++activeOpTypes;
        totalLatencyUs += op.totalUs;
        maxLatencyMs = std::max(maxLatencyMs, op.maxMs);
    }
    if (stats.totalOps > 0) avgLatencyMs = (static_cast<double>(totalLatencyUs) / 1000.0) / static_cast<double>(stats.totalOps);

    dashboardOverviewAddMetric(card, "ops", "Ops", dashboardOverviewFormatCount(stats.totalOps), card.severity, static_cast<double>(stats.totalOps));
    dashboardOverviewAddMetric(card, "successes", "Success Ops", dashboardOverviewFormatCount(stats.totalSuccesses), "healthy", static_cast<double>(stats.totalSuccesses));
    dashboardOverviewAddMetric(card, "alertable_error_rate", "Alertable Errors", dashboardOverviewFormatPercent(stats.alertableErrorRate), card.severity, stats.alertableErrorRate);
    dashboardOverviewAddMetric(card, "alertable_errors", "Alertable Ops", dashboardOverviewFormatCount(stats.alertableErrors), stats.alertableErrors == 0 ? "healthy" : card.severity, static_cast<double>(stats.alertableErrors));
    dashboardOverviewAddMetric(card, "error_rate", "Raw Errors", dashboardOverviewFormatPercent(stats.errorRate), stats.totalErrors == 0 ? "healthy" : "info", stats.errorRate);
    dashboardOverviewAddMetric(card, "total_errors", "Raw Error Ops", dashboardOverviewFormatCount(stats.totalErrors), stats.totalErrors == 0 ? "healthy" : "info", static_cast<double>(stats.totalErrors));
    dashboardOverviewAddMetric(card, "expected_errors", "Expected Ops", dashboardOverviewFormatCount(stats.expectedErrors), stats.expectedErrors == 0 ? "healthy" : "info", static_cast<double>(stats.expectedErrors));
    dashboardOverviewAddMetric(card, "open_handles", "Open Handles", dashboardOverviewFormatCount(stats.openHandlesCurrent), "info", static_cast<double>(stats.openHandlesCurrent));
    dashboardOverviewAddMetric(card, "open_peak", "Peak Handles", dashboardOverviewFormatCount(stats.openHandlesPeak), "info", static_cast<double>(stats.openHandlesPeak));
    dashboardOverviewAddMetric(card, "read_bytes", "Read", dashboardOverviewFormatBytes(stats.readBytes), "info", static_cast<double>(stats.readBytes), "bytes");
    dashboardOverviewAddMetric(card, "write_bytes", "Write", dashboardOverviewFormatBytes(stats.writeBytes), "info", static_cast<double>(stats.writeBytes), "bytes");
    dashboardOverviewAddMetric(card, "avg_latency", "Avg Latency", dashboardOverviewFormatMillis(avgLatencyMs), avgLatencyMs > 100.0 ? "warning" : "info", avgLatencyMs, "ms");
    dashboardOverviewAddMetric(card, "max_latency", "Max Latency", dashboardOverviewFormatMillis(maxLatencyMs), maxLatencyMs > 500.0 ? "warning" : "info", maxLatencyMs, "ms");
    dashboardOverviewAddMetric(card, "op_types", "Op Types", dashboardOverviewFormatCount(activeOpTypes), "info", static_cast<double>(activeOpTypes));
    dashboardOverviewAddMetric(card, "errno_types", "Errno Types", dashboardOverviewFormatCount(stats.topErrors.size()), dashboard_tone::fuseErrnoTypes(stats.topErrors.size(), stats.alertableErrnoTypes, card.severity), static_cast<double>(stats.topErrors.size()));

    if (stats.alertableErrorRate > 0.10) {
        dashboardOverviewAddIssue(card, "system.fuse.error_rate_high", "error", "FUSE alertable error rate is above 10%.", "alertable_error_rate");
    } else if (stats.alertableErrorRate > 0.02) {
        dashboardOverviewAddIssue(card, "system.fuse.error_rate_elevated", "warning", "FUSE alertable error rate is above 2%.", "alertable_error_rate");
    }

    return card;
}

DashboardCardSummary dashboardOverviewBuildCache(const DashboardOverviewCardDescriptor& descriptor, const CacheStatsSnapshot& stats, const std::uint64_t checkedAt) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto requests = stats.hits + stats.misses;
    const auto hitRate = CacheStats::hit_rate(stats);
    // No capacity means the cache has no byte cap (the FS metadata cache) or none was reported: occupancy, free and
    // capacity are unknown then, never 0% of 0 B (#160).
    const auto bounded = stats.capacity_bytes > 0;
    const auto occupancy = bounded
        ? std::optional<double>(static_cast<double>(stats.used_bytes) / static_cast<double>(stats.capacity_bytes))
        : std::nullopt;
    const auto freeBytes = bounded ? std::optional<double>(static_cast<double>(CacheStats::free_bytes(stats))) : std::nullopt;
    const auto capacityBytes = bounded ? std::optional<double>(static_cast<double>(stats.capacity_bytes)) : std::nullopt;
    const auto avgOpMs = CacheStats::avg_op_ms(stats);
    const auto maxOpMs = CacheStats::max_op_ms(stats);
    card.checkedAt = checkedAt;
    card.severity = requests == 0 ? "info" : "healthy";
    card.summary = requests == 0 ? "No cache traffic has been observed yet." : "Cache telemetry is live.";

    dashboardOverviewAddMetric(card, "hit_rate", "Hit Rate", dashboardOverviewFormatPercent(hitRate), card.severity, hitRate);
    dashboardOverviewAddMetric(card, "occupancy", "Occupancy", occupancy ? dashboardOverviewFormatPercent(*occupancy) : "unknown", !occupancy ? "unknown" : *occupancy > 0.90 ? "warning" : "info", occupancy);
    dashboardOverviewAddMetric(card, "used", "Used", dashboardOverviewFormatBytes(stats.used_bytes), "info", static_cast<double>(stats.used_bytes), "bytes");
    dashboardOverviewAddMetric(card, "free", "Free", bounded ? dashboardOverviewFormatBytes(CacheStats::free_bytes(stats)) : "unknown", bounded ? "info" : "unknown", freeBytes, "bytes");
    dashboardOverviewAddMetric(card, "capacity", "Capacity", bounded ? dashboardOverviewFormatBytes(stats.capacity_bytes) : "unknown", bounded ? "info" : "unknown", capacityBytes, "bytes");
    dashboardOverviewAddMetric(card, "requests", "Requests", dashboardOverviewFormatCount(requests), card.severity, static_cast<double>(requests));
    dashboardOverviewAddMetric(card, "hits", "Hits", dashboardOverviewFormatCount(stats.hits), "healthy", static_cast<double>(stats.hits));
    dashboardOverviewAddMetric(card, "misses", "Misses", dashboardOverviewFormatCount(stats.misses), stats.misses == 0 ? "healthy" : "info", static_cast<double>(stats.misses));
    dashboardOverviewAddMetric(card, "inserts", "Inserts", dashboardOverviewFormatCount(stats.inserts), "info", static_cast<double>(stats.inserts));
    dashboardOverviewAddMetric(card, "evictions", "Evictions", dashboardOverviewFormatCount(stats.evictions), stats.evictions == 0 ? "healthy" : "info", static_cast<double>(stats.evictions));
    dashboardOverviewAddMetric(card, "invalidations", "Invalidations", dashboardOverviewFormatCount(stats.invalidations), stats.invalidations == 0 ? "healthy" : "info", static_cast<double>(stats.invalidations));
    dashboardOverviewAddMetric(card, "read_bytes", "Read", dashboardOverviewFormatBytes(stats.bytes_read), "info", static_cast<double>(stats.bytes_read), "bytes");
    dashboardOverviewAddMetric(card, "write_bytes", "Written", dashboardOverviewFormatBytes(stats.bytes_written), "info", static_cast<double>(stats.bytes_written), "bytes");
    dashboardOverviewAddMetric(card, "work_ops", "Work Ops", dashboardOverviewFormatCount(stats.op_count), "info", static_cast<double>(stats.op_count));
    dashboardOverviewAddMetric(card, "avg_op", "Avg Work", dashboardOverviewFormatMillis(avgOpMs), avgOpMs > 100.0 ? "warning" : "info", avgOpMs, "ms");
    dashboardOverviewAddMetric(card, "max_op", "Max Work", dashboardOverviewFormatMillis(maxOpMs), maxOpMs > 500.0 ? "warning" : "info", maxOpMs, "ms");

    return card;
}

DashboardCardSummary dashboardOverviewBuildFsCache(const DashboardOverviewCardDescriptor& descriptor) {
    const auto cache = runtime::Deps::get().fsCache;
    if (!cache) return dashboardOverviewUnavailableCard(descriptor, "Filesystem cache registry is not initialized.");

    const auto stats = cache->stats();
    if (!stats) return dashboardOverviewUnavailableCard(descriptor, "Filesystem cache stats are unavailable.");

    return dashboardOverviewBuildCache(descriptor, *stats, dashboardOverviewUnixTimestamp());
}

DashboardCardSummary dashboardOverviewBuildHttpCache(const DashboardOverviewCardDescriptor& descriptor) {
    const auto cache = runtime::Deps::get().httpCacheStats;
    if (!cache) return dashboardOverviewUnavailableCard(descriptor, "HTTP preview cache stats are not initialized.");
    return dashboardOverviewBuildCache(descriptor, cache->snapshot(), dashboardOverviewUnixTimestamp());
}

DashboardCardSummary dashboardOverviewBuildStorage(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = StorageBackendStats::snapshot();
    card.checkedAt = stats.checkedAt;
    card.severity = dashboardOverviewSeverityFromStatus(stats.overallStatus);
    card.summary = stats.overallStatus == "healthy" ? "Storage backends are healthy." : "Storage backend posture needs attention.";

    const auto problemVaultCount = stats.inactiveVaultCount + stats.degradedVaultCount + stats.errorVaultCount;
    const auto healthyVaultCount = stats.vaultCountTotal > problemVaultCount ? stats.vaultCountTotal - problemVaultCount : 0;
    const auto providerCount = (stats.localVaultCount > 0 ? 1 : 0) + (stats.s3VaultCount > 0 ? 1 : 0);

    dashboardOverviewAddMetric(card, "vaults", "Vaults", dashboardOverviewFormatCount(stats.vaultCountTotal), card.severity, static_cast<double>(stats.vaultCountTotal));
    dashboardOverviewAddMetric(card, "healthy", "Healthy", dashboardOverviewFormatCount(healthyVaultCount), "healthy", static_cast<double>(healthyVaultCount));
    dashboardOverviewAddMetric(card, "problem", "Problem", dashboardOverviewFormatCount(problemVaultCount), problemVaultCount == 0 ? "healthy" : "warning", static_cast<double>(problemVaultCount));
    dashboardOverviewAddMetric(card, "active", "Active", dashboardOverviewFormatCount(stats.activeVaultCount), "healthy", static_cast<double>(stats.activeVaultCount));
    dashboardOverviewAddMetric(card, "inactive", "Inactive", dashboardOverviewFormatCount(stats.inactiveVaultCount), stats.inactiveVaultCount == 0 ? "healthy" : "warning", static_cast<double>(stats.inactiveVaultCount));
    dashboardOverviewAddMetric(card, "local", "Local", dashboardOverviewFormatCount(stats.localVaultCount), "info", static_cast<double>(stats.localVaultCount));
    dashboardOverviewAddMetric(card, "s3", "S3", dashboardOverviewFormatCount(stats.s3VaultCount), "info", static_cast<double>(stats.s3VaultCount));
    dashboardOverviewAddMetric(card, "providers", "Providers", dashboardOverviewFormatCount(providerCount), "info", static_cast<double>(providerCount));
    dashboardOverviewAddMetric(card, "degraded", "Degraded", dashboardOverviewFormatCount(stats.degradedVaultCount), stats.degradedVaultCount == 0 ? "healthy" : "warning", static_cast<double>(stats.degradedVaultCount));
    dashboardOverviewAddMetric(card, "backend_errors", "Errors", dashboardOverviewFormatCount(stats.errorVaultCount), stats.errorVaultCount == 0 ? "healthy" : "error", static_cast<double>(stats.errorVaultCount));

    if (stats.errorVaultCount > 0) {
        dashboardOverviewAddIssue(card, "system.storage.error_vaults", "error", std::to_string(stats.errorVaultCount) + " vault backend(s) are in error.", "vaults");
    }
    if (stats.degradedVaultCount > 0) {
        dashboardOverviewAddIssue(card, "system.storage.degraded_vaults", "warning", std::to_string(stats.degradedVaultCount) + " vault backend(s) are degraded.", "vaults");
    }
    if (stats.vaultCountTotal == 0) {
        dashboardOverviewAddIssue(card, "system.storage.no_vaults", "warning", "No vault backends are available.", "vaults");
    }

    return card;
}

DashboardCardSummary dashboardOverviewBuildDb(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::db::query::stats::DbStats::snapshot();
    if (!stats) return dashboardOverviewUnavailableCard(descriptor, "Database stats are unavailable.");

    card.checkedAt = stats->checkedAt;
    card.severity = dashboardOverviewSeverityFromStatus(stats->status);
    card.summary = stats->connected ? "Database telemetry is live." : "Database is not connected.";

    dashboardOverviewAddMetric(card, "size", "DB Size", dashboardOverviewFormatBytes(stats->dbSizeBytes), "info", static_cast<double>(stats->dbSizeBytes), "bytes");
    dashboardOverviewAddMetric(card, "connections", "Connections", dashboardOverviewFormatCount(stats->connectionsTotal), card.severity, static_cast<double>(stats->connectionsTotal));
    dashboardOverviewAddMetric(card, "active_connections", "Active", dashboardOverviewFormatCount(stats->connectionsActive), "info", static_cast<double>(stats->connectionsActive));
    dashboardOverviewAddMetric(card, "idle_connections", "Idle", dashboardOverviewFormatCount(stats->connectionsIdle), "info", static_cast<double>(stats->connectionsIdle));
    dashboardOverviewAddMetric(card, "idle_tx_connections", "Idle Tx", dashboardOverviewFormatCount(stats->connectionsIdleInTransaction), stats->connectionsIdleInTransaction == 0 ? "healthy" : "warning", static_cast<double>(stats->connectionsIdleInTransaction));
    dashboardOverviewAddMetric(card, "max_connections", "Max Conn", stats->connectionsMax ? dashboardOverviewFormatCount(*stats->connectionsMax) : "unknown", "info", dashboardOverviewOptionalDouble(stats->connectionsMax));
    dashboardOverviewAddMetric(card, "cache_hit", "Cache Hit", stats->cacheHitRatio ? dashboardOverviewFormatPercent(*stats->cacheHitRatio) : "unknown", stats->cacheHitRatio ? "healthy" : "unknown", stats->cacheHitRatio);
    dashboardOverviewAddMetric(card, "slow_queries", "Slow Queries", stats->slowQueryCount ? dashboardOverviewFormatCount(*stats->slowQueryCount) : "unknown", dashboard_tone::zeroIsHealthy(stats->slowQueryCount), dashboardOverviewOptionalDouble(stats->slowQueryCount));
    dashboardOverviewAddMetric(card, "deadlocks", "Deadlocks", dashboardOverviewFormatCount(stats->deadlocks), stats->deadlocks == 0 ? "healthy" : "error", static_cast<double>(stats->deadlocks));
    dashboardOverviewAddMetric(card, "temp_bytes", "Temp Bytes", dashboardOverviewFormatBytes(stats->tempBytes), "info", static_cast<double>(stats->tempBytes), "bytes");
    dashboardOverviewAddMetric(card, "oldest_tx", "Oldest Tx", !stats->connected ? "unknown" : dashboardOverviewFormatOptionalDuration(stats->oldestTransactionAgeSeconds), dashboard_tone::dbOldestTransaction(stats->connected, stats->oldestTransactionAgeSeconds), dashboardOverviewOptionalDouble(stats->oldestTransactionAgeSeconds), "seconds");
    dashboardOverviewAddMetric(card, "largest_tables", "Tables", dashboardOverviewFormatCount(stats->largestTables.size()), "info", static_cast<double>(stats->largestTables.size()));

    if (!stats->connected) {
        dashboardOverviewAddIssue(card, "system.db.disconnected", "error", stats->error.value_or("Database connection is unavailable."));
    } else if (stats->status == "critical") {
        dashboardOverviewAddIssue(card, "system.db.critical", "error", "Database health is critical.");
    } else if (stats->status == "warning") {
        dashboardOverviewAddIssue(card, "system.db.warning", "warning", "Database health needs attention.");
    }

    return card;
}

DashboardCardSummary dashboardOverviewBuildRetention(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::db::query::stats::RetentionStats::snapshot();
    if (!stats) return dashboardOverviewUnavailableCard(descriptor, "Retention stats are unavailable.");

    card.checkedAt = stats->checkedAt;
    card.severity = dashboardOverviewSeverityFromStatus(stats->cleanupStatus);
    card.summary = stats->cleanupStatus == "healthy" ? "Cleanup pressure is under control." : "Cleanup backlog needs attention.";

    dashboardOverviewAddMetric(card, "trash", "Trash", dashboardOverviewFormatCount(stats->trashedFilesCount), "info", static_cast<double>(stats->trashedFilesCount));
    dashboardOverviewAddMetric(card, "overdue", "Overdue", dashboardOverviewFormatCount(stats->trashedFilesPastRetentionCount), stats->trashedFilesPastRetentionCount == 0 ? "healthy" : "warning", static_cast<double>(stats->trashedFilesPastRetentionCount));
    dashboardOverviewAddMetric(card, "trash_bytes", "Trash Bytes", dashboardOverviewFormatBytes(stats->trashedBytesTotal), "info", static_cast<double>(stats->trashedBytesTotal), "bytes");
    dashboardOverviewAddMetric(card, "overdue_bytes", "Overdue Bytes", dashboardOverviewFormatBytes(stats->trashedBytesPastRetention), stats->trashedBytesPastRetention == 0 ? "healthy" : "warning", static_cast<double>(stats->trashedBytesPastRetention), "bytes");
    dashboardOverviewAddMetric(card, "oldest_trash", "Oldest Trash", dashboardOverviewFormatOptionalDuration(stats->oldestTrashedAgeSeconds), stats->oldestTrashedAgeSeconds ? "info" : "healthy", dashboardOverviewOptionalDouble(stats->oldestTrashedAgeSeconds), "seconds");
    dashboardOverviewAddMetric(card, "sync_events", "Sync Events", dashboardOverviewFormatCount(stats->syncEventsTotal), "info", static_cast<double>(stats->syncEventsTotal));
    dashboardOverviewAddMetric(card, "sync_backlog", "Sync Backlog", dashboardOverviewFormatCount(stats->syncEventsPastRetentionCount), stats->syncEventsPastRetentionCount == 0 ? "healthy" : "warning", static_cast<double>(stats->syncEventsPastRetentionCount));
    dashboardOverviewAddMetric(card, "audit_events", "Audit Events", dashboardOverviewFormatCount(stats->auditLogEntriesTotal), "info", static_cast<double>(stats->auditLogEntriesTotal));
    dashboardOverviewAddMetric(card, "audit_backlog", "Audit Backlog", dashboardOverviewFormatCount(stats->auditLogEntriesPastRetentionCount), stats->auditLogEntriesPastRetentionCount == 0 ? "healthy" : "warning", static_cast<double>(stats->auditLogEntriesPastRetentionCount));
    dashboardOverviewAddMetric(card, "share_events", "Share Events", dashboardOverviewFormatCount(stats->shareAccessEventsTotal), "info", static_cast<double>(stats->shareAccessEventsTotal));
    dashboardOverviewAddMetric(card, "cache_entries", "Cache Entries", dashboardOverviewFormatCount(stats->cacheEntriesTotal), "info", static_cast<double>(stats->cacheEntriesTotal));
    dashboardOverviewAddMetric(card, "cache_expired", "Expired Cache", dashboardOverviewFormatCount(stats->cacheEntriesExpired), stats->cacheEntriesExpired == 0 ? "healthy" : "warning", static_cast<double>(stats->cacheEntriesExpired));
    dashboardOverviewAddMetric(card, "cache_candidates", "Evictable", dashboardOverviewFormatCount(stats->cacheEvictionCandidates), stats->cacheEvictionCandidates == 0 ? "healthy" : "info", static_cast<double>(stats->cacheEvictionCandidates));
    dashboardOverviewAddMetric(card, "cache_bytes", "Cache", dashboardOverviewFormatBytes(stats->cacheBytesTotal), "info", static_cast<double>(stats->cacheBytesTotal), "bytes");
    dashboardOverviewAddMetric(card, "trash_retention", "Trash Retention", dashboardOverviewFormatDuration(stats->trashRetentionDays * 86400), "info", static_cast<double>(stats->trashRetentionDays * 86400), "seconds");
    dashboardOverviewAddMetric(card, "cache_expiry", "Cache Expiry", dashboardOverviewFormatDuration(stats->cacheExpiryDays * 86400), "info", static_cast<double>(stats->cacheExpiryDays * 86400), "seconds");

    if (stats->cleanupStatus == "overdue") {
        dashboardOverviewAddIssue(card, "system.retention.overdue", "error", "Retention cleanup is overdue.");
    } else if (stats->cleanupStatus == "warning") {
        dashboardOverviewAddIssue(card, "system.retention.warning", "warning", "Some retained records are past configured cleanup thresholds.");
    } else if (stats->cleanupStatus == "unknown") {
        dashboardOverviewAddIssue(card, "system.retention.unknown", "warning", "Retention configuration or source tables are unavailable.");
    }

    return card;
}

DashboardCardSummary dashboardOverviewBuildOperations(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::db::query::stats::OperationStats::snapshot();
    if (!stats) return dashboardOverviewUnavailableCard(descriptor, "Operation queue stats are unavailable.");

    card.checkedAt = stats->checkedAt;
    card.severity = dashboardOverviewSeverityFromStatus(stats->overallStatus);
    card.summary = stats->overallStatus == "healthy" ? "No stuck work is visible." : "Operation queue needs attention.";

    const auto uploadProgress =
        stats->uploadBytesExpectedActive > 0 ?
            static_cast<double>(stats->uploadBytesReceivedActive) / static_cast<double>(stats->uploadBytesExpectedActive)
        : 0.0;

    dashboardOverviewAddMetric(card, "pending", "Pending", dashboardOverviewFormatCount(stats->pendingOperations), stats->pendingOperations == 0 ? "healthy" : "warning", static_cast<double>(stats->pendingOperations));
    dashboardOverviewAddMetric(card, "in_progress", "In Progress", dashboardOverviewFormatCount(stats->inProgressOperations), "info", static_cast<double>(stats->inProgressOperations));
    dashboardOverviewAddMetric(card, "stalled", "Stalled", dashboardOverviewFormatCount(stats->stalledOperations + stats->stalledShareUploads), stats->stalledOperations + stats->stalledShareUploads == 0 ? "healthy" : "error", static_cast<double>(stats->stalledOperations + stats->stalledShareUploads));
    dashboardOverviewAddMetric(card, "failed_24h", "Failed 24h", dashboardOverviewFormatCount(stats->failedOperations24h + stats->failedShareUploads24h), stats->failedOperations24h + stats->failedShareUploads24h == 0 ? "healthy" : "warning", static_cast<double>(stats->failedOperations24h + stats->failedShareUploads24h));
    dashboardOverviewAddMetric(card, "cancelled_24h", "Cancelled 24h", dashboardOverviewFormatCount(stats->cancelledOperations24h), stats->cancelledOperations24h == 0 ? "healthy" : "warning", static_cast<double>(stats->cancelledOperations24h));
    dashboardOverviewAddMetric(card, "active_uploads", "Uploads", dashboardOverviewFormatCount(stats->activeShareUploads), stats->activeShareUploads == 0 ? "healthy" : "info", static_cast<double>(stats->activeShareUploads));
    dashboardOverviewAddMetric(card, "stalled_uploads", "Stalled Uploads", dashboardOverviewFormatCount(stats->stalledShareUploads), stats->stalledShareUploads == 0 ? "healthy" : "error", static_cast<double>(stats->stalledShareUploads));
    dashboardOverviewAddMetric(card, "failed_uploads_24h", "Failed Uploads", dashboardOverviewFormatCount(stats->failedShareUploads24h), stats->failedShareUploads24h == 0 ? "healthy" : "warning", static_cast<double>(stats->failedShareUploads24h));
    dashboardOverviewAddMetric(card, "upload_progress", "Upload Progress", dashboardOverviewFormatPercent(uploadProgress), "info", uploadProgress);
    dashboardOverviewAddMetric(card, "upload_received", "Upload In", dashboardOverviewFormatBytes(stats->uploadBytesReceivedActive), "info", static_cast<double>(stats->uploadBytesReceivedActive), "bytes");
    dashboardOverviewAddMetric(card, "upload_expected", "Upload Total", dashboardOverviewFormatBytes(stats->uploadBytesExpectedActive), "info", static_cast<double>(stats->uploadBytesExpectedActive), "bytes");
    dashboardOverviewAddMetric(card, "oldest_pending", "Oldest Pending", dashboardOverviewFormatOptionalDuration(stats->oldestPendingOperationAgeSeconds), stats->oldestPendingOperationAgeSeconds ? "warning" : "healthy", dashboardOverviewOptionalDouble(stats->oldestPendingOperationAgeSeconds), "seconds");
    dashboardOverviewAddMetric(card, "oldest_active", "Oldest Active", dashboardOverviewFormatOptionalDuration(stats->oldestInProgressOperationAgeSeconds), "info", dashboardOverviewOptionalDouble(stats->oldestInProgressOperationAgeSeconds), "seconds");
    dashboardOverviewAddMetric(card, "oldest_upload", "Oldest Upload", dashboardOverviewFormatOptionalDuration(stats->oldestActiveUploadAgeSeconds), "info", dashboardOverviewOptionalDouble(stats->oldestActiveUploadAgeSeconds), "seconds");
    dashboardOverviewAddMetric(card, "move_ops", "Move", dashboardOverviewFormatCount(dashboardOverviewMapCount(stats->operationsByType, "move")), "info", static_cast<double>(dashboardOverviewMapCount(stats->operationsByType, "move")));
    dashboardOverviewAddMetric(card, "copy_ops", "Copy", dashboardOverviewFormatCount(dashboardOverviewMapCount(stats->operationsByType, "copy")), "info", static_cast<double>(dashboardOverviewMapCount(stats->operationsByType, "copy")));
    dashboardOverviewAddMetric(card, "rename_ops", "Rename", dashboardOverviewFormatCount(dashboardOverviewMapCount(stats->operationsByType, "rename")), "info", static_cast<double>(dashboardOverviewMapCount(stats->operationsByType, "rename")));
    dashboardOverviewAddMetric(card, "success_ops", "Success", dashboardOverviewFormatCount(dashboardOverviewMapCount(stats->operationsByStatus, "success")), "healthy", static_cast<double>(dashboardOverviewMapCount(stats->operationsByStatus, "success")));
    dashboardOverviewAddMetric(card, "error_ops", "Error", dashboardOverviewFormatCount(dashboardOverviewMapCount(stats->operationsByStatus, "error")), dashboardOverviewMapCount(stats->operationsByStatus, "error") == 0 ? "healthy" : "warning", static_cast<double>(dashboardOverviewMapCount(stats->operationsByStatus, "error")));

    if (stats->stalledOperations + stats->stalledShareUploads > 0) {
        dashboardOverviewAddIssue(card, "system.operations.stalled", "error", "One or more operations or uploads appear stalled.", "stalled");
    } else if (stats->failedOperations24h + stats->failedShareUploads24h > 0) {
        dashboardOverviewAddIssue(card, "system.operations.failed_recent", "warning", "Operations or uploads failed in the last 24 hours.");
    } else if (stats->pendingOperations + stats->inProgressOperations + stats->activeShareUploads > 0) {
        dashboardOverviewAddIssue(card, "system.operations.active_work", "warning", "Queued or active work is present.");
    }

    return card;
}

DashboardCardSummary dashboardOverviewBuildTrends(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::db::query::stats::Snapshot::systemTrends(168);
    if (!stats) return dashboardOverviewUnavailableCard(descriptor, "Trend snapshots are unavailable.");

    card.checkedAt = stats->checkedAt;
    const auto seriesCount = stats->series.size();
    std::uint64_t pointCount = 0;
    std::uint64_t latestSampleAt = 0;
    std::uint64_t threadpoolSeriesCount = 0;
    std::uint64_t fuseSeriesCount = 0;
    std::uint64_t cacheSeriesCount = 0;
    std::uint64_t dbSeriesCount = 0;
    std::uint64_t operationSeriesCount = 0;
    for (const auto& series : stats->series) {
        pointCount += series.points.size();
        for (const auto& point : series.points) latestSampleAt = std::max(latestSampleAt, point.createdAt);
        if (dashboardOverviewTrendBelongsToCard("system.threadpools", series.key)) ++threadpoolSeriesCount;
        if (dashboardOverviewTrendBelongsToCard("system.fuse", series.key)) ++fuseSeriesCount;
        if (dashboardOverviewTrendBelongsToCard("system.fs_cache", series.key) || dashboardOverviewTrendBelongsToCard("system.http_cache", series.key)) ++cacheSeriesCount;
        if (dashboardOverviewTrendBelongsToCard("system.db", series.key)) ++dbSeriesCount;
        if (dashboardOverviewTrendBelongsToCard("system.operations", series.key)) ++operationSeriesCount;
    }

    card.severity = pointCount == 0 ? "info" : "healthy";
    card.summary = pointCount == 0 ? "No historical trend samples are available yet." : "Historical trend samples are available.";
    dashboardOverviewAddMetric(card, "window", "Window", std::to_string(stats->windowHours) + "h", "info");
    if (latestSampleAt > 0) {
        const auto now = dashboardOverviewUnixTimestamp();
        const auto latestAge = now > latestSampleAt ? now - latestSampleAt : 0;
        dashboardOverviewAddMetric(card, "latest_sample_age", "Latest", dashboardOverviewFormatDuration(latestAge), latestAge <= 3600 ? "healthy" : "info", static_cast<double>(latestAge), "seconds");
        dashboardOverviewAddMetric(card, "coverage", "Coverage", dashboardOverviewFormatCount(seriesCount) + " series", card.severity, static_cast<double>(seriesCount));
    } else {
        dashboardOverviewAddMetric(card, "latest_sample_age", "Latest", "none", "info");
        dashboardOverviewAddMetric(card, "coverage", "Coverage", "no data", "info", 0.0);
    }
    dashboardOverviewAddMetric(card, "series", "Series", dashboardOverviewFormatCount(seriesCount), card.severity, static_cast<double>(seriesCount));
    dashboardOverviewAddMetric(card, "points", "Points", dashboardOverviewFormatCount(pointCount), card.severity, static_cast<double>(pointCount));
    dashboardOverviewAddMetric(card, "threadpool_series", "Threadpool", dashboardOverviewFormatCount(threadpoolSeriesCount), "info", static_cast<double>(threadpoolSeriesCount));
    dashboardOverviewAddMetric(card, "fuse_series", "FUSE", dashboardOverviewFormatCount(fuseSeriesCount), "info", static_cast<double>(fuseSeriesCount));
    dashboardOverviewAddMetric(card, "cache_series", "Cache", dashboardOverviewFormatCount(cacheSeriesCount), "info", static_cast<double>(cacheSeriesCount));
    dashboardOverviewAddMetric(card, "db_series", "DB", dashboardOverviewFormatCount(dbSeriesCount), "info", static_cast<double>(dbSeriesCount));
    dashboardOverviewAddMetric(card, "operation_series", "Operations", dashboardOverviewFormatCount(operationSeriesCount), "info", static_cast<double>(operationSeriesCount));

    return card;
}

double dashboardOverviewBudgetNumber(const std::string& amount) {
    try {
        return std::stod(amount.empty() ? "0" : amount);
    } catch (...) {
        return 0.0;
    }
}

std::optional<double> dashboardOverviewBudgetAmount(const std::optional<std::string>& amount) {
    if (!amount || amount->empty()) return std::nullopt;
    try {
        return std::stod(*amount);
    } catch (...) {
        return std::nullopt;
    }
}

// Cents, or enough significant digits to be honest about a sub-cent amount (the console formats the same way).
std::string dashboardOverviewFormatMoney(const double amount, const std::string& currency) {
    const auto magnitude = std::fabs(amount);
    int digits = 2;
    if (magnitude > 0.0 && magnitude < 0.01)
        digits = std::min(8, std::max(2, static_cast<int>(-std::floor(std::log10(magnitude))) + 2));
    char buffer[64];
    std::snprintf(buffer, sizeof(buffer), "%.*f %s", digits, amount, currency.c_str());
    return buffer;
}

// Money carries numeric_value plus the ISO currency as its unit (#160). An amount that was not measured (no monthly
// budget window, no projection yet) is "unknown" with a null numeric_value, never a fake zero.
void dashboardOverviewAddMoneyMetric(
    DashboardCardSummary& card,
    std::string key,
    std::string label,
    const std::optional<double> amount,
    const std::string& currency,
    std::string tone
) {
    const auto code = currency.empty() ? std::string{"USD"} : currency;
    dashboardOverviewAddMetric(
        card,
        std::move(key),
        std::move(label),
        amount ? dashboardOverviewFormatMoney(*amount, code) : "unknown",
        amount ? std::move(tone) : "unknown",
        amount,
        code
    );
}

std::string dashboardOverviewBudgetSeverity(const vh::storage::s3::pricing::PriceBudgetDashboardStats& stats) {
    if (stats.critical_notifications > 0 || stats.blocked_syncs_24h > 0) return "error";
    if (stats.warning_notifications > 0 || stats.pending_overrides > 0) return "warning";
    return stats.active_policies > 0 ? "healthy" : "info";
}

DashboardCardSummary dashboardOverviewBuildPricingBudget(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats();
    card.severity = dashboardOverviewBudgetSeverity(stats);
    card.summary = stats.active_policies == 0
        ? "No S3 price budget policies are active."
        : "S3 price budget guardrails are configured.";

    dashboardOverviewAddMetric(card, "active_policies", "Policies", dashboardOverviewFormatCount(stats.active_policies), stats.active_policies == 0 ? "info" : "healthy", stats.active_policies);
    dashboardOverviewAddMetric(card, "blocked_syncs", "Blocked 24h", dashboardOverviewFormatCount(stats.blocked_syncs_24h), stats.blocked_syncs_24h == 0 ? "healthy" : "error", stats.blocked_syncs_24h);
    dashboardOverviewAddMetric(card, "warnings", "Warnings", dashboardOverviewFormatCount(stats.warning_notifications), stats.warning_notifications == 0 ? "healthy" : "warning", stats.warning_notifications);
    dashboardOverviewAddMetric(card, "critical", "Critical", dashboardOverviewFormatCount(stats.critical_notifications), stats.critical_notifications == 0 ? "healthy" : "error", stats.critical_notifications);
    dashboardOverviewAddMoneyMetric(card, "monthly_spend", "Month", dashboardOverviewBudgetAmount(stats.current_monthly_spend), stats.currency, "info");
    dashboardOverviewAddMoneyMetric(card, "projected_monthly", "Projected", dashboardOverviewBudgetAmount(stats.projected_monthly_spend), stats.currency, stats.critical_notifications ? "error" : "info");
    dashboardOverviewAddMetric(card, "pending_overrides", "Overrides", dashboardOverviewFormatCount(stats.pending_overrides), stats.pending_overrides == 0 ? "healthy" : "warning", stats.pending_overrides);

    if (stats.blocked_syncs_24h > 0)
        dashboardOverviewAddIssue(card, "system.pricing.blocked", "error", "S3 price budget enforcement blocked syncs in the last 24 hours.", "blocked_syncs");
    else if (stats.warning_notifications > 0)
        dashboardOverviewAddIssue(card, "system.pricing.warnings", "warning", "Unacknowledged S3 price budget warnings are active.", "warnings");

    return card;
}

DashboardCardSummary dashboardOverviewBuildPricingProviders(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats();
    card.severity = dashboardOverviewBudgetSeverity(stats);
    card.summary = "Provider S3 budget pressure is based on active policy trends.";

    std::map<std::string, double> totals;
    std::map<std::string, double> projections;
    for (const auto& trend : stats.trends) {
        if (trend.window_type != "monthly") continue;
        const auto provider = trend.provider_key.value_or("global");
        totals[provider] += dashboardOverviewBudgetNumber(trend.total_cost);
        if (trend.projected_window_cost) projections[provider] += dashboardOverviewBudgetNumber(*trend.projected_window_cost);
    }

    // A provider without a monthly budget window has no measured spend: unknown, not zero.
    const auto amountFor = [](const std::map<std::string, double>& values, const std::string& provider) {
        const auto it = values.find(provider);
        return it == values.end() ? std::nullopt : std::optional<double>(it->second);
    };
    for (const auto& provider : {std::string{"aws-s3"}, std::string{"cloudflare-r2"}}) {
        dashboardOverviewAddMoneyMetric(card, provider + "_current", provider, amountFor(totals, provider), stats.currency, "info");
        dashboardOverviewAddMoneyMetric(card, provider + "_projected", provider + " Proj", amountFor(projections, provider), stats.currency, "info");
    }
    dashboardOverviewAddMetric(card, "provider_policies", "Policies", dashboardOverviewFormatCount(stats.active_policies), stats.active_policies == 0 ? "info" : "healthy", stats.active_policies);
    return card;
}

DashboardCardSummary dashboardOverviewBuildPricingVaults(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats();
    card.severity = dashboardOverviewBudgetSeverity(stats);

    std::map<std::uint32_t, double> totals;
    std::uint32_t overageVaults = 0;
    for (const auto& trend : stats.trends) {
        if (!trend.vault_id || trend.window_type != "monthly") continue;
        totals[*trend.vault_id] += dashboardOverviewBudgetNumber(trend.total_cost);
        if (trend.projected_overage) ++overageVaults;
    }
    const auto top = std::max_element(totals.begin(), totals.end(), [](const auto& a, const auto& b) {
        return a.second < b.second;
    });

    card.summary = totals.empty() ? "No vault-scoped S3 budget spend is visible." : "Vault spend trends are available.";
    dashboardOverviewAddMetric(card, "tracked_vaults", "Vaults", dashboardOverviewFormatCount(totals.size()), totals.empty() ? "info" : "healthy", static_cast<double>(totals.size()));
    dashboardOverviewAddMetric(card, "top_vault", "Top Vault", top == totals.end() ? "none" : std::to_string(top->first), "info");
    dashboardOverviewAddMoneyMetric(card, "top_spend", "Top Spend", top == totals.end() ? std::nullopt : std::optional<double>(top->second), stats.currency, "info");
    dashboardOverviewAddMetric(card, "projected_overage_vaults", "Overage", dashboardOverviewFormatCount(overageVaults), overageVaults == 0 ? "healthy" : "warning", overageVaults);
    if (overageVaults > 0)
        dashboardOverviewAddIssue(card, "system.pricing.vault_overage", "warning", "One or more vaults are projected to exceed a budget.", "projected_overage_vaults");
    return card;
}

DashboardCardSummary dashboardOverviewBuildPricingAlerts(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats();
    card.severity = stats.critical_notifications > 0 ? "error" : stats.warning_notifications > 0 ? "warning" : "healthy";
    card.summary = stats.unacknowledged_notifications == 0 ? "No active budget alerts require acknowledgement." : "Budget alerts require review.";

    dashboardOverviewAddMetric(card, "unacknowledged", "Unacked", dashboardOverviewFormatCount(stats.unacknowledged_notifications), stats.unacknowledged_notifications == 0 ? "healthy" : "warning", stats.unacknowledged_notifications);
    dashboardOverviewAddMetric(card, "critical", "Critical", dashboardOverviewFormatCount(stats.critical_notifications), stats.critical_notifications == 0 ? "healthy" : "error", stats.critical_notifications);
    dashboardOverviewAddMetric(card, "warnings", "Warnings", dashboardOverviewFormatCount(stats.warning_notifications), stats.warning_notifications == 0 ? "healthy" : "warning", stats.warning_notifications);
    dashboardOverviewAddMetric(card, "active_alerts", "Active", dashboardOverviewFormatCount(stats.active_notifications.size()), stats.active_notifications.empty() ? "healthy" : "warning", static_cast<double>(stats.active_notifications.size()));
    if (stats.critical_notifications > 0)
        dashboardOverviewAddIssue(card, "system.pricing.critical_alerts", "error", "Critical S3 budget notifications are unacknowledged.", "critical");
    return card;
}

DashboardCardSummary dashboardOverviewBuildPricingCatalog(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats();
    std::uint32_t stale = 0;
    std::uint32_t unverified = 0;
    std::uint32_t unsupported = 0;
    for (const auto& notification : stats.active_notifications) {
        if (notification.type == "pricing.catalog_stale") ++stale;
        if (notification.type == "pricing.catalog_unverified") ++unverified;
        if (notification.type == "pricing.provider_unsupported") ++unsupported;
    }
    const auto issues = stale + unverified + unsupported;
    card.severity = issues == 0 ? "healthy" : "warning";
    card.summary = issues == 0 ? "No active pricing catalog health alerts." : "Pricing catalog health alerts are active.";
    dashboardOverviewAddMetric(card, "catalog_issues", "Issues", dashboardOverviewFormatCount(issues), issues == 0 ? "healthy" : "warning", issues);
    dashboardOverviewAddMetric(card, "stale", "Stale", dashboardOverviewFormatCount(stale), stale == 0 ? "healthy" : "warning", stale);
    dashboardOverviewAddMetric(card, "unverified", "Unverified", dashboardOverviewFormatCount(unverified), unverified == 0 ? "healthy" : "warning", unverified);
    dashboardOverviewAddMetric(card, "unsupported", "Unsupported", dashboardOverviewFormatCount(unsupported), unsupported == 0 ? "healthy" : "warning", unsupported);
    if (issues > 0)
        dashboardOverviewAddIssue(card, "system.pricing.catalog", "warning", "Pricing catalog health affects budget enforcement.", "catalog_issues");
    return card;
}

DashboardCardSummary dashboardOverviewBuildPricingOverrides(const DashboardOverviewCardDescriptor& descriptor) {
    auto card = dashboardOverviewBaseCard(descriptor);
    const auto stats = vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats();
    std::uint32_t approved = 0;
    std::uint32_t denied = 0;
    std::uint32_t used = 0;
    for (const auto& budgetOverride : stats.recent_overrides) {
        if (budgetOverride.status == "approved") ++approved;
        if (budgetOverride.status == "denied") ++denied;
        if (budgetOverride.status == "used") ++used;
    }
    card.severity = stats.blocked_syncs_24h > 0 ? "error" : stats.pending_overrides > 0 ? "warning" : "healthy";
    card.summary = stats.pending_overrides > 0 ? "Budget override requests are waiting for review." : "No pending budget override requests.";
    dashboardOverviewAddMetric(card, "blocked_syncs", "Blocked 24h", dashboardOverviewFormatCount(stats.blocked_syncs_24h), stats.blocked_syncs_24h == 0 ? "healthy" : "error", stats.blocked_syncs_24h);
    dashboardOverviewAddMetric(card, "pending", "Pending", dashboardOverviewFormatCount(stats.pending_overrides), stats.pending_overrides == 0 ? "healthy" : "warning", stats.pending_overrides);
    dashboardOverviewAddMetric(card, "approved", "Approved", dashboardOverviewFormatCount(approved), "info", approved);
    dashboardOverviewAddMetric(card, "denied", "Denied", dashboardOverviewFormatCount(denied), denied == 0 ? "healthy" : "info", denied);
    dashboardOverviewAddMetric(card, "used", "Used", dashboardOverviewFormatCount(used), "info", used);
    if (stats.pending_overrides > 0)
        dashboardOverviewAddIssue(card, "system.pricing.pending_overrides", "warning", "S3 price budget override requests are pending.", "pending");
    return card;
}

DashboardCardSummary dashboardOverviewBuildCard(const DashboardOverviewCardDescriptor& descriptor) {
    try {
        if (descriptor.id == "system.health") return dashboardOverviewBuildSystemHealth(descriptor);
        if (descriptor.id == "system.threadpools") return dashboardOverviewBuildThreadPools(descriptor);
        if (descriptor.id == "system.connections") return dashboardOverviewBuildConnections(descriptor);
        if (descriptor.id == "system.fuse") return dashboardOverviewBuildFuse(descriptor);
        if (descriptor.id == "system.fs_cache") return dashboardOverviewBuildFsCache(descriptor);
        if (descriptor.id == "system.http_cache") return dashboardOverviewBuildHttpCache(descriptor);
        if (descriptor.id == "system.storage") return dashboardOverviewBuildStorage(descriptor);
        if (descriptor.id == "system.db") return dashboardOverviewBuildDb(descriptor);
        if (descriptor.id == "system.retention") return dashboardOverviewBuildRetention(descriptor);
        if (descriptor.id == "system.operations") return dashboardOverviewBuildOperations(descriptor);
        if (descriptor.id == "system.pricing_budget") return dashboardOverviewBuildPricingBudget(descriptor);
        if (descriptor.id == "system.pricing_providers") return dashboardOverviewBuildPricingProviders(descriptor);
        if (descriptor.id == "system.pricing_vaults") return dashboardOverviewBuildPricingVaults(descriptor);
        if (descriptor.id == "system.pricing_alerts") return dashboardOverviewBuildPricingAlerts(descriptor);
        if (descriptor.id == "system.pricing_catalog") return dashboardOverviewBuildPricingCatalog(descriptor);
        if (descriptor.id == "system.pricing_overrides") return dashboardOverviewBuildPricingOverrides(descriptor);
        if (descriptor.id == "system.trends") return dashboardOverviewBuildTrends(descriptor);
        return dashboardOverviewUnavailableCard(descriptor, "Unknown dashboard card.");
    } catch (const std::exception& e) {
        return dashboardOverviewUnavailableCard(descriptor, e.what());
    }
}

DashboardOverviewCardDescriptor dashboardOverviewDescriptorForUnknown(const std::string& id) {
    return {
        .id = id,
        .sectionId = "runtime",
        .title = id.empty() ? "Unknown Card" : id,
        .description = "Requested dashboard card is not registered.",
        .href = "/health",
        .variant = "tiles",
        .size = "2x1",
    };
}

std::vector<DashboardOverviewCardDescriptor> dashboardOverviewRequestedDescriptors(const DashboardOverviewRequest& request) {
    const auto descriptors = dashboardOverviewCardDescriptors();
    if (request.cards.empty()) return descriptors;

    std::unordered_map<std::string, DashboardOverviewCardDescriptor> byId;
    for (const auto& descriptor : descriptors) byId.emplace(descriptor.id, descriptor);

    std::vector<DashboardOverviewCardDescriptor> out;
    out.reserve(request.cards.size());
    for (const auto& requested : request.cards) {
        auto descriptor = byId.contains(requested.id) ? byId.at(requested.id) : dashboardOverviewDescriptorForUnknown(requested.id);
        if (!requested.variant.empty()) descriptor.variant = requested.variant;
        if (!requested.size.empty()) descriptor.size = requested.size;
        out.push_back(std::move(descriptor));
    }
    return out;
}

DashboardSectionSummary dashboardOverviewBuildSection(
    const DashboardOverviewSectionDescriptor& descriptor,
    const std::vector<DashboardCardSummary>& cards
) {
    DashboardSectionSummary section;
    section.id = descriptor.id;
    section.title = descriptor.title;
    section.description = descriptor.description;
    section.href = descriptor.href;
    section.severity = "healthy";
    section.checkedAt = dashboardOverviewUnixTimestamp();

    bool hasCard = false;
    bool hasUnknown = false;
    for (const auto& card : cards) {
        if (card.sectionId != descriptor.id) continue;
        hasCard = true;
        if (card.severity == "unknown") hasUnknown = true;
        if (card.available) section.severity = dashboardOverviewWorstSeverity(section.severity, card.severity);
        section.warningCount += static_cast<std::uint32_t>(card.warnings.size());
        section.errorCount += static_cast<std::uint32_t>(card.errors.size());
        section.checkedAt = std::max(section.checkedAt, card.checkedAt);

        for (const auto& metric : card.metrics) {
            if (section.metrics.size() >= 4) break;
            auto sectionMetric = metric;
            sectionMetric.href = card.href;
            section.metrics.push_back(std::move(sectionMetric));
        }
        for (const auto& warning : card.warnings) section.warnings.push_back(warning);
        for (const auto& error : card.errors) section.errors.push_back(error);
    }

    if (!hasCard) {
        section.severity = "unavailable";
        section.summary = "No dashboard cards are registered for this section.";
    } else if (section.errorCount > 0) {
        section.summary = section.title + " has errors that need attention.";
    } else if (section.warningCount > 0) {
        section.summary = section.title + " has warnings to review.";
    } else if (hasUnknown) {
        section.severity = dashboardOverviewWorstSeverity(section.severity, "unknown");
        section.summary = section.title + " has unknown telemetry.";
    } else {
        section.summary = section.title + " looks healthy.";
    }

    return section;
}

void dashboardOverviewAddAttention(DashboardOverview& overview, const DashboardCardSummary& card, const DashboardIssueSummary& issue) {
    overview.attention.push_back({
        .code = issue.code,
        .severity = issue.severity,
        .cardId = card.id,
        .title = card.title,
        .message = issue.message,
        .href = issue.href ? issue.href : std::optional<std::string>(card.href),
        .metricKey = issue.metricKey,
    });
}

}

namespace dashboard_tone {

std::string zeroIsHealthy(const std::optional<std::uint64_t>& value, const std::string& nonZeroTone) {
    if (!value) return "unknown";
    return *value == 0 ? "healthy" : nonZeroTone;
}

std::string dbOldestTransaction(const bool connected, const std::optional<std::uint64_t>& ageSeconds) {
    if (!connected) return "unknown";
    if (!ageSeconds) return "healthy";
    if (*ageSeconds >= kDbOldestTransactionCriticalSeconds) return "error";
    if (*ageSeconds >= kDbOldestTransactionWarningSeconds) return "warning";
    return "healthy";
}

std::string fuseErrnoTypes(const std::size_t errnoTypes, const std::uint64_t alertableErrnoTypes, const std::string& cardSeverity) {
    if (errnoTypes == 0) return "healthy";
    if (alertableErrnoTypes == 0) return "info";
    return cardSeverity;
}

}

DashboardOverview DashboardOverview::snapshot(const DashboardOverviewRequest& request) {
    return build(request, true);
}

DashboardOverview DashboardOverview::severity() {
    return build({}, false);
}

DashboardOverview DashboardOverview::build(const DashboardOverviewRequest& request, const bool full) {
    DashboardOverview overview;
    overview.checkedAt = dashboardOverviewUnixTimestamp();

    const auto descriptors = dashboardOverviewRequestedDescriptors(request);
    overview.cards.reserve(descriptors.size());
    for (const auto& descriptor : descriptors) {
        auto card = dashboardOverviewBuildCard(descriptor);
        card.variant = descriptor.variant;
        card.size = descriptor.size;
        overview.checkedAt = std::max(overview.checkedAt, card.checkedAt);
        overview.cards.push_back(std::move(card));
    }

    const auto wantsSeries = std::any_of(overview.cards.begin(), overview.cards.end(), [](const auto& card) {
        return card.variant == "visual" || card.variant == "graph" || card.id == "system.trends";
    });
    // Trend series and sections are presentation only; severity never reads them, so the severity-only build skips
    // both (and the trend query).
    if (full && wantsSeries) {
        try {
            dashboardOverviewAttachTrendSeries(overview.cards, vh::db::query::stats::Snapshot::systemTrends(24));
        } catch (...) {
            // Trend series are an optional dashboard-home enhancement. Card summaries remain valid without them.
        }
    }

    if (full) {
        for (const auto& descriptor : dashboardOverviewSectionDescriptors()) {
            overview.sections.push_back(dashboardOverviewBuildSection(descriptor, overview.cards));
        }
    }

    std::string worst = "healthy";
    bool sawVisibleStatus = false;
    bool sawUnknown = false;
    for (const auto& card : overview.cards) {
        if (!card.available) continue;
        sawVisibleStatus = true;
        if (card.severity == "unknown") sawUnknown = true;
        worst = dashboardOverviewWorstSeverity(worst, card.severity);
        overview.warningCount += static_cast<std::uint32_t>(card.warnings.size());
        overview.errorCount += static_cast<std::uint32_t>(card.errors.size());
        for (const auto& error : card.errors) dashboardOverviewAddAttention(overview, card, error);
        for (const auto& warning : card.warnings) dashboardOverviewAddAttention(overview, card, warning);
    }

    if (overview.errorCount > 0) overview.overallStatus = "error";
    else if (overview.warningCount > 0) overview.overallStatus = "warning";
    else if (!sawVisibleStatus) overview.overallStatus = "unavailable";
    else if (sawUnknown || worst == "unknown") overview.overallStatus = "unknown";
    else overview.overallStatus = worst;

    std::sort(overview.attention.begin(), overview.attention.end(), [](const auto& a, const auto& b) {
        if (dashboardOverviewSeverityRank(a.severity) != dashboardOverviewSeverityRank(b.severity))
            return dashboardOverviewSeverityRank(a.severity) > dashboardOverviewSeverityRank(b.severity);
        return a.title < b.title;
    });

    return overview;
}

DashboardOverviewRequest dashboardOverviewRequestFromJson(const nlohmann::json& payload) {
    DashboardOverviewRequest request;
    if (!payload.is_object()) return request;

    request.scope = payload.value("scope", request.scope);
    request.mode = payload.value("mode", request.mode);

    const auto cardsIt = payload.find("cards");
    if (cardsIt != payload.end() && cardsIt->is_array()) {
        for (const auto& raw : *cardsIt) {
            if (!raw.is_object()) continue;
            DashboardCardRequest card{
                .id = raw.value("id", std::string{}),
                .variant = raw.value("variant", std::string{}),
                .size = raw.value("size", std::string{}),
            };
            if (!card.id.empty()) request.cards.push_back(std::move(card));
        }
    }

    return request;
}

void to_json(nlohmann::json& j, const DashboardMetricSummary& metric) {
    j = nlohmann::json{
        {"key", metric.key},
        {"label", metric.label},
        {"value", metric.value},
        {"unit", dashboardOverviewNullable(metric.unit)},
        {"tone", metric.tone},
        {"numeric_value", dashboardOverviewNullable(metric.numericValue)},
        {"href", dashboardOverviewNullable(metric.href)},
    };
}

void to_json(nlohmann::json& j, const DashboardGraphPoint& point) {
    j = nlohmann::json{
        {"created_at", point.createdAt},
        {"value", point.value},
    };
}

void to_json(nlohmann::json& j, const DashboardGraphSeries& series) {
    j = nlohmann::json{
        {"key", series.key},
        {"label", series.label},
        {"unit", series.unit},
        {"tone", series.tone},
        {"points", series.points},
    };
}

void to_json(nlohmann::json& j, const DashboardIssueSummary& issue) {
    j = nlohmann::json{
        {"code", issue.code},
        {"severity", issue.severity},
        {"message", issue.message},
        {"href", dashboardOverviewNullable(issue.href)},
        {"metric_key", dashboardOverviewNullable(issue.metricKey)},
    };
}

void to_json(nlohmann::json& j, const DashboardAttentionItem& item) {
    j = nlohmann::json{
        {"code", item.code},
        {"severity", item.severity},
        {"card_id", item.cardId},
        {"title", item.title},
        {"message", item.message},
        {"href", dashboardOverviewNullable(item.href)},
        {"metric_key", dashboardOverviewNullable(item.metricKey)},
    };
}

void to_json(nlohmann::json& j, const DashboardCardSummary& card) {
    j = nlohmann::json{
        {"id", card.id},
        {"section_id", card.sectionId},
        {"title", card.title},
        {"description", card.description},
        {"href", card.href},
        {"variant", card.variant},
        {"size", card.size},
        {"severity", card.severity},
        {"available", card.available},
        {"unavailable_reason", dashboardOverviewNullable(card.unavailableReason)},
        {"summary", card.summary},
        {"metrics", card.metrics},
        {"series", card.series},
        {"warnings", card.warnings},
        {"errors", card.errors},
        {"checked_at", card.checkedAt},
    };
}

void to_json(nlohmann::json& j, const DashboardSectionSummary& section) {
    j = nlohmann::json{
        {"id", section.id},
        {"title", section.title},
        {"description", section.description},
        {"href", section.href},
        {"severity", section.severity},
        {"warning_count", section.warningCount},
        {"error_count", section.errorCount},
        {"summary", section.summary},
        {"metrics", section.metrics},
        {"warnings", section.warnings},
        {"errors", section.errors},
        {"checked_at", section.checkedAt},
    };
}

nlohmann::json dashboardSeverityJson(const DashboardOverview& overview) {
    return nlohmann::json{
        {"overall_status", overview.overallStatus},
        {"error_count", overview.errorCount},
        {"warning_count", overview.warningCount},
        {"checked_at", overview.checkedAt},
    };
}

void to_json(nlohmann::json& j, const DashboardOverview& overview) {
    j = nlohmann::json{
        {"overall_status", overview.overallStatus},
        {"warning_count", overview.warningCount},
        {"error_count", overview.errorCount},
        {"checked_at", overview.checkedAt},
        {"attention", overview.attention},
        {"sections", overview.sections},
        {"cards", overview.cards},
    };
}

}
