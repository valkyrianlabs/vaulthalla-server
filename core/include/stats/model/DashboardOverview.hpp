#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

namespace vh::stats::model {

// Trend series attached to an overview card: at most this many series (the console draws three), each trimmed to the
// most recent points. Keeps stats.dashboard.overview small enough to poll (#160).
inline constexpr std::size_t kDashboardOverviewMaxSeriesPerCard = 3;
inline constexpr std::size_t kDashboardOverviewMaxPointsPerSeries = 64;

struct DashboardMetricSummary {
    std::string key;
    std::string label;
    std::string value;
    std::optional<std::string> unit;
    std::string tone = "unknown";
    std::optional<double> numericValue;
    std::optional<std::string> href;
};

struct DashboardGraphPoint {
    std::uint64_t createdAt = 0;
    double value = 0.0;
};

struct DashboardGraphSeries {
    std::string key;
    std::string label;
    std::string unit;
    std::string tone = "info";
    std::vector<DashboardGraphPoint> points;
};

struct DashboardIssueSummary {
    std::string code;
    std::string severity;
    std::string message;
    std::optional<std::string> href;
    std::optional<std::string> metricKey;
};

struct DashboardAttentionItem {
    std::string code;
    std::string severity;
    std::string cardId;
    std::string title;
    std::string message;
    std::optional<std::string> href;
    std::optional<std::string> metricKey;
    // What an operator said about the finding (health::annotate): "active", "acknowledged" or "silenced". The
    // severity above is never changed by it.
    std::string state = "active";
};

struct DashboardCardRequest {
    std::string id;
    std::string variant;
    std::string size;
};

struct DashboardOverviewRequest {
    std::string scope = "system";
    std::string mode = "dashboard_home";
    std::vector<DashboardCardRequest> cards;
};

struct DashboardCardSummary {
    std::string id;
    std::string sectionId;
    std::string title;
    std::string description;
    std::string href;
    std::string variant = "tiles";
    std::string size = "2x1";
    std::string severity = "unknown";
    bool available = true;
    std::optional<std::string> unavailableReason;
    std::string summary;
    std::vector<DashboardMetricSummary> metrics;
    std::vector<DashboardGraphSeries> series;
    std::vector<DashboardIssueSummary> warnings;
    std::vector<DashboardIssueSummary> errors;
    std::uint64_t checkedAt = 0;
};

struct DashboardSectionSummary {
    std::string id;
    std::string title;
    std::string description;
    std::string href;
    std::string severity = "unknown";
    std::uint32_t warningCount = 0;
    std::uint32_t errorCount = 0;
    std::string summary;
    std::vector<DashboardMetricSummary> metrics;
    std::vector<DashboardIssueSummary> warnings;
    std::vector<DashboardIssueSummary> errors;
    std::uint64_t checkedAt = 0;
};

struct DashboardOverview {
    std::string overallStatus = "unknown";
    std::uint32_t warningCount = 0;
    std::uint32_t errorCount = 0;
    // The counts without acknowledged and silenced findings: what still asks for a person (health::annotate). Until
    // annotated they equal the counts above, so nothing reads as dealt with by default.
    std::uint32_t unattendedWarningCount = 0;
    std::uint32_t unattendedErrorCount = 0;
    std::uint64_t checkedAt = 0;
    std::vector<DashboardSectionSummary> sections;
    std::vector<DashboardCardSummary> cards;
    std::vector<DashboardAttentionItem> attention;

    static DashboardOverview snapshot(const DashboardOverviewRequest& request = {});
    // The default dashboard's overall_status / warning_count / error_count / checked_at from the same cards and the
    // same aggregation as snapshot(), without trend series or sections. Cards and attention are filled but callers
    // serialize only the four summary fields (stats.dashboard.severity).
    static DashboardOverview severity();

private:
    static DashboardOverview build(const DashboardOverviewRequest& request, bool full);
};

// Metric tones the dashboard cards share (exposed for tests). A value that was not measured is "unknown", never
// "healthy": stats never fake health.
namespace dashboard_tone {

// A count that should be zero: unknown when unmeasured, healthy at zero, otherwise nonZeroTone.
std::string zeroIsHealthy(const std::optional<std::uint64_t>& value, const std::string& nonZeroTone = "warning");

// The database's oldest open transaction against kDbOldestTransaction{Warning,Critical}Seconds. Connected with no
// age means no transaction is open (healthy); disconnected means it was not measured (unknown).
std::string dbOldestTransaction(bool connected, const std::optional<std::uint64_t>& ageSeconds);

// FUSE errno variety: only errnos with alertable occurrences can carry the card's severity. Expected errnos alone
// (lookup ENOENT, statfs EACCES) are info.
std::string fuseErrnoTypes(std::size_t errnoTypes, std::uint64_t alertableErrnoTypes, const std::string& cardSeverity);

}

// The stats.dashboard.severity payload: {overall_status, error_count, warning_count, checked_at}.
nlohmann::json dashboardSeverityJson(const DashboardOverview& overview);

DashboardOverviewRequest dashboardOverviewRequestFromJson(const nlohmann::json& payload);

void to_json(nlohmann::json& j, const DashboardMetricSummary& metric);
void to_json(nlohmann::json& j, const DashboardGraphPoint& point);
void to_json(nlohmann::json& j, const DashboardGraphSeries& series);
void to_json(nlohmann::json& j, const DashboardIssueSummary& issue);
void to_json(nlohmann::json& j, const DashboardAttentionItem& item);
void to_json(nlohmann::json& j, const DashboardCardSummary& card);
void to_json(nlohmann::json& j, const DashboardSectionSummary& section);
void to_json(nlohmann::json& j, const DashboardOverview& overview);

}
