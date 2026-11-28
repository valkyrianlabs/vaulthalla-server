#include "health/Catalog.hpp"

#include <algorithm>

namespace vh::health {

namespace {

Remedy open(std::string label, std::string href) {
    return {.id = "open", .label = std::move(label), .kind = "open", .href = std::move(href)};
}

FindingClass cls(std::string code, std::string cardId, std::string title, std::string maxSeverity, const bool notifies,
                 std::vector<Remedy> remedies) {
    return {.code = std::move(code),
            .cardId = std::move(cardId),
            .title = std::move(title),
            .maxSeverity = std::move(maxSeverity),
            .notifies = notifies,
            .remedies = std::move(remedies)};
}

// The console's pages (DashboardOverview.cpp, dashboardOverviewDescriptors). Desktop maps them to its own sections.
constexpr auto kRuntime = "/health/runtime";
constexpr auto kFilesystem = "/health/filesystem#fuse";
constexpr auto kStorage = "/health/storage#storage-backend";
constexpr auto kDatabase = "/health/storage#database";
constexpr auto kRetention = "/health/storage#retention";
constexpr auto kOperations = "/health/activity#operation-queue";
constexpr auto kSpend = "/cost#spend";
constexpr auto kCostAlerts = "/cost#budget-alerts";
constexpr auto kOverrides = "/cost#overrides";

std::vector<FindingClass> build() {
    // `notifies`: every error, and the warnings that mean something is wrong or waits on a person. A warning that
    // describes normal work does not interrupt anyone: queued or active work is raised by every upload.
    return {
        cls("system.health.unhealthy", "system.health", "The server is not healthy", "error", true,
            {open("Open system health", std::string(kRuntime) + "#system-health")}),
        cls("system.health.fuse_missing", "system.health", "The filesystem is not mounted", "warning", true,
            {open("Open system health", std::string(kRuntime) + "#system-health")}),
        cls("system.threadpools.pressured", "system.threadpools", "Worker pools are under pressure", "warning", false,
            {open("Open thread pools", std::string(kRuntime) + "#thread-pools")}),
        cls("system.threadpools.saturated", "system.threadpools", "Worker pools are saturated", "error", true,
            {open("Open thread pools", std::string(kRuntime) + "#thread-pools")}),
        cls("system.threadpools.degraded", "system.threadpools", "A worker pool is degraded", "error", true,
            {open("Open thread pools", std::string(kRuntime) + "#thread-pools")}),
        cls("system.connections.unauthenticated_critical", "system.connections",
            "Unauthenticated connections are piling up", "error", true,
            {open("Open connections", std::string(kRuntime) + "#connections")}),
        cls("system.connections.unknown", "system.connections", "Connection state is unavailable", "warning", false,
            {open("Open connections", std::string(kRuntime) + "#connections")}),
        cls("system.fuse.error_rate_high", "system.fuse", "Filesystem errors are high", "error", true,
            {open("Open the filesystem", kFilesystem)}),
        cls("system.fuse.error_rate_elevated", "system.fuse", "Filesystem errors are elevated", "warning", true,
            {open("Open the filesystem", kFilesystem)}),
        cls("system.storage.error_vaults", "system.storage", "A vault's storage is in error", "error", true,
            {open("Open storage", kStorage)}),
        cls("system.storage.degraded_vaults", "system.storage", "A vault's storage is degraded", "warning", true,
            {open("Open storage", kStorage)}),
        cls("system.storage.no_vaults", "system.storage", "No vault storage is available", "warning", true,
            {open("Open storage", kStorage)}),
        cls("system.db.disconnected", "system.db", "The database is unreachable", "error", true,
            {open("Open the database", kDatabase)}),
        cls("system.db.critical", "system.db", "The database is in a critical state", "error", true,
            {open("Open the database", kDatabase)}),
        cls("system.db.warning", "system.db", "The database needs attention", "warning", true,
            {open("Open the database", kDatabase)}),
        cls("system.retention.overdue", "system.retention", "Cleanup is overdue", "error", true,
            {open("Open retention", kRetention)}),
        cls("system.retention.warning", "system.retention", "Records are past their cleanup time", "warning", false,
            {open("Open retention", kRetention)}),
        cls("system.retention.unknown", "system.retention", "Retention state is unavailable", "warning", false,
            {open("Open retention", kRetention)}),
        cls("system.operations.stalled", "system.operations", "An operation or upload has stalled", "error", true,
            {open("Open the operation queue", kOperations)}),
        cls("system.operations.failed_recent", "system.operations", "Operations failed in the last day", "warning",
            true, {open("Open the operation queue", kOperations)}),
        cls("system.operations.active_work", "system.operations", "Work is queued or running", "warning", false,
            {open("Open the operation queue", kOperations)}),
        cls("system.pricing.blocked", "system.pricing_budget", "A budget blocked syncs", "error", true,
            {open("Open spend", kSpend)}),
        cls("system.pricing.warnings", "system.pricing_budget", "Budget warnings are waiting", "warning", true,
            {open("Review cost alerts", kCostAlerts)}),
        cls("system.pricing.vault_overage", "system.pricing_vaults", "A vault is heading over budget", "warning", true,
            {open("Open spend", kSpend)}),
        cls("system.pricing.critical_alerts", "system.pricing_alerts", "Critical budget alerts are waiting", "error",
            true, {open("Review cost alerts", kCostAlerts)}),
        cls("system.pricing.catalog", "system.pricing_catalog", "The price catalog needs attention", "warning", true,
            {open("Review cost alerts", kCostAlerts)}),
        cls("system.pricing.pending_overrides", "system.pricing_overrides", "Budget override requests are waiting",
            "warning", true, {open("Review override requests", kOverrides)}),
    };
}

}

const std::vector<FindingClass>& catalog() {
    static const std::vector<FindingClass> all = build();
    return all;
}

const FindingClass* findClass(const std::string_view code) {
    const auto& all = catalog();
    const auto it = std::ranges::find(all, code, &FindingClass::code);
    return it == all.end() ? nullptr : &*it;
}

void to_json(nlohmann::json& j, const Remedy& remedy) {
    j = nlohmann::json{
        {"id", remedy.id},
        {"label", remedy.label},
        {"kind", remedy.kind},
        {"href", remedy.href ? nlohmann::json(*remedy.href) : nlohmann::json(nullptr)},
        {"command", remedy.command ? nlohmann::json(*remedy.command) : nlohmann::json(nullptr)},
        {"payload", remedy.payload},
        {"effect", remedy.effect ? nlohmann::json(*remedy.effect) : nlohmann::json(nullptr)},
    };
}

void to_json(nlohmann::json& j, const FindingClass& cls) {
    j = nlohmann::json{
        {"class", cls.code},
        {"card_id", cls.cardId},
        {"title", cls.title},
        {"max_severity", cls.maxSeverity},
        {"notifies", cls.notifies},
        {"remedies", cls.remedies},
    };
}

}
