// ws book: stats.* (core/src/protocols/ws/handler/Stats.cpp → ops::stats). Every answer is {stats: <model>}; a
// rollup with no data yet is null where the handler says so (stats never fake health).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

// ops::stats::requireVault / requireSystem throw ops::Denied (data.code "denied"); the router refuses a missing or
// expired token with UNAUTHORIZED.
std::vector<std::string> statsRefusals() { return {"unauthorized", "denied"}; }

WsField statsWindowHours() {
    return uinteger("window_hours")
        .opt()
        .gen(gen::intRange(1, 720))
        .desc("Trend window in hours: default 168 (also for 0), clamped to 1..720.");
}

// A vault-scoped stats command: {vault_id} → {stats}; owner, or admin vault View/ViewStats on the vault.
WsCommandUsage statsVaultCommand(std::string name, std::string what, std::string model, const bool nullable,
                                 std::vector<WsField> extraPayload = {}) {
    std::vector<WsField> payload{vaultId()};
    for (auto& f : extraPayload) payload.push_back(std::move(f));
    auto stats = object("stats", std::move(model));
    if (nullable) stats = stats.nullable().desc("null while there is no data for the vault yet.");
    return {.command = std::move(name),
            .description = std::move(what) + " Needs vault ownership or the admin vault View/ViewStats permission "
                                             "on the vault.",
            .payload = std::move(payload),
            .response = {std::move(stats)},
            .refusal_codes = statsRefusals(),
            .client_timeout = kDefaultTimeout};
}

// A system stats command (no payload) → {stats}; needs admin.stats.view.
WsCommandUsage statsSystemCommand(std::string name, std::string what, std::string model, const bool nullable) {
    auto stats = object("stats", std::move(model));
    if (nullable) stats = stats.nullable().desc("null while there is no data yet.");
    return {.command = std::move(name),
            .description = std::move(what) + " Needs admin.stats.view.",
            .input = "none",
            .response = {std::move(stats)},
            .refusal_codes = statsRefusals(),
            .client_timeout = kDefaultTimeout};
}

}

std::vector<WsCommandUsage> statsCommands() {
    std::vector<WsCommandUsage> out;

    // ---- per vault ----
    out.push_back(statsVaultCommand("stats.vault",
        "A vault's capacity and usage figures (computed on the stats thread pool).", "VaultStat", false));
    out.push_back(statsVaultCommand("stats.vault.sync", "A vault's sync health.", "VaultSyncHealth", true));
    out.push_back(statsVaultCommand("stats.vault.activity", "A vault's recent activity: counts, top users and paths, "
                                    "recent events.", "VaultActivity", true));
    out.push_back(statsVaultCommand("stats.vault.shares", "A vault's share-link statistics.", "VaultShareStats", true));
    out.push_back(statsVaultCommand("stats.vault.recovery", "A vault's recovery posture (keys, versions, trash).",
                                    "VaultRecoveryStats", true));
    out.push_back(statsVaultCommand("stats.vault.operations", "A vault's filesystem operation queue and recent errors.",
                                    "OperationStats", true));
    out.push_back(statsVaultCommand("stats.vault.storage", "A vault's storage backend figures.", "StorageBackendStats",
                                    false));
    out.push_back(statsVaultCommand("stats.vault.retention", "A vault's retention (trash, versions, cleanup) figures.",
                                    "RetentionStats", true));
    out.push_back(statsVaultCommand("stats.vault.trends", "A vault's metric trend series from the stats rollups.",
                                    "StatsTrends", true, {statsWindowHours()}));
    out.push_back(statsVaultCommand("stats.vault.security", "A vault's security posture.", "VaultSecurity", true));
    out.push_back(statsVaultCommand("stats.vault.pricing", "A vault's S3 price budget dashboard figures.",
                                    "PriceBudgetDashboardStats", false));

    // ---- dashboard ----
    out.push_back({
        .command = "stats.dashboard.overview",
        .description = "The health dashboard: overall status, attention items, sections and the requested cards (all "
                       "default cards when cards is empty). Needs admin.stats.view.",
        .payload = {str("scope").opt().desc("Default \"system\"."),
                    str("mode").opt().desc("Default \"dashboard_home\"."),
                    objectArray("cards", "", {str("id"), str("variant").opt(), str("size").opt()})
                        .opt()
                        .desc("Cards to compute; entries without an id are ignored.")},
        .response = {object("stats", "DashboardOverview")},
        .refusal_codes = statsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "stats.dashboard.severity",
        .description = "The overall severity of the default overview cards without cards, sections or series (the "
                       "console's health dot). Needs admin.stats.view.",
        .input = "none",
        .response = {object("stats", "DashboardSeverity")},
        .refusal_codes = statsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- system ----
    out.push_back(statsSystemCommand("stats.system.health",
        "Runtime services, protocols, dependencies and a live bounded database probe.", "SystemHealth", false));
    out.push_back(statsSystemCommand("stats.system.threadpools", "Thread pool queue depth and worker pressure.",
                                     "ThreadPoolManagerSnapshot", false));
    out.push_back(statsSystemCommand("stats.system.fuse",
        "FUSE operation counters, latencies and errno totals. Fails (no data.code) when the daemon has no FUSE stats.",
        "FuseStatsSnapshot", false));
    out.push_back(statsSystemCommand("stats.system.db", "Database size, connections and largest tables.", "DbStats",
                                     true));
    out.push_back(statsSystemCommand("stats.system.operations", "Filesystem operation queue and recent errors, all "
                                     "vaults.", "OperationStats", true));
    out.push_back(statsSystemCommand("stats.system.connections", "Live websocket and share connections.",
                                     "ConnectionStats", false));
    out.push_back(statsSystemCommand("stats.system.storage", "Storage backend figures for every vault.",
                                     "StorageBackendStats", false));
    out.push_back(statsSystemCommand("stats.system.retention", "Retention figures for every vault.", "RetentionStats",
                                     true));
    out.push_back(statsSystemCommand("stats.system.pricing", "System-wide S3 price budget dashboard figures.",
                                     "PriceBudgetDashboardStats", false));
    out.push_back(statsSystemCommand("stats.fs.cache",
        "Filesystem metadata cache counters. Fails (no data.code) when the cache has no stats.", "CacheStatsSnapshot",
        false));
    out.push_back(statsSystemCommand("stats.http.cache", "HTTP preview cache counters.", "CacheStatsSnapshot", false));

    out.push_back({
        .command = "stats.system.trends",
        .description = "System metric trend series from the stats rollups. Needs admin.stats.view.",
        .payload = {statsWindowHours()},
        .response = {object("stats", "StatsTrends").nullable().desc("null while there is no data yet.")},
        .refusal_codes = statsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "stats.pricing.budget",
        .description = "S3 price budget dashboard figures: system-wide without vault_id (needs admin.stats.view), one "
                       "vault's with it (vault ownership or admin vault View/ViewStats). A non-object payload means "
                       "system-wide.",
        .payload = {uinteger("vault_id").opt().nullable().gen(gen::ref("vault", {"id"})).desc("Vault id; null or "
                                                                                              "absent: system-wide.")},
        .response = {object("stats", "PriceBudgetDashboardStats")},
        .refusal_codes = statsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
