#include "protocols/ws/handler/Stats.hpp"
#include "ops/Error.hpp"
#include "ops/Stats.hpp"

#include "concurrency/ThreadPoolManager.hpp"
#include "concurrency/ThreadPool.hpp"
#include "db/query/stats/DbStats.hpp"
#include "db/query/stats/OperationStats.hpp"
#include "db/query/stats/RetentionStats.hpp"
#include "db/query/stats/Snapshot.hpp"
#include "db/query/share/Stats.hpp"
#include "db/query/sync/Stats.hpp"
#include "db/query/vault/Activity.hpp"
#include "db/query/vault/Recovery.hpp"
#include "db/query/vault/Security.hpp"
#include "nlohmann/json.hpp"
#include "protocols/ws/Session.hpp"
#include "vault/task/Stats.hpp"
#include "vault/model/Stat.hpp"
#include "identities/User.hpp"
#include "stats/model/CacheStats.hpp"
#include "stats/model/ConnectionStats.hpp"
#include "health/Findings.hpp"
#include "stats/model/DashboardOverview.hpp"
#include "stats/model/DbStats.hpp"
#include "stats/model/FuseStats.hpp"
#include "stats/model/OperationStats.hpp"
#include "stats/model/RetentionStats.hpp"
#include "stats/model/StorageBackendStats.hpp"
#include "stats/model/StatsTrends.hpp"
#include "stats/model/SystemHealth.hpp"
#include "stats/model/ThreadPoolStats.hpp"
#include "stats/model/VaultActivity.hpp"
#include "stats/model/VaultRecovery.hpp"
#include "stats/model/VaultSecurity.hpp"
#include "stats/model/VaultShareStats.hpp"
#include "stats/model/VaultSyncHealth.hpp"
#include "runtime/Deps.hpp"
#include "fs/cache/Registry.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"

#include <future>
#include <utility>
#include <array>
#include <algorithm>

using namespace vh::stats;
using namespace vh::rbac;

namespace vh::protocols::ws::handler {

namespace {

std::uint32_t statsTrendWindowHours(const json& payload) {
    if (!payload.is_object()) return 168;
    const auto raw = payload.value("window_hours", 168u);
    return std::clamp<std::uint32_t>(raw == 0 ? 168 : raw, 1, 24 * 30);
}

}

json Stats::vault(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "stats");

    const auto task = std::make_shared<vault::task::Stats>(vaultId);
    auto future = task->getFuture().value();
    concurrency::ThreadPoolManager::instance().statsPool()->submit(task);

    if (const auto stats = std::get<std::shared_ptr<vault::model::Stat>>(future.get()))
        return {{"stats", stats}};

    throw std::runtime_error("Unable to load vault stats");
}

json Stats::vaultSync(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "sync stats");

    const auto stats = vh::db::query::sync::Stats::getVaultSyncHealth(vaultId);
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::vaultActivity(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "activity stats");

    const auto stats = vh::db::query::vault::Activity::getVaultActivity(vaultId);
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::vaultShares(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "share stats");

    const auto stats = vh::db::query::share::Stats::getVaultShareStats(vaultId);
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::vaultRecovery(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "recovery stats");

    const auto stats = vh::db::query::vault::Recovery::getVaultRecovery(vaultId);
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::vaultOperations(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "operation stats");

    const auto stats = vh::db::query::stats::OperationStats::snapshotForVault(vaultId);
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::vaultStorage(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "storage backend stats");

    return {{"stats", vh::stats::model::StorageBackendStats::snapshotForVault(vaultId)}};
}

json Stats::vaultRetention(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "retention stats");

    const auto stats = vh::db::query::stats::RetentionStats::snapshotForVault(vaultId);
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::vaultTrends(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "trend stats");

    const auto stats = vh::db::query::stats::Snapshot::vaultTrends(vaultId, statsTrendWindowHours(payload));
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::vaultSecurity(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& vaultId = payload.at("vault_id").get<uint32_t>();

    vh::ops::stats::requireVault(session->user, vaultId, "security stats");

    const auto stats = vh::db::query::vault::Security::getVaultSecurity(vaultId);
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::dashboardOverview(const json& payload, const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "dashboard overview stats");
    auto overview = vh::stats::model::DashboardOverview::snapshot(vh::stats::model::dashboardOverviewRequestFromJson(payload));
    // What operators said about the findings (acknowledged, silenced); severities and counts are untouched.
    vh::health::annotate(overview);
    return {{"stats", overview}};
}

json Stats::dashboardSeverity(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "dashboard overview stats");
    auto overview = vh::stats::model::DashboardOverview::severity();
    vh::health::annotate(overview);
    // Wrapped in `stats` like every other stats.* response.
    return {{"stats", vh::stats::model::dashboardSeverityJson(overview)}};
}

json Stats::systemHealth(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "system health");
    return {{"stats", vh::stats::model::SystemHealth::snapshot()}};
}

json Stats::systemThreadPools(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "thread pool stats");
    return {{"stats", vh::stats::model::ThreadPoolManagerSnapshot::snapshot()}};
}

json Stats::systemFuse(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "FUSE stats");
    const auto& stats = runtime::Deps::get().fuseStats;
    if (!stats) throw std::runtime_error("No FUSE stats available.");
    return {{"stats", stats->snapshot()}};
}

json Stats::systemDb(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "database health");
    const auto stats = vh::db::query::stats::DbStats::snapshot();
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::systemOperations(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "operation queue stats");
    const auto stats = vh::db::query::stats::OperationStats::snapshot();
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::systemConnections(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "connection stats");
    return {{"stats", vh::stats::model::ConnectionStats::snapshot()}};
}

json Stats::systemStorage(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "storage backend stats");
    return {{"stats", vh::stats::model::StorageBackendStats::snapshot()}};
}

json Stats::systemRetention(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "retention stats");
    const auto stats = vh::db::query::stats::RetentionStats::snapshot();
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::systemTrends(const json& payload, const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "trend stats");
    const auto stats = vh::db::query::stats::Snapshot::systemTrends(statsTrendWindowHours(payload));
    return {{"stats", stats ? json(*stats) : json(nullptr)}};
}

json Stats::pricingBudget(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object() || !payload.contains("vault_id") || payload.at("vault_id").is_null()) {
        vh::ops::stats::requireSystem(session->user, "system pricing budget stats");
        return {{"stats", vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats()}};
    }

    const auto vaultId = payload.at("vault_id").get<std::uint32_t>();
    vh::ops::stats::requireVault(session->user, vaultId, "pricing budget stats");

    return {{"stats", vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats(vaultId)}};
}

json Stats::vaultPricing(const json& payload, const std::shared_ptr<Session>& session) {
    const auto vaultId = payload.at("vault_id").get<std::uint32_t>();
    vh::ops::stats::requireVault(session->user, vaultId, "pricing stats");

    return {{"stats", vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats(vaultId)}};
}

json Stats::systemPricing(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "system pricing stats");
    return {{"stats", vh::storage::s3::pricing::PriceBudgetService{}.dashboardStats()}};
}

json Stats::fsCache(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "cache stats");
    const auto stats = runtime::Deps::get().fsCache->stats();
    if (!stats) throw std::runtime_error("No cache stats available.");
    return {{"stats", stats}};
}

json Stats::httpCache(const std::shared_ptr<Session>& session) {
    vh::ops::stats::requireSystem(session->user, "cache stats");
    return {{"stats", runtime::Deps::get().httpCacheStats->snapshot()}};
}

}
