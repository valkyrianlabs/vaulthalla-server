// Contract models: stats serializers against their declared shapes (see model_suites.hpp). Every instance is built
// in memory and serialized by the real to_json (core/src/stats/model/*.cpp, vault/model/{Stat,Capacity}.cpp,
// sync/model/*.cpp); nothing here touches the database or the runtime.

#include "model_suites.hpp"

#include "fs/model/File.hpp"
#include "stats/model/CacheStats.hpp"
#include "stats/model/ConnectionStats.hpp"
#include "stats/model/DashboardOverview.hpp"
#include "stats/model/DashboardPreferences.hpp"
#include "stats/model/DbStats.hpp"
#include "stats/model/FuseStats.hpp"
#include "stats/model/OperationStats.hpp"
#include "stats/model/RetentionStats.hpp"
#include "stats/model/StatsTrends.hpp"
#include "stats/model/StorageBackendStats.hpp"
#include "stats/model/SystemHealth.hpp"
#include "stats/model/ThreadPoolStats.hpp"
#include "stats/model/VaultActivity.hpp"
#include "stats/model/VaultRecovery.hpp"
#include "stats/model/VaultSecurity.hpp"
#include "stats/model/VaultShareStats.hpp"
#include "stats/model/VaultSyncHealth.hpp"
#include "sync/model/Conflict.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/Throughput.hpp"
#include "vault/model/Capacity.hpp"
#include "vault/model/Stat.hpp"

#include <memory>
#include <string>
#include <utility>

namespace vh::test_contract_models_stats {

using json = nlohmann::json;
namespace sm = vh::stats::model;
namespace syncm = vh::sync::model;

std::shared_ptr<vh::fs::model::File> conflictFile(const unsigned int id, const std::string& name) {
    auto f = std::make_shared<vh::fs::model::File>();
    f->id = id;
    f->name = name;
    f->path = "/docs/" + name;
    f->size_bytes = 42;
    return f;
}

std::shared_ptr<syncm::Event> fullSyncEvent() {
    auto e = std::make_shared<syncm::Event>();
    e->id = 7;
    e->vault_id = 3;
    e->run_uuid = "run-1";
    e->timestamp_begin = 1700000000;
    e->timestamp_end = 1700000100;
    e->heartbeat_at = 1700000090;
    e->status = syncm::Event::Status::SUCCESS;
    e->trigger = syncm::Event::Trigger::MANUAL;
    e->retry_attempt = 1;
    e->stall_reason = "slow";
    e->error_code = "e1";
    e->error_message = "boom";
    e->num_ops_total = 10;
    e->s3_estimated_cost = "0.01";
    e->s3_estimated_cost_currency = "USD";
    e->s3_price_profile_id = "aws-s3-standard";
    e->s3_price_catalog_version = "2026-10";
    e->s3_price_confidence_level = "exact";
    e->s3_price_estimate_mode = "actual";
    e->s3_price_free_tier_policy = "ignore";
    e->s3_price_free_tiers_applied = false;
    e->s3_price_unknowns_json = R"(["egress"])";
    e->s3_price_breakdown_json = R"([{"meter_key":"request_write","cost":"0.01"}])";
    e->s3_budget_estimated_cost = "0.02";
    e->s3_budget_estimated_cost_currency = "USD";
    e->s3_budget_estimate_mode = "worst_case";
    e->s3_budget_free_tier_policy = "ignore";
    e->s3_budget_free_tiers_applied = true;
    e->divergence_detected = true;
    e->local_state_hash = "aa";
    e->remote_state_hash = "bb";
    e->config_hash = "cc";

    auto t = std::make_unique<syncm::Throughput>();
    t->id = 1;
    t->run_uuid = "run-1";
    t->metric_type = syncm::Throughput::UPLOAD;
    t->num_ops = 4;
    t->size_bytes = 4096;
    t->duration_ms = 12;
    e->throughputs.push_back(std::move(t));

    auto conflict = std::make_shared<syncm::Conflict>();
    conflict->id = 5;
    conflict->event_id = 7;
    conflict->file_id = 9;
    conflict->type = syncm::Conflict::Type::BOTH;
    conflict->resolution = syncm::Conflict::Resolution::KEPT_LOCAL;
    conflict->resolved_at = 1700000200;
    conflict->created_at = 1700000050;
    conflict->artifacts.local = syncm::Artifact(conflictFile(9, "a.txt"), syncm::Artifact::Side::LOCAL);
    conflict->artifacts.upstream = syncm::Artifact(conflictFile(9, "a.txt"), syncm::Artifact::Side::UPSTREAM);
    conflict->reasons.emplace_back("size_mismatch", "File sizes differ.");
    e->conflicts.push_back(conflict);
    return e;
}

void checkVaultStats(vh::test::contract_models::Checker& c) {
    auto capacity = std::make_shared<vh::vault::model::Capacity>();
    capacity->capacity = 1 << 20;
    capacity->logical_size = 300;
    capacity->physical_size = 400;
    capacity->cache_size = 10;
    capacity->free_space = 1000;
    capacity->file_count = 3;
    capacity->directory_count = 1;
    capacity->average_file_size_bytes = 100;
    capacity->largest_file_size_bytes = 200;
    capacity->top_file_extensions_by_size[0] = {"txt", 300};
    c.check(vh::vault::model::statJson(capacity, fullSyncEvent()), "VaultStat", "vault stat with a sync run");
    c.check(vh::vault::model::statJson(capacity, nullptr), "VaultStat", "vault stat before any sync run");

    sm::VaultSyncHealth health;
    health.vaultId = 3;
    health.overallStatus = sm::VaultSyncOverallStatus::Warning;
    health.currentState = sm::VaultSyncCurrentState::Running;
    health.syncEnabled = true;
    health.syncIntervalSeconds = 300;
    health.configuredStrategy = "sync";
    health.conflictPolicy = "ask";
    health.s3BudgetListRequests = 1;
    health.s3BudgetHeadRequests = 2;
    health.s3BudgetGetRequests = 3;
    health.s3BudgetPutRequests = 4;
    health.s3BudgetCopyRequests = 5;
    health.s3BudgetDeleteRequests = 6;
    health.s3BudgetDownloadedBytes = 7;
    health.s3BudgetWarning = "unlimited";
    health.maxRemoteIndexAgeSeconds = 600;
    health.latestEvent = fullSyncEvent();
    health.latestEventId = 7;
    health.latestRunUuid = "run-1";
    health.lastSyncAt = 1700000100;
    health.lastSuccessAt = 1700000100;
    health.lastSuccessAgeSeconds = 60;
    health.oldestActiveAgeSeconds = 5;
    health.latestHeartbeatAgeSeconds = 2;
    health.avgThroughputBytesPerSec24h = 1.5;
    health.peakThroughputBytesPerSec24h = 9.25;
    health.localStateHash = "aa";
    health.remoteStateHash = "bb";
    health.remoteIndexSource = "list";
    health.remoteIndexIndexedAt = 1700000000;
    health.lastErrorCode = "e1";
    health.lastErrorMessage = "boom";
    health.lastStallReason = "slow";
    c.check(json(health), "VaultSyncHealth", "sync health with every optional set");
    c.check(json(sm::VaultSyncHealth{}), "VaultSyncHealth", "sync health without config or history");

    sm::VaultActivity activity;
    activity.vaultId = 3;
    activity.lastActivityAt = 1700000000;
    activity.lastActivityAction = "upload";
    activity.topActiveUsers.push_back({.userId = 2, .userName = "ann", .count = 4});
    activity.topActiveUsers.push_back({});
    activity.topTouchedPaths.push_back({.path = "/a", .action = "upload", .count = 1, .bytes = 9});
    activity.recentActivity.push_back({.source = "fs", .action = "upload", .path = "/a", .userId = 2,
                                       .userName = "ann", .status = "success", .error = "none", .bytes = 9,
                                       .occurredAt = 1700000000});
    c.check(json(activity), "VaultActivity", "vault activity");
    c.check(json(sm::VaultActivity{}), "VaultActivity", "vault activity without data");

    sm::VaultShareStats shares;
    shares.vaultId = 3;
    shares.topLinksByAccess.push_back({.shareId = "s1", .label = "L", .rootPath = "/", .linkType = "download",
                                       .accessMode = "public", .accessCount = 1, .downloadCount = 1, .uploadCount = 0,
                                       .lastAccessedAt = 1700000000});
    shares.recentShareEvents.push_back({.id = 1, .shareId = "s1", .eventType = "download", .status = "success",
                                        .targetPath = "/a", .bytesTransferred = 9, .errorCode = "x",
                                        .errorMessage = "y", .createdAt = 1700000000});
    shares.recentShareEvents.push_back({});
    c.check(json(shares), "VaultShareStats", "vault share stats");

    sm::VaultRecovery recovery;
    recovery.vaultId = 3;
    recovery.retentionSeconds = 86400;
    recovery.lastBackupAt = 1700000000;
    recovery.lastSuccessAt = 1700000000;
    recovery.lastSuccessAgeSeconds = 10;
    recovery.nextExpectedBackupAt = 1700086400;
    recovery.backupStale = false;
    recovery.missedBackupCountEstimate = 0;
    recovery.lastError = "none";
    recovery.recoveryReadiness = "ready";
    recovery.timeSinceLastVerifiedGoodState = 10;
    c.check(json(recovery), "VaultRecoveryStats", "vault recovery stats");
    c.check(json(sm::VaultRecovery{}), "VaultRecoveryStats", "vault recovery stats without data");

    sm::VaultSecurity security;
    security.vaultId = 3;
    security.currentKeyVersion = 2;
    security.keyCreatedAt = 1700000000;
    security.keyAgeDays = 4;
    security.lastDeniedAccessAt = 1700000000;
    security.lastDeniedAccessReason = "denied";
    security.lastPermissionChangeAt = 1700000000;
    security.lastSharePolicyChangeAt = 1700000000;
    security.lastIntegrityCheckAt = 1700000000;
    security.checksumMismatchCount = 0;
    c.check(json(security), "VaultSecurity", "vault security");
    c.check(json(sm::VaultSecurity{}), "VaultSecurity", "vault security without data");
}

void checkSystemStats(vh::test::contract_models::Checker& c) {
    sm::OperationStats ops;
    ops.vaultId = 3;
    ops.scope = "vault";
    ops.oldestPendingOperationAgeSeconds = 1;
    ops.oldestInProgressOperationAgeSeconds = 2;
    ops.oldestActiveUploadAgeSeconds = 3;
    ops.recentOperationErrors.push_back({.source = "fs", .operation = "move", .status = "error", .target = "t",
                                         .path = "/a", .error = "boom", .occurredAt = 1700000000});
    ops.recentOperationErrors.push_back({});
    ops.finalize();
    c.check(json(ops), "OperationStats", "vault operation stats");
    c.check(json(sm::OperationStats{}), "OperationStats", "system operation stats");

    sm::StorageBackendStats storage;
    sm::StorageVaultBackendStats vault;
    vault.vaultId = 3;
    vault.vaultName = "v";
    vault.type = "s3";
    vault.freeSpaceBytes = 1;
    vault.cacheSizeBytes = 2;
    vault.vaultSizeBytes = 3;
    vault.minFreeSpaceOk = true;
    vault.upstreamEncryptionEnabled = true;
    vault.bucket = "b";
    vault.providerOpsTotal = 4;
    vault.providerErrorsTotal = 1;
    vault.providerErrorRate = 0.25;
    vault.providerLatencyAvgMs = 1.5;
    vault.providerLatencyMaxMs = 3.0;
    vault.lastProviderError = "timeout";
    vault.lastProviderSuccessAt = 1700000000;
    storage.vaults.push_back(vault);
    storage.vaults.emplace_back();
    storage.finalize();
    c.check(json(storage), "StorageBackendStats", "storage backends");

    sm::RetentionStats retention;
    retention.vaultId = 3;
    retention.scope = "vault";
    retention.oldestTrashedAgeSeconds = 1;
    retention.oldestAuditLogAgeSeconds = 2;
    retention.oldestShareAccessEventAgeSeconds = 3;
    retention.finalize();
    c.check(json(retention), "RetentionStats", "vault retention");
    c.check(json(sm::RetentionStats{}), "RetentionStats", "system retention");

    sm::StatsTrends trends;
    trends.scope = "vault";
    trends.vaultId = 3;
    trends.series.push_back({.key = "k", .label = "L", .unit = "bytes", .snapshotType = "vault.storage",
                             .points = {{.createdAt = 1700000000, .value = 2.5}}});
    c.check(json(trends), "StatsTrends", "vault trends");
    c.check(json(sm::StatsTrends{}), "StatsTrends", "system trends without series");

    sm::DbStats db;
    db.connected = true;
    db.status = "healthy";
    db.error = "none";
    db.databaseName = "vaulthalla";
    db.connectionsMax = 100;
    db.cacheHitRatio = 0.99;
    db.slowQueryCount = 0;
    db.oldestTransactionAgeSeconds = 5;
    db.largestTables.push_back({.tableName = "files", .totalBytes = 3, .tableBytes = 2, .indexBytes = 1,
                                .rowEstimate = 9});
    c.check(json(db), "DbStats", "database stats");
    c.check(json(sm::DbStats{}), "DbStats", "database stats while disconnected");

    sm::ThreadPoolManagerSnapshot pools;
    pools.pools.push_back({.name = "fuse", .queueDepth = 1, .workerCount = 4, .idleWorkerCount = 3,
                           .busyWorkerCount = 1, .hasIdleWorker = true, .stopped = false, .pressureRatio = 0.25,
                           .status = "healthy"});
    pools.maxPressureRatio = 0.25;
    c.check(json(pools), "ThreadPoolManagerSnapshot", "thread pools");

    sm::FuseStatsSnapshot fuse;
    fuse.errorRate = 0.1;
    fuse.ops.push_back({.op = "read", .count = 2, .successes = 1, .errors = 1, .avgMs = 0.5, .maxMs = 1.0,
                        .errorRate = 0.5});
    fuse.topErrors.push_back({.errnoValue = 2, .name = "ENOENT", .count = 1, .alertableCount = 0});
    c.check(json(fuse), "FuseStatsSnapshot", "fuse stats");

    sm::ConnectionStats connections;
    connections.oldestSessionAgeSeconds = 1;
    connections.oldestUnauthenticatedSessionAgeSeconds = 2;
    connections.sessionsSwept24h = 3;
    connections.connectionsOpened24h = 4;
    connections.connectionsClosed24h = 5;
    connections.connectionErrors24h = 6;
    connections.finalize();
    c.check(json(connections), "ConnectionStats", "connection stats");
    c.check(json(sm::ConnectionStats{}), "ConnectionStats", "connection stats without 24h counters");

    sm::CacheStatsSnapshot cache{.hits = 1, .misses = 1, .used_bytes = 10, .capacity_bytes = 100, .op_count = 2,
                                 .op_total_us = 3000, .op_max_us = 2000};
    c.check(json(std::make_shared<sm::CacheStatsSnapshot>(cache)), "CacheStatsSnapshot", "capped cache");
    c.check(json(sm::CacheStatsSnapshot{}), "CacheStatsSnapshot", "uncapped cache");

    sm::SystemHealth health;
    health.overallStatus = sm::SystemHealthStatus::Healthy;
    health.runtime.services.push_back({.entryName = "fuse", .serviceName = "FUSE", .running = true});
    health.s3Gateway.host = "0.0.0.0";
    health.s3Gateway.port = 39000;
    health.deps.mountState = "mounted";
    health.deps.mountBackend = "fuse3";
    health.deps.mountIsolation = "enforced";
    health.deps.mountDetail = "/mnt/vaulthalla";
    health.deps.secretsBackend = "tpm2";
    health.shell.adminUidBound = true;
    health.database = sm::DatabaseHealth{.poolSize = 4, .reachable = true, .probeLatencyMs = 1, .probeError = "slow"};
    c.check(json(health), "SystemHealth", "healthy system");
    health.overallStatus = sm::SystemHealthStatus::Degraded;
    health.vaultsUnavailable.push_back({.vaultId = 12, .vaultName = "archive", .reason = "key_unsealable",
                                        .detail = "restore it with `vh vault keys import 12 --file <export.json>`"});
    c.check(json(health), "SystemHealth", "a vault whose key doesn't unseal here");
    c.check(json(sm::SystemHealth{}), "SystemHealth", "system before the pool exists");
}

void checkDashboard(vh::test::contract_models::Checker& c) {
    const sm::DashboardMetricSummary metric{.key = "k", .label = "L", .value = "1", .unit = "B", .tone = "healthy",
                                            .numericValue = 1.0, .href = "/health"};
    const sm::DashboardIssueSummary issue{.code = "c", .severity = "warning", .message = "m", .href = "/health",
                                          .metricKey = "k"};
    sm::DashboardCardSummary card;
    card.id = "system.trends";
    card.sectionId = "system";
    card.unavailableReason = "not yet";
    card.metrics = {metric, sm::DashboardMetricSummary{}};
    card.series.push_back({.key = "k", .label = "L", .unit = "B", .tone = "info",
                           .points = {{.createdAt = 1700000000, .value = 1.0}}});
    card.warnings = {issue, sm::DashboardIssueSummary{}};
    card.errors = {issue};
    sm::DashboardSectionSummary section;
    section.id = "system";
    section.metrics = {metric};
    section.warnings = {issue};
    section.errors = {issue};
    sm::DashboardOverview overview;
    overview.overallStatus = "warning";
    overview.cards = {card};
    overview.sections = {section};
    overview.attention.push_back({.code = "c", .severity = "warning", .cardId = "system.trends", .title = "t",
                                  .message = "m", .href = "/health", .metricKey = "k"});
    overview.attention.emplace_back();
    c.check(json(overview), "DashboardOverview", "dashboard overview");
    c.check(sm::dashboardSeverityJson(overview), "DashboardSeverity", "dashboard severity");

    sm::DashboardPreference saved;
    saved.id = 4;
    saved.userId = 2;
    saved.layout = json{{"cards", json::array({json{{"id", "system.health"}, {"size", "2x1"}, {"variant", "tiles"},
                                                    {"visible", true}, {"order", 0}}})}};
    saved.createdAt = 1700000000;
    saved.updatedAt = 1700000001;
    saved.exists = true;
    c.check(json(saved), "DashboardPreference", "saved dashboard layout");
    c.check(json(sm::DashboardPreference{}), "DashboardPreference", "no saved layout");
}

}

namespace vh::test::contract_models {

void checkStatsModels(Checker& c) {
    test_contract_models_stats::checkVaultStats(c);
    test_contract_models_stats::checkSystemStats(c);
    test_contract_models_stats::checkDashboard(c);
}

}
