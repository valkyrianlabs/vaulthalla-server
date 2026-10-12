#include "stats/model/SystemHealth.hpp"

#include "crypto/secrets/KeyProvider.hpp"
#include "db/DBPool.hpp"
#include "fuse/Service.hpp"
#include "db/Transactions.hpp"
#include "protocols/ProtocolService.hpp"
#include "protocols/s3/GatewayService.hpp"
#include "protocols/shell/Server.hpp"
#include "runtime/Deps.hpp"
#include "runtime/Manager.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

namespace vh::stats::model {

namespace {

std::uint64_t unixTimestamp() {
    const auto now = std::chrono::system_clock::now();
    return static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(now));
}

std::size_t countReadyDeps(const DependencyHealth& deps) {
    const std::array<bool, 9> checks{
        deps.storageManager,
        deps.apiKeyManager,
        deps.authManager,
        deps.sessionManager,
        deps.secretsManager,
        deps.syncController,
        deps.fsCache,
        deps.shellUsageManager,
        deps.httpCacheStats
    };

    return static_cast<std::size_t>(std::ranges::count(checks, true));
}

bool depsHealthy(const DependencyHealth& deps, const HealthSummary& summary) {
    return summary.depsReady == summary.depsTotal && (deps.fuseSession || deps.fuseMount == "disabled");
}

bool protocolsHealthy(const ProtocolHealth& protocols, const S3GatewayHealth& s3Gateway) {
    return (!protocols.websocketConfigured || protocols.websocketReady)
        && (!protocols.httpPreviewConfigured || protocols.httpPreviewReady)
        && (!s3Gateway.configured || s3Gateway.ready);
}

std::pair<std::size_t, std::size_t> protocolReadySummary(const ProtocolHealth& protocols,
                                                         const S3GatewayHealth& s3Gateway) {
    std::size_t ready = 0;
    std::size_t total = 0;

    if (protocols.websocketConfigured) {
        ++total;
        if (protocols.websocketReady) ++ready;
    }

    if (protocols.httpPreviewConfigured) {
        ++total;
        if (protocols.httpPreviewReady) ++ready;
    }

    if (s3Gateway.configured) {
        ++total;
        if (s3Gateway.ready) ++ready;
    }

    return {ready, total};
}

constexpr std::chrono::seconds kDatabaseProbeAcquireTimeout{3};

// Bounded live round trip to PostgreSQL that must not park on the pool if every connection is busy. A session
// the server dropped while idle only shows up when used, so it is replaced once (as Transactions::exec does)
// and a recovered server reads as reachable.
void probeDatabase(db::DBPool& pool, DatabaseHealth& out) {
    const auto start = std::chrono::steady_clock::now();
    try {
        auto lease = pool.acquire(kDatabaseProbeAcquireTimeout);
        try {
            pqxx::nontransaction tx(lease->get());
            (void)tx.exec("SELECT 1").one_row_ref();
        } catch (const std::exception&) {
            if (lease->healthy()) throw;
            pool.repair(lease);
            pqxx::nontransaction tx(lease->get());
            (void)tx.exec("SELECT 1").one_row_ref();
        }
        out.reachable = true;
    } catch (const std::exception& e) {
        out.reachable = false;
        out.probeError = e.what();
    }
    out.probeLatencyMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
}

SystemHealthStatus computeOverallStatus(const SystemHealth& health) {
    if (health.runtime.services.empty())
        return SystemHealthStatus::Critical;

    if (!health.deps.storageManager && !health.deps.authManager && !health.deps.sessionManager)
        return SystemHealthStatus::Critical;

    // No pool, or a pool that cannot reach PostgreSQL: nothing that needs the database works.
    if (!health.database || !health.database->reachable || health.database->consecutiveReconnectFailures > 0)
        return SystemHealthStatus::Critical;

    const bool ok = health.runtime.allRunning
        && health.database->brokenIdle == 0
        && protocolsHealthy(health.protocols, health.s3Gateway)
        && depsHealthy(health.deps, health.summary);

    return ok ? SystemHealthStatus::Healthy : SystemHealthStatus::Degraded;
}

}

bool SystemHealth::healthy() const noexcept {
    return overallStatus == SystemHealthStatus::Healthy;
}

std::string SystemHealth::overallStatusString() const {
    return to_string(overallStatus);
}

SystemHealth SystemHealth::snapshot() {
    const auto& manager = runtime::Manager::instance();
    const auto runtimeStatus = manager.status();
    const auto protocolService = manager.getProtocolService();
    const auto s3GatewayService = manager.getS3GatewayService();
    const auto shellServer = manager.getShellServer();
    const auto protocolStatus = protocolService
        ? protocolService->protocolStatus()
        : protocols::ProtocolService::RuntimeStatus{};
    const auto s3GatewayStatus = s3GatewayService
        ? s3GatewayService->gatewayStatus()
        : protocols::s3::GatewayService::RuntimeStatus{};
    const auto depsStatus = runtime::Deps::get().sanityStatus();

    SystemHealth out;
    out.runtime.allRunning = runtimeStatus.allRunning;
    out.runtime.serviceCount = runtimeStatus.services.size();
    out.runtime.services.reserve(runtimeStatus.services.size());

    for (const auto& service : runtimeStatus.services) {
        out.runtime.services.push_back({
            .entryName = service.entryName,
            .serviceName = service.serviceName,
            .running = service.running,
            .interrupted = service.interrupted
        });
    }

    out.protocols = {
        .running = protocolStatus.running,
        .ioContextInitialized = protocolStatus.ioContextInitialized,
        .websocketConfigured = protocolStatus.websocketConfigured,
        .websocketReady = protocolStatus.websocketReady,
        .httpPreviewConfigured = protocolStatus.httpPreviewConfigured,
        .httpPreviewReady = protocolStatus.httpPreviewReady
    };

    out.s3Gateway = {
        .running = s3GatewayStatus.running,
        .configured = s3GatewayStatus.configured,
        .ready = s3GatewayStatus.ready,
        .host = s3GatewayStatus.host,
        .port = s3GatewayStatus.port,
        .activeSessions = s3GatewayStatus.activeSessions,
        .totalRequests = s3GatewayStatus.totalRequests,
        .failedRequests = s3GatewayStatus.failedRequests
    };

    const auto mount = fuse::mountStatus();
    out.deps = {
        .storageManager = depsStatus.storageManager,
        .apiKeyManager = depsStatus.apiKeyManager,
        .authManager = depsStatus.authManager,
        .sessionManager = depsStatus.sessionManager,
        .secretsManager = depsStatus.secretsManager,
        .syncController = depsStatus.syncController,
        .fsCache = depsStatus.fsCache,
        .shellUsageManager = depsStatus.shellUsageManager,
        .httpCacheStats = depsStatus.httpCacheStats,
        .fuseSession = depsStatus.fuseSession,
        .fuseMount = mount.configuredMode,
        .mountState = mount.state,
        .mountBackend = mount.backend,
        .mountIsolation = mount.isolation,
        .mountDetail = mount.detail,
        .secretsBackend = std::string(crypto::secrets::KeyProvider::backend())
    };

    out.shell.adminUidBound = shellServer ? std::optional<bool>(shellServer->adminUIDSet()) : std::nullopt;

    if (const auto pool = db::Transactions::dbPool_) {
        const auto poolStats = pool->stats();
        out.database = DatabaseHealth{
            .poolSize = poolStats.size,
            .idle = poolStats.idle,
            .inUse = poolStats.inUse,
            .brokenIdle = poolStats.brokenIdle,
            .reconnects = poolStats.reconnects,
            .reconnectFailures = poolStats.reconnectFailures,
            .consecutiveReconnectFailures = poolStats.consecutiveReconnectFailures,
            .acquireTimeouts = poolStats.acquireTimeouts
        };
        probeDatabase(*pool, *out.database);
    }

    const auto [protocolsReady, protocolsTotal] = protocolReadySummary(out.protocols, out.s3Gateway);
    out.summary = {
        .servicesReady = static_cast<std::size_t>(std::ranges::count_if(
            out.runtime.services,
            [](const RuntimeServiceHealth& service) { return service.running; }
        )),
        .servicesTotal = out.runtime.services.size(),
        .depsReady = countReadyDeps(out.deps),
        .depsTotal = 9,
        .protocolsReady = protocolsReady,
        .protocolsTotal = protocolsTotal,
        .checkedAt = unixTimestamp()
    };

    out.overallStatus = computeOverallStatus(out);
    return out;
}

std::string to_string(const SystemHealthStatus status) {
    switch (status) {
        case SystemHealthStatus::Healthy:
            return "healthy";
        case SystemHealthStatus::Critical:
            return "critical";
        case SystemHealthStatus::Degraded:
        default:
            return "degraded";
    }
}

void to_json(nlohmann::json& j, const RuntimeServiceHealth& health) {
    j = nlohmann::json{
        {"entry_name", health.entryName},
        {"service_name", health.serviceName},
        {"running", health.running},
        {"interrupted", health.interrupted},
    };
}

void to_json(nlohmann::json& j, const RuntimeHealth& health) {
    j = nlohmann::json{
        {"all_running", health.allRunning},
        {"service_count", health.serviceCount},
        {"services", health.services},
    };
}

void to_json(nlohmann::json& j, const ProtocolHealth& health) {
    j = nlohmann::json{
        {"running", health.running},
        {"io_context_initialized", health.ioContextInitialized},
        {"websocket_configured", health.websocketConfigured},
        {"websocket_ready", health.websocketReady},
        {"http_preview_configured", health.httpPreviewConfigured},
        {"http_preview_ready", health.httpPreviewReady},
    };
}

void to_json(nlohmann::json& j, const S3GatewayHealth& health) {
    j = nlohmann::json{
        {"running", health.running},
        {"configured", health.configured},
        {"ready", health.ready},
        {"host", health.host},
        {"port", health.port},
        {"active_sessions", health.activeSessions},
        {"total_requests", health.totalRequests},
        {"failed_requests", health.failedRequests},
    };
}

void to_json(nlohmann::json& j, const DependencyHealth& health) {
    j = nlohmann::json{
        {"storage_manager", health.storageManager},
        {"api_key_manager", health.apiKeyManager},
        {"auth_manager", health.authManager},
        {"session_manager", health.sessionManager},
        {"secrets_manager", health.secretsManager},
        {"sync_controller", health.syncController},
        {"fs_cache", health.fsCache},
        {"shell_usage_manager", health.shellUsageManager},
        {"http_cache_stats", health.httpCacheStats},
        {"fuse_session", health.fuseSession},
        {"fuse_mount", health.fuseMount},
        {"mount_state", health.mountState},
        {"mount_backend", health.mountBackend},
        {"mount_isolation", health.mountIsolation},
        {"mount_detail", health.mountDetail.empty() ? nlohmann::json(nullptr) : nlohmann::json(health.mountDetail)},
        {"secrets_backend", health.secretsBackend},
    };
}

void to_json(nlohmann::json& j, const ShellHealth& health) {
    j = nlohmann::json{
        {"admin_uid_bound", health.adminUidBound ? nlohmann::json(*health.adminUidBound) : nlohmann::json(nullptr)},
    };
}

void to_json(nlohmann::json& j, const DatabaseHealth& health) {
    j = nlohmann::json{
        {"pool_size", health.poolSize},
        {"idle", health.idle},
        {"in_use", health.inUse},
        {"broken_idle", health.brokenIdle},
        {"reconnects", health.reconnects},
        {"reconnect_failures", health.reconnectFailures},
        {"consecutive_reconnect_failures", health.consecutiveReconnectFailures},
        {"acquire_timeouts", health.acquireTimeouts},
        {"reachable", health.reachable},
        {"probe_latency_ms", health.probeLatencyMs},
        {"probe_error", health.probeError.empty() ? nlohmann::json(nullptr) : nlohmann::json(health.probeError)},
    };
}

void to_json(nlohmann::json& j, const HealthSummary& health) {
    j = nlohmann::json{
        {"services_ready", health.servicesReady},
        {"services_total", health.servicesTotal},
        {"deps_ready", health.depsReady},
        {"deps_total", health.depsTotal},
        {"protocols_ready", health.protocolsReady},
        {"protocols_total", health.protocolsTotal},
        {"checked_at", health.checkedAt},
    };
}

void to_json(nlohmann::json& j, const SystemHealth& health) {
    j = nlohmann::json{
        {"overall_status", to_string(health.overallStatus)},
        {"runtime", health.runtime},
        {"protocols", health.protocols},
        {"s3_gateway", health.s3Gateway},
        {"deps", health.deps},
        {"shell", health.shell},
        {"database", health.database ? nlohmann::json(*health.database) : nlohmann::json(nullptr)},
        {"summary", health.summary},
    };
}

}
