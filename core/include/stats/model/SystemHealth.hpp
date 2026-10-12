#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <nlohmann/json_fwd.hpp>

namespace vh::stats::model {

enum class SystemHealthStatus {
    Healthy,
    Degraded,
    Critical,
};

struct RuntimeServiceHealth {
    std::string entryName;
    std::string serviceName;
    bool running = false;
    bool interrupted = false;
};

struct RuntimeHealth {
    bool allRunning = false;
    std::size_t serviceCount = 0;
    std::vector<RuntimeServiceHealth> services;
};

struct ProtocolHealth {
    bool running = false;
    bool ioContextInitialized = false;
    bool websocketConfigured = false;
    bool websocketReady = false;
    bool httpPreviewConfigured = false;
    bool httpPreviewReady = false;
};

struct S3GatewayHealth {
    bool running = false;
    bool configured = false;
    bool ready = false;
    std::string host;
    std::uint16_t port = 0;
    std::uint64_t activeSessions = 0;
    std::uint64_t totalRequests = 0;
    std::uint64_t failedRequests = 0;
};

struct DependencyHealth {
    bool storageManager = false;
    bool apiKeyManager = false;
    bool authManager = false;
    bool sessionManager = false;
    bool secretsManager = false;
    bool syncController = false;
    bool fsCache = false;
    bool shellUsageManager = false;
    bool httpCacheStats = false;
    bool fuseSession = false;
    // What the filesystem mount can be in this build: "multiuser" (the kernel FUSE bridge, per-caller-uid
    // authorization) or "disabled" (built without it: vaults are served over HTTP/WS/CLI only). A disabled mount is
    // not a missing FUSE session. Mount modes are roadmap #200.
    std::string fuseMount = "multiuser";
    // What the mount actually is (fuse::MountStatus): disabled | mounted | not_mounted | unavailable | unsupported,
    // the FUSE backend, and the isolation guarantee (enforced | unproven | not_applicable).
    std::string mountState;
    std::string mountBackend;
    std::string mountIsolation;
    std::string mountDetail;
    // The secret sealing backend (platform/Sealer.hpp): "tpm2", or "file" (macOS development backend, no hardware
    // binding).
    std::string secretsBackend;
};

struct ShellHealth {
    std::optional<bool> adminUidBound;
};

// DB connection pool state (db::DBPool::stats()) plus a live probe. An unreachable database, or reconnect
// failures, are critical; dead idle connections mean a session loss that hasn't been repaired yet (degraded).
struct DatabaseHealth {
    std::size_t poolSize = 0;
    std::size_t idle = 0;
    std::size_t inUse = 0;
    std::size_t brokenIdle = 0;
    std::uint64_t reconnects = 0;
    std::uint64_t reconnectFailures = 0;
    std::uint32_t consecutiveReconnectFailures = 0;
    std::uint64_t acquireTimeouts = 0;
    // A live, bounded `SELECT 1` taken with the snapshot: the counters above only move when some request has
    // already failed, so on their own an idle daemon reads healthy while PostgreSQL is down.
    bool reachable = false;
    long long probeLatencyMs = 0;
    std::string probeError{};
};

struct HealthSummary {
    std::size_t servicesReady = 0;
    std::size_t servicesTotal = 0;
    std::size_t depsReady = 0;
    std::size_t depsTotal = 0;
    std::size_t protocolsReady = 0;
    std::size_t protocolsTotal = 0;
    std::uint64_t checkedAt = 0;
};

struct SystemHealth {
    SystemHealthStatus overallStatus = SystemHealthStatus::Degraded;
    RuntimeHealth runtime;
    ProtocolHealth protocols;
    S3GatewayHealth s3Gateway;
    DependencyHealth deps;
    ShellHealth shell;
    std::optional<DatabaseHealth> database; // nullopt until the pool exists (critical)
    HealthSummary summary;

    [[nodiscard]] bool healthy() const noexcept;
    [[nodiscard]] std::string overallStatusString() const;

    static SystemHealth snapshot();
};

std::string to_string(SystemHealthStatus status);

void to_json(nlohmann::json& j, const RuntimeServiceHealth& health);
void to_json(nlohmann::json& j, const RuntimeHealth& health);
void to_json(nlohmann::json& j, const ProtocolHealth& health);
void to_json(nlohmann::json& j, const S3GatewayHealth& health);
void to_json(nlohmann::json& j, const DependencyHealth& health);
void to_json(nlohmann::json& j, const ShellHealth& health);
void to_json(nlohmann::json& j, const DatabaseHealth& health);
void to_json(nlohmann::json& j, const HealthSummary& health);
void to_json(nlohmann::json& j, const SystemHealth& health);

}
