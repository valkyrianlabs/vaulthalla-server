#include "stats/model/ConnectionStats.hpp"

#include "auth/session/Manager.hpp"
#include "protocols/ws/ConnectionLifecycleManager.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "runtime/Manager.hpp"

#include <algorithm>
#include <chrono>
#include <nlohmann/json.hpp>

namespace vh::stats::model {

namespace {

template <typename T>
nlohmann::json nullableConnectionValue(const std::optional<T>& value) {
    return value ? nlohmann::json(*value) : nlohmann::json(nullptr);
}

std::uint64_t connectionUnixTimestamp() {
    return static_cast<std::uint64_t>(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()));
}

std::uint64_t ageSeconds(const std::chrono::system_clock::time_point openedAt) {
    const auto now = std::chrono::system_clock::now();
    if (openedAt >= now) return 0;
    return static_cast<std::uint64_t>(std::chrono::duration_cast<std::chrono::seconds>(now - openedAt).count());
}

void assignMinAge(std::optional<std::uint64_t>& current, const std::uint64_t candidate) {
    current = current ? std::max(*current, candidate) : std::optional<std::uint64_t>(candidate);
}

}

// A paired device (the desktop app, an agent) signs in with its certificate and is Device; one in the middle of
// pairing is DevicePairing. Both used to fall through to "unauthenticated", so every connected desktop app
// raised the connection-health warning on the node it was looking at.
std::string sessionModeName(const protocols::ws::SessionMode mode) {
    using protocols::ws::SessionMode;
    switch (mode) {
        case SessionMode::Human: return "human";
        case SessionMode::SharePending: return "share_pending";
        case SessionMode::Share: return "share";
        case SessionMode::Device: return "device";
        case SessionMode::DevicePairing: return "device_pairing";
        case SessionMode::Unauthenticated: return "unauthenticated";
    }
    return "unauthenticated";
}

ConnectionStats ConnectionStats::snapshot() {
    ConnectionStats out;
    out.checkedAt = connectionUnixTimestamp();

    if (const auto lifecycle = runtime::Manager::instance().getConnectionLifecycleManager()) {
        out.sweepIntervalSeconds = lifecycle->sweepIntervalSeconds();
        out.unauthenticatedTimeoutSeconds = lifecycle->unauthenticatedSessionTimeoutSeconds();
        out.idleTimeoutMinutes = lifecycle->idleTimeoutMinutes();
    }

    const auto manager = runtime::Deps::get().sessionManager;
    if (!manager) {
        out.status = "unknown";
        return out;
    }

    for (const auto& [_, session] : manager->getActive()) {
        if (!session) continue;

        out.count(sessionModeName(session->mode()), ageSeconds(session->connectionOpenedAt));
    }

    out.finalize();
    return out;
}

void ConnectionStats::count(const std::string& mode, const std::uint64_t ageSeconds) {
    ++activeWsSessionsTotal;
    assignMinAge(oldestSessionAgeSeconds, ageSeconds);
    ++sessionsByMode[mode];

    if (mode == "human") {
        ++activeHumanSessions;
    } else if (mode == "share") {
        ++activeShareSessions;
    } else if (mode == "share_pending") {
        ++activeSharePendingSessions;
    } else if (mode == "unauthenticated") {
        ++activeUnauthenticatedSessions;
        assignMinAge(oldestUnauthenticatedSessionAgeSeconds, ageSeconds);
    }
    // device, device_pairing: in the total and in sessionsByMode only.
}

void ConnectionStats::finalize() {
    status = activeUnauthenticatedSessions >= kUnauthenticatedFlood ? "critical" : "healthy";
}

void to_json(nlohmann::json& j, const ConnectionStats& stats) {
    j = nlohmann::json{
        {"status", stats.status},
        {"active_ws_sessions_total", stats.activeWsSessionsTotal},
        {"active_human_sessions", stats.activeHumanSessions},
        {"active_share_sessions", stats.activeShareSessions},
        {"active_share_pending_sessions", stats.activeSharePendingSessions},
        {"active_unauthenticated_sessions", stats.activeUnauthenticatedSessions},
        {"oldest_session_age_seconds", nullableConnectionValue(stats.oldestSessionAgeSeconds)},
        {"oldest_unauthenticated_session_age_seconds", nullableConnectionValue(stats.oldestUnauthenticatedSessionAgeSeconds)},
        {"idle_timeout_minutes", stats.idleTimeoutMinutes},
        {"unauthenticated_timeout_seconds", stats.unauthenticatedTimeoutSeconds},
        {"sweep_interval_seconds", stats.sweepIntervalSeconds},
        {"sessions_swept_24h", nullableConnectionValue(stats.sessionsSwept24h)},
        {"connections_opened_24h", nullableConnectionValue(stats.connectionsOpened24h)},
        {"connections_closed_24h", nullableConnectionValue(stats.connectionsClosed24h)},
        {"connection_errors_24h", nullableConnectionValue(stats.connectionErrors24h)},
        {"sessions_by_mode", stats.sessionsByMode},
        {"top_user_agents", nlohmann::json::array()},
        {"top_user_agents_available", stats.topUserAgentsAvailable},
        {"top_remote_ips_limited", nlohmann::json::array()},
        {"top_remote_ips_available", stats.topRemoteIpsAvailable},
        {"checked_at", stats.checkedAt},
    };
}

}
