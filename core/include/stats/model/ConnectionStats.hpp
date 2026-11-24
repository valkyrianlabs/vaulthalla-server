#pragma once

#include <cstdint>
#include <map>
#include <optional>
#include <string>

#include <nlohmann/json_fwd.hpp>

namespace vh::protocols::ws { enum class SessionMode; }

namespace vh::stats::model {

// The name a websocket session's mode is counted under (ConnectionStats::sessionsByMode).
[[nodiscard]] std::string sessionModeName(protocols::ws::SessionMode mode);

struct ConnectionStats {
    std::string status = "healthy";
    std::uint64_t activeWsSessionsTotal = 0;
    std::uint64_t activeHumanSessions = 0;
    std::uint64_t activeShareSessions = 0;
    std::uint64_t activeSharePendingSessions = 0;
    std::uint64_t activeUnauthenticatedSessions = 0;
    std::optional<std::uint64_t> oldestSessionAgeSeconds;
    std::optional<std::uint64_t> oldestUnauthenticatedSessionAgeSeconds;
    std::uint64_t idleTimeoutMinutes = 0;
    std::uint64_t unauthenticatedTimeoutSeconds = 0;
    std::uint64_t sweepIntervalSeconds = 0;
    std::optional<std::uint64_t> sessionsSwept24h;
    std::optional<std::uint64_t> connectionsOpened24h;
    std::optional<std::uint64_t> connectionsClosed24h;
    std::optional<std::uint64_t> connectionErrors24h;
    std::map<std::string, std::uint64_t> sessionsByMode{
        {"unauthenticated", 0},
        {"human", 0},
        {"share_pending", 0},
        {"share", 0},
        {"device", 0},
        {"device_pairing", 0},
    };
    bool topUserAgentsAvailable = false;
    bool topRemoteIpsAvailable = false;
    std::uint64_t checkedAt = 0;

    static ConnectionStats snapshot();
    // Counts one open session of `mode` (a sessionModeName) that has been open for `ageSeconds`.
    void count(const std::string& mode, std::uint64_t ageSeconds);
    // healthy, or critical once unauthenticated sessions pile up (kUnauthenticatedFlood): a socket that has
    // not signed in yet is how every connection starts, and the lifecycle sweep closes the ones that never
    // do, so their mere presence is not a finding.
    void finalize();
    static constexpr std::uint64_t kUnauthenticatedFlood = 20;
};

void to_json(nlohmann::json& j, const ConnectionStats& stats);

}
