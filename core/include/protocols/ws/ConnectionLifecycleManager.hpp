#pragma once

#include "concurrency/AsyncService.hpp"
#include "protocols/ws/Fwd.hpp"

#include <chrono>
#include <cstdint>

namespace vh::protocols::ws {

class ConnectionLifecycleManager final : public concurrency::AsyncService {
  public:
    ConnectionLifecycleManager();
    ~ConnectionLifecycleManager() override;

    [[nodiscard]] std::uint64_t sweepIntervalSeconds() const noexcept;
    [[nodiscard]] std::uint64_t unauthenticatedSessionTimeoutSeconds() const noexcept;
    [[nodiscard]] std::uint64_t idleTimeoutMinutes() const noexcept;

    // DeviceEnded: a paired device whose user can no longer sign in, or a pairing-only connection past
    // kDevicePairingLifetime (a pairing window lasts 10 minutes).
    enum class SweepVerdict { Keep, UnauthenticatedTimeout, InvalidRefreshToken, DeviceEnded, IdleTimeout };
    static constexpr std::chrono::minutes kDevicePairingLifetime{15};
    // What the sweeper does with a session. One still in its handshake is only timed out: it is indexed at TCP
    // accept, before it has tokens, and closing it there made nginx answer 502 to a healthy connection.
    // idleTimeout (0 = off) applies to signed-in web-console sessions only (#319, auth/session/Idle.hpp).
    [[nodiscard]] static SweepVerdict verdict(const Session& session, std::chrono::system_clock::time_point now,
                                              std::chrono::seconds unauthenticatedTimeout,
                                              std::chrono::minutes idleTimeout = std::chrono::minutes{0});

  private:
    void runLoop() override;

    void sweepActiveSessions() const;

    std::chrono::seconds sweep_interval_{30};
    std::chrono::seconds unauthenticated_session_timeout_{60};
    std::chrono::minutes idle_timeout_{30};
};

}
