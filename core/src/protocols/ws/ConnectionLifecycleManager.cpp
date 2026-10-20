#include "protocols/ws/ConnectionLifecycleManager.hpp"
#include "auth/session/Manager.hpp"
#include "auth/session/Validator.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/model/Response.hpp"
#include "runtime/Deps.hpp"
#include "log/Registry.hpp"
#include "config/Registry.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/model/RefreshToken.hpp"
#include "identities/User.hpp"

using namespace vh::protocols::ws;
using namespace vh::auth;
using namespace vh::config;
using namespace std::chrono;

ConnectionLifecycleManager::ConnectionLifecycleManager()
    : AsyncService("LifecycleManager") {
    const auto& config = Registry::get().services.connection_lifecycle_manager;
    sweep_interval_ = seconds(config.sweep_interval_seconds);
    unauthenticated_session_timeout_ = seconds(config.unauthenticated_timeout_seconds);
    idle_timeout_ = minutes(config.idle_timeout_minutes); // TODO: implement idle timeout logic
}

ConnectionLifecycleManager::~ConnectionLifecycleManager() {
    stop();
}

std::uint64_t ConnectionLifecycleManager::sweepIntervalSeconds() const noexcept {
    return static_cast<std::uint64_t>(sweep_interval_.count());
}

std::uint64_t ConnectionLifecycleManager::unauthenticatedSessionTimeoutSeconds() const noexcept {
    return static_cast<std::uint64_t>(unauthenticated_session_timeout_.count());
}

std::uint64_t ConnectionLifecycleManager::idleTimeoutMinutes() const noexcept {
    return static_cast<std::uint64_t>(idle_timeout_.count());
}

void ConnectionLifecycleManager::runLoop() {
    log::Registry::ws()->info("[LifecycleManager] Started connection lifecycle manager.");
    while (!shouldStop()) {
        sweepActiveSessions();
        lazySleep(sweep_interval_);
    }
}

ConnectionLifecycleManager::SweepVerdict ConnectionLifecycleManager::verdict(
    const Session& session, const system_clock::time_point now, const seconds unauthenticatedTimeout) {
    const bool expired = session.connectionOpenedAt + unauthenticatedTimeout < now;
    if (!session.handshakeComplete()) return expired ? SweepVerdict::UnauthenticatedTimeout : SweepVerdict::Keep;
    // The device listener's sessions have no refresh token (the client certificate authenticated them).
    if (session.isDevicePairing())
        return session.connectionOpenedAt + kDevicePairingLifetime < now ? SweepVerdict::DeviceEnded : SweepVerdict::Keep;
    if (session.isDeviceSession())
        return session.user && session.user->authorizing() ? SweepVerdict::Keep : SweepVerdict::DeviceEnded;
    if (!session.user && !session.isShareSession() && expired) return SweepVerdict::UnauthenticatedTimeout;

    const auto refreshToken = session.tokens
                                  ? (session.tokens->refreshToken ? session.tokens->refreshToken
                                                                  : session.tokens->shareRefreshToken)
                                  : nullptr;
    if (!refreshToken || !refreshToken->isValid()) return SweepVerdict::InvalidRefreshToken;
    return SweepVerdict::Keep;
}

void ConnectionLifecycleManager::sweepActiveSessions() const {
    for (const auto& [_, session] : runtime::Deps::get().sessionManager->getActive()) {
        if (!session) continue;
        const auto decision = verdict(*session, system_clock::now(), unauthenticated_session_timeout_);
        if (decision == SweepVerdict::Keep) continue;
        try {
            log::Registry::ws()->debug("[LifecycleManager] Closing {} session opened at {}",
                                       decision == SweepVerdict::UnauthenticatedTimeout ? "unauthenticated"
                                       : decision == SweepVerdict::DeviceEnded          ? "device"
                                                                                        : "expired",
                                       system_clock::to_time_t(session->connectionOpenedAt));
            model::Response::UNAUTHORIZED("unauthenticated_session_timeout",
                decision == SweepVerdict::UnauthenticatedTimeout
                    ? "Session closed due to inactivity. Please authenticate to continue."
                : decision == SweepVerdict::DeviceEnded
                    ? "Session closed: this device's account can no longer sign in, or pairing took too long."
                    : "Session closed due to expired refresh token. Please re-authenticate to continue.")(session);
            runtime::Deps::get().sessionManager->invalidate(session);
        } catch (const std::exception& e) {
            log::Registry::ws()->error("[LifecycleManager] Error while sweeping a session: {}", e.what());
        }
        // Close regardless: a session that failed to invalidate cleanly must not linger and be swept forever.
        session->close();
    }
}
