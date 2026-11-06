#pragma once

#include <chrono>

#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>
#include <boost/asio/ip/tcp.hpp>
#include "auth/session/Assurance.hpp"
#include "identities/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

namespace vh::auth::session {

class Manager {
public:
    // `slot`: the server's websocket_server.max_connections slot, held by the session until it closes.
    void accept(boost::asio::ip::tcp::socket&& socket, const std::shared_ptr<protocols::ws::Router>& router,
                std::unique_ptr<protocols::ws::ConnectionSlot> slot);
    void tryRehydrate(const std::shared_ptr<protocols::ws::Session>& session);

    // Signs the socket's session in: inserts its refresh token's row once, with how the sign-in was proven (aal, amr,
    // auth_time = now), and issues the access token. Throws when the jti already has a row (#354: write-once; a
    // cookie someone else signed in with, or a second promotion, never becomes this session).
    void promote(const std::shared_ptr<protocols::ws::Session>& session,
                 const assurance::Proof& proof = assurance::password());
    void cache(const std::shared_ptr<protocols::ws::Session>& session);
    void rotateRefreshToken(const std::shared_ptr<protocols::ws::Session>& session);
    void rotateShareRefreshToken(const std::shared_ptr<protocols::ws::Session>& session);
    void tryRehydrateShareRefresh(const std::shared_ptr<protocols::ws::Session>& session);
    void renewAccessToken(const std::shared_ptr<protocols::ws::Session>& session, const std::string& existingToken);

    bool validate(const std::shared_ptr<protocols::ws::Session>& session, const std::string& accessToken);
    std::shared_ptr<protocols::ws::Session> validateRawRefreshToken(const std::string& refreshToken);
    std::shared_ptr<protocols::ws::Session> validateRawShareRefreshToken(const std::string& refreshToken);
    void remove(const std::shared_ptr<protocols::ws::Session>& session);
    void invalidate(const std::string& token);
    void invalidate(const std::shared_ptr<protocols::ws::Session>& session);

    // Idle sign-out (#319, auth/session/Idle.hpp). noteUserActivity records real user input on a human session
    // (server clock; database write at most every idle::kActivityWriteInterval). expireIfIdle revokes the refresh
    // token and invalidates the session when it has been idle too long, and says so; the decision is confirmed against
    // the stored token first, because other tabs share the token and may have been active.
    void noteUserActivity(const std::shared_ptr<protocols::ws::Session>& session);
    bool expireIfIdle(const std::shared_ptr<protocols::ws::Session>& session);

    // The MFA policy against a signed-in web session's row (#354; assurance::enforce): when the row is below it, the
    // row is revoked, the session invalidated, and this says so. Devices and share sessions are not checked here.
    bool endIfBelowPolicy(const std::shared_ptr<protocols::ws::Session>& session);

    // auth.sessions.revoke: ends every live socket of `userId` that holds refresh token `jti` (invalidated, closed;
    // `caller` after its reply). The row itself is revoked by the caller first. Returns how many sessions ended.
    std::size_t endSessionsWithRefreshJti(uint32_t userId, const std::string& jti,
                                          const std::shared_ptr<protocols::ws::Session>& caller);

    // A JWT secret rotation (#353): every live session (web, device and share sockets alike) is invalidated and
    // closed, and every cached refresh-token validation dropped, so nothing signed with the old secret is honored
    // from memory. The caller revoked the stored refresh tokens first. Returns how many sessions ended.
    std::size_t endAll();

    std::shared_ptr<protocols::ws::Session> get(const std::string& token);
    std::shared_ptr<protocols::ws::Session> getShareByRefreshJti(const std::string& token);
    std::vector<std::shared_ptr<protocols::ws::Session>> getSessions(const std::shared_ptr<identities::User>& user);
    std::vector<std::shared_ptr<protocols::ws::Session>> getSessionsByUserId(uint32_t userId);

    std::unordered_map<std::string, std::shared_ptr<protocols::ws::Session>> getActive();

private:
    std::unordered_map<std::string, std::shared_ptr<protocols::ws::Session>> sessionsByUUID_;
    std::unordered_map<std::string, std::shared_ptr<protocols::ws::Session>> sessionsByRefreshJti_;
    std::unordered_map<std::string, std::shared_ptr<protocols::ws::Session>> shareSessionsByRefreshJti_;
    std::unordered_multimap<uint32_t, std::shared_ptr<protocols::ws::Session>> sessionsByUserId_;
    std::mutex sessionMutex_;
    // Human refresh tokens re-validated against the database within the last kRevalidateAfter, by jti. Dropped
    // with the session's indexes (logout, invalidation, revokeSessions), so revocation takes effect immediately;
    // otherwise HTTP range bursts (media seeking) would cost one DB round trip per request.
    // Also keyed to rbac::policyEpoch(): a role/override/membership change re-runs the full validation (which
    // reloads the user's roles and groups) on the next request.
    struct ValidatedStamp {
        std::chrono::steady_clock::time_point at;
        uint64_t epoch{};
    };
    std::unordered_map<std::string, ValidatedStamp> validatedAt_;

    void eraseSessionIndexesLocked(
        const std::shared_ptr<protocols::ws::Session>& session,
        std::optional<std::string> jti
    );
    void indexHumanRefreshTokenLocked(const std::shared_ptr<protocols::ws::Session>& session);
    void reindexHumanRefreshTokenLocked(
        const std::shared_ptr<protocols::ws::Session>& session,
        std::optional<std::string> oldJti
    );
    void indexShareRefreshTokenLocked(const std::shared_ptr<protocols::ws::Session>& session);
    void reindexShareRefreshTokenLocked(
        const std::shared_ptr<protocols::ws::Session>& session,
        std::optional<std::string> oldJti
    );
};

inline std::string to_string(
    const std::unordered_map<std::string, std::shared_ptr<protocols::ws::Session>>& sessions
) {
    std::string result;
    for (const auto& [token, session] : sessions)
        result += "Token: " + token + "\n";
    return result;
}

}
