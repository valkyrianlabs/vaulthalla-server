#include "auth/session/Manager.hpp"
#include "rbac/PolicyEpoch.hpp"

#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Validator.hpp"
#include "crypto/util/hash.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "log/Registry.hpp"
#include "protocols/ws/ConnectionLimit.hpp"
#include "protocols/ws/Session.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "runtime/Deps.hpp"
#include "protocols/ws/Router.hpp"

using namespace vh::protocols::ws;
using vh::identities::User;
using vh::identities::Group;

namespace vh::auth::session {

namespace {
[[nodiscard]] std::optional<std::string> humanRefreshJti(const std::shared_ptr<Session>& session) {
    if (!session || !session->tokens || !session->tokens->refreshToken) return std::nullopt;
    if (session->tokens->refreshToken->jti.empty()) return std::nullopt;
    return session->tokens->refreshToken->jti;
}

[[nodiscard]] std::optional<std::string> shareRefreshJti(const std::shared_ptr<Session>& session) {
    if (!session || !session->tokens || !session->tokens->shareRefreshToken) return std::nullopt;
    if (session->tokens->shareRefreshToken->jti.empty()) return std::nullopt;
    return session->tokens->shareRefreshToken->jti;
}

[[nodiscard]] bool isShareRefreshKind(const TokenClaims& claims) {
    return claims.tokenKind == std::string(Issuer::shareRefreshTokenKind());
}

[[nodiscard]] bool isHumanRefreshKind(const TokenClaims& claims) {
    return claims.tokenKind.empty() || claims.tokenKind == std::string(Issuer::refreshTokenKind());
}

[[nodiscard]] std::string refreshTokenSubjectFromStoredToken(
    const std::shared_ptr<auth::model::RefreshToken>& token
) {
    if (!token) return {};
    return token->ipAddress + ":" + token->userAgent;
}

[[nodiscard]] std::shared_ptr<Session> rehydrateHumanSessionFromStoredRefreshToken(
    const std::string& rawToken,
    const TokenClaims& claims
) {
    const auto storedToken = db::query::auth::RefreshToken::get(claims.jti);
    if (!storedToken) throw std::invalid_argument("No stored refresh token found for validation");
    if (!storedToken->isValid()) throw std::invalid_argument("Stored refresh token is not valid");

    Validator::validateClaims(storedToken, claims);

    if (claims.subject != refreshTokenSubjectFromStoredToken(storedToken))
        throw std::runtime_error("Refresh token subject mismatch");

    Validator::verifyStoredRefreshTokenHash(rawToken, storedToken);

    // The stored row names its owner; the canonical account answers whether it may still sign in (a deleted
    // account is a non-authorizing tombstone, so no join against users is needed).
    const auto user = vh::identities::manager().user(storedToken->userId);
    if (!user) throw std::runtime_error("No user found for refresh token");
    if (user->systemOnly()) throw std::runtime_error("System-only users cannot rehydrate human sessions");
    if (!user->authorizing()) throw std::runtime_error("Deactivated users cannot rehydrate sessions");

    storedToken->rawToken = rawToken;

    auto session = std::make_shared<Session>(std::make_shared<Router>());
    session->ipAddress = storedToken->ipAddress;
    session->userAgent = storedToken->userAgent;
    session->tokens->refreshToken = storedToken;
    session->setAuthenticatedUser(user);
    return session;
}

void hydrateShareRefreshToken(
    const std::shared_ptr<Session>& session,
    const std::string& rawToken,
    const TokenClaims& claims
) {
    if (!session || !session->tokens) throw std::invalid_argument("Invalid session for share refresh hydration");
    if (!isShareRefreshKind(claims)) throw std::invalid_argument("Invalid share refresh token kind");
    if (claims.subject != Issuer::buildRefreshTokenSubject(session))
        throw std::runtime_error("Share refresh token subject mismatch");

    auto token = session->tokens->shareRefreshToken;
    if (!token) token = std::make_shared<auth::model::RefreshToken>();

    token->rawToken = rawToken;
    token->jti = claims.jti;
    token->subject = claims.subject;
    token->issuedAt = claims.issuedAt;
    token->expiresAt = claims.expiresAt;
    token->userAgent = session->userAgent;
    token->ipAddress = session->ipAddress;
    token->hashedToken = crypto::hash::tokenDigest(rawToken);

    session->tokens->shareRefreshToken = std::move(token);
}

void copyShareState(const std::shared_ptr<Session>& target, const std::shared_ptr<Session>& source) {
    if (!target || !source || target.get() == source.get() || source->user) return;

    if (source->isShareMode() && source->sharePrincipal()) {
        target->setSharePrincipal(source->sharePrincipal(), source->shareSessionToken());
        return;
    }

    if (source->isSharePending() && !source->shareSessionId().empty() && !source->shareSessionToken().empty())
        target->setPendingShareSession(source->shareSessionId(), source->shareSessionToken());
}
}

void Manager::accept(boost::asio::ip::tcp::socket&& socket, const std::shared_ptr<Router>& router,
                     std::unique_ptr<protocols::ws::ConnectionSlot> slot) {
    const auto session = std::make_shared<Session>(router);
    session->holdConnectionSlot(std::move(slot));
    cache(session);
    session->accept(std::move(socket));
}

void Manager::tryRehydrate(const std::shared_ptr<Session>& session) {
    try {
        if (!session) return;

        Validator::validateRefreshToken(session); // May throw if invalid
        Issuer::accessToken(session); // Assign new access token
        cache(session);
    } catch (const std::exception& ex) {
        log::Registry::ws()->debug(
            "[session::Manager] Rehydration failed for session UUID: {}. Reason: {}",
            session ? session->uuid : "null",
            ex.what()
        );

        rotateRefreshToken(session);
    }
}

void Manager::promote(const std::shared_ptr<Session>& session) {
    if (!session || !session->user || !session->tokens) {
        log::Registry::ws()->debug("[session::Manager] Promotion failed due to missing session, user, or token state");
        throw std::invalid_argument("Invalid session data for promotion");
    }

    if (session->user->systemOnly())
        throw std::runtime_error("System-only users cannot be promoted to human sessions");

    if (!session->tokens->refreshToken || !session->tokens->refreshToken->isValid()) {
        log::Registry::ws()->debug(
            "[session::Manager] Rotating refresh token before promotion for session UUID: {}",
            session->uuid
        );
        rotateRefreshToken(session);
    }

    Issuer::accessToken(session);

    if (!Validator::softValidateActiveSession(session)) {
        log::Registry::ws()->debug("[session::Manager] Promotion failed due to invalid session data");
        throw std::invalid_argument("Invalid session data for promotion");
    }

    session->tokens->refreshToken->userId = session->user->id;

    if (const auto dbToken = db::query::auth::RefreshToken::get(session->tokens->refreshToken->jti)) {
        session->tokens->refreshToken = dbToken;
        cache(session);
        log::Registry::ws()->debug("[session::Manager] Promoted session for user: {} (existing refresh token found)", session->user->name());
        return;
    }

    db::query::auth::RefreshToken::set(session->tokens->refreshToken);

    session->tokens->refreshToken = db::query::auth::RefreshToken::get(session->tokens->refreshToken->jti);
    if (!session->tokens->refreshToken) {
        log::Registry::ws()->debug(
            "[session::Manager] Promotion failed: Unable to retrieve updated refresh token for session UUID: {}",
            session->uuid
        );
        throw std::runtime_error("Failed to retrieve updated refresh token during promotion");
    }

    cache(session);

    log::Registry::ws()->debug(
        "[session::Manager] Promoted session for user: {}",
        session->user->name()
    );
}

void Manager::renewAccessToken(const std::shared_ptr<Session>& session, const std::string& existingToken) {
    if (!session) throw std::invalid_argument("Invalid session for access token renewal");
    if (!session->user) {
        try { Validator::validateRefreshToken(session); }
        catch (const std::exception& ex) {
            log::Registry::ws()->debug(
                "[session::Manager] Access token renewal failed for session UUID: {}. Reason: Refresh-backed user resolution failed. Exception: {}",
                session->uuid,
                ex.what()
            );
            throw std::invalid_argument("Invalid refresh token during access token renewal");
        }
    }

    if (!Validator::validateAccessToken(session, existingToken)) {
        log::Registry::ws()->debug(
            "[session::Manager] Access token renewal failed for session UUID: {}. Reason: Invalid existing access token",
            session->uuid
        );

        try { Validator::validateRefreshToken(session); }
        catch (const std::exception& ex) {
            log::Registry::ws()->debug(
                "[session::Manager] Access token renewal failed for session UUID: {}. Reason: Refresh token validation failed during access token renewal. Exception: {}",
                session->uuid,
                ex.what()
            );
            throw std::invalid_argument("Invalid refresh token during access token renewal");
        }
    }

    Issuer::accessToken(session);
    cache(session);

    log::Registry::ws()->debug(
        "[session::Manager] Renewed access token for session UUID: {}",
        session->uuid
    );
}

void Manager::cache(const std::shared_ptr<Session>& session) {
    if (!session) throw std::invalid_argument("Invalid session data for caching");

    std::lock_guard lock(sessionMutex_);

    sessionsByUUID_[session->uuid] = session;
    reindexHumanRefreshTokenLocked(session, std::nullopt);
    reindexShareRefreshTokenLocked(session, std::nullopt);

    if (session->user)
        sessionsByUserId_.emplace(session->user->id, session);
}

void Manager::eraseSessionIndexesLocked(
    const std::shared_ptr<Session>& session,
    std::optional<std::string> jti
) {
    if (jti) validatedAt_.erase(*jti);
    if (!session) return;

    sessionsByUUID_.erase(session->uuid);

    auto eraseSession = [&](auto& index) {
        for (auto it = index.begin(); it != index.end();) {
            const bool sameJti = jti && it->first == *jti;
            const bool sameSession = it->second == session;
            if (sameJti || sameSession) it = index.erase(it);
            else ++it;
        }
    };

    eraseSession(sessionsByRefreshJti_);
    eraseSession(shareSessionsByRefreshJti_);

    for (auto it = sessionsByUserId_.begin(); it != sessionsByUserId_.end();) {
        if (it->second == session) it = sessionsByUserId_.erase(it);
        else ++it;
    }
}

void Manager::rotateRefreshToken(const std::shared_ptr<Session>& session) {
    if (!session) throw std::invalid_argument("Invalid session for refresh token rotation");

    const auto oldJti = humanRefreshJti(session);

    Issuer::refreshToken(session);

    std::lock_guard lock(sessionMutex_);
    sessionsByUUID_[session->uuid] = session;
    reindexHumanRefreshTokenLocked(session, oldJti);
}

void Manager::rotateShareRefreshToken(const std::shared_ptr<Session>& session) {
    if (!session) throw std::invalid_argument("Invalid session for share refresh token rotation");

    const auto oldJti = shareRefreshJti(session);

    Issuer::shareRefreshToken(session);

    std::lock_guard lock(sessionMutex_);
    sessionsByUUID_[session->uuid] = session;
    reindexShareRefreshTokenLocked(session, oldJti);
}

void Manager::tryRehydrateShareRefresh(const std::shared_ptr<Session>& session) {
    if (!session) throw std::invalid_argument("Invalid session for share refresh token hydration");

    const auto rawToken =
        (session->tokens && session->tokens->shareRefreshToken)
            ? session->tokens->shareRefreshToken->rawToken
            : std::string{};

    if (rawToken.empty()) {
        rotateShareRefreshToken(session);
        return;
    }

    try {
        const auto claims = Issuer::decode(rawToken);
        if (!claims || claims->jti.empty()) throw std::runtime_error("Invalid share refresh token claims");
        hydrateShareRefreshToken(session, rawToken, *claims);

        if (const auto priorSession = getShareByRefreshJti(claims->jti))
            copyShareState(session, priorSession);

        cache(session);
    } catch (const std::exception& ex) {
        log::Registry::ws()->debug(
            "[session::Manager] Share refresh hydration failed for session UUID: {}. Reason: {}",
            session->uuid,
            ex.what()
        );
        rotateShareRefreshToken(session);
    }
}

void Manager::indexHumanRefreshTokenLocked(const std::shared_ptr<Session>& session) {
    if (!session || !session->tokens || !session->tokens->refreshToken) return;

    const auto& jti = session->tokens->refreshToken->jti;
    if (jti.empty()) return;

    if (session->isShareSession()) {
        log::Registry::ws()->debug(
            "[session::Manager] Refusing to index human refresh for share session UUID: {}",
            session->uuid
        );
        return;
    }

    sessionsByRefreshJti_[jti] = session;
}

void Manager::indexShareRefreshTokenLocked(const std::shared_ptr<Session>& session) {
    if (!session || !session->tokens || !session->tokens->shareRefreshToken) return;

    const auto& jti = session->tokens->shareRefreshToken->jti;
    if (jti.empty()) return;

    if (session->user) {
        log::Registry::ws()->debug(
            "[session::Manager] Refusing to index share refresh for human session UUID: {}",
            session->uuid
        );
        return;
    }

    shareSessionsByRefreshJti_[jti] = session;
}

void Manager::reindexHumanRefreshTokenLocked(
    const std::shared_ptr<Session>& session,
    std::optional<std::string> oldJti
) {
    if (!session) return;

    const auto currentJti = humanRefreshJti(session).value_or("");

    for (auto it = sessionsByRefreshJti_.begin(); it != sessionsByRefreshJti_.end();) {
        const bool isOldJti = oldJti && it->first == *oldJti;
        const bool isStaleSessionEntry = it->second == session && it->first != currentJti;
        const bool isShareSessionEntry = it->second == session && session->isShareSession();
        if (isOldJti || isStaleSessionEntry || isShareSessionEntry) it = sessionsByRefreshJti_.erase(it);
        else ++it;
    }

    indexHumanRefreshTokenLocked(session);
}

void Manager::reindexShareRefreshTokenLocked(
    const std::shared_ptr<Session>& session,
    std::optional<std::string> oldJti
) {
    if (!session) return;

    const auto currentJti = shareRefreshJti(session).value_or("");

    for (auto it = shareSessionsByRefreshJti_.begin(); it != shareSessionsByRefreshJti_.end();) {
        const bool isOldJti = oldJti && it->first == *oldJti;
        const bool isStaleSessionEntry = it->second == session && it->first != currentJti;
        const bool isHumanSessionEntry = it->second == session && session->user;
        if (isOldJti || isStaleSessionEntry || isHumanSessionEntry) it = shareSessionsByRefreshJti_.erase(it);
        else ++it;
    }

    indexShareRefreshTokenLocked(session);
}

bool Manager::validate(const std::shared_ptr<Session>& session, const std::string& accessToken) {
    try {
        if (!session) throw std::invalid_argument("Invalid session for validation");

        // A paired device has no tokens: it was authenticated by its key at the TLS handshake, and stays valid while
        // its user may sign in and the connection is open (revocation closes it).
        if (session->onDeviceListener())
            return session->isDeviceSession() && !session->closing() && session->user &&
                   !session->user->systemOnly() && session->user->authorizing();

        if (!session->user) {
            Validator::validateRefreshToken(session);
            Issuer::accessToken(session);
            cache(session);
            return true;
        }

        if (Validator::validateAccessToken(session, accessToken)) {
            if (session->tokens->accessToken->timeRemaining() < std::chrono::minutes(5)) Issuer::accessToken(session);
            cache(session);
            return true;
        }

        Validator::validateRefreshToken(session); // May throw if invalid
        Issuer::accessToken(session); // Assign new access token
        cache(session);
        return true;
    } catch (const std::exception& ex) {
        log::Registry::ws()->debug(
            "[session::Manager] Validation failed for session UUID: {}. Reason: {}",
            session ? session->uuid : "null",
            ex.what()
        );
        return false;
    }
}

std::shared_ptr<Session> Manager::validateRawRefreshToken(const std::string& refreshToken) {
    const auto claims = Issuer::decode(refreshToken);
    if (!claims || claims->jti.empty()) throw std::invalid_argument("Invalid refresh token for validation");
    if (!isHumanRefreshKind(*claims)) throw std::invalid_argument("Refresh token kind is not human refresh");

    const auto session = get(claims->jti);

    if (!session) return rehydrateHumanSessionFromStoredRefreshToken(refreshToken, *claims);
    if (!session->tokens->refreshToken) throw std::invalid_argument("Session does not contain a refresh token for validation");

    if (session->tokens->refreshToken->rawToken.empty()) session->tokens->refreshToken->rawToken = refreshToken;
    else if (session->tokens->refreshToken->rawToken != refreshToken)
        throw std::invalid_argument("Refresh token mismatch for validation");

    constexpr auto kRevalidateAfter = std::chrono::seconds(30);
    const auto now = std::chrono::steady_clock::now();
    bool fresh = false;
    {
        std::lock_guard lock(sessionMutex_);
        const auto it = validatedAt_.find(claims->jti);
        fresh = it != validatedAt_.end() && now - it->second.at < kRevalidateAfter &&
                it->second.epoch == rbac::policyEpoch() &&
                sessionsByRefreshJti_.contains(claims->jti);
    }
    if (!fresh || !session->tokens->refreshToken->isValid()) {
        Validator::validateRefreshToken(session);
        std::lock_guard lock(sessionMutex_);
        if (sessionsByRefreshJti_.contains(claims->jti))
            validatedAt_[claims->jti] = ValidatedStamp{.at = now, .epoch = rbac::policyEpoch()};
    }
    if (!session->user || session->isShareSession())
        throw std::invalid_argument("Refresh token did not resolve to a human session");
    if (session->user->systemOnly())
        throw std::invalid_argument("System-only users cannot use human refresh tokens");

    return session;
}

std::shared_ptr<Session> Manager::validateRawShareRefreshToken(const std::string& refreshToken) {
    const auto claims = Issuer::decode(refreshToken);
    if (!claims || claims->jti.empty()) throw std::invalid_argument("Invalid share refresh token for validation");
    if (!isShareRefreshKind(*claims)) throw std::invalid_argument("Refresh token kind is not share refresh");

    const auto session = getShareByRefreshJti(claims->jti);
    if (!session) throw std::invalid_argument("No share session found for refresh token validation");
    if (session->user) throw std::invalid_argument("Share refresh token resolved to a human session");
    if (!session->isShareMode()) throw std::invalid_argument("Share session is not ready for preview");
    if (!session->tokens || !session->tokens->shareRefreshToken)
        throw std::invalid_argument("Share session does not contain a refresh token");

    const auto token = session->tokens->shareRefreshToken;
    if (token->rawToken.empty()) token->rawToken = refreshToken;
    else if (token->rawToken != refreshToken)
        throw std::invalid_argument("Share refresh token mismatch for validation");

    if (!token->isValid()) throw std::invalid_argument("Share refresh token is not valid");
    Validator::validateClaims(token, claims);
    if (claims->subject != Issuer::buildRefreshTokenSubject(session))
        throw std::runtime_error("Share refresh token subject mismatch");

    return session;
}

void Manager::remove(const std::shared_ptr<Session>& session) {
    if (!session) return;

    auto jti = humanRefreshJti(session);
    if (!jti) jti = shareRefreshJti(session);

    {
        std::lock_guard lock(sessionMutex_);
        eraseSessionIndexesLocked(session, std::move(jti));
    }

    log::Registry::ws()->debug(
        "[session::Manager] Removed runtime session with UUID: {}",
        session->uuid
    );
}

void Manager::invalidate(const std::shared_ptr<Session>& session) {
    if (!session) return;

    const auto uuid = session->uuid;
    auto jti = humanRefreshJti(session);
    if (!jti) jti = shareRefreshJti(session);

    if (session->tokens)
        session->tokens->invalidate();

    {
        std::lock_guard lock(sessionMutex_);
        eraseSessionIndexesLocked(session, std::move(jti));
    }

    log::Registry::ws()->debug(
        "[session::Manager] Invalidated session with UUID: {}",
        uuid
    );
}

void Manager::invalidate(const std::string& token) {
    invalidate(get(token));
}

std::shared_ptr<Session> Manager::get(const std::string& token) {
    std::lock_guard lock(sessionMutex_);

    if (sessionsByUUID_.contains(token)) return sessionsByUUID_[token];
    if (sessionsByRefreshJti_.contains(token)) return sessionsByRefreshJti_[token];

    return nullptr;
}

std::shared_ptr<Session> Manager::getShareByRefreshJti(const std::string& token) {
    std::lock_guard lock(sessionMutex_);

    if (shareSessionsByRefreshJti_.contains(token)) return shareSessionsByRefreshJti_[token];

    return nullptr;
}

std::vector<std::shared_ptr<Session>> Manager::getSessions(const std::shared_ptr<User>& user) {
    if (!user) throw std::invalid_argument("Invalid user");
    return getSessionsByUserId(user->id);
}

std::vector<std::shared_ptr<Session>> Manager::getSessionsByUserId(const uint32_t userId) {
    std::lock_guard lock(sessionMutex_);

    std::vector<std::shared_ptr<Session>> sessions;
    const auto [begin, end] = sessionsByUserId_.equal_range(userId);

    for (auto it = begin; it != end; ++it)
        sessions.push_back(it->second);

    return sessions;
}

std::unordered_map<std::string, std::shared_ptr<Session>> Manager::getActive() {
    std::lock_guard lock(sessionMutex_);
    return sessionsByUUID_;
}

}
