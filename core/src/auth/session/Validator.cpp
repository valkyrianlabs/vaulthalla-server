#include "auth/session/Validator.hpp"
#include "auth/session/Manager.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Issuer.hpp"
#include "protocols/ws/Session.hpp"
#include "log/Registry.hpp"
#include "crypto/util/hash.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "runtime/Deps.hpp"
#include "db/query/auth/RefreshToken.hpp"

using namespace vh::protocols::ws;
using namespace vh::auth::model;

namespace vh::auth::session {

bool Validator::validateAccessToken(const std::shared_ptr<Session>& session, const std::string& accessToken) {
    log::Registry::auth()->debug("[session::Validator] Validating access token for session");

    try {
        if (!hasUsableAccessToken(session)) {
            log::Registry::ws()->debug("[session::Validator] No valid access token found for session");
            return false;
        }

        if (session->tokens->accessToken->rawToken != accessToken) {
            log::Registry::ws()->debug("[session::Validator] Access token mismatch for session");
            return false;
        }

        const auto claims = Issuer::decode(accessToken);
        validateClaims(session->tokens->accessToken, claims);
        if (claims->subject != Issuer::buildAccessTokenSubject(session)) {
            log::Registry::ws()->debug("[session::Validator] Access token subject mismatch: expected {}, got {}", Issuer::buildAccessTokenSubject(session), claims->subject);
            return false;
        }

        return true;
    } catch (const std::exception& e) {
        log::Registry::ws()->debug("[session::Validator] Token validation failed: {}", e.what());
        return false;
    }
}

void Validator::validateRefreshToken(const std::shared_ptr<Session>& session) {
    log::Registry::auth()->debug("[session::Validator] Validating refresh token for session");

    if (!hasUsableRefreshContext(session)) {
        log::Registry::ws()->debug("[session::Validator] No valid refresh token context found for session");
        throw std::runtime_error("No valid refresh token context found for session");
    }

    const auto rawToken = session->tokens->refreshToken->rawToken;
    const auto claims = Issuer::decode(rawToken);

    if (!claims) throw std::runtime_error("Invalid refresh token: unable to decode claims");
    if (!claims->tokenKind.empty() && claims->tokenKind != std::string(Issuer::refreshTokenKind()))
        throw std::runtime_error("Refresh token kind mismatch");

    validateRefreshClaims(session, claims);

    if (tryRehydrateFromPriorSession(session, rawToken, claims)) return;

    rehydrateFromStoredRefreshToken(session, rawToken, claims);
}

bool Validator::tryRehydrateFromPriorSession(const std::shared_ptr<Session>& session, const std::string& rawToken, const std::optional<TokenClaims>& claims) {
    if (!claims) return false;

    const auto priorSession = runtime::Deps::get().sessionManager->get(claims->jti);
    if (!priorSession || priorSession.get() == session.get()) return false;
    if (!priorSession->tokens || !priorSession->tokens->refreshToken) return false;
    if (priorSession->isShareSession()) return false;

    const auto& priorToken = priorSession->tokens->refreshToken;

    if (priorToken->rawToken != rawToken) return false;
    if (!claims->tokenKind.empty() && claims->tokenKind != std::string(Issuer::refreshTokenKind())) return false;

    try {
        validateClaims(priorToken, claims);

        if (claims->subject != Issuer::buildRefreshTokenSubject(session)) {
            log::Registry::ws()->debug(
                "[session::Validator] Refresh token subject mismatch: expected {}, got {}",
                Issuer::buildRefreshTokenSubject(session),
                claims->subject
            );
            return false;
        }

        session->tokens->refreshToken = std::make_shared<auth::model::RefreshToken>(*priorToken);
        session->tokens->refreshToken->rawToken = rawToken;
        if (priorSession->user) {
            if (priorSession->user->systemOnly())
                throw std::runtime_error("System-only users cannot rehydrate human sessions");
            session->setAuthenticatedUser(priorSession->user);
        }

        log::Registry::auth()->debug(
            "[session::Validator] Rehydrated refresh token from prior session for JTI: {}",
            claims->jti
        );

        return true;
    } catch (const std::exception& ex) {
        log::Registry::ws()->debug(
            "[session::Validator] Prior session refresh rehydration failed for JTI {}: {}",
            claims->jti,
            ex.what()
        );
        return false;
    }
}

void Validator::rehydrateFromStoredRefreshToken(const std::shared_ptr<Session>& session, const std::string& rawToken, const std::optional<TokenClaims>& claims) {
    if (!claims)
        throw std::runtime_error("Invalid refresh token: unable to decode claims");

    const auto storedToken = db::query::auth::RefreshToken::get(claims->jti);
    if (!storedToken)
        throw std::runtime_error("No stored refresh token found for JTI");
    // A revoked token (logout elsewhere, account deleted/deactivated/re-roled) must not bring a session back.
    if (!storedToken->isValid())
        throw std::runtime_error("Stored refresh token is not valid");

    validateClaims(storedToken, claims);

    if (claims->subject != Issuer::buildRefreshTokenSubject(session)) {
        log::Registry::ws()->debug(
            "[session::Validator] Refresh token subject mismatch: expected {}, got {}",
            Issuer::buildRefreshTokenSubject(session),
            claims->subject
        );
        throw std::runtime_error("Refresh token subject mismatch");
    }

    checkForDangerousDiversion(session->tokens->refreshToken, storedToken);

    verifyStoredRefreshTokenHash(rawToken, storedToken);

    // The stored row names its owner; a deleted account is a non-authorizing tombstone in the Manager.
    const auto user = vh::identities::manager().user(storedToken->userId);
    if (!user) {
        runtime::Deps::get().sessionManager->invalidate(session);
        log::Registry::auth()->debug(
            "[session::Validator] No user found for JTI: {}, token user ID: {}",
            claims->jti,
            storedToken->userId
        );
        throw std::runtime_error("No user found for refresh token");
    }

    if (user->systemOnly()) {
        runtime::Deps::get().sessionManager->invalidate(session);
        throw std::runtime_error("System-only users cannot use human refresh tokens");
    }

    if (!user->authorizing()) {
        runtime::Deps::get().sessionManager->invalidate(session);
        throw std::runtime_error("Deactivated users cannot use refresh tokens");
    }

    storedToken->rawToken = rawToken;
    session->tokens->refreshToken = storedToken;
    session->setAuthenticatedUser(user);
}

void Validator::verifyStoredRefreshTokenHash(const std::string& rawToken, const std::shared_ptr<RefreshToken>& storedToken) {
    if (!storedToken) throw std::runtime_error("No stored refresh token to verify against");

    const auto match = crypto::hash::verifyToken(rawToken, storedToken->hashedToken);
    if (match == crypto::hash::TokenMatch::Mismatch) throw std::runtime_error("Refresh token hash mismatch");
    if (match != crypto::hash::TokenMatch::Legacy) return;

    // Rows written before #171 hold an Argon2 hash; replace it so this token's later checks take the fast path.
    const auto digest = crypto::hash::tokenDigest(rawToken);
    try {
        if (db::query::auth::RefreshToken::rewriteHash(storedToken->jti, storedToken->hashedToken, digest))
            storedToken->hashedToken = digest;
    } catch (const std::exception& ex) {
        log::Registry::auth()->warn(
            "[session::Validator] Could not rewrite legacy refresh token hash for JTI {}: {}",
            storedToken->jti,
            ex.what()
        );
    }
}

bool Validator::softValidateActiveSession(const std::shared_ptr<Session>& session) {
    if (!session) {
        log::Registry::ws()->debug("[session::Validator] No session found for validation");
        return false;
    }

    if (!session->user) {
        log::Registry::ws()->debug("[session::Validator] No user associated with session");
        return false;
    }

    if (session->user->systemOnly()) {
        log::Registry::ws()->debug("[session::Validator] System-only user cannot hold active human session");
        return false;
    }

    if (!session->tokens) {
        log::Registry::ws()->debug("[session::Validator] No tokens associated with session");
        return false;
    }

    if (!hasUsableAccessToken(session)) {
        log::Registry::ws()->debug("[session::Validator] Access token is not usable for session");
        return false;
    }

    if (!hasUsableRefreshToken(session)) {
        log::Registry::ws()->debug("[session::Validator] Refresh token is not usable for session");
        return false;
    }

    return true;
}

bool Validator::hasUsableAccessToken(const std::shared_ptr<Session>& session) {
    if (!session->tokens->accessToken) {
        log::Registry::ws()->debug("[session::Validator] No access token found in session");
        return false;
    }

    if (!session->tokens->accessToken->isValid()) {
        log::Registry::ws()->debug("[session::Validator] Access token is invalid for session");
        return false;
    }

    return true;
}

bool Validator::hasUsableRefreshToken(const std::shared_ptr<Session>& session) {
    if (!session->tokens->refreshToken) {
        log::Registry::ws()->debug("[session::Validator] No refresh token found in session");
        return false;
    }

    if (!session->tokens->refreshToken->isValid()) {
        log::Registry::ws()->debug("[session::Validator] Refresh token is invalid for session");
        return false;
    }

    return true;
}

bool Validator::hasUsableRefreshContext(const std::shared_ptr<Session>& session) {
    if (!session) {
        log::Registry::ws()->debug("[session::Validator] No session found for refresh context validation");
        return false;
    }

    if (!session->tokens) {
        log::Registry::ws()->debug("[session::Validator] No tokens found in session for refresh context validation");
        return false;
    }

    if (!session->tokens->refreshToken) {
        log::Registry::ws()->debug("[session::Validator] No refresh token found in session for refresh context validation");
        return false;
    }

    if (session->tokens->refreshToken->rawToken.empty() && session->tokens->refreshToken->hashedToken.empty()) {
        log::Registry::ws()->debug("[session::Validator] Refresh token in session has no raw token or hashed token for refresh context validation");
        return false;
    }

    return true;
}

void Validator::checkForDangerousDiversion(const std::shared_ptr<RefreshToken>& incomingToken, const std::shared_ptr<RefreshToken>& storedToken) {
    if (incomingToken->divergesFrom(storedToken)) {
        const auto msg = fmt::format(
            "[session::Validator] Dangerous divergence detected for JTI: {}",
            incomingToken->jti
        );
        log::Registry::ws()->warn(msg);
        log::Registry::audit()->warn(msg);
        throw std::runtime_error("Potential token tampering detected");
    }
}

void Validator::validateClaims(const std::shared_ptr<Token>& t, const std::optional<TokenClaims>& claims) {
    if (!claims)
        throw std::runtime_error("Invalid refresh token: unable to decode claims");

    const auto now = std::chrono::system_clock::now();

    if (claims->expiresAt < now)
        throw std::runtime_error("Refresh token has expired");

    const auto tokenIat = std::chrono::time_point_cast<std::chrono::seconds>(t->issuedAt);
    const auto claimIat = std::chrono::time_point_cast<std::chrono::seconds>(claims->issuedAt);

    if (tokenIat != claimIat) {
        log::Registry::ws()->debug(
            "[session::Validator] Issued at time mismatch for JTI: {}, token issued at: {}, claims issued at: {}",
            claims->jti,
            tokenIat.time_since_epoch().count(),
            claimIat.time_since_epoch().count()
        );
        throw std::runtime_error("Issued at time mismatch in refresh token");
    }

    const auto tokenExp = std::chrono::time_point_cast<std::chrono::seconds>(t->expiresAt);
    const auto claimExp = std::chrono::time_point_cast<std::chrono::seconds>(claims->expiresAt);

    if (claimExp != tokenExp) {
        log::Registry::ws()->debug(
            "[session::Validator] Expiration time mismatch for JTI: {}, token expires at: {}, claims expires at: {}",
            claims->jti,
            tokenExp.time_since_epoch().count(),
            claimExp.time_since_epoch().count()
        );
        throw std::runtime_error("Expiration time mismatch in refresh token");
    }

    if (claims->jti.empty())
        throw std::runtime_error("Missing JTI in refresh token");

    if (claims->jti != t->jti)
        throw std::runtime_error("JTI mismatch in refresh token");

    if (claims->subject.empty())
        throw std::runtime_error("Missing subject in refresh token");
}

void Validator::validateRefreshClaims(const std::shared_ptr<Session>& session, const std::optional<TokenClaims>& claims) {
    if (!claims)
        throw std::runtime_error("Invalid refresh token: unable to decode claims");

    if (claims->expiresAt < std::chrono::system_clock::now())
        throw std::runtime_error("Refresh token has expired");

    if (claims->jti.empty())
        throw std::runtime_error("Missing JTI in refresh token");

    if (claims->subject.empty())
        throw std::runtime_error("Missing subject in refresh token");

    if (claims->subject != Issuer::buildRefreshTokenSubject(session)) {
        log::Registry::ws()->debug(
            "[session::Validator] Refresh token subject mismatch: expected {}, got {}",
            Issuer::buildRefreshTokenSubject(session),
            claims->subject
        );
        throw std::runtime_error("Refresh token subject mismatch");
    }
}

}
