#include "auth/session/Issuer.hpp"
#include "auth/model/RefreshToken.hpp"
#include "config/Registry.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "crypto/util/hash.hpp"
#include "crypto/secrets/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "auth/model/TokenPair.hpp"

#include <chrono>
#include <uuid/uuid.h>
#include <jwt-cpp/jwt.h>
#include <jwt-cpp/traits/nlohmann-json/traits.h>
#include <nlohmann/json.hpp>
#include <utility>

using namespace vh::protocols::ws;

namespace vh::auth::session {

namespace {
std::optional<std::string>& jwtSecretForTesting() {
    static std::optional<std::string> secret;
    return secret;
}

std::string jwtSecret() {
    if (const auto& secret = jwtSecretForTesting()) return *secret;
    return vh::runtime::Deps::get().secretsManager->jwtSecret();
}

void rejectSystemOnlyHumanToken(const std::shared_ptr<Session>& session) {
    if (session && session->user && session->user->systemOnly())
        throw std::runtime_error("System-only users cannot receive normal user tokens");
}
}

static std::string generateUUID() {
    uuid_t uuid;
    char uuidStr[37];
    uuid_generate(uuid);
    uuid_unparse(uuid, uuidStr);
    return {uuidStr};
}

// Every token is an HS256 JWT: a fresh libuuid random jti plus a 256-bit HMAC-SHA256 signature keyed by the
// daemon's JWT secret (64 CSPRNG characters, crypto::secrets::Manager). The signature makes refresh tokens
// unguessable, so they are stored as a plain SHA-256 digest (crypto::hash::tokenDigest), not a password hash (#171).
static void finalizeAndSignToken(
    const std::shared_ptr<Session>& session,
    const std::shared_ptr<model::Token>& t,
    const std::chrono::system_clock::duration ttl,
    const std::string_view tokenKind
) {
    const auto now = std::chrono::time_point_cast<std::chrono::seconds>(
        std::chrono::system_clock::now()
    );
    const auto exp = now + std::chrono::duration_cast<std::chrono::seconds>(ttl);

    t->issuedAt = now;
    t->expiresAt = exp;
    t->jti = generateUUID();
    if (session->user) t->userId = session->user->id;

    auto builder =
        jwt::create<jwt::traits::nlohmann_json>()
        .set_issuer("Vaulthalla")
        .set_subject(t->subject)
        .set_issued_at(now)
        .set_expires_at(exp)
        .set_id(t->jti);

    if (!tokenKind.empty())
        builder.set_payload_claim("token_kind", nlohmann::json(std::string(tokenKind)));

    t->rawToken = builder.sign(jwt::algorithm::hs256{jwtSecret()});
}

void Issuer::accessToken(const std::shared_ptr<Session>& session) {
    rejectSystemOnlyHumanToken(session);

    const auto t = std::make_shared<model::Token>();
    t->subject = buildAccessTokenSubject(session);
    finalizeAndSignToken(
        session,
        t,
        std::chrono::minutes(vh::config::Registry::get().auth.access_token_expiry_minutes),
        accessTokenKind()
    );
    session->tokens->accessToken = t;
    session->sendAccessTokenOnNextResponse();
}

void Issuer::refreshToken(const std::shared_ptr<Session>& session) {
    rejectSystemOnlyHumanToken(session);

    const auto t = std::make_shared<model::RefreshToken>();
    t->subject = buildRefreshTokenSubject(session);
    t->userAgent = session->userAgent;
    t->ipAddress = session->ipAddress;
    finalizeAndSignToken(
        session,
        t,
        std::chrono::days(vh::config::Registry::get().auth.refresh_token_expiry_days),
        refreshTokenKind()
    );
    t->hashedToken = crypto::hash::tokenDigest(t->rawToken);

    if (t->hashedToken.empty()) {
        log::Registry::auth()->error("[session::Issuer] Failed to hash refresh token for session {}: {}", session->uuid, "Hashing failed");
        throw std::runtime_error("Failed to hash refresh token");
    }

    session->tokens->refreshToken = t;

    if (session->tokens->refreshToken != t) {
        log::Registry::auth()->error("[session::Issuer] Failed to assign refresh token to session {}: {}", session->uuid, "Assignment failed");
        throw std::runtime_error("Failed to assign refresh token to session");
    }
}

void Issuer::shareRefreshToken(const std::shared_ptr<Session>& session) {
    const auto t = std::make_shared<model::RefreshToken>();
    t->subject = buildRefreshTokenSubject(session);
    t->userAgent = session->userAgent;
    t->ipAddress = session->ipAddress;
    finalizeAndSignToken(
        session,
        t,
        std::chrono::days(vh::config::Registry::get().auth.refresh_token_expiry_days),
        shareRefreshTokenKind()
    );
    t->hashedToken = crypto::hash::tokenDigest(t->rawToken);

    if (t->hashedToken.empty()) {
        log::Registry::auth()->error("[session::Issuer] Failed to hash share refresh token for session {}", session->uuid);
        throw std::runtime_error("Failed to hash share refresh token");
    }

    session->tokens->shareRefreshToken = t;

    if (session->tokens->shareRefreshToken != t) {
        log::Registry::auth()->error("[session::Issuer] Failed to assign share refresh token to session {}", session->uuid);
        throw std::runtime_error("Failed to assign share refresh token to session");
    }
}

std::optional<TokenClaims> Issuer::decode(const std::string& refreshToken) {
    try {
        const auto decoded = jwt::decode<jwt::traits::nlohmann_json>(refreshToken);

        const auto verifier = jwt::verify<jwt::traits::nlohmann_json>()
            .allow_algorithm(jwt::algorithm::hs256{jwtSecret()})
            .with_issuer("Vaulthalla");

        verifier.verify(decoded);

        const auto tokenKind = decoded.has_payload_claim("token_kind")
                                   ? decoded.get_payload_claim("token_kind").as_string()
                                   : std::string{};

        return TokenClaims {
            .jti = decoded.get_id(),
            .subject = decoded.get_subject(),
            .tokenKind = tokenKind,
            .issuedAt = decoded.get_issued_at(),
            .expiresAt = decoded.get_expires_at()
        };
    } catch (const std::exception& e) {
        log::Registry::auth()->debug("[session::Issuer] Failed to decode refresh token: {}", e.what());
        return std::nullopt;
    }
}

std::string Issuer::buildAccessTokenSubject(const std::shared_ptr<Session>& session) {
    return session->uuid;
}

std::string Issuer::buildRefreshTokenSubject(const std::shared_ptr<Session>& session) {
    return session->ipAddress + ":" + session->userAgent;
}

void Issuer::setJwtSecretForTesting(std::string secret) {
    jwtSecretForTesting() = std::move(secret);
}

void Issuer::clearJwtSecretForTesting() {
    jwtSecretForTesting().reset();
}

}
