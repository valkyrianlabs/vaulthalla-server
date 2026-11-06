#pragma once

#include <memory>
#include <chrono>
#include <string>
#include "auth/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

namespace vh::auth::session {

struct Validator {
    static void validateRefreshToken(const std::shared_ptr<protocols::ws::Session>& session);
    static bool validateAccessToken(const std::shared_ptr<protocols::ws::Session>& session, const std::string& accessToken);

    // Signs the session in from the stored row of its refresh cookie: the row must exist, be live, not idle, match the
    // claims, subject and hash, belong to an authorizing account and satisfy the MFA policy (assurance::enforce).
    static void rehydrateFromStoredRefreshToken(const std::shared_ptr<protocols::ws::Session>& session, const std::string& rawToken, const std::optional<TokenClaims>& claims);

    static bool softValidateActiveSession(const std::shared_ptr<protocols::ws::Session>& session);
    static bool hasUsableAccessToken(const std::shared_ptr<protocols::ws::Session>& session);
    static bool hasUsableRefreshToken(const std::shared_ptr<protocols::ws::Session>& session);

    // Throws unless rawToken matches the stored hash (digest or legacy Argon2). A legacy match is rewritten to the
    // digest form in the DB (and on storedToken); a failed rewrite is logged and never fails the auth.
    static void verifyStoredRefreshTokenHash(const std::string& rawToken, const std::shared_ptr<model::RefreshToken>& storedToken);

    static void checkForDangerousDiversion(const std::shared_ptr<model::RefreshToken>& incomingToken, const std::shared_ptr<model::RefreshToken>& storedToken);
    static bool hasUsableRefreshContext(const std::shared_ptr<protocols::ws::Session>& session);

    static void validateClaims(const std::shared_ptr<model::Token>& t, const std::optional<TokenClaims>& claims);
    static void validateRefreshClaims(const std::shared_ptr<protocols::ws::Session>& session, const std::optional<TokenClaims>& claims);
};

}
