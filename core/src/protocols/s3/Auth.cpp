#include "protocols/s3/Auth.hpp"

#include "config/Registry.hpp"
#include "db/query/identities/User.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/s3/Error.hpp"

#include <algorithm>
#include <cctype>

namespace vh::protocols::s3 {

namespace {
bool hasSecurityTokenHeader(const sigv4::VerificationInput& input) {
    for (const auto& [name, value] : input.headers) {
        auto normalized = name;
        std::ranges::transform(normalized, normalized.begin(), [](const unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (normalized == "x-amz-security-token" && !value.empty()) return true;
    }
    return false;
}

bool configuredHostIsLoopback() {
    auto host = config::Registry::get().s3_gateway.host;
    std::ranges::transform(host, host.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
}
}

Authenticator::Authenticator(const bool requireSigV4)
    : requireSigV4_(requireSigV4) {}

CredentialManager& Authenticator::credentials() const {
    std::scoped_lock lock(credentialsMutex_);
    if (!credentials_)
        credentials_ = std::make_unique<CredentialManager>();
    return *credentials_;
}

AuthContext Authenticator::authenticate(const sigv4::VerificationInput& input) const {
    if (!requireSigV4_) {
        if (!config::Registry::get().dev.enabled && !configuredHostIsLoopback())
            throw S3Error{
                "AccessDenied",
                "Unsigned S3 gateway requests are only allowed in dev mode or on loopback listeners",
                http::status::forbidden,
                input.target};
        auto user = vh::identities::manager().user(1);
        if (!user) throw accessDenied("/");
        return {
            .user = std::move(user),
            .credential = {},
            .credential_id = 0,
            .access_key = "dev-only",
            .scope_mode = "user_access",
            .enforce_budget_for_local_requests = false,
            .dev_context = true
        };
    }

    std::string parseError;
    const auto parsed = sigv4::parseAuthorization(input, parseError);
    if (!parsed) throw S3Error{"SignatureDoesNotMatch", parseError, http::status::forbidden, input.target};

    if (input.target.find("X-Amz-Security-Token=") != std::string::npos || hasSecurityTokenHeader(input))
        throw S3Error{"InvalidToken", "Temporary security tokens are not supported", http::status::bad_request, input.target};

    auto& credentialManager = credentials();
    const auto secret = credentialManager.findEnabledSecret(parsed->credential.access_key);
    if (!secret) throw accessDenied(input.target);

    const auto result = sigv4::verify(input, secret->secret_access_key);
    if (!result.ok) throw S3Error{"SignatureDoesNotMatch", result.error, http::status::forbidden, input.target};

    auto user = vh::identities::manager().user(secret->credential.principal_user_id);
    if (!user || !user->authorizing()) throw accessDenied(input.target);

    credentialManager.markUsed(secret->credential.id);
    return {
        .user = std::move(user),
        .credential = secret->credential,
        .credential_id = secret->credential.id,
        .access_key = secret->credential.access_key,
        .scope_mode = secret->credential.scope_mode,
        .enforce_budget_for_local_requests = secret->credential.enforce_budget_for_local_requests,
        .dev_context = false
    };
}

} // namespace vh::protocols::s3
