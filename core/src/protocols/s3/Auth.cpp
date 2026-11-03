#include "protocols/s3/Auth.hpp"

#include "config/Registry.hpp"
#include "db/query/identities/User.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/s3/Error.hpp"

#include <algorithm>
#include <cctype>
#include <string_view>
#include <vl/sigv4/canonical.hpp>

namespace vh::protocols::s3 {

namespace {
bool configuredHostIsLoopback() {
    auto host = config::Registry::get().s3_gateway.host;
    std::ranges::transform(host, host.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
    });
    return host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]";
}

// vl-sigv4's rule: a request is presigned when its query carries X-Amz-Algorithm. Known before parsing succeeds, so a
// malformed presigned URL answers AuthorizationQueryParametersError rather than AuthorizationHeaderMalformed.
bool presignedRequestTarget(const std::string_view target) {
    const auto q = target.find('?');
    if (q == std::string_view::npos) return false;
    return std::ranges::any_of(vl::sigv4::parseQuery(target.substr(q + 1)),
                               [](const auto& param) { return param.first == "X-Amz-Algorithm"; });
}

// AWS's HTTP status for each S3 error code vl::sigv4::awsErrorCode answers with.
http::status sigv4StatusFor(const vl::sigv4::ErrorCode code) {
    switch (code) {
        case vl::sigv4::ErrorCode::None:
        case vl::sigv4::ErrorCode::MissingAuthorization:
        case vl::sigv4::ErrorCode::MissingDate:
        case vl::sigv4::ErrorCode::InvalidDate:
        case vl::sigv4::ErrorCode::RequestTimeTooSkewed:
        case vl::sigv4::ErrorCode::PresignExpired:
        case vl::sigv4::ErrorCode::SignedHeaderMissing:
        case vl::sigv4::ErrorCode::UnknownAccessKey:
        case vl::sigv4::ErrorCode::SignatureMismatch:
        case vl::sigv4::ErrorCode::ChunkSignatureMismatch: return http::status::forbidden;
        case vl::sigv4::ErrorCode::AmbiguousAuthorization:
        case vl::sigv4::ErrorCode::UnsupportedAlgorithm:
        case vl::sigv4::ErrorCode::MalformedAuthorization:
        case vl::sigv4::ErrorCode::InvalidCredentialScope:
        case vl::sigv4::ErrorCode::UnsupportedService:
        case vl::sigv4::ErrorCode::RegionMismatch:
        case vl::sigv4::ErrorCode::ScopeDateMismatch:
        case vl::sigv4::ErrorCode::MissingSignedHeaders:
        case vl::sigv4::ErrorCode::HostNotSigned:
        case vl::sigv4::ErrorCode::MissingSignature:
        case vl::sigv4::ErrorCode::InvalidExpires:
        case vl::sigv4::ErrorCode::ExpiresTooLarge:
        case vl::sigv4::ErrorCode::SessionTokenNotSupported:
        case vl::sigv4::ErrorCode::PayloadHashMismatch:
        case vl::sigv4::ErrorCode::MalformedChunkedEncoding:
        case vl::sigv4::ErrorCode::ChunkTooLarge:
        case vl::sigv4::ErrorCode::IncompleteBody:
        case vl::sigv4::ErrorCode::DecodedLengthMismatch: return http::status::bad_request;
        case vl::sigv4::ErrorCode::UnsupportedPayloadHash: return http::status::not_implemented;
    }
    return http::status::forbidden;
}
}

vl::sigv4::VerifyOptions gatewayVerifyOptions() {
    vl::sigv4::VerifyOptions options;
    options.service = "s3";
    options.region = std::nullopt;
    options.max_skew = vl::sigv4::kDefaultMaxSkew;
    options.max_presign_expiry = vl::sigv4::kMaxPresignExpiry;
    options.allow_presigned = true;
    options.reject_session_tokens = true;
    options.require_scope_date_match = true;
    options.require_signed_host = true;
    options.imply_zero_content_length = true;
    return options;
}

S3Error sigv4Error(const vl::sigv4::ErrorCode code, const bool presigned, std::string message, std::string resource) {
    if (message.empty()) message = std::string(vl::sigv4::errorCodeName(code));
    return S3Error{std::string(vl::sigv4::awsErrorCode(code, presigned)), std::move(message), sigv4StatusFor(code),
                   std::move(resource)};
}

GatewaySecret verifySignedRequest(const vl::sigv4::VerificationInput& input, const GatewaySecretLookup& lookup,
                                  const vl::sigv4::TimePoint now,
                                  std::optional<vl::sigv4::ChunkVerifier>* streamingBody) {
    auto options = gatewayVerifyOptions();
    options.allow_streaming_signed_payload = streamingBody != nullptr;
    const auto parsed = vl::sigv4::parseAuthorization(input, options);
    if (!parsed)
        throw sigv4Error(parsed.error().code, presignedRequestTarget(input.target), parsed.error().message,
                         input.target);

    // vl-sigv4 reads a session token from the x-amz-security-token header and, for presigned URLs, the query. The
    // gateway has always refused one anywhere in the request-target, header-signed requests included; keep that.
    if (input.target.find("X-Amz-Security-Token=") != std::string::npos)
        throw sigv4Error(vl::sigv4::ErrorCode::SessionTokenNotSupported, parsed->presigned,
                         "Temporary security tokens are not supported", input.target);

    // vl::sigv4::verify calls the lookup only after the secret-free checks pass, so a stale, malformed or
    // body-mismatched request never reaches the credential database or the secret's decryption.
    std::optional<GatewaySecret> found;
    const vl::sigv4::SecretLookup secretLookup = [&](const std::string_view accessKey) -> std::optional<std::string> {
        found = lookup(std::string(accessKey));
        if (!found) return std::nullopt;
        return found->secret_access_key;
    };
    const auto result = vl::sigv4::verify(input, secretLookup, now, options);
    if (!result.ok()) throw sigv4Error(result.code, parsed->presigned, result.message, input.target);
    if (!found)
        throw sigv4Error(vl::sigv4::ErrorCode::UnknownAccessKey, parsed->presigned, "Unknown access key", input.target);
    if (result.body_pending) {
        // Only reachable with streamingBody (allow_streaming_signed_payload is off otherwise).
        auto chain = vl::sigv4::ChunkVerifier::forRequest(result, found->secret_access_key);
        if (!chain || streamingBody == nullptr)
            throw sigv4Error(vl::sigv4::ErrorCode::UnsupportedPayloadHash, parsed->presigned,
                             chain ? "Signed streaming payload outside a streamed request" : chain.error().message,
                             input.target);
        streamingBody->emplace(std::move(*chain));
    }
    return std::move(*found);
}

Authenticator::Authenticator(const bool requireSigV4)
    : requireSigV4_(requireSigV4) {}

CredentialManager& Authenticator::credentials() const {
    std::scoped_lock lock(credentialsMutex_);
    if (!credentials_)
        credentials_ = std::make_unique<CredentialManager>();
    return *credentials_;
}

AuthContext Authenticator::authenticate(const vl::sigv4::VerificationInput& input,
                                        std::optional<vl::sigv4::ChunkVerifier>* streamingBody) const {
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

    const auto secret = verifySignedRequest(
        input,
        [this](const std::string& accessKey) { return credentials().findEnabledSecret(accessKey); },
        vl::sigv4::Clock::now(), streamingBody);

    auto user = vh::identities::manager().user(secret.credential.principal_user_id);
    if (!user || !user->authorizing()) throw accessDenied(input.target);

    credentials().markUsed(secret.credential.id);
    return {
        .user = std::move(user),
        .credential = secret.credential,
        .credential_id = secret.credential.id,
        .access_key = secret.credential.access_key,
        .scope_mode = secret.credential.scope_mode,
        .enforce_budget_for_local_requests = secret.credential.enforce_budget_for_local_requests,
        .dev_context = false
    };
}

} // namespace vh::protocols::s3
