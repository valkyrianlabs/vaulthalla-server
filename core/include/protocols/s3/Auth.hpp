#pragma once

#include "protocols/s3/CredentialManager.hpp"
#include "protocols/s3/Error.hpp"
#include "identities/Fwd.hpp"

#include <boost/beast/http.hpp>
#include <vl/sigv4/verifier.hpp>

#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>

namespace vh::protocols::s3 {

struct AuthContext {
    std::shared_ptr<identities::User> user;
    db::query::s3::GatewayCredential credential;
    uint32_t credential_id{};
    std::string access_key;
    std::string scope_mode{"user_access"};
    bool enforce_budget_for_local_requests{false};
    bool dev_context{false};
};

// ---- SigV4 request authentication (vl-sigv4) ---------------------------------------------------------------------
//
// The gateway verifies AWS Signature Version 4 with vl::sigv4 (the vl-sigv4 library, subprojects/vl-sigv4.wrap). The
// in-tree protocols/s3/SigV4 verifier it replaced has no production callers; it stays only as the reference the
// goldens compare against (core/tests/unit/test_sigv4_goldens.cpp) until a release is verified.

// The verifier options of the gateway: credential scope service "s3", any region (clients sign "us-east-1", "auto",
// custom names), +/-15 min clock skew, presigned URLs of 1 s to 7 days, the implied "content-length: 0" for bodiless
// requests a proxy stripped it from, and no session tokens (gateway keys are long-lived). vl-sigv4's spec checks stay
// on: host must be signed, and the credential scope date must equal the date of x-amz-date.
[[nodiscard]] vl::sigv4::VerifyOptions gatewayVerifyOptions();

// The request as the verifier sees it: method, raw request-target, Host, every header as received (repeated names
// kept, combined by the verifier) and the body. A buffered body is passed as `body`, which must outlive the
// verification; a streamed one as the hex SHA-256 of what the gateway stored (aws-chunked decoded) in `bodySha256`.
template <class Body, class Fields>
vl::sigv4::VerificationInput verificationInput(const http::request<Body, Fields>& req, const std::string_view body,
                                               std::optional<std::string> bodySha256 = std::nullopt) {
    vl::sigv4::VerificationInput out;
    out.method = std::string(req.method_string());
    out.target = std::string(req.target());
    if (const auto host = req.find(http::field::host); host != req.end()) out.host = std::string(host->value());
    for (const auto& field : req)
        out.headers.emplace_back(std::string(field.name_string()), std::string(field.value()));
    out.body = body;
    out.body_sha256 = std::move(bodySha256);
    return out;
}

// The S3 error (code, HTTP status) a verification failure answers with. `message` is the verifier's; it never
// carries a secret or the expected signature.
[[nodiscard]] S3Error sigv4Error(vl::sigv4::ErrorCode code, bool presigned, std::string message, std::string resource);

// Returns the enabled, unexpired gateway credential and its secret for an access key, or nullopt.
using GatewaySecretLookup = std::function<std::optional<GatewaySecret>(const std::string& accessKey)>;

// Authenticates a SigV4 request (Authorization header or presigned query) at `now`. Order: parse (algorithm,
// credential scope, X-Amz-Expires, session tokens), then the secret-free checks (date, skew or presign window, signed
// headers, payload hash), then the credential lookup, then the signature in constant time. The lookup runs at most
// once, and only for a request that passed every check that needs no secret. Throws S3Error (sigv4Error) on failure.
[[nodiscard]] GatewaySecret verifySignedRequest(const vl::sigv4::VerificationInput& input,
                                                const GatewaySecretLookup& lookup, vl::sigv4::TimePoint now);

class Authenticator {
public:
    explicit Authenticator(bool requireSigV4 = true);

    AuthContext authenticate(const vl::sigv4::VerificationInput& input) const;

private:
    bool requireSigV4_{true};
    mutable std::mutex credentialsMutex_;
    mutable std::unique_ptr<CredentialManager> credentials_;

    [[nodiscard]] CredentialManager& credentials() const;
};

}
