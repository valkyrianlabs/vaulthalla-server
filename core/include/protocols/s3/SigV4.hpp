#pragma once

#include <boost/beast/http.hpp>
#include <map>
#include <optional>
#include <string>
#include <vector>

// The S3 gateway's SigV4 verifier (header-signed and presigned requests).
//
// RETIRED from production: the gateway (Authenticator::authenticate, protocols/s3/Auth.hpp) verifies with vl::sigv4
// (the vl-sigv4 library, subprojects/vl-sigv4.wrap), which reproduces this verifier's canonical requests and
// signatures for every S3 golden record (core/tests/unit/test_sigv4_goldens.cpp). This copy stays only as the
// reference the goldens compare against, until a release with vl-sigv4 is verified on the VPS; then it is
// deleted (shared-infrastructure extraction, Phase 1 step 5). Don't add callers.

namespace vh::protocols::s3::sigv4 {

namespace http = boost::beast::http;

struct CredentialScope {
    std::string access_key;
    std::string date;
    std::string region;
    std::string service;
};

struct VerificationInput {
    std::string method;
    std::string target;
    std::string host;
    std::map<std::string, std::string> headers;
    std::string body;
    std::optional<std::string> body_sha256;
};

struct ParsedAuth {
    CredentialScope credential;
    std::string signed_headers;
    std::string signature;
    std::string amz_date;
    std::string payload_hash;
    bool presigned{};
    uint64_t expires_seconds{};
};

struct VerificationResult {
    bool ok{};
    std::string access_key;
    std::string error;
};

std::string sha256Hex(std::string_view data);
std::string hmacSha256Raw(std::string_view key, std::string_view data);
std::string hmacSha256HexFromRaw(std::string_view rawKey, std::string_view data);
std::string canonicalUri(std::string_view path);
std::string canonicalQueryString(std::string_view rawQuery, bool omitSignature = true);
std::string canonicalHeaders(const std::map<std::string, std::string>& headers,
                             const std::string& signedHeaders);
std::string makeCanonicalRequest(const VerificationInput& input, const ParsedAuth& auth);
std::string signingKey(const std::string& secret, const CredentialScope& scope);
std::string signatureFor(const VerificationInput& input, const ParsedAuth& auth, const std::string& secret);
std::optional<ParsedAuth> parseAuthorization(const VerificationInput& input, std::string& error);
VerificationResult verify(const VerificationInput& input, const std::string& secret);

template <class Body, class Fields>
VerificationInput inputFromRequest(const http::request<Body, Fields>& req, const std::string& body) {
    VerificationInput out;
    out.method = std::string(req.method_string());
    out.target = std::string(req.target());
    if (req.find(http::field::host) != req.end()) out.host = std::string(req.at(http::field::host));
    for (const auto& field : req)
        out.headers.emplace(std::string(field.name_string()), std::string(field.value()));
    out.body = body;
    return out;
}

}
