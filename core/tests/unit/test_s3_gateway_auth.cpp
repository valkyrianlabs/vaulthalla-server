// S3 gateway SigV4 authentication through vl-sigv4 (protocols/s3/Auth.hpp: verificationInput, verifySignedRequest,
// sigv4Error), DB-free.
//
//   S3GatewayAuth.*            every rejection class with the S3 error code and HTTP status it answers with, and
//                              whether the credential lookup ran (only after every secret-free check passed)
//   S3GatewayAuthCompat.*      the requests the retired in-tree verifier (protocols/s3/SigV4) and vl-sigv4 judge
//                              differently, one by one: what vl-sigv4 now refuses (all refused by AWS too) and the
//                              spec-valid requests it now accepts
//   S3GatewayClientCaptures.*  requests recorded from real clients (aws-cli 2, boto3, rclone, mc) by a capture server,
//                              verified at the time they were signed (core/test-assets/sigv4/client-requests.jsonl)

#include "protocols/s3/Auth.hpp"
#include "protocols/s3/Router.hpp"
#include "protocols/s3/SigV4.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <vl/sigv4/canonical.hpp>
#include <vl/sigv4/crypto.hpp>
#include <vl/sigv4/signer.hpp>
#include <vl/sigv4/verifier.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace s3gatewayauth {

namespace s3 = vh::protocols::s3;
namespace gw = vh::protocols::s3::sigv4;   // the retired in-tree verifier, kept as the reference
namespace vs = vl::sigv4;
namespace http = boost::beast::http;
using Request = s3::Router::Request;
using Headers = std::vector<std::pair<std::string, std::string>>;

constexpr const char* kAccessKey = "VHTESTACCESSKEY0000000001";
constexpr const char* kSecret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr const char* kHost = "s3.vaulthalla.example.test";

inline Request makeRequest(const std::string& method, const std::string& target, const Headers& headers,
                           std::string body = {}) {
    Request req;
    req.method_string(method);
    req.target(target);
    req.version(11);
    for (const auto& [name, value] : headers) req.insert(name, value);
    req.body() = std::move(body);
    return req;
}

// What a client sends: vl::sigv4::sign's headers (host, x-amz-date, x-amz-content-sha256, authorization) on the wire.
inline Request signedRequest(const std::string& method, const std::string& path, const vs::QueryParams& query,
                             const vs::TimePoint at, std::string body = {}, const Headers& extra = {},
                             const std::string& payloadHash = {}, const std::string& secret = kSecret,
                             const std::string& scopeRegion = "us-east-1") {
    const vs::Request request{.method = method, .host = kHost, .path = path, .query = query,
                              .headers = vs::HeaderList(extra.begin(), extra.end()),
                              .payload_hash = payloadHash.empty() ? vs::sha256Hex(body) : payloadHash};
    const auto s = vs::sign(request, {.access_key = kAccessKey, .secret_key = secret, .session_token = {}},
                            scopeRegion, "s3", at);
    Headers headers(s.headers.begin(), s.headers.end());
    return makeRequest(method, s.target(), headers, std::move(body));
}

inline Request presignedRequest(const std::string& method, const std::string& path, const vs::TimePoint at,
                                const std::chrono::seconds expires) {
    const vs::Request request{.method = method, .host = kHost, .path = path, .query = {}, .headers = {},
                              .payload_hash = {}};
    const auto p = vs::presign(request, {.access_key = kAccessKey, .secret_key = kSecret, .session_token = {}},
                               "us-east-1", "s3", at, expires);
    EXPECT_TRUE(p.has_value());
    return makeRequest(method, p ? p->target() : std::string{"/"}, {{"Host", kHost}});
}

struct Lookup {
    int calls = 0;
    bool known = true;

    s3::GatewaySecretLookup fn() {
        return [this](const std::string& accessKey) -> std::optional<s3::GatewaySecret> {
            ++calls;
            if (!known || accessKey != kAccessKey) return std::nullopt;
            s3::GatewaySecret secret;
            secret.credential.id = 7;
            secret.credential.access_key = accessKey;
            secret.secret_access_key = kSecret;
            return secret;
        };
    }
};

struct Outcome {
    bool ok = false;
    std::string code;
    http::status status = http::status::ok;
    std::string message;
    int lookups = 0;
};

inline Outcome verifyAt(const vs::VerificationInput& input, const vs::TimePoint now, const bool knownKey = true) {
    Lookup lookup;
    lookup.known = knownKey;
    Outcome out;
    try {
        const auto secret = s3::verifySignedRequest(input, lookup.fn(), now);
        out.ok = secret.credential.access_key == kAccessKey && secret.secret_access_key == kSecret;
    } catch (const s3::S3Error& e) {
        out.code = e.code;
        out.status = e.status;
        out.message = e.what();
    }
    out.lookups = lookup.calls;
    return out;
}

inline Outcome verifyNew(const Request& req, const vs::TimePoint now, const bool knownKey = true) {
    return verifyAt(s3::verificationInput(req, req.body()), now, knownKey);
}

// The retired verifier as Router + Authenticator drove it: gw::inputFromRequest, the session-token refusal of
// Auth.cpp, then gw::verify (which reads the clock itself).
inline bool verifyOld(const Request& req, const std::string& secret = kSecret) {
    const auto input = gw::inputFromRequest(req, req.body());
    std::string error;
    if (!gw::parseAuthorization(input, error)) return false;
    if (input.target.find("X-Amz-Security-Token=") != std::string::npos) return false;
    for (const auto& [name, value] : input.headers) {
        std::string lowered = name;
        std::ranges::transform(lowered, lowered.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lowered == "x-amz-security-token" && !value.empty()) return false;
    }
    return gw::verify(input, secret).ok;
}

inline std::string authorization(const std::string& credential, const std::string& signedHeaders,
                                 const std::string& signature) {
    return "AWS4-HMAC-SHA256 Credential=" + credential + ", SignedHeaders=" + signedHeaders + ", Signature=" + signature;
}

inline std::string scopeFor(const std::string& amzDate, const std::string& region = "us-east-1",
                            const std::string& service = "s3") {
    return std::string(kAccessKey) + "/" + amzDate.substr(0, 8) + "/" + region + "/" + service + "/aws4_request";
}

// A header-signed request signed by the retired verifier's own canonicalization (gw::signatureFor), for shapes
// vl::sigv4::sign never produces (host unsigned, odd scopes, ...).
inline Request oldSigned(const std::string& method, const std::string& target, Headers headers,
                         const std::string& credential, const std::string& signedHeaders,
                         const std::string& amzDate, std::string body = {}) {
    auto req = makeRequest(method, target, headers, body);
    const auto input = gw::inputFromRequest(req, req.body());
    const auto scopeParts = [&] {
        std::vector<std::string> parts;
        std::size_t start = 0;
        while (true) {
            const auto end = credential.find('/', start);
            parts.push_back(credential.substr(start, end == std::string::npos ? std::string::npos : end - start));
            if (end == std::string::npos) break;
            start = end + 1;
        }
        return parts;
    }();
    gw::ParsedAuth auth{
        .credential = {.access_key = scopeParts.at(0), .date = scopeParts.at(1), .region = scopeParts.at(2),
                       .service = scopeParts.at(3)},
        .signed_headers = signedHeaders,
        .signature = {},
        .amz_date = amzDate,
        .payload_hash = vs::sha256Hex(body),
        .presigned = false,
        .expires_seconds = 0,
    };
    for (const auto& [name, value] : headers)
        if (vs::toLower(name) == "x-amz-content-sha256") auth.payload_hash = value;
    req.set(http::field::authorization, authorization(credential, signedHeaders, gw::signatureFor(input, auth, kSecret)));
    return req;
}

inline vs::TimePoint now() { return vs::Clock::now(); }

}

// ---- error mapping ------------------------------------------------------------------------------------------------

// Every vl-sigv4 failure has one S3 error code (vl::sigv4::awsErrorCode) and AWS's HTTP status for it.
TEST(S3GatewayAuth, EveryVerifierFailureMapsToAnS3ErrorAndStatus) {
    using vl::sigv4::ErrorCode;
    namespace http = boost::beast::http;
    struct Row {
        ErrorCode code;
        const char* header;   // header-signed
        const char* query;    // presigned
        http::status status;
    };
    const std::vector<Row> rows{
        {ErrorCode::MissingAuthorization, "AccessDenied", "AccessDenied", http::status::forbidden},
        {ErrorCode::AmbiguousAuthorization, "InvalidArgument", "InvalidArgument", http::status::bad_request},
        {ErrorCode::UnsupportedAlgorithm, "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::MalformedAuthorization, "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::InvalidCredentialScope, "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::UnsupportedService, "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::RegionMismatch, "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::InvalidExpires, "AuthorizationQueryParametersError", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::ExpiresTooLarge, "AuthorizationQueryParametersError", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::MissingDate, "AccessDenied", "AccessDenied", http::status::forbidden},
        {ErrorCode::InvalidDate, "AccessDenied", "AccessDenied", http::status::forbidden},
        {ErrorCode::ScopeDateMismatch, "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::RequestTimeTooSkewed, "RequestTimeTooSkewed", "RequestTimeTooSkewed", http::status::forbidden},
        {ErrorCode::PresignExpired, "AccessDenied", "AccessDenied", http::status::forbidden},
        {ErrorCode::MissingSignedHeaders, "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::HostNotSigned, "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::MissingSignature, "AuthorizationHeaderMalformed", "AuthorizationQueryParametersError", http::status::bad_request},
        {ErrorCode::SignedHeaderMissing, "SignatureDoesNotMatch", "SignatureDoesNotMatch", http::status::forbidden},
        {ErrorCode::SessionTokenNotSupported, "InvalidToken", "InvalidToken", http::status::bad_request},
        {ErrorCode::UnsupportedPayloadHash, "NotImplemented", "NotImplemented", http::status::not_implemented},
        {ErrorCode::PayloadHashMismatch, "XAmzContentSHA256Mismatch", "XAmzContentSHA256Mismatch", http::status::bad_request},
        {ErrorCode::UnknownAccessKey, "InvalidAccessKeyId", "InvalidAccessKeyId", http::status::forbidden},
        {ErrorCode::SignatureMismatch, "SignatureDoesNotMatch", "SignatureDoesNotMatch", http::status::forbidden},
    };
    std::set<int> covered;
    for (const auto& row : rows) {
        const auto name = std::string(vl::sigv4::errorCodeName(row.code));
        const auto header = vh::protocols::s3::sigv4Error(row.code, false, "m", "/r");
        EXPECT_EQ(header.code, row.header) << name;
        EXPECT_EQ(header.status, row.status) << name;
        EXPECT_EQ(header.resource, "/r") << name;
        EXPECT_STREQ(header.what(), "m") << name;
        const auto query = vh::protocols::s3::sigv4Error(row.code, true, "m", "/r");
        EXPECT_EQ(query.code, row.query) << name;
        EXPECT_EQ(query.status, row.status) << name;
        covered.insert(static_cast<int>(row.code));
    }
    // Every ErrorCode but None has a row: a new code in vl-sigv4 needs a decision here.
    EXPECT_EQ(covered.size(), static_cast<std::size_t>(vl::sigv4::ErrorCode::SignatureMismatch));
    for (int c = 1; c <= static_cast<int>(vl::sigv4::ErrorCode::SignatureMismatch); ++c) EXPECT_TRUE(covered.contains(c)) << c;
}

TEST(S3GatewayAuth, GatewayOptionsAreS3AnyRegionNoSessionTokens) {
    const auto options = vh::protocols::s3::gatewayVerifyOptions();
    EXPECT_EQ(options.service, "s3");
    EXPECT_FALSE(options.region.has_value());
    EXPECT_EQ(options.max_skew, std::chrono::minutes(15));
    EXPECT_EQ(options.max_presign_expiry, std::chrono::seconds(604800));
    EXPECT_TRUE(options.allow_presigned);
    EXPECT_TRUE(options.reject_session_tokens);
    EXPECT_TRUE(options.require_scope_date_match);
    EXPECT_TRUE(options.require_signed_host);
    EXPECT_TRUE(options.imply_zero_content_length);
}

// ---- accepted requests --------------------------------------------------------------------------------------------

TEST(S3GatewayAuth, AcceptsHeaderSignedAndPresignedRequestsAfterOneLookup) {
    using namespace s3gatewayauth;
    const auto t = now();
    for (const auto& req : {
             signedRequest("GET", "/vh-bucket/dir one/a b+c=d~e%f.txt", {}, t),
             signedRequest("PUT", "/vh-bucket/notes/hello.txt", {{"partNumber", "1"}, {"uploadId", "u+/="}}, t,
                           "hello vaulthalla\n"),
             signedRequest("PUT", "/vh-bucket/big.bin", {}, t, "anything", {}, "UNSIGNED-PAYLOAD"),
             signedRequest("GET", "/vh-bucket/a.txt", {{"versionId", "3/L4kq+tJ="}}, t, {}, {}, {}, kSecret, "auto"),
             presignedRequest("GET", "/vh-bucket/dir one/a b.txt", t, std::chrono::seconds(600)),
             presignedRequest("PUT", "/vh-bucket/upload.bin", t, std::chrono::seconds(604800)),
         }) {
        const auto out = verifyNew(req, t);
        EXPECT_TRUE(out.ok) << req.target() << ": " << out.code << " " << out.message;
        EXPECT_EQ(out.lookups, 1) << req.target();
        EXPECT_TRUE(verifyOld(req)) << req.target();
    }
}

// Session::handleStreamedRequest hashes the stored (aws-chunked decoded) body and leaves request.body() empty.
TEST(S3GatewayAuth, StreamedBodiesAreCheckedThroughTheirHash) {
    using namespace s3gatewayauth;
    const auto t = now();
    auto req = signedRequest("PUT", "/vh-bucket/a.bin", {}, t, "streamed payload");
    const auto body = req.body();
    req.body().clear();
    EXPECT_TRUE(verifyAt(s3::verificationInput(req, {}, vs::sha256Hex(body)), t).ok);
    const auto tampered = verifyAt(s3::verificationInput(req, {}, vs::sha256Hex("other")), t);
    EXPECT_EQ(tampered.code, "XAmzContentSHA256Mismatch");
    EXPECT_EQ(tampered.lookups, 0);

    // STREAMING-UNSIGNED-PAYLOAD-TRAILER (aws-cli 2, boto3 >= 1.36 over HTTPS) skips the body check, as before.
    auto trailer = signedRequest("PUT", "/vh-bucket/a.bin", {}, t, {},
                                 {{"Content-Encoding", "aws-chunked"}, {"x-amz-decoded-content-length", "7"},
                                  {"x-amz-trailer", "x-amz-checksum-crc32"}},
                                 "STREAMING-UNSIGNED-PAYLOAD-TRAILER");
    EXPECT_TRUE(verifyAt(s3::verificationInput(trailer, {}, vs::sha256Hex("decoded")), t).ok);
    EXPECT_TRUE(verifyOld(trailer));

    // Signed chunks (STREAMING-AWS4-HMAC-SHA256-PAYLOAD: mc and the Java SDK over plain HTTP) were refused before as a
    // payload hash mismatch, and still are: neither verifier checks chunk signatures. Now it says so.
    for (const std::string mode : {"STREAMING-AWS4-HMAC-SHA256-PAYLOAD", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD-TRAILER",
                                   "STREAMING-AWS4-ECDSA-P256-SHA256-PAYLOAD"}) {
        auto chunked = signedRequest("PUT", "/vh-bucket/a.bin", {}, t, {},
                                     {{"Content-Encoding", "aws-chunked"}, {"x-amz-decoded-content-length", "7"}}, mode);
        const auto out = verifyAt(s3::verificationInput(chunked, {}, vs::sha256Hex("decoded")), t);
        EXPECT_EQ(out.code, "NotImplemented") << mode;
        EXPECT_EQ(out.status, http::status::not_implemented) << mode;
        EXPECT_EQ(out.lookups, 0) << mode;
        EXPECT_FALSE(verifyOld(chunked)) << mode;
    }
}

// Cloudflare drops "Content-Length: 0" from bodiless requests the AWS CLI CRT client signed it on.
TEST(S3GatewayAuth, ImpliesZeroContentLengthOnlyForAnEmptyUnframedBody) {
    using namespace s3gatewayauth;
    const auto t = now();
    for (const std::string method : {"GET", "HEAD", "DELETE", "POST"}) {
        auto req = signedRequest(method, "/vh-bucket/a.txt", {}, t, {}, {{"Content-Length", "0"}});
        EXPECT_TRUE(verifyNew(req, t).ok) << method;
        req.erase(http::field::content_length);
        EXPECT_TRUE(verifyNew(req, t).ok) << method << " without Content-Length";
        EXPECT_TRUE(verifyOld(req)) << method;
    }
    auto req = signedRequest("PUT", "/vh-bucket/a.txt", {}, t, {}, {{"Content-Length", "0"}}, "UNSIGNED-PAYLOAD");
    req.erase(http::field::content_length);
    req.set(http::field::transfer_encoding, "chunked");
    EXPECT_EQ(verifyNew(req, t).code, "SignatureDoesNotMatch");   // signed header missing: content-length
    req.erase(http::field::transfer_encoding);
    EXPECT_EQ(verifyAt(s3::verificationInput(req, {}, vs::sha256Hex("streamed")), t).code, "SignatureDoesNotMatch");
}

// ---- rejection classes --------------------------------------------------------------------------------------------

// Each class of refusal: the S3 error the gateway answers with and whether the credential lookup (a DB query and the
// secret's decryption) ran. It runs only for requests that passed every check needing no secret.
TEST(S3GatewayAuth, RejectionClassesAnswerTheirS3ErrorAndLookUpTheKeyLast) {
    using namespace s3gatewayauth;
    const auto t = now();
    const auto amzDate = vs::amzDate(t);
    const auto base = [&] { return signedRequest("GET", "/vh-bucket/a.txt", {}, t); };
    const auto withAuth = [&](const std::string& value) {
        auto req = base();
        req.set(http::field::authorization, value);
        return req;
    };
    const auto signatureOf = [](const Request& req) {
        const auto a = std::string(req[http::field::authorization]);
        return a.substr(a.find("Signature=") + 10);
    };
    const std::string sig = signatureOf(base());
    const auto presignedWith = [&](const std::string& replace, const std::string& with) {
        auto req = presignedRequest("GET", "/vh-bucket/a.txt", t, std::chrono::seconds(600));
        auto target = std::string(req.target());
        const auto at = target.find(replace);
        EXPECT_NE(at, std::string::npos) << replace;
        if (at != std::string::npos) target.replace(at, replace.size(), with);
        req.target(target);
        return req;
    };

    struct Row {
        std::string name;
        Request req;
        std::string code;
        http::status status;
        int lookups = 0;
        bool knownKey = true;
    };
    std::vector<Row> rows;
    const auto add = [&](std::string name, Request req, std::string code, const http::status status, const int lookups = 0,
                         const bool knownKey = true) {
        rows.push_back({std::move(name), std::move(req), std::move(code), status, lookups, knownKey});
    };
    using http::status;

    {
        auto req = base();
        req.erase(http::field::authorization);
        add("missing authorization", std::move(req), "AccessDenied", status::forbidden);
    }
    {
        auto req = presignedRequest("GET", "/vh-bucket/a.txt", t, std::chrono::seconds(600));
        req.set(http::field::authorization, std::string(base()[http::field::authorization]));
        add("header and presigned query", std::move(req), "InvalidArgument", status::bad_request);
    }
    add("unsupported algorithm", withAuth("AWS4-HMAC-SHA512 Credential=" + scopeFor(amzDate) +
                                          ", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" + sig),
        "AuthorizationHeaderMalformed", status::bad_request);
    add("presigned unsupported algorithm", presignedWith("X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Algorithm=AWS4-HMAC-SHA1"),
        "AuthorizationQueryParametersError", status::bad_request);
    add("no Signature parameter", withAuth("AWS4-HMAC-SHA256 Credential=" + scopeFor(amzDate) +
                                           ", SignedHeaders=host;x-amz-content-sha256;x-amz-date"),
        "AuthorizationHeaderMalformed", status::bad_request);
    add("credential scope of four parts", withAuth(authorization(std::string(kAccessKey) + "/" + amzDate.substr(0, 8) + "/us-east-1/s3",
                                                                 "host;x-amz-content-sha256;x-amz-date", sig)),
        "AuthorizationHeaderMalformed", status::bad_request);
    add("service other than s3", withAuth(authorization(scopeFor(amzDate, "us-east-1", "sqs"),
                                                        "host;x-amz-content-sha256;x-amz-date", sig)),
        "AuthorizationHeaderMalformed", status::bad_request);
    add("X-Amz-Expires=0", presignedWith("X-Amz-Expires=600", "X-Amz-Expires=0"), "AuthorizationQueryParametersError",
        status::bad_request);
    add("X-Amz-Expires not a number", presignedWith("X-Amz-Expires=600", "X-Amz-Expires=ten"),
        "AuthorizationQueryParametersError", status::bad_request);
    add("X-Amz-Expires over seven days", presignedWith("X-Amz-Expires=600", "X-Amz-Expires=604801"),
        "AuthorizationQueryParametersError", status::bad_request);
    {
        auto req = base();
        req.erase("x-amz-date");
        add("missing x-amz-date", std::move(req), "AccessDenied", status::forbidden);
    }
    {
        auto req = base();
        req.set("x-amz-date", amzDate.substr(0, 15));
        add("x-amz-date not ISO 8601 basic", std::move(req), "AccessDenied", status::forbidden);
    }
    {
        // Scope dated the day before x-amz-date.
        const auto yesterday = vs::amzDate(t - std::chrono::hours(24));
        add("credential scope date differs from x-amz-date",
            withAuth(authorization(scopeFor(yesterday), "host;x-amz-content-sha256;x-amz-date", sig)),
            "AuthorizationHeaderMalformed", status::bad_request);
    }
    add("signed 20 minutes ago", signedRequest("GET", "/vh-bucket/a.txt", {}, t - std::chrono::minutes(20)),
        "RequestTimeTooSkewed", status::forbidden);
    add("signed 20 minutes ahead", signedRequest("GET", "/vh-bucket/a.txt", {}, t + std::chrono::minutes(20)),
        "RequestTimeTooSkewed", status::forbidden);
    add("presigned 20 minutes ahead", presignedRequest("GET", "/vh-bucket/a.txt", t + std::chrono::minutes(20), std::chrono::seconds(3600)),
        "RequestTimeTooSkewed", status::forbidden);
    add("presigned URL expired", presignedRequest("GET", "/vh-bucket/a.txt", t - std::chrono::hours(1), std::chrono::seconds(60)),
        "AccessDenied", status::forbidden);
    add("empty SignedHeaders", withAuth(authorization(scopeFor(amzDate), "", sig)), "AuthorizationHeaderMalformed",
        status::bad_request);
    add("host not signed", withAuth(authorization(scopeFor(amzDate), "x-amz-content-sha256;x-amz-date", sig)),
        "AuthorizationHeaderMalformed", status::bad_request);
    add("empty Signature", withAuth(authorization(scopeFor(amzDate), "host;x-amz-content-sha256;x-amz-date", "")),
        "AuthorizationHeaderMalformed", status::bad_request);
    add("signed header absent from the request",
        withAuth(authorization(scopeFor(amzDate), "host;x-amz-content-sha256;x-amz-date;x-amz-meta-gone", sig)),
        "SignatureDoesNotMatch", status::forbidden);
    {
        auto req = base();
        req.set("x-amz-security-token", "token");
        add("x-amz-security-token header", std::move(req), "InvalidToken", status::bad_request);
    }
    {
        auto req = signedRequest("GET", "/vh-bucket/a.txt", {{"X-Amz-Security-Token", "token"}}, t);
        add("X-Amz-Security-Token in a header-signed request's query", std::move(req), "InvalidToken", status::bad_request);
    }
    add("X-Amz-Security-Token in a presigned URL",
        presignedWith("X-Amz-Algorithm=AWS4-HMAC-SHA256", "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Security-Token=token"),
        "InvalidToken", status::bad_request);
    add("signed streaming payload",
        signedRequest("PUT", "/vh-bucket/a.bin", {}, t, {}, {}, "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"), "NotImplemented",
        status::not_implemented);
    {
        auto req = signedRequest("PUT", "/vh-bucket/a.bin", {}, t, "signed body");
        req.body() = "other body";
        add("body differs from x-amz-content-sha256", std::move(req), "XAmzContentSHA256Mismatch", status::bad_request);
    }
    add("unknown or disabled access key", base(), "InvalidAccessKeyId", status::forbidden, 1, false);
    add("wrong secret", signedRequest("GET", "/vh-bucket/a.txt", {}, t, {}, {}, {}, "not-the-secret"),
        "SignatureDoesNotMatch", status::forbidden, 1);
    {
        auto req = base();
        req.target("/vh-bucket/b.txt");
        add("request changed after signing", std::move(req), "SignatureDoesNotMatch", status::forbidden, 1);
    }

    for (const auto& row : rows) {
        const auto out = verifyNew(row.req, t, row.knownKey);
        EXPECT_FALSE(out.ok) << row.name;
        EXPECT_EQ(out.code, row.code) << row.name << ": " << out.message;
        EXPECT_EQ(out.status, row.status) << row.name;
        EXPECT_EQ(out.lookups, row.lookups) << row.name;
        EXPECT_FALSE(out.message.empty()) << row.name;
        EXPECT_EQ(out.message.find(kSecret), std::string::npos) << row.name;
    }
    EXPECT_EQ(rows.size(), 29u);
}

// A refusal never echoes the secret or the signature the gateway expected; only what the client sent.
TEST(S3GatewayAuth, SignatureMismatchRevealsNeitherSecretNorExpectedSignature) {
    using namespace s3gatewayauth;
    const auto t = now();
    auto req = signedRequest("GET", "/vh-bucket/a.txt", {}, t, {}, {}, {}, "not-the-secret");
    const auto input = s3::verificationInput(req, req.body());
    const auto parsed = vs::parseAuthorization(input, s3::gatewayVerifyOptions());
    ASSERT_TRUE(parsed);
    const auto expected = vs::signatureFor(input, *parsed, kSecret, s3::gatewayVerifyOptions());
    const auto out = verifyAt(input, t);
    EXPECT_EQ(out.code, "SignatureDoesNotMatch");
    EXPECT_EQ(out.message, "Signature mismatch");
    EXPECT_EQ(out.message.find(expected), std::string::npos);
    EXPECT_EQ(out.message.find(kSecret), std::string::npos);
}

// The Authenticator the Router uses: unsigned requests in production get the S3 AccessDenied of an anonymous request.
TEST(S3GatewayAuth, AuthenticatorRefusesAnonymousRequestsBeforeAnyLookup) {
    using namespace s3gatewayauth;
    const vh::protocols::s3::Authenticator authenticator(true);
    const auto req = makeRequest("GET", "/", {{"Host", kHost}});
    try {
        (void)authenticator.authenticate(s3::verificationInput(req, req.body()));
        ADD_FAILURE() << "unsigned request authenticated";
    } catch (const s3::S3Error& e) {
        EXPECT_EQ(e.code, "AccessDenied");
        EXPECT_EQ(e.status, http::status::forbidden);
        EXPECT_STREQ(e.what(), "Missing Authorization header");
    }
}

// ---- where the retired verifier and vl-sigv4 disagree ---------------------------------------------------------

// Requests the retired verifier accepted and vl-sigv4 refuses. Each breaks a rule of SigV4 that AWS S3 enforces, so
// no client that works against AWS sends one; the real-client captures below contain none of them.
TEST(S3GatewayAuthCompat, NowRefusedAsAwsRefusesThem) {
    using namespace s3gatewayauth;
    const auto t = now();
    const auto amzDate = vs::amzDate(t);
    const std::string hash = vs::sha256Hex("");
    const Headers headers{{"Host", kHost}, {"x-amz-content-sha256", hash}, {"x-amz-date", amzDate}};

    struct Row {
        std::string name;
        Request req;
        std::string code;
    };
    std::vector<Row> rows;
    // 1. host not among the signed headers (AWS: "host" must be signed).
    rows.push_back({"host unsigned", oldSigned("GET", "/vh-bucket/a.txt", headers, scopeFor(amzDate),
                                               "x-amz-content-sha256;x-amz-date", amzDate),
                    "AuthorizationHeaderMalformed"});
    // 2. credential scope date other than x-amz-date's date (AWS: "Invalid credential date").
    rows.push_back({"scope date differs", oldSigned("GET", "/vh-bucket/a.txt", headers,
                                                    scopeFor(vs::amzDate(t - std::chrono::hours(48))),
                                                    "host;x-amz-content-sha256;x-amz-date", amzDate),
                    "AuthorizationHeaderMalformed"});
    // 3. empty region in the scope.
    rows.push_back({"empty region", oldSigned("GET", "/vh-bucket/a.txt", headers,
                                              std::string(kAccessKey) + "/" + amzDate.substr(0, 8) + "//s3/aws4_request",
                                              "host;x-amz-content-sha256;x-amz-date", amzDate),
                    "AuthorizationHeaderMalformed"});
    // 4. x-amz-date with trailing characters (the old parser read the first 16).
    {
        const auto junk = amzDate + "junk";
        rows.push_back({"x-amz-date with trailing junk",
                        oldSigned("GET", "/vh-bucket/a.txt", {{"Host", kHost}, {"x-amz-content-sha256", hash}, {"x-amz-date", junk}},
                                  scopeFor(amzDate), "host;x-amz-content-sha256;x-amz-date", junk),
                        "AccessDenied"});
    }
    // 5. empty name in SignedHeaders.
    rows.push_back({"empty signed header name", oldSigned("GET", "/vh-bucket/a.txt", headers, scopeFor(amzDate),
                                                          "host;;x-amz-content-sha256;x-amz-date", amzDate),
                    "AuthorizationHeaderMalformed"});
    // 6. an Authorization part without '=' (ignored before).
    {
        auto req = oldSigned("GET", "/vh-bucket/a.txt", headers, scopeFor(amzDate), "host;x-amz-content-sha256;x-amz-date", amzDate);
        req.set(http::field::authorization, std::string(req[http::field::authorization]) + ", Junk");
        rows.push_back({"authorization part without '='", std::move(req), "AuthorizationHeaderMalformed"});
    }
    // 7. a presigned URL with X-Amz-Expires=0 (the old verifier read it as "never expires").
    {
        const auto req = presignedRequest("GET", "/vh-bucket/a.txt", t, std::chrono::seconds(600));
        auto target = std::string(req.target());
        target.replace(target.find("X-Amz-Expires=600"), 17, "X-Amz-Expires=0");
        // Re-sign with the old canonicalization so the old verifier's signature check passes.
        auto zero = makeRequest("GET", target, {{"Host", kHost}});
        const auto input = gw::inputFromRequest(zero, zero.body());
        std::string error;
        auto parsed = gw::parseAuthorization(input, error);
        ASSERT_TRUE(parsed) << error;
        const auto sig = gw::signatureFor(input, *parsed, kSecret);
        const auto at = target.find("X-Amz-Signature=");
        const auto end = target.find('&', at);
        target = target.substr(0, at) + "X-Amz-Signature=" + sig + (end == std::string::npos ? "" : target.substr(end));
        zero.target(target);
        rows.push_back({"X-Amz-Expires=0", std::move(zero), "AuthorizationQueryParametersError"});
    }
    // 8. an Authorization header on a presigned URL (the old verifier ignored the header).
    {
        auto req = presignedRequest("GET", "/vh-bucket/a.txt", t, std::chrono::seconds(600));
        req.set(http::field::authorization, "Bearer web-session");
        rows.push_back({"authorization header on a presigned URL", std::move(req), "InvalidArgument"});
    }

    for (const auto& row : rows) {
        EXPECT_TRUE(verifyOld(row.req)) << row.name << ": the retired verifier accepted this";
        const auto out = verifyNew(row.req, t);
        EXPECT_FALSE(out.ok) << row.name;
        EXPECT_EQ(out.code, row.code) << row.name << ": " << out.message;
        EXPECT_EQ(out.lookups, 0) << row.name;
    }
}

// Spec-valid requests the retired verifier refused and vl-sigv4 accepts. Each is signed exactly as SigV4 says.
TEST(S3GatewayAuthCompat, SpecValidRequestsTheOldVerifierRefused) {
    using namespace s3gatewayauth;
    const auto t = now();
    // 1. A repeated signed header: SigV4 signs the values joined with ','; the old verifier kept the first.
    {
        const vs::Request request{.method = "PUT", .host = kHost, .path = "/vh-bucket/a.txt", .query = {},
                                  .headers = {{"x-amz-meta-tag", "one"}, {"x-amz-meta-tag", "two"}},
                                  .payload_hash = "UNSIGNED-PAYLOAD"};
        const auto s = vs::sign(request, {.access_key = kAccessKey, .secret_key = kSecret, .session_token = {}},
                                "us-east-1", "s3", t);
        Headers headers;
        for (const auto& [name, value] : s.headers)
            if (name != "x-amz-meta-tag") headers.emplace_back(name, value);
        headers.emplace_back("x-amz-meta-tag", "one");
        headers.emplace_back("x-amz-meta-tag", "two");
        const auto req = makeRequest("PUT", s.target(), headers, "body");
        EXPECT_FALSE(verifyOld(req));
        EXPECT_TRUE(verifyNew(req, t).ok);
    }
    // 2. A header-signed request whose query has an X-Amz-Signature parameter: it is part of the canonical query
    //    (only a presigned URL's own signature is left out); the old verifier always left it out.
    {
        const auto req = signedRequest("GET", "/vh-bucket/a.txt", {{"X-Amz-Signature", "not-mine"}}, t);
        EXPECT_FALSE(verifyOld(req));
        EXPECT_TRUE(verifyNew(req, t).ok);
    }
    // 3. x-amz-content-sha256 in upper-case hex, signed as sent: the body still has to match it.
    {
        const std::string body = "hello";
        auto hash = vs::sha256Hex(body);
        std::ranges::transform(hash, hash.begin(), [](const unsigned char c) { return static_cast<char>(std::toupper(c)); });
        const auto req = signedRequest("PUT", "/vh-bucket/a.txt", {}, t, body, {}, hash);
        EXPECT_FALSE(verifyOld(req));
        EXPECT_TRUE(verifyNew(req, t).ok);
        auto tampered = req;
        tampered.body() = "other";
        EXPECT_EQ(verifyNew(tampered, t).code, "XAmzContentSHA256Mismatch");
    }
}

// ---- real clients ---------------------------------------------------------------------------------------------------

// Requests recorded from aws-cli 2.38 (macOS), rclone 1.69, boto3/botocore 1.34 and mc (2025-08) by a capture server
// (tools/dev/sigv4-capture/), over HTTP and HTTPS, with the test credential below: list buckets, PUT (payload hash,
// UNSIGNED-PAYLOAD, STREAMING-UNSIGNED-PAYLOAD-TRAILER), GET, ranges, HEAD, LIST v2, copy, deletes, multipart, UTF-8
// and special-character keys, versionId, and presigned GET/PUT URLs fetched with curl or urllib. Each is verified at
// the time it was signed, through the production adapter (a Beast request as Session builds it), streamed and buffered.
// The one refusal is mc's upload over plain HTTP: signed chunks, refused by both verifiers.
TEST(S3GatewayClientCaptures, RealClientRequestsVerifyAtTheGateway) {
    using namespace s3gatewayauth;
    constexpr const char* kCaptureAccessKey = "VHCAPTUREFIXTUREKEY00000A";
    constexpr const char* kCaptureSecret = "VHcaptureSecretKey0123456789abcdefghijkl";
    const auto fixture = std::filesystem::path(VH_TEST_ASSETS_DIR) / "sigv4" / "client-requests.jsonl";
    std::ifstream in(fixture);
    ASSERT_TRUE(in) << fixture;

    const s3::GatewaySecretLookup lookup = [&](const std::string& key) -> std::optional<s3::GatewaySecret> {
        if (key != kCaptureAccessKey) return std::nullopt;
        s3::GatewaySecret secret;
        secret.credential.access_key = key;
        secret.secret_access_key = kCaptureSecret;
        return secret;
    };
    const auto outcome = [&](const vs::VerificationInput& input, const vs::TimePoint at) -> std::string {
        try {
            (void)s3::verifySignedRequest(input, lookup, at);
            return "ok";
        } catch (const s3::S3Error& e) {
            return e.code + ": " + e.what();
        }
    };

    std::size_t records = 0, presigned = 0, refused = 0;
    std::set<std::string> clients, payloadModes;
    std::string line;
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        const auto rec = nlohmann::json::parse(line);
        const auto name = rec.at("client").get<std::string>();
        Headers headers;
        for (const auto& h : rec.at("headers")) headers.emplace_back(h.at(0).get<std::string>(), h.at(1).get<std::string>());
        const auto bodySha = rec.at("body_sha256").get<std::string>();
        const auto expect = rec.at("expect").get<std::string>();
        auto req = makeRequest(rec.at("method").get<std::string>(), rec.at("target").get<std::string>(), headers);
        ++records;
        clients.insert(name.substr(0, name.find('/')));

        // Signed at: x-amz-date, or X-Amz-Date of a presigned URL.
        const auto newInput = s3::verificationInput(req, {}, bodySha);
        const auto parsed = vs::parseAuthorization(newInput, s3::gatewayVerifyOptions());
        ASSERT_TRUE(parsed) << name << ": " << parsed.error().message;
        const auto at = vs::parseAmzDate(parsed->amz_date);
        ASSERT_TRUE(at) << name;
        if (parsed->presigned) ++presigned;
        payloadModes.insert(parsed->presigned ? "presigned" : parsed->payload_hash.size() == 64 ? "sha256" : parsed->payload_hash);

        const auto streamed = outcome(newInput, *at);
        if (expect == "ok") {
            EXPECT_EQ(streamed, "ok") << name << " " << req.target();
        } else {
            ++refused;
            EXPECT_EQ(streamed.substr(0, streamed.find(':')), expect) << name;
        }
        if (rec.contains("body")) {
            req.body() = rec.at("body").get<std::string>();
            EXPECT_EQ(outcome(s3::verificationInput(req, req.body()), *at), streamed) << name << " (buffered)";
        }

        // The retired verifier (minus its clock) agrees: same signature, same payload verdict.
        auto oldInput = gw::inputFromRequest(req, req.body());
        oldInput.body_sha256 = bodySha;
        std::string error;
        const auto oldParsed = gw::parseAuthorization(oldInput, error);
        ASSERT_TRUE(oldParsed) << name << ": " << error;
        EXPECT_EQ(gw::signatureFor(oldInput, *oldParsed, kCaptureSecret), vs::toLower(oldParsed->signature)) << name;
        const bool oldPayloadOk = oldParsed->payload_hash == "UNSIGNED-PAYLOAD" ||
                                  oldParsed->payload_hash == "STREAMING-UNSIGNED-PAYLOAD-TRAILER" ||
                                  oldParsed->payload_hash == bodySha;
        EXPECT_EQ(oldPayloadOk, expect == "ok") << name;
    }
    EXPECT_GE(records, 120u);
    EXPECT_GE(presigned, 8u);
    EXPECT_EQ(refused, 1u);
    EXPECT_EQ(clients, (std::set<std::string>{"aws-cli", "boto3", "mc", "rclone"}));
    EXPECT_EQ(payloadModes, (std::set<std::string>{"presigned", "sha256", "UNSIGNED-PAYLOAD", "STREAMING-UNSIGNED-PAYLOAD-TRAILER",
                                                   "STREAMING-AWS4-HMAC-SHA256-PAYLOAD"}));
}
