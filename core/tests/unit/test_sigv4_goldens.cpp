// SigV4 characterization ("golden") tests for Vaulthalla's four AWS Signature Version 4 implementations, DB-free.
//
//   upstream  storage::s3::sigv4::sign                     upstream control plane, Controller::signObjectRequest
//   legacy    storage::s3::curl::buildAuthorizationHeader  vault data path (through the buildAuthorizationTrace seam,
//                                                          which pins the credential-scope date)
//   ses       email::providers::detail::signAwsV4          SesProvider (SES v2 SendEmail)
//   gateway   protocols::s3::sigv4                         the S3 gateway's verifier (makeCanonicalRequest,
//                                                          signatureFor, verify)
//
// These record what the CURRENT code produces, not what SigV4 says it should: SigV4 is being consolidated into one
// library (vl-sigv4), and the swap must change no bytes. The "upstream" records were captured from the in-tree
// storage::s3::sigv4::sign; its production callers (Controller::signObjectRequest, provider::admin::detail::send) now
// sign with vl::sigv4::sign, and the VlSigv4* tests below hold that path to the same records byte for byte. The
// "ses" records were captured from email::providers::detail::signAwsV4; SesProvider::send now signs with
// vl::sigv4::sign too, and the VlSigv4*Ses* tests hold it to every ses record except the four where the old signer
// deviates from SigV4 (kSesSignerDeviations), which are checked against the spec instead. The in-tree signers stay
// (and stay checked) until they are deleted after a verified release. Where implementations disagree for the same input, each
// one's own output is asserted and the disagreement is spelled out in SigV4Goldens.CrossImplementationAgreement.
//
// Every case runs each implementation the way its real callers drive it: upstream with the raw path and query pairs;
// legacy with the path curl-escaped per segment (Controller::constructPaths), the query RFC 3986-encoded in the order
// the caller writes it, and lower-cased header names (Controller::applyRequestOptions); ses with lower-cased headers,
// the path and query as sent, and the body (it hashes the payload itself, so it has no UNSIGNED-PAYLOAD); gateway with
// the request as it arrives on the wire (original header names and values, the query in caller order).
//
// The expected values live in core/test-assets/sigv4/goldens.txt. They were generated once, on Linux/GCC 14, by
// running the code of the commit that added this file (its only production changes are two behaviour-preserving test
// seams: curl::buildAuthorizationTrace and email::providers::detail::signAwsV4), with
//     VH_SIGV4_GOLDENS_WRITE="$PWD/core/test-assets/sigv4/goldens.txt" ./build/core/vh_unit_tests --gtest_filter='SigV4Goldens.*'
// Regenerating rewrites the file from whatever the code does now, so a diff of that file IS the behaviour change:
// never regenerate to get green without reading the diff.

#include "crypto/secrets/Manager.hpp"
#include "email/Message.hpp"
#include "email/Transport.hpp"
#include "email/providers/SesProvider.hpp"
#include "email/providers/SesSigning.hpp"
#include "protocols/s3/SigV4.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "storage/s3/sigv4/Signer.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>
#include <vl/sigv4/crypto.hpp>
#include <vl/sigv4/signer.hpp>

#include <curl/curl.h>

#include <algorithm>
#include <cctype>
#include <cstdlib>
#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

namespace sigv4golden {

namespace up = vh::storage::s3::sigv4;
namespace legacy = vh::storage::s3::curl;
namespace gw = vh::protocols::s3::sigv4;
namespace sesv4 = vh::email::providers::detail;
namespace vlsig = vl::sigv4;

constexpr std::time_t k20150830T123600Z = 1440938160;   // AWS sig-v4 test suite
constexpr std::time_t k20130524T000000Z = 1369353600;   // S3 API reference examples
constexpr std::time_t k20261102T101500Z = 1793614500;   // Vaulthalla-shaped cases

// AWS's documented example credentials (sig-v4 test suite; S3 API reference).
constexpr const char* kSuiteAccessKey = "AKIDEXAMPLE";
constexpr const char* kSuiteSecretKey = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
constexpr const char* kS3DocsAccessKey = "AKIAIOSFODNN7EXAMPLE";
constexpr const char* kS3DocsSecretKey = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
// The STS session token from AWS's documentation (carries '/', '+', '=').
constexpr const char* kSessionToken =
    "AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQWLWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuw"
    "thAx7mSEI/qkPpKPi/kMcGdQrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU9HFvlRd8Tx6q6fE8YQcH"
    "NVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz+scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLx"
    "BA==";
constexpr const char* kVersionId = "3/L4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo=";
constexpr const char* kContinuationToken = "1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J+wm36Hy4vbOwM=";
constexpr const char* kUploadId = "VXBsb2FkIElEIGZvciA2aWWpbmcncyBteS1tb3ZpZS5tMnRzIHVwbG9hZA";
constexpr const char* kS3Host = "s3.us-east-1.amazonaws.com";
constexpr const char* kSesBody =
    R"json({"Content":{"Simple":{"Body":{"Html":{"Charset":"UTF-8","Data":"<strong>Hello</strong>"},"Text":{"Charset":"UTF-8","Data":"Hello"}},"Subject":{"Charset":"UTF-8","Data":"[Vaulthalla] Test operator email"}}},"Destination":{"ToAddresses":["admin@example.com"]},"FromEmailAddress":"Vaulthalla <ops@example.com>","ReplyToAddresses":["reply@example.com"]})json";

enum class Impl { Upstream, Legacy, Ses, Gateway };

inline const char* implName(const Impl impl) {
    switch (impl) {
        case Impl::Upstream: return "upstream";
        case Impl::Legacy: return "legacy";
        case Impl::Ses: return "ses";
        case Impl::Gateway: return "gateway";
    }
    return "?";
}

struct Case {
    std::string name;
    std::string service = "s3";
    std::string region = "us-east-1";
    std::string access_key = kSuiteAccessKey;
    std::string secret_key = kSuiteSecretKey;
    std::string session_token;
    std::time_t time = k20261102T101500Z;
    std::string method = "GET";
    std::string host = kS3Host;
    std::string path = "/";                                          // raw, unencoded
    std::vector<std::pair<std::string, std::string>> query;          // raw, in the order the caller writes it
    std::vector<std::pair<std::string, std::string>> headers;        // extra headers, as the caller writes them
    std::string body;
    bool unsigned_payload = false;                                   // S3 x-amz-content-sha256: UNSIGNED-PAYLOAD
};

inline std::string lowerName(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

inline std::string payloadHashOf(const Case& c) { return c.unsigned_payload ? "UNSIGNED-PAYLOAD" : up::sha256Hex(c.body); }

inline bool applies(const Case& c, const Impl impl) {
    switch (impl) {
        case Impl::Upstream: return true;
        case Impl::Legacy: return c.session_token.empty();   // the data path has no session-token support
        case Impl::Ses: return c.session_token.empty() && !c.unsigned_payload;   // hashes the body itself
        case Impl::Gateway: return true;
    }
    return false;
}

// The query as the URL carries it: RFC 3986-encoded, in caller order, a bare name for an empty value ("?uploads").
inline std::string wireQuery(const Case& c) {
    std::string out;
    for (const auto& [name, value] : c.query) {
        if (!out.empty()) out.push_back('&');
        out += up::uriEncode(name, true);
        if (!value.empty()) out += "=" + up::uriEncode(value, true);
    }
    return out;
}

// Controller::constructPaths: every path segment through curl_easy_escape.
inline std::string legacyPath(const Case& c) {
    legacy::ensureCurlGlobalInit();
    CURL* curl = curl_easy_init();
    const auto escaped = legacy::escapeKeyPreserveSlashes(curl, std::filesystem::path(c.path.substr(1)));
    curl_easy_cleanup(curl);
    return "/" + escaped;
}

inline std::string signatureOf(const std::string& authorization) {
    const auto at = authorization.find("Signature=");
    return at == std::string::npos ? std::string{} : authorization.substr(at + 10);
}

inline std::string signedHeadersOf(const std::string& authorization) {
    const auto at = authorization.find("SignedHeaders=") + 14;
    return authorization.substr(at, authorization.find(',', at) - at);
}

// ---- the four implementations, driven the way their callers drive them ------------------------------------------

inline up::Signed runUpstream(const Case& c, const std::time_t now) {
    up::Request request{.method = c.method, .host = c.host, .path = c.path, .query = c.query, .headers = {},
                        .payload_hash = payloadHashOf(c)};
    for (const auto& [name, value] : c.headers) request.headers[name] = value;
    const up::Credentials credentials{.access_key = c.access_key, .secret_key = c.secret_key,
                                      .session_token = c.session_token};
    return up::sign(request, credentials, c.region, c.service, now);
}

// The vl-sigv4 path, driven exactly as its production callers drive it (Controller::signObjectRequest in
// storage/s3/version.cpp, provider::admin::detail::send in provider/admin/Internal.cpp): extra headers in the std::map
// the callers keep, handed over as a HeaderList; raw path and query pairs; the caller's payload hash.
inline vlsig::Signed runVlSigv4(const Case& c, const std::time_t now) {
    std::map<std::string, std::string> headers;
    for (const auto& [name, value] : c.headers) headers[name] = value;
    const vlsig::Request request{.method = c.method, .host = c.host, .path = c.path, .query = c.query,
                                 .headers = vlsig::HeaderList(headers.begin(), headers.end()),
                                 .payload_hash = payloadHashOf(c)};
    const vlsig::Credentials credentials{.access_key = c.access_key, .secret_key = c.secret_key,
                                         .session_token = c.session_token};
    return vlsig::sign(request, credentials, c.region, c.service, vlsig::Clock::from_time_t(now));
}

// The vl-sigv4 path as SesProvider::send drives it: service "ses" (hard-coded, like the old signer's scope), the
// raw path and query pairs, the caller's extra headers (SendEmail: content-type and x-amz-content-sha256) in a
// HeaderList, and the body's hash. sign() adds host and x-amz-date. For S3-shaped cases it is given the
// x-amz-content-sha256 header runSes signs, since sign() adds that header only for service "s3".
inline vlsig::Signed runVlSigv4Ses(const Case& c, const std::time_t now) {
    vlsig::HeaderList headers(c.headers.begin(), c.headers.end());
    if (c.service == "s3") headers.emplace_back("x-amz-content-sha256", payloadHashOf(c));
    const vlsig::Request request{.method = c.method, .host = c.host, .path = c.path, .query = c.query,
                                 .headers = std::move(headers), .payload_hash = vlsig::sha256Hex(c.body)};
    const vlsig::Credentials credentials{.access_key = c.access_key, .secret_key = c.secret_key, .session_token = {}};
    return vlsig::sign(request, credentials, c.region, "ses", vlsig::Clock::from_time_t(now));
}

// The ses records where the old signer is not SigV4, so vl-sigv4 (spec-correct) differs on purpose, each with the part
// of vl-sigv4's canonical request that the old one gets wrong. None is a
// request SesProvider ever sent: since it was added (d5b2cf9a) it has signed one constant path,
// /v2/email/outbound-emails, with an empty query and two headers whose values have no extra whitespace.
inline const std::map<std::string, std::string>& sesSignerDeviations() {
    static const std::map<std::string, std::string> deviations{
        // query signed as written, unsorted: "Param2=value2&Param1=value1"
        {"aws-suite/get-vanilla-query-order-key-case", "\nParam1=value1&Param2=value2\n"},
        // flag parameter signed bare: "lifecycle", not "lifecycle="
        {"aws-s3-docs/get-bucket-lifecycle", "\nlifecycle=\n"},
        // header value signed untrimmed: "  Cooper   Larson "
        {"s3/put-object-headers-case-and-space", "\nx-amz-meta-owner:Cooper Larson\n"},
        // non-S3 path not double-encoded: "/%E1%88%B4"
        {"aws-suite/get-utf8", "GET\n/%25E1%2588%25B4\n"},
    };
    return deviations;
}

inline std::map<std::string, std::string> legacyHeaders(const Case& c, const std::time_t now) {
    std::map<std::string, std::string> headers{{"host", c.host}, {"x-amz-date", up::amzDate(now)}};
    if (c.service == "s3") headers["x-amz-content-sha256"] = payloadHashOf(c);
    for (const auto& [name, value] : c.headers) headers[lowerName(name)] = value;
    return headers;
}

inline legacy::LegacySigningTrace runLegacy(const Case& c, const std::time_t now) {
    const auto key = std::make_shared<vh::vault::model::APIKey>(0, "sigv4-golden", vh::vault::model::S3Provider::AWS,
                                                                c.access_key, c.secret_key, c.region,
                                                                "https://" + c.host);
    const auto query = wireQuery(c);
    const auto fullPath = legacyPath(c) + (query.empty() ? std::string{} : "?" + query);
    return legacy::buildAuthorizationTrace(key, c.method, fullPath, legacyHeaders(c, now), payloadHashOf(c), "",
                                           up::amzDate(now).substr(0, 8));
}

inline sesv4::SigningResult runSes(const Case& c, const std::time_t now) {
    std::map<std::string, std::string> headers{{"host", c.host}, {"x-amz-date", up::amzDate(now)}};
    if (c.service == "s3") headers["x-amz-content-sha256"] = payloadHashOf(c);
    for (const auto& [name, value] : c.headers) headers[lowerName(name)] = value;
    return sesv4::signAwsV4(c.access_key, c.secret_key, c.region, c.method, up::uriEncode(c.path, false),
                            wireQuery(c), headers, c.body, now);
}

// The request the gateway receives when the upstream signer's output is sent: the caller's own header names and
// values, everything the signer added, the query in caller order.
template <typename SignedRequest>   // up::Signed or vlsig::Signed
gw::VerificationInput gatewayInput(const Case& c, const SignedRequest& sent) {
    gw::VerificationInput input;
    input.method = c.method;
    const auto query = wireQuery(c);
    input.target = sent.encoded_path + (query.empty() ? std::string{} : "?" + query);
    input.host = c.host;
    for (const auto& [name, value] : c.headers) input.headers[name] = value;
    for (const auto& [name, value] : sent.headers) {
        const bool callerSent = std::ranges::any_of(c.headers, [&](const auto& h) { return lowerName(h.first) == name; });
        if (!callerSent) input.headers[name] = value;
    }
    input.body = c.body;
    return input;
}

// The gateway only accepts service "s3" in a credential scope; other services get the ParsedAuth it would build.
inline gw::ParsedAuth gatewayAuth(const Case& c, const gw::VerificationInput& input, const up::Signed& sent) {
    if (c.service == "s3") {
        std::string error;
        auto parsed = gw::parseAuthorization(input, error);
        EXPECT_TRUE(parsed) << c.name << ": " << error;
        if (parsed) return *parsed;
    }
    const auto date = sent.headers.at("x-amz-date");
    const auto hashHeader = sent.headers.find("x-amz-content-sha256");
    return gw::ParsedAuth{
        .credential = {.access_key = c.access_key, .date = date.substr(0, 8), .region = c.region, .service = c.service},
        .signed_headers = signedHeadersOf(sent.authorization),
        .signature = signatureOf(sent.authorization),
        .amz_date = date,
        .payload_hash = hashHeader == sent.headers.end() ? gw::sha256Hex(c.body) : hashHeader->second,
        .presigned = false,
        .expires_seconds = 0,
    };
}

// ---- cases --------------------------------------------------------------------------------------------------------

inline Case suiteCase(std::string name) {
    Case c;
    c.name = "aws-suite/" + std::move(name);
    c.service = "service";
    c.time = k20150830T123600Z;
    c.host = "example.amazonaws.com";
    return c;
}

inline Case s3DocsCase(std::string name) {
    Case c;
    c.name = "aws-s3-docs/" + std::move(name);
    c.access_key = kS3DocsAccessKey;
    c.secret_key = kS3DocsSecretKey;
    c.time = k20130524T000000Z;
    c.host = "examplebucket.s3.amazonaws.com";
    return c;
}

inline Case s3Case(std::string name, std::string method, std::string path, const bool unsignedPayload = true) {
    Case c;
    c.name = "s3/" + std::move(name);
    c.method = std::move(method);
    c.path = std::move(path);
    c.unsigned_payload = unsignedPayload;
    return c;
}

inline const std::vector<Case>& cases() {
    static const std::vector<Case> all = [] {
        std::vector<Case> v;

        v.push_back(suiteCase("get-vanilla"));
        {
            auto c = suiteCase("get-vanilla-query-order-key-case");
            c.query = {{"Param2", "value2"}, {"Param1", "value1"}};
            v.push_back(c);
        }
        {
            auto c = suiteCase("get-vanilla-query-unreserved");
            const std::string unreserved = "-._~0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
            c.query = {{unreserved, unreserved}};
            v.push_back(c);
        }
        {
            // Non-S3 services double-encode the canonical path (upstream), S3 encodes once.
            auto c = suiteCase("get-utf8");
            c.path = "/\xe1\x88\xb4";
            v.push_back(c);
        }
        {
            auto c = suiteCase("post-x-www-form-urlencoded");
            c.method = "POST";
            c.headers = {{"Content-Type", "application/x-www-form-urlencoded"}};
            c.body = "Param1=value1";
            v.push_back(c);
        }

        {
            auto c = s3DocsCase("get-object-range");
            c.path = "/test.txt";
            c.headers = {{"Range", "bytes=0-9"}};
            v.push_back(c);
        }
        {
            auto c = s3DocsCase("get-bucket-lifecycle");
            c.query = {{"lifecycle", ""}};
            v.push_back(c);
        }

        v.push_back(s3Case("get-object", "GET", "/vh-bucket/photos/cat.jpg"));
        {
            auto c = s3Case("get-object-range", "GET", "/vh-bucket/photos/cat.jpg");
            c.headers = {{"Range", "bytes=0-1048575"}};
            v.push_back(c);
        }
        v.push_back(s3Case("head-object", "HEAD", "/vh-bucket/photos/cat.jpg"));
        v.push_back(s3Case("delete-object", "DELETE", "/vh-bucket/photos/cat.jpg"));
        {
            auto c = s3Case("put-object-payload-hash", "PUT", "/vh-bucket/notes/hello.txt", false);
            c.body = "hello vaulthalla\n";
            v.push_back(c);
        }
        {
            // Mixed-case names and untrimmed values, as a caller could write them.
            auto c = s3Case("put-object-headers-case-and-space", "PUT", "/vh-bucket/notes/hello.txt", false);
            c.body = "hello vaulthalla\n";
            c.headers = {{"Content-Type", "text/plain"}, {"X-Amz-Meta-Owner", "  Cooper   Larson "}};
            v.push_back(c);
        }
        v.push_back(s3Case("key-special-chars", "GET", "/vh-bucket/dir one/a b+c=d~e%f.txt"));
        v.push_back(s3Case("key-utf8", "GET", "/vh-bucket/caf\xc3\xa9/r\xc3\xa9sum\xc3\xa9.pdf"));
        {
            auto c = s3Case("get-object-version", "GET", "/vh-bucket/photos/cat.jpg");
            c.query = {{"versionId", kVersionId}};
            v.push_back(c);
        }
        {
            auto c = s3Case("delete-object-version", "DELETE", "/vh-bucket/photos/cat.jpg");
            c.query = {{"versionId", kVersionId}};
            v.push_back(c);
        }
        {
            // Controller::listObjectKeysPage writes the query out of canonical order.
            auto c = s3Case("list-v2-continuation", "GET", "/vh-bucket");
            c.query = {{"list-type", "2"}, {"max-keys", "1000"}, {"continuation-token", kContinuationToken}};
            v.push_back(c);
        }
        {
            auto c = s3Case("multipart-initiate", "POST", "/vh-bucket/big/movie.m2ts");
            c.query = {{"uploads", ""}};
            v.push_back(c);
        }
        {
            auto c = s3Case("multipart-upload-part", "PUT", "/vh-bucket/big/movie.m2ts", false);
            c.query = {{"partNumber", "7"}, {"uploadId", kUploadId}};
            c.body = "part seven bytes";
            v.push_back(c);
        }
        {
            auto c = s3Case("multipart-complete", "POST", "/vh-bucket/big/movie.m2ts", false);
            c.query = {{"uploadId", kUploadId}};
            c.body = "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"etag-1\"</ETag></Part>"
                     "</CompleteMultipartUpload>";
            v.push_back(c);
        }
        {
            auto c = s3Case("multipart-abort", "DELETE", "/vh-bucket/big/movie.m2ts");
            c.query = {{"uploadId", kUploadId}};
            v.push_back(c);
        }
        {
            auto c = s3Case("session-token", "GET", "/vh-bucket/photos/cat.jpg");
            c.session_token = kSessionToken;
            v.push_back(c);
        }
        {
            auto c = s3Case("r2-get-object", "GET", "/vh-bucket/photos/cat.jpg");
            c.name = "r2/get-object";
            c.host = "0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com";
            c.region = "auto";
            v.push_back(c);
        }

        {
            // What SesProvider::send signs: SES v2 SendEmail.
            Case c;
            c.name = "ses/send-email";
            c.service = "ses";
            c.method = "POST";
            c.host = "email.us-east-1.amazonaws.com";
            c.path = "/v2/email/outbound-emails";
            c.body = kSesBody;
            c.headers = {{"Content-Type", "application/json"}, {"X-Amz-Content-Sha256", up::sha256Hex(c.body)}};
            v.push_back(c);
        }
        return v;
    }();
    return all;
}

// ---- golden records -----------------------------------------------------------------------------------------------

using Records = std::map<std::string, std::string>;   // "<case> <impl> <field>" -> value

inline std::string recordKey(const Case& c, const Impl impl, const std::string& field) {
    return c.name + " " + implName(impl) + " " + field;
}

inline Records currentRecords() {
    Records out;
    for (const auto& c : cases()) {
        const auto sent = runUpstream(c, c.time);
        out[recordKey(c, Impl::Upstream, "canonical_request")] = sent.canonical_request;
        out[recordKey(c, Impl::Upstream, "string_to_sign")] = sent.string_to_sign;
        out[recordKey(c, Impl::Upstream, "authorization")] = sent.authorization;
        if (applies(c, Impl::Legacy)) {
            const auto t = runLegacy(c, c.time);
            out[recordKey(c, Impl::Legacy, "canonical_request")] = t.canonical_request;
            out[recordKey(c, Impl::Legacy, "string_to_sign")] = t.string_to_sign;
            out[recordKey(c, Impl::Legacy, "authorization")] = t.authorization;
        }
        if (applies(c, Impl::Ses)) {
            const auto t = runSes(c, c.time);
            out[recordKey(c, Impl::Ses, "canonical_request")] = t.canonicalRequest;
            out[recordKey(c, Impl::Ses, "string_to_sign")] = t.stringToSign;
            out[recordKey(c, Impl::Ses, "authorization")] = t.authorization;
        }
        const auto input = gatewayInput(c, sent);
        const auto auth = gatewayAuth(c, input, sent);
        out[recordKey(c, Impl::Gateway, "canonical_request")] = gw::makeCanonicalRequest(input, auth);
        out[recordKey(c, Impl::Gateway, "signature")] = gw::signatureFor(input, auth, c.secret_key);
    }
    return out;
}

inline std::filesystem::path fixturePath() { return std::filesystem::path(VH_TEST_ASSETS_DIR) / "sigv4" / "goldens.txt"; }

constexpr const char* kFixtureHeader =
    "# SigV4 characterization goldens: what each implementation produces today (core/tests/unit/test_sigv4_goldens.cpp).\n"
    "# Generated by running the code, never edited by hand: see the test file for how to regenerate, and read the diff.\n"
    "# Format: '@@ <case> <implementation> <field>' and then the value, up to the next '@@ ' line.\n";

inline void writeFixture(const std::filesystem::path& path, const Records& records) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out << kFixtureHeader;
    for (const auto& [key, value] : records) out << "@@ " << key << "\n" << value << "\n";
}

inline Records readFixture(const std::filesystem::path& path) {
    Records out;
    std::ifstream in(path, std::ios::binary);
    std::string line, key, value;
    bool inRecord = false;
    const auto flush = [&] {
        if (inRecord) out[key] = value.empty() ? value : value.substr(0, value.size() - 1);
    };
    while (std::getline(in, line)) {
        if (line.starts_with("@@ ")) {
            flush();
            key = line.substr(3);
            value.clear();
            inRecord = true;
        } else if (inRecord) {
            value += line + "\n";
        }
    }
    flush();
    return out;
}

inline const Records& fixture() {
    static const Records records = [] {
        if (const char* target = std::getenv("VH_SIGV4_GOLDENS_WRITE"); target && *target)
            writeFixture(target, currentRecords());
        return readFixture(fixturePath());
    }();
    return records;
}

inline void expectMatchesFixture(const Impl impl) {
    const auto& golden = fixture();
    ASSERT_FALSE(golden.empty()) << "missing or empty fixture " << fixturePath();
    const auto current = currentRecords();
    std::size_t compared = 0;
    for (const auto& [key, value] : current) {
        if (key.find(std::string(" ") + implName(impl) + " ") == std::string::npos) continue;
        ++compared;
        const auto it = golden.find(key);
        if (it == golden.end()) {
            ADD_FAILURE() << "no golden for " << key;
            continue;
        }
        EXPECT_EQ(value, it->second) << key;
    }
    EXPECT_GT(compared, 0u);
}

// Groups the implementations by identical value: "upstream=legacy=gateway | ses".
inline std::string agreement(const Case& c, const bool signatures) {
    std::vector<std::pair<std::string, std::string>> values;   // impl, value
    const auto sent = runUpstream(c, c.time);
    if (signatures) values.emplace_back("upstream", signatureOf(sent.authorization));
    else values.emplace_back("upstream", sent.canonical_request);
    if (applies(c, Impl::Legacy)) {
        const auto t = runLegacy(c, c.time);
        values.emplace_back("legacy", signatures ? signatureOf(t.authorization) : t.canonical_request);
    }
    if (applies(c, Impl::Ses)) {
        const auto t = runSes(c, c.time);
        values.emplace_back("ses", signatures ? signatureOf(t.authorization) : t.canonicalRequest);
    }
    const auto input = gatewayInput(c, sent);
    const auto auth = gatewayAuth(c, input, sent);
    values.emplace_back("gateway", signatures ? gw::signatureFor(input, auth, c.secret_key)
                                              : gw::makeCanonicalRequest(input, auth));

    std::vector<std::vector<std::string>> groups;
    std::vector<std::string> groupValue;
    for (const auto& [impl, value] : values) {
        const auto it = std::ranges::find(groupValue, value);
        if (it == groupValue.end()) {
            groups.push_back({impl});
            groupValue.push_back(value);
        } else {
            groups[static_cast<std::size_t>(it - groupValue.begin())].push_back(impl);
        }
    }
    std::string out;
    for (const auto& group : groups) {
        if (!out.empty()) out += " | ";
        for (std::size_t i = 0; i < group.size(); ++i) out += (i ? "=" : "") + group[i];
    }
    return out;
}

inline const Case& caseNamed(const std::string& name) {
    const auto it = std::ranges::find_if(cases(), [&](const Case& c) { return c.name == name; });
    if (it == cases().end()) throw std::invalid_argument("no SigV4 golden case " + name);
    return *it;
}

}

// ---- the goldens --------------------------------------------------------------------------------------------------

TEST(SigV4Goldens, UpstreamSignerMatchesGoldens) { sigv4golden::expectMatchesFixture(sigv4golden::Impl::Upstream); }
TEST(SigV4Goldens, LegacyDataPathSignerMatchesGoldens) { sigv4golden::expectMatchesFixture(sigv4golden::Impl::Legacy); }
TEST(SigV4Goldens, SesSignerMatchesGoldens) { sigv4golden::expectMatchesFixture(sigv4golden::Impl::Ses); }
TEST(SigV4Goldens, GatewayVerifierMatchesGoldens) { sigv4golden::expectMatchesFixture(sigv4golden::Impl::Gateway); }

// The production signing path: vl-sigv4 reproduces every "upstream" record (canonical request, string to sign,
// Authorization) captured from the in-tree signer.
TEST(SigV4Goldens, VlSigv4MatchesUpstreamGoldens) {
    using namespace sigv4golden;
    const auto& golden = fixture();
    ASSERT_FALSE(golden.empty()) << "missing or empty fixture " << fixturePath();
    std::size_t compared = 0;
    for (const auto& c : cases()) {
        const auto sent = runVlSigv4(c, c.time);
        const std::vector<std::pair<std::string, std::string>> fields{
            {"canonical_request", sent.canonical_request},
            {"string_to_sign", sent.string_to_sign},
            {"authorization", sent.authorization},
        };
        for (const auto& [field, value] : fields) {
            const auto key = recordKey(c, Impl::Upstream, field);
            const auto it = golden.find(key);
            if (it == golden.end()) {
                ADD_FAILURE() << "no golden for " << key;
                continue;
            }
            EXPECT_EQ(value, it->second) << key << " (vl-sigv4)";
            ++compared;
        }
        EXPECT_EQ(sent.signature, signatureOf(sent.authorization)) << c.name;
    }
    EXPECT_EQ(compared, cases().size() * 3);
}

// Beyond the signature, the request on the wire is the same: every header sent (Authorization included), the encoded
// path and the query string, at the cases' times and at the current time.
TEST(SigV4Goldens, VlSigv4SendsWhatTheUpstreamSignerSent) {
    using namespace sigv4golden;
    const auto now = std::time(nullptr);
    for (const auto& c : cases()) {
        for (const auto t : {c.time, now}) {
            const auto before = runUpstream(c, t);
            const auto after = runVlSigv4(c, t);
            EXPECT_EQ(after.headers, before.headers) << c.name << " @" << t;
            EXPECT_EQ(after.encoded_path, before.encoded_path) << c.name << " @" << t;
            EXPECT_EQ(after.query_string, before.query_string) << c.name << " @" << t;
            EXPECT_EQ(after.canonical_request, before.canonical_request) << c.name << " @" << t;
            EXPECT_EQ(after.string_to_sign, before.string_to_sign) << c.name << " @" << t;
            EXPECT_EQ(after.authorization, before.authorization) << c.name << " @" << t;
        }
    }
}

// SesProvider's signing path: vl-sigv4 reproduces every "ses" record (canonical request, string to sign,
// Authorization) captured from detail::signAwsV4, SendEmail included, except the old signer's deviations from SigV4.
TEST(SigV4Goldens, VlSigv4MatchesSesGoldens) {
    using namespace sigv4golden;
    const auto& golden = fixture();
    ASSERT_FALSE(golden.empty()) << "missing or empty fixture " << fixturePath();
    std::size_t compared = 0, deviating = 0;
    for (const auto& c : cases()) {
        if (!applies(c, Impl::Ses)) continue;
        const auto sent = runVlSigv4Ses(c, c.time);
        if (sesSignerDeviations().contains(c.name)) {   // VlSigv4FixesTheSesSignersDeviations
            ++deviating;
            EXPECT_NE(sent.canonical_request, golden.at(recordKey(c, Impl::Ses, "canonical_request"))) << c.name;
            continue;
        }
        const std::vector<std::pair<std::string, std::string>> fields{
            {"canonical_request", sent.canonical_request},
            {"string_to_sign", sent.string_to_sign},
            {"authorization", sent.authorization},
        };
        for (const auto& [field, value] : fields) {
            const auto key = recordKey(c, Impl::Ses, field);
            const auto it = golden.find(key);
            if (it == golden.end()) {
                ADD_FAILURE() << "no golden for " << key;
                continue;
            }
            EXPECT_EQ(value, it->second) << key << " (vl-sigv4)";
            ++compared;
        }
        EXPECT_EQ(sent.signature, signatureOf(sent.authorization)) << c.name;
    }
    EXPECT_EQ(deviating, sesSignerDeviations().size());
    EXPECT_EQ(compared, 8u * 3);   // 12 ses records minus the 4 deviations
    EXPECT_EQ(sesSignerDeviations().count("ses/send-email"), 0u);
}

// Where the old SES signer deviates from SigV4, vl-sigv4 is held to the spec instead of the ses record: its canonical
// request is the one the upstream signer produced for the same request (anchored to AWS's published signatures by
// AnchoredToAwsPublishedSignatures), and it differs from the old one exactly in the deviating part.
TEST(SigV4Goldens, VlSigv4FixesTheSesSignersDeviations) {
    using namespace sigv4golden;
    const auto& golden = fixture();
    for (const auto& [name, specPart] : sesSignerDeviations()) {
        const auto& c = caseNamed(name);
        ASSERT_TRUE(applies(c, Impl::Ses)) << name;
        const auto sent = runVlSigv4Ses(c, c.time);
        const auto& upstream = golden.at(recordKey(c, Impl::Upstream, "canonical_request"));
        const auto& old = golden.at(recordKey(c, Impl::Ses, "canonical_request"));
        EXPECT_EQ(sent.canonical_request, upstream) << name;
        EXPECT_NE(sent.canonical_request, old) << name;
        EXPECT_NE(sent.canonical_request.find(specPart), std::string::npos) << name << ": " << sent.canonical_request;
        EXPECT_EQ(old.find(specPart), std::string::npos) << name;
    }
    // The AWS suite publishes the sorted-query signature for service "service"; vl-sigv4 signing the request exactly
    // as the SES path builds it, under that scope, reproduces it.
    const Case c = caseNamed("aws-suite/get-vanilla-query-order-key-case");
    const vlsig::Request request{.method = c.method, .host = c.host, .path = c.path, .query = c.query,
                                 .headers = {}, .payload_hash = vlsig::sha256Hex(c.body)};
    EXPECT_EQ(vlsig::sign(request, {.access_key = c.access_key, .secret_key = c.secret_key, .session_token = {}},
                          c.region, c.service, vlsig::Clock::from_time_t(c.time)).signature,
              "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500");
}

// Beyond the signature, what SesProvider puts on the wire is the same: x-amz-date, x-amz-content-sha256, the path and
// the query, at the cases' times and at the current time.
TEST(SigV4Goldens, VlSigv4SendsWhatTheSesSignerSent) {
    using namespace sigv4golden;
    const auto now = std::time(nullptr);
    for (const auto& c : cases()) {
        if (!applies(c, Impl::Ses) || sesSignerDeviations().contains(c.name)) continue;
        for (const auto t : {c.time, now}) {
            const auto before = runSes(c, t);
            const auto after = runVlSigv4Ses(c, t);
            EXPECT_EQ(after.headers.at("x-amz-date"), before.amzDate) << c.name << " @" << t;
            if (after.headers.contains("x-amz-content-sha256")) {
                EXPECT_EQ(after.headers.at("x-amz-content-sha256"), before.payloadHash) << c.name << " @" << t;
            }
            EXPECT_EQ(after.headers.at("host"), c.host) << c.name << " @" << t;
            EXPECT_EQ(after.encoded_path, up::uriEncode(c.path, false)) << c.name << " @" << t;
            EXPECT_EQ(after.query_string, wireQuery(c)) << c.name << " @" << t;
            EXPECT_EQ(after.canonical_request, before.canonicalRequest) << c.name << " @" << t;
            EXPECT_EQ(after.string_to_sign, before.stringToSign) << c.name << " @" << t;
            EXPECT_EQ(after.authorization, before.authorization) << c.name << " @" << t;
        }
    }
}

TEST(SigV4Goldens, FixtureHasNoStaleEntries) {
    const auto current = sigv4golden::currentRecords();
    for (const auto& [key, value] : sigv4golden::fixture())
        EXPECT_TRUE(current.contains(key)) << "golden " << key << " is no longer produced";
    EXPECT_EQ(current.size(), sigv4golden::fixture().size());
}

// The published AWS values the goldens are anchored to: what "current behaviour" has to keep meaning.
TEST(SigV4Goldens, AnchoredToAwsPublishedSignatures) {
    using namespace sigv4golden;
    const std::vector<std::pair<std::string, std::string>> published{
        {"aws-suite/get-vanilla", "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"},
        {"aws-suite/get-vanilla-query-order-key-case", "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500"},
        {"aws-suite/post-x-www-form-urlencoded", "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a"},
        {"aws-s3-docs/get-object-range", "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41"},
        {"aws-s3-docs/get-bucket-lifecycle", "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543"},
    };
    for (const auto& [name, signature] : published) {
        const auto& c = caseNamed(name);
        const auto sent = runUpstream(c, c.time);
        EXPECT_EQ(signatureOf(sent.authorization), signature) << name << " upstream";
        EXPECT_EQ(runVlSigv4(c, c.time).signature, signature) << name << " vl-sigv4";
        const auto input = gatewayInput(c, sent);
        EXPECT_EQ(gw::signatureFor(input, gatewayAuth(c, input, sent), c.secret_key), signature) << name << " gateway";
        if (c.service == "s3") {   // legacy and ses hard-code their service ("s3", "ses") in the credential scope
            EXPECT_EQ(signatureOf(runLegacy(c, c.time).authorization), signature) << name << " legacy";
        }
    }
}

// THE DISAGREEMENT TABLE. For every case: which implementations produce the same canonical request, and the same
// final signature ("a=b | c" means a and b agree and c differs). Implementations that don't apply to a case are
// left out (legacy: no session token; ses: no session token and no UNSIGNED-PAYLOAD). Differences that are only the
// hard-coded service in the credential scope (legacy "s3", ses "ses") show as signature splits over equal canonical
// requests. Every other split is a real behavioural difference, explained inline.
TEST(SigV4Goldens, CrossImplementationAgreement) {
    using namespace sigv4golden;
    struct Expected {
        std::string canonical_request;
        std::string signature;
    };
    // Signature splits marked [scope] come only from the service legacy ("s3") and ses ("ses") hard-code.
    const std::map<std::string, Expected> expected{
        {"aws-suite/get-vanilla", {"upstream=legacy=ses=gateway", "upstream=gateway | legacy | ses"}},   // [scope]
        // ses signs the query as given: no sorting ("Param2=value2&Param1=value1").
        {"aws-suite/get-vanilla-query-order-key-case", {"upstream=legacy=gateway | ses", "upstream=gateway | legacy | ses"}},
        {"aws-suite/get-vanilla-query-unreserved", {"upstream=legacy=ses=gateway", "upstream=gateway | legacy | ses"}},   // [scope]
        // upstream double-encodes the path for non-S3 services ("/%25E1%2588%25B4"); the others encode once. The
        // gateway signature differs from upstream's for that reason (its own scope is the case's "service").
        {"aws-suite/get-utf8", {"upstream | legacy=ses=gateway", "upstream | legacy | ses | gateway"}},
        {"aws-suite/post-x-www-form-urlencoded", {"upstream=legacy=ses=gateway", "upstream=gateway | legacy | ses"}},   // [scope]
        {"aws-s3-docs/get-object-range", {"upstream=legacy=ses=gateway", "upstream=legacy=gateway | ses"}},   // [scope]
        // ses keeps a bare subresource bare ("lifecycle", not "lifecycle=").
        {"aws-s3-docs/get-bucket-lifecycle", {"upstream=legacy=gateway | ses", "upstream=legacy=gateway | ses"}},
        {"s3/get-object", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/get-object-range", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/head-object", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/delete-object", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/put-object-payload-hash", {"upstream=legacy=ses=gateway", "upstream=legacy=gateway | ses"}},   // [scope]
        // legacy and ses sign header values verbatim ("  Cooper   Larson "); upstream and the gateway trim and
        // collapse runs of spaces ("Cooper Larson"). A legacy-signed request like this fails at the gateway (and AWS).
        {"s3/put-object-headers-case-and-space", {"upstream=gateway | legacy=ses", "upstream=gateway | legacy | ses"}},
        {"s3/key-special-chars", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/key-utf8", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/get-object-version", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/delete-object-version", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/list-v2-continuation", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/multipart-initiate", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/multipart-upload-part", {"upstream=legacy=ses=gateway", "upstream=legacy=gateway | ses"}},   // [scope]
        {"s3/multipart-complete", {"upstream=legacy=ses=gateway", "upstream=legacy=gateway | ses"}},   // [scope]
        {"s3/multipart-abort", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"s3/session-token", {"upstream=gateway", "upstream=gateway"}},
        {"r2/get-object", {"upstream=legacy=gateway", "upstream=legacy=gateway"}},
        {"ses/send-email", {"upstream=legacy=ses=gateway", "upstream=ses=gateway | legacy"}},   // [scope]
    };
    for (const auto& c : cases()) {
        const auto it = expected.find(c.name);
        const auto cr = agreement(c, false);
        const auto sig = agreement(c, true);
        if (it == expected.end()) {
            ADD_FAILURE() << "no agreement row for " << c.name << ": {\"" << cr << "\", \"" << sig << "\"}";
            continue;
        }
        EXPECT_EQ(cr, it->second.canonical_request) << c.name << " canonical request";
        EXPECT_EQ(sig, it->second.signature) << c.name << " signature";
    }
    EXPECT_EQ(expected.size(), cases().size());
}

// ---- round trips at the current time (the gateway enforces a 15-minute skew) -------------------------------------

TEST(SigV4Goldens, UpstreamSignaturesVerifyAtGateway) {
    using namespace sigv4golden;
    const auto now = std::time(nullptr);
    std::size_t checked = 0;
    for (const auto& c : cases()) {
        if (c.service != "s3") continue;   // the gateway accepts only service s3
        const auto sent = runUpstream(c, now);
        const auto result = gw::verify(gatewayInput(c, sent), c.secret_key);
        EXPECT_TRUE(result.ok) << c.name << ": " << result.error;
        EXPECT_EQ(result.access_key, c.access_key) << c.name;
        ++checked;
    }
    EXPECT_GT(checked, 15u);
}

TEST(SigV4Goldens, VlSigv4SignaturesVerifyAtGateway) {
    using namespace sigv4golden;
    const auto now = std::time(nullptr);
    std::size_t checked = 0;
    for (const auto& c : cases()) {
        if (c.service != "s3") continue;   // the gateway accepts only service s3
        const auto result = gw::verify(gatewayInput(c, runVlSigv4(c, now)), c.secret_key);
        EXPECT_TRUE(result.ok) << c.name << ": " << result.error;
        EXPECT_EQ(result.access_key, c.access_key) << c.name;
        ++checked;
    }
    EXPECT_GT(checked, 15u);
}

TEST(SigV4Goldens, LegacySignaturesAtGateway) {
    using namespace sigv4golden;
    const auto now = std::time(nullptr);
    for (const auto& c : cases()) {
        if (c.service != "s3" || !applies(c, Impl::Legacy)) continue;
        const auto trace = runLegacy(c, now);
        gw::VerificationInput input;
        input.method = c.method;
        const auto query = wireQuery(c);
        input.target = legacyPath(c) + (query.empty() ? std::string{} : "?" + query);
        input.host = c.host;
        for (const auto& [name, value] : legacyHeaders(c, now)) input.headers[name] = value;
        input.headers["authorization"] = trace.authorization;
        input.body = c.body;
        const auto result = gw::verify(input, c.secret_key);
        // legacy signs header values untrimmed, the gateway trims them (CrossImplementationAgreement).
        if (c.name == "s3/put-object-headers-case-and-space") {
            EXPECT_FALSE(result.ok) << c.name;
            EXPECT_EQ(result.error, "Signature mismatch") << c.name;
        } else {
            EXPECT_TRUE(result.ok) << c.name << ": " << result.error;
        }
    }
}

// SesProvider::send (now vl::sigv4::sign) sends exactly the request the old detail::signAwsV4 path sent: same URL,
// same header lines in the same order, same Authorization, and the upstream signer agrees with it.
TEST(SigV4Goldens, SesProviderSendSignsLikeTheGoldens) {
    using namespace sigv4golden;
    auto transport = std::make_unique<vh::email::FakeTransport>();
    transport->response = {.status = 200, .body = R"json({"MessageId":"golden"})json", .headers = ""};
    auto* fake = transport.get();
    vh::email::providers::SesProvider provider(
        {.region = "us-east-1", .endpoint = std::nullopt},
        vh::crypto::secrets::Manager::createForTesting({
            {vh::email::providers::SesProvider::kAccessKeySecret, kSuiteAccessKey},
            {vh::email::providers::SesProvider::kSecretKeySecret, kSuiteSecretKey},
        }),
        std::move(transport));
    const vh::email::Message message{
        .from = {.email = "ops@example.com", .name = "Vaulthalla"},
        .to = {{.email = "admin@example.com", .name = std::nullopt}},
        .replyTo = vh::email::Address{.email = "reply@example.com", .name = std::nullopt},
        .subject = "[Vaulthalla] Test operator email",
        .html = "<strong>Hello</strong>",
        .text = "Hello",
        .idempotencyKey = "sigv4-golden",
        .tags = {},
    };
    ASSERT_TRUE(provider.send(message).ok);
    ASSERT_EQ(fake->requests.size(), 1u);
    const auto& request = fake->requests.front();
    EXPECT_EQ(request.body, kSesBody);   // the payload of the ses/send-email case

    std::string amzDate, authorization;
    for (const auto& header : request.headers) {
        if (header.starts_with("X-Amz-Date: ")) amzDate = header.substr(12);
        if (header.starts_with("Authorization: ")) authorization = header.substr(15);
    }
    ASSERT_EQ(amzDate.size(), 16u);
    std::tm tm{};
    std::istringstream parse(amzDate);
    parse >> std::get_time(&tm, "%Y%m%dT%H%M%SZ");
    ASSERT_FALSE(parse.fail());
    const auto sentAt = timegm(&tm);

    const Case c = caseNamed("ses/send-email");
    const auto old = runSes(c, sentAt);
    EXPECT_EQ(authorization, old.authorization);
    EXPECT_EQ(authorization, runUpstream(c, sentAt).authorization);
    EXPECT_EQ(authorization, runVlSigv4Ses(c, sentAt).authorization);

    // What SesProvider::send built before the migration, from detail::signAwsV4's result.
    EXPECT_EQ(request.method, "POST");
    EXPECT_EQ(request.url, "https://" + c.host + c.path);
    const std::vector<std::string> oldHeaders{
        "Content-Type: application/json",
        "Host: " + c.host,
        "X-Amz-Date: " + old.amzDate,
        "X-Amz-Content-Sha256: " + old.payloadHash,
        "Authorization: " + old.authorization,
    };
    EXPECT_EQ(request.headers, oldHeaders);
}
