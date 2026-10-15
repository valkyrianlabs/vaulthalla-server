#pragma once

#include <ctime>
#include <map>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

// General AWS Signature Version 4 (header signing) for any service: S3 (and S3-compatible providers such as R2),
// SQS, STS. The older storage::s3::curl::buildAuthorizationHeader stays for the vault data path; the upstream control
// plane (#237) signs through this.
//
// Canonical URI: S3 encodes each path segment once (keys are opaque); every other service double-encodes, per the
// SigV4 spec. Canonical query: RFC 3986 encoding of names and values, sorted by name then value. Signed headers: every
// header in the request (lower-cased names, trimmed values) plus host and x-amz-date (and x-amz-content-sha256 for
// S3, x-amz-security-token when a session token is set).
namespace vh::storage::s3::sigv4 {

struct Credentials {
    std::string access_key;
    std::string secret_key;
    std::string session_token;   // optional
};

struct Request {
    std::string method;                                     // GET, PUT, POST, HEAD, DELETE
    std::string host;                                       // host[:port], exactly as the URL has it
    std::string path = "/";                                 // raw, unencoded ("/bucket/a key.txt")
    std::vector<std::pair<std::string, std::string>> query; // raw names and values ("lifecycle", "")
    std::map<std::string, std::string> headers;             // extra headers; names any case
    std::string payload_hash;                               // hex SHA-256 of the body, or "UNSIGNED-PAYLOAD"
};

struct Signed {
    std::map<std::string, std::string> headers;   // every header to send, authorization included (lower-case names)
    std::string encoded_path;                     // the path to put in the URL
    std::string query_string;                     // canonical query, also what the URL carries
    std::string canonical_request;
    std::string string_to_sign;
    std::string authorization;
};

// RFC 3986 percent-encoding of everything but unreserved characters (A-Z a-z 0-9 - _ . ~); '/' kept unless encodeSlash.
[[nodiscard]] std::string uriEncode(std::string_view value, bool encodeSlash);
[[nodiscard]] std::string sha256Hex(std::string_view data);
[[nodiscard]] std::string amzDate(std::time_t t);       // YYYYMMDD'T'HHMMSS'Z'

[[nodiscard]] Signed sign(const Request& request, const Credentials& credentials, const std::string& region,
                          const std::string& service, std::time_t now);

}
