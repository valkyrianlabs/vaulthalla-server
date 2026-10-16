// AWS Signature Version 4 against AWS's published test vectors (sig-v4 test suite: get-vanilla,
// get-vanilla-query-order-key-case, post-x-www-form-urlencoded; S3 GetObject + GET ?lifecycle from the S3 API
// reference), cross-checked with botocore.

#include "storage/s3/sigv4/Signer.hpp"

#include <gtest/gtest.h>

namespace {

namespace sigv4 = vh::storage::s3::sigv4;

constexpr std::time_t k20150830T123600Z = 1440938160;
constexpr std::time_t k20130524T000000Z = 1369353600;

const sigv4::Credentials kSigV4Suite{.access_key = "AKIDEXAMPLE",
                                .secret_key = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY",
                                .session_token = {}};
const sigv4::Credentials kSigV4S3Docs{.access_key = "AKIAIOSFODNN7EXAMPLE",
                                 .secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                                 .session_token = {}};

std::string sigv4SignatureOf(const sigv4::Signed& s) { return s.authorization.substr(s.authorization.find("Signature=") + 10); }

sigv4::Request sigv4TestRequest(std::string method, std::string host, std::string path,
                       std::vector<std::pair<std::string, std::string>> query = {},
                       std::map<std::string, std::string> headers = {}, const std::string& body = {}) {
    return {.method = std::move(method), .host = std::move(host), .path = std::move(path), .query = std::move(query),
            .headers = std::move(headers), .payload_hash = sigv4::sha256Hex(body)};
}

}

TEST(UpstreamSigV4, GetVanilla) {
    const auto s = sigv4::sign(sigv4TestRequest("GET", "example.amazonaws.com", "/"), kSigV4Suite, "us-east-1", "service",
                               k20150830T123600Z);
    EXPECT_EQ(sigv4SignatureOf(s), "5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31");
    EXPECT_NE(s.authorization.find("Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request"), std::string::npos);
    EXPECT_NE(s.authorization.find("SignedHeaders=host;x-amz-date,"), std::string::npos);
    EXPECT_EQ(s.headers.at("x-amz-date"), "20150830T123600Z");
}

TEST(UpstreamSigV4, GetVanillaQueryOrderKeyCase) {
    const auto s = sigv4::sign(sigv4TestRequest("GET", "example.amazonaws.com", "/", {{"Param2", "value2"}, {"Param1", "value1"}}),
                               kSigV4Suite, "us-east-1", "service", k20150830T123600Z);
    EXPECT_EQ(s.query_string, "Param1=value1&Param2=value2");
    EXPECT_EQ(sigv4SignatureOf(s), "b97d918cfa904a5beff61c982a1b6f458b799221646efd99d3219ec94cdf2500");
}

TEST(UpstreamSigV4, PostFormUrlencoded) {
    const auto s = sigv4::sign(sigv4TestRequest("POST", "example.amazonaws.com", "/", {},
                                       {{"Content-Type", "application/x-www-form-urlencoded"}}, "Param1=value1"),
                               kSigV4Suite, "us-east-1", "service", k20150830T123600Z);
    EXPECT_EQ(sigv4SignatureOf(s), "ff11897932ad3f4e8b18135d722051e5ac45fc38421b1da7b9d196a0fe09473a");
    EXPECT_NE(s.authorization.find("SignedHeaders=content-type;host;x-amz-date,"), std::string::npos);
}

TEST(UpstreamSigV4, S3GetObjectWithRange) {
    const auto s = sigv4::sign(sigv4TestRequest("GET", "examplebucket.s3.amazonaws.com", "/test.txt", {}, {{"Range", "bytes=0-9"}}),
                               kSigV4S3Docs, "us-east-1", "s3", k20130524T000000Z);
    EXPECT_EQ(sigv4SignatureOf(s), "f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41");
    EXPECT_NE(s.authorization.find("SignedHeaders=host;range;x-amz-content-sha256;x-amz-date,"), std::string::npos);
    EXPECT_EQ(s.headers.at("x-amz-content-sha256"), sigv4::sha256Hex(""));
}

TEST(UpstreamSigV4, S3SubresourceQuery) {
    const auto s = sigv4::sign(sigv4TestRequest("GET", "examplebucket.s3.amazonaws.com", "/", {{"lifecycle", ""}}), kSigV4S3Docs,
                               "us-east-1", "s3", k20130524T000000Z);
    EXPECT_EQ(s.query_string, "lifecycle=");
    EXPECT_EQ(sigv4SignatureOf(s), "fea454ca298b7da1c68078a5d1bdbfbbe0d65c699e0f91ac7a200a0136783543");
}

TEST(UpstreamSigV4, EncodingRules) {
    EXPECT_EQ(sigv4::uriEncode("a b/c~d", false), "a%20b/c~d");
    EXPECT_EQ(sigv4::uriEncode("a b/c~d", true), "a%20b%2Fc~d");
    EXPECT_EQ(sigv4::uriEncode("é", true), "%C3%A9");
    // S3 encodes key segments once; other services double-encode the canonical path.
    const auto s3 = sigv4::sign(sigv4TestRequest("GET", "h", "/b/a b"), kSigV4Suite, "us-east-1", "s3", k20150830T123600Z);
    EXPECT_EQ(s3.encoded_path, "/b/a%20b");
    EXPECT_NE(s3.canonical_request.find("\n/b/a%20b\n"), std::string::npos);
    const auto other = sigv4::sign(sigv4TestRequest("GET", "h", "/b/a b"), kSigV4Suite, "us-east-1", "sqs", k20150830T123600Z);
    EXPECT_NE(other.canonical_request.find("\n/b/a%2520b\n"), std::string::npos);
    // A session token is sent and signed.
    auto withToken = kSigV4Suite;
    withToken.session_token = "session-token-value";
    const auto t = sigv4::sign(sigv4TestRequest("GET", "h", "/"), withToken, "us-east-1", "sts", k20150830T123600Z);
    EXPECT_EQ(t.headers.at("x-amz-security-token"), "session-token-value");
    EXPECT_NE(t.authorization.find("x-amz-security-token"), std::string::npos);
}
