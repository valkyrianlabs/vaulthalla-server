// The legacy data-plane signer (storage::s3::curl::buildAuthorizationHeader) signs the query in SigV4 canonical order.
// Paged ListObjectsV2 requests are written ?list-type=2&max-keys=N&continuation-token=…, which is out of order; signing
// them as written made every page after the first fail with SignatureDoesNotMatch on AWS.

#include "db/encoding/timestamp.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>

#include <map>
#include <memory>
#include <string>

namespace {

std::shared_ptr<vh::vault::model::APIKey> canonicalQueryTestKey() {
    return std::make_shared<vh::vault::model::APIKey>(0, "unit", vh::vault::model::S3Provider::AWS, "AKIDEXAMPLE",
                                                      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY", "us-east-2",
                                                      "https://s3.us-east-2.amazonaws.com");
}

std::map<std::string, std::string> canonicalQueryTestHeaders() {
    return {
        {"host", "s3.us-east-2.amazonaws.com"},
        {"x-amz-content-sha256", "UNSIGNED-PAYLOAD"},
        {"x-amz-date", vh::db::encoding::getDate() + "T000000Z"},
    };
}

std::string signQuery(const std::string& fullPath, const std::string& canonicalQuery = {}) {
    return vh::storage::s3::curl::buildAuthorizationHeader(canonicalQueryTestKey(), "GET", fullPath,
                                                           canonicalQueryTestHeaders(), "UNSIGNED-PAYLOAD", canonicalQuery);
}

// Independent SigV4 reference over a canonical query the caller already put in order.
std::string referenceSignature(const std::string& path, const std::string& sortedQuery) {
    namespace curl = vh::storage::s3::curl;
    const auto key = canonicalQueryTestKey();
    const auto headers = canonicalQueryTestHeaders();
    const auto date = vh::db::encoding::getDate();
    const std::string canonicalRequest = "GET\n" + path + "\n" + sortedQuery + "\n" +
                                         "host:" + headers.at("host") + "\n" +
                                         "x-amz-content-sha256:UNSIGNED-PAYLOAD\n" +
                                         "x-amz-date:" + headers.at("x-amz-date") + "\n\n" +
                                         "host;x-amz-content-sha256;x-amz-date\nUNSIGNED-PAYLOAD";
    const std::string scope = date + "/" + key->region + "/s3/aws4_request";
    const std::string stringToSign = "AWS4-HMAC-SHA256\n" + headers.at("x-amz-date") + "\n" + scope + "\n" +
                                     curl::sha256Hex(canonicalRequest);
    const auto kDate = curl::hmacSha256Raw("AWS4" + key->secret_access_key, date);
    const auto kSigning = curl::hmacSha256Raw(curl::hmacSha256Raw(curl::hmacSha256Raw(kDate, key->region), "s3"),
                                              "aws4_request");
    return "AWS4-HMAC-SHA256 Credential=" + key->access_key + "/" + scope +
           ", SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature=" +
           curl::hmacSha256HexFromRaw(kSigning, stringToSign);
}

}

TEST(S3CanonicalQueryTest, SortsParametersByNameThenValue) {
    using vh::storage::s3::curl::canonicalQueryString;

    EXPECT_EQ(canonicalQueryString("list-type=2&max-keys=1000&continuation-token=1a%2Bb%2F%3D"),
              "continuation-token=1a%2Bb%2F%3D&list-type=2&max-keys=1000");
    EXPECT_EQ(canonicalQueryString("list-type=2&prefix=dir%2Fsub&continuation-token=t"),
              "continuation-token=t&list-type=2&prefix=dir%2Fsub");
    EXPECT_EQ(canonicalQueryString("uploadId=abc&partNumber=2"), "partNumber=2&uploadId=abc");
    EXPECT_EQ(canonicalQueryString("a=2&b=0&a=1"), "a=1&a=2&b=0");
    // Byte order, as SigV4 specifies: upper case sorts before lower case.
    EXPECT_EQ(canonicalQueryString("b=1&B=2"), "B=2&b=1");
}

TEST(S3CanonicalQueryTest, ValuelessParametersGetAnEmptyValue) {
    using vh::storage::s3::curl::canonicalQueryString;

    EXPECT_EQ(canonicalQueryString("uploads"), "uploads=");
    EXPECT_EQ(canonicalQueryString("versioning"), "versioning=");
    EXPECT_EQ(canonicalQueryString("uploads&prefix=a"), "prefix=a&uploads=");
    EXPECT_EQ(canonicalQueryString(""), "");
    EXPECT_EQ(canonicalQueryString("a=1&&b=2&"), "a=1&b=2");
}

TEST(S3CanonicalQueryTest, DoesNotReencode) {
    using vh::storage::s3::curl::canonicalQueryString;

    EXPECT_EQ(canonicalQueryString("prefix=a%20b&marker=x%2By"), "marker=x%2By&prefix=a%20b");
    EXPECT_EQ(canonicalQueryString("k=a=b"), "k=a=b");
}

TEST(S3CanonicalQueryTest, SignatureIgnoresTheOrderTheQueryWasWrittenIn) {
    const auto sorted = signQuery("/bucket?continuation-token=tok%2B1&list-type=2&max-keys=1000");
    EXPECT_EQ(signQuery("/bucket?list-type=2&max-keys=1000&continuation-token=tok%2B1"), sorted);
    EXPECT_EQ(signQuery("/bucket?max-keys=1000&continuation-token=tok%2B1&list-type=2"), sorted);
    EXPECT_EQ(signQuery("/bucket", "list-type=2&max-keys=1000&continuation-token=tok%2B1"), sorted);
    EXPECT_EQ(sorted, referenceSignature("/bucket", "continuation-token=tok%2B1&list-type=2&max-keys=1000"));
}

TEST(S3CanonicalQueryTest, AlreadyCanonicalQueriesSignAsBefore) {
    // Page 1 of a listing, multipart and flag-only requests were already in order: their signatures must not move.
    EXPECT_EQ(signQuery("/bucket?list-type=2&max-keys=1000"), referenceSignature("/bucket", "list-type=2&max-keys=1000"));
    EXPECT_EQ(signQuery("/bucket/key?partNumber=3&uploadId=u%2Bid"),
              referenceSignature("/bucket/key", "partNumber=3&uploadId=u%2Bid"));
    EXPECT_EQ(signQuery("/bucket/key?uploads"), referenceSignature("/bucket/key", "uploads="));
    EXPECT_EQ(signQuery("/bucket/key"), referenceSignature("/bucket/key", ""));
}
