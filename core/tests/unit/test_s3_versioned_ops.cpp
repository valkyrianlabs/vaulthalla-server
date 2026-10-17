// Version-aware S3 data plane (file recovery, .claude/context/recovery.md), DB-free.
//
// S3VersionedOps*: the real storage::s3::Controller against curl::http's test transport (what is signed and sent,
// how answers are parsed, metering, the protection lock) and the legacy signer's canonical query.
// S3VersionedFake*: the semantics of tests/helpers/versioned_bucket.hpp that later suites rely on.

#include "storage/s3/Controller.hpp"
#include "storage/s3/curl/Http.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"
#include "../helpers/versioned_bucket.hpp"

#include <gtest/gtest.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace s3vtest {

namespace http = vh::storage::s3::curl::http;
namespace s3 = vh::storage::s3;
namespace guard = vh::storage::upstream::guard;
using vh::test_support::versioned::VersionedBucket;
using vh::test_support::versioned::Versioning;

// AWS-shaped version ids carry '+', '/' and '='.
constexpr const char* kAwsVersionId = "3/L4kqtJlcpXroDTDmJ+rmSpXd3dIbrHY+MTRCxf3vjVBH40Nr8X8gdRQBpUMLUo=";
constexpr const char* kAwsVersionIdEncoded = "3%2FL4kqtJlcpXroDTDmJ%2BrmSpXd3dIbrHY%2BMTRCxf3vjVBH40Nr8X8gdRQBpUMLUo%3D";

std::shared_ptr<vh::vault::model::APIKey> awsKey() {
    return std::make_shared<vh::vault::model::APIKey>(1, "recovery-unit", vh::vault::model::S3Provider::AWS,
                                                      "AKIAVERSIONEDUNIT000", "versioned-unit-secret-000000000000000000",
                                                      "us-east-2", "https://s3.us-east-2.amazonaws.com");
}

class ProbeController final : public s3::Controller {
public:
    ProbeController() : Controller(awsKey(), "vh-recovery-bucket") {}

    [[nodiscard]] auto sign(const std::string& method, const std::string& key,
                            const std::vector<std::pair<std::string, std::string>>& query,
                            const std::map<std::string, std::string>& headers = {}) const {
        return signObjectRequest(method, key, query, headers);
    }
};

std::string headerOf(const http::Request& r, const std::string& name) {
    for (const auto& [k, v] : r.headers) {
        std::string lower = k;
        for (auto& c : lower) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lower == name) return v;
    }
    return {};
}

std::string queryOf(const std::string& url) {
    const auto q = url.find('?');
    return q == std::string::npos ? std::string{} : url.substr(q + 1);
}

std::string pathOf(const std::string& url) {
    const auto scheme = url.find("://");
    const auto slash = url.find('/', scheme == std::string::npos ? 0 : scheme + 3);
    const auto q = url.find('?');
    return url.substr(slash, q == std::string::npos ? std::string::npos : q - slash);
}

// Line 3 of a SigV4 canonical request is the canonical query.
std::string canonicalQueryLine(const std::string& canonicalRequest) {
    const auto first = canonicalRequest.find('\n');
    const auto second = canonicalRequest.find('\n', first + 1);
    const auto third = canonicalRequest.find('\n', second + 1);
    return canonicalRequest.substr(second + 1, third - second - 1);
}

http::Response answer(const long status, std::string body = {}, std::vector<std::pair<std::string, std::string>> headers = {}) {
    http::Response r;
    r.status = status;
    r.body = std::move(body);
    r.headers = std::move(headers);
    return r;
}

std::vector<uint8_t> bytesOf(const std::string& s) { return {s.begin(), s.end()}; }

std::string readAll(const s3::Controller& c, const std::string& key, const s3::GetObjectOptions& options) {
    std::string out;
    c.streamObject(key, options, [&](const std::span<const uint8_t> chunk) { out.append(chunk.begin(), chunk.end()); });
    return out;
}

// ---- real Controller over the HTTP test transport --------------------------------------------------------------------

class S3VersionedOpsTest : public ::testing::Test {
protected:
    std::vector<http::Request> sent;
    std::function<http::Response(const http::Request&)> handler;
    ProbeController controller;

    void SetUp() override {
        guard::setForTesting({});
        s3::Controller::resetLastPutOutcome();
        http::setTransportForTesting([this](const http::Request& r) {
            sent.push_back(r);
            return handler ? handler(r) : answer(500);
        });
    }

    void TearDown() override {
        http::setTransportForTesting(std::nullopt);
        guard::clearForTesting();
    }
};

TEST(S3VersionedOpsSigning, LegacyCanonicalQueryIsSortedAndUnchangedWhenAlreadyCanonical) {
    using vh::storage::s3::curl::canonicalQueryString;
    EXPECT_EQ("continuation-token=abc%2Bdef&list-type=2&max-keys=1000",
              canonicalQueryString("list-type=2&max-keys=1000&continuation-token=abc%2Bdef"));
    EXPECT_EQ("uploads=", canonicalQueryString("uploads"));
    EXPECT_EQ("partNumber=3&uploadId=xyz", canonicalQueryString("partNumber=3&uploadId=xyz"));
    EXPECT_EQ("list-type=2&max-keys=1", canonicalQueryString("list-type=2&max-keys=1"));
    EXPECT_EQ("versionId=a%2Fb%3D", canonicalQueryString("versionId=a%2Fb%3D"));
    // Sorted by name, then value: "a" before "a-b" although '-' < '='.
    EXPECT_EQ("a=1&a-b=2", canonicalQueryString("a-b=2&a=1"));
    EXPECT_EQ("", canonicalQueryString(""));

    // The legacy signer signs the canonical order whatever order the URL carries.
    const auto key = awsKey();
    const std::map<std::string, std::string> headers{{"host", "s3.us-east-2.amazonaws.com"},
                                                     {"x-amz-content-sha256", "UNSIGNED-PAYLOAD"},
                                                     {"x-amz-date", "20261016T120000Z"}};
    using vh::storage::s3::curl::buildAuthorizationHeader;
    const auto a = buildAuthorizationHeader(key, "GET", "/b?list-type=2&continuation-token=t", headers, "UNSIGNED-PAYLOAD");
    const auto b = buildAuthorizationHeader(key, "GET", "/b?continuation-token=t&list-type=2", headers, "UNSIGNED-PAYLOAD");
    EXPECT_EQ(a, b);
}

TEST(S3VersionedOpsSigning, HeaderLookupTakesTheFinalResponseBlock) {
    using vh::storage::s3::curl::lastHeaderValue;
    const std::string raw =
        "HTTP/1.1 100 Continue\r\nx-amz-version-id: stale\r\n\r\n"
        "HTTP/1.1 200 OK\r\nETag: \"abc\"\r\nX-Amz-Version-Id: 3/L4+x=\r\n\r\n";
    EXPECT_EQ("\"abc\"", lastHeaderValue(raw, "etag").value_or(""));
    EXPECT_EQ("3/L4+x=", lastHeaderValue(raw, "x-amz-version-id").value_or(""));
    EXPECT_FALSE(lastHeaderValue("HTTP/1.1 200 OK\r\nx-amz-version-id: a\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
                                 "x-amz-version-id"));
    EXPECT_EQ("\"e\"", lastHeaderValue("ETag: \"e\"\r\n", "etag").value_or(""));   // fakes send no status line
}

TEST(S3VersionedOpsSigning, VersionIdIsEncodedOnceForTheUrlAndTheSignature) {
    const ProbeController controller;
    const auto request = controller.sign("GET", "dir/a b+c.txt", {{"versionId", kAwsVersionId}},
                                         {{"if-match", "\"etag\""}, {"range", "bytes=0-9"}});
    EXPECT_EQ("https://s3.us-east-2.amazonaws.com/vh-recovery-bucket/dir/a%20b%2Bc.txt?versionId=" +
                  std::string(kAwsVersionIdEncoded),
              request.url);
    EXPECT_EQ(queryOf(request.url), canonicalQueryLine(request.canonical_request))
        << "the URL must carry exactly the signed query";
    EXPECT_NE(std::string::npos, request.canonical_request.find("/vh-recovery-bucket/dir/a%20b%2Bc.txt\n"));

    bool authorization = false;
    for (const auto& [name, value] : request.headers) {
        EXPECT_NE("host", name) << "curl derives Host from the URL";
        if (name == "authorization") {
            authorization = true;
            EXPECT_NE(std::string::npos, value.find("/us-east-2/s3/aws4_request"));
            EXPECT_NE(std::string::npos, value.find("if-match;range;"));
            EXPECT_EQ(std::string::npos, value.find("versioned-unit-secret")) << "the secret never travels";
        }
    }
    EXPECT_TRUE(authorization);

    // Several parameters: sorted and encoded identically in both places.
    const auto list = controller.sign("GET", {}, {{"versions", ""}, {"prefix", "a/b c"}, {"key-marker", "k+1"},
                                                  {"version-id-marker", kAwsVersionId}, {"max-keys", "10"}});
    EXPECT_EQ("key-marker=k%2B1&max-keys=10&prefix=a%2Fb%20c&version-id-marker=" + std::string(kAwsVersionIdEncoded) +
                  "&versions=",
              queryOf(list.url));
    EXPECT_EQ(queryOf(list.url), canonicalQueryLine(list.canonical_request));
    EXPECT_EQ("/vh-recovery-bucket", pathOf(list.url));
}

TEST_F(S3VersionedOpsTest, HeadVersionParsesMetadataAndRecordsTheOutcome) {
    handler = [](const http::Request&) {
        return answer(200, {}, {{"ETag", "\"0123abcd\""},
                                {"Content-Length", "1048576"},
                                {"Last-Modified", "Wed, 12 Oct 2026 17:50:00 GMT"},
                                {"x-amz-version-id", kAwsVersionId},
                                {"x-amz-storage-class", "STANDARD_IA"},
                                {"X-Amz-Meta-VH-IV", "aXZpdml2aXZpdml2"},
                                {"x-amz-meta-vh-key-version", "3"},
                                {"x-amz-meta-vh-encrypted", "true"},
                                {"x-amz-meta-content-hash", "deadbeef"},
                                {"Content-Type", "application/octet-stream"}});
    };
    s3::Controller::resetLastHeadOutcome();
    const auto head = controller.headObjectVersion("docs/report.pdf", kAwsVersionId);
    ASSERT_TRUE(head);
    ASSERT_EQ(1u, sent.size());
    EXPECT_EQ("HEAD", sent[0].method);
    EXPECT_EQ("versionId=" + std::string(kAwsVersionIdEncoded), queryOf(sent[0].url));
    EXPECT_EQ("/vh-recovery-bucket/docs/report.pdf", pathOf(sent[0].url));
    EXPECT_FALSE(headerOf(sent[0], "authorization").empty());

    EXPECT_FALSE(head->delete_marker);
    EXPECT_EQ(kAwsVersionId, head->version_id);
    EXPECT_EQ("\"0123abcd\"", head->etag);
    EXPECT_EQ(1048576u, head->content_length);
    EXPECT_EQ(std::optional<std::string>("STANDARD_IA"), head->storage_class);
    ASSERT_TRUE(head->last_modified);
    EXPECT_EQ(1791827400, *head->last_modified);   // 2026-10-12T17:50:00Z
    EXPECT_EQ("aXZpdml2aXZpdml2", head->metadata.at("vh-iv"));
    EXPECT_EQ("3", head->metadata.at("vh-key-version"));
    EXPECT_EQ("true", head->metadata.at("vh-encrypted"));
    EXPECT_EQ("deadbeef", head->metadata.at("content-hash"));
    EXPECT_EQ(4u, head->metadata.size()) << "only x-amz-meta-* headers are metadata";

    const auto outcome = s3::Controller::lastHeadOutcome();
    EXPECT_TRUE(outcome.performed);
    EXPECT_EQ(200, outcome.http_status);
    EXPECT_EQ(1u, controller.requestMetrics().head_requests);
}

TEST_F(S3VersionedOpsTest, HeadVersionSeparatesAbsenceDeleteMarkersAndOutages) {
    handler = [](const http::Request&) { return answer(404); };
    EXPECT_FALSE(controller.headObjectVersion("k", "v1"));
    EXPECT_EQ(404, s3::Controller::lastHeadOutcome().http_status);

    handler = [](const http::Request&) {
        return answer(405, {}, {{"x-amz-delete-marker", "true"}, {"x-amz-version-id", "dm1"},
                                {"Last-Modified", "Thu, 01 Jan 2026 00:00:00 GMT"}, {"Allow", "DELETE"}});
    };
    const auto marker = controller.headObjectVersion("k", "dm1");
    ASSERT_TRUE(marker);
    EXPECT_TRUE(marker->delete_marker);
    EXPECT_EQ("dm1", marker->version_id);
    EXPECT_EQ(std::optional<std::time_t>(1767225600), marker->last_modified);

    handler = [](const http::Request&) { return answer(405); };   // 405 without the delete-marker header
    EXPECT_THROW((void)controller.headObjectVersion("k", "v1"), std::runtime_error);

    handler = [](const http::Request&) { return answer(503); };
    EXPECT_THROW((void)controller.headObjectVersion("k", "v1"), std::runtime_error);
    EXPECT_EQ(503, s3::Controller::lastHeadOutcome().http_status);

    handler = [](const http::Request&) { return answer(403); };
    EXPECT_THROW((void)controller.headObjectVersion("k", "v1"), std::runtime_error);

    handler = [](const http::Request&) {
        http::Response r;
        r.transport_ok = false;
        r.transport_error = "Connection refused";
        return r;
    };
    EXPECT_THROW((void)controller.headObjectVersion("k", "v1"), std::runtime_error);
    EXPECT_FALSE(s3::Controller::lastHeadOutcome().transport_ok);

    EXPECT_THROW((void)controller.headObjectVersion("k", ""), std::invalid_argument);
    EXPECT_EQ(6u, sent.size()) << "an empty version id is refused before sending";
    EXPECT_EQ(6u, controller.requestMetrics().head_requests);
}

TEST_F(S3VersionedOpsTest, ListObjectVersionsParsesVersionsDeleteMarkersAndMarkers) {
    handler = [](const http::Request&) {
        return answer(200, R"(<?xml version="1.0" encoding="UTF-8"?>
<ListVersionsResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>vh-recovery-bucket</Name><Prefix>docs/</Prefix><KeyMarker></KeyMarker><VersionIdMarker></VersionIdMarker>
  <NextKeyMarker>docs/b.txt</NextKeyMarker><NextVersionIdMarker>3/L4+older=</NextVersionIdMarker>
  <MaxKeys>4</MaxKeys><IsTruncated>true</IsTruncated>
  <DeleteMarker><Key>docs/a&amp;b.txt</Key><VersionId>dm+1/=</VersionId><IsLatest>true</IsLatest>
    <LastModified>2026-10-12T17:50:30.000Z</LastModified><Owner><ID>o</ID></Owner></DeleteMarker>
  <Version><Key>docs/a&amp;b.txt</Key><VersionId>v+2/=</VersionId><IsLatest>false</IsLatest>
    <LastModified>2026-10-11T10:00:00.000Z</LastModified><ETag>"aaaa"</ETag><Size>12</Size>
    <StorageClass>STANDARD</StorageClass></Version>
  <Version><Key>docs/b.txt</Key><VersionId>null</VersionId><IsLatest>true</IsLatest>
    <LastModified>2026-10-10T10:00:00.000Z</LastModified><ETag>"bbbb-2"</ETag><Size>10485760</Size>
    <StorageClass>GLACIER</StorageClass></Version>
  <Version><Key>docs/b.txt</Key><VersionId>3/L4+older=</VersionId><IsLatest>false</IsLatest>
    <LastModified>2026-10-09T10:00:00.000Z</LastModified><ETag>"cccc"</ETag><Size>0</Size></Version>
</ListVersionsResult>)");
    };
    const auto page = controller.listObjectVersionsPage("docs/", "docs/0", kAwsVersionId, 4);
    ASSERT_EQ(1u, sent.size());
    EXPECT_EQ("GET", sent[0].method);
    EXPECT_EQ("key-marker=docs%2F0&max-keys=4&prefix=docs%2F&version-id-marker=" + std::string(kAwsVersionIdEncoded) +
                  "&versions=",
              queryOf(sent[0].url));
    EXPECT_EQ(1u, controller.requestMetrics().list_requests);
    EXPECT_EQ(0u, controller.requestMetrics().get_requests);

    ASSERT_EQ(4u, page.versions.size());
    EXPECT_TRUE(page.truncated);
    EXPECT_EQ("docs/b.txt", page.next_key_marker);
    EXPECT_EQ("3/L4+older=", page.next_version_id_marker);

    const auto& marker = page.versions[0];
    EXPECT_EQ("docs/a&b.txt", marker.key);
    EXPECT_EQ("dm+1/=", marker.version_id);
    EXPECT_TRUE(marker.delete_marker);
    EXPECT_TRUE(marker.is_latest);
    EXPECT_FALSE(marker.storage_class);
    EXPECT_EQ(std::optional<std::time_t>(1791827430), marker.last_modified);

    const auto& old = page.versions[1];
    EXPECT_FALSE(old.delete_marker);
    EXPECT_FALSE(old.is_latest);
    EXPECT_EQ("\"aaaa\"", old.etag);
    EXPECT_EQ(12u, old.size);
    EXPECT_EQ(std::optional<std::string>("STANDARD"), old.storage_class);

    EXPECT_EQ("null", page.versions[2].version_id);
    EXPECT_EQ(10485760u, page.versions[2].size);
    EXPECT_EQ(std::optional<std::string>("GLACIER"), page.versions[2].storage_class);
    EXPECT_FALSE(page.versions[3].storage_class);
}

TEST_F(S3VersionedOpsTest, ListObjectVersionsNeverReturnsAPartialListing) {
    handler = [](const http::Request&) {
        return answer(200, "<ListVersionsResult><IsTruncated>true</IsTruncated><Version><Key>a</Key>"
                           "<VersionId>v</VersionId><Size>1</Size></Version></ListVersionsResult>");
    };
    EXPECT_THROW((void)controller.listObjectVersionsPage(""), std::runtime_error) << "truncated without NextKeyMarker";

    handler = [](const http::Request&) { return answer(200, "<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>"); };
    const auto empty = controller.listObjectVersionsPage("");
    EXPECT_TRUE(empty.versions.empty());
    EXPECT_FALSE(empty.truncated);
    EXPECT_EQ("max-keys=1000&versions=", queryOf(sent.back().url));

    handler = [](const http::Request&) {
        return answer(403, "<Error><Code>AccessDenied</Code><Message>Access Denied</Message></Error>");
    };
    try {
        (void)controller.listObjectVersionsPage("");
        ADD_FAILURE() << "403 must throw";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("AccessDenied"));
    }

    handler = [](const http::Request&) { return answer(200, "not xml <"); };
    EXPECT_THROW((void)controller.listObjectVersionsPage(""), std::runtime_error);

    const auto before = sent.size();
    EXPECT_THROW((void)controller.listObjectVersionsPage("", {}, "v1"), std::invalid_argument);
    EXPECT_EQ(before, sent.size());
    EXPECT_EQ(before, controller.requestMetrics().list_requests) << "refused before metering";
}

TEST_F(S3VersionedOpsTest, CopyObjectVersionSendsCopySourceWithDirectiveCopy) {
    handler = [](const http::Request&) {
        return answer(200,
                      "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<CopyObjectResult><LastModified>2026-10-16T00:00:00.000Z"
                      "</LastModified><ETag>&quot;9b2cf535f27731c974343645a3985328&quot;</ETag></CopyObjectResult>",
                      {{"x-amz-version-id", "new+v/1="}, {"x-amz-copy-source-version-id", kAwsVersionId}});
    };
    s3::RequestOptions options;
    options.system_headers["X-Amz-Storage-Class"] = "STANDARD_IA";
    options.metadata["vh-iv"] = "must-not-be-sent";
    const auto result = controller.copyObjectVersion("dir/a b+c.txt", kAwsVersionId, "dir/a b+c.txt", 1024, options,
                                                     std::string("\"src-etag\""));
    ASSERT_EQ(1u, sent.size());
    const auto& r = sent[0];
    EXPECT_EQ("PUT", r.method);
    EXPECT_EQ("/vh-recovery-bucket/dir/a%20b%2Bc.txt", pathOf(r.url));
    EXPECT_EQ("", queryOf(r.url));
    EXPECT_EQ("/vh-recovery-bucket/dir/a%20b%2Bc.txt?versionId=" + std::string(kAwsVersionIdEncoded),
              headerOf(r, "x-amz-copy-source"));
    EXPECT_EQ("COPY", headerOf(r, "x-amz-metadata-directive"));
    EXPECT_EQ("\"src-etag\"", headerOf(r, "x-amz-copy-source-if-match"));
    EXPECT_EQ("STANDARD_IA", headerOf(r, "x-amz-storage-class"));
    for (const auto& [name, value] : r.headers)
        EXPECT_FALSE(name.starts_with("x-amz-meta-")) << "COPY keeps the source metadata; never send replacements";
    const auto auth = headerOf(r, "authorization");
    EXPECT_NE(std::string::npos, auth.find("x-amz-copy-source;x-amz-copy-source-if-match;"));
    EXPECT_NE(std::string::npos, auth.find("x-amz-metadata-directive;"));
    EXPECT_TRUE(r.body.empty());

    EXPECT_EQ("\"9b2cf535f27731c974343645a3985328\"", result.etag);
    EXPECT_EQ(std::optional<std::string>("new+v/1="), result.version_id);
    const auto outcome = s3::Controller::lastPutOutcome();
    EXPECT_EQ(result.etag, outcome.etag);
    EXPECT_EQ(result.version_id, outcome.version_id);

    const auto metrics = controller.requestMetrics();
    EXPECT_EQ(1u, metrics.copy_requests);
    EXPECT_EQ(0u, metrics.put_requests);
    EXPECT_EQ(0u, metrics.uploaded_bytes);
}

TEST_F(S3VersionedOpsTest, CopyObjectVersionFailuresIncludingErrorAfter200) {
    handler = [](const http::Request&) {
        return answer(200, "<?xml version=\"1.0\"?>\n<Error><Code>InternalError</Code><Message>We encountered an internal "
                           "error. Please try again.</Message></Error>");
    };
    s3::Controller::recordPutOutcomeForTesting({.etag = "\"stale\"", .version_id = std::string("stale")});
    try {
        (void)controller.copyObjectVersion("k", "v1", "k", 10, {});
        ADD_FAILURE() << "a 200 carrying <Error> is a failed copy";
    } catch (const s3::ObjectNotFound&) {
        ADD_FAILURE() << "wrong type";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string::npos, std::string(e.what()).find("InternalError"));
    }
    EXPECT_TRUE(s3::Controller::lastPutOutcome().etag.empty()) << "a failed copy leaves no outcome";
    EXPECT_FALSE(s3::Controller::lastPutOutcome().version_id);

    handler = [](const http::Request&) { return answer(200, ""); };
    EXPECT_THROW((void)controller.copyObjectVersion("k", "v1", "k", 10, {}), std::runtime_error);

    handler = [](const http::Request&) { return answer(404, "<Error><Code>NoSuchVersion</Code></Error>"); };
    EXPECT_THROW((void)controller.copyObjectVersion("k", "v1", "k", 10, {}), s3::ObjectNotFound);

    handler = [](const http::Request&) { return answer(412, "<Error><Code>PreconditionFailed</Code></Error>"); };
    EXPECT_THROW((void)controller.copyObjectVersion("k", "v1", "k", 10, {}, std::string("\"x\"")),
                 s3::ConditionalRequestFailed);

    handler = [](const http::Request&) {
        return answer(400, "<Error><Code>InvalidRequest</Code><Message>This copy request is illegal</Message></Error>");
    };
    EXPECT_THROW((void)controller.copyObjectVersion("k", "v1", "k", 10, {}), std::runtime_error);
    EXPECT_EQ(5u, controller.requestMetrics().copy_requests);
}

TEST_F(S3VersionedOpsTest, CopyLargerThanFiveGiBIsRefusedBeforeAnyRequest) {
    handler = [](const http::Request&) { return answer(200, "<CopyObjectResult><ETag>\"e\"</ETag></CopyObjectResult>"); };
    EXPECT_THROW((void)controller.copyObjectVersion("big.bin", "v1", "big.bin", s3::Controller::MAX_SINGLE_COPY_BYTES + 1, {}),
                 s3::ObjectTooLargeForCopy);
    EXPECT_TRUE(sent.empty());
    EXPECT_EQ(0u, controller.requestMetrics().copy_requests);

    (void)controller.copyObjectVersion("edge.bin", "v1", "edge.bin", s3::Controller::MAX_SINGLE_COPY_BYTES, {});
    EXPECT_EQ(1u, sent.size()) << "exactly 5 GiB is still one CopyObject";
    EXPECT_EQ(5368709120ULL, s3::Controller::MAX_SINGLE_COPY_BYTES);
}

TEST_F(S3VersionedOpsTest, ProtectedBucketRefusesEveryVersionOpBeforeSending) {
    handler = [](const http::Request&) { return answer(200, "<ListVersionsResult/>"); };
    guard::setForTesting({vh::storage::upstream::identityFor(*awsKey(), "vh-recovery-bucket")});

    EXPECT_THROW((void)controller.listObjectVersionsPage("docs/"), vh::storage::upstream::BucketProtected);
    EXPECT_THROW((void)controller.headObjectVersion("k", "v1"), vh::storage::upstream::BucketProtected);
    EXPECT_THROW((void)controller.copyObjectVersion("k", "v1", "k", 1, {}), vh::storage::upstream::BucketProtected);
    EXPECT_TRUE(sent.empty());
    const auto metrics = controller.requestMetrics();
    EXPECT_EQ(0u, metrics.list_requests + metrics.head_requests + metrics.copy_requests);

    // Unlocked again: the same controller works without being rebuilt.
    guard::setForTesting({});
    (void)controller.listObjectVersionsPage("docs/");
    EXPECT_EQ(1u, sent.size());
}

TEST_F(S3VersionedOpsTest, RequestBudgetsAndUsageCapturesRefuseBeforeSending) {
    handler = [](const http::Request&) { return answer(404); };
    controller.setRequestBudget({.max_list_requests = 0, .max_head_requests = 1, .max_get_requests = std::nullopt,
                                 .max_put_requests = std::nullopt, .max_copy_requests = 0,
                                 .max_delete_requests = std::nullopt, .max_downloaded_bytes = std::nullopt});
    EXPECT_THROW((void)controller.listObjectVersionsPage(""), s3::RequestBudgetExceeded);
    EXPECT_THROW((void)controller.copyObjectVersion("k", "v1", "k", 1, {}), s3::RequestBudgetExceeded);
    EXPECT_FALSE(controller.headObjectVersion("k", "v1"));
    EXPECT_THROW((void)controller.headObjectVersion("k", "v1"), s3::RequestBudgetExceeded);
    EXPECT_EQ(1u, sent.size());
    controller.clearRequestBudget();

    // Each op is metered as its own kind (the same recordRequest feeds every per-thread usage capture).
    controller.resetRequestMetrics();
    handler = [](const http::Request& r) {
        if (r.method == "PUT") return answer(200, "<CopyObjectResult><ETag>\"e\"</ETag></CopyObjectResult>");
        if (r.method == "HEAD") return answer(200, {}, {{"ETag", "\"e\""}, {"Content-Length", "1"}});
        return answer(200, "<ListVersionsResult><IsTruncated>false</IsTruncated></ListVersionsResult>");
    };
    (void)controller.listObjectVersionsPage("");
    (void)controller.headObjectVersion("k", "v1");
    (void)controller.copyObjectVersion("k", "v1", "k2", 1, {});
    const auto metrics = controller.requestMetrics();
    EXPECT_EQ(1u, metrics.list_requests);
    EXPECT_EQ(1u, metrics.head_requests);
    EXPECT_EQ(1u, metrics.copy_requests);
    EXPECT_EQ(0u, metrics.get_requests);
    EXPECT_EQ(0u, metrics.put_requests);
    EXPECT_EQ(0u, metrics.downloaded_bytes);
}

// ---- the versioned fake ----------------------------------------------------------------------------------------------

TEST(S3VersionedFake, VersioningModesFollowS3) {
    VersionedBucket bucket(Versioning::Unversioned);
    bucket.seed("a.txt", "one");
    bucket.seed("a.txt", "two");
    ASSERT_EQ(1u, bucket.history("a.txt").size()) << "unversioned keeps one version";
    EXPECT_EQ("null", bucket.history("a.txt")[0].version_id);

    bucket.setVersioning(Versioning::Enabled);
    const auto v3 = bucket.seed("a.txt", "three");
    EXPECT_NE("null", v3);
    EXPECT_NE(std::string::npos, v3.find('+'));
    EXPECT_NE(std::string::npos, v3.find('/'));
    EXPECT_NE(std::string::npos, v3.find('='));
    auto history = bucket.history("a.txt");
    ASSERT_EQ(2u, history.size());
    EXPECT_EQ(v3, history[0].version_id);
    EXPECT_EQ("null", history[1].version_id) << "pre-versioning objects keep the null version";
    EXPECT_LT(history[1].last_modified, history[0].last_modified);

    const auto marker = bucket.seedDeleteMarker("a.txt");
    EXPECT_FALSE(bucket.current("a.txt"));
    ASSERT_EQ(3u, bucket.history("a.txt").size());
    EXPECT_TRUE(bucket.history("a.txt")[0].delete_marker);
    EXPECT_EQ(marker, bucket.history("a.txt")[0].version_id);
    EXPECT_FALSE(bucket.seedDeleteMarker("never-existed.txt").empty()) << "S3 marks absent keys too";

    bucket.setVersioning(Versioning::Suspended);
    bucket.seed("a.txt", "four");
    bucket.seed("a.txt", "five");
    history = bucket.history("a.txt");
    ASSERT_EQ(3u, history.size()) << "suspended writes replace the single null version";
    EXPECT_EQ("null", history[0].version_id);
    EXPECT_EQ(bytesOf("five"), history[0].body);
    EXPECT_EQ(marker, history[1].version_id);
    EXPECT_EQ(v3, history[2].version_id);
    bucket.seedDeleteMarker("a.txt");
    history = bucket.history("a.txt");
    ASSERT_EQ(3u, history.size());
    EXPECT_TRUE(history[0].delete_marker);
    EXPECT_EQ("null", history[0].version_id);

    EXPECT_TRUE(bucket.purgeVersion("a.txt", v3));
    EXPECT_FALSE(bucket.version("a.txt", v3));
    EXPECT_EQ(0u, bucket.counters().put) << "seeding is never metered";
}

TEST(S3VersionedFake, PutOutcomesAndVersionedGetsThroughTheRealStreamPath) {
    VersionedBucket bucket(Versioning::Enabled);
    s3::RequestOptions options;
    options.metadata = {{"vh-iv", "iv-1"}, {"vh-key-version", "1"}};
    bucket.uploadBufferWithMetadata("f.bin", bytesOf("first"), options);
    const auto first = s3::Controller::lastPutOutcome();
    ASSERT_TRUE(first.version_id);
    EXPECT_FALSE(first.etag.empty());

    options.metadata = {{"vh-iv", "iv-2"}, {"vh-key-version", "2"}};
    bucket.uploadBufferWithMetadata("f.bin", bytesOf("second!"), options);
    const auto second = s3::Controller::lastPutOutcome();
    ASSERT_TRUE(second.version_id);
    EXPECT_NE(*first.version_id, *second.version_id);

    EXPECT_EQ("second!", readAll(bucket, "f.bin", {}));
    s3::GetObjectOptions old;
    old.version_id = first.version_id;
    EXPECT_EQ("first", readAll(bucket, "f.bin", old));
    old.if_match = first.etag;
    old.range = std::make_pair<uint64_t, uint64_t>(1, 3);
    EXPECT_EQ("irs", readAll(bucket, "f.bin", old));
    old.if_match = second.etag;
    EXPECT_THROW(readAll(bucket, "f.bin", old), s3::ConditionalRequestFailed);

    s3::GetObjectOptions missing;
    missing.version_id = "no-such-version";
    EXPECT_THROW(readAll(bucket, "f.bin", missing), s3::ObjectNotFound);

    bucket.deleteObject("f.bin");
    EXPECT_THROW(readAll(bucket, "f.bin", {}), s3::ObjectNotFound);
    s3::GetObjectOptions markerGet;
    markerGet.version_id = bucket.history("f.bin")[0].version_id;
    EXPECT_THROW(readAll(bucket, "f.bin", markerGet), s3::ObjectNotFound) << "a delete marker has no bytes (405)";
    s3::GetObjectOptions stillThere;
    stillThere.version_id = second.version_id;
    EXPECT_EQ("second!", readAll(bucket, "f.bin", stillThere)) << "noncurrent versions survive a delete";

    const auto metrics = bucket.requestMetrics();
    EXPECT_EQ(2u, metrics.put_requests);
    EXPECT_EQ(1u, metrics.delete_requests);
    EXPECT_EQ(8u, metrics.get_requests);
    EXPECT_EQ(4u, bucket.counters().body_gets) << "412/404/405 answers deliver no object bytes";

    VersionedBucket plain(Versioning::Unversioned);
    plain.uploadBufferWithMetadata("p", bytesOf("x"), s3::RequestOptions{});
    EXPECT_FALSE(s3::Controller::lastPutOutcome().version_id) << "unversioned PUTs carry no version id";
    VersionedBucket suspended(Versioning::Suspended);
    suspended.uploadBufferWithMetadata("p", bytesOf("x"), s3::RequestOptions{});
    EXPECT_EQ(std::optional<std::string>("null"), s3::Controller::lastPutOutcome().version_id);
}

TEST(S3VersionedFake, MultipartUploadsGoThroughTheRealDriverAndRecordTheOutcome) {
    VersionedBucket bucket(Versioning::Enabled);
    s3::RequestOptions options;
    options.metadata = {{"vh-iv", "iv"}};
    bucket.uploadLargeObject("big.bin", bytesOf("0123456789"), 4, options);
    const auto outcome = s3::Controller::lastPutOutcome();
    ASSERT_TRUE(outcome.version_id);
    EXPECT_TRUE(outcome.etag.ends_with("-3\"")) << outcome.etag;
    const auto current = bucket.current("big.bin");
    ASSERT_TRUE(current);
    EXPECT_EQ(bytesOf("0123456789"), current->body);
    EXPECT_EQ("iv", current->meta.at("vh-iv"));
    EXPECT_EQ(5u, bucket.requestMetrics().put_requests) << "initiate + 3 parts + complete";
    EXPECT_EQ(10u, bucket.requestMetrics().uploaded_bytes);
}

TEST(S3VersionedFake, ListObjectVersionsPaginatesWithoutDownloading) {
    VersionedBucket bucket(Versioning::Enabled);
    std::vector<std::string> expected;
    for (const auto* key : {"d/a", "d/b", "d/c", "e/x"}) {
        for (int i = 0; i < 3; ++i) bucket.seed(key, std::string(key) + std::to_string(i));
    }
    bucket.seedDeleteMarker("d/b");
    for (const auto* key : {"d/a", "d/b", "d/c"})
        for (const auto& v : bucket.history(key)) expected.push_back(std::string(key) + "@" + v.version_id);

    std::vector<std::string> listed;
    std::string keyMarker, versionMarker;
    unsigned pages = 0;
    for (;;) {
        const auto page = bucket.listObjectVersionsPage("d/", keyMarker, versionMarker, 2);
        ++pages;
        for (const auto& v : page.versions) {
            listed.push_back(v.key + "@" + v.version_id);
            if (v.key == "d/b" && v.is_latest) {
                EXPECT_TRUE(v.delete_marker);
            }
            if (!v.delete_marker) {
                EXPECT_EQ(std::optional<std::string>("STANDARD"), v.storage_class);
            }
        }
        if (!page.truncated) break;
        keyMarker = page.next_key_marker;
        versionMarker = page.next_version_id_marker;
    }
    EXPECT_EQ(expected, listed);
    EXPECT_EQ(5u, pages);   // 10 entries, 2 per page
    EXPECT_EQ(pages, bucket.counters().list);
    EXPECT_EQ(0u, bucket.counters().body_gets) << "listing never downloads";
    EXPECT_EQ(0u, bucket.counters().get);

    // A key marker alone skips every version of that key.
    const auto after = bucket.listObjectVersionsPage("d/", "d/b");
    ASSERT_FALSE(after.versions.empty());
    EXPECT_EQ("d/c", after.versions[0].key);

    // ListObjectsV2 shows only live keys.
    const auto keys = bucket.listObjectKeysPage({}, 1000);
    EXPECT_EQ((std::vector<std::string>{"d/a", "d/c", "e/x"}), keys.keys);
}

TEST(S3VersionedFake, CopyRestoresAVersionWithItsMetadata) {
    VersionedBucket bucket(Versioning::Enabled);
    const auto v1 = bucket.seed("r.txt", bytesOf("original"), {{"vh-iv", "iv-1"}, {"vh-key-version", "1"},
                                                               {"content-hash", "h1"}});
    bucket.seed("r.txt", bytesOf("overwritten"), {{"vh-iv", "iv-2"}, {"vh-key-version", "2"}});

    const auto head = bucket.headObjectVersion("r.txt", v1);
    ASSERT_TRUE(head);
    EXPECT_EQ("iv-1", head->metadata.at("vh-iv"));
    EXPECT_EQ(0u, bucket.counters().body_gets);

    s3::RequestOptions options;
    options.system_headers["x-amz-storage-class"] = "STANDARD_IA";
    const auto result = bucket.copyObjectVersion("r.txt", v1, "r.txt", head->content_length, options, head->etag);
    ASSERT_TRUE(result.version_id);
    EXPECT_EQ(head->etag, result.etag);
    const auto current = bucket.current("r.txt");
    ASSERT_TRUE(current);
    EXPECT_EQ(bytesOf("original"), current->body);
    EXPECT_EQ("iv-1", current->meta.at("vh-iv"));
    EXPECT_EQ("1", current->meta.at("vh-key-version"));
    EXPECT_EQ("h1", current->meta.at("content-hash"));
    EXPECT_EQ(std::optional<std::string>("STANDARD_IA"), current->storage_class);
    EXPECT_EQ(3u, bucket.history("r.txt").size());
    EXPECT_EQ(result.version_id, s3::Controller::lastPutOutcome().version_id);
    EXPECT_EQ(0u, bucket.counters().body_gets) << "a provider copy moves no bytes through the host";
    EXPECT_EQ(1u, bucket.requestMetrics().copy_requests);

    // Copying the current version onto itself is refused like AWS; a stale If-Match and a missing version too.
    EXPECT_THROW((void)bucket.copyObjectVersion("r.txt", *result.version_id, "r.txt", 8, {}), std::runtime_error);
    EXPECT_THROW((void)bucket.copyObjectVersion("r.txt", v1, "r.txt", 8, {}, std::string("\"stale\"")),
                 s3::ConditionalRequestFailed);
    EXPECT_THROW((void)bucket.copyObjectVersion("r.txt", "nope", "r.txt", 8, {}), s3::ObjectNotFound);

    // > 5 GiB: refused before metering, whatever the bucket holds.
    const auto huge = bucket.seed("huge.bin", bytesOf("x"), {}, std::nullopt, s3::Controller::MAX_SINGLE_COPY_BYTES + 1);
    const auto copies = bucket.requestMetrics().copy_requests;
    EXPECT_THROW((void)bucket.copyObjectVersion("huge.bin", huge, "huge.bin",
                                                bucket.version("huge.bin", huge)->size(), {}),
                 s3::ObjectTooLargeForCopy);
    EXPECT_EQ(copies, bucket.requestMetrics().copy_requests);
}

TEST(S3VersionedFake, FailureInjectionBudgetsAndHeadOutcomes) {
    VersionedBucket bucket(Versioning::Enabled);
    const auto v1 = bucket.seed("k", "body");

    bucket.failNext(VersionedBucket::Op::Head, VersionedBucket::Failure::Http503);
    EXPECT_THROW((void)bucket.headObjectVersion("k", v1), std::runtime_error);
    EXPECT_EQ(503, s3::Controller::lastHeadOutcome().http_status);
    EXPECT_EQ(1u, bucket.requestMetrics().head_requests) << "a failed request still costs a request";
    EXPECT_TRUE(bucket.headObjectVersion("k", v1));

    bucket.failNext(VersionedBucket::Op::Head, VersionedBucket::Failure::Transport);
    EXPECT_FALSE(bucket.getHeadObject("k"));
    EXPECT_FALSE(s3::Controller::lastHeadOutcome().transport_ok);
    const auto live = bucket.getHeadObject("k");
    ASSERT_TRUE(live);
    EXPECT_EQ(v1, live->at("x-amz-version-id"));
    EXPECT_EQ(200, s3::Controller::lastHeadOutcome().http_status);

    bucket.failNext(VersionedBucket::Op::Get, VersionedBucket::Failure::Http503);
    EXPECT_THROW(readAll(bucket, "k", {}), std::runtime_error);
    bucket.failNext(VersionedBucket::Op::Any, VersionedBucket::Failure::Transport);
    EXPECT_THROW(bucket.uploadBufferWithMetadata("k", bytesOf("new"), s3::RequestOptions{}), std::runtime_error);
    EXPECT_EQ(1u, bucket.history("k").size()) << "a failed PUT writes nothing";
    EXPECT_TRUE(s3::Controller::lastPutOutcome().etag.empty());
    bucket.failNext(VersionedBucket::Op::Copy, VersionedBucket::Failure::ErrorAfter200);
    EXPECT_THROW((void)bucket.copyObjectVersion("k", v1, "k2", 4, {}), std::runtime_error);
    EXPECT_FALSE(bucket.current("k2"));

    bucket.setRequestBudget({.max_list_requests = 0, .max_head_requests = std::nullopt, .max_get_requests = std::nullopt,
                             .max_put_requests = std::nullopt, .max_copy_requests = std::nullopt,
                             .max_delete_requests = std::nullopt, .max_downloaded_bytes = std::nullopt});
    const auto lists = bucket.counters().list;
    EXPECT_THROW((void)bucket.listObjectVersionsPage(""), s3::RequestBudgetExceeded);
    EXPECT_EQ(lists, bucket.counters().list) << "a budget refusal never reaches the bucket";
    bucket.clearRequestBudget();

    guard::setForTesting({vh::storage::upstream::identityFor(*vh::test_support::versioned::versionedBucketKey(),
                                                             "vh-versioned-bucket")});
    EXPECT_THROW((void)bucket.headObjectVersion("k", v1), vh::storage::upstream::BucketProtected);
    EXPECT_THROW(bucket.deleteObject("k"), vh::storage::upstream::BucketProtected);
    guard::clearForTesting();
    EXPECT_TRUE(bucket.current("k"));
}

}  // namespace s3vtest
