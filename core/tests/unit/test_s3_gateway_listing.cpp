// S3 gateway object listing as an S3 client sees it: ListObjectsV2 and ListObjects pages through the router, signed
// and parsed the way an SDK paginator does it (query values percent-encoded, the answer's key fields percent-decoded
// under EncodingType=url, the continuation token handed back exactly as it was received).
//
// Two things every paginator relies on, both broken before these tests existed:
//   - the continuation token round-trips. It used to be the last key, percent-encoded under EncodingType=url (which
//     boto3 always sends), and S3 clients never decode a token: the second request listed the first page again.
//   - keys come in ascending UTF-8 byte order, and the place a page resumes from is found with the same comparison.
//     The listing used to sort by the database's collation (en_US on a stock PostgreSQL), which puts "big.bin" before
//     "big-single.bin".
// The databases the tests run on decide whether the second one shows: a C-locale cluster (macOS) sorts by bytes anyway.

#include "../helpers/db_suite.hpp"
#include "../helpers/s3_gateway.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/s3/Gateway.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/s3/CredentialManager.hpp"
#include "protocols/s3/Listing.hpp"
#include "protocols/s3/Router.hpp"
#include "protocols/s3/Xml.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"

#include <boost/beast/http.hpp>
#include <gtest/gtest.h>
#include <pqxx/pqxx>
#include <pugixml.hpp>

#include <algorithm>
#include <cstdint>
#include <ctime>
#include <optional>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace vh::test::s3listing {

namespace bhttp = boost::beast::http;
using Query = std::vector<std::pair<std::string, std::string>>;

// RFC 3986 percent-encoding of everything but the unreserved characters: what SDKs do to query values.
inline std::string pctEncode(const std::string& value) {
    static constexpr char hex[] = "0123456789ABCDEF";
    std::string out;
    for (const unsigned char c : value) {
        if ((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' || c == '_' ||
            c == '.' || c == '~') {
            out.push_back(static_cast<char>(c));
        } else {
            out.push_back('%');
            out.push_back(hex[c >> 4]);
            out.push_back(hex[c & 0x0F]);
        }
    }
    return out;
}

// urllib's unquote, which is what botocore applies to the key fields of an EncodingType=url answer.
inline std::string pctDecode(const std::string& value) {
    const auto nibble = [](const char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    std::string out;
    for (std::size_t i = 0; i < value.size(); ++i) {
        if (value[i] == '%' && i + 2 < value.size() && nibble(value[i + 1]) >= 0 && nibble(value[i + 2]) >= 0) {
            out.push_back(static_cast<char>(nibble(value[i + 1]) * 16 + nibble(value[i + 2])));
            i += 2;
        } else {
            out.push_back(value[i]);
        }
    }
    return out;
}

// One answer to a bucket GET, read as an SDK reads it.
struct Page {
    bhttp::status status{};
    std::string body;
    std::string error_code;                       // <Error><Code>
    std::vector<std::string> keys;                // Contents/Key, decoded
    std::vector<std::string> common_prefixes;     // CommonPrefixes/Prefix, decoded
    bool truncated{};
    std::optional<std::string> next_token;        // NextContinuationToken, verbatim: clients never decode it
    std::optional<std::string> next_marker;       // NextMarker, decoded (ListObjects v1)
    std::optional<std::string> marker;            // Marker, decoded (ListObjects v1)
    std::optional<std::string> start_after;       // StartAfter, decoded
    std::optional<std::string> continuation_token;
    std::optional<uint64_t> key_count;
    std::optional<std::string> encoding_type;
    std::optional<std::string> prefix;            // decoded
    std::optional<std::string> delimiter;         // decoded

    // Keys and common prefixes of this page as one ascending list.
    [[nodiscard]] std::vector<std::string> items() const {
        std::vector<std::string> out = keys;
        out.insert(out.end(), common_prefixes.begin(), common_prefixes.end());
        std::ranges::sort(out);
        return out;
    }
};

inline Page parsePage(const bhttp::status status, const std::string& body) {
    Page page;
    page.status = status;
    page.body = body;
    pugi::xml_document doc;
    if (!doc.load_buffer(body.data(), body.size())) {
        ADD_FAILURE() << "the answer is not XML: " << body;
        return page;
    }
    if (const auto error = doc.child("Error")) {
        page.error_code = error.child_value("Code");
        return page;
    }
    const auto root = doc.child("ListBucketResult");
    if (!root) {
        ADD_FAILURE() << "no ListBucketResult in: " << body;
        return page;
    }
    const auto text = [&](const char* name) -> std::optional<std::string> {
        const auto node = root.child(name);
        if (!node) return std::nullopt;
        return std::string(node.child_value());
    };
    page.encoding_type = text("EncodingType");
    const bool url = page.encoding_type == "url";
    const auto key = [&](std::optional<std::string> value) {
        if (value && url) value = pctDecode(*value);
        return value;
    };
    for (const auto contents : root.children("Contents")) page.keys.push_back(*key(contents.child_value("Key")));
    for (const auto prefix : root.children("CommonPrefixes"))
        page.common_prefixes.push_back(*key(prefix.child_value("Prefix")));
    page.truncated = std::string(root.child_value("IsTruncated")) == "true";
    page.next_token = text("NextContinuationToken");
    page.continuation_token = text("ContinuationToken");
    page.next_marker = key(text("NextMarker"));
    page.marker = key(text("Marker"));
    page.start_after = key(text("StartAfter"));
    page.prefix = key(text("Prefix"));
    page.delimiter = key(text("Delimiter"));
    if (const auto count = text("KeyCount")) page.key_count = std::stoull(*count);
    return page;
}

// Any answer, read for its shape: the document element, its text and child elements, and an error's code.
struct Answer {
    bhttp::status status{};
    std::string body;
    std::string root;                    // the document element's name
    std::string text;                    // its own text
    std::vector<std::string> children;   // the names of its child elements
    std::string error_code;              // <Error><Code>
};

inline Answer parseAnswer(const bhttp::status status, const std::string& body) {
    Answer answer;
    answer.status = status;
    answer.body = body;
    pugi::xml_document doc;
    if (body.empty() || !doc.load_buffer(body.data(), body.size())) return answer;
    const auto root = doc.document_element();
    answer.root = root.name();
    answer.text = root.child_value();
    for (const auto child : root.children())
        if (child.type() == pugi::node_element) answer.children.emplace_back(child.name());
    if (answer.root == "Error") answer.error_code = root.child_value("Code");
    return answer;
}

// What S3 answers for `keys` listed under `prefix` with `delimiter` (empty: none): every key, or the common prefix it
// rolls up into, once, in ascending UTF-8 byte order. std::string compares as unsigned bytes, which is that order.
inline std::vector<std::string> expectedItems(const std::vector<std::string>& keys, const std::string& prefix,
                                              const std::string& delimiter) {
    std::set<std::string> items;
    for (const auto& k : keys) {
        if (!k.starts_with(prefix)) continue;
        const auto at = delimiter.empty() ? std::string::npos : k.find(delimiter, prefix.size());
        items.insert(at == std::string::npos ? k : k.substr(0, at + delimiter.size()));
    }
    return {items.begin(), items.end()};
}

// Keys whose byte order and en_US order disagree, and every character a token or a query string could mangle: '/',
// '-', '.', '%', '+', space, uppercase, XML metacharacters and non-ASCII (é, 日本語).
inline std::vector<std::string> trickyKeys() {
    return {
        // The listing of the report: en_US puts big.bin before big-single.bin.
        "probe/big.bin", "probe/big-single.bin", "probe/copy.bin", "probe/inm.bin", "probe/meta.bin",
        "probe/plain.bin", "probe/sha.bin",
        "probe/Big.bin", "probe/BIG.bin", "probe/a", "probe/A", "probe/ab", "probe/a-b", "probe/a.b", "probe/a_b",
        "probe/a~b", "probe/a b.txt", "probe/a+b.txt", "probe/a%2Fb.txt", "probe/a%b", "probe/100%", "probe/%41",
        "probe/a&b<c>'\".txt", "probe/a/b", "probe/a/b%2F/c d", "probe/a/+/x", "probe/e.txt", "probe/f.txt",
        "probe/\xC3\xA9.txt", "probe/\xC3\x89.txt", "probe/\xE6\x97\xA5\xE6\x9C\xAC/\xE8\xAA\x9E.txt",
        "probe/sub dir/x+y", "probe/sub dir/\xC3\xA9", "probe/sub-dir/1", "probe/sub.dir/1", "probe/subdir/1",
        "probe/sub%dir/1", "other/z", "Zeta", "alpha", "_x", "%41", "a-b/c", "a.b/c", "ab/c",
    };
}

}  // namespace vh::test::s3listing

namespace {
namespace s3l = vh::test::s3listing;
namespace s3gw_l = vh::test::s3gw;
}  // namespace

// ── No database: the token and the two answers ───────────────────────────────────────────────────────────────────

TEST(S3GatewayListingTokenTest, RoundTripsEveryPositionInUrlAndXmlSafeCharacters) {
    auto positions = s3l::trickyKeys();
    for (const std::string extra : {"a", "ab", "abc", "abcd", "abcde", "a/", "probe/", " ", "%", "+", "\x7F", "\x01",
                                    "\xF4\x8F\xBF\xBF", "<&>'\""})
        positions.push_back(extra);
    positions.push_back(std::string(1024, 'k'));
    std::set<std::string> tokens;
    for (const auto& position : positions) {
        SCOPED_TRACE(position);
        const auto token = vh::protocols::s3::listing::encodeContinuationToken(position);
        EXPECT_TRUE(token.starts_with("vh1."));
        EXPECT_EQ(token.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_."),
                  std::string::npos)
            << token;
        // The same text after a query string and an XML document have had their way with it.
        EXPECT_EQ(s3l::pctEncode(token), token);
        EXPECT_EQ(vh::protocols::s3::xml::escape(token), token);
        EXPECT_EQ(vh::protocols::s3::listing::decodeContinuationToken(token), std::optional<std::string>{position});
        tokens.insert(token);
    }
    EXPECT_EQ(tokens.size(), std::set<std::string>(positions.begin(), positions.end()).size());
}

TEST(S3GatewayListingTokenTest, RefusesWhatTheGatewayDidNotIssue) {
    using vh::protocols::s3::listing::decodeContinuationToken;
    for (const std::string token :
         {"", "b", "probe/big-single.bin", "probe%2Fbig-single.bin", "vh1", "vh1.", "vh2.YQ", "VH1.YQ", "vh1.Y",
          "vh1.YQ==", "vh1.Y Q", "vh1.Y+Q", "vh1.Y/Q", "vh1.YR" /* leftover bits */, "vh1.gA" /* 0x80 */,
          "vh1.AA" /* NUL */, "vh1.7aCA" /* a surrogate */, "vh1.wIA" /* overlong */})
        EXPECT_FALSE(decodeContinuationToken(token)) << token;
    EXPECT_EQ(decodeContinuationToken("vh1.YQ"), std::optional<std::string>{"a"});
}

TEST(S3GatewayListingTokenTest, KeyTextIsWellFormedUtf8WithoutNul) {
    using vh::protocols::s3::listing::isKeyText;
    for (const auto& key : s3l::trickyKeys()) EXPECT_TRUE(isKeyText(key)) << key;
    EXPECT_TRUE(isKeyText(""));
    EXPECT_TRUE(isKeyText("\xF4\x8F\xBF\xBF"));
    EXPECT_FALSE(isKeyText(std::string("a\0b", 3)));
    for (const std::string bad : {"\x80", "\xC3", "\xC0\xAF", "\xE0\x80\x80", "\xED\xA0\x80", "\xF4\x90\x80\x80",
                                  "\xF8\x88\x80\x80\x80", "a\xFFz", "\xE6\x97"})
        EXPECT_FALSE(isKeyText(bad));
}

// The answer boto3 got in the report, EncodingType=url: key fields percent-encoded, the token not.
TEST(S3GatewayListingXmlTest, V2PercentEncodesKeyFieldsAndNeverTheToken) {
    vh::db::query::s3::ObjectListResult result;
    result.objects.push_back({.vault_id = 1, .object_key = "probe/big-single.bin", .etag = "\"e\"", .size_bytes = 1,
                              .content_type = std::nullopt, .storage_class = std::nullopt, .last_modified = 0,
                              .multipart = false, .part_count = std::nullopt});
    result.next_after = "probe/big-single.bin";
    result.is_truncated = true;

    for (const auto& encoding : {std::optional<std::string>{}, std::optional<std::string>{"url"}}) {
        const auto xml = vh::protocols::s3::xml::listObjectsV2(
            "bucket", result,
            {.prefix = "probe/", .delimiter = std::nullopt, .max_keys = 2, .encoding_type = encoding,
             .marker = std::nullopt, .start_after = std::nullopt, .continuation_token = std::nullopt});
        const auto page = s3l::parsePage(s3l::bhttp::status::ok, xml);
        EXPECT_EQ(page.keys, (std::vector<std::string>{"probe/big-single.bin"}));
        ASSERT_TRUE(page.next_token);
        EXPECT_EQ(page.next_token->find('%'), std::string::npos) << *page.next_token;
        EXPECT_EQ(vh::protocols::s3::listing::decodeContinuationToken(*page.next_token),
                  std::optional<std::string>{"probe/big-single.bin"});
        EXPECT_EQ(page.key_count, std::optional<uint64_t>{1});
        EXPECT_EQ(xml.find("<Marker>"), std::string::npos);
        EXPECT_EQ(xml.find("<NextMarker>"), std::string::npos);
    }
}

TEST(S3GatewayListingXmlTest, V1AnswersMarkerAndNextMarkerAsKeyFields) {
    vh::db::query::s3::ObjectListResult result;
    result.common_prefixes.push_back("a b/");
    result.next_after = "a b/";
    result.is_truncated = true;

    const vh::protocols::s3::xml::ListObjectsRequest request{
        .prefix = "", .delimiter = "/", .max_keys = 1, .encoding_type = "url", .marker = "a a/+",
        .start_after = std::nullopt, .continuation_token = std::nullopt};
    const auto xml = vh::protocols::s3::xml::listObjects("bucket", result, request);
    EXPECT_NE(xml.find("<Marker>a%20a%2F%2B</Marker>"), std::string::npos) << xml;
    EXPECT_NE(xml.find("<NextMarker>a%20b%2F</NextMarker>"), std::string::npos) << xml;
    EXPECT_EQ(xml.find("KeyCount"), std::string::npos);
    EXPECT_EQ(xml.find("ContinuationToken"), std::string::npos);

    auto plain = request;
    plain.encoding_type.reset();
    plain.marker.reset();
    result.is_truncated = false;
    result.next_after.reset();
    const auto last = vh::protocols::s3::xml::listObjects("bucket", result, plain);
    EXPECT_NE(last.find("<Marker></Marker>"), std::string::npos) << last;
    EXPECT_EQ(last.find("<NextMarker>"), std::string::npos);
    EXPECT_NE(last.find("<Prefix>a b/</Prefix>"), std::string::npos);
}

// The documents S3 answers for a subresource a bucket never had configured; the rest have no document.
TEST(S3GatewayListingXmlTest, UnconfiguredBucketSubresourcesAnswerS3sDefaults) {
    const auto answer = [](const std::string& subresource) {
        const auto body = vh::protocols::s3::xml::unconfiguredBucketSubresource(subresource);
        return body ? s3l::parseAnswer(s3l::bhttp::status::ok, *body) : s3l::Answer{};
    };
    for (const auto& [subresource, root] : std::vector<std::pair<std::string, std::string>>{
             {"location", "LocationConstraint"}, {"versioning", "VersioningConfiguration"},
             {"notification", "NotificationConfiguration"}, {"logging", "BucketLoggingStatus"},
             {"accelerate", "AccelerateConfiguration"}}) {
        const auto a = answer(subresource);
        EXPECT_EQ(a.root, root) << subresource << ": " << a.body;
        EXPECT_TRUE(a.text.empty()) << subresource << ": " << a.body;           // us-east-1, never enabled, none
        EXPECT_TRUE(a.children.empty()) << subresource << ": " << a.body;
        EXPECT_NE(a.body.find("xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\""), std::string::npos) << a.body;
    }
    const auto payment = answer("requestPayment");
    EXPECT_EQ(payment.root, "RequestPaymentConfiguration") << payment.body;
    EXPECT_NE(payment.body.find("<Payer>BucketOwner</Payer>"), std::string::npos) << payment.body;
    for (const std::string none : {"lifecycle", "policy", "acl", "versions", "uploads", "policyStatus", "", "x"})
        EXPECT_FALSE(vh::protocols::s3::xml::unconfiguredBucketSubresource(none)) << none;
}

// ── With a database: the query, then the router ──────────────────────────────────────────────────────────────────

class S3GatewayListingDbTest : public vh::test::db::Suite {
protected:
    struct BucketUnderTest {
        std::string name;
        std::string mode;
        uint32_t vault_id{};
    };

    inline static std::vector<BucketUnderTest> buckets;   // local, remote_cache, remote_proxy
    inline static uint32_t adminId = 0;
    inline static std::string accessKey;
    inline static std::string secretKey;
    std::optional<s3gw_l::ConfigRestore> restoreConfig;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_s3_gateway_listing")) return;
        const auto admin = vh::identities::manager().userByName("admin");
        ASSERT_TRUE(admin);
        adminId = admin->id;

        buckets.clear();
        vh::protocols::s3::CredentialCreateOptions options{
            .created_by = admin->id,
            .principal_user_id = admin->id,
            .name = "listing-" + s3gw_l::uniqueSuffix("credential"),
            .scope_mode = "vault_allowlist",
            .description = std::nullopt,
            .expires_at = std::nullopt,
            .vault_scopes = {}
        };
        for (const std::string mode : {"local", "remote_cache", "remote_proxy"}) {
            const auto vaultId = vh::db::Transactions::exec("S3GatewayListingDbTest::vault", [&](pqxx::work& txn) {
                const auto id = txn.exec(
                    "INSERT INTO vault (type, name, owner_id, mount_point, description, uid) "
                    "VALUES ('local', $1, $2, $3, '', gen_random_uuid()) RETURNING id",
                    pqxx::params{"S3 Listing " + mode, admin->id, "s3_listing_" + mode}).one_field_ref().as<uint32_t>();
                txn.exec(
                    "WITH ins AS (INSERT INTO sync (vault_id, interval) VALUES ($1, 300) RETURNING id) "
                    "INSERT INTO fsync (sync_id, conflict_policy) SELECT id, 'keep_both' FROM ins",
                    pqxx::params{id});
                return id;
            });
            std::string name = "listing-" + mode + "-" + std::to_string(vaultId);
            std::ranges::replace(name, '_', '-');
            buckets.push_back({.name = name, .mode = mode, .vault_id = vaultId});
            options.vault_scopes.push_back({
                .credential_id = 0,
                .vault_id = vaultId,
                .can_list = true,
                .can_read = true,
                .can_write = false,
                .can_delete = false,
                .can_admin = false
            });
        }
        vh::runtime::Deps::get().storageManager->initStorageEngines();
        for (const auto& bucket : buckets)
            vh::db::query::s3::Gateway::bindBucket({
                .vault_id = bucket.vault_id,
                .bucket_name = bucket.name,
                .api_exclusive = bucket.mode == "local",
                .mode = bucket.mode,
                .created_by = admin->id
            });

        const vh::protocols::s3::CredentialManager manager;
        const auto secret = manager.createCredential(options);
        accessKey = secret.credential.access_key;
        secretKey = secret.secret_access_key;
    }

    static void TearDownTestSuite() { tearDownDbSuite(); }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        vh::db::Transactions::exec("S3GatewayListingDbTest::clear", [](pqxx::work& txn) {
            txn.exec("DELETE FROM s3_gateway_object");
            txn.exec("DELETE FROM remote_object_index");
        });
        restoreConfig.emplace(vh::config::Registry::get());
        auto cfg = vh::config::Registry::get();
        cfg.s3_gateway.require_sigv4 = true;
        cfg.s3_gateway.allow_path_style = true;
        vh::config::Registry::set(cfg);
    }

    void TearDown() override {
        restoreConfig.reset();
        Suite::TearDown();
    }

    static const BucketUnderTest& bucket(const std::string& mode = "local") {
        return *std::ranges::find(buckets, mode, &BucketUnderTest::mode);
    }

    // Objects as each mode gets them: a local bucket's gateway rows are written by PUT; a remote-backed bucket's are
    // imported from the remote object index when it is listed.
    static void seed(const BucketUnderTest& target, const std::vector<std::string>& keys) {
        vh::db::Transactions::exec("S3GatewayListingDbTest::seed", [&](pqxx::work& txn) {
            for (const auto& key : keys) {
                if (target.mode == "local")
                    txn.exec(
                        "INSERT INTO s3_gateway_object (vault_id, object_key, etag, size_bytes) VALUES ($1, $2, $3, 1)",
                        pqxx::params{target.vault_id, key, "\"etag\""});
                else
                    txn.exec(
                        "INSERT INTO remote_object_index (vault_id, object_key, size_bytes, etag, storage_class, source) "
                        "VALUES ($1, $2, 1, $3, 'STANDARD', 'manifest')",
                        pqxx::params{target.vault_id, key, "\"etag\""});
            }
        });
    }

    // A request as a client signs it: `target` verbatim (a bare subresource stays "?versioning"), signed with the
    // given credential, or unsigned when `key` is empty.
    static s3l::Answer send(const s3l::bhttp::verb verb, const std::string& target, const std::string& key,
                            const std::string& secret, std::string body = {}) {
        vh::protocols::s3::Router::Request request{verb, target, 11};
        request.set(s3l::bhttp::field::host, "127.0.0.1:39000");
        if (!body.empty()) {
            request.set(s3l::bhttp::field::content_type, "application/xml");
            request.body() = std::move(body);
            request.prepare_payload();
        }
        if (!key.empty()) s3gw_l::signRequest(request, key, secret);
        const auto response = vh::protocols::s3::Router{}.route(std::move(request));
        return s3l::parseAnswer(response.result(), response.body());
    }

    static s3l::Answer send(const s3l::bhttp::verb verb, const std::string& target, std::string body = {}) {
        return send(verb, target, accessKey, secretKey, std::move(body));
    }

    // An empty bucket of `mode` of its own (not one of `buckets`), for a test that may delete it.
    static BucketUnderTest freshBucket(const std::string& mode) {
        const auto label = s3gw_l::uniqueSuffix(mode);
        const auto vaultId = vh::db::Transactions::exec("S3GatewayListingDbTest::freshVault", [&](pqxx::work& txn) {
            const auto id = txn.exec(
                "INSERT INTO vault (type, name, owner_id, mount_point, description, uid) "
                "VALUES ('local', $1, $2, $3, '', gen_random_uuid()) RETURNING id",
                pqxx::params{"S3 Subresources " + label, adminId, label.substr(0, 33)}).one_field_ref().as<uint32_t>();
            txn.exec(
                "WITH ins AS (INSERT INTO sync (vault_id, interval) VALUES ($1, 300) RETURNING id) "
                "INSERT INTO fsync (sync_id, conflict_policy) SELECT id, 'keep_both' FROM ins",
                pqxx::params{id});
            return id;
        });
        vh::runtime::Deps::get().storageManager->initStorageEngines();
        std::string name = "subresources-" + mode + "-" + std::to_string(vaultId);
        std::ranges::replace(name, '_', '-');
        vh::db::query::s3::Gateway::bindBucket({
            .vault_id = vaultId,
            .bucket_name = name,
            .api_exclusive = false,
            .mode = mode,
            .created_by = adminId
        });
        return {.name = name, .mode = mode, .vault_id = vaultId};
    }

    static s3l::Page get(const BucketUnderTest& target, const s3l::Query& query) {
        std::string url = "/" + target.name;
        char separator = '?';
        for (const auto& [name, value] : query) {
            url += separator;
            url += s3l::pctEncode(name) + "=" + s3l::pctEncode(value);
            separator = '&';
        }
        vh::protocols::s3::Router::Request request{s3l::bhttp::verb::get, url, 11};
        request.set(s3l::bhttp::field::host, "127.0.0.1:39000");
        s3gw_l::signRequest(request, accessKey, secretKey);
        const auto response = vh::protocols::s3::Router{}.route(std::move(request));
        return s3l::parsePage(response.result(), response.body());
    }

    struct Listing {
        std::vector<std::string> items;   // every page's keys and common prefixes, in the order the pages gave them
        std::size_t pages{};
        bool ok{true};
    };

    // A ListObjectsV2 paginator: follows NextContinuationToken until IsTruncated is false, and gives up, as boto3
    // does, when a page hands back the token that fetched it.
    static Listing paginateV2(const BucketUnderTest& target, s3l::Query query, const std::size_t maxKeys) {
        query.emplace_back("list-type", "2");
        query.emplace_back("max-keys", std::to_string(maxKeys));
        Listing out;
        std::optional<std::string> token;
        for (;;) {
            auto pageQuery = query;
            if (token) pageQuery.emplace_back("continuation-token", *token);
            const auto page = get(target, pageQuery);
            ++out.pages;
            if (page.status != s3l::bhttp::status::ok) {
                ADD_FAILURE() << "page " << out.pages << ": HTTP " << static_cast<int>(page.status) << " " << page.body;
                out.ok = false;
                return out;
            }
            const auto items = page.items();
            out.items.insert(out.items.end(), items.begin(), items.end());
            EXPECT_TRUE(std::ranges::is_sorted(page.keys)) << "page " << out.pages << " keys out of byte order";
            EXPECT_TRUE(std::ranges::is_sorted(page.common_prefixes)) << "page " << out.pages;
            EXPECT_LE(items.size(), maxKeys) << "page " << out.pages;
            EXPECT_EQ(page.key_count, std::optional<uint64_t>{items.size()}) << "page " << out.pages;
            if (!page.truncated) {
                EXPECT_FALSE(page.next_token) << "a last page carries no token";
                return out;
            }
            if (!page.next_token || page.next_token->empty()) {
                ADD_FAILURE() << "page " << out.pages << " is truncated but has no NextContinuationToken";
                out.ok = false;
                return out;
            }
            if (page.next_token == token || out.pages > 10000) {
                ADD_FAILURE() << "page " << out.pages << ": the same next token was received twice: " << *token;
                out.ok = false;
                return out;
            }
            token = page.next_token;
        }
    }

    // A ListObjects (v1) paginator: the next Marker is NextMarker, or the page's last key when there is none.
    static Listing paginateV1(const BucketUnderTest& target, s3l::Query query, const std::size_t maxKeys) {
        query.emplace_back("max-keys", std::to_string(maxKeys));
        Listing out;
        std::optional<std::string> marker;
        for (;;) {
            auto pageQuery = query;
            if (marker) pageQuery.emplace_back("marker", *marker);
            const auto page = get(target, pageQuery);
            ++out.pages;
            if (page.status != s3l::bhttp::status::ok) {
                ADD_FAILURE() << "page " << out.pages << ": HTTP " << static_cast<int>(page.status) << " " << page.body;
                out.ok = false;
                return out;
            }
            const auto items = page.items();
            out.items.insert(out.items.end(), items.begin(), items.end());
            EXPECT_LE(items.size(), maxKeys) << "page " << out.pages;
            EXPECT_FALSE(page.key_count) << "KeyCount belongs to ListObjectsV2";
            EXPECT_FALSE(page.next_token) << "NextContinuationToken belongs to ListObjectsV2";
            EXPECT_EQ(page.marker.value_or("<none>"), marker.value_or("")) << "Marker echoes the request";
            if (!page.truncated) return out;
            std::optional<std::string> next = page.next_marker;
            if (!next && !page.keys.empty()) next = page.keys.back();
            if (!next || next == marker || out.pages > 10000) {
                ADD_FAILURE() << "page " << out.pages << ": no marker to continue from, or the same one twice";
                out.ok = false;
                return out;
            }
            marker = next;
        }
    }

    static std::string describe(const std::string& encoding, const std::size_t maxKeys, const std::string& prefix,
                                const std::string& delimiter) {
        return "encoding-type=" + (encoding.empty() ? "<none>" : encoding) + " max-keys=" + std::to_string(maxKeys) +
               " prefix='" + prefix + "' delimiter='" + delimiter + "'";
    }

    static s3l::Query queryFor(const std::string& encoding, const std::string& prefix, const std::string& delimiter) {
        s3l::Query query;
        if (!encoding.empty()) query.emplace_back("encoding-type", encoding);
        if (!prefix.empty()) query.emplace_back("prefix", prefix);
        if (!delimiter.empty()) query.emplace_back("delimiter", delimiter);
        return query;
    }
};

// Pairs a locale collation and a byte comparison order differently (en_US ignores punctuation and case at first):
// the query sorts them, and resumes after either one, by bytes.
TEST_F(S3GatewayListingDbTest, TheQuerySortsAndResumesByBytesNotByCollation) {
    using vh::db::query::s3::Gateway;
    const std::vector<std::pair<std::string, std::string>> pairs{   // {first in S3, second in S3}
        {"big-single.bin", "big.bin"}, {"B", "a"}, {"Zeta", "alpha"}, {"a b", "a-b"}, {"a-b", "ab"}, {"a.b", "ab"},
        {"a/b", "a_b"}, {"a_b", "ab"}, {"a", "a b"}, {"z", "\xC3\xA9"}, {"\xC3\x89", "\xC3\xA9"}, {"a%b", "a+b"},
        {"a+b", "a-b"}, {"A/z", "a/a"}, {"a/Z", "a/a"}, {"10", "9"}, {"a~", "\xC3\xA9"}};
    const auto keysOf = [](const vh::db::query::s3::ObjectListResult& result) {
        std::vector<std::string> out;
        for (const auto& object : result.objects) out.push_back(object.object_key);
        return out;
    };
    for (const auto& [first, second] : pairs) {
        SCOPED_TRACE("'" + first + "' before '" + second + "'");
        ASSERT_LT(first, second);
        vh::db::Transactions::exec("S3GatewayListingDbTest::clearPair",
                                   [](pqxx::work& txn) { txn.exec("DELETE FROM s3_gateway_object"); });
        seed(bucket(), {second, first});
        const auto vaultId = bucket().vault_id;

        EXPECT_EQ(keysOf(Gateway::listObjectStates(vaultId, {})), (std::vector<std::string>{first, second}));

        vh::db::query::s3::ObjectListParams page;
        page.max_keys = 1;
        const auto firstPage = Gateway::listObjectStates(vaultId, page);
        EXPECT_EQ(keysOf(firstPage), (std::vector<std::string>{first}));
        EXPECT_TRUE(firstPage.is_truncated);
        EXPECT_EQ(firstPage.next_after, std::optional<std::string>{first});
        page.after = firstPage.next_after;
        const auto secondPage = Gateway::listObjectStates(vaultId, page);
        EXPECT_EQ(keysOf(secondPage), (std::vector<std::string>{second}));
        EXPECT_FALSE(secondPage.is_truncated);
        EXPECT_FALSE(secondPage.next_after);
        page.after = second;
        EXPECT_TRUE(keysOf(Gateway::listObjectStates(vaultId, page)).empty());
    }
}

// In-progress multipart uploads list in key order too.
TEST_F(S3GatewayListingDbTest, MultipartUploadsListInByteOrder) {
    const auto vaultId = bucket().vault_id;
    for (const std::string key : {"probe/big.bin", "probe/big-single.bin", "probe/Big.bin", "probe/a b"})
        vh::db::query::s3::Gateway::createMultipartUpload({
            .upload_id = "listing-upload-" + s3l::pctEncode(key),
            .parts_dir_id = "listing-parts-" + s3l::pctEncode(key),
            .vault_id = vaultId,
            .object_key = key,
            .initiated_by = adminId,
            .content_type = std::nullopt,
            .metadata = {},
            .storage_class = std::nullopt
        });

    std::vector<std::string> listed;
    for (const auto& upload : vh::db::query::s3::Gateway::listMultipartUploads(vaultId, "probe/"))
        listed.push_back(upload.object_key);
    EXPECT_EQ(listed, (std::vector<std::string>{"probe/Big.bin", "probe/a b", "probe/big-single.bin", "probe/big.bin"}));
}

// Listing parameters that can't be key text are the client's mistake, not a database error.
TEST_F(S3GatewayListingDbTest, RefusesListingParametersThatAreNotKeyText) {
    seed(bucket(), {"a", "b"});
    for (const std::string name : {"prefix", "delimiter", "start-after"}) {
        const auto page = get(bucket(), {{"list-type", "2"}, {name, "a\xFFz"}});
        EXPECT_EQ(page.status, s3l::bhttp::status::bad_request) << name << ": " << page.body;
        EXPECT_EQ(page.error_code, "InvalidArgument") << name;
    }
    const auto marker = get(bucket(), {{"marker", std::string("a\0z", 3)}});
    EXPECT_EQ(marker.status, s3l::bhttp::status::bad_request) << marker.body;
    EXPECT_EQ(marker.error_code, "InvalidArgument");
}

// The report, as boto3 1.35 made it: seven keys under probe/, MaxKeys=2, EncodingType=url. The second request must
// answer the second page, and big-single.bin ('-' is 0x2d) comes before big.bin ('.' is 0x2e).
TEST_F(S3GatewayListingDbTest, TheReportedListingPagesAndSortsAsS3Does) {
    const std::vector<std::string> keys{"probe/big.bin", "probe/big-single.bin", "probe/copy.bin", "probe/inm.bin",
                                        "probe/meta.bin", "probe/plain.bin", "probe/sha.bin"};
    seed(bucket(), keys);

    const s3l::Query base{{"list-type", "2"}, {"prefix", "probe/"}, {"max-keys", "2"}, {"encoding-type", "url"}};
    const auto first = get(bucket(), base);
    ASSERT_EQ(first.status, s3l::bhttp::status::ok) << first.body;
    EXPECT_EQ(first.keys, (std::vector<std::string>{"probe/big-single.bin", "probe/big.bin"}));
    ASSERT_TRUE(first.truncated);
    ASSERT_TRUE(first.next_token);

    auto secondQuery = base;
    secondQuery.emplace_back("continuation-token", *first.next_token);
    const auto second = get(bucket(), secondQuery);
    ASSERT_EQ(second.status, s3l::bhttp::status::ok) << second.body;
    EXPECT_EQ(second.keys, (std::vector<std::string>{"probe/copy.bin", "probe/inm.bin"}));
    EXPECT_NE(second.next_token, first.next_token);

    const auto all = paginateV2(bucket(), {{"prefix", "probe/"}, {"encoding-type", "url"}}, 2);
    EXPECT_EQ(all.items, s3l::expectedItems(keys, "probe/", ""));
    EXPECT_EQ(all.pages, 4u);
}

// Every page size makes a different key the page boundary, so each tricky key is, in turn, the place a listing resumes
// from: with and without EncodingType=url, with and without a prefix.
TEST_F(S3GatewayListingDbTest, V2PagesEveryKeyOnceInByteOrder) {
    const auto keys = s3l::trickyKeys();
    seed(bucket(), keys);

    for (const std::string encoding : {"", "url"})
        for (const std::string prefix : {"", "probe/", "probe/a", "probe/sub", "probe/a%", "nothing/"})
            for (const std::size_t maxKeys : {1u, 2u, 3u, 7u, 1000u}) {
                SCOPED_TRACE(describe(encoding, maxKeys, prefix, ""));
                const auto listing = paginateV2(bucket(), queryFor(encoding, prefix, ""), maxKeys);
                const auto expected = s3l::expectedItems(keys, prefix, "");
                EXPECT_EQ(listing.items, expected);
                if (listing.ok) {
                    EXPECT_EQ(listing.pages, std::max<std::size_t>(1, (expected.size() + maxKeys - 1) / maxKeys));
                }
            }
}

// With a delimiter a page boundary can fall on a common prefix: the next page must skip every key under it, list each
// common prefix once, and keep keys and prefixes in one byte order. KeyCount counts both.
TEST_F(S3GatewayListingDbTest, V2DelimiterPagesKeysAndCommonPrefixesOnce) {
    const auto keys = s3l::trickyKeys();
    seed(bucket(), keys);

    for (const std::string encoding : {"", "url"})
        for (const std::string delimiter : {"/", "%", "b", "-"})
            for (const std::string prefix : {"", "probe/", "probe/a", "probe/sub", "probe/a/"})
                for (const std::size_t maxKeys : {1u, 2u, 5u, 1000u}) {
                    SCOPED_TRACE(describe(encoding, maxKeys, prefix, delimiter));
                    const auto listing = paginateV2(bucket(), queryFor(encoding, prefix, delimiter), maxKeys);
                    EXPECT_EQ(listing.items, s3l::expectedItems(keys, prefix, delimiter));
                }
}

TEST_F(S3GatewayListingDbTest, V2StartAfterListsStrictlyAfterAKeyThatExistsOrNot) {
    const auto keys = s3l::trickyKeys();
    seed(bucket(), keys);
    const auto sorted = s3l::expectedItems(keys, "", "");

    // An existing key, a key that is not there, one before everything, one after everything, and keys whose en_US
    // position differs from their byte position.
    for (const std::string startAfter :
         {"probe/big-single.bin", "probe/big.bin", "probe/a%2Fb.txt", "probe/a b.txt", "probe/\xC3\xA9.txt",
          "probe/big-", "probe/big", "probe/b", "probe/B", "probe/a/", "probe/zzz", "!", "~~~", "probe/sub dir/",
          "probe/a+", "Zeta", "a"})
        for (const std::string encoding : {"", "url"})
            for (const std::size_t maxKeys : {1u, 4u, 1000u}) {
                SCOPED_TRACE("start-after='" + startAfter + "' " + describe(encoding, maxKeys, "", ""));
                auto query = queryFor(encoding, "", "");
                query.emplace_back("start-after", startAfter);
                std::vector<std::string> expected;
                for (const auto& key : sorted)
                    if (key > startAfter) expected.push_back(key);
                EXPECT_EQ(paginateV2(bucket(), query, maxKeys).items, expected);

                query.emplace_back("list-type", "2");
                const auto page = get(bucket(), query);
                EXPECT_EQ(page.start_after, std::optional<std::string>{startAfter}) << "StartAfter echoes the request";
            }
}

// StartAfter names a key, not a listing item: keys after it that roll up into a common prefix still list that prefix,
// even when StartAfter itself lies inside it. Only a position that is a common prefix skips what is under it.
TEST_F(S3GatewayListingDbTest, V2StartAfterInsideACommonPrefixStillListsIt) {
    seed(bucket(), {"a/1", "a/2", "a/3", "b", "c/1"});

    const auto inside = get(bucket(), {{"list-type", "2"}, {"delimiter", "/"}, {"start-after", "a/2"}});
    ASSERT_EQ(inside.status, s3l::bhttp::status::ok) << inside.body;
    EXPECT_EQ(inside.items(), (std::vector<std::string>{"a/", "b", "c/"}));

    const auto last = get(bucket(), {{"list-type", "2"}, {"delimiter", "/"}, {"start-after", "a/3"}});
    EXPECT_EQ(last.items(), (std::vector<std::string>{"b", "c/"}));

    const auto prefixItself = get(bucket(), {{"list-type", "2"}, {"delimiter", "/"}, {"start-after", "a/"}});
    EXPECT_EQ(prefixItself.items(), (std::vector<std::string>{"b", "c/"}));
}

// The token is opaque: whatever the last key was, it survives a query string and an XML document untouched, the
// answer echoes it, and it wins over StartAfter.
TEST_F(S3GatewayListingDbTest, V2TokenIsOpaqueAndEchoed) {
    seed(bucket(), {"a b/%2F+\xC3\xA9&<1>", "a b/%2F+\xC3\xA9&<2>", "z"});

    for (const std::string encoding : {"", "url"}) {
        SCOPED_TRACE("encoding-type=" + encoding);
        auto query = queryFor(encoding, "", "");
        query.emplace_back("list-type", "2");
        query.emplace_back("max-keys", "1");
        const auto first = get(bucket(), query);
        ASSERT_TRUE(first.next_token) << first.body;
        // Nothing a client would have to encode or decode: no '%', '/', '+', '&', '<' or space.
        EXPECT_EQ(first.next_token->find_first_of("%/+&<> "), std::string::npos) << *first.next_token;
        EXPECT_EQ(first.next_token->find("a b"), std::string::npos) << "the token is not the key";

        query.emplace_back("continuation-token", *first.next_token);
        query.emplace_back("start-after", "zzz");   // ignored when a token is given
        const auto second = get(bucket(), query);
        ASSERT_EQ(second.status, s3l::bhttp::status::ok) << second.body;
        EXPECT_EQ(second.keys, (std::vector<std::string>{"a b/%2F+\xC3\xA9&<2>"}));
        EXPECT_EQ(second.continuation_token, first.next_token);
    }
}

TEST_F(S3GatewayListingDbTest, V2RefusesATokenItDidNotIssue) {
    seed(bucket(), {"a", "b", "c"});

    for (const std::string token : {"b", "not-a-token", "probe%2Fbig-single.bin", "vh1.", "vh1.!!!!", "vh1.gA"}) {
        SCOPED_TRACE(token);
        const auto page = get(bucket(), {{"list-type", "2"}, {"continuation-token", token}});
        EXPECT_EQ(page.status, s3l::bhttp::status::bad_request) << page.body;
        EXPECT_EQ(page.error_code, "InvalidArgument");
    }
}

// ListObjects (v1) pages by Marker. Its answer has Marker and NextMarker (key fields, so percent-encoded under
// EncodingType=url, which SDKs decode) and neither KeyCount nor a continuation token.
TEST_F(S3GatewayListingDbTest, V1PagesByMarkerInByteOrder) {
    const auto keys = s3l::trickyKeys();
    seed(bucket(), keys);

    for (const std::string encoding : {"", "url"})
        for (const std::string delimiter : {"", "/", "%"})
            for (const std::string prefix : {"", "probe/", "probe/a"})
                for (const std::size_t maxKeys : {1u, 3u, 1000u}) {
                    SCOPED_TRACE(describe(encoding, maxKeys, prefix, delimiter));
                    const auto listing = paginateV1(bucket(), queryFor(encoding, prefix, delimiter), maxKeys);
                    EXPECT_EQ(listing.items, s3l::expectedItems(keys, prefix, delimiter));
                }
}

TEST_F(S3GatewayListingDbTest, V1NextMarkerIsTheLastItemOfATruncatedPage) {
    seed(bucket(), {"a/1", "a/2", "b c%", "d"});

    const auto prefixPage = get(bucket(), {{"delimiter", "/"}, {"max-keys", "1"}, {"encoding-type", "url"}});
    ASSERT_EQ(prefixPage.status, s3l::bhttp::status::ok) << prefixPage.body;
    EXPECT_EQ(prefixPage.common_prefixes, (std::vector<std::string>{"a/"}));
    EXPECT_EQ(prefixPage.next_marker, std::optional<std::string>{"a/"});
    EXPECT_NE(prefixPage.body.find("<NextMarker>a%2F</NextMarker>"), std::string::npos) << prefixPage.body;

    const auto keyPage = get(bucket(), {{"delimiter", "/"}, {"max-keys", "1"}, {"marker", "a/"}});
    EXPECT_EQ(keyPage.keys, (std::vector<std::string>{"b c%"}));
    EXPECT_EQ(keyPage.next_marker, std::optional<std::string>{"b c%"});
    EXPECT_EQ(keyPage.marker, std::optional<std::string>{"a/"});

    const auto lastPage = get(bucket(), {{"delimiter", "/"}, {"max-keys", "1"}, {"marker", "b c%"}});
    EXPECT_EQ(lastPage.keys, (std::vector<std::string>{"d"}));
    EXPECT_FALSE(lastPage.truncated);
    EXPECT_FALSE(lastPage.next_marker);
}

// Remote-backed buckets list the remote object index through the same query, so they page and sort the same way.
TEST_F(S3GatewayListingDbTest, RemoteBackedBucketsPageAndSortLikeLocalOnes) {
    const auto keys = s3l::trickyKeys();
    for (const std::string mode : {"remote_cache", "remote_proxy"}) {
        seed(bucket(mode), keys);
        for (const std::string encoding : {"", "url"})
            for (const std::string delimiter : {"", "/"})
                for (const std::size_t maxKeys : {1u, 3u, 1000u}) {
                    SCOPED_TRACE(mode + " " + describe(encoding, maxKeys, "probe/", delimiter));
                    const auto expected = s3l::expectedItems(keys, "probe/", delimiter);
                    EXPECT_EQ(paginateV2(bucket(mode), queryFor(encoding, "probe/", delimiter), maxKeys).items, expected);
                    EXPECT_EQ(paginateV1(bucket(mode), queryFor(encoding, "probe/", delimiter), maxKeys).items, expected);
                }
    }
}

// More keys than one page holds, at the default page size, the way an SDK paginator lists a real bucket.
TEST_F(S3GatewayListingDbTest, ABucketLargerThanOnePageListsCompletely) {
    const auto keys = vh::db::Transactions::exec("S3GatewayListingDbTest::bulk", [&](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO s3_gateway_object (vault_id, object_key, etag, size_bytes)
                SELECT $1,
                       'bulk/' || (i % 7)::text
                           || (ARRAY['-', '.', '/', ' ', '%', '+', '_', 'A', 'a', 'é'])[1 + i % 10]
                           || lpad(i::text, 5, '0'),
                       '"etag"', 1
                FROM generate_series(1, 2500) AS i
            )SQL",
            pqxx::params{bucket().vault_id});
        std::vector<std::string> out;
        for (const auto& row : txn.exec("SELECT object_key FROM s3_gateway_object WHERE vault_id = $1",
                                        pqxx::params{bucket().vault_id}))
            out.push_back(row[0].as<std::string>());
        return out;
    });
    ASSERT_EQ(keys.size(), 2500u);

    for (const std::string encoding : {"", "url"}) {
        SCOPED_TRACE("encoding-type=" + encoding);
        const auto v2 = paginateV2(bucket(), queryFor(encoding, "", ""), 1000);
        EXPECT_EQ(v2.items, s3l::expectedItems(keys, "", ""));
        EXPECT_EQ(v2.pages, 3u);

        const auto v1 = paginateV1(bucket(), queryFor(encoding, "", ""), 1000);
        EXPECT_EQ(v1.items, s3l::expectedItems(keys, "", ""));

        const auto folded = paginateV2(bucket(), queryFor(encoding, "bulk/", "/"), 1000);
        EXPECT_EQ(folded.items, s3l::expectedItems(keys, "bulk/", "/"));
    }
}

// ── Bucket subresources: configuration calls, never a listing, CreateBucket or DeleteBucket ─────────────────────────
//
// Every GET /<bucket>?<subresource> the router did not know used to be answered with a key listing (boto3:
// get_bucket_versioning, get_bucket_lifecycle_configuration and get_bucket_location "succeeded" with nothing in them,
// list_object_versions listed no versions), PUT /<bucket>?<subresource> was CreateBucket and DELETE was DeleteBucket.

namespace vh::test::s3listing {

// The subresources and what S3 answers for each on a bucket that never had it configured: a document (its element),
// an error (its code), or NotImplemented where the gateway can't answer truthfully.
struct SubresourceAnswer {
    std::string subresource;
    bhttp::status status;
    std::string answer;   // the document element for 200, the error code otherwise
};

inline std::vector<SubresourceAnswer> subresourceAnswers() {
    using enum bhttp::status;
    return {
        {"location", ok, "LocationConstraint"},
        {"versioning", ok, "VersioningConfiguration"},
        {"notification", ok, "NotificationConfiguration"},
        {"logging", ok, "BucketLoggingStatus"},
        {"accelerate", ok, "AccelerateConfiguration"},
        {"requestPayment", ok, "RequestPaymentConfiguration"},
        {"lifecycle", not_found, "NoSuchLifecycleConfiguration"},
        {"policy", not_found, "NoSuchBucketPolicy"},
        {"cors", not_found, "NoSuchCORSConfiguration"},
        {"tagging", not_found, "NoSuchTagSet"},
        {"encryption", not_found, "ServerSideEncryptionConfigurationNotFoundError"},
        {"object-lock", not_found, "ObjectLockConfigurationNotFoundError"},
        {"website", not_found, "NoSuchWebsiteConfiguration"},
        {"replication", not_found, "ReplicationConfigurationNotFoundError"},
        {"publicAccessBlock", not_found, "NoSuchPublicAccessBlockConfiguration"},
        {"ownershipControls", not_found, "OwnershipControlsNotFoundError"},
        {"versions", not_implemented, "NotImplemented"},
        {"acl", not_implemented, "NotImplemented"},
        {"policyStatus", not_implemented, "NotImplemented"},
        {"analytics", not_implemented, "NotImplemented"},
        {"inventory", not_implemented, "NotImplemented"},
        {"metrics", not_implemented, "NotImplemented"},
        {"intelligent-tiering", not_implemented, "NotImplemented"},
        {"metadataTable", not_implemented, "NotImplemented"},
        {"session", not_implemented, "NotImplemented"},
        {"delete", not_implemented, "NotImplemented"},          // DeleteObjects is POST ?delete
        {"someFutureSubresource", not_implemented, "NotImplemented"},
    };
}

// The configuration subresources a client writes with PUT and DELETE (and POST, which none of them takes).
inline std::vector<std::string> configurationSubresources() {
    return {"versioning", "lifecycle", "policy", "cors", "tagging", "encryption", "object-lock", "website",
            "replication", "publicAccessBlock", "ownershipControls", "acl", "notification", "logging", "accelerate",
            "requestPayment", "analytics", "inventory", "metrics", "intelligent-tiering", "metadataTable",
            "someFutureSubresource"};
}

// What a client sends to PUT a configuration: a small, well-formed document (its content doesn't matter).
inline std::string configurationBody(const std::string& subresource) {
    if (subresource == "versioning")
        return "<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Status>Enabled</Status>"
               "</VersioningConfiguration>";
    if (subresource == "policy") return R"({"Version":"2012-10-17","Statement":[]})";
    return "<Configuration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"/>";
}

}  // namespace vh::test::s3listing

TEST_F(S3GatewayListingDbTest, BucketSubresourcesAnswerWhatS3AnswersForAnUnconfiguredBucket) {
    for (const std::string mode : {"local", "remote_cache", "remote_proxy"}) {
        seed(bucket(mode), {"a", "listed/key"});
        for (const auto& expected : s3l::subresourceAnswers()) {
            for (const std::string target : {"/" + bucket(mode).name + "?" + expected.subresource,
                                             "/" + bucket(mode).name + "?" + expected.subresource + "="}) {
                SCOPED_TRACE(mode + " GET " + target);
                const auto a = send(s3l::bhttp::verb::get, target);
                EXPECT_EQ(a.status, expected.status) << a.body;
                EXPECT_EQ(a.status == s3l::bhttp::status::ok ? a.root : a.error_code, expected.answer) << a.body;
                EXPECT_EQ(a.body.find("listed/key"), std::string::npos) << "a subresource is not a listing";
                EXPECT_NE(a.root, "ListBucketResult");
            }
        }

        const auto location = send(s3l::bhttp::verb::get, "/" + bucket(mode).name + "?location");
        EXPECT_TRUE(location.text.empty()) << "us-east-1 is an empty LocationConstraint: " << location.body;
        const auto versioning = send(s3l::bhttp::verb::get, "/" + bucket(mode).name + "?versioning");
        EXPECT_TRUE(versioning.children.empty()) << "never enabled: no Status, no MfaDelete: " << versioning.body;
        const auto several = send(s3l::bhttp::verb::get, "/" + bucket(mode).name + "?versioning&lifecycle");
        EXPECT_EQ(several.status, s3l::bhttp::status::not_implemented) << several.body;
    }
}

// The listing, paging and signing parameters, valued or bare, still list; ?uploads still lists multipart uploads.
TEST_F(S3GatewayListingDbTest, ListingParametersAreNotSubresources) {
    for (const std::string mode : {"local", "remote_cache", "remote_proxy"}) {
        SCOPED_TRACE(mode);
        seed(bucket(mode), {"a", "b/c"});
        const auto& name = bucket(mode).name;

        const auto v2 = get(bucket(mode), {{"list-type", "2"}, {"x-id", "ListObjectsV2"}, {"fetch-owner", "true"},
                                           {"encoding-type", "url"}, {"max-keys", "1000"}});
        EXPECT_EQ(v2.status, s3l::bhttp::status::ok) << v2.body;
        EXPECT_EQ(v2.keys, (std::vector<std::string>{"a", "b/c"}));

        for (const std::string query : {"?prefix&delimiter=%2F", "?prefix=&delimiter=%2F&marker", "?list-type=2&prefix&start-after"}) {
            const auto bare = send(s3l::bhttp::verb::get, "/" + name + query);
            EXPECT_EQ(bare.status, s3l::bhttp::status::ok) << query << ": " << bare.body;
            EXPECT_EQ(bare.root, "ListBucketResult") << query << ": " << bare.body;
        }

        for (const std::string query : {"?uploads", "?uploads&prefix=a", "?uploads&key-marker&upload-id-marker"}) {
            const auto uploads = send(s3l::bhttp::verb::get, "/" + name + query);
            EXPECT_EQ(uploads.status, s3l::bhttp::status::ok) << query << ": " << uploads.body;
            EXPECT_EQ(uploads.root, "ListMultipartUploadsResult") << query << ": " << uploads.body;
        }
    }
}

// The write cases. Before, with a credential that may create and delete buckets, PUT /<bucket>?versioning (or any
// configuration PUT) was CreateBucket, which created a bucket that did not exist, and DELETE /<bucket>?lifecycle (or
// any configuration DELETE) was DeleteBucket, which deleted an empty bucket. Now each is NotImplemented and changes
// nothing; a missing bucket stays missing (NoSuchBucket, as a listing of it answers).
TEST_F(S3GatewayListingDbTest, ConfigurationWritesNeitherCreateNorDeleteABucket) {
    using vh::db::query::s3::Gateway;
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    const vh::protocols::s3::CredentialManager manager;
    const auto owner = manager.createCredential({
        .created_by = admin->id,
        .principal_user_id = admin->id,
        .name = "subresources-owner-" + s3gw_l::uniqueSuffix("credential"),
        .scope_mode = "user_access",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .vault_scopes = {}
    });
    const auto ownerSend = [&](const s3l::bhttp::verb verb, const std::string& target, std::string body = {}) {
        return send(verb, target, owner.credential.access_key, owner.secret_access_key, std::move(body));
    };

    for (const std::string mode : {"local", "remote_cache", "remote_proxy"}) {
        const auto target = freshBucket(mode);
        for (const auto& subresource : s3l::configurationSubresources()) {
            const auto url = "/" + target.name + "?" + subresource;
            SCOPED_TRACE(mode + " " + url);

            const auto put = ownerSend(s3l::bhttp::verb::put, url, s3l::configurationBody(subresource));
            EXPECT_EQ(put.status, s3l::bhttp::status::not_implemented) << put.body;
            EXPECT_EQ(put.error_code, "NotImplemented") << put.body;

            const auto del = ownerSend(s3l::bhttp::verb::delete_, url);
            EXPECT_EQ(del.status, s3l::bhttp::status::not_implemented) << del.body;
            EXPECT_EQ(del.error_code, "NotImplemented") << del.body;
            ASSERT_TRUE(Gateway::resolveBucket(target.name)) << "a configuration DELETE deleted the bucket";

            const auto post = ownerSend(s3l::bhttp::verb::post, url, s3l::configurationBody(subresource));
            EXPECT_EQ(post.status, s3l::bhttp::status::not_implemented) << post.body;
        }
        // Nothing was configured, and the bucket is still empty and still there.
        const auto versioning = ownerSend(s3l::bhttp::verb::get, "/" + target.name + "?versioning");
        EXPECT_EQ(versioning.root, "VersioningConfiguration") << versioning.body;
        EXPECT_TRUE(versioning.children.empty()) << versioning.body;
        const auto lifecycle = ownerSend(s3l::bhttp::verb::get, "/" + target.name + "?lifecycle");
        EXPECT_EQ(lifecycle.error_code, "NoSuchLifecycleConfiguration") << lifecycle.body;

        // The credential can delete this bucket: DeleteBucket itself still does.
        const auto deleted = ownerSend(s3l::bhttp::verb::delete_, "/" + target.name);
        EXPECT_EQ(deleted.status, s3l::bhttp::status::no_content) << deleted.body;
        EXPECT_FALSE(Gateway::resolveBucket(target.name));
    }

    const auto absent = "subresources-absent-" + std::to_string(bucket().vault_id);
    ASSERT_FALSE(Gateway::resolveBucket(absent));
    for (const auto& subresource : s3l::configurationSubresources()) {
        SCOPED_TRACE("PUT /" + absent + "?" + subresource);
        const auto put = ownerSend(s3l::bhttp::verb::put, "/" + absent + "?" + subresource,
                                   s3l::configurationBody(subresource));
        EXPECT_EQ(put.status, s3l::bhttp::status::not_found) << put.body;
        EXPECT_EQ(put.error_code, "NoSuchBucket") << put.body;
        ASSERT_FALSE(Gateway::resolveBucket(absent)) << "a configuration PUT created the bucket";
    }
}

// A caller who may not list a bucket gets the error a listing gets, whatever subresource or method it names: nothing
// about the bucket's configuration, and no hint that a configuration call would have been treated differently.
TEST_F(S3GatewayListingDbTest, SubresourceCallsAreAuthorisedAsAListingIs) {
    const auto outsiderVault = freshBucket("local");   // the only vault the outsider credential may list
    const vh::protocols::s3::CredentialManager manager;
    const auto outsider = manager.createCredential({
        .created_by = adminId,
        .principal_user_id = adminId,
        .name = "subresources-outsider-" + s3gw_l::uniqueSuffix("credential"),
        .scope_mode = "vault_allowlist",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .vault_scopes = {{
            .credential_id = 0,
            .vault_id = outsiderVault.vault_id,
            .can_list = true,
            .can_read = true,
            .can_write = true,
            .can_delete = true,
            .can_admin = true
        }}
    });
    const std::vector<std::pair<s3l::bhttp::verb, std::string>> calls{
        {s3l::bhttp::verb::get, "?versioning"}, {s3l::bhttp::verb::get, "?location"},
        {s3l::bhttp::verb::get, "?lifecycle"}, {s3l::bhttp::verb::get, "?versions"},
        {s3l::bhttp::verb::get, "?acl"}, {s3l::bhttp::verb::get, "?someFutureSubresource"},
        {s3l::bhttp::verb::put, "?versioning"}, {s3l::bhttp::verb::put, "?policy"},
        {s3l::bhttp::verb::delete_, "?lifecycle"}, {s3l::bhttp::verb::delete_, "?policy"},
        {s3l::bhttp::verb::post, "?lifecycle"}};

    const auto sameAsListing = [&](const std::string& bucketName, const std::string& who, const std::string& key,
                                   const std::string& secret) {
        const auto listing = send(s3l::bhttp::verb::get, "/" + bucketName, key, secret);
        EXPECT_NE(listing.status, s3l::bhttp::status::ok) << who << ": " << listing.body;
        for (const auto& [verb, query] : calls) {
            SCOPED_TRACE(who + " " + std::string(s3l::bhttp::to_string(verb)) + " /" + bucketName + query);
            const auto a = send(verb, "/" + bucketName + query, key, secret);
            EXPECT_EQ(a.status, listing.status) << a.body;
            EXPECT_EQ(a.error_code, listing.error_code) << a.body;
        }
    };

    for (const std::string mode : {"local", "remote_cache", "remote_proxy"}) {
        sameAsListing(bucket(mode).name, mode + " outsider", outsider.credential.access_key, outsider.secret_access_key);
        sameAsListing(bucket(mode).name, mode + " unsigned", "", "");
        EXPECT_TRUE(vh::db::query::s3::Gateway::resolveBucket(bucket(mode).name));
    }
    sameAsListing("subresources-missing-" + std::to_string(outsiderVault.vault_id), "missing bucket", accessKey,
                  secretKey);
    const auto missing = send(s3l::bhttp::verb::get, "/subresources-missing-" +
                                                         std::to_string(outsiderVault.vault_id) + "?versioning");
    EXPECT_EQ(missing.error_code, "NoSuchBucket") << missing.body;
}
