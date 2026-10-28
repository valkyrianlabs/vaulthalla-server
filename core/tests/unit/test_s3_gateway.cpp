#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/s3/Gateway.hpp"
#include "db/query/vault/Vault.hpp"
#include "concurrency/ThreadPoolManager.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "config/config_yaml.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/Path.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/s3/CredentialManager.hpp"
#include "ops/Error.hpp"
#include "ops/S3Gateway.hpp"
#include "protocols/s3/MultipartStore.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "protocols/s3/GatewayService.hpp"
#include "protocols/s3/Router.hpp"
#include "protocols/s3/Session.hpp"
#include "protocols/s3/SigV4.hpp"
#include "protocols/s3/Xml.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/handler/S3Gateway.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/fs/glob/model/Pattern.hpp"
#include "rbac/permission/admin/S3Gateway.hpp"
#include "rbac/s3/policy/Evaluator.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "UsageManager.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/pricing/GatewayPriceEstimate.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/Vault.hpp"

#include <boost/asio.hpp>
#include <boost/beast/http.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>
#include <paths.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <yaml-cpp/yaml.h>

#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <optional>
#include <sstream>
#include <thread>
#include <utility>
#include <vector>

namespace {
namespace beast = boost::beast;

// Own helper (not the identically named one in test_s3_cost_safety.cpp): unity builds only share it when both
// files land in the same chunk.
std::string s3GatewayUniqueSuffix(const std::string& label) {
    return label + "_" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
}

namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

struct ConfigRestore {
    vh::config::Config previous;

    explicit ConfigRestore(vh::config::Config cfg)
        : previous(std::move(cfg)) {}

    ~ConfigRestore() {
        vh::config::Registry::set(previous);
    }
};

struct ThreadPoolShutdown {
    bool active = false;

    ~ThreadPoolShutdown() {
        if (active)
            vh::concurrency::ThreadPoolManager::instance().shutdown();
    }
};

uint16_t freeLoopbackPort() {
    boost::asio::io_context ioc;
    tcp::acceptor acceptor(ioc, tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), 0));
    return acceptor.local_endpoint().port();
}

http::response<http::string_body> httpGetRoot(const uint16_t port) {
    boost::asio::io_context ioc;
    tcp::socket socket(ioc);
    socket.connect(tcp::endpoint(boost::asio::ip::make_address("127.0.0.1"), port));

    timeval timeout{
        .tv_sec = 5,
        .tv_usec = 0
    };
    (void)::setsockopt(socket.native_handle(), SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)::setsockopt(socket.native_handle(), SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    http::request<http::string_body> req{http::verb::get, "/", 11};
    req.set(http::field::host, "127.0.0.1:" + std::to_string(port));
    req.set(http::field::user_agent, "vaulthalla-s3-gateway-test");
    req.prepare_payload();

    http::write(socket, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(socket, buffer, res);
    return res;
}

std::string amzNow() {
    const auto now = std::chrono::system_clock::now();
    const auto ts = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&ts, &tm);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y%m%dT%H%M%SZ");
    return out.str();
}

std::string amzAfter(const std::chrono::seconds offset) {
    const auto ts = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now() + offset);
    std::tm tm{};
    gmtime_r(&ts, &tm);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y%m%dT%H%M%SZ");
    return out.str();
}

std::string scopeDate(const std::string& amzDate) {
    return amzDate.substr(0, 8);
}

void signS3GatewayRequest(
    vh::protocols::s3::Router::Request& request,
    const std::string& accessKey,
    const std::string& secretKey,
    const std::string& signedHeaders = "host;x-amz-content-sha256;x-amz-date") {
    using namespace vh::protocols::s3::sigv4;

    const auto bodyHash = sha256Hex(request.body());
    const auto amzDate = amzNow();
    request.set("x-amz-content-sha256", bodyHash);
    request.set("x-amz-date", amzDate);

    VerificationInput input = inputFromRequest(request, request.body());
    ParsedAuth auth{
        .credential = {
            .access_key = accessKey,
            .date = scopeDate(amzDate),
            .region = "us-east-1",
            .service = "s3"
        },
        .signed_headers = signedHeaders,
        .signature = {},
        .amz_date = amzDate,
        .payload_hash = bodyHash
    };
    auth.signature = signatureFor(input, auth, secretKey);
    request.set(
        http::field::authorization,
        "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + auth.credential.date + "/us-east-1/s3/aws4_request, "
        "SignedHeaders=" + auth.signed_headers + ", Signature=" + auth.signature);
}

uint32_t ensureS3GatewayAdminRole(pqxx::work& txn, const vh::rbac::role::Admin& role) {
    return txn.exec(
        R"SQL(
            INSERT INTO admin_role (
                name,
                description,
                identity_permissions,
                audit_permissions,
                settings_permissions,
                roles_permissions,
                vaults_permissions,
                keys_permissions,
                s3_gateway_permissions
            )
            VALUES ($1, $2, $3::bit(32), $4::bit(8), $5::bit(64), $6::bit(16), $7::bit(32), $8::bit(32), $9::bit(8))
            ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                identity_permissions = EXCLUDED.identity_permissions,
                audit_permissions = EXCLUDED.audit_permissions,
                settings_permissions = EXCLUDED.settings_permissions,
                roles_permissions = EXCLUDED.roles_permissions,
                vaults_permissions = EXCLUDED.vaults_permissions,
                keys_permissions = EXCLUDED.keys_permissions,
                s3_gateway_permissions = EXCLUDED.s3_gateway_permissions
            RETURNING id
        )SQL",
        pqxx::params{
            role.name,
            role.description,
            role.identities.toBitString(),
            role.audits.toBitString(),
            role.settings.toBitString(),
            role.roles.toBitString(),
            role.vaults.toBitString(),
            role.keys.toBitString(),
            role.s3Gateway.toBitString()
        }).one_field_ref().as<uint32_t>();
}

uint32_t insertS3GatewayHydratableTestUser(
    pqxx::work& txn,
    const std::string& name,
    const std::string& email,
    const vh::rbac::role::Admin& role = vh::rbac::role::Admin::None()) {
    const auto userId = txn.exec(
        "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
        pqxx::params{name, email, "hash"}
    ).one_field_ref().as<uint32_t>();
    const auto roleId = ensureS3GatewayAdminRole(txn, role);
    txn.exec(
        "INSERT INTO admin_role_assignments (user_id, role_id) VALUES ($1, $2)",
        pqxx::params{userId, roleId});
    return userId;
}

std::vector<uint8_t> hexBytes(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (std::size_t i = 0; i + 1 < hex.size(); i += 2)
        out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    return out;
}

std::string uniqueS3Name(const std::string& label) {
    auto out = vh::vault::model::slugifyName(s3GatewayUniqueSuffix(label));
    if (out.size() > 63) out.resize(63);
    while (!out.empty() && out.back() == '-') out.pop_back();
    if (out.size() < 3) out = "s3-" + out;
    return out;
}

} // namespace

TEST(S3GatewayConfigTest, DefaultsToDisabledFiveGiBBodyLimit) {
    const vh::config::S3GatewayConfig cfg;

    EXPECT_FALSE(cfg.enabled);
    EXPECT_EQ(cfg.host, "0.0.0.0");
    EXPECT_EQ(cfg.port, 39000);
    EXPECT_EQ(cfg.max_body_size_bytes, 5ull * 1024ull * 1024ull * 1024ull);
    EXPECT_TRUE(cfg.require_sigv4);
    EXPECT_EQ(cfg.default_bucket_mode, "local");
    EXPECT_TRUE(cfg.default_api_exclusive);
    // The remote vault defaults moved to vaults.s3 (#164).
    const vh::config::VaultsS3Config vaultDefaults;
    EXPECT_EQ(vaultDefaults.default_remote_sync_strategy, "cache");
    EXPECT_EQ(vaultDefaults.default_remote_conflict_policy, "ask");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.list, "0.00000001");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.head, "0.00000001");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.get, "0.00000001");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.put, "0.00000001");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.delete_, "0.00000001");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.copy, "0.00000001");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.downloaded_gb, "0.00000000");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.uploaded_gb, "0.00000000");
}

TEST(S3GatewayConfigTest, YamlMapsBodyLimitMbAndClampsMultipartValues) {
    const auto node = YAML::Load(R"yaml(
enabled: true
host: 127.0.0.1
port: 39123
max_body_size_mb: 64
require_sigv4: false
allow_path_style: false
allow_virtual_hosted_style: true
multipart:
  part_dir: /tmp/vh-s3-parts
  min_part_size_mb: 1
  abort_after_days: 0
synthetic_local_request_cost_usd:
  list: "0.00000002"
  head: "0.00000003"
  get: "0.00000004"
  put: "0.00000005"
  delete: "0.00000006"
  copy: "0.00000007"
  downloaded_gb: "0.00000008"
  uploaded_gb: "0.00000009"
)yaml");

    const auto cfg = node.as<vh::config::S3GatewayConfig>();

    EXPECT_TRUE(cfg.enabled);
    EXPECT_EQ(cfg.host, "127.0.0.1");
    EXPECT_EQ(cfg.port, 39123);
    EXPECT_EQ(cfg.max_body_size_bytes, 64ull * 1024ull * 1024ull);
    EXPECT_FALSE(cfg.require_sigv4);
    EXPECT_FALSE(cfg.allow_path_style);
    EXPECT_TRUE(cfg.allow_virtual_hosted_style);
    EXPECT_EQ(cfg.multipart.min_part_size_mb, 5u);
    EXPECT_EQ(cfg.multipart.abort_after_days, 1u);
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.list, "0.00000002");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.head, "0.00000003");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.get, "0.00000004");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.put, "0.00000005");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.delete_, "0.00000006");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.copy, "0.00000007");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.downloaded_gb, "0.00000008");
    EXPECT_EQ(cfg.synthetic_local_request_cost_usd.uploaded_gb, "0.00000009");
}

TEST(S3GatewayConfigTest, JsonAndYamlPreferExplicitBytesOverMegabytes) {
    const nlohmann::json raw = {
        {"max_body_size_bytes", 12345},
        {"max_body_size_mb", 64}
    };
    const auto jsonCfg = raw.get<vh::config::S3GatewayConfig>();
    EXPECT_EQ(jsonCfg.max_body_size_bytes, 12345u);

    const auto yamlCfg = YAML::Load(R"yaml(
max_body_size_bytes: 54321
max_body_size_mb: 64
)yaml").as<vh::config::S3GatewayConfig>();
    EXPECT_EQ(yamlCfg.max_body_size_bytes, 54321u);
}

TEST(S3GatewayConfigTest, MultipartPartDirIsNotEmittedAndLegacyPartDirIsIgnored) {
    const auto yamlCfg = YAML::Load(R"yaml(
multipart:
  part_dir: /tmp/legacy-vh-s3-parts
  min_part_size_mb: 8
  abort_after_days: 3
)yaml").as<vh::config::S3GatewayConfig>();
    EXPECT_EQ(yamlCfg.multipart.min_part_size_mb, 8u);
    EXPECT_EQ(yamlCfg.multipart.abort_after_days, 3u);

    const auto yamlNode = YAML::convert<vh::config::S3GatewayMultipartConfig>::encode(yamlCfg.multipart);
    EXPECT_FALSE(static_cast<bool>(yamlNode["part_dir"]));

    nlohmann::json jsonCfg = yamlCfg.multipart;
    EXPECT_FALSE(jsonCfg.contains("part_dir"));

    const auto fromJson = nlohmann::json{
        {"part_dir", "/tmp/legacy-json-vh-s3-parts"},
        {"min_part_size_mb", 9},
        {"abort_after_days", 4}
    }.get<vh::config::S3GatewayMultipartConfig>();
    EXPECT_EQ(fromJson.min_part_size_mb, 9u);
    EXPECT_EQ(fromJson.abort_after_days, 4u);
}

TEST(S3GatewayMultipartTest, PartRootUsesGeneratedHiddenBackingPath) {
    const auto oldBackingPath = vh::paths::backingPath;
    const auto tempBacking = std::filesystem::temp_directory_path() / s3GatewayUniqueSuffix("vh_s3_gateway_parts_root");
    vh::paths::backingPath = tempBacking;

    EXPECT_EQ(vh::protocols::s3::MultipartStore::partRoot(),
              vh::paths::getS3GatewayMultipartPartsPath());
    EXPECT_EQ(vh::protocols::s3::MultipartStore::partRoot().filename().string(),
              std::string(VH_S3_GATEWAY_MULTIPART_PARTS_DIRNAME));

    vh::paths::backingPath = tempBacking / "changed";
    EXPECT_EQ(vh::protocols::s3::MultipartStore::partRoot(),
              vh::paths::getS3GatewayMultipartPartsPath());

    vh::paths::backingPath = oldBackingPath;
    std::filesystem::remove_all(tempBacking);
}

TEST(S3GatewayXmlTest, EscapesXmlReservedCharacters) {
    EXPECT_EQ(vh::protocols::s3::xml::escape("a&b<c>d\"e'f"),
              "a&amp;b&lt;c&gt;d&quot;e&apos;f");
}

TEST(S3GatewayXmlTest, DeleteResultHonorsQuietModeAndErrors) {
    using namespace vh::protocols::s3::xml;
    const auto xml = deleteResult({DeletedObject{.key = "ok.txt"}},
                                  {DeleteError{.key = "bad&.txt", .code = "AccessDenied", .message = "no <delete>"}},
                                  true);
    EXPECT_EQ(xml.find("<Deleted>"), std::string::npos);
    EXPECT_NE(xml.find("<Key>bad&amp;.txt</Key>"), std::string::npos);
    EXPECT_NE(xml.find("<Message>no &lt;delete&gt;</Message>"), std::string::npos);
}

TEST(S3GatewayXmlTest, ListObjectsV2UrlEncodesKeyFieldsWhenRequested) {
    vh::db::query::s3::ObjectListResult result;
    result.objects.push_back({
        .vault_id = 1,
        .object_key = "folder/a b&<.txt",
        .etag = "\"etag\"",
        .size_bytes = 3,
        .content_type = "text/plain",
        .storage_class = "STANDARD",
        .last_modified = 0,
        .multipart = false,
        .part_count = std::nullopt
    });
    result.common_prefixes.push_back("folder/sub dir/");
    result.next_continuation_token = "folder/next key&.txt";
    result.is_truncated = true;

    const auto xml = vh::protocols::s3::xml::listObjectsV2(
        "bucket",
        result,
        "folder/",
        std::make_optional<std::string>("/"),
        1000,
        std::make_optional<std::string>("url"));

    EXPECT_NE(xml.find("<EncodingType>url</EncodingType>"), std::string::npos);
    EXPECT_NE(xml.find("<Prefix>folder%2F</Prefix>"), std::string::npos);
    EXPECT_NE(xml.find("<Delimiter>%2F</Delimiter>"), std::string::npos);
    EXPECT_NE(xml.find("<Key>folder%2Fa%20b%26%3C.txt</Key>"), std::string::npos);
    EXPECT_NE(xml.find("<CommonPrefixes><Prefix>folder%2Fsub%20dir%2F</Prefix></CommonPrefixes>"), std::string::npos);
    EXPECT_NE(xml.find("<NextContinuationToken>folder%2Fnext%20key%26.txt</NextContinuationToken>"), std::string::npos);
}

TEST(S3GatewayObjectStoreTest, ComputesS3StyleEtags) {
    using vh::protocols::s3::ObjectStore;
    const std::vector<uint8_t> hello{'h', 'e', 'l', 'l', 'o'};

    EXPECT_EQ(ObjectStore::md5Hex(hello), "5d41402abc4b2a76b9719d911017c592");
    EXPECT_EQ(ObjectStore::multipartEtag({
                  hexBytes("5d41402abc4b2a76b9719d911017c592"),
                  hexBytes("7d793037a0760186574b0282f2f435e7")
              }),
              "\"065947336a2f2a95ba8899f3675c3be6-2\"");
}

TEST(S3GatewayObjectStoreTest, RejectsTraversalObjectKeys) {
    using vh::protocols::s3::ObjectStore;

    EXPECT_EQ(ObjectStore::keyToVaultPath("nested/object.txt"), "/nested/object.txt");
    EXPECT_THROW((void)ObjectStore::keyToVaultPath("../escape.txt"), std::runtime_error);
    EXPECT_THROW((void)ObjectStore::keyToVaultPath("nested/../../escape.txt"), std::runtime_error);
}

TEST(S3GatewayObjectStoreTest, PreservesDirectoryMarkerTrailingSlash) {
    using vh::protocols::s3::ObjectStore;

    const auto vaultPath = ObjectStore::keyToVaultPath("folder/");
    EXPECT_EQ(vaultPath.generic_string(), "/folder/");
    EXPECT_EQ(ObjectStore::vaultPathToKey(vaultPath), "folder/");
}

TEST(S3GatewayObjectStoreTest, OnlyDevCredentialFastPathBypassesDatabase) {
    using vh::protocols::s3::AuthContext;
    using vh::protocols::s3::ObjectStore;
    using Action = vh::rbac::permission::vault::FilesystemAction;

    AuthContext dev;
    dev.credential_id = 123;
    dev.scope_mode = "vault_allowlist";
    dev.dev_context = true;
    EXPECT_TRUE(ObjectStore::credentialAllows(dev, 55, Action::Delete));

    AuthContext userAccess;
    userAccess.credential_id = 123;
    userAccess.scope_mode = "user_access";
    EXPECT_FALSE(ObjectStore::credentialAllows(userAccess, 55, Action::Read));

    AuthContext unknownScope;
    unknownScope.credential_id = 123;
    unknownScope.scope_mode = "unknown";
    EXPECT_FALSE(ObjectStore::credentialAllows(unknownScope, 55, Action::Read));
}

TEST(S3GatewayObjectStoreTest, UserAccessCredentialDoesNotAuthorizeBucketAdminWithoutGatewayRole) {
    using vh::protocols::s3::GatewayAccessContext;
    using vh::protocols::s3::ObjectStore;
    using vh::protocols::s3::ResolvedBucket;

    vh::identities::UserState userState;
    userState.name = "gateway-user-access-non-admin";
    userState.roles.admin = std::make_shared<vh::rbac::role::Admin>( vh::rbac::role::Admin::None(42));
    auto user = vh::identities::User::detached(42, std::move(userState));

    ResolvedBucket bucket{
        .bucket_name = "admin-op",
        .vault_id = 55,
        .mode = "local",
        .api_exclusive = true,
        .engine = nullptr,
        .actor = user,
        .gateway_access = GatewayAccessContext{
            .credential_id = 123,
            .access_key = "VHTESTUSERACCESS",
            .scope_mode = "user_access",
            .credential = {},
            .dev_context = false
        }
    };

    EXPECT_FALSE(ObjectStore::credentialAllowsAdmin(bucket));

    {

        auto next = *user->state();

        next.roles.admin = std::make_shared<vh::rbac::role::Admin>(
        vh::rbac::role::Admin::SuperAdmin(user->id));

        user->replaceDetachedState(std::move(next));

    }
    EXPECT_FALSE(ObjectStore::credentialAllowsAdmin(bucket));
}

TEST(S3GatewayPricingTest, OperationNamesMatchBudgetLedgerValues) {
    using namespace vh::storage::s3::pricing;

    EXPECT_EQ(toString(S3GatewayOperation::PutObject), "PutObject");
    EXPECT_EQ(toString(S3GatewayOperation::GetObject), "GetObject");
    EXPECT_EQ(toString(S3GatewayOperation::DeleteObject), "DeleteObject");
    EXPECT_EQ(toString(S3GatewayOperation::CompleteMultipartUpload), "CompleteMultipartUpload");
}

TEST(S3GatewayRouterTest, ParsesPathStyleBucketAndPreservesPlusInKey) {
    using vh::protocols::s3::Router;

    Router::Request request{boost::beast::http::verb::get, "/bucket/a+b%2Bc.txt?prefix=a+b&encoding-type=url", 11};
    request.set(boost::beast::http::field::host, "127.0.0.1:39000");

    const auto parsed = Router::parseRequestTarget(request);
    EXPECT_EQ(parsed.bucket, "bucket");
    EXPECT_EQ(parsed.key, "a+b+c.txt");
    ASSERT_TRUE(parsed.query.contains("prefix"));
    EXPECT_EQ(parsed.query.at("prefix"), "a+b");
    EXPECT_EQ(parsed.query.at("encoding-type"), "url");
}

TEST(S3GatewayRouterTest, ParsesVirtualHostedBucket) {
    using vh::protocols::s3::Router;

    Router::Request request{boost::beast::http::verb::get, "/folder/a%20b+plus.txt?uploads", 11};
    request.set(boost::beast::http::field::host, "photos.example.test:39000");

    const auto parsed = Router::parseRequestTarget(request);
    EXPECT_EQ(parsed.bucket, "photos");
    EXPECT_EQ(parsed.key, "folder/a b+plus.txt");
    EXPECT_TRUE(parsed.query.contains("uploads"));
}

TEST(S3GatewayRouterTest, DedicatedS3HostUsesPathStyleWhenProxyMarkerIsPresent) {
    using vh::protocols::s3::Router;

    Router::Request object{boost::beast::http::verb::get, "/bucket/a%2Fb.txt?uploadId=1", 11};
    object.set(boost::beast::http::field::host, "s3.vaulthalla.dev");
    object.set("X-Vaulthalla-S3-Path-Style-Only", "true");
    const auto parsed = Router::parseRequestTarget(object);
    EXPECT_EQ(parsed.bucket, "bucket");
    EXPECT_EQ(parsed.key, "a/b.txt");
    ASSERT_TRUE(parsed.query.contains("uploadId"));
    EXPECT_EQ(parsed.query.at("uploadId"), "1");
}

TEST(S3GatewayRouterTest, ApiS3IsOrdinaryPathStyleWithoutPrefixRouting) {
    using vh::protocols::s3::Router;

    Router::Request request{boost::beast::http::verb::get, "/api/s3/bucket/key.txt", 11};
    request.set(boost::beast::http::field::host, "127.0.0.1:39000");

    const auto parsed = Router::parseRequestTarget(request);
    EXPECT_EQ(parsed.bucket, "api");
    EXPECT_EQ(parsed.key, "s3/bucket/key.txt");
}

TEST(S3GatewayRouterTest, PublicHostStillTriggersVirtualHostedBucketWithoutProxyMarker) {
    using vh::protocols::s3::Router;

    Router::Request request{boost::beast::http::verb::get, "/path-bucket/object.txt", 11};
    request.set(boost::beast::http::field::host, "photos.example.test:39000");

    const auto parsed = Router::parseRequestTarget(request);
    EXPECT_EQ(parsed.bucket, "photos");
    EXPECT_EQ(parsed.key, "path-bucket/object.txt");
}

TEST(S3GatewayRouterTest, FalsePathStyleOnlyMarkerLeavesVirtualHostedBucketEnabled) {
    using vh::protocols::s3::Router;

    Router::Request request{boost::beast::http::verb::get, "/path-bucket/object.txt", 11};
    request.set(boost::beast::http::field::host, "photos.example.test:39000");
    request.set("X-Vaulthalla-S3-Path-Style-Only", "false");

    const auto parsed = Router::parseRequestTarget(request);
    EXPECT_EQ(parsed.bucket, "photos");
    EXPECT_EQ(parsed.key, "path-bucket/object.txt");
}

TEST(S3GatewayRouterTest, RejectsPathStyleWhenDisabled) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.allow_path_style = false;
    cfg.s3_gateway.allow_virtual_hosted_style = true;
    vh::config::Registry::set(cfg);

    using vh::protocols::s3::Router;
    Router::Request request{boost::beast::http::verb::get, "/bucket/object.txt", 11};
    request.set(boost::beast::http::field::host, "127.0.0.1:39000");

    EXPECT_THROW((void)Router::parseRequestTarget(request), vh::protocols::s3::S3Error);
}

TEST(S3GatewayRouterTest, HonorsVirtualHostedStyleDisabled) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.allow_path_style = true;
    cfg.s3_gateway.allow_virtual_hosted_style = false;
    vh::config::Registry::set(cfg);

    using vh::protocols::s3::Router;
    Router::Request request{boost::beast::http::verb::get, "/path-bucket/object.txt", 11};
    request.set(boost::beast::http::field::host, "photos.example.test:39000");

    const auto parsed = Router::parseRequestTarget(request);
    EXPECT_EQ(parsed.bucket, "path-bucket");
    EXPECT_EQ(parsed.key, "object.txt");
}

TEST(S3GatewayRouterTest, ParsesCopySourceBeforeDecodingQuerySeparators) {
    using vh::protocols::s3::Router;

    const auto source = Router::parseCopySource("/source-bucket/folder/a%3Fb%2Bc.txt?versionId=123");
    EXPECT_EQ(source.bucket, "source-bucket");
    EXPECT_EQ(source.key, "folder/a?b+c.txt");
    ASSERT_TRUE(source.query.contains("versionId"));
    EXPECT_EQ(source.query.at("versionId"), "123");
}

TEST(S3GatewayRouterTest, ComputesAwsChecksumHeaderValues) {
    using vh::protocols::s3::Router;

    const std::vector<uint8_t> hello{'h', 'e', 'l', 'l', 'o'};
    EXPECT_EQ(Router::checksumCrc32Base64(hello), "NhCmhg==");
    EXPECT_EQ(Router::checksumSha256Base64(hello), "LPJNul+wow4m6DsqxbninhsWHlwfp0JecwQzYpOLmCQ=");
}

TEST(S3GatewaySigV4Test, CanonicalizesUriAndQuery) {
    using namespace vh::protocols::s3::sigv4;

    EXPECT_EQ(canonicalUri("/photos/a b/%7Efile.txt"), "/photos/a%20b/~file.txt");
    EXPECT_EQ(canonicalUri("/photos/a+b.txt"), "/photos/a%2Bb.txt");
    EXPECT_EQ(canonicalQueryString("b=two&a=1&X-Amz-Signature=dead&a=0&space=a%20b"),
              "a=0&a=1&b=two&space=a%20b");
    EXPECT_EQ(canonicalQueryString("prefix=a+b&space=a%20b"), "prefix=a%2Bb&space=a%20b");
}

TEST(S3GatewaySigV4Test, VerifiesHeaderSignatureAndRejectsTampering) {
    using namespace vh::protocols::s3::sigv4;

    const std::string secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const std::string accessKey = "VHTESTACCESSKEY";
    const std::string amzDate = amzNow();

    VerificationInput input{
        .method = "PUT",
        .target = "/bucket/path/to/object.txt?partNumber=1&uploadId=upload",
        .host = "localhost:39000",
        .headers = {
            {"host", "localhost:39000"},
            {"x-amz-content-sha256", sha256Hex("payload")},
            {"x-amz-date", amzDate}
        },
        .body = "payload",
        .body_sha256 = std::nullopt
    };

    ParsedAuth auth{
        .credential = {
            .access_key = accessKey,
            .date = scopeDate(amzDate),
            .region = "us-east-1",
            .service = "s3"
        },
        .signed_headers = "host;x-amz-content-sha256;x-amz-date",
        .signature = {},
        .amz_date = amzDate,
        .payload_hash = sha256Hex("payload")
    };

    auth.signature = signatureFor(input, auth, secret);
    input.headers["authorization"] =
        "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + auth.credential.date + "/us-east-1/s3/aws4_request, "
        "SignedHeaders=" + auth.signed_headers + ", Signature=" + auth.signature;

    auto ok = verify(input, secret);
    EXPECT_TRUE(ok.ok) << ok.error;
    EXPECT_EQ(ok.access_key, accessKey);

    input.body.clear();
    input.body_sha256 = sha256Hex("payload");
    auto streamedOk = verify(input, secret);
    EXPECT_TRUE(streamedOk.ok) << streamedOk.error;

    input.body_sha256 = sha256Hex("tampered");
    auto bad = verify(input, secret);
    EXPECT_FALSE(bad.ok);
}

TEST(S3GatewaySigV4Test, AcceptsAwsStreamingUnsignedPayloadTrailerHashConstant) {
    using namespace vh::protocols::s3::sigv4;

    const std::string secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const std::string accessKey = "VHTESTACCESSKEY";
    const std::string amzDate = amzNow();
    constexpr std::string_view payloadMode = "STREAMING-UNSIGNED-PAYLOAD-TRAILER";

    VerificationInput input{
        .method = "PUT",
        .target = "/bucket/object.txt",
        .host = "localhost:39000",
        .headers = {
            {"host", "localhost:39000"},
            {"x-amz-content-sha256", std::string(payloadMode)},
            {"x-amz-date", amzDate},
            {"x-amz-decoded-content-length", "5"},
            {"x-amz-trailer", "x-amz-checksum-crc32"}
        },
        .body = "aws-chunked-wire-body",
        .body_sha256 = sha256Hex("decoded")
    };

    ParsedAuth auth{
        .credential = {
            .access_key = accessKey,
            .date = scopeDate(amzDate),
            .region = "us-east-1",
            .service = "s3"
        },
        .signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-decoded-content-length;x-amz-trailer",
        .signature = {},
        .amz_date = amzDate,
        .payload_hash = std::string(payloadMode)
    };
    auth.signature = signatureFor(input, auth, secret);
    input.headers["authorization"] =
        "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + auth.credential.date + "/us-east-1/s3/aws4_request, "
        "SignedHeaders=" + auth.signed_headers + ", Signature=" + auth.signature;

    const auto ok = verify(input, secret);
    EXPECT_TRUE(ok.ok) << ok.error;
    EXPECT_EQ(ok.access_key, accessKey);
}

TEST(S3GatewaySigV4Test, RejectsMissingSignedHeader) {
    using namespace vh::protocols::s3::sigv4;

    const std::string secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const std::string accessKey = "VHTESTACCESSKEY";
    const std::string amzDate = amzNow();

    VerificationInput input{
        .method = "GET",
        .target = "/bucket/object.txt",
        .host = "localhost:39000",
        .headers = {
            {"host", "localhost:39000"},
            {"x-amz-content-sha256", "UNSIGNED-PAYLOAD"},
            {"x-amz-date", amzDate}
        },
        .body = {},
        .body_sha256 = std::nullopt
    };

    ParsedAuth auth{
        .credential = {
            .access_key = accessKey,
            .date = scopeDate(amzDate),
            .region = "us-east-1",
            .service = "s3"
        },
        .signed_headers = "host;x-amz-content-sha256;x-amz-date;x-amz-meta-missing",
        .signature = {},
        .amz_date = amzDate,
        .payload_hash = "UNSIGNED-PAYLOAD"
    };
    auth.signature = signatureFor(input, auth, secret);
    input.headers["authorization"] =
        "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + auth.credential.date + "/us-east-1/s3/aws4_request, "
        "SignedHeaders=" + auth.signed_headers + ", Signature=" + auth.signature;

    const auto result = verify(input, secret);
    EXPECT_FALSE(result.ok);
    EXPECT_NE(result.error.find("Signed header missing"), std::string::npos);
}

namespace {

// What the AWS CLI's CRT transfer client sends: "Content-Length: 0" on a bodiless request, signed.
vh::protocols::s3::sigv4::VerificationInput signedWithZeroContentLength(
    const std::string& method, const std::string& secret, const std::string& accessKey) {
    using namespace vh::protocols::s3::sigv4;

    const std::string amzDate = amzNow();
    VerificationInput input{
        .method = method,
        .target = "/bucket/object.txt",
        .host = "s3.example.test",
        .headers = {
            {"Host", "s3.example.test"},
            {"Content-Length", "0"},
            {"x-amz-content-sha256", sha256Hex("")},
            {"x-amz-date", amzDate}
        },
        .body = {},
        .body_sha256 = std::nullopt
    };
    ParsedAuth auth{
        .credential = {.access_key = accessKey, .date = scopeDate(amzDate), .region = "us-east-1", .service = "s3"},
        .signed_headers = "content-length;host;x-amz-content-sha256;x-amz-date",
        .signature = {},
        .amz_date = amzDate,
        .payload_hash = sha256Hex("")
    };
    auth.signature = signatureFor(input, auth, secret);
    input.headers["Authorization"] =
        "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + auth.credential.date + "/us-east-1/s3/aws4_request, "
        "SignedHeaders=" + auth.signed_headers + ", Signature=" + auth.signature;
    return input;
}

}

// Cloudflare (and other proxies) drop "Content-Length: 0" from bodiless requests; the signature still covers it.
TEST(S3GatewaySigV4Test, CanonicalizesSignedContentLengthStrippedByProxyAsZero) {
    using namespace vh::protocols::s3::sigv4;

    const std::string secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const std::string accessKey = "VHTESTACCESSKEY";

    for (const std::string method : {"GET", "HEAD", "DELETE", "POST"}) {
        auto input = signedWithZeroContentLength(method, secret, accessKey);
        const auto direct = verify(input, secret);
        EXPECT_TRUE(direct.ok) << method << ": " << direct.error;

        input.headers.erase("Content-Length");
        const auto proxied = verify(input, secret);
        EXPECT_TRUE(proxied.ok) << method << " without Content-Length: " << proxied.error;
        EXPECT_EQ(proxied.access_key, accessKey);
    }
}

// The implied length is the body the gateway actually read, never a free pass for content-length.
TEST(S3GatewaySigV4Test, MissingSignedContentLengthIsOnlyImpliedForAnEmptyUnchunkedBody) {
    using namespace vh::protocols::s3::sigv4;

    const std::string secret = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY";
    const std::string accessKey = "VHTESTACCESSKEY";

    {
        auto input = signedWithZeroContentLength("PUT", secret, accessKey);
        input.headers.erase("Content-Length");
        input.headers["Transfer-Encoding"] = "chunked";
        const auto result = verify(input, secret);
        EXPECT_FALSE(result.ok);
        EXPECT_EQ(result.error, "Signed header missing from request: content-length");
    }
    {
        auto input = signedWithZeroContentLength("PUT", secret, accessKey);
        input.headers.erase("Content-Length");
        input.headers["x-amz-content-sha256"] = "UNSIGNED-PAYLOAD";
        input.body = "payload";
        const auto result = verify(input, secret);
        EXPECT_FALSE(result.ok);
        EXPECT_EQ(result.error, "Signed header missing from request: content-length");
    }
    {
        auto input = signedWithZeroContentLength("PUT", secret, accessKey);
        input.headers.erase("Content-Length");
        input.body_sha256 = sha256Hex("streamed");
        const auto result = verify(input, secret);
        EXPECT_FALSE(result.ok);
    }
    {
        // A length the client signed as non-zero cannot be satisfied by an empty request.
        const std::string amzDate = amzNow();
        VerificationInput input{
            .method = "PUT",
            .target = "/bucket/object.txt",
            .host = "s3.example.test",
            .headers = {
                {"host", "s3.example.test"},
                {"content-length", "5"},
                {"x-amz-content-sha256", "UNSIGNED-PAYLOAD"},
                {"x-amz-date", amzDate}
            },
            .body = {},
            .body_sha256 = std::nullopt
        };
        ParsedAuth auth{
            .credential = {.access_key = accessKey, .date = scopeDate(amzDate), .region = "us-east-1", .service = "s3"},
            .signed_headers = "content-length;host;x-amz-content-sha256;x-amz-date",
            .signature = {},
            .amz_date = amzDate,
            .payload_hash = "UNSIGNED-PAYLOAD"
        };
        auth.signature = signatureFor(input, auth, secret);
        input.headers.erase("content-length");
        input.headers["authorization"] =
            "AWS4-HMAC-SHA256 Credential=" + accessKey + "/" + auth.credential.date + "/us-east-1/s3/aws4_request, "
            "SignedHeaders=" + auth.signed_headers + ", Signature=" + auth.signature;
        const auto result = verify(input, secret);
        EXPECT_FALSE(result.ok);
        EXPECT_EQ(result.error, "Signature mismatch");
    }
}

TEST(S3GatewaySigV4Test, RejectsMalformedPresignedExpiresWithoutThrowing) {
    using namespace vh::protocols::s3::sigv4;

    VerificationInput input{
        .method = "GET",
        .target = "/bucket/object.txt"
                  "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                  "&X-Amz-Credential=VHTESTACCESSKEY%2F20260531%2Fus-east-1%2Fs3%2Faws4_request"
                  "&X-Amz-Date=20260531T120000Z"
                  "&X-Amz-Expires=not-a-number"
                  "&X-Amz-SignedHeaders=host"
                  "&X-Amz-Signature=deadbeef",
        .host = "localhost:39000",
        .headers = {{"host", "localhost:39000"}},
        .body = {},
        .body_sha256 = std::nullopt
    };

    EXPECT_NO_THROW({
        const auto result = verify(input, "secret");
        EXPECT_FALSE(result.ok);
        EXPECT_EQ(result.error, "Invalid X-Amz-Expires");
    });
}

TEST(S3GatewaySigV4Test, RejectsPresignedUrlsDatedTooFarInFuture) {
    using namespace vh::protocols::s3::sigv4;

    const std::string amzDate = amzAfter(std::chrono::hours(1));
    VerificationInput input{
        .method = "GET",
        .target = "/bucket/object.txt"
                  "?X-Amz-Algorithm=AWS4-HMAC-SHA256"
                  "&X-Amz-Credential=VHTESTACCESSKEY%2F" + scopeDate(amzDate) + "%2Fus-east-1%2Fs3%2Faws4_request"
                  "&X-Amz-Date=" + amzDate +
                  "&X-Amz-Expires=60"
                  "&X-Amz-SignedHeaders=host"
                  "&X-Amz-Signature=deadbeef",
        .host = "localhost:39000",
        .headers = {{"host", "localhost:39000"}},
        .body = {},
        .body_sha256 = std::nullopt
    };

    const auto result = verify(input, "secret");
    EXPECT_FALSE(result.ok);
    EXPECT_EQ(result.error, "Signature date is outside allowed skew");
}

TEST(S3GatewayServiceTest, EnabledServiceBindsAndReturnsS3XmlErrors) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.enabled = true;
    cfg.s3_gateway.host = "127.0.0.1";
    cfg.s3_gateway.port = freeLoopbackPort();
    cfg.s3_gateway.require_sigv4 = true;
    vh::config::Registry::set(cfg);

    vh::concurrency::ThreadPoolManager::instance().init();
    ThreadPoolShutdown shutdownPools{true};

    vh::protocols::s3::GatewayService service;
    service.start();

    auto status = service.gatewayStatus();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!status.ready && service.isRunning() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        status = service.gatewayStatus();
    }

    ASSERT_TRUE(status.configured);
    ASSERT_TRUE(status.ready);

    const auto response = httpGetRoot(cfg.s3_gateway.port);

    EXPECT_EQ(response.result(), http::status::forbidden);
    EXPECT_NE(response.body().find("<Code>SignatureDoesNotMatch</Code>"), std::string::npos);
    EXPECT_NE(response.body().find("<RequestId>"), std::string::npos);
    EXPECT_FALSE(response["x-amz-request-id"].empty());
    EXPECT_EQ(response[http::field::cache_control], "private, no-store");
    EXPECT_GE(service.gatewayStatus().totalRequests, 1u);

    service.stop();
}

// Sessions run on pool threads with sockets bound to the gateway's io_context: stopping must not free the context
// while one is still alive (heap-use-after-free under ASan), and must end idle keep-alive connections.
TEST(S3GatewayServiceTest, StopEndsOpenConnectionsBeforeFreeingTheirContext) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.enabled = true;
    cfg.s3_gateway.host = "127.0.0.1";
    cfg.s3_gateway.port = freeLoopbackPort();
    vh::config::Registry::set(cfg);

    vh::concurrency::ThreadPoolManager::instance().init();
    ThreadPoolShutdown shutdownPools{true};

    vh::protocols::s3::GatewayService service;
    service.start();

    const auto readyBy = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!service.gatewayStatus().ready && std::chrono::steady_clock::now() < readyBy)
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
    ASSERT_TRUE(service.gatewayStatus().ready);

    boost::asio::io_context clientContext;
    std::vector<boost::asio::ip::tcp::socket> idle;
    for (int i = 0; i < 3; ++i) {
        idle.emplace_back(clientContext);
        idle.back().connect({boost::asio::ip::make_address("127.0.0.1"), cfg.s3_gateway.port});
    }

    const auto acceptedBy = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (vh::protocols::s3::Session::metrics().activeSessions < idle.size() &&
           std::chrono::steady_clock::now() < acceptedBy)
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    ASSERT_GE(vh::protocols::s3::Session::metrics().activeSessions, idle.size());

    const auto stopStarted = std::chrono::steady_clock::now();
    service.stop();

    EXPECT_EQ(vh::protocols::s3::Session::metrics().activeSessions, 0u);
    EXPECT_LT(std::chrono::steady_clock::now() - stopStarted, std::chrono::seconds(5));
}

TEST(S3GatewayServiceTest, DisabledServiceReportsNotConfiguredWithoutFailing) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.enabled = false;
    cfg.s3_gateway.host = "127.0.0.1";
    cfg.s3_gateway.port = freeLoopbackPort();
    vh::config::Registry::set(cfg);

    vh::protocols::s3::GatewayService service;
    service.start();

    auto status = service.gatewayStatus();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(2);
    while (status.host.empty() && service.isRunning() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        status = service.gatewayStatus();
    }

    EXPECT_TRUE(status.running);
    EXPECT_FALSE(status.configured);
    EXPECT_FALSE(status.ready);
    EXPECT_EQ(status.host, "127.0.0.1");
    EXPECT_EQ(status.port, cfg.s3_gateway.port);

    service.stop();
}

class S3GatewayDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static uint32_t userId = 0;
    inline static uint32_t vaultId = 0;

    static bool hasDbEnv() {
        return std::getenv("VH_TEST_DB_USER") &&
               std::getenv("VH_TEST_DB_PASS") &&
               std::getenv("VH_TEST_DB_HOST") &&
               std::getenv("VH_TEST_DB_PORT") &&
               std::getenv("VH_TEST_DB_NAME");
    }

    static void SetUpTestSuite() {
        if (!hasDbEnv()) {
            skipTests = true;
            std::cout << "[test_s3_gateway] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }

        vh::paths::enableTestMode();
        const auto pathRoot = std::filesystem::temp_directory_path() / s3GatewayUniqueSuffix("vh_s3_gateway_db_paths");
        std::filesystem::remove_all(pathRoot);
        vh::paths::backingPath = pathRoot / "backing";
        vh::paths::mountPath = pathRoot / "mount";
        std::filesystem::create_directories(vh::paths::backingPath);
        std::filesystem::create_directories(vh::paths::mountPath);
        vh::db::Transactions::init();
        vh::db::seed::nuke_and_recreate_schema_public();
        vh::db::Transactions::dbPool_->initPreparedStatements();
        vh::seed::seed_database();

        vaultId = vh::db::Transactions::exec("S3GatewayDbTest::seed", [](pqxx::work& txn) {
            S3GatewayDbTest::userId = insertS3GatewayHydratableTestUser(
                txn,
                "s3_gateway_user",
                "s3-gateway@vaulthalla.test");

            const auto seededVaultId = txn.exec(
                "INSERT INTO vault (type, name, owner_id, mount_point, description) VALUES ($1, $2, $3, $4, $5) RETURNING id",
                pqxx::params{"local", "S3 Gateway Test Vault", userId, "s3_gateway_test", ""}
            ).one_field_ref().as<uint32_t>();
            txn.exec(
                "WITH ins AS (INSERT INTO sync (vault_id, interval) VALUES ($1, 300) RETURNING id) "
                "INSERT INTO fsync (sync_id, conflict_policy) SELECT id, 'keep_both' FROM ins",
                pqxx::params{seededVaultId});
            return seededVaultId;
        });
        vh::runtime::Deps::init();
        vh::fs::Filesystem::init(vh::runtime::Deps::get().storageManager);
        vh::runtime::Deps::get().storageManager->initStorageEngines();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        vh::db::Transactions::exec("S3GatewayDbTest::clearObjects", [](pqxx::work& txn) {
            txn.exec("DELETE FROM s3_gateway_bucket");
            txn.exec("DELETE FROM s3_gateway_credentials");
            txn.exec("DELETE FROM s3_gateway_multipart_upload");
            txn.exec("DELETE FROM s3_gateway_object");
            txn.exec("DELETE FROM remote_object_index");
        });
        vh::runtime::Deps::get().storageManager->initStorageEngines();
    }

    static void putObject(const std::string& key) {
        vh::db::query::s3::Gateway::upsertObject({
            .vault_id = vaultId,
            .object_key = key,
            .etag = "\"etag-" + key + "\"",
            .size_bytes = 1,
            .content_type = "text/plain",
            .storage_class = std::nullopt,
            .last_modified = std::time(nullptr),
            .multipart = false,
            .part_count = std::nullopt
        });
    }

    static uint32_t createLocalVault(const std::string& label, const uint32_t ownerId) {
        const auto newVaultId = vh::db::Transactions::exec("S3GatewayDbTest::createLocalVault", [&](pqxx::work& txn) {
            const auto mountPoint = s3GatewayUniqueSuffix("s3gw");
            const auto seededVaultId = txn.exec(
                "INSERT INTO vault (type, name, owner_id, mount_point, description) VALUES ($1, $2, $3, $4, $5) RETURNING id",
                pqxx::params{"local", "S3 Gateway " + label, ownerId, mountPoint.substr(0, 33), ""}
            ).one_field_ref().as<uint32_t>();
            txn.exec(
                "WITH ins AS (INSERT INTO sync (vault_id, interval) VALUES ($1, 300) RETURNING id) "
                "INSERT INTO fsync (sync_id, conflict_policy) SELECT id, 'keep_both' FROM ins",
                pqxx::params{seededVaultId});
            return seededVaultId;
        });
        vh::runtime::Deps::get().storageManager->initStorageEngines();
        return newVaultId;
    }

    static uint32_t roleIdByName(const std::string& roleName) {
        return vh::db::Transactions::exec("S3GatewayDbTest::roleIdByName", [&](pqxx::work& txn) {
            const auto res = txn.exec(
                "SELECT id FROM vault_role WHERE name = $1 LIMIT 1",
                pqxx::params{roleName});
            if (res.empty()) throw std::runtime_error("vault role not found: " + roleName);
            return res.one_field_ref().as<uint32_t>();
        });
    }

    static uint32_t userWithAdminRole(const std::string& label, const vh::rbac::role::Admin& role) {
        return vh::db::Transactions::exec("S3GatewayDbTest::userWithAdminRole", [&](pqxx::work& txn) {
            return insertS3GatewayHydratableTestUser(
                txn,
                "s3_gateway_" + label + "_" + s3GatewayUniqueSuffix("user"),
                "s3-gateway-" + label + "-" + s3GatewayUniqueSuffix("email") + "@vaulthalla.test",
                role);
        });
    }

    static vh::rbac::role::Admin adminRoleWithS3(
        const std::string& label,
        vh::rbac::permission::admin::S3Gateway s3Gateway,
        vh::rbac::permission::admin::Vaults vaults = vh::rbac::permission::admin::Vaults::None(),
        vh::rbac::permission::admin::Roles roles = vh::rbac::permission::admin::Roles::None()) {
        auto roleName = "s3gw_" + label;
        if (roleName.size() > 45) roleName.resize(45);
        return vh::rbac::role::Admin::Custom(
            roleName,
            "S3 gateway test role",
            vh::rbac::permission::admin::Identities::None(),
            std::move(vaults),
            vh::rbac::permission::admin::Audits::None(),
            vh::rbac::permission::admin::Settings::None(),
            std::move(roles),
            vh::rbac::permission::admin::Keys::None(),
            std::move(s3Gateway));
    }

    static std::shared_ptr<vh::protocols::ws::Session> wsSessionForUser(const uint32_t targetUserId) {
        auto session = std::make_shared<vh::protocols::ws::Session>(
            std::make_shared<vh::protocols::ws::Router>());
        session->user = vh::identities::manager().user(targetUserId);
        if (!session->user) throw std::runtime_error("test user not found");
        return session;
    }

    static void assignPrincipalVaultRole(
        const uint32_t targetVaultId,
        const uint32_t targetUserId,
        const std::string& roleName) {
        vh::db::Transactions::exec("S3GatewayDbTest::assignPrincipalVaultRole", [&](pqxx::work& txn) {
            const auto roleId = txn.exec(
                "SELECT id FROM vault_role WHERE name = $1 LIMIT 1",
                pqxx::params{roleName}).one_field_ref().as<uint32_t>();
            txn.exec(
                "INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) "
                "VALUES ($1, 'user', $2, $3) "
                "ON CONFLICT (vault_id, subject_type, subject_id) DO UPDATE SET role_id = EXCLUDED.role_id",
                pqxx::params{targetVaultId, targetUserId, roleId});
        });
        // Written behind the identity manager: republish, as its revision watcher does in the daemon.
        (void)vh::identities::manager().reconcile();
    }

    static vh::db::query::s3::GatewayCredential createCredential(
        const uint32_t principalUserId,
        const std::string& scopeMode) {
        vh::db::query::s3::GatewayCredential credential;
        credential.user_id = principalUserId;
        credential.principal_user_id = principalUserId;
        credential.created_by = principalUserId;
        credential.name = "s3gw-" + scopeMode + "-" + s3GatewayUniqueSuffix("credential");
        credential.access_key = "VHTEST" + s3GatewayUniqueSuffix("ACCESS").substr(0, 24);
        credential.encrypted_secret_access_key = {1, 2, 3};
        credential.iv = {4, 5, 6};
        credential.enabled = true;
        credential.scope_mode = scopeMode;
        credential.id = vh::db::query::s3::Gateway::createCredential(credential);
        return credential;
    }

    static void assignCredentialVaultRole(
        const uint32_t credentialId,
        const uint32_t targetVaultId,
        const std::string& roleName,
        const std::optional<uint32_t> createdBy = std::nullopt) {
        vh::db::query::s3::Gateway::upsertCredentialVaultRoleAssignment({
            .credential_id = credentialId,
            .vault_id = targetVaultId,
            .vault_role_id = roleIdByName(roleName),
            .enabled = true,
            .created_by = createdBy
        });
    }

    static void setCredentialDefaultVaultRole(
        const uint32_t credentialId,
        const std::string& roleName,
        const std::optional<uint32_t> createdBy = std::nullopt) {
        vh::db::query::s3::Gateway::upsertCredentialDefaultVaultRole(
            credentialId,
            roleIdByName(roleName),
            true,
            createdBy);
    }

    static void selectCredentialVault(
        const uint32_t credentialId,
        const uint32_t targetVaultId,
        const std::optional<uint32_t> createdBy = std::nullopt) {
        vh::db::query::s3::Gateway::upsertCredentialSelectedVault(
            credentialId,
            targetVaultId,
            true,
            createdBy);
    }

    static vh::rbac::permission::Override makeGatewayOverride(
        const std::string& permission,
        const std::string& pattern,
        const vh::rbac::permission::OverrideOpt effect) {
        vh::rbac::permission::Override out;
        out.permission.qualified_name = permission;
        out.effect = effect;
        out.enabled = true;
        out.pattern = vh::rbac::fs::glob::model::Pattern::make(pattern);
        return out;
    }

    static vh::rbac::s3::policy::Decision evaluateS3(
        const std::shared_ptr<vh::identities::User>& principal,
        const uint32_t credentialId,
        const std::string& scopeMode,
        const uint32_t targetVaultId,
        const vh::rbac::s3::policy::S3Action action,
        const std::filesystem::path& path = "/object.txt",
        const bool objectExists = true) {
        return vh::rbac::s3::policy::Evaluator::evaluate({
            .principal = principal,
            .credential_id = credentialId,
            .scope_mode = scopeMode,
            .vault_id = targetVaultId,
            .vault_path = path,
            .fuse_path = path,
            .action = action,
            .object_exists = objectExists,
            .is_directory_marker = path == std::filesystem::path{"/"},
            .target_user_id = std::nullopt
        });
    }
};

TEST_F(S3GatewayDbTest, ListObjectsContinuationTokenDoesNotSkipFirstObjectOnNextPage) {
    putObject("a.txt");
    putObject("b.txt");
    putObject("c.txt");

    vh::db::query::s3::ObjectListParams firstParams;
    firstParams.max_keys = 2;
    const auto first = vh::db::query::s3::Gateway::listObjectStates(vaultId, firstParams);

    ASSERT_TRUE(first.is_truncated);
    ASSERT_EQ(first.objects.size(), 2u);
    ASSERT_TRUE(first.next_continuation_token);
    EXPECT_EQ(*first.next_continuation_token, "b.txt");

    vh::db::query::s3::ObjectListParams secondParams;
    secondParams.max_keys = 2;
    secondParams.continuation_token = first.next_continuation_token;
    const auto second = vh::db::query::s3::Gateway::listObjectStates(vaultId, secondParams);

    ASSERT_FALSE(second.is_truncated);
    ASSERT_EQ(second.objects.size(), 1u);
    EXPECT_EQ(second.objects[0].object_key, "c.txt");
}

TEST_F(S3GatewayDbTest, ListObjectsMaxKeysZeroReturnsNoObjects) {
    putObject("a.txt");

    vh::db::query::s3::ObjectListParams params;
    params.max_keys = 0;
    const auto result = vh::db::query::s3::Gateway::listObjectStates(vaultId, params);

    EXPECT_FALSE(result.is_truncated);
    EXPECT_FALSE(result.next_continuation_token);
    EXPECT_TRUE(result.objects.empty());
    EXPECT_TRUE(result.common_prefixes.empty());
}

TEST_F(S3GatewayDbTest, ListObjectsTreatsPrefixWildcardCharactersLiterally) {
    putObject("a%literal.txt");
    putObject("a_literal.txt");
    putObject("ab.txt");

    vh::db::query::s3::ObjectListParams percentParams;
    percentParams.prefix = "a%";
    const auto percent = vh::db::query::s3::Gateway::listObjectStates(vaultId, percentParams);

    ASSERT_EQ(percent.objects.size(), 1u);
    EXPECT_EQ(percent.objects[0].object_key, "a%literal.txt");

    vh::db::query::s3::ObjectListParams underscoreParams;
    underscoreParams.prefix = "a_";
    const auto underscore = vh::db::query::s3::Gateway::listObjectStates(vaultId, underscoreParams);

    ASSERT_EQ(underscore.objects.size(), 1u);
    EXPECT_EQ(underscore.objects[0].object_key, "a_literal.txt");
}

TEST_F(S3GatewayDbTest, UserAccessCredentialUsesPrincipalRbacWithoutGatewayRoleAssignment) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    const auto credential = createCredential(admin->id, "user_access");

    const auto decision = evaluateS3(
        admin,
        credential.id,
        credential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject);

    EXPECT_TRUE(decision.allowed);
    EXPECT_TRUE(decision.principal_allowed);
    EXPECT_TRUE(decision.credential_allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::Allowed, decision.reason);
    EXPECT_TRUE(vh::db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id).empty());
    EXPECT_FALSE(vh::db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id));
    EXPECT_TRUE(vh::db::query::s3::Gateway::listCredentialSelectedVaults(credential.id).empty());
}

TEST_F(S3GatewayDbTest, UserAccessCredentialCannotExceedPrincipalRbac) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    const auto unownedVaultId = createLocalVault(s3GatewayUniqueSuffix("user_access_denied"), admin->id);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = unownedVaultId,
        .bucket_name = "binding-no-access-" + std::to_string(unownedVaultId),
        .api_exclusive = true,
        .mode = "local",
        .created_by = admin->id
    });
    const auto principal = vh::identities::manager().user(userId);
    ASSERT_TRUE(principal);
    ASSERT_FALSE(principal->isAdmin());
    const auto credential = createCredential(principal->id, "user_access");

    const auto decision = evaluateS3(
        principal,
        credential.id,
        credential.scope_mode,
        unownedVaultId,
        vh::rbac::s3::policy::S3Action::GetObject);

    EXPECT_FALSE(decision.allowed);
    EXPECT_FALSE(decision.principal_allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::PrincipalRbacDenied, decision.reason);
}

TEST_F(S3GatewayDbTest, VaultAllowlistCredentialRequiresSelectedVaultAndDefaultRole) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    const auto credential = createCredential(admin->id, "vault_allowlist");

    const auto unselected = evaluateS3(
        admin,
        credential.id,
        credential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject);

    EXPECT_FALSE(unselected.allowed);
    EXPECT_TRUE(unselected.principal_allowed);
    EXPECT_FALSE(unselected.credential_allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::VaultNotSelected, unselected.reason);

    selectCredentialVault(credential.id, vaultId, admin->id);

    const auto missingDefault = evaluateS3(
        admin,
        credential.id,
        credential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject);

    EXPECT_FALSE(missingDefault.allowed);
    EXPECT_TRUE(missingDefault.principal_allowed);
    EXPECT_FALSE(missingDefault.credential_allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::MissingDefaultRole, missingDefault.reason);
}

TEST_F(S3GatewayDbTest, VaultAllowlistDefaultRoleRequiresPrincipalAndCredentialAllow) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    auto credential = createCredential(admin->id, "vault_allowlist");
    setCredentialDefaultVaultRole(credential.id, "reader", admin->id);
    selectCredentialVault(credential.id, vaultId, admin->id);

    auto read = evaluateS3(
        admin,
        credential.id,
        credential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject);
    EXPECT_TRUE(read.allowed);
    EXPECT_TRUE(vh::db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id).empty());

    auto write = evaluateS3(
        admin,
        credential.id,
        credential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::PutObject,
        "/new-object.txt",
        false);
    EXPECT_FALSE(write.allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::EffectiveCredentialRoleDenied, write.reason);

    const auto adminOwnedVaultId = createLocalVault(s3GatewayUniqueSuffix("allowlist_principal_denied"), admin->id);
    const auto principal = vh::identities::manager().user(userId);
    ASSERT_TRUE(principal);
    credential = createCredential(principal->id, "vault_allowlist");
    setCredentialDefaultVaultRole(credential.id, "manager", principal->id);
    selectCredentialVault(credential.id, adminOwnedVaultId, principal->id);

    auto principalDenied = evaluateS3(
        principal,
        credential.id,
        credential.scope_mode,
        adminOwnedVaultId,
        vh::rbac::s3::policy::S3Action::GetObject);
    EXPECT_FALSE(principalDenied.allowed);
    EXPECT_FALSE(principalDenied.principal_allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::PrincipalRbacDenied, principalDenied.reason);
}

TEST_F(S3GatewayDbTest, VaultAllowlistPerVaultRoleOverridesDefaultRoleForOneVault) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    const auto secondVaultId = createLocalVault(s3GatewayUniqueSuffix("allowlist_role_override"), admin->id);
    const auto credential = createCredential(admin->id, "vault_allowlist");
    setCredentialDefaultVaultRole(credential.id, "reader", admin->id);
    selectCredentialVault(credential.id, vaultId, admin->id);
    selectCredentialVault(credential.id, secondVaultId, admin->id);
    assignCredentialVaultRole(credential.id, secondVaultId, "contributor", admin->id);

    const auto firstWrite = evaluateS3(
        admin,
        credential.id,
        credential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::PutObject,
        "/first.txt",
        false);
    EXPECT_FALSE(firstWrite.allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::EffectiveCredentialRoleDenied, firstWrite.reason);

    const auto secondWrite = evaluateS3(
        admin,
        credential.id,
        credential.scope_mode,
        secondVaultId,
        vh::rbac::s3::policy::S3Action::PutObject,
        "/second.txt",
        false);
    EXPECT_TRUE(secondWrite.allowed);
}

TEST_F(S3GatewayDbTest, VaultAllowlistRoleOverridesApplyToCredentialAperture) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    const auto credential = createCredential(admin->id, "vault_allowlist");
    setCredentialDefaultVaultRole(credential.id, "reader", admin->id);
    selectCredentialVault(credential.id, vaultId, admin->id);
    vh::db::query::s3::Gateway::upsertCredentialDefaultVaultRoleOverride(
        credential.id,
        makeGatewayOverride(
            "vault.fs.files.download",
            "/private/**",
            vh::rbac::permission::OverrideOpt::DENY));

    auto publicRead = evaluateS3(
        admin,
        credential.id,
        credential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject,
        "/public/report.txt");
    EXPECT_TRUE(publicRead.allowed);

    auto privateRead = evaluateS3(
        admin,
        credential.id,
        credential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject,
        "/private/report.txt");
    EXPECT_FALSE(privateRead.allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::EffectiveCredentialRoleDenied, privateRead.reason);
    ASSERT_TRUE(privateRead.credential_decision);
    EXPECT_EQ(vh::rbac::fs::policy::Decision::Reason::DeniedByOverride,
              privateRead.credential_decision->reason);

    const auto secondVaultId = createLocalVault(s3GatewayUniqueSuffix("allowlist_override_narrow"), admin->id);
    const auto perVaultCredential = createCredential(admin->id, "vault_allowlist");
    setCredentialDefaultVaultRole(perVaultCredential.id, "reader", admin->id);
    selectCredentialVault(perVaultCredential.id, vaultId, admin->id);
    selectCredentialVault(perVaultCredential.id, secondVaultId, admin->id);
    assignCredentialVaultRole(perVaultCredential.id, secondVaultId, "reader", admin->id);
    vh::db::query::s3::Gateway::upsertCredentialVaultRoleOverride(
        perVaultCredential.id,
        secondVaultId,
        makeGatewayOverride(
            "vault.fs.files.download",
            "/private/**",
            vh::rbac::permission::OverrideOpt::DENY));

    auto firstVaultPrivateRead = evaluateS3(
        admin,
        perVaultCredential.id,
        perVaultCredential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject,
        "/private/report.txt");
    EXPECT_TRUE(firstVaultPrivateRead.allowed);

    auto secondVaultPrivateRead = evaluateS3(
        admin,
        perVaultCredential.id,
        perVaultCredential.scope_mode,
        secondVaultId,
        vh::rbac::s3::policy::S3Action::GetObject,
        "/private/report.txt");
    EXPECT_FALSE(secondVaultPrivateRead.allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::EffectiveCredentialRoleDenied, secondVaultPrivateRead.reason);
    ASSERT_TRUE(secondVaultPrivateRead.credential_decision);
    EXPECT_EQ(vh::rbac::fs::policy::Decision::Reason::DeniedByOverride,
              secondVaultPrivateRead.credential_decision->reason);

    const auto allowCredential = createCredential(admin->id, "vault_allowlist");
    setCredentialDefaultVaultRole(allowCredential.id, "implicit_deny", admin->id);
    selectCredentialVault(allowCredential.id, vaultId, admin->id);
    assignCredentialVaultRole(allowCredential.id, vaultId, "implicit_deny", admin->id);
    vh::db::query::s3::Gateway::upsertCredentialVaultRoleOverride(
        allowCredential.id,
        vaultId,
        makeGatewayOverride(
            "vault.fs.files.download",
            "/allowed/**",
            vh::rbac::permission::OverrideOpt::ALLOW));

    auto allowedByOverride = evaluateS3(
        admin,
        allowCredential.id,
        allowCredential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject,
        "/allowed/report.txt");
    EXPECT_TRUE(allowedByOverride.allowed);
    ASSERT_TRUE(allowedByOverride.credential_decision);
    EXPECT_EQ(vh::rbac::fs::policy::Decision::Reason::AllowedByOverride,
              allowedByOverride.credential_decision->reason);
}

TEST_F(S3GatewayDbTest, GlobalCredentialUsesPrincipalRbacAndRequiresAdminPrincipal) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    const auto globalAdminCredential = createCredential(admin->id, "global");
    const auto secondVaultId = createLocalVault(s3GatewayUniqueSuffix("global_default"), admin->id);

    auto missingDefault = evaluateS3(
        admin,
        globalAdminCredential.id,
        globalAdminCredential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject);
    EXPECT_FALSE(missingDefault.allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::MissingDefaultRole, missingDefault.reason);

    setCredentialDefaultVaultRole(globalAdminCredential.id, "reader", admin->id);

    auto adminDecision = evaluateS3(
        admin,
        globalAdminCredential.id,
        globalAdminCredential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::GetObject);
    EXPECT_TRUE(adminDecision.allowed);

    auto secondVaultRead = evaluateS3(
        admin,
        globalAdminCredential.id,
        globalAdminCredential.scope_mode,
        secondVaultId,
        vh::rbac::s3::policy::S3Action::GetObject);
    EXPECT_TRUE(secondVaultRead.allowed);

    auto adminWriteDenied = evaluateS3(
        admin,
        globalAdminCredential.id,
        globalAdminCredential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::PutObject,
        "/global-write.txt",
        false);
    EXPECT_FALSE(adminWriteDenied.allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::EffectiveCredentialRoleDenied, adminWriteDenied.reason);

    assignCredentialVaultRole(globalAdminCredential.id, vaultId, "manager", admin->id);
    auto adminWriteAllowedByException = evaluateS3(
        admin,
        globalAdminCredential.id,
        globalAdminCredential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::PutObject,
        "/global-write.txt",
        false);
    EXPECT_TRUE(adminWriteAllowedByException.allowed);

    assignPrincipalVaultRole(vaultId, userId, "manager");
    const auto nonAdmin = vh::identities::manager().user(userId);
    ASSERT_TRUE(nonAdmin);
    ASSERT_FALSE(nonAdmin->isAdmin());
    const auto globalUserCredential = createCredential(nonAdmin->id, "global");
    setCredentialDefaultVaultRole(globalUserCredential.id, "manager", nonAdmin->id);

    auto userDecision = evaluateS3(
        nonAdmin,
        globalUserCredential.id,
        globalUserCredential.scope_mode,
        vaultId,
        vh::rbac::s3::policy::S3Action::PutObject,
        "/new-global-object.txt",
        false);
    EXPECT_FALSE(userDecision.allowed);
    EXPECT_TRUE(userDecision.principal_allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::GlobalPrincipalRequired, userDecision.reason);
}

TEST_F(S3GatewayDbTest, ManagementS3ActionsRequireExplicitManagementGates) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    const auto decision = evaluateS3(
        admin,
        0,
        "user_access",
        vaultId,
        vh::rbac::s3::policy::S3Action::ManageCredential);

    EXPECT_FALSE(decision.allowed);
    EXPECT_EQ(vh::rbac::s3::policy::Decision::Reason::NoFilesystemMapping, decision.reason);
}

TEST_F(S3GatewayDbTest, VaultAllowlistScopesMirrorToGatewayVaultRoles) {
    vh::identities::UserState adminState;
    adminState.name = "admin-principal";
    adminState.roles.admin = std::make_shared<vh::rbac::role::Admin>( vh::rbac::role::Admin::SuperAdmin(userId));
    auto admin = vh::identities::User::detached(userId, std::move(adminState));

    vh::db::query::s3::GatewayCredential credential;
    credential.user_id = admin->id;
    credential.principal_user_id = admin->id;
    credential.created_by = admin->id;
    credential.name = "scoped-admin-test";
    credential.access_key = "VHTESTSCOPEDADMIN";
    credential.encrypted_secret_access_key = {1, 2, 3};
    credential.iv = {4, 5, 6};
    credential.enabled = true;
    credential.scope_mode = "vault_allowlist";
    credential.id = vh::db::query::s3::Gateway::createCredential(credential);

    vh::db::query::s3::Gateway::replaceCredentialScopeShorthand(credential.id, {{
        .credential_id = credential.id,
        .vault_id = vaultId,
        .can_list = true,
        .can_read = true,
        .can_write = true,
        .can_delete = true,
        .can_admin = false
    }});

    auto assignments = vh::db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id);
    EXPECT_TRUE(assignments.empty());
    auto defaultRole = vh::db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    ASSERT_TRUE(defaultRole);
    EXPECT_EQ(defaultRole->vault_role_id, roleIdByName("manager"));
    auto selectedVaults = vh::db::query::s3::Gateway::listCredentialSelectedVaults(credential.id);
    ASSERT_EQ(selectedVaults.size(), 1u);
    EXPECT_EQ(selectedVaults.front().vault_id, vaultId);
    auto role = vh::db::query::s3::Gateway::getCredentialVaultRoleForVault(credential.id, vaultId);
    EXPECT_FALSE(role);
    auto effectiveRole = vh::db::query::s3::Gateway::getEffectiveCredentialVaultRole(credential.id, vaultId, credential.scope_mode);
    ASSERT_TRUE(effectiveRole);
    EXPECT_EQ(effectiveRole->name, "manager");

    vh::db::query::s3::Gateway::replaceCredentialScopeShorthand(credential.id, {{
        .credential_id = credential.id,
        .vault_id = vaultId,
        .can_list = true,
        .can_read = true,
        .can_write = false,
        .can_delete = true,
        .can_admin = false
    }});

    assignments = vh::db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id);
    EXPECT_TRUE(assignments.empty());
    defaultRole = vh::db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    ASSERT_TRUE(defaultRole);
    EXPECT_EQ(defaultRole->vault_role_id, roleIdByName("manager"));
    role = vh::db::query::s3::Gateway::getCredentialVaultRoleForVault(credential.id, vaultId);
    EXPECT_FALSE(role);
    effectiveRole = vh::db::query::s3::Gateway::getEffectiveCredentialVaultRole(credential.id, vaultId, credential.scope_mode);
    ASSERT_TRUE(effectiveRole);
    EXPECT_EQ(effectiveRole->name, "manager");

    vh::db::query::s3::Gateway::replaceCredentialScopeShorthand(credential.id, {{
        .credential_id = credential.id,
        .vault_id = vaultId,
        .can_list = true,
        .can_read = true,
        .can_write = false,
        .can_delete = false,
        .can_admin = false
    }});

    defaultRole = vh::db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    ASSERT_TRUE(defaultRole);
    EXPECT_EQ(defaultRole->vault_role_id, roleIdByName("reader"));
    assignments = vh::db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id);
    EXPECT_TRUE(assignments.empty());
    role = vh::db::query::s3::Gateway::getCredentialVaultRoleForVault(credential.id, vaultId);
    EXPECT_FALSE(role);
    effectiveRole = vh::db::query::s3::Gateway::getEffectiveCredentialVaultRole(credential.id, vaultId, credential.scope_mode);
    ASSERT_TRUE(effectiveRole);
    EXPECT_EQ(effectiveRole->name, "reader");
}

TEST_F(S3GatewayDbTest, SignedDeleteBucketUsesCanAdminWithoutCanDeleteScope) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.require_sigv4 = true;
    cfg.s3_gateway.allow_path_style = true;
    vh::config::Registry::set(cfg);

    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());

    const std::string bucketName = "admin-delete-" + std::to_string(vaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .api_exclusive = false,
        .mode = "local",
        .created_by = admin->id
    });

    const vh::protocols::s3::CredentialManager manager;
    auto secret = manager.createCredential({
        .created_by = admin->id,
        .principal_user_id = admin->id,
        .name = "route-admin-delete-" + s3GatewayUniqueSuffix("credential"),
        .scope_mode = "vault_allowlist",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .vault_scopes = {{
            .credential_id = 0,
            .vault_id = vaultId,
            .can_list = false,
            .can_read = false,
            .can_write = false,
            .can_delete = false,
            .can_admin = true
        }}
    });

    vh::protocols::s3::Router::Request request{http::verb::delete_, "/" + bucketName, 11};
    request.set(http::field::host, "localhost:39000");
    signS3GatewayRequest(request, secret.credential.access_key, secret.secret_access_key);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::no_content) << response.body();
    EXPECT_FALSE(vh::db::query::s3::Gateway::resolveBucket(bucketName));
}

TEST_F(S3GatewayDbTest, SignedDedicatedHostRootListsBuckets) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.require_sigv4 = true;
    cfg.s3_gateway.allow_path_style = true;
    cfg.s3_gateway.allow_virtual_hosted_style = true;
    vh::config::Registry::set(cfg);

    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);

    const vh::protocols::s3::CredentialManager manager;
    auto secret = manager.createCredential({
        .created_by = admin->id,
        .principal_user_id = admin->id,
        .name = "dedicated-root-" + s3GatewayUniqueSuffix("credential"),
        .scope_mode = "user_access",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .vault_scopes = {}
    });

    vh::protocols::s3::Router::Request request{http::verb::get, "/", 11};
    request.set(http::field::host, "s3.vaulthalla.dev");
    request.set("X-Vaulthalla-S3-Path-Style-Only", "true");
    signS3GatewayRequest(request, secret.credential.access_key, secret.secret_access_key);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_NE(response.body().find("<ListAllMyBucketsResult"), std::string::npos);
}

// The request the AWS CLI CRT client makes through Cloudflare: content-length signed as 0, the header stripped.
TEST_F(S3GatewayDbTest, SignedListBucketsSurvivesProxyStrippedContentLengthAndIsNeverCacheable) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.require_sigv4 = true;
    cfg.s3_gateway.allow_path_style = true;
    vh::config::Registry::set(cfg);

    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);

    const vh::protocols::s3::CredentialManager manager;
    auto secret = manager.createCredential({
        .created_by = admin->id,
        .principal_user_id = admin->id,
        .name = "stripped-length-" + s3GatewayUniqueSuffix("credential"),
        .scope_mode = "user_access",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .vault_scopes = {}
    });

    vh::protocols::s3::Router::Request request{http::verb::get, "/", 11};
    request.set(http::field::host, "localhost:39000");
    request.set(http::field::content_length, "0");
    signS3GatewayRequest(request, secret.credential.access_key, secret.secret_access_key,
                         "content-length;host;x-amz-content-sha256;x-amz-date");
    request.erase(http::field::content_length);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_NE(response.body().find("<ListAllMyBucketsResult"), std::string::npos);
    EXPECT_EQ(response[http::field::cache_control], "private, no-store");
}

TEST_F(S3GatewayDbTest, SignedDedicatedHostPutAndGetAuthenticateAndRoutePathStyle) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.require_sigv4 = true;
    cfg.s3_gateway.allow_path_style = true;
    cfg.s3_gateway.allow_virtual_hosted_style = true;
    vh::config::Registry::set(cfg);

    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());

    const std::string bucketName = "dedicated-route-" + std::to_string(vaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .api_exclusive = true,
        .mode = "local",
        .created_by = admin->id
    });

    const vh::protocols::s3::CredentialManager manager;
    auto secret = manager.createCredential({
        .created_by = admin->id,
        .principal_user_id = admin->id,
        .name = "dedicated-object-" + s3GatewayUniqueSuffix("credential"),
        .scope_mode = "vault_allowlist",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .vault_scopes = {{
            .credential_id = 0,
            .vault_id = vaultId,
            .can_list = true,
            .can_read = true,
            .can_write = true,
            .can_delete = false,
            .can_admin = false
        }}
    });

    const auto addDedicatedHostHeaders = [](vh::protocols::s3::Router::Request& request) {
        request.set(http::field::host, "s3.vaulthalla.dev");
        request.set("X-Vaulthalla-S3-Path-Style-Only", "true");
    };

    vh::protocols::s3::Router::Request put{http::verb::put, "/" + bucketName + "/key.txt", 11};
    put.body() = "dedicated host body";
    put.prepare_payload();
    addDedicatedHostHeaders(put);
    signS3GatewayRequest(put, secret.credential.access_key, secret.secret_access_key);

    const vh::protocols::s3::Router router;
    auto response = router.route(std::move(put));
    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_TRUE(vh::db::query::s3::Gateway::getObjectState(vaultId, "key.txt"));

    vh::protocols::s3::Router::Request get{http::verb::get, "/" + bucketName + "/key.txt", 11};
    addDedicatedHostHeaders(get);
    signS3GatewayRequest(get, secret.credential.access_key, secret.secret_access_key);
    response = router.route(std::move(get));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_EQ(response.body(), "dedicated host body");
}

// The scope rule moved from CredentialManager::validateScopeMutation into ops::s3_gateway, the one place both
// surfaces authorize credential policy.
TEST_F(S3GatewayDbTest, NonAdminScopeMutationCannotGrantGatewayAdminScope) {
    const auto user = vh::identities::manager().user(userId);
    ASSERT_TRUE(user);
    EXPECT_THROW(
        (void)vh::ops::s3_gateway::createCredential(user, {
            .name = "non-admin-admin-scope-" + s3GatewayUniqueSuffix("credential"),
            .scope_mode = std::string{"vault_allowlist"},
            .vault_access = {{
                .vault_id = vaultId,
                .list = true,
                .read = true,
                .write = false,
                .del = false,
                .admin = true
            }}}),
        vh::ops::Error);
}

TEST_F(S3GatewayDbTest, NonAdminScopeMutationCannotNameUnownedVaultEvenWithNoActions) {
    const auto unownedVaultId = vh::db::Transactions::exec(
        "S3GatewayDbTest::seedUnownedScopeVault",
        [](pqxx::work& txn) {
            const auto admin = vh::identities::manager().userByName("admin");
            if (!admin) throw std::runtime_error("admin user not available");
            const auto mount = s3GatewayUniqueSuffix("s3gw_unscope").substr(0, 33);
            const auto seededVaultId = txn.exec(
                "INSERT INTO vault (type, name, owner_id, mount_point, description) VALUES ($1, $2, $3, $4, $5) RETURNING id",
                pqxx::params{"local", "S3 Gateway Unowned Scope Vault", admin->id, mount, ""}
            ).one_field_ref().as<uint32_t>();
            txn.exec(
                "WITH ins AS (INSERT INTO sync (vault_id, interval) VALUES ($1, 300) RETURNING id) "
                "INSERT INTO fsync (sync_id, conflict_policy) SELECT id, 'keep_both' FROM ins",
                pqxx::params{seededVaultId});
            return seededVaultId;
        });

    const auto user = vh::identities::manager().user(userId);
    ASSERT_TRUE(user);
    EXPECT_THROW(
        (void)vh::ops::s3_gateway::createCredential(user, {
            .name = "non-admin-unowned-" + s3GatewayUniqueSuffix("credential"),
            .scope_mode = std::string{"vault_allowlist"},
            .vault_access = {{
                .vault_id = unownedVaultId,
                .list = false,
                .read = false,
                .write = false,
                .del = false,
                .admin = false
            }}}),
        vh::ops::Error);
}

TEST_F(S3GatewayDbTest, UserAccessCredentialCannotCreateBucketWithoutAdminPrincipal) {
    auto user = vh::identities::manager().user(userId);
    ASSERT_TRUE(user);
    ASSERT_FALSE(user->isAdmin());

    vh::protocols::s3::AuthContext auth{
        .user = user,
        .credential = {},
        .credential_id = 123,
        .access_key = "VHTESTUSERACCESSCREATE",
        .scope_mode = "user_access",
        .dev_context = false
    };

    const vh::protocols::s3::ObjectStore store;
    EXPECT_THROW((void)store.createBucket("user-access-create-denied", auth), vh::protocols::s3::S3Error);
}

TEST_F(S3GatewayDbTest, S3GatewayWebSocketListHandlersAcceptNullPayloads) {
    auto session = std::make_shared<vh::protocols::ws::Session>(
        std::make_shared<vh::protocols::ws::Router>());
    session->user = vh::identities::manager().user(userId);
    ASSERT_TRUE(session->user);

    const auto credentials = vh::protocols::ws::handler::S3Gateway::credentialsList(nlohmann::json(nullptr), session);
    ASSERT_TRUE(credentials.contains("credentials"));
    EXPECT_TRUE(credentials.at("credentials").is_array());

    const auto policies = vh::protocols::ws::handler::S3Gateway::budgetPolicyList(nlohmann::json(nullptr), session);
    ASSERT_TRUE(policies.contains("policies"));
    EXPECT_TRUE(policies.at("policies").is_array());
}

TEST_F(S3GatewayDbTest, S3GatewayWebSocketNormalizesCredentialScopeNames) {
    auto session = std::make_shared<vh::protocols::ws::Session>(
        std::make_shared<vh::protocols::ws::Router>());
    session->user = vh::identities::manager().user(1);
    ASSERT_TRUE(session->user);
    ASSERT_TRUE(session->user->isAdmin());

    const auto created = vh::protocols::ws::handler::S3Gateway::credentialsCreate({
        {"name", "ws-normalized-scope-" + s3GatewayUniqueSuffix("credential")},
        {"scope_mode", "vault-allowlist"},
        {"vault_scopes", nlohmann::json::array({
            {
                {"vault_id", vaultId},
                {"can_list", true},
                {"can_read", true},
                {"can_write", false},
                {"can_delete", false},
                {"can_admin", false}
            }
        })}
    }, session);
    ASSERT_TRUE(created.contains("credential"));
    EXPECT_EQ("vault_allowlist", created.at("credential").at("scope_mode").get<std::string>());
    const auto accessKey = created.at("credential").at("access_key").get<std::string>();
    const auto credential = vh::db::query::s3::Gateway::getCredentialByAccessKey(accessKey);
    ASSERT_TRUE(credential);
    EXPECT_EQ("vault_allowlist", credential->scope_mode);
    EXPECT_EQ(1u, vh::db::query::s3::Gateway::listCredentialSelectedVaults(credential->id).size());
    EXPECT_TRUE(vh::db::query::s3::Gateway::getCredentialDefaultVaultRole(credential->id));

    const auto updated = vh::protocols::ws::handler::S3Gateway::credentialsScopeUpdate({
        {"access_key", accessKey},
        {"scope_mode", "user-access"}
    }, session);
    ASSERT_TRUE(updated.contains("credential"));
    EXPECT_EQ("user_access", updated.at("credential").at("scope_mode").get<std::string>());
    EXPECT_TRUE(vh::db::query::s3::Gateway::listCredentialSelectedVaults(credential->id).empty());
    EXPECT_FALSE(vh::db::query::s3::Gateway::getCredentialDefaultVaultRole(credential->id));
}

TEST_F(S3GatewayDbTest, S3GatewayWebSocketRoleAssignmentAndOverrideEndpointsWork) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    const auto session = wsSessionForUser(admin->id);
    const auto credential = createCredential(admin->id, "user_access");

    const auto assigned = vh::protocols::ws::handler::S3Gateway::credentialsRolesAssign({
        {"credential_id", credential.id},
        {"vault_id", vaultId},
        {"vault_role_name", "reader"},
        {"enabled", true}
    }, session);
    ASSERT_TRUE(assigned.contains("assignment"));
    EXPECT_EQ(credential.id, assigned.at("assignment").at("credential_id").get<uint32_t>());
    EXPECT_EQ(vaultId, assigned.at("assignment").at("vault_id").get<uint32_t>());
    EXPECT_EQ("reader", assigned.at("assignment").at("role").at("name").get<std::string>());

    const auto updatedCredential = vh::db::query::s3::Gateway::getCredentialByAccessKey(credential.access_key);
    ASSERT_TRUE(updatedCredential);
    EXPECT_EQ("vault_allowlist", updatedCredential->scope_mode);

    const auto listed = vh::protocols::ws::handler::S3Gateway::credentialsRolesList({
        {"credential_id", credential.id}
    }, session);
    ASSERT_TRUE(listed.contains("roles"));
    ASSERT_EQ(1u, listed.at("roles").size());
    EXPECT_TRUE(listed.at("roles").front().contains("vault"));

    const auto addedOverride = vh::protocols::ws::handler::S3Gateway::credentialsRoleOverridesAdd({
        {"credential_id", credential.id},
        {"vault_name", "S3 Gateway Test Vault"},
        {"permission_qualified", "vault.fs.files.download"},
        {"glob_path", "/private/**"},
        {"effect", "deny"},
        {"enabled", true}
    }, session);
    ASSERT_TRUE(addedOverride.contains("override"));
    const auto overrideId = addedOverride.at("override").at("id").get<uint32_t>();
    EXPECT_EQ("vault.fs.files.download", addedOverride.at("override").at("permission_qualified").get<std::string>());
    EXPECT_EQ("/private/**", addedOverride.at("override").at("glob_path").get<std::string>());

    const auto overrides = vh::protocols::ws::handler::S3Gateway::credentialsRoleOverridesList({
        {"credential_id", credential.id},
        {"vault_id", vaultId}
    }, session);
    ASSERT_TRUE(overrides.contains("overrides"));
    ASSERT_EQ(1u, overrides.at("overrides").size());
    EXPECT_EQ(overrideId, overrides.at("overrides").front().at("id").get<uint32_t>());

    // #165: a bare `id` no longer stands in for override_id (or credential_id); the override survives the refusal.
    EXPECT_THROW((void)vh::protocols::ws::handler::S3Gateway::credentialsRoleOverridesRemove({
        {"credential_id", credential.id},
        {"vault_id", vaultId},
        {"id", overrideId}
    }, session), vh::ops::Invalid);
    EXPECT_EQ(1u, vh::db::query::s3::Gateway::listCredentialVaultRoleOverrides(credential.id, vaultId).size());

    const auto removedOverride = vh::protocols::ws::handler::S3Gateway::credentialsRoleOverridesRemove({
        {"credential_id", credential.id},
        {"vault_id", vaultId},
        {"override_id", overrideId}
    }, session);
    EXPECT_TRUE(removedOverride.at("removed").get<bool>());

    const auto revoked = vh::protocols::ws::handler::S3Gateway::credentialsRolesRevoke({
        {"credential_id", credential.id},
        {"vault_id", vaultId}
    }, session);
    EXPECT_TRUE(revoked.at("revoked").get<bool>());
    EXPECT_TRUE(vh::db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id).empty());
}

TEST_F(S3GatewayDbTest, S3GatewayWebSocketDefaultRoleSelectedVaultAndDefaultOverrideEndpointsWork) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    const auto session = wsSessionForUser(admin->id);
    const auto secondVaultId = createLocalVault(s3GatewayUniqueSuffix("ws_selected"), admin->id);
    const auto credential = createCredential(admin->id, "vault_allowlist");

    const auto initialDefault = vh::protocols::ws::handler::S3Gateway::credentialsDefaultRoleGet({
        {"credential_id", credential.id}
    }, session);
    ASSERT_TRUE(initialDefault.contains("default_role"));
    EXPECT_TRUE(initialDefault.at("default_role").is_null());

    const auto setDefault = vh::protocols::ws::handler::S3Gateway::credentialsDefaultRoleSet({
        {"credential_id", credential.id},
        {"vault_role_name", "reader"},
        {"enabled", true}
    }, session);
    ASSERT_TRUE(setDefault.contains("default_role"));
    EXPECT_EQ("reader", setDefault.at("default_role").at("role").at("name").get<std::string>());

    const auto addedSelected = vh::protocols::ws::handler::S3Gateway::credentialsSelectedVaultsAdd({
        {"credential_id", credential.id},
        {"vault_id", vaultId},
        {"enabled", true}
    }, session);
    ASSERT_TRUE(addedSelected.contains("selected_vault"));
    EXPECT_EQ(vaultId, addedSelected.at("selected_vault").at("vault_id").get<uint32_t>());
    EXPECT_TRUE(addedSelected.at("selected_vault").contains("vault"));

    const auto replacedSelected = vh::protocols::ws::handler::S3Gateway::credentialsSelectedVaultsReplace({
        {"credential_id", credential.id},
        {"selected_vault_ids", {vaultId, secondVaultId}}
    }, session);
    ASSERT_TRUE(replacedSelected.contains("selected_vaults"));
    EXPECT_EQ(2u, replacedSelected.at("selected_vaults").size());

    const auto listedSelected = vh::protocols::ws::handler::S3Gateway::credentialsSelectedVaultsList({
        {"credential_id", credential.id}
    }, session);
    ASSERT_TRUE(listedSelected.contains("selected_vaults"));
    EXPECT_EQ(2u, listedSelected.at("selected_vaults").size());

    const auto removedSelected = vh::protocols::ws::handler::S3Gateway::credentialsSelectedVaultsRemove({
        {"credential_id", credential.id},
        {"vault_id", secondVaultId}
    }, session);
    EXPECT_TRUE(removedSelected.at("removed").get<bool>());

    const auto addedOverride = vh::protocols::ws::handler::S3Gateway::credentialsDefaultRoleOverridesAdd({
        {"credential_id", credential.id},
        {"permission_qualified", "vault.fs.files.download"},
        {"glob_path", "/shared/**"},
        {"effect", "deny"},
        {"enabled", true}
    }, session);
    ASSERT_TRUE(addedOverride.contains("override"));
    const auto overrideId = addedOverride.at("override").at("id").get<uint32_t>();
    EXPECT_EQ("vault.fs.files.download", addedOverride.at("override").at("permission_qualified").get<std::string>());
    EXPECT_EQ("/shared/**", addedOverride.at("override").at("glob_path").get<std::string>());

    const auto listedOverrides = vh::protocols::ws::handler::S3Gateway::credentialsDefaultRoleOverridesList({
        {"credential_id", credential.id}
    }, session);
    ASSERT_TRUE(listedOverrides.contains("overrides"));
    ASSERT_EQ(1u, listedOverrides.at("overrides").size());
    EXPECT_EQ(overrideId, listedOverrides.at("overrides").front().at("id").get<uint32_t>());

    EXPECT_THROW((void)vh::protocols::ws::handler::S3Gateway::credentialsDefaultRoleOverridesRemove({
        {"credential_id", credential.id},
        {"id", overrideId}
    }, session), vh::ops::Invalid);
    EXPECT_EQ(1u, vh::db::query::s3::Gateway::listCredentialDefaultVaultRoleOverrides(credential.id).size());

    const auto removedOverride = vh::protocols::ws::handler::S3Gateway::credentialsDefaultRoleOverridesRemove({
        {"credential_id", credential.id},
        {"override_id", overrideId}
    }, session);
    EXPECT_TRUE(removedOverride.at("removed").get<bool>());

    const auto clearedDefault = vh::protocols::ws::handler::S3Gateway::credentialsDefaultRoleClear({
        {"credential_id", credential.id}
    }, session);
    EXPECT_TRUE(clearedDefault.at("cleared").get<bool>());
    EXPECT_FALSE(vh::db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id));
}

TEST_F(S3GatewayDbTest, S3GatewayWebSocketDefaultPolicyMutationRequiresCredentialAndVaultAuthority) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());
    const auto adminCredential = createCredential(admin->id, "vault_allowlist");
    const auto actorSession = wsSessionForUser(userId);

    EXPECT_THROW(
        (void)vh::protocols::ws::handler::S3Gateway::credentialsDefaultRoleSet({
            {"credential_id", adminCredential.id},
            {"vault_role_name", "reader"}
        }, actorSession),
        std::exception);

    const auto manageUserId = userWithAdminRole(
        "selected_no_vault",
        adminRoleWithS3("selected_no_vault", vh::rbac::permission::admin::S3Gateway::CredentialManager()));
    const auto manageSession = wsSessionForUser(manageUserId);
    const auto manageCredential = createCredential(manageUserId, "vault_allowlist");
    (void)vh::protocols::ws::handler::S3Gateway::credentialsDefaultRoleSet({
        {"credential_id", manageCredential.id},
        {"vault_role_name", "reader"}
    }, manageSession);

    EXPECT_THROW(
        (void)vh::protocols::ws::handler::S3Gateway::credentialsSelectedVaultsAdd({
            {"credential_id", manageCredential.id},
            {"vault_id", vaultId}
        }, manageSession),
        std::exception);
}

TEST_F(S3GatewayDbTest, S3GatewayWebSocketPermissionGatesUseGatewayAdminPermissions) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    const auto adminCredential = createCredential(admin->id, "user_access");

    const auto noGatewayUserId = userWithAdminRole(
        "no_gateway",
        adminRoleWithS3("none", vh::rbac::permission::admin::S3Gateway::None()));
    const auto noGatewaySession = wsSessionForUser(noGatewayUserId);
    EXPECT_THROW(
        (void)vh::protocols::ws::handler::S3Gateway::status(nlohmann::json(nullptr), noGatewaySession),
        std::exception);

    const auto viewUserId = userWithAdminRole(
        "view",
        adminRoleWithS3("view", vh::rbac::permission::admin::S3Gateway::ViewOnly()));
    const auto viewSession = wsSessionForUser(viewUserId);
    EXPECT_NO_THROW((void)vh::protocols::ws::handler::S3Gateway::status(nlohmann::json(nullptr), viewSession));
    EXPECT_THROW(
        (void)vh::protocols::ws::handler::S3Gateway::credentialsRevoke({
            {"access_key", adminCredential.access_key}
        }, viewSession),
        std::exception);

    const auto manageUserId = userWithAdminRole(
        "manage_credentials",
        adminRoleWithS3("manage_credentials", vh::rbac::permission::admin::S3Gateway::CredentialManager()));
    const auto manageSession = wsSessionForUser(manageUserId);
    const auto manageCredential = createCredential(manageUserId, "user_access");
    EXPECT_THROW(
        (void)vh::protocols::ws::handler::S3Gateway::credentialsScopeUpdate({
            {"credential_id", manageCredential.id},
            {"scope_mode", "user_access"},
            {"principal_user_id", userId}
        }, manageSession),
        std::exception);

    EXPECT_THROW(
        (void)vh::protocols::ws::handler::S3Gateway::bucketsBind({
            {"bucket_name", "gate-bind-" + std::to_string(vaultId)},
            {"vault_id", vaultId}
        }, manageSession),
        std::exception);

    EXPECT_THROW(
        (void)vh::protocols::ws::handler::S3Gateway::budgetPolicyUpsert({
            {"scope", "gateway_credential"},
            {"gateway_credential_id", manageCredential.id},
            {"mode", "enforce"},
            {"max_daily_cost", "1.00"},
            {"currency", "USD"}
        }, manageSession),
        std::exception);

    EXPECT_THROW(
        (void)vh::protocols::ws::handler::S3Gateway::credentialsRolesAssign({
            {"credential_id", manageCredential.id},
            {"vault_id", vaultId},
            {"vault_role_name", "reader"}
        }, manageSession),
        std::exception);
}

// Stage 0 S4: `vh s3-gateway creds scope <cred> revoke-vault <vault>` used to delete the credential's vault role
// assignment and selected vault after only "principal or ManageCredentials", with no vault-role Revoke check. The ws
// twin (s3.gateway.credentials.selectedVaults.remove) always required RolePermissions::Revoke on that vault.
TEST_F(S3GatewayDbTest, CliScopeRevokeVaultRequiresVaultRoleRevoke) {
    if (!vh::runtime::Deps::get().shellUsageManager)
        vh::runtime::Deps::get().shellUsageManager = std::make_shared<vh::protocols::shell::UsageManager>();
    const auto router = std::make_shared<vh::protocols::shell::Router>();
    vh::protocols::shell::commands::registerS3GatewayCommands(router);

    const auto principalId = userWithAdminRole(
        "revoke_principal",
        adminRoleWithS3("revoke_principal", vh::rbac::permission::admin::S3Gateway::None()));
    assignPrincipalVaultRole(vaultId, principalId, "reader");
    const auto credential = createCredential(principalId, "vault_allowlist");
    setCredentialDefaultVaultRole(credential.id, "reader");
    selectCredentialVault(credential.id, vaultId);
    assignCredentialVaultRole(credential.id, vaultId, "reader");

    const auto selectedCount = [&] {
        return vh::db::query::s3::Gateway::listCredentialSelectedVaults(credential.id).size();
    };
    const auto assignmentCount = [&] {
        return vh::db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id).size();
    };
    ASSERT_EQ(1u, selectedCount());
    ASSERT_EQ(1u, assignmentCount());

    const auto line = "s3-gateway creds scope " + std::to_string(credential.id) + " revoke-vault " + std::to_string(vaultId);
    const auto run = [&](const uint32_t callerId) {
        const auto caller = vh::identities::manager().user(callerId);
        try {
            return router->executeLine(line, caller, nullptr).exit_code;
        } catch (const std::exception&) {
            return 1;
        }
    };

    // Credential manager that may retarget principals but holds no vault-role rights on this vault.
    const auto managerId = userWithAdminRole(
        "revoke_manager",
        adminRoleWithS3("revoke_manager", vh::rbac::permission::admin::S3Gateway::PrincipalAssigner()));
    EXPECT_NE(0, run(managerId));
    EXPECT_EQ(1u, selectedCount()) << "revoke-vault removed the selected vault without vault-role Revoke";
    EXPECT_EQ(1u, assignmentCount()) << "revoke-vault removed the role assignment without vault-role Revoke";

    // Positive control: a caller with vault-role authority (super_admin) still revokes through the same line.
    const auto superAdmin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(superAdmin);
    ASSERT_TRUE(superAdmin->isSuperAdmin());
    EXPECT_EQ(0, run(superAdmin->id));
    EXPECT_EQ(0u, selectedCount());
    EXPECT_EQ(0u, assignmentCount());
}

TEST_F(S3GatewayDbTest, S3GatewayWebSocketAssignPrincipalPermissionAllowsRetargeting) {
    const auto assignerUserId = userWithAdminRole(
        "assigner",
        adminRoleWithS3("assigner", vh::rbac::permission::admin::S3Gateway::PrincipalAssigner()));
    const auto assignerSession = wsSessionForUser(assignerUserId);
    const auto credential = createCredential(assignerUserId, "user_access");

    const auto updated = vh::protocols::ws::handler::S3Gateway::credentialsScopeUpdate({
        {"credential_id", credential.id},
        {"scope_mode", "user_access"},
        {"principal_user_id", userId}
    }, assignerSession);

    ASSERT_TRUE(updated.contains("credential"));
    EXPECT_EQ(userId, updated.at("credential").at("principal_user_id").get<uint32_t>());
}

TEST_F(S3GatewayDbTest, S3GatewayWebSocketRejectsRemoteModeForLocalVaultBinding) {
    auto session = std::make_shared<vh::protocols::ws::Session>(
        std::make_shared<vh::protocols::ws::Router>());
    session->user = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(session->user);
    ASSERT_TRUE(session->user->isSuperAdmin());

    EXPECT_THROW(
        vh::protocols::ws::handler::S3Gateway::bucketsBind({
            {"bucket_name", "local-as-remote-" + std::to_string(vaultId)},
            {"vault_id", vaultId},
            {"mode", "remote_cache"}
        }, session),
        std::exception);

    const auto bound = vh::protocols::ws::handler::S3Gateway::bucketsBind({
        {"bucket_name", "local-binding-" + std::to_string(vaultId)},
        {"vault_id", vaultId}
    }, session);
    EXPECT_TRUE(bound.at("bound").get<bool>());
    const auto binding = vh::db::query::s3::Gateway::resolveBucket("local-binding-" + std::to_string(vaultId));
    ASSERT_TRUE(binding);
    EXPECT_EQ("local", binding->mode);
}

TEST_F(S3GatewayDbTest, VaultSlugDefaultsAndDisplayRenameDoesNotRewriteBindings) {
    auto session = std::make_shared<vh::protocols::ws::Session>(
        std::make_shared<vh::protocols::ws::Router>());
    session->user = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(session->user);
    ASSERT_TRUE(session->user->isSuperAdmin());

    auto vault = std::make_shared<vh::vault::model::Vault>();
    vault->name = "My Photos";
    vault->description = "Slug default test";
    vault->owner_id = userId;
    vault->type = vh::vault::model::VaultType::Local;
    vault->is_active = true;

    auto sync = std::make_shared<vh::sync::model::LocalPolicy>();
    sync->conflict_policy = vh::sync::model::LocalPolicy::ConflictPolicy::KeepBoth;

    vault = vh::runtime::Deps::get().storageManager->addVault(vault, sync);
    ASSERT_TRUE(vault);
    EXPECT_EQ("my-photos", vault->slug);
    EXPECT_EQ("my-photos", vault->effectiveFuseName());
    const auto mountPoint = vault->mount_point.string();
    const auto initialFuseRoot = vh::runtime::Deps::get().storageManager
        ->getEngine(vault->id)
        ->paths
        ->absRelToRoot(vh::runtime::Deps::get().storageManager->getEngine(vault->id)->paths->vaultRoot,
                       vh::fs::model::PathType::FUSE_ROOT);
    EXPECT_EQ(initialFuseRoot, std::filesystem::path("/my-photos"));

    const auto bound = vh::protocols::ws::handler::S3Gateway::bucketsBind({
        {"vault_id", vault->id}
    }, session);
    EXPECT_TRUE(bound.at("bound").get<bool>());
    ASSERT_TRUE(vh::db::query::s3::Gateway::resolveBucket("my-photos"));

    auto renamed = vh::db::query::vault::Vault::getVault(vault->id);
    ASSERT_TRUE(renamed);
    renamed->name = "Archive Photos";
    vh::runtime::Deps::get().storageManager->updateVault(renamed);

    const auto reloaded = vh::db::query::vault::Vault::getVault(vault->id);
    ASSERT_TRUE(reloaded);
    EXPECT_EQ("Archive Photos", reloaded->name);
    EXPECT_EQ("my-photos", reloaded->slug);
    EXPECT_EQ("my-photos", reloaded->effectiveFuseName());
    EXPECT_EQ(mountPoint, reloaded->mount_point.string());
    ASSERT_TRUE(vh::db::query::s3::Gateway::resolveBucket("my-photos"));
}

TEST_F(S3GatewayDbTest, SlugAndFuseOverrideControlOnlyDefaultFuseBinding) {
    auto vault = std::make_shared<vh::vault::model::Vault>();
    vault->name = "Slug Update " + s3GatewayUniqueSuffix("vault");
    vault->description = "Slug update test";
    vault->owner_id = userId;
    vault->type = vh::vault::model::VaultType::Local;
    vault->is_active = true;

    auto sync = std::make_shared<vh::sync::model::LocalPolicy>();
    sync->conflict_policy = vh::sync::model::LocalPolicy::ConflictPolicy::KeepBoth;

    vault = vh::runtime::Deps::get().storageManager->addVault(vault, sync);
    ASSERT_TRUE(vault);

    auto update = vh::db::query::vault::Vault::getVault(vault->id);
    ASSERT_TRUE(update);
    update->slug = "renamed-default-" + std::to_string(vault->id);
    vh::runtime::Deps::get().storageManager->updateVault(update);

    auto reloaded = vh::db::query::vault::Vault::getVault(vault->id);
    ASSERT_TRUE(reloaded);
    EXPECT_EQ(update->slug, reloaded->effectiveFuseName());
    EXPECT_EQ(
        std::filesystem::path("/") / update->slug,
        vh::runtime::Deps::get().storageManager->getEngine(vault->id)->paths->absRelToRoot(
            vh::runtime::Deps::get().storageManager->getEngine(vault->id)->paths->vaultRoot,
            vh::fs::model::PathType::FUSE_ROOT));

    reloaded->fuse_name = "custom-root-" + std::to_string(vault->id);
    vh::runtime::Deps::get().storageManager->updateVault(reloaded);
    auto overridden = vh::db::query::vault::Vault::getVault(vault->id);
    ASSERT_TRUE(overridden);
    EXPECT_EQ(*reloaded->fuse_name, overridden->effectiveFuseName());

    overridden->slug = "slug-after-override-" + std::to_string(vault->id);
    vh::runtime::Deps::get().storageManager->updateVault(overridden);
    auto afterSlugUpdate = vh::db::query::vault::Vault::getVault(vault->id);
    ASSERT_TRUE(afterSlugUpdate);
    EXPECT_EQ("slug-after-override-" + std::to_string(vault->id), afterSlugUpdate->slug);
    EXPECT_EQ(*reloaded->fuse_name, afterSlugUpdate->effectiveFuseName());
    EXPECT_FALSE(vh::db::query::s3::Gateway::resolveBucket(afterSlugUpdate->slug));
}

TEST_F(S3GatewayDbTest, ExplicitS3BucketBindingSurvivesVaultNameAndSlugUpdates) {
    auto session = std::make_shared<vh::protocols::ws::Session>(
        std::make_shared<vh::protocols::ws::Router>());
    session->user = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(session->user);
    ASSERT_TRUE(session->user->isSuperAdmin());

    const auto targetVaultId = createLocalVault(s3GatewayUniqueSuffix("explicit_bucket"), userId);
    const auto bucketName = "explicit-binding-" + std::to_string(targetVaultId);
    const auto bound = vh::protocols::ws::handler::S3Gateway::bucketsBind({
        {"vault_id", targetVaultId},
        {"bucket_name", bucketName}
    }, session);
    EXPECT_TRUE(bound.at("bound").get<bool>());

    auto vault = vh::db::query::vault::Vault::getVault(targetVaultId);
    ASSERT_TRUE(vault);
    vault->name = "Renamed Explicit Bucket Vault";
    vault->slug = "renamed-explicit-" + std::to_string(targetVaultId);
    vh::runtime::Deps::get().storageManager->updateVault(vault);

    ASSERT_TRUE(vh::db::query::s3::Gateway::resolveBucket(bucketName));
    EXPECT_FALSE(vh::db::query::s3::Gateway::resolveBucket(vault->slug));
}

TEST_F(S3GatewayDbTest, RejectsInvalidAndDuplicateExternalNames) {
    auto vault = std::make_shared<vh::vault::model::Vault>();
    vault->name = "Invalid Slug " + s3GatewayUniqueSuffix("vault");
    vault->slug = "Invalid_Slug";
    vault->owner_id = userId;
    vault->type = vh::vault::model::VaultType::Local;

    auto sync = std::make_shared<vh::sync::model::LocalPolicy>();
    EXPECT_THROW((void)vh::db::query::vault::Vault::upsertVault(vault, sync), std::invalid_argument);

    auto first = std::make_shared<vh::vault::model::Vault>();
    first->name = "Duplicate Slug A " + s3GatewayUniqueSuffix("vault");
    first->slug = uniqueS3Name("duplicate-slug");
    first->owner_id = userId;
    first->type = vh::vault::model::VaultType::Local;
    const auto duplicateSlug = first->slug;
    first->id = vh::db::query::vault::Vault::upsertVault(first, std::make_shared<vh::sync::model::LocalPolicy>());

    auto second = std::make_shared<vh::vault::model::Vault>();
    second->name = "Duplicate Slug B " + s3GatewayUniqueSuffix("vault");
    second->slug = duplicateSlug;
    second->owner_id = userId;
    second->type = vh::vault::model::VaultType::Local;
    EXPECT_THROW((void)vh::db::query::vault::Vault::upsertVault(second, std::make_shared<vh::sync::model::LocalPolicy>()), std::invalid_argument);

    auto fuseA = vh::db::query::vault::Vault::getVault(first->id);
    ASSERT_TRUE(fuseA);
    fuseA->fuse_name = "shared-fuse-" + std::to_string(first->id);
    vh::db::query::vault::Vault::upsertVault(fuseA);

    auto fuseB = std::make_shared<vh::vault::model::Vault>();
    fuseB->name = "Duplicate Fuse " + s3GatewayUniqueSuffix("vault");
    fuseB->slug = uniqueS3Name("duplicate-fuse");
    fuseB->fuse_name = fuseA->fuse_name;
    fuseB->owner_id = userId;
    fuseB->type = vh::vault::model::VaultType::Local;
    EXPECT_THROW((void)vh::db::query::vault::Vault::upsertVault(fuseB, std::make_shared<vh::sync::model::LocalPolicy>()), std::invalid_argument);

    EXPECT_THROW(vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = "Bad_Bucket",
        .api_exclusive = false,
        .mode = "local",
        .created_by = userId
    }), std::invalid_argument);
}

TEST_F(S3GatewayDbTest, DisabledAndExpiredCredentialsDoNotAuthenticate) {
    const vh::protocols::s3::CredentialManager manager;
    auto active = manager.createCredential({
        .created_by = userId,
        .principal_user_id = userId,
        .name = "disabled-auth-" + s3GatewayUniqueSuffix("credential"),
        .scope_mode = "user_access",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .vault_scopes = {}
    });
    ASSERT_TRUE(manager.findEnabledSecret(active.credential.access_key));

    vh::db::Transactions::exec("S3GatewayDbTest::disableCredential", [&](pqxx::work& txn) {
        txn.exec(
            "UPDATE s3_gateway_credentials SET enabled = FALSE WHERE id = $1",
            pqxx::params{active.credential.id});
    });
    EXPECT_FALSE(manager.findEnabledSecret(active.credential.access_key));

    auto expired = manager.createCredential({
        .created_by = userId,
        .principal_user_id = userId,
        .name = "expired-auth-" + s3GatewayUniqueSuffix("credential"),
        .scope_mode = "user_access",
        .description = std::nullopt,
        .expires_at = std::time(nullptr) - 60,
        .vault_scopes = {}
    });
    EXPECT_FALSE(manager.findEnabledSecret(expired.credential.access_key));
}

TEST_F(S3GatewayDbTest, CredentialScopeShorthandWritesFinalRbacTablesAndGatesActions) {
    const auto secondVaultId = createLocalVault(s3GatewayUniqueSuffix("scope"), userId);

    vh::db::query::s3::GatewayCredential credential;
    credential.user_id = userId;
    credential.principal_user_id = userId;
    credential.created_by = userId;
    credential.name = "scope-query-" + s3GatewayUniqueSuffix("credential");
    credential.access_key = "VHTESTSCOPEQUERY" + std::to_string(vaultId);
    credential.encrypted_secret_access_key = {1, 2, 3};
    credential.iv = {4, 5, 6};
    credential.enabled = true;
    credential.scope_mode = "vault_allowlist";
    credential.id = vh::db::query::s3::Gateway::createCredential(credential);

    vh::db::query::s3::Gateway::replaceCredentialScopeShorthand(credential.id, {
        {
            .credential_id = credential.id,
            .vault_id = vaultId,
            .can_list = true,
            .can_read = true,
            .can_write = false,
            .can_delete = false,
            .can_admin = false
        },
        {
            .credential_id = credential.id,
            .vault_id = secondVaultId,
            .can_list = true,
            .can_read = false,
            .can_write = true,
            .can_delete = true,
            .can_admin = false
        }
    });

    auto selectedVaults = vh::db::query::s3::Gateway::listCredentialSelectedVaults(credential.id);
    ASSERT_EQ(selectedVaults.size(), 2u);
    auto defaultRole = vh::db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    ASSERT_TRUE(defaultRole);
    EXPECT_EQ(defaultRole->vault_role_id, roleIdByName("implicit_deny"));
    auto assignments = vh::db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id);
    ASSERT_EQ(assignments.size(), 2u);

    vh::db::query::s3::Gateway::replaceCredentialScopeShorthand(credential.id, {{
        .credential_id = credential.id,
        .vault_id = secondVaultId,
        .can_list = true,
        .can_read = true,
        .can_write = true,
        .can_delete = false,
        .can_admin = false
    }});
    selectedVaults = vh::db::query::s3::Gateway::listCredentialSelectedVaults(credential.id);
    ASSERT_EQ(selectedVaults.size(), 1u);
    EXPECT_EQ(selectedVaults.front().vault_id, secondVaultId);
    assignments = vh::db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id);
    EXPECT_TRUE(assignments.empty());
    defaultRole = vh::db::query::s3::Gateway::getCredentialDefaultVaultRole(credential.id);
    ASSERT_TRUE(defaultRole);
    EXPECT_EQ(defaultRole->vault_role_id, roleIdByName("contributor"));
    const auto credentialRole = vh::db::query::s3::Gateway::getCredentialVaultRoleForVault(credential.id, secondVaultId);
    EXPECT_FALSE(credentialRole);
    const auto effectiveRole = vh::db::query::s3::Gateway::getEffectiveCredentialVaultRole(credential.id, secondVaultId, credential.scope_mode);
    ASSERT_TRUE(effectiveRole);
    EXPECT_EQ(effectiveRole->name, "contributor");

    vh::db::Transactions::exec("S3GatewayDbTest::assignPrincipalGatewayScopeVaultRole", [&](pqxx::work& txn) {
        const auto roleId = txn.exec(
            "SELECT id FROM vault_role WHERE name = 'manager' LIMIT 1"
        ).one_field_ref().as<uint32_t>();
        txn.exec(
            "INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) "
            "VALUES ($1, 'user', $2, $3) "
            "ON CONFLICT (vault_id, subject_type, subject_id) DO UPDATE SET role_id = EXCLUDED.role_id",
            pqxx::params{secondVaultId, userId, roleId});
    });
    (void)vh::identities::manager().reconcile();   // written behind the identity manager

    auto user = vh::identities::manager().user(userId);
    ASSERT_TRUE(user);
    vh::protocols::s3::AuthContext auth{
        .user = user,
        .credential = credential,
        .credential_id = credential.id,
        .access_key = credential.access_key,
        .scope_mode = "vault_allowlist",
        .dev_context = false
    };
    using Action = vh::rbac::permission::vault::FilesystemAction;
    EXPECT_TRUE(vh::protocols::s3::ObjectStore::credentialAllows(auth, secondVaultId, Action::Write));
    EXPECT_FALSE(vh::protocols::s3::ObjectStore::credentialAllows(auth, secondVaultId, Action::Delete));
    EXPECT_FALSE(vh::protocols::s3::ObjectStore::credentialAllows(auth, vaultId, Action::Read));
}

TEST_F(S3GatewayDbTest, SignedRouteScopeDeniedReturnsS3XmlAccessDenied) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.require_sigv4 = true;
    cfg.s3_gateway.allow_path_style = true;
    vh::config::Registry::set(cfg);

    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());

    const std::string bucketName = "scope-denied-" + std::to_string(vaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .api_exclusive = true,
        .mode = "local",
        .created_by = admin->id
    });

    const auto selectedOtherVaultId = createLocalVault(s3GatewayUniqueSuffix("scope_denied_selected"), admin->id);
    const vh::protocols::s3::CredentialManager manager;
    auto secret = manager.createCredential({
        .created_by = admin->id,
        .principal_user_id = admin->id,
        .name = "route-scope-denied-" + s3GatewayUniqueSuffix("credential"),
        .scope_mode = "vault_allowlist",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .default_vault_role_id = roleIdByName("reader"),
        .selected_vault_ids = {selectedOtherVaultId},
        .vault_scopes = {}
    });

    vh::protocols::s3::Router::Request request{http::verb::head, "/" + bucketName, 11};
    request.set(http::field::host, "localhost:39000");
    signS3GatewayRequest(request, secret.credential.access_key, secret.secret_access_key);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::forbidden);
    EXPECT_NE(response.body().find("<Code>AccessDenied</Code>"), std::string::npos);
    EXPECT_NE(response.body().find("<RequestId>"), std::string::npos);
}

TEST_F(S3GatewayDbTest, MultipartUploadUsesOpaquePartDirAndCompleteKeepsRoot) {
    std::filesystem::remove_all(vh::protocols::s3::MultipartStore::partRoot());

    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);

    const std::string bucketName = "multipart-complete-" + std::to_string(vaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .api_exclusive = true,
        .mode = "local",
        .created_by = admin->id
    });
    const vh::protocols::s3::ObjectStore objects;
    const auto bucket = objects.resolveBucket(bucketName, admin);

    const vh::protocols::s3::MultipartStore store;
    const std::string key = "very-secret-object.txt";
    const auto uploadId = store.createUpload(bucket, key, {});
    const auto upload = vh::db::query::s3::Gateway::getMultipartUpload(uploadId);
    ASSERT_TRUE(upload);
    EXPECT_FALSE(upload->parts_dir_id.empty());
    EXPECT_NE(upload->parts_dir_id, upload->upload_id);

    const auto part = store.uploadPart(bucket, key, uploadId, 1, {'p', 'a', 'r', 't'});
    const auto partDir = vh::protocols::s3::MultipartStore::partRoot() / upload->parts_dir_id;
    EXPECT_EQ(part.path, partDir / "1");
    EXPECT_TRUE(std::filesystem::exists(part.path));
    EXPECT_EQ(part.path.string().find(bucketName), std::string::npos);
    EXPECT_EQ(part.path.string().find(key), std::string::npos);
    EXPECT_TRUE(std::filesystem::exists(vh::protocols::s3::MultipartStore::partRoot()));

    const auto dirPerms = std::filesystem::status(partDir).permissions() &
        (std::filesystem::perms::owner_all | std::filesystem::perms::group_all | std::filesystem::perms::others_all);
    EXPECT_EQ(dirPerms, std::filesystem::perms::owner_all);

    const auto state = store.completeUpload(bucket, key, uploadId, {{1, part.etag}});
    EXPECT_TRUE(state.multipart);
    EXPECT_FALSE(std::filesystem::exists(partDir));
    EXPECT_TRUE(std::filesystem::exists(vh::protocols::s3::MultipartStore::partRoot()));

    std::filesystem::remove_all(vh::protocols::s3::MultipartStore::partRoot());
}

TEST_F(S3GatewayDbTest, AbortMultipartUploadRemovesOpaquePartDirAndKeepsRoot) {
    std::filesystem::remove_all(vh::protocols::s3::MultipartStore::partRoot());

    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);

    const std::string bucketName = "multipart-abort-" + std::to_string(vaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .api_exclusive = true,
        .mode = "local",
        .created_by = admin->id
    });
    const vh::protocols::s3::ObjectStore objects;
    const auto bucket = objects.resolveBucket(bucketName, admin);

    const vh::protocols::s3::MultipartStore store;
    const std::string key = "abort-secret-object.txt";
    const auto uploadId = store.createUpload(bucket, key, {});
    const auto upload = vh::db::query::s3::Gateway::getMultipartUpload(uploadId);
    ASSERT_TRUE(upload);

    const auto part = store.uploadPart(bucket, key, uploadId, 1, {'p', 'a', 'r', 't'});
    const auto partDir = vh::protocols::s3::MultipartStore::partRoot() / upload->parts_dir_id;
    ASSERT_TRUE(std::filesystem::exists(part.path));

    store.abortUpload(bucket, key, uploadId);

    EXPECT_FALSE(vh::db::query::s3::Gateway::getMultipartUpload(uploadId));
    EXPECT_TRUE(vh::db::query::s3::Gateway::listMultipartParts(uploadId).empty());
    EXPECT_FALSE(std::filesystem::exists(partDir));
    EXPECT_TRUE(std::filesystem::exists(vh::protocols::s3::MultipartStore::partRoot()));

    std::filesystem::remove_all(vh::protocols::s3::MultipartStore::partRoot());
}

TEST_F(S3GatewayDbTest, AbortExpiredMultipartUploadsUsesConfiguredRetention) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    std::filesystem::remove_all(vh::protocols::s3::MultipartStore::partRoot());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.multipart.abort_after_days = 1;
    vh::config::Registry::set(cfg);

    const std::string oldUpload = "old-upload-" + std::to_string(vaultId);
    const std::string freshUpload = "fresh-upload-" + std::to_string(vaultId);
    const std::string oldPartsDirId = "old-parts-" + std::to_string(vaultId);
    const std::string freshPartsDirId = "fresh-parts-" + std::to_string(vaultId);
    vh::db::query::s3::Gateway::createMultipartUpload({
        .upload_id = oldUpload,
        .parts_dir_id = oldPartsDirId,
        .vault_id = vaultId,
        .object_key = "old.txt",
        .initiated_by = userId,
        .content_type = std::nullopt,
        .metadata = {},
        .storage_class = std::nullopt
    });
    vh::db::query::s3::Gateway::createMultipartUpload({
        .upload_id = freshUpload,
        .parts_dir_id = freshPartsDirId,
        .vault_id = vaultId,
        .object_key = "fresh.txt",
        .initiated_by = userId,
        .content_type = std::nullopt,
        .metadata = {},
        .storage_class = std::nullopt
    });

    const auto oldPartDir = vh::protocols::s3::MultipartStore::partRoot() / oldPartsDirId;
    const auto oldPartPath = oldPartDir / "1";
    std::filesystem::create_directories(oldPartPath.parent_path());
    std::ofstream(oldPartPath, std::ios::binary) << "old part";
    vh::db::query::s3::Gateway::upsertMultipartPart({
        .upload_id = oldUpload,
        .part_number = 1,
        .etag = "\"etag\"",
        .size_bytes = 8,
        .md5 = std::vector<uint8_t>(16, 0),
        .path = oldPartPath,
        .created_at = std::time(nullptr)
    });

    const auto cutoffTime = std::time(nullptr) - 2 * 24 * 60 * 60;
    vh::db::Transactions::exec("S3GatewayDbTest::ageMultipartUpload", [&](pqxx::work& txn) {
        txn.exec(
            "UPDATE s3_gateway_multipart_upload SET initiated_at = TO_TIMESTAMP($1::double precision) WHERE upload_id = $2",
            pqxx::params{cutoffTime, oldUpload});
    });

    vh::protocols::s3::MultipartStore store;
    EXPECT_EQ(store.abortExpiredUploads(), 1u);

    EXPECT_FALSE(vh::db::query::s3::Gateway::getMultipartUpload(oldUpload));
    EXPECT_TRUE(vh::db::query::s3::Gateway::listMultipartParts(oldUpload).empty());
    EXPECT_FALSE(std::filesystem::exists(oldPartPath));
    EXPECT_FALSE(std::filesystem::exists(oldPartDir));
    EXPECT_TRUE(std::filesystem::exists(vh::protocols::s3::MultipartStore::partRoot()));
    EXPECT_TRUE(vh::db::query::s3::Gateway::getMultipartUpload(freshUpload));

    std::filesystem::remove_all(vh::protocols::s3::MultipartStore::partRoot());
}

TEST_F(S3GatewayDbTest, DeleteObjectStateAndRemoteIndexRemovesGatewayAndRemoteRows) {
    putObject("delete-me.txt");
    vh::db::query::s3::Gateway::upsertObjectMetadata(
        vaultId,
        "delete-me.txt",
        {{"color", "blue"}});

    vh::db::Transactions::exec("S3GatewayDbTest::insertRemoteObjectIndex", [](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO remote_object_index (vault_id, object_key, size_bytes, etag, source)
                VALUES ($1, $2, $3, $4, $5)
            )SQL",
            pqxx::params{S3GatewayDbTest::vaultId, "delete-me.txt", 1, "\"remote-etag\"", "event"});
    });

    vh::db::query::s3::Gateway::deleteObjectStateAndRemoteIndex(vaultId, "/delete-me.txt");

    EXPECT_FALSE(vh::db::query::s3::Gateway::getObjectState(vaultId, "delete-me.txt"));
    EXPECT_TRUE(vh::db::query::s3::Gateway::listObjectMetadata(vaultId, "delete-me.txt").empty());

    const auto remoteRows = vh::db::Transactions::exec(
        "S3GatewayDbTest::countRemoteObjectIndex",
        [](pqxx::work& txn) {
            return txn.exec(
                "SELECT COUNT(*) FROM remote_object_index WHERE vault_id = $1 AND object_key = $2",
                pqxx::params{S3GatewayDbTest::vaultId, "delete-me.txt"}).one_field_ref().as<int>();
        });
    EXPECT_EQ(remoteRows, 0);
}

TEST_F(S3GatewayDbTest, RemoteBackedListDetectsStaleRemoteIndex) {
    vh::db::Transactions::exec("S3GatewayDbTest::insertStaleRemoteObjectIndex", [](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO remote_object_index (vault_id, object_key, size_bytes, etag, source, indexed_at)
                VALUES ($1, $2, $3, $4, $5, TO_TIMESTAMP($6::double precision))
            )SQL",
            pqxx::params{
                S3GatewayDbTest::vaultId,
                "stale-index.txt",
                1,
                "\"remote-etag\"",
                "manifest",
                std::time(nullptr) - 2 * 24 * 60 * 60});
    });

    auto vault = std::make_shared<vh::vault::model::Vault>();
    vault->id = vaultId;
    vault->name = "S3 Gateway Test Vault";
    vault->mount_point = "s3_gateway_test";

    auto policy = std::make_shared<vh::sync::model::RemotePolicy>();
    policy->max_remote_index_age = std::chrono::seconds(60);

    auto engine = std::make_shared<vh::storage::CloudEngine>();
    engine->vault = vault;
    engine->sync = policy;

    const vh::protocols::s3::ResolvedBucket bucket{
        .bucket_name = "remote-cache",
        .vault_id = vaultId,
        .mode = "remote_cache",
        .api_exclusive = true,
        .engine = engine,
        .actor = vh::identities::manager().user(userId),
        .gateway_access = std::nullopt
    };

    const vh::protocols::s3::ObjectStore store;
    EXPECT_TRUE(store.remoteIndexStale(bucket));

    policy->max_remote_index_age = std::chrono::hours(24 * 7);
    EXPECT_FALSE(store.remoteIndexStale(bucket));
}

TEST_F(S3GatewayDbTest, GatewayServiceBindsAndServesS3XmlWhenEnabled) {
    ConfigRestore restoreConfig(vh::config::Registry::get());

    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.enabled = true;
    cfg.s3_gateway.host = "127.0.0.1";
    cfg.s3_gateway.port = freeLoopbackPort();
    cfg.s3_gateway.require_sigv4 = false;
    vh::config::Registry::set(cfg);

    vh::concurrency::ThreadPoolManager::instance().init();
    ThreadPoolShutdown shutdownPools{true};

    vh::protocols::s3::GatewayService service;
    service.start();

    auto status = service.gatewayStatus();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    while (!status.ready && service.isRunning() && std::chrono::steady_clock::now() < deadline) {
        std::this_thread::sleep_for(std::chrono::milliseconds(25));
        status = service.gatewayStatus();
    }

    ASSERT_TRUE(status.configured);
    ASSERT_TRUE(status.ready);

    const auto response = httpGetRoot(cfg.s3_gateway.port);

    EXPECT_EQ(response.result(), http::status::ok);
    EXPECT_NE(response.body().find("<ListAllMyBucketsResult"), std::string::npos);
    EXPECT_FALSE(response["x-amz-request-id"].empty());
    EXPECT_EQ(response[http::field::cache_control], "private, no-store");
    EXPECT_GE(service.gatewayStatus().totalRequests, 1u);

    service.stop();
}

TEST_F(S3GatewayDbTest, ListObjectsDelimiterPaginatesCommonPrefixesOnce) {
    putObject("a/1.txt");
    putObject("a/2.txt");
    putObject("b/1.txt");

    vh::db::query::s3::ObjectListParams firstParams;
    firstParams.max_keys = 1;
    firstParams.delimiter = "/";
    const auto first = vh::db::query::s3::Gateway::listObjectStates(vaultId, firstParams);

    ASSERT_TRUE(first.is_truncated);
    ASSERT_TRUE(first.objects.empty());
    ASSERT_EQ(first.common_prefixes.size(), 1u);
    EXPECT_EQ(first.common_prefixes[0], "a/");
    ASSERT_TRUE(first.next_continuation_token);
    EXPECT_EQ(*first.next_continuation_token, "a/");

    vh::db::query::s3::ObjectListParams secondParams;
    secondParams.max_keys = 1;
    secondParams.delimiter = "/";
    secondParams.continuation_token = first.next_continuation_token;
    const auto second = vh::db::query::s3::Gateway::listObjectStates(vaultId, secondParams);

    ASSERT_FALSE(second.is_truncated);
    ASSERT_TRUE(second.objects.empty());
    ASSERT_EQ(second.common_prefixes.size(), 1u);
    EXPECT_EQ(second.common_prefixes[0], "b/");
}

TEST_F(S3GatewayDbTest, ObjectStoreLocalListUsesMetadataEtagsForFilesystemEntries) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());

    const auto localVaultId = createLocalVault(s3GatewayUniqueSuffix("metadata_list_local"), admin->id);
    const auto engine = vh::runtime::Deps::get().storageManager->getEngine(localVaultId);
    ASSERT_TRUE(engine);
    const std::filesystem::path vaultPath = "/metadata-only-list.txt";
    auto created = vh::fs::Filesystem::createFile({
        .path = vaultPath,
        .fuse_path = engine->vaultPathToFusePath(vaultPath),
        .buffer = {'p', 'l', 'a', 'i', 'n', 't', 'e', 'x', 't'},
        .engine = engine,
        .user = admin,
        .overwrite = true
    });
    ASSERT_TRUE(created);

    const auto bucketName = "metadata-list-" + std::to_string(localVaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = localVaultId,
        .bucket_name = bucketName,
        .api_exclusive = false,
        .mode = "local",
        .created_by = admin->id
    });

    const vh::protocols::s3::ObjectStore store;
    const auto bucket = store.resolveBucket(bucketName, admin);
    const auto listed = store.listObjects(bucket, {});

    ASSERT_EQ(1u, listed.objects.size());
    EXPECT_EQ("metadata-only-list.txt", listed.objects.front().object_key);
    EXPECT_TRUE(listed.objects.front().etag.starts_with("\"vh-meta-"));
    EXPECT_NE("\"66a7fb99f149162da3d8c6c15c225d0f\"", listed.objects.front().etag);
}

TEST_F(S3GatewayDbTest, ObjectStoreRemoteListUsesRemoteIndexWithoutGatewayRows) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());

    const auto remoteVaultId = createLocalVault(s3GatewayUniqueSuffix("metadata_list_remote"), admin->id);
    const auto bucketName = "remote-index-list-" + std::to_string(remoteVaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = remoteVaultId,
        .bucket_name = bucketName,
        .api_exclusive = false,
        .mode = "remote_cache",
        .created_by = admin->id
    });
    vh::db::Transactions::exec("S3GatewayDbTest::insertRemoteIndexListObject", [&](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO remote_object_index (vault_id, object_key, size_bytes, etag, storage_class, source)
                VALUES ($1, $2, $3, $4, $5, $6)
            )SQL",
            pqxx::params{remoteVaultId, "indexed/only.txt", 12, "\"remote-index-etag\"", "STANDARD", "manifest"});
    });

    const vh::protocols::s3::ObjectStore store;
    const auto bucket = store.resolveBucket(bucketName, admin);
    const auto listed = store.listObjects(bucket, {});

    ASSERT_EQ(1u, listed.objects.size());
    EXPECT_EQ("indexed/only.txt", listed.objects.front().object_key);
    EXPECT_EQ("\"remote-index-etag\"", listed.objects.front().etag);
    EXPECT_EQ(12u, listed.objects.front().size_bytes);
    ASSERT_TRUE(listed.objects.front().storage_class);
    EXPECT_EQ("STANDARD", *listed.objects.front().storage_class);
}

TEST_F(S3GatewayDbTest, DeleteBucketRejectsLocalFilesystemEntriesWithoutGatewayRows) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());

    const auto localVaultId = createLocalVault(s3GatewayUniqueSuffix("delete_bucket_local"), admin->id);
    const auto engine = vh::runtime::Deps::get().storageManager->getEngine(localVaultId);
    ASSERT_TRUE(engine);
    const std::filesystem::path vaultPath = "/only-in-fs.txt";
    ASSERT_TRUE(vh::fs::Filesystem::createFile({
        .path = vaultPath,
        .fuse_path = engine->vaultPathToFusePath(vaultPath),
        .buffer = {'l', 'o', 'c', 'a', 'l'},
        .engine = engine,
        .user = admin,
        .overwrite = true
    }));

    const auto bucketName = "delete-local-non-empty-" + std::to_string(localVaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = localVaultId,
        .bucket_name = bucketName,
        .api_exclusive = false,
        .mode = "local",
        .created_by = admin->id
    });

    const vh::protocols::s3::ObjectStore store;
    try {
        store.deleteBucket(bucketName, admin);
        FAIL() << "expected BucketNotEmpty";
    } catch (const vh::protocols::s3::S3Error& error) {
        EXPECT_EQ("BucketNotEmpty", error.code);
    }
    EXPECT_TRUE(vh::db::query::s3::Gateway::resolveBucket(bucketName));
}

TEST_F(S3GatewayDbTest, DeleteBucketRejectsRemoteIndexLiveObjects) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());

    const auto remoteVaultId = createLocalVault(s3GatewayUniqueSuffix("delete_bucket_remote"), admin->id);
    const auto bucketName = "delete-remote-non-empty-" + std::to_string(remoteVaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = remoteVaultId,
        .bucket_name = bucketName,
        .api_exclusive = false,
        .mode = "remote_cache",
        .created_by = admin->id
    });
    vh::db::Transactions::exec("S3GatewayDbTest::insertRemoteIndexBucketDeleteObject", [&](pqxx::work& txn) {
        txn.exec(
            R"SQL(
                INSERT INTO remote_object_index (vault_id, object_key, size_bytes, etag, source)
                VALUES ($1, $2, $3, $4, $5)
            )SQL",
            pqxx::params{remoteVaultId, "live-remote.txt", 7, "\"live-remote\"", "manifest"});
    });

    const vh::protocols::s3::ObjectStore store;
    try {
        store.deleteBucket(bucketName, admin);
        FAIL() << "expected BucketNotEmpty";
    } catch (const vh::protocols::s3::S3Error& error) {
        EXPECT_EQ("BucketNotEmpty", error.code);
    }
    EXPECT_TRUE(vh::db::query::s3::Gateway::resolveBucket(bucketName));
}

TEST_F(S3GatewayDbTest, DeleteBucketAllowsTrulyEmptyApiExclusiveBucket) {
    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    ASSERT_TRUE(admin->isSuperAdmin());

    const auto emptyVaultId = createLocalVault(s3GatewayUniqueSuffix("delete_bucket_empty"), admin->id);
    const auto bucketName = "delete-empty-" + std::to_string(emptyVaultId);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = emptyVaultId,
        .bucket_name = bucketName,
        .api_exclusive = true,
        .mode = "local",
        .created_by = admin->id
    });

    const vh::protocols::s3::ObjectStore store;
    EXPECT_NO_THROW(store.deleteBucket(bucketName, admin));
    EXPECT_FALSE(vh::db::query::s3::Gateway::resolveBucket(bucketName));
}
