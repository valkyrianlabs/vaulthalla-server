#include "db/query/rbac/role/Admin.hpp"
#include "auth/Manager.hpp"
#include "db/encoding/interval.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/s3/Gateway.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/vault/Vault.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "crypto/id/Generator.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/Path.hpp"
#include "fs/model/File.hpp"
#include "fs/model/file/Trashed.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/s3/CredentialManager.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "protocols/s3/Router.hpp"
#include "protocols/s3/SigV4.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/ws/handler/Pricing.hpp"
#include "protocols/ws/handler/S3Gateway.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/ScopedS3RequestBudget.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/curl/helpers.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "sync/Cloud.hpp"
#include "sync/Planner.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "sync/model/Policy.hpp"
#include "sync/model/RemoteManifest.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/ScopedOp.hpp"
#include "sync/tasks/Delete.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "UsageManager.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <chrono>
#include <algorithm>
#include <barrier>
#include <cstdlib>
#include <ctime>
#include <deque>
#include <filesystem>
#include <future>
#include <fstream>
#include <functional>
#include <iomanip>
#include <map>
#include <memory>
#include <optional>
#include <sstream>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {
namespace http = boost::beast::http;

struct S3CostConfigRestore {
    vh::config::Config previous;

    explicit S3CostConfigRestore(vh::config::Config cfg)
        : previous(std::move(cfg)) {}

    ~S3CostConfigRestore() {
        vh::config::Registry::set(previous);
    }
};

std::shared_ptr<vh::vault::model::APIKey> dummyApiKey() {
    return std::make_shared<vh::vault::model::APIKey>(
        1,
        "unit",
        vh::vault::model::S3Provider::AWS,
        "ABCDEFGHIJKLMNOPQRST",
        "ABCDEFGHIJKLMNOPQRSTABCDEFGHIJKLMNOPQRST",
        "us-east-1",
        "https://s3.example.com");
}

class CountingS3Controller final : public vh::storage::s3::Controller {
public:
    int head_object_calls = 0;
    int download_to_buffer_calls = 0;
    int upload_object_with_metadata_calls = 0;
    int upload_buffer_with_metadata_calls = 0;
    int upload_buffer_conditional_calls = 0;
    int delete_object_calls = 0;
    int list_objects_calls = 0;
    bool upload_buffer_with_metadata_failure = false;
    bool delete_object_not_found = false;
    bool delete_object_failure = false;
    std::filesystem::path last_uploaded_key;
    std::size_t last_uploaded_buffer_size = 0;
    std::unordered_map<std::string, std::string> last_metadata;
    std::map<std::string, std::string> last_system_headers;
    std::optional<std::unordered_map<std::string, std::string>> head_response;
    std::vector<uint8_t> download_payload;
    std::deque<std::vector<uint8_t>> download_payloads;
    std::vector<std::filesystem::path> deleted_keys;
    std::u8string list_objects_xml = u8"<ListBucketResult></ListBucketResult>";

    CountingS3Controller()
        : Controller(dummyApiKey(), "unit-bucket") {}

    void uploadObjectWithMetadata(
        const std::filesystem::path&,
        const std::filesystem::path&,
        const std::unordered_map<std::string, std::string>& metadata) const override {
        vh::storage::s3::RequestOptions options;
        options.metadata = metadata;
        uploadObjectWithMetadata(std::filesystem::path{}, std::filesystem::path{}, options);
    }

    void uploadObjectWithMetadata(
        const std::filesystem::path&,
        const std::filesystem::path&,
        const vh::storage::s3::RequestOptions& options) const override {
        auto* self = const_cast<CountingS3Controller*>(this);
        ++self->upload_object_with_metadata_calls;
        self->last_metadata = options.metadata;
        self->last_system_headers = options.system_headers;
    }

    void uploadLargeObject(
        const std::filesystem::path&,
        const std::filesystem::path&,
        uintmax_t,
        const std::unordered_map<std::string, std::string>& metadata) const override {
        vh::storage::s3::RequestOptions options;
        options.metadata = metadata;
        uploadLargeObject(std::filesystem::path{}, std::filesystem::path{}, 0, options);
    }

    void uploadLargeObject(
        const std::filesystem::path&,
        const std::filesystem::path&,
        uintmax_t,
        const vh::storage::s3::RequestOptions& options) const override {
        auto* self = const_cast<CountingS3Controller*>(this);
        self->last_metadata = options.metadata;
        self->last_system_headers = options.system_headers;
    }

    void uploadLargeObject(
        const std::filesystem::path&,
        const std::vector<uint8_t>&,
        uintmax_t,
        const vh::storage::s3::RequestOptions& options) const override {
        auto* self = const_cast<CountingS3Controller*>(this);
        self->last_metadata = options.metadata;
        self->last_system_headers = options.system_headers;
    }

    void downloadToBuffer(const std::filesystem::path&, std::vector<uint8_t>& out) const override {
        auto* self = const_cast<CountingS3Controller*>(this);
        self->recordRequest(RequestKind::Get);
        ++self->download_to_buffer_calls;
        if (!self->download_payloads.empty()) {
            out = std::move(self->download_payloads.front());
            self->download_payloads.pop_front();
            self->recordRequest(RequestKind::DownloadBytes, out.size());
            return;
        }
        out = self->download_payload;
        self->recordRequest(RequestKind::DownloadBytes, out.size());
    }

    void uploadBufferWithMetadata(
        const std::filesystem::path& key,
        const std::vector<uint8_t>& buffer,
        const std::unordered_map<std::string, std::string>& metadata) const override {
        vh::storage::s3::RequestOptions options;
        options.metadata = metadata;
        uploadBufferWithMetadata(key, buffer, options);
    }

    void uploadBufferWithMetadata(
        const std::filesystem::path& key,
        const std::vector<uint8_t>& buffer,
        const vh::storage::s3::RequestOptions& options) const override {
        auto* self = const_cast<CountingS3Controller*>(this);
        ++self->upload_buffer_with_metadata_calls;
        self->last_uploaded_key = key;
        self->last_uploaded_buffer_size = buffer.size();
        self->last_metadata = options.metadata;
        self->last_system_headers = options.system_headers;
        self->recordRequest(RequestKind::Put);
        self->recordUploadBytes(buffer.size());
        if (self->upload_buffer_with_metadata_failure)
            throw std::runtime_error("upload failed after upstream PUT attempt");
    }

    void uploadBufferWithMetadataConditional(
        const std::filesystem::path&,
        const std::vector<uint8_t>&,
        const std::unordered_map<std::string, std::string>&,
        const std::optional<std::string>&,
        const std::optional<std::string>&) const override {
        uploadBufferWithMetadataConditional(
            std::filesystem::path{},
            std::vector<uint8_t>{},
            vh::storage::s3::RequestOptions{},
            std::nullopt,
            std::nullopt);
    }

    void uploadBufferWithMetadataConditional(
        const std::filesystem::path&,
        const std::vector<uint8_t>&,
        const vh::storage::s3::RequestOptions& options,
        const std::optional<std::string>&,
        const std::optional<std::string>&) const override {
        auto* self = const_cast<CountingS3Controller*>(this);
        ++self->upload_buffer_conditional_calls;
        self->last_metadata = options.metadata;
        self->last_system_headers = options.system_headers;
        self->recordRequest(RequestKind::Put);
    }

    std::optional<std::unordered_map<std::string, std::string>> getHeadObject(
        const std::filesystem::path&) const override {
        auto* self = const_cast<CountingS3Controller*>(this);
        ++self->head_object_calls;
        self->recordRequest(RequestKind::Head);
        return head_response;
    }

    void deleteObject(const std::filesystem::path& key) const override {
        auto* self = const_cast<CountingS3Controller*>(this);
        ++self->delete_object_calls;
        self->deleted_keys.push_back(key);
        self->recordRequest(RequestKind::Delete);
        if (self->delete_object_not_found)
            throw vh::storage::s3::ObjectNotFound("NoSuchKey");
        if (self->delete_object_failure)
            throw std::runtime_error("delete failed");
    }

    std::u8string listObjects(const std::filesystem::path&) const override {
        auto* self = const_cast<CountingS3Controller*>(this);
        ++self->list_objects_calls;
        self->recordRequest(RequestKind::List);
        return self->list_objects_xml;
    }
};

class ManifestRaceS3Controller final : public vh::storage::s3::Controller {
public:
    mutable std::vector<std::optional<std::unordered_map<std::string, std::string>>> head_responses;
    mutable std::size_t head_index = 0;
    mutable std::vector<int> conditional_failures;
    mutable std::size_t failure_index = 0;
    mutable std::vector<std::optional<std::string>> if_match_values;
    mutable std::vector<std::optional<std::string>> if_none_match_values;
    std::string manifest;

    explicit ManifestRaceS3Controller(std::string manifestBody = {})
        : Controller(dummyApiKey(), "unit-bucket"),
          manifest(std::move(manifestBody)) {}

    void uploadBufferWithMetadataConditional(
        const std::filesystem::path&,
        const std::vector<uint8_t>&,
        const std::unordered_map<std::string, std::string>&,
        const std::optional<std::string>& ifMatch,
        const std::optional<std::string>& ifNoneMatch) const override {
        uploadBufferWithMetadataConditional(
            std::filesystem::path{},
            std::vector<uint8_t>{},
            vh::storage::s3::RequestOptions{},
            ifMatch,
            ifNoneMatch);
    }

    void uploadBufferWithMetadataConditional(
        const std::filesystem::path&,
        const std::vector<uint8_t>&,
        const vh::storage::s3::RequestOptions&,
        const std::optional<std::string>& ifMatch,
        const std::optional<std::string>& ifNoneMatch) const override {
        if_match_values.push_back(ifMatch);
        if_none_match_values.push_back(ifNoneMatch);
        if (failure_index < conditional_failures.size()) {
            const auto code = conditional_failures[failure_index++];
            throw vh::storage::s3::ConditionalRequestFailed(
                "Conditional S3 PUT failed for manifest (HTTP " + std::to_string(code) + ")");
        }
    }

    void downloadToBuffer(const std::filesystem::path&, std::vector<uint8_t>& outBuffer) const override {
        outBuffer.assign(manifest.begin(), manifest.end());
    }

    std::optional<std::unordered_map<std::string, std::string>> getHeadObject(
        const std::filesystem::path&) const override {
        if (head_index < head_responses.size()) return head_responses[head_index++];
        return std::nullopt;
    }
};

class BudgetProbeS3Controller final : public vh::storage::s3::Controller {
public:
    using RequestKind = vh::storage::s3::Controller::RequestKind;

    int set_budget_calls = 0;
    int clear_budget_calls = 0;
    int reset_metrics_calls = 0;

    BudgetProbeS3Controller()
        : Controller(dummyApiKey(), "unit-bucket") {}

    void setRequestBudget(const vh::storage::s3::S3RequestBudget& budget) const override {
        ++const_cast<BudgetProbeS3Controller*>(this)->set_budget_calls;
        Controller::setRequestBudget(budget);
    }

    void clearRequestBudget() const override {
        ++const_cast<BudgetProbeS3Controller*>(this)->clear_budget_calls;
        Controller::clearRequestBudget();
    }

    void resetRequestMetrics() const override {
        ++const_cast<BudgetProbeS3Controller*>(this)->reset_metrics_calls;
        Controller::resetRequestMetrics();
    }

    void count(RequestKind kind, uint64_t amount = 1) const {
        recordRequest(kind, amount);
    }

    void simulateMultipartPutCounts(int parts) const {
        count(RequestKind::Put); // initiate
        for (int i = 0; i < parts; ++i) count(RequestKind::Put);
        count(RequestKind::Put); // complete
    }
};

bool hasDbEnv() {
    return std::getenv("VH_TEST_DB_USER") &&
           std::getenv("VH_TEST_DB_PASS") &&
           std::getenv("VH_TEST_DB_HOST") &&
           std::getenv("VH_TEST_DB_PORT") &&
           std::getenv("VH_TEST_DB_NAME");
}

std::string uniqueSuffix(const std::string& label) {
    const auto ticks = std::chrono::steady_clock::now().time_since_epoch().count();
    return label + "_" + std::to_string(ticks);
}

std::string uniqueBucketName(const std::string& label) {
    auto out = "gw-" + uniqueSuffix(label);
    for (auto& c : out) {
        if (c == '_') c = '-';
    }
    if (out.size() > 63) out.resize(63);
    while (!out.empty() && out.back() == '-') out.pop_back();
    if (out.size() < 3) out = "gw0";
    return out;
}

std::string gatewayAmzNow() {
    const auto now = std::chrono::system_clock::now();
    const auto ts = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    gmtime_r(&ts, &tm);
    std::ostringstream out;
    out << std::put_time(&tm, "%Y%m%dT%H%M%SZ");
    return out.str();
}

std::string gatewayScopeDate(const std::string& amzDate) {
    return amzDate.substr(0, 8);
}

void signGatewayRouteRequest(
    vh::protocols::s3::Router::Request& request,
    const std::string& accessKey,
    const std::string& secretKey) {
    using namespace vh::protocols::s3::sigv4;

    const auto bodyHash = sha256Hex(request.body());
    const auto amzDate = gatewayAmzNow();
    request.set("x-amz-content-sha256", bodyHash);
    request.set("x-amz-date", amzDate);

    VerificationInput input = inputFromRequest(request, request.body());
    ParsedAuth auth{
        .credential = {
            .access_key = accessKey,
            .date = gatewayScopeDate(amzDate),
            .region = "us-east-1",
            .service = "s3"
        },
        .signed_headers = "host;x-amz-content-sha256;x-amz-date",
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

uint32_t ensureS3CostAdminRole(pqxx::work& txn, const vh::rbac::role::Admin& role) {
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

uint32_t ensureS3CostUnprivilegedAdminRole(pqxx::work& txn) {
    return ensureS3CostAdminRole(txn, vh::rbac::role::Admin::None());
}

uint32_t ensureS3CostSuperAdminRole(pqxx::work& txn) {
    return ensureS3CostAdminRole(txn, vh::rbac::role::Admin::SuperAdmin());
}

uint32_t ensureS3CostVaultAdminRole(pqxx::work& txn) {
    return ensureS3CostAdminRole(txn, vh::rbac::role::Admin::VaultAdmin());
}

vh::rbac::role::Admin s3GatewayBudgetManagerRole(const std::optional<std::uint32_t> userId = std::nullopt) {
    auto s3Gateway = vh::rbac::permission::admin::S3Gateway::None();
    s3Gateway.grant(vh::rbac::permission::admin::S3GatewayPermissions::ManageBudgets);
    return vh::rbac::role::Admin::Custom(
        "s3_gateway_budget_manager",
        "Test role that may manage S3 gateway budgets only.",
        vh::rbac::permission::admin::Identities::None(),
        vh::rbac::permission::admin::Vaults::None(),
        vh::rbac::permission::admin::Audits::None(),
        vh::rbac::permission::admin::Settings::None(),
        vh::rbac::permission::admin::Roles::None(),
        vh::rbac::permission::admin::Keys::None(),
        s3Gateway,
        userId);
}

uint32_t insertS3CostHydratableTestUser(pqxx::work& txn, const std::string& name, const std::string& email) {
    const auto userId = txn.exec(
        "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
        pqxx::params{name, email, "hash"}
    ).one_field_ref().as<uint32_t>();
    const auto roleId = ensureS3CostUnprivilegedAdminRole(txn);
    txn.exec(
        "INSERT INTO admin_role_assignments (user_id, role_id) VALUES ($1, $2)",
        pqxx::params{userId, roleId});
    return userId;
}

uint32_t seedS3CostUserForDbTest(const std::string& suffix, const std::string& label) {
    return vh::db::Transactions::exec("S3CostSafetyTest::seedUser", [&](pqxx::work& txn) {
        return insertS3CostHydratableTestUser(
            txn,
            "s3_cost_safety_" + label + "_" + suffix,
            "s3-cost-safety-" + label + "-" + suffix + "@vaulthalla.test");
    });
}

uint32_t seedS3CostSuperAdminUserForDbTest(const std::string& suffix, const std::string& label) {
    return vh::db::Transactions::exec("S3CostSafetyTest::seedSuperAdminUser", [&](pqxx::work& txn) {
        const auto userId = txn.exec(
            "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
            pqxx::params{
                "s3_cost_safety_admin_" + label + "_" + suffix,
                "s3-cost-safety-admin-" + label + "-" + suffix + "@vaulthalla.test",
                "hash"
            }).one_field_ref().as<uint32_t>();
        const auto roleId = ensureS3CostSuperAdminRole(txn);
        txn.exec(
            "INSERT INTO admin_role_assignments (user_id, role_id) VALUES ($1, $2)",
            pqxx::params{userId, roleId});
        return userId;
    });
}

uint32_t seedS3CostVaultAdminUserForDbTest(const std::string& suffix, const std::string& label) {
    return vh::db::Transactions::exec("S3CostSafetyTest::seedVaultAdminUser", [&](pqxx::work& txn) {
        const auto userId = txn.exec(
            "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
            pqxx::params{
                "s3_cost_safety_vault_admin_" + label + "_" + suffix,
                "s3-cost-safety-vault-admin-" + label + "-" + suffix + "@vaulthalla.test",
                "hash"
            }).one_field_ref().as<uint32_t>();
        const auto roleId = ensureS3CostVaultAdminRole(txn);
        txn.exec(
            "INSERT INTO admin_role_assignments (user_id, role_id) VALUES ($1, $2)",
            pqxx::params{userId, roleId});
        return userId;
    });
}

void deleteIncompleteS3CostVaultFixturesForDbTest() {
    vh::db::Transactions::exec("S3CostSafetyTest::deleteIncompleteS3VaultFixtures", [&](pqxx::work& txn) {
        txn.exec(
            "DELETE FROM vault v "
            "WHERE v.type = 's3' "
            "AND ("
            "    NOT EXISTS (SELECT 1 FROM s3 WHERE s3.vault_id = v.id) "
            " OR NOT EXISTS ("
            "        SELECT 1 "
            "        FROM sync sy "
            "        JOIN rsync rs ON rs.sync_id = sy.id "
            "        WHERE sy.vault_id = v.id"
            "    )"
            ")");
    });
}

void clearS3PriceBudgetStateForDbTest() {
    vh::db::Transactions::exec("S3CostSafetyTest::clearPriceBudgetState", [](pqxx::work& txn) {
        txn.exec("DELETE FROM s3_price_budget_alert_state");
        txn.exec("DELETE FROM s3_price_budget_override");
        txn.exec("DELETE FROM operator_notification WHERE type LIKE 'budget.%' OR type LIKE 's3.%'");
        txn.exec("DELETE FROM s3_price_budget_ledger");
        txn.exec("DELETE FROM s3_price_budget_policy");
    });
}

void ensureDbReady() {
    static bool initialized = false;
    if (!initialized) {
        vh::db::Transactions::init();
        vh::db::seed::nuke_and_recreate_schema_public();
        vh::db::Transactions::dbPool_->initPreparedStatements();
        initialized = true;
    }
    clearS3PriceBudgetStateForDbTest();
}

void ensureWritableTestPathRoots() {
    static bool initialized = false;
    if (initialized) return;

    const auto root = std::filesystem::temp_directory_path() / uniqueSuffix("vh_s3_cost_safety_paths");
    std::filesystem::remove_all(root);
    vh::paths::backingPath = root / "backing";
    vh::paths::mountPath = root / "mount";
    std::filesystem::create_directories(vh::paths::backingPath);
    std::filesystem::create_directories(vh::paths::mountPath);
    initialized = true;
}

nlohmann::json gatewayRouteMeter(
    const std::string& meterKey,
    const std::string& rate,
    const std::string& rateUnit) {
    return {
        {"meter_key", meterKey},
        {"meter_type", "request"},
        {"unit", "operation"},
        {"billing_unit", rateUnit},
        {"rounding_rule", "none"},
        {"free_tier_scope", "none"},
        {"rules", nlohmann::json::object()},
        {"tiers", nlohmann::json::array({{
            {"rate", rate},
            {"rate_unit", rateUnit},
            {"tier_start", "0"}
        }})}
    };
}

void seedAwsGatewayRoutePriceCatalog() {
    ensureWritableTestPathRoots();

    const auto profile = nlohmann::json{
        {"schema_version", "1.0"},
        {"kind", "vaulthalla.rating_profile"},
        {"profile_id", "aws-s3/us-east-1/standard"},
        {"catalog_version", "gateway-route-fixture"},
        {"provider", {{"id", "aws-s3"}, {"display_name", "AWS S3"}, {"api_family", "s3-compatible"}}},
        {"scope", {{"region", "us-east-1"}, {"storage_class", "standard"}, {"currency", "USD"}}},
        {"confidence", {{"level", "high"}, {"score", "0.90"}, {"reasons", nlohmann::json::array()}, {"unknowns", nlohmann::json::array()}}},
        {"operation_map", {
            {"PutObject", {{"meter_key", "request_write"}, {"multiplier", "1"}, {"rules", nlohmann::json::object()}}},
            {"UploadPart", {{"meter_key", "request_write"}, {"multiplier", "1"}, {"rules", nlohmann::json::object()}}},
            {"CompleteMultipartUpload", {{"meter_key", "request_write"}, {"multiplier", "1"}, {"rules", nlohmann::json::object()}}},
            {"CopyObject", {{"meter_key", "request_write"}, {"multiplier", "1"}, {"rules", nlohmann::json::object()}}},
            {"GetObject", {{"meter_key", "request_read"}, {"multiplier", "1"}, {"rules", nlohmann::json::object()}}},
            {"HeadObject", {{"meter_key", "request_read"}, {"multiplier", "1"}, {"rules", nlohmann::json::object()}}},
            {"DeleteObject", {{"meter_key", "free_operations"}, {"multiplier", "1"}, {"rules", nlohmann::json::object()}}},
            {"DeleteObjects", {{"meter_key", "free_operations"}, {"multiplier", "1"}, {"rules", nlohmann::json::object()}}},
            {"ListObjectsV2", {{"meter_key", "request_write"}, {"multiplier", "1"}, {"rules", nlohmann::json::object()}}}
        }},
        {"meters", {
            {"request_write", gatewayRouteMeter("request_write", "0.005", "request_1000")},
            {"request_read", gatewayRouteMeter("request_read", "0.0004", "request_1000")},
            {"free_operations", gatewayRouteMeter("free_operations", "0", "operation")}
        }},
        {"storage_rules", nlohmann::json::array()},
        {"provenance", nlohmann::json::object()},
        {"integrity", {{"content_sha256", ""}, {"signature_alg", "Ed25519"}, {"signature_ref", ""}}}
    };
    const auto profileBody = profile.dump();
    const std::string href = "profiles/aws-s3/us-east-1/standard.json";
    const auto manifest = nlohmann::json{
        {"schema_version", "1.0"},
        {"kind", "vaulthalla.price_manifest"},
        {"catalog_version", "gateway-route-fixture"},
        {"generated_at", "2026-05-26T20:00:10Z"},
        {"profile_count", 1},
        {"profiles", nlohmann::json::array({{
            {"profile_id", "aws-s3/us-east-1/standard"},
            {"provider", "aws-s3"},
            {"region", "us-east-1"},
            {"storage_class", "standard"},
            {"currency", "USD"},
            {"href", href},
            {"sha256", vh::storage::s3::curl::sha256Hex(profileBody)},
            {"signature", href + ".sig"},
            {"confidence_level", "high"},
            {"effective_at", "2026-05-26T20:00:10Z"}
        }})},
        {"full_catalog", nlohmann::json::object()},
        {"schemas", nlohmann::json::object()},
        {"integrity", {{"content_sha256", ""}, {"signature_alg", "Ed25519"}, {"signature_ref", "manifest.json.sig"}}}
    };

    const auto cacheRoot = vh::paths::getBackingPath() / "price-cache" / "artifacts";
    std::filesystem::create_directories(cacheRoot / "profiles/aws-s3/us-east-1");
    std::ofstream(cacheRoot / href, std::ios::binary | std::ios::trunc) << profileBody;
    std::ofstream(cacheRoot / "manifest.json", std::ios::binary | std::ios::trunc) << manifest.dump();
}

void ensureSeededRuntimeReady() {
    static bool seeded = false;
    ensureWritableTestPathRoots();
    ensureDbReady();
    if (!seeded) {
        deleteIncompleteS3CostVaultFixturesForDbTest();
        vh::seed::seed_database();
        vh::runtime::Deps::init();
        vh::fs::Filesystem::init(vh::runtime::Deps::get().storageManager);
        seeded = true;
    }
}

uint32_t seedS3VaultForDbTest(const std::string& suffix) {
    return vh::db::Transactions::exec("S3CostSafetyTest::seedS3Vault", [&](pqxx::work& txn) {
        const auto userId = insertS3CostHydratableTestUser(
            txn,
            "s3_cost_safety_user_" + suffix,
            "s3-cost-safety-" + suffix + "@vaulthalla.test");

        return txn.exec(
            "INSERT INTO vault (type, name, owner_id, mount_point, description) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            pqxx::params{
                "s3",
                "S3 Cost Safety " + suffix,
                userId,
                "0123456789ABCDEFGHJKMNPQRSTVWXYZ",
                ""
            }).one_field_ref().as<uint32_t>();
    });
}

vh::storage::s3::pricing::PriceEstimateReport budgetEstimateForDbTest(
    const std::string& cost,
    const bool verified = true,
    const bool stale = false) {
    vh::storage::s3::pricing::PriceEstimateReport report;
    report.available = true;
    report.supported = true;
    report.stale = stale;
    report.estimated_cost = cost;
    report.currency = "USD";
    report.price_profile_id = "aws-s3/us-east-1/standard";
    report.catalog_version = "test";
    report.catalog_source = "test";
    report.catalog_verified = verified;
    report.catalog_age_seconds = 60;
    report.confidence_level = "high";
    report.estimate_mode = "budget_conservative";
    report.free_tier_policy = "ignore_account_wide_free_tiers";
    report.free_tiers_applied = false;
    report.breakdown = nlohmann::json::array();
    return report;
}

std::uint32_t ownerForVaultDbTest(const std::uint32_t vaultId) {
    return vh::db::Transactions::exec("S3CostSafetyTest::ownerForVault", [&](pqxx::work& txn) {
        return txn.exec(
            "SELECT owner_id FROM vault WHERE id = $1",
            pqxx::params{vaultId}).one_field_ref().as<std::uint32_t>();
    });
}

void attachS3ProviderForDbTest(const std::uint32_t vaultId, const std::string& provider) {
    vh::db::Transactions::exec("S3CostSafetyTest::attachS3Provider", [&](pqxx::work& txn) {
        const auto ownerId = txn.exec(
            "SELECT owner_id FROM vault WHERE id = $1",
            pqxx::params{vaultId}).one_field_ref().as<std::uint32_t>();
        const auto apiKeyId = txn.exec(
            "INSERT INTO api_keys "
            "(user_id, name, provider, access_key, encrypted_secret_access_key, iv, region, endpoint) "
            "VALUES ($1, $2, $3, $4, decode('00','hex'), decode('00','hex'), $5, $6) RETURNING id",
            pqxx::params{
                ownerId,
                "budget-provider-" + std::to_string(vaultId),
                provider,
                "access-" + std::to_string(vaultId),
                "us-east-1",
                "https://s3.example.com"
            }).one_field_ref().as<std::uint32_t>();
        txn.exec(
            "INSERT INTO s3 (vault_id, api_key_id, bucket) VALUES ($1, $2, $3) "
            "ON CONFLICT (vault_id) DO UPDATE SET api_key_id = EXCLUDED.api_key_id, bucket = EXCLUDED.bucket",
            pqxx::params{vaultId, apiKeyId, "bucket-" + std::to_string(vaultId)});
    });
}

vh::storage::s3::pricing::PriceBudgetPolicy saveVaultBudgetPolicyForDbTest(
    const std::uint32_t vaultId,
    std::optional<std::string> providerKey,
    const vh::storage::s3::pricing::PriceBudgetMode mode,
    const std::optional<std::string>& monthlyLimit,
    const bool requireVerified = true) {
    vh::storage::s3::pricing::PriceBudgetPolicy policy;
    policy.scope = vh::storage::s3::pricing::PriceBudgetScope::Vault;
    policy.vault_id = vaultId;
    policy.provider_key = std::move(providerKey);
    policy.mode = mode;
    policy.currency = "USD";
    policy.max_monthly_cost = monthlyLimit;
    policy.require_verified_catalog = requireVerified;
    policy.allow_stale_catalog = false;
    return vh::storage::s3::pricing::PriceBudgetService{}.upsertPolicy(std::move(policy));
}

uint32_t seedGatewayCredentialForDbTest(const uint32_t userId, const std::string& suffix) {
    vh::db::query::s3::GatewayCredential credential;
    credential.user_id = userId;
    credential.principal_user_id = userId;
    credential.created_by = userId;
    credential.name = "gateway-budget-" + suffix;
    credential.access_key = "VHTESTBUDGET" + suffix.substr(0, std::min<std::size_t>(suffix.size(), 32));
    std::ranges::replace(credential.access_key, '-', '_');
    credential.encrypted_secret_access_key = {1, 2, 3};
    credential.iv = {4, 5, 6};
    credential.enabled = true;
    credential.scope_mode = "user_access";
    return vh::db::query::s3::Gateway::createCredential(credential);
}

uint32_t s3CostVaultRoleIdByName(const std::string& roleName) {
    return vh::db::Transactions::exec("S3CostSafetyTest::vaultRoleIdByName", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT id FROM vault_role WHERE name = $1 LIMIT 1",
            pqxx::params{roleName});
        if (!res.empty()) return res.one_field_ref().as<uint32_t>();

        const auto role = [&]() {
            if (roleName == "implicit_deny") return vh::rbac::role::Vault::ImplicitDeny();
            if (roleName == "reader") return vh::rbac::role::Vault::Reader();
            if (roleName == "contributor") return vh::rbac::role::Vault::Contributor();
            if (roleName == "manager") return vh::rbac::role::Vault::Manager();
            throw std::runtime_error("vault role not found: " + roleName);
        }();
        return txn.exec(
            R"SQL(
                INSERT INTO vault_role (
                    name,
                    description,
                    files_permissions,
                    directories_permissions,
                    sync_permissions,
                    roles_permissions
                )
                VALUES ($1, $2, $3::bit(32), $4::bit(32), $5::bit(32), $6::bit(16))
                ON CONFLICT (name) DO UPDATE SET
                    description = EXCLUDED.description,
                    files_permissions = EXCLUDED.files_permissions,
                    directories_permissions = EXCLUDED.directories_permissions,
                    sync_permissions = EXCLUDED.sync_permissions,
                    roles_permissions = EXCLUDED.roles_permissions
                RETURNING id
            )SQL",
            pqxx::params{
                role.name,
                role.description,
                role.fs.files.toBitString(),
                role.fs.directories.toBitString(),
                role.sync.toBitString(),
                role.roles.toBitString()
            }).one_field_ref().as<uint32_t>();
    });
}

std::optional<vh::db::query::s3::GatewayCredential> gatewayCredentialByIdForDbTest(const uint32_t credentialId) {
    const auto credentials = vh::db::query::s3::Gateway::listCredentialsAdmin(true);
    const auto it = std::ranges::find_if(credentials, [&](const auto& credential) {
        return credential.id == credentialId;
    });
    if (it == credentials.end()) return std::nullopt;
    return *it;
}

vh::storage::s3::pricing::PriceBudgetPolicy saveGatewayBudgetPolicyForDbTest(
    const vh::storage::s3::pricing::PriceBudgetScope scope,
    const uint32_t credentialId,
    const std::optional<uint32_t> vaultId,
    const vh::storage::s3::pricing::PriceBudgetMode mode,
    const std::string& monthlyLimit,
    const bool requireVerified = true) {
    vh::storage::s3::pricing::PriceBudgetPolicy policy;
    policy.scope = scope;
    policy.gateway_credential_id = credentialId;
    policy.vault_id = vaultId;
    policy.mode = mode;
    policy.currency = "USD";
    policy.max_monthly_cost = monthlyLimit;
    policy.require_verified_catalog = requireVerified;
    policy.allow_stale_catalog = false;
    return vh::storage::s3::pricing::PriceBudgetService{}.upsertPolicy(std::move(policy));
}

vh::storage::s3::pricing::PriceBudgetPolicy saveGenericBudgetPolicyForDbTest(
    const vh::storage::s3::pricing::PriceBudgetScope scope,
    std::optional<std::string> providerKey,
    std::optional<uint32_t> vaultId,
    const vh::storage::s3::pricing::PriceBudgetMode mode,
    const std::optional<std::string>& monthlyLimit,
    const std::optional<std::string>& dailyLimit = std::nullopt,
    const std::optional<std::string>& runLimit = std::nullopt) {
    vh::storage::s3::pricing::PriceBudgetPolicy policy;
    policy.scope = scope;
    policy.provider_key = std::move(providerKey);
    policy.vault_id = vaultId;
    policy.mode = mode;
    policy.currency = "USD";
    policy.max_run_cost = runLimit;
    policy.max_daily_cost = dailyLimit;
    policy.max_monthly_cost = monthlyLimit;
    policy.require_verified_catalog = false;
    policy.allow_stale_catalog = false;
    return vh::storage::s3::pricing::PriceBudgetService{}.upsertPolicy(std::move(policy));
}

std::uint32_t countPriceBudgetLedgerForRunDbTest(const std::string& runUuid) {
    return vh::db::Transactions::exec("S3CostSafetyTest::countPriceBudgetLedgerForRun", [&](pqxx::work& txn) {
        return txn.exec(
            "SELECT COUNT(*) AS c FROM s3_price_budget_ledger WHERE run_uuid = $1",
            pqxx::params{runUuid}).one_row_ref()["c"].as<std::uint32_t>();
    });
}

std::uint32_t countGatewaySyncOriginForDbTest(
    const std::uint32_t vaultId,
    const std::string& objectKey,
    const std::string& operation) {
    return vh::db::Transactions::exec("S3CostSafetyTest::countGatewaySyncOrigin", [&](pqxx::work& txn) {
        return txn.exec(
            "SELECT COUNT(*) AS c FROM s3_gateway_sync_origin "
            "WHERE vault_id = $1 AND object_key = $2 AND operation = $3",
            pqxx::params{vaultId, objectKey, operation}).one_row_ref()["c"].as<std::uint32_t>();
    });
}

std::shared_ptr<vh::storage::CloudEngine> makeDbBackedCloudEngine(
    const uint32_t vaultId,
    const std::shared_ptr<vh::storage::s3::Controller>& controller) {
    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = vaultId;
    vault->owner_id = 1;
    vault->type = vh::vault::model::VaultType::S3;
    vault->name = "s3-cost-safety-db";
    vault->mount_point = "s3-cost-safety-db";

    auto policy = std::make_shared<vh::sync::model::RemotePolicy>();
    policy->vault_id = vaultId;

    auto engine = std::make_shared<vh::storage::CloudEngine>();
    engine->vault = vault;
    engine->sync = policy;
    engine->setS3ControllerForTesting(controller);
    return engine;
}

uint32_t seedDryRunS3VaultForDbTest(
    const std::string& suffix,
    const std::shared_ptr<CountingS3Controller>& controller) {
    ensureSeededRuntimeReady();
    deleteIncompleteS3CostVaultFixturesForDbTest();

    const auto owner = vh::identities::manager().userByName("admin");
    if (!owner) throw std::runtime_error("admin user not available for dry-run test");

    auto key = std::make_shared<vh::vault::model::APIKey>(
        owner->id,
        "dry-run-key-" + suffix,
        vh::vault::model::S3Provider::AWS,
        "ABCDEFGHIJKLMNOPQRST",
        "ABCDEFGHIJKLMNOPQRSTABCDEFGHIJKLMNOPQRST",
        "us-east-1",
        "https://s3.example.com");
    vh::runtime::Deps::get().apiKeyManager->addAPIKey(key);

    auto vault = std::make_shared<vh::vault::model::S3Vault>(
        "dry-run-vault-" + suffix,
        key->id,
        "dry-run-bucket-" + suffix);
    vault->owner_id = owner->id;
    vault->description = "dry-run auth test";
    vault->mount_point = vh::crypto::id::Generator({.namespace_token = vault->name}).generate();

    auto policy = std::make_shared<vh::sync::model::RemotePolicy>();
    const auto vaultId = vh::db::query::vault::Vault::upsertVault(vault, policy);

    vh::runtime::Deps::get().storageManager->initStorageEngines();
    const auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(controller);
    return vaultId;
}

uint32_t seedLocalGatewayRouteVaultForDbTest(const std::string& suffix) {
    ensureSeededRuntimeReady();

    const auto owner = vh::identities::manager().userByName("admin");
    if (!owner) throw std::runtime_error("admin user not available for local gateway route budget test");

    const auto vaultId = vh::db::Transactions::exec("S3CostSafetyTest::seedLocalGatewayRouteVault", [&](pqxx::work& txn) {
        const auto mountPoint = vh::crypto::id::Generator({.namespace_token = "local-gateway-" + suffix}).generate();
        const auto seededVaultId = txn.exec(
            "INSERT INTO vault (type, name, owner_id, mount_point, description) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            pqxx::params{
                "local",
                "Local Gateway Route Budget " + suffix,
                owner->id,
                mountPoint,
                "local gateway route budget test"
            }).one_field_ref().as<uint32_t>();
        txn.exec(
            "WITH ins AS (INSERT INTO sync (vault_id, interval) VALUES ($1, 300) RETURNING id) "
            "INSERT INTO fsync (sync_id, conflict_policy) SELECT id, 'keep_both' FROM ins",
            pqxx::params{seededVaultId});
        return seededVaultId;
    });

    vh::runtime::Deps::get().storageManager->initStorageEngines();
    return vaultId;
}

std::shared_ptr<vh::identities::User> dryRunActor(
    const uint32_t id,
    vh::rbac::role::Admin role) {
    vh::identities::UserState state;
    state.name = "dry-run-actor-" + std::to_string(id);
    state.roles.admin = std::make_shared<vh::rbac::role::Admin>(std::move(role));
    return vh::identities::User::detached(id, std::move(state));
}

std::shared_ptr<vh::protocols::ws::Session> superAdminWsSession() {
    auto session = std::make_shared<vh::protocols::ws::Session>(
        std::make_shared<vh::protocols::ws::Router>());
    vh::identities::UserState state;
    state.name = "admin";
    state.roles.admin = std::make_shared<vh::rbac::role::Admin>(vh::rbac::role::Admin::SuperAdmin(1));
    session->user = vh::identities::User::detached(1, std::move(state));
    return session;
}

std::shared_ptr<vh::protocols::ws::Session> wsSessionForUser(
    const uint32_t userId,
    vh::rbac::role::Admin role = vh::rbac::role::Admin::None()) {
    auto session = std::make_shared<vh::protocols::ws::Session>(
        std::make_shared<vh::protocols::ws::Router>());
    session->user = dryRunActor(userId, std::move(role));
    return session;
}

std::shared_ptr<vh::protocols::shell::Router> s3GatewayShellRouterForDbTest() {
    ensureWritableTestPathRoots();
    if (!vh::runtime::Deps::get().shellUsageManager)
        vh::runtime::Deps::get().shellUsageManager = std::make_shared<vh::protocols::shell::UsageManager>();
    auto router = std::make_shared<vh::protocols::shell::Router>();
    vh::protocols::shell::commands::registerS3GatewayCommands(router);
    return router;
}

vh::protocols::shell::CommandResult runDryRunCommand(
    const uint32_t vaultId,
    const std::shared_ptr<vh::identities::User>& user,
    const bool refreshIndex = false) {
    vh::protocols::shell::CommandCall call;
    call.name = "vault";
    call.user = user;
    call.positionals = {"dry-run", std::to_string(vaultId)};
    if (refreshIndex) call.options.push_back({"refresh-index", std::nullopt});
    return vh::protocols::shell::commands::vault::handle_sync(call);
}

uint32_t seedLegacyRsyncPolicyForDbTest(
    const std::string& suffix,
    const std::optional<uint64_t> customGetBudget = std::nullopt) {
    const auto vaultId = seedS3VaultForDbTest(suffix);
    vh::db::Transactions::exec("S3CostSafetyTest::seedLegacyRsyncPolicy", [&](pqxx::work& txn) {
        const auto syncId = txn.exec(
            "INSERT INTO sync (vault_id) VALUES ($1) RETURNING id",
            pqxx::params{vaultId}).one_field_ref().as<uint32_t>();

        if (customGetBudget) {
            txn.exec(
                "INSERT INTO rsync (sync_id, s3_budget_get_requests) VALUES ($1, $2)",
                pqxx::params{syncId, *customGetBudget});
        } else {
            txn.exec("INSERT INTO rsync (sync_id) VALUES ($1)", pqxx::params{syncId});
        }
    });
    return vaultId;
}

void applyS3BudgetBackfillMigrationForDbTest() {
    vh::db::Transactions::exec("S3CostSafetyTest::applyS3BudgetBackfillMigration", [&](pqxx::work& txn) {
        const auto migration = vh::paths::getPsqlSchemasPath() / "088_backfill_s3_budget_defaults.sql";
        txn.exec(vh::db::seed::readFileToString(migration));
    });
}

std::shared_ptr<vh::sync::model::RemotePolicy> loadRemotePolicyForDbTest(const uint32_t vaultId) {
    return vh::db::Transactions::exec("S3CostSafetyTest::loadRemotePolicy", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT rs.*, s.* "
            "FROM rsync rs JOIN sync s ON s.id = rs.sync_id "
            "WHERE s.vault_id = $1",
            pqxx::params{vaultId});
        return std::make_shared<vh::sync::model::RemotePolicy>(res.one_row_ref());
    });
}

class ScopedPathRoots {
public:
    explicit ScopedPathRoots(std::filesystem::path root)
        : root_(std::move(root)),
          oldBackingPath_(vh::paths::backingPath),
          oldMountPath_(vh::paths::mountPath) {
        std::filesystem::remove_all(root_);
        vh::paths::backingPath = root_ / "backing";
        vh::paths::mountPath = root_ / "mount";
        std::filesystem::create_directories(vh::paths::backingPath);
        std::filesystem::create_directories(vh::paths::mountPath);
    }

    ~ScopedPathRoots() {
        vh::paths::backingPath = oldBackingPath_;
        vh::paths::mountPath = oldMountPath_;
        std::filesystem::remove_all(root_);
    }

private:
    std::filesystem::path root_;
    std::filesystem::path oldBackingPath_;
    std::filesystem::path oldMountPath_;
};

std::shared_ptr<vh::storage::CloudEngine> makePlanningEngine() {
    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 77;
    vault->owner_id = 88;
    vault->quota = 1024 * 1024 * 1024;
    vault->name = "s3-cost-safety";
    vault->mount_point = "s3-cost-safety";

    auto policy = std::make_shared<vh::sync::model::RemotePolicy>();
    policy->vault_id = vault->id;

    auto engine = std::make_shared<vh::storage::CloudEngine>();
    engine->vault = vault;
    engine->sync = policy;
    return engine;
}

std::shared_ptr<vh::fs::model::File> remoteFile(
    const std::string& key,
    const std::optional<std::string>& storageClass = std::nullopt) {
    auto file = std::make_shared<vh::fs::model::File>(key, 42, std::time(nullptr));
    if (storageClass) file->remote_storage_class = *storageClass;
    return file;
}

void configureS3GatewayRouteBudgetConfig() {
    auto cfg = vh::config::Registry::get();
    cfg.s3_gateway.require_sigv4 = true;
    cfg.s3_gateway.allow_path_style = true;
    cfg.s3_gateway.allow_virtual_hosted_style = false;
    cfg.pricing.enabled = true;
    cfg.pricing.storage_rates_api.remote_refresh_enabled = false;
    cfg.pricing.storage_rates_api.signature_warning_only = true;
    cfg.pricing.storage_rates_api.signature_public_key_path.reset();
    vh::config::Registry::set(cfg);
}

struct GatewayRouteBudgetFixture {
    uint32_t vault_id{0};
    std::string bucket_name;
    std::shared_ptr<CountingS3Controller> controller;
    vh::protocols::s3::GatewaySecret secret;
};

GatewayRouteBudgetFixture setupGatewayRouteBudgetFixture(
    const std::string& label,
    const vh::storage::s3::pricing::PriceBudgetScope scope,
    const std::string& monthlyLimit,
    const vh::storage::s3::pricing::PriceBudgetMode mode = vh::storage::s3::pricing::PriceBudgetMode::Enforce,
    const bool enforceBudgetForLocalRequests = false) {
    ensureSeededRuntimeReady();
    seedAwsGatewayRoutePriceCatalog();

    auto fake = std::make_shared<CountingS3Controller>();
    const auto suffix = uniqueSuffix(label);
    const auto vaultId = seedDryRunS3VaultForDbTest(suffix, fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);
    std::static_pointer_cast<vh::vault::model::S3Vault>(engine->vault)->encrypt_upstream = false;

    const auto owner = vh::identities::manager().userByName("admin");
    if (!owner) throw std::runtime_error("admin user not available for S3 gateway route budget test");

    const auto bucketName = uniqueBucketName(label);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .api_exclusive = true,
        .mode = "remote_cache",
        .created_by = owner->id
    });

    const vh::protocols::s3::CredentialManager manager;
    auto secret = manager.createCredential({
        .created_by = owner->id,
        .principal_user_id = owner->id,
        .name = "route-budget-" + suffix,
        .scope_mode = "user_access",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .vault_scopes = {},
        .enforce_budget_for_local_requests = enforceBudgetForLocalRequests
    });

    saveGatewayBudgetPolicyForDbTest(
        scope,
        secret.credential.id,
        scope == vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault
            ? std::make_optional(vaultId)
            : std::optional<uint32_t>{},
        mode,
        monthlyLimit,
        false);

    return {
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .controller = fake,
        .secret = std::move(secret)
    };
}

GatewayRouteBudgetFixture setupLocalGatewayRouteBudgetFixture(
    const std::string& label,
    const vh::storage::s3::pricing::PriceBudgetScope scope,
    const std::string& monthlyLimit,
    const vh::storage::s3::pricing::PriceBudgetMode mode = vh::storage::s3::pricing::PriceBudgetMode::Enforce,
    const bool enforceBudgetForLocalRequests = false) {
    ensureSeededRuntimeReady();

    const auto suffix = uniqueSuffix(label);
    const auto vaultId = seedLocalGatewayRouteVaultForDbTest(suffix);
    const auto owner = vh::identities::manager().userByName("admin");
    if (!owner) throw std::runtime_error("admin user not available for local S3 gateway route budget test");

    const auto bucketName = uniqueBucketName(label);
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .api_exclusive = true,
        .mode = "local",
        .created_by = owner->id
    });

    const vh::protocols::s3::CredentialManager manager;
    auto secret = manager.createCredential({
        .created_by = owner->id,
        .principal_user_id = owner->id,
        .name = "route-local-budget-" + suffix,
        .scope_mode = "user_access",
        .description = std::nullopt,
        .expires_at = std::nullopt,
        .vault_scopes = {},
        .enforce_budget_for_local_requests = enforceBudgetForLocalRequests
    });

    saveGatewayBudgetPolicyForDbTest(
        scope,
        secret.credential.id,
        scope == vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault
            ? std::make_optional(vaultId)
            : std::optional<uint32_t>{},
        mode,
        monthlyLimit,
        false);

    return {
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .controller = nullptr,
        .secret = std::move(secret)
    };
}

void setGatewayRouteRequestBudget(
    const GatewayRouteBudgetFixture& fixture,
    const std::function<void(vh::storage::s3::S3RequestBudget&)>& mutate) {
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(fixture.vault_id));
    auto policy = engine->remote_policy();
    ASSERT_TRUE(policy);
    policy->s3_request_budget = {};
    mutate(policy->s3_request_budget);
}

vh::protocols::s3::Router::Request signedGatewayRouteRequest(
    const http::verb method,
    const std::string& target,
    const vh::protocols::s3::GatewaySecret& secret,
    const std::string& body = {}) {
    vh::protocols::s3::Router::Request request{method, target, 11};
    request.set(http::field::host, "localhost:39000");
    request.body() = body;
    request.prepare_payload();
    signGatewayRouteRequest(request, secret.credential.access_key, secret.secret_access_key);
    return request;
}

std::string textBetween(const std::string& text, const std::string& open, const std::string& close) {
    const auto start = text.find(open);
    if (start == std::string::npos) return {};
    const auto valueStart = start + open.size();
    const auto end = text.find(close, valueStart);
    if (end == std::string::npos) return {};
    return text.substr(valueStart, end - valueStart);
}

void expectGatewayLedgerCommitted(
    const GatewayRouteBudgetFixture& fixture,
    const std::string& operation,
    const std::string& objectKey,
    const std::optional<bool> synthetic = std::nullopt,
    const std::optional<std::string>& usageSource = std::nullopt) {
    const auto ledger = vh::storage::s3::pricing::PriceBudgetService{}.listLedger(
        20,
        fixture.vault_id,
        fixture.secret.credential.id);
    const auto it = std::ranges::find_if(ledger, [&](const auto& entry) {
        return entry.operation && *entry.operation == operation &&
            entry.object_key && *entry.object_key == objectKey;
    });
    ASSERT_NE(it, ledger.end());
    EXPECT_EQ(fixture.vault_id, it->vault_id);
    ASSERT_TRUE(it->gateway_credential_id);
    EXPECT_EQ(fixture.secret.credential.id, *it->gateway_credential_id);
    EXPECT_TRUE(it->request_uuid);
    EXPECT_TRUE(it->estimated_cost);
    EXPECT_EQ("committed", it->status);
    ASSERT_TRUE(it->committed_cost);
    if (synthetic) {
        EXPECT_EQ(*synthetic, it->synthetic);
    }
    if (usageSource) {
        ASSERT_TRUE(it->usage_source);
        EXPECT_EQ(*usageSource, *it->usage_source);
    }
}

void expectGatewayLedgerAbsent(
    const GatewayRouteBudgetFixture& fixture,
    const std::string& operation,
    const std::string& objectKey) {
    const auto ledger = vh::storage::s3::pricing::PriceBudgetService{}.listLedger(
        20,
        fixture.vault_id,
        fixture.secret.credential.id);
    const auto it = std::ranges::find_if(ledger, [&](const auto& entry) {
        return entry.operation && *entry.operation == operation &&
            entry.object_key && *entry.object_key == objectKey &&
            entry.status != "released" &&
            entry.status != "expired";
    });
    EXPECT_EQ(it, ledger.end());
}

} // namespace

TEST(S3CostSafetyTest, ScopedS3RequestUsageCaptureDoesNotCrossContaminateConcurrentThreads) {
    std::barrier start(2);

    auto worker = [&](const std::size_t payloadSize) {
        vh::storage::CloudEngine engine;
        CountingS3Controller controller;
        controller.download_payload.assign(payloadSize, static_cast<uint8_t>('x'));
        start.arrive_and_wait();

        vh::storage::ScopedS3RequestUsageCapture capture(engine);
        std::vector<uint8_t> out;
        controller.downloadToBuffer("object.bin", out);
        return capture.usage();
    };

    auto first = std::async(std::launch::async, worker, 3);
    auto second = std::async(std::launch::async, worker, 11);

    const auto firstUsage = first.get();
    const auto secondUsage = second.get();

    EXPECT_EQ(1, firstUsage.get_requests);
    EXPECT_EQ(3, firstUsage.downloaded_bytes);
    EXPECT_TRUE(firstUsage.touched_upstream);
    EXPECT_EQ(1, secondUsage.get_requests);
    EXPECT_EQ(11, secondUsage.downloaded_bytes);
    EXPECT_TRUE(secondUsage.touched_upstream);
}

TEST(S3CostSafetyTest, PolicyIntervalsDefaultAndClampToNonZero) {
    vh::sync::model::RemotePolicy remote;
    EXPECT_EQ(300, remote.interval.count());
    EXPECT_TRUE(remote.enabled);
    EXPECT_EQ(
        "balanced",
        vh::sync::model::s3BudgetPresetName(remote.s3_request_budget));
    EXPECT_TRUE(remote.s3_request_budget.max_list_requests.has_value());
    ASSERT_TRUE(remote.max_remote_index_age);
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(24)).count(), remote.max_remote_index_age->count());
    EXPECT_EQ(std::chrono::duration_cast<std::chrono::seconds>(std::chrono::hours(2)).count(), vh::sync::model::remoteIndexAgeFromString("2h")->count());
    EXPECT_FALSE(vh::sync::model::remoteIndexAgeFromString("unlimited").has_value());

    EXPECT_EQ(300, vh::sync::model::Policy::clampInterval(std::chrono::seconds(0)).count());
    EXPECT_EQ(300, vh::sync::model::Policy::clampInterval(std::chrono::seconds(-5)).count());
    EXPECT_EQ(15, vh::sync::model::Policy::clampInterval(std::chrono::seconds(15)).count());
    EXPECT_EQ(300, vh::db::encoding::parseSyncInterval("").count());
}

TEST(S3CostSafetyTest, EngineFreeSpaceSaturatesFiniteQuota) {
    ScopedPathRoots paths(std::filesystem::temp_directory_path() / "vh_engine_quota_finite");

    auto vault = std::make_shared<vh::vault::model::Vault>();
    vault->id = 1001;
    vault->name = "quota-test";
    vault->mount_point = "quota-test";
    vault->quota = vh::storage::Engine::MIN_FREE_SPACE + 1024;

    vh::storage::Engine engine;
    engine.vault = vault;
    engine.paths = std::make_shared<vh::fs::model::Path>("quota-test", "quota-test");
    std::filesystem::create_directories(engine.paths->backingVaultRoot);
    std::filesystem::create_directories(engine.paths->cacheRoot);

    EXPECT_EQ(1024u, engine.freeSpace());

    std::ofstream(engine.paths->backingVaultRoot / "used.bin", std::ios::binary) << std::string(200, 'x');
    EXPECT_EQ(824u, engine.freeSpace());

    vault->quota = vh::storage::Engine::MIN_FREE_SPACE - 1;
    EXPECT_EQ(0u, engine.freeSpace());
}

TEST(S3CostSafetyTest, EngineFreeSpaceTreatsZeroQuotaAsUnlimitedWithoutUnderflow) {
    ScopedPathRoots paths(std::filesystem::temp_directory_path() / "vh_engine_quota_unlimited");

    auto vault = std::make_shared<vh::vault::model::Vault>();
    vault->id = 1002;
    vault->name = "quota-unlimited-test";
    vault->mount_point = "quota-unlimited-test";
    vault->quota = 0;

    vh::storage::Engine engine;
    engine.vault = vault;
    engine.paths = std::make_shared<vh::fs::model::Path>("quota-unlimited-test", "quota-unlimited-test");
    std::filesystem::create_directories(engine.paths->backingVaultRoot);
    std::filesystem::create_directories(engine.paths->cacheRoot);

    // Free space moves while the test runs (a shared CI disk): the engine's reading must fall between the readings
    // taken just before and just after it, less the reserve, never an underflowed huge value.
    const auto usable = [](const std::uintmax_t free) {
        return free > vh::storage::Engine::MIN_FREE_SPACE ? free - vh::storage::Engine::MIN_FREE_SPACE : 0;
    };
    std::error_code ec;
    const auto before = std::filesystem::space(engine.paths->backingRoot, ec).available;
    ASSERT_FALSE(ec);
    const auto reported = engine.freeSpace();
    const auto after = std::filesystem::space(engine.paths->backingRoot, ec).available;
    ASSERT_FALSE(ec);

    EXPECT_GE(reported, usable(std::min(before, after)));
    EXPECT_LE(reported, usable(std::max(before, after)));
}

TEST(S3CostSafetyTest, UnlimitedBudgetPolicyPrintsLegacyWarning) {
    auto remote = std::make_shared<vh::sync::model::RemotePolicy>();
    remote->s3_request_budget = vh::sync::model::s3RequestBudgetForPreset(
        vh::sync::model::S3BudgetPreset::Unlimited);

    const auto text = vh::sync::model::to_string(remote);
    EXPECT_NE(std::string::npos, text.find("unlimited/legacy budget"));
    EXPECT_NE(std::string::npos, text.find("--s3-budget-preset balanced"));
}

TEST(S3CostSafetyTest, MigrationBackfillsAllNullLegacyS3BudgetsToBalancedPreset) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 budget migration test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedLegacyRsyncPolicyForDbTest(uniqueSuffix("budget_backfill"));
    applyS3BudgetBackfillMigrationForDbTest();

    const auto policy = loadRemotePolicyForDbTest(vaultId);
    const auto balanced = vh::sync::model::s3RequestBudgetForPreset(vh::sync::model::S3BudgetPreset::Balanced);
    EXPECT_EQ(balanced.max_list_requests, policy->s3_request_budget.max_list_requests);
    EXPECT_EQ(balanced.max_head_requests, policy->s3_request_budget.max_head_requests);
    EXPECT_EQ(balanced.max_get_requests, policy->s3_request_budget.max_get_requests);
    EXPECT_EQ(balanced.max_put_requests, policy->s3_request_budget.max_put_requests);
    EXPECT_EQ(balanced.max_copy_requests, policy->s3_request_budget.max_copy_requests);
    EXPECT_EQ(balanced.max_delete_requests, policy->s3_request_budget.max_delete_requests);
    EXPECT_EQ(balanced.max_downloaded_bytes, policy->s3_request_budget.max_downloaded_bytes);
    EXPECT_EQ("balanced", vh::sync::model::s3BudgetPresetName(policy->s3_request_budget));
    EXPECT_EQ(100u, policy->s3_request_budget.max_list_requests.value_or(0));

    const auto text = vh::sync::model::to_string(policy);
    EXPECT_NE(std::string::npos, text.find("Preset: balanced"));
    EXPECT_EQ(std::string::npos, text.find("unlimited/legacy budget"));
}

TEST(S3CostSafetyTest, MigrationDoesNotOverwriteCustomS3BudgetRows) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 budget migration test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedLegacyRsyncPolicyForDbTest(uniqueSuffix("budget_custom"), 42);
    applyS3BudgetBackfillMigrationForDbTest();

    const auto policy = loadRemotePolicyForDbTest(vaultId);
    EXPECT_FALSE(policy->s3_request_budget.max_list_requests.has_value());
    ASSERT_TRUE(policy->s3_request_budget.max_get_requests.has_value());
    EXPECT_EQ(42u, *policy->s3_request_budget.max_get_requests);
    EXPECT_FALSE(policy->s3_request_budget.max_head_requests.has_value());
    EXPECT_FALSE(policy->s3_request_budget.max_put_requests.has_value());
    EXPECT_FALSE(policy->s3_request_budget.max_copy_requests.has_value());
    EXPECT_FALSE(policy->s3_request_budget.max_delete_requests.has_value());
    EXPECT_FALSE(policy->s3_request_budget.max_downloaded_bytes.has_value());
    EXPECT_EQ("custom", vh::sync::model::s3BudgetPresetName(policy->s3_request_budget));
}

TEST(S3CostSafetyTest, WsVaultGetAndUpdateRoundTripS3SyncBudget) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed websocket vault update test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("ws_budget"), fake);
    const auto session = superAdminWsSession();

    auto before = vh::protocols::ws::handler::Vaults::get({{"id", vaultId}}, session);
    ASSERT_TRUE(before.contains("vault"));
    ASSERT_TRUE(before["vault"].contains("sync"));
    ASSERT_TRUE(before["vault"]["sync"].contains("s3_request_budget"));

    auto payload = before["vault"];
    payload["name"] = "ws-budget-updated-" + std::to_string(vaultId);
    payload["sync"]["enabled"] = true;
    payload["sync"]["interval"] = 120;
    payload["sync"]["strategy"] = "sync";
    payload["sync"]["conflict_policy"] = "keep_newest";
    payload["sync"]["max_remote_index_age_seconds"] = 60;
    payload["sync"]["s3_request_budget"] = {
        {"list_requests", nullptr},
        {"head_requests", 12},
        {"get_requests", 42},
        {"put_requests", 13},
        {"copy_requests", 14},
        {"delete_requests", 15},
        {"downloaded_bytes", nullptr}
    };

    const auto update = vh::protocols::ws::handler::Vaults::update(payload, session);
    ASSERT_TRUE(update.contains("vault"));
    EXPECT_EQ(payload["name"].get<std::string>(), update["vault"]["name"].get<std::string>());

    const auto persisted = loadRemotePolicyForDbTest(vaultId);
    EXPECT_FALSE(persisted->s3_request_budget.max_list_requests.has_value());
    ASSERT_TRUE(persisted->s3_request_budget.max_get_requests.has_value());
    EXPECT_EQ(42u, *persisted->s3_request_budget.max_get_requests);
    EXPECT_FALSE(persisted->s3_request_budget.max_downloaded_bytes.has_value());
    EXPECT_EQ(120, persisted->interval.count());
    EXPECT_EQ(vh::sync::model::RemotePolicy::Strategy::Sync, persisted->strategy);
    EXPECT_EQ(vh::sync::model::RemotePolicy::ConflictPolicy::KeepNewest, persisted->conflict_policy);
    ASSERT_TRUE(persisted->max_remote_index_age);
    EXPECT_EQ(60, persisted->max_remote_index_age->count());

    const auto after = vh::protocols::ws::handler::Vaults::get({{"id", vaultId}}, session);
    EXPECT_TRUE(after["vault"]["sync"]["s3_request_budget"]["list_requests"].is_null());
    EXPECT_EQ(42u, after["vault"]["sync"]["s3_request_budget"]["get_requests"].get<uint32_t>());
    EXPECT_TRUE(after["vault"]["sync"]["s3_request_budget"]["downloaded_bytes"].is_null());
    EXPECT_EQ(60, after["vault"]["sync"]["max_remote_index_age_seconds"].get<int>());

    const auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    ASSERT_TRUE(engine);
    ASSERT_TRUE(engine->remote_policy()->s3_request_budget.max_get_requests);
    EXPECT_EQ(42u, *engine->remote_policy()->s3_request_budget.max_get_requests);
}

// Stage 0 S6: storage.vault.update only checked that a new api_key_id existed, never APIPermissions::Consume, so a
// caller with vault Edit could bind any API key to a vault. storage.vault.add and CLI `vault update --api-key` both
// require Consume; the gate applies only when the key actually changes.
TEST(S3CostSafetyTest, WsVaultUpdateRequiresConsumeToChangeApiKey) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed ws vault update consume test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto suffix = uniqueSuffix("ws_update_consume");
    const auto vaultId = seedDryRunS3VaultForDbTest(suffix, fake);
    const auto keyIdBefore = [&] {
        return std::static_pointer_cast<vh::vault::model::S3Vault>(
            vh::db::query::vault::Vault::getVault(vaultId))->api_key_id;
    };
    const auto originalKeyId = keyIdBefore();

    const auto admin = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(admin);
    auto otherKey = std::make_shared<vh::vault::model::APIKey>(
        admin->id,
        "consume-gate-key-" + suffix,
        vh::vault::model::S3Provider::AWS,
        "ABCDEFGHIJKLMNOPQRST",
        "ABCDEFGHIJKLMNOPQRSTABCDEFGHIJKLMNOPQRST",
        "us-east-1",
        "https://s3.example.com");
    vh::runtime::Deps::get().apiKeyManager->addAPIKey(otherKey);
    ASSERT_NE(originalKeyId, otherKey->id);

    // Vault editor with no API-key permissions at all.
    const auto editorId = seedS3CostUserForDbTest(suffix, "editor");
    const auto editorSession = wsSessionForUser(editorId, vh::rbac::role::Admin::Custom(
        "ws_update_consume_editor",
        "vault editor without key permissions",
        vh::rbac::permission::admin::Identities::None(),
        vh::rbac::permission::admin::Vaults::Full(),
        vh::rbac::permission::admin::Audits::None(),
        vh::rbac::permission::admin::Settings::None(),
        vh::rbac::permission::admin::Roles::None(),
        vh::rbac::permission::admin::Keys::None(),
        vh::rbac::permission::admin::S3Gateway::None()));

    const auto before = vh::protocols::ws::handler::Vaults::get({{"id", vaultId}}, superAdminWsSession());
    ASSERT_TRUE(before.contains("vault"));

    auto swapKey = before["vault"];
    swapKey["api_key_id"] = otherKey->id;
    try {
        (void)vh::protocols::ws::handler::Vaults::update(swapKey, editorSession);
        ADD_FAILURE() << "vault Edit alone attached an API key the caller cannot consume";
    } catch (const std::exception& e) {
        EXPECT_NE(std::string(e.what()).find("api-key"), std::string::npos) << e.what();
    }
    EXPECT_EQ(originalKeyId, keyIdBefore());

    // Same key: no Consume needed, so the editor's ordinary edit is not caught by the gate.
    auto sameKey = before["vault"];
    sameKey["description"] = "edited without touching the key";
    try {
        (void)vh::protocols::ws::handler::Vaults::update(sameKey, editorSession);
    } catch (const std::exception& e) {
        EXPECT_EQ(std::string(e.what()).find("api-key"), std::string::npos) << e.what();
    }
    EXPECT_EQ(originalKeyId, keyIdBefore());
}

TEST(S3CostSafetyTest, DryRunViewOnlyUsesFreshLocalIndexWithoutS3Refresh) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed dry-run auth test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("dryrun_view"), fake);
    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, remoteFile("remote.txt"), "manifest");

    const auto viewOnly = dryRunActor(
        90'001,
        vh::rbac::role::Admin::Auditor(90'001));
    const auto before = vh::db::query::sync::RemoteObjectIndex::summaryForVault(vaultId);

    const auto result = runDryRunCommand(vaultId, viewOnly);
    const auto after = vh::db::query::sync::RemoteObjectIndex::summaryForVault(vaultId);

    EXPECT_EQ(0, result.exit_code) << result.stderr_text;
    EXPECT_EQ(0, fake->head_object_calls);
    EXPECT_EQ(0, fake->download_to_buffer_calls);
    EXPECT_EQ(0u, fake->requestMetrics().head_requests);
    EXPECT_EQ(0u, fake->requestMetrics().get_requests);
    EXPECT_EQ(before.manifest_updated_at, after.manifest_updated_at);
    EXPECT_EQ(std::string::npos, result.stdout_text.find("may refresh"));
}

TEST(S3CostSafetyTest, DryRunRefreshIndexRequiresTriggerPermission) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed dry-run auth test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("dryrun_refresh_denied"), fake);
    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, remoteFile("remote.txt"), "manifest");

    const auto viewOnly = dryRunActor(
        90'002,
        vh::rbac::role::Admin::Auditor(90'002));

    const auto result = runDryRunCommand(vaultId, viewOnly, true);

    EXPECT_EQ(2, result.exit_code);
    EXPECT_NE(std::string::npos, result.stderr_text.find("permission to refresh"));
    EXPECT_EQ(0, fake->head_object_calls);
    EXPECT_EQ(0, fake->download_to_buffer_calls);
}

TEST(S3CostSafetyTest, DryRunRefreshIndexWithTriggerMayUseS3HeadMetrics) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed dry-run auth test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("dryrun_refresh_allowed"), fake);
    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, remoteFile("remote.txt"), "manifest");

    const auto trigger = dryRunActor(
        90'003,
        vh::rbac::role::Admin::PlatformOperator(90'003));

    const auto result = runDryRunCommand(vaultId, trigger, true);

    EXPECT_EQ(0, result.exit_code) << result.stderr_text;
    EXPECT_EQ(1, fake->head_object_calls);
    EXPECT_EQ(0, fake->download_to_buffer_calls);
    EXPECT_EQ(1u, fake->requestMetrics().head_requests);
    EXPECT_NE(std::string::npos, result.stdout_text.find("Note: --refresh-index may refresh the remote index manifest before planning."));
    EXPECT_NE(std::string::npos, result.stdout_text.find("HEAD: 1"));
}

TEST(S3CostSafetyTest, DryRunReportsMissingAndStaleLocalIndexWithoutS3Refresh) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed dry-run auth test due to missing environment variables.";

    const auto viewOnly = dryRunActor(
        90'004,
        vh::rbac::role::Admin::Auditor(90'004));

    auto missingFake = std::make_shared<CountingS3Controller>();
    const auto missingVaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("dryrun_missing"), missingFake);
    const auto missing = runDryRunCommand(missingVaultId, viewOnly);
    EXPECT_EQ(2, missing.exit_code);
    EXPECT_EQ(
        "vault sync dry-run: no remote index is available; run reconcile, inventory import, event ingestion, or dry-run --refresh-index.",
        missing.stderr_text);
    EXPECT_EQ(0, missingFake->head_object_calls);

    auto staleFake = std::make_shared<CountingS3Controller>();
    const auto staleVaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("dryrun_stale"), staleFake);
    vh::db::Transactions::exec("S3CostSafetyTest::seedStaleDryRunIndex", [&](pqxx::work& txn) {
        txn.exec(
            "INSERT INTO remote_object_index "
            "(vault_id, object_key, size_bytes, last_modified, etag, source, indexed_at) "
            "VALUES ($1, $2, $3, CURRENT_TIMESTAMP - INTERVAL '2 hours', $4, $5, CURRENT_TIMESTAMP - INTERVAL '2 hours')",
            pqxx::params{staleVaultId, "stale.txt", 1, "\"stale\"", "manifest"});
    });
    auto staleEngine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(staleVaultId));
    staleEngine->remote_policy()->max_remote_index_age = std::chrono::seconds(60);

    const auto stale = runDryRunCommand(staleVaultId, viewOnly);
    EXPECT_EQ(2, stale.exit_code);
    EXPECT_EQ(
        "vault sync dry-run: remote index is stale; run dry-run --refresh-index, reconcile, inventory import, or event ingestion.",
        stale.stderr_text);
    EXPECT_EQ(0, staleFake->head_object_calls);
}

TEST(S3CostSafetyTest, DbFileBackingPathOmitsGlobalRootAlias) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed backing path reconstruction test due to missing environment variables.";

    ensureSeededRuntimeReady();
    const auto suffix = uniqueSuffix("entry_backing");
    const auto mountAlias = vh::crypto::id::Generator({.namespace_token = "vault-" + suffix}).generate();
    const auto dirAlias = vh::crypto::id::Generator({.namespace_token = "dir-" + suffix}).generate();
    const auto fileAlias = vh::crypto::id::Generator({.namespace_token = "file-" + suffix}).generate();
    const auto dirName = "folder-" + suffix;
    const auto fileName = "file-" + suffix + ".txt";
    const auto filePath = std::filesystem::path("/") / dirName / fileName;

    const auto vaultId = vh::db::Transactions::exec("S3CostSafetyTest::seedEntryBackingPathRows", [&](pqxx::work& txn) {
        const auto userId = insertS3CostHydratableTestUser(
            txn,
            "entry_backing_user_" + suffix,
            "entry-backing-" + suffix + "@vaulthalla.test");

        const auto seededVaultId = txn.exec(
            "INSERT INTO vault (type, name, owner_id, mount_point, description) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            pqxx::params{
                "local",
                "Entry Backing " + suffix,
                userId,
                mountAlias,
                ""
            }).one_field_ref().as<uint32_t>();
        txn.exec(
            "WITH ins AS (INSERT INTO sync (vault_id, interval) VALUES ($1, 300) RETURNING id) "
            "INSERT INTO fsync (sync_id, conflict_policy) SELECT id, 'keep_both' FROM ins",
            pqxx::params{seededVaultId});

        const auto rootId = txn.exec(
            "SELECT id FROM fs_entry WHERE parent_id IS NULL AND vault_id IS NULL AND path = '/' AND name = '/'"
        ).one_field_ref().as<uint32_t>();

        const auto vaultEntryId = txn.exec(
            "INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, mode) "
            "VALUES ($1, $2, $3, $4, $5, $5, '/', 0755) RETURNING id",
            pqxx::params{seededVaultId, rootId, "entry_backing_" + suffix, mountAlias, userId}
        ).one_field_ref().as<uint32_t>();
        txn.exec(
            "INSERT INTO directories (fs_entry_id, size_bytes, file_count, subdirectory_count) VALUES ($1, 4, 1, 1)",
            pqxx::params{vaultEntryId});

        const auto dirId = txn.exec(
            "INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, mode) "
            "VALUES ($1, $2, $3, $4, $5, $5, $6, 0755) RETURNING id",
            pqxx::params{seededVaultId, vaultEntryId, dirName, dirAlias, userId, "/" + dirName}
        ).one_field_ref().as<uint32_t>();
        txn.exec(
            "INSERT INTO directories (fs_entry_id, size_bytes, file_count, subdirectory_count) VALUES ($1, 4, 1, 0)",
            pqxx::params{dirId});

        const auto fileId = txn.exec(
            "INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, mode) "
            "VALUES ($1, $2, $3, $4, $5, $5, $6, 0644) RETURNING id",
            pqxx::params{seededVaultId, dirId, fileName, fileAlias, userId, filePath.string()}
        ).one_field_ref().as<uint32_t>();
        txn.exec(
            "INSERT INTO files (fs_entry_id, size_bytes, mime_type, content_hash, encryption_iv) "
            "VALUES ($1, 4, 'text/plain', 'hash', 'iv')",
            pqxx::params{fileId});

        return seededVaultId;
    });

    const auto file = vh::db::query::fs::File::getFileByPath(vaultId, filePath);
    ASSERT_TRUE(file);
    EXPECT_EQ(vh::paths::getBackingPath() / mountAlias / dirAlias / fileAlias, file->backing_path);
}

TEST(S3CostSafetyTest, SigV4SignedHeadersIncludeMetadataHeaders) {
    const std::map<std::string, std::string> headers{
        {"content-type", "application/octet-stream"},
        {"host", "s3.example.com"},
        {"x-amz-content-sha256", vh::storage::s3::curl::sha256Hex("ciphertext")},
        {"x-amz-date", "20260525T000000Z"},
        {"x-amz-meta-vh-encrypted", "true"},
        {"x-amz-meta-vh-iv", "iv"},
        {"x-amz-meta-vh-key-version", "3"},
    };

    const auto auth = vh::storage::s3::curl::buildAuthorizationHeader(
        dummyApiKey(),
        "PUT",
        "/unit-bucket/ciphertext.bin",
        headers,
        headers.at("x-amz-content-sha256"));

    EXPECT_NE(
        std::string::npos,
        auth.find(
            "SignedHeaders=content-type;host;x-amz-content-sha256;x-amz-date;"
            "x-amz-meta-vh-encrypted;x-amz-meta-vh-iv;x-amz-meta-vh-key-version"));
}

TEST(S3CostSafetyTest, RemoteEncryptedPayloadUsesCaseInsensitiveHeadMetadata) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed encrypted remote metadata test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("head_iv_case"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const std::vector<uint8_t> plaintext{'s', 'e', 'c', 'r', 'e', 't'};
    auto encryptedSource = remoteFile("mixed-case-head.bin");
    const auto ciphertext = engine->encryptionManager->encrypt(plaintext, encryptedSource);

    fake->head_response = std::unordered_map<std::string, std::string>{
        {"X-Amz-Meta-Vh-Encrypted", "true"},
        {"X-Amz-Meta-Vh-Iv", encryptedSource->encryption_iv},
        {"X-Amz-Meta-Vh-Key-Version", std::to_string(encryptedSource->encrypted_with_key_version)},
    };

    auto remote = remoteFile("mixed-case-head.bin");
    remote->remote_encrypted = true;
    const auto decrypted = engine->decryptRemotePayload(remote->path, ciphertext, remote);

    EXPECT_EQ(plaintext, decrypted);
    EXPECT_EQ(1, fake->head_object_calls);
}

TEST(S3CostSafetyTest, ExplicitRemotePlaintextMetadataWinsOverLocalFileIv) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed plaintext remote provenance test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("plain_head_false"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const auto owner = vh::identities::manager().user(engine->vault->owner_id);
    ASSERT_TRUE(owner);

    const std::filesystem::path path = "/plain-head-false.txt";
    const auto local = vh::fs::Filesystem::createFile({
        .path = path,
        .fuse_path = engine->vaultPathToFusePath(path),
        .buffer = {'l', 'o', 'c', 'a', 'l'},
        .engine = engine,
        .user = owner,
        .overwrite = true,
    });
    ASSERT_TRUE(local);
    ASSERT_FALSE(local->encryption_iv.empty());
    ASSERT_GT(local->encrypted_with_key_version, 0u);

    fake->head_response = std::unordered_map<std::string, std::string>{
        {"x-amz-meta-vh-encrypted", "false"},
    };

    const std::vector<uint8_t> plaintext{'p', 'l', 'a', 'i', 'n'};
    const auto decrypted = engine->decryptRemotePayload(
        path,
        plaintext,
        local,
        vh::storage::CloudEngine::RemoteEncryptionResolveOptions{false, true});

    EXPECT_EQ(plaintext, decrypted);
}

TEST(S3CostSafetyTest, ShareStyleRemotePayloadDoesNotTrustLocalFileIv) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed share plaintext provenance test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("share_local_iv"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const std::vector<uint8_t> localPlaintext{'l', 'o', 'c', 'a', 'l'};
    auto local = remoteFile("share/plain-remote.txt");
    (void)engine->encryptionManager->encrypt(localPlaintext, local);
    ASSERT_FALSE(local->encryption_iv.empty());
    ASSERT_GT(local->encrypted_with_key_version, 0u);

    fake->head_response = std::nullopt;

    const std::vector<uint8_t> remotePlaintext{'r', 'e', 'm', 'o', 't', 'e'};
    const auto decrypted = engine->decryptRemotePayload(local->path, remotePlaintext, local, {});

    EXPECT_EQ(remotePlaintext, decrypted);
}

TEST(S3CostSafetyTest, TrustedRemoteFileMetadataDecryptsWhenHeadMetadataMissing) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed trusted remote provenance test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("trusted_remote_iv"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const std::vector<uint8_t> plaintext{'s', 'e', 'c', 'r', 'e', 't'};
    auto remote = remoteFile("trusted/from-index.bin");
    remote->remote_encrypted = true;
    const auto ciphertext = engine->encryptionManager->encrypt(plaintext, remote);
    fake->head_response = std::nullopt;

    const auto decrypted = engine->decryptRemotePayload(
        remote->path,
        ciphertext,
        remote,
        vh::storage::CloudEngine::RemoteEncryptionResolveOptions{true, false});

    EXPECT_EQ(plaintext, decrypted);
    EXPECT_EQ(0, fake->head_object_calls);
}

TEST(S3CostSafetyTest, RemoteObjectIndexRoundTripsEncryptionMetadata) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed remote index metadata test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("remote_index_iv"));
    auto remote = remoteFile("encrypted/from-index.txt");
    remote->content_hash = "content-hash";
    remote->remote_encrypted = true;
    remote->encryption_iv = "iv-from-index";
    remote->encrypted_with_key_version = 7;

    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, remote, "manifest");
    const auto files = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);

    ASSERT_EQ(1u, files.size());
    EXPECT_EQ("/encrypted/from-index.txt", files[0]->path.string());
    ASSERT_TRUE(files[0]->content_hash);
    EXPECT_EQ("content-hash", *files[0]->content_hash);
    ASSERT_TRUE(files[0]->remote_encrypted);
    EXPECT_TRUE(*files[0]->remote_encrypted);
    EXPECT_EQ("iv-from-index", files[0]->encryption_iv);
    EXPECT_EQ(7u, files[0]->encrypted_with_key_version);
}

TEST(S3CostSafetyTest, RemoteObjectIndexPreservesEncryptionMetadataForSameObjectOnly) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed remote index metadata test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("remote_index_preserve_iv"));
    auto manifest = remoteFile("encrypted/preserve.txt");
    manifest->updated_at = 1'777'777'000;
    manifest->remote_etag = "\"same-etag\"";
    manifest->remote_version_id = "version-a";
    manifest->content_hash = "content-hash";
    manifest->remote_encrypted = true;
    manifest->encryption_iv = "iv-from-manifest";
    manifest->encrypted_with_key_version = 4;
    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, manifest, "manifest");

    auto sameFromList = remoteFile("encrypted/preserve.txt");
    sameFromList->updated_at = manifest->updated_at;
    sameFromList->size_bytes = manifest->size_bytes;
    sameFromList->remote_etag = manifest->remote_etag;
    sameFromList->remote_version_id = manifest->remote_version_id;
    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, sameFromList, "list_objects_v2");

    auto files = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    ASSERT_EQ(1u, files.size());
    EXPECT_EQ("content-hash", files[0]->content_hash.value_or(""));
    ASSERT_TRUE(files[0]->remote_encrypted);
    EXPECT_TRUE(*files[0]->remote_encrypted);
    EXPECT_EQ("iv-from-manifest", files[0]->encryption_iv);
    EXPECT_EQ(4u, files[0]->encrypted_with_key_version);

    auto changedFromList = remoteFile("encrypted/preserve.txt");
    changedFromList->updated_at = manifest->updated_at;
    changedFromList->size_bytes = manifest->size_bytes;
    changedFromList->remote_etag = "\"changed-etag\"";
    changedFromList->remote_version_id = manifest->remote_version_id;
    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, changedFromList, "list_objects_v2");

    files = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    ASSERT_EQ(1u, files.size());
    EXPECT_FALSE(files[0]->content_hash);
    EXPECT_FALSE(files[0]->remote_encrypted);
    EXPECT_TRUE(files[0]->encryption_iv.empty());
    EXPECT_EQ(0u, files[0]->encrypted_with_key_version);
}

TEST(S3CostSafetyTest, PlaintextUpstreamUploadMutationDoesNotPoisonRemoteIndexWithLocalIv) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed remote index upload provenance test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("upload_plain_index"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);
    std::static_pointer_cast<vh::vault::model::S3Vault>(engine->vault)->encrypt_upstream = false;

    auto local = remoteFile("uploads/plain.txt");
    local->size_bytes = 5;
    local->updated_at = std::time(nullptr);
    (void)engine->encryptionManager->encrypt({'l', 'o', 'c', 'a', 'l'}, local);
    const auto originalIv = local->encryption_iv;
    const auto originalKeyVersion = local->encrypted_with_key_version;

    const std::vector<vh::sync::model::Action> plan{
        {vh::sync::model::ActionType::Upload, {.rel = u8"uploads/plain.txt"}, local, nullptr}
    };

    ASSERT_NO_THROW(engine->applyRemoteIndexMutation(plan));

    EXPECT_EQ(originalIv, local->encryption_iv);
    EXPECT_EQ(originalKeyVersion, local->encrypted_with_key_version);

    const auto indexed = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    ASSERT_EQ(1u, indexed.size());
    ASSERT_TRUE(indexed[0]->remote_encrypted);
    EXPECT_FALSE(*indexed[0]->remote_encrypted);
    EXPECT_TRUE(indexed[0]->encryption_iv.empty());
    EXPECT_EQ(0u, indexed[0]->encrypted_with_key_version);
    EXPECT_FALSE(indexed[0]->remote_storage_class);
}

TEST(S3CostSafetyTest, EncryptedUpstreamUploadMutationStoresRemoteEncryptionMetadata) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed remote index upload provenance test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("upload_encrypted_index"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);
    std::static_pointer_cast<vh::vault::model::S3Vault>(engine->vault)->encrypt_upstream = true;

    auto local = remoteFile("uploads/encrypted.txt");
    local->size_bytes = 5;
    local->updated_at = std::time(nullptr);
    (void)engine->encryptionManager->encrypt({'l', 'o', 'c', 'a', 'l'}, local);

    const std::vector<vh::sync::model::Action> plan{
        {vh::sync::model::ActionType::Upload, {.rel = u8"uploads/encrypted.txt"}, local, nullptr}
    };

    ASSERT_NO_THROW(engine->applyRemoteIndexMutation(plan));

    const auto indexed = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    ASSERT_EQ(1u, indexed.size());
    ASSERT_TRUE(indexed[0]->remote_encrypted);
    EXPECT_TRUE(*indexed[0]->remote_encrypted);
    EXPECT_EQ(local->encryption_iv, indexed[0]->encryption_iv);
    EXPECT_EQ(local->encrypted_with_key_version, indexed[0]->encrypted_with_key_version);
    EXPECT_FALSE(indexed[0]->remote_storage_class);
}

TEST(S3CostSafetyTest, UploadMutationStoresConfiguredAwsStorageClass) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed remote index storage tier test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("upload_aws_tier_index"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const auto s3Vault = std::static_pointer_cast<vh::vault::model::S3Vault>(engine->vault);
    s3Vault->storage_tier_id = "standard_ia";
    engine->setS3ProviderProfileForTesting(
        vh::storage::s3::provider::resolve(vh::vault::model::S3Provider::AWS));

    auto local = remoteFile("uploads/aws-tier.txt");
    local->size_bytes = 5;
    local->updated_at = std::time(nullptr);
    (void)engine->encryptionManager->encrypt({'l', 'o', 'c', 'a', 'l'}, local);

    const std::vector<vh::sync::model::Action> plan{
        {vh::sync::model::ActionType::Upload, {.rel = u8"uploads/aws-tier.txt"}, local, nullptr}
    };

    ASSERT_NO_THROW(engine->applyRemoteIndexMutation(plan));

    const auto indexed = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    ASSERT_EQ(1u, indexed.size());
    ASSERT_TRUE(indexed[0]->remote_storage_class);
    EXPECT_EQ("STANDARD_IA", *indexed[0]->remote_storage_class);
}

TEST(S3CostSafetyTest, UploadMutationStoresConfiguredR2StorageClass) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed remote index storage tier test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("upload_r2_tier_index"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const auto s3Vault = std::static_pointer_cast<vh::vault::model::S3Vault>(engine->vault);
    s3Vault->storage_tier_id = "infrequent_access";
    engine->setS3ProviderProfileForTesting(
        vh::storage::s3::provider::resolve(vh::vault::model::S3Provider::CloudflareR2));

    auto local = remoteFile("uploads/r2-tier.txt");
    local->size_bytes = 5;
    local->updated_at = std::time(nullptr);
    (void)engine->encryptionManager->encrypt({'l', 'o', 'c', 'a', 'l'}, local);

    const std::vector<vh::sync::model::Action> plan{
        {vh::sync::model::ActionType::Upload, {.rel = u8"uploads/r2-tier.txt"}, local, nullptr}
    };

    ASSERT_NO_THROW(engine->applyRemoteIndexMutation(plan));

    const auto indexed = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    ASSERT_EQ(1u, indexed.size());
    ASSERT_TRUE(indexed[0]->remote_storage_class);
    EXPECT_EQ("STANDARD_IA", *indexed[0]->remote_storage_class);
}

TEST(S3CostSafetyTest, S3VaultDbRoundTripsStorageTierId) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 vault storage tier test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("vault_tier_roundtrip"), fake);

    auto vault = std::static_pointer_cast<vh::vault::model::S3Vault>(
        vh::db::query::vault::Vault::getVault(vaultId));
    ASSERT_TRUE(vault);
    EXPECT_FALSE(vault->storage_tier_id);

    vault->storage_tier_id = "standard_ia";
    vh::db::query::vault::Vault::upsertVault(vault);

    auto reloaded = std::static_pointer_cast<vh::vault::model::S3Vault>(
        vh::db::query::vault::Vault::getVault(vaultId));
    ASSERT_TRUE(reloaded);
    ASSERT_TRUE(reloaded->storage_tier_id);
    EXPECT_EQ("standard_ia", *reloaded->storage_tier_id);

    reloaded->storage_tier_id = std::nullopt;
    vh::db::query::vault::Vault::upsertVault(reloaded);

    auto cleared = std::static_pointer_cast<vh::vault::model::S3Vault>(
        vh::db::query::vault::Vault::getVault(vaultId));
    ASSERT_TRUE(cleared);
    EXPECT_FALSE(cleared->storage_tier_id);
}

TEST(S3CostSafetyTest, StorageManagerUpdateRemovesOldEnginePathEntry) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed storage manager update test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("manager_update_path"), fake);
    const auto manager = vh::runtime::Deps::get().storageManager;

    const auto originalEngine = manager->getEngine(vaultId);
    ASSERT_TRUE(originalEngine);
    ASSERT_TRUE(originalEngine->paths);
    const auto oldPath = originalEngine->paths->absRelToRoot(
        originalEngine->paths->vaultRoot,
        vh::fs::model::PathType::FUSE_ROOT);

    auto vault = vh::db::query::vault::Vault::getVault(vaultId);
    ASSERT_TRUE(vault);
    // Since vault slugs/fuse names (#95) the FUSE path follows effectiveFuseName(), not the display name,
    // so change the fuse name to force a path change.
    vault->fuse_name = vault->effectiveFuseName() + "-renamed";
    manager->updateVault(vault);

    const auto refreshedEngine = manager->getEngine(vaultId);
    ASSERT_TRUE(refreshedEngine);
    ASSERT_TRUE(refreshedEngine->paths);
    const auto newPath = refreshedEngine->paths->absRelToRoot(
        refreshedEngine->paths->vaultRoot,
        vh::fs::model::PathType::FUSE_ROOT);

    EXPECT_NE(oldPath, newPath);
    EXPECT_NE(originalEngine.get(), refreshedEngine.get());

    const auto engines = manager->getEngines();
    const auto matchingVaults = std::count_if(engines.begin(), engines.end(), [vaultId](const auto& engine) {
        return engine && engine->vault && engine->vault->id == vaultId;
    });
    EXPECT_EQ(1, matchingVaults);
    EXPECT_EQ(nullptr, manager->resolveStorageEngine(oldPath));
    EXPECT_EQ(refreshedEngine, manager->resolveStorageEngine(newPath));
}

TEST(S3CostSafetyTest, StorageManagerRejectsDuplicateVaultNameForSameOwner) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed duplicate vault test due to missing environment variables.";
    ensureSeededRuntimeReady();

    const auto owner = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(owner);
    const auto name = "dup-vault-" + uniqueSuffix("dup");
    const auto makeVault = [&] {
        auto vault = std::make_shared<vh::vault::model::Vault>();
        vault->name = name;
        vault->owner_id = owner->id;
        vault->type = vh::vault::model::VaultType::Local;
        return vault;
    };
    const auto manager = vh::runtime::Deps::get().storageManager;

    const auto first = manager->addVault(makeVault(), std::make_shared<vh::sync::model::LocalPolicy>());
    ASSERT_TRUE(first);
    // Regression: the web console created a second same-named vault (suffixed FUSE name) while the CLI refused.
    EXPECT_THROW(manager->addVault(makeVault(), std::make_shared<vh::sync::model::LocalPolicy>()), std::runtime_error);
    EXPECT_TRUE(vh::db::query::vault::Vault::vaultExists(name, owner->id));

    manager->removeVault(first->id);
}

TEST(S3CostSafetyTest, RegisterUserCreatesOwnedDefaultVault) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed registration test due to missing environment variables.";
    ensureSeededRuntimeReady();

    // Regression: web-console registration always failed ("Sync cannot be null on vault creation") after
    // the user row was written, because the default vault was upserted with no owner and no sync policy.
    auto manager = std::make_shared<vh::auth::Manager>();
    vh::identities::UserState draft;
    draft.name = "reg_" + uniqueSuffix("default_vault");
    draft.email = draft.name + "@vaulthalla.test";
    draft.roles.admin = vh::db::query::rbac::role::Admin::get("unprivileged");
    ASSERT_TRUE(draft.roles.admin);

    ASSERT_NO_THROW((void)manager->registerUser(draft, "Zq9#" + uniqueSuffix("pw") + "!Xw-Long"));
    const auto stored = vh::identities::manager().userByName(draft.name);
    ASSERT_TRUE(stored);
    EXPECT_TRUE(vh::db::query::vault::Vault::vaultExists(draft.name + "'s Local Disk Vault", stored->id));
}

TEST(S3CostSafetyTest, DeletingAVaultOwnerDoesNotBreakVaultLoading) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed owner deletion test due to missing environment variables.";
    ensureSeededRuntimeReady();

    // Regression: owner_id is ON DELETE SET NULL; the next listVaults threw "Attempt to convert SQL null to
    // unsigned int" and the daemon could not start after any vault owner was deleted.
    auto manager = std::make_shared<vh::auth::Manager>();
    vh::identities::UserState draft;
    draft.name = "orphan_" + uniqueSuffix("owner");
    draft.email = draft.name + "@vaulthalla.test";
    draft.roles.admin = vh::db::query::rbac::role::Admin::get("unprivileged");
    ASSERT_TRUE(draft.roles.admin);
    (void)manager->registerUser(draft, "Zq9#" + uniqueSuffix("pw") + "!Xw-Long");
    const auto stored = vh::identities::manager().userByName(draft.name);
    ASSERT_TRUE(stored);

    vh::identities::manager().deleteUser(stored->id);
    EXPECT_TRUE(stored->deleted()) << "the reference taken before the delete holds a tombstone";

    std::vector<std::shared_ptr<vh::vault::model::Vault>> vaults;
    ASSERT_NO_THROW(vaults = vh::db::query::vault::Vault::listVaults());
    const auto orphan = std::ranges::find_if(vaults, [&](const auto& v) { return v->name == draft.name + "'s Local Disk Vault"; });
    ASSERT_NE(orphan, vaults.end());
    EXPECT_EQ((*orphan)->owner_id, 0u);
}

TEST(S3CostSafetyTest, IndexRemoteOnlyPreservesEncryptionMetadataInLocalRow) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed remote index-only test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("index_only_iv"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    auto remote = remoteFile("index-only-encrypted.txt");
    remote->content_hash = "remote-content-hash";
    remote->remote_encrypted = true;
    remote->encryption_iv = "remote-iv";
    remote->encrypted_with_key_version = 5;

    engine->indexAndDeleteFile(remote);

    const auto indexed = vh::db::query::fs::File::getFileByPath(vaultId, "/index-only-encrypted.txt");
    ASSERT_TRUE(indexed);
    ASSERT_TRUE(indexed->content_hash);
    EXPECT_EQ("remote-content-hash", *indexed->content_hash);
    EXPECT_EQ("remote-iv", indexed->encryption_iv);
    EXPECT_EQ(5u, indexed->encrypted_with_key_version);
}

TEST(S3CostSafetyTest, RemoteEncryptedDownloadCreatesBackingParentsAndDecrypts) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed encrypted remote download test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("download_parents"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const std::vector<uint8_t> plaintext{'d', 'o', 'w', 'n', 'l', 'o', 'a', 'd'};
    auto remote = remoteFile("nested/remote/encrypted.png");
    remote->remote_encrypted = true;
    fake->download_payload = engine->encryptionManager->encrypt(plaintext, remote);

    auto task = std::make_shared<vh::sync::Cloud>(engine);
    task->s3Map.emplace(remote->path.u8string(), remote);
    task->ensureDirectoriesFromRemote();

    const auto created = engine->downloadFile(remote);
    ASSERT_TRUE(created);
    EXPECT_TRUE(std::filesystem::exists(created->backing_path.parent_path()));
    EXPECT_TRUE(std::filesystem::exists(created->backing_path));
    EXPECT_EQ(plaintext, engine->decrypt(created));
}

TEST(S3CostSafetyTest, KnownEncryptedRemoteWithoutIvFailsBeforeLocalCreate) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed encrypted remote failure test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("missing_iv"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);
    fake->download_payload = {'c', 'i', 'p', 'h', 'e', 'r'};
    fake->head_response = std::unordered_map<std::string, std::string>{
        {"x-amz-meta-vh-encrypted", "true"},
    };

    auto remote = remoteFile("missing-iv.txt");
    remote->remote_encrypted = true;

    EXPECT_THROW((void)engine->downloadFile(remote), std::runtime_error);
    EXPECT_FALSE(vh::db::query::fs::File::getFileByPath(vaultId, "/missing-iv.txt"));
}

TEST(S3CostSafetyTest, DeleteRemoteDoesNotRequireEncryptionMetadata) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed delete remote test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("delete_no_iv"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    auto remote = remoteFile("delete-without-iv.txt");
    auto op = std::make_shared<vh::sync::model::ScopedOp>();
    vh::sync::tasks::Delete task(engine, remote, op, vh::sync::tasks::Delete::Type::REMOTE);

    task();

    EXPECT_TRUE(op->success);
    EXPECT_EQ(1, fake->delete_object_calls);
    EXPECT_EQ(0, fake->head_object_calls);
    EXPECT_EQ(0, fake->download_to_buffer_calls);
}

TEST(S3CostSafetyTest, GatewayRemoteDeleteMarksTombstoneWithoutDirectUpstreamDelete) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed gateway remote delete test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto suffix = uniqueSuffix("gateway_delete_nosuchkey");
    const auto bucketName = uniqueBucketName("gateway-delete-nosuchkey");
    const auto vaultId = seedDryRunS3VaultForDbTest(suffix, fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const auto owner = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(owner);
    ASSERT_TRUE(owner->isSuperAdmin());

    constexpr std::string_view objectKey = "already-gone.txt";
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .api_exclusive = true,
        .mode = "remote_cache",
        .created_by = owner->id
    });
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = vaultId,
        .object_key = std::string(objectKey),
        .etag = "\"gateway-etag\"",
        .size_bytes = 42,
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });
    vh::db::query::s3::Gateway::upsertObjectMetadata(vaultId, std::string(objectKey), {{"color", "blue"}});
    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, remoteFile(std::string(objectKey)), "manifest");

    vh::protocols::s3::ObjectStore store;
    vh::protocols::s3::ResolvedBucket bucket{
        .bucket_name = bucketName,
        .vault_id = vaultId,
        .mode = "remote_cache",
        .api_exclusive = true,
        .engine = engine,
        .actor = owner,
        .gateway_access = std::nullopt
    };

    ASSERT_NO_THROW(store.deleteObject(bucket, std::string(objectKey)));

    EXPECT_EQ(0, fake->delete_object_calls);
    EXPECT_TRUE(fake->deleted_keys.empty());
    EXPECT_FALSE(vh::db::query::s3::Gateway::getObjectState(vaultId, std::string(objectKey)));
    EXPECT_TRUE(vh::db::query::s3::Gateway::listObjectMetadata(vaultId, std::string(objectKey)).empty());
    EXPECT_THROW((void)store.headObject(bucket, std::string(objectKey)), vh::protocols::s3::S3Error);

    const auto listed = store.listObjects(bucket, {});
    EXPECT_TRUE(listed.objects.empty());
    const auto trashed = vh::db::query::fs::File::listTrashedFiles(vaultId);
    EXPECT_TRUE(std::ranges::any_of(trashed, [&](const auto& file) {
        return file && file->path.generic_string() == std::string("/") + std::string(objectKey) &&
            !file->deleted_at.has_value();
    }));

    const auto indexed = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    EXPECT_TRUE(std::ranges::any_of(indexed, [&](const auto& file) {
        return file && file->path.generic_string() == std::string("/") + std::string(objectKey);
    }));
}

TEST(S3CostSafetyTest, GatewayRemoteDeleteIgnoresDirectUpstreamFailureBecauseSyncOwnsPurge) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed gateway remote delete test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    fake->delete_object_failure = true;
    const auto suffix = uniqueSuffix("gateway_delete_failure");
    const auto bucketName = uniqueBucketName("gateway-delete-failure");
    const auto vaultId = seedDryRunS3VaultForDbTest(suffix, fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const auto owner = vh::identities::manager().userByName("admin");
    ASSERT_TRUE(owner);
    ASSERT_TRUE(owner->isSuperAdmin());

    constexpr std::string_view objectKey = "must-not-local-delete.txt";
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = vaultId,
        .bucket_name = bucketName,
        .api_exclusive = true,
        .mode = "remote_cache",
        .created_by = owner->id
    });
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = vaultId,
        .object_key = std::string(objectKey),
        .etag = "\"gateway-etag\"",
        .size_bytes = 42,
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });
    vh::db::query::s3::Gateway::upsertObjectMetadata(vaultId, std::string(objectKey), {{"color", "red"}});
    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, remoteFile(std::string(objectKey)), "manifest");

    vh::protocols::s3::ObjectStore store;
    vh::protocols::s3::ResolvedBucket bucket{
        .bucket_name = bucketName,
        .vault_id = vaultId,
        .mode = "remote_cache",
        .api_exclusive = true,
        .engine = engine,
        .actor = owner,
        .gateway_access = std::nullopt
    };

    EXPECT_NO_THROW(store.deleteObject(bucket, std::string(objectKey)));

    EXPECT_EQ(0, fake->delete_object_calls);
    EXPECT_FALSE(vh::db::query::s3::Gateway::getObjectState(vaultId, std::string(objectKey)));
    EXPECT_TRUE(vh::db::query::s3::Gateway::listObjectMetadata(vaultId, std::string(objectKey)).empty());

    const auto indexed = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    EXPECT_TRUE(std::ranges::any_of(indexed, [&](const auto& file) {
        return file && file->path.generic_string() == std::string("/") + std::string(objectKey);
    }));
}

TEST(S3CostSafetyTest, CloudTrashPurgeDeletesRemoteIndexWithoutRemoteOnlyDownload) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed cloud trash purge test due to missing environment variables.";

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("trash_purge"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);

    const auto owner = vh::identities::manager().user(engine->vault->owner_id);
    ASSERT_TRUE(owner);

    const std::filesystem::path dir = "/Vaulthalla-media";
    const std::filesystem::path path = dir / "foo.txt";
    ASSERT_NO_THROW(engine->mkdir(dir, owner));

    auto created = vh::fs::Filesystem::createFile({
        .path = path,
        .fuse_path = engine->vaultPathToFusePath(path),
        .buffer = {'d', 'e', 'l', 'e', 't', 'e', 'd'},
        .engine = engine,
        .user = owner,
    });
    ASSERT_TRUE(created);

    auto remote = remoteFile("Vaulthalla-media/foo.txt");
    remote->size_bytes = created->size_bytes;
    remote->updated_at = created->updated_at;
    remote->remote_etag = "\"remote-before-delete\"";
    vh::db::query::sync::RemoteObjectIndex::upsertFile(vaultId, remote, "manifest");

    ASSERT_NO_THROW(engine->remove(path, owner->id));
    EXPECT_FALSE(vh::db::query::fs::File::getFileByPath(vaultId, path));
    ASSERT_EQ(1u, vh::db::query::fs::File::listTrashedFiles(vaultId).size());

    auto task = std::make_shared<vh::sync::Cloud>(engine);
    task->startTask();
    task->removeTrashedFiles();
    ASSERT_NE(vh::sync::model::Event::Status::ERROR, task->event->status);
    task->initBins();
    task->sync();
    task->clearBins();

    EXPECT_EQ(1, fake->delete_object_calls);
    ASSERT_EQ(1u, fake->deleted_keys.size());
    EXPECT_EQ("Vaulthalla-media/foo.txt", fake->deleted_keys[0].generic_string());
    EXPECT_EQ(0, fake->download_to_buffer_calls);
    EXPECT_EQ(0u, fake->requestMetrics().get_requests);
    EXPECT_FALSE(vh::db::query::fs::File::getFileByPath(vaultId, path));
    EXPECT_TRUE(vh::db::query::fs::File::listTrashedFiles(vaultId).empty());

    const auto indexed = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId);
    EXPECT_TRUE(std::ranges::none_of(indexed, [&](const auto& file) {
        return file && file->path == path;
    }));
}

TEST(S3CostSafetyTest, RemoveTrashedFileUsesAbsoluteBackingPathDirectly) {
    ScopedPathRoots paths(std::filesystem::temp_directory_path() / "vh_trash_absolute_backing");

    auto vault = std::make_shared<vh::vault::model::Vault>();
    vault->id = 2001;
    vault->name = "trash-absolute";
    vault->mount_point = "trash-absolute";

    vh::storage::Engine engine;
    engine.vault = vault;
    engine.paths = std::make_shared<vh::fs::model::Path>("trash-absolute", "trash-absolute");

    const auto backing = engine.paths->backingVaultRoot / "nested" / "file.txt";
    std::filesystem::create_directories(backing.parent_path());
    std::ofstream(backing, std::ios::binary) << "deleted";
    ASSERT_TRUE(std::filesystem::exists(backing));

    auto trashed = std::make_shared<vh::fs::model::file::Trashed>();
    trashed->vault_id = vault->id;
    trashed->path = "/nested/file.txt";
    trashed->backing_path = backing;
    trashed->base32_alias = backing.filename().string();
    trashed->size_bytes = 7;

    engine.removeLocally(trashed);

    EXPECT_FALSE(std::filesystem::exists(backing));
    // Purging a trashed file never removes the folder it was in (#168).
    EXPECT_TRUE(std::filesystem::is_directory(backing.parent_path()));
}

TEST(S3CostSafetyTest, PlannerMarksCacheRemoteOnlyAsIndexOnly) {
    auto engine = makePlanningEngine();
    auto cloud = std::make_shared<vh::sync::Cloud>(engine);
    auto policy = std::static_pointer_cast<vh::sync::model::RemotePolicy>(engine->sync);
    policy->strategy = vh::sync::model::RemotePolicy::Strategy::Cache;

    const auto remote = remoteFile("remote-only.txt");
    cloud->s3Map.emplace(remote->path.u8string(), remote);

    const auto plan = vh::sync::Planner::build(cloud, policy);

    auto it = std::ranges::find_if(plan, [](const auto& action) {
        return action.type == vh::sync::model::ActionType::IndexRemoteOnly;
    });
    ASSERT_NE(plan.end(), it);
    EXPECT_TRUE(it->freeAfterDownload);

    const auto estimate = vh::sync::Planner::estimateS3Cost(plan);
    EXPECT_EQ(1u, estimate.remote_index_objects);
    EXPECT_EQ(0u, estimate.get_requests);
    EXPECT_EQ(0u, estimate.planned_body_download_bytes);
}

TEST(S3CostSafetyTest, PlannerPreflightsDownloadedByteBudgetBeforeBodyGets) {
    auto engine = makePlanningEngine();
    auto cloud = std::make_shared<vh::sync::Cloud>(engine);
    auto policy = std::static_pointer_cast<vh::sync::model::RemotePolicy>(engine->sync);
    policy->strategy = vh::sync::model::RemotePolicy::Strategy::Sync;
    policy->s3_request_budget.max_downloaded_bytes = 41;

    const auto remote = remoteFile("remote-only.txt");
    cloud->s3Map.emplace(remote->path.u8string(), remote);

    EXPECT_THROW(
        (void)vh::sync::Planner::build(cloud, policy),
        vh::storage::s3::RequestBudgetExceeded);
}

TEST(S3CostSafetyTest, BudgetExceededStageMarksEventStalledWithoutGenericError) {
    auto engine = makePlanningEngine();
    auto cloud = std::make_shared<vh::sync::Cloud>(engine);
    cloud->event = std::make_shared<vh::sync::model::Event>();
    cloud->runningFlag = true;

    const vh::sync::Stage stages[] = {
        {"budget", [] {
            throw vh::storage::s3::RequestBudgetExceeded("S3 request budget exceeded for DELETE");
        }}
    };

    cloud->runStages(stages);

    EXPECT_EQ(vh::sync::model::Event::Status::STALLED, cloud->event->status);
    EXPECT_EQ("S3 request budget exceeded for DELETE", cloud->event->stall_reason);
    EXPECT_TRUE(cloud->event->error_message.empty());
}

TEST(S3CostSafetyTest, StaleIndexFailureMarksEventStalledWithoutGenericError) {
    auto engine = makePlanningEngine();
    auto cloud = std::make_shared<vh::sync::Cloud>(engine);
    cloud->event = std::make_shared<vh::sync::model::Event>();
    cloud->runningFlag = true;

    const vh::sync::Stage stages[] = {
        {"freshness", [] {
            throw vh::sync::model::SyncStalled("remote index is stale and manifest refresh failed");
        }}
    };

    cloud->runStages(stages);

    EXPECT_EQ(vh::sync::model::Event::Status::STALLED, cloud->event->status);
    EXPECT_EQ("remote index is stale and manifest refresh failed", cloud->event->stall_reason);
    EXPECT_TRUE(cloud->event->error_message.empty());
}

TEST(S3CostSafetyTest, TerminalStalledEventStatusSurvivesShutdownStatusParsing) {
    vh::sync::model::Event event;
    event.status = vh::sync::model::Event::Status::STALLED;
    event.stall_reason = "S3 price budget would be exceeded";
    event.timestamp_begin = std::time(nullptr) - 10;
    event.timestamp_end = std::time(nullptr);

    event.parseCurrentStatus();

    EXPECT_EQ(vh::sync::model::Event::Status::STALLED, event.status);
    EXPECT_EQ("S3 price budget would be exceeded", event.stall_reason);
    EXPECT_TRUE(event.error_message.empty());
}

TEST(S3CostSafetyTest, PriceBudgetDryRunDoesNotCreateReservations) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed price budget reservation test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("budget_dry_run"));
    saveVaultBudgetPolicyForDbTest(
        vaultId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "10.00000000");

    const auto runUuid = uniqueSuffix("dry-run");
    const auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = runUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("1.00000000"),
        .dry_run = true,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {}
    });

    EXPECT_TRUE(decision.allowed);
    EXPECT_TRUE(decision.reservations.empty());
    EXPECT_EQ(0u, countPriceBudgetLedgerForRunDbTest(runUuid));
}

TEST(S3CostSafetyTest, PriceBudgetBlockedBeforeExecuteDoesNotReserveSpend) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed price budget reservation test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("budget_blocked"));
    saveVaultBudgetPolicyForDbTest(
        vaultId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "0.10000000");

    const auto runUuid = uniqueSuffix("blocked-run");
    const auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = runUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("1.00000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {}
    });

    EXPECT_FALSE(decision.allowed);
    EXPECT_TRUE(decision.stalled);
    EXPECT_TRUE(decision.reservations.empty());
    EXPECT_EQ(0u, countPriceBudgetLedgerForRunDbTest(runUuid));
}

TEST(S3CostSafetyTest, PriceBudgetWarnPolicyWithUnverifiedCatalogDoesNotReserveSpend) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed price budget reservation test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("budget_unverified_warn"));
    saveVaultBudgetPolicyForDbTest(
        vaultId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Warn,
        "10.00000000");

    const auto runUuid = uniqueSuffix("unverified-warn");
    const auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = runUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("1.00000000", false),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {}
    });

    EXPECT_TRUE(decision.allowed);
    ASSERT_FALSE(decision.warnings.empty());
    EXPECT_TRUE(decision.reservations.empty());
    EXPECT_EQ(0u, countPriceBudgetLedgerForRunDbTest(runUuid));
}

TEST(S3CostSafetyTest, PriceBudgetReservationsConstrainSubsequentSharedPolicyChecks) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed price budget concurrency test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("budget_shared"));
    saveVaultBudgetPolicyForDbTest(
        vaultId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "1.00000000");

    vh::storage::s3::pricing::PriceBudgetService service;
    const auto first = service.preflight({
        .vault_id = vaultId,
        .run_uuid = uniqueSuffix("shared-a"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.60000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {}
    });
    ASSERT_TRUE(first.allowed);
    ASSERT_FALSE(first.reservations.empty());

    const auto second = service.preflight({
        .vault_id = vaultId,
        .run_uuid = uniqueSuffix("shared-b"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.60000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {}
    });

    EXPECT_FALSE(second.allowed);
    EXPECT_TRUE(second.stalled);
    EXPECT_TRUE(second.reservations.empty());
}

TEST(S3CostSafetyTest, GatewayCredentialMonthlyBudgetAggregatesAcrossVaults) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed gateway credential price budget test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gateway_key_budget");
    const auto firstVaultId = seedS3VaultForDbTest(suffix + "_a");
    const auto secondVaultId = seedS3VaultForDbTest(suffix + "_b");
    const auto credentialId = seedGatewayCredentialForDbTest(ownerForVaultDbTest(firstVaultId), suffix);
    const auto policy = saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        credentialId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "1.00000000");
    ASSERT_EQ(credentialId, *policy.gateway_credential_id);

    vh::storage::s3::pricing::PriceBudgetService service;
    const auto firstRun = uniqueSuffix("gateway-key-a");
    const auto first = service.preflight({
        .vault_id = firstVaultId,
        .run_uuid = firstRun,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.60000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = firstRun,
        .operation = "PutObject",
        .object_key = "one.bin"
    });
    ASSERT_TRUE(first.allowed);
    ASSERT_FALSE(first.reservations.empty());

    const auto secondRun = uniqueSuffix("gateway-key-b");
    const auto second = service.preflight({
        .vault_id = secondVaultId,
        .run_uuid = secondRun,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.60000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = secondRun,
        .operation = "GetObject",
        .object_key = "two.bin"
    });

    EXPECT_FALSE(second.allowed);
    EXPECT_TRUE(second.stalled);
    EXPECT_TRUE(second.reservations.empty());

    const auto ledger = service.listLedger(10, firstVaultId, credentialId);
    ASSERT_FALSE(ledger.empty());
    EXPECT_EQ(credentialId, ledger.front().gateway_credential_id);
    EXPECT_EQ(firstVaultId, ledger.front().vault_id);
    ASSERT_TRUE(ledger.front().operation);
    EXPECT_EQ("PutObject", *ledger.front().operation);
    ASSERT_TRUE(ledger.front().object_key);
    EXPECT_EQ("one.bin", *ledger.front().object_key);
}

TEST(S3CostSafetyTest, GatewayCredentialVaultMonthlyBudgetCountsOnlyThatPair) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed gateway credential/vault price budget test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gateway_key_vault_budget");
    const auto firstVaultId = seedS3VaultForDbTest(suffix + "_a");
    const auto secondVaultId = seedS3VaultForDbTest(suffix + "_b");
    const auto credentialId = seedGatewayCredentialForDbTest(ownerForVaultDbTest(firstVaultId), suffix);
    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault,
        credentialId,
        firstVaultId,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "1.00000000");
    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault,
        credentialId,
        secondVaultId,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "1.00000000");

    vh::storage::s3::pricing::PriceBudgetService service;
    const auto first = service.preflight({
        .vault_id = firstVaultId,
        .run_uuid = uniqueSuffix("gateway-key-vault-a"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.60000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = uniqueSuffix("gateway-key-vault-a-req"),
        .operation = "PutObject",
        .object_key = "first.bin"
    });
    ASSERT_TRUE(first.allowed);
    ASSERT_FALSE(first.reservations.empty());

    const auto secondVault = service.preflight({
        .vault_id = secondVaultId,
        .run_uuid = uniqueSuffix("gateway-key-vault-b"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.60000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = uniqueSuffix("gateway-key-vault-b-req"),
        .operation = "PutObject",
        .object_key = "second.bin"
    });
    EXPECT_TRUE(secondVault.allowed);
    EXPECT_FALSE(secondVault.reservations.empty());

    const auto firstVaultAgain = service.preflight({
        .vault_id = firstVaultId,
        .run_uuid = uniqueSuffix("gateway-key-vault-a-again"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.60000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = uniqueSuffix("gateway-key-vault-a-again-req"),
        .operation = "PutObject",
        .object_key = "first-again.bin"
    });
    EXPECT_FALSE(firstVaultAgain.allowed);
    EXPECT_TRUE(firstVaultAgain.stalled);
}

TEST(S3CostSafetyTest, GatewayPriceBudgetDecisionRetainsAllBlockingChecksAndPrimary) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed gateway budget blocking-chain test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gateway_blocking_chain");
    const auto vaultId = seedS3VaultForDbTest(suffix);
    const auto credentialId = seedGatewayCredentialForDbTest(ownerForVaultDbTest(vaultId), suffix);
    const auto keyPolicy = saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        credentialId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "0.10000000",
        false);
    const auto vaultPolicy = saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault,
        credentialId,
        vaultId,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "0.10000000",
        false);

    const auto runUuid = uniqueSuffix("gateway-blocking-chain-run");
    const auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = runUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("1.00000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = runUuid + "-request",
        .operation = "PutObject",
        .object_key = "blocking-chain.bin"
    });

    EXPECT_FALSE(decision.allowed);
    EXPECT_TRUE(decision.stalled);
    ASSERT_EQ(2u, decision.blocking_checks.size());
    EXPECT_TRUE(std::ranges::find(decision.blocking_policy_ids, keyPolicy.id) != decision.blocking_policy_ids.end());
    EXPECT_TRUE(std::ranges::find(decision.blocking_policy_ids, vaultPolicy.id) != decision.blocking_policy_ids.end());
    ASSERT_TRUE(decision.primary_blocking_check);
    EXPECT_EQ("monthly", decision.primary_blocking_window);
    EXPECT_EQ(keyPolicy.id, decision.primary_blocking_check->policy_id);
    EXPECT_EQ("gateway_credential", decision.primary_blocking_scope);
}

TEST(S3CostSafetyTest, GatewayPriceBudgetVaultPolicyBlocksEvenWhenCredentialHasRoom) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed gateway budget vault blocker test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gateway_vault_blocks");
    const auto vaultId = seedS3VaultForDbTest(suffix);
    const auto credentialId = seedGatewayCredentialForDbTest(ownerForVaultDbTest(vaultId), suffix);
    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        credentialId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "10.00000000",
        false);
    const auto vaultPolicy = saveGenericBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::Vault,
        std::nullopt,
        vaultId,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "0.10000000");

    const auto runUuid = uniqueSuffix("gateway-vault-blocks-run");
    const auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = runUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("1.00000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = runUuid + "-request",
        .operation = "GetObject",
        .object_key = "vault-blocks.bin"
    });

    EXPECT_FALSE(decision.allowed);
    ASSERT_TRUE(decision.primary_blocking_check);
    EXPECT_EQ(vaultPolicy.id, decision.primary_blocking_check->policy_id);
    EXPECT_EQ("vault", decision.primary_blocking_scope);
    EXPECT_TRUE(decision.reservations.empty());
}

TEST(S3CostSafetyTest, GatewayPriceBudgetProviderPolicyBlocksEvenWhenCredentialVaultHasRoom) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed gateway budget provider blocker test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gateway_provider_blocks");
    const auto vaultId = seedS3VaultForDbTest(suffix);
    const auto credentialId = seedGatewayCredentialForDbTest(ownerForVaultDbTest(vaultId), suffix);
    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault,
        credentialId,
        vaultId,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "10.00000000",
        false);
    const auto providerPolicy = saveGenericBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::Provider,
        "aws-s3",
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "0.10000000");

    const auto runUuid = uniqueSuffix("gateway-provider-blocks-run");
    const auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = runUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("1.00000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = runUuid + "-request",
        .operation = "PutObject",
        .object_key = "provider-blocks.bin"
    });

    EXPECT_FALSE(decision.allowed);
    ASSERT_TRUE(decision.primary_blocking_check);
    EXPECT_EQ(providerPolicy.id, decision.primary_blocking_check->policy_id);
    EXPECT_EQ("provider", decision.primary_blocking_scope);
}

TEST(S3CostSafetyTest, GatewayCredentialWarnBudgetAllowsAndWarns) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed gateway credential warn budget test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gateway_key_warn");
    const auto vaultId = seedS3VaultForDbTest(suffix);
    const auto credentialId = seedGatewayCredentialForDbTest(ownerForVaultDbTest(vaultId), suffix);
    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        credentialId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Warn,
        "0.10000000");

    const auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = uniqueSuffix("gateway-key-warn"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("1.00000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = uniqueSuffix("gateway-key-warn-req"),
        .operation = "GetObject",
        .object_key = "warn.bin"
    });

    EXPECT_TRUE(decision.allowed);
    ASSERT_FALSE(decision.warnings.empty());
    EXPECT_NE(std::string::npos, decision.warnings.front().find("would exceed monthly limit"));
}

TEST(S3CostSafetyTest, S3GatewayWsBudgetPolicyListDisableAndStatusForCredentialScopes) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway WS budget policy test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gateway_ws_budget_policy");
    const auto vaultId = seedS3VaultForDbTest(suffix);
    const auto credentialId = seedGatewayCredentialForDbTest(ownerForVaultDbTest(vaultId), suffix);
    const auto session = superAdminWsSession();

    const auto keyPolicyResponse = vh::protocols::ws::handler::S3Gateway::budgetPolicyUpsert({
        {"scope", "gateway_credential"},
        {"gateway_credential_id", credentialId},
        {"mode", "enforce"},
        {"currency", "USD"},
        {"max_monthly_cost", "2.00000000"},
        {"require_verified_catalog", false}
    }, session);
    ASSERT_TRUE(keyPolicyResponse.contains("policy"));
    EXPECT_EQ("gateway_credential", keyPolicyResponse["policy"]["scope"].get<std::string>());
    EXPECT_EQ(credentialId, keyPolicyResponse["policy"]["gateway_credential_id"].get<std::uint32_t>());

    const auto keyVaultPolicyResponse = vh::protocols::ws::handler::S3Gateway::budgetPolicyUpsert({
        {"scope", "gateway_credential_vault"},
        {"gateway_credential_id", credentialId},
        {"vault_id", vaultId},
        {"mode", "warn"},
        {"currency", "USD"},
        {"max_monthly_cost", "1.00000000"},
        {"require_verified_catalog", false}
    }, session);
    ASSERT_TRUE(keyVaultPolicyResponse.contains("policy"));
    EXPECT_EQ("gateway_credential_vault", keyVaultPolicyResponse["policy"]["scope"].get<std::string>());
    EXPECT_EQ(vaultId, keyVaultPolicyResponse["policy"]["vault_id"].get<std::uint32_t>());

    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::budgetPolicyUpsert({
        {"scope", "vault"},
        {"vault_id", vaultId},
        {"mode", "enforce"},
        {"currency", "USD"},
        {"max_monthly_cost", "3.00000000"},
        {"require_verified_catalog", false}
    }, session), std::exception);
    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::budgetPolicyDisable({
        {"scope", "vault"},
        {"vault_id", vaultId}
    }, session), std::exception);

    vh::storage::s3::pricing::PriceBudgetPolicy genericVaultPolicy;
    genericVaultPolicy.scope = vh::storage::s3::pricing::PriceBudgetScope::Vault;
    genericVaultPolicy.vault_id = vaultId;
    genericVaultPolicy.mode = vh::storage::s3::pricing::PriceBudgetMode::Report;
    genericVaultPolicy.currency = "USD";
    genericVaultPolicy.max_monthly_cost = "3.00000000";
    genericVaultPolicy.require_verified_catalog = false;
    genericVaultPolicy.allow_stale_catalog = false;
    const auto savedGenericVaultPolicy = vh::storage::s3::pricing::PriceBudgetService{}.upsertPolicy(std::move(genericVaultPolicy));
    ASSERT_EQ("vault", vh::storage::s3::pricing::toString(savedGenericVaultPolicy.scope));

    const auto listed = vh::protocols::ws::handler::S3Gateway::budgetPolicyList({
        {"gateway_credential_id", credentialId},
        {"include_inactive", false}
    }, session);
    ASSERT_TRUE(listed.contains("policies"));
    EXPECT_GE(listed["policies"].size(), 2u);
    EXPECT_TRUE(std::ranges::any_of(listed["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == credentialId;
    }));
    EXPECT_TRUE(std::ranges::any_of(listed["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential_vault" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            policy.at("vault_id").get<std::uint32_t>() == vaultId;
    }));
    EXPECT_TRUE(std::ranges::none_of(listed["policies"], [](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "vault";
    }));

    const auto runUuid = uniqueSuffix("gateway-ws-budget-ledger");
    auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = runUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.25000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = runUuid + "-request",
        .operation = "PutObject",
        .object_key = "ws-managed.bin"
    });
    ASSERT_TRUE(decision.allowed) << decision.reason;
    ASSERT_FALSE(decision.reservations.empty());
    vh::storage::s3::pricing::PriceBudgetService{}.commit(decision.reservations, "0.25000000");

    const auto genericRunUuid = uniqueSuffix("gateway-ws-generic-ledger");
    auto genericDecision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = genericRunUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.12500000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {}
    });
    ASSERT_TRUE(genericDecision.allowed) << genericDecision.reason;
    ASSERT_FALSE(genericDecision.reservations.empty());
    vh::storage::s3::pricing::PriceBudgetService{}.commit(genericDecision.reservations, "0.12500000");

    const auto status = vh::protocols::ws::handler::S3Gateway::budgetStatus({
        {"gateway_credential_id", credentialId},
        {"vault_id", vaultId},
        {"limit", 10}
    }, session);
    ASSERT_TRUE(status.contains("policies"));
    ASSERT_TRUE(status.contains("ledger"));
    ASSERT_TRUE(status.contains("trends"));
    EXPECT_TRUE(std::ranges::any_of(status["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == credentialId;
    }));
    EXPECT_TRUE(std::ranges::any_of(status["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential_vault" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            policy.at("vault_id").get<std::uint32_t>() == vaultId;
    }));
    EXPECT_TRUE(std::ranges::any_of(status["ledger"], [&](const nlohmann::json& row) {
        return row.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            row.at("vault_id").get<std::uint32_t>() == vaultId &&
            row.at("operation").get<std::string>() == "PutObject" &&
            row.at("status").get<std::string>() == "committed";
    }));
    EXPECT_TRUE(std::ranges::any_of(status["trends"], [&](const nlohmann::json& trend) {
        if (!trend.contains("gateway_credential_id") || trend.at("gateway_credential_id").is_null()) return false;
        return trend.at("scope").get<std::string>() == "gateway_credential" &&
            trend.at("window_type").get<std::string>() == "monthly" &&
            trend.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            trend.at("total_cost").get<std::string>() == "0.25000000" &&
            trend.at("remaining").get<std::string>() == "1.75000000";
    }));
    EXPECT_TRUE(std::ranges::any_of(status["trends"], [&](const nlohmann::json& trend) {
        if (!trend.contains("gateway_credential_id") || trend.at("gateway_credential_id").is_null()) return false;
        if (!trend.contains("vault_id") || trend.at("vault_id").is_null()) return false;
        return trend.at("scope").get<std::string>() == "gateway_credential_vault" &&
            trend.at("window_type").get<std::string>() == "monthly" &&
            trend.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            trend.at("vault_id").get<std::uint32_t>() == vaultId &&
            trend.at("total_cost").get<std::string>() == "0.25000000" &&
            trend.at("remaining").get<std::string>() == "0.75000000";
    }));

    const auto vaultOnlyStatus = vh::protocols::ws::handler::S3Gateway::budgetStatus({
        {"vault_id", vaultId},
        {"limit", 20}
    }, session);
    EXPECT_TRUE(std::ranges::none_of(vaultOnlyStatus["policies"], [](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "vault";
    }));
    EXPECT_TRUE(std::ranges::none_of(vaultOnlyStatus["ledger"], [&](const nlohmann::json& row) {
        if (!row.contains("run_uuid") || row.at("run_uuid").is_null()) return false;
        return row.at("run_uuid").get<std::string>() == genericRunUuid;
    }));
    EXPECT_TRUE(std::ranges::none_of(vaultOnlyStatus["trends"], [](const nlohmann::json& trend) {
        return trend.at("scope").get<std::string>() == "vault";
    }));
    EXPECT_TRUE(std::ranges::any_of(vaultOnlyStatus["trends"], [&](const nlohmann::json& trend) {
        if (!trend.contains("gateway_credential_id") || trend.at("gateway_credential_id").is_null()) return false;
        if (!trend.contains("vault_id") || trend.at("vault_id").is_null()) return false;
        return trend.at("scope").get<std::string>() == "gateway_credential_vault" &&
            trend.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            trend.at("vault_id").get<std::uint32_t>() == vaultId &&
            trend.at("total_cost").get<std::string>() == "0.25000000";
    }));

    const auto disabled = vh::protocols::ws::handler::S3Gateway::budgetPolicyDisable({
        {"scope", "gateway_credential_vault"},
        {"gateway_credential_id", credentialId},
        {"vault_id", vaultId}
    }, session);
    EXPECT_TRUE(disabled.at("disabled").get<bool>());

    const auto listedActive = vh::protocols::ws::handler::S3Gateway::budgetPolicyList({
        {"gateway_credential_id", credentialId},
        {"vault_id", vaultId},
        {"include_inactive", false}
    }, session);
    EXPECT_TRUE(std::ranges::any_of(listedActive["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == credentialId;
    }));
    EXPECT_TRUE(std::ranges::none_of(listedActive["policies"], [](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential_vault";
    }));
}

// Stage 0 S5: pricing.budget.status with only an owned gateway_credential_id (no vault_id) used to return the
// system-wide notification and override lists (listNotifications/listOverrides with vault_id = nullopt) to any
// credential owner. Non-super-admins now only get rows for vaults they can view.
TEST(S3CostSafetyTest, GenericPricingWsCredentialStatusDoesNotLeakOtherVaultsNotificationsOrOverrides) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed pricing status leak test due to missing environment variables.";
    ensureDbReady();

    const auto ownVaultId = seedS3VaultForDbTest(uniqueSuffix("status_leak_own"));
    const auto foreignVaultId = seedS3VaultForDbTest(uniqueSuffix("status_leak_foreign"));
    const auto ownerId = ownerForVaultDbTest(ownVaultId);
    const auto foreignOwnerId = ownerForVaultDbTest(foreignVaultId);
    ASSERT_NE(ownerId, foreignOwnerId);
    const auto credentialId = seedGatewayCredentialForDbTest(ownerId, uniqueSuffix("status_leak_cred"));

    vh::storage::s3::pricing::PriceBudgetService service;
    const auto makeNotification = [&](const std::uint32_t vaultId, const std::string& title) {
        vh::storage::s3::pricing::PriceBudgetNotification notification;
        notification.type = "budget.warn_threshold";
        notification.severity = "warning";
        notification.title = title;
        notification.message = title;
        notification.vault_id = vaultId;
        return service.createNotification(std::move(notification));
    };
    const auto ownNotification = makeNotification(ownVaultId, "status leak own vault");
    const auto foreignNotification = makeNotification(foreignVaultId, "status leak foreign vault");

    const auto foreignPolicy = saveVaultBudgetPolicyForDbTest(
        foreignVaultId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "0.10000000");
    const auto foreignOverride = service.requestOverride({
        .run_uuid = uniqueSuffix("status-leak-run"),
        .vault_id = foreignVaultId,
        .requested_by = foreignOwnerId,
        .reason = "status leak regression",
        .policy_ids = {foreignPolicy.id},
        .estimated_cost = "1.00000000",
        .currency = "USD",
        .ttl_minutes = 30
    });

    const auto status = vh::protocols::ws::handler::Pricing::status({
        {"gateway_credential_id", credentialId}
    }, wsSessionForUser(ownerId));

    ASSERT_TRUE(status.contains("notifications"));
    ASSERT_TRUE(status.contains("overrides"));
    EXPECT_TRUE(std::ranges::none_of(status["notifications"], [&](const nlohmann::json& row) {
        return row.at("id").get<std::uint32_t>() == foreignNotification.id;
    })) << "credential owner saw another vault's budget notification";
    EXPECT_TRUE(std::ranges::none_of(status["overrides"], [&](const nlohmann::json& row) {
        return row.at("id").get<std::uint32_t>() == foreignOverride.id;
    })) << "credential owner saw another vault's budget override";
    EXPECT_TRUE(std::ranges::all_of(status["notifications"], [&](const nlohmann::json& row) {
        return row.contains("vault_id") && !row.at("vault_id").is_null() &&
            row.at("vault_id").get<std::uint32_t>() == ownVaultId;
    }));
    EXPECT_TRUE(std::ranges::any_of(status["notifications"], [&](const nlohmann::json& row) {
        return row.at("id").get<std::uint32_t>() == ownNotification.id;
    })) << "owner's own vault notification should stay visible";
}

TEST(S3CostSafetyTest, GenericPricingWsGatewayCredentialStatusFiltersPoliciesAndTrends) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed generic pricing WS gateway credential filter test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gw_ws_generic_filter");
    const auto vaultId = seedS3VaultForDbTest(suffix);
    const auto otherVaultId = seedS3VaultForDbTest(uniqueSuffix("gw_ws_generic_filter_other_vault"));
    const auto ownerId = ownerForVaultDbTest(vaultId);
    const auto credentialId = seedGatewayCredentialForDbTest(ownerId, uniqueSuffix("gw_gen_a"));
    const auto otherCredentialId = seedGatewayCredentialForDbTest(ownerId, uniqueSuffix("gw_gen_b"));
    const auto ownerSession = wsSessionForUser(ownerId);

    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        credentialId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Report,
        "3.00000000",
        false);
    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault,
        credentialId,
        vaultId,
        vh::storage::s3::pricing::PriceBudgetMode::Report,
        "2.00000000",
        false);
    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault,
        credentialId,
        otherVaultId,
        vh::storage::s3::pricing::PriceBudgetMode::Report,
        "2.00000000",
        false);
    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        otherCredentialId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Report,
        "3.00000000",
        false);
    saveGatewayBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault,
        otherCredentialId,
        vaultId,
        vh::storage::s3::pricing::PriceBudgetMode::Report,
        "2.00000000",
        false);

    const auto runUuid = uniqueSuffix("gw-generic-filter-primary");
    auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = runUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.25000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = runUuid + "-request",
        .operation = "PutObject",
        .object_key = "generic-filter-primary.bin"
    });
    ASSERT_TRUE(decision.allowed) << decision.reason;
    ASSERT_FALSE(decision.reservations.empty());
    vh::storage::s3::pricing::PriceBudgetService{}.commit(decision.reservations, "0.25000000");

    const auto otherRunUuid = uniqueSuffix("gw-generic-filter-other");
    auto otherDecision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = otherRunUuid,
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.75000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = otherCredentialId,
        .request_uuid = otherRunUuid + "-request",
        .operation = "GetObject",
        .object_key = "generic-filter-other.bin"
    });
    ASSERT_TRUE(otherDecision.allowed) << otherDecision.reason;
    ASSERT_FALSE(otherDecision.reservations.empty());
    vh::storage::s3::pricing::PriceBudgetService{}.commit(otherDecision.reservations, "0.75000000");

    const auto listed = vh::protocols::ws::handler::Pricing::policyList({
        {"gateway_credential_id", credentialId},
        {"include_inactive", false}
    }, ownerSession);
    ASSERT_TRUE(listed.contains("policies"));
    EXPECT_TRUE(std::ranges::any_of(listed["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == credentialId;
    }));
    EXPECT_TRUE(std::ranges::any_of(listed["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential_vault" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            policy.at("vault_id").get<std::uint32_t>() == vaultId;
    }));
    EXPECT_TRUE(std::ranges::none_of(listed["policies"], [&](const nlohmann::json& policy) {
        return policy.contains("gateway_credential_id") &&
            !policy.at("gateway_credential_id").is_null() &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == otherCredentialId;
    }));
    const auto vaultScopedListed = vh::protocols::ws::handler::Pricing::policyList({
        {"gateway_credential_id", credentialId},
        {"vault_id", vaultId},
        {"include_inactive", false}
    }, ownerSession);
    EXPECT_TRUE(std::ranges::none_of(vaultScopedListed["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential_vault" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            policy.at("vault_id").get<std::uint32_t>() == otherVaultId;
    }));

    const auto status = vh::protocols::ws::handler::Pricing::status({
        {"gateway_credential_id", credentialId},
        {"vault_id", vaultId},
        {"limit", 20}
    }, ownerSession);
    ASSERT_TRUE(status.contains("policies"));
    ASSERT_TRUE(status.contains("ledger"));
    ASSERT_TRUE(status.contains("trends"));
    EXPECT_TRUE(std::ranges::any_of(status["ledger"], [&](const nlohmann::json& row) {
        return row.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            row.at("run_uuid").get<std::string>() == runUuid;
    }));
    EXPECT_TRUE(std::ranges::none_of(status["ledger"], [&](const nlohmann::json& row) {
        return row.contains("gateway_credential_id") &&
            !row.at("gateway_credential_id").is_null() &&
            row.at("gateway_credential_id").get<std::uint32_t>() == otherCredentialId;
    }));
    EXPECT_TRUE(std::ranges::any_of(status["trends"], [&](const nlohmann::json& trend) {
        if (!trend.contains("gateway_credential_id") || trend.at("gateway_credential_id").is_null()) return false;
        return trend.at("scope").get<std::string>() == "gateway_credential" &&
            trend.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            trend.at("total_cost").get<std::string>() == "0.25000000";
    }));
    EXPECT_TRUE(std::ranges::any_of(status["trends"], [&](const nlohmann::json& trend) {
        if (!trend.contains("gateway_credential_id") || trend.at("gateway_credential_id").is_null()) return false;
        if (!trend.contains("vault_id") || trend.at("vault_id").is_null()) return false;
        return trend.at("scope").get<std::string>() == "gateway_credential_vault" &&
            trend.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            trend.at("vault_id").get<std::uint32_t>() == vaultId &&
            trend.at("total_cost").get<std::string>() == "0.25000000";
    }));
    EXPECT_TRUE(std::ranges::none_of(status["trends"], [&](const nlohmann::json& trend) {
        return trend.contains("gateway_credential_id") &&
            !trend.at("gateway_credential_id").is_null() &&
            trend.at("gateway_credential_id").get<std::uint32_t>() == otherCredentialId;
    }));
}

TEST(S3CostSafetyTest, S3GatewayWsNonAdminCredentialManagementIsScopedToPrincipal) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway WS credential permission test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gw_ws_cred");
    const auto actorUserId = seedS3CostUserForDbTest(suffix, "actor");
    const auto otherUserId = seedS3CostUserForDbTest(suffix, "other");
    const auto actorSession = wsSessionForUser(actorUserId);

    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::credentialsCreate({
        {"name", "cross-user-" + suffix},
        {"principal_user_id", otherUserId},
        {"scope_mode", "user_access"}
    }, actorSession), std::exception);

    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::credentialsCreate({
        {"name", "global-" + suffix},
        {"scope_mode", "global"}
    }, actorSession), std::exception);

    const auto noAssignAdminUserId = seedS3CostVaultAdminUserForDbTest(suffix, "no_assign");
    const auto noAssignAdminSession = wsSessionForUser(
        noAssignAdminUserId,
        vh::rbac::role::Admin::VaultAdmin(noAssignAdminUserId));
    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::credentialsCreate({
        {"name", "cross-user-admin-no-assign-" + suffix},
        {"principal_user_id", otherUserId},
        {"scope_mode", "user_access"}
    }, noAssignAdminSession), std::exception);

    const auto otherCredentialId = seedGatewayCredentialForDbTest(otherUserId, "other_" + suffix);
    const auto otherCredentialSelector = std::to_string(otherCredentialId);
    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::credentialsScopeUpdate({
        {"access_key", otherCredentialSelector},
        {"scope_mode", "user_access"}
    }, actorSession), std::exception);
    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::credentialsRevoke({
        {"access_key", otherCredentialSelector}
    }, actorSession), std::exception);

    const auto otherCredential = gatewayCredentialByIdForDbTest(otherCredentialId);
    ASSERT_TRUE(otherCredential.has_value());
    EXPECT_TRUE(otherCredential->enabled);
    EXPECT_EQ(otherUserId, otherCredential->principal_user_id);

    const auto ownedCredentialId = seedGatewayCredentialForDbTest(actorUserId, suffix + "_owned");
    const auto adminUserId = seedS3CostSuperAdminUserForDbTest(suffix, "scope_admin");
    const auto adminSession = wsSessionForUser(adminUserId, vh::rbac::role::Admin::SuperAdmin(adminUserId));
    const auto globalUpdate = vh::protocols::ws::handler::S3Gateway::credentialsScopeUpdate({
        {"access_key", std::to_string(ownedCredentialId)},
        {"scope_mode", "global"},
        {"principal_user_id", adminSession->user->id},
        {"default_vault_role_id", s3CostVaultRoleIdByName("reader")}
    }, adminSession);
    ASSERT_TRUE(globalUpdate.contains("credential"));

    const auto globalCredential = gatewayCredentialByIdForDbTest(ownedCredentialId);
    ASSERT_TRUE(globalCredential.has_value());
    EXPECT_EQ("global", globalCredential->scope_mode);
    EXPECT_EQ(adminSession->user->id, globalCredential->principal_user_id);
    ASSERT_TRUE(globalCredential->created_by);
    EXPECT_EQ(adminSession->user->id, *globalCredential->created_by);
    EXPECT_FALSE(vh::protocols::s3::ObjectStore::credentialAllows(
        vh::protocols::s3::AuthContext{
            .user = adminSession->user,
            .credential = *globalCredential,
            .credential_id = globalCredential->id,
            .access_key = globalCredential->access_key,
            .scope_mode = globalCredential->scope_mode,
            .dev_context = false
        },
        0,
        vh::rbac::permission::vault::FilesystemAction::Write));
}

TEST(S3CostSafetyTest, S3GatewayWsNonAdminBudgetManagementRequiresVaultAuthority) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway WS budget permission test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gateway_ws_non_admin_budget");
    const auto vaultId = seedS3VaultForDbTest(suffix);
    const auto ownerId = ownerForVaultDbTest(vaultId);
    const auto outsiderId = seedS3CostUserForDbTest(suffix, "outsider");
    const auto ownerCredentialId = seedGatewayCredentialForDbTest(ownerId, suffix + "_owner");
    const auto ownerSession = wsSessionForUser(ownerId);
    const auto budgetOwnerSession = wsSessionForUser(ownerId, s3GatewayBudgetManagerRole(ownerId));
    const auto outsiderSession = wsSessionForUser(outsiderId);
    const auto adminSession = superAdminWsSession();

    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::budgetPolicyUpsert({
        {"scope", "gateway_credential"},
        {"gateway_credential_id", ownerCredentialId},
        {"mode", "enforce"},
        {"currency", "USD"},
        {"max_monthly_cost", "1.00000000"},
        {"require_verified_catalog", false}
    }, ownerSession), std::exception);
    EXPECT_THROW(vh::protocols::ws::handler::Pricing::policyUpsert({
        {"scope", "gateway_credential"},
        {"gateway_credential_id", ownerCredentialId},
        {"mode", "enforce"},
        {"currency", "USD"},
        {"max_monthly_cost", "1.00000000"},
        {"require_verified_catalog", false}
    }, ownerSession), std::exception);
    EXPECT_THROW(vh::protocols::ws::handler::Pricing::policyDisable({
        {"scope", "gateway_credential"},
        {"gateway_credential_id", ownerCredentialId}
    }, ownerSession), std::exception);

    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::budgetPolicyUpsert({
        {"scope", "gateway_credential_vault"},
        {"gateway_credential_id", ownerCredentialId},
        {"vault_id", vaultId},
        {"mode", "enforce"},
        {"currency", "USD"},
        {"max_monthly_cost", "1.00000000"},
        {"require_verified_catalog", false}
    }, ownerSession), std::exception);

    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::budgetPolicyDisable({
        {"scope", "gateway_credential_vault"},
        {"gateway_credential_id", ownerCredentialId},
        {"vault_id", vaultId}
    }, ownerSession), std::exception);

    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::budgetPolicyUpsert({
        {"scope", "gateway_credential_vault"},
        {"gateway_credential_id", ownerCredentialId},
        {"vault_id", vaultId},
        {"mode", "enforce"},
        {"currency", "USD"},
        {"max_monthly_cost", "1.00000000"},
        {"require_verified_catalog", false}
    }, outsiderSession), std::exception);

    const auto keyPolicyResponse = vh::protocols::ws::handler::S3Gateway::budgetPolicyUpsert({
        {"scope", "gateway_credential"},
        {"gateway_credential_id", ownerCredentialId},
        {"mode", "enforce"},
        {"currency", "USD"},
        {"max_monthly_cost", "1.00000000"},
        {"require_verified_catalog", false}
    }, adminSession);
    ASSERT_TRUE(keyPolicyResponse.contains("policy"));

    EXPECT_THROW(vh::protocols::ws::handler::S3Gateway::budgetPolicyDisable({
        {"scope", "gateway_credential"},
        {"gateway_credential_id", ownerCredentialId}
    }, ownerSession), std::exception);

    const auto keyVaultPolicyResponse = vh::protocols::ws::handler::S3Gateway::budgetPolicyUpsert({
        {"scope", "gateway_credential_vault"},
        {"gateway_credential_id", ownerCredentialId},
        {"vault_id", vaultId},
        {"mode", "enforce"},
        {"currency", "USD"},
        {"max_monthly_cost", "0.50000000"},
        {"require_verified_catalog", false}
    }, budgetOwnerSession);
    ASSERT_TRUE(keyVaultPolicyResponse.contains("policy"));
    EXPECT_EQ("gateway_credential_vault", keyVaultPolicyResponse["policy"]["scope"].get<std::string>());
    EXPECT_EQ(vaultId, keyVaultPolicyResponse["policy"]["vault_id"].get<std::uint32_t>());

    const auto disabled = vh::protocols::ws::handler::S3Gateway::budgetPolicyDisable({
        {"scope", "gateway_credential_vault"},
        {"gateway_credential_id", ownerCredentialId},
        {"vault_id", vaultId}
    }, budgetOwnerSession);
    EXPECT_TRUE(disabled.at("disabled").get<bool>());
}

TEST(S3CostSafetyTest, S3GatewayCliBudgetStatusJsonAndKeyOnlyAuthorization) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway CLI budget test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gw_cli_bud");
    const auto vaultId = seedS3VaultForDbTest(suffix);
    attachS3ProviderForDbTest(vaultId, "AWS");
    const auto ownerId = ownerForVaultDbTest(vaultId);
    const auto otherUserId = seedS3CostUserForDbTest(suffix, "other_credential_owner");
    const auto credentialId = seedGatewayCredentialForDbTest(ownerId, suffix + "_owner");
    const auto otherCredentialId = seedGatewayCredentialForDbTest(otherUserId, suffix + "_other");
    const auto router = s3GatewayShellRouterForDbTest();
    const auto owner = dryRunActor(ownerId, vh::rbac::role::Admin::None(ownerId));
    const auto budgetOwner = dryRunActor(ownerId, s3GatewayBudgetManagerRole(ownerId));
    const auto admin = superAdminWsSession()->user;
    const auto credentialArg = std::to_string(credentialId);
    const auto vaultArg = std::to_string(vaultId);

    const auto deniedSetKey = router->executeLine(
        "s3-gateway budget set-key " + credentialArg + " --monthly 2.00000000 --mode enforce",
        owner);
    EXPECT_NE(0, deniedSetKey.exit_code);
    EXPECT_NE(std::string::npos, deniedSetKey.stderr_text.find("admin.s3_gateway.manage_budgets"));

    const auto adminSetKey = router->executeLine(
        "s3-gateway budget set-key " + credentialArg + " --monthly 2.00000000 --mode enforce --currency USD",
        admin);
    ASSERT_EQ(0, adminSetKey.exit_code) << adminSetKey.stderr_text;

    const auto ownerSetKeyVaultDenied = router->executeLine(
        "s3-gateway budget set-key-vault " + credentialArg + " --vault " + vaultArg +
            " --monthly 1.00000000 --mode warn --currency USD",
        owner);
    EXPECT_NE(0, ownerSetKeyVaultDenied.exit_code);
    EXPECT_NE(std::string::npos, ownerSetKeyVaultDenied.stderr_text.find("admin.s3_gateway.manage_budgets"));

    const auto budgetOwnerSetKeyVault = router->executeLine(
        "s3-gateway budget set-key-vault " + credentialArg + " --vault " + vaultArg +
            " --monthly 1.00000000 --mode warn --currency USD",
        budgetOwner);
    ASSERT_EQ(0, budgetOwnerSetKeyVault.exit_code) << budgetOwnerSetKeyVault.stderr_text;

    const auto budgetOwnerSetOtherKeyVault = router->executeLine(
        "s3-gateway budget set-key-vault " + std::to_string(otherCredentialId) + " --vault " + vaultArg +
            " --monthly 0.50000000 --mode enforce --currency USD",
        budgetOwner);
    ASSERT_EQ(0, budgetOwnerSetOtherKeyVault.exit_code) << budgetOwnerSetOtherKeyVault.stderr_text;

    const auto ownerOtherStatus = router->executeLine(
        "s3-gateway budget status --key " + std::to_string(otherCredentialId) + " --vault " + vaultArg + " --json",
        owner);
    ASSERT_EQ(0, ownerOtherStatus.exit_code) << ownerOtherStatus.stderr_text;
    const auto parsedOwnerOtherStatus = nlohmann::json::parse(ownerOtherStatus.stdout_text);
    EXPECT_TRUE(std::ranges::any_of(parsedOwnerOtherStatus["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential_vault" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == otherCredentialId &&
            policy.at("vault_id").get<std::uint32_t>() == vaultId;
    }));
    EXPECT_TRUE(std::ranges::none_of(parsedOwnerOtherStatus["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == otherCredentialId;
    }));

    const auto ownerDisableOtherKeyVault = router->executeLine(
        "s3-gateway budget disable-key-vault " + std::to_string(otherCredentialId) + " --vault " + vaultArg,
        budgetOwner);
    ASSERT_EQ(0, ownerDisableOtherKeyVault.exit_code) << ownerDisableOtherKeyVault.stderr_text;

    auto decision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = uniqueSuffix("gateway-cli-budget-ledger"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.25000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = credentialId,
        .request_uuid = uniqueSuffix("gateway-cli-budget-request"),
        .operation = "PutObject",
        .object_key = "cli-managed.bin"
    });
    ASSERT_TRUE(decision.allowed) << decision.reason;
    ASSERT_FALSE(decision.reservations.empty());
    vh::storage::s3::pricing::PriceBudgetService{}.commit(decision.reservations, "0.25000000");

    const auto genericPolicy = saveVaultBudgetPolicyForDbTest(
        vaultId,
        "aws-s3",
        vh::storage::s3::pricing::PriceBudgetMode::Report,
        "3.00000000",
        false);
    ASSERT_EQ(vaultId, *genericPolicy.vault_id);
    auto genericDecision = vh::storage::s3::pricing::PriceBudgetService{}.preflight({
        .vault_id = vaultId,
        .run_uuid = uniqueSuffix("gateway-cli-generic-ledger"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("0.12500000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {}
    });
    ASSERT_TRUE(genericDecision.allowed) << genericDecision.reason;
    ASSERT_FALSE(genericDecision.reservations.empty());
    vh::storage::s3::pricing::PriceBudgetService{}.commit(genericDecision.reservations, "0.12500000");

    const auto status = router->executeLine(
        "s3-gateway budget status --key " + credentialArg + " --vault " + vaultArg + " --limit 10 --json",
        admin);
    ASSERT_EQ(0, status.exit_code) << status.stderr_text;
    const auto parsed = nlohmann::json::parse(status.stdout_text);
    ASSERT_TRUE(parsed.contains("policies"));
    ASSERT_TRUE(parsed.contains("ledger"));
    ASSERT_TRUE(parsed.contains("trends"));
    EXPECT_TRUE(std::ranges::any_of(parsed["policies"], [&](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "gateway_credential" &&
            policy.at("gateway_credential_id").get<std::uint32_t>() == credentialId;
    }));
    EXPECT_TRUE(std::ranges::any_of(parsed["trends"], [&](const nlohmann::json& trend) {
        if (!trend.contains("gateway_credential_id") || trend.at("gateway_credential_id").is_null()) return false;
        return trend.at("scope").get<std::string>() == "gateway_credential" &&
            trend.at("window_type").get<std::string>() == "monthly" &&
            trend.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            trend.at("total_cost").get<std::string>() == "0.25000000";
    }));
    EXPECT_TRUE(std::ranges::any_of(parsed["trends"], [&](const nlohmann::json& trend) {
        if (!trend.contains("gateway_credential_id") || trend.at("gateway_credential_id").is_null()) return false;
        if (!trend.contains("vault_id") || trend.at("vault_id").is_null()) return false;
        return trend.at("scope").get<std::string>() == "gateway_credential_vault" &&
            trend.at("window_type").get<std::string>() == "monthly" &&
            trend.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            trend.at("vault_id").get<std::uint32_t>() == vaultId &&
            trend.at("remaining").get<std::string>() == "0.75000000";
    }));

    const auto vaultOnlyStatus = router->executeLine(
        "s3-gateway budget status --vault " + vaultArg + " --limit 20 --json",
        admin);
    ASSERT_EQ(0, vaultOnlyStatus.exit_code) << vaultOnlyStatus.stderr_text;
    const auto parsedVaultOnly = nlohmann::json::parse(vaultOnlyStatus.stdout_text);
    EXPECT_TRUE(std::ranges::none_of(parsedVaultOnly["policies"], [](const nlohmann::json& policy) {
        return policy.at("scope").get<std::string>() == "vault";
    }));
    EXPECT_TRUE(std::ranges::none_of(parsedVaultOnly["ledger"], [](const nlohmann::json& row) {
        return !row.contains("gateway_credential_id") || row.at("gateway_credential_id").is_null();
    }));
    EXPECT_TRUE(std::ranges::none_of(parsedVaultOnly["trends"], [](const nlohmann::json& trend) {
        return trend.at("scope").get<std::string>() == "vault";
    }));
    EXPECT_TRUE(std::ranges::any_of(parsedVaultOnly["trends"], [&](const nlohmann::json& trend) {
        if (!trend.contains("gateway_credential_id") || trend.at("gateway_credential_id").is_null()) return false;
        if (!trend.contains("vault_id") || trend.at("vault_id").is_null()) return false;
        return trend.at("scope").get<std::string>() == "gateway_credential_vault" &&
            trend.at("gateway_credential_id").get<std::uint32_t>() == credentialId &&
            trend.at("vault_id").get<std::uint32_t>() == vaultId &&
            trend.at("total_cost").get<std::string>() == "0.25000000";
    }));

    const auto vaultOnlyLedger = router->executeLine(
        "s3-gateway budget ledger --vault " + vaultArg + " --limit 20 --json",
        admin);
    ASSERT_EQ(0, vaultOnlyLedger.exit_code) << vaultOnlyLedger.stderr_text;
    const auto parsedVaultOnlyLedger = nlohmann::json::parse(vaultOnlyLedger.stdout_text);
    EXPECT_TRUE(std::ranges::none_of(parsedVaultOnlyLedger, [](const nlohmann::json& row) {
        return !row.contains("gateway_credential_id") || row.at("gateway_credential_id").is_null();
    }));

    const auto ownerDisableKey = router->executeLine(
        "s3-gateway budget disable-key " + credentialArg,
        owner);
    EXPECT_NE(0, ownerDisableKey.exit_code);
    EXPECT_NE(std::string::npos, ownerDisableKey.stderr_text.find("admin.s3_gateway.manage_budgets"));
}

TEST(S3CostSafetyTest, S3GatewayCliScopeSetRetargetsPrincipalAndAuditsGlobalConversion) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway CLI scope test due to missing environment variables.";
    ensureDbReady();

    const auto suffix = uniqueSuffix("gw_cli_scope");
    const auto ownerId = seedS3CostUserForDbTest(suffix, "owner");
    const auto credentialId = seedGatewayCredentialForDbTest(ownerId, suffix + "_owned");
    const auto router = s3GatewayShellRouterForDbTest();
    const auto noAssignAdminUserId = seedS3CostVaultAdminUserForDbTest(suffix, "cli_no_assign");
    const auto noAssignAdmin = dryRunActor(noAssignAdminUserId, vh::rbac::role::Admin::VaultAdmin(noAssignAdminUserId));
    const auto denied = router->executeLine(
        "s3-gateway creds create cli-no-assign-" + suffix + " --user " + std::to_string(ownerId),
        noAssignAdmin);
    EXPECT_NE(0, denied.exit_code);
    EXPECT_NE(std::string::npos, denied.stderr_text.find("admin.s3_gateway.assign_principal"));

    const auto adminUserId = seedS3CostSuperAdminUserForDbTest(suffix, "scope_admin");
    const auto admin = dryRunActor(adminUserId, vh::rbac::role::Admin::SuperAdmin(adminUserId));
    const auto credentialArg = std::to_string(credentialId);

    (void)s3CostVaultRoleIdByName("reader");
    const auto result = router->executeLine(
        "s3-gateway creds scope " + credentialArg + " set --scope global --user " + std::to_string(admin->id) + " --role reader",
        admin);
    ASSERT_EQ(0, result.exit_code) << result.stderr_text;

    const auto updated = gatewayCredentialByIdForDbTest(credentialId);
    ASSERT_TRUE(updated.has_value());
    EXPECT_EQ("global", updated->scope_mode);
    EXPECT_EQ(admin->id, updated->principal_user_id);
    ASSERT_TRUE(updated->created_by);
    EXPECT_EQ(admin->id, *updated->created_by);
    EXPECT_FALSE(vh::protocols::s3::ObjectStore::credentialAllows(
        vh::protocols::s3::AuthContext{
            .user = admin,
            .credential = *updated,
            .credential_id = updated->id,
            .access_key = updated->access_key,
            .scope_mode = updated->scope_mode,
            .dev_context = false
        },
        0,
        vh::rbac::permission::vault::FilesystemAction::Write));
}

TEST(S3CostSafetyTest, GatewayRemotePutLocalFirstDoesNotCommitCredentialBudgetByDefault) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-put-budget",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");

    auto request = signedGatewayRouteRequest(
        http::verb::put,
        "/" + fixture.bucket_name + "/put-object.txt",
        fixture.secret,
        "payload");

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_EQ(0, fixture.controller->upload_buffer_with_metadata_calls);
    EXPECT_TRUE(vh::db::query::fs::File::getFileByPath(fixture.vault_id, "/put-object.txt"));
    ASSERT_TRUE(vh::db::query::s3::Gateway::getObjectState(fixture.vault_id, "put-object.txt"));
    EXPECT_EQ(1u, countGatewaySyncOriginForDbTest(fixture.vault_id, "put-object.txt", "put"));
    expectGatewayLedgerAbsent(fixture, "PutObject", "put-object.txt");
}

TEST(S3CostSafetyTest, GatewayRemoteGetRoutePreflightsAndCommitsCredentialVaultBudget) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-get-budget",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault,
        "1.00000000");
    constexpr std::string_view objectKey = "remote-get.txt";
    fixture.controller->download_payload = {'r', 'e', 'm', 'o', 't', 'e'};
    fixture.controller->head_response = std::unordered_map<std::string, std::string>{
        {"x-amz-meta-vh-encrypted", "false"}
    };
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = fixture.vault_id,
        .object_key = std::string(objectKey),
        .etag = "\"remote-get-etag\"",
        .size_bytes = fixture.controller->download_payload.size(),
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });

    auto request = signedGatewayRouteRequest(
        http::verb::get,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_EQ("remote", response.body());
    EXPECT_EQ(1, fixture.controller->download_to_buffer_calls);
    expectGatewayLedgerCommitted(fixture, "GetObject", std::string(objectKey), false, "remote_download");
}

TEST(S3CostSafetyTest, GatewayRemoteGetPriceBudgetDeniedReturnsXmlAccessDeniedBeforeRemoteDownload) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-get-price-budget-denied",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "0.00000000");
    constexpr std::string_view objectKey = "price-budget-get.txt";
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = fixture.vault_id,
        .object_key = std::string(objectKey),
        .etag = "\"price-budget-get\"",
        .size_bytes = 128,
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });

    auto request = signedGatewayRouteRequest(
        http::verb::get,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::forbidden);
    EXPECT_NE(std::string::npos, response.body().find("<Code>AccessDenied</Code>"));
    EXPECT_NE(std::string::npos, response.body().find("S3 gateway price budget exceeded"));
    EXPECT_NE(std::string::npos, response.body().find("operation=GetObject"));
    EXPECT_NE(std::string::npos, response.body().find("provider_key=aws-s3"));
    EXPECT_EQ(0, fixture.controller->download_to_buffer_calls);
    expectGatewayLedgerAbsent(fixture, "GetObject", std::string(objectKey));
}

TEST(S3CostSafetyTest, GatewayRemoteListDoesNotConsumeRequestOrPriceBudgetByDefault) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-list-no-budget",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "0.00000100");
    setGatewayRouteRequestBudget(fixture, [](auto& budget) {
        budget.max_list_requests = 0;
    });

    auto request = signedGatewayRouteRequest(
        http::verb::get,
        "/" + fixture.bucket_name + "?list-type=2",
        fixture.secret);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_EQ(0, fixture.controller->list_objects_calls);
    const auto ledger = vh::storage::s3::pricing::PriceBudgetService{}.listLedger(
        10,
        fixture.vault_id,
        fixture.secret.credential.id);
    EXPECT_TRUE(ledger.empty());
}

TEST(S3CostSafetyTest, GatewayLocalMaterializedGetDoesNotConsumeUpstreamBudgetByDefault) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-local-get-no-budget",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");
    constexpr std::string_view objectKey = "local-get.txt";
    const vh::protocols::s3::Router router;
    auto put = signedGatewayRouteRequest(
        http::verb::put,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret,
        "local payload");
    ASSERT_EQ(router.route(std::move(put)).result(), http::status::ok);
    setGatewayRouteRequestBudget(fixture, [](auto& budget) {
        budget.max_get_requests = 0;
    });

    auto get = signedGatewayRouteRequest(
        http::verb::get,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);
    const auto response = router.route(std::move(get));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_EQ("local payload", response.body());
    EXPECT_EQ(0, fixture.controller->download_to_buffer_calls);
    expectGatewayLedgerAbsent(fixture, "GetObject", std::string(objectKey));
}

TEST(S3CostSafetyTest, GatewayLocalMaterializedGetCanCommitSyntheticGatewayBudgetWhenEnabled) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-local-get-synthetic",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000",
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        true);
    constexpr std::string_view objectKey = "local-get-synthetic.txt";
    const vh::protocols::s3::Router router;
    auto put = signedGatewayRouteRequest(
        http::verb::put,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret,
        "local payload");
    ASSERT_EQ(router.route(std::move(put)).result(), http::status::ok);

    auto get = signedGatewayRouteRequest(
        http::verb::get,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);
    const auto response = router.route(std::move(get));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_EQ(0, fixture.controller->download_to_buffer_calls);
    expectGatewayLedgerCommitted(fixture, "GetObject", std::string(objectKey), true, "local_cache");
}

TEST(S3CostSafetyTest, GatewayPureLocalBucketWithLocalEnforcementConsumesSyntheticKeyBudgetAndCanDeny) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupLocalGatewayRouteBudgetFixture(
        "route-pure-local-synthetic",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "0.00000001",
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        true);
    saveGenericBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::Global,
        std::nullopt,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Report,
        "1.00000000");
    saveGenericBudgetPolicyForDbTest(
        vh::storage::s3::pricing::PriceBudgetScope::Vault,
        std::nullopt,
        fixture.vault_id,
        vh::storage::s3::pricing::PriceBudgetMode::Report,
        "1.00000000");

    constexpr std::string_view objectKey = "pure-local-budget.txt";
    const vh::protocols::s3::Router router;
    auto put = signedGatewayRouteRequest(
        http::verb::put,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret,
        "local payload");
    const auto putResponse = router.route(std::move(put));
    ASSERT_EQ(putResponse.result(), http::status::ok) << putResponse.body();

    expectGatewayLedgerCommitted(fixture, "PutObject", std::string(objectKey), true, "sync_deferred");
    const auto afterPutLedger = vh::storage::s3::pricing::PriceBudgetService{}.listLedger(
        20,
        fixture.vault_id,
        std::nullopt);
    ASSERT_FALSE(afterPutLedger.empty());
    EXPECT_TRUE(std::ranges::all_of(afterPutLedger, [&](const auto& entry) {
        return entry.gateway_credential_id &&
            *entry.gateway_credential_id == fixture.secret.credential.id &&
            entry.provider_key == "gateway-local" &&
            entry.synthetic;
    }));

    auto get = signedGatewayRouteRequest(
        http::verb::get,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);
    const auto denied = router.route(std::move(get));

    EXPECT_EQ(denied.result(), http::status::forbidden);
    EXPECT_NE(std::string::npos, denied.body().find("<Code>AccessDenied</Code>"));
    EXPECT_NE(std::string::npos, denied.body().find("S3 gateway synthetic local budget exceeded"));
    EXPECT_NE(std::string::npos, denied.body().find("provider_key=gateway-local"));
    EXPECT_NE(std::string::npos, denied.body().find("operation=GetObject"));
}

TEST(S3CostSafetyTest, GatewayRemoteDeleteLocalFirstDoesNotCommitCredentialBudgetByDefault) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-delete-budget",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");
    constexpr std::string_view objectKey = "remote-delete.txt";
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = fixture.vault_id,
        .object_key = std::string(objectKey),
        .etag = "\"remote-delete-etag\"",
        .size_bytes = 42,
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });
    vh::db::query::sync::RemoteObjectIndex::upsertFile(
        fixture.vault_id,
        remoteFile(std::string(objectKey)),
        "manifest");

    auto request = signedGatewayRouteRequest(
        http::verb::delete_,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::no_content) << response.body();
    EXPECT_EQ(0, fixture.controller->delete_object_calls);
    EXPECT_FALSE(vh::db::query::s3::Gateway::getObjectState(fixture.vault_id, std::string(objectKey)));
    const auto indexed = vh::db::query::sync::RemoteObjectIndex::listFilesForVault(fixture.vault_id);
    EXPECT_TRUE(std::ranges::any_of(indexed, [&](const auto& file) {
        return file && file->path.generic_string() == std::string("/") + std::string(objectKey);
    }));
    const auto actor = vh::identities::manager().user(fixture.secret.credential.principal_user_id);
    ASSERT_TRUE(actor);
    const vh::protocols::s3::ObjectStore objectStore;
    const auto listed = objectStore.listObjects(objectStore.resolveBucket(fixture.bucket_name, actor), {});
    EXPECT_TRUE(listed.objects.empty());
    EXPECT_EQ(1u, countGatewaySyncOriginForDbTest(fixture.vault_id, std::string(objectKey), "delete"));
    expectGatewayLedgerAbsent(fixture, "DeleteObject", std::string(objectKey));
}

TEST(S3CostSafetyTest, GatewayRemoteDeleteLocalFirstCanCommitSyntheticGatewayBudgetWhenEnabled) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-delete-synthetic",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000",
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        true);
    constexpr std::string_view objectKey = "remote-delete-synthetic.txt";
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = fixture.vault_id,
        .object_key = std::string(objectKey),
        .etag = "\"remote-delete-synthetic\"",
        .size_bytes = 42,
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });

    auto request = signedGatewayRouteRequest(
        http::verb::delete_,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::no_content) << response.body();
    EXPECT_EQ(0, fixture.controller->delete_object_calls);
    EXPECT_EQ(1u, countGatewaySyncOriginForDbTest(fixture.vault_id, std::string(objectKey), "delete"));
    expectGatewayLedgerCommitted(fixture, "DeleteObject", std::string(objectKey), true, "sync_deferred");
}

TEST(S3CostSafetyTest, GatewayRemoteMultipartLocalFirstDoesNotCommitCredentialBudgetByDefault) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-multipart-budget",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");
    constexpr std::string_view objectKey = "multipart-object.txt";

    const vh::protocols::s3::Router router;
    auto initiate = signedGatewayRouteRequest(
        http::verb::post,
        "/" + fixture.bucket_name + "/" + std::string(objectKey) + "?uploads",
        fixture.secret);
    const auto initiateResponse = router.route(std::move(initiate));
    ASSERT_EQ(initiateResponse.result(), http::status::ok) << initiateResponse.body();
    const auto uploadId = textBetween(initiateResponse.body(), "<UploadId>", "</UploadId>");
    ASSERT_FALSE(uploadId.empty());

    auto uploadPart = signedGatewayRouteRequest(
        http::verb::put,
        "/" + fixture.bucket_name + "/" + std::string(objectKey) + "?partNumber=1&uploadId=" + uploadId,
        fixture.secret,
        "multipart payload");
    const auto uploadPartResponse = router.route(std::move(uploadPart));
    ASSERT_EQ(uploadPartResponse.result(), http::status::ok) << uploadPartResponse.body();
    const auto partEtag = std::string(uploadPartResponse[http::field::etag]);
    ASSERT_FALSE(partEtag.empty());

    const auto completeBody =
        "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>" +
        partEtag +
        "</ETag></Part></CompleteMultipartUpload>";
    auto complete = signedGatewayRouteRequest(
        http::verb::post,
        "/" + fixture.bucket_name + "/" + std::string(objectKey) + "?uploadId=" + uploadId,
        fixture.secret,
        completeBody);
    const auto completeResponse = router.route(std::move(complete));
    EXPECT_EQ(completeResponse.result(), http::status::ok) << completeResponse.body();
    EXPECT_EQ(0, fixture.controller->upload_buffer_with_metadata_calls);
    EXPECT_TRUE(vh::db::query::fs::File::getFileByPath(fixture.vault_id, "/" + std::string(objectKey)));
    ASSERT_TRUE(vh::db::query::s3::Gateway::getObjectState(fixture.vault_id, std::string(objectKey)));

    expectGatewayLedgerAbsent(fixture, "CreateMultipartUpload", std::string(objectKey));
    expectGatewayLedgerAbsent(fixture, "UploadPart", std::string(objectKey));
    expectGatewayLedgerAbsent(fixture, "CompleteMultipartUpload", std::string(objectKey));
}

TEST(S3CostSafetyTest, GatewayRemoteCopyRoutePreflightsAndCommitsCopyBudget) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-copy-budget",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");
    vh::db::query::s3::Gateway::bindBucket({
        .vault_id = fixture.vault_id,
        .bucket_name = fixture.bucket_name,
        .api_exclusive = true,
        .mode = "remote_proxy",
        .created_by = fixture.secret.credential.principal_user_id
    });
    constexpr std::string_view sourceKey = "copy-source.txt";
    constexpr std::string_view destKey = "copy-dest.txt";
    fixture.controller->download_payloads.push_back({'c', 'o', 'p', 'y'});
    const auto remoteManifest = vh::sync::model::remote_manifest::buildIndexV1(fixture.vault_id, {});
    fixture.controller->download_payloads.emplace_back(remoteManifest.begin(), remoteManifest.end());
    fixture.controller->head_response = std::unordered_map<std::string, std::string>{
        {"x-amz-meta-vh-encrypted", "false"}
    };
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = fixture.vault_id,
        .object_key = std::string(sourceKey),
        .etag = "\"copy-source-etag\"",
        .size_bytes = 4,
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });

    vh::protocols::s3::Router::Request request{
        http::verb::put,
        "/" + fixture.bucket_name + "/" + std::string(destKey),
        11};
    request.set(http::field::host, "localhost:39000");
    request.set("x-amz-copy-source", "/" + fixture.bucket_name + "/" + std::string(sourceKey));
    request.prepare_payload();
    signGatewayRouteRequest(request, fixture.secret.credential.access_key, fixture.secret.secret_access_key);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_EQ(1, fixture.controller->download_to_buffer_calls);
    EXPECT_EQ(0, fixture.controller->upload_buffer_with_metadata_calls);
    EXPECT_TRUE(vh::db::query::fs::File::getFileByPath(fixture.vault_id, "/" + std::string(destKey)));
    expectGatewayLedgerAbsent(fixture, "GetObject", std::string(sourceKey));
    expectGatewayLedgerCommitted(fixture, "CopyObject", std::string(sourceKey));
}

TEST(S3CostSafetyTest, GatewayRemoteUploadPartFailureBeforeSyncDoesNotReserveBudgetByDefault) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-upload-part-release",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");
    constexpr std::string_view objectKey = "multipart-release.txt";

    const vh::protocols::s3::Router router;
    auto initiate = signedGatewayRouteRequest(
        http::verb::post,
        "/" + fixture.bucket_name + "/" + std::string(objectKey) + "?uploads",
        fixture.secret);
    const auto initiateResponse = router.route(std::move(initiate));
    ASSERT_EQ(initiateResponse.result(), http::status::ok) << initiateResponse.body();
    const auto uploadId = textBetween(initiateResponse.body(), "<UploadId>", "</UploadId>");
    ASSERT_FALSE(uploadId.empty());

    auto uploadPart = signedGatewayRouteRequest(
        http::verb::put,
        "/" + fixture.bucket_name + "/" + std::string(objectKey) + "?partNumber=1&uploadId=" + uploadId,
        fixture.secret,
        "bad checksum body");
    uploadPart.set("content-md5", "AAAAAAAAAAAAAAAAAAAAAA==");
    const auto uploadPartResponse = router.route(std::move(uploadPart));

    EXPECT_EQ(uploadPartResponse.result(), http::status::bad_request);
    EXPECT_NE(std::string::npos, uploadPartResponse.body().find("<Code>BadDigest</Code>"));
    EXPECT_EQ(0, fixture.controller->upload_buffer_with_metadata_calls);
    expectGatewayLedgerAbsent(fixture, "UploadPart", std::string(objectKey));
}

TEST(S3CostSafetyTest, GatewayRemotePutLocalFirstIgnoresUpstreamRequestBudgetByDefault) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-put-request-budget-denied",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");
    setGatewayRouteRequestBudget(fixture, [](auto& budget) {
        budget.max_put_requests = 0;
    });

    auto request = signedGatewayRouteRequest(
        http::verb::put,
        "/" + fixture.bucket_name + "/request-budget-denied.txt",
        fixture.secret,
        "payload");

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::ok) << response.body();
    EXPECT_EQ(0, fixture.controller->upload_buffer_with_metadata_calls);
    EXPECT_TRUE(vh::db::query::fs::File::getFileByPath(fixture.vault_id, "/request-budget-denied.txt"));
    expectGatewayLedgerAbsent(fixture, "PutObject", "request-budget-denied.txt");
}

TEST(S3CostSafetyTest, GatewayRemoteGetRequestBudgetDeniedBeforeRemoteDownload) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-get-request-budget-denied",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");
    setGatewayRouteRequestBudget(fixture, [](auto& budget) {
        budget.max_get_requests = 0;
    });
    constexpr std::string_view objectKey = "request-budget-get.txt";
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = fixture.vault_id,
        .object_key = std::string(objectKey),
        .etag = "\"request-budget-get\"",
        .size_bytes = 128,
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });

    auto request = signedGatewayRouteRequest(
        http::verb::get,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::service_unavailable);
    EXPECT_NE(std::string::npos, response.body().find("<Code>SlowDown</Code>"));
    EXPECT_NE(std::string::npos, response.body().find("kind=GET"));
    EXPECT_EQ(0, fixture.controller->download_to_buffer_calls);
    expectGatewayLedgerAbsent(fixture, "GetObject", std::string(objectKey));
}

TEST(S3CostSafetyTest, GatewayRemoteGetDownloadedBytesBudgetDeniedDuringRemoteDownload) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-get-byte-request-budget-denied",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");
    setGatewayRouteRequestBudget(fixture, [](auto& budget) {
        budget.max_get_requests = 1;
        budget.max_downloaded_bytes = 4;
    });
    constexpr std::string_view objectKey = "request-budget-bytes.txt";
    fixture.controller->download_payload.assign(5, static_cast<uint8_t>('x'));
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = fixture.vault_id,
        .object_key = std::string(objectKey),
        .etag = "\"request-budget-bytes\"",
        .size_bytes = 5,
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });

    auto request = signedGatewayRouteRequest(
        http::verb::get,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::service_unavailable);
    EXPECT_NE(std::string::npos, response.body().find("<Code>SlowDown</Code>"));
    EXPECT_NE(std::string::npos, response.body().find("kind=downloaded bytes"));
    EXPECT_EQ(1, fixture.controller->download_to_buffer_calls);
    expectGatewayLedgerAbsent(fixture, "GetObject", std::string(objectKey));
}

TEST(S3CostSafetyTest, GatewayRemoteDeleteLocalFirstIgnoresUpstreamRequestBudgetByDefault) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-delete-request-budget-denied",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "1.00000000");
    setGatewayRouteRequestBudget(fixture, [](auto& budget) {
        budget.max_delete_requests = 0;
    });
    constexpr std::string_view objectKey = "request-budget-delete.txt";
    vh::db::query::s3::Gateway::upsertObject({
        .vault_id = fixture.vault_id,
        .object_key = std::string(objectKey),
        .etag = "\"request-budget-delete\"",
        .size_bytes = 42,
        .content_type = "text/plain",
        .storage_class = std::nullopt,
        .last_modified = std::time(nullptr),
        .multipart = false,
        .part_count = std::nullopt
    });

    auto request = signedGatewayRouteRequest(
        http::verb::delete_,
        "/" + fixture.bucket_name + "/" + std::string(objectKey),
        fixture.secret);

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::no_content) << response.body();
    EXPECT_EQ(0, fixture.controller->delete_object_calls);
    EXPECT_FALSE(vh::db::query::s3::Gateway::getObjectState(fixture.vault_id, std::string(objectKey)));
    expectGatewayLedgerAbsent(fixture, "DeleteObject", std::string(objectKey));
}

TEST(S3CostSafetyTest, GatewaySyntheticLocalBudgetDeniedReturnsXmlAccessDeniedBeforeLocalPut) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-budget-denied",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredentialVault,
        "0.00000000",
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        true);

    auto request = signedGatewayRouteRequest(
        http::verb::put,
        "/" + fixture.bucket_name + "/denied-object.txt",
        fixture.secret,
        "payload");

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::forbidden);
    EXPECT_NE(std::string::npos, response.body().find("<Code>AccessDenied</Code>"));
    EXPECT_NE(std::string::npos, response.body().find("S3 gateway synthetic local budget exceeded"));
    EXPECT_NE(std::string::npos, response.body().find("scope=gateway_credential_vault"));
    EXPECT_NE(std::string::npos, response.body().find("policy_id="));
    EXPECT_NE(std::string::npos, response.body().find("window=monthly"));
    EXPECT_NE(std::string::npos, response.body().find("provider_key=gateway-local"));
    EXPECT_NE(std::string::npos, response.body().find("vault_id=" + std::to_string(fixture.vault_id)));
    EXPECT_NE(std::string::npos, response.body().find("gateway_credential_id=" + std::to_string(fixture.secret.credential.id)));
    EXPECT_NE(std::string::npos, response.body().find("operation=PutObject"));
    EXPECT_NE(std::string::npos, response.body().find("request_uuid="));
    EXPECT_EQ(0, fixture.controller->upload_buffer_with_metadata_calls);
    EXPECT_EQ(0, fixture.controller->upload_object_with_metadata_calls);
    EXPECT_FALSE(vh::db::query::fs::File::getFileByPath(fixture.vault_id, "/denied-object.txt"));
    const auto ledger = vh::storage::s3::pricing::PriceBudgetService{}.listLedger(
        10,
        fixture.vault_id,
        fixture.secret.credential.id);
    EXPECT_TRUE(ledger.empty());
}

TEST(S3CostSafetyTest, GatewaySyntheticLocalKeyBudgetDeniedReturnsPolicyScopeWindowInXml) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed S3 gateway route budget test due to missing environment variables.";
    S3CostConfigRestore restoreConfig(vh::config::Registry::get());
    configureS3GatewayRouteBudgetConfig();

    auto fixture = setupGatewayRouteBudgetFixture(
        "route-key-budget-denied",
        vh::storage::s3::pricing::PriceBudgetScope::GatewayCredential,
        "0.00000000",
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        true);

    auto request = signedGatewayRouteRequest(
        http::verb::put,
        "/" + fixture.bucket_name + "/denied-key-budget.txt",
        fixture.secret,
        "payload");

    const vh::protocols::s3::Router router;
    const auto response = router.route(std::move(request));

    EXPECT_EQ(response.result(), http::status::forbidden);
    EXPECT_NE(std::string::npos, response.body().find("<Code>AccessDenied</Code>"));
    EXPECT_NE(std::string::npos, response.body().find("S3 gateway synthetic local budget exceeded"));
    EXPECT_NE(std::string::npos, response.body().find("scope=gateway_credential"));
    EXPECT_NE(std::string::npos, response.body().find("policy_id="));
    EXPECT_NE(std::string::npos, response.body().find("window=monthly"));
    EXPECT_NE(std::string::npos, response.body().find("operation=PutObject"));
    EXPECT_EQ(0, fixture.controller->upload_buffer_with_metadata_calls);
    EXPECT_FALSE(vh::db::query::fs::File::getFileByPath(fixture.vault_id, "/denied-key-budget.txt"));
}

TEST(S3CostSafetyTest, PriceBudgetStaleReservationsExpireSafely) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed price budget stale reservation test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("budget_stale"));
    saveVaultBudgetPolicyForDbTest(
        vaultId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Report,
        "10.00000000");

    vh::storage::s3::pricing::PriceBudgetService service;
    const auto decision = service.preflight({
        .vault_id = vaultId,
        .run_uuid = uniqueSuffix("stale-reservation"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("1.00000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {}
    });
    ASSERT_FALSE(decision.reservations.empty());
    const auto reservationId = decision.reservations.front().id;

    vh::db::Transactions::exec("S3CostSafetyTest::agePriceBudgetReservation", [&](pqxx::work& txn) {
        txn.exec(
            "UPDATE s3_price_budget_ledger "
            "SET created_at = CURRENT_TIMESTAMP - interval '25 hours' "
            "WHERE id = $1",
            pqxx::params{reservationId});
    });

    service.expireStaleReservations();

    const auto status = vh::db::Transactions::exec("S3CostSafetyTest::priceBudgetReservationStatus", [&](pqxx::work& txn) {
        return txn.exec(
            "SELECT status FROM s3_price_budget_ledger WHERE id = $1",
            pqxx::params{reservationId}).one_field_ref().as<std::string>();
    });
    EXPECT_EQ("expired", status);
}

TEST(S3CostSafetyTest, PriceBudgetOverrideRequiresExactVaultRunPolicySet) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed price budget override test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("budget_override_exact"));
    const auto ownerId = ownerForVaultDbTest(vaultId);
    const auto basePolicy = saveVaultBudgetPolicyForDbTest(
        vaultId,
        std::nullopt,
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "0.10000000");
    const auto providerPolicy = saveVaultBudgetPolicyForDbTest(
        vaultId,
        "aws-s3",
        vh::storage::s3::pricing::PriceBudgetMode::Enforce,
        "0.10000000");

    vh::storage::s3::pricing::PriceBudgetService service;
    const auto runUuid = uniqueSuffix("override-run");
    const auto requested = service.requestOverride({
        .run_uuid = runUuid,
        .vault_id = vaultId,
        .requested_by = ownerId,
        .reason = "release readiness exact policy set test",
        .policy_ids = {basePolicy.id, providerPolicy.id},
        .estimated_cost = "1.00000000",
        .currency = "USD",
        .ttl_minutes = 30
    });
    const auto approved = service.approveOverride(requested.id, ownerId);
    ASSERT_EQ("approved", approved.status);

    EXPECT_FALSE(service.consumeApprovedOverride(vaultId, {basePolicy.id}, runUuid));

    const auto consumed = service.consumeApprovedOverride(vaultId, {basePolicy.id, providerPolicy.id}, runUuid);
    ASSERT_TRUE(consumed);
    EXPECT_EQ(requested.id, consumed->id);
    EXPECT_EQ("used", consumed->status);

    EXPECT_FALSE(service.consumeApprovedOverride(vaultId, {basePolicy.id, providerPolicy.id}, runUuid));
}

TEST(S3CostSafetyTest, VaultPricingDashboardStatsOnlyUseApplicableProviderScopeAndVaultLedgerRows) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed pricing dashboard scope test due to missing environment variables.";
    ensureDbReady();

    const auto awsVaultId = seedS3VaultForDbTest(uniqueSuffix("pricing_aws"));
    const auto r2VaultId = seedS3VaultForDbTest(uniqueSuffix("pricing_r2"));
    const auto localVaultId = vh::db::Transactions::exec("S3CostSafetyTest::seedLocalVaultForPricingStats", [&](pqxx::work& txn) {
        const auto userId = insertS3CostHydratableTestUser(
            txn,
            "local-pricing-user",
            uniqueSuffix("local-pricing") + "@vaulthalla.test");
        const auto vaultId = txn.exec(
            "INSERT INTO vault (type, name, owner_id, mount_point, description) VALUES ($1, $2, $3, $4, $5) RETURNING id",
            pqxx::params{"local", uniqueSuffix("Local Pricing"), userId, "ABCDEFGHJKMNPQRSTVWXYZ0123456789", ""})
            .one_field_ref().as<std::uint32_t>();
        txn.exec(
            "WITH ins AS (INSERT INTO sync (vault_id, interval) VALUES ($1, 300) RETURNING id) "
            "INSERT INTO fsync (sync_id, conflict_policy) SELECT id, 'keep_both' FROM ins",
            pqxx::params{vaultId});
        return vaultId;
    });
    attachS3ProviderForDbTest(awsVaultId, "AWS");
    attachS3ProviderForDbTest(r2VaultId, "Cloudflare R2");

    vh::storage::s3::pricing::PriceBudgetPolicy awsProviderPolicy;
    awsProviderPolicy.scope = vh::storage::s3::pricing::PriceBudgetScope::Provider;
    awsProviderPolicy.provider_key = "aws-s3";
    awsProviderPolicy.mode = vh::storage::s3::pricing::PriceBudgetMode::Report;
    awsProviderPolicy.currency = "USD";
    awsProviderPolicy.max_monthly_cost = "10.00000000";
    awsProviderPolicy = vh::storage::s3::pricing::PriceBudgetService{}.upsertPolicy(std::move(awsProviderPolicy));

    vh::storage::s3::pricing::PriceBudgetService service;
    const auto awsDecision = service.preflight({
        .vault_id = awsVaultId,
        .run_uuid = uniqueSuffix("aws-ledger"),
        .provider_key = "aws-s3",
        .provider_supported = true,
        .estimate = budgetEstimateForDbTest("3.00000000"),
        .dry_run = false,
        .override_policy_ids = {},
        .gateway_credential_id = {},
        .request_uuid = {},
        .operation = {},
        .object_key = {}
    });
    ASSERT_FALSE(awsDecision.reservations.empty());
    service.commit(awsDecision.reservations, std::make_optional<std::string>("3.00000000"));

    const auto r2Stats = service.dashboardStats(r2VaultId);
    EXPECT_EQ(0u, r2Stats.active_policies);
    // No monthly window in scope: spend is unknown (null), never a fake "0.00000000" (#160).
    EXPECT_FALSE(r2Stats.current_monthly_spend.has_value());
    EXPECT_FALSE(r2Stats.projected_monthly_spend.has_value());
    EXPECT_TRUE(r2Stats.trends.empty());

    const auto localStats = service.dashboardStats(localVaultId);
    EXPECT_EQ(0u, localStats.active_policies);
    // No monthly window in scope: spend is unknown (null), never a fake "0.00000000" (#160).
    EXPECT_FALSE(localStats.current_monthly_spend.has_value());
    EXPECT_FALSE(localStats.projected_monthly_spend.has_value());
    EXPECT_TRUE(localStats.trends.empty());
}

TEST(S3CostSafetyTest, RemoteIndexSummaryAppliesMaxAgeFreshnessPolicy) {
    vh::db::query::sync::RemoteIndexSummary summary;
    summary.object_count = 10;
    summary.indexed_at = 1000;

    EXPECT_FALSE(summary.isStale(std::chrono::seconds(60), 1059));
    EXPECT_TRUE(summary.isStale(std::chrono::seconds(60), 1061));
    EXPECT_FALSE(summary.isStale(std::nullopt, 999999));
}

TEST(S3CostSafetyTest, StaleRemoteIndexAfterManifestRefreshFailureStallsWithoutGenericError) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed stale index regression test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("stale_index"));
    vh::db::Transactions::exec("S3CostSafetyTest::seedStaleRemoteIndex", [&](pqxx::work& txn) {
        txn.exec(
            "INSERT INTO remote_object_index "
            "(vault_id, object_key, size_bytes, last_modified, etag, source, indexed_at) "
            "VALUES ($1, $2, $3, CURRENT_TIMESTAMP - INTERVAL '2 hours', $4, $5, CURRENT_TIMESTAMP - INTERVAL '2 hours')",
            pqxx::params{vaultId, "stale.txt", 1, "\"stale\"", "manifest"});
    });

    auto fake = std::make_shared<ManifestRaceS3Controller>();
    auto engine = makeDbBackedCloudEngine(vaultId, fake);
    std::static_pointer_cast<vh::sync::model::RemotePolicy>(engine->sync)->max_remote_index_age = std::chrono::seconds(60);

    auto cloud = std::make_shared<vh::sync::Cloud>(engine);
    cloud->event = std::make_shared<vh::sync::model::Event>();
    cloud->runningFlag = true;

    const vh::sync::Stage stages[] = {
        {"initBins", [&] { cloud->initBins(); }}
    };
    cloud->runStages(stages);

    EXPECT_EQ(vh::sync::model::Event::Status::STALLED, cloud->event->status);
    EXPECT_TRUE(cloud->event->error_message.empty());
    EXPECT_NE(std::string::npos, cloud->event->stall_reason.find("remote index is stale and manifest refresh failed"));
    EXPECT_NE(std::string::npos, cloud->event->stall_reason.find("vault sync reconcile"));
}

TEST(S3CostSafetyTest, FirstManifestPublishUsesIfNoneMatchAndReportsConflict) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed manifest publish regression test due to missing environment variables.";
    ensureDbReady();

    const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("manifest_first"));
    auto fake = std::make_shared<ManifestRaceS3Controller>();
    fake->conditional_failures = {412};
    auto engine = makeDbBackedCloudEngine(vaultId, fake);

    EXPECT_THROW(
        engine->publishRemoteIndexManifest(std::nullopt),
        vh::storage::s3::ConditionalRequestFailed);

    ASSERT_EQ(1u, fake->if_match_values.size());
    EXPECT_FALSE(fake->if_match_values[0].has_value());
    ASSERT_TRUE(fake->if_none_match_values[0].has_value());
    EXPECT_EQ("*", *fake->if_none_match_values[0]);
}

TEST(S3CostSafetyTest, DirectManifestPublishRetriesFirstPublishConflictWithFreshETag) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed manifest retry regression test due to missing environment variables.";
    ensureDbReady();

    for (const auto code : {412, 409}) {
        const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("manifest_first_retry_" + std::to_string(code)));
        auto fake = std::make_shared<ManifestRaceS3Controller>();
        fake->conditional_failures = {code};
        fake->head_responses = {
            std::unordered_map<std::string, std::string>{{"ETag", "\"etag-existing\""}},
            std::unordered_map<std::string, std::string>{{"ETag", "\"etag-after-publish\""}},
        };
        auto engine = makeDbBackedCloudEngine(vaultId, fake);

        EXPECT_NO_THROW(engine->publishRemoteIndexManifestWithRetry());

        ASSERT_EQ(2u, fake->if_match_values.size());
        EXPECT_FALSE(fake->if_match_values[0].has_value());
        ASSERT_TRUE(fake->if_none_match_values[0].has_value());
        EXPECT_EQ("*", *fake->if_none_match_values[0]);
        ASSERT_TRUE(fake->if_match_values[1].has_value());
        EXPECT_EQ("\"etag-existing\"", *fake->if_match_values[1]);
        EXPECT_FALSE(fake->if_none_match_values[1].has_value());
    }
}

TEST(S3CostSafetyTest, ManifestPublishConflictRetriesAfterRefreshingKnownETag) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed manifest retry regression test due to missing environment variables.";
    ensureDbReady();

    for (const auto code : {412, 409}) {
        const auto vaultId = seedS3VaultForDbTest(uniqueSuffix("manifest_retry_" + std::to_string(code)));
        const auto manifest = vh::sync::model::remote_manifest::buildIndexV1(vaultId, {});
        auto fake = std::make_shared<ManifestRaceS3Controller>(manifest);
        fake->conditional_failures = {code};
        fake->head_responses = {
            std::unordered_map<std::string, std::string>{{"ETag", "\"etag-1\""}},
            std::unordered_map<std::string, std::string>{{"ETag", "\"etag-2\""}},
            std::unordered_map<std::string, std::string>{{"ETag", "\"etag-3\""}},
        };
        auto engine = makeDbBackedCloudEngine(vaultId, fake);

        auto file = std::make_shared<vh::fs::model::File>();
        file->path = "/docs/report.txt";
        file->size_bytes = 12;
        file->updated_at = std::time(nullptr);

        const std::vector<vh::sync::model::Action> plan{
            {vh::sync::model::ActionType::Upload, {.rel = u8"docs/report.txt"}, file, nullptr}
        };

        EXPECT_NO_THROW(engine->applyRemoteIndexMutation(plan));

        ASSERT_EQ(2u, fake->if_match_values.size());
        ASSERT_TRUE(fake->if_match_values[0].has_value());
        ASSERT_TRUE(fake->if_match_values[1].has_value());
        EXPECT_EQ("\"etag-1\"", *fake->if_match_values[0]);
        EXPECT_EQ("\"etag-2\"", *fake->if_match_values[1]);
        EXPECT_FALSE(fake->if_none_match_values[0].has_value());
        EXPECT_FALSE(fake->if_none_match_values[1].has_value());
    }
}

TEST(S3CostSafetyTest, BudgetMetricsAfterAsyncFailureMarkEventStalled) {
    struct Case {
        BudgetProbeS3Controller::RequestKind kind;
        vh::storage::s3::S3RequestBudget budget;
        const char* reason;
    };

    std::vector<Case> cases;
    {
        vh::storage::s3::S3RequestBudget budget;
        budget.max_put_requests = 0;
        cases.push_back({BudgetProbeS3Controller::RequestKind::Put, budget, "S3 request budget exceeded for PUT"});
    }
    {
        vh::storage::s3::S3RequestBudget budget;
        budget.max_get_requests = 0;
        cases.push_back({BudgetProbeS3Controller::RequestKind::Get, budget, "S3 request budget exceeded for GET"});
    }
    {
        vh::storage::s3::S3RequestBudget budget;
        budget.max_delete_requests = 0;
        cases.push_back({BudgetProbeS3Controller::RequestKind::Delete, budget, "S3 request budget exceeded for DELETE"});
    }

    for (const auto& c : cases) {
        auto vault = std::make_shared<vh::vault::model::S3Vault>();
        vault->id = 99;
        vault->owner_id = 100;

        auto policy = std::make_shared<vh::sync::model::RemotePolicy>();
        auto fake = std::make_shared<BudgetProbeS3Controller>();
        auto engine = std::make_shared<vh::storage::CloudEngine>();
        engine->vault = vault;
        engine->sync = policy;
        engine->setS3ControllerForTesting(fake);

        fake->setRequestBudget(c.budget);
        try {
            fake->count(c.kind);
        } catch (const vh::storage::s3::RequestBudgetExceeded&) {
        }

        auto cloud = std::make_shared<vh::sync::Cloud>(engine);
        cloud->event = std::make_shared<vh::sync::model::Event>();

        EXPECT_TRUE(cloud->markBudgetExceededIfAny());
        EXPECT_EQ(vh::sync::model::Event::Status::STALLED, cloud->event->status);
        EXPECT_EQ(c.reason, cloud->event->stall_reason);
        EXPECT_TRUE(cloud->event->error_message.empty());
    }
}

TEST(S3CostSafetyTest, SharedStageRemoteDeleteBudgetFailureMarksEventStalled) {
    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 99;
    vault->owner_id = 100;

    auto policy = std::make_shared<vh::sync::model::RemotePolicy>();
    auto fake = std::make_shared<BudgetProbeS3Controller>();
    auto engine = std::make_shared<vh::storage::CloudEngine>();
    engine->vault = vault;
    engine->sync = policy;
    engine->setS3ControllerForTesting(fake);

    vh::storage::s3::S3RequestBudget budget;
    budget.max_delete_requests = 0;
    fake->setRequestBudget(budget);
    try {
        fake->count(BudgetProbeS3Controller::RequestKind::Delete);
    } catch (const vh::storage::s3::RequestBudgetExceeded&) {
    }

    auto cloud = std::make_shared<vh::sync::Cloud>(engine);
    cloud->event = std::make_shared<vh::sync::model::Event>();

    EXPECT_TRUE(cloud->markBudgetExceededIfAny());
    EXPECT_EQ(vh::sync::model::Event::Status::STALLED, cloud->event->status);
    EXPECT_EQ("S3 request budget exceeded for DELETE", cloud->event->stall_reason);
    EXPECT_TRUE(cloud->event->error_message.empty());
}

TEST(S3CostSafetyTest, ScopedBudgetClearsAfterThrownException) {
    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 99;
    vault->owner_id = 100;

    auto fake = std::make_shared<BudgetProbeS3Controller>();
    vh::storage::CloudEngine engine;
    engine.vault = vault;
    engine.setS3ControllerForTesting(fake);

    EXPECT_THROW({
        const vh::storage::ScopedS3RequestBudget guard(
            engine,
            vh::sync::model::s3RequestBudgetForPreset(vh::sync::model::S3BudgetPreset::Conservative));
        throw std::runtime_error("synthetic failure");
    }, std::runtime_error);

    EXPECT_EQ(1, fake->reset_metrics_calls);
    EXPECT_EQ(1, fake->set_budget_calls);
    EXPECT_EQ(1, fake->clear_budget_calls);

    EXPECT_NO_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Get));
}

TEST(S3CostSafetyTest, ScopedBudgetClearsAfterBudgetException) {
    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 99;
    vault->owner_id = 100;

    auto fake = std::make_shared<BudgetProbeS3Controller>();
    vh::storage::CloudEngine engine;
    engine.vault = vault;
    engine.setS3ControllerForTesting(fake);

    vh::storage::s3::S3RequestBudget budget;
    budget.max_get_requests = 0;

    EXPECT_THROW({
        const vh::storage::ScopedS3RequestBudget guard(engine, budget);
        fake->count(BudgetProbeS3Controller::RequestKind::Get);
    }, vh::storage::s3::RequestBudgetExceeded);

    EXPECT_EQ(1, fake->clear_budget_calls);
    EXPECT_NO_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Get));
}

TEST(S3CostSafetyTest, RequestBudgetsThrowBeforeNextRequest) {
    auto fake = std::make_shared<BudgetProbeS3Controller>();

    vh::storage::s3::S3RequestBudget budget;
    budget.max_list_requests = 1;
    budget.max_head_requests = 1;
    budget.max_get_requests = 1;
    budget.max_put_requests = 1;
    budget.max_copy_requests = 1;
    budget.max_delete_requests = 1;
    budget.max_downloaded_bytes = 10;
    fake->setRequestBudget(budget);

    EXPECT_NO_THROW(fake->count(BudgetProbeS3Controller::RequestKind::List));
    EXPECT_NO_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Head));
    EXPECT_NO_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Get));
    EXPECT_NO_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Put));
    EXPECT_NO_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Copy));
    EXPECT_NO_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Delete));
    EXPECT_NO_THROW(fake->count(BudgetProbeS3Controller::RequestKind::DownloadBytes, 10));

    EXPECT_THROW(fake->count(BudgetProbeS3Controller::RequestKind::List), vh::storage::s3::RequestBudgetExceeded);
    EXPECT_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Head), vh::storage::s3::RequestBudgetExceeded);
    EXPECT_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Get), vh::storage::s3::RequestBudgetExceeded);
    EXPECT_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Put), vh::storage::s3::RequestBudgetExceeded);
    EXPECT_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Copy), vh::storage::s3::RequestBudgetExceeded);
    EXPECT_THROW(fake->count(BudgetProbeS3Controller::RequestKind::Delete), vh::storage::s3::RequestBudgetExceeded);
    EXPECT_THROW(fake->count(BudgetProbeS3Controller::RequestKind::DownloadBytes, 1), vh::storage::s3::RequestBudgetExceeded);

    const auto metrics = fake->requestMetrics();
    EXPECT_EQ(1u, metrics.list_requests);
    EXPECT_EQ(1u, metrics.head_requests);
    EXPECT_EQ(1u, metrics.get_requests);
    EXPECT_EQ(1u, metrics.put_requests);
    EXPECT_EQ(1u, metrics.copy_requests);
    EXPECT_EQ(1u, metrics.delete_requests);
    EXPECT_EQ(10u, metrics.downloaded_bytes);
}

TEST(S3CostSafetyTest, MultipartUploadCountsInitiatePartsAndComplete) {
    auto fake = std::make_shared<BudgetProbeS3Controller>();

    vh::storage::s3::S3RequestBudget budget;
    budget.max_put_requests = 4;
    fake->setRequestBudget(budget);

    EXPECT_NO_THROW(fake->simulateMultipartPutCounts(2));
    EXPECT_EQ(4u, fake->requestMetrics().put_requests);

    fake->resetRequestMetrics();
    budget.max_put_requests = 3;
    fake->setRequestBudget(budget);
    EXPECT_THROW(fake->simulateMultipartPutCounts(2), vh::storage::s3::RequestBudgetExceeded);
    EXPECT_EQ(3u, fake->requestMetrics().put_requests);
}

TEST(S3CostSafetyTest, PlannerBlocksArchiveBodyDownloads) {
    auto engine = makePlanningEngine();
    auto cloud = std::make_shared<vh::sync::Cloud>(engine);
    auto policy = std::static_pointer_cast<vh::sync::model::RemotePolicy>(engine->sync);
    policy->strategy = vh::sync::model::RemotePolicy::Strategy::Sync;

    const auto remote = remoteFile("cold/remote-only.dat", "GLACIER");
    cloud->s3Map.emplace(remote->path.u8string(), remote);

    vh::sync::model::S3CostEstimate notes;
    const auto plan = vh::sync::Planner::build(cloud, policy, &notes);

    const auto downloads = std::ranges::count_if(plan, [](const auto& action) {
        return action.type == vh::sync::model::ActionType::Download;
    });
    EXPECT_EQ(0, downloads);
    EXPECT_EQ(1u, notes.archive_tier_downloads_skipped);
}

TEST(S3CostSafetyTest, EventStoresS3PlanEstimateForDashboard) {
    vh::sync::model::Event event;
    vh::sync::model::S3CostEstimate estimate;
    estimate.list_requests = 1;
    estimate.head_requests = 2;
    estimate.get_requests = 3;
    estimate.put_requests = 4;
    estimate.copy_requests = 5;
    estimate.delete_requests = 6;
    estimate.planned_body_download_bytes = 7;
    estimate.planned_upload_bytes = 8;
    estimate.remote_index_objects = 9;
    estimate.archive_tier_downloads_skipped = 10;

    event.applyS3CostEstimate(estimate);

    EXPECT_EQ(1u, event.s3_estimated_list_requests);
    EXPECT_EQ(2u, event.s3_estimated_head_requests);
    EXPECT_EQ(3u, event.s3_estimated_get_requests);
    EXPECT_EQ(4u, event.s3_estimated_put_requests);
    EXPECT_EQ(5u, event.s3_estimated_copy_requests);
    EXPECT_EQ(6u, event.s3_estimated_delete_requests);
    EXPECT_EQ(7u, event.s3_estimated_body_download_bytes);
    EXPECT_EQ(8u, event.s3_estimated_upload_bytes);
    EXPECT_EQ(9u, event.s3_remote_index_objects);
    EXPECT_EQ(10u, event.s3_archive_downloads_skipped);
}

TEST(S3CostSafetyTest, IndexThroughputDoesNotInflateTransferredBytes) {
    vh::sync::model::Event event;

    auto upload = std::make_unique<vh::sync::model::Throughput>();
    upload->metric_type = vh::sync::model::Throughput::UPLOAD;
    auto uploadOp = upload->newOp();
    uploadOp->size_bytes = 10;
    uploadOp->success = true;

    auto download = std::make_unique<vh::sync::model::Throughput>();
    download->metric_type = vh::sync::model::Throughput::DOWNLOAD;
    auto downloadOp = download->newOp();
    downloadOp->size_bytes = 20;
    downloadOp->success = true;

    auto index = std::make_unique<vh::sync::model::Throughput>();
    index->metric_type = vh::sync::model::Throughput::INDEX;
    auto indexOp = index->newOp();
    indexOp->size_bytes = 1024;
    indexOp->success = true;

    event.throughputs.push_back(std::move(upload));
    event.throughputs.push_back(std::move(download));
    event.throughputs.push_back(std::move(index));

    event.computeDashboardStats();

    EXPECT_EQ(3u, event.num_ops_total);
    EXPECT_EQ(10u, event.bytes_up);
    EXPECT_EQ(20u, event.bytes_down);
}

TEST(S3CostSafetyTest, FilesFromS3XmlParsesStorageClassETagAndRestoreStatus) {
    const std::u8string xml = u8R"XML(
<ListBucketResult>
  <Contents>
    <Key>archive/report.bin</Key>
    <LastModified>2026-01-02T03:04:05.000Z</LastModified>
    <ETag>&quot;abc123&quot;</ETag>
    <Size>123</Size>
    <StorageClass>DEEP_ARCHIVE</StorageClass>
    <RestoreStatus>
      <IsRestoreInProgress>true</IsRestoreInProgress>
    </RestoreStatus>
  </Contents>
</ListBucketResult>
)XML";

    const auto files = vh::fs::model::filesFromS3XML(xml);
    ASSERT_EQ(1u, files.size());
    ASSERT_TRUE(files[0]->remote_storage_class);
    ASSERT_TRUE(files[0]->remote_etag);
    EXPECT_EQ("DEEP_ARCHIVE", *files[0]->remote_storage_class);
    EXPECT_EQ("\"abc123\"", *files[0]->remote_etag);
    ASSERT_TRUE(files[0]->remote_restore_status);
    EXPECT_NE(std::string::npos, files[0]->remote_restore_status->find("IsRestoreInProgress"));
    EXPECT_TRUE(files[0]->requiresArchiveRestoreForBodyGet());
}

TEST(S3CostSafetyTest, FilesFromS3XmlSkipsVaulthallaManifestObjects) {
    const std::u8string xml = u8R"XML(
<ListBucketResult>
  <Contents>
    <Key>.vaulthalla/index-v1.json</Key>
    <LastModified>2026-01-02T03:04:05.000Z</LastModified>
    <ETag>&quot;manifest&quot;</ETag>
    <Size>123</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <Contents>
    <Key>data/report.txt</Key>
    <LastModified>2026-01-02T03:04:05.000Z</LastModified>
    <ETag>&quot;data&quot;</ETag>
    <Size>12</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
</ListBucketResult>
)XML";

    const auto files = vh::fs::model::filesFromS3XML(xml);
    ASSERT_EQ(1u, files.size());
    EXPECT_EQ("/data/report.txt", files[0]->path.string());
}

TEST(S3CostSafetyTest, RemoteManifestRoundTripsIndexMetadata) {
    auto standard = remoteFile("docs/readme.txt", "STANDARD");
    standard->remote_etag = "\"etag-readme\"";
    standard->content_hash = "content-hash";
    standard->encryption_iv = "iv";
    standard->encrypted_with_key_version = 7;
    standard->remote_version_id = "version-1";
    standard->remote_sequencer = "000000000000000A";

    auto manifestObject = remoteFile(".vaulthalla/index-v1.json", "STANDARD");
    const std::vector<std::shared_ptr<vh::fs::model::File>> files{standard, manifestObject};

    const auto manifest = vh::sync::model::remote_manifest::buildIndexV1(123, files);
    const auto parsed = vh::sync::model::remote_manifest::parseIndexV1(manifest);

    ASSERT_EQ(1u, parsed.size());
    EXPECT_EQ("/docs/readme.txt", parsed[0]->path.string());
    ASSERT_TRUE(parsed[0]->remote_storage_class);
    EXPECT_EQ("STANDARD", *parsed[0]->remote_storage_class);
    ASSERT_TRUE(parsed[0]->remote_etag);
    EXPECT_EQ("\"etag-readme\"", *parsed[0]->remote_etag);
    ASSERT_TRUE(parsed[0]->content_hash);
    EXPECT_EQ("content-hash", *parsed[0]->content_hash);
    EXPECT_EQ("iv", parsed[0]->encryption_iv);
    EXPECT_EQ(7u, parsed[0]->encrypted_with_key_version);
    ASSERT_TRUE(parsed[0]->remote_version_id);
    EXPECT_EQ("version-1", *parsed[0]->remote_version_id);
    ASSERT_TRUE(parsed[0]->remote_sequencer);
    EXPECT_EQ("000000000000000A", *parsed[0]->remote_sequencer);
}

TEST(S3CostSafetyTest, S3SequencerComparisonRejectsOlderEvents) {
    using vh::db::query::sync::s3SequencerIsNewerOrEqual;
    const auto seq = [](const char* value) { return std::make_optional<std::string>(value); };

    EXPECT_TRUE(s3SequencerIsNewerOrEqual(seq("A"), seq("9")));
    EXPECT_TRUE(s3SequencerIsNewerOrEqual(seq("000A"), seq("A")));
    EXPECT_TRUE(s3SequencerIsNewerOrEqual(seq("10"), seq("F")));
    EXPECT_FALSE(s3SequencerIsNewerOrEqual(seq("9"), seq("A")));
    EXPECT_FALSE(s3SequencerIsNewerOrEqual(seq("F"), seq("10")));
    EXPECT_TRUE(s3SequencerIsNewerOrEqual(std::nullopt, seq("10")));
    EXPECT_TRUE(s3SequencerIsNewerOrEqual(seq("10"), std::nullopt));
}

TEST(S3CostSafetyTest, RemoteManifestValidatesVaultIdCountAndChecksum) {
    auto standard = remoteFile("docs/readme.txt", "STANDARD");
    const std::vector<std::shared_ptr<vh::fs::model::File>> files{standard};

    const auto manifest = vh::sync::model::remote_manifest::buildIndexV1(123, files);
    EXPECT_NO_THROW((void)vh::sync::model::remote_manifest::parseIndexV1(manifest, 123));
    EXPECT_THROW(
        (void)vh::sync::model::remote_manifest::parseIndexV1(manifest, 456),
        std::runtime_error);

    auto parsed = nlohmann::json::parse(manifest);
    parsed["object_count"] = 99;
    EXPECT_THROW(
        (void)vh::sync::model::remote_manifest::parseIndexV1(parsed.dump(), 123),
        std::runtime_error);

    parsed = nlohmann::json::parse(manifest);
    parsed["objects"][0]["size_bytes"] = 999;
    EXPECT_THROW(
        (void)vh::sync::model::remote_manifest::parseIndexV1(parsed.dump(), 123),
        std::runtime_error);
}

TEST(S3CostSafetyTest, SelectedDownloadBlocksIntelligentTieringArchiveStatus) {
    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 99;
    vault->owner_id = 100;
    vault->encrypt_upstream = true;

    auto fake = std::make_shared<CountingS3Controller>();
    fake->head_response = std::unordered_map<std::string, std::string>{
        {"x-amz-storage-class", "INTELLIGENT_TIERING"},
        {"x-amz-archive-status", "ARCHIVE_ACCESS"},
    };

    vh::storage::CloudEngine engine;
    engine.vault = vault;
    engine.setS3ControllerForTesting(fake);

    const auto file = remoteFile("archive-tier/object.bin", "INTELLIGENT_TIERING");
    EXPECT_TRUE(engine.selectedDownloadRequiresRestore(file));
}

TEST(S3CostSafetyTest, EncryptedUploadDoesNotDownloadAfterPut) {
    const auto tempDir = std::filesystem::temp_directory_path() / "vh_s3_cost_safety_upload";
    std::filesystem::remove_all(tempDir);
    std::filesystem::create_directories(tempDir);
    const auto backing = tempDir / "ciphertext.bin";
    std::ofstream(backing, std::ios::binary) << "ciphertext";

    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 99;
    vault->owner_id = 100;
    vault->encrypt_upstream = true;

    auto fake = std::make_shared<CountingS3Controller>();
    vh::storage::CloudEngine engine;
    engine.vault = vault;
    engine.setS3ControllerForTesting(fake);

    auto file = std::make_shared<vh::fs::model::File>();
    file->path = "/ciphertext.bin";
    file->backing_path = backing;
    file->size_bytes = std::filesystem::file_size(backing);
    file->content_hash = "content-hash";
    file->encryption_iv = "iv";
    file->encrypted_with_key_version = 3;

    engine.upload(file);

    EXPECT_EQ(1, fake->upload_object_with_metadata_calls);
    EXPECT_EQ(0, fake->download_to_buffer_calls);
    EXPECT_EQ("true", fake->last_metadata.at("vh-encrypted"));
    EXPECT_EQ("iv", fake->last_metadata.at("vh-iv"));
    EXPECT_EQ("3", fake->last_metadata.at("vh-key-version"));

    std::filesystem::remove_all(tempDir);
}

TEST(S3CostSafetyTest, PlaintextUpstreamEmptyUploadWritesZeroByteRemoteObject) {
    const auto tempDir = std::filesystem::temp_directory_path() / "vh_s3_plain_empty_upload";
    std::filesystem::remove_all(tempDir);
    std::filesystem::create_directories(tempDir);
    const auto backing = tempDir / "empty.bin";
    std::ofstream(backing, std::ios::binary | std::ios::trunc).close();

    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 99;
    vault->owner_id = 100;
    vault->encrypt_upstream = false;

    auto fake = std::make_shared<CountingS3Controller>();
    vh::storage::CloudEngine engine;
    engine.vault = vault;
    engine.setS3ControllerForTesting(fake);

    auto file = std::make_shared<vh::fs::model::File>();
    file->path = "/empty.txt";
    file->backing_path = backing;
    file->size_bytes = 0;
    file->content_hash = "empty-content-hash";

    engine.upload(file);

    EXPECT_EQ(1, fake->upload_buffer_with_metadata_calls);
    EXPECT_EQ("empty.txt", fake->last_uploaded_key.generic_string());
    EXPECT_EQ(0u, fake->last_uploaded_buffer_size);
    EXPECT_EQ("false", fake->last_metadata.at("vh-encrypted"));
    EXPECT_EQ("empty-content-hash", fake->last_metadata.at("content-hash"));

    std::filesystem::remove_all(tempDir);
}

TEST(S3CostSafetyTest, PlaintextUploadBufferObjectWritesDirectoryMarkerKey) {
    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 99;
    vault->owner_id = 100;
    vault->encrypt_upstream = false;

    auto fake = std::make_shared<CountingS3Controller>();
    vh::storage::CloudEngine engine;
    engine.vault = vault;
    engine.setS3ControllerForTesting(fake);

    const auto file = engine.uploadBufferObject("/folder/", {}, "marker-content-hash");

    EXPECT_EQ(1, fake->upload_buffer_with_metadata_calls);
    EXPECT_EQ("folder/", fake->last_uploaded_key.generic_string());
    EXPECT_EQ(0u, fake->last_uploaded_buffer_size);
    ASSERT_TRUE(file);
    EXPECT_EQ("/folder/", file->path.generic_string());
    EXPECT_EQ(0u, file->size_bytes);
    ASSERT_TRUE(file->remote_encrypted);
    EXPECT_FALSE(*file->remote_encrypted);
    ASSERT_TRUE(file->content_hash);
    EXPECT_EQ("marker-content-hash", *file->content_hash);
    EXPECT_EQ("false", fake->last_metadata.at("vh-encrypted"));
    EXPECT_EQ("marker-content-hash", fake->last_metadata.at("content-hash"));
}

TEST(S3CostSafetyTest, EncryptedUpstreamEmptyUploadStoresEncryptedPayloadMetadata) {
    if (!hasDbEnv()) GTEST_SKIP() << "Skipping db-backed empty encrypted upload test due to missing environment variables.";

    const auto tempDir = std::filesystem::temp_directory_path() / "vh_s3_encrypted_empty_upload";
    std::filesystem::remove_all(tempDir);
    std::filesystem::create_directories(tempDir);
    const auto backing = tempDir / "empty.bin";
    std::ofstream(backing, std::ios::binary | std::ios::trunc).close();

    auto fake = std::make_shared<CountingS3Controller>();
    const auto vaultId = seedDryRunS3VaultForDbTest(uniqueSuffix("empty_encrypted_upload"), fake);
    auto engine = std::static_pointer_cast<vh::storage::CloudEngine>(
        vh::runtime::Deps::get().storageManager->getEngine(vaultId));
    engine->setS3ControllerForTesting(fake);
    std::static_pointer_cast<vh::vault::model::S3Vault>(engine->vault)->encrypt_upstream = true;

    auto file = std::make_shared<vh::fs::model::File>();
    file->path = "/empty.txt";
    file->backing_path = backing;
    file->size_bytes = 0;
    file->content_hash = "empty-content-hash";

    engine->upload(file);

    EXPECT_EQ(1, fake->upload_buffer_with_metadata_calls);
    EXPECT_EQ("empty.txt", fake->last_uploaded_key.generic_string());
    EXPECT_GT(fake->last_uploaded_buffer_size, 0u);
    EXPECT_EQ("true", fake->last_metadata.at("vh-encrypted"));
    ASSERT_FALSE(file->encryption_iv.empty());
    EXPECT_EQ(file->encryption_iv, fake->last_metadata.at("vh-iv"));
    EXPECT_GT(file->encrypted_with_key_version, 0u);
    EXPECT_EQ(std::to_string(file->encrypted_with_key_version), fake->last_metadata.at("vh-key-version"));

    std::filesystem::remove_all(tempDir);
}

TEST(S3CostSafetyTest, EncryptedUploadPassesConfiguredStorageClassAsSystemHeader) {
    const auto tempDir = std::filesystem::temp_directory_path() / "vh_s3_storage_tier_upload";
    std::filesystem::remove_all(tempDir);
    std::filesystem::create_directories(tempDir);
    const auto backing = tempDir / "ciphertext.bin";
    std::ofstream(backing, std::ios::binary) << "ciphertext";

    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 99;
    vault->owner_id = 100;
    vault->encrypt_upstream = true;
    vault->storage_tier_id = "standard_ia";

    auto fake = std::make_shared<CountingS3Controller>();
    vh::storage::CloudEngine engine;
    engine.vault = vault;
    engine.setS3ControllerForTesting(fake);
    engine.setS3ProviderProfileForTesting(
        vh::storage::s3::provider::resolve(vh::vault::model::S3Provider::AWS));

    auto file = std::make_shared<vh::fs::model::File>();
    file->path = "/ciphertext.bin";
    file->backing_path = backing;
    file->size_bytes = std::filesystem::file_size(backing);
    file->content_hash = "content-hash";
    file->encryption_iv = "iv";
    file->encrypted_with_key_version = 3;

    engine.upload(file);

    EXPECT_EQ(1, fake->upload_object_with_metadata_calls);
    ASSERT_TRUE(fake->last_system_headers.contains("x-amz-storage-class"));
    EXPECT_EQ("STANDARD_IA", fake->last_system_headers.at("x-amz-storage-class"));
    EXPECT_FALSE(fake->last_metadata.contains("storage-class"));

    std::filesystem::remove_all(tempDir);
}

TEST(S3CostSafetyTest, EncryptedUploadResolvesRelativeBackingPath) {
    const auto oldBackingPath = vh::paths::backingPath;
    const auto oldMountPath = vh::paths::mountPath;
    struct PathRestore {
        std::filesystem::path backing;
        std::filesystem::path mount;
        ~PathRestore() {
            vh::paths::backingPath = backing;
            vh::paths::mountPath = mount;
        }
    } restore{oldBackingPath, oldMountPath};

    const auto tempDir = std::filesystem::temp_directory_path() / "vh_s3_cost_safety_relative_upload";
    std::filesystem::remove_all(tempDir);
    vh::paths::backingPath = tempDir / "backing";
    vh::paths::mountPath = tempDir / "mount";
    std::filesystem::create_directories(vh::paths::backingPath);
    std::filesystem::create_directories(vh::paths::mountPath);

    const std::filesystem::path relBacking = std::filesystem::path("vault-alias") / "file-alias";
    const auto absBacking = vh::paths::backingPath / relBacking;
    std::filesystem::create_directories(absBacking.parent_path());
    std::ofstream(absBacking, std::ios::binary) << "ciphertext";

    auto vault = std::make_shared<vh::vault::model::S3Vault>();
    vault->id = 99;
    vault->owner_id = 100;
    vault->name = "relative-upload";
    vault->mount_point = "vault-alias";
    vault->encrypt_upstream = true;

    auto fake = std::make_shared<CountingS3Controller>();
    vh::storage::CloudEngine engine;
    engine.vault = vault;
    engine.paths = std::make_shared<vh::fs::model::Path>("relative-upload", "vault-alias");
    engine.setS3ControllerForTesting(fake);

    auto file = std::make_shared<vh::fs::model::File>();
    file->path = "/ciphertext.bin";
    file->backing_path = relBacking;
    file->size_bytes = std::filesystem::file_size(absBacking);
    file->content_hash = "content-hash";
    file->encryption_iv = "iv";
    file->encrypted_with_key_version = 3;

    engine.upload(file);

    EXPECT_EQ(1, fake->upload_object_with_metadata_calls);
    EXPECT_EQ(0, fake->download_to_buffer_calls);

    std::filesystem::remove_all(tempDir);
}
