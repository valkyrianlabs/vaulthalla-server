// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Price budgets, settings and health through both surfaces (Phase 2). The web let any vault owner change (and so
// disable) a vault's price budget and accepted budgets on local vaults and unknown providers; settings.update
// skipped email validation and email.config.update clamped what the CLI refused; and stats.system.health had no
// live database probe, so it could read healthy while PostgreSQL was down (S11). ops::pricing and ops::config
// now hold those rules, and SystemHealth owns the probe.

#include "../helpers/identities.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Config.hpp"
#include "ops/Error.hpp"
#include "ops/Pricing.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Email.hpp"
#include "protocols/ws/handler/Pricing.hpp"
#include "protocols/ws/handler/Settings.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "stats/model/SystemHealth.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/pricing/PriceBudget.hpp"
#include "UsageManager.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <string>

namespace vh::test_ops_parity_pricing_config {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
namespace budget = storage::s3::pricing;

std::string pcTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

class PricingConfigParityTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser;

    static UserPtr seedUser(const std::string& prefix, const std::string& roleName = "unprivileged") {
        const auto name = prefix + "_" + pcTag();
        auto user = vh::test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test", "x", std::nullopt);
        return vh::identities::manager().user(user->id);
    }

    static ops::vaults::VaultPtr s3VaultFor(const UserPtr& owner) {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "pc_key_" + pcTag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-00000000000000000000000",
                                                          "us-east-1", "https://s3.example.com");
        const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        return ops::vaults::create(superUser, {.name = "pc_s3_" + pcTag(), .type = vault::model::VaultType::S3,
                                               .owner_id = owner->id,
                                               .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = "pc-bucket"}});
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_ops_parity_pricing_config] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_pc_parity_" + pcTag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerPricingCommands(router);
        protocols::shell::commands::registerEmailCommands(router);
        protocols::shell::commands::registerS3GatewayCommands(router);

        superUser = seedUser("pc_super", "super_admin");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static int cli(const std::string& line, const UserPtr& user) {
        try {
            return router->executeLine(line, user, nullptr).exit_code;
        } catch (const std::exception&) {
            return 1;
        }
    }

    static std::shared_ptr<protocols::ws::Session> ws(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    static bool wsOk(const std::function<void()>& fn) {
        try {
            fn();
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    static bool hasVaultPolicy(const uint32_t vaultId) {
        for (const auto& p : budget::PriceBudgetService{}.listPolicies(true))
            if (p.scope == budget::PriceBudgetScope::Vault && p.vault_id == vaultId && p.is_active) return true;
        return false;
    }
};

TEST_F(PricingConfigParityTest, VaultBudgetsNeedVaultEditOnBothSurfaces) {
    // The web let any owner change, and so disable, a budget an admin imposed on their vault.
    const auto owner = seedUser("pc_owner");
    const auto vault = s3VaultFor(owner);
    ASSERT_EQ(cli("pricing budget set-vault " + std::to_string(vault->id) + " --max-monthly 5.00 --mode enforce", superUser), 0);
    ASSERT_TRUE(hasVaultPolicy(vault->id));

    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Pricing::policyDisable(json{{"scope", "vault"}, {"vault_id", vault->id}}, ws(owner));
    }));
    EXPECT_NE(cli("pricing budget disable-vault " + std::to_string(vault->id), owner), 0);
    EXPECT_TRUE(hasVaultPolicy(vault->id)) << "the owner removed an admin-imposed budget";

    EXPECT_TRUE(wsOk([&] {
        (void)protocols::ws::handler::Pricing::policyDisable(json{{"scope", "vault"}, {"vault_id", vault->id}}, ws(superUser));
    }));
    EXPECT_FALSE(hasVaultPolicy(vault->id));
}

TEST_F(PricingConfigParityTest, BudgetTargetsAreValidatedOnBothSurfaces) {
    const auto local = ops::vaults::create(superUser, {.name = "pc_local_" + pcTag(), .type = vault::model::VaultType::Local});
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Pricing::policyUpsert(
            json{{"scope", "vault"}, {"vault_id", local->id}, {"max_monthly_cost", "1.00"}}, ws(superUser));
    })) << "the web accepted a price budget on a local vault";
    EXPECT_NE(cli("pricing budget set-vault " + std::to_string(local->id) + " --max-monthly 1.00", superUser), 0);

    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Pricing::policyUpsert(
            json{{"scope", "provider"}, {"provider_key", "not-a-provider"}, {"max_monthly_cost", "1.00"}}, ws(superUser));
    })) << "the web accepted an unknown provider";
    EXPECT_NE(cli("pricing budget set-provider not-a-provider --max-monthly 1.00", superUser), 0);

    for (const auto& p : budget::PriceBudgetService{}.listPolicies(true)) {
        EXPECT_NE(p.vault_id, std::optional<uint32_t>{local->id});
        EXPECT_NE(p.provider_key, std::optional<std::string>{"not-a-provider"});
    }
}

TEST_F(PricingConfigParityTest, SettingsWritesAreValidatedOnEverySurface) {
    const auto before = json(config::Registry::get());
    // settings.update used to write email fields with no validation at all.
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Settings::update(json{{"email", {{"from", "not an address"}}}}, ws(superUser));
    }));
    // email.config.update used to clamp what the CLI refuses.
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Email::updateConfig(
            json{{"operator_emails", {{"alerting", {{"health_poll_seconds", 5}}}}}}, ws(superUser));
    }));
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Email::updateConfig(
            json{{"operator_emails", {{"weekly_digest", {{"hour_local", 30}}}}}}, ws(superUser));
    }));
    // settings.update could point the daemon at any executable directory as the converter helpers.
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Settings::update(
            json{{"preview", {{"derive", {{"helper_dir", "/tmp"}}}}}}, ws(superUser));
    }));
    EXPECT_NE(cli("email alerting set health-poll-seconds 5", superUser), 0);
    EXPECT_NE(cli("email weekly set hour 30", superUser), 0);
    EXPECT_EQ(json(config::Registry::get()), before) << "a refused write changed the settings";

    // Only super admins change settings, and only gateway service managers toggle the gateway.
    const auto plain = seedUser("pc_plain");
    EXPECT_FALSE(wsOk([&] { (void)protocols::ws::handler::Settings::update(json::object(), ws(plain)); }));
    EXPECT_THROW((void)ops::config::setGatewayEnabled(plain, !config::Registry::get().s3_gateway.enabled), ops::Denied);
    EXPECT_NE(cli("s3-gateway enable", plain), 0);
}

TEST(SystemHealthProbe, SnapshotCarriesALiveDatabaseProbe) {
    if (!std::getenv("VH_TEST_DB_HOST")) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    db::Transactions::init();
    const auto health = stats::model::SystemHealth::snapshot();
    ASSERT_TRUE(health.database);
    EXPECT_TRUE(health.database->reachable) << health.database->probeError;
    const auto j = json(health);
    EXPECT_TRUE(j.at("database").at("reachable").get<bool>());
    EXPECT_TRUE(j.at("database").contains("probe_latency_ms"));
}

}
