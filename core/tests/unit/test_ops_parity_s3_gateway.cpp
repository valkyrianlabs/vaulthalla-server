// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The S3 gateway through both surfaces (Phase 2). `vh s3-gateway` and ws s3.gateway.* each re-implemented the
// credential, grant, bucket and budget rules and drifted: the web let a vault owner hand their credential role
// administration (S7), defaulted overrides to allow-everything (S10), told anyone whether a bucket existed before
// checking permission (S10), resolved vault names to the first match across owners, created remote-cache vaults
// it could orphan, and gave budgets different defaults. ops::s3_gateway is now the one implementation.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/s3/Gateway.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Roles.hpp"
#include "ops/S3Gateway.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/S3Gateway.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
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

namespace vh::test_ops_parity_s3_gateway {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
namespace gw = ops::s3_gateway;

std::string gwTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

std::string bucketTag() { return "gwp-" + gwTag(); }

class GatewayParityTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser;

    static UserPtr seedUser(const std::string& prefix, const std::string& roleName = "unprivileged") {
        const auto name = prefix + "_" + gwTag();
        return test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test");
    }

    static ops::vaults::VaultPtr vaultFor(const UserPtr& owner, const std::string& name = "") {
        return ops::vaults::create(superUser, {.name = name.empty() ? "gwp_vault_" + gwTag() : name,
                                               .type = vault::model::VaultType::Local, .owner_id = owner->id});
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_ops_parity_s3_gateway] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_gw_parity_" + gwTag());
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
        protocols::shell::commands::registerS3GatewayCommands(router);

        superUser = seedUser("gwp_super", "super_admin");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static std::pair<int, std::string> cli(const std::string& line, const UserPtr& user) {
        try {
            const auto res = router->executeLine(line, user, nullptr);
            return {res.exit_code, res.stdout_text + res.stderr_text};
        } catch (const std::exception& e) {
            return {1, e.what()};
        }
    }

    static std::shared_ptr<protocols::ws::Session> ws(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    static std::string wsError(const std::function<void()>& fn) {
        try {
            fn();
            return "";
        } catch (const std::exception& e) {
            return std::string("refused: ") + e.what();
        }
    }

    static bool wsOk(const std::function<void()>& fn) { return wsError(fn).empty(); }
};

TEST_F(GatewayParityTest, RoleAdministrationIsNotGrantedByNonAdminsOnEitherSurface) {
    // S7: a credential manager who may assign roles on a vault, but is not an admin, could give another principal's
    // credential a role with role-administration rights through the web (only Assign was checked); the CLI refused.
    const auto assignVaultRole = [](const uint32_t vaultId, const UserPtr& user, const std::string& role) {
        (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = vaultId, .subject = {.type = "user", .id = user->id}},
                                                      .role = role});
    };
    const auto owner = seedUser("gwp_owner");
    const auto vault = vaultFor(owner);
    const auto managerRole = "gwp_credmgr_" + gwTag();
    (void)ops::roles::createAdminRole(superUser, {.name = managerRole, .permissions = {.changes = {
        {"admin.s3_gateway.manage_credentials", true}, {"admin.s3_gateway.assign_principal", true}}}}, "test");
    const auto dave = seedUser("gwp_dave");
    const auto carol = seedUser("gwp_carol", managerRole);
    // Vault-role authority over other users comes from the global vault policy on the admin role.
    (void)vh::identities::manager().updateUser(carol->id, [&](identities::UserState& s) {
        auto role = std::make_shared<rbac::role::Admin>(*s.roles.admin);
        role->vGlobals = rbac::permission::admin::VaultGlobals::Manager(carol->id);
        s.roles.admin = role;
    });
    assignVaultRole(vault->id, dave, "contributor");
    ASSERT_FALSE(carol->isAdmin());
    const auto credential = gw::createCredential(superUser, {.name = "gwp_cred_" + gwTag(), .principal_id = dave->id}).credential;

    EXPECT_NE(cli("s3-gateway creds role assign " + std::to_string(credential.id) + " --vault " + std::to_string(vault->id) +
                  " --role manager", carol).first, 0);
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::S3Gateway::credentialsRolesAssign(
            json{{"credential_id", credential.id}, {"vault_id", vault->id}, {"vault_role_name", "manager"}}, ws(carol));
    }));
    EXPECT_TRUE(db::query::s3::Gateway::listCredentialVaultRoleAssignments(credential.id).empty());

    // A role within what the principal can do is fine, through either surface.
    const auto [code, out] = cli("s3-gateway creds role assign " + std::to_string(credential.id) + " --vault " +
                                 std::to_string(vault->id) + " --role reader", carol);
    EXPECT_EQ(code, 0) << out;
    EXPECT_TRUE(wsOk([&] {
        (void)protocols::ws::handler::S3Gateway::credentialsRolesAssign(
            json{{"credential_id", credential.id}, {"vault_id", vault->id}, {"vault_role_name", "contributor"}}, ws(carol));
    }));
}

TEST_F(GatewayParityTest, OverridesNeedAnEffectAndAPathOnBothSurfaces) {
    // S10: the web defaulted a missing effect to allow and a missing path to "**".
    const auto vault = vaultFor(superUser);
    const auto credential = gw::createCredential(superUser, {.name = "gwp_ovr_" + gwTag()}).credential;
    (void)gw::assignRole(superUser, credential.id, vault->id, db::query::rbac::role::Vault::get("reader")->id);

    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::S3Gateway::credentialsRoleOverridesAdd(
            json{{"credential_id", credential.id}, {"vault_id", vault->id}, {"permission", "download"}}, ws(superUser));
    }));
    EXPECT_NE(cli("s3-gateway creds role override add " + std::to_string(credential.id) + " --vault " +
                  std::to_string(vault->id) + " --permission download", superUser).first, 0);
    EXPECT_TRUE(db::query::s3::Gateway::listCredentialVaultRoleOverrides(credential.id, vault->id).empty());

    EXPECT_TRUE(wsOk([&] {
        (void)protocols::ws::handler::S3Gateway::credentialsRoleOverridesAdd(
            json{{"credential_id", credential.id}, {"vault_id", vault->id}, {"permission", "download"},
                 {"effect", "deny"}, {"glob_path", "/private/**"}}, ws(superUser));
    }));
    ASSERT_EQ(db::query::s3::Gateway::listCredentialVaultRoleOverrides(credential.id, vault->id).size(), 1u);
    EXPECT_EQ(db::query::s3::Gateway::listCredentialVaultRoleOverrides(credential.id, vault->id).front().glob_path(), "/private/**");
}

TEST_F(GatewayParityTest, UnbindRefusesBeforeRevealingWhetherABucketExists) {
    const auto vault = vaultFor(superUser);
    const auto bucket = bucketTag();
    (void)gw::bindBucket(superUser, {.vault_id = vault->id, .bucket_name = bucket});
    const auto bob = seedUser("gwp_bob");

    const auto existing = wsError([&] { (void)protocols::ws::handler::S3Gateway::bucketsUnbind(json{{"bucket_name", bucket}}, ws(bob)); });
    const auto missing = wsError([&] { (void)protocols::ws::handler::S3Gateway::bucketsUnbind(json{{"bucket_name", bucketTag()}}, ws(bob)); });
    EXPECT_FALSE(existing.empty());
    EXPECT_EQ(existing, missing) << "the answer used to differ: {unbound:false} for a missing bucket";
    EXPECT_EQ(cli("s3-gateway bucket unbind " + bucket, bob).second, cli("s3-gateway bucket unbind " + bucketTag(), bob).second);
    EXPECT_TRUE(db::query::s3::Gateway::resolveBucket(bucket));
}

TEST_F(GatewayParityTest, VaultNamesAreNeverResolvedToTheFirstMatch) {
    const auto alice = seedUser("gwp_alice"), bob = seedUser("gwp_bob");
    const auto shared = "gwp_same_" + gwTag();
    const auto aliceVault = vaultFor(alice, shared);
    (void)vaultFor(bob, shared);

    const auto ambiguous = bucketTag();
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::S3Gateway::bucketsBind(json{{"vault_name", shared}, {"bucket_name", ambiguous}}, ws(superUser));
    }));
    EXPECT_NE(cli("s3-gateway bucket bind " + ambiguous + " --vault " + shared, superUser).first, 0);
    EXPECT_FALSE(db::query::s3::Gateway::resolveBucket(ambiguous));

    // Naming the owner settles it, on both surfaces. (A vault has one binding, so each is checked as it lands.)
    const auto viaWs = bucketTag(), viaCli = bucketTag();
    ASSERT_TRUE(wsOk([&] {
        (void)protocols::ws::handler::S3Gateway::bucketsBind(
            json{{"vault_name", shared}, {"owner_id", alice->id}, {"bucket_name", viaWs}}, ws(superUser));
    }));
    ASSERT_TRUE(db::query::s3::Gateway::resolveBucket(viaWs));
    EXPECT_EQ(db::query::s3::Gateway::resolveBucket(viaWs)->vault_id, aliceVault->id);
    ASSERT_EQ(cli("s3-gateway bucket bind " + viaCli + " --vault " + shared + " --owner " + alice->name(), superUser).first, 0);
    ASSERT_TRUE(db::query::s3::Gateway::resolveBucket(viaCli));
    EXPECT_EQ(db::query::s3::Gateway::resolveBucket(viaCli)->vault_id, aliceVault->id);
}

TEST_F(GatewayParityTest, BudgetsGetTheSameDefaultsOnBothSurfaces) {
    const auto viaWs = gw::createCredential(superUser, {.name = "gwp_bud_ws_" + gwTag()}).credential;
    const auto viaCli = gw::createCredential(superUser, {.name = "gwp_bud_cli_" + gwTag()}).credential;

    const auto saved = protocols::ws::handler::S3Gateway::budgetPolicyUpsert(
        json{{"scope", "gateway_credential"}, {"gateway_credential_id", viaWs.id}, {"max_monthly_cost", "3.00"}}, ws(superUser));
    ASSERT_EQ(cli("s3-gateway budget set-key " + std::to_string(viaCli.id) + " --monthly 3.00", superUser).first, 0);

    const auto policies = gw::listBudgets(superUser, {});
    const auto find = [&](const uint32_t credentialId) {
        for (const auto& p : policies) if (p.gateway_credential_id == credentialId) return p;
        throw std::runtime_error("policy not found");
    };
    const auto a = find(viaWs.id), b = find(viaCli.id);
    EXPECT_EQ(a.mode, b.mode) << "the web defaulted to report, the CLI to enforce";
    EXPECT_EQ(a.mode, storage::s3::pricing::PriceBudgetMode::Enforce);
    EXPECT_EQ(a.max_catalog_age_seconds, b.max_catalog_age_seconds);
    EXPECT_EQ(saved.at("policy").at("mode").get<std::string>(), "enforce");
}

TEST_F(GatewayParityTest, RemovingAVaultFromACredentialRemovesItsRoleToo) {
    const auto vaultA = vaultFor(superUser), vaultB = vaultFor(superUser);
    const auto reader = db::query::rbac::role::Vault::get("reader")->id;
    const auto viaWs = gw::createCredential(superUser, {.name = "gwp_rm_ws_" + gwTag()}).credential;
    const auto viaCli = gw::createCredential(superUser, {.name = "gwp_rm_cli_" + gwTag()}).credential;
    (void)gw::assignRole(superUser, viaWs.id, vaultA->id, reader);
    (void)gw::assignRole(superUser, viaCli.id, vaultB->id, reader);

    (void)protocols::ws::handler::S3Gateway::credentialsSelectedVaultsRemove(
        json{{"credential_id", viaWs.id}, {"vault_id", vaultA->id}}, ws(superUser));
    ASSERT_EQ(cli("s3-gateway creds scope " + std::to_string(viaCli.id) + " revoke-vault " + std::to_string(vaultB->id),
                  superUser).first, 0);
    EXPECT_TRUE(db::query::s3::Gateway::listCredentialVaultRoleAssignments(viaWs.id).empty())
        << "the web left the per-vault role behind";
    EXPECT_TRUE(db::query::s3::Gateway::listCredentialVaultRoleAssignments(viaCli.id).empty());

    // Nothing left to revoke is an error on both, not a silent success.
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::S3Gateway::credentialsRolesRevoke(
            json{{"credential_id", viaWs.id}, {"vault_id", vaultA->id}}, ws(superUser));
    }));
    EXPECT_NE(cli("s3-gateway creds role revoke " + std::to_string(viaCli.id) + " --vault " + std::to_string(vaultB->id),
                  superUser).first, 0);
}

TEST_F(GatewayParityTest, CredentialScopesAreDecidedTheSameWay) {
    const auto vault = vaultFor(superUser);
    // Asking for user-access while naming vaults is contradictory: refused, never silently re-scoped.
    EXPECT_NE(cli("s3-gateway creds create gwp_c_" + gwTag() + " --scope user-access --vault " + std::to_string(vault->id),
                  superUser).first, 0);
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::S3Gateway::credentialsCreate(
            json{{"name", "gwp_c_" + gwTag()}, {"scope_mode", "user-access"}, {"vault_scopes", {{{"vault_id", vault->id}}}}},
            ws(superUser));
    }));

    // Naming vaults without a scope means vault-allowlist on both, with the same grant.
    const auto cliName = "gwp_c_cli_" + gwTag(), wsName = "gwp_c_ws_" + gwTag();
    const auto [code, out] = cli("s3-gateway creds create " + cliName + " --vault " + std::to_string(vault->id) + " --write",
                                 superUser);
    ASSERT_EQ(code, 0) << out;
    (void)protocols::ws::handler::S3Gateway::credentialsCreate(
        json{{"name", wsName}, {"vault_scopes", {{{"vault_id", vault->id}, {"can_write", true}}}}}, ws(superUser));

    const auto a = gw::getCredential(superUser, gw::Ref{cliName}), b = gw::getCredential(superUser, gw::Ref{wsName});
    EXPECT_EQ(a.scope_mode, "vault_allowlist");
    EXPECT_EQ(a.scope_mode, b.scope_mode);
    const auto roleOf = [](const gw::Credential& c) {
        const auto d = db::query::s3::Gateway::getCredentialDefaultVaultRole(c.id);
        return d ? d->vault_role_id : 0u;
    };
    EXPECT_EQ(roleOf(a), roleOf(b));
}

TEST_F(GatewayParityTest, RemoteCacheBucketsAreNotCreatedOverABoundName) {
    const auto vault = vaultFor(superUser);
    const auto taken = bucketTag();
    (void)gw::bindBucket(superUser, {.vault_id = vault->id, .bucket_name = taken});
    auto key = std::make_shared<vault::model::APIKey>(superUser->id, "gwp_key_" + gwTag(), vault::model::S3Provider::AWS,
                                                      "AKIATESTACCESSKEY000", "secret-value-00000000000000000000000",
                                                      "us-east-1", "https://s3.example.com");
    const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);

    const auto vaultsBefore = db::query::vault::Vault::listVaults().size();
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::S3Gateway::bucketsCreateRemoteCache(
            json{{"bucket_name", taken}, {"api_key_id", keyId}, {"upstream_bucket", "upstream"}}, ws(superUser));
    }));
    EXPECT_NE(cli("s3-gateway bucket create-remote-cache " + taken + " --api-key " + std::to_string(keyId) +
                  " --upstream-bucket upstream", superUser).first, 0);
    EXPECT_EQ(db::query::vault::Vault::listVaults().size(), vaultsBefore) << "a vault was created and left unbound";
}

}
