// Per-user global vault policy (user_global_vault_policy). Before 1.8.0 every account had one all-zero "self" row:
// VaultGlobals' default constructor labelled all three scopes "self" (they collapsed on the (user_id, scope) key) and
// roles loaded from admin_role carry no preset, so no account but the super admin (who bypasses the check) could use
// a vault through its global policy, its own default vault included.

#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <string>

namespace vh::test_global_vault_policy {

using Action = rbac::permission::vault::FilesystemAction;
using UserPtr = std::shared_ptr<identities::User>;

std::string gvpTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

// scope -> files_permissions bitstring
std::map<std::string, std::string> policyRows(const uint32_t userId) {
    return db::Transactions::exec("gvp::rows", [&](pqxx::work& txn) {
        std::map<std::string, std::string> out;
        for (const auto& row : txn.exec("SELECT scope::text, files_permissions::text FROM user_global_vault_policy "
                                        "WHERE user_id = $1", pqxx::params{userId}))
            out[row[0].as<std::string>()] = row[1].as<std::string>();
        return out;
    });
}

bool allZero(const std::string& bits) { return bits.find('1') == std::string::npos; }

TEST(GlobalVaultPolicy, DefaultScopesAreDistinct) {
    const rbac::permission::admin::VaultGlobals globals;
    EXPECT_EQ(globals.self.scope, rbac::role::vault::Global::Scope::Self);
    EXPECT_EQ(globals.admin.scope, rbac::role::vault::Global::Scope::Admin);
    EXPECT_EQ(globals.user.scope, rbac::role::vault::Global::Scope::User);
}

TEST(GlobalVaultPolicy, BuiltinPresetIsBoundToTheUser) {
    const auto auditor = rbac::role::Admin::builtin("auditor", 7);
    ASSERT_TRUE(auditor);
    EXPECT_TRUE(auditor->vGlobals.self.fs.files.canDownload()) << "the auditor preset is Reader";
    EXPECT_FALSE(rbac::role::Admin::builtin("not_a_builtin_role", 7));
}

class GlobalVaultPolicyDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_global_vault_policy] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_gvp_" + gvpTag());
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
        superUser = vh::identities::manager().userByName("admin");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static UserPtr create(const std::string& prefix, const std::string& role) {
        const auto created = ops::users::create(superUser, {.name = prefix + "_" + gvpTag(), .role = role,
                                                            .password = std::string("Gvp-Test-Pass-123")});
        return vh::identities::manager().user(created.user->id);
    }

    static bool canOnOwnVault(const UserPtr& user, const Action action) {
        const auto vault = db::query::vault::Vault::listUserVaults(user->id).front();
        const auto engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        const auto root = engine->paths->absRelToRoot(engine->paths->vaultRoot, fs::model::PathType::FUSE_ROOT);
        return rbac::resolver::Vault::has<Action>({.user = user, .permission = action, .vault_id = vault->id, .path = root});
    }
};

TEST_F(GlobalVaultPolicyDbTest, NewAccountsGetTheirRolesPresetInAllThreeScopes) {
    const auto auditor = create("gvp_auditor", "auditor");
    const auto rows = policyRows(auditor->id);
    ASSERT_EQ(rows.size(), 3u) << "one row per scope; they used to collapse into a single self row";
    for (const auto& [scope, files] : rows) EXPECT_FALSE(allZero(files)) << scope << " should carry the Reader preset";
    EXPECT_TRUE(canOnOwnVault(auditor, Action::List));
    EXPECT_TRUE(canOnOwnVault(auditor, Action::Read));

    // unprivileged means no global vault rights, as defined.
    const auto plain = create("gvp_plain", "unprivileged");
    const auto plainRows = policyRows(plain->id);
    ASSERT_EQ(plainRows.size(), 3u);
    for (const auto& [scope, files] : plainRows) EXPECT_TRUE(allZero(files)) << scope;
    EXPECT_FALSE(canOnOwnVault(plain, Action::Read));
}

TEST_F(GlobalVaultPolicyDbTest, ARoleChangeRewritesThePolicy) {
    const auto user = create("gvp_change", "unprivileged");
    ASSERT_FALSE(canOnOwnVault(user, Action::Read));
    (void)ops::users::update(superUser, {.id = user->id, .role = std::string("auditor")});
    const auto rows = policyRows(user->id);
    ASSERT_EQ(rows.size(), 3u);
    for (const auto& [scope, files] : rows) EXPECT_FALSE(allZero(files)) << scope;
    EXPECT_TRUE(canOnOwnVault(vh::identities::manager().user(user->id), Action::Read));
}

// A custom role is seeded from --from (or nothing: unprivileged) and then owns its own bitmasks. It stores no global
// vault policy, so its accounts are seeded from the unprivileged constructor.
TEST_F(GlobalVaultPolicyDbTest, CustomRolesCopyTheirSourceAndSeedAccountsUnprivileged) {
    const auto auditor = rbac::role::Admin::Auditor();
    const auto custom = ops::roles::createAdminRole(superUser, {.name = "gvp_custom_" + gvpTag(),
                                                                .from = std::string("auditor")}, "test");
    EXPECT_EQ(custom->toFlagsString(), auditor.toFlagsString()) << "--from copies the source role's permissions";

    const auto blank = ops::roles::createAdminRole(superUser, {.name = "gvp_blank_" + gvpTag()}, "test");
    EXPECT_EQ(blank->toFlagsString(), rbac::role::Admin::None().toFlagsString()) << "no --from starts unprivileged";

    const auto user = create("gvp_custom_user", custom->name);
    const auto rows = policyRows(user->id);
    ASSERT_EQ(rows.size(), 3u);
    for (const auto& [scope, files] : rows) EXPECT_TRUE(allZero(files)) << scope;
    EXPECT_FALSE(canOnOwnVault(user, Action::Read));
}

TEST_F(GlobalVaultPolicyDbTest, StartupRepairsAccountsWrittenTheOldWay) {
    const auto user = create("gvp_legacy", "auditor");
    // The shape every pre-1.8.0 account has: one all-zero self row.
    db::Transactions::exec("gvp::legacy", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM user_global_vault_policy WHERE user_id = $1", pqxx::params{user->id});
        txn.exec("INSERT INTO user_global_vault_policy (user_id, scope, files_permissions, directories_permissions, "
                 "sync_permissions, roles_permissions) VALUES ($1, 'self', B'0'::bit(32), B'0'::bit(32), "
                 "B'0'::bit(32), B'0'::bit(16))", pqxx::params{user->id});
    });
    (void)vh::identities::manager().reconcile();   // the revision watcher's job in the daemon
    ASSERT_FALSE(canOnOwnVault(vh::identities::manager().user(user->id), Action::Read));

    seed::reconcileGlobalVaultPolicies();
    const auto rows = policyRows(user->id);
    ASSERT_EQ(rows.size(), 3u);
    for (const auto& [scope, files] : rows) EXPECT_FALSE(allZero(files)) << scope;
    EXPECT_TRUE(canOnOwnVault(vh::identities::manager().user(user->id), Action::Read));

    // Idempotent: a correctly written account is left alone.
    seed::reconcileGlobalVaultPolicies();
    EXPECT_EQ(policyRows(user->id), rows);
}

}
