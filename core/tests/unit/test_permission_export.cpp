#include "rbac/role/Vault.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/vault/Global.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "crypto/util/hash.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/rbac/role/vault/Global.hpp"
#include "db/Transactions.hpp"
#include "seed/include/init_db_tables.hpp"

#include <paths.h>
#include <gtest/gtest.h>

using namespace vh;

class PermExportTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;

    static void SetUpTestSuite() {
        if (!static_cast<bool>(std::getenv("VH_TEST_DB_USER")) ||
            !static_cast<bool>(std::getenv("VH_TEST_DB_PASS")) ||
            !static_cast<bool>(std::getenv("VH_TEST_DB_HOST")) ||
            !static_cast<bool>(std::getenv("VH_TEST_DB_PORT")) ||
            !static_cast<bool>(std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_permission_export] Skipping db tests due to missing environment variables." <<
                    std::endl;
            return;
        }

        paths::enableTestMode();
        db::Transactions::init();
        db::seed::wipe_all_data_restart_identity();
        db::seed::init_tables_if_not_exists();
        db::Transactions::dbPool_->initPreparedStatements();
    }

    void SetUp() override {
        /* no op for now */
    }
};

TEST_F(PermExportTest, TestVaultPermExport) {
    const auto vRole = rbac::role::Vault::PowerUser();
    EXPECT_FALSE(vRole.toFlagsString().empty());

    const auto flags = vRole.getFlags();
    EXPECT_FALSE(flags.empty());
}

TEST_F(PermExportTest, TestAdminPermExport) {
    const auto role = rbac::role::Admin::SecurityAdmin();
    EXPECT_FALSE(role.toFlagsString().empty());

    const auto flags = role.getFlags();
    EXPECT_FALSE(flags.empty());
}

TEST_F(PermExportTest, TestAdminRoleDBRoundTripBitStrings) {
    if (skipTests)
        GTEST_SKIP() << "Skipping db tests due to missing environment variables.";

    const auto role = std::make_shared<rbac::role::Admin>(rbac::role::Admin::SuperAdmin());
    role->id = 0;
    role->name = "test_super_admin_roundtrip";
    role->description = "A test super admin role";

    const auto identitiesBefore = role->identities.toBitString();
    const auto vaultsBefore = role->vaults.toBitString();
    const auto auditsBefore = role->audits.toBitString();
    const auto settingsBefore = role->settings.toBitString();
    const auto rolesBefore = role->roles.toBitString();
    const auto keysBefore = role->keys.toBitString();

    db::query::rbac::role::Admin::upsert(role);

    const auto roundtrip = db::query::rbac::role::Admin::get(role->name);
    ASSERT_NE(roundtrip, nullptr);

    EXPECT_EQ(roundtrip->identities.toBitString(), identitiesBefore);
    EXPECT_EQ(roundtrip->vaults.toBitString(), vaultsBefore);
    EXPECT_EQ(roundtrip->audits.toBitString(), auditsBefore);
    EXPECT_EQ(roundtrip->settings.toBitString(), settingsBefore);
    EXPECT_EQ(roundtrip->roles.toBitString(), rolesBefore);
    EXPECT_EQ(roundtrip->keys.toBitString(), keysBefore);
}

TEST_F(PermExportTest, TestVaultRoleDBRoundTripBitStrings) {
    if (skipTests)
        GTEST_SKIP() << "Skipping db tests due to missing environment variables.";

    const auto role = std::make_shared<rbac::role::Vault>(rbac::role::Vault::PowerUser());
    role->id = 0;
    role->name = "test_power_user_vault_roundtrip";
    role->description = "A test power user vault role";

    const auto rolesBefore = role->roles.toBitString();
    const auto syncBefore = role->sync.toBitString();
    const auto fsFilesBefore = role->fs.files.toBitString();
    const auto fsDirectoriesBefore = role->fs.directories.toBitString();

    db::query::rbac::role::Vault::upsert(role);

    const auto roundtrip = db::query::rbac::role::Vault::get(role->name);
    ASSERT_NE(roundtrip, nullptr);

    EXPECT_EQ(roundtrip->roles.toBitString(), rolesBefore);
    EXPECT_EQ(roundtrip->sync.toBitString(), syncBefore);
    EXPECT_EQ(roundtrip->fs.files.toBitString(), fsFilesBefore);
    EXPECT_EQ(roundtrip->fs.directories.toBitString(), fsDirectoriesBefore);
}

TEST_F(PermExportTest, TestUserAdminVaultGlobalsDBRoundTripBitStrings) {
    if (skipTests)
        GTEST_SKIP() << "Skipping db tests due to missing environment variables.";

    if (!db::query::rbac::role::Admin::get(rbac::role::Admin::SuperAdmin().name))
        db::query::rbac::role::Admin::upsert(std::make_shared<rbac::role::Admin>(rbac::role::Admin::SuperAdmin()));

    const auto created = vh::test::identities::createUser(
        "test_user_vglobals_roundtrip", db::query::rbac::role::Admin::get(rbac::role::Admin::SuperAdmin().name),
        "test_user_vglobals_roundtrip@vaulthalla.test", vh::crypto::hash::password("test_password"));
    ASSERT_NE(created, nullptr);
    ASSERT_NE(created->id, 0u);
    ASSERT_NE(created->state()->roles.admin, nullptr);

    // A local copy of the account's admin role carrying the policy to write.
    const auto userId = created->id;
    const auto role = std::make_shared<rbac::role::Admin>(*created->state()->roles.admin);

    role->vGlobals.self =
            rbac::role::vault::Global::PowerUser(userId, rbac::role::vault::Global::Scope::Self);

    role->vGlobals.user =
            rbac::role::vault::Global::PowerUser(userId, rbac::role::vault::Global::Scope::User);

    role->vGlobals.admin =
            rbac::role::vault::Global::PowerUser(userId, rbac::role::vault::Global::Scope::Admin);

    const auto selfRolesBefore = role->vGlobals.self.roles.toBitString();
    const auto selfSyncBefore = role->vGlobals.self.sync.toBitString();
    const auto selfFsFilesBefore = role->vGlobals.self.fs.files.toBitString();
    const auto selfFsDirectoriesBefore = role->vGlobals.self.fs.directories.toBitString();

    const auto userRolesBefore = role->vGlobals.user.roles.toBitString();
    const auto userSyncBefore = role->vGlobals.user.sync.toBitString();
    const auto userFsFilesBefore = role->vGlobals.user.fs.files.toBitString();
    const auto userFsDirectoriesBefore = role->vGlobals.user.fs.directories.toBitString();

    const auto adminRolesBefore = role->vGlobals.admin.roles.toBitString();
    const auto adminSyncBefore = role->vGlobals.admin.sync.toBitString();
    const auto adminFsFilesBefore = role->vGlobals.admin.fs.files.toBitString();
    const auto adminFsDirectoriesBefore = role->vGlobals.admin.fs.directories.toBitString();

    db::query::rbac::role::vault::Global::upsert(
        std::make_shared<rbac::role::vault::Global>(role->vGlobals.self)
    );
    db::query::rbac::role::vault::Global::upsert(
        std::make_shared<rbac::role::vault::Global>(role->vGlobals.user)
    );
    db::query::rbac::role::vault::Global::upsert(
        std::make_shared<rbac::role::vault::Global>(role->vGlobals.admin)
    );

    // Written behind the Manager's back: a reload (what the revision watcher does for out-of-band writes) must
    // publish it into the canonical object the test already holds.
    vh::identities::manager().refresh({.users = {userId}});
    const auto roundtrip = vh::identities::manager().user(userId);
    ASSERT_EQ(roundtrip.get(), created.get());
    ASSERT_NE(roundtrip, nullptr);
    ASSERT_NE(roundtrip->state()->roles.admin, nullptr);

    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.self.roles.toBitString(), selfRolesBefore);
    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.self.sync.toBitString(), selfSyncBefore);
    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.self.fs.files.toBitString(), selfFsFilesBefore);
    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.self.fs.directories.toBitString(), selfFsDirectoriesBefore);

    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.user.roles.toBitString(), userRolesBefore);
    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.user.sync.toBitString(), userSyncBefore);
    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.user.fs.files.toBitString(), userFsFilesBefore);
    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.user.fs.directories.toBitString(), userFsDirectoriesBefore);

    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.admin.roles.toBitString(), adminRolesBefore);
    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.admin.sync.toBitString(), adminSyncBefore);
    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.admin.fs.files.toBitString(), adminFsFilesBefore);
    EXPECT_EQ(roundtrip->state()->roles.admin->vGlobals.admin.fs.directories.toBitString(), adminFsDirectoriesBefore);
}
