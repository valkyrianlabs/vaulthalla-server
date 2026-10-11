#include "../helpers/identities.hpp"
#include "auth/Manager.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "rbac/permission/admin/Identities.hpp"
#include "rbac/permission/admin/identities/Base.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "seed/include/SqlDeployer.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

namespace vh::auth::test_password_change {
using json = nlohmann::json;

struct ScopedRuntimeAuthManager {
    std::shared_ptr<vh::auth::Manager> previous;

    explicit ScopedRuntimeAuthManager(std::shared_ptr<vh::auth::Manager> manager)
        : previous(vh::runtime::Deps::get().authManager) {
        vh::runtime::Deps::get().authManager = std::move(manager);
    }

    ~ScopedRuntimeAuthManager() {
        vh::runtime::Deps::get().authManager = std::move(previous);
    }
};

std::shared_ptr<vh::protocols::ws::Session> sessionFor(const std::shared_ptr<vh::identities::User>& user) {
    auto session = std::make_shared<vh::protocols::ws::Session>(std::make_shared<vh::protocols::ws::Router>());
    session->user = user;
    return session;
}

bool authenticate(const std::string& name, const std::string& password) {
    return vh::db::query::identities::User::authenticateUser(name, password);
}

class AuthPasswordChangeTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;

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
            std::cout << "[test_auth_password_change] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }

        vh::paths::enableTestMode();
        vh::db::Transactions::init();
        vh::db::seed::nuke_and_recreate_schema_public();
        vh::db::seed::init_tables_if_not_exists();
        vh::db::Transactions::dbPool_->initPreparedStatements();
        vh::seed::initPermissions();
        vh::seed::initRoles();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static std::shared_ptr<vh::identities::User> createUser(
        const std::string& name,
        const std::string& password,
        const std::string& roleName = "unprivileged"
    ) {
        auto role = vh::db::query::rbac::role::Admin::get(roleName);
        if (!role) throw std::runtime_error("Missing admin role: " + roleName);
        return vh::test::identities::createUser(name, role, name + "@vaulthalla.test",
                                                vh::crypto::hash::password(password));
    }

    static std::shared_ptr<vh::identities::User> createSystemOnlyUser(
        const std::string& name,
        const std::string& password
    ) {
        const auto role = vh::db::query::rbac::role::Admin::get("unprivileged");
        if (!role) throw std::runtime_error("Missing unprivileged role");

        const auto id = vh::db::Transactions::exec("AuthPasswordChangeTest::createSystemOnlyUser", [&](pqxx::work& txn) {
            txn.exec("SELECT set_config('vaulthalla.bootstrap', 'on', true)");

            const auto userId = txn.exec(
                R"SQL(
                    INSERT INTO users (name, email, password_hash, is_active, protected, system_only)
                    VALUES ($1, $2, $3, TRUE, FALSE, TRUE)
                    RETURNING id
                )SQL",
                pqxx::params{name, name + "@vaulthalla.test", vh::crypto::hash::password(password)}
            ).one_field_ref().as<unsigned int>();

            txn.exec(
                "INSERT INTO admin_role_assignments (user_id, role_id) VALUES ($1, $2)",
                pqxx::params{userId, role->id}
            );

            return userId;
        });

        return vh::identities::manager().user(id);
    }
};
// #163: password_changed_at had no column, so it was null after every reload.
void backdatePasswordChange(const unsigned int userId) {
    vh::db::Transactions::exec("AuthPasswordChangeTest::backdate", [&](pqxx::work& txn) {
        txn.exec("UPDATE users SET password_changed_at = NOW() - INTERVAL '30 days' WHERE id = $1", pqxx::params{userId});
    });
}

// Seconds since the stored password_changed_at, or nullopt when it is NULL.
std::optional<double> passwordChangedSecondsAgo(const unsigned int userId) {
    return vh::db::Transactions::exec("AuthPasswordChangeTest::changedAgo", [&](pqxx::work& txn) {
        return txn.exec("SELECT EXTRACT(EPOCH FROM (NOW() - password_changed_at))::double precision FROM users WHERE id = $1",
                        pqxx::params{userId}).one_field_ref().as<std::optional<double>>();
    });
}

bool justNow(const std::optional<double>& secondsAgo) { return secondsAgo && *secondsAgo >= 0.0 && *secondsAgo < 120.0; }

TEST(AuthPasswordPermissionTest, ResetPasswordBitIsAdditiveAndSeededOnlyForOrgAndSuperAdmins) {
    using P = vh::rbac::permission::admin::identities::IdentityPermissions;

    EXPECT_EQ(static_cast<unsigned int>(P::View), 1u);
    EXPECT_EQ(static_cast<unsigned int>(P::Add), 2u);
    EXPECT_EQ(static_cast<unsigned int>(P::Edit), 4u);
    EXPECT_EQ(static_cast<unsigned int>(P::Delete), 8u);
    EXPECT_EQ(static_cast<unsigned int>(P::ResetPassword), 16u);

    const auto orgAdmin = vh::rbac::role::Admin::OrgAdmin();
    EXPECT_TRUE(orgAdmin.identities.users.canResetPassword());
    EXPECT_TRUE(orgAdmin.identities.admins.canResetPassword());

    const auto superAdmin = vh::rbac::role::Admin::SuperAdmin();
    EXPECT_TRUE(superAdmin.identities.users.canResetPassword());
    EXPECT_TRUE(superAdmin.identities.admins.canResetPassword());

    const auto identityAdmin = vh::rbac::role::Admin::IdentityAdmin();
    EXPECT_FALSE(identityAdmin.identities.users.canResetPassword());
    EXPECT_FALSE(identityAdmin.identities.admins.canResetPassword());

    const auto securityAdmin = vh::rbac::role::Admin::SecurityAdmin();
    EXPECT_FALSE(securityAdmin.identities.users.canResetPassword());
    EXPECT_FALSE(securityAdmin.identities.admins.canResetPassword());
}

TEST_F(AuthPasswordChangeTest, SelfPasswordChangePersistsToDatabase) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);

    const auto user = createUser("self_password_change", "old-password");
    const auto session = sessionFor(user);

    const auto response = vh::protocols::ws::handler::Auth::changePassword(
        json{{"id", user->id}, {"old_password", "old-password"}, {"new_password", "new-password"}},
        session
    );

    EXPECT_EQ(response.at("user").at("id").get<unsigned int>(), user->id);
    EXPECT_FALSE(authenticate(user->name(), "old-password"));
    EXPECT_TRUE(authenticate(user->name(), "new-password"));
}

TEST_F(AuthPasswordChangeTest, SelfPasswordChangeRequiresOldPassword) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);

    const auto user = createUser("self_password_missing_old", "old-password");
    const auto session = sessionFor(user);

    EXPECT_THROW(
        (void) vh::protocols::ws::handler::Auth::changePassword(
            json{{"id", user->id}, {"new_password", "new-password"}},
            session
        ),
        std::runtime_error
    );

    EXPECT_TRUE(authenticate(user->name(), "old-password"));
    EXPECT_FALSE(authenticate(user->name(), "new-password"));
}

TEST_F(AuthPasswordChangeTest, AdminResetPersistsWithoutOldPasswordWhenPermissionIsGranted) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);

    const auto actor = createUser("password_reset_actor", "actor-password", "admin");
    const auto target = createUser("password_reset_target", "old-password");
    const auto session = sessionFor(actor);

    const auto response = vh::protocols::ws::handler::Auth::changePassword(
        json{{"id", target->id}, {"new_password", "new-password"}},
        session
    );

    EXPECT_EQ(response.at("user").at("id").get<unsigned int>(), target->id);
    EXPECT_FALSE(authenticate(target->name(), "old-password"));
    EXPECT_TRUE(authenticate(target->name(), "new-password"));
}

TEST_F(AuthPasswordChangeTest, AdminResetIsDeniedWithoutResetPermission) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);

    const auto actor = createUser("password_reset_denied_actor", "actor-password", "identity_admin");
    const auto target = createUser("password_reset_denied_target", "old-password");
    const auto session = sessionFor(actor);

    EXPECT_THROW(
        (void) vh::protocols::ws::handler::Auth::changePassword(
            json{{"id", target->id}, {"new_password", "new-password"}},
            session
        ),
        std::runtime_error
    );

    EXPECT_TRUE(authenticate(target->name(), "old-password"));
    EXPECT_FALSE(authenticate(target->name(), "new-password"));
}

TEST_F(AuthPasswordChangeTest, AdminResetUsesAdminScopeForAdminTargets) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);

    // The target is an admin-class account the actor outranks. (This test used to reset a super_admin's password
    // from the admin role: the escalation SuperAdminPasswordCannotBeResetByOthers now refuses.)
    const auto actor = createUser("admin_password_reset_actor", "actor-password", "admin");
    const auto target = createUser("admin_password_reset_target", "old-password", "auditor");
    ASSERT_TRUE(vh::ops::users::isAdminIdentity(*target->state()->roles.admin));
    ASSERT_TRUE(vh::ops::roles::permissionsBeyondActor(actor, *target->state()->roles.admin).empty());

    // The users scope is not enough for an admin-class account.
    const auto usersOnly = createUser("admin_password_reset_users_only", "actor-password", "identity_admin");
    EXPECT_THROW((void)vh::protocols::ws::handler::Auth::changePassword(
        json{{"id", target->id}, {"new_password", "new-password"}}, sessionFor(usersOnly)), std::runtime_error);
    EXPECT_TRUE(authenticate(target->name(), "old-password"));

    const auto session = sessionFor(actor);

    const auto response = vh::protocols::ws::handler::Auth::changePassword(
        json{{"id", target->id}, {"new_password", "new-password"}},
        session
    );

    EXPECT_EQ(response.at("user").at("id").get<unsigned int>(), target->id);
    EXPECT_FALSE(authenticate(target->name(), "old-password"));
    EXPECT_TRUE(authenticate(target->name(), "new-password"));
}

TEST_F(AuthPasswordChangeTest, SuperAdminPasswordCannotBeResetByOthers) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);

    const auto actor = createUser("super_reset_actor", "actor-password", "admin");
    const auto target = createUser("super_reset_target", "old-password", "super_admin");

    EXPECT_THROW((void)vh::protocols::ws::handler::Auth::changePassword(
        json{{"id", target->id}, {"new_password", "new-password"}}, sessionFor(actor)), std::runtime_error);
    EXPECT_TRUE(authenticate(target->name(), "old-password"));
}

TEST_F(AuthPasswordChangeTest, PasswordResetRejectsSystemOnlyTarget) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);

    const auto actor = createUser("system_only_reset_actor", "actor-password", "admin");
    const auto target = createSystemOnlyUser("system_only_reset_target", "old-password");
    const auto session = sessionFor(actor);

    EXPECT_THROW(
        (void) vh::protocols::ws::handler::Auth::changePassword(
            json{{"id", target->id}, {"new_password", "new-password"}},
            session
        ),
        std::runtime_error
    );
}

TEST_F(AuthPasswordChangeTest, ChangePasswordRejectsMissingSessionUser) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);

    const auto target = createUser("missing_session_target", "old-password");
    const auto session = std::make_shared<vh::protocols::ws::Session>(std::make_shared<vh::protocols::ws::Router>());

    EXPECT_THROW(
        (void) vh::protocols::ws::handler::Auth::changePassword(
            json{{"id", target->id}, {"new_password", "new-password"}},
            session
        ),
        std::runtime_error
    );

    EXPECT_TRUE(authenticate(target->name(), "old-password"));
}

// Regression (#126): the web "Edit User" form sends auth.user.update with the target's id; the handler used to
// ignore it and apply the edit (name/email/is_active) to the calling admin instead.
TEST_F(AuthPasswordChangeTest, UpdateUserTargetsPayloadIdNotCaller) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);
    const auto admin = createUser("upd_admin_target", "admin-password", "admin");
    const auto target = createUser("upd_plain_target", "plain-password");

    const auto response = vh::protocols::ws::handler::Auth::updateUser(
        json{{"id", target->id}, {"name", "upd_plain_renamed"}, {"email", "renamed@vaulthalla.test"},
             {"is_active", false}, {"role", target->state()->roles.admin->name}, {"password", ""}},
        sessionFor(admin));

    const auto reloadedTarget = vh::identities::manager().user(target->id);
    const auto reloadedAdmin = vh::identities::manager().user(admin->id);
    EXPECT_EQ(reloadedTarget->name(), "upd_plain_renamed");
    EXPECT_FALSE(reloadedTarget->state()->meta.is_active);
    EXPECT_EQ(reloadedAdmin->name(), "upd_admin_target");
    EXPECT_TRUE(reloadedAdmin->state()->meta.is_active);
    EXPECT_EQ(response.at("user").at("id").get<unsigned int>(), target->id);
}

TEST_F(AuthPasswordChangeTest, UpdateUserRefusesSelfPrivilegeAndIdentityChanges) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);
    const auto admin = createUser("upd_admin_self", "admin-password", "admin");
    const auto session = sessionFor(admin);
    using vh::protocols::ws::handler::Auth;

    EXPECT_THROW(Auth::updateUser(json{{"id", admin->id}, {"role", "super_admin"}}, session), std::runtime_error);
    EXPECT_THROW(Auth::updateUser(json{{"id", admin->id}, {"role", "unprivileged"}}, session), std::runtime_error);
    EXPECT_THROW(Auth::updateUser(json{{"id", admin->id}, {"linux_uid", 4242}}, session), std::runtime_error);
    EXPECT_THROW(Auth::updateUser(json{{"id", admin->id}, {"is_active", false}}, session), std::runtime_error);
    EXPECT_THROW(Auth::updateUser(json{{"id", admin->id}, {"updated_by", 1}}, session), std::runtime_error);

    const auto reloaded = vh::identities::manager().user(admin->id);
    EXPECT_EQ(reloaded->state()->roles.admin->name, "admin");
    EXPECT_FALSE(reloaded->state()->meta.linux_uid.has_value());
    EXPECT_TRUE(reloaded->state()->meta.is_active);
}

TEST_F(AuthPasswordChangeTest, UpdateUserRequiresEditPermissionForOthers) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);
    const auto plain = createUser("upd_plain_actor", "plain-password");
    const auto other = createUser("upd_plain_victim", "victim-password");

    EXPECT_THROW(vh::protocols::ws::handler::Auth::updateUser(
        json{{"id", other->id}, {"name", "upd_hijacked"}}, sessionFor(plain)), std::runtime_error);
    EXPECT_EQ(vh::identities::manager().user(other->id)->name(), "upd_plain_victim");
}

TEST_F(AuthPasswordChangeTest, NewAccountsRecordWhenTheirPasswordWasSet) {
    const auto user = createUser("pwd_changed_new", "first-password");
    EXPECT_TRUE(justNow(passwordChangedSecondsAgo(user->id)));
    ASSERT_TRUE(user->state()->meta.password_changed_at) << "loaded with the user";
}

TEST_F(AuthPasswordChangeTest, SelfChangeAndAdminResetPersistPasswordChangedAt) {
    auto manager = std::make_shared<vh::auth::Manager>();
    ScopedRuntimeAuthManager scoped(manager);

    const auto user = createUser("pwd_changed_self", "old-password");
    backdatePasswordChange(user->id);
    ASSERT_FALSE(justNow(passwordChangedSecondsAgo(user->id)));

    const auto response = vh::protocols::ws::handler::Auth::changePassword(
        json{{"id", user->id}, {"old_password", "old-password"}, {"new_password", "new-password"}},
        sessionFor(user));
    EXPECT_TRUE(justNow(passwordChangedSecondsAgo(user->id)));
    EXPECT_FALSE(response.at("user").at("password_changed_at").is_null());
    const auto reloaded = vh::identities::manager().user(user->id);
    ASSERT_TRUE(reloaded->state()->meta.password_changed_at) << "survives a reload (and so a restart)";

    const auto actor = createUser("pwd_changed_actor", "actor-password", "admin");
    const auto target = createUser("pwd_changed_target", "old-password");
    backdatePasswordChange(target->id);
    (void)vh::protocols::ws::handler::Auth::changePassword(json{{"id", target->id}, {"new_password", "new-password"}},
                                                           sessionFor(actor));
    EXPECT_TRUE(justNow(passwordChangedSecondsAgo(target->id)));
}

TEST_F(AuthPasswordChangeTest, UpdatesThatKeepThePasswordKeepPasswordChangedAt) {
    const auto user = createUser("pwd_changed_keep", "same-password");
    backdatePasswordChange(user->id);

    (void)vh::identities::manager().updateUser(user->id, [](vh::identities::UserState& s) {
        s.email = "pwd_changed_keep_new@vaulthalla.test";
    });

    const auto ago = passwordChangedSecondsAgo(user->id);
    ASSERT_TRUE(ago);
    EXPECT_GT(*ago, 29.0 * 86400.0);
}

// Migration 102 runs on upgraded installs and may meet itself again: re-running it changes nothing.
TEST_F(AuthPasswordChangeTest, PasswordChangedAtMigrationIsIdempotent) {
    const auto user = createUser("pwd_changed_rerun", "some-password");
    backdatePasswordChange(user->id);
    const auto sql = vh::db::seed::readFileToString(
        std::filesystem::path(VH_PSQL_TEST_SCHEMAS_PATH) / "102_password_changed_at.sql");
    vh::db::Transactions::exec("AuthPasswordChangeTest::rerun102", [&](pqxx::work& txn) { txn.exec(sql); });
    const auto ago = passwordChangedSecondsAgo(user->id);
    ASSERT_TRUE(ago);
    EXPECT_GT(*ago, 29.0 * 86400.0);
}

} // namespace vh::auth::test_password_change
