// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Users through both surfaces (Phase 2). Before: the CLI wrote accounts straight to the DB (no default vault, no
// registration validation) while the web went through auth::Manager; both judged "admin" by User::isAdmin(),
// which is false for the built-in admin role, so anyone who could add users could mint or promote admins (S3);
// deleting an account through the web "invalidated" a session keyed by the user id, which matched nothing (S9);
// a deactivated account could still log in; the web could rename the super admin the daemon looks up by name;
// and auth::Manager served logins from a cache the CLI never updated. ops::users now owns all of it.

#include "../helpers/identities.hpp"
#include "auth/Manager.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Manager.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/model/Token.hpp"
#include "ops/Error.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "vault/model/Vault.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Manager.hpp"
#include "UsageManager.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <set>
#include <string>

namespace vh::test_ops_parity_users {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;

std::string usersTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

constexpr const char* PASSWORD = "Correct-Horse-Battery-9";

class UserParityTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser;

    // Seeded straight into the DB, as an existing account would be.
    static UserPtr seedUser(const std::string& prefix, const std::string& roleName) {
        const auto name = prefix + "_" + usersTag();
        return test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test",
                                            crypto::hash::password(PASSWORD));
    }

    static std::string customRole(const std::vector<std::string>& permissions) {
        const auto name = "up_role_" + usersTag();
        std::vector<std::pair<std::string, bool>> changes;
        for (const auto& p : permissions) changes.emplace_back(p, true);
        (void)ops::roles::createAdminRole(superUser, {.name = name, .permissions = {.changes = changes}}, "test");
        return name;
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_ops_parity_users] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_user_parity_" + usersTag());
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
        auth::session::Issuer::setJwtSecretForTesting("user-parity-test-secret");

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerUserCommands(router);

        superUser = seedUser("up_super", "super_admin");
    }

    static void TearDownTestSuite() {
        if (!skipTests) auth::session::Issuer::clearJwtSecretForTesting();
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
        s->ipAddress = "127.0.0.1";
        s->userAgent = "user-parity-test";
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

    static std::string roleOf(const unsigned int id) {
        const auto u = vh::identities::manager().user(id);
        const auto s = u ? u->state() : nullptr;
        return s && s->roles.admin ? s->roles.admin->name : "";
    }

    // A socket as the server accepts it: anonymous, with a refresh token, then logged in.
    static std::shared_ptr<protocols::ws::Session> connected() {
        auto session = ws(nullptr);
        runtime::Deps::get().sessionManager->rotateRefreshToken(session);
        return session;
    }

    static std::shared_ptr<protocols::ws::Session> loggedIn(const UserPtr& user) { return loggedIn(user->name()); }

    static std::shared_ptr<protocols::ws::Session> loggedIn(const std::string& name) {
        auto session = connected();
        runtime::Deps::get().authManager->loginUser(name, PASSWORD, session);
        return session;
    }

    static bool hasLiveRefreshToken(const unsigned int userId) {
        for (const auto& t : db::query::auth::RefreshToken::list(userId)) if (t && !t->revoked) return true;
        return false;
    }
};

TEST_F(UserParityTest, CreateMakesTheSameAccountAndDefaultVaultOnBothSurfaces) {
    const auto cliName = "up_cli_" + usersTag(), wsName = "up_ws_" + usersTag();
    const auto [code, out] = cli("user create " + cliName + " --role unprivileged --email " + cliName + "@x.test", superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_NE(out.find("Password: "), std::string::npos) << "the generated password is shown once";
    (void)protocols::ws::handler::Auth::registerUser(json{{"name", wsName}, {"email", wsName + "@x.test"},
        {"password", PASSWORD}, {"is_active", true}, {"role", "unprivileged"}}, ws(superUser));

    const auto a = vh::identities::manager().userByName(cliName), b = vh::identities::manager().userByName(wsName);
    ASSERT_TRUE(a && b);
    EXPECT_EQ(a->state()->roles.admin->name, b->state()->roles.admin->name);
    EXPECT_EQ(a->isActive(), b->isActive());
    EXPECT_FALSE(db::query::vault::Vault::listUserVaults(a->id).empty()) << "the CLI used to skip the default vault";
    EXPECT_EQ(db::query::vault::Vault::listUserVaults(a->id).size(), db::query::vault::Vault::listUserVaults(b->id).size());

    // Validation is the same too: a bad email is refused on both.
    EXPECT_NE(cli("user create up_bad_" + usersTag() + " --role unprivileged --email nope", superUser).first, 0);
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Auth::registerUser(json{{"name", "up_bad_" + usersTag()}, {"email", "nope"},
            {"password", PASSWORD}, {"role", "unprivileged"}}, ws(superUser));
    }));
}

TEST_F(UserParityTest, BuiltInRolesClassifyAsAdminsExceptUnprivileged) {
    for (const auto& role : db::query::rbac::role::Admin::list()) {
        if (role->name.starts_with("up_")) continue;
        EXPECT_EQ(ops::users::isAdminIdentity(*role), role->name != "unprivileged") << role->name;
    }
}

TEST_F(UserParityTest, NobodyMintsOrPromotesAccountsAboveThemselves) {
    // identity_admin may add and edit users, but holds far less than the built-in admin role (S3).
    const auto idAdmin = seedUser("up_idadmin", "identity_admin");
    EXPECT_NE(cli("user create up_mint_" + usersTag() + " --role admin", idAdmin).first, 0);
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Auth::registerUser(json{{"name", "up_mint_" + usersTag()},
            {"password", PASSWORD}, {"role", "admin"}}, ws(idAdmin));
    }));

    const auto plain = seedUser("up_plain", "unprivileged");
    EXPECT_NE(cli("user update " + plain->name() + " --role admin", idAdmin).first, 0);
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Auth::updateUser(json{{"id", plain->id}, {"role", "admin"}}, ws(idAdmin));
    }));
    EXPECT_EQ(roleOf(plain->id), "unprivileged");

    // Ordinary account management still works for them.
    const auto [code, out] = cli("user create up_ok_" + usersTag() + " --role unprivileged", idAdmin);
    EXPECT_EQ(code, 0) << out;
}

TEST_F(UserParityTest, AccountsAboveTheActorCannotBeManaged) {
    // Holds every identity permission, nothing else: can manage admin-class accounts in general, but not one whose
    // role grants what it lacks (an auditor sees audits) - no reset-and-take-over, no delete.
    const auto mgr = seedUser("up_mgr", customRole({
        "admin.identities.admins.view", "admin.identities.admins.add", "admin.identities.admins.edit",
        "admin.identities.admins.delete", "admin.identities.admins.reset-password",
        "admin.identities.users.view", "admin.identities.users.add", "admin.identities.users.edit",
        "admin.identities.users.delete", "admin.identities.users.reset-password"}));
    const auto auditor = seedUser("up_auditor", "auditor");

    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Auth::changePassword(json{{"id", auditor->id}, {"new_password", "Another-Pass-77"}}, ws(mgr));
    }));
    EXPECT_NE(cli("user delete " + auditor->name() + " --yes", mgr).first, 0);
    EXPECT_FALSE(wsOk([&] { (void)protocols::ws::handler::Auth::deleteUser(json{{"id", auditor->id}, {"confirm", true}}, ws(mgr)); }));
    EXPECT_NE(cli("user update " + auditor->name() + " --disable", mgr).first, 0);
    EXPECT_TRUE(vh::identities::manager().user(auditor->id));

    // An admin-class account within the actor's reach is fine.
    const auto minor = seedUser("up_minor", customRole({"admin.identities.users.view"}));
    EXPECT_EQ(cli("user update " + minor->name() + " --email minor@x.test", mgr).first, 0);
    EXPECT_TRUE(wsOk([&] { (void)protocols::ws::handler::Auth::deleteUser(json{{"id", minor->id}, {"confirm", true}}, ws(mgr)); }));
}

TEST_F(UserParityTest, DeactivationAndDeletionEndSessions) {
    // S9: deleting through the web "invalidated" a session keyed by the user id, which matched nothing.
    const auto& sessions = runtime::Deps::get().sessionManager;
    const auto victim = seedUser("up_victim", "unprivileged");
    const auto session = loggedIn(victim);
    const auto accessToken = session->tokens->accessToken->rawToken;
    ASSERT_FALSE(sessions->getSessionsByUserId(victim->id).empty());
    ASSERT_TRUE(hasLiveRefreshToken(victim->id));

    ASSERT_EQ(cli("user update " + victim->name() + " --disable", superUser).first, 0);
    EXPECT_TRUE(sessions->getSessionsByUserId(victim->id).empty());
    EXPECT_FALSE(hasLiveRefreshToken(victim->id));
    EXPECT_FALSE(sessions->validate(session, accessToken)) << "the open socket kept working";
    EXPECT_THROW(loggedIn(victim), std::exception) << "deactivated accounts used to log in";

    // Deleted through the web: same outcome.
    const auto gone = seedUser("up_gone", "unprivileged");
    const auto goneSession = loggedIn(gone);
    const auto goneToken = goneSession->tokens->accessToken->rawToken;
    (void)protocols::ws::handler::Auth::deleteUser(json{{"id", gone->id}, {"confirm", true}}, ws(superUser));
    EXPECT_TRUE(sessions->getSessionsByUserId(gone->id).empty());
    EXPECT_FALSE(sessions->validate(goneSession, goneToken));

    // A role change ends sessions too: they carry the old role.
    const auto demoted = seedUser("up_demoted", "auditor");
    (void)loggedIn(demoted);
    ASSERT_EQ(cli("user update " + demoted->name() + " --role unprivileged", superUser).first, 0);
    EXPECT_TRUE(sessions->getSessionsByUserId(demoted->id).empty());
}

TEST_F(UserParityTest, LoginReadsTheAccountAsItIsNow) {
    // A CLI rename used to leave the old name logging in from auth::Manager's cache.
    const auto user = seedUser("up_renamed", "unprivileged");
    (void)loggedIn(user);
    const auto oldName = user->name();
    const auto newName = "up_newname_" + usersTag();
    ASSERT_EQ(cli("user update " + oldName + " --name " + newName, superUser).first, 0);
    EXPECT_EQ(user->name(), newName) << "the reference held across the rename sees it";
    EXPECT_THROW((void)loggedIn(oldName), std::exception);
    EXPECT_NO_THROW((void)loggedIn(newName));
}

TEST_F(UserParityTest, SelfServiceLimitsMatch) {
    // The daemon finds the super admin by name: the web used to let it rename itself.
    EXPECT_NE(cli("user update " + superUser->name() + " --name up_renamed_super", superUser).first, 0);
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Auth::updateUser(json{{"id", superUser->id}, {"name", "up_renamed_super"}}, ws(superUser));
    }));

    const auto self = seedUser("up_self", "identity_admin");
    EXPECT_NE(cli("user delete " + self->name() + " --yes", self).first, 0);
    EXPECT_FALSE(wsOk([&] { (void)protocols::ws::handler::Auth::deleteUser(json{{"id", self->id}, {"confirm", true}}, ws(self)); }));
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Auth::updateUser(json{{"id", self->id}, {"is_active", false}}, ws(self));
    }));
    EXPECT_NE(cli("user update " + self->name() + " --role unprivileged", self).first, 0);

    // The web never validated email on update.
    EXPECT_FALSE(wsOk([&] {
        (void)protocols::ws::handler::Auth::updateUser(json{{"id", self->id}, {"email", "not-an-email"}}, ws(self));
    }));
    EXPECT_NE(cli("user update " + self->name() + " --email not-an-email", self).first, 0);
    EXPECT_TRUE(wsOk([&] {
        (void)protocols::ws::handler::Auth::updateUser(json{{"id", self->id}, {"email", "fine@x.test"}}, ws(self));
    }));
}

TEST_F(UserParityTest, ListShowsWhatTheActorMayViewOnBothSurfaces) {
    const auto viewer = seedUser("up_viewer", customRole({"admin.identities.users.view"}));
    (void)seedUser("up_listed_plain", "unprivileged");
    (void)seedUser("up_listed_admin", "auditor");

    const auto listed = protocols::ws::handler::Auth::listUsers(ws(viewer)).at("users");
    std::set<std::string> wsNames;
    for (const auto& u : listed) {
        wsNames.insert(u.at("name").get<std::string>());
        const auto acct = vh::identities::manager().user(u.at("id").get<unsigned int>());
        if (acct->id != viewer->id) {
            EXPECT_FALSE(ops::users::isAdminIdentity(*acct->state()->roles.admin)) << acct->name();
        }
    }
    EXPECT_TRUE(wsNames.contains(viewer->name()));

    const auto [code, out] = cli("user list", viewer);
    ASSERT_EQ(code, 0) << out;
    for (const auto& name : wsNames) EXPECT_NE(out.find(name), std::string::npos) << name;

    // #146: the list is a slim projection (no permission sets); the single-user read keeps the full role.
    for (const auto& u : listed) {
        const auto& role = u.at("admin_role");
        EXPECT_FALSE(role.contains("permissions")) << u.at("name");
        EXPECT_FALSE(role.contains("s3_gateway")) << u.at("name");
        EXPECT_TRUE(role.at("id").is_number());
        EXPECT_TRUE(role.at("name").is_string());
        EXPECT_TRUE(role.contains("description"));
        EXPECT_EQ(role.at("type"), "admin");
        ASSERT_TRUE(u.at("vault_roles").is_array());
        for (const auto& vr : u.at("vault_roles")) EXPECT_FALSE(vr.contains("permissions"));
    }
    const auto single = protocols::ws::handler::Auth::getUser(json{{"id", viewer->id}}, ws(superUser)).at("user");
    EXPECT_TRUE(single.at("admin_role").contains("permissions"));

    // The session payload (login / refresh / isAuthenticated) keeps every permission but only {qualified, value}.
    const auto session = protocols::ws::handler::Auth::sessionUser(*viewer);
    const auto& perms = session.at("admin_role").at("permissions");
    ASSERT_TRUE(perms.is_array());
    EXPECT_EQ(perms.size(), single.at("admin_role").at("permissions").size());
    for (const auto& p : perms) {
        EXPECT_EQ(p.size(), 2u) << p.dump();
        EXPECT_TRUE(p.at("qualified").is_string());
        EXPECT_TRUE(p.at("value").is_boolean());
    }

    // Nobody without a view permission lists anything.
    EXPECT_NE(cli("user list", seedUser("up_blind", "unprivileged")).first, 0);
    // And --sort is a column, not SQL.
    EXPECT_NE(cli("user list --sort \"id; DELETE FROM users\"", superUser).first, 0);
    EXPECT_TRUE(vh::identities::manager().user(viewer->id));
}

// #133: deleting an account used to leave its vaults ownerless. Now it asks first, then transfers or destroys them.
TEST_F(UserParityTest, DeletingAnAccountAsksAndThenTransfersOrDestroysItsVaults) {
    const auto vaultFor = [](const UserPtr& owner) {
        return ops::vaults::create(superUser, {.name = "up_v_" + usersTag(), .type = vault::model::VaultType::Local,
                                               .owner_id = owner->id});
    };
    const auto ownerOf = [](const unsigned int vaultId) -> std::optional<uint32_t> {
        const auto v = db::query::vault::Vault::getVault(vaultId);
        return v ? std::optional<uint32_t>{v->owner_id} : std::nullopt;
    };

    // Unconfirmed: the question, naming the vaults, and nothing changes. Same on both surfaces.
    const auto doomed = seedUser("up_doomed", "unprivileged");
    const auto doomedVault = vaultFor(doomed);
    try {
        (void)ops::users::remove(superUser, {.id = doomed->id});
        ADD_FAILURE() << "deletion went ahead without confirmation";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, "user_delete");
        const std::string text = e.what();
        EXPECT_NE(text.find(ops::users::USER_DELETE_CONFIRMATION), std::string::npos) << text;
        EXPECT_NE(text.find(doomedVault->name), std::string::npos) << text;
    }
    const auto [code, out] = cli("user delete " + doomed->name(), superUser);
    EXPECT_NE(code, 0);
    EXPECT_NE(out.find("--yes"), std::string::npos) << out;
    EXPECT_FALSE(wsOk([&] { (void)protocols::ws::handler::Auth::deleteUser(json{{"id", doomed->id}}, ws(superUser)); }));
    EXPECT_TRUE(vh::identities::manager().user(doomed->id));
    EXPECT_EQ(ownerOf(doomedVault->id), doomed->id);

    // Confirmed without a transfer: the vaults go with the account.
    ASSERT_EQ(cli("user delete " + doomed->name() + " --yes", superUser).first, 0);
    EXPECT_FALSE(vh::identities::manager().user(doomed->id));
    EXPECT_FALSE(ownerOf(doomedVault->id)) << "the vault was left behind, ownerless";

    // Confirmed with a transfer: the heir owns them afterwards.
    const auto leaving = seedUser("up_leaving", "unprivileged"), heir = seedUser("up_heir", "unprivileged");
    const auto kept = vaultFor(leaving);
    ASSERT_TRUE(wsOk([&] {
        (void)protocols::ws::handler::Auth::deleteUser(
            json{{"id", leaving->id}, {"transfer_to", heir->id}, {"confirm", true}}, ws(superUser));
    }));
    EXPECT_FALSE(vh::identities::manager().user(leaving->id));
    EXPECT_EQ(ownerOf(kept->id), heir->id);
}

TEST_F(UserParityTest, VaultOwnershipTransferIsForAdministrators) {
    // May delete plain accounts but holds no vault rights: deleting is not a licence to move vaults between users.
    const auto deleter = seedUser("up_deleter", customRole({"admin.identities.users.delete", "admin.identities.users.view"}));
    const auto leaving = seedUser("up_leaving2", "unprivileged"), heir = seedUser("up_heir2", "unprivileged");
    const auto v = ops::vaults::create(superUser, {.name = "up_v2_" + usersTag(), .type = vault::model::VaultType::Local,
                                                   .owner_id = leaving->id});
    EXPECT_THROW((void)ops::users::remove(deleter, {.id = leaving->id, .transfer_to = heir->id, .confirmed = true}), ops::Denied);
    EXPECT_TRUE(vh::identities::manager().user(leaving->id)) << "a refused transfer must change nothing";
    EXPECT_EQ(db::query::vault::Vault::getVault(v->id)->owner_id, leaving->id);

    // An owner can't hand their own vault to someone else either.
    EXPECT_NE(cli("vault update " + std::to_string(v->id) + " --owner " + heir->name(), leaving).first, 0);
    EXPECT_EQ(db::query::vault::Vault::getVault(v->id)->owner_id, leaving->id);

    // A clash with a vault the heir already has is refused before anything changes.
    (void)ops::vaults::create(superUser, {.name = v->name, .type = vault::model::VaultType::Local, .owner_id = heir->id});
    EXPECT_THROW((void)ops::users::remove(superUser, {.id = leaving->id, .transfer_to = heir->id, .confirmed = true}),
                 ops::Conflict);
    EXPECT_TRUE(vh::identities::manager().user(leaving->id));
}

}
