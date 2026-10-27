// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The global vault policy (user_global_vault_policy) is read in the scope the vault falls under for the account: its
// own vault (self), a vault owned by an admin identity (admin), anyone else's (user). The filesystem evaluator's last
// stage used to try self, admin, user in turn, but a stage always decides, so the self scope answered for every vault:
// a policy whose self scope granted more than its others' scopes granted that on everyone's vaults, and one whose
// self scope granted less denied on others' vaults what the policy granted there. The seeded presets hid it (every
// scope is the same).
//
// Oracle: for every filesystem action on a file and a directory, the enforcing resolver (the FUSE, ws, CLI, HTTP,
// share and S3 principal paths all call it) must equal the evaluator applied to exactly the expected scope's bits;
// then the same verdicts through the ws fs handlers, `vh fs ls`, the HTTP/CLI access layer and the accessible-vaults
// list. The admin vault permissions (admin.vaults.<scope>, storage.vault.get) pick the scope by the same function.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/helpers.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/Transfer.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "rbac/fs/policy/Evaluator.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/VaultScope.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/vault/Global.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "UsageManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <pqxx/pqxx>

#include <array>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vh::test_vault_scope_rbac {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using Action = rbac::permission::vault::FilesystemAction;
using Scope = rbac::role::vault::Global::Scope;
using Base = rbac::role::vault::Base;
using rbac::resolver::VaultScope;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

constexpr std::array kActions{
    Action::Preview, Action::Write, Action::Read, Action::Overwrite, Action::Rename, Action::Delete, Action::Move,
    Action::Copy, Action::Touch, Action::Link, Action::List, Action::Lookup, Action::ShareInternal,
    Action::SharePublic, Action::SharePublicValidated,
};

const char* name(const VaultScope s) {
    switch (s) {
        case VaultScope::Self: return "self";
        case VaultScope::Admin: return "admin";
        case VaultScope::User: return "user";
    }
    return "?";
}

class VaultScopeRbacTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser, plainOwner, adminOwner;
    inline static unsigned int plainVault = 0, adminVault = 0;
    inline static std::shared_ptr<sync::Controller> previousController;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_vault_scope_rbac] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_vault_scope_" + tag());
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
        // Earlier suites in this binary used their own schema: their cached entries and engines (ids reused after the
        // reset) would answer for ours.
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerAllCommands(router);
        // The mutating fs handlers wake the vault's sync after a change.
        previousController = runtime::Deps::get().syncController;
        runtime::Deps::setSyncController(std::make_shared<sync::Controller>());

        // super_admin can't be assigned through ops::users (nobody holds more); seeded-style accounts hold it. A second
        // one owns the "admin" scope's vault (User::isAdmin()).
        superUser = seededSuperAdmin("vs_super");
        adminOwner = seededSuperAdmin("vs_admin_owner");
        plainOwner = createUser("vs_plain_owner", "unprivileged");
        plainVault = vaultFor(plainOwner);
        adminVault = vaultFor(adminOwner);
        protocols::http::access::clearCachesForTesting();
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        runtime::Deps::setSyncController(previousController);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static UserPtr seededSuperAdmin(const std::string& prefix) {
        const auto created = test::identities::createUser(prefix + "_" + tag(),
                                                          db::query::rbac::role::Admin::get("super_admin"),
                                                          std::nullopt, "x", std::nullopt);
        return identities::manager().user(created->id);
    }

    static UserPtr createUser(const std::string& prefix, const std::string& role) {
        const auto created = ops::users::create(superUser, {.name = prefix + "_" + tag(), .role = role,
                                                            .password = std::string("Vault-Scope-Pass-123")});
        return identities::manager().user(created.user->id);
    }

    // A vault owned by `owner` holding /doc.txt and /dir/inner.txt.
    static unsigned int vaultFor(const UserPtr& owner) {
        const auto id = ops::vaults::create(superUser, {.name = "vs_vault_" + tag(),
                                                        .type = vault::model::VaultType::Local,
                                                        .owner_id = owner->id})->id;
        const auto engine = runtime::Deps::get().storageManager->getEngine(id);
        (void)fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/dir"), .engine = engine, .user = superUser});
        for (const std::string path : {"/doc.txt", "/dir/inner.txt"}) {
            const std::string text = "scope " + path;
            (void)fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                              .buffer = std::vector<uint8_t>(text.begin(), text.end()),
                                              .engine = engine, .user = superUser, .overwrite = true});
        }
        return id;
    }

    // An account on a custom admin role (no seeded preset) whose global vault policy is written per scope, the way an
    // operator editing user_global_vault_policy would leave it; `vaultPerms` are admin.vaults.<scope>.* grants.
    static UserPtr customAccount(const std::string& prefix, const Base& self, const Base& admin, const Base& user,
                                 const std::vector<std::string>& vaultPerms) {
        ops::roles::CreateRole req{.name = prefix + "_role_" + tag()};
        for (const auto& p : vaultPerms) req.permissions.changes.emplace_back(p, true);
        const auto role = ops::roles::createAdminRole(superUser, req, "test");
        const auto account = createUser(prefix, role->name);
        const auto globals = rbac::permission::admin::VaultGlobals::Custom(
            rbac::role::vault::Global::Custom(account->id, Scope::Self, self),
            rbac::role::vault::Global::Custom(account->id, Scope::Admin, admin),
            rbac::role::vault::Global::Custom(account->id, Scope::User, user));
        db::Transactions::exec("vault_scope::policy", [&](pqxx::work& txn) {
            db::query::identities::upsertGlobalVRoles(txn, globals, account->id);
        });
        (void)identities::manager().reconcile();
        auto fresh = identities::manager().user(account->id);
        const auto* stored = fresh->authz().vaultGlobals();
        EXPECT_TRUE(stored && stored->self.fs.files.raw() == self.fs.files.raw() &&
                    stored->admin.fs.files.raw() == admin.fs.files.raw() &&
                    stored->user.fs.files.raw() == user.fs.files.raw())
            << "the per-scope policy did not load";
        return fresh;
    }

    static std::shared_ptr<storage::Engine> engine(const unsigned int vaultId) {
        return runtime::Deps::get().storageManager->getEngine(vaultId);
    }

    static bool resolverAllows(const UserPtr& user, const unsigned int vaultId, const Action action,
                               const std::string& vaultPath) {
        const rbac::resolver::vault::QuietFilesystemDenials quiet;
        return rbac::resolver::Vault::has<Action>({.user = user, .permission = action, .vault_id = vaultId,
                                                   .path = engine(vaultId)->vaultPathToFusePath(vaultPath)});
    }

    // The evaluator applied to one scope's bits, with nothing else in play.
    static bool scopeAllows(const rbac::role::vault::Global& scope, const Action action, const std::string& vaultPath,
                            const bool isDirectory) {
        return rbac::fs::policy::Evaluator::evaluate(scope.fs, {.action = action, .vaultPath = vaultPath,
                                                                .exists = true, .isDirectory = isDirectory}).allowed;
    }

    // Every action on a file and a directory: the resolver equals the expected scope's bits. Returns how many
    // verdicts the self scope would have answered differently (the bug's footprint on this vault).
    static unsigned expectScope(const UserPtr& user, const unsigned int vaultId, const VaultScope expected) {
        SCOPED_TRACE(std::string("vault ") + std::to_string(vaultId) + ", expected scope " + name(expected));
        const auto* globals = user->authz().vaultGlobals();
        if (!globals) {
            ADD_FAILURE() << "no global vault policy";
            return 0;
        }
        const auto vault = engine(vaultId)->vault;
        EXPECT_EQ(rbac::resolver::vaultScope(*user, vault->owner_id), std::optional{expected});
        const auto& scope = rbac::resolver::inScope(expected, *globals);
        unsigned differsFromSelf = 0;
        for (const auto& [path, isDir] : {std::pair{std::string("/doc.txt"), false},
                                          std::pair{std::string("/dir"), true}}) {
            for (const auto action : kActions) {
                const bool want = scopeAllows(scope, action, path, isDir);
                EXPECT_EQ(resolverAllows(user, vaultId, action, path), want)
                    << "action " << static_cast<int>(action) << " on " << path;
                if (want != scopeAllows(globals->self, action, path, isDir)) ++differsFromSelf;
            }
        }
        return differsFromSelf;
    }

    static std::shared_ptr<protocols::ws::Session> ws(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    static bool succeeds(const std::function<void()>& fn) {
        try {
            fn();
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    static bool wsList(const UserPtr& user, const unsigned int vaultId) {
        return succeeds([&] {
            (void)protocols::ws::handler::fs::Storage::listDir(json{{"vault_id", vaultId}, {"path", "/"}}, ws(user));
        });
    }

    static bool wsMkdir(const UserPtr& user, const unsigned int vaultId) {
        return succeeds([&] {
            (void)protocols::ws::handler::fs::Storage::mkdir(json{{"vault_id", vaultId}, {"path", "/made_" + tag()}},
                                                             ws(user));
        });
    }

    // fs.entry.delete on a scratch file created for the attempt.
    static bool wsDelete(const UserPtr& user, const unsigned int vaultId) {
        const auto e = engine(vaultId);
        const auto path = "/scratch_" + tag() + ".txt";
        const std::string text = "scratch";
        (void)fs::Filesystem::createFile({.path = path, .fuse_path = e->vaultPathToFusePath(path),
                                          .buffer = std::vector<uint8_t>(text.begin(), text.end()), .engine = e,
                                          .user = superUser, .overwrite = true});
        return succeeds([&] {
            (void)protocols::ws::handler::fs::Storage::remove(json{{"vault_id", vaultId}, {"path", path}}, ws(user));
        });
    }

    static bool wsManage(const UserPtr& user, const unsigned int vaultId) {
        return succeeds([&] { (void)protocols::ws::handler::Vaults::get(json{{"id", vaultId}}, ws(user)); });
    }

    static int cliLs(const UserPtr& user, const unsigned int vaultId) {
        try {
            return router->executeLine("fs ls " + std::to_string(vaultId) + " /", user, nullptr).exit_code;
        } catch (const std::exception&) {
            return -1;
        }
    }

    // The access layer `vh fs` and the HTTP lanes (human and device) resolve through.
    static bool access(const UserPtr& user, const unsigned int vaultId, const std::string& path,
                       const protocols::http::access::Need need, const protocols::http::access::Expect expect) {
        return succeeds([&] { (void)protocols::http::access::resolveUserPath(user, vaultId, path, need, expect); });
    }

    static std::optional<ops::vaults::AccessibleVault> accessible(const UserPtr& user, const unsigned int vaultId) {
        for (auto& v : ops::vaults::listAccessible(user))
            if (v.vault && v.vault->id == vaultId) return v;
        return std::nullopt;
    }
};

// Self grants everything, others' scopes nothing: full access on the own vault, none on anyone else's. Before the fix
// every verdict on others' vaults came from the self scope (full access everywhere).
TEST_F(VaultScopeRbacTest, SelfScopeBeyondOthersStaysOnTheOwnVault) {
    const auto actor = customAccount("vs_self_heavy", Base::Full(), Base::None(), Base::None(),
                                     {"admin.vaults.self.view"});
    const auto own = vaultFor(actor);

    EXPECT_EQ(expectScope(actor, own, VaultScope::Self), 0u);
    EXPECT_GT(expectScope(actor, plainVault, VaultScope::User), 0u) << "the scopes differ, so self must not answer";
    EXPECT_GT(expectScope(actor, adminVault, VaultScope::Admin), 0u);

    // ws
    EXPECT_TRUE(wsList(actor, own));
    EXPECT_TRUE(wsMkdir(actor, own));
    EXPECT_TRUE(wsDelete(actor, own));
    for (const auto other : {plainVault, adminVault}) {
        SCOPED_TRACE(other);
        EXPECT_FALSE(wsList(actor, other));
        EXPECT_FALSE(wsMkdir(actor, other));
        EXPECT_FALSE(wsDelete(actor, other));
        EXPECT_FALSE(wsManage(actor, other)) << "admin.vaults: self view only";
    }
    EXPECT_TRUE(wsManage(actor, own));

    // CLI and the access layer (HTTP human/device lanes and `vh fs get|ls|put`)
    using protocols::http::access::Need;
    using protocols::http::access::Expect;
    EXPECT_EQ(cliLs(actor, own), 0);
    EXPECT_TRUE(access(actor, own, "/doc.txt", Need::Download, Expect::File));
    EXPECT_TRUE(access(actor, own, "/doc.txt", Need::Overwrite, Expect::File));
    for (const auto other : {plainVault, adminVault}) {
        SCOPED_TRACE(other);
        EXPECT_EQ(cliLs(actor, other), protocols::shell::transfer::exitcode::kNoPerm);
        EXPECT_FALSE(access(actor, other, "/doc.txt", Need::Download, Expect::File));
        EXPECT_FALSE(access(actor, other, "/doc.txt", Need::Preview, Expect::File));
        EXPECT_FALSE(access(actor, other, "/doc.txt", Need::Overwrite, Expect::File));
        EXPECT_FALSE(access(actor, other, "/dir", Need::List, Expect::Directory));
    }

    // The accessible list: the own vault only.
    const auto ownRow = accessible(actor, own);
    ASSERT_TRUE(ownRow);
    EXPECT_TRUE(ownRow->browse);
    EXPECT_TRUE(ownRow->manage);
    EXPECT_FALSE(accessible(actor, plainVault));
    EXPECT_FALSE(accessible(actor, adminVault));
}

// The reverse, with distinct admin and user scopes: nothing on the own vault, Manager on admins' vaults, Reader on
// everyone else's. Before the fix the empty self scope denied every one of these.
TEST_F(VaultScopeRbacTest, OthersScopesBeyondSelfApplyToOthersVaults) {
    const auto actor = customAccount("vs_others_heavy", Base::None(), Base::Manager(), Base::Reader(),
                                     {"admin.vaults.admin.view", "admin.vaults.user.view"});
    const auto own = vaultFor(actor);

    EXPECT_EQ(expectScope(actor, own, VaultScope::Self), 0u);
    EXPECT_GT(expectScope(actor, plainVault, VaultScope::User), 0u);
    EXPECT_GT(expectScope(actor, adminVault, VaultScope::Admin), 0u);

    // ws: Reader on the plain account's vault, Manager on the admin's, nothing on the own one.
    EXPECT_FALSE(wsList(actor, own));
    EXPECT_FALSE(wsMkdir(actor, own));
    EXPECT_FALSE(wsDelete(actor, own));
    EXPECT_FALSE(wsManage(actor, own));
    EXPECT_TRUE(wsList(actor, plainVault));
    EXPECT_FALSE(wsMkdir(actor, plainVault));
    EXPECT_FALSE(wsDelete(actor, plainVault));
    EXPECT_TRUE(wsManage(actor, plainVault));
    EXPECT_TRUE(wsList(actor, adminVault));
    EXPECT_TRUE(wsMkdir(actor, adminVault));
    EXPECT_TRUE(wsDelete(actor, adminVault));
    EXPECT_TRUE(wsManage(actor, adminVault));

    using protocols::http::access::Need;
    using protocols::http::access::Expect;
    EXPECT_EQ(cliLs(actor, own), protocols::shell::transfer::exitcode::kNoPerm);
    EXPECT_FALSE(access(actor, own, "/doc.txt", Need::Download, Expect::File));
    EXPECT_EQ(cliLs(actor, plainVault), 0);
    EXPECT_TRUE(access(actor, plainVault, "/doc.txt", Need::Download, Expect::File));
    EXPECT_FALSE(access(actor, plainVault, "/doc.txt", Need::Overwrite, Expect::File));
    EXPECT_EQ(cliLs(actor, adminVault), 0);
    EXPECT_TRUE(access(actor, adminVault, "/doc.txt", Need::Download, Expect::File));
    EXPECT_TRUE(access(actor, adminVault, "/doc.txt", Need::Overwrite, Expect::File));
    EXPECT_TRUE(access(actor, adminVault, "/dir", Need::List, Expect::Directory));

    // The accessible list: the own vault listed as owner with neither flag, the others through the admin policy.
    const auto ownRow = accessible(actor, own);
    ASSERT_TRUE(ownRow);
    EXPECT_FALSE(ownRow->browse);
    EXPECT_FALSE(ownRow->manage);
    for (const auto other : {plainVault, adminVault}) {
        const auto row = accessible(actor, other);
        ASSERT_TRUE(row) << other;
        EXPECT_TRUE(row->browse) << other;
        EXPECT_TRUE(row->manage) << other;
        ASSERT_FALSE(row->via.empty());
        EXPECT_EQ(row->via.front(), ops::vaults::AccessVia::AdminPolicy) << other;
    }
}

// The seeded presets are the same in every scope, so reading the right scope changes nothing for them: on every vault
// each verdict equals both the vault's scope and the self scope (the old reading).
TEST_F(VaultScopeRbacTest, SeededRolesDecideAsBefore) {
    unsigned checked = 0;
    for (const auto& role : db::query::rbac::role::Admin::list()) {
        if (role->name == "super_admin") continue;  // bypasses the evaluator
        const auto preset = rbac::role::Admin::builtin(role->name, 0);
        if (!preset) continue;
        SCOPED_TRACE(role->name);
        const auto actor = createUser("vs_seeded_" + role->name, role->name);
        const auto own = vaultFor(actor);
        EXPECT_EQ(expectScope(actor, own, VaultScope::Self), 0u);
        EXPECT_EQ(expectScope(actor, plainVault, VaultScope::User), 0u) << "seeded scopes are identical";
        EXPECT_EQ(expectScope(actor, adminVault, VaultScope::Admin), 0u);
        ++checked;
    }
    EXPECT_GE(checked, 9u);
}

}
