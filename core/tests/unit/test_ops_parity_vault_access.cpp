// "Vaults I can access" (ops::vaults::listAccessible): `vh vault list --accessible` and ws
// storage.vault.accessible.list. storage.vault.list follows the admin role's vault policy alone, so an unprivileged
// account that owns a vault or holds a vault role on it (its own or a group's) saw nothing there. The accessible list
// reaches every path, and its browse/manage flags must be exactly what the enforcing resolvers decide: browse is what
// fs.dir.list {path: "/"} allows, manage what storage.vault.get allows. Both surfaces must return the same rows for
// every seeded admin role, and the rows must match the role's bits.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Groups.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/permission/admin/Vaults.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/vault/Global.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Manager.hpp"
#include "UsageManager.hpp"
#include "vault/model/Vault.hpp"

#include "log/Registry.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <spdlog/logger.h>
#include <spdlog/sinks/ringbuffer_sink.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <optional>
#include <algorithm>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace vh::test_ops_parity_vault_access {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

// The auth logger's warnings for the life of the scope.
struct AuthWarnings {
    std::shared_ptr<spdlog::logger> logger = log::Registry::auth();
    std::shared_ptr<spdlog::sinks::ringbuffer_sink_mt> sink = std::make_shared<spdlog::sinks::ringbuffer_sink_mt>(1024);
    spdlog::level::level_enum previous = logger->level();

    AuthWarnings() {
        sink->set_level(spdlog::level::warn);
        sink->set_pattern("[%l] %v");
        logger->sinks().push_back(sink);
        if (previous > spdlog::level::warn) logger->set_level(spdlog::level::warn);
    }
    ~AuthWarnings() {
        std::erase(logger->sinks(), std::static_pointer_cast<spdlog::sinks::sink>(sink));
        logger->set_level(previous);
    }
    AuthWarnings(const AuthWarnings&) = delete;
    AuthWarnings& operator=(const AuthWarnings&) = delete;

    [[nodiscard]] std::size_t count(const std::string_view needle) const {
        const auto lines = sink->last_formatted();
        return static_cast<std::size_t>(std::ranges::count_if(lines, [&](const std::string& l) {
            return l.find(needle) != std::string::npos;
        }));
    }
};

const std::set<std::string> kSeededRoles = {"unprivileged", "auditor", "support", "identity_admin", "security_admin",
                                            "platform_operator", "vault_admin", "admin", "super_admin",
                                            "key_custodian"};

class VaultAccessParityTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_ops_parity_vault_access] Skipping db tests due to missing environment variables."
                      << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_vault_access_" + tag());
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
        protocols::shell::commands::vault::registerCommands(router);

        // super_admin can't be assigned through ops::users (nobody holds more); a seeded-style account holds it.
        const auto created = test::identities::createUser("va_super_" + tag(),
                                                          db::query::rbac::role::Admin::get("super_admin"),
                                                          std::nullopt, "x", std::nullopt);
        superUser = identities::manager().user(created->id);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    // Through ops::users, as every product path does: the role's global vault policy is seeded from its preset.
    static UserPtr createUser(const std::string& prefix, const std::string& role) {
        const auto created = ops::users::create(superUser, {.name = prefix + "_" + tag(), .role = role,
                                                            .password = std::string("Vault-Access-Pass-123")});
        return identities::manager().user(created.user->id);
    }

    static unsigned int vaultFor(const UserPtr& owner, const std::string& prefix = "va_vault") {
        return ops::vaults::create(superUser, {.name = prefix + "_" + tag(), .type = vault::model::VaultType::Local,
                                               .owner_id = owner->id})->id;
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

    static bool succeeds(const std::function<void()>& fn) {
        try {
            fn();
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    // The rows on both surfaces; they must be identical.
    static json bothSurfaces(const UserPtr& user) {
        const auto [code, out] = cli("vault list --accessible --json", user);
        EXPECT_EQ(code, 0) << out;
        const auto viaWs = protocols::ws::handler::Vaults::listAccessible(ws(user));
        json viaCli;
        try {
            viaCli = json::parse(out);
        } catch (const std::exception&) {
            ADD_FAILURE() << "CLI output is not JSON: " << out;
            return viaWs.at("vaults");
        }
        EXPECT_EQ(viaCli, viaWs) << "CLI and ws disagree";
        return viaWs.at("vaults");
    }

    static std::optional<json> row(const json& rows, const unsigned int vaultId) {
        for (const auto& r : rows)
            if (r.at("id").get<unsigned int>() == vaultId) return std::optional<json>(std::in_place, r);
        return std::nullopt;
    }

    static std::vector<std::string> via(const json& r) { return r.at("via").get<std::vector<std::string>>(); }

    // What the enforcing commands themselves answer: the flags must equal these.
    static bool canBrowse(const UserPtr& user, const unsigned int vaultId) {
        return succeeds([&] {
            (void)protocols::ws::handler::fs::Storage::listDir(json{{"vault_id", vaultId}, {"path", "/"}}, ws(user));
        });
    }

    static bool canManage(const UserPtr& user, const unsigned int vaultId) {
        return succeeds([&] { (void)protocols::ws::handler::Vaults::get(json{{"id", vaultId}}, ws(user)); });
    }

    static void expectFlagsEnforced(const UserPtr& user, const json& rows) {
        for (const auto& r : rows) {
            const auto id = r.at("id").get<unsigned int>();
            EXPECT_EQ(r.at("browse").get<bool>(), canBrowse(user, id)) << "browse vs fs.dir.list on vault " << id;
            EXPECT_EQ(r.at("manage").get<bool>(), canManage(user, id)) << "manage vs storage.vault.get on vault " << id;
            EXPECT_FALSE(via(r).empty()) << id;
        }
    }
};

// Every seeded admin role: CLI and ws return the same rows; the rows for an own vault, a vault of an unprivileged
// account and a vault of an admin account follow the role's bits (the scope the vault falls under), and both flags
// match what fs.dir.list and storage.vault.get really allow.
TEST_F(VaultAccessParityTest, EverySeededRoleAgreesOnBothSurfacesAndWithItsBits) {
    const auto plainOwner = createUser("va_plain_owner", "unprivileged");
    // The "admin" scope covers vaults of admin-shaped accounts (User::isAdmin: may delete admins and remove their
    // vaults), which ops::users can't create; a second super-admin account is one.
    const auto adminOwner = identities::manager().user(
        test::identities::createUser("va_admin_owner_" + tag(), db::query::rbac::role::Admin::get("super_admin"),
                                     std::nullopt, "x", std::nullopt)->id);
    ASSERT_TRUE(adminOwner->isAdmin());
    const auto plainVault = vaultFor(plainOwner, "va_plain");
    const auto adminVault = vaultFor(adminOwner, "va_admin");

    unsigned checked = 0;
    for (const auto& role : db::query::rbac::role::Admin::list()) {
        if (!kSeededRoles.contains(role->name)) continue;
        SCOPED_TRACE(role->name);
        const auto caller = role->name == "super_admin" ? superUser : createUser("va_" + role->name, role->name);
        const auto ownVault = vaultFor(caller, "va_own");
        const auto rows = bothSurfaces(caller);
        expectFlagsEnforced(caller, rows);

        const bool super = caller->isSuperAdmin();
        const auto state = caller->state();
        const auto perms = caller->vaultsPerms();
        const auto& globals = state->roles.admin->vGlobals;

        // Own vault: always listed (the owner is a path), self scope.
        const auto own = row(rows, ownVault);
        ASSERT_TRUE(own) << "an own vault is always listed";
        EXPECT_EQ(own->at("browse").get<bool>(), super || globals.self.fs.directories.canList());
        EXPECT_EQ(own->at("manage").get<bool>(), super || perms.self.canView());
        EXPECT_EQ(via(*own).front(), "owner");
        EXPECT_EQ(own->at("owner").get<std::string>(), caller->name());

        // Others' vaults: listed exactly when the admin role grants browse or manage in that scope.
        for (const auto& [vaultId, scopeUser, scopeVaults, scope] :
             {std::tuple{plainVault, &globals.user, &perms.user, "user"},
              std::tuple{adminVault, &globals.admin, &perms.admin, "admin"}}) {
            SCOPED_TRACE(scope);
            const bool browse = super || scopeUser->fs.directories.canList();
            const bool manage = super || scopeVaults->canView();
            const auto r = row(rows, vaultId);
            ASSERT_EQ(r.has_value(), browse || manage);
            if (!r) continue;
            EXPECT_EQ(r->at("browse").get<bool>(), browse);
            EXPECT_EQ(r->at("manage").get<bool>(), manage);
            EXPECT_EQ(via(*r), std::vector<std::string>{super ? "super_admin" : "admin_policy"});
        }

        // A super admin reaches every live vault; the plain list agrees with manage for everyone.
        if (super) {
            EXPECT_EQ(rows.size(), db::query::vault::Vault::listLiveVaults().size());
        }
        std::set<unsigned int> managed, listed;
        for (const auto& r : rows)
            if (r.at("manage").get<bool>()) managed.insert(r.at("id").get<unsigned int>());
        for (const auto& v : ops::vaults::list(caller, {.limit = 10'000})) listed.insert(v->id);
        EXPECT_EQ(managed, listed) << "storage.vault.list is the manage subset";
        ++checked;
    }
    EXPECT_EQ(checked, kSeededRoles.size());
}

// The case that motivated it: an unprivileged account's own vault is invisible to storage.vault.list, and listed
// here as owner. The unprivileged role grants no filesystem or admin vault permission, so neither flag is set:
// ownership alone opens nothing until a role is assigned.
TEST_F(VaultAccessParityTest, UnprivilegedOwnerSeesTheirVault) {
    const auto owner = createUser("va_owner", "unprivileged");
    const auto vaultId = vaultFor(owner);
    EXPECT_TRUE(ops::vaults::list(owner).empty()) << "storage.vault.list follows the admin role alone";

    const auto rows = bothSurfaces(owner);
    expectFlagsEnforced(owner, rows);
    const auto r = row(rows, vaultId);
    ASSERT_TRUE(r);
    EXPECT_EQ(via(*r), std::vector<std::string>{"owner"});
    EXPECT_FALSE(r->at("browse").get<bool>());
    EXPECT_FALSE(r->at("manage").get<bool>());
    for (const auto& other : rows) EXPECT_EQ(other.at("owner_id").get<unsigned int>(), owner->id);

    // Listing probes every vault; a "no" there is an answer, not a refused request, so nothing is logged. A real
    // fs.dir.list refusal still is.
    const AuthWarnings warnings;
    (void)ops::vaults::listAccessible(owner);
    EXPECT_EQ(warnings.count("Filesystem permission denied"), 0u);
    EXPECT_FALSE(canBrowse(owner, vaultId));
    EXPECT_EQ(warnings.count("Filesystem permission denied"), 1u);
}

// A vault role assigned to the account: browse through the role, no manage; the owner of the vault is someone else.
TEST_F(VaultAccessParityTest, DirectVaultRoleGrantsBrowse) {
    const auto owner = createUser("va_role_owner", "unprivileged");
    const auto member = createUser("va_role_member", "unprivileged");
    const auto vaultId = vaultFor(owner);
    EXPECT_FALSE(row(bothSurfaces(member), vaultId));

    (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = vaultId, .subject = {.type = "user", .id = member->id}},
                                                  .role = std::string("reader")});
    EXPECT_TRUE(ops::vaults::list(member).empty());
    const auto rows = bothSurfaces(member);
    expectFlagsEnforced(member, rows);
    const auto r = row(rows, vaultId);
    ASSERT_TRUE(r);
    EXPECT_EQ(via(*r), std::vector<std::string>{"vault_role"});
    EXPECT_TRUE(r->at("browse").get<bool>());
    EXPECT_FALSE(r->at("manage").get<bool>());
    EXPECT_EQ(r->at("owner").get<std::string>(), owner->name());

    // An implicit_deny role is still a path (via), but opens nothing.
    (void)ops::roles::unassignVaultRole(superUser, {.vault_id = vaultId, .subject = {.type = "user", .id = member->id}});
    (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = vaultId, .subject = {.type = "user", .id = member->id}},
                                                  .role = std::string("implicit_deny")});
    const auto denied = row(bothSurfaces(member), vaultId);
    ASSERT_TRUE(denied);
    EXPECT_EQ(via(*denied), std::vector<std::string>{"vault_role"});
    EXPECT_FALSE(denied->at("browse").get<bool>());
    EXPECT_FALSE(canBrowse(member, vaultId));
}

// A vault role held by one of the account's groups; leaving the group takes the vault away.
TEST_F(VaultAccessParityTest, GroupVaultRoleGrantsBrowseUntilTheMemberLeaves) {
    const auto owner = createUser("va_group_owner", "unprivileged");
    const auto member = createUser("va_group_member", "unprivileged");
    const auto vaultId = vaultFor(owner);
    const auto group = ops::groups::create(superUser, {.name = "va_group_" + tag()});
    (void)ops::groups::addMember(superUser, {.group = group->id, .user = member->id});
    (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = vaultId, .subject = {.type = "group", .id = group->id}},
                                                  .role = std::string("reader")});

    const auto rows = bothSurfaces(member);
    expectFlagsEnforced(member, rows);
    const auto r = row(rows, vaultId);
    ASSERT_TRUE(r);
    EXPECT_EQ(via(*r), std::vector<std::string>{"group_role"});
    EXPECT_TRUE(r->at("browse").get<bool>());
    EXPECT_FALSE(r->at("manage").get<bool>());

    // Both paths at once: reported together, in order.
    (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = vaultId, .subject = {.type = "user", .id = member->id}},
                                                  .role = std::string("reader")});
    const auto both = row(bothSurfaces(member), vaultId);
    ASSERT_TRUE(both);
    EXPECT_EQ(via(*both), (std::vector<std::string>{"vault_role", "group_role"}));
    (void)ops::roles::unassignVaultRole(superUser, {.vault_id = vaultId, .subject = {.type = "user", .id = member->id}});

    (void)ops::groups::removeMember(superUser, {.group = group->id, .user = member->id});
    EXPECT_FALSE(row(bothSurfaces(member), vaultId));
}

// Admin global vault policy on others' vaults: a custom admin role with admin.vaults.user.view manages an
// unprivileged account's vault (no filesystem: a custom role's global vault policy starts empty); the seeded auditor
// (Reader globals, view in every scope) browses and manages it. Neither is a locally assigned role.
TEST_F(VaultAccessParityTest, AdminPolicyReachesOthersVaults) {
    const auto owner = createUser("va_policy_owner", "unprivileged");
    const auto vaultId = vaultFor(owner);

    const auto viewerRole = "va_viewer_" + tag();
    (void)ops::roles::createAdminRole(superUser, {.name = viewerRole, .permissions = {.changes = {
        {"admin.vaults.user.view", true}}}}, "test");
    const auto viewer = createUser("va_viewer", viewerRole);
    const auto rows = bothSurfaces(viewer);
    expectFlagsEnforced(viewer, rows);
    const auto r = row(rows, vaultId);
    ASSERT_TRUE(r);
    EXPECT_EQ(via(*r), std::vector<std::string>{"admin_policy"});
    EXPECT_FALSE(r->at("browse").get<bool>());
    EXPECT_TRUE(r->at("manage").get<bool>());

    const auto auditor = createUser("va_auditor", "auditor");
    const auto auditorRow = row(bothSurfaces(auditor), vaultId);
    ASSERT_TRUE(auditorRow);
    EXPECT_EQ(via(*auditorRow), std::vector<std::string>{"admin_policy"});
    EXPECT_TRUE(auditorRow->at("browse").get<bool>());
    EXPECT_TRUE(auditorRow->at("manage").get<bool>());
}

// A deactivated account reaches nothing, whatever it owns or holds.
TEST_F(VaultAccessParityTest, DeactivatedAccountGetsAnEmptyList) {
    const auto owner = createUser("va_deactivated", "auditor");
    const auto vaultId = vaultFor(owner);
    ASSERT_TRUE(row(bothSurfaces(owner), vaultId));

    (void)ops::users::update(superUser, {.id = owner->id, .is_active = false});
    EXPECT_TRUE(ops::vaults::listAccessible(owner).empty());
    EXPECT_TRUE(bothSurfaces(owner).empty());
}

// Deleted vaults (pending purge) are not listed; a restore brings the vault back.
TEST_F(VaultAccessParityTest, DeletedVaultsAreExcluded) {
    const auto owner = createUser("va_deleted_owner", "auditor");
    const auto vaultId = vaultFor(owner);
    ASSERT_TRUE(row(bothSurfaces(owner), vaultId));
    ASSERT_TRUE(row(bothSurfaces(superUser), vaultId));

    (void)ops::vaults::remove(superUser, {.id = vaultId});
    EXPECT_FALSE(row(bothSurfaces(owner), vaultId));
    EXPECT_FALSE(row(bothSurfaces(superUser), vaultId));

    (void)ops::vaults::restore(superUser, vaultId);
    EXPECT_TRUE(row(bothSurfaces(owner), vaultId));
}

// The CLI takes no filters or paging with --accessible, and prints a table without --json.
TEST_F(VaultAccessParityTest, CliRefusesFiltersAndPrintsATable) {
    const auto owner = createUser("va_cli", "unprivileged");
    const auto vaultId = vaultFor(owner, "va_cli_vault");
    for (const auto* line : {"vault list --accessible --limit 5", "vault list --accessible --local",
                             "vault list --accessible --s3", "vault list --accessible --sort name"})
        EXPECT_EQ(cli(line, owner).first, 2) << line;
    const auto [code, out] = cli("vault list --accessible", owner);
    ASSERT_EQ(code, 0) << out;
    EXPECT_NE(out.find(std::to_string(vaultId)), std::string::npos) << out;
    EXPECT_NE(out.find("owner"), std::string::npos) << out;
    EXPECT_NE(out.find("BROWSE"), std::string::npos) << out;
}

// More vaults than a list page (100): the accessible list, and the engines the resolvers need, cover all of them.
// Every "all vaults" caller used to read one default page and silently stop at 100.
TEST_F(VaultAccessParityTest, ReachesPastOneListPage) {
    const auto owner = createUser("va_many", "auditor");
    std::vector<unsigned int> ids;
    for (int i = 0; i < 101; ++i) ids.push_back(vaultFor(owner, "va_many"));
    ASSERT_GT(db::query::vault::Vault::listLiveVaults().size(), 100u);

    runtime::Deps::get().storageManager->initStorageEngines();  // as at startup
    for (const auto id : ids) EXPECT_TRUE(runtime::Deps::get().storageManager->getEngine(id)) << id;
    const auto rows = bothSurfaces(owner);
    for (const auto id : ids) {
        const auto r = row(rows, id);
        ASSERT_TRUE(r) << id;
        EXPECT_TRUE(r->at("browse").get<bool>()) << id;
    }
}

}
