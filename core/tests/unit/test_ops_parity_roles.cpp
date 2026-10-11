// Role and permission editing through both surfaces (Phase 2). Before this, permission edits were silently dropped:
// the resolver could not apply 77/87 admin permissions, CLI --allow-*/--deny-* flags were skipped, `--from` was
// ignored, unknown keys vanished, and CLI vault-role overrides were never persisted. Every check below compares
// stored permission state, never output text.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/Permission.hpp"
#include "db/query/rbac/permission/Override.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/rbac/role/vault/Assignments.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Roles.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/rbac.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/rbac/roles/Admin.hpp"
#include "protocols/ws/handler/rbac/roles/Vault.hpp"
#include "rbac/permission/Override.hpp"
#include "rbac/resolver/permission/EnumPack.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "UsageManager.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <set>
#include <string>

namespace vh::test_ops_parity_roles {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using AdminResolver = rbac::resolver::PermissionResolverEnumPack<std::shared_ptr<rbac::role::Admin>>::type;

std::string rolesTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

std::string adminBits(const std::string& name) {
    const auto r = db::query::rbac::role::Admin::get(name);
    if (!r) return "<missing>";
    return r->identities.toBitString() + r->vaults.toBitString() + r->audits.toBitString() + r->settings.toBitString() +
           r->roles.toBitString() + r->keys.toBitString() + r->s3Gateway.toBitString() + r->stats.toBitString();
}

std::string vaultBits(const std::string& name) {
    const auto r = db::query::rbac::role::Vault::get(name);
    if (!r) return "<missing>";
    return r->fs.files.toBitString() + r->fs.directories.toBitString() + r->sync.toBitString() + r->roles.toBitString();
}

// The qualified permission names a stored admin role grants.
std::set<std::string> grantedAdmin(const std::string& name) {
    std::set<std::string> out;
    const auto r = db::query::rbac::role::Admin::get(name);
    if (!r) return out;
    for (const auto& p : r->toPermissions())
        if (AdminResolver::has(r, p)) out.insert(p.qualified_name);
    return out;
}

class RoleParityTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser, orgAdmin;

    static UserPtr createUser(const std::string& name, const std::string& roleName) {
        return test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test");
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_ops_parity_roles] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::seed::init_tables_if_not_exists();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::initPermissions();
        seed::initRoles();

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::rbac::registerCommands(router);
        protocols::shell::commands::vault::registerCommands(router);

        superUser = createUser("rp_super_" + rolesTag(), "super_admin");
        orgAdmin = createUser("rp_admin_" + rolesTag(), "admin");
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

    // A complete web snapshot granting exactly `granted`.
    static json adminSnapshot(const std::set<std::string>& granted) {
        json perms = json::array();
        for (const auto& p : rbac::role::Admin::None().toPermissions())
            perms.push_back({{"qualified", p.qualified_name}, {"value", granted.contains(p.qualified_name)}});
        return perms;
    }

    static unsigned int createVault(const std::string& name, const unsigned int ownerId) {
        return db::Transactions::exec("RoleParityTest::createVault", [&](pqxx::work& txn) {
            const auto id = txn.exec(
                "INSERT INTO vault (type, name, owner_id, mount_point, description) VALUES ('local', $1, $2, $3, '') RETURNING id",
                pqxx::params{name, ownerId, name.substr(0, 30)}).one_field_ref().as<unsigned int>();
            txn.exec("WITH ins AS (INSERT INTO sync (vault_id, interval) VALUES ($1, 300) RETURNING id) "
                     "INSERT INTO fsync (sync_id, conflict_policy) SELECT id, 'keep_both' FROM ins", pqxx::params{id});
            return id;
        });
    }
};

TEST_F(RoleParityTest, CliFlagsAndWebSnapshotProduceTheSameAdminRole) {
    const std::set<std::string> want{"admin.identities.users.view", "admin.audits.view"};
    const auto cliName = "rp_cli_" + rolesTag(), wsName = "rp_ws_" + rolesTag();

    const auto [code, out] = cli("role admin create " + cliName + " --allow-users-view --allow-audit-view", superUser);
    ASSERT_EQ(code, 0) << out;
    (void)protocols::ws::handler::rbac::roles::Admin::add(
        json{{"name", wsName}, {"permissions", adminSnapshot(grantedAdmin(cliName))}}, ws(superUser));

    EXPECT_EQ(grantedAdmin(cliName).size(), 2u) << "CLI flags were not applied";
    EXPECT_EQ(adminBits(cliName), adminBits(wsName));
}

// #166: admin.stats.view is an ordinary admin permission on both surfaces: `--allow-stats-view` and the web snapshot
// store the same bit, and the plain `admin` role (which holds it) may grant it under the escalation ceiling.
TEST_F(RoleParityTest, StatsViewIsGrantedTheSameWayOnBothSurfaces) {
    const std::set<std::string> want{"admin.stats.view"};
    const auto cliName = "rp_stats_cli_" + rolesTag(), wsName = "rp_stats_ws_" + rolesTag();

    const auto [code, out] = cli("role admin create " + cliName + " --allow-stats-view", orgAdmin);
    ASSERT_EQ(code, 0) << out;
    (void)protocols::ws::handler::rbac::roles::Admin::add(json{{"name", wsName}, {"permissions", adminSnapshot(want)}},
                                                         ws(orgAdmin));

    EXPECT_EQ(grantedAdmin(cliName), want);
    EXPECT_EQ(grantedAdmin(wsName), want);
    EXPECT_EQ(adminBits(cliName), adminBits(wsName));
    EXPECT_EQ(db::query::rbac::role::Admin::get(cliName)->stats.toBitString(), "00000001");

    ASSERT_EQ(cli("role admin update " + cliName + " --deny-stats-view", orgAdmin).first, 0);
    EXPECT_TRUE(grantedAdmin(cliName).empty());
}

TEST_F(RoleParityTest, CliCreateFromInheritsAndDenyRevokes) {
    const auto name = "rp_from_" + rolesTag();
    const auto [code, out] = cli("role admin create " + name + " --from auditor --deny-audit-view", superUser);
    ASSERT_EQ(code, 0) << out;

    auto expected = grantedAdmin("auditor");
    ASSERT_FALSE(expected.empty());
    expected.erase("admin.audits.view");
    EXPECT_EQ(grantedAdmin(name), expected);
}

TEST_F(RoleParityTest, CliUpdateAppliesFlagsAndWebUpdateAppliesSnapshot) {
    const auto name = "rp_upd_" + rolesTag();
    ASSERT_EQ(cli("role admin create " + name + " --allow-users-view", superUser).first, 0);

    const auto [code, out] = cli("role admin update " + name + " --deny-users-view --allow-groups-view", superUser);
    ASSERT_EQ(code, 0) << out;
    EXPECT_EQ(grantedAdmin(name), (std::set<std::string>{"admin.identities.groups.view"}));

    const auto id = db::query::rbac::role::Admin::get(name)->id;
    (void)protocols::ws::handler::rbac::roles::Admin::update(
        json{{"id", id}, {"permissions", adminSnapshot({"admin.identities.users.edit"})}}, ws(superUser));
    EXPECT_EQ(grantedAdmin(name), (std::set<std::string>{"admin.identities.users.edit"}));
}

TEST_F(RoleParityTest, UnknownFlagsAndBadSnapshotsAreRefusedNotDropped) {
    const auto name = "rp_bad_" + rolesTag();
    EXPECT_NE(cli("role admin create " + name + " --allow-not-a-permission", superUser).first, 0);
    EXPECT_EQ(db::query::rbac::role::Admin::get(name), nullptr);

    auto partial = adminSnapshot({});
    partial.erase(partial.begin());
    EXPECT_THROW((void)protocols::ws::handler::rbac::roles::Admin::add(json{{"name", name}, {"permissions", partial}}, ws(superUser)),
                 std::exception) << "an incomplete snapshot must be refused";
    auto unknown = adminSnapshot({});
    unknown.push_back({{"qualified", "admin.nope.view"}, {"value", true}});
    EXPECT_THROW((void)protocols::ws::handler::rbac::roles::Admin::add(json{{"name", name}, {"permissions", unknown}}, ws(superUser)),
                 std::exception) << "an unknown permission must be refused";
    EXPECT_EQ(db::query::rbac::role::Admin::get(name), nullptr);
}

TEST_F(RoleParityTest, NobodyGrantsAdminPermissionsTheyDoNotHold) {
    // The built-in `admin` role can manage roles but cannot delete users; it must not mint a role that can.
    ASSERT_FALSE(AdminResolver::has(std::make_shared<rbac::role::Admin>(*orgAdmin->state()->roles.admin), *[] {
        for (const auto& p : rbac::role::Admin::None().toPermissions())
            if (p.qualified_name == "admin.identities.users.delete") return std::make_shared<rbac::permission::Permission>(p);
        return std::shared_ptr<rbac::permission::Permission>{};
    }()));

    const auto cliName = "rp_ceil_cli_" + rolesTag(), wsName = "rp_ceil_ws_" + rolesTag();
    EXPECT_NE(cli("role admin create " + cliName + " --allow-users-delete", orgAdmin).first, 0);
    EXPECT_THROW((void)protocols::ws::handler::rbac::roles::Admin::add(
        json{{"name", wsName}, {"permissions", adminSnapshot({"admin.identities.users.delete"})}}, ws(orgAdmin)), std::exception);
    EXPECT_EQ(db::query::rbac::role::Admin::get(cliName), nullptr);
    EXPECT_EQ(db::query::rbac::role::Admin::get(wsName), nullptr);

    // Within the ceiling it works, and the ceiling also guards updates.
    ASSERT_EQ(cli("role admin create " + cliName + " --allow-users-view", orgAdmin).first, 0);
    EXPECT_NE(cli("role admin update " + cliName + " --allow-users-delete", orgAdmin).first, 0);
    EXPECT_FALSE(grantedAdmin(cliName).contains("admin.identities.users.delete"));
}

TEST_F(RoleParityTest, VaultRoleFlagsIncludingShareApply) {
    const auto cliName = "rp_vr_cli_" + rolesTag(), wsName = "rp_vr_ws_" + rolesTag();
    const auto [code, out] = cli("role vault create " + cliName + " --allow-files-upload --allow-files-share-public", superUser);
    ASSERT_EQ(code, 0) << out;
    const auto role = db::query::rbac::role::Vault::get(cliName);
    ASSERT_TRUE(role);
    EXPECT_TRUE(role->fs.files.canSharePublicly()) << "share permissions were not applicable before Phase 2";

    json perms = json::array();
    using VaultResolver = rbac::resolver::PermissionResolverEnumPack<std::shared_ptr<rbac::role::Vault>>::type;
    for (const auto& p : role->toPermissions())
        perms.push_back({{"qualified", p.qualified_name}, {"value", VaultResolver::has(role, p)}});
    (void)protocols::ws::handler::rbac::roles::Vault::add(json{{"name", wsName}, {"permissions", perms}}, ws(superUser));
    EXPECT_EQ(vaultBits(cliName), vaultBits(wsName));
}

TEST_F(RoleParityTest, AssignmentsAndOverridesPersistAndUnassigningNothingFails) {
    const auto member = createUser("rp_member_" + rolesTag(), "unprivileged");
    const auto vaultId = createVault("rp_vault_" + rolesTag(), superUser->id);
    const auto roleName = "rp_assign_" + rolesTag();
    ASSERT_EQ(cli("role vault create " + roleName + " --allow-files-download", superUser).first, 0);

    // Removing a role nobody holds used to report success (and `vault role remove` was not even reachable).
    const auto [rcode, rout] = cli("vault role remove " + std::to_string(vaultId) + " " + roleName + " -u " + member->name(), superUser);
    EXPECT_NE(rcode, 0);
    EXPECT_NE(rout.find("no vault role is assigned"), std::string::npos) << rout;

    const auto [code, out] = cli("vault role assign " + std::to_string(vaultId) + " " + roleName + " -u " + member->name(), superUser);
    ASSERT_EQ(code, 0) << out;
    const auto assignment = db::query::rbac::role::vault::Assignments::get(vaultId, "user", member->id);
    ASSERT_TRUE(assignment);

    // Overrides used to mutate an in-memory copy and never reach the database.
    const auto [ocode, oout] = cli("vault role override add " + std::to_string(vaultId) + " " + roleName + " -u " +
                                   member->name() + " --deny-files-download --pattern /secret/**", superUser);
    ASSERT_EQ(ocode, 0) << oout;
    const auto stored = db::query::rbac::permission::Override::listAssigned(assignment->assignment_id);
    ASSERT_EQ(stored.size(), 1u);
    EXPECT_EQ(stored.front()->effect, rbac::permission::OverrideOpt::DENY);
    EXPECT_EQ(stored.front()->glob_path(), "/secret/**");

    EXPECT_NE(cli("vault role override add " + std::to_string(vaultId) + " " + roleName + " -u " + member->name() +
                  " --deny-files-download", superUser).first, 0) << "--pattern is required";

    const auto overrideId = std::to_string(stored.front()->id);
    const auto [ucode, uout] = cli("vault role override update " + std::to_string(vaultId) + " " + roleName + " " +
                                   overrideId + " -u " + member->name() + " --allow --disable", superUser);
    ASSERT_EQ(ucode, 0) << uout;
    const auto updated = db::query::rbac::permission::Override::get(stored.front()->id);
    EXPECT_EQ(updated->effect, rbac::permission::OverrideOpt::ALLOW);
    EXPECT_FALSE(updated->enabled);

    ASSERT_EQ(cli("vault role override remove " + std::to_string(vaultId) + " " + roleName + " " + overrideId + " -u " +
                  member->name(), superUser).first, 0);
    EXPECT_TRUE(db::query::rbac::permission::Override::listAssigned(assignment->assignment_id).empty());

    // The same lifecycle over ws (role.vault.overrides.*) lands in the same rows.
    const json target{{"vault_id", vaultId}, {"subject_type", "user"}, {"subject_id", member->id}};
    json addPayload = target;
    addPayload["pattern"] = "/secret/**";
    addPayload["permissions"] = json::array({{{"qualified", "vault.fs.files.download"}, {"value", false}}});
    const auto added = protocols::ws::handler::rbac::roles::Vault::addOverrides(addPayload, ws(superUser));
    ASSERT_EQ(added.at("overrides").size(), 1u);
    const auto wsStored = db::query::rbac::permission::Override::listAssigned(assignment->assignment_id);
    ASSERT_EQ(wsStored.size(), 1u);
    EXPECT_EQ(wsStored.front()->effect, rbac::permission::OverrideOpt::DENY);
    EXPECT_EQ(wsStored.front()->glob_path(), "/secret/**");
    EXPECT_EQ(protocols::ws::handler::rbac::roles::Vault::listOverrides(target, ws(superUser)).at("overrides").size(), 1u);

    json updatePayload = target;
    updatePayload["override_id"] = wsStored.front()->id;
    updatePayload["effect"] = "allow";
    updatePayload["enabled"] = false;
    (void)protocols::ws::handler::rbac::roles::Vault::updateOverride(updatePayload, ws(superUser));
    const auto wsUpdated = db::query::rbac::permission::Override::get(wsStored.front()->id);
    EXPECT_EQ(wsUpdated->effect, rbac::permission::OverrideOpt::ALLOW);
    EXPECT_FALSE(wsUpdated->enabled);
    updatePayload["effect"] = "maybe";
    EXPECT_THROW((void)protocols::ws::handler::rbac::roles::Vault::updateOverride(updatePayload, ws(superUser)), ops::Invalid);

    json removePayload = target;
    removePayload["override_id"] = wsStored.front()->id;
    (void)protocols::ws::handler::rbac::roles::Vault::removeOverride(removePayload, ws(superUser));
    EXPECT_TRUE(db::query::rbac::permission::Override::listAssigned(assignment->assignment_id).empty());

    // ws unassign of the same assignment, then nothing is left to remove on either surface.
    (void)protocols::ws::handler::rbac::roles::Vault::unassign(
        json{{"vault_id", vaultId}, {"subject_type", "user"}, {"subject_id", member->id}}, ws(superUser));
    EXPECT_EQ(db::query::rbac::role::vault::Assignments::get(vaultId, "user", member->id), nullptr);
    EXPECT_THROW((void)ops::roles::unassignVaultRole(superUser, {.vault_id = vaultId, .subject = {.type = "user", .id = member->id}}),
                 ops::NotFound);
}

}

namespace vh::test_ops_parity_roles {

// The web's role forms build their snapshot from the seeded `permissions.list` rows filtered by domain prefix, and
// role snapshots are now strict. The seeded set must therefore equal what each role type exports.
TEST_F(RoleParityTest, SeededPermissionsMatchWhatRolesExport) {
    std::set<std::string> seededAdmin, seededVault, exportedAdmin, exportedVault;
    for (const auto& p : db::query::rbac::Permission::listPermissions()) {
        if (p->qualified_name.starts_with("admin.")) seededAdmin.insert(p->qualified_name);
        if (p->qualified_name.starts_with("vault.")) seededVault.insert(p->qualified_name);
    }
    for (const auto& p : rbac::role::Admin::None().toPermissions()) exportedAdmin.insert(p.qualified_name);
    for (const auto& p : rbac::role::Vault().toPermissions()) exportedVault.insert(p.qualified_name);
    EXPECT_EQ(seededAdmin, exportedAdmin);
    EXPECT_EQ(seededVault, exportedVault);
}

}
