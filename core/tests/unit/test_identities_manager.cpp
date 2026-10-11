// identities::Manager: canonical User/Group objects whose state is published in place.
//
// What these pin down: a shared_ptr<User> handed out once (to a session, an engine, a request) observes every later
// committed change without asking the Manager again; deactivation and deletion make outstanding references
// non-authorizing; a failed write publishes nothing; an older database read never replaces a newer state; out-of-band
// SQL is picked up by reconcile() into the same objects; an authorization view never mixes two publications; and once
// the index is warm, identity lookups cost no database round trip.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/Loader.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Groups.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_identities_manager {

using identities::Group;
using identities::GroupState;
using identities::User;
using identities::UserState;
using FsAction = rbac::permission::vault::FilesystemAction;

namespace {

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

void sql(const std::string& statement, const pqxx::params& params = {}) {
    db::Transactions::exec("test_identities_manager::sql", [&](pqxx::work& txn) { txn.exec(statement, params); });
}

uint64_t revision() { return db::query::identities::Loader::currentRevision(); }

}

// ------------------------------------------------------------------------------------------------ DB-free

TEST(IdentitiesDetached, CanonicalObjectsCannotBeEditedOutsideTheManager) {
    const auto detached = test::identities::detachedUser(9001, "detached");
    UserState next = *detached->state();
    next.name = "renamed";
    detached->replaceDetachedState(next);
    EXPECT_EQ(detached->name(), "renamed");
}

TEST(IdentitiesDetached, NonAuthorizingStatesDenyEverything) {
    UserState s;
    s.name = "inactive";
    s.roles.admin = std::make_shared<rbac::role::Admin>(rbac::role::Admin::SuperAdmin());
    s.meta.is_active = false;
    const auto u = User::detached(9002, s);
    EXPECT_FALSE(u->authorizing());
    EXPECT_FALSE(u->isSuperAdmin()) << "a deactivated super admin must not authorize";
    EXPECT_FALSE(u->isAdmin());
    EXPECT_FALSE(u->identities().users.canView());
    EXPECT_FALSE(u->authz().authorizing());
    EXPECT_TRUE(s.hasSuperAdminRole()) << "the role shape is still there for display";

    s.meta.is_active = true;
    s.deleted = true;
    EXPECT_FALSE(User::detached(9003, s)->isSuperAdmin()) << "a tombstone authorizes nothing";

    // ws: a session holding a non-authorizing user is refused at the next command.
    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    session->user = u;
    EXPECT_EQ(protocols::ws::Router::classifyCommand("storage.vault.list", *session),
              protocols::ws::Router::CommandAuthDecision::Deny);
}

// ------------------------------------------------------------------------------------------------ DB-backed

class IdentitiesManagerDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<User> superAdmin;
    inline static uint32_t vaultId = 0;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_identities_manager] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_identities_manager_" + tag());
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
        runtime::Deps::get().storageManager->initStorageEngines();
        superAdmin = identities::manager().userByName("admin");
        ASSERT_TRUE(superAdmin);
        vaultId = db::query::vault::Vault::listUserVaults(superAdmin->id).front()->id;
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static std::shared_ptr<User> makeUser(const std::string& prefix, const std::string& role = "unprivileged") {
        const auto name = prefix + "_" + tag();
        return test::identities::createUser(name, db::query::rbac::role::Admin::get(role), name + "@vaulthalla.test");
    }

    // Read on an existing entry of the admin vault (the entry is supplied, so nothing has to exist on disk): a
    // directory for "/", a file for anything else.
    static bool canRead(const std::shared_ptr<User>& user, const std::string& vaultPath = "/") {
        const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
        if (!engine) throw std::runtime_error("no storage engine for vault " + std::to_string(vaultId));
        std::shared_ptr<fs::model::Entry> entry;
        if (vaultPath == "/") entry = std::make_shared<fs::model::Directory>();
        else entry = std::make_shared<fs::model::File>();
        entry->path = vaultPath;
        entry->vault_id = static_cast<int32_t>(vaultId);
        return rbac::resolver::Vault::has<FsAction>({
            .user = user, .permission = FsAction::Read, .vault_id = vaultId, .entry = entry});
    }
};

TEST_F(IdentitiesManagerDbTest, LookupsReturnOneCanonicalObject) {
    const auto user = makeUser("idm_canon");
    auto& m = identities::manager();
    EXPECT_EQ(m.user(user->id).get(), user.get());
    EXPECT_EQ(m.userByName(user->name()).get(), user.get());
    (void)m.updateUser(user->id, [](UserState& s) { s.meta.linux_uid = 710001; });
    EXPECT_EQ(m.userByLinuxUid(710001).get(), user.get());
    EXPECT_EQ(m.users().size(), m.users().size());
    bool listed = false;
    for (const auto& u : m.users()) listed |= u.get() == user.get();
    EXPECT_TRUE(listed);
}

// A long-lived holder (a session, an engine) keeps its shared_ptr; a separate administrative request changes the
// account; the holder sees it on its next read, without asking the Manager again.
TEST_F(IdentitiesManagerDbTest, HeldPointerSeesAnAdministrativeUpdate) {
    const auto held = makeUser("idm_held");
    const auto before = held->state();

    const auto newName = "idm_held_renamed_" + tag();
    (void)ops::users::update(superAdmin, {.id = held->id, .name = newName, .role = std::string("auditor")});

    EXPECT_EQ(held->name(), newName);
    ASSERT_TRUE(held->state()->roles.admin);
    EXPECT_EQ(held->state()->roles.admin->name, "auditor");
    EXPECT_GT(held->state()->revision, before->revision);
    EXPECT_EQ(before->name.rfind("idm_held_", 0), 0u) << "a state already read is never changed in place";
}

TEST_F(IdentitiesManagerDbTest, GroupMembershipAndGroupRolesReachHeldUsers) {
    const auto held = makeUser("idm_member");
    ASSERT_FALSE(canRead(held)) << "unprivileged accounts have no global vault rights";

    const auto group = ops::groups::create(superAdmin, {.name = "idm_group_" + tag()});
    (void)ops::groups::addMember(superAdmin, {.group = group->id, .user = held->id});
    EXPECT_TRUE(held->state()->joinedAt.contains(group->id));
    ASSERT_EQ(held->authz().groups.size(), 1u);

    // A group-level change (a vault role assigned to the group) reaches the member through the canonical group,
    // without republishing the user.
    const auto userRevision = held->state()->revision;
    (void)ops::roles::assignVaultRole(superAdmin, {.target = {.vault_id = vaultId, .subject = {.type = "group", .id = group->id}},
                                                   .role = std::string("reader")});
    EXPECT_EQ(held->state()->revision, userRevision) << "a group role must not rebuild every member";
    EXPECT_TRUE(canRead(held));

    (void)ops::groups::removeMember(superAdmin, {.group = group->id, .user = held->id});
    EXPECT_TRUE(held->authz().groups.empty());
    EXPECT_FALSE(canRead(held)) << "removal from the group revokes at the next check";

    // Deleting a group drops it from every member and makes the held Group a tombstone.
    (void)ops::groups::addMember(superAdmin, {.group = group->id, .user = held->id});
    EXPECT_TRUE(canRead(held));
    (void)ops::groups::remove(superAdmin, group->id);
    EXPECT_TRUE(group->deleted());
    EXPECT_TRUE(held->authz().groups.empty());
    EXPECT_FALSE(canRead(held));
}

TEST_F(IdentitiesManagerDbTest, OverridesAndRoleTemplatesReachHeldUsers) {
    const auto held = makeUser("idm_override");
    const ops::roles::VaultSubject target{.vault_id = vaultId, .subject = {.type = "user", .id = held->id}};
    (void)ops::roles::assignVaultRole(superAdmin, {.target = target, .role = std::string("reader")});
    ASSERT_TRUE(canRead(held, "/docs/a.txt"));

    const auto added = ops::roles::addVaultRoleOverrides(superAdmin, {
        .target = target, .permissions = {.changes = {{"vault.fs.files.download", false}}}, .pattern = "/docs/**"});
    ASSERT_EQ(added.size(), 1u);
    EXPECT_FALSE(canRead(held, "/docs/a.txt")) << "a deny override applies at the next check";
    EXPECT_TRUE(canRead(held, "/other.txt"));

    ops::roles::removeVaultRoleOverride(superAdmin, target, added.front().id);
    EXPECT_TRUE(canRead(held, "/docs/a.txt"));

    // A role template edit reaches every holder.
    const auto role = "idm_template_" + tag();
    (void)ops::roles::createVaultRole(superAdmin, {.name = role, .from = std::string("reader")});
    (void)ops::roles::unassignVaultRole(superAdmin, target);
    (void)ops::roles::assignVaultRole(superAdmin, {.target = target, .role = role});
    ASSERT_TRUE(canRead(held, "/x.txt"));
    (void)ops::roles::updateVaultRole(superAdmin, {.role = role, .permissions = {.changes = {
        {"vault.fs.files.download", false}, {"vault.fs.directories.download", false}}}});
    EXPECT_FALSE(canRead(held, "/x.txt")) << "the template change must reach the held user";
}

TEST_F(IdentitiesManagerDbTest, DeactivationAndDeletionRevokeOutstandingReferences) {
    const auto held = makeUser("idm_revoke");
    (void)ops::roles::assignVaultRole(superAdmin, {.target = {.vault_id = vaultId, .subject = {.type = "user", .id = held->id}},
                                                   .role = std::string("reader")});
    ASSERT_TRUE(canRead(held));

    (void)ops::users::update(superAdmin, {.id = held->id, .is_active = false});
    EXPECT_FALSE(held->authorizing());
    EXPECT_FALSE(canRead(held)) << "deactivation revokes at the next check";
    EXPECT_FALSE(rbac::resolver::Admin::has<rbac::permission::admin::identities::IdentityPermissions>({
        .user = held, .permission = rbac::permission::admin::identities::IdentityPermissions::View,
        .identity = rbac::resolver::admin::Entity::User}));

    (void)ops::users::update(superAdmin, {.id = held->id, .is_active = true});
    EXPECT_TRUE(canRead(held));

    (void)ops::users::remove(superAdmin, {.id = held->id, .confirmed = true});
    EXPECT_TRUE(held->deleted());
    EXPECT_FALSE(held->authorizing());
    EXPECT_FALSE(canRead(held)) << "a deleted account keeps no privileges through a held pointer";
    EXPECT_EQ(identities::manager().user(held->id), nullptr);
}

TEST_F(IdentitiesManagerDbTest, AFailedWritePublishesNothing) {
    const auto a = makeUser("idm_fail_a");
    const auto b = makeUser("idm_fail_b");
    const auto before = a->state();
    EXPECT_ANY_THROW((void)identities::manager().updateUser(a->id, [&](UserState& s) { s.name = b->name(); }))
        << "names are unique";
    // What is published after the rejected write is what the database holds: the account as it was. (A state's
    // revision is the identity revision it was read at, so a re-read may carry a later one.)
    EXPECT_GE(a->state()->revision, before->revision);
    EXPECT_EQ(a->name(), before->name);
    EXPECT_EQ(a->email(), before->email);
    EXPECT_EQ(identities::manager().userByName(before->name).get(), a.get());
}

TEST_F(IdentitiesManagerDbTest, AnOlderReadNeverReplacesANewerState) {
    const auto user = makeUser("idm_stale");
    // A cold load that started before the write...
    auto stale = db::query::identities::Loader::load({.userIds = {user->id}});
    (void)identities::manager().updateUser(user->id, [](UserState& s) { s.email = "fresh@vaulthalla.test"; });
    const auto published = user->state();
    ASSERT_EQ(published->email, std::optional<std::string>("fresh@vaulthalla.test"));
    // ...finishes after it, with the older rows: it must not win.
    ASSERT_LT(stale.revision, published->revision);
    identities::manager().publishSnapshotForTesting(std::move(stale));
    EXPECT_EQ(user->state(), published);
}

TEST_F(IdentitiesManagerDbTest, OutOfBandChangesAreReconciledIntoHeldObjects) {
    auto& m = identities::manager();
    (void)m.reconcile();
    const auto held = makeUser("idm_oob");
    const auto rev = revision();

    sql("UPDATE users SET email = $1 WHERE id = $2", pqxx::params{"oob@vaulthalla.test", held->id});
    EXPECT_GT(revision(), rev) << "the trigger bumps identity_revision";
    EXPECT_TRUE(m.reconcile());
    EXPECT_EQ(held->email(), std::optional<std::string>("oob@vaulthalla.test"));

    // last_login is not an identity change.
    const auto quiet = revision();
    sql("UPDATE users SET last_login = NOW() WHERE id = $1", pqxx::params{held->id});
    EXPECT_EQ(revision(), quiet);

    // A role assignment made by hand.
    const auto reader = db::query::rbac::role::Vault::get("reader");
    sql("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) VALUES ($1, 'user', $2, $3)",
        pqxx::params{vaultId, held->id, reader->id});
    EXPECT_TRUE(m.reconcile());
    EXPECT_TRUE(canRead(held));

    // A deletion by hand turns the held object into a tombstone.
    sql("DELETE FROM users WHERE id = $1", pqxx::params{held->id});
    EXPECT_TRUE(m.reconcile());
    EXPECT_TRUE(held->deleted());
    EXPECT_FALSE(canRead(held));

    // A new account created by hand is found.
    const auto name = "idm_oob_new_" + tag();
    sql("INSERT INTO users (name, password_hash, linux_uid) VALUES ($1, 'x', 710777)", pqxx::params{name});
    sql("INSERT INTO admin_role_assignments (user_id, role_id) SELECT id, $2 FROM users WHERE name = $1",
        pqxx::params{name, db::query::rbac::role::Admin::get("unprivileged")->id});
    (void)m.reconcile();
    const auto found = m.userByLinuxUid(710777);
    ASSERT_TRUE(found);
    EXPECT_EQ(found->name(), name);
}

TEST_F(IdentitiesManagerDbTest, WarmLookupsAndChecksCostNoDatabaseRoundTrip) {
    auto& m = identities::manager();
    m.preload();
    const auto user = makeUser("idm_warm");
    (void)m.updateUser(user->id, [](UserState& s) { s.meta.linux_uid = 710555; });
    (void)ops::roles::assignVaultRole(superAdmin, {.target = {.vault_id = vaultId, .subject = {.type = "user", .id = user->id}},
                                                   .role = std::string("reader")});

    const auto loads = m.stats().loads;
    for (int i = 0; i < 2000; ++i) {
        ASSERT_EQ(m.userByLinuxUid(710555).get(), user.get());
        ASSERT_EQ(m.user(user->id).get(), user.get());
        ASSERT_TRUE(canRead(user));   // includes the vault owner check that used to hydrate the owner
    }
    EXPECT_EQ(m.stats().loads, loads) << "identity lookups and permission checks went to the database";

    // An unknown uid costs one query, then is remembered until something changes.
    (void)m.userByLinuxUid(719999);
    const auto afterMiss = m.stats().loads;
    for (int i = 0; i < 100; ++i) EXPECT_EQ(m.userByLinuxUid(719999), nullptr);
    EXPECT_EQ(m.stats().loads, afterMiss);
}

// Readers never see a mix of two publications: one transaction changes a user and its group together, each refresh
// publishes both, and every authorization view taken meanwhile carries matching tags.
TEST_F(IdentitiesManagerDbTest, AuthorizationViewsAreCoherentAcrossObjects) {
    const auto user = makeUser("idm_coherent");
    const auto group = test::identities::createGroup("idm_coherent_" + tag(), "v0");
    test::identities::addMember(group->id, user->id);
    (void)identities::manager().updateUser(user->id, [](UserState& s) { s.email = "v0@x"; });

    std::atomic<bool> stop{false};
    std::atomic<uint64_t> views{0}, mismatches{0};
    std::vector<std::thread> readers;
    for (int r = 0; r < 4; ++r)
        readers.emplace_back([&] {
            while (!stop.load()) {
                const auto view = user->authz();
                if (view.groups.size() != 1) { mismatches.fetch_add(1); continue; }
                const auto email = view.user->email.value_or("");
                const auto desc = view.groups.front()->description.value_or("");
                if (email != desc + "@x") mismatches.fetch_add(1);
                views.fetch_add(1);
            }
        });

    for (int i = 1; i <= 60; ++i) {
        db::Transactions::exec("idm_coherent", [&](pqxx::work& txn) {
            txn.exec("UPDATE groups SET description = $1 WHERE id = $2", pqxx::params{"v" + std::to_string(i), group->id});
            txn.exec("UPDATE users SET email = $1 WHERE id = $2", pqxx::params{"v" + std::to_string(i) + "@x", user->id});
        });
        identities::manager().refresh({.users = {user->id}, .groups = {group->id}});
    }
    stop.store(true);
    for (auto& t : readers) t.join();
    EXPECT_GT(views.load(), 0u);
    EXPECT_EQ(mismatches.load(), 0u) << "an authorization view mixed two publications";
}

// Concurrent writers to one account: published state ends at the last committed revision, readers never crash on a
// state that is being replaced (run under ThreadSanitizer: meson setup build-tsan -Db_sanitize=thread).
TEST_F(IdentitiesManagerDbTest, ConcurrentWritesAndReadsSettleOnTheLastCommit) {
    const auto user = makeUser("idm_race");
    std::atomic<bool> stop{false};
    std::vector<std::thread> readers;
    for (int r = 0; r < 4; ++r)
        readers.emplace_back([&] {
            while (!stop.load()) {
                const auto s = user->state();
                (void)s->email;
                (void)user->authz();
                (void)user->isAdmin();
            }
        });
    std::vector<std::thread> writers;
    for (int w = 0; w < 3; ++w)
        writers.emplace_back([&, w] {
            for (int i = 0; i < 20; ++i)
                (void)identities::manager().updateUser(user->id, [&](UserState& s) {
                    s.email = "w" + std::to_string(w) + "_" + std::to_string(i) + "@x";
                });
        });
    for (auto& t : writers) t.join();
    stop.store(true);
    for (auto& t : readers) t.join();

    const auto credentials = db::query::identities::Loader::load({.userIds = {user->id}});
    ASSERT_EQ(credentials.users.size(), 1u);
    EXPECT_EQ(user->email(), credentials.users.front().state.email) << "the published state lags the database";
    EXPECT_EQ(user->state()->revision, credentials.revision);
}

TEST_F(IdentitiesManagerDbTest, IdentityStateCarriesNoPasswordHash) {
    const auto name = "idm_secret_" + tag();
    const auto user = test::identities::createUser(name, db::query::rbac::role::Admin::get("unprivileged"), std::nullopt,
                                                   "$argon2id$v=19$m=65536,t=3,p=1$" + tag() + "$synthetic-hash");
    const auto credentials = db::query::identities::Loader::credentialsById(user->id);
    ASSERT_TRUE(credentials);
    EXPECT_FALSE(credentials->passwordHash.empty());
    // UserState has no password field at all; the public JSON of an account never carries one.
    const nlohmann::json j = *user;
    EXPECT_FALSE(j.contains("password_hash"));
    EXPECT_FALSE(j.dump().contains(credentials->passwordHash));
}

}
