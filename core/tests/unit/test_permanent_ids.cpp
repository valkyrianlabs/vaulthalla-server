// Folder, symlink and snapshot ids and remote accounts (server mirror phase 1b, migrations 158/159;
// design/peers/identity.md "How an account is named across servers", "Remote accounts", invariant 1;
// design/peers/mirror.md "Permanent ids for every entry").
//
// What these pin down: every folder, symlink and snapshot gets its uid when it is created and never another; accounts,
// groups and roles get no second id (a remote account is named by its home server's node id and its integer id
// there, unique per home server); names are unique among local accounts only; a remote account holds no credential,
// admin role or global vault policy (the database refuses them), can never become one from a local account, and is
// refused by every authentication path at the one place identities are loaded for authorisation
// (UserState::authorizing). The upgrade backfill is in test_sql_deployer_history.cpp, the read-only manifest
// collector in test_manifest_db.cpp.

#include "../helpers/db_suite.hpp"
#include "../helpers/identities.hpp"
#include "../helpers/web_session.hpp"

#include "auth/mfa/Factors.hpp"
#include "auth/mfa/SignIn.hpp"
#include "auth/session/Assurance.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Symlink.hpp"
#include "db/query/identities/Loader.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/recovery/Snapshot.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Symlink.hpp"
#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/Actor.hpp"
#include "rbac/PolicyEpoch.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/seed_db.hpp"
#include "share/Link.hpp"
#include "share/Manager.hpp"
#include "share/Types.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <atomic>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace vh::test_permanent_ids {

using namespace vh::test::web;

namespace {

constexpr auto kPeerNode = "peer-node-1";

std::string uuidOf(const crypto::id::ObjectUid& uid) { return crypto::id::toUuid(uid); }


void sql(const std::string& statement, const pqxx::params& params = {}) {
    db::Transactions::exec("test_permanent_ids::sql", [&](pqxx::work& txn) { txn.exec(statement, params); });
}

std::optional<std::string> sqlText(const std::string& statement, const pqxx::params& params = {}) {
    return db::Transactions::exec("test_permanent_ids::sqlText", [&](pqxx::work& txn) -> std::optional<std::string> {
        const auto res = txn.exec(statement, params);
        if (res.empty() || res[0][0].is_null()) return std::nullopt;
        return res[0][0].as<std::string>();
    });
}

// The account's id on its home server: distinct per remote row this process inserts.
uint32_t nextHomeId() {
    static std::atomic<uint32_t> next{1000};
    return next.fetch_add(1);
}

// A remote account as the link's principal stream will make it (nothing creates one yet): no password, its home
// server's node id and its id there.
uint32_t insertRemoteUser(const std::string& name, const std::optional<std::string>& email = std::nullopt) {
    return db::Transactions::exec("test_permanent_ids::insertRemoteUser", [&](pqxx::work& txn) {
        return txn.exec("INSERT INTO users (name, email, password_hash, remote, home_node, home_id) "
                        "VALUES ($1, $2, '', TRUE, $3, $4) RETURNING id",
                        pqxx::params{name, email, kPeerNode, nextHomeId()}).one_field_ref().as<uint32_t>();
    });
}

uint32_t insertRemoteGroup(const std::string& name) {
    return db::Transactions::exec("test_permanent_ids::insertRemoteGroup", [&](pqxx::work& txn) {
        return txn.exec("INSERT INTO groups (name, remote, home_node, home_id) VALUES ($1, TRUE, $2, $3) RETURNING id",
                        pqxx::params{name, kPeerNode, nextHomeId()}).one_field_ref().as<uint32_t>();
    });
}

// The statement fails with a check_violation naming a remote account (the trigger, not some other constraint).
void expectRefusedForRemote(const std::string& statement, const pqxx::params& params, const std::string& what) {
    try {
        sql(statement, params);
        ADD_FAILURE() << what << ": accepted for a remote account";
    } catch (const pqxx::check_violation& e) {
        EXPECT_NE(std::string(e.what()).find("remote account"), std::string::npos) << what << ": " << e.what();
    } catch (const std::exception& e) {
        ADD_FAILURE() << what << ": refused for another reason: " << e.what();
    }
}

// Publishes `id`'s current state with `edit` applied, as if the database said so (the database itself would refuse
// such a state: these prove the paths ask UserState::authorizing, whatever put the account in that state).
void publishEdited(const uint32_t id, const std::function<void(identities::UserState&)>& edit) {
    auto snap = db::query::identities::Loader::load({.userIds = {id}});
    ASSERT_EQ(snap.users.size(), 1u);
    edit(snap.users[0].state);
    identities::manager().publishSnapshotForTesting(std::move(snap));
}

}

// ------------------------------------------------------------------------------------------------ DB-free

TEST(RemoteAccounts, ARemoteStateAuthorizesNothing) {
    identities::UserState s;
    s.name = "cooper";
    s.remote = true;
    s.homeNode = kPeerNode;
    s.roles.admin = std::make_shared<rbac::role::Admin>(rbac::role::Admin::SuperAdmin());
    s.roles.vaults[1] = std::make_shared<rbac::role::Vault>(rbac::role::Vault::Manager());
    const auto u = identities::User::detached(9101, s);
    EXPECT_FALSE(u->authorizing());
    EXPECT_FALSE(u->isSuperAdmin());
    EXPECT_FALSE(u->isAdmin());
    EXPECT_FALSE(u->identities().users.canView());
    EXPECT_FALSE(u->getDirectVaultRole(1)) << "an entry for a remote account does nothing where it is remote";
    EXPECT_FALSE(u->authz().authorizing());

    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    session->user = u;
    EXPECT_EQ(protocols::ws::Router::classifyCommand("storage.vault.list", *session),
              protocols::ws::Router::CommandAuthDecision::Deny);

    s.remote = false;
    EXPECT_TRUE(identities::User::detached(9102, s)->isSuperAdmin()) << "the same state, local, does authorize";
}

TEST(RemoteAccounts, ARemoteGroupsVaultRolesTakeNoEffect) {
    identities::GroupState remote;
    remote.name = "editors";
    remote.remote = true;
    remote.homeNode = kPeerNode;
    remote.roles.vaults[1] = std::make_shared<rbac::role::Vault>(rbac::role::Vault::Editor());
    auto local = remote;
    local.remote = false;
    local.homeNode.reset();

    identities::UserState s;
    s.name = "member";
    s.groups = {identities::Group::detached(1, remote), identities::Group::detached(2, local)};
    const auto view = identities::User::detached(9103, s)->authz();
    ASSERT_EQ(view.groups.size(), 1u);
    EXPECT_FALSE(view.groups.front()->remote);
}

// ------------------------------------------------------------------------------------------------ DB-backed

class PermanentIdsDb : public vh::test::db::Suite {
protected:
    AuthRuntime auth_{};
    inline static uint32_t vaultId = 0;
    inline static std::shared_ptr<storage::Engine> engine;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_permanent_ids")) return;
        const auto vault = ops::vaults::create(superUser, {.name = "permanent_ids_" + tag(),
                                                           .type = vault::model::VaultType::Local});
        vaultId = vault->id;
        engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    }

    static void TearDownTestSuite() {
        engine.reset();
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        ASSERT_TRUE(engine);
    }

    void mkdir(const std::string& path) const {
        ASSERT_EQ(fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath(path), .engine = engine, .user = superUser}),
                  0);
    }
};

TEST_F(PermanentIdsDb, EveryFolderSymlinkAndSnapshotGetsItsUidWhenItIsCreated) {
    // Accounts and groups keep their integer id and nothing else: a local one has no home server or id there.
    const auto user = newUser("unprivileged");
    EXPECT_FALSE(user->remote());
    EXPECT_FALSE(user->homeNode()) << "a local account belongs to this server";
    EXPECT_FALSE(user->homeId());
    const auto group = test::identities::createGroup("t_group_" + tag());
    EXPECT_FALSE(group->remote());

    // No second id on accounts, groups or roles: an account of another server is named by (home_node, home_id), and
    // no role id crosses the link.
    for (const auto* table : {"users", "groups", "vault_role", "admin_role"})
        EXPECT_EQ(sqlText("SELECT count(*)::text FROM information_schema.columns WHERE table_schema = current_schema() "
                          "AND table_name = $1 AND column_name = 'uid'", pqxx::params{std::string(table)}), "0")
            << table;

    // A folder of a local vault: assigned at insert (not by the manifest collector), kept by the model.
    mkdir("/ids");
    const auto dir = db::query::fs::Directory::getDirectoryByPath(vaultId, "/ids");
    ASSERT_TRUE(dir && dir->uid);
    EXPECT_EQ(sqlText("SELECT uid::text FROM directories WHERE fs_entry_id = $1", pqxx::params{dir->id}),
              uuidOf(*dir->uid));

    // A symlink.
    auto link = std::make_shared<fs::model::Symlink>();
    link->vault_id = static_cast<int32_t>(vaultId);
    link->parent_id = static_cast<int32_t>(dir->id);
    link->name = "latest";
    link->path = "/ids/latest";
    link->target = "elsewhere";
    link->base32_alias = "link" + tag();
    link->mode = 0777;
    link->created_by = link->last_modified_by = static_cast<int32_t>(superUser->id);
    const auto linkId = db::query::fs::Symlink::upsertSymlink(link);
    ASSERT_TRUE(link->uid);
    EXPECT_EQ(sqlText("SELECT uid::text FROM symlinks WHERE fs_entry_id = $1", pqxx::params{linkId}), uuidOf(*link->uid));

    // A snapshot, from its insert (the collector used to give one at the first publish).
    const auto snapshotId = db::query::recovery::Snapshot::create(
        {.vault_id = vaultId, .name = "ids " + tag(), .root_path = "/", .root_type = vh::recovery::PointKind::Directory});
    EXPECT_TRUE(sqlText("SELECT uid::text FROM recovery_snapshot WHERE id = $1", pqxx::params{snapshotId}));

    // Nothing in the vault is without one.
    EXPECT_EQ(sqlText("SELECT count(*)::text FROM directories d JOIN fs_entry e ON e.id = d.fs_entry_id "
                      "WHERE e.vault_id = $1 AND d.uid IS NULL", pqxx::params{vaultId}), "0");
}

TEST_F(PermanentIdsDb, AFolderUidNeverChangesOnceAssigned) {
    mkdir("/immutable");
    const auto dir = db::query::fs::Directory::getDirectoryByPath(vaultId, "/immutable");
    ASSERT_TRUE(dir);
    const auto where = "fs_entry_id = " + std::to_string(dir->id);
    EXPECT_ANY_THROW(sql("UPDATE directories SET uid = gen_random_uuid() WHERE " + where));
    EXPECT_NO_THROW(sql("UPDATE directories SET uid = uid WHERE " + where)) << "a same-value write passes";
    EXPECT_ANY_THROW(sql("UPDATE directories SET uid = NULL WHERE " + where));
}

TEST_F(PermanentIdsDb, NamesAreUniqueAmongLocalAccountsOnly) {
    const auto local = newUser("unprivileged");
    const auto remoteId = insertRemoteUser(local->name(), std::string("shared@vaulthalla.test"));
    EXPECT_NE(remoteId, local->id);
    EXPECT_ANY_THROW((void)test::identities::createUser(local->name(), db::query::rbac::role::Admin::get("unprivileged")))
        << "two local accounts still never share a name";
    EXPECT_NO_THROW((void)insertRemoteUser("t_remote_only_" + tag(), std::string("shared@vaulthalla.test")))
        << "nor does a remote account's email clash with anything";

    // Names find the local account; the remote one is reached by id and says what it is.
    EXPECT_EQ(identities::manager().userByName(local->name()), local);
    const auto remote = identities::manager().user(remoteId);
    ASSERT_TRUE(remote);
    EXPECT_TRUE(remote->remote());
    EXPECT_EQ(remote->homeNode(), kPeerNode);
    EXPECT_TRUE(remote->homeId()) << "named by its home server and its id there";
    EXPECT_FALSE(remote->authorizing());

    const auto onlyRemote = "t_only_remote_" + tag();
    (void)insertRemoteUser(onlyRemote);
    EXPECT_FALSE(identities::manager().userByName(onlyRemote)) << "a remote account is never found by name";

    const auto group = test::identities::createGroup("t_group_" + tag());
    const auto remoteGroupId = insertRemoteGroup(group->name());
    EXPECT_ANY_THROW((void)test::identities::createGroup(group->name()));
    EXPECT_EQ(identities::manager().groupByName(group->name()), group);
    const auto remoteGroup = identities::manager().group(remoteGroupId);
    ASSERT_TRUE(remoteGroup);
    EXPECT_TRUE(remoteGroup->remote());
}

TEST_F(PermanentIdsDb, ARemoteAccountHasNoCredentialsAndNoLocalAccountBecomesOne) {
    const auto refused = [](const std::string& statement, const pqxx::params& params) {
        try {
            sql(statement, params);
        } catch (const pqxx::sql_error&) {
            return true;
        }
        return false;
    };
    const auto name = "t_remote_" + tag();
    EXPECT_TRUE(refused("INSERT INTO users (name, password_hash, remote, home_node, home_id) "
                        "VALUES ($1, 'x', TRUE, 'peer', 7)", pqxx::params{name})) << "no password hash";
    EXPECT_TRUE(refused("INSERT INTO users (name, password_hash, remote, home_node, home_id, linux_uid) "
                        "VALUES ($1, '', TRUE, 'peer', 7, 54321)", pqxx::params{name})) << "no Linux uid";
    EXPECT_TRUE(refused("INSERT INTO users (name, password_hash, remote, home_id) VALUES ($1, '', TRUE, 7)",
                        pqxx::params{name})) << "a remote account names its home node";
    EXPECT_TRUE(refused("INSERT INTO users (name, password_hash, remote, home_node) VALUES ($1, '', TRUE, 'peer')",
                        pqxx::params{name})) << "and its id there";
    EXPECT_TRUE(refused("INSERT INTO users (name, password_hash, home_node, home_id) VALUES ($1, 'x', 'peer', 7)",
                        pqxx::params{name})) << "a local account has no home server";
    EXPECT_TRUE(refused("INSERT INTO groups (name, remote, home_node, home_id, linux_gid) "
                        "VALUES ($1, TRUE, 'peer', 7, 54321)", pqxx::params{name})) << "a remote group has no Linux gid";
    EXPECT_TRUE(refused("INSERT INTO groups (name, remote, home_node) VALUES ($1, TRUE, 'peer')", pqxx::params{name}));

    // One row per account of a home server; the same id on another server is another account.
    EXPECT_FALSE(refused("INSERT INTO users (name, password_hash, remote, home_node, home_id) "
                         "VALUES ($1, '', TRUE, 'peer-a', 7)", pqxx::params{name + "_a"}));
    EXPECT_TRUE(refused("INSERT INTO users (name, password_hash, remote, home_node, home_id) "
                        "VALUES ($1, '', TRUE, 'peer-a', 7)", pqxx::params{name + "_again"}))
        << "(home_node, home_id) is unique among remote accounts";
    EXPECT_FALSE(refused("INSERT INTO users (name, password_hash, remote, home_node, home_id) "
                         "VALUES ($1, '', TRUE, 'peer-b', 7)", pqxx::params{name + "_b"}));
    EXPECT_FALSE(refused("INSERT INTO groups (name, remote, home_node, home_id) VALUES ($1, TRUE, 'peer-a', 7)",
                         pqxx::params{name + "_g"})) << "groups are numbered apart from users";
    EXPECT_TRUE(refused("INSERT INTO groups (name, remote, home_node, home_id) VALUES ($1, TRUE, 'peer-a', 7)",
                        pqxx::params{name + "_g2"}));

    const auto local = newUser("unprivileged");
    EXPECT_TRUE(refused("UPDATE users SET remote = TRUE, home_node = 'peer', home_id = 8, password_hash = '' WHERE id = $1",
                        pqxx::params{local->id})) << "a local account never becomes remote";
    const auto group = test::identities::createGroup("t_group_" + tag());
    EXPECT_TRUE(refused("UPDATE groups SET remote = TRUE, home_node = 'peer', home_id = 8 WHERE id = $1",
                        pqxx::params{group->id}));

    // The account writes refuse a remote account: it changes only on its home server.
    const auto remoteId = insertRemoteUser(name);
    EXPECT_ANY_THROW(identities::manager().setPasswordHash(remoteId, crypto::hash::password(kPassword)));
    EXPECT_ANY_THROW((void)identities::manager().updateUser(remoteId, [](identities::UserState& s) {
        s.meta.linux_uid = 54321;
    }));
    EXPECT_ANY_THROW(runtime::Deps::get().authManager->resetPassword(remoteId, kPassword));
    identities::UserState draft;
    draft.name = "t_drafted_remote_" + tag();
    draft.remote = true;
    draft.homeNode = kPeerNode;
    draft.roles.admin = db::query::rbac::role::Admin::get("unprivileged");
    EXPECT_ANY_THROW((void)identities::manager().createUser(draft, "")) << "nothing creates remote accounts yet";
}

TEST_F(PermanentIdsDb, ARemoteAccountHoldsNoCredentialAdminRoleOrGlobalPolicy) {
    const auto remoteId = insertRemoteUser("t_remote_" + tag());
    const auto local = newUser("unprivileged");
    // A minimal row is enough: the trigger runs before the table's own constraints, so a refusal that names a remote
    // account is the trigger's.
    for (const auto* table : {"refresh_tokens", "webauthn_credentials", "totp_factors", "recovery_code_batches",
                              "recovery_codes", "devices", "connector_grants", "key_backup_grants",
                              "admin_role_assignments", "user_global_vault_policy"})
        expectRefusedForRemote(std::string("INSERT INTO ") + table + " (user_id) VALUES ($1)", pqxx::params{remoteId},
                               table);
    expectRefusedForRemote("INSERT INTO s3_gateway_credentials (user_id, principal_user_id) VALUES ($1, $2)",
                           pqxx::params{local->id, remoteId}, "s3_gateway_credentials principal");
    expectRefusedForRemote("INSERT INTO s3_gateway_credentials (user_id, principal_user_id) VALUES ($1, $2)",
                           pqxx::params{remoteId, local->id}, "s3_gateway_credentials owner");
    // Moving an existing row onto a remote account is refused the same way.
    expectRefusedForRemote("UPDATE admin_role_assignments SET user_id = $1 WHERE user_id = $2",
                           pqxx::params{remoteId, local->id}, "admin_role_assignments update");

    // A vault role on a remote account is allowed (shared access lists name people of either server) and does nothing
    // here.
    sql("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) "
        "SELECT $1, 'user', $2, id FROM vault_role WHERE name = 'manager'", pqxx::params{vaultId, remoteId});
    identities::manager().refresh({.users = {remoteId}});
    const auto remote = identities::manager().user(remoteId);
    ASSERT_TRUE(remote);
    EXPECT_FALSE(remote->hasDirectVaultRole(vaultId));
    EXPECT_FALSE(remote->state()->roles.admin) << "no admin role was ever loaded for it";
}

// identity.md invariant 1: a remote account can authenticate through no path.

TEST_F(PermanentIdsDb, PasswordSignInNeverReachesARemoteAccount) {
    const auto remoteName = "t_remote_" + tag();
    (void)insertRemoteUser(remoteName);
    const auto s = connect();
    const auto refused = call([&] {
        return protocols::ws::handler::Auth::login(json{{"name", remoteName}, {"password", ""}}, s);
    });
    EXPECT_FALSE(refused.ok);
    EXPECT_EQ(refused.message, auth::Manager::kLoginFailed) << "the same answer as an unknown name";
    EXPECT_FALSE(s->user);

    // A local account sharing a remote account's name signs in as itself.
    const auto local = newUser("unprivileged");
    (void)insertRemoteUser(local->name());
    const auto ls = connect();
    const auto ok = login(local, ls);
    ASSERT_TRUE(ok.ok) << ok.code << " " << ok.message;
    ASSERT_TRUE(ls->user);
    EXPECT_EQ(ls->user->id, local->id);
}

TEST_F(PermanentIdsDb, PasskeySignInNeverReachesARemoteAccount) {
    const auto remoteId = insertRemoteUser("t_remote_" + tag());
    const auto remote = identities::manager().user(remoteId);
    ASSERT_TRUE(remote);
    // It can hold no passkey (or any other factor)...
    const test_webauthn::Authenticator authenticator;
    EXPECT_ANY_THROW(enrollPasskey(remote, authenticator));
    // ...and the sign-in every factor finishes through refuses it.
    const auto s = connect();
    EXPECT_ANY_THROW(auth::mfa::signin::complete(s, remote, auth::session::assurance::password(), "webauthn"));
    EXPECT_FALSE(s->user);
}

TEST_F(PermanentIdsDb, SessionsAndRefreshTokensNeverServeARemoteAccount) {
    const auto local = newUser("unprivileged");
    const auto s = connect();
    ASSERT_TRUE(login(local, s).ok);
    const auto cookie = cookieOf(s);
    ASSERT_TRUE(httpLaneAccepts(cookie));

    publishEdited(local->id, [](identities::UserState& st) {
        st.remote = true;
        st.homeNode = kPeerNode;
    });
    EXPECT_FALSE(local->authorizing());
    // The HTTP lanes revalidate a cached session every 30 s or at the next policy change; then it is refused.
    rbac::bumpPolicyEpoch();
    EXPECT_FALSE(httpLaneAccepts(cookie)) << "the HTTP lanes";
    EXPECT_FALSE(connect(cookie)->user) << "a websocket rehydrating from the cookie";
    EXPECT_EQ(protocols::ws::Router::classifyCommand("storage.vault.list", *s),
              protocols::ws::Router::CommandAuthDecision::Deny) << "the socket already signed in";
    identities::manager().refresh({.users = {local->id}});
}

TEST_F(PermanentIdsDb, PairedDevicesNeverServeARemoteAccount) {
    const auto remoteId = insertRemoteUser("t_remote_" + tag());
    EXPECT_ANY_THROW((void)pairedDevice(identities::manager().user(remoteId))) << "it cannot be paired";

    const auto local = newUser("unprivileged");
    const auto device = pairedDevice(local);
    publishEdited(local->id, [](identities::UserState& st) {
        st.remote = true;
        st.homeNode = kPeerNode;
    });
    EXPECT_EQ(protocols::ws::Router::classifyCommand("storage.vault.list", *device.session),
              protocols::ws::Router::CommandAuthDecision::Deny);
    identities::manager().refresh({.users = {local->id}});
}

TEST_F(PermanentIdsDb, ARemoteAccountCannotOpenAShare) {
    const auto remoteId = insertRemoteUser("t_remote_" + tag());
    sql("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) "
        "SELECT $1, 'user', $2, id FROM vault_role WHERE name = 'manager'", pqxx::params{vaultId, remoteId});
    identities::manager().refresh({.users = {remoteId}});
    const auto root = db::query::fs::Directory::getDirectoryByPath(vaultId, "/");
    ASSERT_TRUE(root);

    share::Manager shares;
    share::Link link;
    link.vault_id = vaultId;
    link.root_entry_id = root->id;
    link.root_path = "/";
    link.target_type = share::TargetType::Directory;
    link.link_type = share::LinkType::Access;
    link.access_mode = share::AccessMode::Public;
    link.allowed_ops = share::bit(share::Operation::List);
    link.expires_at = std::time(nullptr) + 3600;
    EXPECT_ANY_THROW((void)shares.createLink(rbac::Actor::human(identities::manager().user(remoteId)),
                                             {.link = link, .public_role = share::RoleAssignmentRequest{
                                                                .vault_role_name = rbac::role::Vault::Reader().name}}));
}

TEST_F(PermanentIdsDb, TheControlSocketNeverMapsToARemoteAccount) {
    // `vh` resolves the caller's Linux uid (root: the account named root); a remote account has neither.
    const auto name = "t_remote_" + tag();
    const auto remoteId = insertRemoteUser(name);
    EXPECT_ANY_THROW(sql("UPDATE users SET linux_uid = 54322 WHERE id = $1", pqxx::params{remoteId}));
    EXPECT_FALSE(identities::manager().userByName(name));
    seed::reconcileSystemPrincipals();
    (void)insertRemoteUser("root");
    const auto root = identities::manager().userByName("root");
    ASSERT_TRUE(root);
    EXPECT_FALSE(root->remote()) << "the name root finds the local root";
    EXPECT_FALSE(root->homeId());
}

}
