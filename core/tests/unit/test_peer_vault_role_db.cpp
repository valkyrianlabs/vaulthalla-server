// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// A linked server's vault role (server mirror phase 2, wave 2; design/peers/identity.md "Decided and given";
// migration 162). On the core: the precedence (per-vault over the link's default, implicit_deny as "no access", none
// otherwise, nothing for an unlinked server, nothing from any account's rows), the resolver the next waves call
// (rbac::resolver::PeerVault), and who may manage it (the switch, a person, the vault-role assignment right, audit
// lines naming the server). On the mirror: a vault held as another server's copy resolves from its core's grant
// alone (rbac::mirrored): exactly the grant for this server's super admins, nothing for anyone else whatever local
// rows say, nothing without a grant, and ordinary resolution back the moment the mirror_vault row goes.

#include "../helpers/db_suite.hpp"
#include "../helpers/identities.hpp"
#include "audit/Trail.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/helpers.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/PeerPolicy.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/PeerPolicy.hpp"
#include "mirror/access/Access.hpp"
#include "rbac/Mirrored.hpp"
#include "rbac/PolicyEpoch.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/permission/admin/Vaults.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/permission/vault/Roles.hpp"
#include "rbac/permission/vault/sync/Action.hpp"
#include "rbac/resolver/PeerVault.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Global.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <functional>
#include <string>
#include <vector>

namespace vh::test_peer_vault_role_db {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using Action = rbac::permission::vault::FilesystemAction;
using RolePerm = rbac::permission::vault::RolePermissions;
using SyncActionPerm = rbac::permission::vault::sync::SyncActionPermissions;
using AdminVaultPerm = rbac::permission::admin::VaultPermissions;
using Source = rbac::resolver::PeerVaultRole::Source;
using rbac::resolver::PeerVault;
namespace dc = vh::device::crypto;
namespace mirror = db::query::mirror;

std::string tag() {
    static std::atomic<unsigned> n{0};
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000) + "r" +
           std::to_string(n.fetch_add(1));
}

class PeerVaultRoleDb : public vh::test::db::Suite {
protected:
    inline static UserPtr super;
    inline static UserPtr plainOwner;
    inline static UserPtr plainMember;
    inline static UserPtr roleHolder;
    inline static UserPtr selfOwner;  // its own vaults through its global vault policy (and admin.vaults.self.*)

    static void SetUpTestSuite() {
        if (!setUpDbSuite("peer_vault_role")) return;
        super = identities::manager().user(
            test::identities::createUser("pv_super_" + tag(), db::query::rbac::role::Admin::get("super_admin"),
                                         std::nullopt, "x", std::nullopt)->id);
        plainOwner = account("pv_owner", "unprivileged");
        plainMember = account("pv_member", "unprivileged");
        roleHolder = account("pv_holder", "unprivileged");
        selfOwner = policyAccount("pv_selfowner", rbac::role::vault::Base::Full(), true, false, false,
                                  {"admin.vaults.self.view", "admin.vaults.self.edit"});
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        rbac::mirrored::resetForTesting();
        vh::mirror::access::resetForTesting();
        tearDownDbSuite();
    }

    static UserPtr account(const std::string& prefix, const std::string& role) {
        const auto created = ops::users::create(super, {.name = prefix + "_" + tag(), .role = role,
                                                        .password = std::string("Peer-Vault-Role-Pass-123")});
        return identities::manager().user(created.user->id);
    }

    // An account on a custom admin role whose global vault policy grants `base` in the scopes named (the rest none).
    static UserPtr policyAccount(const std::string& prefix, const rbac::role::vault::Base& base, const bool self,
                                 const bool admin, const bool user, const std::vector<std::string>& adminPerms = {}) {
        using Scope = rbac::role::vault::Global::Scope;
        ops::roles::CreateRole req{.name = prefix + "_role_" + tag()};
        for (const auto& perm : adminPerms) req.permissions.changes.emplace_back(perm, true);
        const auto role = ops::roles::createAdminRole(super, req, "test");
        const auto a = account(prefix, role->name);
        const auto none = rbac::role::vault::Base::None();
        const auto globals = rbac::permission::admin::VaultGlobals::Custom(
            rbac::role::vault::Global::Custom(a->id, Scope::Self, self ? base : none),
            rbac::role::vault::Global::Custom(a->id, Scope::Admin, admin ? base : none),
            rbac::role::vault::Global::Custom(a->id, Scope::User, user ? base : none));
        db::Transactions::exec("peer_vault_role::policy", [&](pqxx::work& txn) {
            db::query::identities::upsertGlobalVRoles(txn, globals, a->id);
        });
        (void)identities::manager().reconcile();
        return identities::manager().user(a->id);
    }

    static vh::peer::Record newPeer(const std::string& name = "vps") {
        const auto t = tag();
        const auto spki = dc::sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(t.data()), t.size()));
        return db::query::peer::Peers::insert(
            {.node_id = "node-" + name + "-" + t, .name = name + "-" + t, .spki_sha256 = dc::toHex(spki)});
    }

    // A local vault owned by `owner` with /doc.txt and the folder /dir.
    static unsigned int vaultFor(const UserPtr& owner) {
        const auto id = ops::vaults::create(super, {.name = "pv_vault_" + tag(), .type = vault::model::VaultType::Local,
                                                    .owner_id = owner->id})->id;
        const auto engine = runtime::Deps::get().storageManager->getEngine(id);
        (void)fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/dir"), .engine = engine, .user = super});
        const std::string text = "peer vault role";
        (void)fs::Filesystem::createFile({.path = "/doc.txt", .fuse_path = engine->vaultPathToFusePath("/doc.txt"),
                                          .buffer = std::vector<uint8_t>(text.begin(), text.end()), .engine = engine,
                                          .user = super, .overwrite = true});
        return id;
    }

    static bool fsAllows(const UserPtr& user, const unsigned int vaultId, const Action action, const std::string& path) {
        const rbac::resolver::vault::QuietFilesystemDenials quiet;
        const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
        return rbac::resolver::Vault::has<Action>(
            {.user = user, .permission = action, .vault_id = vaultId, .path = engine->vaultPathToFusePath(path)});
    }

    static bool peerMay(const vh::peer::Record& p, const unsigned int vaultId, const Action action,
                        const std::string& path = "/doc.txt", const bool isDirectory = false) {
        return PeerVault::may(p.id, vaultId, action, path, true, isDirectory);
    }

    static mirror::Grant grantOf(const rbac::role::Vault& role, const std::string& node) {
        return {.role_name = role.name, .files = role.fs.files.toMask(), .directories = role.fs.directories.toMask(),
                .sync = role.sync.toMask(), .roles = role.roles.toMask(), .granted_by_node = node, .granted_at = 0};
    }

    static json lastAudit(const std::string& action) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("peer vault role audit", [&](pqxx::work& txn) {
            const auto res = txn.exec("SELECT details FROM audit_event WHERE action = $1 ORDER BY seq DESC LIMIT 1",
                                      pqxx::params{action});
            return res.empty() ? json() : json::parse(res[0][0].as<std::string>());
        });
    }

    static std::shared_ptr<protocols::ws::Session> deviceSession(const std::string& scope, const bool relayed) {
        auto p = std::make_shared<vh::device::Peer>();
        p->spki.fill(relayed ? 0x41 : 0x42);
        p->spkiHex = dc::toHex(p->spki);
        p->address = "10.0.0.8";
        p->deviceRowId = 11;
        p->relayed = relayed;
        p->scope = scope;
        return protocols::ws::Session::devicePrincipal(std::move(p), super, [] {});
    }

    static std::shared_ptr<protocols::ws::Session> console(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    static void assignPeer(const UserPtr& actor, const unsigned int vaultId, const vh::peer::Record& p,
                           const std::string& role) {
        (void)ops::roles::assignVaultRole(actor, {.target = {.vault_id = vaultId, .subject = {.type = "peer", .id = p.id}},
                                                  .role = role});
    }
};

// ------------------------------------------------------------------------------------------------ the core

TEST_F(PeerVaultRoleDb, APerVaultRoleBeatsTheLinkDefaultNoAccessWinsAndNeitherMeansNone) {
    const auto p = newPeer();
    const auto v = vaultFor(plainOwner);
    (void)mirror::MirrorVaults::startCore(v, p.id);

    auto r = PeerVault::role(p.id, v);
    EXPECT_EQ(r.source, Source::None);
    EXPECT_TRUE(r.linked);
    EXPECT_TRUE(r.mirrored);
    EXPECT_FALSE(r.grantsAnything());
    EXPECT_FALSE(peerMay(p, v, Action::Read)) << "neither a default nor an assignment: nothing";

    (void)ops::peer_policy::set(super, std::to_string(p.id), ops::roles::Ref{std::string("reader")});
    r = PeerVault::role(p.id, v);
    ASSERT_EQ(r.source, Source::LinkDefault);
    ASSERT_TRUE(r.role);
    EXPECT_EQ(r.role->name, "reader") << "told by name";
    EXPECT_TRUE(peerMay(p, v, Action::Read));
    EXPECT_FALSE(peerMay(p, v, Action::Write)) << "the default's permissions, no more";

    assignPeer(super, v, p, "contributor");
    r = PeerVault::role(p.id, v);
    ASSERT_EQ(r.source, Source::Vault);
    EXPECT_EQ(r.role->name, "contributor");
    EXPECT_TRUE(peerMay(p, v, Action::Write)) << "the per-vault role beats the default";

    assignPeer(super, v, p, std::string(rbac::resolver::kPeerNoAccessRole));
    r = PeerVault::role(p.id, v);
    EXPECT_EQ(r.source, Source::Vault);
    EXPECT_TRUE(r.no_access);
    EXPECT_FALSE(r.grantsAnything());
    for (const auto a : {Action::Read, Action::List, Action::Lookup, Action::Write, Action::Delete})
        EXPECT_FALSE(peerMay(p, v, a, a == Action::List ? "/dir" : "/doc.txt", a == Action::List))
            << "no access wins over a default that grants it";

    (void)ops::roles::unassignVaultRole(super, {.vault_id = v, .subject = {.type = "peer", .id = p.id}});
    EXPECT_EQ(PeerVault::role(p.id, v).source, Source::LinkDefault) << "back to the default";
    (void)ops::peer_policy::set(super, std::to_string(p.id), std::nullopt);
    EXPECT_EQ(PeerVault::role(p.id, v).source, Source::None);
    EXPECT_FALSE(peerMay(p, v, Action::Read));
}

TEST_F(PeerVaultRoleDb, TheDefaultAppliesOnlyToVaultsMirroredOverThatLink) {
    const auto p = newPeer();
    const auto other = newPeer("other");
    const auto mirrored = vaultFor(plainOwner);
    const auto notMirrored = vaultFor(plainOwner);
    const auto withOther = vaultFor(plainOwner);
    (void)mirror::MirrorVaults::startCore(mirrored, p.id);
    (void)mirror::MirrorVaults::startCore(withOther, other.id);
    (void)ops::peer_policy::set(super, p.node_id, ops::roles::Ref{std::string("editor")});

    EXPECT_TRUE(peerMay(p, mirrored, Action::Write));
    EXPECT_FALSE(PeerVault::role(p.id, notMirrored).mirrored);
    EXPECT_FALSE(peerMay(p, notMirrored, Action::Read)) << "not mirrored over the link: nothing arrives, nothing allowed";
    EXPECT_FALSE(peerMay(p, withOther, Action::Read)) << "mirrored with another server";
    EXPECT_EQ(PeerVault::role(p.id, notMirrored).source, Source::LinkDefault)
        << "what it would hold, for an offer to name";
}

TEST_F(PeerVaultRoleDb, AnUnlinkedOrUnknownServerHoldsNothingWhateverRowsRemain) {
    const auto p = newPeer();
    const auto v = vaultFor(plainOwner);
    (void)mirror::MirrorVaults::startCore(v, p.id);
    (void)ops::peer_policy::set(super, std::to_string(p.id), ops::roles::Ref{std::string("power_user")});
    assignPeer(super, v, p, "power_user");
    ASSERT_TRUE(peerMay(p, v, Action::Delete));

    ASSERT_TRUE(db::query::peer::Peers::revoke(p.id));
    const auto r = PeerVault::role(p.id, v);
    EXPECT_FALSE(r.linked);
    EXPECT_EQ(r.source, Source::None);
    EXPECT_FALSE(r.grantsAnything());
    EXPECT_FALSE(peerMay(p, v, Action::Read)) << "revoked: nothing, though both rows are still there";
    EXPECT_FALSE(PeerVault::role(999999, v).linked);
    EXPECT_FALSE(PeerVault::may(999999, v, Action::Read, "/doc.txt", true, false));
    EXPECT_THROW(assignPeer(super, v, p, "reader"), ops::Conflict) << "a revoked server is not assigned anything";
    EXPECT_THROW((void)ops::peer_policy::set(super, std::to_string(p.id), std::nullopt), ops::Conflict);
}

TEST_F(PeerVaultRoleDb, ALinkedServerGainsNothingFromAnAccountsOrAGroupsRows) {
    const auto p = newPeer();
    const auto v = vaultFor(plainOwner);
    (void)mirror::MirrorVaults::startCore(v, p.id);
    const auto full = db::query::rbac::role::Vault::get("power_user");
    ASSERT_TRUE(full);
    // Rows of every other subject kind under the peer's own number: a user, a group (no account or group need exist
    // for the row: subject_id has no foreign key).
    db::Transactions::exec("peer_vault_role::others", [&](pqxx::work& txn) {
        for (const auto* type : {"user", "group"})
            txn.exec("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) VALUES ($1, $2, $3, $4) "
                     "ON CONFLICT DO NOTHING",
                     pqxx::params{v, std::string(type), p.id, full->id});
    });
    const auto r = PeerVault::role(p.id, v);
    EXPECT_EQ(r.source, Source::None);
    for (const auto a : {Action::Read, Action::Write, Action::Delete}) EXPECT_FALSE(peerMay(p, v, a));
    // An account that is a super admin, the vault's owner or holds a role is still nothing to the peer.
    assignPeer(super, v, p, "reader");
    EXPECT_FALSE(peerMay(p, v, Action::Write)) << "only its own row";
}

TEST_F(PeerVaultRoleDb, AnAssignmentNamesALinkedServerAndTakesNoPathOverride) {
    const auto v = vaultFor(plainOwner);
    const auto reader = db::query::rbac::role::Vault::get("reader");
    EXPECT_THROW(db::Transactions::exec("peer_vault_role::ghost", [&](pqxx::work& txn) {
                     txn.exec("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) "
                              "VALUES ($1, 'peer', 987654, $2)",
                              pqxx::params{v, reader->id});
                 }),
                 std::exception)
        << "migration 162: a peer assignment names a peer row";
    EXPECT_THROW((void)ops::roles::assignVaultRole(
                     super, {.target = {.vault_id = v, .subject = {.type = "peer", .id = 987654}}, .role = "reader"}),
                 ops::NotFound);

    const auto p = newPeer();
    assignPeer(super, v, p, "reader");
    EXPECT_THROW((void)ops::roles::addVaultRoleOverrides(
                     super, {.target = {.vault_id = v, .subject = {.type = "peer", .id = p.id}},
                             .permissions = {.changes = {{"vault.fs.files.download", true}}}, .pattern = "/**"}),
                 ops::Invalid);
    db::Transactions::exec("peer_vault_role::override", [&](pqxx::work& txn) {
        const auto a = txn.exec("SELECT id FROM vault_role_assignments WHERE vault_id = $1 AND subject_type = 'peer'",
                                pqxx::params{v}).one_field_ref().as<int>();
        const auto perm = txn.exec("SELECT id FROM permission ORDER BY id LIMIT 1").one_field_ref().as<int>();
        pqxx::subtransaction sub(txn, "peer_override");
        EXPECT_THROW(sub.exec("INSERT INTO vault_permission_overrides (assignment_id, permission_id, glob_path, effect) "
                              "VALUES ($1, $2, '/**', 'allow')",
                              pqxx::params{a, perm}),
                     pqxx::sql_error)
            << "migration 162 refuses it too";
        sub.abort();
    });
}

TEST_F(PeerVaultRoleDb, ThePeerAssignmentIsListedAsSuchAndAuditedNamingTheServer) {
    const auto p = newPeer();
    const auto v = vaultFor(plainOwner);
    assignPeer(super, v, p, "reader");
    const auto audited = lastAudit("rbac.vault_role.assign");
    EXPECT_EQ(audited.at("subject").at("type"), "peer");
    EXPECT_EQ(audited.at("subject").at("id"), p.id);
    EXPECT_EQ(audited.value("node_id", ""), p.node_id);

    const auto listed = ops::roles::listVaultRoleAssignments(super, v);
    const auto it = std::ranges::find_if(listed, [](const auto& r) {
        return r->assignment && r->assignment->subject_type == "peer";
    });
    ASSERT_NE(it, listed.end());
    const json j = **it;
    EXPECT_EQ(j.at("name"), "reader");
    EXPECT_EQ(j.at("assignment").at("subject_name"), p.name);
    EXPECT_EQ(j.at("assignment").at("subject_node_id"), p.node_id);
    EXPECT_EQ(j.at("assignment").at("subject_revoked"), false);
    EXPECT_FALSE(j.at("assignment").contains("in_effect")) << "the core's rows are in effect: no annotation";

    const auto all = ops::roles::listVaultRoleAssignments(super, std::nullopt);
    EXPECT_TRUE(std::ranges::any_of(all, [&](const auto& r) {
        return r->assignment && r->assignment->subject_type == "peer" && r->assignment->subject_node_id == p.node_id;
    }));

    (void)ops::roles::unassignVaultRole(super, {.vault_id = v, .subject = {.type = "peer", .id = p.id}});
    EXPECT_EQ(lastAudit("rbac.vault_role.unassign").value("node_id", ""), p.node_id);

    (void)ops::peer_policy::set(super, p.name, ops::roles::Ref{std::string("reader")});
    const auto policyAudit = lastAudit("peer.policy.set");
    EXPECT_EQ(policyAudit.at("peer"), p.id);
    EXPECT_EQ(policyAudit.at("node_id"), p.node_id);
    EXPECT_EQ(policyAudit.at("previous_role_id"), nullptr);
    const auto reader = db::query::rbac::role::Vault::get("reader");
    EXPECT_EQ(policyAudit.at("role_id"), reader->id);
    EXPECT_THROW((void)ops::roles::removeVaultRole(super, reader->id), ops::Conflict) << "a link's default is in use";
    (void)ops::peer_policy::set(super, p.name, std::nullopt);
}

// ------------------------------------------------------------------------------------------------ who may

TEST_F(PeerVaultRoleDb, APersonDecidesNeverAnAgentAScopedOrARelayedDevice) {
    namespace stepup = auth::stepup;
    const auto p = newPeer();
    const auto v = vaultFor(plainOwner);
    const auto expectForbidden = [&](const char* what) {
        for (const auto& fn : std::vector<std::function<void()>>{
                 [&] { (void)ops::peer_policy::get(super, std::to_string(p.id)); },
                 [&] { (void)ops::peer_policy::set(super, std::to_string(p.id), std::nullopt); },
                 [&] { assignPeer(super, v, p, "reader"); }}) {
            try {
                fn();
                ADD_FAILURE() << what << " decided for a linked server";
            } catch (const ops::Refused& e) {
                EXPECT_EQ(e.code, "peer_forbidden") << what;
            }
        }
    };
    {
        const stepup::Scope agent(stepup::Channel::Agent);
        expectForbidden("an agent");
    }
    const auto scoped = deviceSession("write", false);
    {
        const stepup::Scope scope(scoped);
        expectForbidden("a scoped device");
    }
    const auto relayed = deviceSession("destructive", true);
    {
        const stepup::Scope scope(relayed);
        expectForbidden("a relayed device");
    }
    const auto desktop = deviceSession("destructive", false);
    {
        const stepup::Scope scope(desktop);
        EXPECT_NO_THROW((void)ops::peer_policy::get(super, std::to_string(p.id)))
            << "a full-access Desktop connected directly: a person's channel";
        // A vault role assignment from a device asks a person's approval (identity.admin), as for a user or a group:
        // past the linked-server gate, not refused by it.
        EXPECT_THROW(assignPeer(super, v, p, "reader"), ops::StepUpRequired);
    }
    {
        const stepup::Scope host(stepup::Channel::Host);
        EXPECT_NO_THROW((void)ops::peer_policy::set(super, std::to_string(p.id), ops::roles::Ref{std::string("guest")}));
    }
    scoped->close();
    relayed->close();
    desktop->close();
}

TEST_F(PeerVaultRoleDb, ManagingItTakesTheVaultRoleAssignmentRightAndTheDefaultTakesItEverywhere) {
    const auto p = newPeer();
    const auto own = policyAccount("pv_selfmgr", rbac::role::vault::Base::Full(), true, false, false);
    const auto everywhere = policyAccount("pv_allmgr", rbac::role::vault::Base::Full(), true, true, true);
    const auto ownVault = vaultFor(own);
    const auto othersVault = vaultFor(plainOwner);

    // Per vault: the same right as for a user or a group (vault.roles.assign in the vault's scope).
    EXPECT_NO_THROW(assignPeer(own, ownVault, p, "reader")) << "roles.assign on its own vaults";
    EXPECT_THROW(assignPeer(own, othersVault, p, "reader"), ops::Denied) << "not on another account's";
    EXPECT_THROW(assignPeer(plainMember, othersVault, p, "reader"), ops::Denied);
    EXPECT_NO_THROW(assignPeer(everywhere, othersVault, p, "reader"));

    // The link's default reaches every vault mirrored over the link: the right in every scope.
    EXPECT_THROW((void)ops::peer_policy::set(own, std::to_string(p.id), std::nullopt), ops::Denied);
    EXPECT_THROW((void)ops::peer_policy::get(plainMember, std::to_string(p.id)), ops::Denied);
    EXPECT_NO_THROW((void)ops::peer_policy::set(everywhere, std::to_string(p.id), ops::roles::Ref{std::string("reader")}));
    const auto seen = ops::peer_policy::get(everywhere, std::to_string(p.id));
    ASSERT_TRUE(seen.role);
    EXPECT_EQ(seen.role->name, "reader");
    EXPECT_EQ(seen.set_by, everywhere->id);
    EXPECT_EQ(seen.set_by_name, everywhere->name());
    EXPECT_TRUE(seen.set_at.has_value());
    EXPECT_THROW((void)ops::peer_policy::set(super, std::to_string(p.id),
                                             ops::roles::Ref{std::string(rbac::resolver::kPeerNoAccessRole)}),
                 ops::Invalid)
        << "no access is a per-vault override";
    EXPECT_THROW((void)ops::peer_policy::set(super, std::to_string(p.id), ops::roles::Ref{std::string("no_such_role")}),
                 ops::NotFound);
    EXPECT_THROW((void)ops::peer_policy::get(super, "no-such-server"), ops::NotFound);
}

// In the console, setting either role is an identity.admin step-up (as every vault role assignment is); checks first.
TEST_F(PeerVaultRoleDb, SettingItInTheConsoleIsAnIdentityAdminStepUp) {
    namespace stepup = auth::stepup;
    const auto p = newPeer();
    const auto v = vaultFor(plainOwner);
    auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = super;
    web->tokens->refreshToken = std::make_shared<auth::model::RefreshToken>();
    web->tokens->refreshToken->jti = "peer-policy-jti-" + tag();
    web->tokens->refreshToken->aal = 1;
    web->tokens->refreshToken->amr = {"pwd"};
    web->tokens->refreshToken->authTime = std::chrono::system_clock::now() - std::chrono::hours(1);
    const stepup::Scope scope(web);
    for (const auto& fn : std::vector<std::function<void()>>{
             [&] { (void)ops::peer_policy::set(super, std::to_string(p.id), ops::roles::Ref{std::string("reader")}); },
             [&] { assignPeer(super, v, p, "reader"); }}) {
        try {
            fn();
            ADD_FAILURE() << "the console set a linked server's role without a step-up";
        } catch (const ops::StepUpRequired& e) {
            EXPECT_EQ(e.family, "identity.admin");
        }
    }
    EXPECT_FALSE(ops::peer_policy::get(super, std::to_string(p.id)).set_at) << "nothing was written";
    EXPECT_THROW((void)ops::peer_policy::set(super, std::to_string(p.id),
                                             ops::roles::Ref{std::string(rbac::resolver::kPeerNoAccessRole)}),
                 ops::Invalid)
        << "the checks come before the step-up";
}

TEST_F(PeerVaultRoleDb, TheWsCommandsAnswerThePolicyShape) {
    namespace handler = protocols::ws::handler;
    const auto p = newPeer();
    auto out = handler::PeerPolicy::set(json{{"peer", std::to_string(p.id)}, {"role", "contributor"}}, console(super));
    EXPECT_EQ(out.at("policy").at("peer").at("node_id"), p.node_id);
    EXPECT_EQ(out.at("policy").at("role").at("name"), "contributor");
    EXPECT_TRUE(out.at("policy").at("role").at("permissions").is_array()) << "by name, with its actual permissions";
    EXPECT_FALSE(out.at("policy").at("role").contains("assignment"));
    EXPECT_EQ(out.at("policy").at("set_by"), super->id);

    out = handler::PeerPolicy::get(json{{"peer", p.name}}, console(super));
    EXPECT_EQ(out.at("policy").at("role").at("name"), "contributor");
    out = handler::PeerPolicy::set(json{{"peer", p.node_id}, {"role", nullptr}}, console(super));
    EXPECT_TRUE(out.at("policy").at("role").is_null());
    EXPECT_THROW((void)handler::PeerPolicy::set(json{{"peer", p.node_id}}, console(super)), ops::Invalid);
    EXPECT_THROW((void)handler::PeerPolicy::set(json{{"peer", p.node_id}, {"role", true}}, console(super)), ops::Invalid);
    EXPECT_THROW((void)handler::PeerPolicy::get(json::object(), console(super)), ops::Invalid);
}

// ------------------------------------------------------------------------------------------------ the mirror

TEST_F(PeerVaultRoleDb, OnAMirroredVaultASuperAdminGetsExactlyTheGrantAndNobodyElseAnything) {
    const auto core = newPeer("core");
    const auto group = test::identities::createGroup("pv_group_" + tag());
    identities::manager().addMembers(group->id, {plainMember->id});
    const auto globalHolder = policyAccount("pv_global", rbac::role::vault::Base::Full(), true, true, true);
    const auto v = vaultFor(selfOwner);
    // Every local source, before the vault becomes a mirror (afterwards the access list can't be edited here).
    (void)ops::roles::assignVaultRole(super, {.target = {.vault_id = v, .subject = {.type = "user", .id = roleHolder->id}},
                                              .role = "power_user"});
    (void)ops::roles::assignVaultRole(super, {.target = {.vault_id = v, .subject = {.type = "group", .id = group->id}},
                                              .role = "power_user"});
    for (const auto& u : {roleHolder, plainMember, globalHolder, selfOwner})
        ASSERT_TRUE(fsAllows(u, v, Action::Read, "/doc.txt")) << u->name() << " reads it before it is a mirror";
    ASSERT_TRUE(fsAllows(super, v, Action::Write, "/doc.txt"));

    const auto epoch = rbac::policyEpoch();
    (void)mirror::MirrorVaults::startMirror(v, core.id);
    EXPECT_GT(rbac::policyEpoch(), epoch) << "authorization caches miss after the change";
    ASSERT_TRUE(rbac::mirrored::find(v)) << "published before startMirror returned";

    // No grant recorded: nobody, super admins included.
    for (const auto& u : {super, roleHolder, plainMember, globalHolder, selfOwner}) {
        EXPECT_FALSE(fsAllows(u, v, Action::Read, "/doc.txt")) << u->name();
        EXPECT_FALSE(fsAllows(u, v, Action::List, "/")) << u->name();
    }

    ASSERT_TRUE(mirror::MirrorVaults::recordGrant(v, grantOf(rbac::role::Vault::Reader(), core.node_id)));
    const auto held = rbac::mirrored::find(v);
    ASSERT_TRUE(held && held->grant);
    EXPECT_EQ(held->grant->role_name, "reader");
    EXPECT_EQ(held->grant->granted_by_node, core.node_id);

    EXPECT_TRUE(fsAllows(super, v, Action::Read, "/doc.txt")) << "the grant, for a super admin";
    EXPECT_TRUE(fsAllows(super, v, Action::List, "/"));
    EXPECT_TRUE(fsAllows(super, v, Action::List, "/dir"));
    EXPECT_FALSE(fsAllows(super, v, Action::Write, "/new.txt")) << "outside the grant: refused, even a super admin";
    EXPECT_FALSE(fsAllows(super, v, Action::Delete, "/doc.txt"));
    EXPECT_FALSE(fsAllows(super, v, Action::Overwrite, "/doc.txt"));
    EXPECT_FALSE(rbac::resolver::Vault::has<SyncActionPerm>(
        {.user = super, .permission = SyncActionPerm::Trigger, .vault_id = v}))
        << "the reader role triggers no sync";
    EXPECT_FALSE(rbac::resolver::Vault::has<RolePerm>({.user = super, .permission = RolePerm::Assign, .vault_id = v}));
    for (const auto& u : {roleHolder, plainMember, globalHolder, selfOwner}) {
        EXPECT_FALSE(fsAllows(u, v, Action::Read, "/doc.txt"))
            << u->name() << ": a local role, a group's, a global vault policy or ownership: nothing";
        EXPECT_FALSE(fsAllows(u, v, Action::List, "/")) << u->name();
    }

    // admin.vaults.*: no admin role's vault powers; a super admin still sees it, never edits or removes it here.
    const auto adminHas = [&](const UserPtr& u, const AdminVaultPerm perm) {
        return rbac::resolver::Admin::has<AdminVaultPerm>({.user = u, .permission = perm, .vault_id = v});
    };
    EXPECT_TRUE(adminHas(super, AdminVaultPerm::View));
    EXPECT_TRUE(adminHas(super, AdminVaultPerm::ViewStats));
    EXPECT_FALSE(adminHas(super, AdminVaultPerm::Edit));
    EXPECT_FALSE(adminHas(super, AdminVaultPerm::Remove));
    EXPECT_FALSE(adminHas(selfOwner, AdminVaultPerm::View)) << "ownership is no way in";
    EXPECT_FALSE(adminHas(globalHolder, AdminVaultPerm::View));

    // The accessible list: a super admin, as one; nobody else.
    const auto listedFor = [&](const UserPtr& u) {
        const auto list = ops::vaults::listAccessible(u);
        const auto it = std::ranges::find_if(list, [&](const auto& e) { return e.vault && e.vault->id == v; });
        return it == list.end() ? std::optional<ops::vaults::AccessibleVault>{} : std::optional(*it);
    };
    const auto superRow = listedFor(super);
    ASSERT_TRUE(superRow);
    EXPECT_TRUE(superRow->browse);
    EXPECT_EQ(superRow->via, std::vector{ops::vaults::AccessVia::SuperAdmin});
    for (const auto& u : {roleHolder, plainMember, globalHolder, selfOwner}) EXPECT_FALSE(listedFor(u)) << u->name();

    // A wider grant widens exactly that much; clearing it leaves nobody.
    ASSERT_TRUE(mirror::MirrorVaults::recordGrant(v, grantOf(rbac::role::Vault::Contributor(), core.node_id)));
    EXPECT_TRUE(fsAllows(super, v, Action::Write, "/new.txt"));
    EXPECT_FALSE(fsAllows(roleHolder, v, Action::Read, "/doc.txt"));
    ASSERT_TRUE(mirror::MirrorVaults::clearGrant(v));
    EXPECT_FALSE(fsAllows(super, v, Action::Read, "/doc.txt"));

    // The row goes: ordinary resolution, at once.
    ASSERT_TRUE(mirror::MirrorVaults::recordGrant(v, grantOf(rbac::role::Vault::Reader(), core.node_id)));
    ASSERT_TRUE(mirror::MirrorVaults::remove(v));
    EXPECT_FALSE(rbac::mirrored::find(v));
    EXPECT_TRUE(fsAllows(super, v, Action::Write, "/doc.txt")) << "a super admin as always";
    for (const auto& u : {roleHolder, plainMember, globalHolder, selfOwner})
        EXPECT_TRUE(fsAllows(u, v, Action::Read, "/doc.txt")) << u->name() << ": its local source again";
    EXPECT_TRUE(adminHas(super, AdminVaultPerm::Edit));
    EXPECT_TRUE(listedFor(selfOwner));
}

TEST_F(PeerVaultRoleDb, AMirroredVaultsAccessListingShowsTheCoresGrantReadOnly) {
    const auto core = newPeer("core");
    const auto v = vaultFor(selfOwner);
    (void)ops::roles::assignVaultRole(super, {.target = {.vault_id = v, .subject = {.type = "user", .id = roleHolder->id}},
                                              .role = "editor"});
    (void)mirror::MirrorVaults::startMirror(v, core.id);
    ASSERT_TRUE(mirror::MirrorVaults::recordGrant(v, grantOf(rbac::role::Vault::Reader(), core.node_id)));

    const auto listed = ops::roles::listVaultRoleAssignments(super, v);
    ASSERT_EQ(listed.size(), 2u);
    const json grant = *listed.front();
    EXPECT_EQ(grant.at("name"), "reader");
    EXPECT_EQ(grant.at("assignment").at("subject_type"), "server");
    EXPECT_EQ(grant.at("assignment").at("editable"), false);
    EXPECT_EQ(grant.at("assignment").at("in_effect"), true);
    EXPECT_EQ(grant.at("assignment").at("owned_by").at("node_id"), core.node_id);
    EXPECT_EQ(grant.at("assignment").at("owned_by").at("name"), core.name);
    EXPECT_EQ(grant.at("assignment").at("owned_by").at("peer_id"), core.id);
    const json local = *listed.back();
    EXPECT_EQ(local.at("assignment").at("subject_type"), "user");
    EXPECT_EQ(local.at("assignment").at("in_effect"), false) << "a local row does nothing here";

    const auto all = ops::roles::listVaultRoleAssignments(super, std::nullopt);
    EXPECT_EQ(std::ranges::count_if(all, [&](const auto& r) {
                  return r->assignment && r->assignment->subject_type == "server" && r->assignment->vault_id == v;
              }),
              1);
    EXPECT_THROW((void)ops::roles::listVaultRoleAssignments(selfOwner, v), ops::Denied) << "the owner is nobody here";
    EXPECT_FALSE(std::ranges::any_of(ops::roles::listVaultRoleAssignments(roleHolder, std::nullopt), [&](const auto& r) {
        return r->assignment && r->assignment->vault_id == v;
    }));

    // Read-only from every local surface: assignments and overrides refuse, even with a grant that would let a super
    // admin manage roles there.
    ASSERT_TRUE(mirror::MirrorVaults::recordGrant(v, grantOf(rbac::role::Vault::Full(), core.node_id)));
    ASSERT_TRUE(rbac::resolver::Vault::has<RolePerm>({.user = super, .permission = RolePerm::Assign,
                                                       .target_subject_type = std::string("user"),
                                                       .target_subject_id = plainMember->id, .vault_id = v}));
    EXPECT_THROW((void)ops::roles::assignVaultRole(
                     super, {.target = {.vault_id = v, .subject = {.type = "user", .id = plainMember->id}}, .role = "power_user"}),
                 ops::Conflict);
    EXPECT_THROW((void)ops::roles::unassignVaultRole(super, {.vault_id = v, .subject = {.type = "user", .id = roleHolder->id}}),
                 ops::Conflict);
    EXPECT_THROW((void)ops::roles::addVaultRoleOverrides(
                     super, {.target = {.vault_id = v, .subject = {.type = "user", .id = roleHolder->id}},
                             .permissions = {.changes = {{"vault.fs.files.download", true}}}, .pattern = "/**"}),
                 ops::Conflict);
    ASSERT_TRUE(mirror::MirrorVaults::remove(v));
}

TEST_F(PeerVaultRoleDb, AnOutOfBandChangeIsPickedUpAndANonMirroredVaultCostsOneLoad) {
    rbac::mirrored::resetForTesting();
    EXPECT_FALSE(rbac::mirrored::any()) << "nothing held: the resolvers' first and only question";
    const auto core = newPeer("core");
    const auto v = vaultFor(selfOwner);
    const auto other = vaultFor(selfOwner);
    EXPECT_FALSE(rbac::mirrored::reconcile()) << "nothing changed";

    // psql by hand: a mirror row the daemon did not write.
    db::Transactions::exec("peer_vault_role::psql", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role) VALUES ($1, $2, 'mirror')", pqxx::params{v, core.id});
    });
    EXPECT_TRUE(fsAllows(super, v, Action::Read, "/doc.txt")) << "not seen until the watcher's pass";
    EXPECT_TRUE(rbac::mirrored::reconcile());
    EXPECT_TRUE(rbac::mirrored::any());
    EXPECT_FALSE(fsAllows(super, v, Action::Read, "/doc.txt")) << "a mirror with no grant";
    EXPECT_TRUE(fsAllows(super, other, Action::Write, "/doc.txt")) << "another vault resolves as always";
    EXPECT_TRUE(fsAllows(selfOwner, other, Action::Read, "/doc.txt"));
    EXPECT_FALSE(rbac::mirrored::reconcile()) << "the same rows publish nothing";

    // orphaned: still the other server's copy until it is detached.
    db::Transactions::exec("peer_vault_role::orphan", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_vault SET role = 'orphaned' WHERE vault_id = $1", pqxx::params{v});
    });
    EXPECT_TRUE(rbac::mirrored::reconcile());
    EXPECT_FALSE(fsAllows(selfOwner, v, Action::Read, "/doc.txt"));
    // A core row is this server's own vault: ordinary resolution.
    db::Transactions::exec("peer_vault_role::core", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_vault SET role = 'core' WHERE vault_id = $1", pqxx::params{v});
    });
    EXPECT_TRUE(rbac::mirrored::reconcile());
    EXPECT_TRUE(fsAllows(selfOwner, v, Action::Read, "/doc.txt"));
    EXPECT_FALSE(rbac::mirrored::any());
    ASSERT_TRUE(mirror::MirrorVaults::remove(v));
    EXPECT_FALSE(mirror::MirrorVaults::recordGrant(other, grantOf(rbac::role::Vault::Reader(), core.node_id)))
        << "no grant on a vault that is not a mirror here";
}

}
