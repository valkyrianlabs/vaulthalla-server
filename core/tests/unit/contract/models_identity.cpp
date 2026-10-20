// Contract models: identity serializers (users and their projections, groups, admin and vault roles, permissions,
// overrides) against their declared shapes (see model_suites.hpp). DB-free: detached users and groups, built-in
// roles, through the real serializers.

#include "model_suites.hpp"

#include "identities/Group.hpp"
#include "identities/User.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "rbac/permission/Override.hpp"
#include "rbac/permission/Permission.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"

#include <memory>
#include <vector>

namespace vh::test_contract_models_identity {

using json = nlohmann::json;

constexpr std::time_t kT0 = 1792483200;

std::shared_ptr<rbac::role::Admin> adminRole(const std::optional<uint32_t> userId) {
    auto role = std::make_shared<rbac::role::Admin>(rbac::role::Admin::OrgAdmin(userId));
    role->id = 2;
    role->name = "org_admin";
    role->description = "Organization administrator";
    role->created_at = kT0;
    role->updated_at = kT0 + 10;
    if (userId) role->assigned_at = kT0 + 20;
    return role;
}

std::shared_ptr<rbac::role::Vault> vaultRole(const bool assigned) {
    auto role = std::make_shared<rbac::role::Vault>(rbac::role::Vault::Editor());
    role->id = 4;
    role->name = "editor";
    role->description = "Read and write files";
    role->created_at = kT0;
    role->updated_at = kT0 + 10;
    if (assigned) {
        role->assigned_at = kT0 + 30;
        role->assign(7, "user", 3);
    }
    return role;
}

identities::UserState userState(const bool full) {
    identities::UserState s;
    s.name = full ? "alice" : "bob";
    s.meta.created_at = kT0;
    s.meta.updated_at = kT0 + 5;
    s.roles.admin = adminRole(full ? std::optional<uint32_t>(7) : std::nullopt);
    if (full) {
        s.email = "alice@example.com";
        s.isProtected = true;
        s.meta.linux_uid = 2900000007;
        s.meta.created_by = 1;
        s.meta.updated_by = 1;
        s.meta.last_login = kT0 + 100;
        s.meta.password_changed_at = kT0 + 50;
        s.meta.deactivated_at = kT0 + 200;
        s.roles.vaults.emplace(3, vaultRole(true));
    }
    return s;
}

}

namespace vh::test::contract_models {

void checkIdentityModels(Checker& c) {
    using namespace test_contract_models_identity;

    // Permission: a catalog row (id set, no value) and a role's exported permissions (value set) below.
    rbac::permission::Permission catalog(3, "admin.identities.users.view", "View users");
    catalog.id = 11;
    c.check(json(catalog), "Permission", "catalog permission (permission.get)");

    // AdminRole: bound to an account, and a definition (user_id null).
    c.check(json(*adminRole(7)), "AdminRole", "admin role assigned to user 7");
    c.check(json(*adminRole(std::nullopt)), "AdminRole", "admin role definition");

    // VaultRole: an assignment and a definition.
    c.check(json(*vaultRole(true)), "VaultRole", "vault role assigned to user 7 on vault 3");
    c.check(json(*vaultRole(false)), "VaultRole", "vault role definition");

    // PermissionOverride.
    rbac::permission::Override deny;
    deny.id = 21;
    deny.assignment_id = 8;
    deny.permission = catalog;
    deny.effect = rbac::permission::OverrideOpt::DENY;
    deny.enabled = false;
    deny.pattern = rbac::fs::glob::model::Pattern::make("/docs/**");
    c.check(json(deny), "PermissionOverride", "deny override");

    // Users: full (every optional, a vault role) and bare (no email, no vault roles: vault_roles is {}).
    const auto alice = identities::User::detached(7, userState(true));
    const auto bob = identities::User::detached(8, userState(false));
    c.check(json(*alice), "User", "full user");
    c.check(json(*bob), "User", "user without email or vault roles");
    c.check(protocols::ws::handler::Auth::sessionUser(*alice), "SessionUser", "session user with a vault role");
    c.check(protocols::ws::handler::Auth::sessionUser(*bob), "SessionUser", "session user without vault roles");
    c.check(identities::to_public_json(alice), "PublicUser", "public user");
    c.check(identities::to_public_json(bob), "PublicUser", "public user without email");

    // UserSummary (to_list_json): a user without an admin role has admin_role null.
    auto noAdmin = userState(false);
    noAdmin.name = "carol";
    noAdmin.roles.admin.reset();
    const auto carol = identities::User::detached(9, std::move(noAdmin));
    for (const auto& row : identities::to_list_json({alice, bob, carol})) c.check(row, "UserSummary", "user list row");

    // Group with a member (gid and updated_at set), a bare group, and a member whose account no longer resolves.
    identities::GroupState gs;
    gs.name = "engineering";
    gs.description = "Engineers";
    gs.linux_gid = 2900000100;
    gs.created_at = kT0;
    gs.updated_at = kT0 + 40;
    const auto group = identities::Group::detached(12, std::move(gs));
    const std::vector<identities::GroupMember> members{{.user = alice, .joined_at = kT0 + 60},
                                                       {.user = nullptr, .joined_at = kT0 + 70}};
    c.check(identities::to_json(*group, &members), "Group", "group with members");
    identities::GroupState bare;
    bare.name = "empty";
    bare.created_at = kT0;
    c.check(identities::to_json(*identities::Group::detached(13, std::move(bare))), "Group", "group without members");
}

}
