#pragma once

#include "ops/Actor.hpp"
#include "db/model/ListQueryParams.hpp"
#include "rbac/Fwd.hpp"
// Vault-role overrides are returned by value: callers need the complete type (libc++ refuses a vector of an
// incomplete one).
#include "rbac/permission/Override.hpp"

#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <variant>
#include <vector>

// Role and permission mutation shared by `vh role ...` / `vh vault role ...` and the ws role.* commands.
// Every permission change, from either surface, goes through one representation (PermissionEdit) and one
// resolver mechanism (PermissionResolver::applyChanges), so a permission is either applied or refused, never
// silently dropped. Rules that used to live in protocols/RoleGuards (reserved super_admin, own-role and
// in-use protection) live here, plus the escalation ceiling: nobody grants an admin permission they do not hold.
namespace vh::ops::roles {

using AdminRolePtr = std::shared_ptr<rbac::role::Admin>;
using VaultRolePtr = std::shared_ptr<rbac::role::Vault>;

// A role as the caller named it: by id, or by its unique name.
using Ref = std::variant<unsigned int, std::string>;

inline constexpr std::string_view kSuperAdminRoleName = "super_admin";

// Named permission changes: qualified permission name (admin.identities.users.view) -> grant (true) / revoke
// (false). A delta (CLI --allow-*/--deny-*) changes only what it names; `complete` marks a full snapshot (the
// web's role forms send every permission) and requires a value for each one.
struct PermissionEdit {
    std::vector<std::pair<std::string, bool>> changes{};
    bool complete = false;
};

struct CreateRole {
    std::string name;
    std::string description{};
    std::optional<Ref> from{};       // start from this role's permissions instead of an empty role
    PermissionEdit permissions{};
};

// Patch semantics: an empty optional leaves the field unchanged.
struct UpdateRole {
    Ref role;
    std::optional<std::string> name{};
    std::optional<std::string> description{};
    PermissionEdit permissions{};
};

// `auditSource` labels security notifications ("shell", "websocket"); it never affects a decision.
[[nodiscard]] AdminRolePtr createAdminRole(const Actor& actor, const CreateRole& req, std::string_view auditSource);
[[nodiscard]] AdminRolePtr updateAdminRole(const Actor& actor, const UpdateRole& req, std::string_view auditSource);
AdminRolePtr removeAdminRole(const Actor& actor, const Ref& role, std::string_view auditSource);
[[nodiscard]] AdminRolePtr getAdminRole(const Actor& actor, const Ref& role);
[[nodiscard]] std::vector<AdminRolePtr> listAdminRoles(const Actor& actor, db::model::ListQueryParams params = {});

[[nodiscard]] VaultRolePtr createVaultRole(const Actor& actor, const CreateRole& req);
[[nodiscard]] VaultRolePtr updateVaultRole(const Actor& actor, const UpdateRole& req);
VaultRolePtr removeVaultRole(const Actor& actor, const Ref& role);
[[nodiscard]] VaultRolePtr getVaultRole(const Actor& actor, const Ref& role);
[[nodiscard]] std::vector<VaultRolePtr> listVaultRoles(const Actor& actor, db::model::ListQueryParams params = {});

// Why `actor` may not hold or hand out `role`: the admin permissions `role` grants that `actor` lacks (empty when
// allowed). Used for admin-role assignment to users as well as role edits.
[[nodiscard]] std::vector<std::string> permissionsBeyondActor(const Actor& actor, const rbac::role::Admin& role);

// ---- vault role assignments ----

struct Subject {
    std::string type;   // "user" or "group"
    unsigned int id = 0;
};

struct VaultSubject {
    unsigned int vault_id = 0;
    Subject subject;
};

struct AssignVaultRole {
    VaultSubject target;
    Ref role;
};

// Returns the assignment (the vault role with assignment info).
VaultRolePtr assignVaultRole(const Actor& actor, const AssignVaultRole& req);
// Returns the assignment that was removed; NotFound when nothing is assigned.
VaultRolePtr unassignVaultRole(const Actor& actor, const VaultSubject& target);
// Assignments on one vault, or on every vault the actor may view role assignments for.
[[nodiscard]] std::vector<VaultRolePtr> listVaultRoleAssignments(const Actor& actor, std::optional<unsigned int> vaultId);

// ---- per-assignment permission overrides (path-scoped allow/deny on top of the assigned vault role) ----

struct AddOverrides {
    VaultSubject target;
    PermissionEdit permissions;      // grant = allow override, revoke = deny override
    std::string pattern;             // glob the overrides apply to
    bool enabled = true;
};

struct UpdateOverride {
    VaultSubject target;
    unsigned int override_id = 0;
    std::optional<bool> allow{};
    std::optional<std::string> pattern{};
    std::optional<bool> enabled{};
};

std::vector<rbac::permission::Override> addVaultRoleOverrides(const Actor& actor, const AddOverrides& req);
rbac::permission::Override updateVaultRoleOverride(const Actor& actor, const UpdateOverride& req);
void removeVaultRoleOverride(const Actor& actor, const VaultSubject& target, unsigned int overrideId);
[[nodiscard]] std::vector<rbac::permission::Override> listVaultRoleOverrides(const Actor& actor, const VaultSubject& target);

}
