#include "ops/Roles.hpp"
#include "rbac/PolicyEpoch.hpp"

#include "db/query/identities/Group.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/Permission.hpp"
#include "db/query/rbac/permission/Override.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/rbac/role/admin/Assignments.hpp"
#include "db/query/rbac/role/vault/Assignments.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "notifications/SecurityAlertProducer.hpp"
#include "rbac/fs/glob/Tokenizer.hpp"
#include "rbac/fs/glob/model/Pattern.hpp"
#include "rbac/permission/Override.hpp"
#include "rbac/permission/vault/Roles.hpp"
#include "rbac/resolver/permission/EnumPack.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "vault/model/Vault.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <unordered_map>
#include <string>
#include <utility>

namespace vh::ops::roles {

namespace {
// Authorization caches key on rbac::policyEpoch(); any vault role mutation (successful or not) invalidates them.
struct PolicyEpochBump {
    ~PolicyEpochBump() { rbac::bumpPolicyEpoch(); }
};
}

namespace {

using AdminResolver = rbac::resolver::PermissionResolverEnumPack<std::shared_ptr<rbac::role::Admin>>::type;
using VaultResolver = rbac::resolver::PermissionResolverEnumPack<std::shared_ptr<rbac::role::Vault>>::type;
using AdminRoleQuery = db::query::rbac::role::Admin;
using VaultRoleQuery = db::query::rbac::role::Vault;
using VaultAssignments = db::query::rbac::role::vault::Assignments;
using RolePerm = rbac::permission::vault::RolePermissions;

// The actor's admin role as a mutable copy for the permission resolvers (none unless the actor is authorizing).
std::shared_ptr<rbac::role::Admin> actorAdminRole(const Actor& actor) {
    const auto state = actor->state();
    if (!state->authorizing() || !state->roles.admin) return nullptr;
    return std::make_shared<rbac::role::Admin>(*state->roles.admin);
}

// Which identity an assignment or override write republishes.
identities::Touched touchedBy(const Subject& subject) {
    if (subject.type == "user") return {.users = {subject.id}};
    if (subject.type == "group") return {.groups = {subject.id}};
    return {};
}

std::string describeRef(const Ref& ref) {
    if (const auto* id = std::get_if<unsigned int>(&ref)) return std::to_string(*id);
    return std::get<std::string>(ref);
}

template<class Query>
auto findRole(const Ref& ref) {
    if (const auto* id = std::get_if<unsigned int>(&ref)) {
        if (*id == 0) throw Invalid("role ID must be a positive integer");
        return Query::get(*id);
    }
    return Query::get(std::get<std::string>(ref));
}

AdminRolePtr requireAdminRole(const Ref& ref) {
    auto role = findRole<AdminRoleQuery>(ref);
    if (!role) throw NotFound("admin role not found: " + describeRef(ref));
    return role;
}

VaultRolePtr requireVaultRole(const Ref& ref) {
    auto role = findRole<VaultRoleQuery>(ref);
    if (!role) throw NotFound("vault role not found: " + describeRef(ref));
    return role;
}

void throwProblems(const std::string& what, const std::vector<std::string>& problems) {
    if (problems.empty()) return;
    std::string msg = what + ":";
    for (const auto& p : problems) msg += "\n  - " + p;
    throw Invalid(msg);
}

template<class Resolver, class RolePtr>
void applyEdit(RolePtr& staged, const PermissionEdit& edit) {
    throwProblems("invalid permission changes",
                  Resolver::applyChanges(staged, staged->toPermissions(), edit.changes, edit.complete));
}

void requireName(const std::string& name, const std::string_view kind) {
    if (name.empty()) throw Invalid(std::string(kind) + " role name is required");
}

// The escalation ceiling: `staged` may not grant an admin permission that the actor lacks, unless `baseline`
// (the role as it was) already granted it. Revoking is always allowed.
void requireWithinCeiling(const Actor& actor, const rbac::role::Admin& staged, const rbac::role::Admin* baseline) {
    const auto actorRole = actorAdminRole(actor);
    const auto stagedPtr = std::make_shared<rbac::role::Admin>(staged);
    const auto basePtr = baseline ? std::make_shared<rbac::role::Admin>(*baseline) : nullptr;
    std::vector<std::string> beyond;
    for (const auto& perm : stagedPtr->toPermissions()) {
        if (!AdminResolver::has(stagedPtr, perm)) continue;
        if (basePtr && AdminResolver::has(basePtr, perm)) continue;
        if (!actorRole || !AdminResolver::has(actorRole, perm)) beyond.push_back(perm.qualified_name);
    }
    if (beyond.empty()) return;
    std::string msg = "you cannot grant admin permissions you do not hold:";
    for (const auto& name : beyond) msg += " " + name;
    throw Denied(msg);
}

bool isOwnRole(const Actor& actor, const rbac::role::Admin& role) {
    const auto state = actor->state();
    return state->roles.admin && state->roles.admin->name == role.name;
}

void requireSubjectExists(const Subject& subject) {
    if (subject.type == "user") {
        if (!vh::identities::manager().user(subject.id))
            throw NotFound("user not found: " + std::to_string(subject.id));
    } else if (subject.type == "group") {
        if (!vh::identities::manager().group(subject.id))
            throw NotFound("group not found: " + std::to_string(subject.id));
    } else {
        throw Invalid("subject type must be 'user' or 'group', got '" + subject.type + "'");
    }
}

void requireVaultExists(const unsigned int vaultId) {
    if (!db::query::vault::Vault::getVault(vaultId)) throw NotFound("vault not found: " + std::to_string(vaultId));
}

void requireVaultRolePermission(const Actor& actor, const VaultSubject& target, const RolePerm permission,
                                const std::string& refusal) {
    if (!rbac::resolver::Vault::has<RolePerm>({
            .user = actor,
            .permission = permission,
            .target_subject_type = target.subject.type,
            .target_subject_id = target.subject.id,
            .vault_id = target.vault_id
        })) throw Denied(refusal);
}

VaultRolePtr requireAssignment(const VaultSubject& target) {
    auto assignment = VaultAssignments::get(target.vault_id, target.subject.type, target.subject.id);
    if (!assignment)
        throw NotFound("no vault role is assigned to " + target.subject.type + " " + std::to_string(target.subject.id) +
                       " on vault " + std::to_string(target.vault_id));
    return assignment;
}

}

std::vector<std::string> permissionsBeyondActor(const Actor& actor, const rbac::role::Admin& role) {
    requireActor(actor);
    const auto rolePtr = std::make_shared<rbac::role::Admin>(role);
    const auto actorRole = actorAdminRole(actor);
    std::vector<std::string> beyond;
    for (const auto& perm : rolePtr->toPermissions())
        if (AdminResolver::has(rolePtr, perm) && (!actorRole || !AdminResolver::has(actorRole, perm)))
            beyond.push_back(perm.qualified_name);
    return beyond;
}

// ---------------------------------------------------------------------------------------------------- admin roles

AdminRolePtr createAdminRole(const Actor& actor, const CreateRole& req, const std::string_view auditSource) {
    requireActor(actor);
    if (!actor->adminRolePerms().canAdd()) throw Denied("you do not have permission to create admin roles");

    requireName(req.name, "admin");
    if (req.name == kSuperAdminRoleName || AdminRoleQuery::exists(req.name))
        throw Conflict("admin role already exists: '" + req.name + "'");

    auto staged = req.from ? std::make_shared<rbac::role::Admin>(*requireAdminRole(*req.from))
                           : std::make_shared<rbac::role::Admin>(rbac::role::Admin::None());
    staged->id = 0;
    staged->assignment_id = 0;
    staged->user_id.reset();
    staged->name = req.name;
    staged->description = req.description;
    applyEdit<AdminResolver>(staged, req.permissions);
    requireWithinCeiling(actor, *staged, nullptr);

    unsigned int id = 0;
    try {
        id = AdminRoleQuery::insert(staged);
    } catch (const pqxx::unique_violation&) {
        throw Conflict("admin role already exists: '" + req.name + "'");
    }
    auto created = AdminRoleQuery::get(id);
    if (!created) throw std::runtime_error("admin role '" + req.name + "' was created but could not be read back");
    notifications::enqueueAdminRoleCreated(created, notifications::actorFromUser(std::string(auditSource), actor));
    return created;
}

AdminRolePtr updateAdminRole(const Actor& actor, const UpdateRole& req, const std::string_view auditSource) {
    requireActor(actor);
    if (!actor->adminRolePerms().canEdit()) throw Denied("you do not have permission to edit admin roles");

    const auto existing = requireAdminRole(req.role);
    if (existing->name == kSuperAdminRoleName)
        throw Denied("the built-in '" + std::string(kSuperAdminRoleName) + "' role cannot be modified");
    if (isOwnRole(actor, *existing))
        throw Denied("cannot modify the admin role assigned to your own account ('" + existing->name + "')");

    auto staged = std::make_shared<rbac::role::Admin>(*existing);
    if (req.name) {
        requireName(*req.name, "admin");
        if (*req.name != existing->name) {
            if (*req.name == kSuperAdminRoleName)
                throw Denied("cannot rename a role to the reserved name '" + std::string(kSuperAdminRoleName) + "'");
            if (AdminRoleQuery::exists(*req.name)) throw Conflict("admin role already exists: '" + *req.name + "'");
        }
        staged->name = *req.name;
    }
    if (req.description) staged->description = *req.description;
    applyEdit<AdminResolver>(staged, req.permissions);
    requireWithinCeiling(actor, *staged, existing.get());

    // Every holder's published state carries the role's permissions.
    identities::manager().mutate({.everyone = true}, [&] { AdminRoleQuery::upsert(staged); });
    auto updated = AdminRoleQuery::get(existing->id);
    if (!updated) throw std::runtime_error("admin role " + std::to_string(existing->id) + " could not be read back");
    notifications::enqueueAdminRoleUpdated(updated, notifications::actorFromUser(std::string(auditSource), actor));
    return updated;
}

AdminRolePtr removeAdminRole(const Actor& actor, const Ref& ref, const std::string_view auditSource) {
    requireActor(actor);
    if (!actor->adminRolePerms().canDelete()) throw Denied("you do not have permission to delete admin roles");

    auto existing = requireAdminRole(ref);
    if (existing->name == kSuperAdminRoleName)
        throw Denied("the built-in '" + std::string(kSuperAdminRoleName) + "' role cannot be deleted");
    if (isOwnRole(actor, *existing))
        throw Denied("cannot delete the admin role assigned to your own account ('" + existing->name + "')");
    if (db::query::rbac::role::admin::Assignments::countAssignmentsForRole(existing->id) > 0)
        throw Conflict("cannot delete role '" + existing->name +
                       "' because it has active assignments; remove those assignments first");

    AdminRoleQuery::remove(existing->id);
    notifications::enqueueAdminRoleDeleted(existing, notifications::actorFromUser(std::string(auditSource), actor));
    return existing;
}

AdminRolePtr getAdminRole(const Actor& actor, const Ref& ref) {
    requireActor(actor);
    if (!actor->adminRolePerms().canView()) throw Denied("you do not have permission to view admin roles");
    return requireAdminRole(ref);
}

std::vector<AdminRolePtr> listAdminRoles(const Actor& actor, db::model::ListQueryParams params) {
    requireActor(actor);
    if (!actor->adminRolePerms().canView()) throw Denied("you do not have permission to view admin roles");
    return AdminRoleQuery::list(std::move(params));
}

// ---------------------------------------------------------------------------------------------------- vault roles

VaultRolePtr createVaultRole(const Actor& actor, const CreateRole& req) {
    requireActor(actor);
    if (!actor->vaultRolePerms().canAdd()) throw Denied("you do not have permission to create vault roles");

    requireName(req.name, "vault");
    if (VaultRoleQuery::exists(req.name)) throw Conflict("vault role already exists: '" + req.name + "'");

    auto staged = req.from ? std::make_shared<rbac::role::Vault>(*requireVaultRole(*req.from))
                           : std::make_shared<rbac::role::Vault>();
    staged->id = 0;
    staged->assignment_id = 0;
    staged->assignment.reset();
    staged->fs.overrides.clear();
    staged->name = req.name;
    staged->description = req.description;
    applyEdit<VaultResolver>(staged, req.permissions);

    unsigned int id = 0;
    try {
        id = VaultRoleQuery::insert(staged);
    } catch (const pqxx::unique_violation&) {
        throw Conflict("vault role already exists: '" + req.name + "'");
    }
    auto created = VaultRoleQuery::get(id);
    if (!created) throw std::runtime_error("vault role '" + req.name + "' was created but could not be read back");
    return created;
}

VaultRolePtr updateVaultRole(const Actor& actor, const UpdateRole& req) {
    const PolicyEpochBump bumpOnExit;
    requireActor(actor);
    if (!actor->vaultRolePerms().canEdit()) throw Denied("you do not have permission to edit vault roles");

    const auto existing = requireVaultRole(req.role);
    auto staged = std::make_shared<rbac::role::Vault>(*existing);
    if (req.name) {
        requireName(*req.name, "vault");
        if (*req.name != existing->name && VaultRoleQuery::exists(*req.name))
            throw Conflict("vault role already exists: '" + *req.name + "'");
        staged->name = *req.name;
    }
    if (req.description) staged->description = *req.description;
    applyEdit<VaultResolver>(staged, req.permissions);

    identities::manager().mutate({.everyone = true}, [&] { VaultRoleQuery::upsert(staged); });
    auto updated = VaultRoleQuery::get(existing->id);
    if (!updated) throw std::runtime_error("vault role " + std::to_string(existing->id) + " could not be read back");
    return updated;
}

VaultRolePtr removeVaultRole(const Actor& actor, const Ref& ref) {
    const PolicyEpochBump bumpOnExit;
    requireActor(actor);
    if (!actor->vaultRolePerms().canDelete()) throw Denied("you do not have permission to delete vault roles");

    auto existing = requireVaultRole(ref);
    if (VaultAssignments::countAssignmentsForRole(existing->id) > 0)
        throw Conflict("cannot delete vault role '" + existing->name +
                       "' because it has active assignments; remove those assignments first");
    VaultRoleQuery::remove(existing->id);
    return existing;
}

VaultRolePtr getVaultRole(const Actor& actor, const Ref& ref) {
    requireActor(actor);
    if (!actor->vaultRolePerms().canView()) throw Denied("you do not have permission to view vault roles");
    return requireVaultRole(ref);
}

std::vector<VaultRolePtr> listVaultRoles(const Actor& actor, db::model::ListQueryParams params) {
    requireActor(actor);
    if (!actor->vaultRolePerms().canView()) throw Denied("you do not have permission to view vault roles");
    return VaultRoleQuery::list(std::move(params));
}

// ---------------------------------------------------------------------------------------------- assignments

VaultRolePtr assignVaultRole(const Actor& actor, const AssignVaultRole& req) {
    const PolicyEpochBump bumpOnExit;
    requireActor(actor);
    requireVaultRolePermission(actor, req.target, RolePerm::Assign,
                               "you do not have permission to assign vault roles to this subject on this vault");
    requireVaultExists(req.target.vault_id);
    requireSubjectExists(req.target.subject);
    const auto role = requireVaultRole(req.role);

    identities::manager().mutate(touchedBy(req.target.subject), [&] {
        VaultAssignments::assign(req.target.vault_id, req.target.subject.type, req.target.subject.id, role->id);
    });
    auto assignment = VaultAssignments::get(req.target.vault_id, req.target.subject.type, req.target.subject.id);
    if (!assignment) throw std::runtime_error("vault role assignment could not be read back");
    return assignment;
}

VaultRolePtr unassignVaultRole(const Actor& actor, const VaultSubject& target) {
    const PolicyEpochBump bumpOnExit;
    requireActor(actor);
    requireVaultRolePermission(actor, target, RolePerm::Revoke,
                               "you do not have permission to remove vault roles from this subject on this vault");
    auto assignment = requireAssignment(target);
    identities::manager().mutate(touchedBy(target.subject), [&] {
        VaultAssignments::unassign(target.vault_id, target.subject.type, target.subject.id);
    });
    return assignment;
}

std::vector<VaultRolePtr> listVaultRoleAssignments(const Actor& actor, const std::optional<unsigned int> vaultId) {
    requireActor(actor);
    const auto canView = [&](const unsigned int id) {
        return rbac::resolver::Vault::has<RolePerm>({.user = actor, .permission = RolePerm::View, .vault_id = id});
    };
    if (vaultId) {
        if (!canView(*vaultId)) throw Denied("you do not have permission to view role assignments for this vault");
        return VaultAssignments::listForVault(*vaultId);
    }
    auto all = VaultAssignments::listAll();
    std::erase_if(all, [&](const VaultRolePtr& r) { return !r || !r->assignment || !canView(r->assignment->vault_id); });
    return all;
}

// ---------------------------------------------------------------------------------------------- overrides

std::vector<rbac::permission::Override> addVaultRoleOverrides(const Actor& actor, const AddOverrides& req) {
    const PolicyEpochBump bumpOnExit;
    requireActor(actor);
    requireVaultRolePermission(actor, req.target, RolePerm::AssignOverride,
                               "you do not have permission to add overrides for this subject on this vault");
    if (req.permissions.changes.empty()) throw Invalid("at least one permission is required");
    if (!rbac::fs::glob::Tokenizer::isValid(req.pattern)) throw Invalid("invalid override pattern '" + req.pattern + "'");
    const auto assignment = requireAssignment(req.target);

    // Override support is a property of the permission's type (only file/directory permissions are path-scoped),
    // which the role's exported permissions carry; the stored row supplies the id the override references.
    std::unordered_map<std::string, rbac::permission::Permission> exported;
    for (auto& perm : rbac::role::Vault().toPermissions()) exported.emplace(perm.qualified_name, perm);

    std::vector<std::shared_ptr<rbac::permission::Override>> staged;
    std::vector<std::string> problems;
    for (const auto& [name, allow] : req.permissions.changes) {
        const auto typed = exported.find(name);
        if (typed == exported.end()) { problems.push_back("unknown vault permission '" + name + "'"); continue; }
        if (!VaultResolver::hasOverrideSupport(typed->second)) {
            problems.push_back("permission '" + name + "' cannot be overridden by path");
            continue;
        }
        const auto perm = db::query::rbac::Permission::getPermissionByName(name);
        if (!perm) { problems.push_back("permission '" + name + "' is not seeded"); continue; }
        auto ov = std::make_shared<rbac::permission::Override>();
        ov->assignment_id = assignment->assignment_id;
        ov->permission = *perm;
        ov->effect = allow ? rbac::permission::OverrideOpt::ALLOW : rbac::permission::OverrideOpt::DENY;
        ov->enabled = req.enabled;
        ov->pattern = rbac::fs::glob::model::Pattern::make(req.pattern);
        staged.push_back(std::move(ov));
    }
    throwProblems("invalid overrides", problems);

    std::vector<rbac::permission::Override> created;
    identities::manager().mutate(touchedBy(req.target.subject), [&] {
        for (const auto& ov : staged) {
            ov->id = db::query::rbac::permission::Override::add(ov);
            created.push_back(*ov);
        }
    });
    return created;
}

rbac::permission::Override updateVaultRoleOverride(const Actor& actor, const UpdateOverride& req) {
    const PolicyEpochBump bumpOnExit;
    requireActor(actor);
    requireVaultRolePermission(actor, req.target, RolePerm::AssignOverride,
                               "you do not have permission to change overrides for this subject on this vault");
    const auto assignment = requireAssignment(req.target);
    auto ov = db::query::rbac::permission::Override::get(req.override_id);
    if (!ov || ov->assignment_id != assignment->assignment_id)
        throw NotFound("override " + std::to_string(req.override_id) + " not found on this assignment");

    if (req.allow) ov->effect = *req.allow ? rbac::permission::OverrideOpt::ALLOW : rbac::permission::OverrideOpt::DENY;
    if (req.pattern) {
        if (!rbac::fs::glob::Tokenizer::isValid(*req.pattern)) throw Invalid("invalid override pattern '" + *req.pattern + "'");
        ov->pattern = rbac::fs::glob::model::Pattern::make(*req.pattern);
    }
    if (req.enabled) ov->enabled = *req.enabled;
    identities::manager().mutate(touchedBy(req.target.subject),
                                 [&] { db::query::rbac::permission::Override::update(ov); });
    return *db::query::rbac::permission::Override::get(req.override_id);
}

void removeVaultRoleOverride(const Actor& actor, const VaultSubject& target, const unsigned int overrideId) {
    const PolicyEpochBump bumpOnExit;
    requireActor(actor);
    requireVaultRolePermission(actor, target, RolePerm::RevokeOverride,
                               "you do not have permission to remove overrides for this subject on this vault");
    const auto assignment = requireAssignment(target);
    const auto ov = db::query::rbac::permission::Override::get(overrideId);
    if (!ov || ov->assignment_id != assignment->assignment_id)
        throw NotFound("override " + std::to_string(overrideId) + " not found on this assignment");
    identities::manager().mutate(touchedBy(target.subject),
                                 [&] { db::query::rbac::permission::Override::remove(overrideId); });
}

std::vector<rbac::permission::Override> listVaultRoleOverrides(const Actor& actor, const VaultSubject& target) {
    requireActor(actor);
    requireVaultRolePermission(actor, target, RolePerm::ViewOverride,
                               "you do not have permission to view overrides for this subject on this vault");
    const auto assignment = requireAssignment(target);
    std::vector<rbac::permission::Override> out;
    for (const auto& ov : db::query::rbac::permission::Override::listAssigned(assignment->assignment_id))
        if (ov) out.push_back(*ov);
    return out;
}

}
