// ws models: identity — users, groups, admin and vault roles, permissions and overrides (core/src/identities,
// core/src/rbac). Checked against their serializers by core/tests/unit/contract/models_identity.cpp.

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField identityTimestamp(std::string name) {
    return str(std::move(name)).desc("ISO-8601 UTC (\"2026-10-20T12:00:00Z\").");
}

// rbac::role::Meta (core/src/rbac/role/Meta.cpp to_json): the role identity every role JSON starts with.
std::vector<WsField> identityRoleMeta() {
    return {uinteger("id"),
            str("name"),
            str("description"),
            integer("created_at").desc("Unix seconds."),
            integer("updated_at").desc("Unix seconds."),
            integer("assigned_at").nullable().desc("Unix seconds, when the role was assigned to the subject; null on "
                                                   "a role definition.")};
}

std::vector<WsField> identityWith(std::vector<WsField> base, std::vector<WsField> more) {
    for (auto& f : more) base.push_back(std::move(f));
    return base;
}

// {qualified, value}: a permission reduced to its name and grant (Auth::sessionUser).
WsField identityPermissionValues(std::string name) {
    return objectArray(std::move(name), "", {str("qualified"), boolean("value")});
}

// User::vault_roles: an array of roles, or an empty object when the user has none (to_json's historic shape).
WsField identityVaultRolesUnion(const std::string& roleModel) {
    WsField roles{.types = {"array"}, .items = "object", .model = roleModel};
    return anyOf("vault_roles", {"array", "object"})
        .alternatives({roles, alt({"object"}).desc("{} when the user holds no vault role.")})
        .desc("Direct vault role assignments.");
}

// identities::to_json(User) / to_list_json: baseJson's members.
std::vector<WsField> identityUserBase() {
    return {uinteger("id"),
            str("name"),
            str("email").nullable(),
            boolean("is_protected"),
            boolean("system_only"),
            boolean("is_active"),
            identityTimestamp("created_at"),
            identityTimestamp("updated_at"),
            identityTimestamp("last_login").nullable(),
            identityTimestamp("password_changed_at").nullable(),
            identityTimestamp("deactivated_at").nullable(),
            uinteger("linux_uid").opt().desc("Present when the account is bound to a Linux uid."),
            uinteger("created_by").opt(),
            uinteger("updated_by").opt()};
}

}

std::vector<WsModel> identityModels() {
    std::vector<WsModel> out;

    out.push_back(model("Permission",
        "One permission (rbac::permission::to_json(Permission), core/src/rbac/permission/Permission.cpp).",
        {uinteger("bit_position"),
         str("qualified").desc("Qualified name (\"admin.identities.users.view\")."),
         str("description"),
         str("slug").desc("The last segment of the qualified name."),
         uinteger("id").opt().desc("The catalog row id: present on catalog permissions (permission.get, "
                                   "permissions.list, overrides), absent on a role's exported permissions."),
         boolean("value").opt().desc("Granted: present on a role's exported permissions.")}));

    out.push_back(model("AdminRole",
        "An admin role (rbac::role::to_json(Admin), core/src/rbac/role/Admin.cpp): its identity, every admin "
        "permission with its value, and the S3 gateway capability summary.",
        identityWith(identityRoleMeta(),
                     {uinteger("user_id").nullable().desc("The account the role is bound to; null on a definition."),
                      objectArray("permissions", "Permission"),
                      object("s3_gateway", "",
                             {boolean("view"), boolean("manage_service"), boolean("manage_credentials"),
                              boolean("assign_principal"), boolean("manage_buckets"), boolean("manage_budgets")})
                          .desc("rbac::permission::admin::S3Gateway to_json.")})));

    out.push_back(model("VaultRoleAssignment",
        "Who holds a vault role where (rbac::role::to_json(Vault::AssignmentInfo), core/src/rbac/role/Vault.cpp).",
        {str("subject_id").desc("A user or group id, as a decimal string."),
         str("vault_id").desc("Vault id, as a decimal string."),
         str("subject_type").desc("user, group, public or actor.")}));

    out.push_back(model("VaultRole",
        "A vault role (rbac::role::to_json(Vault), core/src/rbac/role/Vault.cpp): a definition, or an assignment "
        "of one (then `assignment` and `assigned_at` are set).",
        identityWith(identityRoleMeta(),
                     {objectArray("permissions", "Permission"),
                      object("assignment", "VaultRoleAssignment").opt()})));

    out.push_back(model("PermissionOverride",
        "A path-scoped allow/deny override on a vault role assignment (rbac::permission::to_json(Override), "
        "core/src/rbac/permission/Override.cpp).",
        {uinteger("id"),
         object("permission", "Permission"),
         str("effect").oneOf({"allow", "deny"}),
         uinteger("assignment_id"),
         boolean("enabled"),
         str("glob_path").desc("Vault-relative glob (\"/docs/**\").")}));

    out.push_back(model("PublicUser",
        "A user's public identity (identities::to_public_json, core/src/identities/User.cpp).",
        {uinteger("id"), str("name"), str("email").nullable(), boolean("is_active")}));

    out.push_back(model("User",
        "A user with its full roles and permissions (identities::to_json(User), core/src/identities/User.cpp).",
        identityWith(identityUserBase(),
                     {object("admin_role", "AdminRole"), identityVaultRolesUnion("VaultRole")})));

    out.push_back(model("SessionAdminRole",
        "AdminRole as the session user carries it: permissions reduced to {qualified, value} "
        "(protocols::ws::handler::Auth::sessionUser).",
        identityWith(identityRoleMeta(),
                     {uinteger("user_id").nullable(),
                      identityPermissionValues("permissions"),
                      object("s3_gateway", "",
                             {boolean("view"), boolean("manage_service"), boolean("manage_credentials"),
                              boolean("assign_principal"), boolean("manage_buckets"), boolean("manage_budgets")})})));

    out.push_back(model("SessionVaultRole",
        "VaultRole as the session user carries it: permissions reduced to {qualified, value} (Auth::sessionUser).",
        identityWith(identityRoleMeta(),
                     {identityPermissionValues("permissions"), object("assignment", "VaultRoleAssignment").opt()})));

    out.push_back(model("SessionUser",
        "The signed-in user as auth.login / auth.refresh / auth.isAuthenticated send it: User with every role's "
        "permissions reduced to {qualified, value} (protocols::ws::handler::Auth::sessionUser).",
        identityWith(identityUserBase(),
                     {object("admin_role", "SessionAdminRole"), identityVaultRolesUnion("SessionVaultRole")})));

    out.push_back(model("RoleSummary",
        "A role's identity without its permissions (identities::to_list_json's roleSummary).",
        {uinteger("id"),
         str("name"),
         str("description"),
         str("type").oneOf({"admin", "vault"}),
         integer("assigned_at").nullable().desc("Unix seconds."),
         object("assignment", "VaultRoleAssignment").opt().desc("Vault roles.")}));

    out.push_back(model("UserSummary",
        "The slim user list projection (identities::to_list_json, core/src/identities/User.cpp): the user fields of "
        "User, roles as RoleSummary.",
        identityWith(identityUserBase(),
                     {object("admin_role", "RoleSummary").nullable(), objectArray("vault_roles", "RoleSummary")})));

    out.push_back(model("GroupMember",
        "A group membership (identities::to_json(GroupMember), core/src/identities/Group.cpp).",
        {object("user", "PublicUser").nullable().desc("null if the member's account no longer resolves."),
         identityTimestamp("joined_at")}));

    out.push_back(model("Group",
        "A group with its members (identities::to_json(Group, members), core/src/identities/Group.cpp).",
        {uinteger("id"),
         str("name"),
         str("description").nullable(),
         identityTimestamp("created_at"),
         objectArray("members", "GroupMember"),
         uinteger("gid").opt().desc("The Linux gid, when set."),
         identityTimestamp("updated_at").opt()}));

    return out;
}

}
