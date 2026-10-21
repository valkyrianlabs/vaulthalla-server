// ws book: admin and vault role definitions, vault role assignment and its overrides
// (core/src/protocols/ws/handler/rbac/roles/{Admin,Vault}.cpp → ops::roles).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

// The assignment target: a user or group on a vault.
std::vector<WsField> vaultSubjectPayload() {
    return {vaultId(),
            str("subject_type").oneOf({"user", "group"}),
            uinteger("subject_id").gen(gen::ref("subject", {"id"})).desc("A user id or a group id, per subject_type.")};
}

WsField vaultRoleIdField(std::string name = "id") { return uinteger(std::move(name)).gen(gen::ref("role.vault", {"id"})); }

WsField adminRoleIdField() { return uinteger("id").gen(gen::ref("role.admin", {"id"})); }

// {qualified, value} per permission: the role forms' complete snapshot (overrides: value true = allow, false = deny).
WsField rolePermissionValues() {
    return objectArray("permissions", "", {str("qualified").desc("Qualified permission name."), boolean("value")});
}

std::vector<WsField> roleCreatePayload() {
    return {str("name").gen(gen::freshName("role_")),
            str("description").opt().gen(gen::pattern("role {a}{a}{a}{a}{a}")),
            rolePermissionValues().opt().desc("Every permission as {qualified, value}: a complete snapshot, or core "
                                              "refuses the edit. Absent: no permission changes.")};
}

std::vector<WsField> roleUpdatePayload(WsField id) {
    return {std::move(id),
            str("name").opt().nullable().gen(gen::freshName("role_")),
            str("description").opt().nullable(),
            rolePermissionValues().opt().desc("When present, a complete {qualified, value} snapshot.")};
}

WsField vaultRoleOverrideId() {
    return uinteger("override_id").gen(gen::ref("vault_role_override", {"id"})).desc("From role.vault.overrides.list.");
}

}

std::vector<WsCommandUsage> roleCommands() {
    std::vector<WsCommandUsage> out;

    auto assignPayload = vaultSubjectPayload();
    assignPayload.push_back(vaultRoleIdField().desc("The vault role to assign."));
    out.push_back({
        .command = "role.vault.assign",
        .description = "Assign a vault role to a user or group on a vault (one assignment per subject and vault).",
        .payload = assignPayload,
        .response = {object("assignment", "VaultRole")},
        .refusal_codes = opsRefusals(),
        .operation = "roles.vault.assign",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "role.vault.unassign",
        .description = "Remove a subject's vault role assignment on a vault.",
        .payload = vaultSubjectPayload(),
        .response = {boolean("unassigned")},
        .refusal_codes = opsRefusals(),
        .operation = "roles.vault.unassign",
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "role.vault.get",
        .description = "One vault role definition.",
        .payload = {vaultRoleIdField()},
        .response = {object("role", "VaultRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "roles.vault.list",
        .description = "Every vault role definition.",
        .input = "none",
        .response = {objectArray("roles", "VaultRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "roles.vault.list.assigned",
        .description = "The role assignments on one vault (id is the vault id).",
        .payload = {uinteger("id").gen(gen::ref("vault", {"id"})).desc("Vault id.")},
        .response = {objectArray("assigned_roles", "VaultRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- admin roles ----
    out.push_back({
        .command = "role.admin.add",
        .description = "Create an admin role. Nobody grants an admin permission they do not hold.",
        .payload = roleCreatePayload(),
        .response = {object("role", "AdminRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "role.admin.update",
        .description = "Patch an admin role (name, description; permissions as a complete snapshot). Core refuses edits "
                       "to super_admin and to the caller's own role, and grants beyond the caller's own permissions.",
        .payload = roleUpdatePayload(adminRoleIdField()),
        .response = {object("role", "AdminRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "role.admin.delete",
        .description = "Delete an admin role; the answer's role is the deleted role's id.",
        .payload = {adminRoleIdField()},
        .response = {uinteger("role").desc("The deleted role's id.")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "role.admin.get",
        .description = "One admin role with its permissions.",
        .payload = {adminRoleIdField()},
        .response = {object("role", "AdminRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "role.admin.get.byName",
        .description = "One admin role by name.",
        .payload = {str("name").gen(gen::ref("role.admin", {"name"}))},
        .response = {object("role", "AdminRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "roles.admin.list",
        .description = "Every admin role the caller may view.",
        .input = "none",
        .response = {objectArray("roles", "AdminRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- vault role definitions ----
    out.push_back({
        .command = "role.vault.add",
        .description = "Create a vault role definition (assigning it is role.vault.assign).",
        .payload = roleCreatePayload(),
        .response = {object("role", "VaultRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "role.vault.update",
        .description = "Patch a vault role definition (name, description; permissions as a complete snapshot).",
        .payload = roleUpdatePayload(vaultRoleIdField()),
        .response = {object("role", "VaultRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "role.vault.delete",
        .description = "Delete a vault role definition.",
        .payload = {vaultRoleIdField()},
        .response = {uinteger("role_id")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "role.vault.get.byName",
        .description = "One vault role definition by name.",
        .payload = {str("name").gen(gen::ref("role.vault", {"name"}))},
        .response = {object("role", "VaultRole")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- per-assignment overrides ----
    out.push_back({
        .command = "role.vault.overrides.list",
        .description = "The path-scoped allow/deny overrides on one assignment (a subject's role on a vault).",
        .payload = vaultSubjectPayload(),
        .response = {objectArray("overrides", "PermissionOverride")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    auto overridesAdd = vaultSubjectPayload();
    overridesAdd.push_back(rolePermissionValues().opt().desc(
        "{qualified, value}: value true = allow, false = deny. At least one is required (invalid otherwise)."));
    overridesAdd.push_back(str("pattern").gen(gen::constant("/docs/**")).desc("Vault-relative glob (\"/docs/**\")."));
    overridesAdd.push_back(boolean("enabled").opt().desc("Default true."));
    out.push_back({
        .command = "role.vault.overrides.add",
        .description = "Add allow/deny overrides for a pattern on one assignment (same ops as `vh vault role override "
                       "add`).",
        .payload = overridesAdd,
        .response = {objectArray("overrides", "PermissionOverride").desc("The overrides created.")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    auto overridesUpdate = vaultSubjectPayload();
    overridesUpdate.push_back(vaultRoleOverrideId());
    overridesUpdate.push_back(str("effect").opt().nullable().oneOf({"allow", "deny"}));
    overridesUpdate.push_back(str("pattern").opt().nullable());
    overridesUpdate.push_back(boolean("enabled").opt().nullable());
    out.push_back({
        .command = "role.vault.overrides.update",
        .description = "Patch one override (effect, pattern, enabled; absent or null are unchanged).",
        .payload = overridesUpdate,
        .response = {object("override", "PermissionOverride")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    auto overridesRemove = vaultSubjectPayload();
    overridesRemove.push_back(vaultRoleOverrideId());
    out.push_back({
        .command = "role.vault.overrides.remove",
        .description = "Remove one override from an assignment.",
        .payload = overridesRemove,
        .response = {boolean("removed")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
