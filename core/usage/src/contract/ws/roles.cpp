// ws book: vault role assignment (core/src/protocols/ws/handler/rbac/roles/Vault.cpp).

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

    return out;
}

}
