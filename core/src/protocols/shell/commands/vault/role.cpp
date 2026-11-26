#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "ops/Roles.hpp"
#include "rbac/role/Vault.hpp"
#include "vault/model/Vault.hpp"

#include <nlohmann/json.hpp>

#include <string>

namespace vh::protocols::shell::commands::vault {
    // Resolves the CLI's vault argument (name+owner or id) and --user/--group subject into the op's target.
    static std::optional<CommandResult> vaultRoleCliTarget(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage,
                                                           const char* err, ops::roles::VaultSubject& out,
                                                           std::string& vaultName) {
        const auto vLkp = resolveVault(call, call.positionals.at(0), usage, err);
        if (!vLkp || !vLkp.ptr) return invalid(vLkp.error);
        const auto subjLkp = parseSubject(call, err);
        if (!subjLkp || !subjLkp.ptr) return invalid(subjLkp.error);
        out = {.vault_id = vLkp.ptr->id, .subject = {.type = subjLkp.ptr->type, .id = subjLkp.ptr->id}};
        vaultName = vLkp.ptr->name;
        return std::nullopt;
    }

    static ops::roles::Ref vaultRoleCliRoleRef(const std::string& nameOrId) {
        if (const auto id = parseUInt(nameOrId)) return *id;
        return nameOrId;
    }

    static CommandResult handle_vault_role_assign(const CommandCall &call) {
        const auto usage = resolveUsage({"vault", "role", "assign"});
        validatePositionals(call, usage);

        ops::roles::VaultSubject target;
        std::string vaultName;
        if (auto err = vaultRoleCliTarget(call, usage, "vault role assign", target, vaultName)) return *err;

        return runOp("vault role assign", [&] {
            return ops::roles::assignVaultRole(call.user, {.target = target, .role = vaultRoleCliRoleRef(call.positionals.at(1))});
        }, [&](const auto& assignment) {
            const auto& a = assignment->assignment;
            const auto subject = a && a->subject_name ? "linked server '" + *a->subject_name + "'"
                                                      : target.subject.type + " " + std::to_string(target.subject.id);
            return "Successfully assigned role '" + assignment->name + "' to " + subject + " for vault '" + vaultName + "'";
        });
    }

    static CommandResult handle_vault_role_remove(const CommandCall &call) {
        const auto usage = resolveUsage({"vault", "role", "remove"});
        validatePositionals(call, usage);

        ops::roles::VaultSubject target;
        std::string vaultName;
        if (auto err = vaultRoleCliTarget(call, usage, "vault role remove", target, vaultName)) return *err;

        return runOp("vault role remove", [&] { return ops::roles::unassignVaultRole(call.user, target); },
            [&](const auto& removed) {
                return "Successfully removed role '" + removed->name + "' from vault '" + vaultName + "'";
            });
    }

    static CommandResult handle_vault_role_list(const CommandCall &call) {
        const auto usage = resolveUsage({"vault", "role", "list"});
        validatePositionals(call, usage);

        std::optional<unsigned int> vaultId;
        if (!call.positionals.empty()) {
            const auto vLkp = resolveVault(call, call.positionals.at(0), usage, "vault role list");
            if (!vLkp || !vLkp.ptr) return invalid(vLkp.error);
            vaultId = vLkp.ptr->id;
        }

        return runOp("vault role list", [&] { return ops::roles::listVaultRoleAssignments(call.user, vaultId); },
            [](const auto& roles) -> std::string {
                if (roles.empty()) return "No vault roles found.";
                nlohmann::json j;
                j["roles"] = roles;
                return j.dump(4);
            });
    }

    static bool isVaultRoleMatch(const std::string &cmd, const std::string_view input) {
        return isCommandMatch({"vault", "role", cmd}, input);
    }

    CommandResult handle_vault_role(const CommandCall &call) {
        if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
            return usage(call.constructFullArgs());

        const auto [sub, subcall] = descend(call);

        if (isVaultRoleMatch({"assign"}, sub)) return handle_vault_role_assign(subcall);
        if (isVaultRoleMatch({"remove"}, sub)) return handle_vault_role_remove(subcall);
        if (isVaultRoleMatch({"list"}, sub)) return handle_vault_role_list(subcall);
        if (isVaultRoleMatch({"override"}, sub)) return handle_vault_role_override(subcall);

        return invalid(call.constructFullArgs(), "Unknown vault role subcommand: '" + std::string(sub) + "'");
    }
}
