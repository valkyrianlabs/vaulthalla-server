#include "cli/Context.hpp"
#include "types/Type.hpp"
#include "cmd/generators.hpp"
#include "UsageManager.hpp"
#include "identities/User.hpp"
#include "vault/model/Vault.hpp"
#include "identities/Group.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"

#include <stdexcept>

using namespace vh::protocols::shell;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::rbac;
using namespace vh::vault::model;

namespace vh::test::integration::cli {
    Context::Context()
        : usage(std::make_shared<UsageManager>()) {
        for (const auto& entity : ENTITIES) {
            for (const auto& action : ACTIONS) {
                const auto eStr = std::string(entity);
                const auto aStr = std::string(action);

                if (entity == "role") {
                    const auto cmdBase = eStr + " " + aStr;
                    const auto adminCmd = cmdBase + " admin";
                    const auto vaultCmd = cmdBase + " vault";
                    const auto adminUsage = usage->resolve({eStr, "admin", aStr});
                    const auto vaultUsage = usage->resolve({eStr, "vault", aStr});
                    if (!adminUsage) throw std::runtime_error("EntityFactory: unknown command usage: " + adminCmd);
                    if (!vaultUsage) throw std::runtime_error("EntityFactory: unknown command usage: " + vaultCmd);
                    commands[adminCmd] = adminUsage;
                    commands[vaultCmd] = vaultUsage;
                    continue;
                }
                const auto cmdName = eStr + " " + aStr;
                const auto cmdUsage = usage->resolve({eStr, aStr});
                if (!cmdUsage) throw std::runtime_error("EntityFactory: unknown command usage: " + cmdName);
                commands[cmdName] = cmdUsage;
            }
        }
    }

    std::string Context::getCommandName(const EntityType& type, const std::string& action) {
        switch (type) {
            case EntityType::USER:  return "user " + action;
            case EntityType::VAULT: return "vault " + action;
            case EntityType::GROUP: return "group " + action;
            case EntityType::ADMIN_ROLE: return "role " + action + " admin";
            case EntityType::VAULT_ROLE: return "role " + action + " vault";
            default: throw std::runtime_error("EntityFactory: unsupported entity type for command name");
        }
    }

    std::shared_ptr<CommandUsage> Context::getCommand(const EntityType& type, const std::string& action) const {
        return commands.at(getCommandName(type, action));
    }

    std::shared_ptr<User> Context::pickRandomUser() const {
        if (users.empty()) throw std::runtime_error("cli::Context: no users available to pick from");
        return users[generateRandomIndex(users.size())];
    }

    std::shared_ptr<Group> Context::pickRandomGroup() const {
        if (groups.empty()) throw std::runtime_error("cli::Context: no groups available to pick from");
        return groups[generateRandomIndex(groups.size())];
    }

    std::shared_ptr<Vault> Context::pickRandomVault() const {
        if (vaults.empty()) throw std::runtime_error("cli::Context: no vaults available to pick from");
        return vaults[generateRandomIndex(vaults.size())];
    }

    std::shared_ptr<Vault> Context::pickVaultOwnedBy(const std::shared_ptr<User>& user) const {
        if (vaults.empty()) throw std::runtime_error("cli::Context: no vaults available to pick from");
        std::vector<std::shared_ptr<Vault>> owned;
        for (const auto& v : vaults) if (v->owner_id == user->id) owned.push_back(v);
        if (owned.empty()) throw std::runtime_error("cli::Context: user owns no vaults to pick from");
        return owned[generateRandomIndex(owned.size())];
    }

    std::shared_ptr<role::Admin> Context::randomAdminRole() const {
        if (adminRoles.empty()) throw std::runtime_error("cli::Context: no admin roles available to pick from");
        return adminRoles[generateRandomIndex(adminRoles.size())];
    }

    std::shared_ptr<role::Vault> Context::randomVaultRole() const {
        if (vaultRoles.empty()) throw std::runtime_error("cli::Context: no vault roles available to pick from");
        return vaultRoles[generateRandomIndex(vaultRoles.size())];
    }
}
