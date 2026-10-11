#include "cmd/Builder.hpp"
#include "cmd/generators.hpp"
#include "cli/Context.hpp"
#include "CommandUsage.hpp"
#include "randomizer/VaultRole.hpp"

#include <iomanip>

using vh::identities::User;
using vh::identities::Group;
using namespace vh::rbac;
using namespace vh::vault::model;

namespace vh::test::integration::cmd {
    VaultRoleCommandBuilder::VaultRoleCommandBuilder(const std::shared_ptr<protocols::shell::UsageManager>& usage, const std::shared_ptr<cli::Context>& ctx)
        : Builder(usage, ctx, std::vector<std::string>{"role", "vault"}), vaultRoleAliases_(ctx) {}

    std::string VaultRoleCommandBuilder::updateAndResolveVar(const std::shared_ptr<role::Vault>& entity, const std::string& field) {
        const std::string usagePath = "vault/update";

        if (vaultRoleAliases_.isName(field)) {
            entity->name = generateRoleName(EntityType::VAULT_ROLE, usagePath);
            return entity->name;
        }

        if (vaultRoleAliases_.isDescription(field)) {
            entity->description = "Updated vault role description";
            return entity->description;
        }

        if (vaultRoleAliases_.isPermissions(field)) {
            randomizer::VaultRole::assignRandomPermissions(entity);
            return entity->toFlagsString();
        }

        throw std::runtime_error("VaultRoleCommandBuilder: unsupported vault role field for update: " + field);
    }

    static std::optional<std::string> resolveVar(const std::string& name, const std::shared_ptr<role::Vault>& role) {
        if (name == "id" || name == "role_id") return std::to_string(role->id);
        if (name == "name" || name == "role_name") return role->name;
        if (name == "description" || name == "desc") return role->description;
        if (name == "permissions" || name == "perms") return role->toFlagsString();
        throw std::runtime_error("VaultRoleCommandBuilder: unsupported vault role field for resolveVar: " + name);
    }

    static std::string randomizePrimaryPositional(const std::shared_ptr<role::Vault>& entity) {
        if (generateRandomIndex(10000) < 5000) return std::to_string(entity->id);
        return entity->name;
    }

    std::string VaultRoleCommandBuilder::create(const std::shared_ptr<role::Vault>& entity) {
        const auto cmd = root_->findSubcommand("create");
        if (!cmd) throw std::runtime_error("VaultRoleCommandBuilder: 'create' command usage not found");

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << " " << randomAlias(cmd->aliases) << " " << entity->name;

        for (const auto& opt : cmd->required) {
            oss << ' ' << randomFlagAlias(opt.option_tokens);
            if (auto val = resolveVar(opt.option_tokens[0], entity); val) oss << ' ' << *val;
            else throw std::runtime_error("VaultRoleCommandBuilder: unsupported vault role field for create: " + opt.option_tokens[0]);
        }

        for (const auto& option : cmd->optional) {
            if (coin()) {
                if (option.option_tokens[0] == "from") {
                    if (!ctx_->vaultRoles.empty() && coin())
                        oss << ' ' << randomFlagAlias(option.option_tokens) << ' ' << std::to_string(ctx_->randomVaultRole()->id);
                    continue;
                }

                if (option.label.contains("description")) {
                    oss << ' ' << randomFlagAlias(option.option_tokens) << ' ' << quoted(updateAndResolveVar(entity, option.option_tokens[0]));
                    continue;
                }

                oss << ' ' << randomAlias(option.option_tokens);
                if (auto val = resolveVar(option.option_tokens[0], entity); val) oss << ' ' << *val;
                else throw std::runtime_error("VaultRoleCommandBuilder: unsupported vault role field for create: " + option.option_tokens[0]);
            }
        }

        oss << ' ' << entity->toFlagsString();

        return oss.str();
    }

    std::string VaultRoleCommandBuilder::update(const std::shared_ptr<role::Vault>& entity) {
        const auto cmd = root_->findSubcommand("update");
        if (!cmd) throw std::runtime_error("VaultRoleCommandBuilder: 'update' command usage not found");

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);

        unsigned int numUpdated = 0;
        for (const auto& opt : cmd->optional) {
            if (coin() || numUpdated == 0) {
                if (opt.label.contains("description")) {
                    oss << ' ' << randomFlagAlias(opt.option_tokens) << ' ' << quoted(updateAndResolveVar(entity, opt.option_tokens[0]));
                    continue;
                }

                oss << ' ' << randomFlagAlias(opt.option_tokens);
                oss << ' ' << updateAndResolveVar(entity, opt.option_tokens[0]);
                ++numUpdated;
            }
        }

        numUpdated = 0;
        for (const auto& flag : cmd->optional_flags) {
            if (flag.label.contains("filter")) continue;
            if (coin() || numUpdated == 0) {
                if (flag.label.contains("permissions")) oss << ' ' << updateAndResolveVar(entity, flag.label);
                else oss << ' ' << randomFlagAlias(flag.aliases);
                ++numUpdated;
            }
        }

        return oss.str();
    }

    std::string VaultRoleCommandBuilder::info(const std::shared_ptr<role::Vault>& entity) {
        const auto cmd = root_->findSubcommand("info");
        if (!cmd) throw std::runtime_error("VaultRoleCommandBuilder: 'info' command usage not found");

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);

        return oss.str();
    }

    std::string VaultRoleCommandBuilder::list() {
        const auto cmd = root_->findSubcommand("list");
        if (!cmd) throw std::runtime_error("VaultRoleCommandBuilder: 'list' command usage not found");

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        for (const auto& flag : cmd->optional_flags)
            if (generateRandomIndex(10000) < 5000) oss << " --" << randomAlias(flag.aliases);

        return oss.str();
    }

    std::string VaultRoleCommandBuilder::remove(const std::shared_ptr<role::Vault>& entity) {
        const auto cmd = root_->findSubcommand("delete");
        if (!cmd) throw std::runtime_error("VaultRoleCommandBuilder: 'delete' command usage not found");

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        if (generateRandomIndex(10000) < 5000) oss << ' ' << entity->id;
        else oss << ' ' << entity->name;

        return oss.str();
    }
}
