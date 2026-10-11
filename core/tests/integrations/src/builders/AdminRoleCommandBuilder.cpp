#include "cmd/Builder.hpp"
#include "cmd/generators.hpp"
#include "cli/Context.hpp"
#include "CommandUsage.hpp"
#include "rbac/role/Admin.hpp"
#include "randomizer/AdminRole.hpp"

using namespace vh::rbac;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::vault::model;

namespace vh::test::integration::cmd {
    AdminRoleCommandBuilder::AdminRoleCommandBuilder(const std::shared_ptr<protocols::shell::UsageManager>& usage, const std::shared_ptr<cli::Context>& ctx)
        : Builder(usage, ctx, std::vector<std::string>{"role", "admin"}), adminRoleAliases_(ctx) {}

    std::string AdminRoleCommandBuilder::updateAndResolveVar(const std::shared_ptr<role::Admin>& entity, const std::string& field) {
        const std::string usagePath = "role/update";

        if (adminRoleAliases_.isName(field)) {
            entity->name = generateRoleName(EntityType::ADMIN_ROLE, usagePath);
            return entity->name;
        }

        if (adminRoleAliases_.isDescription(field)) {
            entity->description = generateDescription(usagePath);
            return entity->description;
        }

        if (adminRoleAliases_.isPermissions(field)) {
            randomizer::AdminRole::assignRandomPermissions(entity);
            return entity->toFlagsString();
        }

        throw std::runtime_error("AdminRoleCommandBuilder: unsupported user role field for update: " + field);
    }

    static std::optional<std::string> resolveVar(const std::string& name, const std::shared_ptr<role::Admin>& role) {
        if (name == "id" || name == "role_id") return std::to_string(role->id);
        if (name == "name" || name == "role_name") return role->name;
        if (name == "description" || name == "desc") return role->description;
        if (name == "permissions" || name == "perms") return role->toFlagsString();
        throw std::runtime_error("AdminRoleCommandBuilder: unsupported user role field for resolveVar: " + name);
    }

    static std::string randomizePrimaryPositional(const std::shared_ptr<role::Admin>& entity) {
        if (generateRandomIndex(10000) < 5000) return std::to_string(entity->id);
        return entity->name;
    }

    std::string AdminRoleCommandBuilder::create(const std::shared_ptr<role::Admin>& entity) {
        const auto cmd = root_->findSubcommand("create");
        if (!cmd) throw std::runtime_error("AdminRoleCommandBuilder: 'create' command usage not found");

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << " " << randomAlias(cmd->aliases) << " " << entity->name;

        for (const auto& opt : cmd->required) {
            oss << ' ' << randomFlagAlias(opt.option_tokens);
            if (auto val = resolveVar(opt.option_tokens[0], entity); val) oss << ' ' << *val;
            else throw std::runtime_error("AdminRoleCommandBuilder: unsupported user role field for create: " + opt.option_tokens[0]);
        }

        for (const auto& option : cmd->optional) {
            // A description left off the command line is no description, in the model too (Validate compares).
            if (option.label.contains("description") && !coin()) {
                entity->description.clear();
                continue;
            }
            if (option.label.contains("description") || coin()) {
                if (option.option_tokens[0] == "from") {
                    if (!ctx_->adminRoles.empty() && coin())
                        oss << ' ' << randomFlagAlias(option.option_tokens) << ' ' << std::to_string(ctx_->randomAdminRole()->id);
                    continue;
                }

                if (option.label.contains("description")) {
                    oss << ' ' << randomFlagAlias(option.option_tokens) << ' ' << quoted(updateAndResolveVar(entity, option.option_tokens[0]));
                    continue;
                }

                oss << ' ' << randomFlagAlias(option.option_tokens);
                if (auto val = resolveVar(option.option_tokens[0], entity); val) oss << ' ' << *val;
                else throw std::runtime_error("AdminRoleCommandBuilder: unsupported user role field for create: " + option.option_tokens[0]);
            }
        }

        oss << ' ' << entity->toFlagsString();

        return oss.str();
    }

    BuiltCommand AdminRoleCommandBuilder::update(const std::shared_ptr<role::Admin>& entity) {
        const auto cmd = root_->findSubcommand("update");
        if (!cmd) throw std::runtime_error("AdminRoleCommandBuilder: 'update' command usage not found");

        const auto proposed = std::make_shared<role::Admin>(*entity);

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);

        unsigned int numUpdated = 0;
        for (const auto& opt : cmd->optional) {
            if (coin() || numUpdated == 0) {
                if (opt.label.contains("description")) {
                    oss << ' ' << randomFlagAlias(opt.option_tokens) << ' ' << quoted(updateAndResolveVar(proposed, opt.option_tokens[0]));
                    continue;
                }

                oss << ' ' << randomFlagAlias(opt.option_tokens);
                oss << ' ' << updateAndResolveVar(proposed, opt.option_tokens[0]);
                ++numUpdated;
            }
        }

        numUpdated = 0;
        for (const auto& flag : cmd->optional_flags) {
            if (flag.label.contains("filter")) continue;
            if (coin() || numUpdated == 0) {
                if (flag.label.contains("permissions")) oss << ' ' << updateAndResolveVar(proposed, flag.label);
                else oss << ' ' << randomFlagAlias(flag.aliases);
                ++numUpdated;
            }
        }

        return {oss.str(), [entity, proposed] { *entity = *proposed; }};
    }

    std::string AdminRoleCommandBuilder::info(const std::shared_ptr<role::Admin>& entity) {
        const auto cmd = root_->findSubcommand("info");
        if (!cmd) throw std::runtime_error("AdminRoleCommandBuilder: 'info' command usage not found");

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);

        return oss.str();
    }

    std::string AdminRoleCommandBuilder::list() {
        const auto cmd = root_->findSubcommand("list");
        if (!cmd) throw std::runtime_error("AdminRoleCommandBuilder: 'list' command usage not found");

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        for (const auto& flag : cmd->optional_flags)
            if (generateRandomIndex(10000) < 5000) oss << " --" << randomAlias(flag.aliases);

        return oss.str();
    }

    std::string AdminRoleCommandBuilder::remove(const std::shared_ptr<role::Admin>& entity) {
        const auto cmd = root_->findSubcommand("delete");
        if (!cmd) throw std::runtime_error("AdminRoleCommandBuilder: 'delete' command usage not found");

        std::ostringstream oss;
        oss << "vh role " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        if (generateRandomIndex(10000) < 5000) oss << ' ' << entity->id;
        else oss << ' ' << entity->name;

        return oss.str();
    }
}
