#include "cmd/Builder.hpp"
#include "entity/Edit.hpp"
#include "cmd/generators.hpp"
#include "cli/Context.hpp"
#include "CommandUsage.hpp"

using vh::identities::User;
using vh::identities::Group;

namespace vh::test::integration::cmd {
    UserCommandBuilder::UserCommandBuilder(const std::shared_ptr<protocols::shell::UsageManager>& usage, const std::shared_ptr<cli::Context>& ctx)
        : Builder(usage, ctx, "user"), userAliases_(ctx) {}

    std::string UserCommandBuilder::updateAndResolveVar(const std::shared_ptr<User>& entity, const std::string& field) {
        if (!entity) throw std::runtime_error("UserCommandBuilder: entity is null in updateAndResolveVar");
        if (field.empty()) throw std::runtime_error("UserCommandBuilder: field is empty in updateAndResolveVar");

        const std::string usagePath = "user/update";
        if (userAliases_.isName(field)) {
            entity::edit(entity, [&](auto& s) { s.name = generateName(usagePath); });
            return entity->name();
        }

        if (userAliases_.isEmail(field)) {
            std::string email = generateEmail(usagePath);
            entity::edit(entity, [&](auto& s) { s.email = std::make_optional(email); });
            return email;
        }

        if (userAliases_.isRole(field)) {
            if (ctx_->adminRoles.empty()) throw std::runtime_error("UserCommandBuilder: no user roles available to assign");
            entity::edit(entity, [&](auto& s) { s.roles.admin = ctx_->randomAdminRole(); });
            return std::to_string(entity->state()->roles.admin->id);
        }

        if (userAliases_.isLinuxUID(field)) {
            const auto linuxUid = randomLinuxId();
            entity::edit(entity, [&](auto& s) { s.meta.linux_uid = std::make_optional(linuxUid); });
            return std::to_string(linuxUid);
        }

        throw std::runtime_error("UserCommandBuilder: unsupported user field for update: " + field);
    }

    static std::optional<std::string> resolveVar(const std::string& name, const std::shared_ptr<User>& user) {
        if (name == "id" || name == "user_id") return std::to_string(user->id);
        if (name == "name" || name == "username") return user->name();
        if (name == "email") return user->email();
        if (name == "role" || name == "role_id") return std::to_string(user->state()->roles.admin->id);
        throw std::runtime_error("UserCommandBuilder: unsupported user field for resolveVar: " + name);
    }

    static std::string randomizePrimaryPositional(const std::shared_ptr<User>& entity) {
        if (!entity) throw std::runtime_error("UserCommandBuilder: entity is null in randomizePrimaryPositional");
        if (entity->name().empty()) throw std::runtime_error("UserCommandBuilder: entity name is empty in randomizePrimaryPositional");
        if (coin()) return std::to_string(entity->id);
        return entity->name();
    }

    std::string UserCommandBuilder::create(const std::shared_ptr<User>& entity) {
        const auto cmd = root_->findSubcommand("create");
        if (!cmd) throw std::runtime_error("UserCommandBuilder: 'create' command usage not found");
        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);

        for (const auto& pos : cmd->positionals) oss << ' ' << *resolveVar(pos.label, entity);

        for (const auto& opt : cmd->required) {
            oss << ' ' << randomFlagAlias(opt.option_tokens);
            if (auto val = resolveVar(opt.option_tokens[0], entity); val) oss << ' ' << *val;
            else throw std::runtime_error("UserCommandBuilder: unsupported user field for create: " + opt.option_tokens[0]);
        }
        return oss.str();
    }

    std::string UserCommandBuilder::update(const std::shared_ptr<User>& entity) {
        const auto cmd = root_->findSubcommand("update");
        if (!cmd) throw std::runtime_error("UserCommandBuilder: 'update' command usage not found");
        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);
        unsigned int updated = 0;
        for (const auto& field : cmd->optional) {
            if (coin() || updated == 0) {
                oss << ' ' << randomFlagAlias(field.option_tokens);
                oss << ' ' << updateAndResolveVar(entity, field.option_tokens[0]);
                ++updated;
            }
        }
        return oss.str();
    }

    std::string UserCommandBuilder::remove(const std::shared_ptr<User>& entity) {
        const auto cmd = root_->findSubcommand("delete");
        if (!cmd) throw std::runtime_error("UserCommandBuilder: 'delete' command usage not found");
        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);
        oss << " --yes";  // deletion asks first (#133); the harness has no terminal
        return oss.str();
    }

    std::string UserCommandBuilder::info(const std::shared_ptr<User>& entity) {
        const auto cmd = root_->findSubcommand("info");
        if (!cmd) throw std::runtime_error("UserCommandBuilder: 'info' command usage not found");
        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);
        return oss.str();
    }

    std::string UserCommandBuilder::list() {
        const auto cmd = root_->findSubcommand("list");
        if (!cmd) throw std::runtime_error("UserCommandBuilder: 'list' command usage not found");
        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        return oss.str();
    }
}
