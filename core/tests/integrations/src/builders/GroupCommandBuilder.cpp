#include "cmd/Builder.hpp"
#include "entity/Edit.hpp"
#include "cmd/generators.hpp"
#include "cli/Context.hpp"
#include "CommandUsage.hpp"

using namespace vh::protocols::shell;
using vh::identities::User;
using vh::identities::Group;

namespace vh::test::integration::cmd {
    GroupCommandBuilder::GroupCommandBuilder(const std::shared_ptr<UsageManager>& usage, const std::shared_ptr<cli::Context>& ctx)
        : Builder(usage, ctx, "group"), groupAliases_(ctx) {}

    std::string GroupCommandBuilder::updateAndResolveVar(const std::shared_ptr<Group>& entity, const std::string& field) {
        const std::string usagePath = "group/update";

        if (groupAliases_.isName(field)) {
            entity::edit(entity, [&](auto& s) { s.name = generateName(usagePath); });
            return entity->name();
        }

        if (groupAliases_.isDescription(field)) {
            if (coin()) {
                const auto desc = generateDescription(usagePath);
                entity::edit(entity, [&](auto& s) { s.description = std::make_optional(desc); });
                return desc;
            }
            entity::edit(entity, [&](auto& s) { s.description = std::make_optional(std::string("")); });
            return "";
        }

        if (groupAliases_.isLinuxGID(field)) {
            const auto gid = randomLinuxId();
            entity::edit(entity, [&](auto& s) { s.linux_gid = std::make_optional(gid); });
            return std::to_string(gid);
        }

        throw std::runtime_error("GroupCommandBuilder: unsupported group field for update: " + field);
    }

    static std::optional<std::string> resolveVar(const std::string& name, const std::shared_ptr<Group>& group) {
        if (name == "id" || name == "group_id") return std::to_string(group->id);
        if (name == "name" || name == "group_name") return group->name();
        if (name == "description" || name == "desc") return group->description();
        throw std::runtime_error("GroupCommandBuilder: unsupported group field for resolveVar: " + name);
    }

    static std::string randomizePrimaryPositional(const std::shared_ptr<Group>& entity) {
        if (coin()) return std::to_string(entity->id);
        return entity->name();
    }

    static std::string randomizeSecondaryPositional(const std::shared_ptr<User>& entity) {
        if (coin()) return std::to_string(entity->id);
        return entity->name();
    }

    std::string GroupCommandBuilder::create(const std::shared_ptr<Group>& entity) {
        const auto cmd = root_->findSubcommand("create");
        if (!cmd) throw std::runtime_error("GroupCommandBuilder: 'create' command usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases) << ' ' << entity->name();
        for (const auto& opt : cmd->required) {
            oss << ' ' << randomAlias(opt.option_tokens);
            if (auto val = resolveVar(opt.option_tokens[0], entity); val) oss << ' ' << *val;
            else throw std::runtime_error("GroupCommandBuilder: unsupported group field for create: " + opt.option_tokens[0]);
        }
        return oss.str();
    }

    std::string GroupCommandBuilder::update(const std::shared_ptr<Group>& entity) {
        const auto cmd = root_->findSubcommand("update");
        if (!cmd) throw std::runtime_error("GroupCommandBuilder: 'update' command usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);

        unsigned int updated = 0;
        for (const auto& opt : cmd->optional) {
            if (coin() || updated == 0) {
                oss << ' ' << randomFlagAlias(opt.option_tokens);
                if (opt.label.contains("description")) oss << ' ' << quoted(updateAndResolveVar(entity, opt.option_tokens[0]));
                else oss << ' ' << updateAndResolveVar(entity, opt.option_tokens[0]);
                ++updated;
            }
        }

        return oss.str();
    }

    std::string GroupCommandBuilder::remove(const std::shared_ptr<Group>& entity) {
        const auto cmd = root_->findSubcommand("delete");
        if (!cmd) throw std::runtime_error("GroupCommandBuilder: 'delete' command usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);
        return oss.str();
    }

    std::string GroupCommandBuilder::info(const std::shared_ptr<Group>& entity) {
        const auto cmd = root_->findSubcommand("info");
        if (!cmd) throw std::runtime_error("GroupCommandBuilder: 'info' command usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        oss << ' ' << randomizePrimaryPositional(entity);
        return oss.str();
    }

    std::string GroupCommandBuilder::list() {
        const auto cmd = root_->findSubcommand("list");
        if (!cmd) throw std::runtime_error("GroupCommandBuilder: 'list' command usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(cmd->aliases);
        for (const auto& flag : cmd->optional_flags)
            if (generateRandomIndex(10000) < 5000) oss << " --" << randomAlias(flag.aliases);
        return oss.str();
    }

    std::string GroupCommandBuilder::addUser(const std::shared_ptr<Group>& entity, const std::shared_ptr<User>& user) const {
        const auto baseCmd = root_->findSubcommand("user");
        if (!baseCmd) throw std::runtime_error("GroupCommandBuilder: 'group user' command usage not found");
        const auto addCmd = baseCmd->findSubcommand("add");
        if (!addCmd) throw std::runtime_error("GroupCommandBuilder: 'group user add' command usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(baseCmd->aliases) << ' ' << randomAlias(addCmd->aliases);

        for (const auto& pos : addCmd->positionals) {
            if (pos.label == "group") oss << ' ' << randomizePrimaryPositional(entity);
            else if (pos.label == "user") oss << ' ' << randomizeSecondaryPositional(user);
            else throw std::runtime_error("GroupCommandBuilder: unsupported positional in 'group user add': " + pos.label);
        }

        return oss.str();
    }

    std::string GroupCommandBuilder::removeUser(const std::shared_ptr<Group>& entity, const std::shared_ptr<User>& user) const {
        const auto baseCmd = root_->findSubcommand("user");
        if (!baseCmd) throw std::runtime_error("GroupCommandBuilder: 'group user' command usage not found");
        const auto rmCmd = baseCmd->findSubcommand("remove");
        if (!rmCmd) throw std::runtime_error("GroupCommandBuilder: 'group user remove' command usage not found");

        std::ostringstream oss;
        oss << "vh " << randomAlias(root_->aliases) << ' ' << randomAlias(baseCmd->aliases) << ' ' << randomAlias(rmCmd->aliases);
        for (const auto& pos : rmCmd->positionals) {
            if (pos.label == "group") oss << ' ' << randomizePrimaryPositional(entity);
            else if (pos.label == "user") oss << ' ' << randomizeSecondaryPositional(user);
            else throw std::runtime_error("GroupCommandBuilder: unsupported positional in 'group user remove': " + pos.label);
        }
        return oss.str();
    }
}
