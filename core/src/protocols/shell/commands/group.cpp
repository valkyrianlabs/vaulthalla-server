#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/types.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "protocols/shell/util/runOp.hpp"
#include "ops/Groups.hpp"
#include "include/identities/Group.hpp"
#include "identities/User.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include "CommandUsage.hpp"

using namespace vh;
using namespace vh::protocols::shell;
using vh::identities::User;
using vh::identities::Group;

// CLI syntax only: a numeric positional names a group or user by id, anything else by name.
static ops::groups::Ref groupCliRef(const std::string& nameOrId) {
    if (const auto id = parseUInt(nameOrId)) return *id;
    return nameOrId;
}

static std::optional<unsigned int> groupLinuxGidOption(const CommandCall& call, const std::shared_ptr<CommandUsage>& usage) {
    const auto value = optVal(call, usage->resolveOptional("linux-gid")->option_tokens);
    if (!value) return std::nullopt;
    const auto parsed = parseUInt(*value);
    if (!parsed || *parsed == 0) throw ops::Invalid("--linux-gid must be a positive integer");
    return parsed;
}

static CommandResult handle_group_create(const CommandCall& call) {
    const auto usage = resolveUsage({"group", "create"});
    validatePositionals(call, usage);

    return runOp("group create", [&] {
        return ops::groups::create(call.user, {
            .name = call.positionals[0],
            .description = optVal(call, usage->resolveOptional("description")->option_tokens).value_or(""),
            .linux_gid = groupLinuxGidOption(call, usage)
        });
    }, [](const auto& group) { return "Successfully created new group:\n" + to_string(group); });
}

static CommandResult handle_group_update(const CommandCall& call) {
    const auto usage = resolveUsage({"group", "update"});
    validatePositionals(call, usage);

    return runOp("group update", [&] {
        return ops::groups::update(call.user, {
            .group = groupCliRef(call.positionals[0]),
            .name = optVal(call, usage->resolveOptional("name")->option_tokens),
            .description = optVal(call, usage->resolveOptional("description")->option_tokens),
            .linux_gid = groupLinuxGidOption(call, usage)
        });
    }, [](const auto& group) { return "Successfully updated group:\n" + to_string(group); });
}

static CommandResult handle_group_delete(const CommandCall& call) {
    const auto usage = resolveUsage({"group", "delete"});
    validatePositionals(call, usage);

    return runOp("group delete", [&] { return ops::groups::remove(call.user, groupCliRef(call.positionals[0])); },
        [](const auto& group) {
            return "Successfully deleted group '" + group->name() + "' (ID: " + std::to_string(group->id) + ")";
        });
}

static CommandResult handle_group_info(const CommandCall& call) {
    const auto usage = resolveUsage({"group", "info"});
    validatePositionals(call, usage);

    return runOp("group info", [&] { return ops::groups::get(call.user, groupCliRef(call.positionals[0])); },
        [](const auto& group) { return to_string(group); });
}

static CommandResult handle_group_list(const CommandCall& call) {
    const auto usage = resolveUsage({"group", "list"});
    validatePositionals(call, usage);

    return runOp("group list", [&] { return ops::groups::list(call.user, parseListQuery(call)); },
        [](const auto& groups) { return to_string(groups); });
}

static CommandResult handle_group_add_user(const CommandCall& call) {
    const auto usage = resolveUsage({"group", "user", "add"});
    validatePositionals(call, usage);

    return runOp("group user add", [&] {
        return ops::groups::addMember(call.user, {
            .group = groupCliRef(call.positionals[0]),
            .user = groupCliRef(call.positionals[1])
        });
    }, [&](const auto& group) {
        return "Successfully added user '" + call.positionals[1] + "' to group '" + group->name() + "'";
    });
}

static CommandResult handle_group_remove_user(const CommandCall& call) {
    const auto usage = resolveUsage({"group", "user", "remove"});
    validatePositionals(call, usage);

    return runOp("group user remove", [&] {
        return ops::groups::removeMember(call.user, {
            .group = groupCliRef(call.positionals[0]),
            .user = groupCliRef(call.positionals[1])
        });
    }, [&](const auto& group) {
        return "Successfully removed user '" + call.positionals[1] + "' from group '" + group->name() + "'";
    });
}

static CommandResult handle_group_list_users(const CommandCall& call) {
    if (call.positionals.empty()) return invalid("group user list: missing group name or ID");
    return runOp("group user list", [&] { return ops::groups::members(call.user, groupCliRef(call.positionals[0])); },
        [](const auto& members) { return to_string(members); });
}

static bool isGroupUserMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"group", "user", cmd}, input);
}

static CommandResult handle_group_user(const CommandCall& call) {
    const auto [action, subcall] = descend(call);
    if (isGroupUserMatch("add", action)) return handle_group_add_user(subcall);
    if (isGroupUserMatch("remove", action)) return handle_group_remove_user(subcall);
    if (isGroupUserMatch("list", action)) return handle_group_list_users(subcall);
    return invalid(call.constructFullArgs(), "Unknown group user action: '" + std::string(action) + "'");
}

static bool isGroupMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"group", cmd}, input);
}

static CommandResult handle_group(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);

    if (isGroupMatch("create", sub)) return handle_group_create(subcall);
    if (isGroupMatch("update", sub)) return handle_group_update(subcall);
    if (isGroupMatch("delete", sub)) return handle_group_delete(subcall);
    if (isGroupMatch("info", sub)) return handle_group_info(subcall);
    if (isGroupMatch("list", sub)) return handle_group_list(subcall);
    if (isGroupMatch("user", sub)) return handle_group_user(subcall);

    return invalid(call.constructFullArgs(), "Unknown group subcommand: '" + std::string(sub) + "'");
}

void commands::registerGroupCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("group"), handle_group);
}
