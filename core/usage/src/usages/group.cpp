#include "usages.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::group {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const auto namePos = Positional::Alias("group", "Name of the group", "name", contract::gen::freshName("group_"));
static const auto nameOptional = Optional::Single("group", "New name for the group", "name", "new_name")
                                     .withGen("new_name", contract::gen::freshName("group_"));
static const auto groupPos = Positional::WithAliases("group", "Name or ID of the group", {"name", "id"},
                                                    contract::gen::ref("group", {"name", "id"}));
static const auto descriptionOpt = Optional::ManyToOne("description", "Description of the group", {"desc", "d"}, "description")
                                       .withGen("description", contract::gen::pattern("group {a}{a}{a}{a}{a}"));
static const auto linuxGidOpt = Optional::ManyToOne("linux_group", "Linux GID for system integration", {"linux-gid", "gid"}, "id")
                                    .withGen("id", contract::gen::testLinuxId());

static std::shared_ptr<CommandUsage> list(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List all groups in the system.";
    cmd->optional_flags = { jsonFlag };
    cmd->optional = listQueryOptions();
    cmd->examples.push_back({"vh groups", "List all groups."});
    return cmd;
}

static std::shared_ptr<CommandUsage> create(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"create", "new", "add", "mk"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Create a new group.";
    cmd->positionals = { namePos };
    cmd->optional = { descriptionOpt, linuxGidOpt };
    cmd->examples = {
        {"vh group create devs --desc \"Development Team\" --linux-gid 1001", "Create a new group named 'devs'."},
        {"vh group mk admins --linux-gid 2001", "Create a new group named 'admins' with Linux GID 2001 (using alias)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> remove(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"delete", "remove", "del", "rm"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Delete an existing group by name or ID.";
    cmd->positionals = { groupPos };
    cmd->examples = {
        {"vh group delete devs", "Delete the group named 'devs'."},
        {"vh group rm 42", "Delete the group with ID 42 (using alias)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> info(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"info", "show", "get"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Display detailed information about a group.";
    cmd->positionals = { groupPos };
    cmd->examples = {
        {"vh group info devs", "Show information for the group named 'devs'."},
        {"vh group get 42", "Show information for the group with ID 42 (using alias)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> update(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"update", "set", "mod", "modify"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Update properties of an existing group.";
    cmd->positionals = { groupPos };
    cmd->optional = { descriptionOpt, linuxGidOpt, nameOptional };
    return cmd;
}

static std::shared_ptr<CommandUsage> user_list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List all users in a specific group.";
    cmd->pluralAliasImpliesList = true;
    cmd->positionals = { groupPos };
    cmd->examples = {
        {"vh group user list devs", "List all users in the 'devs' group."},
        {"vh group users 42", "List all users in the group with ID 42 (using alias)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> user_add(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"add", "new", "mk"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Add a user to a specific group.";
    cmd->positionals = { groupPos, userPos };
    cmd->examples = {
        {"vh group user add devs alice", "Add user 'alice' to the 'devs' group."},
        {"vh group user add 42 1001", "Add user with ID 1001 to the group with ID 42."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> user_remove(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"remove", "del", "rm"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Remove a user from a specific group.";
    cmd->positionals = { groupPos, userPos };
    cmd->examples.push_back({"vh group user remove devs alice", "Remove user 'alice' from the 'devs' group."});
    cmd->examples.push_back({"vh group user remove 42 1001", "Remove user with ID 1001 from the group with ID 42."});
    return cmd;
}

// Children are attached by base(), which also wires their test usage: building them here as well left two copies,
// and the test usage pointed at the copy nobody kept (expired weak_ptrs).
static std::shared_ptr<CommandUsage> group_user(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"user", "u"};
    cmd->pluralAliasImpliesList = true;
    cmd->description = "Add or remove users from a group.";
    return cmd;
}

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"group", "g"};
    cmd->pluralAliasImpliesList = true;
    cmd->description = "Manage a single group.";
    cmd->examples = {
        {"vh group create devs --desc \"Development Team\" --linux-gid 1001", "Create a new group named 'devs'."},
        {"vh group delete devs", "Delete the group named 'devs'."},
        {"vh group info devs", "Show information for the group named 'devs'."},
        {"vh group update devs --desc \"Updated Description\" --linux-gid 2001", "Update the description and Linux GID of 'devs'."},
        {"vh group user add devs alice", "Add user 'alice' to the 'devs' group."},
        {"vh group user remove devs alice", "Remove user 'alice' from the 'devs' group."},
        {"vh group users devs", "List all users in the 'devs' group."}
    };

    // ---------- build subcommands (stack pointers) ----------
    const auto listCmd        = list(cmd->weak_from_this());
    const auto createCmd      = create(cmd->weak_from_this());
    const auto removeCmd      = remove(cmd->weak_from_this());
    const auto infoCmd        = info(cmd->weak_from_this());
    const auto updateCmd      = update(cmd->weak_from_this());

    // membership subtree
    const auto groupUserCmd   = group_user(cmd->weak_from_this());
    const auto usersCmd       = user_list(groupUserCmd->weak_from_this());
    const auto userAddCmd     = user_add(groupUserCmd->weak_from_this());
    const auto userRmCmd      = user_remove(groupUserCmd->weak_from_this());
    groupUserCmd->subcommands = { userAddCmd, userRmCmd, usersCmd };

    // ---------- test commands ----------
    const auto createMultiple = TestCommandUsage::Multiple(createCmd);
    const auto createSingle = TestCommandUsage::Single(createCmd);
    const auto removeMultiple = TestCommandUsage::Multiple(removeCmd, 0, 0);
    const auto removeSingle = TestCommandUsage::Single(removeCmd);
    const auto infoSingle = TestCommandUsage::Single(infoCmd);
    const auto updateSingle = TestCommandUsage::Single(updateCmd);
    const auto usersSingle = TestCommandUsage::Single(usersCmd);
    const auto userAddSingle = TestCommandUsage::Single(userAddCmd);
    const auto userAddMultiple = TestCommandUsage::Multiple(userAddCmd);
    const auto userRmSingle = TestCommandUsage::Single(userRmCmd);
    const auto userRmMultiple = TestCommandUsage::Multiple(userRmCmd);

    // list: should tolerate empty; best with a few groups present
    listCmd->test_usage.setup = { createMultiple };
    listCmd->test_usage.teardown = { removeMultiple };

    // create: verify info/update/users, then clean
    createCmd->test_usage.lifecycle = { infoSingle, updateSingle, usersSingle };
    createCmd->test_usage.teardown = { removeSingle };

    // remove: ensure a group exists first
    removeCmd->test_usage.setup = { createSingle };

    // info: exercise on fresh groups; clean them up
    infoCmd->test_usage.setup = { createMultiple };
    infoCmd->test_usage.teardown = { removeMultiple };

    // update: same as info; validate round-trips don’t corrupt invariants
    updateCmd->test_usage.setup = { createMultiple };
    updateCmd->test_usage.teardown = { removeMultiple };

    // users (list members): make sure members exist, then remove them, then delete group
    usersCmd->test_usage.setup = { createSingle, userAddMultiple };
    usersCmd->test_usage.teardown = { userRmMultiple, removeSingle };

    // membership add: ensure group exists; list users afterward; clean up
    userAddCmd->test_usage.setup = { createSingle };
    userAddCmd->test_usage.lifecycle = { usersSingle };
    userAddCmd->test_usage.teardown = { userRmSingle, removeSingle };

    // membership remove: ensure group + at least one member
    userRmCmd->test_usage.setup = { createSingle, userAddSingle };
    userRmCmd->test_usage.lifecycle = { usersSingle };
    userRmCmd->test_usage.teardown = { removeSingle };

    // ---------- finalize ----------
    cmd->subcommands = {
        listCmd,
        createCmd,
        removeCmd,
        infoCmd,
        updateCmd,
        usersCmd,      // expose "vh group users" as sibling
        groupUserCmd   // expose "vh group user [add|remove]"
    };

    return cmd;
}


std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Group Commands";
    book->root = base(parent);
    return book;
}

}
