#include "usages.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::user {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const auto userPos = Positional::WithAliases("username", "Username or ID of the user", {"name", "id"},
                                                   contract::gen::ref("user", {"name", "id"}));
static const auto namePos = Positional::Alias("username", "Username of the user", "name", contract::gen::freshName("user_"));
static const auto nameOpt = Optional::Single("username", "New username for the user", "name", "new_name")
                                .withGen("new_name", contract::gen::freshName("user_"));
static const auto emailOpt = Optional::ManyToOne("email", "Email address of the user", {"email", "e"}, "email")
                                 .withGen("email", contract::gen::email());
static const auto role = Option::Multi("role", "Role name or ID to assign to the user", {"role", "r"}, {"name", "id"})
                             .withGen("name", contract::gen::ref("role.admin", {"name"}))
                             .withGen("id", contract::gen::ref("role.admin", {"id"}));
static const auto linuxUidOpt = Optional::ManyToOne("linux_uid", "Linux UID for system integration",
                                                    {"linux-uid", "uid"}, "id")
                                    .withGen("id", contract::gen::testLinuxId());
static const auto disableFlag = Flag::WithAliases("disable", "Deactivate the account and end its sessions",
                                                  {"disable", "deactivate"});
static const auto enableFlag = Flag::WithAliases("enable", "Reactivate a deactivated account", {"enable", "activate"});

static std::shared_ptr<CommandUsage> list(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "List all users in the system.";
    cmd->optional = listQueryOptions();
    cmd->examples = {
        {"vh users", "List all users in the system."},
        {"vh user", "List all users in the system (using alias)."},
        {"vh u", "List all users in the system (using shortest alias)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> create(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"create", "new", "add", "mk"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Create a new user.";
    cmd->positionals = {namePos};
    cmd->required = {role};
    cmd->optional = {emailOpt, linuxUidOpt};
    cmd->examples = {
        {"vh user create alice --role admin --email alice123@icann.org --linux-uid 1001",
         "Create a new user named 'alice' with admin role, email, and Linux UID."},
        {"vh user new bob --role unprivileged --email bon@icann.org --linux-uid 1002",
         "Create a new user named 'bob' with no admin permissions, email, and Linux UID (using alias)."},
        {"vh u mk charlie --role 2", "Create a new user named 'charlie' with role ID 2 (using shortest alias)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> remove(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"delete", "remove", "rm"};
    cmd->effect = CommandEffect::Destructive;
    cmd->description = "Delete an existing user by username. The user's vaults are destroyed unless ownership is "
                       "transferred with --transfer-to; you are asked to confirm either way.";
    cmd->positionals = {userPos};
    cmd->optional = {Optional::ManyToOne("transfer_to", "Give the user's vaults to this user instead of destroying them",
                                         {"transfer-to"}, "user")
                         .withGen("user", contract::gen::ref("user", {"name", "id"}))};
    cmd->optional_flags = {Flag::Alias("yes", "Delete without asking for confirmation", "yes")};
    cmd->examples = {
        {"vh user delete alice", "Delete the user named 'alice' after confirming; her vaults are destroyed."},
        {"vh user delete alice --transfer-to bob", "Delete 'alice' and give her vaults to 'bob' (administrators only)."},
        {"vh user remove bob --yes", "Delete the user named 'bob' without asking (using alias)."},
        {"vh u rm charlie", "Delete the user named 'charlie' (using shortest alias)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> info(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"info", "show", "get"};
    cmd->effect = CommandEffect::Read;
    cmd->description = "Get information about a specific user by username.";
    cmd->positionals = {userPos};
    cmd->examples = {
        {"vh user info alice", "Get information about the user named 'alice'."},
        {"vh user get bob", "Get information about the user named 'bob' (using alias)."},
        {"vh u show charlie", "Get information about the user named 'charlie' (using shortest alias)."}
    };
    return cmd;
}

static std::shared_ptr<CommandUsage> update(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"update", "set", "modify", "edit"};
    cmd->effect = CommandEffect::Write;
    cmd->description = "Update properties of an existing user.";
    cmd->positionals = {userPos};
    cmd->optional = {nameOpt, emailOpt, Optional(role), linuxUidOpt};
    cmd->optional_flags = {disableFlag, enableFlag};
    cmd->examples = {
        {"vh user update alice --email alice123@icann.org --role unprivileged",
         "Update user 'alice' with a new email and role."},
        {"vh user set bob --name robert --linux-uid 2002",
         "Change username of 'bob' to 'robert' and update Linux UID (using alias)."},
        {"vh user update mallory --disable", "Deactivate 'mallory' and end the account's sessions."},
        {"vh u edit charlie --email charlie@limewire.net --role 3",
         "Update user 'charlie' with a new email and role ID (using shortest alias)."}
    };
    return cmd;
}

// #360: another account's MFA (ops/Mfa.hpp), and the documented host recovery for a user who lost every factor.
static std::shared_ptr<CommandUsage> mfa(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"mfa"};
    cmd->description = "Multi-factor sign-in of a user: status, require, and reset (host recovery). Run it as the "
                       "Linux user bound to your Vaulthalla account, never with sudo: you may act on your own account, "
                       "or on one whose password you may reset; a super admin's only as a super admin.";

    auto status = buildBaseUsage(cmd->weak_from_this());
    status->aliases = {"status", "info", "show"};
    status->effect = CommandEffect::Read;
    status->description = "Whether the user must have MFA and why, their factors (no secrets), recovery codes left, "
                          "and the recovery cooldown.";
    status->positionals = {userPos};
    status->optional_flags = {Flag::WithAliases("json_output", "Print it as JSON", {"json"})};
    status->examples = {{"vh user mfa status alice", "Show alice's sign-in factors."}};

    auto reset = buildBaseUsage(cmd->weak_from_this());
    reset->aliases = {"reset"};
    reset->effect = CommandEffect::Destructive;
    reset->description = "Reset the MFA of a user who lost every factor: their passkeys and authenticator apps are "
                         "disabled, recovery codes voided, every session signed out and the key-backup grants of "
                         "their paired devices revoked (the devices stay paired). They set up a new factor at their "
                         "next sign-in, and key export, device approval, account administration, secrets and settings "
                         "changes wait for the recovery cooldown. Audited and mailed to the security recipients.";
    reset->positionals = {userPos};
    reset->optional = {Optional::ManyToOne("reason", "Why (kept in the audit trail; default: host recovery)",
                                           {"reason"}, "text")
                           .withGen("text", contract::gen::freshName("reason_"))};
    reset->optional_flags = {Flag::Alias("yes", "Reset without asking for confirmation", "yes")};
    reset->examples = {
        {"vh user mfa reset admin", "The sole super admin, as the Linux user bound to 'admin', after losing every factor."},
        {"vh user mfa reset alice --reason \"lost phone, ticket 42\" --yes", "Reset alice's MFA without asking."}};

    auto require = buildBaseUsage(cmd->weak_from_this());
    require->aliases = {"require"};
    require->effect = CommandEffect::Write;
    require->description = "Require MFA for one user whatever the policy level (--off: stop requiring it; the policy "
                           "may still). Applies at the user's next request.";
    require->positionals = {userPos};
    require->optional_flags = {Flag::Alias("off", "Stop requiring MFA for this user", "off")};
    require->examples = {{"vh user mfa require bob", "bob must set up a second factor at his next sign-in."},
                         {"vh user mfa require bob --off", "Back to what the policy says."}};

    cmd->subcommands = {status, reset, require};
    cmd->examples = {{"vh user mfa status alice", "Show alice's sign-in factors."},
                     {"vh user mfa reset alice", "Reset alice's MFA after she lost every factor."}};
    return cmd;
}

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"user", "u"};
    cmd->description = "Manage a single user.";
    cmd->pluralAliasImpliesList = true;

    // ---------- subcommands ----------
    const auto listCmd = list(cmd->weak_from_this());
    const auto createCmd = create(cmd->weak_from_this());
    const auto removeCmd = remove(cmd->weak_from_this());
    const auto infoCmd = info(cmd->weak_from_this());
    const auto updateCmd = update(cmd->weak_from_this());
    const auto mfaCmd = mfa(cmd->weak_from_this());

    // ---------- examples ----------
    cmd->examples = {
        {"vh user create alice --role admin --email alice123@icann.org --linux-uid 1001",
         "Create a new user named 'alice' with admin role, email, and Linux UID."},
        {"vh user delete alice", "Delete the user named 'alice'."},
        {"vh user info alice", "Get information about the user named 'alice'."},
        {"vh user update alice --email alice123@icann.org --role unprivileged",
         "Update user 'alice' with a new email and role."}
    };

    const auto createSingle = TestCommandUsage::Single(createCmd);
    const auto createMultiple = TestCommandUsage::Multiple(createCmd);
    const auto removeSingle = TestCommandUsage::Single(removeCmd);
    const auto removeMultiple = TestCommandUsage::Multiple(removeCmd);
    const auto infoSingle = TestCommandUsage::Single(infoCmd);
    const auto updateSingle = TestCommandUsage::Single(updateCmd);

    // ---------- lifecycles ----------
    // list: better with some users present
    listCmd->test_usage.setup = {createMultiple};
    listCmd->test_usage.teardown = {removeMultiple};

    // create: verify info and update, then remove
    createCmd->test_usage.lifecycle = {infoSingle, updateSingle};
    createCmd->test_usage.teardown = {removeSingle};

    // remove: ensure a user exists first
    removeCmd->test_usage.setup = {createSingle};

    // info: make sure a user exists before querying
    infoCmd->test_usage.setup = {createSingle};
    infoCmd->test_usage.teardown = {removeSingle};

    // update: same as info
    updateCmd->test_usage.setup = {createSingle};
    updateCmd->test_usage.teardown = {removeSingle};

    // ---------- finalize ----------
    cmd->subcommands = {
        listCmd,
        createCmd,
        removeCmd,
        infoCmd,
        updateCmd,
        mfaCmd
    };

    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "User Commands";
    book->root = base(parent);
    return book;
}

}