#include "usages.hpp"

using namespace vh::protocols::shell;

namespace vh::protocols::shell::role {

static std::shared_ptr<CommandUsage> buildBaseUsage(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = std::make_shared<CommandUsage>();
    cmd->parent = parent;
    return cmd;
}

static const auto rolePos = Positional::WithAliases("role", "ID or name of the role", {"id", "name"});
static const auto newRolePos = Positional::Alias("role_name", "Name for the new role", "name", contract::gen::freshName("role_"));
static const auto descriptionOpt = Optional::ManyToOne("description", "Description of the role", {"description", "desc", "d"}, "description")
                                       .withGen("description", contract::gen::pattern("role {a}{a}{a}{a}{a}"));
static const auto roleNameOpt = Optional::Single("role_name", "New name for the role", "name", "new_name")
                                    .withGen("new_name", contract::gen::freshName("role_"));
static const auto inheritFrom = Optional::OneToMany("inherit_from", "Inherit permissions from an existing role ID or name", "from", {"id", "name"});

// The same entries name an admin role under `vh role admin` and a vault role under `vh role vault`.
static Positional rolePosFor(const std::string& entity) { return rolePos.withGen(contract::gen::ref(entity, {"id", "name"})); }

static Optional inheritFromFor(const std::string& entity) {
    return inheritFrom.withGen("id", contract::gen::ref(entity, {"id"})).withGen("name", contract::gen::ref(entity, {"name"}));
}

static const auto adminRolePos = rolePosFor("role.admin");
static const auto vaultRolePos = rolePosFor("role.vault");
static const auto adminInheritFrom = inheritFromFor("role.admin");
static const auto vaultInheritFrom = inheritFromFor("role.vault");

static std::shared_ptr<CommandUsage> admin_list(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->description = "List all admin roles in the system.";
    cmd->optional_flags = { jsonFlag };
    cmd->optional = listQueryOptions();
    cmd->examples.push_back({"vh role admin list", "List all admin roles."});
    cmd->examples.push_back({"vh role admin list --json", "List all admin roles in JSON format."});
    return cmd;
}

static std::shared_ptr<CommandUsage> admin_info(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"info", "show", "get"};
    cmd->description = "Display detailed information about a specific admin role.";
    cmd->positionals = { adminRolePos };
    cmd->examples.push_back({"vh role admin info super_admin", "Show information for the admin role named 'super_admin'."});
    cmd->examples.push_back({"vh role admin info 42", "Show information for the admin role with ID 42."});
    return cmd;
}

static std::shared_ptr<CommandUsage> admin_create(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"create", "new", "add", "mk"};
    cmd->description = "Create a new admin role with specified permissions.";
    cmd->positionals = { newRolePos };
    cmd->optional = { descriptionOpt, adminInheritFrom };
    cmd->examples.push_back({"vh role admin create audit_reader --description \"Read-only audit access\" --allow-audit-view",
                            "Create a new admin role named 'audit_reader' with audit viewing permission."});
    cmd->examples.push_back({"vh role admin create user_ops --allow-users-view --allow-users-edit",
                            "Create a new admin role named 'user_ops' with user identity management permissions."});
    cmd->examples.push_back({"vh role admin create settings_admin --from super_admin --deny-settings-services-edit",
                            "Create a new admin role from 'super_admin' and revoke service settings edit permission."});
    cmd->option_prefixes = {"allow-", "deny-"};
    return cmd;
}

static std::shared_ptr<CommandUsage> admin_update(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"update", "set", "modify", "edit"};
    cmd->description = "Update properties and permissions of an existing admin role.";
    cmd->positionals = { adminRolePos };
    cmd->optional = { descriptionOpt, roleNameOpt };
    cmd->examples.push_back({"vh role admin update audit_reader --name audit_observer --allow-audit-view",
                            "Rename 'audit_reader' to 'audit_observer' and ensure audit viewing permission is granted."});
    cmd->examples.push_back({"vh role admin update user_ops --deny-users-edit",
                            "Revoke user identity modification permission from 'user_ops'."});
    cmd->examples.push_back({"vh role admin update settings_admin --deny-settings-share-edit --deny-settings-services-edit",
                            "Revoke sharing and services settings edit permissions from 'settings_admin'."});
    cmd->examples.push_back({"vh role admin update support --allow-stats-view",
                            "Let the 'support' role view runtime health and system stats (the console's Health area)."});
    cmd->examples.push_back({"vh role admin update support --allow-upstream-view --allow-upstream-protect",
                            "Let the 'support' role see upstream bucket inventory and protect buckets (not unprotect them)."});
    cmd->option_prefixes = {"allow-", "deny-"};
    return cmd;
}

static std::shared_ptr<CommandUsage> admin_remove(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"delete", "remove", "del", "rm"};
    cmd->description = "Delete an existing admin role by ID or name.";
    cmd->positionals = { adminRolePos };
    cmd->examples.push_back({"vh role admin delete audit_reader", "Delete the admin role named 'audit_reader'."});
    cmd->examples.push_back({"vh role admin rm 42", "Delete the admin role with ID 42."});
    return cmd;
}

static std::shared_ptr<CommandUsage> vault_list(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"list", "ls"};
    cmd->description = "List all vault roles in the system.";
    cmd->optional_flags = { jsonFlag };
    cmd->optional = listQueryOptions();
    cmd->examples.push_back({"vh role vault list", "List all vault roles."});
    cmd->examples.push_back({"vh role vault list --json", "List all vault roles in JSON format."});
    return cmd;
}

static std::shared_ptr<CommandUsage> vault_info(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"info", "show", "get"};
    cmd->description = "Display detailed information about a specific vault role.";
    cmd->positionals = { vaultRolePos };
    cmd->examples.push_back({"vh role vault info power_user", "Show information for the vault role named 'power_user'."});
    cmd->examples.push_back({"vh role vault info 7", "Show information for the vault role with ID 7."});
    return cmd;
}

static std::shared_ptr<CommandUsage> vault_create(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"create", "new", "add", "mk"};
    cmd->description = "Create a new vault role with specified permissions.";
    cmd->positionals = { newRolePos };
    cmd->optional = { descriptionOpt, vaultInheritFrom };
    cmd->examples.push_back({"vh role vault create uploader --description \"Upload-only vault role\" --allow-files-upload --allow-dirs-upload",
                            "Create a vault role named 'uploader' with file and directory upload permissions."});
    cmd->examples.push_back({"vh role vault create publisher --allow-files-share-public --allow-files-share-public_with_val",
                            "Create a vault role named 'publisher' with public sharing permissions."});
    cmd->examples.push_back({"vh role vault create sync_operator --from power_user --allow-sync-action-trigger --deny-files-delete",
                            "Create a vault role from 'power_user', allow sync triggering, and revoke file deletion."});
    cmd->option_prefixes = {"allow-", "deny-"};
    return cmd;
}

static std::shared_ptr<CommandUsage> vault_update(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"update", "set", "modify", "edit"};
    cmd->description = "Update properties and permissions of an existing vault role.";
    cmd->positionals = { vaultRolePos };
    cmd->optional = { descriptionOpt, roleNameOpt };
    cmd->examples.push_back({"vh role vault update uploader --name ingest_only --allow-files-upload --allow-dirs-upload",
                            "Rename 'uploader' to 'ingest_only' and ensure upload permissions are granted."});
    cmd->examples.push_back({"vh role vault update publisher --deny-files-share-public",
                            "Revoke public sharing permission from 'publisher'."});
    cmd->examples.push_back({"vh role vault update power_user --allow-files-rename --allow-dirs-rename --deny-files-delete",
                            "Grant rename permissions and revoke file deletion for 'power_user'."});
    cmd->option_prefixes = {"allow-", "deny-"};
    return cmd;
}

static std::shared_ptr<CommandUsage> vault_remove(const std::weak_ptr<CommandUsage>& parent) {
    const auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"delete", "remove", "del", "rm"};
    cmd->description = "Delete an existing vault role by ID or name.";
    cmd->positionals = { vaultRolePos };
    cmd->examples.push_back({"vh role vault delete uploader", "Delete the vault role named 'uploader'."});
    cmd->examples.push_back({"vh role vault rm 7", "Delete the vault role with ID 7."});
    return cmd;
}

static std::shared_ptr<CommandUsage> admin_base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"admin", "a"};
    cmd->description = "Manage admin roles.";

    const auto listCmd   = admin_list(cmd->weak_from_this());
    const auto createCmd = admin_create(cmd->weak_from_this());
    const auto removeCmd = admin_remove(cmd->weak_from_this());
    const auto infoCmd   = admin_info(cmd->weak_from_this());
    const auto updateCmd = admin_update(cmd->weak_from_this());

    const auto createSingle = TestCommandUsage::Single(createCmd);
    const auto createMultiple = TestCommandUsage::Multiple(createCmd);
    const auto removeSingle = TestCommandUsage::Single(removeCmd);
    const auto removeMultiple = TestCommandUsage::Multiple(removeCmd);
    const auto infoSingle = TestCommandUsage::Single(infoCmd);
    const auto updateSingle = TestCommandUsage::Single(updateCmd);

    listCmd->test_usage.setup = { createMultiple };
    listCmd->test_usage.teardown = { removeMultiple };

    createCmd->test_usage.lifecycle = { infoSingle, updateSingle };
    createCmd->test_usage.teardown = { removeSingle };

    removeCmd->test_usage.setup = { createSingle };

    infoCmd->test_usage.setup = { createMultiple };
    infoCmd->test_usage.teardown = { removeMultiple };

    updateCmd->test_usage.setup = { createMultiple };
    updateCmd->test_usage.teardown = { removeMultiple };

    cmd->subcommands = { listCmd, createCmd, removeCmd, infoCmd, updateCmd };
    return cmd;
}

static std::shared_ptr<CommandUsage> vault_base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"vault", "v"};
    cmd->description = "Manage vault roles.";

    const auto listCmd   = vault_list(cmd->weak_from_this());
    const auto createCmd = vault_create(cmd->weak_from_this());
    const auto removeCmd = vault_remove(cmd->weak_from_this());
    const auto infoCmd   = vault_info(cmd->weak_from_this());
    const auto updateCmd = vault_update(cmd->weak_from_this());

    const auto createSingle = TestCommandUsage::Single(createCmd);
    const auto createMultiple = TestCommandUsage::Multiple(createCmd);
    const auto removeSingle = TestCommandUsage::Single(removeCmd);
    const auto removeMultiple = TestCommandUsage::Multiple(removeCmd);
    const auto infoSingle = TestCommandUsage::Single(infoCmd);
    const auto updateSingle = TestCommandUsage::Single(updateCmd);

    listCmd->test_usage.setup = { createMultiple };
    listCmd->test_usage.teardown = { removeMultiple };

    createCmd->test_usage.lifecycle = { infoSingle, updateSingle };
    createCmd->test_usage.teardown = { removeSingle };

    removeCmd->test_usage.setup = { createSingle };

    infoCmd->test_usage.setup = { createMultiple };
    infoCmd->test_usage.teardown = { removeMultiple };

    updateCmd->test_usage.setup = { createMultiple };
    updateCmd->test_usage.teardown = { removeMultiple };

    cmd->subcommands = { listCmd, createCmd, removeCmd, infoCmd, updateCmd };
    return cmd;
}

static std::shared_ptr<CommandUsage> base(const std::weak_ptr<CommandUsage>& parent) {
    auto cmd = buildBaseUsage(parent);
    cmd->aliases = {"role", "roles", "r"};
    cmd->pluralAliasImpliesList = false;
    cmd->description = "Manage admin and vault roles.";

    const auto adminCmd = admin_base(cmd->weak_from_this());
    const auto vaultCmd = vault_base(cmd->weak_from_this());

    cmd->subcommands = { adminCmd, vaultCmd };
    return cmd;
}

std::shared_ptr<CommandBook> get(const std::weak_ptr<CommandUsage>& parent) {
    const auto book = std::make_shared<CommandBook>();
    book->title = "Role Commands";
    book->root = base(parent);
    return book;
}

}
