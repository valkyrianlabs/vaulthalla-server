#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"

#include <string>
#include <string_view>
#include <vector>
#include <memory>

using namespace vh;
using namespace vh::protocols::shell;
using namespace vh::protocols::shell::commands::vault;

static bool isVaultMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"vault", cmd}, input);
}

static CommandResult handle_vault(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);

    if (isVaultMatch("sync", sub)) return handle_sync(subcall);
    if (isVaultMatch("list", sub)) return handle_vaults_list(subcall);
    if (isVaultMatch("info", sub)) return handle_vault_info(subcall);
    if (isVaultMatch("create", sub)) return handle_vault_create(subcall);
    if (isVaultMatch("update", sub)) return handle_vault_update(subcall);
    if (isVaultMatch("delete", sub)) return handle_vault_delete(subcall);
    if (isVaultMatch("restore", sub)) return handle_vault_restore(subcall);
    if (isVaultMatch("deleted", sub)) return handle_vaults_deleted(subcall);
    if (isVaultMatch("keys", sub)) return handle_vault_keys(subcall);
    if (isVaultMatch("role", sub)) return handle_vault_role(subcall);
    if (isVaultMatch("recovery", sub)) return handle_vault_recovery(subcall);

    return invalid(call.constructFullArgs(), "Unknown vault subcommand: '" + std::string(sub) + "'");
}

void commands::vault::registerCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("vault"), handle_vault);
}
