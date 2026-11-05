#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"
#include <string>
#include <string_view>

namespace vh::protocols::shell::commands {

namespace {

bool isSetupMatch(const std::string& cmd, const std::string_view input) {
    return isCommandMatch({"setup", cmd}, input);
}

CommandResult handleSetup(const CommandCall& call) {
    if (call.positionals.empty() || hasKey(call, "help") || hasKey(call, "h"))
        return usage(call.constructFullArgs());

    const auto [sub, subcall] = descend(call);

    if (isSetupMatch("assign-admin", sub)) return setup::handleAssignAdmin(subcall);
    if (isSetupMatch("db", sub)) return setup::handleDb(subcall);
    if (isSetupMatch("remote-db", sub)) return setup::handleRemoteDb(subcall);
    if (isSetupMatch("nginx", sub)) return setup::handleNginx(subcall);
    if (isSetupMatch("local-tls", sub)) return setup::handleLocalTls(subcall);
    if (isSetupMatch("set-super-admin-password", sub)) return setup::handleSetSuperAdminPassword(subcall);

    return invalid(call.constructFullArgs(), "Unknown setup subcommand: '" + std::string(sub) + "'");
}

}

void registerSetupCommands(const std::shared_ptr<Router>& r) {
    setup::registerCommands(r);
}

void setup::registerCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("setup"), handleSetup);
}

}
