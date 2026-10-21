// `vh mcp` and `vh skill` run inside the vh client and never reach a current daemon. They are registered here so the
// daemon's help, option checks and usage tests know them, and so an older vh client that forwards them gets a clear
// answer instead of "unknown command".

#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/helpers.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/util/argsHelpers.hpp"
#include "runtime/Deps.hpp"
#include "usage/include/UsageManager.hpp"

#include <string>

namespace vh::protocols::shell::commands {

namespace {

CommandResult handleClientSide(const CommandCall& call) {
    if (hasKey(call, "help") || hasKey(call, "h")) return usage(call.constructFullArgs());
    return invalid("vh " + call.name + " runs in the vh client itself; this vh is older than the daemon. "
                   "Use the vh installed with this version of Vaulthalla.");
}

}

void registerClientCommands(const std::shared_ptr<Router>& r) {
    const auto usageManager = runtime::Deps::get().shellUsageManager;
    r->registerCommand(usageManager->resolve("mcp"), handleClientSide);
    r->registerCommand(usageManager->resolve("skill"), handleClientSide);
}

}
