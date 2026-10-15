#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "protocols/shell/commands/rbac.hpp"
#include "protocols/shell/Router.hpp"
#include "CommandUsage.hpp"

void vh::protocols::shell::commands::registerAllCommands(const std::shared_ptr<Router>& r) {
    vault::registerCommands(r);
    rbac::registerCommands(r);
    registerAPIKeyCommands(r);
    registerSystemCommands(r);
    registerUserCommands(r);
    registerGroupCommands(r);
    registerSecretsCommands(r);
    registerEmailCommands(r);
    registerPricingCommands(r);
    registerSyncCommands(r);
    registerS3GatewayCommands(r);
    registerSetupCommands(r);
    registerTeardownCommands(r);
    registerStatusCommands(r);
    registerFsCommands(r);
    registerUpstreamCommands(r);
}
