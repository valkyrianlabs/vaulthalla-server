#pragma once

#include <memory>
#include "protocols/shell/Fwd.hpp"

namespace vh::protocols::shell::commands {

void registerAllCommands(const std::shared_ptr<Router>& r);

void registerAPIKeyCommands(const std::shared_ptr<Router>& r);
void registerSystemCommands(const std::shared_ptr<Router>& r);
void registerUserCommands(const std::shared_ptr<Router>& r);
void registerGroupCommands(const std::shared_ptr<Router>& r);
void registerSecretsCommands(const std::shared_ptr<Router>& r);
void registerEmailCommands(const std::shared_ptr<Router>& r);
void registerPricingCommands(const std::shared_ptr<Router>& r);
void registerSyncCommands(const std::shared_ptr<Router>& r);
void registerS3GatewayCommands(const std::shared_ptr<Router>& r);
void registerSetupCommands(const std::shared_ptr<Router>& r);
void registerTeardownCommands(const std::shared_ptr<Router>& r);
void registerStatusCommands(const std::shared_ptr<Router>& r);
void registerFsCommands(const std::shared_ptr<Router>& r);
void registerUpstreamCommands(const std::shared_ptr<Router>& r);
void registerRecoveryCommands(const std::shared_ptr<Router>& r);
void registerSnapshotCommands(const std::shared_ptr<Router>& r);
void registerDeviceCommands(const std::shared_ptr<Router>& r);
// `vh mcp`, `vh skill`: client-side commands (commands/client.cpp).
void registerClientCommands(const std::shared_ptr<Router>& r);

}
