#pragma once

#include "protocols/shell/types.hpp"
#include "protocols/shell/Fwd.hpp"

#include <memory>

namespace vh::protocols::shell::commands {

void registerSetupCommands(const std::shared_ptr<Router>& r);

namespace setup {
    void registerCommands(const std::shared_ptr<Router>& r);

    CommandResult handleAssignAdmin(const CommandCall& call);
    CommandResult handleDb(const CommandCall& call);
    CommandResult handleRemoteDb(const CommandCall& call);
    CommandResult handleNginx(const CommandCall& call);
    CommandResult handleLocalTls(const CommandCall& call);
    CommandResult handleSetSuperAdminPassword(const CommandCall& call);
}

}
