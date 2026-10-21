#include "fields.hpp"

#include <algorithm>
#include <iterator>
#include <stdexcept>

namespace vh::contract::ws {

std::vector<WsCommandUsage> commands() {
    std::vector<WsCommandUsage> all;
    for (auto&& part : {detail::authCommands(), detail::fsCommands(), detail::groupCommands(), detail::roleCommands(),
                        detail::vaultCommands(), detail::shareCommands(), detail::metaCommands(),
                        detail::upstreamCommands(), detail::recoveryCommands(), detail::shareSessionCommands(),
                        detail::syncCommands(), detail::apiKeyCommands(), detail::permissionCommands(),
                        detail::statsCommands(), detail::dashboardCommands(), detail::s3GatewayCommands(),
                        detail::pricingCommands(), detail::settingsCommands(), detail::emailCommands(),
                        detail::deviceCommands(), detail::vaultKeyCommands()})
        all.insert(all.end(), std::make_move_iterator(part.begin()), std::make_move_iterator(part.end()));

    std::ranges::sort(all, {}, &WsCommandUsage::command);
    if (const auto dup = std::ranges::adjacent_find(all, {}, &WsCommandUsage::command); dup != all.end())
        throw std::logic_error("ws command book declares " + dup->command + " twice");
    return all;
}

}
