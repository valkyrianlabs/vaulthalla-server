#include "fields.hpp"

#include <algorithm>
#include <array>
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
                        detail::deviceCommands(), detail::vaultKeyCommands(), detail::auditCommands()})
        all.insert(all.end(), std::make_move_iterator(part.begin()), std::make_move_iterator(part.end()));

    std::ranges::sort(all, {}, &WsCommandUsage::command);
    // #359: the step-up families, from their one table.
    for (const auto& row : stepUpTable()) {
        const auto it = std::ranges::find(all, row.command, &WsCommandUsage::command);
        if (it == all.end()) throw std::logic_error("step-up table names " + row.command + ", which the book lacks");
        it->step_up = row.family;
        if (std::ranges::find(it->refusal_codes, "step_up_required") == it->refusal_codes.end())
            it->refusal_codes.emplace_back("step_up_required");
        // #360: the recovery cooldown's families (auth::stepup::cooldownFamily) refuse while it runs.
        static constexpr std::array kCooldownFamilies{"keys", "device.trust", "identity.admin", "secrets", "settings"};
        if (std::ranges::find(kCooldownFamilies, row.family) != kCooldownFamilies.end() &&
            std::ranges::find(it->refusal_codes, "recovery_cooldown") == it->refusal_codes.end())
            it->refusal_codes.emplace_back("recovery_cooldown");
    }
    if (const auto dup = std::ranges::adjacent_find(all, {}, &WsCommandUsage::command); dup != all.end())
        throw std::logic_error("ws command book declares " + dup->command + " twice");
    return all;
}

}
