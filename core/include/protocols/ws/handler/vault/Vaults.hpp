#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"
#include "ops/Vaults.hpp"

namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Vaults {
    static json list(const std::shared_ptr<Session>& session);
    static json add(const json& payload, const std::shared_ptr<Session>& session);
    static json update(const json& payload, const std::shared_ptr<Session>& session);
    // Safe deletion (#162): remove schedules (or, with now, purges on the next pass); see ops::vaults::Remove.
    static json remove(const json& payload, const std::shared_ptr<Session>& session);
    static json removalPlan(const json& payload, const std::shared_ptr<Session>& session);
    static json listDeleted(const std::shared_ptr<Session>& session);
    static json restore(const json& payload, const std::shared_ptr<Session>& session);
    static json get(const json& payload, const std::shared_ptr<Session>& session);
    static json sync(const json& payload, const std::shared_ptr<Session>& session);

    // The JSON storage.vault.get and storage.vault.remove.plan answer with (the contract's Vault and VaultRemovalPlan
    // models; core/tests/unit/contract/models_vaults.cpp checks them).
    static json detailsJson(const ops::vaults::Details& details);
    static json removalPlanJson(const ops::vaults::RemovalPlan& plan);
};

} // namespace vh::websocket
