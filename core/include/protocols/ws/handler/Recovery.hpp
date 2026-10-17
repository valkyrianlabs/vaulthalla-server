#pragma once

#include <memory>
#include <nlohmann/json_fwd.hpp>
#include "protocols/ws/Fwd.hpp"

// ws recovery.* and vault.recovery.*: adapters from payloads to ops::recovery. Payloads are read with the
// ops/RecoveryJson.hpp readers and answered with its shapes; NeedsConfirmation codes are the ops::recovery ones.
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Recovery {
    static json list(const json& payload, const std::shared_ptr<Session>& session);
    static json inspect(const json& payload, const std::shared_ptr<Session>& session);
    static json plan(const json& payload, const std::shared_ptr<Session>& session);
    static json planGet(const json& payload, const std::shared_ptr<Session>& session);
    static json restore(const json& payload, const std::shared_ptr<Session>& session);
    static json snapshotCreate(const json& payload, const std::shared_ptr<Session>& session);
    static json pointDelete(const json& payload, const std::shared_ptr<Session>& session);
    static json costs(const json& payload, const std::shared_ptr<Session>& session);

    static json vaultStatus(const json& payload, const std::shared_ptr<Session>& session);
    static json vaultUpdate(const json& payload, const std::shared_ptr<Session>& session);
    static json vaultDisclosure(const json& payload, const std::shared_ptr<Session>& session);
    static json vaultSuspend(const json& payload, const std::shared_ptr<Session>& session);
};

}
