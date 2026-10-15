#pragma once

#include <memory>
#include <nlohmann/json_fwd.hpp>
#include "protocols/ws/Fwd.hpp"

// ws upstream.* (#237, #96): adapters from payloads to ops::upstream; JSON shapes come from ops/UpstreamJson.hpp.
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Upstream {
    static json adminEnable(const json& payload, const std::shared_ptr<Session>& session);
    static json adminDisable(const json& payload, const std::shared_ptr<Session>& session);
    static json adminStatus(const json& payload, const std::shared_ptr<Session>& session);

    static json bucketList(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketProtect(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketUnprotect(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketInspect(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketLifecycleSet(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketAdoptPreflight(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketDetach(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketCleanupPreflight(const json& payload, const std::shared_ptr<Session>& session);
    static json bucketCleanup(const json& payload, const std::shared_ptr<Session>& session);

    static json eventsEnable(const json& payload, const std::shared_ptr<Session>& session);
    static json eventsDisable(const json& payload, const std::shared_ptr<Session>& session);
    static json eventsRepair(const json& payload, const std::shared_ptr<Session>& session);
    static json eventsStatus(const json& payload, const std::shared_ptr<Session>& session);

    static json auditList(const json& payload, const std::shared_ptr<Session>& session);
};

}
