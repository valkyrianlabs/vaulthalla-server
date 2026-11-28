#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

namespace vh::protocols::ws::handler {

using json = nlohmann::json;

// health.* (design/health/findings.md): health findings with what operators said about them, through ops::health
// (admin.stats.view to read, admin.stats.manage to acknowledge, silence and turn back on).
struct Health {
    static json findingsList(const json& payload, const std::shared_ptr<Session>& session);
    static json findingAcknowledge(const json& payload, const std::shared_ptr<Session>& session);
    static json findingSilence(const json& payload, const std::shared_ptr<Session>& session);
    static json findingUnsilence(const json& payload, const std::shared_ptr<Session>& session);
    // The push (§6): health.changed while subscribed (protocols::ws::HealthNotifier).
    static json subscribe(const std::shared_ptr<Session>& session);
    static json unsubscribe(const std::shared_ptr<Session>& session);
};

}
