#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

namespace vh::protocols::ws::handler {

using json = nlohmann::json;

// audit.* (#323): the tamper-evident audit trail, through ops::audit (admin.audits.view).
struct Audit {
    static json list(const json& payload, const std::shared_ptr<Session>& session);
    static json verify(const std::shared_ptr<Session>& session);
    static json exportEvents(const json& payload, const std::shared_ptr<Session>& session);
};

}
