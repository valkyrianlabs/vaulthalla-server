#pragma once

#include "nlohmann/json_fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <memory>

// fs.changes.* (#259): thin adapters over ops::fs_changes.
namespace vh::protocols::ws::handler::fs {

using json = nlohmann::json;

struct Changes {
    static json list(const json& payload, const std::shared_ptr<Session>& session);
};

}
