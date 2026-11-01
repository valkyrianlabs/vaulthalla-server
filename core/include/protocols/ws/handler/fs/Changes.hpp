#pragma once

#include "nlohmann/json_fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <memory>

// fs.changes.* (#259, #260): thin adapters over ops::fs_changes and the ChangeNotifier.
namespace vh::protocols::ws::handler::fs {

using json = nlohmann::json;

struct Changes {
    static json list(const json& payload, const std::shared_ptr<Session>& session);
    static json subscribe(const json& payload, const std::shared_ptr<Session>& session);
    static json unsubscribe(const json& payload, const std::shared_ptr<Session>& session);
};

}
