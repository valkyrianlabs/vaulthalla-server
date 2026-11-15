#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

// ws cloud.relay.* (ops::cloud_relay; design/cloud/relay.md): the Vaulthalla Cloud relay's local switch and status.
// The status reads the database and the service's memory (no cloud call on a ws thread); enable and disable only
// record the switch and wake the service.
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct CloudRelay {
    static json status(const json& payload, const std::shared_ptr<Session>& session);
    static json enable(const json& payload, const std::shared_ptr<Session>& session);
    static json disable(const json& payload, const std::shared_ptr<Session>& session);
};

}
