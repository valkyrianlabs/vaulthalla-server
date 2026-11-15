#include "protocols/ws/handler/CloudRelay.hpp"

#include "ops/CloudRelay.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

// Named, not anonymous: the unity build joins this file with the other handlers.
namespace cloud_relay_ws {

const ops::Actor& actorOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw ops::Denied("not authenticated");
    return session->user;
}

}

json CloudRelay::status(const json&, const std::shared_ptr<Session>& session) {
    return ops::cloud_relay::toJson(ops::cloud_relay::status(cloud_relay_ws::actorOf(session)));
}

json CloudRelay::enable(const json&, const std::shared_ptr<Session>& session) {
    return ops::cloud_relay::toJson(
        ops::cloud_relay::enable(cloud_relay_ws::actorOf(session), ops::cloud_relay::Channel::Web));
}

json CloudRelay::disable(const json&, const std::shared_ptr<Session>& session) {
    return ops::cloud_relay::toJson(
        ops::cloud_relay::disable(cloud_relay_ws::actorOf(session), ops::cloud_relay::Channel::Web));
}

}
