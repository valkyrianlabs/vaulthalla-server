#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

// ws peer.policy.get / peer.policy.set (ops/PeerPolicy.hpp): a linked server's default vault role on this server.
// Management commands, like the rest of peer.*: refused on scoped and relayed devices and to agents.
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct PeerPolicy {
    static json get(const json& payload, const std::shared_ptr<Session>& session);
    static json set(const json& payload, const std::shared_ptr<Session>& session);
};

}
