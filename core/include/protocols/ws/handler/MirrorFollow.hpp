#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

// ws peer.mirror.tree / peer.mirror.log / peer.mirror.ack / peer.mirror.notify / peer.mirror.submit: the server mirror's data plane
// (design/peers/mirror.md "As built: following the core"; mirror::follow::Protocol). Only on a linked server's Peer
// session (Router::classifyCommand: the peer wire set), refused while peers.experimental is off. Never an agent, a
// scoped or relayed device or a person's session: the router denies the wire set to every other kind of session.
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct MirrorFollow {
    static json tree(const json& payload, const std::shared_ptr<Session>& session);
    static json log(const json& payload, const std::shared_ptr<Session>& session);
    static json ack(const json& payload, const std::shared_ptr<Session>& session);
    static json notify(const json& payload, const std::shared_ptr<Session>& session);
    // peer.mirror.submit: a change made on the mirror (wave 4 piece B; mirror::submit).
    static json submit(const json& payload, const std::shared_ptr<Session>& session);
    // peer.mirror.resync: the mirror starts its copy over; the core takes its baseline again (wave 5 piece B).
    static json resync(const json& payload, const std::shared_ptr<Session>& session);
};

}
