#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

// ws peer.* (design/peers/link.md; ops/Peers.hpp). Management (peer.status, peer.pairing.*, peer.link.*, peer.list,
// peer.get, peer.rename, peer.unlink) on a signed-in super admin's session or a full-access device's; peer.pair.* on the device
// listener's pairing-only connections (the dialling server); the wire set (peer.hello, peer.ping, peer.endpoints,
// peer.identity.rotate, peer.unlinked) only on a linked server's Peer session (Router::classifyCommand).
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Peers {
    // Management. status answers whether peers.experimental is on (the only one that answers while it is off).
    static json status(const std::shared_ptr<Session>& session);
    static json pairingOpen(const std::shared_ptr<Session>& session);
    static json pairingClose(const std::shared_ptr<Session>& session);
    static json pairingPending(const std::shared_ptr<Session>& session);
    static json pairingApprove(const json& payload, const std::shared_ptr<Session>& session);
    static json pairingDeny(const json& payload, const std::shared_ptr<Session>& session);
    static json linkStart(const json& payload, const std::shared_ptr<Session>& session);
    static json linkStatus(const json& payload, const std::shared_ptr<Session>& session);
    static json linkCancel(const json& payload, const std::shared_ptr<Session>& session);
    static json list(const json& payload, const std::shared_ptr<Session>& session);
    static json get(const json& payload, const std::shared_ptr<Session>& session);
    static json rename(const json& payload, const std::shared_ptr<Session>& session);
    static json unlink(const json& payload, const std::shared_ptr<Session>& session);
    // The dialling server's side of pairing (pairing-only connections).
    static json pairRequest(const json& payload, const std::shared_ptr<Session>& session);
    static json pairConfirm(const json& payload, const std::shared_ptr<Session>& session);
    static json pairStatus(const json& payload, const std::shared_ptr<Session>& session);
    // A linked server's session.
    static json hello(const json& payload, const std::shared_ptr<Session>& session);
    static json ping(const std::shared_ptr<Session>& session);
    static json endpoints(const json& payload, const std::shared_ptr<Session>& session);
    static json identityRotate(const json& payload, const std::shared_ptr<Session>& session);
    static json unlinked(const std::shared_ptr<Session>& session);
};

}
