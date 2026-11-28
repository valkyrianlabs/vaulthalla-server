#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

// ws mirror.* and peer.mirror.* (design/peers/mirror.md "Starting a mirror"; ops/Mirrors.hpp, mirror/start/Start.hpp).
// Management (mirror.add, mirror.pending, mirror.accept, mirror.decline, mirror.cancel, mirror.list, mirror.get,
// mirror.accept_all.set, mirror.keep_removed.set) on a signed-in person's session or a full-access device's; the wire set of piece A
// (peer.mirror.offer, .answer, .keys, .begin, .grant, .cancel) only on a linked server's Peer session
// (Router::classifyCommand, isPeerWireCommand).
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Mirrors {
    static json add(const json& payload, const std::shared_ptr<Session>& session);
    static json pending(const std::shared_ptr<Session>& session);
    static json accept(const json& payload, const std::shared_ptr<Session>& session);
    static json decline(const json& payload, const std::shared_ptr<Session>& session);
    static json cancel(const json& payload, const std::shared_ptr<Session>& session);
    static json list(const std::shared_ptr<Session>& session);
    static json get(const json& payload, const std::shared_ptr<Session>& session);
    static json acceptAllSet(const json& payload, const std::shared_ptr<Session>& session);
    static json keepRemovedSet(const json& payload, const std::shared_ptr<Session>& session);
    // A change made here that the core refused (wave 4 piece B): mirror.held.list | discard | retry.
    static json heldList(const json& payload, const std::shared_ptr<Session>& session);
    static json heldDiscard(const json& payload, const std::shared_ptr<Session>& session);
    static json heldRetry(const json& payload, const std::shared_ptr<Session>& session);
    // mirror.resync: a stopped copy starts over from its core's tree (wave 5 piece B).
    static json resync(const json& payload, const std::shared_ptr<Session>& session);
    // mirror.switch: a planned switch of the core role, asked on either server (wave 5 piece B).
    static json switchRole(const json& payload, const std::shared_ptr<Session>& session);
    // mirror.takeover: the mirror takes over as the vault's core while its core is gone (wave 5 piece B).
    static json takeover(const json& payload, const std::shared_ptr<Session>& session);
    // mirror.relink.*: compare, plan and apply a relink of a vault both servers hold since their mirror ended.
    static json relinkCompare(const json& payload, const std::shared_ptr<Session>& session);
    static json relinkGet(const json& payload, const std::shared_ptr<Session>& session);
    static json relinkEntries(const json& payload, const std::shared_ptr<Session>& session);
    static json relinkPlan(const json& payload, const std::shared_ptr<Session>& session);
    static json relinkApply(const json& payload, const std::shared_ptr<Session>& session);

    // A linked server's session.
    static json offer(const json& payload, const std::shared_ptr<Session>& session);
    static json answer(const json& payload, const std::shared_ptr<Session>& session);
    static json mirrorAllSet(const json& payload, const std::shared_ptr<Session>& session);
    static json keys(const json& payload, const std::shared_ptr<Session>& session);
    static json key(const json& payload, const std::shared_ptr<Session>& session);   // peer.mirror.key (a rotation)
    static json begin(const json& payload, const std::shared_ptr<Session>& session);
    static json grant(const json& payload, const std::shared_ptr<Session>& session);
    static json cancelWire(const json& payload, const std::shared_ptr<Session>& session);
};

}
