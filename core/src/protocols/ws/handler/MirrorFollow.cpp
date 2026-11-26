#include "protocols/ws/handler/MirrorFollow.hpp"

#include "mirror/follow/Protocol.hpp"
#include "ops/Error.hpp"
#include "ops/Peers.hpp"
#include "peer/Peer.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

namespace {

// The linked server asking: a Peer session with a peer row (the router admits no other session to the wire set; this
// is the second check).
uint32_t mirrorFollowCaller(const std::shared_ptr<Session>& session) {
    vh::ops::peers::requireExperimental();
    if (!session || !session->isPeerSession() || !session->peerPrincipal() || session->peerPrincipal()->pairing ||
        session->peerPrincipal()->peer_id == 0)
        throw ops::Denied("only a linked server may ask this");
    return session->peerPrincipal()->peer_id;
}

const json& mirrorFollowPayload(const json& payload) {
    if (!payload.is_object()) throw ops::Invalid("the payload is an object");
    return payload;
}

}

json MirrorFollow::tree(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::follow::serveTree(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

json MirrorFollow::log(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::follow::serveLog(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

json MirrorFollow::ack(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::follow::serveAck(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

json MirrorFollow::notify(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::follow::receiveNotify(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

}
