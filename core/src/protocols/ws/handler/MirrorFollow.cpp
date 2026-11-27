#include "protocols/ws/handler/MirrorFollow.hpp"

#include "db/query/peer/Peer.hpp"
#include "mirror/follow/Protocol.hpp"
#include "mirror/resync/Resync.hpp"
#include "mirror/submit/Submit.hpp"
#include "mirror/switching/Switch.hpp"
#include "mirror/takeover/Takeover.hpp"
#include "ops/Error.hpp"
#include "peer/Peer.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

namespace {

// The linked server asking: a Peer session with a peer row (the router admits no other session to the wire set; this
// is the second check).
uint32_t mirrorFollowCaller(const std::shared_ptr<Session>& session) {
    if (!session || !session->isPeerSession() || !session->peerPrincipal() || session->peerPrincipal()->pairing ||
        session->peerPrincipal()->peer_id == 0)
        throw ops::Denied("only a linked server may ask this");
    // The link still live (the starting half's wire handlers check the same): an unlinked server asks nothing more.
    const auto row = vh::db::query::peer::Peers::byId(session->peerPrincipal()->peer_id);
    if (!row || row->revoked()) throw ops::Refused("peer_revoked", "this link is unlinked");
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

json MirrorFollow::resync(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::resync::serveResync(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

json MirrorFollow::switchRequest(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::switching::serveRequest(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

json MirrorFollow::switchPrepare(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::switching::servePrepare(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

json MirrorFollow::switchCommit(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::switching::serveCommit(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

json MirrorFollow::promoted(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::takeover::servePromoted(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

json MirrorFollow::submit(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::submit::serveSubmit(mirrorFollowCaller(session), mirrorFollowPayload(payload));
}

}
