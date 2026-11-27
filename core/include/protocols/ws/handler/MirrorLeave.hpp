#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

// ws mirror.detach.preview, mirror.detach, mirror.detach.copy(.get|.cancel) and the wire's peer.mirror.detached (wave 5, piece A; ops/MirrorLeave.hpp,
// mirror/leave/Leave.hpp). The management commands on a signed-in person's session or a full-access device's; the wire
// command only on a linked server's Peer session (Router::isPeerWireCommand).
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct MirrorLeave {
    static json detachPreview(const json& payload, const std::shared_ptr<Session>& session);
    static json detach(const json& payload, const std::shared_ptr<Session>& session);
    // Detach a copy (mirror/copy/Copy.hpp): start, progress, cancel.
    static json detachCopy(const json& payload, const std::shared_ptr<Session>& session);
    static json detachCopyGet(const json& payload, const std::shared_ptr<Session>& session);
    static json detachCopyCancel(const json& payload, const std::shared_ptr<Session>& session);
    static json versionsSet(const json& payload, const std::shared_ptr<Session>& session);
    static json heldGet(const json& payload, const std::shared_ptr<Session>& session);

    // A linked server's session.
    static json detached(const json& payload, const std::shared_ptr<Session>& session);
    static json deleting(const json& payload, const std::shared_ptr<Session>& session);
};

}
