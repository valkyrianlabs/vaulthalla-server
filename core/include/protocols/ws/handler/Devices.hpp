#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

// ws device.*: paired devices (ops::devices). device.pair.* runs on the device listener's pairing-only connections
// (and a paired device's own session), device.identity.rotate / device.server.identity only on a paired device's
// session; the rest on a signed-in human's session or a paired device's (a device acts as its user).
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Devices {
    // The device's side of pairing.
    static json pairRequest(const json& payload, const std::shared_ptr<Session>& session);
    static json pairConfirm(const json& payload, const std::shared_ptr<Session>& session);
    static json pairStatus(const json& payload, const std::shared_ptr<Session>& session);
    // A paired device's own session.
    static json identityRotate(const json& payload, const std::shared_ptr<Session>& session);
    static json serverIdentity(const std::shared_ptr<Session>& session);
    // The owner's side of pairing.
    static json pairingOpen(const std::shared_ptr<Session>& session);
    static json pairingClose(const std::shared_ptr<Session>& session);
    static json pairingPending(const std::shared_ptr<Session>& session);
    static json pairingApprove(const json& payload, const std::shared_ptr<Session>& session);
    static json pairingDeny(const json& payload, const std::shared_ptr<Session>& session);
    // Devices.
    static json list(const json& payload, const std::shared_ptr<Session>& session);
    static json rename(const json& payload, const std::shared_ptr<Session>& session);
    static json revoke(const json& payload, const std::shared_ptr<Session>& session);
    // The listener's exposure (super admins).
    static json remoteStatus(const std::shared_ptr<Session>& session);
    static json remoteEnable(const std::shared_ptr<Session>& session);
    static json remoteDisable(const std::shared_ptr<Session>& session);
};

}
