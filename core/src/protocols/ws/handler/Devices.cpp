#include "protocols/ws/handler/Devices.hpp"

#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "ops/Devices.hpp"
#include "ops/Error.hpp"
#include "protocols/device/Service.hpp"
#include "protocols/ws/Session.hpp"
#include "config/Registry.hpp"

#include <ctime>

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

namespace {

namespace devices = ::vh::ops::devices;

// The connection's device identity. Only the device listener has one; the router never routes device.pair.* or the
// device-only commands elsewhere, but a handler must not trust that.
const vh::device::Peer& peerOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->devicePeer())
        throw ops::Refused("device_unknown", "this command is only answered on the device listener");
    return *session->devicePeer();
}

const ops::Actor& actorOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw ops::Denied("not authenticated");
    return session->user;
}

std::string requiredString(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || !payload.at(key).is_string())
        throw ops::Invalid(std::string(key) + " is required (a string)");
    return payload.at(key).get<std::string>();
}

std::vector<uint8_t> requiredBase64(const json& payload, const char* key) {
    const auto decoded = vh::device::crypto::fromBase64(requiredString(payload, key));
    if (!decoded || decoded->empty()) throw ops::Invalid(std::string(key) + " must be standard base64 (with padding)");
    return *decoded;
}

json windowJson(const vh::device::PairingWindow& w) {
    return {{"owner_id", w.owner_id}, {"opened_at", static_cast<int64_t>(w.opened_at)},
            {"expires_at", static_cast<int64_t>(w.expires_at)}};
}

// The node's clock, so a client counts a window down without trusting its own.
int64_t serverTime() { return static_cast<int64_t>(std::time(nullptr)); }

json statusJson(const protocols::device::ListenerStatus& s) {
    return {{"enabled", s.enabled},
            {"remote", s.remote},
            {"port", s.port},
            {"listening", s.listening},
            {"address", s.listening ? json(s.address) : json(nullptr)},
            {"error", s.error ? json(*s.error) : json(nullptr)},
            {"server_spki_sha256", s.server_spki_sha256.empty() ? json(nullptr) : json(s.server_spki_sha256)},
            {"connections", s.connections}};
}

}

json Devices::pairRequest(const json& payload, const std::shared_ptr<Session>& session) {
    const auto receipt = devices::pairRequest(peerOf(session), {
        .name = requiredString(payload, "name"),
        .platform = requiredString(payload, "platform"),
        .app_version = payload.is_object() && payload.contains("app_version") && payload.at("app_version").is_string()
                           ? payload.at("app_version").get<std::string>() : std::string{},
        .commitment = requiredString(payload, "commitment"),
    });
    return {{"request_id", receipt.request_id},
            {"nonce_server", vh::device::crypto::toHex(receipt.nonce_server)},
            {"expires_at", static_cast<int64_t>(receipt.expires_at)}};
}

json Devices::pairConfirm(const json& payload, const std::shared_ptr<Session>& session) {
    const auto expires = devices::pairConfirm(peerOf(session), requiredString(payload, "request_id"),
                                              requiredString(payload, "nonce_device"));
    return {{"state", "pending"}, {"expires_at", static_cast<int64_t>(expires)}};
}

json Devices::pairStatus(const json& payload, const std::shared_ptr<Session>& session) {
    const auto status = devices::pairStatus(peerOf(session), requiredString(payload, "request_id"));
    json out{{"state", vh::device::to_string(status.state)}};
    if (status.node_id) out["node_id"] = *status.node_id;
    if (status.node_name) out["node_name"] = *status.node_name;
    if (status.device_id) out["device_id"] = *status.device_id;
    return out;
}

json Devices::identityRotate(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object() || !payload.contains("timestamp") || !payload.at("timestamp").is_number_integer())
        throw ops::Invalid("timestamp is required (integer Unix seconds)");
    const auto deviceId = devices::rotateIdentity(actorOf(session), peerOf(session),
                                                  requiredBase64(payload, "certificate"),
                                                  payload.at("timestamp").get<int64_t>(),
                                                  requiredBase64(payload, "signature"));
    return {{"device_id", deviceId}};
}

json Devices::serverIdentity(const std::shared_ptr<Session>& session) {
    const auto info = devices::serverIdentity(peerOf(session));
    return {{"spki_sha256", info.spki_sha256}};
}

json Devices::pairingOpen(const std::shared_ptr<Session>& session) {
    const auto window = devices::openWindow(actorOf(session));
    // What the person types into Desktop: the listener's port, and whether another host can reach it at all.
    const auto cfg = config::Registry::get().device_server;
    return {{"window", windowJson(window)}, {"server_time", serverTime()}, {"port", cfg.port}, {"remote", cfg.remote}};
}

json Devices::pairingClose(const json& payload, const std::shared_ptr<Session>& session) {
    const bool any = payload.is_object() && payload.value("any", false);
    return {{"closed", devices::closeWindow(actorOf(session), any)}};
}

json Devices::pairingPending(const std::shared_ptr<Session>& session) {
    const auto list = devices::pending(actorOf(session));
    json requests = json::array();
    for (const auto& r : list.requests)
        requests.push_back({{"request_id", r.request_id},
                            {"name", r.name},
                            {"platform", r.platform},
                            {"app_version", r.app_version},
                            {"source_ip", r.source_ip},
                            {"device_id", r.device_id},
                            {"code_choices", r.code_choices},
                            {"created_at", static_cast<int64_t>(r.created_at)},
                            {"expires_at", static_cast<int64_t>(r.expires_at)}});
    return {{"window", list.window ? windowJson(*list.window) : json(nullptr)}, {"requests", std::move(requests)},
            {"server_time", serverTime()}};
}

json Devices::pairingApprove(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"device", devices::approve(actorOf(session), requiredString(payload, "request_id"),
                                        requiredString(payload, "code"))}};
}

json Devices::pairingDeny(const json& payload, const std::shared_ptr<Session>& session) {
    devices::deny(actorOf(session), requiredString(payload, "request_id"));
    return {{"denied", true}};
}

json Devices::list(const json& payload, const std::shared_ptr<Session>& session) {
    const bool all = payload.is_object() && payload.value("all", false);
    return {{"devices", devices::list(actorOf(session), all)}};
}

json Devices::rename(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"device", devices::rename(actorOf(session), requiredString(payload, "device_id"),
                                       requiredString(payload, "name"))}};
}

json Devices::revoke(const json& payload, const std::shared_ptr<Session>& session) {
    const auto* self = session && session->devicePeer() ? session->devicePeer().get() : nullptr;
    const auto device = devices::revoke(actorOf(session), requiredString(payload, "device_id"), self);
    // "Unpair this Mac": its own session ends too, once this reply has gone out.
    if (self && self->deviceRowId == device.id) session->closeAfterReply();
    return {{"device", device}};
}

json Devices::remoteStatus(const std::shared_ptr<Session>& session) {
    return {{"status", statusJson(devices::remoteStatus(actorOf(session)))}};
}

json Devices::remoteEnable(const std::shared_ptr<Session>& session) {
    return {{"status", statusJson(devices::setRemote(actorOf(session), true))}};
}

json Devices::remoteDisable(const std::shared_ptr<Session>& session) {
    return {{"status", statusJson(devices::setRemote(actorOf(session), false))}};
}

}
