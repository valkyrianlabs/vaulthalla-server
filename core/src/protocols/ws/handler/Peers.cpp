#include "protocols/ws/handler/Peers.hpp"

#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "ops/Error.hpp"
#include "ops/Peers.hpp"
#include "peer/Links.hpp"
#include "peer/Peer.hpp"
#include "protocols/ws/Session.hpp"

#include <ctime>
#include <stdexcept>

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

namespace {

namespace peers = ::vh::ops::peers;
namespace dc = vh::device::crypto;

const ops::Actor& peerActorOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw ops::Denied("not authenticated");
    return session->user;
}

// The pairing-only connection's key (the device listener only; the router routes peer.pair.* nowhere else).
const vh::device::Peer& peerConnectionOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->isDevicePairing() || !session->devicePeer())
        throw ops::Refused("device_unknown", "this command is only answered on a pairing connection of the device "
                                             "listener");
    return *session->devicePeer();
}

std::string peerRequiredText(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || !payload.at(key).is_string())
        throw ops::Invalid(std::string(key) + " is required (a string)");
    return payload.at(key).get<std::string>();
}

std::optional<std::string> peerOptionalText(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    if (!payload.at(key).is_string()) throw ops::Invalid(std::string(key) + " must be a string");
    return payload.at(key).get<std::string>();
}

int64_t peerServerTime() { return static_cast<int64_t>(std::time(nullptr)); }

json peerWindowJson(const vh::device::PairingWindow& w) {
    return {{"owner_id", w.owner_id}, {"opened_at", static_cast<int64_t>(w.opened_at)},
            {"expires_at", static_cast<int64_t>(w.expires_at)}};
}

json peerAdvertisementJson(const protocols::device::endpoints::Advertisement& a) {
    json candidates = json::array();
    for (const auto& c : a.candidates)
        candidates.push_back({{"host", c.host}, {"port", c.port},
                              {"kind", std::string(protocols::device::endpoints::to_string(c.kind))}});
    return {{"port", a.port}, {"remote", a.remote}, {"listening", a.listening},
            {"generated_at", static_cast<int64_t>(a.generated_at)}, {"candidates", std::move(candidates)}};
}

json peerLinkedJson(const peers::Linked& l) {
    json j = l.record;
    j["health"] = vh::peer::toJson(l.health);
    return j;
}

}

json Peers::pairingOpen(const std::shared_ptr<Session>& session) {
    const auto opened = peers::openWindow(peerActorOf(session));
    return {{"window", peerWindowJson(opened.window)}, {"server_time", peerServerTime()}, {"node_id", opened.node_id},
            {"name", opened.name}, {"spki_sha256", opened.spki_sha256},
            {"endpoints", peerAdvertisementJson(opened.endpoints)}};
}

json Peers::pairingClose(const std::shared_ptr<Session>& session) {
    return {{"closed", peers::closeWindow(peerActorOf(session))}};
}

json Peers::pairingPending(const std::shared_ptr<Session>& session) {
    const auto list = peers::pending(peerActorOf(session));
    json requests = json::array();
    for (const auto& r : list.requests)
        requests.push_back({{"request_id", r.request_id}, {"node_id", r.node_id}, {"name", r.name},
                            {"product_version", r.product_version}, {"peer_protocol", r.peer_protocol},
                            {"spki_sha256", r.spki_sha256}, {"source_ip", r.source_ip},
                            {"code_choices", r.code_choices}, {"created_at", static_cast<int64_t>(r.created_at)},
                            {"expires_at", static_cast<int64_t>(r.expires_at)}});
    return {{"window", list.window ? peerWindowJson(*list.window) : json(nullptr)}, {"requests", std::move(requests)},
            {"server_time", peerServerTime()}};
}

json Peers::pairingApprove(const json& payload, const std::shared_ptr<Session>& session) {
    const auto row = peers::approve(peerActorOf(session), peerRequiredText(payload, "request_id"), peerRequiredText(payload, "code"),
                                    peerOptionalText(payload, "expect_spki"));
    return {{"peer", row}};
}

json Peers::pairingDeny(const json& payload, const std::shared_ptr<Session>& session) {
    peers::deny(peerActorOf(session), peerRequiredText(payload, "request_id"));
    return {{"denied", true}};
}

json Peers::linkStart(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object() || !payload.contains("endpoints")) throw ops::Invalid("endpoints is required");
    const auto endpoints = vh::peer::endpointsFromJson(payload.at("endpoints"));
    return {{"link", vh::peer::toJson(peers::linkStart(peerActorOf(session), endpoints, peerOptionalText(payload, "expect_spki")))}};
}

json Peers::linkStatus(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"link", vh::peer::toJson(peers::linkStatus(peerActorOf(session), peerRequiredText(payload, "link_id")))}};
}

json Peers::linkCancel(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"link", vh::peer::toJson(peers::linkCancel(peerActorOf(session), peerRequiredText(payload, "link_id")))}};
}

json Peers::list(const json& payload, const std::shared_ptr<Session>& session) {
    const bool all = payload.is_object() && payload.value("all", false);
    json out = json::array();
    for (const auto& l : peers::list(peerActorOf(session), all)) out.push_back(peerLinkedJson(l));
    return {{"peers", std::move(out)}};
}

json Peers::get(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"peer", peerLinkedJson(peers::get(peerActorOf(session), peerRequiredText(payload, "peer")))}};
}

json Peers::rename(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"peer", peers::rename(peerActorOf(session), peerRequiredText(payload, "peer"), peerRequiredText(payload, "name"))}};
}

json Peers::unlink(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"peer", peers::unlink(peerActorOf(session), peerRequiredText(payload, "peer"))}};
}

json Peers::pairRequest(const json& payload, const std::shared_ptr<Session>& session) {
    const auto receipt = peers::pairRequest(peerConnectionOf(session), payload);
    return {{"request_id", receipt.request_id}, {"nonce_b", dc::toHex(receipt.nonce_b)},
            {"card", vh::peer::toJson(receipt.card)}, {"expires_at", static_cast<int64_t>(receipt.expires_at)}};
}

json Peers::pairConfirm(const json& payload, const std::shared_ptr<Session>& session) {
    const auto expires = peers::pairConfirm(peerConnectionOf(session), peerRequiredText(payload, "request_id"),
                                            peerRequiredText(payload, "nonce_a"));
    return {{"state", "pending"}, {"expires_at", static_cast<int64_t>(expires)}};
}

json Peers::pairStatus(const json& payload, const std::shared_ptr<Session>& session) {
    const auto status = peers::pairStatus(peerConnectionOf(session), peerRequiredText(payload, "request_id"));
    return {{"state", vh::device::to_string(status.state)}};
}

json Peers::hello(const json& payload, const std::shared_ptr<Session>& session) {
    const auto links = vh::peer::linkService();
    if (!links) throw std::runtime_error("the link service is not available");
    return links->helloReceived(session, payload);
}

json Peers::ping(const std::shared_ptr<Session>& session) {
    (void)session;
    return {{"time", peerServerTime()}};
}

json Peers::endpoints(const json& payload, const std::shared_ptr<Session>& session) {
    const auto links = vh::peer::linkService();
    if (!links) throw std::runtime_error("the link service is not available");
    return links->endpointsReceived(session, payload);
}

json Peers::identityRotate(const json& payload, const std::shared_ptr<Session>& session) {
    peers::identityRotateReceived(session, payload);
    return {{"stored", true}};
}

json Peers::unlinked(const std::shared_ptr<Session>& session) {
    peers::unlinkedReceived(session);
    return {{"revoked", true}};
}

}
