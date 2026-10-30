#include "protocols/ws/handler/Meta.hpp"
#include "Contract.hpp"
#include "WsProtocol.hpp"
#include "db/query/device/Device.hpp"
#include "device/Peer.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/handler_templates.hpp"

#include <version.h>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <optional>

namespace vh::protocols::ws::handler {

namespace {

// client.name / client.version: what a log line and devices.app_version can hold (the pairing rule for app_version).
std::string clientText(const json& client, const char* member) {
    const auto it = client.find(member);
    if (it == client.end() || it->is_null()) return {};
    if (!it->is_string()) throw ops::Invalid(std::string("client.") + member + " must be a string");
    const auto& text = it->get_ref<const std::string&>();
    if (text.size() > 64 || !std::ranges::all_of(text, [](const unsigned char c) { return c >= 0x20 && c < 0x7f; }))
        throw ops::Invalid(std::string("client.") + member + " must be at most 64 printable ASCII characters");
    return text;
}

std::optional<int> protocolBound(const json& protocol, const char* member) {
    const auto it = protocol.find(member);
    if (it == protocol.end() || it->is_null()) return std::nullopt;
    if (!it->is_number_integer() || it->get<int64_t>() < 0 || it->get<int64_t>() > 1'000'000)
        throw ops::Invalid(std::string("protocol.") + member + " must be a non-negative integer");
    return static_cast<int>(it->get<int64_t>());
}

const json& objectMember(const json& payload, const char* member) {
    static const json kEmpty = json::object();
    const auto it = payload.find(member);
    if (it == payload.end() || it->is_null()) return kEmpty;
    if (!it->is_object()) throw ops::Invalid(std::string(member) + " must be an object");
    return *it;
}

// A paired device's client.version is its app version: refresh the stored one (pairing wrote the first). Never fails
// the hello.
void refreshDeviceAppVersion(const Session& session, const std::string& version) {
    const auto& peer = session.devicePeer();
    if (version.empty() || !session.isDeviceSession() || !peer || !peer->paired()) return;
    try {
        if (db::query::device::Devices::updateAppVersion(*peer->deviceRowId, version))
            log::Registry::ws()->info("[Meta] device {} now reports app version {}", peer->shortId(), version);
    } catch (const std::exception& e) {
        log::Registry::ws()->debug("[Meta] app_version update for device {} failed: {}", peer->shortId(), e.what());
    }
}

}

json Meta::contract() {
    const auto& id = vh::contract::identity();
    return {{"contract_version", id.version}, {"contract_hash", id.contract_hash}, {"ws_hash", id.ws_hash},
            {"models_hash", id.models_hash}};
}

json Meta::hello(const json& payload, const std::shared_ptr<Session>& session,
                 const std::vector<std::string>& commands) {
    if (!payload.is_object()) throw ops::Invalid("payload must be an object");
    const auto& client = objectMember(payload, "client");
    const auto& protocol = objectMember(payload, "protocol");
    Session::ClientInfo info{.name = clientText(client, "name"), .version = clientText(client, "version")};
    const auto clientMin = protocolBound(protocol, "min");
    const auto clientMax = protocolBound(protocol, "max");

    const auto version = vh::contract::negotiateProtocol(clientMin, clientMax);
    if (!version) {
        log::Registry::ws()->debug("[Meta] hello from {} {}: protocol {}..{} unsupported (server speaks {}..{})",
                                  info.name.empty() ? "an unnamed client" : info.name, info.version,
                                  clientMin.value_or(vh::contract::kProtocolMin),
                                  clientMax.value_or(vh::contract::kProtocolVersion), vh::contract::kProtocolMin,
                                  vh::contract::kProtocolVersion);
        throw core::DetailedRefusal(
            "protocol_unsupported",
            "This server speaks ws protocol " + std::to_string(vh::contract::kProtocolMin) + " to " +
                std::to_string(vh::contract::kProtocolVersion) + " (Vaulthalla " VH_VERSION
                "); the client's range doesn't overlap it.",
            json{{"server_min", vh::contract::kProtocolMin}, {"server_max", vh::contract::kProtocolVersion},
                 {"server_version", VH_VERSION}});
    }

    if (session) {
        refreshDeviceAppVersion(*session, info.version);
        log::Registry::ws()->debug("[Meta] hello from {} {}: protocol {}",
                                   info.name.empty() ? "an unnamed client" : info.name, info.version, *version);
        session->setHello(*version, std::move(info));
    }

    return {{"server", {{"name", "vaulthalla"}, {"version", VH_VERSION}}},
            {"protocol",
             {{"version", *version}, {"min", vh::contract::kProtocolMin}, {"max", vh::contract::kProtocolVersion}}},
            {"capabilities", vh::contract::capabilityNames()},
            {"commands", commands},
            {"contract", contract()}};
}

}
