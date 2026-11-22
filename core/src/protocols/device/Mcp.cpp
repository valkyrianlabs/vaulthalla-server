#include "protocols/device/Mcp.hpp"

#include "device/Peer.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace vh::protocols::device::mcp {

void setCallDeadlineForTesting(const std::chrono::milliseconds deadline) {
    protocols::mcp::setCallDeadlineForTesting(deadline);
}

protocols::http::model::preview::Response handle(protocols::http::request&& req, const std::shared_ptr<ws::Session>& principal) {
    namespace bhttp = boost::beast::http;
    if (!principal || !principal->isDeviceSession() || principal->closing()) {
        bhttp::response<bhttp::string_body> res{bhttp::status::forbidden, req.version()};
        res.set(bhttp::field::server, "Vaulthalla");
        res.set(bhttp::field::content_type, "application/json");
        res.set(bhttp::field::cache_control, "no-store");
        res.keep_alive(req.keep_alive());
        res.body() = nlohmann::json{{"error", "device_unknown"}}.dump();
        res.prepare_payload();
        return res;
    }

    const auto& peer = principal->devicePeer();
    protocols::mcp::Principal who{
        .user = principal->user,
        .origin = "device " + (peer ? peer->shortId() : std::string{"?"}) + " mcp",
        // A paired device acts with every effect its user may (the ceiling a scoped device will carry goes here).
        .ceiling = protocols::shell::CommandEffect::Destructive,
        .ended = [principal]() -> std::optional<std::string> {
            if (principal->closing() || !principal->user || !principal->user->authorizing())
                return std::string("this device session has ended");
            return std::nullopt;
        }};
    return protocols::mcp::handle(std::move(req), who);
}

}
