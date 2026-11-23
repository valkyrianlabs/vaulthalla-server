#include "protocols/device/Mcp.hpp"

#include "device/Peer.hpp"
#include "device/ScopeAudit.hpp"
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
        // "device <id16> mcp", and " scope <scope>" for a scoped device (vh::device::auditOrigin).
        .origin = peer ? ::vh::device::auditOrigin(*peer, "mcp") : std::string("device ? mcp"),
        // The device's scope (migration 152): destructive for every unscoped pairing, exactly as before; a scope the
        // catalog doesn't know reads as the narrowest (fail closed).
        .ceiling = peer ? vh::mcp::parseCeiling(peer->scope).value_or(protocols::shell::CommandEffect::Read)
                        : protocols::shell::CommandEffect::Read,
        .ended = [principal]() -> std::optional<std::string> {
            if (principal->closing() || !principal->user || !principal->user->authorizing())
                return std::string("this device session has ended");
            return std::nullopt;
        },
        .refused = [principal](const std::string& command, const std::string& effect) {
            if (const auto& p = principal->devicePeer())
                ::vh::device::scope_audit::refused(*p, principal->user, "mcp", command,
                                                   effect.empty() ? std::nullopt : std::optional<std::string_view>(effect));
        }};
    return protocols::mcp::handle(std::move(req), who);
}

}
