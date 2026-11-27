#include "protocols/ws/handler/MirrorLeave.hpp"

#include "db/query/peer/Peer.hpp"
#include "mirror/leave/Leave.hpp"
#include "ops/Error.hpp"
#include "ops/MirrorLeave.hpp"
#include "ops/Mirrors.hpp"
#include "protocols/shell/Transfer.hpp"
#include "storage/PlaintextReader.hpp"
#include "ops/Peers.hpp"
#include "peer/Peer.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

#include <limits>
#include <optional>
#include <string>

namespace vh::protocols::ws::handler {

namespace ws_mirror_leave_detail {

// mirror.held.get answers inline up to this size.
constexpr uint64_t kHeldInlineMax = 8ull * 1024 * 1024;

const ops::Actor& leaveActorOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw ops::Denied("not authenticated");
    return session->user;
}

uint32_t leaveVaultId(const json& payload) {
    if (!payload.is_object() || !payload.contains("vault_id")) throw ops::Invalid("vault_id is required");
    const auto& v = payload.at("vault_id");
    if (v.is_number_integer() && v.get<int64_t>() >= 1 && v.get<int64_t>() <= std::numeric_limits<int32_t>::max())
        return static_cast<uint32_t>(v.get<int64_t>());
    throw ops::Invalid("vault_id must be a positive integer");
}

std::optional<std::string> leaveOptionalText(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    const auto& v = payload.at(key);
    if (v.is_string()) return v.get<std::string>();
    if (v.is_number_integer() && v.get<int64_t>() >= 1) return std::to_string(v.get<int64_t>());
    throw ops::Invalid(std::string(key) + " must be a string");
}

vh::peer::Record leavePeerOf(const std::shared_ptr<Session>& session) {
    ::vh::ops::peers::requireExperimental();
    const auto& principal = session ? session->peerPrincipal() : nullptr;
    if (!principal || principal->peer_id == 0) throw ops::Denied("not a linked server's session");
    const auto row = db::query::peer::Peers::byId(principal->peer_id);
    if (!row || row->revoked()) throw ops::Refused("peer_revoked", "this link is unlinked");
    return *row;
}

}

json MirrorLeave::detachPreview(const json& payload, const std::shared_ptr<Session>& session) {
    using namespace ws_mirror_leave_detail;
    return {{"preview", vh::mirror::leave::toJson(
                            ::vh::ops::mirrors::detachPreview(leaveActorOf(session), leaveVaultId(payload)))}};
}

json MirrorLeave::detach(const json& payload, const std::shared_ptr<Session>& session) {
    using namespace ws_mirror_leave_detail;
    const ::vh::ops::mirrors::DetachRequest req{.vault_id = leaveVaultId(payload),
                                                .owner = leaveOptionalText(payload, "owner"),
                                                .confirm_name = leaveOptionalText(payload, "confirm_name")};
    return {{"detached", vh::mirror::leave::toJson(::vh::ops::mirrors::detach(leaveActorOf(session), req))}};
}

json MirrorLeave::versionsSet(const json& payload, const std::shared_ptr<Session>& session) {
    using namespace ws_mirror_leave_detail;
    if (!payload.contains("enabled") || !payload.at("enabled").is_boolean()) throw ops::Invalid("enabled is required (a boolean)");
    const auto limit = [&](const char* key) -> std::optional<uint64_t> {
        if (!payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
        if (!payload.at(key).is_number_unsigned()) throw ops::Invalid(std::string(key) + " must be a non-negative integer");
        return payload.at(key).get<uint64_t>();
    };
    const auto small = [&](const char* key) -> std::optional<unsigned int> {
        const auto v = limit(key);
        if (v && *v > 100000) throw ops::Invalid(std::string(key) + " is out of range");
        return v ? std::optional<unsigned int>(static_cast<unsigned int>(*v)) : std::nullopt;
    };
    const auto set = ::vh::ops::mirrors::setVersions(
        leaveActorOf(session), {.vault_id = leaveVaultId(payload), .enabled = payload.at("enabled").get<bool>(),
                                .keep_last = small("keep_last"), .max_age_days = small("max_age_days"),
                                .quota_bytes = limit("quota_bytes")});
    return {{"versions", ::vh::ops::mirrors::toJson(set)}};
}

json MirrorLeave::heldGet(const json& payload, const std::shared_ptr<Session>& session) {
    using namespace ws_mirror_leave_detail;
    if (!payload.is_object() || !payload.contains("id") || !payload.at("id").is_number_unsigned())
        throw ops::Invalid("id is required (the held change's number)");
    const auto content = ::vh::ops::mirrors::heldContent(leaveActorOf(session), payload.at("id").get<uint64_t>());
    // Inline, bounded: a larger version is fetched with `vh mirror save` (streamed).
    if (content.size > kHeldInlineMax)
        throw ops::Refused("too_large", "this version is " + std::to_string(content.size) +
                                            " bytes: fetch it with vh mirror save " + std::to_string(content.held.id));
    const auto bytes = storage::readAll(*content.reader, kHeldInlineMax);
    return {{"held", ::vh::ops::mirrors::toJson(content.held)}, {"name", content.name}, {"size", content.size},
            {"content_b64", protocols::shell::transfer::encode(bytes)}};
}

json MirrorLeave::deleting(const json& payload, const std::shared_ptr<Session>& session) {
    using namespace ws_mirror_leave_detail;
    return vh::mirror::leave::deletingReceived(leavePeerOf(session), payload);
}

json MirrorLeave::detached(const json& payload, const std::shared_ptr<Session>& session) {
    using namespace ws_mirror_leave_detail;
    return vh::mirror::leave::detachedReceived(leavePeerOf(session), payload);
}

}
