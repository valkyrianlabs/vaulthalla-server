#include "protocols/ws/handler/Mirrors.hpp"

#include "db/query/peer/Peer.hpp"
#include "mirror/rotate/Rotate.hpp"
#include "mirror/start/Start.hpp"
#include "ops/Error.hpp"
#include "ops/Mirrors.hpp"
#include "ops/Peers.hpp"
#include "peer/Peer.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

#include <limits>

namespace vh::protocols::ws::handler {

namespace {

namespace mirrors = ::vh::ops::mirrors;

const ops::Actor& mirrorActorOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw ops::Denied("not authenticated");
    return session->user;
}

std::string mirrorRequiredText(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || !payload.at(key).is_string())
        throw ops::Invalid(std::string(key) + " is required (a string)");
    return payload.at(key).get<std::string>();
}

// A number, or a string of digits (the CLI's and the console's ways of naming one).
std::optional<uint32_t> mirrorOptionalId(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    const auto& v = payload.at(key);
    if (v.is_number_unsigned() && v.get<uint64_t>() >= 1 && v.get<uint64_t>() <= std::numeric_limits<int32_t>::max())
        return static_cast<uint32_t>(v.get<uint64_t>());
    if (v.is_number_integer() && v.get<int64_t>() >= 1 && v.get<int64_t>() <= std::numeric_limits<int32_t>::max())
        return static_cast<uint32_t>(v.get<int64_t>());
    throw ops::Invalid(std::string(key) + " must be a positive integer");
}

uint32_t mirrorRequiredId(const json& payload, const char* key) {
    const auto id = mirrorOptionalId(payload, key);
    if (!id) throw ops::Invalid(std::string(key) + " is required");
    return *id;
}

// The offer's reference: its number here or its uid.
std::string mirrorOfferRef(const json& payload) {
    if (!payload.is_object() || !payload.contains("offer")) throw ops::Invalid("offer is required");
    const auto& v = payload.at("offer");
    if (v.is_string()) return v.get<std::string>();
    if (v.is_number_integer() && v.get<int64_t>() >= 1) return std::to_string(v.get<int64_t>());
    throw ops::Invalid("offer is the offer's number or its uid");
}

json mirrorOffers(const std::vector<ops::mirrors::Offer>& list) {
    json out = json::array();
    for (const auto& o : list) out.push_back(mirrors::toJson(o));
    return out;
}

// The linked server on the other end of this Peer session (the router admits nothing else here).
vh::peer::Record mirrorPeerOf(const std::shared_ptr<Session>& session) {
    const auto& principal = session ? session->peerPrincipal() : nullptr;
    if (!principal || principal->peer_id == 0) throw ops::Denied("not a linked server's session");
    const auto row = db::query::peer::Peers::byId(principal->peer_id);
    if (!row || row->revoked()) throw ops::Refused("peer_revoked", "this link is unlinked");
    return *row;
}

}

json Mirrors::add(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"offer", mirrors::toJson(mirrors::add(mirrorActorOf(session), {.vault_id = mirrorRequiredId(payload, "vault_id"),
                                                                            .peer = mirrorRequiredText(payload, "peer")}))}};
}

json Mirrors::pending(const std::shared_ptr<Session>& session) {
    return {{"offers", mirrorOffers(mirrors::pending(mirrorActorOf(session)))}};
}

json Mirrors::accept(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"offer", mirrors::toJson(mirrors::accept(mirrorActorOf(session), mirrorOfferRef(payload)))}};
}

json Mirrors::decline(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"offer", mirrors::toJson(mirrors::decline(mirrorActorOf(session), mirrorOfferRef(payload)))}};
}

json Mirrors::cancel(const json& payload, const std::shared_ptr<Session>& session) {
    mirrors::CancelRequest req{.vault_id = mirrorOptionalId(payload, "vault_id")};
    if (payload.is_object() && payload.contains("offer") && !payload.at("offer").is_null()) req.offer = mirrorOfferRef(payload);
    if (payload.is_object() && payload.contains("remove_copy") && !payload.at("remove_copy").is_null()) {
        if (!payload.at("remove_copy").is_boolean()) throw ops::Invalid("remove_copy must be a boolean");
        req.remove_copy = payload.at("remove_copy").get<bool>();
    }
    return mirrors::toJson(mirrors::cancel(mirrorActorOf(session), req));
}

json Mirrors::list(const std::shared_ptr<Session>& session) {
    json vaults = json::array();
    for (const auto& m : mirrors::list(mirrorActorOf(session))) vaults.push_back(mirrors::toJson(m));
    return {{"vaults", std::move(vaults)}};
}

json Mirrors::get(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"vault", mirrors::toJson(mirrors::get(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id")))}};
}

json Mirrors::acceptAllSet(const json& payload, const std::shared_ptr<Session>& session) {
    const auto peerRef = mirrorRequiredText(payload, "peer");
    if (!payload.contains("enabled") || !payload.at("enabled").is_boolean()) throw ops::Invalid("enabled is required (a boolean)");
    const auto& actor = mirrorActorOf(session);
    const auto set = mirrors::setAcceptAll(actor, peerRef, payload.at("enabled").get<bool>());
    return mirrors::toJson(set, ::vh::ops::peers::resolveRef(peerRef));
}

json Mirrors::keepRemovedSet(const json& payload, const std::shared_ptr<Session>& session) {
    const auto peerRef = mirrorRequiredText(payload, "peer");
    if (!payload.contains("enabled") || !payload.at("enabled").is_boolean()) throw ops::Invalid("enabled is required (a boolean)");
    const auto set = mirrors::setKeepRemoved(mirrorActorOf(session), peerRef, payload.at("enabled").get<bool>());
    return mirrors::toJson(set, ::vh::ops::peers::resolveRef(peerRef));
}

json Mirrors::mirrorAllSet(const json& payload, const std::shared_ptr<Session>& session) {
    const auto peerRef = mirrorRequiredText(payload, "peer");
    if (!payload.contains("enabled") || !payload.at("enabled").is_boolean()) throw ops::Invalid("enabled is required (a boolean)");
    const auto set = mirrors::setMirrorAll(mirrorActorOf(session), peerRef, payload.at("enabled").get<bool>());
    return mirrors::toJson(set, ::vh::ops::peers::resolveRef(peerRef));
}

json Mirrors::heldList(const json& payload, const std::shared_ptr<Session>& session) {
    bool all = false;
    if (payload.is_object() && payload.contains("all") && !payload.at("all").is_null()) {
        if (!payload.at("all").is_boolean()) throw ops::Invalid("all must be a boolean");
        all = payload.at("all").get<bool>();
    }
    json out = json::array();
    for (const auto& h : mirrors::held(mirrorActorOf(session), mirrorOptionalId(payload, "vault_id"), all))
        out.push_back(mirrors::toJson(h));
    return {{"held", std::move(out)}};
}

json Mirrors::heldDiscard(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"held", mirrors::toJson(mirrors::discardHeld(mirrorActorOf(session), mirrorRequiredId(payload, "id")))}};
}

json Mirrors::heldRetry(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"held", mirrors::toJson(mirrors::retryHeld(mirrorActorOf(session), mirrorRequiredId(payload, "id")))}};
}

json Mirrors::resync(const json& payload, const std::shared_ptr<Session>& session) {
    return mirrors::resync(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"));
}

json Mirrors::switchRole(const json& payload, const std::shared_ptr<Session>& session) {
    bool acceptNoAccess = false;
    if (payload.is_object() && payload.contains("accept_no_access") && !payload.at("accept_no_access").is_null()) {
        if (!payload.at("accept_no_access").is_boolean()) throw ops::Invalid("accept_no_access must be a boolean");
        acceptNoAccess = payload.at("accept_no_access").get<bool>();
    }
    return mirrors::switchRole(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"), acceptNoAccess);
}

json Mirrors::takeover(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object() || !payload.contains("confirm") || !payload.at("confirm").is_string())
        throw ops::Invalid("confirm is the vault's name, typed");
    return mirrors::takeover(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"),
                             payload.at("confirm").get<std::string>());
}

json Mirrors::relinkCompare(const json& payload, const std::shared_ptr<Session>& session) {
    return mirrors::relinkCompare(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"),
                                  mirrorRequiredText(payload, "peer"));
}

json Mirrors::relinkGet(const json& payload, const std::shared_ptr<Session>& session) {
    return mirrors::relinkStatus(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"));
}

json Mirrors::relinkEntries(const json& payload, const std::shared_ptr<Session>& session) {
    const auto num = [&](const char* key, const uint64_t fallback) {
        if (!payload.contains(key) || payload.at(key).is_null()) return fallback;
        if (!payload.at(key).is_number_unsigned()) throw ops::Invalid(std::string(key) + " must be a non-negative integer");
        return payload.at(key).get<uint64_t>();
    };
    std::string kind;
    if (payload.contains("kind") && !payload.at("kind").is_null()) kind = mirrorRequiredText(payload, "kind");
    return mirrors::relinkEntries(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"), kind, num("offset", 0),
                                  num("limit", 100));
}

json Mirrors::relinkPlan(const json& payload, const std::shared_ptr<Session>& session) {
    vh::mirror::relink::PlanEdit edit;
    const auto optText = [&](const char* key) -> std::optional<std::string> {
        if (!payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
        return mirrorRequiredText(payload, key);
    };
    const auto choiceOf = [](const json& item) -> std::optional<std::string> {
        if (!item.contains("choice") || item.at("choice").is_null()) return std::nullopt;
        if (!item.at("choice").is_string()) throw ops::Invalid("a choice is this, theirs, both or null");
        return item.at("choice").get<std::string>();
    };
    edit.core = optText("core");
    edit.default_choice = optText("default");
    if (payload.contains("set") && !payload.at("set").is_null()) {
        if (!payload.at("set").is_array() || payload.at("set").size() > 10'000)
            throw ops::Invalid("set is a list of {uid, choice} (at most 10000)");
        for (const auto& item : payload.at("set")) {
            if (!item.is_object() || !item.contains("uid") || !item.at("uid").is_string())
                throw ops::Invalid("each of set is {uid, choice}");
            edit.set.push_back({.uid = item.at("uid").get<std::string>(), .choice = choiceOf(item)});
        }
    }
    if (payload.contains("by_kind") && !payload.at("by_kind").is_null()) {
        if (!payload.at("by_kind").is_array()) throw ops::Invalid("by_kind is a list of {kind, choice}");
        for (const auto& item : payload.at("by_kind")) {
            if (!item.is_object()) throw ops::Invalid("each of by_kind is {kind, choice}");
            const auto kind = item.contains("kind") && item.at("kind").is_string() ? item.at("kind").get<std::string>()
                                                                                    : std::string{};
            edit.by_kind.push_back({.kind = kind, .choice = choiceOf(item)});
        }
    }
    if (payload.contains("discard") && !payload.at("discard").is_null()) {
        if (!payload.at("discard").is_boolean()) throw ops::Invalid("discard must be a boolean");
        edit.discard = payload.at("discard").get<bool>();
    }
    return mirrors::relinkPlan(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"), edit);
}

json Mirrors::relinkApply(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object() || !payload.contains("confirm") || !payload.at("confirm").is_string())
        throw ops::Invalid("confirm is the vault's name, typed");
    std::string keep, peer;
    if (payload.contains("keep") && !payload.at("keep").is_null()) keep = mirrorRequiredText(payload, "keep");
    if (payload.contains("peer") && !payload.at("peer").is_null()) peer = mirrorRequiredText(payload, "peer");
    return mirrors::relinkApply(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"),
                                payload.at("confirm").get<std::string>(), keep, peer);
}

json Mirrors::relinkPending(const json&, const std::shared_ptr<Session>& session) {
    return {{"requests", mirrors::relinkPending(mirrorActorOf(session))}};
}

json Mirrors::relinkAccept(const json& payload, const std::shared_ptr<Session>& session) {
    return mirrors::relinkAccept(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"));
}

json Mirrors::relinkDecline(const json& payload, const std::shared_ptr<Session>& session) {
    return mirrors::relinkDecline(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"));
}

json Mirrors::relinkApprove(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object() || !payload.contains("confirm") || !payload.at("confirm").is_string())
        throw ops::Invalid("confirm is the vault's name, typed");
    return mirrors::relinkApprove(mirrorActorOf(session), mirrorRequiredId(payload, "vault_id"),
                                  payload.at("confirm").get<std::string>());
}

json Mirrors::offer(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::start::offerReceived(mirrorPeerOf(session), payload);
}

json Mirrors::answer(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::start::answerReceived(mirrorPeerOf(session), payload);
}

json Mirrors::keys(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::start::keysReceived(mirrorPeerOf(session), payload);
}

json Mirrors::key(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::rotate::keyReceived(mirrorPeerOf(session), payload);
}

json Mirrors::begin(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::start::beginReceived(mirrorPeerOf(session), payload);
}

json Mirrors::grant(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::start::grantReceived(mirrorPeerOf(session), payload);
}

json Mirrors::cancelWire(const json& payload, const std::shared_ptr<Session>& session) {
    return vh::mirror::start::cancelReceived(mirrorPeerOf(session), payload);
}

}
