#include "protocols/ws/handler/PeerPolicy.hpp"

#include "ops/Error.hpp"
#include "ops/PeerPolicy.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

namespace {

const ops::Actor& peerPolicyActorOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw ops::Denied("not authenticated");
    return session->user;
}

std::string peerPolicyRef(const json& payload) {
    if (!payload.is_object() || !payload.contains("peer") || !payload.at("peer").is_string())
        throw ops::Invalid("peer is required (a string: its number, node id, name or key)");
    return payload.at("peer").get<std::string>();
}

}

json PeerPolicy::get(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"policy", ops::peer_policy::toJson(ops::peer_policy::get(peerPolicyActorOf(session), peerPolicyRef(payload)))}};
}

json PeerPolicy::set(const json& payload, const std::shared_ptr<Session>& session) {
    const auto& actor = peerPolicyActorOf(session);
    const auto ref = peerPolicyRef(payload);
    if (!payload.contains("role")) throw ops::Invalid("role is required: a vault role's id or name, or null for none");
    const auto& r = payload.at("role");
    std::optional<ops::roles::Ref> role;
    if (r.is_number_unsigned()) role = r.get<unsigned int>();
    else if (r.is_string()) role = r.get<std::string>();
    else if (!r.is_null()) throw ops::Invalid("role is a vault role's id or name, or null for none");
    return {{"policy", ops::peer_policy::toJson(ops::peer_policy::set(actor, ref, role))}};
}

}
