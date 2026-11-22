#include "protocols/ws/handler/Connector.hpp"

#include "identities/User.hpp"
#include "ops/Connector.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

// Named, not anonymous: the unity build joins this file with the other handlers.
namespace connector_ws {

namespace op = ::vh::ops::connector;

const ops::Actor& actorOf(const std::shared_ptr<Session>& session) {
    if (!session || !session->user) throw ops::Denied("not authenticated");
    return session->user;
}

std::string requiredString(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || !payload.at(key).is_string())
        throw ops::Invalid(std::string(key) + " (a string) is required");
    return payload.at(key).get<std::string>();
}

std::optional<bool> optionalBool(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    if (!payload.at(key).is_boolean()) throw ops::Invalid(std::string(key) + " must be true or false");
    return payload.at(key).get<bool>();
}

std::vector<std::string> stringArray(const json& v, const char* key) {
    if (!v.is_array()) throw ops::Invalid(std::string(key) + " must be an array of strings");
    std::vector<std::string> out;
    for (const auto& e : v) {
        if (!e.is_string()) throw ops::Invalid(std::string(key) + " must be an array of strings");
        out.push_back(e.get<std::string>());
    }
    return out;
}

}

json Connector::status(const json&, const std::shared_ptr<Session>& session) {
    return connector_ws::op::toJson(connector_ws::op::status(connector_ws::actorOf(session)));
}

json Connector::enable(const json& payload, const std::shared_ptr<Session>& session) {
    namespace d = connector_ws;
    return d::op::toJson(d::op::enable(d::actorOf(session), d::op::Channel::Web, d::requiredString(payload, "url")));
}

json Connector::disable(const json&, const std::shared_ptr<Session>& session) {
    namespace d = connector_ws;
    return d::op::toJson(d::op::disable(d::actorOf(session), d::op::Channel::Web));
}

json Connector::policyUpdate(const json& payload, const std::shared_ptr<Session>& session) {
    namespace d = connector_ws;
    d::op::Policy p;
    if (payload.is_object() && payload.contains("max_scope") && !payload.at("max_scope").is_null())
        p.max_scope = d::requiredString(payload, "max_scope");
    p.dcr_enabled = d::optionalBool(payload, "dcr_enabled");
    if (payload.is_object() && payload.contains("client_hosts") && !payload.at("client_hosts").is_null())
        p.client_hosts = d::stringArray(payload.at("client_hosts"), "client_hosts");
    return d::op::toJson(d::op::setPolicy(d::actorOf(session), d::op::Channel::Web, p));
}

json Connector::grantsList(const json& payload, const std::shared_ptr<Session>& session) {
    namespace d = connector_ws;
    const bool all = d::optionalBool(payload, "all").value_or(false);
    json out = json::array();
    for (const auto& g : d::op::listGrants(d::actorOf(session), all)) out.push_back(d::op::toJson(g));
    return {{"grants", out}};
}

json Connector::grantsRevoke(const json& payload, const std::shared_ptr<Session>& session) {
    namespace d = connector_ws;
    const auto& actor = d::actorOf(session);
    if (d::optionalBool(payload, "all").value_or(false)) {
        std::optional<uint32_t> user;
        if (payload.contains("user_id") && !payload.at("user_id").is_null()) {
            if (!payload.at("user_id").is_number_unsigned()) throw ops::Invalid("user_id must be a user id");
            user = payload.at("user_id").get<uint32_t>();
        }
        return {{"revoked", d::op::revokeGrants(actor, user)}};
    }
    (void)d::op::revokeGrant(actor, d::requiredString(payload, "id"));
    return {{"revoked", 1}};
}

json Connector::clientsList(const json&, const std::shared_ptr<Session>& session) {
    namespace d = connector_ws;
    json out = json::array();
    for (const auto& c : d::op::listClients(d::actorOf(session))) out.push_back(d::op::toJson(c));
    return {{"clients", out}};
}

json Connector::clientsAdd(const json& payload, const std::shared_ptr<Session>& session) {
    namespace d = connector_ws;
    if (!payload.is_object() || !payload.contains("redirect_uris")) throw ops::Invalid("redirect_uris is required");
    return d::op::toJson(d::op::addClient(d::actorOf(session), d::op::Channel::Web, d::requiredString(payload, "name"),
                                          d::stringArray(payload.at("redirect_uris"), "redirect_uris")));
}

json Connector::clientsRemove(const json& payload, const std::shared_ptr<Session>& session) {
    namespace d = connector_ws;
    return {{"grants_revoked",
             d::op::removeClient(d::actorOf(session), d::op::Channel::Web, d::requiredString(payload, "id"))}};
}

}
