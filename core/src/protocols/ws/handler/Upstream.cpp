#include "protocols/ws/handler/Upstream.hpp"

#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Upstream.hpp"
#include "ops/UpstreamJson.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

#include <optional>
#include <string>

namespace vh::protocols::ws::handler {

namespace {

namespace up = vh::ops::upstream;

// Payload readers: a member of the wrong type is a refusal (`invalid`), never a fault.
const json& upPayloadObject(const json& payload) {
    static const json empty = json::object();
    if (payload.is_null()) return empty;
    if (!payload.is_object()) throw vh::ops::Invalid("payload must be an object");
    return payload;
}

unsigned int upRequiredId(const json& payload, const char* name) {
    const auto& p = upPayloadObject(payload);
    if (!p.contains(name) || !p.at(name).is_number_integer() || p.at(name).get<int64_t>() <= 0)
        throw vh::ops::Invalid(std::string(name) + " must be a positive integer");
    return static_cast<unsigned int>(p.at(name).get<int64_t>());
}

std::optional<unsigned int> upOptionalUInt(const json& payload, const char* name) {
    const auto& p = upPayloadObject(payload);
    if (!p.contains(name) || p.at(name).is_null()) return std::nullopt;
    if (!p.at(name).is_number_integer() || p.at(name).get<int64_t>() < 0)
        throw vh::ops::Invalid(std::string(name) + " must be a non-negative integer");
    return static_cast<unsigned int>(p.at(name).get<int64_t>());
}

std::optional<std::string> upOptionalString(const json& payload, const char* name) {
    const auto& p = upPayloadObject(payload);
    if (!p.contains(name) || p.at(name).is_null()) return std::nullopt;
    if (!p.at(name).is_string()) throw vh::ops::Invalid(std::string(name) + " must be a string");
    return p.at(name).get<std::string>();
}

std::string upRequiredString(const json& payload, const char* name) {
    auto v = upOptionalString(payload, name);
    if (!v || v->empty()) throw vh::ops::Invalid(std::string(name) + " is required");
    return *v;
}

bool upOptionalBool(const json& payload, const char* name, const bool fallback = false) {
    const auto& p = upPayloadObject(payload);
    if (!p.contains(name) || p.at(name).is_null()) return fallback;
    if (!p.at(name).is_boolean()) throw vh::ops::Invalid(std::string(name) + " must be a boolean");
    return p.at(name).get<bool>();
}

up::KeyRef upKeyOf(const json& payload) { return upRequiredId(payload, "api_key_id"); }

}

json Upstream::adminEnable(const json& payload, const std::shared_ptr<Session>& session) {
    up::AdminEnable req;
    if (auto token = upOptionalString(payload, "provider_token"); token && !token->empty()) req.provider_token = std::move(token);
    req.clear_provider_token = upOptionalBool(payload, "clear_provider_token");
    return {{"admin", up::enableAdmin(session->user, upKeyOf(payload), req)}};
}

json Upstream::adminDisable(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"admin", up::disableAdmin(session->user, upKeyOf(payload))}};
}

json Upstream::adminStatus(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"admin", up::adminStatus(session->user, upKeyOf(payload), upOptionalBool(payload, "probe"))}};
}

json Upstream::bucketList(const json& payload, const std::shared_ptr<Session>& session) {
    up::InventoryQuery query;
    query.token = upOptionalString(payload, "token").value_or("");
    if (const auto max = upOptionalUInt(payload, "max")) query.max = *max;
    if (const auto state = upOptionalString(payload, "state"); state && !state->empty())
        query.state = up::bucketStateFromString(*state);
    if (const auto filter = upOptionalString(payload, "filter"); filter && !filter->empty()) query.filter = filter;
    return {{"inventory", up::inventory(session->user, upKeyOf(payload), query)}};
}

json Upstream::bucketProtect(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"bucket", up::protect(session->user, upKeyOf(payload), upRequiredString(payload, "bucket"),
                                   upOptionalString(payload, "reason").value_or(""))}};
}

json Upstream::bucketUnprotect(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"bucket", up::unprotect(session->user, upKeyOf(payload), upRequiredString(payload, "bucket"),
                                     upOptionalBool(payload, "confirm"))}};
}

json Upstream::bucketInspect(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"inspection", up::inspect(session->user, upKeyOf(payload), upRequiredString(payload, "bucket"))}};
}

json Upstream::bucketLifecycleSet(const json& payload, const std::shared_ptr<Session>& session) {
    const auto patch = up::lifecyclePatchFromJson(upPayloadObject(payload));
    return {{"inspection", up::setLifecycle(session->user, upKeyOf(payload), upRequiredString(payload, "bucket"), patch)}};
}

json Upstream::bucketAdoptPreflight(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"report", up::adoptPreflight(session->user, upKeyOf(payload), upRequiredString(payload, "bucket"),
                                          upOptionalUInt(payload, "max_objects").value_or(10000),
                                          upOptionalUInt(payload, "sample_heads").value_or(16))}};
}

json Upstream::bucketDetach(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"bucket", up::detach(session->user, upKeyOf(payload), upRequiredString(payload, "bucket"))}};
}

json Upstream::bucketCleanupPreflight(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"plan", up::cleanupPreflight(session->user, upKeyOf(payload), upRequiredString(payload, "bucket"))}};
}

json Upstream::bucketCleanup(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"result", up::cleanup(session->user, upKeyOf(payload), upRequiredString(payload, "bucket"),
                                   upOptionalString(payload, "confirm_token").value_or(""),
                                   upOptionalBool(payload, "delete_bucket", true))}};
}

json Upstream::eventsEnable(const json& payload, const std::shared_ptr<Session>& session) {
    up::EventsEnable req;
    req.prefix = upOptionalString(payload, "prefix").value_or("");
    if (auto foreign = upOptionalString(payload, "foreign_objects"); foreign && !foreign->empty())
        req.foreign_objects = std::move(foreign);
    return {{"events", up::enableEvents(session->user, upRequiredId(payload, "vault_id"), req)}};
}

json Upstream::eventsDisable(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"events", up::disableEvents(session->user, upRequiredId(payload, "vault_id"))}};
}

json Upstream::eventsRepair(const json& payload, const std::shared_ptr<Session>& session) {
    return {{"events", up::repairEvents(session->user, upRequiredId(payload, "vault_id"))}};
}

json Upstream::eventsStatus(const json& payload, const std::shared_ptr<Session>& session) {
    std::optional<unsigned int> vaultId;
    if (const auto id = upOptionalUInt(payload, "vault_id"); id && *id > 0) vaultId = id;
    return {{"events", up::eventStatus(session->user, vaultId)}};
}

json Upstream::auditList(const json& payload, const std::shared_ptr<Session>& session) {
    up::AuditQuery query;
    if (auto bucket = upOptionalString(payload, "bucket"); bucket && !bucket->empty()) query.bucket = std::move(bucket);
    if (const auto limit = upOptionalUInt(payload, "limit"); limit && *limit > 0) query.limit = *limit;
    return {{"entries", up::audit(session->user, query)}};
}

}
