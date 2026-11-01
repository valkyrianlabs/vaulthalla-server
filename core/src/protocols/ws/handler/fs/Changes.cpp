#include "protocols/ws/handler/fs/Changes.hpp"

#include "ops/FsChanges.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler::fs {

namespace {

// A JSON integer >= 0 (a parsed frame holds one as unsigned, a json built in code may hold it signed).
bool isNonNegativeInteger(const json& value) {
    return value.is_number_unsigned() || (value.is_number_integer() && value.get<int64_t>() >= 0);
}

uint64_t unsignedMember(const json& payload, const char* name, const uint64_t fallback) {
    if (!payload.contains(name) || payload.at(name).is_null()) return fallback;
    if (!isNonNegativeInteger(payload.at(name))) throw ops::Invalid(std::string(name) + " must be a non-negative integer");
    return payload.at(name).get<uint64_t>();
}

}

json Changes::list(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object() || !payload.contains("vault_id") || !isNonNegativeInteger(payload.at("vault_id")) ||
        payload.at("vault_id").get<uint64_t>() > UINT32_MAX)
        throw ops::Invalid("vault_id must be a vault id");
    ops::fs_changes::ListRequest request{.vault_id = payload.at("vault_id").get<uint32_t>(),
                                         .limit = unsignedMember(payload, "limit", ops::fs_changes::kDefaultLimit)};
    if (payload.contains("since") && !payload.at("since").is_null()) request.since = unsignedMember(payload, "since", 0);
    return ops::fs_changes::toJson(ops::fs_changes::list(session->user, request));
}

}
