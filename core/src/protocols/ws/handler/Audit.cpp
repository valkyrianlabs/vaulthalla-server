#include "protocols/ws/handler/Audit.hpp"

#include "identities/User.hpp"
#include "ops/Audit.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

namespace {

constexpr std::size_t kExportMaxBytes = 32 * 1024 * 1024;  // larger exports: `vh audit export`

template <typename T>
std::optional<T> optional(const json& payload, const char* key) {
    if (!payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    try {
        return payload.at(key).get<T>();
    } catch (const json::exception&) {
        throw ops::Invalid(std::string(key) + " has the wrong type");
    }
}

}

json Audit::list(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object()) throw ops::Invalid("audit.list expects an object");
    const ops::audit::Filter filter{
        .before_seq = optional<uint64_t>(payload, "before_seq"),
        .since_us = optional<uint64_t>(payload, "since_us"),
        .until_us = optional<uint64_t>(payload, "until_us"),
        .action_prefix = optional<std::string>(payload, "action"),
        .actor_id = optional<uint32_t>(payload, "actor_id"),
        .vault_id = optional<uint32_t>(payload, "vault_id"),
        .outcome = optional<std::string>(payload, "outcome"),
    };
    const auto limit = optional<uint64_t>(payload, "limit").value_or(100);
    const auto page = ops::audit::list(session ? session->user : nullptr, filter, static_cast<std::size_t>(limit));
    json events = json::array();
    for (const auto& r : page.events) events.push_back(ops::audit::toJson(r));
    return {{"events", std::move(events)},
            {"next_before", page.next_before ? json(*page.next_before) : json(nullptr)}};
}

json Audit::verify(const std::shared_ptr<Session>& session) {
    return {{"verification", ops::audit::toJson(ops::audit::verify(session ? session->user : nullptr))}};
}

json Audit::exportEvents(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.is_object()) throw ops::Invalid("audit.export expects an object");
    std::string ndjson;
    bool truncated = false;
    const auto count = ops::audit::exportNdjson(
        session ? session->user : nullptr, optional<uint64_t>(payload, "since_us"),
        optional<uint64_t>(payload, "until_us"), [&](const std::string_view line) {
            if (ndjson.size() + line.size() + 1 > kExportMaxBytes) {
                truncated = true;
                return;
            }
            ndjson.append(line);
            ndjson.push_back('\n');
        });
    if (truncated)
        throw ops::Invalid("this export is over 32 MiB; narrow since_us/until_us or use `vh audit export`");
    return {{"ndjson", std::move(ndjson)}, {"events", count}};
}

}
