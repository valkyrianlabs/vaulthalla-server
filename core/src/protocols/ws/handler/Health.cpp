#include "protocols/ws/handler/Health.hpp"

#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Health.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

namespace {

template <typename T>
std::optional<T> optionalField(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    try {
        return payload.at(key).get<T>();
    } catch (const json::exception&) {
        throw ops::Invalid(std::string(key) + " has the wrong type");
    }
}

std::string requiredClass(const json& payload, const char* command) {
    if (!payload.is_object()) throw ops::Invalid(std::string(command) + " expects an object");
    const auto cls = optionalField<std::string>(payload, "class");
    if (!cls || cls->empty()) throw ops::Invalid("class is required");
    return *cls;
}

ops::Actor actorOf(const std::shared_ptr<Session>& session) { return session ? session->user : nullptr; }

}

json Health::findingsList(const json& payload, const std::shared_ptr<Session>& session) {
    const auto includeCatalog = optionalField<bool>(payload, "include_catalog").value_or(false);
    return {{"health", ops::health::list(actorOf(session), includeCatalog)}};
}

json Health::findingAcknowledge(const json& payload, const std::shared_ptr<Session>& session) {
    const auto cls = requiredClass(payload, "health.finding.acknowledge");
    return {{"health", ops::health::acknowledge(actorOf(session), cls,
                                                optionalField<std::string>(payload, "subject").value_or(""),
                                                optionalField<std::string>(payload, "note"))}};
}

json Health::findingSilence(const json& payload, const std::shared_ptr<Session>& session) {
    ops::health::SilenceRequest request{.cls = requiredClass(payload, "health.finding.silence")};
    request.subject = optionalField<std::string>(payload, "subject").value_or("");
    request.forSeconds = optionalField<std::uint64_t>(payload, "for_seconds");
    request.until = optionalField<std::uint64_t>(payload, "until");
    request.severity = optionalField<std::string>(payload, "severity");
    request.note = optionalField<std::string>(payload, "note");
    return {{"health", ops::health::silence(actorOf(session), request)}};
}

json Health::findingUnsilence(const json& payload, const std::shared_ptr<Session>& session) {
    const auto cls = requiredClass(payload, "health.finding.unsilence");
    return {{"health", ops::health::unsilence(actorOf(session), cls,
                                              optionalField<std::string>(payload, "subject").value_or(""))}};
}

}
