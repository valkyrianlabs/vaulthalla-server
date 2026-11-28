#include "protocols/ws/handler/Health.hpp"

#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Health.hpp"
#include "protocols/ws/HealthNotifier.hpp"
#include "protocols/ws/Session.hpp"

#include <nlohmann/json.hpp>

namespace vh::protocols::ws::handler {

namespace {

// Unity build: every handler shares this anonymous namespace, so the helpers carry the area's name.
template <typename T>
std::optional<T> healthField(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key) || payload.at(key).is_null()) return std::nullopt;
    try {
        return payload.at(key).get<T>();
    } catch (const json::exception&) {
        throw ops::Invalid(std::string(key) + " has the wrong type");
    }
}

std::string healthClass(const json& payload, const char* command) {
    if (!payload.is_object()) throw ops::Invalid(std::string(command) + " expects an object");
    const auto cls = healthField<std::string>(payload, "class");
    if (!cls || cls->empty()) throw ops::Invalid("class is required");
    return *cls;
}

ops::Actor healthActor(const std::shared_ptr<Session>& session) { return session ? session->user : nullptr; }

}

json Health::findingsList(const json& payload, const std::shared_ptr<Session>& session) {
    const auto includeCatalog = healthField<bool>(payload, "include_catalog").value_or(false);
    return {{"health", ops::health::list(healthActor(session), includeCatalog)}};
}

json Health::findingAcknowledge(const json& payload, const std::shared_ptr<Session>& session) {
    const auto cls = healthClass(payload, "health.finding.acknowledge");
    return {{"health", ops::health::acknowledge(healthActor(session), cls,
                                                healthField<std::string>(payload, "subject").value_or(""),
                                                healthField<std::string>(payload, "note"))}};
}

json Health::findingSilence(const json& payload, const std::shared_ptr<Session>& session) {
    ops::health::SilenceRequest request{.cls = healthClass(payload, "health.finding.silence")};
    request.subject = healthField<std::string>(payload, "subject").value_or("");
    request.forSeconds = healthField<std::uint64_t>(payload, "for_seconds");
    request.until = healthField<std::uint64_t>(payload, "until");
    request.severity = healthField<std::string>(payload, "severity");
    request.note = healthField<std::string>(payload, "note");
    return {{"health", ops::health::silence(healthActor(session), request)}};
}

json Health::findingUnsilence(const json& payload, const std::shared_ptr<Session>& session) {
    const auto cls = healthClass(payload, "health.finding.unsilence");
    return {{"health", ops::health::unsilence(healthActor(session), cls,
                                              healthField<std::string>(payload, "subject").value_or(""))}};
}

json Health::subscribe(const std::shared_ptr<Session>& session) {
    return {{"revision", HealthNotifier::instance()->subscribe(session)}};
}

json Health::unsubscribe(const std::shared_ptr<Session>& session) {
    HealthNotifier::instance()->unsubscribe(session);
    return {{"subscribed", false}};
}

}
