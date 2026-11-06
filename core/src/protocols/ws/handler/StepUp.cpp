#include "protocols/ws/handler/StepUp.hpp"

#include "auth/stepup/StepUp.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/core/Refusal.hpp"

#include <chrono>

namespace vh::protocols::ws::handler {

json StepUp::begin(const json& payload, const std::shared_ptr<Session>& session) {
    if (!payload.contains("family") || !payload.at("family").is_string()) throw ops::Invalid("family is required");
    const auto family = auth::stepup::parseFamily(payload.at("family").get<std::string>());
    if (!family) throw ops::Invalid("unknown step-up family");
    std::optional<std::string> target;
    if (payload.contains("target") && !payload.at("target").is_null()) {
        if (!payload.at("target").is_string()) throw ops::Invalid("target is a string");
        target = payload.at("target").get<std::string>();
    }
    return auth::stepup::begin(session, *family, target);
}

json StepUp::finish(const json& payload, const std::shared_ptr<Session>& session) {
    const auto done = auth::stepup::finish(session, payload);
    if (!done.grant) {
        throw core::DetailedRefusal(
            "step_up_failed",
            done.attempts_remaining == 0 ? "Too many failed attempts: this session was signed out. Sign in again."
                                         : "That didn't work. Try again.",
            {{"attempts_remaining", done.attempts_remaining}});
    }
    const auto& g = *done.grant;
    return {{"family", std::string(auth::stepup::to_string(g.family))},
            {"target", g.target ? json(*g.target) : json(nullptr)},
            {"expires_at", std::chrono::duration_cast<std::chrono::seconds>(g.expires_at.time_since_epoch()).count()},
            {"uses", auth::stepup::targetBound(g.family) ? json(1) : json(nullptr)}};
}

}
