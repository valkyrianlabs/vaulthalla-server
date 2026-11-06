#pragma once

#include "protocols/ws/Fwd.hpp"

#include <nlohmann/json.hpp>

#include <memory>

// auth.stepup.begin / auth.stepup.finish (#359; MFA design note section 5.4): the console's answer to a command that
// refused with step_up_required. begin names the family (and the target the refusal named) and gets the methods and,
// for a passkey, a challenge bound to this session, family and target; finish answers it and leaves a grant on this
// session, after which the console resends the original request. Web sessions only (auth/stepup/StepUp.hpp).
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct StepUp {
    static json begin(const json& payload, const std::shared_ptr<Session>& session);
    static json finish(const json& payload, const std::shared_ptr<Session>& session);
};

}
