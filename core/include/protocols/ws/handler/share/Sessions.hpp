#pragma once

#include <functional>
#include <cstdint>
#include <memory>
#include <optional>
#include <nlohmann/json_fwd.hpp>
#include "protocols/ws/Fwd.hpp"
#include "share/Fwd.hpp"

namespace vh::protocols::ws::handler::share {

using json = nlohmann::json;

struct Sessions {
    using ManagerFactory = std::function<std::shared_ptr<vh::share::Manager>()>;

    static json open(const json& payload, const std::shared_ptr<Session>& session);
    static json startEmailChallenge(const json& payload, const std::shared_ptr<Session>& session);
    static json confirmEmailChallenge(const json& payload, const std::shared_ptr<Session>& session);

    // A link's public view (SharePublicLink); effective_allowed_ops (the operations the share session may actually
    // run) is included when given, i.e. once the session is ready.
    static json publicLinkJson(const vh::share::Link& link, std::optional<uint32_t> effectiveAllowedOps);

    static void setManagerFactoryForTesting(ManagerFactory factory);
    static void resetManagerFactoryForTesting();
};

}
