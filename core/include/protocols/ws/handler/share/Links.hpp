#pragma once

#include <functional>
#include <memory>
#include <nlohmann/json_fwd.hpp>
#include "protocols/ws/Fwd.hpp"
#include "share/Fwd.hpp"

namespace vh::protocols::ws::handler::share {

using json = nlohmann::json;

struct Links {
    using ManagerFactory = std::function<std::shared_ptr<vh::share::Manager>()>;

    static json create(const json& payload, const std::shared_ptr<Session>& session);
    static json get(const json& payload, const std::shared_ptr<Session>& session);
    static json list(const json& payload, const std::shared_ptr<Session>& session);
    static json update(const json& payload, const std::shared_ptr<Session>& session);
    static json revoke(const json& payload, const std::shared_ptr<Session>& session);
    static json rotateToken(const json& payload, const std::shared_ptr<Session>& session);

    // A link as its managers see it: the management JSON without token material (ShareLink).
    static json managementJson(const vh::share::Link& link);

    static void setManagerFactoryForTesting(ManagerFactory factory);
    static void resetManagerFactoryForTesting();
};

}
