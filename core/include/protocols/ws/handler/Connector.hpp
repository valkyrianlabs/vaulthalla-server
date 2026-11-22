#pragma once

#include <nlohmann/json_fwd.hpp>
#include <memory>
#include "protocols/ws/Fwd.hpp"

// ws connector.* (ops::connector; design/core/mcp-remote-signin.md): remote connectors' switch, policy, registered
// clients and grants ("connected apps").
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct Connector {
    static json status(const json& payload, const std::shared_ptr<Session>& session);
    static json enable(const json& payload, const std::shared_ptr<Session>& session);
    static json disable(const json& payload, const std::shared_ptr<Session>& session);
    static json policyUpdate(const json& payload, const std::shared_ptr<Session>& session);
    static json grantsList(const json& payload, const std::shared_ptr<Session>& session);
    static json grantsRevoke(const json& payload, const std::shared_ptr<Session>& session);
    static json clientsList(const json& payload, const std::shared_ptr<Session>& session);
    static json clientsAdd(const json& payload, const std::shared_ptr<Session>& session);
    static json clientsRemove(const json& payload, const std::shared_ptr<Session>& session);
};

}
