#pragma once

#include <memory>
#include <nlohmann/json_fwd.hpp>
#include "protocols/ws/Fwd.hpp"

// vault.keys.* (ops::vault_keys): key backup status for any signed-in session; export, its confirmation and import
// only on a paired device's session (D4: never through the browser; MCP has no ws path at all).
namespace vh::protocols::ws::handler {

using json = nlohmann::json;

struct VaultKeys {
    static json status(const json& payload, const std::shared_ptr<Session>& session);
    static json exportKeys(const json& payload, const std::shared_ptr<Session>& session);
    static json confirmExport(const json& payload, const std::shared_ptr<Session>& session);
    static json importKeys(const json& payload, const std::shared_ptr<Session>& session);
};

}
