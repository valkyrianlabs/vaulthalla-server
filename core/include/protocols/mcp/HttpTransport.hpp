#pragma once

#include "identities/Fwd.hpp"
#include "protocols/http/Router.hpp"
#include "Mcp.hpp"  // vh::mcp (core/usage): the catalog, the server and CommandEffect

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>

// MCP over Streamable HTTP for the daemon's remote principals: POST only (no SSE stream, no MCP session id), JSON
// responses (202 for notifications), Origin refused, unknown MCP-Protocol-Version 400, JSON content type required,
// batches refused. The catalog and JSON-RPC server are the ones `vh mcp` uses (core/usage/src/mcp): the same tools,
// exclusions, destructive gate and structured confirmations, limited to the principal's effect ceiling. Each tool call
// runs as one non-interactive CLI line through shell::Router::executeLine for the principal's user, under
// AgentCallScope and an Agent step-up scope (an agent never steps up), abandoned (not interrupted) after a deadline.
//
// Who the principal is, and how it authenticated, is the caller's: the device listener's /mcp (a paired device's
// session, protocols/device/Mcp.hpp) and, later, the connector listener (a bearer grant).
namespace vh::protocols::mcp {

struct Principal {
    std::shared_ptr<identities::User> user;
    // Read by the audit sink on every line the command writes ("device 1a2b3c4d5e6f7a8b mcp").
    std::string origin;
    // The principal's limit (vh::mcp::withinCeiling): tools/list shows, and tools/call runs, nothing above it.
    shell::CommandEffect ceiling = shell::CommandEffect::Destructive;
    // Asked before every call: a message when the principal can no longer act (session closed, grant revoked).
    std::function<std::optional<std::string>()> ended;
};

[[nodiscard]] http::model::preview::Response handle(http::request&& req, const Principal& principal);

inline constexpr std::chrono::minutes kCallDeadline{10};
void setCallDeadlineForTesting(std::chrono::milliseconds deadline);

}
