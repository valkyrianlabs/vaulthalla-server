#pragma once

#include "protocols/http/Router.hpp"
#include "protocols/ws/Fwd.hpp"

#include <chrono>
#include <memory>

// Remote MCP on the device listener: Streamable HTTP (POST /mcp, JSON responses, no SSE stream, no MCP session id)
// for a paired device's session only. The catalog and JSON-RPC server are the ones `vh mcp` uses (core/usage/src/mcp):
// the same tools, exclusions (key and secret export, pairing, the listener's exposure, ...), destructive gate and
// structured confirmations. Each tool call runs as one non-interactive CLI line through shell::Router::executeLine
// for the device's user, abandoned after a deadline (the command itself is not interrupted).
namespace vh::protocols::device::mcp {

[[nodiscard]] protocols::http::model::preview::Response handle(protocols::http::request&& req, const std::shared_ptr<ws::Session>& principal);

inline constexpr std::chrono::minutes kCallDeadline{10};
void setCallDeadlineForTesting(std::chrono::milliseconds deadline);

}
