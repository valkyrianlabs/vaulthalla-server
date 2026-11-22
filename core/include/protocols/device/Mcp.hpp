#pragma once

#include "protocols/http/Router.hpp"
#include "protocols/mcp/HttpTransport.hpp"
#include "protocols/ws/Fwd.hpp"

#include <chrono>
#include <memory>

// Remote MCP on the device listener: the shared Streamable HTTP transport (protocols/mcp/HttpTransport.hpp) for a
// paired device's session only, as the device's user, with the device's ceiling (every effect today; a scoped device
// carries a narrower one later, design/core/mcp-remote-signin.md "Scoped devices").
namespace vh::protocols::device::mcp {

[[nodiscard]] protocols::http::model::preview::Response handle(protocols::http::request&& req, const std::shared_ptr<ws::Session>& principal);

inline constexpr std::chrono::minutes kCallDeadline = protocols::mcp::kCallDeadline;
void setCallDeadlineForTesting(std::chrono::milliseconds deadline);

}
