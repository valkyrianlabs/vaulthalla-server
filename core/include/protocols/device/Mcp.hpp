#pragma once

#include "protocols/http/Router.hpp"
#include "protocols/mcp/HttpTransport.hpp"
#include "protocols/ws/Fwd.hpp"

#include <chrono>
#include <memory>

// Remote MCP on the device listener: the shared Streamable HTTP transport (protocols/mcp/HttpTransport.hpp) for a
// paired device's session only, as the device's user, with the device's scope as its ceiling (destructive, i.e. none,
// unless it was paired or set narrower: design/core/mcp-remote-signin.md "Scoped devices").
namespace vh::protocols::device::mcp {

[[nodiscard]] protocols::http::model::preview::Response handle(protocols::http::request&& req, const std::shared_ptr<ws::Session>& principal);

inline constexpr std::chrono::minutes kCallDeadline = protocols::mcp::kCallDeadline;
void setCallDeadlineForTesting(std::chrono::milliseconds deadline);

}
