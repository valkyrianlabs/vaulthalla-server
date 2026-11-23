#pragma once

#include "device/Peer.hpp"
#include "identities/Fwd.hpp"

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

// Scoped devices, accountable at audit time (design/core/mcp-remote-signin.md, "Scoped devices"), through the existing
// hash-chained trail only.
namespace vh::device {

// The audit origin of a device's request ("[via ...]" on every line it writes, the chain's `origin` column):
// "device <id16>", then " <surface>" when given ("mcp"), then " scope <scope>" for a scoped device. An unscoped
// device's origin is exactly what it was before scopes.
[[nodiscard]] std::string auditOrigin(const Peer& peer, std::string_view surface = {});

namespace scope_audit {

// At most this many refusals a minute are recorded per device; the rest are counted and reported (`suppressed`) with
// the next one recorded, so a looping agent can't flood the trail and no refusal goes unaccounted.
inline constexpr int kPerWindow = 5;
inline constexpr std::chrono::seconds kWindow{60};

// Records device.scope.refused (outcome denied) for a request the device's scope refused: the device row, the surface
// ("ws", "http" or "mcp"), what was asked (a ws command, an HTTP method and lane, an MCP command), its effect (null
// when unknown) and the scope. A command the contract doesn't know is recorded as "(unknown)", never as sent.
void refused(const Peer& peer, const std::shared_ptr<identities::User>& user, std::string_view surface,
             std::string_view what, std::optional<std::string_view> effect);

void resetForTesting();
// Ends every device's current window (tests: the next refusal starts a new one and reports what was suppressed).
void expireWindowsForTesting();

}

}
