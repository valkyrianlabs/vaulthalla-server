#pragma once

#include <chrono>

namespace vh::protocols::ws { class Session; }

// Idle sign-out for web-console sessions (#319). A human session's idle clock is the refresh token's lastActivity:
// set by the server (its own clock) at sign-in and whenever the console reports real user input (auth.activity),
// never by background traffic. Past services.connection_lifecycle_manager.idle_timeout_minutes the refresh token is
// revoked wherever the session is next used, and the lifecycle sweep closes its socket, so the console can't sign
// back in silently. Paired devices (mTLS) and share sessions are not human web sessions and are exempt.
namespace vh::auth::session::idle {

// The configured timeout; zero means disabled.
[[nodiscard]] std::chrono::minutes timeout();

// Whether this session is subject to idle sign-out: signed in as a person, over the web listener, not a share link.
[[nodiscard]] bool applies(const protocols::ws::Session& session);

[[nodiscard]] constexpr bool expired(const std::chrono::system_clock::time_point lastActivity,
                                     const std::chrono::system_clock::time_point now,
                                     const std::chrono::minutes limit) {
    return limit.count() > 0 && now - lastActivity > limit;
}

// expired() for this session's refresh token now. False when idle sign-out doesn't apply.
[[nodiscard]] bool sessionExpired(const protocols::ws::Session& session);

// How often the console may report activity that the server writes to the database (more often is accepted and
// ignored): bounds DB writes without losing more than this much of the idle window.
inline constexpr std::chrono::seconds kActivityWriteInterval{30};

}
