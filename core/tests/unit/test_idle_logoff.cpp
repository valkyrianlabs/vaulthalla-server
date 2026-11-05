// #319: idle sign-out for web-console sessions. services.connection_lifecycle_manager.idle_timeout_minutes was read
// and never enforced ("TODO: implement idle timeout logic"). The idle clock is the refresh token's lastActivity, set
// by the server at sign-in and on auth.activity (real input reported by the console); the sweep closes sessions past
// it, and any use of an idle token revokes it. Paired devices and share links are exempt; 0 turns it off.
// DB-backed behaviour (revocation, rehydration, other tabs) is in test_ops_parity_users.cpp.

#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Idle.hpp"
#include "config/Registry.hpp"
#include "identities/User.hpp"
#include "protocols/ws/ConnectionLifecycleManager.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <memory>

namespace vh::test_idle_logoff {

using namespace std::chrono_literals;
using Lifecycle = protocols::ws::ConnectionLifecycleManager;
using Verdict = Lifecycle::SweepVerdict;
namespace idle = auth::session::idle;

namespace {

std::shared_ptr<protocols::ws::Session> signedIn(const std::chrono::system_clock::time_point lastActivity) {
    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    session->markHandshakeCompleteForTesting();
    identities::UserState state;
    state.name = "idle-test";
    session->user = identities::User::detached(41, std::move(state));
    auto token = std::make_shared<auth::model::RefreshToken>();
    token->jti = "00000000-0000-4000-8000-000000000319";
    token->hashedToken = "sha256:test";
    token->expiresAt = std::chrono::system_clock::now() + 24h;
    token->lastActivity = lastActivity;
    session->tokens->refreshToken = token;
    return session;
}

}

TEST(IdleLogoff, ExpiryIsStrictlyPastTheLimitAndZeroTurnsItOff) {
    const auto now = std::chrono::system_clock::now();
    EXPECT_FALSE(idle::expired(now - 29min, now, 30min));
    EXPECT_FALSE(idle::expired(now - 30min, now, 30min));
    EXPECT_TRUE(idle::expired(now - 30min - 1s, now, 30min));
    EXPECT_FALSE(idle::expired(now - 24h, now, 0min)) << "0 disables idle sign-out";
}

TEST(IdleLogoff, TheSweepEndsIdleWebSessionsOnly) {
    const auto now = std::chrono::system_clock::now();
    const auto active = signedIn(now - 5min);
    const auto idleOne = signedIn(now - 31min);

    EXPECT_EQ(Lifecycle::verdict(*active, now, 60s, 30min), Verdict::Keep);
    EXPECT_EQ(Lifecycle::verdict(*idleOne, now, 60s, 30min), Verdict::IdleTimeout);
    EXPECT_EQ(Lifecycle::verdict(*idleOne, now, 60s, 0min), Verdict::Keep) << "0 disables idle sign-out";
    EXPECT_EQ(Lifecycle::verdict(*idleOne, now, 60s), Verdict::Keep) << "callers that don't pass a timeout";
    EXPECT_TRUE(idle::applies(*idleOne));

    // Background traffic doesn't move the clock: only lastActivity does, and nothing but sign-in and auth.activity
    // writes it. A token refresh (lastUsed) leaves an idle session idle.
    idleOne->tokens->refreshToken->lastUsed = now;
    EXPECT_EQ(Lifecycle::verdict(*idleOne, now, 60s, 30min), Verdict::IdleTimeout);
}

TEST(IdleLogoff, ShareSessionsAndUnauthenticatedSessionsAreExempt) {
    const auto now = std::chrono::system_clock::now();
    auto anonymous = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    anonymous->markHandshakeCompleteForTesting();
    EXPECT_FALSE(idle::applies(*anonymous));
    EXPECT_FALSE(idle::sessionExpired(*anonymous));

    const auto idleOne = signedIn(now - 31min);
    idleOne->tokens->refreshToken = nullptr;
    EXPECT_FALSE(idle::applies(*idleOne)) << "no refresh token: not a web-console session";
}

TEST(IdleLogoff, TheShippedDefaultIsThirtyMinutes) {
    EXPECT_EQ(config::ConnectionLifecycleManagerConfig{}.idle_timeout_minutes, 30u);
}

}
