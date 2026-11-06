#pragma once

#include "auth/session/Assurance.hpp"
#include "identities/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

// The two-step console sign-in (#357; MFA design note sections 5.2, 5.3, 7.2 and 8). auth::Manager::loginUser checks
// the password; beginIfDue decides whether that completes the sign-in or leaves the socket pending (auth/mfa/
// Pending.hpp); the ws handlers (protocols/ws/handler/Mfa.cpp) run the factor and call complete().
//
// complete() is the only place a pending sign-in becomes a session: setAuthenticatedUser and promote(), which inserts
// the socket's refresh row once, with the proof (aal, amr, auth_time). Nothing before it touches session->user.
namespace vh::auth::mfa::signin {

// The second factors `userId` can answer with here, in the console's order: "webauthn" (a usable passkey and
// passkeys configured), "totp" (a confirmed authenticator), "recovery_code" (an acknowledged batch with codes left).
// Factors the account's policy rule refuses (auth.mfa.admin_webauthn_only / admin_device_bound_only) are left out.
[[nodiscard]] std::vector<std::string> methods(const identities::User& user);

// After a correct password. False when the sign-in may complete now at aal 1: the account has no usable factor and
// need not have MFA. Otherwise the socket is left pending and this returns true:
//   - kind Mfa when the account has a usable factor its policy rule allows (whatever the level: an enrolled factor is
//     always asked for);
//   - kind Enrollment when it must have MFA and has none the rule allows (the guided first run, 10 minutes; for an
//     admin held to passkeys whose only factor is an authenticator app, a passkey is all it may set up).
// Audited as auth.mfa.challenge. Throws ops::Refused("mfa_unavailable") when the account's only factors can't be
// used on this server (passkeys while auth.webauthn is unset) and it has no recovery codes: the sign-in can't go on,
// and a password alone never completes it.
[[nodiscard]] bool beginIfDue(const std::shared_ptr<protocols::ws::Session>& session,
                              const std::shared_ptr<identities::User>& user);

// Signs the socket in as `user` with `proof` (one refresh row, the access token on the next answer), ends the pending
// state and records the sign-in (last login, auth.login.success with `method`).
void complete(const std::shared_ptr<protocols::ws::Session>& session, const std::shared_ptr<identities::User>& user,
              const session::assurance::Proof& proof, std::string_view method);

// Ends a pending sign-in (cancel, expiry, too many failures, sign-out) and drops its open challenges.
void end(const std::shared_ptr<protocols::ws::Session>& session, std::string_view reason);

// Factor failures per account, across sockets (design 7.3): the 5th failure in a streak delays the account's next
// factor by 1 minute, and every further one doubles it, up to 15 minutes. Never a permanent lock (an attacker could lock
// a real user out): the delay is all there is, and a streak ends 15 quiet minutes after the last failure or delay, or
// at the next success. The 10th failure of a streak notifies the user and the security recipients. In memory: a
// daemon restart forgets streaks (the audit trail keeps every failure).
inline constexpr int kAccountFailureLimit = 5;
inline constexpr int kAccountNotifyAt = 10;
inline constexpr std::chrono::minutes kAccountFailureWindow{15};
inline constexpr std::chrono::minutes kAccountFirstDelay{1};
inline constexpr std::chrono::minutes kAccountMaxDelay{15};

// The streak arithmetic, without storage, clocks or side effects (unit-tested on its own).
class AccountBackoff {
public:
    using Clock = std::chrono::steady_clock;

    struct Failure {
        int failures{};                     // in this streak, this one included
        std::chrono::seconds delay{0};      // from now until the account may try again (0: no delay yet)
        bool notify{false};                 // this failure reached kAccountNotifyAt (once per streak)
    };

    Failure fail(Clock::time_point now);
    [[nodiscard]] std::chrono::seconds retryAfter(Clock::time_point now) const;
    // The delay a streak of `failures` sets: 0 below the limit, then 1, 2, 4, 8, 15, 15, ... minutes.
    [[nodiscard]] static std::chrono::seconds delayFor(int failures) noexcept;
    // A streak that ended (15 quiet minutes) counts from zero again.
    [[nodiscard]] bool expired(Clock::time_point now) const;

private:
    int failures_{0};
    Clock::time_point last_{};
    Clock::time_point lockedUntil_{};
    bool notified_{false};
};

// Zero when the account may try a factor now, else how long until it may.
[[nodiscard]] std::chrono::seconds accountRetryAfter(uint32_t userId,
                                                     AccountBackoff::Clock::time_point now = AccountBackoff::Clock::now());
// A failed factor: records it, audits auth.mfa.lockout when it sets a delay, and notifies at the 10th.
AccountBackoff::Failure recordAccountFailure(uint32_t userId,
                                             AccountBackoff::Clock::time_point now = AccountBackoff::Clock::now());
void clearAccountFailures(uint32_t userId);
// Tests.
void resetAccountFailuresForTesting();

}
