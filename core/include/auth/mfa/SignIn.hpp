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
[[nodiscard]] std::vector<std::string> methods(uint32_t userId);

// After a correct password. False when the sign-in may complete now at aal 1: the account has no usable factor and
// need not have MFA. Otherwise the socket is left pending and this returns true:
//   - kind Mfa when the account has a usable factor (whatever the policy: an enrolled factor is always asked for);
//   - kind Enrollment when it must have MFA and has none (the guided first run, 10 minutes).
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

// Factor failures per account, across sockets: 5 within 15 minutes and the account's sign-in factors are refused
// (rate_limited) until the oldest of them is 15 minutes old. Never a permanent lock. In memory; the policy issue (#360)
// adds the doubling backoff and notifications.
inline constexpr int kAccountFailureLimit = 5;
inline constexpr std::chrono::minutes kAccountFailureWindow{15};

// Zero when the account may try a factor now, else how long until it may.
[[nodiscard]] std::chrono::seconds accountRetryAfter(uint32_t userId);
void recordAccountFailure(uint32_t userId);
void clearAccountFailures(uint32_t userId);
// Tests.
void resetAccountFailuresForTesting();

}
