#pragma once

#include "auth/Fwd.hpp"
#include "identities/Fwd.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

// Session assurance (#354; MFA design note docs/dev/mfa-design.md section 5.3). A signed-in web session's refresh
// token row records how the sign-in was proven: aal (1: one factor, 2: a second factor or a passkey), amr (the
// methods) and auth_time. The row is written once, at sign-in, and is the only authority: the refresh JWT is minted
// at the websocket handshake, before anyone signs in, and carries no level.
//
// The MFA policy is checked against that row on every use of the session: rehydrating from the cookie (handshake,
// validate, auth.refresh, the HTTP lanes) and every validation of a signed-in socket. A row below what the policy
// requires for its user is revoked and the session refused, which is how a policy raise, an upgrade or an admin
// "require MFA" takes effect: at next use, never by trusting a claim. Until the policy issue (#360) installs a real
// policy, every row satisfies it.
namespace vh::auth::session::assurance {

// amr values (RFC 8176 names where one fits).
inline constexpr std::string_view kPassword = "pwd";
inline constexpr std::string_view kHardwareKey = "hwk";  // device-bound passkey or security key
inline constexpr std::string_view kSoftwareKey = "swk";  // synced passkey
inline constexpr std::string_view kOneTimeCode = "otp";  // TOTP
inline constexpr std::string_view kRecoveryCode = "rec";

// How a sign-in was proven: what promote() writes on the new row.
struct Proof {
    uint8_t aal{1};
    std::vector<std::string> amr{std::string(kPassword)};
};

// A password sign-in with no second factor.
[[nodiscard]] Proof password();

// Whether the stored row still satisfies the account's MFA policy.
using Policy = std::function<bool(const identities::User& user, const model::RefreshToken& row)>;

[[nodiscard]] bool satisfied(const identities::User& user, const model::RefreshToken& row);

// The check on a session's use: when `row` no longer satisfies the policy, revokes it (the stored row and this copy),
// records auth.session.revoke (reason assurance_policy) and throws std::runtime_error. A no-op otherwise.
void enforce(const identities::User& user, model::RefreshToken& row);

// Installs the policy (null: every row satisfies it). Bumps rbac::policyEpoch(), so no validation cache keeps a session
// that the new policy refuses.
void setPolicy(Policy policy);

// The MFA policy or a user's factors changed: bumps rbac::policyEpoch() so the 30 s refresh validation cache
// (session::Manager) re-reads every row on its next use.
void policyChanged() noexcept;

}
