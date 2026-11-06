#pragma once

#include "auth/Fwd.hpp"
#include "identities/Fwd.hpp"

#include <cstdint>
#include <string_view>

// Who must sign in with a second factor (#357; MFA design note docs/dev/mfa-design.md section 7.1, decision D2).
//
// Levels: `optional` (nobody, unless the account's own user_mfa.required is set), `admins` (the super admin and every
// account whose admin role holds a privileged permission; see privileged()), `all` (every human account). Every
// install runs `admins` (D2); the policy issue (#360) makes the level configurable and audits weakening it.
//
// The same answer is applied twice, so neither a password nor an old session can get around it:
//   - at sign-in (auth::mfa::signin::beginIfDue): a password alone never completes the sign-in of an account that
//     must have MFA; it reaches pending-MFA (or pending-enrollment when the account has no factor yet);
//   - on every use of a signed-in web session, through the session assurance hook (auth/session/Assurance.hpp): a
//     refresh row at aal 1 of an account that must have MFA is revoked and refused. Sessions signed in before an
//     upgrade, a role change or a policy raise are never grandfathered (D2).
// Device sessions (Vaulthalla Desktop over the pinned mTLS tunnel) never sign in with a password and carry no level:
// none of this applies to them, and they never prompt.
namespace vh::auth::mfa::policy {

enum class Level : uint8_t { Optional, Admins, All };
[[nodiscard]] std::string_view to_string(Level level) noexcept;

// The level in force. `admins` unless setLevel changed it.
[[nodiscard]] Level level() noexcept;
// Changes the level (tests; the policy issue's configuration). Bumps the policy epoch, so cached session validations
// re-read their rows.
void setLevel(Level level);

// The super admin, or an account whose admin role may change users or admins (add, edit, delete, reset passwords),
// admin or vault roles (add, edit, delete), any settings section (edit), or encryption keys (export, rotate). The
// list is published in the auth.mfa.status contract entry.
[[nodiscard]] bool privileged(const identities::User& user);

enum class Reason : uint8_t { None, PolicyAdmins, PolicyAll, UserRequired };
// "none", "policy_admins", "policy_all", "user_required" (auth.mfa.status policy.reason).
[[nodiscard]] std::string_view to_string(Reason reason) noexcept;

struct Requirement {
    bool required{false};
    Reason reason{Reason::None};
};

// Whether `user` must sign in with a second factor. Reads user_mfa.required from the database.
[[nodiscard]] Requirement requirement(const identities::User& user);

// The session assurance policy: a row satisfies it at aal 2, or when its account need not have MFA. Cheap on the hot
// path: an aal 2 row is decided without a lookup, and user_mfa.required is cached per account and policy epoch.
[[nodiscard]] bool rowSatisfies(const identities::User& user, const model::RefreshToken& row);

// Installs rowSatisfies as the session assurance policy (daemon startup).
void install();

}
