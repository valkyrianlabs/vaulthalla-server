#pragma once

#include "auth/Fwd.hpp"
#include "auth/mfa/Factors.hpp"
#include "config/Config.hpp"
#include "identities/Fwd.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Who must sign in with a second factor (#357; MFA design note docs/dev/mfa-design.md section 7.1, decision D2).
//
// Levels: `optional` (nobody, unless the account's own user_mfa.required is set), `admins` (the super admin and every
// account whose admin role holds a privileged permission; see privileged()), `all` (every human account). The level is
// auth.mfa.policy (#360), `admins` on new and upgraded installs (D2: a config.yaml without the key runs it). Changing
// it is a settings change (settings step-up); weakening it is audited and mailed to the security recipients
// (ops/Config.cpp, weakenings()).
//
// Accounts the admins policy names (privileged()) can be held to stronger factors: auth.mfa.admin_webauthn_only
// (passkeys only, no authenticator app) and admin_device_bound_only (device-bound passkeys only, no synced ones; implies
// webauthn only). A factor the rule refuses doesn't count: it can't sign in, step up or satisfy the policy, so an
// admin holding only such factors is led through enrollment again, and a session it signed in is refused at next use.
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

// The level in force: auth.mfa.policy.
[[nodiscard]] Level level() noexcept;
[[nodiscard]] std::optional<Level> parseLevel(std::string_view name) noexcept;
// Sets auth.mfa.policy in the running configuration (tests; the daemon changes it through settings.update). Bumps the
// policy epoch, so cached session validations re-read their rows.
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

// What `user` may use as a factor (auth.mfa.admin_webauthn_only / admin_device_bound_only, for privileged accounts).
struct FactorRule {
    bool totp{true};             // authenticator apps
    bool synced_passkeys{true};  // passkeys with the backup-eligible flag (1Password, iCloud Keychain, ...)
    [[nodiscard]] bool restricted() const noexcept { return !totp || !synced_passkeys; }
};
[[nodiscard]] FactorRule factorRule(const identities::User& user);
// `backupEligible` is the passkey's BE flag (ignored for TOTP).
[[nodiscard]] bool factorAllowed(const identities::User& user, FactorKind kind, bool backupEligible = false);
[[nodiscard]] bool factorAllowed(const identities::User& user, const Factor& factor);
// Whether the account has a factor it can sign in with now that the rule allows (not suspended).
[[nodiscard]] bool hasAllowedFactor(const identities::User& user);
// The account's passkeys usable on this server (passkeys::usableCredentials) that the rule allows. `excludeRecovery`:
// also leave out those marked created_during_recovery (a step-up of a cooldown family while the cooldown runs).
[[nodiscard]] std::vector<WebAuthnCredential> allowedPasskeys(const identities::User& user, bool excludeRecovery = false);
// Whether the account has a confirmed authenticator app the rule allows (`excludeRecovery` as above).
[[nodiscard]] bool hasAllowedTotp(const identities::User& user, bool excludeRecovery = false);

// The session assurance policy: a row satisfies it at aal 2 (with a proof the factor rule allows; a recovery code
// always does, since enrolling an allowed factor is what that session must do next), or when its account need not
// have MFA. Cheap on the hot path: an aal 2 row is decided without a lookup, and user_mfa.required is cached per
// account and policy epoch.
[[nodiscard]] bool rowSatisfies(const identities::User& user, const model::RefreshToken& row);

// What a settings change weakens (design 7.1): "policy" (to a level that requires fewer accounts),
// "admin_webauthn_only" / "admin_device_bound_only" (turned off), "webauthn.rp_id" (changed from a set value). Empty when nothing
// weakens.
[[nodiscard]] std::vector<std::string> weakenings(const config::AuthConfig& from, const config::AuthConfig& to);
// Whether a settings change touches the MFA policy at all (auth.mfa.policy, the admin flags, auth.webauthn.rp_id).
[[nodiscard]] bool policyChanged(const config::AuthConfig& from, const config::AuthConfig& to);

// Installs rowSatisfies as the session assurance policy (daemon startup).
void install();

}
