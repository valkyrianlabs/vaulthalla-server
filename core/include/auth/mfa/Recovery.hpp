#pragma once

#include "identities/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <nlohmann/json_fwd.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// What a recovery does to an account (#360; MFA design note section 7.4, decision D4). Three paths, each auditable
// from the trail alone (section 7.5):
//
//   - a recovery-code sign-in (auth.mfa.verify with method recovery_code): the session is RecoveryRestricted (its row's
//     amr holds "rec"). Every other web session of the account is signed out and the key-backup grants of its paired
//     devices are revoked, automatically. The devices themselves are listed for the person to revoke one by one, never
//     revoked here (a lost browser factor must not break a legitimate Desktop's sync).
//   - an admin reset (auth.mfa.admin.reset) and a host reset (`vh user mfa reset`): every factor is disabled (kept for
//     the audit trail), every recovery code voided, every session signed out, the key-backup grants revoked, and the
//     account is marked required (user_mfa.required): its next sign-in is the guided enrollment.
//
// All three start the recovery cooldown (auth.mfa.recovery_cooldown_hours, user_mfa.recovery_cooldown_until): until it
// ends, keys, device.trust, identity.admin, secrets and settings are refused (recovery_cooldown, auth/stepup), and a
// factor enrolled meanwhile is marked created_during_recovery and can't satisfy a step-up of those families. The user
// and the security recipients are notified (notifications/AccountSecurity.hpp).
//
// Authorization is the caller's: ops::mfa decides who may reset whom.
namespace vh::auth::mfa::recovery {

enum class Reason : uint8_t { RecoveryCode, AdminReset, CliReset };
// "recovery_code", "admin_reset", "cli_reset" (key_backup_grants.revoked_reason, audit details).
[[nodiscard]] std::string_view to_string(Reason reason) noexcept;

// auth.mfa.recovery_cooldown_hours.
[[nodiscard]] std::chrono::hours cooldown();
// The account's cooldown end (Unix seconds) while it runs, else nullopt.
[[nodiscard]] std::optional<int64_t> cooldownUntil(uint32_t userId);
// DB-free tests: answer cooldownUntil from `source` instead of user_mfa while the guard lives.
class CooldownSourceForTesting {
public:
    explicit CooldownSourceForTesting(std::function<std::optional<int64_t>(uint32_t)> source);
    ~CooldownSourceForTesting();
    CooldownSourceForTesting(const CooldownSourceForTesting&) = delete;
    CooldownSourceForTesting& operator=(const CooldownSourceForTesting&) = delete;
};
// Whether a factor enrolled now counts as enrolled during recovery: the cooldown runs, or the session asking signed in
// with a recovery code.
[[nodiscard]] bool enrollingDuringRecovery(uint32_t userId, bool recoveryRestrictedSession);

// A paired device as the recovery answer lists it (the person decides whether to revoke it).
struct DeviceSummary {
    uint32_t id{};
    std::string name{};
    std::string platform{};
    std::optional<int64_t> last_seen_at{};
    bool key_backup_revoked{false};
};
void to_json(nlohmann::json& j, const DeviceSummary& d);

// The account's live paired devices.
[[nodiscard]] std::vector<DeviceSummary> devices(uint32_t userId);

// Revokes the key-backup grants of the account's live devices (ops::backup_grants::revokeForUser, #362), each
// recorded as keys.backup.grant.revoke. Returns how many. `actor`: who caused it (the account itself for a recovery
// code).
std::size_t revokeKeyBackupGrants(uint32_t userId, Reason reason, std::optional<uint32_t> actorId);

struct SignInEffects {
    std::size_t sessions_revoked{};
    std::size_t grants_revoked{};
    int64_t cooldown_until{};
    std::vector<DeviceSummary> devices{};
};
// After a recovery-code sign-in completed on `session` (signed in, its row written): the effects above, recorded as
// auth.mfa.recovery.signin, and the notices.
[[nodiscard]] SignInEffects afterRecoveryCodeSignIn(const std::shared_ptr<protocols::ws::Session>& session,
                                                    const std::string& batchId, std::size_t codesRemaining);

struct Resetter {
    std::optional<uint32_t> id{};  // the admin or CLI user
    std::string name{};
    Reason channel{Reason::AdminReset};  // AdminReset (ws) or CliReset (vh)
};

struct ResetEffects {
    std::size_t factors_disabled{};
    std::size_t recovery_batches_voided{};
    std::size_t sessions_revoked{};
    std::size_t grants_revoked{};
    int64_t cooldown_until{};
};
void to_json(nlohmann::json& j, const ResetEffects& e);

// Resets `target`'s MFA (see the namespace comment), recorded as auth.mfa.admin.reset by `by` with `reason`, plus
// auth.mfa.factor.remove per factor and keys.backup.grant.revoke per device, and notified.
ResetEffects reset(const identities::User& target, const Resetter& by, std::string_view reason);

}
