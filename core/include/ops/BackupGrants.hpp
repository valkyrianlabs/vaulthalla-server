#pragma once

#include "db/query/device/BackupGrant.hpp"
#include "device/Device.hpp"
#include "device/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "ops/Actor.hpp"

#include <nlohmann/json_fwd.hpp>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Key-backup grants (#362; MFA design note docs/dev/mfa-design.md section 6.4, decisions D1 and D4;
// docs/reference/device-approvals.md "Key-backup grants").
//
// Vaulthalla Desktop backs up every needed version of each vault key to 1Password in the background. Three acts are
// kept apart:
//   - consent: device.backup.grant.create {vault_ids}, once, deliberate: a device.trust approval (the device's approval
//     key, a console approval, or a passkey / password+TOTP step-up in the console);
//   - ongoing backup (reconnects, new key versions, rotations, mid-rotation versions): vault.keys.export from that
//     device for a vault its grant names needs no step-up, ever (covering() below);
//   - a discretionary export (a vault outside the grant, a suspended grant, export all of a vault it doesn't name):
//     the keys step-up for that export, target-bound.
//
// A grant is bound to one device row and one user and names its vaults explicitly. A vault is added only by
// device.backup.grant.extend (another device.trust approval). It is capped at kMaxExportsPerHour vault exports per
// hour; above that it is suspended (keys.backup.grant.suspend) and the user notified, and confirming it again lifts the
// suspension. It is revoked automatically when the device is revoked (with it, in one transaction), the user is
// deactivated, deleted or loses the encryption-key Export permission (the identities publication hook, the export
// itself, and the sweep), the user's MFA is reset or a recovery-code sign-in happens (revokeForUser, called by the
// recovery paths), or the device hasn't connected for kDeviceIdle (the handshake, before it records the connection,
// and the sweep). By hand: device.backup.grant.revoke, which needs nothing (revocation makes things safer).
//
// D1: devices paired before the grant table existed keep their automatic backup through an origin 'migrated' grant
// over exactly the vaults their user could export at migration time (migratePending, once, at the first start after
// migration 130). Nothing is made for a user without the Export permission, and no vault is added that the user
// couldn't export then. confirm turns it into 'approved'; revoke ends it.
//
// D4: after a recovery-code sign-in revoked the grant, and while the recovery cooldown runs, the same device may
// re-create it only with its approval key (device_approval), only when that key was registered before the recovery,
// and only for vaults the revoked grant named.
//
// Every change is in the audit trail: keys.backup.grant.create|extend|confirm|migrate|suspend|revoke, and every use
// keys.backup.export {grant_id, versions} (the vault in vault_id). Details carry ids and counts only.
namespace vh::ops::backup_grants {

using Grant = db::query::device::BackupGrant;

inline constexpr std::size_t kMaxExportsPerHour = 60;
inline constexpr std::chrono::hours kExportWindow{1};
inline constexpr std::chrono::hours kDeviceIdle{24 * 90};

// Why a grant ended (key_backup_grants.revoked_reason).
enum class Revocation : uint8_t {
    Manual,            // device.backup.grant.revoke
    DeviceRevoked,     // the device was unpaired
    UserInactive,      // the user was deactivated or deleted
    ExportPermission,  // the user no longer holds encryption-key Export
    RecoveryCode,      // a recovery-code sign-in (D4)
    AdminReset,        // an admin reset the user's MFA
    CliReset,          // `vh user mfa reset`
    DeviceIdle,        // the device hasn't connected for kDeviceIdle
};
[[nodiscard]] std::string_view to_string(Revocation why) noexcept;

// {id, device_id (the device's 64-hex id), device_name, origin, approved_via, vault_ids, created_at, confirmed_at,
//  last_used_at, suspended_at, revoked_at, revoked_reason, active}: times are Unix seconds or null. The first reads the
// device row; the second takes it (null members when it is gone).
[[nodiscard]] nlohmann::json toJson(const Grant& grant);
[[nodiscard]] nlohmann::json toJson(const Grant& grant, const std::optional<vh::device::Device>& device);

// Whether `user` may hold a key-backup grant at all: signs in, and is a super admin or holds encryption-key Export.
[[nodiscard]] bool mayHold(const identities::User& user);

// ---- commands (ws device.backup.grant.*). `self` is the calling device's connection on a paired device's session.

// The caller's grants (live first); on a device's session, that device's only.
[[nodiscard]] std::vector<Grant> list(const Actor& actor, const vh::device::Peer* self);
// A new grant for the caller's own device (`self`, or `device` by its id on a console session) over `vaultIds` (each a
// vault the caller may export). device.trust step-up, target device.backup.grant.create:<device row>:<vaults>.
[[nodiscard]] Grant create(const Actor& actor, const vh::device::Peer* self, const std::optional<std::string>& device,
                           const std::vector<uint32_t>& vaultIds);
// Adds vaults to a live grant of the caller's. device.trust, target device.backup.grant.extend:<grant>:<vaults>.
[[nodiscard]] Grant extend(const Actor& actor, const vh::device::Peer* self, uint32_t grantId,
                           const std::vector<uint32_t>& vaultIds);
// Confirms a live grant: a migrated one becomes approved, a suspended one active again. device.trust, target
// device.backup.grant.confirm:<grant>.
[[nodiscard]] Grant confirm(const Actor& actor, const vh::device::Peer* self, uint32_t grantId);
// Revokes a live grant of the caller's (super admins: anyone's). No step-up.
[[nodiscard]] Grant revoke(const Actor& actor, const vh::device::Peer* self, uint32_t grantId);

// The step-up target of create/extend: the vault ids ascending, comma-separated, or "sha256:<32 hex>" of that list when
// the target would exceed auth::stepup::kMaxTargetLength.
[[nodiscard]] std::string createTarget(uint32_t deviceRowId, std::vector<uint32_t> vaultIds);
[[nodiscard]] std::string extendTarget(uint32_t grantId, std::vector<uint32_t> vaultIds);
[[nodiscard]] std::string confirmTarget(uint32_t grantId);
// D4's exception to the recovery cooldown, for auth::approval: whether `target` is a create target for this device
// whose latest grant a recovery-code sign-in revoked and whose live approval key predates that revocation. Only then
// may the device's approval key be challenged for device.trust while the cooldown runs; create still checks the vaults.
[[nodiscard]] bool recoveryRecreateTarget(uint32_t deviceRowId, const std::string& target);

// ---- the export path (ops::vault_keys)

struct Use {
    uint32_t grant_id{};
    uint32_t device_id{};
    uint32_t user_id{};
    std::string user_name{};
};
// On a paired device's session (the request's step-up Scope is Device): the device's active grant when it names every
// vault in `vaultIds` and its cap allows that many more exports this hour; nullopt otherwise (the caller then asks for
// the keys step-up). A grant whose user may no longer hold one, or whose device was revoked, is revoked here. Going
// over the cap suspends the grant and notifies the user.
[[nodiscard]] std::optional<Use> covering(const std::vector<uint32_t>& vaultIds);
// After a covered export: last_used_at, and keys.backup.export {grant_id, device, versions} for the vault.
void recordUse(const Use& use, uint32_t vaultId, const std::vector<unsigned int>& versions);

// ---- automatic revocation

// Revokes the live grants of a device / a user for `why`, each audited as keys.backup.grant.revoke. `actorId`: who
// caused it (nullopt: the daemon). Returns the revoked grants.
std::vector<Grant> revokeForDevice(uint32_t deviceId, Revocation why, std::optional<uint32_t> actorId = std::nullopt);
std::vector<Grant> revokeForUser(uint32_t userId, Revocation why, std::optional<uint32_t> actorId = std::nullopt);
// Audits grants a device revocation already revoked in its own transaction (db Devices::revoke / revokeAll).
void auditRevoked(const std::vector<Grant>& grants, Revocation why, std::optional<uint32_t> actorId);
// The device handshake, before it records the connection: revokes the device's live grant when the device hasn't
// connected for kDeviceIdle (since last_seen_at, or since pairing when it never did). True when it did.
bool revokeIfIdle(const vh::device::Device& device, std::time_t now = std::time(nullptr));
// Checks every live grant (or those of `userIds`) against the triggers: device revoked or idle, user gone, inactive or
// without Export. Returns how many it revoked. The DB sweep, startup and the identities publication hook call it.
std::size_t reconcile(const std::optional<std::vector<uint32_t>>& userIds = std::nullopt);
// identities::Manager's publication hook: every published account change is checked at once.
void installIdentityHook();

// ---- D1

// Turns the migration's snapshot into origin 'migrated' grants (see the namespace comment). Idempotent: each snapshot
// row is claimed once. A device whose authority migration 129's interim column had revoked (#360) gets its grant
// already revoked (time and reason carried over): no live authority, only D4's re-creation record. Returns how many
// live grants it made.
std::size_t migratePending();

// ---- notices and tests

// The user's notice when a grant is suspended (account security notice; tests: a sink).
using SuspendNotice = std::function<void(const Grant& grant)>;
void setSuspendNoticeForTesting(SuspendNotice sink);
void resetExportWindowsForTesting();

}
