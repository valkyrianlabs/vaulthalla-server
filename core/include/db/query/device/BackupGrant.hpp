#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// The `key_backup_grants`, `key_backup_grant_vaults` and `key_backup_grant_migration` tables (migration 129, #362).
// Trusted primitives: callers (device::backup, ops::backup_grants) authorize, decide and audit.
namespace vh::db::query::device {

struct BackupGrant {
    uint32_t id{};
    uint32_t device_id{};
    uint32_t user_id{};
    std::string origin{};                      // "approved" or "migrated"
    std::optional<std::string> approved_via{};  // webauthn, password_totp, device_approval, console_approval
    std::vector<uint32_t> vault_ids{};          // ascending
    std::time_t created_at{};
    std::optional<std::time_t> confirmed_at{};
    std::optional<std::time_t> last_used_at{};
    std::optional<std::time_t> suspended_at{};
    std::optional<std::time_t> revoked_at{};
    std::optional<std::string> revoked_reason{};

    [[nodiscard]] bool live() const noexcept { return !revoked_at; }
    // Live and not suspended: the only state in which it covers an export.
    [[nodiscard]] bool active() const noexcept { return !revoked_at && !suspended_at; }
    [[nodiscard]] bool names(uint32_t vaultId) const noexcept;
};

struct NewBackupGrant {
    uint32_t device_id{};
    uint32_t user_id{};
    std::string origin{"approved"};
    std::optional<std::string> approved_via{};
    std::vector<uint32_t> vault_ids{};
};

// A device of the D1 snapshot that the daemon has not turned into a grant yet.
struct PendingMigration {
    uint32_t device_id{};
    uint32_t user_id{};
    bool device_live{};
};

class BackupGrants {
public:
    [[nodiscard]] static std::optional<BackupGrant> byId(uint32_t id);
    // The device's live grant (suspended or not), if any.
    [[nodiscard]] static std::optional<BackupGrant> liveForDevice(uint32_t deviceId);
    // The device's most recently revoked grant.
    [[nodiscard]] static std::optional<BackupGrant> lastRevokedForDevice(uint32_t deviceId);
    // Every grant of the user, live first, newest first.
    [[nodiscard]] static std::vector<BackupGrant> listForUser(uint32_t userId);
    // Every live grant (all users), or the live grants of `userIds`.
    [[nodiscard]] static std::vector<BackupGrant> listLive();
    [[nodiscard]] static std::vector<BackupGrant> listLiveForUsers(const std::vector<uint32_t>& userIds);

    // Inserts a grant and its vaults. ops::Conflict when the device already has a live grant or is not live.
    [[nodiscard]] static BackupGrant create(const NewBackupGrant& g);
    // Adds vaults to a live grant. nullopt when the grant is not live.
    [[nodiscard]] static std::optional<BackupGrant> addVaults(uint32_t grantId, const std::vector<uint32_t>& vaultIds);
    // A live grant becomes origin 'approved', confirmed now, by `approvedVia`, and no longer suspended. nullopt when
    // the grant is not live.
    [[nodiscard]] static std::optional<BackupGrant> confirm(uint32_t grantId, const std::optional<std::string>& approvedVia);
    // Suspends a live, active grant. nullopt when it was not (already suspended, or revoked).
    [[nodiscard]] static std::optional<BackupGrant> suspend(uint32_t grantId);
    // Revokes a live grant with `reason`. nullopt when it was not live.
    [[nodiscard]] static std::optional<BackupGrant> revoke(uint32_t grantId, const std::string& reason);
    // Revokes the device's / the user's live grants with `reason`; the revoked rows.
    [[nodiscard]] static std::vector<BackupGrant> revokeForDevice(uint32_t deviceId, const std::string& reason);
    [[nodiscard]] static std::vector<BackupGrant> revokeForUser(uint32_t userId, const std::string& reason);
    // last_used_at = now.
    static void touch(uint32_t grantId);

    // Whether the device's approval key is live and was registered before `grantId` was revoked (D4: re-creating a
    // grant a recovery-code sign-in revoked).
    [[nodiscard]] static bool approvalKeyPredatesRevocation(uint32_t deviceId, uint32_t grantId);

    // ---- D1 (the migration's snapshot)
    [[nodiscard]] static std::vector<PendingMigration> pendingMigration();
    // In one transaction: removes the device's snapshot row and, when `vaultIds` is set and the device is live and
    // has no grant yet, inserts its origin 'migrated' grant. The grant, if one was made.
    [[nodiscard]] static std::optional<BackupGrant> migrate(uint32_t deviceId, uint32_t userId,
                                                            const std::optional<std::vector<uint32_t>>& vaultIds);
};

}
