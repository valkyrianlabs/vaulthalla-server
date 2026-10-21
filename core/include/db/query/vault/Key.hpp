#pragma once

#include <ctime>
#include <memory>
#include <optional>
#include <vector>

#include "vault/Fwd.hpp"

namespace vh::db::query::vault {

class Key {
    using K = vh::vault::model::Key;
    using KeyPtr = std::shared_ptr<K>;

public:
    [[nodiscard]] static unsigned int addVaultKey(const KeyPtr& key);
    static void deleteVaultKey(unsigned int vaultId);
    static void updateVaultKey(const KeyPtr& key);
    static KeyPtr getVaultKey(unsigned int vaultId);
    [[nodiscard]] static unsigned int rotateVaultKey(const KeyPtr& newKey);
    static void markKeyRotationFinished(unsigned int vaultId);
    [[nodiscard]] static bool keyRotationInProgress(unsigned int vaultId);
    [[nodiscard]] static KeyPtr getRotationInProgressOldKey(unsigned int vaultId);

    // Retired versions (vault_keys_trashed), still sealed under the vault master. Rotation never deletes them: data
    // recovery keeps (local versions, snapshots, provider object versions) may still be sealed with any of them.
    // updated_at of a retired key is when it was retired.
    [[nodiscard]] static KeyPtr getRetiredVaultKey(unsigned int vaultId, unsigned int version);  // nullptr if none
    [[nodiscard]] static std::vector<unsigned int> retiredKeyVersions(unsigned int vaultId);      // ascending
    [[nodiscard]] static bool hasRetiredKeyVersion(unsigned int vaultId, unsigned int version);
    // Key versions recoverable data still references (recovery_blob, live upstream_object_version rows), ascending:
    // the same set trigger recovery_guard_retired_vault_key protects. Unencrypted data (version 0/NULL) is left out.
    [[nodiscard]] static std::vector<unsigned int> recoveryReferencedKeyVersions(unsigned int vaultId);
    // Export tracking (#162): `vh vault keys export` records the version it exported. A rotation makes the current
    // version a new one, so an older export no longer counts.
    static void markExported(unsigned int vaultId, unsigned int version);
    // When the current key version was exported, or nullopt if it never was (or no export was recorded).
    [[nodiscard]] static std::optional<std::time_t> currentKeyExportedAt(unsigned int vaultId);
    // The last recorded export (any version; stale when it isn't the current one).
    struct ExportRecord {
        std::optional<unsigned int> version{};
        std::optional<std::time_t> at{};
    };
    [[nodiscard]] static ExportRecord exportRecord(unsigned int vaultId);
    // Marks `version` exported only while it is still the current version (one statement, so a rotation in between
    // wins). Returns when it was recorded, or nullopt when the version is no longer current.
    [[nodiscard]] static std::optional<std::time_t> markExportedIfCurrent(unsigned int vaultId, unsigned int version);
    // Retired versions whose rotation has not finished re-encrypting the vault (rotation_completed_at IS NULL),
    // ascending: the outgoing key still decrypts files the sync pass hasn't reached.
    [[nodiscard]] static std::vector<unsigned int> rotationPendingKeyVersions(unsigned int vaultId);
};

}
