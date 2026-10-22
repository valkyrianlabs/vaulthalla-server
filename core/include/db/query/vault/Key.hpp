#pragma once

#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "fs/Fwd.hpp"
#include "vault/Fwd.hpp"

namespace vh::db::query::vault {

class Key {
    using K = vh::vault::model::Key;
    using KeyPtr = std::shared_ptr<K>;

public:
    // What the daemon records about a key version it holds (migration 113): its key check (vault/KeyCheck.hpp) and this
    // node's attestation over it (vault/KeyAttestation.hpp; absent when signing failed, backfilled later).
    struct Provenance {
        std::string key_check{};
        std::optional<unsigned int> attestation_key_id{};
        std::vector<uint8_t> attestation{};
    };
    // Inserts a vault's first key (version 1) and records its provenance (computed for version 1) in the same
    // transaction.
    [[nodiscard]] static unsigned int addVaultKey(const KeyPtr& key, const std::optional<Provenance>& provenance);
    static void deleteVaultKey(unsigned int vaultId);
    static void updateVaultKey(const KeyPtr& key);
    static KeyPtr getVaultKey(unsigned int vaultId);
    // Retires the current version and makes newKey the next one, in one transaction under the vault's rotation lock.
    // `expected` is the version the caller computed newKey's provenance for (current + 1; with no vault_keys row, the
    // version inserted): recorded when the database assigns that version, else left for the backfill. When `outgoing`
    // names the retiring version, the retired row's provenance is filled if it was never recorded (a row from before
    // migration 113). Salvage: `closePrior` first marks every pending rotation finished (its outgoing key isn't held,
    // and EncryptionManager holds one outgoing key), and `closeOutgoing` marks the version retired here finished too
    // when this host can't use it: no held key could re-encrypt their files. Provenance is computed before the
    // transaction: signing reads the database too.
    struct NewVersion {
        unsigned int version{};
        std::optional<Provenance> provenance{};
    };
    struct Outgoing {
        unsigned int version{};
        Provenance provenance{};
    };
    [[nodiscard]] static unsigned int rotateVaultKey(const KeyPtr& newKey, const NewVersion& expected,
                                                     const std::optional<Outgoing>& outgoing = std::nullopt,
                                                     bool closePrior = false, bool closeOutgoing = false);
    // Lazy backfill: the daemon unsealed `rec` and computed its provenance from the key. Stores it in every row holding
    // exactly these sealed bytes (vault_keys, vault_keys_trashed, vault_deletion_key copies) whose recorded key check
    // differs or whose attestation is missing: one conditional UPDATE per table, in one statement. Returns the rows
    // changed.
    static unsigned int recordProvenance(const K& rec, const Provenance& provenance);

    // This node's key attestation public keys (key_attestation_keys). The id of `publicKey`, inserted (and every
    // other key marked retired) when it is new.
    [[nodiscard]] static unsigned int attestationKeyId(const std::vector<uint8_t>& publicKey);
    [[nodiscard]] static std::optional<std::vector<uint8_t>> attestationPublicKey(unsigned int keyId);
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

    // ---- key import (vh vault keys import, ws vault.keys.import; .claude/context/key-backup.md)

    enum class SealedTable { Current, Retired, DeletionCopy };
    // One sealed row an import writes: re-sealed bytes for `version` in `table`.
    struct SealedWrite {
        SealedTable table{SealedTable::Current};
        unsigned int version{};
        std::vector<uint8_t> encrypted_key{}, iv{};
        // What the row held when the import was planned (encrypted_key, iv); nullopt = there was no row (insert).
        std::optional<std::pair<std::vector<uint8_t>, std::vector<uint8_t>>> expected{};
        bool rotation_pending{false};  // a new retired row whose rotation hasn't finished re-encrypting the vault
        Provenance provenance{};       // recorded with the row (the attestation that proved these bytes)
    };
    // Every write in one transaction under the vault's rotation lock (the advisory lock rotate_vault_key takes).
    // Existing rows keep their version, created_at, export marks and rotation state. Throws ops::Conflict, writing
    // nothing, when any row no longer holds what the plan read.
    static void writeImported(unsigned int vaultId, const std::vector<SealedWrite>& writes);
    // Local ciphertext sealed under `version`, smallest first: files rows (with backing paths) and recovery blobs.
    struct SealedSample {
        std::string path{};  // files: the backing path; blobs: the storage name
        std::string iv{};    // base64
        std::string vault_path{};   // files only: the vault path (the object key upstream, without its leading slash)
        uint64_t plaintext_bytes{};  // files only
    };
    [[nodiscard]] static std::vector<SealedSample> sampleSealedFiles(unsigned int vaultId, unsigned int version,
                                                                     unsigned int limit);
    [[nodiscard]] static std::vector<SealedSample> sampleRecoveryBlobs(unsigned int vaultId, unsigned int version,
                                                                       unsigned int limit);
    [[nodiscard]] static bool filesSealedUnder(unsigned int vaultId, unsigned int version);

    // ---- what the vault's data is sealed under (load_key's refusal to mint, import's "no ciphertext anywhere")

    // A short description of the sealed content the vault has ("3 files, 1 recovery blob"), or nullopt when it has
    // none: files rows with an IV, recovery blobs, live provider object versions, encrypted remote index entries.
    [[nodiscard]] static std::optional<std::string> sealedContentSummary(unsigned int vaultId);
    // Distinct key versions live files rows are sealed under (rows with an IV), ascending.
    [[nodiscard]] static std::vector<unsigned int> liveFileKeyVersions(unsigned int vaultId);
    // Every key version any of those sources records, ascending.
    [[nodiscard]] static std::vector<unsigned int> dataKeyVersions(unsigned int vaultId);
    // Every key version the daemon's own records reference, ascending: the vault_keys row, retired rows and the
    // version each retirement rotated to (version + 1), a deleted vault's retained copies and recorded version, and
    // dataKeyVersions. An import restores only these (it never introduces a version), and a vault with no vault_keys
    // row takes the highest of them as its current version.
    [[nodiscard]] static std::vector<unsigned int> referencedKeyVersions(unsigned int vaultId);
    [[nodiscard]] static bool ciphertextExistsUnder(unsigned int vaultId, unsigned int version);
    // The smallest object recorded upstream under `version`: object key, stored size, IV (base64). Encrypted
    // remote_object_index rows first, else files rows (the caller skips those with a local copy).
    struct RemoteSample {
        std::string object_key{};
        uint64_t stored_bytes{};
        std::string iv{};
    };
    [[nodiscard]] static std::vector<RemoteSample> remoteSamples(unsigned int vaultId, unsigned int version,
                                                                 unsigned int limit);

    // ---- key salvage (vault_key_salvage; key-backup.md "Salvage")

    struct Salvage {
        unsigned int id{}, vault_id{};
        std::vector<unsigned int> versions{};
        std::optional<unsigned int> new_version{};
        std::string state{};  // running | finished
        std::time_t started_at{};
        std::optional<std::time_t> finished_at{};
        unsigned int salvaged{}, unrecoverable{}, skipped_remote{}, deferred{}, failed{};
        std::string failures_json{"[]"};
    };
    // Starts a pass (state running). Throws ops::Conflict when one is already running for the vault.
    [[nodiscard]] static unsigned int startSalvage(unsigned int vaultId, const std::vector<unsigned int>& versions,
                                                   std::optional<unsigned int> startedBy);
    [[nodiscard]] static std::optional<Salvage> runningSalvage(unsigned int vaultId);
    [[nodiscard]] static std::optional<Salvage> lastSalvage(unsigned int vaultId);
    static void setSalvageNewVersion(unsigned int id, unsigned int newVersion);
    static void finishSalvage(const Salvage& report);
    // Every version any salvage of the vault named (running or finished), ascending: files sealed under them are being
    // salvaged or are unrecoverable, so they don't keep the vault from starting or a rotation from finishing.
    [[nodiscard]] static std::vector<unsigned int> salvageVersions(unsigned int vaultId);
    // Live files rows sealed under `version` (rows with an IV), for a salvage pass.
    [[nodiscard]] static std::vector<std::shared_ptr<vh::fs::model::File>> filesSealedUnderVersion(unsigned int vaultId,
                                                                                                   unsigned int version);
};

}
