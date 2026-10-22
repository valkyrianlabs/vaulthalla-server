#pragma once

#include "crypto/SecretKey.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "fs/Fwd.hpp"

#include <string>
#include <vector>
#include <map>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <ctime>
#include <span>
#include <filesystem>
#include <shared_mutex>
#include <stdexcept>

namespace vh::vault {

// The vault does not hold this key version: it never existed, or it was never retained (version 0 = unencrypted).
class KeyVersionUnavailable final : public std::runtime_error {
public:
    KeyVersionUnavailable(unsigned int vaultId, unsigned int version);
    [[nodiscard]] unsigned int vaultId() const { return vaultId_; }
    [[nodiscard]] unsigned int version() const { return version_; }

private:
    unsigned int vaultId_, version_;
};

// The vault's keys can't be loaded on this host, and minting a new one would orphan sealed data (load_key). The vault
// stays unavailable until `vh vault keys import` restores them. code: "key_missing" (no vault_keys row while sealed
// content exists), "key_unsealable" (a needed row doesn't unseal under this host's vault master), "version_missing"
// (a pending rotation's outgoing key, or a version live files are sealed under, isn't held). what() says what to run.
class KeyUnavailable final : public std::runtime_error {
public:
    KeyUnavailable(unsigned int vaultId, std::string code, const std::string& what);
    [[nodiscard]] unsigned int vaultId() const { return vaultId_; }
    [[nodiscard]] const std::string& code() const { return code_; }

private:
    unsigned int vaultId_;
    std::string code_;
};

class EncryptionManager {
public:
    explicit EncryptionManager(unsigned int vault_id);

    // Test-only: a manager over an in-memory key, no TPM or database (optionally mid-rotation with oldKey).
    struct ForTesting {};
    EncryptionManager(ForTesting, unsigned int vault_id, std::span<const uint8_t> key, unsigned int version,
                      std::span<const uint8_t> oldKey = {});
    // Test-only (ForTesting managers): a retired version historicalKeySnapshot() serves without a database.
    void addHistoricalKeyForTesting(unsigned int version, std::span<const uint8_t> key);

    // The current key and its version, read together (never a torn pair while rotation swaps them).
    struct CurrentKey {
        crypto::SecretKeyPtr key;
        unsigned int version{};
    };
    [[nodiscard]] CurrentKey currentKey() const;

    // The key that decrypts data written under keyVersion (same rules as decrypt()). The snapshot stays valid
    // (and wiped only when released) even if rotation finishes meanwhile.
    // Deliberately strict: live reads must never accept a retired key (an object claiming one must not decrypt).
    [[nodiscard]] crypto::SecretKeyPtr keySnapshot(unsigned int keyVersion) const;

    // Recovery reads only: any version this vault still holds. The current and the mid-rotation old key come from
    // memory; a retired one is unsealed from vault_keys_trashed under the vault master on demand and cached briefly
    // (at most kHistoricalCacheSize versions, dropped after kHistoricalCacheIdle unused). Throws
    // KeyVersionUnavailable for a version the vault doesn't hold.
    [[nodiscard]] crypto::SecretKeyPtr historicalKeySnapshot(unsigned int keyVersion) const;

    // Drops the cached retired keys unused for longer than kHistoricalCacheIdle as of `now`; returns how many. Runs on
    // every historicalKeySnapshot() and from VaultRetentionService's loop (every 30 s) for every engine, so an idle
    // key leaves memory without a later access (it is wiped once the last outstanding snapshot is released).
    std::size_t evictIdleHistoricalKeys(std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now()) const;
    // Test-only: puts a retired key into the cache as if unsealed and last used at lastUsed.
    void cacheHistoricalKeyForTesting(unsigned int version, std::span<const uint8_t> key,
                                      std::chrono::steady_clock::time_point lastUsed);
    [[nodiscard]] std::size_t cachedHistoricalKeyCount() const;

    // The current version and every retained (retired) one, ascending.
    [[nodiscard]] std::vector<unsigned int> retainedKeyVersions() const;
    [[nodiscard]] bool hasKeyVersion(unsigned int keyVersion) const;

    // The retired versions recoverable data still references (recovery_blob, live provider object versions), unsealed
    // and ascending, for key export; `missing` lists referenced versions the vault no longer holds. The current
    // version is never included (export carries it already).
    struct HistoricalKey {
        unsigned int version{};
        crypto::SecretKeyPtr key;
        std::time_t created_at{}, retired_at{};
    };
    struct ReferencedHistoricalKeys {
        std::vector<HistoricalKey> keys;
        std::vector<unsigned int> missing;
    };
    [[nodiscard]] ReferencedHistoricalKeys referencedHistoricalKeys() const;

    static constexpr std::size_t kHistoricalCacheSize = 8;
    static constexpr std::chrono::minutes kHistoricalCacheIdle{10};

    // Must be called before encrypt/decrypt. Mints the vault's first key only when the vault has no sealed content;
    // otherwise a missing or unusable key throws KeyUnavailable (see there).
    void load_key();

    // Every version this manager creates or unseals gets its provenance recorded (key check + this node's attestation,
    // vault/KeyAttestation.hpp): at creation, and lazily when a row from before migration 113 unseals.
    void prepare_key_rotation();
    void finish_key_rotation();

    // Key salvage (ops::vault_keys, key-backup.md "Salvage") for a vault whose current key this host can't use, so no
    // engine runs (or one that can't start until the salvage names a version): the same database rotation as prepare_key_rotation, to a fresh key sealed under this host's vault
    // master and attested. `expectedVersion` is the version it becomes (current + 1, or the highest referenced version
    // + 1 without a key row). Pending rotations are closed (their outgoing key isn't held); the version retired here
    // stays a pending rotation only when `outgoingHeld` (this host unseals it, so the rotation pass can re-key its
    // files). Returns the version.
    [[nodiscard]] static unsigned int mintSalvageKey(unsigned int vaultId, unsigned int expectedVersion, bool outgoingHeld);

    [[nodiscard]] std::vector<uint8_t>
    rotateDecryptEncrypt(const std::vector<uint8_t>& ciphertext, const std::shared_ptr<fs::model::File>& f) const;

    // Encrypt data with vault key, returns ciphertext.
    // Populates out_b64_iv with base64-encoded IV.
    [[nodiscard]] std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::shared_ptr<fs::model::File>& f) const;

    void encryptFileToFile(const std::filesystem::path& plaintextPath,
                           const std::filesystem::path& ciphertextPath,
                           const std::shared_ptr<fs::model::File>& f) const;

    // Re-seals a retained generation (sealed under srcKeyVersion with srcIvB64) into dst under the current key with
    // a fresh IV, streaming, and records the new IV and version on f like encryptFileToFile. dst holds the result
    // only once this returns: a source that fails authentication throws storage::IntegrityError and leaves no dst.
    // An unencrypted empty generation (empty IV, version 0, zero bytes) yields an empty dst and an empty IV/version
    // 0 on f, as every empty file is stored; a non-empty unencrypted source is refused (std::invalid_argument).
    void resealFileToCurrent(const std::filesystem::path& src, const std::string& srcIvB64, unsigned int srcKeyVersion,
                             const std::filesystem::path& dst, const std::shared_ptr<fs::model::File>& f) const;

    // In-memory form of resealFileToCurrent for a sealed buffer (body‖tag).
    [[nodiscard]] std::vector<uint8_t> resealToCurrent(const std::vector<uint8_t>& ciphertext, const std::string& srcIvB64,
                                                       unsigned int srcKeyVersion,
                                                       const std::shared_ptr<fs::model::File>& f) const;

    // Decrypt using base64-encoded IV and ciphertext
    [[nodiscard]] std::vector<uint8_t> decrypt(const std::vector<uint8_t>& ciphertext,
                                 const std::string& b64_iv, unsigned int keyVersion) const;

    // Streams a ciphertext file (AES-256-GCM body followed by its 16-byte tag) into a plaintext file. Nothing is
    // left at plaintextPath unless the tag verifies.
    void decryptFileToFile(const std::filesystem::path& ciphertextPath,
                           const std::filesystem::path& plaintextPath,
                           const std::string& b64_iv, unsigned int keyVersion) const;

    [[nodiscard]] std::vector<uint8_t> get_key(const std::string& callingFunctionName) const;

    [[nodiscard]] unsigned int get_key_version() const;

    [[nodiscard]] bool rotation_in_progress() const;

private:
    std::unique_ptr<crypto::secrets::KeyProvider> tpmKeyProvider_;
    std::atomic<bool> rotation_in_progress_{false};
    unsigned int vault_id_;

    // Guards version_, key_ and old_key_ as one unit. Readers copy the shared_ptr snapshots under a shared lock;
    // rotation replaces them under an exclusive lock. Key bytes are immutable and wiped on last release.
    mutable std::shared_mutex keyMutex_;
    unsigned int version_{};
    crypto::SecretKeyPtr key_, old_key_;

    // Unsealed retired keys, by version. Separate from keyMutex_ so a slow unseal never blocks live reads.
    struct CachedKey {
        crypto::SecretKeyPtr key;
        std::chrono::steady_clock::time_point lastUsed;
    };
    mutable std::mutex historicalMutex_;
    mutable std::map<unsigned int, CachedKey> historicalCache_;
    std::map<unsigned int, crypto::SecretKeyPtr> testHistorical_;  // ForTesting only; never evicted

    [[nodiscard]] crypto::SecretKeyPtr liveKeyFor(unsigned int keyVersion) const;  // current/rotation-old or null
    [[nodiscard]] crypto::SecretKeyPtr cachedHistoricalKey(unsigned int keyVersion) const;
    void cacheHistoricalKey(unsigned int keyVersion, const crypto::SecretKeyPtr& key) const;
    std::size_t evictIdleLocked(std::chrono::steady_clock::time_point now) const;  // historicalMutex_ held
};

}
