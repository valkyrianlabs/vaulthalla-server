#pragma once

#include "crypto/SecretKey.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "fs/Fwd.hpp"

#include <string>
#include <vector>
#include <memory>
#include <atomic>
#include <span>
#include <filesystem>
#include <shared_mutex>

namespace vh::vault {

class EncryptionManager {
public:
    explicit EncryptionManager(unsigned int vault_id);

    // Test-only: a manager over an in-memory key, no TPM or database (optionally mid-rotation with oldKey).
    struct ForTesting {};
    EncryptionManager(ForTesting, unsigned int vault_id, std::span<const uint8_t> key, unsigned int version,
                      std::span<const uint8_t> oldKey = {});

    // The current key and its version, read together (never a torn pair while rotation swaps them).
    struct CurrentKey {
        crypto::SecretKeyPtr key;
        unsigned int version{};
    };
    [[nodiscard]] CurrentKey currentKey() const;

    // The key that decrypts data written under keyVersion (same rules as decrypt()). The snapshot stays valid
    // (and wiped only when released) even if rotation finishes meanwhile.
    [[nodiscard]] crypto::SecretKeyPtr keySnapshot(unsigned int keyVersion) const;

    // Must be called before encrypt/decrypt
    void load_key();

    void prepare_key_rotation();
    void finish_key_rotation();

    [[nodiscard]] std::vector<uint8_t>
    rotateDecryptEncrypt(const std::vector<uint8_t>& ciphertext, const std::shared_ptr<fs::model::File>& f) const;

    // Encrypt data with vault key, returns ciphertext.
    // Populates out_b64_iv with base64-encoded IV.
    [[nodiscard]] std::vector<uint8_t> encrypt(const std::vector<uint8_t>& plaintext, const std::shared_ptr<fs::model::File>& f) const;

    void encryptFileToFile(const std::filesystem::path& plaintextPath,
                           const std::filesystem::path& ciphertextPath,
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
};

}
