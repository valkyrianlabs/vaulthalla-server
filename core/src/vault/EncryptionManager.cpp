#include "vault/EncryptionManager.hpp"
#include "crypto/util/encrypt.hpp"
#include "crypto/util/Gcm.hpp"
#include "log/Registry.hpp"
#include "db/query/vault/Key.hpp"
#include "vault/model/Key.hpp"
#include "fs/model/File.hpp"

#include <sodium.h>
#include <openssl/evp.h>
#include <algorithm>
#include <array>
#include <fstream>
#include <stdexcept>
#include <paths.h>
#include <fmt/format.h>

using namespace vh::vault;
using namespace vh::crypto;
using namespace vh::crypto::util;
using namespace vh::fs::model;

namespace {
// The one-shot crypto helpers take std::vector keys; this copy is wiped as soon as it goes out of scope.
struct WipedKeyCopy {
    explicit WipedKeyCopy(const SecretKeyPtr& key) : bytes(key->bytes().begin(), key->bytes().end()) {}
    ~WipedKeyCopy() { sodium_memzero(bytes.data(), bytes.size()); }
    WipedKeyCopy(const WipedKeyCopy&) = delete;
    WipedKeyCopy& operator=(const WipedKeyCopy&) = delete;
    std::vector<uint8_t> bytes;
};
}

EncryptionManager::EncryptionManager(const unsigned int vault_id)
    : vault_id_(vault_id) {
    tpmKeyProvider_ = std::make_unique<secrets::KeyProvider>(paths::testMode ? "test_vault_master" : "vault_master");
    tpmKeyProvider_->init();
    load_key();
}

EncryptionManager::EncryptionManager(ForTesting, const unsigned int vault_id, const std::span<const uint8_t> key,
                                     const unsigned int version, const std::span<const uint8_t> oldKey)
    : vault_id_(vault_id), version_(version), key_(std::make_shared<const SecretKey>(key)) {
    if (!oldKey.empty()) {
        old_key_ = std::make_shared<const SecretKey>(oldKey);
        rotation_in_progress_.store(true);
    }
}

unsigned int EncryptionManager::get_key_version() const {
    std::shared_lock lock(keyMutex_);
    return version_;
}

bool EncryptionManager::rotation_in_progress() const { return rotation_in_progress_.load(); }

EncryptionManager::CurrentKey EncryptionManager::currentKey() const {
    std::shared_lock lock(keyMutex_);
    if (!key_) throw std::runtime_error("Vault key is not initialized");
    return {key_, version_};
}

void EncryptionManager::load_key() {
    if (!tpmKeyProvider_) throw std::logic_error("load_key requires a TPM-backed EncryptionManager");
    const bool rotating = db::query::vault::Key::keyRotationInProgress(vault_id_);
    const auto rec = db::query::vault::Key::getVaultKey(vault_id_);
    const auto masterKey = tpmKeyProvider_->getMasterKey();

    if (!rec) {
        // First time: generate and seal new vault key
        const auto vaultKey = SecretKey::random();
        const WipedKeyCopy raw(vaultKey);

        std::vector<uint8_t> iv;
        const auto enc_key = encrypt_aes256_gcm(raw.bytes, masterKey, iv);

        const auto key = std::make_shared<vault::model::Key>();
        key->vaultId = vault_id_;
        key->encrypted_key = enc_key;
        key->iv = iv;
        key->version = db::query::vault::Key::addVaultKey(key);

        {
            std::unique_lock lock(keyMutex_);
            version_ = key->version;
            key_ = vaultKey;
            old_key_.reset();
        }
        rotation_in_progress_.store(false);
        const auto msg = fmt::format("[VaultEncryptionManager] Created new sealed AES256-GCM key for vault {} with version {}",
                                     vault_id_, key->version);
        log::Registry::audit()->info(msg);
        log::Registry::crypto()->info(msg);
        return;
    }

    auto rawKey = decrypt_aes256_gcm(rec->encrypted_key, masterKey, rec->iv);
    if (rawKey.size() != AES_KEY_SIZE) throw std::runtime_error("Vault key must be 32 bytes (AES-256)");
    auto current = std::make_shared<const SecretKey>(rawKey);
    sodium_memzero(rawKey.data(), rawKey.size());

    SecretKeyPtr previous;
    if (rotating) {
        const auto oldKey = db::query::vault::Key::getRotationInProgressOldKey(vault_id_);
        if (!oldKey) {
            log::Registry::crypto()->error("[VaultEncryptionManager] No old key found for rotation in progress for vault {}",
                                         vault_id_);
            throw std::runtime_error("No old key found for rotation in progress");
        }

        auto rawOld = decrypt_aes256_gcm(oldKey->encrypted_key, masterKey, oldKey->iv);
        if (rawOld.size() != AES_KEY_SIZE) {
            log::Registry::crypto()->error("[VaultEncryptionManager] Old vault key must be 32 bytes (AES-256), got {} bytes",
                                         rawOld.size());
            throw std::runtime_error("Old vault key must be 32 bytes (AES-256)");
        }
        previous = std::make_shared<const SecretKey>(rawOld);
        sodium_memzero(rawOld.data(), rawOld.size());
        log::Registry::crypto()->debug("[VaultEncryptionManager] Loaded old key for vault {} during rotation", vault_id_);
    }

    {
        std::unique_lock lock(keyMutex_);
        version_ = rec->version;
        key_ = std::move(current);
        old_key_ = std::move(previous);
    }
    rotation_in_progress_.store(rotating);
}

void EncryptionManager::prepare_key_rotation() {
    if (!tpmKeyProvider_) throw std::logic_error("prepare_key_rotation requires a TPM-backed EncryptionManager");
    if (db::query::vault::Key::keyRotationInProgress(vault_id_)) {
        log::Registry::crypto()->warn("[VaultEncryptionManager] Key rotation already in progress for vault {}", vault_id_);
        return;
    }

    log::Registry::crypto()->debug("[VaultEncryptionManager] Preparing key rotation for vault {}", vault_id_);

    const auto next = SecretKey::random();
    const WipedKeyCopy raw(next);

    std::vector<uint8_t> iv;
    const auto key = std::make_shared<vault::model::Key>();
    key->vaultId = vault_id_;
    key->encrypted_key = encrypt_aes256_gcm(raw.bytes, tpmKeyProvider_->getMasterKey(), iv);
    key->iv = std::move(iv);
    // Persist first: if this throws, the in-memory keys are untouched.
    key->version = db::query::vault::Key::rotateVaultKey(key);

    {
        std::unique_lock lock(keyMutex_);
        old_key_ = key_;
        key_ = next;
        version_ = key->version;
        rotation_in_progress_.store(true);
    }

    const auto msg = fmt::format("[VaultEncryptionManager] Prepared key rotation for vault {} with new version {}",
                                         vault_id_, key->version);
    log::Registry::audit()->info(msg);
    log::Registry::crypto()->info(msg);
}

void EncryptionManager::finish_key_rotation() {
    if (!db::query::vault::Key::keyRotationInProgress(vault_id_)) {
        log::Registry::crypto()->warn("[VaultEncryptionManager] No key rotation in progress for vault {}", vault_id_);
        return;
    }

    db::query::vault::Key::markKeyRotationFinished(vault_id_);
    unsigned int version = 0;
    {
        std::unique_lock lock(keyMutex_);
        old_key_.reset();  // wiped once the last in-flight snapshot is released
        rotation_in_progress_.store(false);
        version = version_;
    }

    const auto msg = fmt::format("[VaultEncryptionManager] Finished key rotation for vault {} with version {}",
                                         vault_id_, version);
    log::Registry::audit()->info(msg);
    log::Registry::crypto()->info(msg);
}

std::vector<uint8_t> EncryptionManager::rotateDecryptEncrypt(const std::vector<uint8_t>& ciphertext, const std::shared_ptr<File>& f) const {
    try {
        SecretKeyPtr oldKey, newKey;
        unsigned int version = 0;
        {
            std::shared_lock lock(keyMutex_);
            oldKey = old_key_;
            newKey = key_;
            version = version_;
        }

        if (f->encrypted_with_key_version == version) {
            log::Registry::crypto()->debug("[VaultEncryptionManager] Key version {} is current for vault {}, no rotation needed",
                                         f->encrypted_with_key_version, vault_id_);
            return ciphertext;
        }

        if (!rotation_in_progress_.load() || !oldKey) {
            const auto msg = fmt::format(
                "[VaultEncryptionManager] Key rotation not in progress for vault {}, but key version {} is not current",
                vault_id_, f->encrypted_with_key_version);
            log::Registry::audit()->warn(msg);
            log::Registry::crypto()->warn(msg);
            throw std::runtime_error("Key rotation not in progress, cannot rotate key");
        }

        if (f->encrypted_with_key_version != version - 1)
            log::Registry::crypto()->warn("[VaultEncryptionManager] Key version {} is not the previous version {}, using the previous key",
                                        f->encrypted_with_key_version, version - 1);

        const WipedKeyCopy oldRaw(oldKey);
        const WipedKeyCopy newRaw(newKey);
        auto decrypted = decrypt_aes256_gcm(ciphertext, oldRaw.bytes, b64_decode(f->encryption_iv));

        std::vector<uint8_t> iv;
        const auto encrypted = encrypt_aes256_gcm(decrypted, newRaw.bytes, iv);
        sodium_memzero(decrypted.data(), decrypted.size());

        if (encrypted.size() != ciphertext.size()) {
            log::Registry::crypto()->error("[VaultEncryptionManager] Encrypted data size mismatch after key rotation");
            throw std::runtime_error("Encrypted data size mismatch after key rotation");
        }

        f->encryption_iv = b64_encode(iv);
        f->encrypted_with_key_version = version;

        return encrypted;
    } catch (const std::exception& e) {
        log::Registry::crypto()->error("[VaultEncryptionManager] Exception during key rotation: {}", e.what());
        throw std::runtime_error("Key rotation failed: " + std::string(e.what()));
    }
}

std::vector<uint8_t> EncryptionManager::encrypt(const std::vector<uint8_t>& plaintext, const std::shared_ptr<File>& f) const {
    const auto [key, version] = currentKey();
    const WipedKeyCopy raw(key);
    std::vector<uint8_t> iv;
    auto ciphertext = encrypt_aes256_gcm(plaintext, raw.bytes, iv);
    f->encryption_iv = b64_encode(iv);
    f->encrypted_with_key_version = version;
    return ciphertext;
}

void EncryptionManager::encryptFileToFile(
    const std::filesystem::path& plaintextPath,
    const std::filesystem::path& ciphertextPath,
    const std::shared_ptr<File>& f) const {
    if (!f) throw std::invalid_argument("Cannot encrypt file without file metadata");
    const auto [key, version] = currentKey();

    std::ifstream in(plaintextPath, std::ios::binary);
    if (!in) throw std::runtime_error("Failed to open plaintext file for encryption: " + plaintextPath.string());

    std::filesystem::create_directories(ciphertextPath.parent_path());
    std::ofstream out(ciphertextPath, std::ios::binary | std::ios::trunc);
    if (!out) throw std::runtime_error("Failed to open ciphertext file for encryption: " + ciphertextPath.string());

    std::array<uint8_t, AES_IV_SIZE> iv{};
    randombytes_buf(iv.data(), iv.size());

    GcmStreamEncryptor encryptor(key->bytes(), iv);
    std::array<unsigned char, 64 * 1024> input{};
    std::array<unsigned char, input.size()> output{};
    while (in) {
        in.read(reinterpret_cast<char*>(input.data()), static_cast<std::streamsize>(input.size()));
        const auto read = in.gcount();
        if (read <= 0) break;
        const auto n = static_cast<std::size_t>(read);
        encryptor.update({input.data(), n}, {output.data(), n});
        out.write(reinterpret_cast<const char*>(output.data()), read);
        if (!out) throw std::runtime_error("Failed writing ciphertext file: " + ciphertextPath.string());
    }
    if (in.bad()) throw std::runtime_error("Failed reading plaintext file: " + plaintextPath.string());

    const auto tag = encryptor.finish();
    out.write(reinterpret_cast<const char*>(tag.data()), static_cast<std::streamsize>(tag.size()));
    out.close();
    if (!out) throw std::runtime_error("Failed writing AES-GCM tag: " + ciphertextPath.string());
    sodium_memzero(input.data(), input.size());

    f->encryption_iv = b64_encode(std::vector<uint8_t>(iv.begin(), iv.end()));
    f->encrypted_with_key_version = version;
}

SecretKeyPtr EncryptionManager::keySnapshot(const unsigned int keyVersion) const {
    std::shared_lock lock(keyMutex_);
    if (!key_) throw std::runtime_error("Vault key is not initialized");

    if (rotation_in_progress_.load()) {
        if (!old_key_) throw std::runtime_error("Key rotation in progress but keys are not set");

        if (keyVersion == version_) return key_;
        if (keyVersion + 1 == version_) return old_key_;

        log::Registry::crypto()->warn("[VaultEncryptionManager] Key version {} is not resolvable during rotation to {} for vault {}",
                                      keyVersion, version_, vault_id_);
        throw std::runtime_error("Key version mismatch");
    }

    if (keyVersion != version_) {
        log::Registry::crypto()->warn("[VaultEncryptionManager] Key version mismatch: expected {}, got {} for vault {}",
                                    version_, keyVersion, vault_id_);
        throw std::runtime_error("Key version mismatch");
    }

    return key_;
}

std::vector<uint8_t> EncryptionManager::decrypt(const std::vector<uint8_t>& ciphertext, const std::string& b64_iv, const unsigned int keyVersion) const {
    const WipedKeyCopy raw(keySnapshot(keyVersion));
    return decrypt_aes256_gcm(ciphertext, raw.bytes, b64_decode(b64_iv));
}

void EncryptionManager::decryptFileToFile(
    const std::filesystem::path& ciphertextPath,
    const std::filesystem::path& plaintextPath,
    const std::string& b64_iv,
    const unsigned int keyVersion) const {
    const WipedKeyCopy raw(keySnapshot(keyVersion));
    decrypt_aes256_gcm_file(ciphertextPath, plaintextPath, raw.bytes, b64_decode(b64_iv));
}

std::vector<uint8_t> EncryptionManager::get_key(const std::string& callingFunctionName) const {
    const auto key = currentKey().key;

    const auto msg = fmt::format("[VaultEncryptionManager] Returning key for vault {} in function: {}",
                           vault_id_, callingFunctionName);
    log::Registry::crypto()->debug(msg);
    log::Registry::audit()->debug(msg);

    return {key->bytes().begin(), key->bytes().end()};
}
