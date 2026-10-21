#include "vault/EncryptionManager.hpp"
#include "crypto/util/encrypt.hpp"
#include "crypto/util/Gcm.hpp"
#include "crypto/util/reseal.hpp"
#include "log/Registry.hpp"
#include "db/query/vault/Key.hpp"
#include "vault/model/Key.hpp"
#include "fs/model/File.hpp"

#include <sodium.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include <unistd.h>
#include <algorithm>
#include <array>
#include <cerrno>
#include <fstream>
#include <stdexcept>
#include <system_error>
#include <paths.h>
#include <ranges>
#include <iterator>
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

KeyVersionUnavailable::KeyVersionUnavailable(const unsigned int vaultId, const unsigned int version)
    : std::runtime_error(fmt::format("Vault {} does not hold key version {}", vaultId, version)),
      vaultId_(vaultId), version_(version) {}

KeyUnavailable::KeyUnavailable(const unsigned int vaultId, std::string code, const std::string& what)
    : std::runtime_error(what), vaultId_(vaultId), code_(std::move(code)) {}

namespace {
std::string keyImportHint(const unsigned int vaultId) {
    return fmt::format("Restore it from a key export or backup: vh vault keys import {} --file <export.json>", vaultId);
}

std::vector<uint8_t> unsealKeyRowOrThrow(const unsigned int vaultId, const vh::vault::model::Key& rec,
                                   const std::vector<uint8_t>& masterKey) {
    std::vector<uint8_t> raw;
    try {
        raw = decrypt_aes256_gcm(rec.encrypted_key, masterKey, rec.iv);
    } catch (const std::exception& e) {
        throw KeyUnavailable(vaultId, "key_unsealable",
                             fmt::format("Key version {} of vault {} does not unseal under this host's vault master "
                                         "({}): the master key changed or the key row is damaged. {}",
                                         rec.version, vaultId, e.what(), keyImportHint(vaultId)));
    }
    if (raw.size() != AES_KEY_SIZE) {
        sodium_memzero(raw.data(), raw.size());
        throw KeyUnavailable(vaultId, "key_unsealable",
                             fmt::format("Key version {} of vault {} is not a 32-byte AES key. {}", rec.version,
                                         vaultId, keyImportHint(vaultId)));
    }
    return raw;
}
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

void EncryptionManager::addHistoricalKeyForTesting(const unsigned int version, const std::span<const uint8_t> key) {
    if (tpmKeyProvider_) throw std::logic_error("addHistoricalKeyForTesting is for ForTesting managers only");
    std::scoped_lock lock(historicalMutex_);
    testHistorical_[version] = std::make_shared<const SecretKey>(key);
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
        // Never mint a key for a vault whose data is sealed under one: the new key could decrypt none of it, and an
        // import of the real key would then be refused as replacing a working key.
        if (const auto sealed = db::query::vault::Key::sealedContentSummary(vault_id_)) {
            const auto msg = fmt::format("Vault {} has sealed content ({}) but no key record; refusing to create a new "
                                         "key that could never decrypt it. {}", vault_id_, *sealed, keyImportHint(vault_id_));
            log::Registry::crypto()->error("[VaultEncryptionManager] {}", msg);
            throw KeyUnavailable(vault_id_, "key_missing", msg);
        }

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

    auto rawKey = unsealKeyRowOrThrow(vault_id_, *rec, masterKey);
    auto current = std::make_shared<const SecretKey>(rawKey);
    sodium_memzero(rawKey.data(), rawKey.size());

    SecretKeyPtr previous;
    if (rotating) {
        std::shared_ptr<vault::model::Key> oldKey;
        try {
            oldKey = db::query::vault::Key::getRotationInProgressOldKey(vault_id_);
        } catch (const std::exception&) {}
        if (!oldKey)
            throw KeyUnavailable(vault_id_, "version_missing",
                                 fmt::format("Vault {} is rotating its key but the outgoing key is missing. {}",
                                             vault_id_, keyImportHint(vault_id_)));
        auto rawOld = unsealKeyRowOrThrow(vault_id_, *oldKey, masterKey);
        previous = std::make_shared<const SecretKey>(rawOld);
        sodium_memzero(rawOld.data(), rawOld.size());
        log::Registry::crypto()->debug("[VaultEncryptionManager] Loaded old key for vault {} during rotation", vault_id_);
    }

    // Live files sealed under a version this vault no longer holds (a database restored from before a rotation lost
    // its row): starting would serve undecryptable files, so the vault waits for an import.
    for (const auto v : db::query::vault::Key::liveFileKeyVersions(vault_id_)) {
        if (v == rec->version || (rotating && v + 1 == rec->version)) continue;
        if (!db::query::vault::Key::hasRetiredKeyVersion(vault_id_, v))
            throw KeyUnavailable(vault_id_, "version_missing",
                                 fmt::format("Files of vault {} are sealed under key version {}, which this host no "
                                             "longer holds. {}", vault_id_, v, keyImportHint(vault_id_)));
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

SecretKeyPtr EncryptionManager::liveKeyFor(const unsigned int keyVersion) const {
    std::shared_lock lock(keyMutex_);
    if (key_ && keyVersion == version_) return key_;
    if (old_key_ && keyVersion + 1 == version_) return old_key_;
    return nullptr;
}

SecretKeyPtr EncryptionManager::cachedHistoricalKey(const unsigned int keyVersion) const {
    std::scoped_lock lock(historicalMutex_);
    if (const auto it = testHistorical_.find(keyVersion); it != testHistorical_.end()) return it->second;

    const auto now = std::chrono::steady_clock::now();
    evictIdleLocked(now);
    const auto it = historicalCache_.find(keyVersion);
    if (it == historicalCache_.end()) return nullptr;
    it->second.lastUsed = now;
    return it->second.key;
}

std::size_t EncryptionManager::evictIdleLocked(const std::chrono::steady_clock::time_point now) const {
    return std::erase_if(historicalCache_, [&](const auto& kv) { return now - kv.second.lastUsed > kHistoricalCacheIdle; });
}

std::size_t EncryptionManager::evictIdleHistoricalKeys(const std::chrono::steady_clock::time_point now) const {
    std::scoped_lock lock(historicalMutex_);
    return evictIdleLocked(now);
}

void EncryptionManager::cacheHistoricalKeyForTesting(const unsigned int version, const std::span<const uint8_t> key,
                                                     const std::chrono::steady_clock::time_point lastUsed) {
    std::scoped_lock lock(historicalMutex_);
    historicalCache_[version] = {std::make_shared<const SecretKey>(key), lastUsed};
}

std::size_t EncryptionManager::cachedHistoricalKeyCount() const {
    std::scoped_lock lock(historicalMutex_);
    return historicalCache_.size();
}

void EncryptionManager::cacheHistoricalKey(const unsigned int keyVersion, const SecretKeyPtr& key) const {
    std::scoped_lock lock(historicalMutex_);
    historicalCache_[keyVersion] = {key, std::chrono::steady_clock::now()};
    while (historicalCache_.size() > kHistoricalCacheSize) {
        const auto lru = std::ranges::min_element(historicalCache_, {}, [](const auto& kv) { return kv.second.lastUsed; });
        historicalCache_.erase(lru);  // outstanding snapshots keep their key until released, then it is wiped
    }
}

SecretKeyPtr EncryptionManager::historicalKeySnapshot(const unsigned int keyVersion) const {
    if (auto live = liveKeyFor(keyVersion)) return live;
    if (auto cached = cachedHistoricalKey(keyVersion)) return cached;
    if (keyVersion == 0 || !tpmKeyProvider_) throw KeyVersionUnavailable(vault_id_, keyVersion);

    const auto rec = db::query::vault::Key::getRetiredVaultKey(vault_id_, keyVersion);
    if (!rec) {
        // A rotation may have moved the version between the two lookups; it is in memory then.
        if (auto live = liveKeyFor(keyVersion)) return live;
        throw KeyVersionUnavailable(vault_id_, keyVersion);
    }

    auto raw = decrypt_aes256_gcm(rec->encrypted_key, tpmKeyProvider_->getMasterKey(), rec->iv);
    if (raw.size() != AES_KEY_SIZE) {
        sodium_memzero(raw.data(), raw.size());
        throw std::runtime_error(fmt::format("Retired key version {} of vault {} is not 32 bytes", keyVersion, vault_id_));
    }
    auto key = std::make_shared<const SecretKey>(raw);
    sodium_memzero(raw.data(), raw.size());
    cacheHistoricalKey(keyVersion, key);
    log::Registry::crypto()->info("[VaultEncryptionManager] Unsealed retired key version {} of vault {} for recovery",
                                  keyVersion, vault_id_);
    return key;
}

std::vector<unsigned int> EncryptionManager::retainedKeyVersions() const {
    std::vector<unsigned int> out;
    {
        std::shared_lock lock(keyMutex_);
        if (key_) out.push_back(version_);
        if (old_key_ && version_ > 0) out.push_back(version_ - 1);
    }
    {
        std::scoped_lock lock(historicalMutex_);
        for (const auto& version : testHistorical_ | std::views::keys) out.push_back(version);
    }
    if (tpmKeyProvider_) std::ranges::copy(db::query::vault::Key::retiredKeyVersions(vault_id_), std::back_inserter(out));
    std::ranges::sort(out);
    const auto dup = std::ranges::unique(out);
    out.erase(dup.begin(), dup.end());
    return out;
}

bool EncryptionManager::hasKeyVersion(const unsigned int keyVersion) const {
    if (keyVersion == 0) return false;
    if (liveKeyFor(keyVersion)) return true;
    {
        std::scoped_lock lock(historicalMutex_);
        if (testHistorical_.contains(keyVersion) || historicalCache_.contains(keyVersion)) return true;
    }
    return tpmKeyProvider_ && db::query::vault::Key::hasRetiredKeyVersion(vault_id_, keyVersion);
}

EncryptionManager::ReferencedHistoricalKeys EncryptionManager::referencedHistoricalKeys() const {
    ReferencedHistoricalKeys out;
    if (!tpmKeyProvider_) return out;
    const auto current = get_key_version();
    for (const auto version : db::query::vault::Key::recoveryReferencedKeyVersions(vault_id_)) {
        if (version == current) continue;
        const auto record = db::query::vault::Key::getRetiredVaultKey(vault_id_, version);
        if (!record) {
            out.missing.push_back(version);
            continue;
        }
        out.keys.push_back({version, historicalKeySnapshot(version), record->created_at, record->updated_at});
    }
    return out;
}

void EncryptionManager::resealFileToCurrent(const std::filesystem::path& src, const std::string& srcIvB64,
                                            const unsigned int srcKeyVersion, const std::filesystem::path& dst,
                                            const std::shared_ptr<File>& f) const {
    if (!f) throw std::invalid_argument("Cannot re-seal a file without file metadata");

    if (srcIvB64.empty()) {
        // Every empty file is stored unencrypted (no IV, version 0, zero bytes); anything else here is plaintext.
        if (std::filesystem::file_size(src) != 0)
            throw std::invalid_argument("Refusing to re-seal an unencrypted generation: " + src.string());
        if (dst.has_parent_path()) std::filesystem::create_directories(dst.parent_path());
        const int fd = ::open(dst.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
        if (fd < 0) throw std::system_error(errno, std::generic_category(), "open " + dst.string());
        ::close(fd);
        f->encryption_iv.clear();
        f->encrypted_with_key_version = 0;
        return;
    }

    const auto oldKey = historicalKeySnapshot(srcKeyVersion);
    const auto [newKey, version] = currentKey();
    f->encryption_iv = resealFile(src, *oldKey, srcIvB64, dst, *newKey);
    f->encrypted_with_key_version = version;
}

std::vector<uint8_t> EncryptionManager::resealToCurrent(const std::vector<uint8_t>& ciphertext,
                                                        const std::string& srcIvB64, const unsigned int srcKeyVersion,
                                                        const std::shared_ptr<File>& f) const {
    if (!f) throw std::invalid_argument("Cannot re-seal a file without file metadata");

    if (srcIvB64.empty()) {
        if (!ciphertext.empty()) throw std::invalid_argument("Refusing to re-seal an unencrypted generation");
        f->encryption_iv.clear();
        f->encrypted_with_key_version = 0;
        return {};
    }

    const auto oldKey = historicalKeySnapshot(srcKeyVersion);
    const auto [newKey, version] = currentKey();
    std::vector<uint8_t> iv;
    auto out = resealBuffer(ciphertext, *oldKey, b64_decode(srcIvB64), *newKey, iv);
    f->encryption_iv = b64_encode(iv);
    f->encrypted_with_key_version = version;
    return out;
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
