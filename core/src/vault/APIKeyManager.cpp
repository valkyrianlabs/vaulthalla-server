#include "vault/APIKeyManager.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/identities/User.hpp"
#include "crypto/util/encrypt.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "vault/model/APIKey.hpp"

#include <sodium.h>
#include <stdexcept>
#include <paths.h>

using namespace vh::crypto;
using namespace vh::crypto::util;
using namespace vh::vault;
using namespace vh::vault::model;

APIKeyManager::APIKeyManager() {
    const std::string tpmKeyName = paths::testMode ? "test_ak_master" : "ak_master";
    tpmKeyProvider_ = std::make_unique<secrets::KeyProvider>(tpmKeyName);
    tpmKeyProvider_->init();

    initAPIKeys();
}

void APIKeyManager::initAPIKeys() {
    std::scoped_lock lock(apiKeysMutex_);
    auto keys = db::query::vault::APIKey::listAPIKeys();
    for (const auto& key : keys) {
        apiKeys_[key->id] = key;
    }
}

unsigned int APIKeyManager::addAPIKey(std::shared_ptr<APIKey>& key) {
    std::scoped_lock lock(apiKeysMutex_);

    const auto owner = vh::identities::manager().user(key->user_id);
    if (!owner) throw std::runtime_error("API key owner not found");
    if (owner->systemOnly()) throw std::runtime_error("system-only users cannot receive normal API keys");

    // --- Encrypt secret_access_key before storage ---
    const auto masterKey = tpmKeyProvider_->getMasterKey();
    std::vector<uint8_t> iv;
    const auto plaintext = std::vector<uint8_t>(key->secret_access_key.begin(),
                                          key->secret_access_key.end());

    const auto ciphertext = encrypt_aes256_gcm(plaintext, masterKey, iv);

    // Replace sensitive data with encrypted representation
    key->encrypted_secret_access_key = ciphertext;
    key->iv = iv;
    key->secret_access_key.clear(); // wipe plaintext from memory

    // Persist to DB
    key->id = db::query::vault::APIKey::upsertAPIKey(key);

    // Refresh from DB (ensures created_at, etc. are up to date)
    key = db::query::vault::APIKey::getAPIKey(key->id);

    // Cache in memory
    apiKeys_[key->id] = key;

    return key->id;
}

void APIKeyManager::updateAPIKey(const std::shared_ptr<APIKey>& key) {
    std::scoped_lock lock(apiKeysMutex_);

    const auto stored = db::query::vault::APIKey::getAPIKey(key->id);
    if (!stored) throw std::runtime_error("API key not found");

    if (key->secret_access_key.empty()) {
        key->encrypted_secret_access_key = stored->encrypted_secret_access_key;
        key->iv = stored->iv;
    } else {
        const auto masterKey = tpmKeyProvider_->getMasterKey();
        std::vector<uint8_t> iv;
        const auto plaintext = std::vector<uint8_t>(key->secret_access_key.begin(), key->secret_access_key.end());
        key->encrypted_secret_access_key = encrypt_aes256_gcm(plaintext, masterKey, iv);
        key->iv = iv;
        sodium_memzero(key->secret_access_key.data(), key->secret_access_key.size());
        key->secret_access_key.clear();
    }

    db::query::vault::APIKey::updateAPIKey(key);
    if (auto refreshed = db::query::vault::APIKey::getAPIKey(key->id)) apiKeys_[key->id] = std::move(refreshed);
}

void APIKeyManager::removeAPIKey(const unsigned int keyId) {
    std::scoped_lock lock(apiKeysMutex_);
    if (!apiKeys_.erase(keyId) && !db::query::vault::APIKey::getAPIKey(keyId))
        throw std::runtime_error("API key not found");
    db::query::vault::APIKey::removeAPIKey(keyId);
}

std::vector<std::shared_ptr<APIKey>> APIKeyManager::listAPIKeys() const {
    std::scoped_lock lock(apiKeysMutex_);
    return db::query::vault::APIKey::listAPIKeys();
}

std::vector<std::shared_ptr<APIKey>> APIKeyManager::listUserAPIKeys(unsigned int userId) const {
    std::scoped_lock lock(apiKeysMutex_);
    return db::query::vault::APIKey::listAPIKeys(userId);
}

std::shared_ptr<APIKey> APIKeyManager::getAPIKey(const unsigned int keyId) const {
    std::scoped_lock lock(apiKeysMutex_);

    auto key = db::query::vault::APIKey::getAPIKey(keyId);
    if (!key) throw std::runtime_error("API key not found");

    // --- Decrypt secret_access_key before returning ---
    const auto masterKey = tpmKeyProvider_->getMasterKey();
    auto decrypted = decrypt_aes256_gcm(
        key->encrypted_secret_access_key, masterKey, key->iv);

    key->secret_access_key.assign(decrypted.begin(), decrypted.end());

    return key;
}
