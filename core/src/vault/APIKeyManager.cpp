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
    sodium_memzero(decrypted.data(), decrypted.size());

    if (!key->encrypted_provider_token.empty() && !key->provider_token_iv.empty()) {
        auto token = decrypt_aes256_gcm(key->encrypted_provider_token, masterKey, key->provider_token_iv);
        key->provider_token.assign(token.begin(), token.end());
        sodium_memzero(token.data(), token.size());
    }

    return key;
}

void APIKeyManager::setProviderToken(const unsigned int keyId, std::optional<std::string> token) {
    std::scoped_lock lock(apiKeysMutex_);
    if (!db::query::vault::APIKey::getAPIKey(keyId)) throw std::runtime_error("API key not found");

    if (!token || token->empty()) {
        db::query::vault::APIKey::clearProviderToken(keyId);
    } else {
        const auto masterKey = tpmKeyProvider_->getMasterKey();
        std::vector<uint8_t> iv;
        std::vector<uint8_t> plaintext(token->begin(), token->end());
        const auto ciphertext = encrypt_aes256_gcm(plaintext, masterKey, iv);
        sodium_memzero(plaintext.data(), plaintext.size());
        sodium_memzero(token->data(), token->size());
        db::query::vault::APIKey::setProviderToken(keyId, ciphertext, iv);
    }
    if (auto refreshed = db::query::vault::APIKey::getAPIKey(keyId)) apiKeys_[keyId] = std::move(refreshed);
}

void APIKeyManager::setAdmin(const unsigned int keyId, const bool enabled, const std::optional<std::string>& accountRef,
                             const std::optional<std::string>& capabilitiesJson,
                             const std::optional<std::time_t> validatedAt) {
    std::scoped_lock lock(apiKeysMutex_);
    db::query::vault::APIKey::setAdmin(keyId, enabled, accountRef, capabilitiesJson, validatedAt);
    if (auto refreshed = db::query::vault::APIKey::getAPIKey(keyId)) apiKeys_[keyId] = std::move(refreshed);
}

void APIKeyManager::setAccountRef(const unsigned int keyId, const std::optional<std::string>& accountRef) {
    std::scoped_lock lock(apiKeysMutex_);
    db::query::vault::APIKey::setAccountRef(keyId, accountRef);
    if (auto refreshed = db::query::vault::APIKey::getAPIKey(keyId)) apiKeys_[keyId] = std::move(refreshed);
}
