#include "vault/APIKeyManager.hpp"
#include "crypto/secrets/Versioned.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/identities/User.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/util/encrypt.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "vault/model/APIKey.hpp"

#include <sodium.h>
#include <stdexcept>

using namespace vh::crypto;
using namespace vh::crypto::util;
using namespace vh::vault;
using namespace vh::vault::model;

namespace {

constexpr auto kApiKeyMasterSlot = secrets::versioned::Slot::ApiKeyMaster;

// The bytes `key` stores, unwrapped under the API key master the row names. The caller wipes the result.
std::vector<uint8_t> unwrapStoredApiKeyBytes(const APIKey& key, const std::vector<uint8_t>& ciphertext,
                                  const std::vector<uint8_t>& iv) {
    return secrets::versioned::unwrap(kApiKeyMasterSlot, ciphertext, iv, key.master_version);
}

}

APIKeyManager::APIKeyManager() {
    // The current API key master, unsealed now: generated only while no API key exists, else MasterSecretLost (#326).
    (void)secrets::versioned::provider(kApiKeyMasterSlot, secrets::versioned::currentVersion(kApiKeyMasterSlot));

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

    // --- Encrypt secret_access_key before storage, and store it under the master that wrapped it ---
    {
        const secrets::versioned::Writer writer(kApiKeyMasterSlot);
        auto wrapped = writer.wrap(viewBytes(key->secret_access_key));
        key->encrypted_secret_access_key = std::move(wrapped.ciphertext);
        key->iv = std::move(wrapped.iv);
        key->master_version = wrapped.master_version;
        wipeSecret(key->secret_access_key);
        key->secret_access_key.clear();

        key->id = db::query::vault::APIKey::upsertAPIKey(key);
    }

    // Refresh from DB (ensures created_at, etc. are up to date)
    key = db::query::vault::APIKey::getAPIKey(key->id);

    // Cache in memory
    apiKeys_[key->id] = key;

    return key->id;
}

void APIKeyManager::updateAPIKey(const std::shared_ptr<APIKey>& key) {
    std::scoped_lock lock(apiKeysMutex_);
    // Held from the read to the write, so the stored wrap and the one written are under the same (current) master.
    const secrets::versioned::Writer writer(kApiKeyMasterSlot);

    const auto stored = db::query::vault::APIKey::getAPIKey(key->id);
    if (!stored) throw std::runtime_error("API key not found");

    if (key->secret_access_key.empty()) {
        key->encrypted_secret_access_key = stored->encrypted_secret_access_key;
        key->iv = stored->iv;
        key->master_version = stored->master_version;
    } else {
        auto wrapped = writer.wrap(viewBytes(key->secret_access_key));
        key->encrypted_secret_access_key = std::move(wrapped.ciphertext);
        key->iv = std::move(wrapped.iv);
        key->master_version = wrapped.master_version;
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

    // --- Decrypt secret_access_key (and the provider token) under the master the row names ---
    {
        const WipedKeyCopy decrypted(unwrapStoredApiKeyBytes(*key, key->encrypted_secret_access_key, key->iv));
        key->secret_access_key.assign(decrypted.bytes.begin(), decrypted.bytes.end());
    }

    if (!key->encrypted_provider_token.empty() && !key->provider_token_iv.empty()) {
        const WipedKeyCopy token(unwrapStoredApiKeyBytes(*key, key->encrypted_provider_token, key->provider_token_iv));
        key->provider_token.assign(token.bytes.begin(), token.bytes.end());
    }

    return key;
}

void APIKeyManager::setProviderToken(const unsigned int keyId, std::optional<std::string> token) {
    std::scoped_lock lock(apiKeysMutex_);
    const secrets::versioned::Writer writer(kApiKeyMasterSlot);
    if (!db::query::vault::APIKey::getAPIKey(keyId)) throw std::runtime_error("API key not found");

    if (!token || token->empty()) {
        db::query::vault::APIKey::clearProviderToken(keyId);
    } else {
        const auto wrapped = writer.wrap(viewBytes(*token));
        wipeSecret(*token);
        db::query::vault::APIKey::setProviderToken(keyId, wrapped.ciphertext, wrapped.iv, wrapped.master_version);
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
