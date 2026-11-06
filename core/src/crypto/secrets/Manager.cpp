#include "crypto/secrets/Manager.hpp"
#include "db/query/crypto/Secret.hpp"
#include "crypto/model/Secret.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/util/encrypt.hpp"
#include "crypto/util/hash.hpp"
#include "log/Registry.hpp"

#include <paths.h>

#include <algorithm>
#include <stdexcept>
#include <utility>

using namespace vh::crypto::util;
using namespace vh::crypto::model;

namespace vh::crypto::secrets {

Manager::Manager()
: tpmKeyProvider_(std::make_unique<KeyProvider>(paths::testMode ? "test_master" : "master")) {
    tpmKeyProvider_->init();
}

Manager::Manager(std::unordered_map<std::string, std::string> testSecrets)
: testSecrets_(std::move(testSecrets)) {}

std::shared_ptr<Manager> Manager::createForTesting(std::unordered_map<std::string, std::string> secrets) {
    return std::shared_ptr<Manager>(new Manager(std::move(secrets)));
}

std::string Manager::jwtSecret() const {
    if (const auto cached = jwtSecret_.load()) return *cached;
    std::scoped_lock lock(jwtMutex_);
    if (const auto cached = jwtSecret_.load()) return *cached;
    auto secret = std::make_shared<const std::string>(getOrInitSecret("jwt_secret"));
    jwtSecret_.store(secret);
    return *secret;
}

void Manager::setJWTSecret(const std::string& secret) const {
    std::scoped_lock lock(jwtMutex_);
    setEncryptedValue("jwt_secret", secret);
    jwtSecret_.store(std::make_shared<const std::string>(secret));
}

std::optional<std::string> Manager::getSecret(const std::string& key) const {
    if (testSecrets_) {
        std::scoped_lock lock(mutex_);
        const auto it = testSecrets_->find(key);
        if (it == testSecrets_->end()) return std::nullopt;
        return it->second;
    }

    const auto secret = db::query::crypto::Secret::getSecret(key);
    if (!secret) return std::nullopt;
    return decryptStoredSecret(secret->value, secret->iv);
}

void Manager::setSecret(const std::string& key, const std::string& value) const {
    if (testSecrets_) {
        std::scoped_lock lock(mutex_);
        (*testSecrets_)[key] = value;
        return;
    }

    setEncryptedValue(key, value);
}

bool Manager::hasSecret(const std::string& key) const {
    if (testSecrets_) {
        std::scoped_lock lock(mutex_);
        return testSecrets_->contains(key);
    }
    return db::query::crypto::Secret::secretExists(key);
}

crypto::SecretBytes Manager::sealedKey(const std::string& key, const std::size_t size,
                                      const DependentsCheck& dependents) const {
    if (size == 0) throw std::invalid_argument("a sealed key needs a size");

    if (hasSecret(key)) {
        auto stored = getSecret(key);  // throws when the master can't open it
        if (!stored) throw std::runtime_error("internal secret '" + key + "' vanished while loading");
        if (stored->size() != size) {
            wipeSecret(*stored);
            throw std::runtime_error("internal secret '" + key + "' has the wrong length");
        }
        SecretBytes out(viewBytes(*stored));
        wipeSecret(*stored);
        return out;
    }

    if (dependents)
        if (const auto what = dependents())
            throw MasterSecretLost("internal secret '" + key + "' is missing, but " + *what +
                                   " depend on it; refusing to generate a replacement that could never open them. "
                                   "Restore the database's internal_secrets row together with this host's sealed "
                                   "master, or reset the affected accounts' factors.");

    auto fresh = SecretBytes::random(size);
    std::string text(fresh.bytes().begin(), fresh.bytes().end());
    try {
        setSecret(key, text);
    } catch (...) {
        wipeSecret(text);
        throw;
    }
    wipeSecret(text);
    auto back = getSecret(key);
    const bool same = back && std::ranges::equal(viewBytes(*back), fresh.bytes());
    if (back) wipeSecret(*back);
    if (!same) throw std::runtime_error("internal secret '" + key + "' did not read back identically after sealing");
    return fresh;
}

std::string Manager::getOrInitSecret(const std::string& key) const {
    if (testSecrets_) {
        std::scoped_lock lock(mutex_);
        if (const auto it = testSecrets_->find(key); it != testSecrets_->end())
            return it->second;

        const auto newSecret = hash::generate_secure_password(64);
        (*testSecrets_)[key] = newSecret;
        return newSecret;
    }

    const auto secret = db::query::crypto::Secret::getSecret(key);
    if (!secret) {
        const auto newSecret = hash::generate_secure_password(64);
        setEncryptedValue(key, newSecret);
        return newSecret;
    }

    try {
        return decryptStoredSecret(secret->value, secret->iv);
    } catch (const std::exception& e) {
        // Only secrets this process can mint itself may be replaced. An unreadable one means the stored value
        // was sealed under a different master key (DB adopted after purge, or restored without its
        // .sealed_master.blob); regenerating it only invalidates outstanding sessions.
        if (!isRegenerableSecret(key)) throw;
        log::Registry::runtime()->warn(
            "[secrets] Stored secret '{}' cannot be decrypted with this host's master key ({}); regenerating it. "
            "Existing sessions are invalidated.", key, e.what());
        const auto newSecret = hash::generate_secure_password(64);
        setEncryptedValue(key, newSecret);
        return newSecret;
    }
}

bool Manager::isRegenerableSecret(const std::string& key) {
    return key == "jwt_secret";
}

std::string Manager::decryptStoredSecret(const std::vector<uint8_t>& value, const std::vector<uint8_t>& iv) const {
    std::scoped_lock lock(mutex_);
    const WipedKeyCopy decrypted(decrypt_aes256_gcm(value, tpmKeyProvider_->getMasterKey(), iv));
    return {decrypted.bytes.begin(), decrypted.bytes.end()};
}

void Manager::setEncryptedValue(const std::string& key, const std::string& value) const {
    std::scoped_lock lock(mutex_);

    std::vector<uint8_t> iv;
    const auto ciphertext = encrypt_aes256_gcm(viewBytes(value), tpmKeyProvider_->getMasterKey(), iv);

    const auto secret = std::make_shared<Secret>();
    secret->key = key;
    secret->value = ciphertext;
    secret->iv = iv;

    db::query::crypto::Secret::upsertSecret(secret);
}

}
