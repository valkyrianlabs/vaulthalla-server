#pragma once

#include "crypto/SecretBytes.hpp"
#include "crypto/secrets/KeyProvider.hpp"

#include "concurrency/AtomicSharedPtr.hpp"

#include <atomic>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace vh::crypto::secrets {

class Manager {
public:
    Manager();
    [[nodiscard]] static std::shared_ptr<Manager> createForTesting(std::unordered_map<std::string, std::string> secrets);

    std::string jwtSecret() const;
    void setJWTSecret(const std::string& secret) const;
    // Replaces the JWT signing secret with a fresh one (64 CSPRNG characters) and revokes every stored refresh token,
    // in one transaction, then serves the new secret (#353, `vh secret jwt rotate`). Every access and refresh token
    // signed before stops verifying at once; the caller ends the live sessions (auth::session::Manager::endAll).
    // Only the jwt_secret row changes: the host master that wraps internal_secrets (and with it the MFA keys, the
    // share-token pepper and the email credentials) is not touched. Returns how many refresh tokens were revoked.
    std::size_t rotateJWTSecret() const;
    [[nodiscard]] std::optional<std::string> getSecret(const std::string& key) const;
    void setSecret(const std::string& key, const std::string& value) const;
    [[nodiscard]] bool hasSecret(const std::string& key) const;

    // A data-wrapping key of exactly `size` bytes kept in internal_secrets under `key`, sealed under the host master
    // like the share pepper (MFA's mfa_seal and mfa_pepper, #356). When the row exists it is unsealed; a row the
    // master can't open, or one of the wrong length, throws (fail closed: it is never replaced). When there is no row,
    // `dependents` is asked first: records that a fresh key could never open make it MasterSecretLost, never a
    // regeneration. Otherwise a fresh key is generated, sealed and read back, and only counts as stored once the read
    // returns the same bytes. Every plain copy on the way is wiped.
    [[nodiscard]] crypto::SecretBytes sealedKey(const std::string& key, std::size_t size,
                                                const DependentsCheck& dependents) const;

private:
    explicit Manager(std::unordered_map<std::string, std::string> testSecrets);

    mutable std::mutex mutex_;
    // The JWT secret signs and verifies every session token; it is read and unsealed once, then served from
    // memory. Every write goes through setJWTSecret()/getOrInitSecret() in this process, which republish it.
    mutable std::mutex jwtMutex_;
    mutable concurrency::AtomicSharedPtr<const std::string> jwtSecret_;
    std::unique_ptr<KeyProvider> tpmKeyProvider_;
    mutable std::optional<std::unordered_map<std::string, std::string>> testSecrets_;

    std::string getOrInitSecret(const std::string& key) const;
    [[nodiscard]] static bool isRegenerableSecret(const std::string& key);
    std::string decryptStoredSecret(const std::vector<uint8_t>& value, const std::vector<uint8_t>& iv) const;
    void setEncryptedValue(const std::string& key, const std::string& value) const;
};

}
