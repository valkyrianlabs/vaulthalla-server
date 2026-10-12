#pragma once

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
    [[nodiscard]] std::optional<std::string> getSecret(const std::string& key) const;
    void setSecret(const std::string& key, const std::string& value) const;
    [[nodiscard]] bool hasSecret(const std::string& key) const;

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
