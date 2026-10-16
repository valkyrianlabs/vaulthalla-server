#pragma once

#include "crypto/secrets/KeyProvider.hpp"
#include "vault/Fwd.hpp"
#include <ctime>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

namespace vh::vault {

class APIKeyManager {
public:
    APIKeyManager();

    void initAPIKeys();

    // Trusted primitives: no authorization here. Who may create, see, remove or consume a key is decided by
    // rbac::resolver (admin keys.api self/user/admin permissions) in ops::api_keys. A hidden "key belongs to the
    // caller" check used to contradict it (admins could not remove users' keys on the web, and S3 vaults using a
    // key their owner may consume but does not own could not build their engine).
    unsigned int addAPIKey(std::shared_ptr<model::APIKey>& key);
    // In place, keeping the id. A non-empty key->secret_access_key is sealed as the new secret (and wiped from
    // `key`); an empty one keeps the stored ciphertext.
    void updateAPIKey(const std::shared_ptr<model::APIKey>& key);
    void removeAPIKey(unsigned int keyId);

    [[nodiscard]] std::vector<std::shared_ptr<model::APIKey>> listAPIKeys() const;
    [[nodiscard]] std::vector<std::shared_ptr<model::APIKey>> listUserAPIKeys(unsigned int userId) const;
    // With the secret (and the provider token, when one is stored) decrypted. Throws when the key does not exist.
    [[nodiscard]] std::shared_ptr<model::APIKey> getAPIKey(unsigned int keyId) const;

    // Provider administration (#237). A token is sealed with the same master key as the S3 secret and the plaintext
    // wiped; nullopt removes the stored token.
    void setProviderToken(unsigned int keyId, std::optional<std::string> token);
    // Absent optionals keep the stored value.
    void setAdmin(unsigned int keyId, bool enabled, const std::optional<std::string>& accountRef,
                  const std::optional<std::string>& capabilitiesJson, std::optional<std::time_t> validatedAt);
    void setAccountRef(unsigned int keyId, const std::optional<std::string>& accountRef);

private:
    mutable std::mutex apiKeysMutex_;
    std::unordered_map<unsigned int, std::shared_ptr<model::APIKey>> apiKeys_;
    std::unique_ptr<crypto::secrets::KeyProvider> tpmKeyProvider_;
};

}
