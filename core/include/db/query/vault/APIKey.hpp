#pragma once

#include "db/model/ListQueryParams.hpp"
#include "identities/Fwd.hpp"
#include "vault/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace vh::db::query::vault {

class APIKey {
    using AK = vh::vault::model::APIKey;
    using APIKeyPtr = std::shared_ptr<AK>;

public:
    APIKey() = default;

    static unsigned int upsertAPIKey(const APIKeyPtr& key);

    // Rewrites every column but user_id/created_at from `key` (encrypted secret included), keeping the id.
    static void updateAPIKey(const APIKeyPtr& key);

    static void removeAPIKey(unsigned int keyId);

    // (vault id, vault name) of every vault whose s3 binding uses the key.
    static std::vector<std::pair<unsigned int, std::string>> listVaultsUsingKey(unsigned int keyId);

    static std::vector<APIKeyPtr> listAPIKeys(unsigned int userId, const model::ListQueryParams& params = {});

    static std::vector<APIKeyPtr> listAPIKeys(const model::ListQueryParams& params = {});

    static APIKeyPtr getAPIKey(unsigned int keyId);

    static APIKeyPtr getAPIKey(const std::string& keyName);

    [[nodiscard]] static std::optional<unsigned int> getAPIKeyOwnerId(unsigned int keyId);

    // Provider administration (#237). Absent optionals keep the stored value.
    static void setAdmin(unsigned int keyId, bool enabled, const std::optional<std::string>& accountRef,
                         const std::optional<std::string>& capabilitiesJson, std::optional<std::time_t> validatedAt);
    // Sealed Cloudflare account token (ciphertext + IV, as for the S3 secret).
    static void setProviderToken(unsigned int keyId, const std::vector<uint8_t>& ciphertext, const std::vector<uint8_t>& iv);
    static void clearProviderToken(unsigned int keyId);
    // nullopt clears it (e.g. the key's endpoint or provider changed, so the old account no longer applies).
    static void setAccountRef(unsigned int keyId, const std::optional<std::string>& accountRef);
    // The key now points somewhere else: no administration, no probe results, no Cloudflare token, no account.
    static void resetAdmin(unsigned int keyId);
};

}
