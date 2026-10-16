#pragma once

#include <nlohmann/json_fwd.hpp>
#include <string>
#include <vector>
#include <ctime>
#include <optional>
#include <memory>
#include "vault/Fwd.hpp"
#include "db/Fwd.hpp"

namespace vh::vault::model {

enum class S3Provider {
    AWS, CloudflareR2, Wasabi, BackblazeB2,
    DigitalOcean, MinIO, Ceph, Storj, Other
};

std::string to_string(S3Provider provider);
S3Provider s3_provider_from_string(const std::string& str);

struct APIKey {
    unsigned int id{0};
    unsigned int user_id{0};
    std::string name;
    std::time_t created_at{std::time(nullptr)};

    // S3 standard metadata
    S3Provider provider{S3Provider::AWS};
    std::string access_key;
    std::string region;
    std::string endpoint;

    // Encrypted parts (stored in DB)
    std::vector<uint8_t> encrypted_secret_access_key, iv;

    // Runtime only (never stored in DB)
    std::string secret_access_key;

    // Provider administration (#237, migration 110). An admin-enabled key may also list/create buckets and run the
    // event infrastructure for its account; ops::upstream decides who may use that.
    bool admin_enabled{false};
    std::optional<std::string> provider_account_id;     // resolved account (AWS via STS, R2 from the endpoint)
    std::optional<std::string> admin_capabilities_json; // last capability probe (JSON text)
    std::optional<std::time_t> admin_validated_at;
    // Cloudflare R2 only: the account API token (bearer) for Queues + event notifications. Sealed like the secret.
    std::vector<uint8_t> encrypted_provider_token, provider_token_iv;
    std::string provider_token;                         // runtime only, decrypted on demand; never serialized

    [[nodiscard]] bool hasProviderToken() const { return !encrypted_provider_token.empty() || !provider_token.empty(); }

    APIKey() = default;
    explicit APIKey(pqxx::row_ref row);
    APIKey(unsigned int userId, std::string name,
           S3Provider provider, std::string accessKey,
           std::string secretAccessKey,
           std::string region, std::string endpoint);
};

// JSON
void to_json(nlohmann::json& j, const APIKey& k);
void to_json(nlohmann::json& j, const std::shared_ptr<APIKey>& k);
void to_json(nlohmann::json& j, const std::vector<std::shared_ptr<APIKey>>& k);
void from_json(const nlohmann::json& j, APIKey& key);

std::string to_string(const std::shared_ptr<APIKey>& key);
std::string to_string(const std::vector<std::shared_ptr<APIKey>>& keys);

nlohmann::json generate_json_key_object(const std::shared_ptr<Vault>& v,
                                               const std::vector<uint8_t>& key,
                                               const std::shared_ptr<Key>& vk,
                                               const std::string& exportedBy);

nlohmann::json generate_json_key_info_object(const std::shared_ptr<Vault>& v,
                                               const std::shared_ptr<Key>& vk,
                                               const std::string& exportedBy);
}
