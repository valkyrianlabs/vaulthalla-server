#include "vault/model/APIKey.hpp"
#include "db/query/identities/User.hpp"
#include "../../../include/identities/User.hpp"
#include "vault/model/Vault.hpp"
#include "vault/model/Key.hpp"
#include "protocols/shell/Table.hpp"
#include "protocols/shell/util/lineHelpers.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/encoding/bytea.hpp"
#include "db/encoding/has.hpp"
#include "crypto/util/encrypt.hpp"
#include "identities/Manager.hpp"

#include <unordered_map>
#include <stdexcept>
#include <pqxx/result>
#include <nlohmann/json.hpp>
#include <version.h>
#include <chrono>
#include <ctime>

using namespace vh::vault::model;
using namespace vh::protocols::shell;
using namespace vh::crypto::util;
using namespace vh::db::encoding;

// --- S3Provider helpers ---
std::string vh::vault::model::to_string(S3Provider provider) {
    switch (provider) {
        case S3Provider::AWS: return "AWS";
        case S3Provider::CloudflareR2: return "Cloudflare R2";
        case S3Provider::Wasabi: return "Wasabi";
        case S3Provider::BackblazeB2: return "Backblaze B2";
        case S3Provider::DigitalOcean: return "DigitalOcean";
        case S3Provider::MinIO: return "MinIO";
        case S3Provider::Ceph: return "Ceph";
        case S3Provider::Storj: return "Storj";
        case S3Provider::Other: return "Other";
        default: throw std::invalid_argument("Unknown S3Provider enum value");
    }
}

S3Provider vh::vault::model::s3_provider_from_string(const std::string& str) {
    static const std::unordered_map<std::string, S3Provider> mapping = {
        {"AWS", S3Provider::AWS}, {"Cloudflare R2", S3Provider::CloudflareR2},
        {"Wasabi", S3Provider::Wasabi}, {"Backblaze B2", S3Provider::BackblazeB2},
        {"DigitalOcean", S3Provider::DigitalOcean}, {"MinIO", S3Provider::MinIO},
        {"Ceph", S3Provider::Ceph}, {"Storj", S3Provider::Storj},
        {"Other", S3Provider::Other}
    };
    auto it = mapping.find(str);
    if (it != mapping.end()) return it->second;
    throw std::invalid_argument("Invalid S3Provider string: " + str);
}

// --- APIKey constructors ---
APIKey::APIKey(const unsigned int userId, std::string name,
               const S3Provider provider, std::string accessKey,
               std::string secretAccessKey,
               std::string region, std::string endpoint)
    : user_id(userId),
      name(std::move(name)),
      provider(provider),
      access_key(std::move(accessKey)),
      region(std::move(region)),
      endpoint(std::move(endpoint)),
      secret_access_key(std::move(secretAccessKey)) {}

APIKey::APIKey(pqxx::row_ref row)
    : id(row["id"].as<unsigned int>()),
      user_id(row["user_id"].as<unsigned int>()),
      name(row["name"].as<std::string>()),
      created_at(parsePostgresTimestamp(row["created_at"].as<std::string>())),
      provider(s3_provider_from_string(row["provider"].as<std::string>())),
      access_key(row["access_key"].as<std::string>()),
      region(row["region"].as<std::string>()),
      endpoint(row["endpoint"].as<std::string>()),
      encrypted_secret_access_key(from_hex_bytea(row["encrypted_secret_access_key"].as<std::string>())),
      iv(from_hex_bytea(row["iv"].as<std::string>())) {
    // Admin columns (migration 110); absent in projections that don't select them.
    admin_enabled = try_get<bool>(row, "admin_enabled").value_or(false);
    provider_account_id = try_get<std::string>(row, "provider_account_id");
    admin_capabilities_json = try_get<std::string>(row, "admin_capabilities");
    if (const auto at = try_get<std::string>(row, "admin_validated_at")) admin_validated_at = parsePostgresTimestamp(*at);
    if (const auto token = try_get<std::string>(row, "encrypted_provider_token")) encrypted_provider_token = from_hex_bytea(*token);
    if (const auto tokenIv = try_get<std::string>(row, "provider_token_iv")) provider_token_iv = from_hex_bytea(*tokenIv);
}

void vh::vault::model::from_json(const nlohmann::json& j, APIKey& key) {
    key.id = j.at("api_key_id").get<unsigned int>();
    key.user_id = j.at("user_id").get<unsigned int>();
    key.name = j.at("name").get<std::string>();
    key.created_at = parsePostgresTimestamp(j.at("created_at").get<std::string>());
    key.provider = s3_provider_from_string(j.at("provider").get<std::string>());
    key.access_key = j.at("access_key").get<std::string>();
    key.region = j.at("region").get<std::string>();
    key.endpoint = j.at("endpoint").get<std::string>();
    // secret_access_key intentionally not parsed (comes from decryption at runtime)
}

void vh::vault::model::to_json(nlohmann::json& j, const APIKey& k) {
    j = nlohmann::json{
            {"api_key_id", k.id},
            {"user_id", k.user_id},
            {"name", k.name},
            {"created_at", timestampToString(k.created_at)},
            {"provider", to_string(k.provider)},
            {"access_key", k.access_key},
            {"region", k.region},
            {"endpoint", k.endpoint},
            {"admin_enabled", k.admin_enabled},
            {"provider_account_id", k.provider_account_id ? nlohmann::json(*k.provider_account_id) : nlohmann::json(nullptr)},
            {"has_provider_token", k.hasProviderToken()},
            {"admin_validated_at", k.admin_validated_at ? nlohmann::json(timestampToString(*k.admin_validated_at)) : nlohmann::json(nullptr)},
            // Encrypted fields (and the provider token) are never part of the public JSON representation
    };
}

void vh::vault::model::to_json(nlohmann::json& j, const std::shared_ptr<APIKey>& k) {
    to_json(j, *k);
}

void vh::vault::model::to_json(nlohmann::json& j, const std::vector<std::shared_ptr<APIKey>>& k) {
    j = nlohmann::json::array();
    for (const auto& key : k) j.push_back(key);
}

namespace {
// The owner's name, or a placeholder when the account no longer resolves (it used to dereference null).
std::string ownerName(const uint32_t userId) {
    const auto owner = vh::identities::manager().user(userId);
    return owner ? owner->name() : "(unknown user " + std::to_string(userId) + ")";
}
}

std::string vh::vault::model::to_string(const std::shared_ptr<APIKey>& key) {
    std::string out = key->name + " (ID: " + std::to_string(key->id) + ")\n";
    out += "  User: " + ownerName(key->user_id) + "\n";
    out += "  Created: " + timestampToString(key->created_at) + "\n";
    out += "  Provider: " + to_string(key->provider) + "\n";
    out += "  Access Key: " + key->access_key + "\n";
    out += "  Region: " + key->region + "\n";
    out += "  Endpoint: " + key->endpoint + "\n";
    out += std::string("  Provider admin: ") + (key->admin_enabled ? "enabled" : "disabled") + "\n";
    if (key->provider_account_id) out += "  Account: " + *key->provider_account_id + "\n";
    if (key->admin_enabled) out += std::string("  Provider token: ") + (key->hasProviderToken() ? "stored" : "none") + "\n";
    return out;
}

std::string vh::vault::model::to_string(const std::vector<std::shared_ptr<APIKey>>& keys) {
    if (keys.empty()) return "No API keys found.\n";

    Table tbl({
        {"ID", Align::Right, 4, 10, false, false},
        {"Name", Align::Left, 4, 32, false, false},
        {"User", Align::Left, 4, 20, false, false},
        {"Provider", Align::Left, 4, 20, false, false},
        {"Created At", Align::Left, 4, 20, false, false}
    }, term_width());

    for (const auto& key : keys) {
        if (!key) continue; // Skip null pointers
        tbl.add_row({
            std::to_string(key->id),
            key->name,
            ownerName(key->user_id),
            to_string(key->provider),
            timestampToString(key->created_at)
        });
    }

    return "API Keys:\n" + tbl.render();
}

nlohmann::json vh::vault::model::generate_json_key_object(const std::shared_ptr<Vault>& v,
                                               const std::vector<uint8_t>& key,
                                               const std::shared_ptr<Key>& vk,
                                               const std::string& exportedBy) {
    return {
            {"vault_id", v->id},
            {"vault_name", v->name},
            {"key", b64_encode(key)},
            {"key_info",
                {
                    {"type", "AES-256-GCM"},
                    {"key_size", key.size()},
                    {"key_version", vk->version},
                    {"iv_size", 12},
                    {"tag_size", 16},
                    {"iv_gen", "libsodium::randombytes_buf"},
                    {"cipher_impl", "libsodium::crypto_aead_aes256gcm"},
                    {"hardware_accel", "AES-NI (runtime checked)"},
                    {"aad", false},
                    {"files_hashed_with", "libsodium"},
                    {"sealed_by", "Vaulthalla v" + std::string(VH_VERSION)},
                    {"created_at", timestampToString(vk->created_at)},
                    {"exported_by", exportedBy},
                    {"exported_at", timestampToString(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()))}
                }
            }
    };
}

nlohmann::json vh::vault::model::generate_json_key_info_object(const std::shared_ptr<Vault>& v,
                                               const std::shared_ptr<Key>& vk,
                                               const std::string& exportedBy) {
    return {
                {"vault_id", v->id},
                {"vault_name", v->name},
                {"key_info",
                    {
                        {"type", "AES-256-GCM"},
                        {"key_size", AES_KEY_SIZE},
                        {"key_version", vk->version},
                        {"iv_size", 12},
                        {"tag_size", 16},
                        {"iv_gen", "libsodium::randombytes_buf"},
                        {"cipher_impl", "libsodium::crypto_aead_aes256gcm"},
                        {"hardware_accel", "AES-NI (runtime checked)"},
                        {"aad", false},
                        {"files_hashed_with", "libsodium"},
                        {"sealed_by", "Vaulthalla v" + std::string(VH_VERSION)},
                        {"created_at", timestampToString(vk->created_at)},
                        {"exported_by", exportedBy},
                        {"exported_at", timestampToString(std::chrono::system_clock::to_time_t(std::chrono::system_clock::now()))}
                    }
                }
    };
}
