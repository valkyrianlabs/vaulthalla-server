#include "vault/model/S3Vault.hpp"

#include <paths.h>
#include "db/encoding/has.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/row>
#include <optional>
#include <stdexcept>
#include <string>
#include <utility>

namespace vh::vault::model {

std::string_view to_string(const StorageLayout layout) {
    switch (layout) {
    case StorageLayout::Transparent: return "transparent";
    case StorageLayout::PathV0: return "path_v0";
    case StorageLayout::OpaqueV1: return "opaque_v1";
    }
    throw std::invalid_argument("unknown storage layout");
}

StorageLayout storageLayoutFromString(const std::string_view text) {
    if (text == "transparent") return StorageLayout::Transparent;
    if (text == "path_v0") return StorageLayout::PathV0;
    if (text == "opaque_v1") return StorageLayout::OpaqueV1;
    throw std::invalid_argument("unknown storage layout: " + std::string(text));
}

std::string_view describe(const StorageLayout layout) {
    switch (layout) {
    case StorageLayout::Transparent: return "transparent (readable object names, unencrypted objects)";
    case StorageLayout::PathV0: return "path (v0): encrypted objects under their file paths";
    case StorageLayout::OpaqueV1: return "opaque (v1)";
    }
    throw std::invalid_argument("unknown storage layout");
}

StorageLayout layoutFor(const bool encryptUpstream) {
    return encryptUpstream ? StorageLayout::PathV0 : StorageLayout::Transparent;
}

namespace {
std::optional<StorageLayout>& newEncryptingLayoutOverride() {
    static std::optional<StorageLayout> layout;
    return layout;
}
}

StorageLayout layoutForNewVault(const bool encryptUpstream) {
    if (!encryptUpstream) return StorageLayout::Transparent;
    if (paths::isTestMode() && newEncryptingLayoutOverride()) return *newEncryptingLayoutOverride();
    return StorageLayout::OpaqueV1;
}

void setNewEncryptingLayoutForTesting(const std::optional<StorageLayout> layout) {
    if (layout == StorageLayout::Transparent) throw std::invalid_argument("an encrypting vault is never transparent");
    newEncryptingLayoutOverride() = layout;
}

S3Vault::S3Vault(const std::string& name, const unsigned int apiKeyID, std::string bucketName)
    : Vault(), api_key_id(apiKeyID), bucket(std::move(bucketName)) {
    this->name = name;
    this->type = VaultType::S3;
    this->is_active = true;
    this->created_at = std::time(nullptr);
}

S3Vault::S3Vault(pqxx::row_ref row)
    : Vault(row),
      api_key_id(row["api_key_id"].as<std::optional<unsigned int>>().value_or(0)),
      bucket(row["bucket"].as<std::optional<std::string>>().value_or("")),
      storage_tier_id(row["storage_tier_id"].as<std::optional<std::string>>()),
      encrypt_upstream(row["encrypt_upstream"].as<std::optional<bool>>().value_or(true)),
      storage_layout(db::encoding::try_get<std::string>(row, "storage_layout")
                         .transform([](const std::string& text) { return storageLayoutFromString(text); })
                         .value_or(layoutFor(encrypt_upstream))) {}

void to_json(nlohmann::json& j, const S3Vault& v) {
    to_json(j, static_cast<const Vault&>(v));
    j["api_key_id"] = v.api_key_id;
    j["bucket"] = v.bucket;
    j["storage_tier_id"] = v.storage_tier_id ? nlohmann::json(*v.storage_tier_id) : nlohmann::json(nullptr);
    j["encrypt_upstream"] = v.encrypt_upstream;
    j["storage_layout"] = to_string(v.storage_layout);
}

void from_json(const nlohmann::json& j, S3Vault& v) {
    from_json(j, static_cast<Vault&>(v));
    v.api_key_id = j.at("api_key_id").get<unsigned int>();
    v.bucket = j.at("bucket").get<std::string>();
    if (j.contains("storage_tier_id") && !j.at("storage_tier_id").is_null())
        v.storage_tier_id = j.at("storage_tier_id").get<std::string>();
    else
        v.storage_tier_id = std::nullopt;
    v.encrypt_upstream = j.value("encrypt_upstream", true);
}

}
