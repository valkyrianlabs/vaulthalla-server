#pragma once

#include "Vault.hpp"
#include <string>
#include <nlohmann/json_fwd.hpp>
#include <cstdint>
#include <optional>
#include <string_view>
#include "db/Fwd.hpp"

namespace vh::vault::model {

// s3.storage_layout (design/encryption/01-provider-blind-storage.md §4.6): how the vault's objects sit in the bucket.
// Internal and versioned, never a user choice: it follows encrypt_upstream (the database CHECK ties them), and only the
// layout migration (WS1-c) moves a vault between path_v0 and opaque_v1.
//   Transparent  readable keys, plaintext objects (encrypt_upstream = false)
//   PathV0       path keys, legacy GCM objects, plaintext index (encrypt_upstream = true; today's layout)
//   OpaqueV1     opaque `o/<file uid>` keys (encrypt_upstream = true): every new encrypting vault since the restore
//                drill passed (#371). Existing path_v0 vaults keep their layout until the layout migration (WS1-c).
enum class StorageLayout { Transparent, PathV0, OpaqueV1 };

[[nodiscard]] std::string_view to_string(StorageLayout layout);                 // "transparent", "path_v0", "opaque_v1"
[[nodiscard]] StorageLayout storageLayoutFromString(std::string_view text);     // throws std::invalid_argument
[[nodiscard]] std::string_view describe(StorageLayout layout);                  // for status output
// The layout an existing vault gets when its encrypt_upstream changes: transparent or path_v0 (moving an existing
// vault into opaque_v1 is the layout migration's job, WS1-c).
[[nodiscard]] StorageLayout layoutFor(bool encryptUpstream);
// The layout a new vault is created with: opaque_v1 when it encrypts upstream (spec 01 §4.6, #371), else transparent.
[[nodiscard]] StorageLayout layoutForNewVault(bool encryptUpstream);
// Test seam (test mode only): new encrypting vaults get `layout` (path_v0) instead, so the suites of the path_v0 data
// plane, which existing vaults still use until WS1-c, keep exercising it. nullopt restores the product's default.
void setNewEncryptingLayoutForTesting(std::optional<StorageLayout> layout);

struct S3Vault : Vault {
    uint32_t api_key_id{};
    std::string bucket;
    std::optional<std::string> storage_tier_id;
    bool encrypt_upstream{true};
    // Read-only: stored by Vault::upsertVault from encrypt_upstream, never taken from a request.
    StorageLayout storage_layout{StorageLayout::PathV0};

    S3Vault() = default;
    S3Vault(const std::string& name, uint32_t apiKeyID, std::string bucketName);
    explicit S3Vault(pqxx::row_ref row);
};

void to_json(nlohmann::json& j, const S3Vault& v);
void from_json(const nlohmann::json& j, S3Vault& v);

}
