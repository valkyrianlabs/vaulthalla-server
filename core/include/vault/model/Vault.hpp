#pragma once

#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>
#include <nlohmann/json_fwd.hpp>
#include <filesystem>
#include "db/Fwd.hpp"
#include "crypto/id/ObjectUid.hpp"

namespace vh::vault::model {

enum class VaultType { Local, S3 };

std::string to_string(const VaultType& type);
VaultType from_string(const std::string& type);

struct Vault {
    uint32_t id{}, owner_id{};
    // vault.uid (spec 01 §4.1): drawn by Vault::upsertVault when the vault is created, never changed. Empty only on a
    // vault not yet stored.
    std::optional<vh::crypto::id::ObjectUid> uid{};
    std::string name, description{};
    std::string slug{};
    std::optional<std::string> fuse_name{};
    uintmax_t quota{};
    VaultType type{VaultType::Local};
    std::filesystem::path mount_point;
    bool allow_fs_write{false};
    bool is_active{true};
    std::time_t created_at{};

    Vault() = default;
    virtual ~Vault() = default;
    explicit Vault(pqxx::row_ref row);

    [[nodiscard]] std::string quotaStr() const;
    void setQuotaFromStr(const std::string& str);
    [[nodiscard]] std::string effectiveFuseName() const;
};

std::string slugifyName(std::string_view name);
[[nodiscard]] bool isValidVaultSlug(std::string_view slug);
[[nodiscard]] bool isValidS3Name(std::string_view name);
[[nodiscard]] bool isValidFuseName(std::string_view fuseName);
void requireValidVaultSlug(std::string_view slug);
void requireValidS3Name(std::string_view name);
void requireValidFuseName(std::string_view fuseName);

void to_json(nlohmann::json& j, const Vault& v);
void from_json(const nlohmann::json& j, Vault& v);

void to_json(nlohmann::json& j, const std::vector<std::shared_ptr<Vault>>& vaults);

std::string to_string(const Vault& v);
std::string to_string(const std::shared_ptr<Vault>& v);
std::string to_string(const std::vector<std::shared_ptr<Vault>>& vaults);

}
