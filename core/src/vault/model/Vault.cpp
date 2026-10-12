#include "vault/model/Vault.hpp"
#include "vault/model/S3Vault.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/encoding/has.hpp"
#include "protocols/shell/util/lineHelpers.hpp"
#include "protocols/shell/Table.hpp"
#include "db/query/vault/Vault.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/row>
#include <fmt/format.h>
#include <algorithm>
#include <cctype>
#include <stdexcept>

using namespace vh::vault::model;
using namespace vh::protocols::shell;
using namespace vh::db::encoding;

namespace {
    void trimTrailingHyphens(std::string& value) {
        while (!value.empty() && value.back() == '-') value.pop_back();
    }

    void trimLeadingHyphens(std::string& value) {
        while (!value.empty() && value.front() == '-') value.erase(value.begin());
    }

    void normalizeSlugLength(std::string& value) {
        trimLeadingHyphens(value);
        trimTrailingHyphens(value);
        if (value.empty()) value = "vault";
        if (value.size() > 63) {
            value.resize(63);
            trimTrailingHyphens(value);
            if (value.empty()) value = "vault";
        }
        while (value.size() < 3) value.push_back('0');
    }
}

std::string vh::vault::model::slugifyName(const std::string_view name) {
    std::string out;
    out.reserve(std::min<std::size_t>(name.size(), 63));

    bool previousWasHyphen = false;
    for (const auto raw : name) {
        const auto c = static_cast<unsigned char>(raw);
        if (std::isalnum(c)) {
            out.push_back(static_cast<char>(std::tolower(c)));
            previousWasHyphen = false;
        } else if (!previousWasHyphen) {
            out.push_back('-');
            previousWasHyphen = true;
        }
    }

    normalizeSlugLength(out);
    return out;
}

bool vh::vault::model::isValidVaultSlug(const std::string_view slug) {
    if (slug.size() < 3 || slug.size() > 63) return false;
    const auto isLowerAlnum = [](const char c) {
        return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
    };
    if (!isLowerAlnum(slug.front()) || !isLowerAlnum(slug.back())) return false;
    return std::ranges::all_of(slug, [&](const char c) {
        return isLowerAlnum(c) || c == '-';
    });
}

bool vh::vault::model::isValidS3Name(const std::string_view name) {
    return isValidVaultSlug(name);
}

bool vh::vault::model::isValidFuseName(const std::string_view fuseName) {
    if (fuseName.empty() || fuseName == "." || fuseName == "..") return false;
    return std::ranges::none_of(fuseName, [](const char c) {
        return c == '/' || c == '\\' || c == '\0';
    });
}

void vh::vault::model::requireValidVaultSlug(const std::string_view slug) {
    if (!isValidVaultSlug(slug))
        throw std::invalid_argument("vault.slug must be 3-63 chars, lowercase a-z, 0-9, or hyphen, and begin and end with a letter or digit.");
}

void vh::vault::model::requireValidS3Name(const std::string_view name) {
    if (!isValidS3Name(name))
        throw std::invalid_argument("S3 bucket name must be 3-63 chars, lowercase a-z, 0-9, or hyphen, and begin and end with a letter or digit.");
}

void vh::vault::model::requireValidFuseName(const std::string_view fuseName) {
    if (!isValidFuseName(fuseName))
        throw std::invalid_argument("vault.fuse_name must be a safe single path component: not empty, not '.' or '..', and without slash, backslash, or NUL.");
}

std::string Vault::quotaStr() const {
    if (quota == 0) return "unlimited";
    if (quota < 1024) return fmt::format("{}B", static_cast<unsigned long long>(quota));
    if (quota < 1024 * 1024) return fmt::format("{:.2f}K", static_cast<double>(quota) / 1024);
    if (quota < 1024 * 1024 * 1024) return fmt::format("{:.2f}M", static_cast<double>(quota) / (1024 * 1024));
    if (quota < 1024ull * 1024 * 1024 * 1024) return fmt::format("{:.2f}G", static_cast<double>(quota) / (1024 * 1024 * 1024));
    return fmt::format("{:.2f}T", static_cast<double>(quota) / (1024ull * 1024 * 1024 * 1024));
}

void Vault::setQuotaFromStr(const std::string& str) {
    const auto identifier = str.back();
    if (str == "unlimited") {
        quota = 0;
        return;
    }
    try {
        if (identifier == 'B' || identifier == 'b') quota = std::stoull(str.substr(0, str.size() - 1));
        else if (identifier == 'K' || identifier == 'k')
            quota = static_cast<uintmax_t>(std::stoull(str.substr(0, str.size() - 1)) * 1024ULL);
        else if (identifier == 'M' || identifier == 'm')
            quota = static_cast<uintmax_t>(std::stoull(str.substr(0, str.size() - 1)) * 1024ULL * 1024ULL);
        else if (identifier == 'G' || identifier == 'g')
            quota = static_cast<uintmax_t>(std::stoull(str.substr(0, str.size() - 1)) * 1024ULL * 1024ULL * 1024ULL);
        else if (identifier == 'T' || identifier == 't')
            quota = static_cast<uintmax_t>(std::stoull(str.substr(0, str.size() - 1)) * 1024ULL * 1024ULL * 1024ULL * 1024ULL);
        else quota = std::stoull(str);
    } catch (const std::exception& e) {
        throw std::invalid_argument("Invalid quota string: " + str);
    }
}

std::string Vault::effectiveFuseName() const {
    return fuse_name && !fuse_name->empty() ? *fuse_name : slug;
}


std::string vh::vault::model::to_string(const VaultType& type) {
    switch (type) {
        case VaultType::Local: return "local";
        case VaultType::S3: return "s3";
        default: return "unknown";
    }
}

VaultType vh::vault::model::from_string(const std::string& type) {
    if (type == "local") return VaultType::Local;
    if (type == "s3") return VaultType::S3;
    throw std::invalid_argument("Invalid VaultType: " + type);
}

Vault::Vault(pqxx::row_ref row)
    : id(row["id"].as<unsigned int>()),
      // vault.owner_id is ON DELETE SET NULL: deleting a user leaves their vaults ownerless (0, shown as N/A).
      // Reading it as non-null threw in listVaults and stopped the daemon from starting at all (vh-storage).
      owner_id(row["owner_id"].is_null() ? 0u : row["owner_id"].as<unsigned int>()),
      name(row["name"].as<std::string>()),
      description(try_get<std::string>(row, "description").value_or("")),
      slug(try_get<std::string>(row, "slug").value_or(slugifyName(name))),
      fuse_name(try_get<std::string>(row, "fuse_name")),
      quota(row["quota"].as<unsigned long long>()),
      type(from_string(row["type"].as<std::string>())),
      mount_point(std::filesystem::path(row["mount_point"].as<std::string>())),
      allow_fs_write(row["allow_fs_write"].as<bool>()),
      is_active(row["is_active"].as<bool>()),
      created_at(parsePostgresTimestamp(row["created_at"].c_str())) {}

void vh::vault::model::to_json(nlohmann::json& j, const Vault& v) {
    j = {
        {"id", v.id},
        {"name", v.name},
        {"slug", v.slug},
        {"fuse_name", v.fuse_name ? nlohmann::json(*v.fuse_name) : nlohmann::json(nullptr)},
        {"effective_fuse_name", v.effectiveFuseName()},
        {"type", to_string(v.type)},
        {"description", v.description},
        {"quota", v.quota},
        {"owner_id", v.owner_id},
        {"mount_point", v.mount_point.string()},
        {"allow_fs_write", v.allow_fs_write},
        {"is_active", v.is_active},
        {"created_at", timestampToString(v.created_at)}
    };
}

void vh::vault::model::from_json(const nlohmann::json& j, Vault& v) {
    v.id = j.at("id").get<unsigned int>();
    v.name = j.at("name").get<std::string>();
    if (j.contains("slug") && !j.at("slug").is_null()) v.slug = j.at("slug").get<std::string>();
    if (j.contains("fuse_name")) {
        if (j.at("fuse_name").is_null()) v.fuse_name = std::nullopt;
        else v.fuse_name = j.at("fuse_name").get<std::string>();
    }
    v.description = j.at("description").get<std::string>();
    v.quota = j.at("quota").get<unsigned long long>();
    v.type = from_string(j.at("type").get<std::string>());
    v.owner_id = j.at("owner_id").get<unsigned int>();
    v.mount_point = std::filesystem::path(j.at("mount_point").get<std::string>());
    if (j.contains("allow_fs_write")) v.allow_fs_write = j.at("allow_fs_write").get<bool>();
    v.is_active = j.at("is_active").get<bool>();
    v.created_at = parseTimestampFromString(j.at("created_at").get<std::string>());
}

void vh::vault::model::to_json(nlohmann::json& j, const std::vector<std::shared_ptr<Vault>>& vaults) {
    j = nlohmann::json::array();
    for (const auto& vault : vaults) {
        if (const auto* s3 = dynamic_cast<const S3Vault*>(vault.get())) j.push_back(*s3);
        else j.push_back(*vault);
    }
}

std::string vh::vault::model::to_string(const Vault& v) {
    std::string out = "Name: " + v.name + "\n";
    out += "Slug: " + v.slug + "\n";
    out += "FUSE Name: " + v.effectiveFuseName() + "\n";
    out += "ID: " + std::to_string(v.id) + "\n";
    out += "Owner ID: " + std::to_string(v.owner_id) + "\n";
    out += "Type: " + to_string(v.type) + "\n";
    if (const auto* s3 = dynamic_cast<const S3Vault*>(&v)) {
        out += "API Key ID: " + std::to_string(s3->api_key_id) + "\n";
        out += "Bucket: " + s3->bucket + "\n";
        out += "Storage Tier: " + s3->storage_tier_id.value_or("provider default") + "\n";
    }
    out += "Description: " + v.description + "\n";
    out += "Mount Point: " + v.mount_point.string() + "\n";
    out += "Quota: ";
    if (v.quota == 0) out += "\u221E\n";  // ∞ symbol
    else out += fmt::format("{} ({} bytes)\n", human_bytes(v.quota), static_cast<unsigned long long>(v.quota));
    out += "Created At: " + timestampToString(v.created_at) + "\n";
    out += "Allow FS Write: " + std::string(v.allow_fs_write ? "true" : "false") + "\n";
    out += "Is Active: " + std::string(v.is_active ? "true" : "false") + "\n";
    return out;
}

std::string vh::vault::model::to_string(const std::shared_ptr<Vault>& v) {
    if (!v) return "null";
    return to_string(*v);
}


std::string vh::vault::model::to_string(const std::vector<std::shared_ptr<Vault>>& vaults) {

    Table tbl({
        {"ID",    Align::Right, 3, 8,   false, false },
        { "OWNER", Align::Right, 4, 16,  false, false },
        { "NAME",  Align::Left,  4, 64,  false, false },
        { "TYPE",  Align::Left,  4, 24,  false, false },
        { "QUOTA", Align::Right, 5, 32,  false, false },
        // description wraps, effectively acts as flex column
        { "DESCRIPTION", Align::Left, 11, 2000, true, false },
    }, /*term_width*/ term_width());

    if (vaults.empty()) {
        auto out = tbl.render();
        out += "\n";
        out += "No vaults found\n";
        return out;
    }

    for (const auto& vp : vaults) {
        const auto& v = *vp;
        const std::string quota = (v.quota == 0)
            ? "∞"
            : fmt::format("{} ({})",
                          human_bytes(static_cast<uint64_t>(v.quota)),
                          static_cast<unsigned long long>(v.quota));

        std::string owner = v.owner_id != 0 ?
            db::query::vault::Vault::getVaultOwnersName(v.id) + " (ID: " + std::to_string(v.owner_id) + ")" : "N/A";

        tbl.add_row({
            std::to_string(v.id),
            owner,
            v.name,
            to_string(v.type),
            quota,
            v.description
        });
    }

    std::string out;
    out += "vaulthalla vaults:\n";
    out += tbl.render();
    return out;
}
