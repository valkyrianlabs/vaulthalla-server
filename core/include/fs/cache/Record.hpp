#pragma once

#include <filesystem>
#include <ctime>
#include <memory>
#include <vector>
#include <nlohmann/json_fwd.hpp>
#include <string>
#include <optional>
#include "db/Fwd.hpp"

namespace vh::fs::cache {

struct Record {
    enum class Type { File, Thumbnail, Derived };
    enum class Status { Ready, Failed };

    unsigned int id{}, vault_id{}, file_id{};
    std::filesystem::path path{};   // relative to the vault's cache root
    Type type{Type::Derived};
    uintmax_t size{};
    std::time_t last_accessed{}, created_at{};

    // Derived artifacts (type Derived): identity, validity and sealing metadata (see preview::cache::Store).
    std::string kind{}, variant{}, source_id{};
    unsigned int generator_version{1};
    std::string artifact_iv{};
    unsigned int artifact_key_version{};
    Status status{Status::Ready};
    std::string failure_reason{};
    std::optional<unsigned int> page_count{};   // PDF renders/thumbnails: the document's page count (migration 109)

    Record() = default;
    explicit Record(pqxx::row_ref row);
};

void to_json(nlohmann::json& j, const Record& index);
void from_json(const nlohmann::json& j, Record& index);

std::string to_string(const Record::Type& type);
Record::Type typeFromString(const std::string& str);
}
