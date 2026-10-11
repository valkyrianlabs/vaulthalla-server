#include "fs/cache/Record.hpp"
#include "db/encoding/timestamp.hpp"

#include <pqxx/result>
#include <nlohmann/json.hpp>

using namespace vh::fs::cache;
using namespace vh::db::encoding;

Record::Record(pqxx::row_ref row)
    : id(row.at("id").as<unsigned int>()),
      vault_id(row.at("vault_id").as<unsigned int>()),
      file_id(row.at("file_id").as<unsigned int>()),
      path(row.at("path").as<std::string>()),
      type(typeFromString(row.at("type").as<std::string>())),
      size(row.at("size").as<uintmax_t>()),
      last_accessed(parsePostgresTimestamp(row.at("last_accessed").as<std::string>())),
      created_at(parsePostgresTimestamp(row.at("created_at").as<std::string>())) {
    const auto text = [&row](const char* column) -> std::string {
        const auto field = row[column];
        return field.is_null() ? std::string{} : field.as<std::string>();
    };
    kind = text("kind");
    variant = text("variant");
    source_id = text("source_id");
    artifact_iv = text("artifact_iv");
    failure_reason = text("failure_reason");
    if (!row["generator_version"].is_null()) generator_version = row["generator_version"].as<unsigned int>();
    if (!row["artifact_key_version"].is_null()) artifact_key_version = row["artifact_key_version"].as<unsigned int>();
    status = text("status") == "failed" ? Status::Failed : Status::Ready;
    for (const auto& field : row)
        if (std::string_view(field.name()) == "page_count" && !field.is_null()) page_count = field.as<unsigned int>();
}

void vh::fs::cache::to_json(nlohmann::json& j, const Record& index) {
    j = {
        {"id", index.id},
        {"vault_id", index.vault_id},
        {"file_id", index.file_id},
        {"path", index.path.string()},
        {"type", to_string(index.type)},
        {"size", index.size},
        {"last_accessed", timestampToString(index.last_accessed)},
        {"created_at", timestampToString(index.created_at)},
        {"kind", index.kind},
        {"variant", index.variant},
        {"status", index.status == Record::Status::Failed ? "failed" : "ready"}
    };
}

void vh::fs::cache::from_json(const nlohmann::json& j, Record& index) {
    index.id = j.value("id", 0);
    index.vault_id = j.value("vault_id", 0);
    index.file_id = j.value("file_id", 0);
    index.path = j.value("path", std::filesystem::path{});
    index.type = typeFromString(j.value("type", "file"));
    index.size = j.value("size", 0u);
    index.last_accessed = parseTimestampFromString(j.value("last_accessed", ""));
    index.created_at = parseTimestampFromString(j.value("created_at", ""));
}

std::string vh::fs::cache::to_string(const Record::Type& type) {
    switch (type) {
        case Record::Type::File: return "file";
        case Record::Type::Thumbnail: return "thumbnail";
        case Record::Type::Derived: return "derived";
        default: throw std::invalid_argument("Unknown CacheIndex type");
    }
}

Record::Type vh::fs::cache::typeFromString(const std::string& str) {
    if (str == "file") return Record::Type::File;
    if (str == "thumbnail") return Record::Type::Thumbnail;
    if (str == "derived") return Record::Type::Derived;
    throw std::invalid_argument("Unknown CacheIndex type: " + str);
}

