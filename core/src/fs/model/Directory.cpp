#include "fs/model/Directory.hpp"
#include "db/encoding/has.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/query/fs/Entry.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/result>
#include <pqxx/transaction_base>
#include <unordered_map>

using namespace vh::fs::model;
using namespace vh::db::encoding;

Directory::Directory(pqxx::row_ref row, const pqxx::result& parentRows)
    : Entry(row, parentRows),
      file_count(row["file_count"].as<unsigned int>()),
      subdirectory_count(row["subdirectory_count"].as<unsigned int>()),
      uid(try_get<std::string>(row, "uid").transform([](const std::string& text) {
          return vh::crypto::id::fromUuid(text);
      })) {}

void vh::fs::model::to_json(nlohmann::json& j, const Directory& d) {
    to_json(j, static_cast<const Entry&>(d));
    j["type"] = "directory"; // Helpful for client
    j["file_count"] = d.file_count;
    j["subdirectory_count"] = d.subdirectory_count;
}

void vh::fs::model::from_json(const nlohmann::json& j, Directory& d) {
    from_json(j, static_cast<Entry&>(d));
    d.file_count = j.at("file_count").get<unsigned int>();
    d.subdirectory_count = j.at("subdirectory_count").get<unsigned int>();
}

std::vector<std::shared_ptr<Directory>> vh::fs::model::directories_from_pq_res(const pqxx::result& res, pqxx::transaction_base& txn) {
    std::vector<std::shared_ptr<Directory>> directories;
    directories.reserve(res.size());
    std::unordered_map<unsigned int, pqxx::result> chains;
    for (const auto& row : res) {
        if (const auto parentId = row["parent_id"].as<std::optional<unsigned int>>()) {
            auto chain = chains.find(*parentId);
            if (chain == chains.end())
                chain = chains.emplace(*parentId, db::query::fs::Entry::collectParentChain(txn, *parentId)).first;
            directories.push_back(std::make_shared<Directory>(row, chain->second));
        } else directories.push_back(std::make_shared<Directory>(row, pqxx::result{}));
    }
    return directories;
}
