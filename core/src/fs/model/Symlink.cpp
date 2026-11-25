#include "fs/model/Symlink.hpp"
#include "db/encoding/has.hpp"
#include "db/query/fs/Entry.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/result>
#include <pqxx/transaction_base>
#include <unordered_map>

using namespace vh::fs::model;

Symlink::Symlink(pqxx::row_ref row, const pqxx::result& parentRows)
    : Entry(row, parentRows),
      target(row["target"].as<std::string>()),
      uid(vh::db::encoding::try_get<std::string>(row, "uid").transform([](const std::string& text) {
          return vh::crypto::id::fromUuid(text);
      })) {
    size_bytes = target.size();
}

void vh::fs::model::to_json(nlohmann::json& j, const Symlink& s) {
    to_json(j, static_cast<const Entry&>(s));
    j["type"] = "symlink";
    j["target"] = s.target;
}

void vh::fs::model::from_json(const nlohmann::json& j, Symlink& s) {
    from_json(j, static_cast<Entry&>(s));
    s.target = j.at("target").get<std::string>();
    s.size_bytes = s.target.size();
}

void vh::fs::model::to_json(nlohmann::json& j, const std::vector<std::shared_ptr<Symlink>>& symlinks) {
    j = nlohmann::json::array();
    for (const auto& symlink : symlinks) j.push_back(*symlink);
}

std::vector<std::shared_ptr<Symlink>> vh::fs::model::symlinks_from_pq_res(const pqxx::result& res, pqxx::transaction_base& txn) {
    std::vector<std::shared_ptr<Symlink>> symlinks;
    symlinks.reserve(res.size());
    std::unordered_map<unsigned int, pqxx::result> chains;
    for (const auto& row : res) {
        if (const auto parentId = row["parent_id"].as<std::optional<unsigned int>>()) {
            auto chain = chains.find(*parentId);
            if (chain == chains.end())
                chain = chains.emplace(*parentId, db::query::fs::Entry::collectParentChain(txn, *parentId)).first;
            symlinks.push_back(std::make_shared<Symlink>(row, chain->second));
        } else symlinks.push_back(std::make_shared<Symlink>(row, pqxx::result{}));
    }
    return symlinks;
}
