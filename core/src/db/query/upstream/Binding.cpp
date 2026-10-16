#include "db/query/upstream/Binding.hpp"

#include "db/Transactions.hpp"

namespace vh::db::query::upstream {

std::vector<VaultBinding> Binding::forBucketName(const std::string& bucket) {
    return Transactions::exec("upstream::Binding::forBucketName", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT v.id, v.name, v.deleted_at IS NOT NULL AS deleted, s3.api_key_id "
            "FROM s3 JOIN vault v ON v.id = s3.vault_id WHERE s3.bucket = $1 AND s3.api_key_id IS NOT NULL "
            "ORDER BY v.id",
            pqxx::params{bucket});
        std::vector<VaultBinding> out;
        out.reserve(res.size());
        for (const auto& row : res)
            out.push_back({.vault_id = row["id"].as<uint32_t>(),
                           .vault_name = row["name"].as<std::string>(),
                           .deleted = row["deleted"].as<bool>(),
                           .api_key_id = row["api_key_id"].as<uint32_t>()});
        return out;
    });
}

}
