#include "recovery/provider/State.hpp"

#include "db/Transactions.hpp"

#include <pqxx/result>

namespace vh::recovery::provider {

BucketVersioning bucketVersioningForVault(const uint32_t vaultId, const std::time_t now) {
    return db::Transactions::read("recovery::provider::bucketVersioningForVault", [&](pqxx::transaction_base& txn) {
        BucketVersioning v;
        const auto res = txn.exec(R"SQL(
            SELECT COALESCE(versioning_status, 'unknown') AS status, versioning_enabled_by_vaulthalla,
                   extract(epoch FROM versioning_settles_at)::bigint AS settles_at
            FROM upstream_bucket WHERE vault_id = $1
            ORDER BY updated_at DESC, id DESC LIMIT 1
        )SQL", pqxx::params{vaultId});
        if (res.empty()) return v;
        const auto row = res.one_row_ref();
        v.status = row["status"].as<std::string>();
        v.enabled_by_vaulthalla = row["versioning_enabled_by_vaulthalla"].as<bool>();
        if (!row["settles_at"].is_null()) v.settles_at = static_cast<std::time_t>(row["settles_at"].as<int64_t>());
        v.settled = v.status == "enabled" && (!v.settles_at || now >= *v.settles_at);
        return v;
    });
}

}
