#include "db/query/recovery/Policy.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/query/recovery/detail/Fields.hpp"

#include <pqxx/result>

namespace vh::db::query::recovery {

PolicyRow Policy::get(const uint32_t vaultId) {
    return Transactions::read("recovery::Policy::get", [&](pqxx::transaction_base& txn) {
        PolicyRow p;
        p.vault_id = vaultId;
        const auto res = txn.exec(pqxx::prepped{"recovery_policy_get"}, pqxx::params{vaultId});
        if (res.empty()) return p;
        const auto row = res.one_row_ref();
        p.stored = true;
        p.mode = vh::recovery::modeFromString(row["mode"].as<std::string>());
        p.snapshot_quota_bytes = detail::optU64(row["snapshot_quota_bytes"]);
        p.cost_alert_monthly = detail::opt<std::string>(row["cost_alert_monthly"]);
        p.cost_alert_currency = detail::opt<std::string>(row["cost_alert_currency"]);
        p.local_versioning.enabled = row["local_versioning"].as<bool>();
        p.local_versioning.keep_last = detail::opt<unsigned int>(row["version_keep_last"]);
        p.local_versioning.max_age_days = detail::opt<unsigned int>(row["version_max_age_days"]);
        p.local_versioning.quota_bytes = detail::optU64(row["version_quota_bytes"]);
        p.updated_at = detail::optTime(row["updated_at"]);
        p.updated_by = detail::opt<uint32_t>(row["updated_by"]);
        return p;
    });
}

void Policy::upsert(const PolicyRow& row) {
    const auto& lv = row.local_versioning;
    std::optional<std::string> alert = row.cost_alert_monthly;
    if (alert && alert->empty()) alert.reset();
    Transactions::exec("recovery::Policy::upsert", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"recovery_policy_upsert"},
                 pqxx::params{row.vault_id, vh::recovery::to_string(row.mode), detail::optI64(row.snapshot_quota_bytes),
                              alert, alert ? row.cost_alert_currency : std::nullopt, lv.enabled,
                              lv.keep_last ? std::make_optional(static_cast<int>(*lv.keep_last)) : std::nullopt,
                              lv.max_age_days ? std::make_optional(static_cast<int>(*lv.max_age_days)) : std::nullopt,
                              detail::optI64(lv.quota_bytes), row.updated_by});
    });
}

std::vector<uint32_t> Policy::listLocalVersioningVaults() {
    return Transactions::read("recovery::Policy::listLocalVersioningVaults", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_policy_list_local_versioning"});
        return mapRows(res, [](const pqxx::row_ref r) { return r["vault_id"].as<uint32_t>(); });
    });
}

}
