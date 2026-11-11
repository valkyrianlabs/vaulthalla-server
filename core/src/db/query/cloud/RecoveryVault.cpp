#include "db/query/cloud/RecoveryVault.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>

namespace vh::db::query::cloud {

namespace recovery_vault_detail {

constexpr const char* kSelect =
    "SELECT vault_id, vault_uid, installation_id, enrolled_by, EXTRACT(EPOCH FROM enrolled_at)::BIGINT, "
    "EXTRACT(EPOCH FROM last_upload_at)::BIGINT FROM cloud_recovery_vault";

RecoveryVaultRow rowOf(const pqxx::row_ref r) {
    return {.vault_id = r[0].as<uint32_t>(), .vault_uid = r[1].as<std::string>(), .installation_id = r[2].as<std::string>(),
            .enrolled_by = r[3].as<std::string>(), .enrolled_at = static_cast<std::time_t>(r[4].as<int64_t>()),
            .last_upload_at = static_cast<std::time_t>(r[5].as<int64_t>())};
}

}

std::vector<RecoveryVaultRow> RecoveryVaults::list() {
    return Transactions::exec("cloud::RecoveryVaults::list", [&](pqxx::work& txn) {
        std::vector<RecoveryVaultRow> out;
        for (const auto r : txn.exec(std::string(recovery_vault_detail::kSelect) + " ORDER BY vault_id"))
            out.push_back(recovery_vault_detail::rowOf(r));
        return out;
    });
}

std::optional<RecoveryVaultRow> RecoveryVaults::get(const uint32_t vaultId) {
    return Transactions::exec("cloud::RecoveryVaults::get", [&](pqxx::work& txn) -> std::optional<RecoveryVaultRow> {
        const auto res = txn.exec(std::string(recovery_vault_detail::kSelect) + " WHERE vault_id = $1", pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return recovery_vault_detail::rowOf(res[0]);
    });
}

void RecoveryVaults::upsert(const RecoveryVaultRow& row) {
    Transactions::exec("cloud::RecoveryVaults::upsert", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO cloud_recovery_vault (vault_id, vault_uid, installation_id, enrolled_by) VALUES ($1, $2, $3, "
                 "$4) ON CONFLICT (vault_id) DO UPDATE SET vault_uid = EXCLUDED.vault_uid, installation_id = "
                 "EXCLUDED.installation_id, last_upload_at = CURRENT_TIMESTAMP",
                 pqxx::params{row.vault_id, row.vault_uid, row.installation_id, row.enrolled_by});
    });
}

bool RecoveryVaults::remove(const uint32_t vaultId) {
    return Transactions::exec("cloud::RecoveryVaults::remove", [&](pqxx::work& txn) {
        return txn.exec("DELETE FROM cloud_recovery_vault WHERE vault_id = $1", pqxx::params{vaultId}).affected_rows() == 1;
    });
}

}
