#include "db/query/mirror/Versions.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>

namespace vh::db::query::mirror {

std::optional<VersionsRow> MirrorVersions::get(const uint32_t vaultId) {
    return Transactions::exec("mirror::MirrorVersions::get", [&](pqxx::work& txn) -> std::optional<VersionsRow> {
        const auto r = txn.exec("SELECT keep_versions::text, keep_versions_set_by, "
                                "  EXTRACT(EPOCH FROM keep_versions_set_at)::BIGINT FROM mirror_vault WHERE vault_id = $1",
                                pqxx::params{vaultId});
        if (r.empty()) return std::nullopt;
        VersionsRow row;
        if (!r[0][0].is_null()) row.policy = nlohmann::json::parse(r[0][0].as<std::string>());
        if (!r[0][1].is_null()) row.set_by = r[0][1].as<uint32_t>();
        if (!r[0][2].is_null()) row.set_at = static_cast<std::time_t>(r[0][2].as<int64_t>());
        return row;
    });
}

bool MirrorVersions::set(const uint32_t vaultId, const nlohmann::json& policy, const std::optional<uint32_t> by) {
    return Transactions::exec("mirror::MirrorVersions::set", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_vault SET keep_versions = $2::jsonb, keep_versions_set_by = $3, "
                        "  keep_versions_set_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                        "WHERE vault_id = $1 AND role = 'mirror'",
                        pqxx::params{vaultId, policy.dump(), by})
                   .affected_rows() > 0;
    });
}

std::map<uint32_t, nlohmann::json> MirrorVersions::all() {
    return Transactions::exec("mirror::MirrorVersions::all", [&](pqxx::work& txn) {
        std::map<uint32_t, nlohmann::json> out;
        for (const auto row : txn.exec("SELECT vault_id, keep_versions::text FROM mirror_vault "
                                       "WHERE role = 'mirror' AND keep_versions IS NOT NULL"))
            out.emplace(row[0].as<uint32_t>(), nlohmann::json::parse(row[1].as<std::string>()));
        return out;
    });
}

}
