#include "db/query/peer/VaultPolicy.hpp"

#include "db/Transactions.hpp"
#include "rbac/role/Vault.hpp"

#include <pqxx/pqxx>

namespace vh::db::query::peer {

namespace {

std::optional<uint32_t> peerOptionalId(const pqxx::row_ref row, const char* column) {
    if (row[column].is_null()) return std::nullopt;
    return row[column].as<uint32_t>();
}

std::shared_ptr<vh::rbac::role::Vault> peerVaultRoleById(pqxx::work& txn, const std::optional<uint32_t> id) {
    if (!id) return nullptr;
    const auto res = txn.exec(pqxx::prepped{"vault_role_get_by_id"}, pqxx::params{*id});
    if (res.empty()) return nullptr;
    return std::make_shared<vh::rbac::role::Vault>(res.one_row_ref());
}

}

LinkDefault VaultPolicy::get(const uint32_t peerId) {
    return Transactions::exec("peer::VaultPolicy::get", [&](pqxx::work& txn) {
        LinkDefault out{.peer_id = peerId};
        const auto res = txn.exec("SELECT role_id, set_by, EXTRACT(EPOCH FROM set_at)::BIGINT AS set_at "
                                  "FROM peer_vault_policy WHERE peer_id = $1",
                                  pqxx::params{peerId});
        if (res.empty()) return out;
        const auto row = res.one_row_ref();
        out.role = peerVaultRoleById(txn, peerOptionalId(row, "role_id"));
        if (!row["set_by"].is_null()) out.set_by = row["set_by"].as<uint32_t>();
        out.set_at = static_cast<std::time_t>(row["set_at"].as<int64_t>());
        return out;
    });
}

void VaultPolicy::set(const uint32_t peerId, const std::optional<uint32_t> roleId, const uint32_t setBy) {
    Transactions::exec("peer::VaultPolicy::set", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO peer_vault_policy (peer_id, role_id, set_by, set_at) "
                 "VALUES ($1, NULLIF($2::integer, 0), $3, CURRENT_TIMESTAMP) "
                 "ON CONFLICT (peer_id) DO UPDATE SET role_id = EXCLUDED.role_id, set_by = EXCLUDED.set_by, "
                 "  set_at = EXCLUDED.set_at",
                 pqxx::params{peerId, roleId.value_or(0u), setBy});
    });
}

uint32_t VaultPolicy::countForRole(const uint32_t roleId) {
    return Transactions::exec("peer::VaultPolicy::countForRole", [&](pqxx::work& txn) {
        return txn.exec("SELECT count(*) FROM peer_vault_policy WHERE role_id = $1", pqxx::params{roleId})
            .one_field_ref()
            .as<uint32_t>();
    });
}

PeerStanding VaultPolicy::standing(const uint32_t peerId, const uint32_t vaultId) {
    return Transactions::exec("peer::VaultPolicy::standing", [&](pqxx::work& txn) {
        PeerStanding out;
        const auto res = txn.exec(
            "SELECT p.revoked_at IS NULL AS live, "
            "  (SELECT a.id FROM vault_role_assignments a "
            "   WHERE a.vault_id = $2 AND a.subject_type = 'peer' AND a.subject_id = p.id) AS assignment_id, "
            "  (SELECT d.role_id FROM peer_vault_policy d WHERE d.peer_id = p.id) AS default_role_id, "
            "  EXISTS (SELECT 1 FROM mirror_vault m WHERE m.vault_id = $2 AND m.peer_id = p.id AND m.role = 'core') "
            "    AS mirrored_from_here, "
            "  EXISTS (SELECT 1 FROM vault v WHERE v.id = $2 AND v.deleted_at IS NULL) AS vault_live "
            "FROM peer p WHERE p.id = $1",
            pqxx::params{peerId, vaultId});
        if (res.empty()) return out;
        const auto row = res.one_row_ref();
        out.exists = true;
        out.live = row["live"].as<bool>();
        out.mirrored_from_here = row["mirrored_from_here"].as<bool>();
        out.vault_live = row["vault_live"].as<bool>();
        if (!row["assignment_id"].is_null()) {
            const auto a = txn.exec(pqxx::prepped{"vault_role_assignment_get_by_id"},
                                    pqxx::params{row["assignment_id"].as<uint32_t>()});
            if (!a.empty()) out.vault_role = std::make_shared<vh::rbac::role::Vault>(a.one_row_ref());
        }
        out.link_default = peerVaultRoleById(txn, peerOptionalId(row, "default_role_id"));
        return out;
    });
}

}
