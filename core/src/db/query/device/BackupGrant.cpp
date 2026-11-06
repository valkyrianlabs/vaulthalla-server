#include "db/query/device/BackupGrant.hpp"

#include "db/Transactions.hpp"
#include "ops/Error.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <charconv>
#include <string_view>

namespace vh::db::query::device {

namespace {

constexpr const char* kBackupGrantColumns = R"SQL(
    g.id, g.device_id, g.user_id, g.origin, g.approved_via,
    COALESCE((SELECT string_agg(v.vault_id::TEXT, ',' ORDER BY v.vault_id) FROM key_backup_grant_vaults v
              WHERE v.grant_id = g.id), '') AS vault_ids,
    EXTRACT(EPOCH FROM g.created_at)::BIGINT AS created_at,
    EXTRACT(EPOCH FROM g.confirmed_at)::BIGINT AS confirmed_at,
    EXTRACT(EPOCH FROM g.last_used_at)::BIGINT AS last_used_at,
    EXTRACT(EPOCH FROM g.suspended_at)::BIGINT AS suspended_at,
    EXTRACT(EPOCH FROM g.revoked_at)::BIGINT AS revoked_at,
    g.revoked_reason
)SQL";

std::string backupGrantSelect(const std::string& where) {
    return std::string("SELECT ") + kBackupGrantColumns + " FROM key_backup_grants g " + where;
}

std::optional<std::time_t> backupGrantTime(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return static_cast<std::time_t>(f.as<int64_t>());
}

std::vector<uint32_t> backupGrantVaultList(const std::string_view csv) {
    std::vector<uint32_t> out;
    std::size_t pos = 0;
    while (pos < csv.size()) {
        const auto comma = csv.find(',', pos);
        const auto part = csv.substr(pos, comma == std::string_view::npos ? std::string_view::npos : comma - pos);
        uint32_t id = 0;
        if (std::from_chars(part.data(), part.data() + part.size(), id).ec == std::errc{}) out.push_back(id);
        if (comma == std::string_view::npos) break;
        pos = comma + 1;
    }
    return out;
}

BackupGrant backupGrantFromRow(const pqxx::row_ref row) {
    BackupGrant g;
    g.id = row["id"].as<uint32_t>();
    g.device_id = row["device_id"].as<uint32_t>();
    g.user_id = row["user_id"].as<uint32_t>();
    g.origin = row["origin"].as<std::string>();
    if (!row["approved_via"].is_null()) g.approved_via = row["approved_via"].as<std::string>();
    g.vault_ids = backupGrantVaultList(row["vault_ids"].as<std::string>());
    g.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    g.confirmed_at = backupGrantTime(row["confirmed_at"]);
    g.last_used_at = backupGrantTime(row["last_used_at"]);
    g.suspended_at = backupGrantTime(row["suspended_at"]);
    g.revoked_at = backupGrantTime(row["revoked_at"]);
    if (!row["revoked_reason"].is_null()) g.revoked_reason = row["revoked_reason"].as<std::string>();
    return g;
}

std::vector<BackupGrant> backupGrantRows(const pqxx::result& res) {
    std::vector<BackupGrant> out;
    out.reserve(res.size());
    for (const auto& r : res) out.push_back(backupGrantFromRow(r));
    return out;
}

std::optional<BackupGrant> backupGrantOne(pqxx::transaction_base& txn, const uint32_t id) {
    const auto res = txn.exec(backupGrantSelect("WHERE g.id = $1"), pqxx::params{id});
    if (res.empty()) return std::nullopt;
    return backupGrantFromRow(res.one_row_ref());
}

void backupGrantAddVaults(pqxx::work& txn, const uint32_t grantId, const std::vector<uint32_t>& vaultIds) {
    for (const auto v : vaultIds)
        txn.exec("INSERT INTO key_backup_grant_vaults (grant_id, vault_id) VALUES ($1, $2) ON CONFLICT DO NOTHING",
                 pqxx::params{grantId, v});
}

std::vector<BackupGrant> backupGrantRevokeWhere(const std::string& ctx, const std::string& where, const pqxx::params& p) {
    return Transactions::exec(ctx, [&](pqxx::work& txn) {
        std::vector<uint32_t> ids;
        for (const auto& r : txn.exec("UPDATE key_backup_grants SET revoked_at = NOW(), revoked_reason = $1 " + where +
                                          " AND revoked_at IS NULL RETURNING id",
                                      p))
            ids.push_back(r[0].as<uint32_t>());
        std::ranges::sort(ids);
        std::vector<BackupGrant> out;
        for (const auto id : ids)
            if (auto g = backupGrantOne(txn, id)) out.push_back(std::move(*g));
        return out;
    });
}

}

bool BackupGrant::names(const uint32_t vaultId) const noexcept {
    return std::ranges::binary_search(vault_ids, vaultId);
}

std::optional<BackupGrant> BackupGrants::byId(const uint32_t id) {
    return Transactions::read("BackupGrants::byId", [&](pqxx::transaction_base& txn) { return backupGrantOne(txn, id); });
}

std::optional<BackupGrant> BackupGrants::liveForDevice(const uint32_t deviceId) {
    return Transactions::read("BackupGrants::liveForDevice", [&](pqxx::transaction_base& txn) -> std::optional<BackupGrant> {
        const auto res = txn.exec(backupGrantSelect("WHERE g.device_id = $1 AND g.revoked_at IS NULL"),
                                  pqxx::params{deviceId});
        if (res.empty()) return std::nullopt;
        return backupGrantFromRow(res[0]);
    });
}

std::optional<BackupGrant> BackupGrants::lastRevokedForDevice(const uint32_t deviceId) {
    return Transactions::read("BackupGrants::lastRevokedForDevice",
                              [&](pqxx::transaction_base& txn) -> std::optional<BackupGrant> {
        const auto res = txn.exec(backupGrantSelect("WHERE g.device_id = $1 AND g.revoked_at IS NOT NULL "
                                                    "ORDER BY g.revoked_at DESC, g.id DESC LIMIT 1"),
                                  pqxx::params{deviceId});
        if (res.empty()) return std::nullopt;
        return backupGrantFromRow(res[0]);
    });
}

std::vector<BackupGrant> BackupGrants::listForUser(const uint32_t userId) {
    return Transactions::read("BackupGrants::listForUser", [&](pqxx::transaction_base& txn) {
        return backupGrantRows(txn.exec(backupGrantSelect("WHERE g.user_id = $1 "
                                                          "ORDER BY (g.revoked_at IS NULL) DESC, g.id DESC"),
                                        pqxx::params{userId}));
    });
}

std::vector<BackupGrant> BackupGrants::listLive() {
    return Transactions::read("BackupGrants::listLive", [&](pqxx::transaction_base& txn) {
        return backupGrantRows(txn.exec(backupGrantSelect("WHERE g.revoked_at IS NULL ORDER BY g.id")));
    });
}

std::vector<BackupGrant> BackupGrants::listLiveForUsers(const std::vector<uint32_t>& userIds) {
    std::vector<BackupGrant> out;
    if (userIds.empty()) return out;
    for (auto& g : listLive())
        if (std::ranges::find(userIds, g.user_id) != userIds.end()) out.push_back(std::move(g));
    return out;
}

BackupGrant BackupGrants::create(const NewBackupGrant& g) {
    try {
        return Transactions::exec("BackupGrants::create", [&](pqxx::work& txn) {
            // The device row is locked so a revocation can't slip between the check and the insert.
            if (txn.exec("SELECT 1 FROM devices WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE",
                         pqxx::params{g.device_id, g.user_id})
                    .empty())
                throw ops::Conflict("this device is not paired with this node");
            if (!txn.exec("SELECT 1 FROM key_backup_grants WHERE device_id = $1 AND revoked_at IS NULL",
                          pqxx::params{g.device_id})
                     .empty())
                throw ops::Conflict("this device already has a key-backup grant: extend it instead");
            const auto id = txn.exec("INSERT INTO key_backup_grants (device_id, user_id, origin, approved_via, "
                                     "confirmed_at) VALUES ($1, $2, $3, $4, CASE WHEN $3 = 'approved' THEN NOW() END) "
                                     "RETURNING id",
                                     pqxx::params{g.device_id, g.user_id, g.origin, g.approved_via})
                                .one_field_ref()
                                .as<uint32_t>();
            backupGrantAddVaults(txn, id, g.vault_ids);
            return *backupGrantOne(txn, id);
        });
    } catch (const pqxx::unique_violation&) {
        throw ops::Conflict("this device already has a key-backup grant: extend it instead");
    }
}

std::optional<BackupGrant> BackupGrants::addVaults(const uint32_t grantId, const std::vector<uint32_t>& vaultIds) {
    return Transactions::exec("BackupGrants::addVaults", [&](pqxx::work& txn) -> std::optional<BackupGrant> {
        if (txn.exec("SELECT 1 FROM key_backup_grants WHERE id = $1 AND revoked_at IS NULL FOR UPDATE",
                     pqxx::params{grantId})
                .empty())
            return std::nullopt;
        backupGrantAddVaults(txn, grantId, vaultIds);
        return backupGrantOne(txn, grantId);
    });
}

std::optional<BackupGrant> BackupGrants::confirm(const uint32_t grantId, const std::optional<std::string>& approvedVia) {
    return Transactions::exec("BackupGrants::confirm", [&](pqxx::work& txn) -> std::optional<BackupGrant> {
        if (txn.exec("UPDATE key_backup_grants SET origin = 'approved', confirmed_at = NOW(), suspended_at = NULL, "
                     "approved_via = COALESCE($2, approved_via) WHERE id = $1 AND revoked_at IS NULL",
                     pqxx::params{grantId, approvedVia})
                .affected_rows() == 0)
            return std::nullopt;
        return backupGrantOne(txn, grantId);
    });
}

std::optional<BackupGrant> BackupGrants::suspend(const uint32_t grantId) {
    return Transactions::exec("BackupGrants::suspend", [&](pqxx::work& txn) -> std::optional<BackupGrant> {
        if (txn.exec("UPDATE key_backup_grants SET suspended_at = NOW() "
                     "WHERE id = $1 AND revoked_at IS NULL AND suspended_at IS NULL",
                     pqxx::params{grantId})
                .affected_rows() == 0)
            return std::nullopt;
        return backupGrantOne(txn, grantId);
    });
}

std::optional<BackupGrant> BackupGrants::revoke(const uint32_t grantId, const std::string& reason) {
    auto out = backupGrantRevokeWhere("BackupGrants::revoke", "WHERE id = $2", pqxx::params{reason, grantId});
    if (out.empty()) return std::nullopt;
    return std::move(out.front());
}

std::vector<BackupGrant> BackupGrants::revokeForDevice(const uint32_t deviceId, const std::string& reason) {
    return backupGrantRevokeWhere("BackupGrants::revokeForDevice", "WHERE device_id = $2", pqxx::params{reason, deviceId});
}

std::vector<BackupGrant> BackupGrants::revokeForUser(const uint32_t userId, const std::string& reason) {
    return backupGrantRevokeWhere("BackupGrants::revokeForUser", "WHERE user_id = $2", pqxx::params{reason, userId});
}

void BackupGrants::touch(const uint32_t grantId) {
    Transactions::exec("BackupGrants::touch", [&](pqxx::work& txn) {
        txn.exec("UPDATE key_backup_grants SET last_used_at = NOW() WHERE id = $1", pqxx::params{grantId});
    });
}

bool BackupGrants::approvalKeyPredatesRevocation(const uint32_t deviceId, const uint32_t grantId) {
    return Transactions::read("BackupGrants::approvalKeyPredatesRevocation", [&](pqxx::transaction_base& txn) {
        return !txn.exec("SELECT 1 FROM device_approval_keys k JOIN key_backup_grants g ON g.device_id = k.device_id "
                         "WHERE k.device_id = $1 AND g.id = $2 AND k.revoked_at IS NULL AND g.revoked_at IS NOT NULL "
                         "AND k.registered_at < g.revoked_at",
                         pqxx::params{deviceId, grantId})
                    .empty();
    });
}

std::vector<PendingMigration> BackupGrants::pendingMigration() {
    return Transactions::read("BackupGrants::pendingMigration", [&](pqxx::transaction_base& txn) {
        std::vector<PendingMigration> out;
        for (const auto& r : txn.exec("SELECT m.device_id, d.user_id, d.revoked_at IS NULL FROM key_backup_grant_migration m "
                                      "JOIN devices d ON d.id = m.device_id ORDER BY m.device_id"))
            out.push_back({.device_id = r[0].as<uint32_t>(), .user_id = r[1].as<uint32_t>(),
                           .device_live = r[2].as<bool>()});
        return out;
    });
}

std::optional<BackupGrant> BackupGrants::migrate(const uint32_t deviceId, const uint32_t userId,
                                                 const std::optional<std::vector<uint32_t>>& vaultIds) {
    return Transactions::exec("BackupGrants::migrate", [&](pqxx::work& txn) -> std::optional<BackupGrant> {
        // The snapshot row is the claim: only the transaction that removes it migrates the device.
        if (txn.exec("DELETE FROM key_backup_grant_migration WHERE device_id = $1", pqxx::params{deviceId})
                .affected_rows() == 0)
            return std::nullopt;
        if (!vaultIds) return std::nullopt;
        if (txn.exec("SELECT 1 FROM devices WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE",
                     pqxx::params{deviceId, userId})
                .empty())
            return std::nullopt;
        if (!txn.exec("SELECT 1 FROM key_backup_grants WHERE device_id = $1", pqxx::params{deviceId}).empty())
            return std::nullopt;
        const auto id = txn.exec("INSERT INTO key_backup_grants (device_id, user_id, origin) VALUES ($1, $2, 'migrated') "
                                 "RETURNING id",
                                 pqxx::params{deviceId, userId})
                            .one_field_ref()
                            .as<uint32_t>();
        backupGrantAddVaults(txn, id, *vaultIds);
        return backupGrantOne(txn, id);
    });
}

}
