#include "db/query/mirror/MirrorVault.hpp"

#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "ops/Error.hpp"
#include "rbac/Mirrored.hpp"

#include <pqxx/pqxx>
#include <pqxx/subtransaction>

#include <chrono>
#include <string>
#include <thread>

namespace vh::db::query::mirror {

namespace {

constexpr const char* kMirrorVaultColumns = R"SQL(
    vault_id, peer_id, role, term, last_seq, acked_term, acked_seq, pruned_term, pruned_seq,
    encode(digest, 'hex') AS digest, digest_entries, state,
    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at,
    EXTRACT(EPOCH FROM numbered_at)::BIGINT AS numbered_at, EXTRACT(EPOCH FROM acked_at)::BIGINT AS acked_at,
    granted_role_name, granted_files_permissions::bigint AS granted_files,
    granted_directories_permissions::bigint AS granted_directories, granted_sync_permissions::bigint AS granted_sync,
    granted_roles_permissions::bigint AS granted_roles, granted_by_node,
    EXTRACT(EPOCH FROM granted_at)::BIGINT AS granted_at
)SQL";

std::string selectMirrorVaults(const std::string& where) {
    return std::string("SELECT ") + kMirrorVaultColumns + " FROM mirror_vault " + where;
}

MirrorVault mirrorVaultFrom(const pqxx::row_ref row) {
    MirrorVault m;
    m.vault_id = row["vault_id"].as<uint32_t>();
    m.peer_id = row["peer_id"].as<uint32_t>();
    m.role = row["role"].as<std::string>();
    m.term = row["term"].as<uint64_t>();
    m.last_seq = row["last_seq"].as<uint64_t>();
    if (!row["acked_term"].is_null())
        m.acked = Position{row["acked_term"].as<uint64_t>(), row["acked_seq"].as<uint64_t>()};
    m.pruned = {row["pruned_term"].as<uint64_t>(), row["pruned_seq"].as<uint64_t>()};
    const auto digest = vh::mirror::hashFromHex(row["digest"].as<std::string>());
    m.digest = vh::mirror::Digest::fromBytes(digest, row["digest_entries"].as<int64_t>());
    m.state = row["state"].as<std::string>();
    m.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    m.updated_at = static_cast<std::time_t>(row["updated_at"].as<int64_t>());
    if (!row["numbered_at"].is_null()) m.numbered_at = static_cast<std::time_t>(row["numbered_at"].as<int64_t>());
    if (!row["acked_at"].is_null()) m.acked_at = static_cast<std::time_t>(row["acked_at"].as<int64_t>());
    if (!row["granted_role_name"].is_null())
        m.grant = Grant{.role_name = row["granted_role_name"].as<std::string>(),
                        .files = static_cast<uint64_t>(row["granted_files"].as<int64_t>()),
                        .directories = static_cast<uint64_t>(row["granted_directories"].as<int64_t>()),
                        .sync = static_cast<uint64_t>(row["granted_sync"].as<int64_t>()),
                        .roles = static_cast<uint64_t>(row["granted_roles"].as<int64_t>()),
                        .granted_by_node = row["granted_by_node"].as<std::string>(),
                        .granted_at = static_cast<std::time_t>(row["granted_at"].as<int64_t>())};
    return m;
}

// Whoever may resolve a permission on the vault sees the change before the write returns (rbac::mirrored).
template <class T>
T mirrorAccessRepublished(T result) {
    vh::rbac::mirrored::reload();
    return result;
}

// SHARE on the entry tables: waits for every transaction that has written one of them and holds new writers off
// until this transaction ends. Each attempt waits at most kLockWaitMs, inside a savepoint whose rollback releases
// whatever it had locked, so a writer this one waits for is never also waiting for it.
void lockEntryTables(pqxx::work& txn) {
    for (int attempt = 1;; ++attempt) {
        pqxx::subtransaction sub(txn, "mirror_start_lock");
        try {
            sub.exec("SET LOCAL lock_timeout = '" + std::to_string(MirrorVaults::kLockWaitMs) + "ms'");
            sub.exec("LOCK TABLE fs_entry, files, directories, symlinks, files_trashed IN SHARE MODE");
            sub.exec("SET LOCAL lock_timeout TO DEFAULT");
            sub.commit();
            return;
        } catch (const pqxx::sql_error& e) {
            sub.abort();
            if (e.sqlstate() != "55P03" || attempt >= MirrorVaults::kLockAttempts) throw;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

}

std::optional<MirrorVault> MirrorVaults::get(const uint32_t vaultId) {
    return Transactions::exec("mirror::MirrorVaults::get", [&](pqxx::work& txn) -> std::optional<MirrorVault> {
        const auto res = txn.exec(selectMirrorVaults("WHERE vault_id = $1"), pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return mirrorVaultFrom(res.one_row_ref());
    });
}

std::vector<MirrorVault> MirrorVaults::list() {
    return Transactions::exec("mirror::MirrorVaults::list", [&](pqxx::work& txn) {
        std::vector<MirrorVault> out;
        for (const auto row : txn.exec(selectMirrorVaults("ORDER BY vault_id"))) out.push_back(mirrorVaultFrom(row));
        return out;
    });
}

MirrorVault MirrorVaults::startCore(const uint32_t vaultId, const uint32_t peerId, const uint64_t term) {
    if (term < 1) throw ops::Invalid("a term starts at 1");
    // Local accounts are named by this server's node id from the first row on.
    (void)vh::db::query::device::Devices::nodeId();
    return Transactions::exec("mirror::MirrorVaults::startCore", [&](pqxx::work& txn) {
        if (txn.exec("SELECT 1 FROM vault WHERE id = $1 AND deleted_at IS NULL", pqxx::params{vaultId}).empty())
            throw ops::NotFound("no such vault");
        if (txn.exec("SELECT 1 FROM peer WHERE id = $1 AND revoked_at IS NULL", pqxx::params{peerId}).empty())
            throw ops::NotFound("no such linked server");
        lockEntryTables(txn);
        if (!txn.exec("SELECT 1 FROM mirror_vault WHERE vault_id = $1", pqxx::params{vaultId}).empty())
            throw ops::Conflict("this vault is mirrored already");

        // Leftovers of an earlier mirror of this vault the Janitor has not swept yet.
        txn.exec("DELETE FROM vault_replication_log WHERE vault_id = $1", pqxx::params{vaultId});
        txn.exec("DELETE FROM mirror_entry_hash WHERE vault_id = $1", pqxx::params{vaultId});
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role, term) VALUES ($1, $2, 'core', $3)",
                 pqxx::params{vaultId, peerId, static_cast<int64_t>(term)});
        txn.exec("INSERT INTO mirror_entry_hash (vault_id, entry_uid, entry_hash) "
                 "SELECT $1, entry_uid, entry_hash FROM vh_mirror_tree($1)",
                 pqxx::params{vaultId});
        txn.exec("UPDATE mirror_vault m SET digest = d.digest, digest_entries = d.entries "
                 "FROM (SELECT vh_mirror_digest(entry_hash) AS digest, count(*) AS entries "
                 "      FROM mirror_entry_hash WHERE vault_id = $1) d "
                 "WHERE m.vault_id = $1",
                 pqxx::params{vaultId});
        return mirrorVaultFrom(txn.exec(selectMirrorVaults("WHERE vault_id = $1"), pqxx::params{vaultId}).one_row_ref());
    });
}

MirrorVault MirrorVaults::startMirror(const uint32_t vaultId, const uint32_t peerId, const uint64_t term) {
    if (term < 1) throw ops::Invalid("a term starts at 1");
    return mirrorAccessRepublished(Transactions::exec("mirror::MirrorVaults::startMirror", [&](pqxx::work& txn) {
        if (txn.exec("SELECT 1 FROM vault WHERE id = $1 AND deleted_at IS NULL", pqxx::params{vaultId}).empty())
            throw ops::NotFound("no such vault");
        if (txn.exec("SELECT 1 FROM peer WHERE id = $1 AND revoked_at IS NULL", pqxx::params{peerId}).empty())
            throw ops::NotFound("no such linked server");
        if (!txn.exec("SELECT 1 FROM mirror_vault WHERE vault_id = $1 FOR UPDATE", pqxx::params{vaultId}).empty())
            throw ops::Conflict("this vault is mirrored already");
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role, term) VALUES ($1, $2, 'mirror', $3)",
                 pqxx::params{vaultId, peerId, static_cast<int64_t>(term)});
        return mirrorVaultFrom(txn.exec(selectMirrorVaults("WHERE vault_id = $1"), pqxx::params{vaultId}).one_row_ref());
    }));
}

bool MirrorVaults::recordGrant(const uint32_t vaultId, const Grant& grant) {
    if (grant.role_name.empty() || grant.role_name.size() > 50) throw ops::Invalid("a granted role's name is 1-50 characters");
    if (grant.granted_by_node.empty() || grant.granted_by_node.size() > 64)
        throw ops::Invalid("the granting server's node id is 1-64 characters");
    return mirrorAccessRepublished(Transactions::exec("mirror::MirrorVaults::recordGrant", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_vault SET granted_role_name = $2, granted_files_permissions = $3::bigint::bit(32), "
                        "  granted_directories_permissions = $4::bigint::bit(32), "
                        "  granted_sync_permissions = $5::bigint::bit(32), granted_roles_permissions = $6::bigint::bit(16), "
                        "  granted_by_node = $7, "
                        "  granted_at = CASE WHEN $8::bigint = 0 THEN CURRENT_TIMESTAMP ELSE to_timestamp($8::bigint) END, "
                        "  updated_at = CURRENT_TIMESTAMP "
                        "WHERE vault_id = $1 AND role IN ('mirror', 'orphaned')",
                        pqxx::params{vaultId, grant.role_name, static_cast<int64_t>(grant.files & 0xffffffffu),
                                     static_cast<int64_t>(grant.directories & 0xffffffffu),
                                     static_cast<int64_t>(grant.sync & 0xffffffffu),
                                     static_cast<int64_t>(grant.roles & 0xffffu), grant.granted_by_node,
                                     static_cast<int64_t>(grant.granted_at)})
                   .affected_rows() > 0;
    }));
}

bool MirrorVaults::clearGrant(const uint32_t vaultId) {
    return mirrorAccessRepublished(Transactions::exec("mirror::MirrorVaults::clearGrant", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_vault SET granted_role_name = NULL, granted_files_permissions = NULL, "
                        "  granted_directories_permissions = NULL, granted_sync_permissions = NULL, "
                        "  granted_roles_permissions = NULL, granted_by_node = NULL, granted_at = NULL, "
                        "  updated_at = CURRENT_TIMESTAMP "
                        "WHERE vault_id = $1 AND granted_role_name IS NOT NULL",
                        pqxx::params{vaultId})
                   .affected_rows() > 0;
    }));
}

bool MirrorVaults::remove(const uint32_t vaultId) {
    return mirrorAccessRepublished(Transactions::exec("mirror::MirrorVaults::remove", [&](pqxx::work& txn) {
        const auto gone = txn.exec("DELETE FROM mirror_vault WHERE vault_id = $1", pqxx::params{vaultId}).affected_rows();
        txn.exec("DELETE FROM vault_replication_log WHERE vault_id = $1", pqxx::params{vaultId});
        txn.exec("DELETE FROM mirror_entry_hash WHERE vault_id = $1", pqxx::params{vaultId});
        return gone > 0;
    }));
}

bool MirrorVaults::acknowledge(const uint32_t vaultId, const Position at) {
    return Transactions::exec("mirror::MirrorVaults::acknowledge", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_vault SET acked_term = $2, acked_seq = $3, acked_at = CURRENT_TIMESTAMP, "
                        "  updated_at = CURRENT_TIMESTAMP "
                        "WHERE vault_id = $1 AND role = 'core' AND ($2::bigint, $3::bigint) <= (term, last_seq) "
                        "  AND (acked_term IS NULL OR (acked_term, acked_seq) <= ($2::bigint, $3::bigint))",
                        pqxx::params{vaultId, static_cast<int64_t>(at.term), static_cast<int64_t>(at.seq)})
                   .affected_rows() > 0;
    });
}

bool MirrorVaults::setState(const uint32_t vaultId, const std::string& state) {
    if (state != "live" && state != "paused" && state != "diverged") throw ops::Invalid("unknown mirror state: " + state);
    return Transactions::exec("mirror::MirrorVaults::setState", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_vault SET state = $2, updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
                        pqxx::params{vaultId, state})
                   .affected_rows() > 0;
    });
}

bool MirrorVaults::orphan(const uint32_t vaultId) {
    return mirrorAccessRepublished(Transactions::exec("mirror::MirrorVaults::orphan", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_vault SET role = 'orphaned', updated_at = CURRENT_TIMESTAMP "
                        "WHERE vault_id = $1 AND role = 'mirror'",
                        pqxx::params{vaultId})
                   .affected_rows() > 0;
    }));
}

}
