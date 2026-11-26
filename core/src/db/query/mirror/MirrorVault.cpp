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
#include <vector>

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
    EXTRACT(EPOCH FROM granted_at)::BIGINT AS granted_at,
    baseline_term, baseline_seq, encode(baseline_digest, 'hex') AS baseline_digest, baseline_entries, baseline_rows,
    copy_cursor, copy_finished, stop_reason, stop_detail::text AS stop_detail,
    EXTRACT(EPOCH FROM stopped_at)::BIGINT AS stopped_at
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
    if (!row["baseline_term"].is_null())
        m.baseline = Position{row["baseline_term"].as<uint64_t>(), row["baseline_seq"].as<uint64_t>()};
    if (!row["baseline_digest"].is_null())
        m.baseline_digest = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(row["baseline_digest"].as<std::string>()),
                                                          row["baseline_entries"].is_null()
                                                              ? 0
                                                              : row["baseline_entries"].as<int64_t>());
    if (!row["baseline_rows"].is_null()) m.baseline_rows = row["baseline_rows"].as<uint64_t>();
    m.copy_cursor = row["copy_cursor"].as<uint64_t>();
    m.copy_finished = row["copy_finished"].as<bool>();
    if (!row["stop_reason"].is_null()) m.stop_reason = row["stop_reason"].as<std::string>();
    m.stop_detail = row["stop_detail"].is_null() ? nlohmann::json::object()
                                                 : nlohmann::json::parse(row["stop_detail"].as<std::string>());
    if (!row["stopped_at"].is_null()) m.stopped_at = static_cast<std::time_t>(row["stopped_at"].as<int64_t>());
    return m;
}

// Whoever may resolve a permission on the vault sees the change before the write returns (rbac::mirrored).
template <class T>
T mirrorAccessRepublished(T result) {
    vh::rbac::mirrored::reload();
    return result;
}

// The writers of the entry tables running now (their virtual transaction ids): every one that may have changed the
// vault before the `starting` row was visible to it. A writer that takes its RowExclusiveLock after this read runs its
// triggers after the row committed, and waits in vh_mirror_core_term instead.
std::vector<std::string> mirrorEntryWritersNow(pqxx::work& txn) {
    std::vector<std::string> out;
    for (const auto row : txn.exec(
             "SELECT DISTINCT l.virtualtransaction FROM pg_locks l "
             "WHERE l.locktype = 'relation' AND l.granted AND l.mode = 'RowExclusiveLock' "
             "  AND l.pid IS DISTINCT FROM pg_backend_pid() "
             "  AND l.database = (SELECT oid FROM pg_database WHERE datname = current_database()) "
             "  AND l.relation IN ('fs_entry'::regclass, 'files'::regclass, 'directories'::regclass, "
             "                     'symlinks'::regclass, 'files_trashed'::regclass)"))
        out.push_back(row[0].as<std::string>());
    return out;
}

// Waits until none of `writers` is running, polling, for at most kLockWaitMs x kLockAttempts. False when one still is.
bool mirrorWaitForWriters(const std::vector<std::string>& writers) {
    if (writers.empty()) return true;
    std::string list = "{";
    for (const auto& w : writers) {
        if (list.size() > 1) list += ',';
        list += '"' + w + '"';
    }
    list += '}';
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(MirrorVaults::kLockWaitMs) * MirrorVaults::kLockAttempts;
    for (;;) {
        const bool running = Transactions::exec("mirror::MirrorVaults::startCore writers", [&](pqxx::work& txn) {
            return txn.exec("SELECT EXISTS (SELECT 1 FROM pg_locks WHERE virtualtransaction = ANY($1::text[]))",
                            pqxx::params{list})
                .one_field()
                .as<bool>();
        });
        if (!running) return true;
        if (std::chrono::steady_clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

// The `starting` row's lock: every writer of the vault that saw the row holds a share of it until it commits. Each
// attempt waits at most kLockWaitMs, inside a savepoint, so a writer this one waits for is never also waiting for it.
void mirrorLockStartingRow(pqxx::work& txn, const uint32_t vaultId) {
    for (int attempt = 1;; ++attempt) {
        pqxx::subtransaction sub(txn, "mirror_start_lock");
        try {
            sub.exec("SET LOCAL lock_timeout = '" + std::to_string(MirrorVaults::kLockWaitMs) + "ms'");
            const auto row = sub.exec("SELECT 1 FROM mirror_vault WHERE vault_id = $1 AND role = 'core' "
                                      "AND state = 'starting' FOR UPDATE",
                                      pqxx::params{vaultId});
            sub.exec("SET LOCAL lock_timeout TO DEFAULT");
            if (row.empty()) throw ops::Conflict("another start of this vault's mirror took over");
            sub.commit();
            return;
        } catch (const pqxx::sql_error& e) {
            sub.abort();
            if (e.sqlstate() != "55P03") throw;
            if (attempt >= MirrorVaults::kLockAttempts)
                throw ops::Conflict("the vault is busy: its writers did not let the baseline start; try again");
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

void mirrorDropStartingRow(const uint32_t vaultId) noexcept {
    try {
        Transactions::exec("mirror::MirrorVaults::startCore undo", [&](pqxx::work& txn) {
            txn.exec("DELETE FROM mirror_vault WHERE vault_id = $1 AND role = 'core' AND state = 'starting'",
                     pqxx::params{vaultId});
        });
    } catch (...) {
        // A leftover `starting` row only costs the vault's writers a share lock; the next start replaces it.
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

std::optional<MirrorVault> MirrorVaults::get(pqxx::work& txn, const uint32_t vaultId, const bool forUpdate) {
    const auto res = txn.exec(selectMirrorVaults(forUpdate ? "WHERE vault_id = $1 FOR UPDATE" : "WHERE vault_id = $1"),
                              pqxx::params{vaultId});
    if (res.empty()) return std::nullopt;
    return mirrorVaultFrom(res.one_row_ref());
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

    // 1. The `starting` row: from its commit on, a writer of this vault waits in its trigger (vh_mirror_core_term)
    //    while the baseline runs. A leftover one (a start that crashed) is replaced, unless a start holds it now.
    Transactions::exec("mirror::MirrorVaults::startCore begin", [&](pqxx::work& txn) {
        if (txn.exec("SELECT 1 FROM vault WHERE id = $1 AND deleted_at IS NULL", pqxx::params{vaultId}).empty())
            throw ops::NotFound("no such vault");
        if (txn.exec("SELECT 1 FROM peer WHERE id = $1 AND revoked_at IS NULL", pqxx::params{peerId}).empty())
            throw ops::NotFound("no such linked server");
        const auto existing = txn.exec("SELECT state FROM mirror_vault WHERE vault_id = $1", pqxx::params{vaultId});
        if (!existing.empty() && existing[0][0].as<std::string>() != "starting")
            throw ops::Conflict("this vault is mirrored already");
        if (!existing.empty()) {
            pqxx::subtransaction sub(txn, "mirror_start_existing");
            try {
                sub.exec("SELECT 1 FROM mirror_vault WHERE vault_id = $1 FOR UPDATE NOWAIT", pqxx::params{vaultId});
                sub.exec("DELETE FROM mirror_vault WHERE vault_id = $1", pqxx::params{vaultId});
                sub.commit();
            } catch (const pqxx::sql_error& e) {
                sub.abort();
                if (e.sqlstate() == "55P03") throw ops::Conflict("a mirror of this vault is being started");
                throw;
            }
        }
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role, term, state) VALUES ($1, $2, 'core', $3, 'starting')",
                 pqxx::params{vaultId, peerId, static_cast<int64_t>(term)});
    });

    try {
        // 2. Every writer of the entry tables already running may have changed the vault without seeing the row: each
        //    commits (into the baseline) or rolls back before the tree is read.
        const auto writers = Transactions::exec("mirror::MirrorVaults::startCore writers",
                                                [](pqxx::work& txn) { return mirrorEntryWritersNow(txn); });
        if (!mirrorWaitForWriters(writers))
            throw ops::Conflict("the vault is busy: writers that were running did not finish; try again");

        // 3. Under the row's lock (no writer of the vault is between its change and its commit), the tree as it is now:
        //    each entry's state and hash kept for the first copy, the hashes for the log, the digest; then live.
        return Transactions::exec("mirror::MirrorVaults::startCore baseline", [&](pqxx::work& txn) {
            mirrorLockStartingRow(txn, vaultId);
            // Leftovers of an earlier mirror of this vault the Janitor has not swept yet.
            txn.exec("DELETE FROM vault_replication_log WHERE vault_id = $1", pqxx::params{vaultId});
            txn.exec("DELETE FROM mirror_entry_hash WHERE vault_id = $1", pqxx::params{vaultId});
            txn.exec("DELETE FROM mirror_baseline WHERE vault_id = $1", pqxx::params{vaultId});
            // A folder before what is under it (by depth), trashed files after every live entry.
            txn.exec("INSERT INTO mirror_baseline (vault_id, ord, entry_uid, state, entry_hash) "
                     "SELECT $1, row_number() OVER (ORDER BY t.trashed, t.depth, t.entry_uid), t.entry_uid, t.state, "
                     "       vh_mirror_state_hash(t.state) "
                     "FROM vh_mirror_tree_states($1) t",
                     pqxx::params{vaultId});
            txn.exec("INSERT INTO mirror_entry_hash (vault_id, entry_uid, entry_hash) "
                     "SELECT vault_id, entry_uid, entry_hash FROM mirror_baseline WHERE vault_id = $1",
                     pqxx::params{vaultId});
            txn.exec("UPDATE mirror_vault m SET digest = d.digest, digest_entries = d.entries, state = 'live', "
                     "  baseline_term = m.term, baseline_seq = 0, baseline_digest = d.digest, baseline_entries = d.entries, "
                     "  baseline_rows = d.entries, baseline_vault = vh_mirror_vault_state($1), "
                     "  updated_at = CURRENT_TIMESTAMP "
                     "FROM (SELECT vh_mirror_digest(entry_hash) AS digest, count(*) AS entries "
                     "      FROM mirror_baseline WHERE vault_id = $1) d "
                     "WHERE m.vault_id = $1",
                     pqxx::params{vaultId});
            return mirrorVaultFrom(
                txn.exec(selectMirrorVaults("WHERE vault_id = $1"), pqxx::params{vaultId}).one_row_ref());
        });
    } catch (...) {
        mirrorDropStartingRow(vaultId);
        throw;
    }
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
        txn.exec("DELETE FROM mirror_baseline WHERE vault_id = $1", pqxx::params{vaultId});
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
    if (state != "live" && state != "paused" && state != "diverged" && state != "expired" && state != "stopped")
        throw ops::Invalid("unknown mirror state: " + state);
    return Transactions::exec("mirror::MirrorVaults::setState", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_vault SET state = $2, updated_at = CURRENT_TIMESTAMP, "
                        "  stop_reason = CASE WHEN $2 = 'live' THEN NULL ELSE stop_reason END, "
                        "  stop_detail = CASE WHEN $2 = 'live' THEN NULL ELSE stop_detail END, "
                        "  stopped_at = CASE WHEN $2 = 'live' THEN NULL ELSE stopped_at END "
                        "WHERE vault_id = $1 AND state <> 'starting'",
                        pqxx::params{vaultId, state})
                   .affected_rows() > 0;
    });
}

std::optional<MirrorVault> MirrorVaults::byVaultUid(const std::string& vaultUuid) {
    return Transactions::exec("mirror::MirrorVaults::byVaultUid", [&](pqxx::work& txn) -> std::optional<MirrorVault> {
        pqxx::subtransaction sub(txn, "mirror_by_uid");
        try {
            const auto res = sub.exec(selectMirrorVaults("WHERE vault_id = (SELECT id FROM vault "
                                                         "WHERE uid = $1::uuid AND deleted_at IS NULL)"),
                                      pqxx::params{vaultUuid});
            sub.commit();
            if (res.empty()) return std::nullopt;
            return mirrorVaultFrom(res.one_row_ref());
        } catch (const pqxx::data_exception&) {
            sub.abort();
            return std::nullopt;   // not a uuid: no such vault
        }
    });
}

std::optional<std::string> MirrorVaults::vaultUidOf(const uint32_t vaultId) {
    return Transactions::exec("mirror::MirrorVaults::vaultUidOf", [&](pqxx::work& txn) -> std::optional<std::string> {
        const auto res = txn.exec("SELECT uid::text FROM vault WHERE id = $1 AND deleted_at IS NULL AND uid IS NOT NULL",
                                  pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return res[0][0].as<std::string>();
    });
}

bool MirrorVaults::stop(const uint32_t vaultId, const std::string& state, const std::string& reason,
                        const nlohmann::json& detail) {
    if (state != "diverged" && state != "expired" && state != "stopped")
        throw ops::Invalid("a mirror stops as diverged, expired or stopped, not " + state);
    auto text = detail.dump();
    if (text.size() > 16 * 1024) text = nlohmann::json{{"truncated", true}}.dump();
    return Transactions::exec("mirror::MirrorVaults::stop", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_vault SET state = $2, stop_reason = $3, stop_detail = $4::jsonb, "
                        "  stopped_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                        "WHERE vault_id = $1 AND state <> 'starting'",
                        pqxx::params{vaultId, state, reason.substr(0, 200), text})
                   .affected_rows() > 0;
    });
}

namespace {

std::optional<vh::mirror::Digest> mirrorDigestAt(pqxx::work& txn, const uint32_t vaultId, const Position at) {
    const auto mv = txn.exec("SELECT baseline_term, baseline_seq, encode(baseline_digest, 'hex') AS d, baseline_entries "
                             "FROM mirror_vault WHERE vault_id = $1 AND role = 'core' AND state <> 'starting'",
                             pqxx::params{vaultId});
    if (mv.empty()) return std::nullopt;
    if (!mv[0]["baseline_term"].is_null() && !mv[0]["d"].is_null() &&
        Position{mv[0]["baseline_term"].as<uint64_t>(), mv[0]["baseline_seq"].as<uint64_t>()} == at)
        return vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(mv[0]["d"].as<std::string>()),
                                             mv[0]["baseline_entries"].as<int64_t>());
    const auto row = txn.exec("SELECT encode(digest_after, 'hex') AS d, entries_after FROM vault_replication_log "
                              "WHERE vault_id = $1 AND term = $2 AND seq = $3 AND digest_after IS NOT NULL",
                              pqxx::params{vaultId, static_cast<int64_t>(at.term), static_cast<int64_t>(at.seq)});
    if (row.empty()) return std::nullopt;
    return vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(row[0]["d"].as<std::string>()),
                                         row[0]["entries_after"].as<int64_t>());
}

}

std::optional<vh::mirror::Digest> MirrorVaults::digestAt(const uint32_t vaultId, const Position at) {
    return Transactions::exec("mirror::MirrorVaults::digestAt",
                              [&](pqxx::work& txn) { return mirrorDigestAt(txn, vaultId, at); });
}

AckOutcome MirrorVaults::acknowledgeChecked(const uint32_t vaultId, const Position at, const vh::mirror::Digest& theirs) {
    AckOutcome out;
    const bool mismatch = Transactions::exec("mirror::MirrorVaults::acknowledgeChecked", [&](pqxx::work& txn) {
        const auto mv = txn.exec("SELECT acked_term, acked_seq FROM mirror_vault "
                                 "WHERE vault_id = $1 AND role = 'core' AND state <> 'starting' FOR NO KEY UPDATE",
                                 pqxx::params{vaultId});
        if (mv.empty()) return false;
        const auto ours = mirrorDigestAt(txn, vaultId, at);
        if (!ours) {
            // Pruned since it was acknowledged: a repeat of an acknowledgement already compared.
            if (!mv[0]["acked_term"].is_null() &&
                at <= Position{mv[0]["acked_term"].as<uint64_t>(), mv[0]["acked_seq"].as<uint64_t>()}) {
                out.known = out.match = true;
            }
            return false;
        }
        out.known = true;
        out.core_digest = *ours;
        out.match = *ours == theirs;
        if (!out.match) return true;
        out.recorded =
            txn.exec("UPDATE mirror_vault SET acked_term = $2, acked_seq = $3, acked_at = CURRENT_TIMESTAMP, "
                     "  updated_at = CURRENT_TIMESTAMP "
                     "WHERE vault_id = $1 AND ($2::bigint, $3::bigint) <= (term, last_seq) "
                     "  AND (acked_term IS NULL OR (acked_term, acked_seq) <= ($2::bigint, $3::bigint))",
                     pqxx::params{vaultId, static_cast<int64_t>(at.term), static_cast<int64_t>(at.seq)})
                .affected_rows() > 0;
        // The first copy is done once anything is acknowledged: its baseline has no reader left (baseline_rows NULL:
        // dropped; its position and digest stay, for a repeated acknowledgement there).
        txn.exec("DELETE FROM mirror_baseline WHERE vault_id = $1", pqxx::params{vaultId});
        txn.exec("UPDATE mirror_vault SET baseline_rows = NULL WHERE vault_id = $1", pqxx::params{vaultId});
        return false;
    });
    if (mismatch)
        (void)stop(vaultId, "diverged", "mirror_digest_mismatch",
                   {{"term", at.term}, {"seq", at.seq}, {"core_digest", out.core_digest.hex()},
                    {"core_entries", out.core_digest.entries}, {"mirror_digest", theirs.hex()},
                    {"mirror_entries", theirs.entries}});
    return out;
}

bool MirrorVaults::recordAcknowledged(const uint32_t vaultId, const Position at) {
    return Transactions::exec("mirror::MirrorVaults::recordAcknowledged", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_vault SET acked_term = $2, acked_seq = $3, acked_at = CURRENT_TIMESTAMP, "
                        "  updated_at = CURRENT_TIMESTAMP "
                        "WHERE vault_id = $1 AND role = 'mirror' "
                        "  AND (acked_term IS NULL OR (acked_term, acked_seq) <= ($2::bigint, $3::bigint))",
                        pqxx::params{vaultId, static_cast<int64_t>(at.term), static_cast<int64_t>(at.seq)})
                   .affected_rows() > 0;
    });
}

}
