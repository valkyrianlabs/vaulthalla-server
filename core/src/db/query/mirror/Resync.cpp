#include "db/query/mirror/Resync.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>

#include <string>

namespace vh::db::query::mirror {

namespace {

std::optional<std::string> resyncText(const pqxx::field_ref f) {
    return f.is_null() ? std::nullopt : std::optional<std::string>(f.as<std::string>());
}

}

bool Resync::resetMirror(pqxx::work& txn, const uint32_t vaultId, const uint32_t actorId) {
    const auto n = txn.exec("UPDATE mirror_vault SET state = 'live', stop_reason = NULL, stop_detail = NULL, "
                            "  stopped_at = NULL, copy_cursor = 0, copy_finished = FALSE, last_seq = 0, "
                            "  acked_term = NULL, acked_seq = NULL, acked_at = NULL, "
                            "  baseline_term = NULL, baseline_seq = NULL, baseline_digest = NULL, "
                            "  baseline_entries = NULL, baseline_rows = NULL, baseline_vault = NULL, "
                            "  digest = decode(repeat('00', 32), 'hex'), digest_entries = 0, "
                            "  resync_at = CURRENT_TIMESTAMP, resync_by = $2, resync_count = resync_count + 1, "
                            "  scrubbed_at = NULL, updated_at = CURRENT_TIMESTAMP "
                            "WHERE vault_id = $1 AND role = 'mirror'",
                            pqxx::params{vaultId, actorId})
                       .affected_rows();
    if (n == 0) return false;
    txn.exec("DELETE FROM mirror_entry_hash WHERE vault_id = $1", pqxx::params{vaultId});
    txn.exec("DELETE FROM mirror_dirty WHERE vault_id = $1", pqxx::params{vaultId});
    return true;
}

std::vector<Leftover> Resync::leftovers(pqxx::work& txn, const uint32_t vaultId) {
    std::vector<Leftover> out;
    const auto live = txn.exec(
        "SELECT e.id, COALESCE(f.object_uid, d.uid, s.uid)::text AS uid, "
        "  CASE WHEN f.fs_entry_id IS NOT NULL THEN 'file' WHEN d.fs_entry_id IS NOT NULL THEN 'directory' "
        "       ELSE 'symlink' END AS kind, e.path, e.name, "
        "  CASE WHEN pe.path = '/' THEN v.uid::text ELSE p.uid::text END AS parent_uid, "
        "  COALESCE(f.encryption_iv, '') AS generation, COALESCE(f.encrypted_with_key_version, 0) AS key_version, "
        "  COALESCE(f.size_bytes, 0) AS size, COALESCE(f.content_hash, '') AS content_hash, "
        "  COALESCE(s.target, '') AS target, length(e.path) - length(replace(e.path, '/', '')) AS depth "
        "FROM fs_entry e JOIN vault v ON v.id = e.vault_id "
        "LEFT JOIN files f ON f.fs_entry_id = e.id LEFT JOIN directories d ON d.fs_entry_id = e.id "
        "LEFT JOIN symlinks s ON s.fs_entry_id = e.id LEFT JOIN fs_entry pe ON pe.id = e.parent_id "
        "LEFT JOIN directories p ON p.fs_entry_id = e.parent_id "
        "WHERE e.vault_id = $1 AND e.path <> '/' AND COALESCE(f.fs_entry_id, d.fs_entry_id, s.fs_entry_id) IS NOT NULL "
        "  AND NOT vh_mirror_upload_staging(CASE WHEN f.fs_entry_id IS NOT NULL THEN e.name END) "
        "  AND NOT EXISTS (SELECT 1 FROM mirror_entry_hash h WHERE h.vault_id = $1 "
        "                  AND h.entry_uid = COALESCE(f.object_uid, d.uid, s.uid)) "
        "ORDER BY depth DESC, e.id",
        pqxx::params{vaultId});
    for (const auto row : live) {
        Leftover l;
        l.id = row["id"].as<uint32_t>();
        l.uid = row["uid"].as<std::string>();
        l.kind = row["kind"].as<std::string>();
        l.path = row["path"].as<std::string>();
        l.name = row["name"].as<std::string>();
        l.parent_uid = resyncText(row["parent_uid"]);
        l.generation = row["generation"].as<std::string>();
        l.key_version = row["key_version"].as<uint32_t>();
        l.size = row["size"].as<uint64_t>();
        l.content_hash = row["content_hash"].as<std::string>();
        l.target = row["target"].as<std::string>();
        l.depth = row["depth"].as<uint32_t>();
        out.push_back(std::move(l));
    }
    // Trash rows (not purged, with an object uid) the core's tree does not hold: after the live entries (no depth).
    for (const auto row : txn.exec("SELECT t.id, t.object_uid::text AS uid, t.path, t.backing_path, t.size_bytes "
                                   "FROM files_trashed t WHERE t.vault_id = $1 AND t.deleted_at IS NULL "
                                   "  AND t.object_uid IS NOT NULL "
                                   "  AND NOT EXISTS (SELECT 1 FROM mirror_entry_hash h WHERE h.vault_id = $1 "
                                   "                  AND h.entry_uid = t.object_uid) "
                                   "  AND NOT EXISTS (SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                   "                  WHERE e.vault_id = $1 AND f.object_uid = t.object_uid) "
                                   "ORDER BY t.id",
                                   pqxx::params{vaultId})) {
        Leftover l;
        l.id = row["id"].as<uint32_t>();
        l.uid = row["uid"].as<std::string>();
        l.kind = "file";
        l.trashed = true;
        l.path = row["path"].as<std::string>();
        const auto slash = l.path.find_last_of('/');
        l.name = slash == std::string::npos ? l.path : l.path.substr(slash + 1);
        l.size = row["size_bytes"].as<uint64_t>();
        l.backing = row["backing_path"].as<std::string>();
        out.push_back(std::move(l));
    }
    return out;
}

bool Resync::heldOpenFor(pqxx::work& txn, const uint32_t vaultId, const std::string& uid) {
    return !txn.exec("SELECT 1 FROM mirror_held WHERE vault_id = $1 AND entry_uid = $2::uuid AND state = 'open' LIMIT 1",
                     pqxx::params{vaultId, uid})
                .empty();
}

bool Resync::prepareCoreRebaseline(const uint32_t vaultId, const uint32_t peerId) {
    return Transactions::exec("mirror::Resync::prepareCoreRebaseline", [&](pqxx::work& txn) {
        if (txn.exec("UPDATE mirror_vault SET state = 'starting', updated_at = CURRENT_TIMESTAMP "
                     "WHERE vault_id = $1 AND peer_id = $2 AND role = 'core'",
                     pqxx::params{vaultId, peerId})
                .affected_rows() == 0)
            return false;
        for (const auto* table : {"vault_replication_log", "mirror_entry_hash", "mirror_baseline", "mirror_submission"})
            txn.exec(std::string("DELETE FROM ") + table + " WHERE vault_id = $1", pqxx::params{vaultId});
        return true;
    });
}

void Resync::restoreCoreRow(const uint32_t vaultId, const uint32_t peerId, const uint64_t term, const std::string& why) {
    Transactions::exec("mirror::Resync::restoreCoreRow", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO mirror_vault (vault_id, peer_id, role, term, state, stop_reason, stop_detail, stopped_at) "
                 "VALUES ($1, $2, 'core', $3, 'diverged', 'mirror_resync_failed', jsonb_build_object('why', $4::text), "
                 "        CURRENT_TIMESTAMP) "
                 "ON CONFLICT (vault_id) DO UPDATE SET state = 'diverged', stop_reason = 'mirror_resync_failed', "
                 "  stop_detail = EXCLUDED.stop_detail, stopped_at = CURRENT_TIMESTAMP "
                 "  WHERE mirror_vault.state = 'starting'",
                 pqxx::params{vaultId, peerId, static_cast<int64_t>(term), why.substr(0, 400)});
    });
}

void Resync::recordCoreResync(const uint32_t vaultId) {
    Transactions::exec("mirror::Resync::recordCoreResync", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_vault SET resync_at = CURRENT_TIMESTAMP, resync_count = resync_count + 1 "
                 "WHERE vault_id = $1 AND role = 'core'",
                 pqxx::params{vaultId});
    });
}

std::vector<uint32_t> Resync::scrubDue(const std::chrono::hours every) {
    return Transactions::exec("mirror::Resync::scrubDue", [&](pqxx::work& txn) {
        std::vector<uint32_t> out;
        for (const auto row : txn.exec("SELECT vault_id FROM mirror_vault "
                                       "WHERE state = 'live' AND (role = 'core' OR (role = 'mirror' AND copy_finished)) "
                                       "  AND (scrubbed_at IS NULL OR scrubbed_at < CURRENT_TIMESTAMP - make_interval("
                                       "       hours => $1)) ORDER BY vault_id",
                                       pqxx::params{static_cast<int>(every.count())}))
            out.push_back(row[0].as<uint32_t>());
        return out;
    });
}

ScrubFinding Resync::scrub(const uint32_t vaultId) {
    return Transactions::exec("mirror::Resync::scrub", [&](pqxx::work& txn) {
        ScrubFinding out;
        // One statement, one snapshot: the tables and the recorded hashes are read as of the same moment (each writer
        // changes both in one transaction). An entry a change made here holds dirty is this server's own until it
        // settles.
        const auto rows = txn.exec(
            "WITH t AS (SELECT entry_uid, entry_hash FROM vh_mirror_tree($1)), "
            "  h AS (SELECT entry_uid, entry_hash FROM mirror_entry_hash WHERE vault_id = $1), "
            "  d AS (SELECT COALESCE(t.entry_uid, h.entry_uid) AS uid, encode(t.entry_hash, 'hex') AS tables, "
            "              encode(h.entry_hash, 'hex') AS recorded "
            "       FROM t FULL JOIN h ON h.entry_uid = t.entry_uid "
            "       WHERE t.entry_hash IS DISTINCT FROM h.entry_hash "
            "         AND NOT EXISTS (SELECT 1 FROM mirror_dirty m WHERE m.vault_id = $1 "
            "                         AND m.entry_uid = COALESCE(t.entry_uid, h.entry_uid))) "
            "SELECT uid::text, tables, recorded, count(*) OVER () AS n FROM d ORDER BY uid LIMIT 20",
            pqxx::params{vaultId});
        for (const auto row : rows) {
            out.differences = row["n"].as<uint64_t>();
            out.first.push_back({.uid = row["uid"].as<std::string>(), .tables = resyncText(row["tables"]),
                                 .recorded = resyncText(row["recorded"])});
        }
        // The mirror's running digest is the sum of what it recorded (the core's lags its numbering: not compared).
        const auto drift = txn.exec("SELECT m.digest <> COALESCE((SELECT vh_mirror_digest(entry_hash) FROM "
                                    "  mirror_entry_hash WHERE vault_id = $1), decode(repeat('00', 32), 'hex')) "
                                    "  OR m.digest_entries <> (SELECT count(*) FROM mirror_entry_hash WHERE vault_id = $1) "
                                    "FROM mirror_vault m WHERE m.vault_id = $1 AND m.role = 'mirror' "
                                    "  AND NOT EXISTS (SELECT 1 FROM mirror_dirty WHERE vault_id = $1)",
                                    pqxx::params{vaultId});
        out.digestDrift = !drift.empty() && drift[0][0].as<bool>();
        txn.exec("UPDATE mirror_vault SET scrubbed_at = CURRENT_TIMESTAMP WHERE vault_id = $1", pqxx::params{vaultId});
        return out;
    });
}

}
