#include "db/query/mirror/Detach.hpp"

#include "db/Transactions.hpp"
#include "ops/Error.hpp"

#include <pqxx/pqxx>

namespace vh::db::query::mirror {

namespace mirror_detach_detail {

constexpr auto kRecordColumns =
    "id, side, vault_id, vault_uid::text AS vault_uid, peer_id, fork_term, fork_seq, digest_matched, was_state, missing, "
    "owner_id, detached_by, EXTRACT(EPOCH FROM detached_at)::BIGINT AS detached_at, "
    "EXTRACT(EPOCH FROM rekeyed_at)::BIGINT AS rekeyed_at";

DetachRecord recordFrom(const pqxx::row_ref row) {
    DetachRecord r;
    r.id = row["id"].as<uint32_t>();
    r.side = row["side"].as<std::string>();
    r.vault_id = row["vault_id"].as<uint32_t>();
    r.vault_uid = row["vault_uid"].as<std::string>();
    r.peer_id = row["peer_id"].as<uint32_t>();
    r.fork = {row["fork_term"].as<uint64_t>(), row["fork_seq"].as<uint64_t>()};
    if (!row["digest_matched"].is_null()) r.digest_matched = row["digest_matched"].as<bool>();
    if (!row["was_state"].is_null()) r.was_state = row["was_state"].as<std::string>();
    r.missing = row["missing"].as<uint64_t>();
    if (!row["owner_id"].is_null()) r.owner_id = row["owner_id"].as<uint32_t>();
    if (!row["detached_by"].is_null()) r.detached_by = row["detached_by"].as<uint32_t>();
    r.detached_at = static_cast<std::time_t>(row["detached_at"].as<int64_t>());
    if (!row["rekeyed_at"].is_null()) r.rekeyed_at = static_cast<std::time_t>(row["rekeyed_at"].as<int64_t>());
    return r;
}

// A live file whose current generation a content row still expects: its contents are not here.
constexpr auto kMissingFrom =
    " FROM mirror_content_pending p "
    " JOIN files f ON f.object_uid = p.object_uid AND COALESCE(f.encryption_iv, '') = p.generation "
    " JOIN fs_entry e ON e.id = f.fs_entry_id AND e.vault_id = p.vault_id "
    "WHERE p.vault_id = $1";

}

std::vector<MissingFile> MirrorDetach::missing(const uint32_t vaultId) {
    using namespace mirror_detach_detail;
    return Transactions::exec("mirror::MirrorDetach::missing", [&](pqxx::work& txn) {
        std::vector<MissingFile> out;
        for (const auto row : txn.exec(std::string("SELECT e.id, p.object_uid::text, e.path, COALESCE(f.size_bytes, 0), "
                                                   "p.state, p.last_error") +
                                           kMissingFrom + " ORDER BY e.path",
                                       pqxx::params{vaultId})) {
            MissingFile m;
            m.file_id = row[0].as<uint32_t>();
            m.uid = row[1].as<std::string>();
            m.path = row[2].as<std::string>();
            m.size_bytes = row[3].as<uint64_t>();
            m.state = row[4].as<std::string>();
            if (!row[5].is_null()) m.last_error = row[5].as<std::string>();
            out.push_back(std::move(m));
        }
        return out;
    });
}

uint64_t MirrorDetach::countMissing(const uint32_t vaultId) {
    using namespace mirror_detach_detail;
    return Transactions::exec("mirror::MirrorDetach::countMissing", [&](pqxx::work& txn) {
        return txn.exec(std::string("SELECT count(*)") + kMissingFrom, pqxx::params{vaultId}).one_field_ref().as<uint64_t>();
    });
}

DetachOutcome MirrorDetach::detach(const DetachInput& in) {
    using namespace mirror_detach_detail;
    return Transactions::exec("mirror::MirrorDetach::detach", [&](pqxx::work& txn) {
        DetachOutcome out;
        const auto row = MirrorVaults::get(txn, in.vault_id, true);
        if (!row || (row->role != "mirror" && row->role != "orphaned"))
            throw vh::ops::Conflict("vault " + std::to_string(in.vault_id) + " is not held here as another server's copy");
        out.was = *row;
        const auto vault = txn.exec("SELECT uid::text, owner_id FROM vault WHERE id = $1 FOR UPDATE",
                                    pqxx::params{in.vault_id});
        if (vault.empty()) throw vh::ops::NotFound("no vault with ID " + std::to_string(in.vault_id));
        const auto vaultUid = vault[0][0].as<std::string>();
        out.previous_owner = vault[0][1].as<uint32_t>();

        // Contents that never arrived: the entry stays, its row says so for good (an open fails, the list is exact).
        out.missing = txn.exec("UPDATE mirror_content_pending p SET state = 'missing', "
                               "  last_error = 'the vault was detached before these contents arrived from its core' "
                               "FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                               "WHERE p.vault_id = $1 AND e.vault_id = p.vault_id AND f.object_uid = p.object_uid "
                               "  AND COALESCE(f.encryption_iv, '') = p.generation",
                               pqxx::params{in.vault_id})
                          .affected_rows();
        txn.exec("DELETE FROM mirror_content_pending WHERE vault_id = $1 AND state <> 'missing'", pqxx::params{in.vault_id});

        // Pending changes: ordinary local changes now, or (a write the file no longer holds) the person's held change.
        for (const auto& [pendingId, held] : in.changes.held) {
            Pending::remove(txn, pendingId);
            out.held.emplace_back(pendingId, Pending::hold(txn, held));
        }
        for (const auto pendingId : in.changes.dropped) {
            Pending::remove(txn, pendingId);
            out.dropped.push_back(pendingId);
        }

        // The linked server's role on the vault goes with the row (its grant) and any assignment naming it; the owner
        // is a person of this server now.
        txn.exec("DELETE FROM vault_role_assignments WHERE vault_id = $1 AND subject_type = 'peer'", pqxx::params{in.vault_id});
        txn.exec("UPDATE vault SET owner_id = $2 WHERE id = $1", pqxx::params{in.vault_id, in.owner_id});

        // The mirror's offer of the vault ends: told to the core when it is next reachable (unless the link is gone).
        txn.exec("UPDATE mirror_offer SET state = 'detached', notify = $3, reason = 'detached_by_mirror', "
                 "  finished_at = COALESCE(finished_at, CURRENT_TIMESTAMP), updated_at = CURRENT_TIMESTAMP "
                 "WHERE side = 'mirror' AND vault_uid = $1::uuid AND peer_id = $2 "
                 "  AND state IN ('installed', 'started', 'orphaned')",
                 pqxx::params{vaultUid, row->peer_id, in.tell_core});

        std::optional<bool> matched;
        if (row->state == "diverged") matched = false;
        else if (row->acked) matched = true;
        const auto rec = txn.exec(std::string("INSERT INTO mirror_detached (side, vault_id, vault_uid, peer_id, fork_term, "
                                              "  fork_seq, digest_matched, was_state, missing, owner_id, detached_by) "
                                              "VALUES ('mirror', $1, $2::uuid, $3, $4, $5, $6, $7, $8, $9, $10) RETURNING ") +
                                      kRecordColumns,
                                  pqxx::params{in.vault_id, vaultUid, row->peer_id, static_cast<int64_t>(row->term),
                                               static_cast<int64_t>(row->last_seq), matched,
                                               row->role == "orphaned" ? std::string("orphaned") : row->state,
                                               static_cast<int64_t>(out.missing), in.owner_id, in.actor_id});
        out.record = recordFrom(rec.one_row_ref());

        // The row and what hangs off it (log, entry hashes, baseline, submissions, the rest of pending and dirty).
        (void)MirrorVaults::remove(txn, in.vault_id);
        return out;
    });
}

DetachRecord MirrorDetach::recordCore(const uint32_t vaultId, const uint32_t peerId, const Position fork,
                                      const uint64_t missing) {
    using namespace mirror_detach_detail;
    return Transactions::exec("mirror::MirrorDetach::recordCore", [&](pqxx::work& txn) {
        const auto existing = txn.exec(std::string("SELECT ") + kRecordColumns +
                                           " FROM mirror_detached WHERE side = 'core' AND vault_id = $1 AND peer_id = $2 "
                                           "  AND rekeyed_at IS NULL ORDER BY id DESC LIMIT 1",
                                       pqxx::params{vaultId, peerId});
        if (!existing.empty()) return recordFrom(existing[0]);
        return recordFrom(txn.exec(std::string("INSERT INTO mirror_detached (side, vault_id, vault_uid, peer_id, fork_term, "
                                               "  fork_seq, missing) "
                                               "SELECT 'core', id, uid, $2, $3, $4, $5 FROM vault WHERE id = $1 RETURNING ") +
                                       kRecordColumns,
                                   pqxx::params{vaultId, peerId, static_cast<int64_t>(fork.term),
                                                static_cast<int64_t>(fork.seq), static_cast<int64_t>(missing)})
                              .one_row_ref());
    });
}

std::optional<DetachRecord> MirrorDetach::forVault(const uint32_t vaultId) {
    using namespace mirror_detach_detail;
    return Transactions::exec("mirror::MirrorDetach::forVault", [&](pqxx::work& txn) -> std::optional<DetachRecord> {
        const auto res = txn.exec(std::string("SELECT ") + kRecordColumns +
                                      " FROM mirror_detached WHERE vault_id = $1 AND rekeyed_at IS NULL "
                                      "ORDER BY id DESC LIMIT 1",
                                  pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return recordFrom(res[0]);
    });
}

std::optional<DetachRecord> MirrorDetach::between(const std::string& vaultUuid, const uint32_t peerId) {
    using namespace mirror_detach_detail;
    return Transactions::exec("mirror::MirrorDetach::between", [&](pqxx::work& txn) -> std::optional<DetachRecord> {
        const auto res = txn.exec(std::string("SELECT ") + kRecordColumns +
                                      " FROM mirror_detached WHERE vault_uid = $1::uuid AND peer_id = $2 "
                                      "  AND rekeyed_at IS NULL ORDER BY id DESC LIMIT 1",
                                  pqxx::params{vaultUuid, peerId});
        if (res.empty()) return std::nullopt;
        return recordFrom(res[0]);
    });
}

std::vector<DetachRecord> MirrorDetach::list() {
    using namespace mirror_detach_detail;
    return Transactions::exec("mirror::MirrorDetach::list", [&](pqxx::work& txn) {
        std::vector<DetachRecord> out;
        for (const auto row : txn.exec(std::string("SELECT ") + kRecordColumns + " FROM mirror_detached ORDER BY id"))
            out.push_back(recordFrom(row));
        return out;
    });
}

}
