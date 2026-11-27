#include "db/query/mirror/Takeover.hpp"

#include "db/Transactions.hpp"
#include "mirror/access/Access.hpp"
#include "ops/Error.hpp"
#include "rbac/Mirrored.hpp"

#include <pqxx/pqxx>

#include <string>
#include <vector>

namespace vh::db::query::mirror {

namespace {

constexpr const char* kTakeoverColumns = R"SQL(
    id, vault_id, peer_id, from_term, term, fork_seq, encode(fork_digest, 'hex') AS fork_digest, fork_entries,
    fork_rows, pending_made_local, held, contents_missing, by_id, by_name, detail::text AS detail,
    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, EXTRACT(EPOCH FROM settled_at)::BIGINT AS settled_at,
    settled_how, old_core_outcome, old_core_changes
)SQL";

Takeover takeoverFrom(const pqxx::row_ref row) {
    Takeover t;
    t.id = row["id"].as<uint64_t>();
    t.vault_id = row["vault_id"].as<uint32_t>();
    t.peer_id = row["peer_id"].as<uint32_t>();
    t.from_term = row["from_term"].as<uint64_t>();
    t.term = row["term"].as<uint64_t>();
    t.fork_seq = row["fork_seq"].as<uint64_t>();
    t.fork_digest = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(row["fork_digest"].as<std::string>()),
                                                  row["fork_entries"].as<int64_t>());
    t.fork_rows = row["fork_rows"].as<uint64_t>();
    t.pending_made_local = row["pending_made_local"].as<uint32_t>();
    t.held = row["held"].as<uint32_t>();
    t.contents_missing = row["contents_missing"].as<uint32_t>();
    if (!row["by_id"].is_null()) t.by_id = row["by_id"].as<uint32_t>();
    if (!row["by_name"].is_null()) t.by_name = row["by_name"].as<std::string>();
    t.detail = row["detail"].is_null() ? nlohmann::json::object() : nlohmann::json::parse(row["detail"].as<std::string>());
    t.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    if (!row["settled_at"].is_null()) t.settled_at = static_cast<std::time_t>(row["settled_at"].as<int64_t>());
    if (!row["settled_how"].is_null()) t.settled_how = row["settled_how"].as<std::string>();
    if (!row["old_core_outcome"].is_null()) t.old_core_outcome = row["old_core_outcome"].as<std::string>();
    if (!row["old_core_changes"].is_null()) t.old_core_changes = row["old_core_changes"].as<uint32_t>();
    return t;
}

std::optional<Takeover> takeoverOne(pqxx::work& txn, const std::string& where, const pqxx::params& params) {
    const auto r = txn.exec(std::string("SELECT ") + kTakeoverColumns + " FROM mirror_takeover " + where, params);
    if (r.empty()) return std::nullopt;
    return takeoverFrom(r[0]);
}

}

Takeovers::Taken Takeovers::take(const uint32_t vaultId, const std::optional<uint32_t> byId, const std::string& byName,
                                 const uint32_t contentsMissing) {
    auto out = Transactions::exec("mirror::Takeovers::take", [&](pqxx::work& txn) {
        Taken taken;
        const auto mv = MirrorVaults::get(txn, vaultId, true);
        if (!mv || mv->role != "mirror")
            throw vh::ops::Refused("mirror_not_mirror", "this server does not hold the vault as another server's mirror");
        if (!mv->copy_finished)
            throw vh::ops::Refused("mirror_first_copy", "the first copy of the vault has not finished here: it holds no "
                                                        "whole tree to be the core of");
        if (mv->state == "diverged")
            throw vh::ops::Refused("mirror_diverged", "this copy no longer matches its core: start it over (vh mirror "
                                                      "resync) while the core answers, or detach it");
        if (mv->state == "starting") throw vh::ops::Conflict("the vault's mirror is starting; try again");
        const pqxx::params v{vaultId};

        // A switch still open here (prepared or preparing) ends: the core that prepared it is not coming back.
        txn.exec("UPDATE mirror_switch SET phase = 'abandoned', reason = 'mirror_taken_over', "
                 "  detail = jsonb_build_object('why', 'this server took over as the core'), "
                 "  ended_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP "
                 "WHERE vault_id = $1 AND ended_at IS NULL",
                 v);

        // ---- the record and the fork base (the tree as the old core last confirmed it)
        const auto counts = txn.exec(
            "SELECT (SELECT count(*) FROM mirror_pending WHERE vault_id = $1) AS pending, "
            "  (SELECT count(*) FROM mirror_held WHERE vault_id = $1 AND state = 'open') AS held",
            v);
        const auto id = txn.exec("INSERT INTO mirror_takeover (vault_id, peer_id, from_term, term, fork_seq, fork_digest, "
                                 "  fork_entries, pending_made_local, held, contents_missing, by_id, by_name) "
                                 "VALUES ($1, $2, $3::bigint, $3::bigint + 1, $4, decode($5, 'hex'), $6, $7, $8, $9, $10, $11) "
                                 "RETURNING id",
                                 pqxx::params{vaultId, mv->peer_id, static_cast<int64_t>(mv->term),
                                              static_cast<int64_t>(mv->last_seq), mv->digest.hex(), mv->digest.entries,
                                              counts[0]["pending"].as<int64_t>(), counts[0]["held"].as<int64_t>(),
                                              static_cast<int64_t>(contentsMissing),
                                              byId ? std::optional<int64_t>(*byId) : std::nullopt,
                                              byName.substr(0, 255)})
                            .one_field()
                            .as<int64_t>();
        txn.exec("WITH t AS (SELECT * FROM vh_mirror_tree_states($1)), "
                 "  b AS (SELECT t.entry_uid, t.trashed, t.depth, t.state FROM t "
                 "        WHERE NOT EXISTS (SELECT 1 FROM mirror_dirty d WHERE d.vault_id = $1 "
                 "                          AND d.entry_uid = t.entry_uid) "
                 "        UNION ALL "
                 "        SELECT d.entry_uid, d.confirmed_kind = 'trashed', COALESCE(t.depth, 0), d.confirmed "
                 "        FROM mirror_dirty d LEFT JOIN t ON t.entry_uid = d.entry_uid "
                 "        WHERE d.vault_id = $1 AND d.confirmed_kind <> 'none') "
                 "INSERT INTO mirror_fork_base (takeover_id, ord, entry_uid, state, entry_hash) "
                 "SELECT $2, row_number() OVER (ORDER BY b.trashed, b.depth, b.entry_uid), b.entry_uid, b.state, "
                 "       vh_mirror_state_hash(b.state) FROM b",
                 pqxx::params{vaultId, id});
        const auto base = txn.exec("SELECT encode(COALESCE(vh_mirror_digest(entry_hash), decode(repeat('00', 32), 'hex')), "
                                   "  'hex') AS d, count(*) AS n FROM mirror_fork_base WHERE takeover_id = $1",
                                   pqxx::params{id});
        const auto baseDigest = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(base[0]["d"].as<std::string>()),
                                                              base[0]["n"].as<int64_t>());
        taken.fork_base_matches = baseDigest == mv->digest;
        txn.exec("UPDATE mirror_takeover SET fork_rows = $2, detail = jsonb_build_object('fork_base_matches', $3::boolean, "
                 "  'fork_base_digest', $4::text, 'was', $5::text) WHERE id = $1",
                 pqxx::params{id, base[0]["n"].as<int64_t>(), taken.fork_base_matches, baseDigest.hex(), mv->state});

        // When the person's pending changes are in the tree now, the old core's tree at the fork point is not this
        // server's at (term + 1, 0): a baseline of it is kept, so an old core that committed nothing since copies it
        // over its own entries (the resync copy) instead of following from there.
        const bool baseline = counts[0]["pending"].as<int64_t>() > 0;

        // ---- the person's changes: ordinary local changes of the vault now (held ones stay listed)
        for (const auto row : txn.exec("SELECT id FROM mirror_pending WHERE vault_id = $1 ORDER BY id", v))
            taken.pending_ids.push_back(row[0].as<uint64_t>());
        txn.exec("DELETE FROM mirror_pending WHERE vault_id = $1", v);
        txn.exec("DELETE FROM mirror_dirty WHERE vault_id = $1", v);

        // ---- the core in term + 1: its entry hashes and digest are its tree as it is now
        txn.exec("DELETE FROM mirror_entry_hash WHERE vault_id = $1", v);
        txn.exec("INSERT INTO mirror_entry_hash (vault_id, entry_uid, entry_hash) "
                 "SELECT $1, entry_uid, entry_hash FROM vh_mirror_tree($1)",
                 v);
        for (const auto* table : {"vault_replication_log", "mirror_baseline", "mirror_submission"})
            txn.exec(std::string("DELETE FROM ") + table + " WHERE vault_id = $1", v);
        if (baseline)
            txn.exec("INSERT INTO mirror_baseline (vault_id, ord, entry_uid, state, entry_hash) "
                     "SELECT $1, row_number() OVER (ORDER BY t.trashed, t.depth, t.entry_uid), t.entry_uid, t.state, "
                     "       vh_mirror_state_hash(t.state) FROM vh_mirror_tree_states($1) t",
                     v);
        txn.exec("UPDATE mirror_vault m SET role = 'core', term = m.term + 1, last_seq = 0, acked_term = NULL, "
                 "  acked_seq = NULL, acked_at = NULL, pruned_term = 0, pruned_seq = 0, numbered_at = NULL, "
                 "  digest = d.digest, digest_entries = d.entries, "
                 "  baseline_term = m.term + 1, baseline_seq = 0, baseline_digest = d.digest, baseline_entries = d.entries, "
                 "  baseline_rows = (SELECT NULLIF(count(*), 0) FROM mirror_baseline WHERE vault_id = $1), "
                 "  baseline_vault = vh_mirror_vault_state($1), granted_role_name = NULL, granted_files_permissions = NULL, granted_directories_permissions = NULL, "
                 "  granted_sync_permissions = NULL, granted_roles_permissions = NULL, granted_by_node = NULL, "
                 "  granted_at = NULL, state = 'live', stop_reason = NULL, stop_detail = NULL, stopped_at = NULL, "
                 "  scrubbed_at = NULL, updated_at = CURRENT_TIMESTAMP "
                 "FROM (SELECT COALESCE(vh_mirror_digest(entry_hash), decode(repeat('00', 32), 'hex')) AS digest, "
                 "             count(*) AS entries FROM mirror_entry_hash WHERE vault_id = $1) d "
                 "WHERE m.vault_id = $1",
                 v);
        // The start's offer changes side, so ending the mirror later is told from this server, its core now.
        txn.exec("UPDATE mirror_offer SET side = CASE side WHEN 'core' THEN 'mirror' ELSE 'core' END, "
                 "  updated_at = CURRENT_TIMESTAMP "
                 "WHERE id = (SELECT o.id FROM mirror_offer o JOIN vault vv ON vv.uid = o.vault_uid "
                 "            WHERE vv.id = $1 AND o.state = 'started' ORDER BY o.id DESC LIMIT 1)",
                 v);
        taken.takeover = *takeoverOne(txn, "WHERE id = $1", pqxx::params{id});
        return taken;
    });
    vh::rbac::mirrored::reload();
    vh::mirror::access::reload();
    return out;
}

std::optional<Takeover> Takeovers::get(const uint64_t id) {
    return Transactions::exec("mirror::Takeovers::get", [&](pqxx::work& txn) {
        return takeoverOne(txn, "WHERE id = $1", pqxx::params{static_cast<int64_t>(id)});
    });
}

std::optional<Takeover> Takeovers::openOf(const uint32_t vaultId) {
    return Transactions::exec("mirror::Takeovers::openOf", [&](pqxx::work& txn) {
        return takeoverOne(txn, "WHERE vault_id = $1 AND settled_at IS NULL", pqxx::params{vaultId});
    });
}

std::optional<Takeover> Takeovers::latestOf(const uint32_t vaultId) {
    return Transactions::exec("mirror::Takeovers::latestOf", [&](pqxx::work& txn) {
        return takeoverOne(txn, "WHERE vault_id = $1 ORDER BY id DESC LIMIT 1", pqxx::params{vaultId});
    });
}

std::vector<nlohmann::json> Takeovers::forkBase(const uint64_t id, const uint64_t after, const std::size_t limit) {
    return Transactions::exec("mirror::Takeovers::forkBase", [&](pqxx::work& txn) {
        std::vector<nlohmann::json> out;
        for (const auto row : txn.exec("SELECT state::text FROM mirror_fork_base WHERE takeover_id = $1 AND ord > $2 "
                                       "ORDER BY ord LIMIT $3",
                                       pqxx::params{static_cast<int64_t>(id), static_cast<int64_t>(after),
                                                    static_cast<int64_t>(limit)}))
            out.push_back(nlohmann::json::parse(row[0].as<std::string>()));
        return out;
    });
}

std::vector<Takeover> Takeovers::untold() {
    return Transactions::exec("mirror::Takeovers::untold", [&](pqxx::work& txn) {
        std::vector<Takeover> out;
        for (const auto row : txn.exec(std::string("SELECT ") + kTakeoverColumns +
                                       " FROM mirror_takeover WHERE settled_at IS NULL AND old_core_outcome IS NULL "
                                       "ORDER BY id"))
            out.push_back(takeoverFrom(row));
        return out;
    });
}

void Takeovers::recordOutcome(const uint64_t id, const std::string& outcome, const std::optional<uint32_t> changes) {
    if (outcome != "following" && outcome != "rejoining" && outcome != "forced")
        throw vh::ops::Invalid("an old core answers following, rejoining or forced");
    const bool republish = Transactions::exec("mirror::Takeovers::recordOutcome", [&](pqxx::work& txn) {
        const auto t = takeoverOne(txn, "WHERE id = $1 FOR UPDATE", pqxx::params{static_cast<int64_t>(id)});
        if (!t || !t->open()) return false;
        txn.exec("UPDATE mirror_takeover SET old_core_outcome = $2, old_core_changes = $3, told_at = CURRENT_TIMESTAMP "
                 "WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), outcome,
                              changes ? std::optional<int64_t>(*changes) : std::nullopt});
        if (outcome == "following") {
            txn.exec("UPDATE mirror_takeover SET settled_at = CURRENT_TIMESTAMP, settled_how = 'returned' WHERE id = $1",
                     pqxx::params{static_cast<int64_t>(id)});
            txn.exec("DELETE FROM mirror_fork_base WHERE takeover_id = $1", pqxx::params{static_cast<int64_t>(id)});
            return false;
        }
        if (outcome == "forced") {
            txn.exec("UPDATE mirror_vault SET state = 'forked', updated_at = CURRENT_TIMESTAMP "
                     "WHERE vault_id = $1 AND role = 'core'",
                     pqxx::params{t->vault_id});
            return true;
        }
        return false;
    });
    if (republish) vh::mirror::access::reload();
}

bool Takeovers::settle(const uint64_t id, const std::string& how, const nlohmann::json& detail) {
    if (how != "switched" && how != "returned" && how != "merged" && how != "ended")
        throw vh::ops::Invalid("a take over settles as switched, returned, merged or ended");
    return Transactions::exec("mirror::Takeovers::settle", [&](pqxx::work& txn) {
        const auto n = txn.exec("UPDATE mirror_takeover SET settled_at = CURRENT_TIMESTAMP, settled_how = $2, "
                                "  detail = COALESCE(detail, '{}'::jsonb) || $3::jsonb "
                                "WHERE id = $1 AND settled_at IS NULL",
                                pqxx::params{static_cast<int64_t>(id), how, detail.dump()})
                           .affected_rows();
        if (n == 0) return false;
        txn.exec("DELETE FROM mirror_fork_base WHERE takeover_id = $1", pqxx::params{static_cast<int64_t>(id)});
        return true;
    });
}

}
