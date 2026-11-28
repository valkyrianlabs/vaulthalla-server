#include "db/query/mirror/Relink.hpp"

#include "db/Transactions.hpp"
#include "ops/Error.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <string>

namespace vh::db::query::mirror {

namespace relink_db_detail {

std::optional<std::string> textOr(const pqxx::field_ref f) {
    return f.is_null() ? std::nullopt : std::optional<std::string>(f.as<std::string>());
}

std::optional<vh::mirror::Digest> digestOr(const pqxx::field_ref hex, const pqxx::field_ref entries) {
    if (hex.is_null()) return std::nullopt;
    return vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(hex.as<std::string>()),
                                         entries.is_null() ? 0 : entries.as<int64_t>());
}

constexpr auto kRelinkColumns =
    "id, relink_uid::text AS relink_uid, vault_id, peer_id, side, phase, mode, core, default_choice, role, term, "
    "this_status, theirs_status, encode(this_digest, 'hex') AS this_digest, this_entries, "
    "encode(theirs_digest, 'hex') AS theirs_digest, theirs_entries, summary::text AS summary, by_node, by_id, by_name, "
    "error, EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, EXTRACT(EPOCH FROM updated_at)::BIGINT AS updated_at, "
    "EXTRACT(EPOCH FROM applied_at)::BIGINT AS applied_at, EXTRACT(EPOCH FROM finished_at)::BIGINT AS finished_at";

Relink relinkFrom(const pqxx::row_ref row) {
    Relink r;
    r.id = row["id"].as<uint64_t>();
    r.relink_uid = row["relink_uid"].as<std::string>();
    r.vault_id = row["vault_id"].as<uint32_t>();
    r.peer_id = row["peer_id"].as<uint32_t>();
    r.side = row["side"].as<std::string>();
    r.phase = row["phase"].as<std::string>();
    r.mode = row["mode"].as<std::string>();
    r.core = row["core"].as<std::string>();
    r.default_choice = textOr(row["default_choice"]);
    r.role = textOr(row["role"]);
    if (!row["term"].is_null()) r.term = row["term"].as<uint64_t>();
    r.this_status = textOr(row["this_status"]);
    r.theirs_status = textOr(row["theirs_status"]);
    r.this_digest = digestOr(row["this_digest"], row["this_entries"]);
    r.theirs_digest = digestOr(row["theirs_digest"], row["theirs_entries"]);
    r.summary = nlohmann::json::parse(row["summary"].as<std::string>(), nullptr, false);
    if (r.summary.is_discarded()) r.summary = nlohmann::json::object();
    r.by_node = textOr(row["by_node"]);
    if (!row["by_id"].is_null()) r.by_id = row["by_id"].as<uint32_t>();
    r.by_name = textOr(row["by_name"]);
    r.error = textOr(row["error"]);
    r.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    r.updated_at = static_cast<std::time_t>(row["updated_at"].as<int64_t>());
    if (!row["applied_at"].is_null()) r.applied_at = static_cast<std::time_t>(row["applied_at"].as<int64_t>());
    if (!row["finished_at"].is_null()) r.finished_at = static_cast<std::time_t>(row["finished_at"].as<int64_t>());
    return r;
}

std::optional<Relink> relinkOne(pqxx::work& txn, const std::string& where, const pqxx::params& params) {
    const auto res = txn.exec(std::string("SELECT ") + kRelinkColumns + " FROM mirror_relink " + where, params);
    if (res.empty()) return std::nullopt;
    return relinkFrom(res[0]);
}

nlohmann::json jsonOr(const pqxx::field_ref f) {
    if (f.is_null()) return nullptr;
    auto j = nlohmann::json::parse(f.as<std::string>(), nullptr, false);
    return j.is_discarded() ? nlohmann::json(nullptr) : j;
}

constexpr auto kEntryColumns = "entry_uid::text AS uid, kind, array_to_json(aspects)::text AS aspects, path, "
                               "this_state::text AS this_state, theirs_state::text AS theirs_state, choice, request_id, "
                               "outcome, outcome_note";

RelinkEntry entryFrom(const pqxx::row_ref row) {
    RelinkEntry e;
    e.uid = row["uid"].as<std::string>();
    e.kind = row["kind"].as<std::string>();
    const auto aspects = jsonOr(row["aspects"]);
    if (aspects.is_array())
        for (const auto& a : aspects)
            if (a.is_string()) e.aspects.push_back(a.get<std::string>());
    e.path = row["path"].as<std::string>();
    e.this_state = jsonOr(row["this_state"]);
    e.theirs_state = jsonOr(row["theirs_state"]);
    e.choice = textOr(row["choice"]);
    e.request_id = textOr(row["request_id"]);
    e.outcome = textOr(row["outcome"]);
    e.outcome_note = textOr(row["outcome_note"]);
    return e;
}

std::map<std::string, std::string> hashesOf(const pqxx::result& res) {
    std::map<std::string, std::string> out;
    for (const auto row : res) out[row[0].as<std::string>()] = row[1].as<std::string>();
    return out;
}

// A core's recorded hashes, every entry changed after `p` taken back to the state its first change since replaced
// (an entry created since has none).
std::map<std::string, std::string> overlaid(pqxx::work& txn, const uint32_t vaultId, const Position p) {
    return hashesOf(txn.exec(
        "WITH after AS (SELECT DISTINCT ON (entry_uid) entry_uid, prev_hash FROM vault_replication_log "
        "               WHERE vault_id = $1 AND entry_uid IS NOT NULL "
        "                 AND (seq IS NULL OR (term, seq) > ($2::bigint, $3::bigint)) "
        "               ORDER BY entry_uid, term, seq NULLS LAST, id) "
        "SELECT h.entry_uid::text, encode(h.entry_hash, 'hex') FROM mirror_entry_hash h "
        "WHERE h.vault_id = $1 AND NOT EXISTS (SELECT 1 FROM after a WHERE a.entry_uid = h.entry_uid) "
        "UNION ALL SELECT entry_uid::text, encode(prev_hash, 'hex') FROM after WHERE prev_hash IS NOT NULL",
        pqxx::params{vaultId, static_cast<int64_t>(p.term), static_cast<int64_t>(p.seq)}));
}

RelinkBase baseIn(pqxx::work& txn, const uint32_t vaultId, const std::optional<Position> since) {
    RelinkBase out;
    const auto row = MirrorVaults::get(txn, vaultId, false);
    if (!row) {
        const auto mark = txn.exec("SELECT term, seq FROM mirror_base_mark WHERE vault_id = $1", pqxx::params{vaultId});
        if (mark.empty()) return out;
        out.available = true;
        out.source = "kept";
        out.at = Position{mark[0][0].as<uint64_t>(), mark[0][1].as<uint64_t>()};
        out.hashes = hashesOf(txn.exec("SELECT entry_uid::text, encode(entry_hash, 'hex') FROM mirror_base "
                                       "WHERE vault_id = $1",
                                       pqxx::params{vaultId}));
        return out;
    }
    // An open take over: the tree as the old core last confirmed it (its fork base).
    const auto t = txn.exec("SELECT t.id, t.from_term, t.fork_seq FROM mirror_takeover t WHERE t.vault_id = $1 "
                            "  AND t.settled_at IS NULL AND EXISTS (SELECT 1 FROM mirror_fork_base b "
                            "  WHERE b.takeover_id = t.id) ORDER BY t.id DESC LIMIT 1",
                            pqxx::params{vaultId});
    if (!t.empty()) {
        out.available = true;
        out.source = "fork_base";
        out.at = Position{t[0][1].as<uint64_t>(), t[0][2].as<uint64_t>()};
        out.hashes = hashesOf(txn.exec("SELECT entry_uid::text, encode(entry_hash, 'hex') FROM mirror_fork_base "
                                       "WHERE takeover_id = $1",
                                       pqxx::params{t[0][0].as<int64_t>()}));
        return out;
    }
    if (row->role == "core") {
        std::optional<Position> p;
        const auto rj = txn.exec("SELECT fork_term, fork_seq FROM mirror_rejoin WHERE vault_id = $1 "
                                 "  AND phase IN ('draining', 'rejoining', 'forked') ORDER BY id DESC LIMIT 1",
                                 pqxx::params{vaultId});
        if (!rj.empty()) {
            p = Position{rj[0][0].as<uint64_t>(), rj[0][1].as<uint64_t>()};
            out.source = "rejoin";
        } else if (since) {
            p = since;
            out.source = "agreed";
        } else if (row->acked) {
            p = row->acked;
            out.source = "acknowledged";
        }
        // The log no longer holds what changed after it: nothing can be said.
        if (!p || *p < row->pruned) return RelinkBase{};
        out.available = true;
        out.at = p;
        out.hashes = overlaid(txn, vaultId, *p);
        return out;
    }
    if (row->role == "orphaned" || row->copy_finished) {
        out.available = true;
        out.source = "entry_hashes";
        out.at = row->position();
        out.hashes = hashesOf(txn.exec("SELECT entry_uid::text, encode(entry_hash, 'hex') FROM mirror_entry_hash "
                                       "WHERE vault_id = $1",
                                       pqxx::params{vaultId}));
    }
    return out;
}

}

std::vector<RelinkTreeRow> Relinks::tree(const uint32_t vaultId) {
    return Transactions::exec("mirror::Relinks::tree", [&](pqxx::work& txn) {
        std::vector<RelinkTreeRow> out;
        const auto res = txn.exec(
            "WITH t AS (SELECT s.entry_uid, s.trashed, s.state FROM vh_mirror_tree_states($1) s), "
            "  p AS (SELECT COALESCE(f.object_uid, d.uid, l.uid) AS uid, e.path, COALESCE(f.encryption_iv, '') AS gen "
            "        FROM fs_entry e LEFT JOIN files f ON f.fs_entry_id = e.id "
            "        LEFT JOIN directories d ON d.fs_entry_id = e.id LEFT JOIN symlinks l ON l.fs_entry_id = e.id "
            "        WHERE e.vault_id = $1 AND e.path <> '/') "
            "SELECT t.entry_uid::text AS uid, t.trashed, t.state::text AS state, "
            "  encode(vh_mirror_state_hash(t.state), 'hex') AS hash, "
            "  CASE WHEN t.trashed THEN COALESCE(t.state -> 'trashed' ->> 'path', '') ELSE COALESCE(p.path, '') END AS path, "
            "  CASE WHEN t.trashed THEN '' ELSE COALESCE(p.gen, '') END AS gen "
            "FROM t LEFT JOIN p ON p.uid = t.entry_uid AND NOT t.trashed ORDER BY t.entry_uid",
            pqxx::params{vaultId});
        out.reserve(res.size());
        for (const auto row : res) {
            RelinkTreeRow r;
            r.uid = row["uid"].as<std::string>();
            r.trashed = row["trashed"].as<bool>();
            r.state = nlohmann::json::parse(row["state"].as<std::string>());
            r.hash = row["hash"].as<std::string>();
            r.path = row["path"].as<std::string>();
            r.generation = row["gen"].as<std::string>();
            out.push_back(std::move(r));
        }
        return out;
    });
}

vh::mirror::Digest Relinks::digest(const uint32_t vaultId) { return Digests::recompute(vaultId); }

RelinkBase Relinks::base(const uint32_t vaultId, const std::optional<Position> since) {
    return Transactions::exec("mirror::Relinks::base",
                              [&](pqxx::work& txn) { return relink_db_detail::baseIn(txn, vaultId, since); });
}

void Relinks::keepBase(pqxx::work& txn, const uint32_t vaultId) {
    const auto row = MirrorVaults::get(txn, vaultId, false);
    if (!row) return;
    const auto b = relink_db_detail::baseIn(txn, vaultId, std::nullopt);
    if (!b.available || !b.at) return;
    const pqxx::params v{vaultId};
    txn.exec("DELETE FROM mirror_base WHERE vault_id = $1", v);
    const std::string source = b.source == "fork_base" ? "fork_base" : row->role == "core" ? "acknowledged" : "entry_hashes";
    txn.exec("INSERT INTO mirror_base_mark (vault_id, peer_id, role, term, seq, entries, source) "
             "VALUES ($1, $2, $3, $4, $5, $6, $7) "
             "ON CONFLICT (vault_id) DO UPDATE SET peer_id = EXCLUDED.peer_id, role = EXCLUDED.role, term = EXCLUDED.term, "
             "  seq = EXCLUDED.seq, entries = EXCLUDED.entries, source = EXCLUDED.source, taken_at = CURRENT_TIMESTAMP",
             pqxx::params{vaultId, row->peer_id, row->role, static_cast<int64_t>(b.at->term),
                          static_cast<int64_t>(b.at->seq), static_cast<int64_t>(b.hashes.size()), source});
    nlohmann::json hashes = nlohmann::json::object();
    for (const auto& [u, h] : b.hashes) hashes[u] = h;
    txn.exec("INSERT INTO mirror_base (vault_id, entry_uid, entry_hash) "
             "SELECT $1, key::uuid, decode(value, 'hex') FROM jsonb_each_text($2::jsonb)",
             pqxx::params{vaultId, hashes.dump()});
}

RelinkFacts Relinks::facts(const uint32_t vaultId, const std::string& peerNode) {
    return Transactions::exec("mirror::Relinks::facts", [&](pqxx::work& txn) {
        RelinkFacts f;
        const pqxx::params v{vaultId};
        f.row = MirrorVaults::get(txn, vaultId, false);
        if (f.row) {
            const auto n = txn.exec("SELECT node_id FROM peer WHERE id = $1", pqxx::params{f.row->peer_id});
            if (!n.empty()) f.row_peer_node = n[0][0].as<std::string>();
            f.max_term = f.row->term;
        }
        const auto d = txn.exec("SELECT d.id, d.fork_term, d.fork_seq FROM mirror_detached d JOIN peer p ON p.id = d.peer_id "
                                "WHERE d.vault_id = $1 AND p.node_id = $2 AND d.rekeyed_at IS NULL "
                                "  AND d.relinked_at IS NULL ORDER BY d.id DESC LIMIT 1",
                                pqxx::params{vaultId, peerNode});
        if (!d.empty()) {
            f.detach_id = d[0][0].as<uint32_t>();
            f.detach_fork = Position{d[0][1].as<uint64_t>(), d[0][2].as<uint64_t>()};
            f.max_term = std::max(f.max_term, f.detach_fork->term);
        }
        const auto t = txn.exec("SELECT id, from_term, fork_seq, term FROM mirror_takeover WHERE vault_id = $1 "
                                "  AND settled_at IS NULL ORDER BY id DESC LIMIT 1", v);
        if (!t.empty()) {
            f.takeover_id = t[0][0].as<uint64_t>();
            f.takeover_fork = Position{t[0][1].as<uint64_t>(), t[0][2].as<uint64_t>()};
            f.takeover_term = t[0][3].as<uint64_t>();
            f.max_term = std::max(f.max_term, f.takeover_term);
        }
        const auto r = txn.exec("SELECT id, fork_term, fork_seq, new_term FROM mirror_rejoin WHERE vault_id = $1 "
                                "  AND phase IN ('draining', 'rejoining', 'forked') ORDER BY id DESC LIMIT 1", v);
        if (!r.empty()) {
            f.rejoin_id = r[0][0].as<uint64_t>();
            f.rejoin_fork = Position{r[0][1].as<uint64_t>(), r[0][2].as<uint64_t>()};
            f.rejoin_term = r[0][3].as<uint64_t>();
            f.max_term = std::max(f.max_term, f.rejoin_term);
        }
        const auto m = txn.exec("SELECT m.term, m.seq, p.node_id FROM mirror_base_mark m "
                                "LEFT JOIN peer p ON p.id = m.peer_id WHERE m.vault_id = $1", v);
        if (!m.empty()) {
            f.base_mark = Position{m[0][0].as<uint64_t>(), m[0][1].as<uint64_t>()};
            f.base_peer_node = relink_db_detail::textOr(m[0][2]);
            f.max_term = std::max(f.max_term, f.base_mark->term);
        }
        // Every term this vault's records with any server reached (a later term is never reused).
        f.max_term = std::max(f.max_term, txn.exec("SELECT COALESCE(max(fork_term), 0) FROM mirror_detached "
                                                   "WHERE vault_id = $1", v).one_field().as<uint64_t>());
        f.max_term = std::max(f.max_term, txn.exec("SELECT COALESCE(max(term), 0) FROM mirror_takeover WHERE vault_id = $1",
                                                   v).one_field().as<uint64_t>());
        f.max_term = std::max(f.max_term, txn.exec("SELECT COALESCE(max(new_term), 0) FROM mirror_rejoin WHERE vault_id = $1",
                                                   v).one_field().as<uint64_t>());
        f.pending = txn.exec("SELECT count(*) FROM mirror_pending WHERE vault_id = $1", v).one_field().as<uint64_t>();
        f.unnumbered = txn.exec("SELECT count(*) FROM vault_replication_log WHERE vault_id = $1 AND seq IS NULL", v)
                           .one_field()
                           .as<uint64_t>();
        f.submissions = txn.exec("SELECT count(*) FROM mirror_submission WHERE vault_id = $1 "
                                 "  AND state IN ('queued', 'running')", v)
                            .one_field()
                            .as<uint64_t>();
        f.switch_running = !txn.exec("SELECT 1 FROM mirror_switch WHERE vault_id = $1 AND ended_at IS NULL LIMIT 1", v)
                                .empty();
        f.start_running = !txn.exec("SELECT 1 FROM mirror_offer o JOIN vault x ON x.uid = o.vault_uid WHERE x.id = $1 "
                                    "  AND o.finished_at IS NULL LIMIT 1", v)
                               .empty();
        f.copy_running = !txn.exec("SELECT 1 FROM mirror_copy WHERE source_vault_id = $1 AND state = 'running' LIMIT 1", v)
                              .empty();
        f.deleting = !txn.exec("SELECT 1 FROM vault WHERE id = $1 AND deleted_at IS NOT NULL", v).empty();
        f.contents_missing = txn.exec("SELECT count(*) FROM mirror_content_pending WHERE vault_id = $1 AND state = 'missing'",
                                      v).one_field().as<uint64_t>();
        return f;
    });
}

std::vector<RelinkKey> Relinks::keys(const uint32_t vaultId) {
    return Transactions::exec("mirror::Relinks::keys", [&](pqxx::work& txn) {
        std::vector<RelinkKey> out;
        for (const auto row : txn.exec(
                 "SELECT k.version, TRUE AS current, k.key_check, o.origin_node_id, o.origin_vault_id, o.origin_key_check "
                 "FROM vault_keys k LEFT JOIN vault_key_origin o ON o.vault_id = k.vault_id AND o.version = k.version "
                 "WHERE k.vault_id = $1 "
                 "UNION ALL "
                 "SELECT t.version, FALSE, t.key_check, o.origin_node_id, o.origin_vault_id, o.origin_key_check "
                 "FROM vault_keys_trashed t LEFT JOIN vault_key_origin o ON o.vault_id = t.vault_id AND o.version = t.version "
                 "WHERE t.vault_id = $1 AND NOT EXISTS (SELECT 1 FROM vault_keys k WHERE k.vault_id = $1 "
                 "                                      AND k.version = t.version) "
                 "ORDER BY 1",
                 pqxx::params{vaultId})) {
            RelinkKey k;
            k.version = row[0].as<uint32_t>();
            k.current = row[1].as<bool>();
            k.check = relink_db_detail::textOr(row[2]);
            k.origin_node = relink_db_detail::textOr(row[3]);
            if (!row[4].is_null()) k.origin_vault = row[4].as<uint64_t>();
            k.origin_check = relink_db_detail::textOr(row[5]);
            out.push_back(std::move(k));
        }
        return out;
    });
}

Relink Relinks::create(const NewRelink& in) {
    using namespace relink_db_detail;
    return Transactions::exec("mirror::Relinks::create", [&](pqxx::work& txn) {
        // One open relink per vault: an open plan (nothing applied yet) is replaced; one being applied is not.
        const auto open = relinkOne(txn, "WHERE vault_id = $1 AND phase IN ('open', 'prepared', 'bring', 'copying') "
                                         "FOR UPDATE",
                                    pqxx::params{in.vault_id});
        if (open && open->phase != "open")
            throw ops::Refused("mirror_relink_running", "a relink of this vault is being applied (" + open->phase + ")");
        if (open)
            txn.exec("UPDATE mirror_relink SET phase = 'cancelled', error = 'replaced by a new comparison', "
                     "  updated_at = CURRENT_TIMESTAMP, finished_at = CURRENT_TIMESTAMP WHERE id = $1",
                     pqxx::params{static_cast<int64_t>(open->id)});
        const auto hexOf = [](const std::optional<vh::mirror::Digest>& d) {
            return d ? std::optional<std::string>(d->hex()) : std::nullopt;
        };
        const auto entriesOf = [](const std::optional<vh::mirror::Digest>& d) {
            return d ? std::optional<int64_t>(d->entries) : std::nullopt;
        };
        const auto id = txn.exec("INSERT INTO mirror_relink (relink_uid, vault_id, peer_id, side, phase, mode, core, "
                                 "  default_choice, this_status, theirs_status, this_digest, this_entries, theirs_digest, "
                                 "  theirs_entries, summary, by_node, by_id, by_name) "
                                 "VALUES (COALESCE(NULLIF($1, '')::uuid, gen_random_uuid()), $2, $3, $4, $5, $6, $7, $8, $9, $10, decode($11, 'hex'), $12, "
                                 "  decode($13, 'hex'), $14, $15::jsonb, $16, $17, $18) RETURNING id",
                                 pqxx::params{in.relink_uid, in.vault_id, in.peer_id, in.side, in.phase, in.mode, in.core,
                                              in.default_choice, in.this_status, in.theirs_status, hexOf(in.this_digest),
                                              entriesOf(in.this_digest), hexOf(in.theirs_digest),
                                              entriesOf(in.theirs_digest), in.summary.dump(), in.by_node, in.by_id,
                                              in.by_name ? std::optional<std::string>(in.by_name->substr(0, 255))
                                                         : std::nullopt})
                            .one_field()
                            .as<int64_t>();
        return *relinkOne(txn, "WHERE id = $1", pqxx::params{id});
    });
}

std::optional<Relink> Relinks::get(const uint64_t id) {
    return Transactions::exec("mirror::Relinks::get", [&](pqxx::work& txn) {
        return relink_db_detail::relinkOne(txn, "WHERE id = $1", pqxx::params{static_cast<int64_t>(id)});
    });
}

std::optional<Relink> Relinks::byUid(const uint32_t vaultId, const std::string& relinkUid) {
    return Transactions::exec("mirror::Relinks::byUid", [&](pqxx::work& txn) {
        return relink_db_detail::relinkOne(txn, "WHERE vault_id = $1 AND relink_uid = $2::uuid ORDER BY id DESC LIMIT 1",
                                           pqxx::params{vaultId, relinkUid});
    });
}

std::optional<Relink> Relinks::openOf(const uint32_t vaultId) {
    return Transactions::exec("mirror::Relinks::openOf", [&](pqxx::work& txn) {
        return relink_db_detail::relinkOne(txn, "WHERE vault_id = $1 AND phase IN ('open', 'prepared', 'bring', 'copying') "
                                                "ORDER BY id DESC LIMIT 1",
                                           pqxx::params{vaultId});
    });
}

std::optional<Relink> Relinks::latestOf(const uint32_t vaultId) {
    return Transactions::exec("mirror::Relinks::latestOf", [&](pqxx::work& txn) {
        return relink_db_detail::relinkOne(txn, "WHERE vault_id = $1 ORDER BY id DESC LIMIT 1", pqxx::params{vaultId});
    });
}

std::vector<Relink> Relinks::inPhase(const std::string& phase) {
    return Transactions::exec("mirror::Relinks::inPhase", [&](pqxx::work& txn) {
        std::vector<Relink> out;
        for (const auto row : txn.exec(std::string("SELECT ") + relink_db_detail::kRelinkColumns +
                                           " FROM mirror_relink WHERE phase = $1 ORDER BY id",
                                       pqxx::params{phase}))
            out.push_back(relink_db_detail::relinkFrom(row));
        return out;
    });
}

bool Relinks::setPhase(const uint64_t id, const std::vector<std::string>& from, const std::string& to,
                       const std::optional<std::string>& error) {
    return Transactions::exec("mirror::Relinks::setPhase", [&](pqxx::work& txn) {
        const bool finished = to == "done" || to == "failed" || to == "stale" || to == "cancelled";
        return txn.exec("UPDATE mirror_relink SET phase = $2, error = COALESCE($4, error), updated_at = CURRENT_TIMESTAMP, "
                        "  finished_at = CASE WHEN $5 THEN CURRENT_TIMESTAMP ELSE finished_at END "
                        "WHERE id = $1 AND phase IN (SELECT jsonb_array_elements_text($3::jsonb))",
                        pqxx::params{static_cast<int64_t>(id), to, nlohmann::json(from).dump(),
                                     error ? std::optional<std::string>(error->substr(0, 2000)) : std::nullopt, finished})
                   .affected_rows() > 0;
    });
}

void Relinks::setPlan(const uint64_t id, const std::optional<std::string>& core,
                      const std::optional<std::string>& defaultChoice, const bool clearDefault) {
    Transactions::exec("mirror::Relinks::setPlan", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_relink SET core = COALESCE($2, core), "
                 "  default_choice = CASE WHEN $4 THEN NULL ELSE COALESCE($3, default_choice) END, "
                 "  updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), core, defaultChoice, clearDefault});
    });
}

void Relinks::setApplied(const uint64_t id, const std::string& role, const uint64_t term, const std::string& mode) {
    Transactions::exec("mirror::Relinks::setApplied", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_relink SET role = $2, term = $3, mode = $4, applied_at = CURRENT_TIMESTAMP, "
                 "  updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), role, static_cast<int64_t>(term), mode});
    });
}

void Relinks::setSummary(const uint64_t id, const nlohmann::json& summary) {
    Transactions::exec("mirror::Relinks::setSummary", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_relink SET summary = $2::jsonb, updated_at = CURRENT_TIMESTAMP WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), summary.dump()});
    });
}

void Relinks::addEntries(const uint64_t id, const std::vector<RelinkEntry>& entries) {
    if (entries.empty()) return;
    Transactions::exec("mirror::Relinks::addEntries", [&](pqxx::work& txn) {
        // In slices: one statement per thousand entries.
        for (std::size_t from = 0; from < entries.size(); from += 1000) {
            const auto to = std::min(entries.size(), from + 1000);
            nlohmann::json rows = nlohmann::json::array();
            for (std::size_t i = from; i < to; ++i) {
                const auto& e = entries[i];
                rows.push_back({{"uid", e.uid}, {"kind", e.kind}, {"aspects", e.aspects}, {"path", e.path},
                                {"this_state", e.this_state}, {"theirs_state", e.theirs_state},
                                {"choice", e.choice ? nlohmann::json(*e.choice) : nlohmann::json(nullptr)}});
            }
            txn.exec("INSERT INTO mirror_relink_entry (relink_id, entry_uid, kind, aspects, path, this_state, theirs_state, "
                     "  choice) "
                     "SELECT $1, (r ->> 'uid')::uuid, r ->> 'kind', "
                     "  ARRAY(SELECT jsonb_array_elements_text(r -> 'aspects')), r ->> 'path', "
                     "  NULLIF(r -> 'this_state', 'null'::jsonb), NULLIF(r -> 'theirs_state', 'null'::jsonb), r ->> 'choice' "
                     "FROM jsonb_array_elements($2::jsonb) AS r "
                     "ON CONFLICT (relink_id, entry_uid) DO UPDATE SET kind = EXCLUDED.kind, aspects = EXCLUDED.aspects, "
                     "  path = EXCLUDED.path, this_state = EXCLUDED.this_state, theirs_state = EXCLUDED.theirs_state, "
                     "  choice = EXCLUDED.choice",
                     pqxx::params{static_cast<int64_t>(id), rows.dump()});
        }
    });
}

std::vector<RelinkEntry> Relinks::entries(const uint64_t id) {
    return Transactions::exec("mirror::Relinks::entries", [&](pqxx::work& txn) {
        std::vector<RelinkEntry> out;
        for (const auto row : txn.exec(std::string("SELECT ") + relink_db_detail::kEntryColumns +
                                           " FROM mirror_relink_entry WHERE relink_id = $1 ORDER BY path, entry_uid",
                                       pqxx::params{static_cast<int64_t>(id)}))
            out.push_back(relink_db_detail::entryFrom(row));
        return out;
    });
}

std::vector<RelinkEntry> Relinks::page(const uint64_t id, const std::string& kind, const uint64_t offset,
                                       const uint64_t limit, uint64_t& total) {
    return Transactions::exec("mirror::Relinks::page", [&](pqxx::work& txn) {
        std::vector<RelinkEntry> out;
        total = txn.exec("SELECT count(*) FROM mirror_relink_entry WHERE relink_id = $1 AND ($2 = '' OR kind = $2)",
                         pqxx::params{static_cast<int64_t>(id), kind})
                    .one_field()
                    .as<uint64_t>();
        for (const auto row : txn.exec(std::string("SELECT ") + relink_db_detail::kEntryColumns +
                                           " FROM mirror_relink_entry WHERE relink_id = $1 AND ($2 = '' OR kind = $2) "
                                           "ORDER BY path, entry_uid OFFSET $3 LIMIT $4",
                                       pqxx::params{static_cast<int64_t>(id), kind, static_cast<int64_t>(offset),
                                                    static_cast<int64_t>(limit)}))
            out.push_back(relink_db_detail::entryFrom(row));
        return out;
    });
}

std::optional<RelinkEntry> Relinks::entry(const uint64_t id, const std::string& uid) {
    return Transactions::exec("mirror::Relinks::entry", [&](pqxx::work& txn) -> std::optional<RelinkEntry> {
        const auto res = txn.exec(std::string("SELECT ") + relink_db_detail::kEntryColumns +
                                      " FROM mirror_relink_entry WHERE relink_id = $1 AND entry_uid = $2::uuid",
                                  pqxx::params{static_cast<int64_t>(id), uid});
        if (res.empty()) return std::nullopt;
        return relink_db_detail::entryFrom(res[0]);
    });
}

bool Relinks::setChoice(const uint64_t id, const std::string& uid, const std::optional<std::string>& choice) {
    return Transactions::exec("mirror::Relinks::setChoice", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_relink_entry SET choice = $3 WHERE relink_id = $1 AND entry_uid = $2::uuid",
                        pqxx::params{static_cast<int64_t>(id), uid, choice})
                   .affected_rows() > 0;
    });
}

uint64_t Relinks::setChoiceByKind(const uint64_t id, const std::string& kind, const std::optional<std::string>& choice) {
    return Transactions::exec("mirror::Relinks::setChoiceByKind", [&](pqxx::work& txn) {
        return static_cast<uint64_t>(txn.exec("UPDATE mirror_relink_entry SET choice = $3 "
                                              "WHERE relink_id = $1 AND ($2 = '' OR kind = $2)",
                                              pqxx::params{static_cast<int64_t>(id), kind, choice})
                                         .affected_rows());
    });
}

void Relinks::setOutcome(const uint64_t id, const std::string& uid, const std::optional<std::string>& requestId,
                         const std::string& outcome, const std::string& note) {
    Transactions::exec("mirror::Relinks::setOutcome", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_relink_entry SET request_id = COALESCE($3, request_id), outcome = $4, outcome_note = $5 "
                 "WHERE relink_id = $1 AND entry_uid = $2::uuid",
                 pqxx::params{static_cast<int64_t>(id), uid, requestId, outcome.substr(0, 32), note.substr(0, 1000)});
    });
}

void Relinks::release(pqxx::work& txn, const uint32_t vaultId, const uint64_t relinkId, const bool becomingMirror) {
    const pqxx::params v{vaultId};
    txn.exec("UPDATE mirror_detached SET relinked_at = CURRENT_TIMESTAMP, relink_id = $2 "
             "WHERE vault_id = $1 AND rekeyed_at IS NULL AND relinked_at IS NULL",
             pqxx::params{vaultId, static_cast<int64_t>(relinkId)});
    txn.exec("DELETE FROM mirror_fork_base WHERE takeover_id IN (SELECT id FROM mirror_takeover WHERE vault_id = $1 "
             "  AND settled_at IS NULL)", v);
    txn.exec("UPDATE mirror_takeover SET settled_at = CURRENT_TIMESTAMP, settled_how = 'relinked', "
             "  detail = COALESCE(detail, '{}'::jsonb) || jsonb_build_object('relink_id', $2::bigint) "
             "WHERE vault_id = $1 AND settled_at IS NULL",
             pqxx::params{vaultId, static_cast<int64_t>(relinkId)});
    txn.exec("UPDATE mirror_rejoin SET phase = 'relinked', decided_at = COALESCE(decided_at, CURRENT_TIMESTAMP) "
             "WHERE vault_id = $1 AND phase IN ('draining', 'rejoining', 'forked')", v);
    (void)MirrorVaults::remove(txn, vaultId);
    txn.exec("DELETE FROM mirror_base WHERE vault_id = $1", v);
    txn.exec("DELETE FROM mirror_base_mark WHERE vault_id = $1", v);
    if (becomingMirror)
        txn.exec("UPDATE mirror_content_pending SET state = 'waiting', last_error = NULL WHERE vault_id = $1 "
                 "  AND state = 'missing'", v);
}

}
