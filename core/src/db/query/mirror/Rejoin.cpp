#include "db/query/mirror/Rejoin.hpp"

#include "db/Transactions.hpp"
#include "mirror/access/Access.hpp"
#include "ops/Error.hpp"
#include "rbac/Mirrored.hpp"

#include <pqxx/pqxx>

#include <string>
#include <vector>

namespace vh::db::query::mirror {

namespace {

constexpr const char* kRejoinColumns = R"SQL(
    id, vault_id, peer_id, new_term, fork_term, fork_seq, encode(fork_digest, 'hex') AS fork_digest, fork_entries,
    encode(baseline_digest, 'hex') AS baseline_digest, baseline_entries, phase, changes,
    COALESCE(array_to_json(writers)::text, '[]') AS writers, detail::text AS detail,
    EXTRACT(EPOCH FROM created_at)::BIGINT AS created_at, EXTRACT(EPOCH FROM decided_at)::BIGINT AS decided_at
)SQL";

Rejoin rejoinFrom(const pqxx::row_ref row) {
    Rejoin r;
    r.id = row["id"].as<uint64_t>();
    r.vault_id = row["vault_id"].as<uint32_t>();
    r.peer_id = row["peer_id"].as<uint32_t>();
    r.new_term = row["new_term"].as<uint64_t>();
    r.fork = {row["fork_term"].as<uint64_t>(), row["fork_seq"].as<uint64_t>()};
    r.fork_digest = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(row["fork_digest"].as<std::string>()),
                                                  row["fork_entries"].as<int64_t>());
    if (!row["baseline_digest"].is_null())
        r.baseline_digest = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(row["baseline_digest"].as<std::string>()),
                                                          row["baseline_entries"].as<int64_t>());
    r.phase = row["phase"].as<std::string>();
    r.changes = row["changes"].as<uint32_t>();
    for (const auto& w : nlohmann::json::parse(row["writers"].as<std::string>()))
        if (w.is_string()) r.writers.push_back(w.get<std::string>());
    r.detail = row["detail"].is_null() ? nlohmann::json::object() : nlohmann::json::parse(row["detail"].as<std::string>());
    r.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    if (!row["decided_at"].is_null()) r.decided_at = static_cast<std::time_t>(row["decided_at"].as<int64_t>());
    return r;
}

std::optional<Rejoin> rejoinOne(pqxx::work& txn, const std::string& where, const pqxx::params& params) {
    const auto r = txn.exec(std::string("SELECT ") + kRejoinColumns + " FROM mirror_rejoin " + where, params);
    if (r.empty()) return std::nullopt;
    return rejoinFrom(r[0]);
}

void rejoinRepublish(const bool roles) {
    if (roles) vh::rbac::mirrored::reload();
    vh::mirror::access::reload();
}

constexpr const char* kOpen = "phase IN ('draining', 'rejoining', 'forked')";

// The start's offer of the vault changes side with the role (as a switch's does).
void rejoinFlipOffer(pqxx::work& txn, const uint32_t vaultId) {
    txn.exec("UPDATE mirror_offer SET side = CASE side WHEN 'core' THEN 'mirror' ELSE 'core' END, "
             "  updated_at = CURRENT_TIMESTAMP "
             "WHERE id = (SELECT o.id FROM mirror_offer o JOIN vault v ON v.uid = o.vault_uid "
             "            WHERE v.id = $1 AND o.state = 'started' ORDER BY o.id DESC LIMIT 1)",
             pqxx::params{vaultId});
}

}

std::optional<Rejoin> Rejoins::get(const uint64_t id) {
    return Transactions::exec("mirror::Rejoins::get", [&](pqxx::work& txn) {
        return rejoinOne(txn, "WHERE id = $1", pqxx::params{static_cast<int64_t>(id)});
    });
}

std::optional<Rejoin> Rejoins::openOf(const uint32_t vaultId) {
    return Transactions::exec("mirror::Rejoins::openOf", [&](pqxx::work& txn) {
        return rejoinOne(txn, std::string("WHERE vault_id = $1 AND ") + kOpen, pqxx::params{vaultId});
    });
}

std::optional<Rejoin> Rejoins::latestOf(const uint32_t vaultId) {
    return Transactions::exec("mirror::Rejoins::latestOf", [&](pqxx::work& txn) {
        return rejoinOne(txn, "WHERE vault_id = $1 ORDER BY id DESC LIMIT 1", pqxx::params{vaultId});
    });
}

std::vector<Rejoin> Rejoins::draining() {
    return Transactions::exec("mirror::Rejoins::draining", [&](pqxx::work& txn) {
        std::vector<Rejoin> out;
        for (const auto row : txn.exec(std::string("SELECT ") + kRejoinColumns +
                                       " FROM mirror_rejoin WHERE phase = 'draining' ORDER BY id"))
            out.push_back(rejoinFrom(row));
        return out;
    });
}

Rejoin Rejoins::begin(const uint32_t vaultId, const uint32_t peerId, const uint64_t newTerm, const Position fork,
                      const vh::mirror::Digest& forkDigest, const std::optional<vh::mirror::Digest>& baselineDigest) {
    bool froze = false;
    auto out = Transactions::exec("mirror::Rejoins::begin", [&](pqxx::work& txn) {
        const auto mv = MirrorVaults::get(txn, vaultId, true);
        if (!mv || mv->peer_id != peerId) throw vh::ops::NotFound("Not found");
        if (const auto open = rejoinOne(txn, std::string("WHERE vault_id = $1 AND ") + kOpen, pqxx::params{vaultId}))
            return *open;
        if (mv->role != "core" || mv->term >= newTerm)
            throw vh::ops::Refused("mirror_term_stale", "this server holds the vault in term " + std::to_string(mv->term));
        const auto id =
            txn.exec("INSERT INTO mirror_rejoin (vault_id, peer_id, new_term, fork_term, fork_seq, fork_digest, "
                     "  fork_entries, baseline_digest, baseline_entries, phase) "
                     "VALUES ($1, $2, $3, $4, $5, decode($6, 'hex'), $7, decode(NULLIF($8, ''), 'hex'), $9, 'draining') "
                     "RETURNING id",
                     pqxx::params{vaultId, peerId, static_cast<int64_t>(newTerm), static_cast<int64_t>(fork.term),
                                  static_cast<int64_t>(fork.seq), forkDigest.hex(), forkDigest.entries,
                                  baselineDigest ? baselineDigest->hex() : std::string{},
                                  baselineDigest ? std::optional<int64_t>(baselineDigest->entries) : std::nullopt})
                .one_field()
                .as<int64_t>();
        txn.exec("UPDATE mirror_vault SET state = 'rejoining', updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
                 pqxx::params{vaultId});
        froze = true;
        return *rejoinOne(txn, "WHERE id = $1", pqxx::params{id});
    });
    if (froze) rejoinRepublish(false);
    return out;
}

void Rejoins::recordWriters(const uint64_t id, const std::vector<std::string>& writers) {
    std::string list = "{";
    for (const auto& w : writers) {
        if (list.size() > 1) list += ',';
        list += '"' + w + '"';
    }
    list += '}';
    Transactions::exec("mirror::Rejoins::recordWriters", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_rejoin SET writers = $2::text[] WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), list});
    });
}

Rejoin Rejoins::forked(const uint32_t vaultId, const uint32_t peerId, const uint64_t otherTerm, const Position otherFork,
                       const vh::mirror::Digest& otherForkDigest) {
    bool froze = false;
    auto out = Transactions::exec("mirror::Rejoins::forked", [&](pqxx::work& txn) {
        const auto mv = MirrorVaults::get(txn, vaultId, true);
        if (!mv || mv->peer_id != peerId || mv->role != "core") throw vh::ops::NotFound("Not found");
        if (const auto open = rejoinOne(txn, std::string("WHERE vault_id = $1 AND ") + kOpen, pqxx::params{vaultId}))
            return *open;
        const auto id =
            txn.exec("INSERT INTO mirror_rejoin (vault_id, peer_id, new_term, fork_term, fork_seq, fork_digest, "
                     "  fork_entries, phase, decided_at, detail) "
                     "VALUES ($1, $2, $3, $4, $5, decode($6, 'hex'), $7, 'forked', CURRENT_TIMESTAMP, "
                     "  jsonb_build_object('own_term', $8::bigint)) RETURNING id",
                     pqxx::params{vaultId, peerId, static_cast<int64_t>(otherTerm), static_cast<int64_t>(otherFork.term),
                                  static_cast<int64_t>(otherFork.seq), otherForkDigest.hex(), otherForkDigest.entries,
                                  static_cast<int64_t>(mv->term)})
                .one_field()
                .as<int64_t>();
        txn.exec("UPDATE mirror_vault SET state = 'forked', updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
                 pqxx::params{vaultId});
        froze = true;
        return *rejoinOne(txn, "WHERE id = $1", pqxx::params{id});
    });
    if (froze) rejoinRepublish(false);
    return out;
}

Rejoins::Decided Rejoins::decide(const uint64_t id, const uint32_t resyncBy) {
    auto out = Transactions::exec("mirror::Rejoins::decide", [&](pqxx::work& txn) -> Decided {
        const auto r = rejoinOne(txn, "WHERE id = $1 FOR UPDATE", pqxx::params{static_cast<int64_t>(id)});
        if (!r || r->phase != "draining") return {.waits = "the rejoin is not draining"};
        const auto mv = MirrorVaults::get(txn, r->vault_id, true);
        if (!mv || mv->role != "core" || mv->state != "rejoining") return {.waits = "the vault is not rejoining here"};
        const pqxx::params v{r->vault_id};
        if (txn.exec("SELECT EXISTS (SELECT 1 FROM vault_replication_log WHERE vault_id = $1 AND seq IS NULL)", v)
                .one_field()
                .as<bool>())
            return {.waits = "a change still waits for its number"};
        const bool nothingNew = mv->term == r->fork.term && mv->last_seq == r->fork.seq && mv->digest == r->fork_digest;
        if (!nothingNew) {
            const auto changes = txn.exec("SELECT count(*) FROM vault_replication_log WHERE vault_id = $1 "
                                          "AND seq IS NOT NULL AND (term, seq) > ($2::bigint, $3::bigint)",
                                          pqxx::params{r->vault_id, static_cast<int64_t>(r->fork.term),
                                                       static_cast<int64_t>(r->fork.seq)})
                                     .one_field()
                                     .as<int64_t>();
            txn.exec("UPDATE mirror_rejoin SET phase = 'rejoining', changes = $2, decided_at = CURRENT_TIMESTAMP, "
                     "  detail = jsonb_build_object('last', jsonb_build_object('term', $3::bigint, 'seq', $4::bigint), "
                     "    'digest', $5::text) WHERE id = $1",
                     pqxx::params{static_cast<int64_t>(id), changes, static_cast<int64_t>(mv->term),
                                  static_cast<int64_t>(mv->last_seq), mv->digest.hex()});
            return {.phase = "rejoining", .changes = static_cast<uint32_t>(changes)};
        }
        // Nothing past the fork point: the vault's mirror in the new term.
        const bool sameTree = r->baseline_digest && *r->baseline_digest == r->fork_digest;
        txn.exec("UPDATE mirror_vault SET role = 'mirror', term = $2, last_seq = 0, acked_term = NULL, acked_seq = NULL, "
                 "  acked_at = NULL, pruned_term = 0, pruned_seq = 0, numbered_at = NULL, baseline_term = NULL, "
                 "  baseline_seq = NULL, baseline_digest = NULL, baseline_entries = NULL, baseline_rows = NULL, "
                 "  baseline_vault = NULL, copy_finished = TRUE, vault_state = vh_mirror_vault_state($1), state = 'live', "
                 "  stop_reason = NULL, stop_detail = NULL, stopped_at = NULL, updated_at = CURRENT_TIMESTAMP "
                 "WHERE vault_id = $1",
                 pqxx::params{r->vault_id, static_cast<int64_t>(r->new_term)});
        for (const auto* table : {"vault_replication_log", "mirror_baseline", "mirror_submission"})
            txn.exec(std::string("DELETE FROM ") + table + " WHERE vault_id = $1", v);
        if (!sameTree) {
            // The new core's tree at (new_term, 0) is not the fork point's: its first copy again, over the entries
            // here (the resync copy: by uid, the bytes of a generation held here reused).
            txn.exec("UPDATE mirror_vault SET copy_cursor = 0, copy_finished = FALSE, "
                     "  digest = decode(repeat('00', 32), 'hex'), digest_entries = 0, "
                     "  resync_at = CURRENT_TIMESTAMP, resync_by = $2, resync_count = resync_count + 1 WHERE vault_id = $1",
                     pqxx::params{r->vault_id, resyncBy});
            txn.exec("DELETE FROM mirror_entry_hash WHERE vault_id = $1", v);
            txn.exec("DELETE FROM mirror_dirty WHERE vault_id = $1", v);
        }
        rejoinFlipOffer(txn, r->vault_id);
        txn.exec("UPDATE mirror_rejoin SET phase = 'following', decided_at = CURRENT_TIMESTAMP, "
                 "  detail = jsonb_build_object('copy', $2::boolean) WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(id), !sameTree});
        return {.phase = "following"};
    });
    if (out.waits.empty()) rejoinRepublish(out.phase == "following");
    return out;
}

bool Rejoins::closeForked(const uint32_t vaultId) {
    return Transactions::exec("mirror::Rejoins::closeForked", [&](pqxx::work& txn) {
        return txn.exec("UPDATE mirror_rejoin SET phase = 'resynced', decided_at = COALESCE(decided_at, CURRENT_TIMESTAMP) "
                        "WHERE vault_id = $1 AND phase = 'forked'",
                        pqxx::params{vaultId})
                   .affected_rows() > 0;
    });
}

bool Rejoins::toMirrorForResync(const uint32_t vaultId) {
    const bool done = Transactions::exec("mirror::Rejoins::toMirrorForResync", [&](pqxx::work& txn) {
        const auto r = rejoinOne(txn, std::string("WHERE vault_id = $1 AND phase IN ('rejoining', 'forked') FOR UPDATE"),
                                 pqxx::params{vaultId});
        if (!r) return false;
        const pqxx::params v{vaultId};
        txn.exec("UPDATE mirror_vault SET role = 'mirror', term = $2, last_seq = 0, acked_term = NULL, acked_seq = NULL, "
                 "  acked_at = NULL, pruned_term = 0, pruned_seq = 0, numbered_at = NULL, baseline_term = NULL, "
                 "  baseline_seq = NULL, baseline_digest = NULL, baseline_entries = NULL, baseline_rows = NULL, "
                 "  baseline_vault = NULL, copy_finished = TRUE, state = 'stopped', stop_reason = 'mirror_rejoin_resync', "
                 "  stop_detail = jsonb_build_object('why', 'its copy starts over from the other server'), "
                 "  stopped_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
                 pqxx::params{vaultId, static_cast<int64_t>(r->new_term)});
        for (const auto* table : {"vault_replication_log", "mirror_baseline", "mirror_submission"})
            txn.exec(std::string("DELETE FROM ") + table + " WHERE vault_id = $1", v);
        txn.exec("DELETE FROM mirror_fork_base WHERE takeover_id IN (SELECT id FROM mirror_takeover WHERE vault_id = $1)",
                 v);
        txn.exec("UPDATE mirror_takeover SET settled_at = CURRENT_TIMESTAMP, settled_how = 'ended' "
                 "WHERE vault_id = $1 AND settled_at IS NULL",
                 v);
        txn.exec("UPDATE mirror_rejoin SET phase = 'resynced', decided_at = COALESCE(decided_at, CURRENT_TIMESTAMP) "
                 "WHERE id = $1",
                 pqxx::params{static_cast<int64_t>(r->id)});
        rejoinFlipOffer(txn, vaultId);
        return true;
    });
    if (done) rejoinRepublish(true);
    return done;
}

}
