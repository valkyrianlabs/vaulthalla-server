#include "db/query/mirror/Log.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>

#include <algorithm>
#include <map>
#include <optional>
#include <set>
#include <utility>
#include <string>

namespace vh::db::query::mirror {

namespace {

// Rows a retention pass deletes per statement.
constexpr int64_t kPruneBatch = 50'000;

constexpr const char* kLogColumns = R"SQL(
    term, seq, txid, op, entry_uid::text AS entry_uid, entry_type, parent_uid::text AS parent_uid, name,
    state::text AS state, encode(entry_hash, 'hex') AS entry_hash, encode(prev_hash, 'hex') AS prev_hash,
    actor_node, actor_id, origin, EXTRACT(EPOCH FROM logged_at)::BIGINT AS logged_at
)SQL";

template <typename T>
std::optional<T> optionalField(const pqxx::row_ref row, const char* column) {
    if (row[column].is_null()) return std::nullopt;
    return row[column].as<T>();
}

std::optional<vh::mirror::Hash> optionalHash(const pqxx::row_ref row, const char* column) {
    if (row[column].is_null()) return std::nullopt;
    return vh::mirror::hashFromHex(row[column].as<std::string>());
}

Row logRowFrom(const pqxx::row_ref row) {
    Row r;
    r.term = row["term"].as<uint64_t>();
    r.seq = row["seq"].as<uint64_t>();
    r.txid = row["txid"].as<uint64_t>();
    r.op = row["op"].as<std::string>();
    r.entry_uid = optionalField<std::string>(row, "entry_uid");
    r.entry_type = optionalField<std::string>(row, "entry_type");
    r.parent_uid = optionalField<std::string>(row, "parent_uid");
    r.name = optionalField<std::string>(row, "name");
    r.state = nlohmann::json::parse(row["state"].as<std::string>());
    r.entry_hash = optionalHash(row, "entry_hash");
    r.prev_hash = optionalHash(row, "prev_hash");
    if (!row["actor_id"].is_null())
        r.actor = Account{.node = row["actor_node"].is_null() ? std::string{} : row["actor_node"].as<std::string>(),
                          .id = row["actor_id"].as<uint32_t>()};
    r.origin = optionalField<std::string>(row, "origin");
    r.logged_at = static_cast<std::time_t>(row["logged_at"].as<int64_t>());
    return r;
}

// One numbering transaction for one vault: at most kSequenceBatch rows of whole groups (a larger group alone), in the
// order of each group's last row. Rows numbered: 0 when nothing is pending or the vault is not this server's core.
uint64_t numberBatch(const uint32_t vaultId, Sequenced::Vault& out) {
    return Transactions::exec("mirror::Log::sequence", [&](pqxx::work& txn) -> uint64_t {
        // The row lock serialises sequencers of the vault; each statement below reads after it (READ COMMITTED).
        const auto mv = txn.exec("SELECT term, last_seq, encode(digest, 'hex') AS digest, digest_entries FROM mirror_vault "
                                 "WHERE vault_id = $1 AND role = 'core' AND state <> 'starting' FOR NO KEY UPDATE",
                                 pqxx::params{vaultId});
        if (mv.empty()) return 0;
        const auto term = mv[0]["term"].as<uint64_t>();
        const auto base = mv[0]["last_seq"].as<uint64_t>();
        auto digest = vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(mv[0]["digest"].as<std::string>()),
                                                    mv[0]["digest_entries"].as<int64_t>());

        // The oldest pending groups by their last row, then their rows by txid = ANY (an index condition whatever
        // the statistics say: a fresh, unanalysed backlog made a join of the log with itself a nested loop over every
        // pending row, 1.5 ms a row), ordered here; numbers are written by id.
        const auto groups = txn.exec("SELECT txid, max(id) AS last_id FROM vault_replication_log "
                                     "WHERE vault_id = $1 AND term = $2 AND seq IS NULL "
                                     "GROUP BY txid ORDER BY last_id LIMIT $3",
                                     pqxx::params{vaultId, static_cast<int64_t>(term),
                                                  static_cast<int64_t>(Log::kSequenceBatch)});
        if (groups.empty()) return 0;
        std::map<uint64_t, int64_t> lastIdOf;
        std::string txids = "{";
        for (const auto row : groups) {
            if (txids.size() > 1) txids += ',';
            txids += std::to_string(row["txid"].as<int64_t>());
            lastIdOf[row["txid"].as<uint64_t>()] = row["last_id"].as<int64_t>();
        }
        txids += '}';
        struct PendingRow {
            int64_t last_id{};   // its group's last row: the group's place in commit order
            int64_t id{};
            uint64_t txid{};
            std::optional<vh::mirror::Hash> entry_hash{}, prev_hash{};
        };
        std::vector<PendingRow> pendingRows;
        for (const auto row : txn.exec("SELECT id, txid, encode(entry_hash, 'hex') AS entry_hash, "
                                       "       encode(prev_hash, 'hex') AS prev_hash FROM vault_replication_log "
                                       "WHERE vault_id = $1 AND txid = ANY($2::bigint[]) AND term = $3 AND seq IS NULL",
                                       pqxx::params{vaultId, txids, static_cast<int64_t>(term)})) {
            const auto t = row["txid"].as<uint64_t>();
            pendingRows.push_back({.last_id = lastIdOf[t], .id = row["id"].as<int64_t>(), .txid = t,
                                   .entry_hash = optionalHash(row, "entry_hash"), .prev_hash = optionalHash(row, "prev_hash")});
        }
        std::ranges::sort(pendingRows, {}, [](const PendingRow& r) { return std::pair(r.last_id, r.id); });
        // Numbers, and on each group's last row the digest once the group is applied (MirrorVaults::digestAt).
        std::string ids = "{", seqs = "{", digests = "{", entries = "{";
        uint64_t next = base;
        uint64_t numberedGroups = 0;
        for (std::size_t i = 0; i < pendingRows.size(); ++i) {
            const auto& row = pendingRows[i];
            // Whole groups only: stop at a group boundary once the batch is full.
            if (i > 0 && pendingRows[i - 1].txid != row.txid && next - base >= Log::kSequenceBatch) break;
            if (row.entry_hash) digest.add(*row.entry_hash);
            if (row.prev_hash) digest.remove(*row.prev_hash);
            const bool lastOfGroup = i + 1 == pendingRows.size() || pendingRows[i + 1].txid != row.txid;
            if (next > base) {
                ids += ',';
                seqs += ',';
                digests += ',';
                entries += ',';
            }
            ids += std::to_string(row.id);
            seqs += std::to_string(++next);
            digests += lastOfGroup ? digest.hex() : std::string("NULL");
            entries += lastOfGroup ? std::to_string(digest.entries) : std::string("NULL");
            if (lastOfGroup) ++numberedGroups;
        }
        if (next == base) return 0;
        ids += '}';
        seqs += '}';
        digests += '}';
        entries += '}';
        const auto updated = txn.exec(
            "UPDATE vault_replication_log l SET seq = n.seq, digest_after = decode(n.digest, 'hex'), "
            "  entries_after = n.entries "
            "FROM unnest($1::bigint[], $2::bigint[], $3::text[], $4::bigint[]) AS n(id, seq, digest, entries) "
            "WHERE l.id = n.id",
            pqxx::params{ids, seqs, digests, entries}).affected_rows();
        if (updated == 0) return 0;

        const auto last = base + static_cast<uint64_t>(updated);
        txn.exec("UPDATE mirror_vault SET last_seq = $2, digest = decode($3, 'hex'), digest_entries = $4, "
                 "  numbered_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
                 pqxx::params{vaultId, static_cast<int64_t>(last), digest.hex(), digest.entries});
        out.last = {term, last};
        out.groups += numberedGroups;
        out.rows += updated;
        return updated;
    });
}

// The distinct vault ids of a table's index on (vault_id, ...), read as a loose index scan.
std::vector<uint32_t> vaultsOf(pqxx::work& txn, const std::string& table, const std::string& predicate) {
    const auto where = predicate.empty() ? std::string{} : " AND " + predicate;
    std::vector<uint32_t> out;
    for (const auto row : txn.exec(
             "WITH RECURSIVE v AS ("
             "  SELECT (SELECT min(vault_id) FROM " + table + " WHERE TRUE" + where + ") AS id "
             "  UNION ALL "
             "  SELECT (SELECT min(vault_id) FROM " + table + " WHERE vault_id > v.id" + where + ") FROM v "
             "  WHERE v.id IS NOT NULL"
             ") SELECT id FROM v WHERE id IS NOT NULL"))
        out.push_back(row[0].as<uint32_t>());
    return out;
}

}

bool Log::pending() {
    return Transactions::read("mirror::Log::pending", [](pqxx::transaction_base& txn) {
        return txn.exec("SELECT EXISTS (SELECT 1 FROM vault_replication_log WHERE seq IS NULL)").one_field().as<bool>();
    });
}

std::optional<Sequenced::Vault> Log::sequence(const uint32_t vaultId) {
    Sequenced::Vault out{.vault_id = vaultId};
    for (;;) {
        const auto numbered = numberBatch(vaultId, out);
        if (numbered < kSequenceBatch) break;
    }
    if (out.rows == 0) return std::nullopt;
    return out;
}

Sequenced Log::sequence() {
    Sequenced out;
    if (!pending()) return out;
    const auto vaults = Transactions::read("mirror::Log::pendingVaults", [](pqxx::transaction_base& txn) {
        std::vector<uint32_t> ids;
        for (const auto row : txn.exec("SELECT DISTINCT l.vault_id FROM vault_replication_log l "
                                       "JOIN mirror_vault m ON m.vault_id = l.vault_id AND m.role = 'core' AND m.state <> 'starting' "
                                       "WHERE l.seq IS NULL AND l.term = m.term ORDER BY 1"))
            ids.push_back(row[0].as<uint32_t>());
        return ids;
    });
    for (const auto vaultId : vaults) {
        if (const auto v = sequence(vaultId)) {
            out.rows += v->rows;
            out.vaults.push_back(*v);
        }
    }
    return out;
}

Page Log::groupsAfter(const uint32_t vaultId, const Position after, const std::size_t limit) {
    const auto pageRows = static_cast<int64_t>(std::clamp<std::size_t>(limit, 1, kMaxPageRows));
    return Transactions::exec("mirror::Log::groupsAfter", [&](pqxx::work& txn) {
        Page page{.last = after};
        const auto mv = txn.exec("SELECT term, last_seq, pruned_term, pruned_seq FROM mirror_vault "
                                 "WHERE vault_id = $1 AND role = 'core' AND state <> 'starting'",
                                 pqxx::params{vaultId});
        if (mv.empty()) {
            page.expired = true;
            return page;
        }
        const Position numbered{mv[0]["term"].as<uint64_t>(), mv[0]["last_seq"].as<uint64_t>()};
        const Position pruned{mv[0]["pruned_term"].as<uint64_t>(), mv[0]["pruned_seq"].as<uint64_t>()};
        if (after < pruned || after > numbered) {
            page.expired = true;
            return page;
        }

        const auto t = static_cast<int64_t>(after.term);
        const auto s = static_cast<int64_t>(after.seq);
        auto res = txn.exec(std::string("SELECT ") + kLogColumns + " FROM vault_replication_log "
                            "WHERE vault_id = $1 AND seq IS NOT NULL AND (term, seq) > ($2::bigint, $3::bigint) "
                            "ORDER BY term, seq LIMIT $4",
                            pqxx::params{vaultId, t, s, pageRows + 1});
        std::vector<Row> rows;
        rows.reserve(res.size());
        for (const auto row : res) rows.push_back(logRowFrom(row));
        if (static_cast<int64_t>(rows.size()) > pageRows) {
            // The extra row says whether the page's last group goes on past it: then that group waits for the next
            // page, unless it is the only one.
            const auto extra = rows.back();
            rows.pop_back();
            while (!rows.empty() && rows.back().term == extra.term && rows.back().txid == extra.txid) rows.pop_back();
            if (rows.empty()) {
                for (const auto row : txn.exec(std::string("SELECT ") + kLogColumns + " FROM vault_replication_log "
                                               "WHERE vault_id = $1 AND term = $2 AND txid = $3 AND seq IS NOT NULL "
                                               "ORDER BY seq",
                                               pqxx::params{vaultId, static_cast<int64_t>(extra.term),
                                                            static_cast<int64_t>(extra.txid)}))
                    rows.push_back(logRowFrom(row));
            }
        }
        for (auto& row : rows) {
            if (page.groups.empty() || page.groups.back().term != row.term || page.groups.back().txid != row.txid)
                page.groups.push_back({.term = row.term, .txid = row.txid, .first_seq = row.seq, .last_seq = row.seq});
            auto& group = page.groups.back();
            group.last_seq = row.seq;
            group.rows.push_back(std::move(row));
        }
        if (!page.groups.empty()) page.last = {page.groups.back().term, page.groups.back().last_seq};
        page.more = page.last < numbered;

        // Retention may have dropped part of what was read after the first check.
        const auto now = txn.exec("SELECT pruned_term, pruned_seq FROM mirror_vault WHERE vault_id = $1",
                                  pqxx::params{vaultId});
        if (now.empty() || after < Position{now[0][0].as<uint64_t>(), now[0][1].as<uint64_t>()})
            page = Page{.last = after, .expired = true};
        return page;
    });
}

Pruned Log::prune(const std::chrono::seconds maxAge, const uint64_t maxRows) {
    Pruned out;
    const auto cores = Transactions::read("mirror::Log::pruneVaults", [](pqxx::transaction_base& txn) {
        std::vector<uint32_t> ids;
        for (const auto row : txn.exec("SELECT vault_id FROM mirror_vault WHERE role = 'core' ORDER BY vault_id"))
            ids.push_back(row[0].as<uint32_t>());
        return ids;
    });

    for (const auto vaultId : cores) {
        for (;;) {
            const auto removed = Transactions::exec("mirror::Log::prune", [&](pqxx::work& txn) -> uint64_t {
                const auto mv = txn.exec("SELECT term, last_seq, acked_term, acked_seq, pruned_term, pruned_seq "
                                         "FROM mirror_vault WHERE vault_id = $1 AND role = 'core' FOR NO KEY UPDATE",
                                         pqxx::params{vaultId});
                if (mv.empty() || mv[0]["acked_term"].is_null()) return 0;   // nothing acknowledged: nothing goes
                const Position acked{mv[0]["acked_term"].as<uint64_t>(), mv[0]["acked_seq"].as<uint64_t>()};
                const Position numbered{mv[0]["term"].as<uint64_t>(), mv[0]["last_seq"].as<uint64_t>()};
                const Position pruned{mv[0]["pruned_term"].as<uint64_t>(), mv[0]["pruned_seq"].as<uint64_t>()};

                // By age: everything numbered before the oldest row still inside the window (sequence order is close
                // to time order; all of a group shares its transaction's time), or all of it.
                Position cut = numbered;
                const auto young = txn.exec(
                    "SELECT term, seq FROM vault_replication_log WHERE vault_id = $1 AND seq IS NOT NULL "
                    "  AND logged_at >= CURRENT_TIMESTAMP - ($2::bigint * INTERVAL '1 second') "
                    "ORDER BY term, seq LIMIT 1",
                    pqxx::params{vaultId, static_cast<int64_t>(maxAge.count())});
                if (!young.empty()) {
                    const Position y{young[0][0].as<uint64_t>(), young[0][1].as<uint64_t>()};
                    cut = y.seq > 1 ? Position{y.term, y.seq - 1} : pruned;
                }
                // By count: more than maxRows behind the newest number goes too.
                if (numbered.seq > maxRows) cut = std::max(cut, Position{numbered.term, numbered.seq - maxRows});
                // Never past what the mirror acknowledged.
                cut = std::min(cut, acked);
                if (cut <= pruned) return 0;

                // Never through the middle of a group: back to the end of the group before.
                const auto boundary = txn.exec(
                    "SELECT (SELECT min(g.seq) FROM vault_replication_log g WHERE g.vault_id = c.vault_id "
                    "        AND g.term = c.term AND g.txid = c.txid AND g.seq IS NOT NULL) AS first_seq, "
                    "       EXISTS (SELECT 1 FROM vault_replication_log n WHERE n.vault_id = c.vault_id "
                    "               AND n.term = c.term AND n.seq = c.seq + 1 AND n.txid = c.txid) AS cut_inside "
                    "FROM vault_replication_log c WHERE c.vault_id = $1 AND c.term = $2 AND c.seq = $3",
                    pqxx::params{vaultId, static_cast<int64_t>(cut.term), static_cast<int64_t>(cut.seq)});
                if (!boundary.empty() && boundary[0]["cut_inside"].as<bool>())
                    cut.seq = boundary[0]["first_seq"].as<uint64_t>() - 1;
                if (cut <= pruned) return 0;

                const auto deleted = txn.exec(
                    "DELETE FROM vault_replication_log WHERE id IN ("
                    "  SELECT id FROM vault_replication_log WHERE vault_id = $1 AND seq IS NOT NULL "
                    "    AND (term, seq) <= ($2::bigint, $3::bigint) ORDER BY term, seq LIMIT $4)",
                    pqxx::params{vaultId, static_cast<int64_t>(cut.term), static_cast<int64_t>(cut.seq), kPruneBatch})
                                         .affected_rows();
                // A partial batch reached the cut; a full one may not have: record only what is certainly gone.
                if (static_cast<int64_t>(deleted) < kPruneBatch) {
                    txn.exec("UPDATE mirror_vault SET pruned_term = $2, pruned_seq = $3, updated_at = CURRENT_TIMESTAMP "
                             "WHERE vault_id = $1",
                             pqxx::params{vaultId, static_cast<int64_t>(cut.term), static_cast<int64_t>(cut.seq)});
                } else {
                    const auto reached = txn.exec("SELECT term, seq FROM vault_replication_log WHERE vault_id = $1 "
                                                  "AND seq IS NOT NULL ORDER BY term, seq LIMIT 1",
                                                  pqxx::params{vaultId});
                    if (!reached.empty()) {
                        const Position first{reached[0][0].as<uint64_t>(), reached[0][1].as<uint64_t>()};
                        const auto through = first.seq > 1 ? Position{first.term, first.seq - 1} : pruned;
                        txn.exec("UPDATE mirror_vault SET pruned_term = $2, pruned_seq = $3, "
                                 "  updated_at = CURRENT_TIMESTAMP WHERE vault_id = $1",
                                 pqxx::params{vaultId, static_cast<int64_t>(through.term),
                                              static_cast<int64_t>(through.seq)});
                    }
                }
                return deleted;
            });
            out.rows += removed;
            if (static_cast<int64_t>(removed) < kPruneBatch) break;
        }
    }

    // Vaults that are not this server's core (any more): their rows and entry hashes have no reader.
    out.orphans = Transactions::exec("mirror::Log::pruneOrphans", [&](pqxx::work& txn) {
        uint64_t removed = 0;
        std::set<uint32_t> vaults;
        for (const auto id : vaultsOf(txn, "vault_replication_log", "seq IS NOT NULL")) vaults.insert(id);
        for (const auto id : vaultsOf(txn, "vault_replication_log", "seq IS NULL")) vaults.insert(id);
        for (const auto id : vaultsOf(txn, "mirror_entry_hash", "")) vaults.insert(id);
        for (const auto vaultId : vaults) {
            if (std::ranges::binary_search(cores, vaultId)) continue;
            const auto role = txn.exec("SELECT role FROM mirror_vault WHERE vault_id = $1", pqxx::params{vaultId});
            if (!role.empty() && role[0][0].as<std::string>() == "core")
                continue;   // became a core after the list above was read
            removed += txn.exec("DELETE FROM vault_replication_log WHERE vault_id = $1", pqxx::params{vaultId})
                           .affected_rows();
            // A mirror keeps the entry hashes of what it applied (its compare-and-set and digest; mirror::apply).
            if (role.empty())
                removed += txn.exec("DELETE FROM mirror_entry_hash WHERE vault_id = $1", pqxx::params{vaultId})
                               .affected_rows();
        }
        return removed;
    });
    return out;
}

std::vector<Row> Log::groupRows(const uint32_t vaultId, const uint64_t term, const uint64_t txid, const uint64_t afterSeq,
                                const std::size_t limit) {
    const auto rows = static_cast<int64_t>(std::clamp<std::size_t>(limit, 1, kMaxPageRows));
    return Transactions::exec("mirror::Log::groupRows", [&](pqxx::work& txn) {
        std::vector<Row> out;
        for (const auto row : txn.exec(std::string("SELECT ") + kLogColumns + " FROM vault_replication_log "
                                       "WHERE vault_id = $1 AND term = $2 AND txid = $3 AND seq IS NOT NULL AND seq > $4 "
                                       "ORDER BY seq LIMIT $5",
                                       pqxx::params{vaultId, static_cast<int64_t>(term), static_cast<int64_t>(txid),
                                                    static_cast<int64_t>(afterSeq), rows}))
            out.push_back(logRowFrom(row));
        return out;
    });
}

std::optional<std::pair<uint64_t, uint64_t>> Log::groupSpan(const uint32_t vaultId, const uint64_t term,
                                                            const uint64_t txid) {
    return Transactions::exec("mirror::Log::groupSpan", [&](pqxx::work& txn) -> std::optional<std::pair<uint64_t, uint64_t>> {
        const auto r = txn.exec("SELECT min(seq), max(seq) FROM vault_replication_log "
                                "WHERE vault_id = $1 AND term = $2 AND txid = $3 AND seq IS NOT NULL",
                                pqxx::params{vaultId, static_cast<int64_t>(term), static_cast<int64_t>(txid)});
        if (r.empty() || r[0][0].is_null()) return std::nullopt;
        return std::make_pair(r[0][0].as<uint64_t>(), r[0][1].as<uint64_t>());
    });
}

void Log::markMirrorApply(pqxx::work& txn) {
    txn.exec("SELECT set_config('vh.mirror_apply', 'on', true)");
}

void Log::markMirrorLocal(pqxx::work& txn) {
    txn.exec("SELECT set_config('vh.mirror_local', 'on', true)");
}

vh::mirror::Digest Digests::recompute(const uint32_t vaultId) {
    return Transactions::exec("mirror::Digests::recompute", [&](pqxx::work& txn) {
        const auto row = txn.exec("SELECT encode(vh_mirror_digest(entry_hash), 'hex') AS digest, count(*) AS entries "
                                  "FROM vh_mirror_tree($1)",
                                  pqxx::params{vaultId}).one_row();
        return vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(row["digest"].as<std::string>()),
                                             row["entries"].as<int64_t>());
    });
}

vh::mirror::Digest Digests::stored(const uint32_t vaultId) {
    return Transactions::exec("mirror::Digests::stored", [&](pqxx::work& txn) {
        const auto row = txn.exec("SELECT encode(vh_mirror_digest(entry_hash), 'hex') AS digest, count(*) AS entries "
                                  "FROM mirror_entry_hash WHERE vault_id = $1",
                                  pqxx::params{vaultId}).one_row();
        return vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(row["digest"].as<std::string>()),
                                             row["entries"].as<int64_t>());
    });
}

vh::mirror::Hash Digests::hashInDatabase(const nlohmann::json& state) {
    return Transactions::exec("mirror::Digests::hashInDatabase", [&](pqxx::work& txn) {
        return vh::mirror::hashFromHex(
            txn.exec("SELECT encode(vh_mirror_state_hash($1::jsonb), 'hex')", pqxx::params{state.dump()})
                .one_field()
                .as<std::string>());
    });
}

}
