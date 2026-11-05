#include "db/query/audit/Trail.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>

#include <stdexcept>

namespace vh::db::query::audit {

namespace {

using vh::audit::Hash;

Hash hashField(const pqxx::row_ref row, const char* column) {
    const auto parsed = vh::audit::hashFromHex(row[column].as<std::string>());
    if (!parsed) throw std::runtime_error(std::string("audit: malformed ") + column);
    return *parsed;
}

template <typename T>
std::optional<T> opt(const pqxx::row_ref row, const char* column) {
    if (row[column].is_null()) return std::nullopt;
    return row[column].as<T>();
}

constexpr const char* kRecordColumns =
    "seq, occurred_us, level, action, outcome, actor_id, actor, origin, vault_id, entry_id, message, details, "
    "encode(prev_hash, 'hex') AS prev_hash, encode(hash, 'hex') AS hash";

vh::audit::Record recordFrom(const pqxx::row_ref row) {
    vh::audit::Record r;
    r.seq = row["seq"].as<uint64_t>();
    r.occurred_us = row["occurred_us"].as<uint64_t>();
    r.level = row["level"].as<std::string>();
    r.action = row["action"].as<std::string>();
    r.outcome = row["outcome"].as<std::string>();
    r.actor_id = opt<uint32_t>(row, "actor_id");
    r.actor = row["actor"].as<std::string>();
    r.origin = row["origin"].as<std::string>();
    r.vault_id = opt<uint32_t>(row, "vault_id");
    r.entry_id = opt<uint64_t>(row, "entry_id");
    r.message = row["message"].as<std::string>();
    r.details = row["details"].as<std::string>();
    r.prev_hash = hashField(row, "prev_hash");
    r.hash = hashField(row, "hash");
    return r;
}

vh::audit::SignedHead headFrom(const pqxx::row_ref row) {
    vh::audit::SignedHead h;
    h.seq = row["seq"].as<uint64_t>();
    h.hash = hashField(row, "hash");
    h.signed_us = row["signed_us"].as<uint64_t>();
    h.node_id = row["node_id"].as<std::string>();
    h.key_id = row["key_id"].as<unsigned int>();
    const auto sig = row["signature"].as<std::string>();
    for (std::size_t i = 0; i + 1 < sig.size(); i += 2)
        h.signature.push_back(static_cast<uint8_t>(std::stoi(sig.substr(i, 2), nullptr, 16)));
    return h;
}

constexpr const char* kHeadColumns =
    "seq, encode(hash, 'hex') AS hash, signed_us, node_id, key_id, encode(signature, 'hex') AS signature";

}

std::optional<Tail> Trail::tail() {
    return Transactions::exec("audit::Trail::tail", [](pqxx::work& txn) -> std::optional<Tail> {
        auto res = txn.exec("SELECT seq, encode(hash, 'hex') AS hash FROM audit_event ORDER BY seq DESC LIMIT 1");
        if (res.empty())
            res = txn.exec("SELECT seq, encode(hash, 'hex') AS hash FROM audit_checkpoint ORDER BY seq DESC LIMIT 1");
        if (res.empty()) return std::nullopt;
        const auto row = res[0];
        return Tail{.seq = row["seq"].as<uint64_t>(), .hash = hashField(row, "hash")};
    });
}

void Trail::append(const std::vector<vh::audit::Record>& records) {
    if (records.empty()) return;
    Transactions::exec("audit::Trail::append", [&](pqxx::work& txn) {
        for (const auto& r : records) {
            txn.exec(
                "INSERT INTO audit_event (seq, occurred_us, level, action, outcome, actor_id, actor, origin, vault_id, "
                "entry_id, message, details, prev_hash, hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, "
                "$12, decode($13, 'hex'), decode($14, 'hex'))",
                pqxx::params{r.seq, r.occurred_us, r.level, r.action, r.outcome, r.actor_id, r.actor, r.origin,
                             r.vault_id, r.entry_id, r.message, r.details, vh::audit::toHex(r.prev_hash),
                             vh::audit::toHex(r.hash)});
        }
    });
}

void Trail::appendHead(const vh::audit::SignedHead& h) {
    Transactions::exec("audit::Trail::appendHead", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO audit_head (seq, hash, signed_us, node_id, key_id, signature) "
                 "VALUES ($1, decode($2, 'hex'), $3, $4, $5, decode($6, 'hex'))",
                 pqxx::params{h.seq, vh::audit::toHex(h.hash), h.signed_us, h.node_id, h.key_id,
                              vh::audit::toHex(h.signature)});
    });
}

std::optional<vh::audit::SignedHead> Trail::lastHead() {
    return Transactions::exec("audit::Trail::lastHead", [](pqxx::work& txn) -> std::optional<vh::audit::SignedHead> {
        const auto res = txn.exec(std::string("SELECT ") + kHeadColumns +
                                  " FROM audit_head ORDER BY seq DESC, signed_us DESC LIMIT 1");
        if (res.empty()) return std::nullopt;
        return headFrom(res[0]);
    });
}

std::vector<vh::audit::SignedHead> Trail::heads() {
    return Transactions::exec("audit::Trail::heads", [](pqxx::work& txn) {
        std::vector<vh::audit::SignedHead> out;
        for (const auto row : txn.exec(std::string("SELECT ") + kHeadColumns + " FROM audit_head ORDER BY seq, signed_us"))
            out.push_back(headFrom(row));
        return out;
    });
}

std::optional<vh::audit::Checkpoint> Trail::checkpoint() {
    return Transactions::exec("audit::Trail::checkpoint", [](pqxx::work& txn) -> std::optional<vh::audit::Checkpoint> {
        const auto res = txn.exec("SELECT seq, encode(hash, 'hex') AS hash, purged FROM audit_checkpoint "
                                  "ORDER BY seq DESC LIMIT 1");
        if (res.empty()) return std::nullopt;
        return vh::audit::Checkpoint{.seq = res[0]["seq"].as<uint64_t>(), .hash = hashField(res[0], "hash"),
                                     .purged = res[0]["purged"].as<uint64_t>()};
    });
}

std::vector<vh::audit::Record> Trail::range(const uint64_t afterSeq, const std::size_t limit) {
    return Transactions::exec("audit::Trail::range", [&](pqxx::work& txn) {
        std::vector<vh::audit::Record> out;
        const auto res = txn.exec(std::string("SELECT ") + kRecordColumns +
                                      " FROM audit_event WHERE seq > $1 ORDER BY seq LIMIT $2",
                                  pqxx::params{afterSeq, static_cast<int64_t>(limit)});
        out.reserve(res.size());
        for (const auto row : res) out.push_back(recordFrom(row));
        return out;
    });
}

std::vector<vh::audit::Record> Trail::list(const Filter& f, const std::size_t limit) {
    return Transactions::exec("audit::Trail::list", [&](pqxx::work& txn) {
        std::vector<vh::audit::Record> out;
        const auto res = txn.exec(
            std::string("SELECT ") + kRecordColumns +
                " FROM audit_event WHERE ($1::bigint IS NULL OR seq < $1) "
                "AND ($2::bigint IS NULL OR occurred_us >= $2) AND ($3::bigint IS NULL OR occurred_us < $3) "
                "AND ($4::text IS NULL OR starts_with(action, $4)) AND ($5::int IS NULL OR actor_id = $5) "
                "AND ($6::int IS NULL OR vault_id = $6) AND ($7::text IS NULL OR outcome = $7) "
                "ORDER BY seq DESC LIMIT $8",
            pqxx::params{f.before_seq, f.since_us, f.until_us, f.action_prefix, f.actor_id, f.vault_id, f.outcome,
                         static_cast<int64_t>(limit)});
        out.reserve(res.size());
        for (const auto row : res) out.push_back(recordFrom(row));
        return out;
    });
}

uint64_t Trail::count() {
    return Transactions::exec("audit::Trail::count", [](pqxx::work& txn) {
        return txn.exec("SELECT COUNT(*) FROM audit_event").one_field().as<uint64_t>();
    });
}

uint64_t Trail::purgeBefore(const uint64_t cutoffUs) {
    return Transactions::exec("audit::Trail::purgeBefore", [&](pqxx::work& txn) {
        return txn.exec("SELECT vh_audit_purge_before($1)", pqxx::params{cutoffUs}).one_field().as<uint64_t>();
    });
}

}
