#include "db/query/peer/Peer.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "device/Crypto.hpp"
#include "ops/Error.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <algorithm>

namespace vh::db::query::peer {

namespace {

using json = nlohmann::json;

constexpr const char* kPeerColumns = R"SQL(
    id, node_id, name, spki_sha256, next_spki_sha256, rotate_counter, attest_public_keys::text AS attest_public_keys,
    wrap_public_key, endpoints::text AS endpoints, sharing, approved_by, compared_by, peer_protocol, product_version,
    EXTRACT(EPOCH FROM linked_at)::BIGINT AS linked_at, EXTRACT(EPOCH FROM last_seen_at)::BIGINT AS last_seen_at,
    EXTRACT(EPOCH FROM revoked_at)::BIGINT AS revoked_at
)SQL";

std::string selectPeers(const std::string& where) { return std::string("SELECT ") + kPeerColumns + " FROM peer " + where; }

vh::peer::Key32 key32(const std::vector<uint8_t>& raw) {
    vh::peer::Key32 out{};
    if (raw.size() == out.size()) std::ranges::copy(raw, out.begin());
    return out;
}

Record peerFromRow(const pqxx::row_ref row) {
    Record r;
    r.id = row["id"].as<uint32_t>();
    r.node_id = row["node_id"].as<std::string>();
    r.name = row["name"].as<std::string>();
    r.spki_sha256 = row["spki_sha256"].as<std::string>();
    if (!row["next_spki_sha256"].is_null()) r.next_spki_sha256 = row["next_spki_sha256"].as<std::string>();
    r.rotate_counter = row["rotate_counter"].as<uint64_t>();
    for (const auto& k : json::parse(row["attest_public_keys"].as<std::string>()))
        if (k.is_string())
            if (const auto raw = vh::device::crypto::fromBase64(k.get<std::string>()); raw && raw->size() == 32)
                r.attest_public_keys.push_back(key32(*raw));
    r.wrap_public_key = key32(encoding::from_hex_bytea(row["wrap_public_key"].as<std::string>()));
    // Written by this server only (validated on the way in): what it stored, it reads back.
    try {
        r.endpoints = vh::peer::endpointsFromJson(json::parse(row["endpoints"].as<std::string>()));
    } catch (const ops::Error&) {
        r.endpoints.clear();
    }
    r.sharing = row["sharing"].as<std::string>();
    if (!row["approved_by"].is_null()) r.approved_by = row["approved_by"].as<uint32_t>();
    r.compared_by = row["compared_by"].as<std::string>();
    r.peer_protocol = row["peer_protocol"].as<uint32_t>();
    r.product_version = row["product_version"].as<std::string>();
    r.linked_at = static_cast<std::time_t>(row["linked_at"].as<int64_t>());
    if (!row["last_seen_at"].is_null()) r.last_seen_at = static_cast<std::time_t>(row["last_seen_at"].as<int64_t>());
    if (!row["revoked_at"].is_null()) r.revoked_at = static_cast<std::time_t>(row["revoked_at"].as<int64_t>());
    return r;
}

std::optional<Record> onePeer(const pqxx::result& res) {
    if (res.empty()) return std::nullopt;
    return peerFromRow(res.one_row_ref());
}

std::string keysJson(const std::vector<vh::peer::Key32>& keys) {
    json out = json::array();
    for (const auto& k : keys) out.push_back(vh::device::crypto::toBase64(k));
    return out.dump();
}

}

std::optional<Record> Peers::byId(const uint32_t id) {
    return Transactions::read("Peers::byId", [&](pqxx::transaction_base& txn) {
        return onePeer(txn.exec(selectPeers("WHERE id = $1"), pqxx::params{id}));
    });
}

std::optional<Record> Peers::liveBySpki(const std::string& spkiHex) {
    return Transactions::read("Peers::liveBySpki", [&](pqxx::transaction_base& txn) {
        return onePeer(txn.exec(selectPeers("WHERE revoked_at IS NULL AND (spki_sha256 = $1 OR next_spki_sha256 = $1) "
                                            "ORDER BY (spki_sha256 = $1) DESC, id LIMIT 1"),
                                pqxx::params{spkiHex}));
    });
}

std::optional<Record> Peers::liveByNodeId(const std::string& nodeId) {
    return Transactions::read("Peers::liveByNodeId", [&](pqxx::transaction_base& txn) {
        return onePeer(txn.exec(selectPeers("WHERE revoked_at IS NULL AND node_id = $1"), pqxx::params{nodeId}));
    });
}

bool Peers::spkiKnown(const std::string& spkiHex) {
    return Transactions::read("Peers::spkiKnown", [&](pqxx::transaction_base& txn) {
        return !txn.exec("SELECT 1 FROM peer WHERE spki_sha256 = $1 OR next_spki_sha256 = $1 LIMIT 1",
                         pqxx::params{spkiHex})
                    .empty();
    });
}

std::vector<Record> Peers::listAll() {
    return Transactions::read("Peers::listAll", [&](pqxx::transaction_base& txn) {
        return mapRows(txn.exec(selectPeers("ORDER BY id")), peerFromRow);
    });
}

std::vector<Record> Peers::listLive() {
    return Transactions::read("Peers::listLive", [&](pqxx::transaction_base& txn) {
        return mapRows(txn.exec(selectPeers("WHERE revoked_at IS NULL ORDER BY id")), peerFromRow);
    });
}

std::size_t Peers::countLive() {
    return Transactions::read("Peers::countLive", [&](pqxx::transaction_base& txn) {
        return txn.exec("SELECT count(*) FROM peer WHERE revoked_at IS NULL").one_field_ref().as<std::size_t>();
    });
}

Record Peers::insert(const NewPeer& p) {
    try {
        return Transactions::exec("Peers::insert", [&](pqxx::work& txn) {
            // A key a live row announced as its next one is that peer's too.
            if (!txn.exec("SELECT 1 FROM peer WHERE revoked_at IS NULL AND next_spki_sha256 = $1",
                          pqxx::params{p.spki_sha256})
                     .empty())
                throw ops::Conflict("this server key is already linked here");
            const auto res = txn.exec(
                "INSERT INTO peer (node_id, name, spki_sha256, attest_public_keys, wrap_public_key, endpoints, "
                "approved_by, compared_by, peer_protocol, product_version, last_seen_at) "
                "VALUES ($1, $2, $3, $4::jsonb, $5, $6::jsonb, $7, $8, $9, $10, CURRENT_TIMESTAMP) RETURNING id",
                pqxx::params{p.node_id, p.name, p.spki_sha256, keysJson(p.attest_public_keys),
                             encoding::to_hex_bytea(std::vector<uint8_t>(p.wrap_public_key.begin(),
                                                                         p.wrap_public_key.end())),
                             vh::peer::toJson(p.endpoints).dump(), p.approved_by, p.compared_by, p.peer_protocol,
                             p.product_version});
            const auto id = res.one_field_ref().as<uint32_t>();
            return peerFromRow(txn.exec(selectPeers("WHERE id = $1"), pqxx::params{id}).one_row_ref());
        });
    } catch (const pqxx::unique_violation&) {
        throw ops::Conflict("this server is already linked here (unlink it first to link it again)");
    }
}

std::optional<Record> Peers::rename(const uint32_t id, const std::string& name) {
    return Transactions::exec("Peers::rename", [&](pqxx::work& txn) -> std::optional<Record> {
        if (txn.exec("UPDATE peer SET name = $2 WHERE id = $1", pqxx::params{id, name}).affected_rows() == 0)
            return std::nullopt;
        return onePeer(txn.exec(selectPeers("WHERE id = $1"), pqxx::params{id}));
    });
}

std::optional<Record> Peers::revoke(const uint32_t id) {
    return Transactions::exec("Peers::revoke", [&](pqxx::work& txn) -> std::optional<Record> {
        txn.exec("UPDATE peer SET revoked_at = CURRENT_TIMESTAMP, next_spki_sha256 = NULL "
                 "WHERE id = $1 AND revoked_at IS NULL",
                 pqxx::params{id});
        return onePeer(txn.exec(selectPeers("WHERE id = $1"), pqxx::params{id}));
    });
}

std::size_t Peers::revokeAllExcept(const std::vector<uint32_t>& keep) {
    return Transactions::exec("Peers::revokeAllExcept", [&](pqxx::work& txn) {
        std::string ids = "{";
        for (std::size_t i = 0; i < keep.size(); ++i) ids += (i ? "," : "") + std::to_string(keep[i]);
        ids += "}";
        return static_cast<std::size_t>(
            txn.exec("UPDATE peer SET revoked_at = CURRENT_TIMESTAMP, next_spki_sha256 = NULL "
                     "WHERE revoked_at IS NULL AND NOT (id = ANY($1::bigint[]))",
                     pqxx::params{ids})
                .affected_rows());
    });
}

void Peers::setEndpoints(const uint32_t id, const std::vector<vh::peer::Endpoint>& endpoints) {
    Transactions::exec("Peers::setEndpoints", [&](pqxx::work& txn) {
        txn.exec("UPDATE peer SET endpoints = $2::jsonb WHERE id = $1 AND revoked_at IS NULL",
                 pqxx::params{id, vh::peer::toJson(endpoints).dump()});
    });
}

void Peers::recordHello(const uint32_t id, const uint32_t peerProtocol, const std::string& productVersion) {
    Transactions::exec("Peers::recordHello", [&](pqxx::work& txn) {
        txn.exec("UPDATE peer SET peer_protocol = $2, product_version = $3, last_seen_at = CURRENT_TIMESTAMP "
                 "WHERE id = $1 AND revoked_at IS NULL",
                 pqxx::params{id, peerProtocol, productVersion});
    });
}

void Peers::touch(const uint32_t id) {
    Transactions::exec("Peers::touch", [&](pqxx::work& txn) {
        txn.exec("UPDATE peer SET last_seen_at = CURRENT_TIMESTAMP WHERE id = $1 AND revoked_at IS NULL",
                 pqxx::params{id});
    });
}

bool Peers::announceNext(const uint32_t id, const std::string& nextSpki, const uint64_t counter) {
    return Transactions::exec("Peers::announceNext", [&](pqxx::work& txn) {
        return txn.exec("UPDATE peer SET next_spki_sha256 = $2, rotate_counter = $3 "
                        "WHERE id = $1 AND revoked_at IS NULL AND rotate_counter < $3 AND spki_sha256 <> $2",
                        pqxx::params{id, nextSpki, static_cast<int64_t>(counter)})
                   .affected_rows() == 1;
    });
}

bool Peers::promoteNext(const uint32_t id, const std::string& spkiHex) {
    return Transactions::exec("Peers::promoteNext", [&](pqxx::work& txn) {
        return txn.exec("UPDATE peer SET spki_sha256 = next_spki_sha256, next_spki_sha256 = NULL "
                        "WHERE id = $1 AND revoked_at IS NULL AND next_spki_sha256 = $2",
                        pqxx::params{id, spkiHex})
                   .affected_rows() == 1;
    });
}

}
