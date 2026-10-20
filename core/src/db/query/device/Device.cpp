#include "db/query/device/Device.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "ops/Error.hpp"

#include <pqxx/pqxx>

namespace vh::db::query::device {

namespace {

constexpr const char* kColumns = R"SQL(
    d.id, d.user_id, COALESCE(u.name, '') AS user_name, d.name, d.platform, d.app_version, d.spki_sha256,
    d.previous_spki_sha256, d.approved_by, EXTRACT(EPOCH FROM d.created_at)::BIGINT AS created_at,
    EXTRACT(EPOCH FROM d.last_seen_at)::BIGINT AS last_seen_at, d.last_ip,
    EXTRACT(EPOCH FROM d.revoked_at)::BIGINT AS revoked_at
)SQL";

std::string select(const std::string& where) {
    return std::string("SELECT ") + kColumns + " FROM devices d LEFT JOIN users u ON u.id = d.user_id " + where;
}

template <class T>
std::optional<T> opt(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return f.as<T>();
}

Device fromRow(const pqxx::row_ref row) {
    Device d;
    d.id = row["id"].as<uint32_t>();
    d.user_id = row["user_id"].as<uint32_t>();
    d.user_name = row["user_name"].as<std::string>();
    d.name = row["name"].as<std::string>();
    d.platform = row["platform"].as<std::string>();
    d.app_version = row["app_version"].as<std::string>();
    d.spki_sha256 = row["spki_sha256"].as<std::string>();
    d.previous_spki_sha256 = opt<std::string>(row["previous_spki_sha256"]);
    d.approved_by = opt<uint32_t>(row["approved_by"]);
    d.created_at = static_cast<std::time_t>(row["created_at"].as<int64_t>());
    if (const auto t = opt<int64_t>(row["last_seen_at"])) d.last_seen_at = static_cast<std::time_t>(*t);
    d.last_ip = opt<std::string>(row["last_ip"]);
    if (const auto t = opt<int64_t>(row["revoked_at"])) d.revoked_at = static_cast<std::time_t>(*t);
    return d;
}

std::optional<Device> one(const pqxx::result& res) {
    if (res.empty()) return std::nullopt;
    return fromRow(res.one_row_ref());
}

}

std::optional<Device> Devices::byId(const uint32_t id) {
    return Transactions::read("Devices::byId", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(select("WHERE d.id = $1"), pqxx::params{id});
        return one(res);
    });
}

std::optional<Device> Devices::byCurrentSpki(const std::string& spkiHex) {
    return Transactions::read("Devices::byCurrentSpki", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(select("WHERE d.spki_sha256 = $1"), pqxx::params{spkiHex});
        return one(res);
    });
}

std::optional<Device> Devices::byAnySpki(const std::string& spkiHex) {
    return Transactions::read("Devices::byAnySpki", [&](pqxx::transaction_base& txn) {
        // At most one row each way (UNIQUE spki, unique partial index on the previous key); the current key wins.
        const auto res = txn.exec(select("WHERE d.spki_sha256 = $1 OR d.previous_spki_sha256 = $1 "
                                         "ORDER BY (d.spki_sha256 = $1) DESC LIMIT 1"),
                                  pqxx::params{spkiHex});
        return one(res);
    });
}

bool Devices::spkiKnown(const std::string& spkiHex) {
    return Transactions::read("Devices::spkiKnown", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec("SELECT 1 FROM devices WHERE spki_sha256 = $1 OR previous_spki_sha256 = $1 LIMIT 1",
                                  pqxx::params{spkiHex});
        return !res.empty();
    });
}

std::vector<Device> Devices::listForUser(const uint32_t userId) {
    return Transactions::read("Devices::listForUser", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(select("WHERE d.user_id = $1 ORDER BY d.id"), pqxx::params{userId});
        return mapRows(res, fromRow);
    });
}

std::vector<Device> Devices::listAll() {
    return Transactions::read("Devices::listAll", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(select("ORDER BY d.id"));
        return mapRows(res, fromRow);
    });
}

Device Devices::insert(const NewDevice& d) {
    try {
        return Transactions::exec("Devices::insert", [&](pqxx::work& txn) {
            // UNIQUE(spki_sha256) covers current keys; a key that is some device's previous one is refused too.
            if (!txn.exec("SELECT 1 FROM devices WHERE previous_spki_sha256 = $1", pqxx::params{d.spki_sha256}).empty())
                throw ops::Conflict("this device key is already known to this node");
            const auto res = txn.exec(
                "INSERT INTO devices (user_id, approved_by, name, platform, app_version, spki_sha256, last_ip) "
                "VALUES ($1, $2, $3, $4, $5, $6, NULLIF($7, '')) RETURNING id",
                pqxx::params{d.user_id, d.approved_by, d.name, d.platform, d.app_version, d.spki_sha256, d.last_ip});
            const auto id = res.one_field_ref().as<uint32_t>();
            const auto row = txn.exec(select("WHERE d.id = $1"), pqxx::params{id});
            return fromRow(row.one_row_ref());
        });
    } catch (const pqxx::unique_violation&) {
        throw ops::Conflict("this device key is already known to this node");
    }
}

std::optional<Device> Devices::rename(const uint32_t id, const std::string& name) {
    return Transactions::exec("Devices::rename", [&](pqxx::work& txn) -> std::optional<Device> {
        if (txn.exec("UPDATE devices SET name = $2 WHERE id = $1", pqxx::params{id, name}).affected_rows() == 0)
            return std::nullopt;
        const auto res = txn.exec(select("WHERE d.id = $1"), pqxx::params{id});
        return one(res);
    });
}

std::optional<Device> Devices::revoke(const uint32_t id) {
    return Transactions::exec("Devices::revoke", [&](pqxx::work& txn) -> std::optional<Device> {
        // Both keys stay recorded: a revoked key can never be approved again (spec §6).
        txn.exec("UPDATE devices SET revoked_at = CURRENT_TIMESTAMP WHERE id = $1 AND revoked_at IS NULL",
                 pqxx::params{id});
        const auto res = txn.exec(select("WHERE d.id = $1"), pqxx::params{id});
        return one(res);
    });
}

bool Devices::rotate(const uint32_t id, const std::string& oldSpki, const std::string& newSpki) {
    try {
        return Transactions::exec("Devices::rotate", [&](pqxx::work& txn) {
            return txn.exec("UPDATE devices SET previous_spki_sha256 = spki_sha256, spki_sha256 = $3 "
                            "WHERE id = $1 AND spki_sha256 = $2 AND revoked_at IS NULL",
                            pqxx::params{id, oldSpki, newSpki})
                       .affected_rows() == 1;
        });
    } catch (const pqxx::unique_violation&) {
        throw ops::Conflict("the new device key is already known to this node");
    }
}

void Devices::clearPrevious(const uint32_t id, const std::string& currentSpki) {
    Transactions::exec("Devices::clearPrevious", [&](pqxx::work& txn) {
        txn.exec("UPDATE devices SET previous_spki_sha256 = NULL "
                 "WHERE id = $1 AND spki_sha256 = $2 AND previous_spki_sha256 IS NOT NULL",
                 pqxx::params{id, currentSpki});
    });
}

void Devices::touch(const uint32_t id, const std::string& ip) {
    Transactions::exec("Devices::touch", [&](pqxx::work& txn) {
        txn.exec("UPDATE devices SET last_seen_at = CURRENT_TIMESTAMP, last_ip = NULLIF($2, '') "
                 "WHERE id = $1 AND (last_seen_at IS NULL OR last_seen_at < CURRENT_TIMESTAMP - INTERVAL '60 seconds' "
                 "OR last_ip IS DISTINCT FROM NULLIF($2, ''))",
                 pqxx::params{id, ip});
    });
}

std::string Devices::nodeId() {
    return Transactions::exec("Devices::nodeId", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO device_node (singleton, node_id) VALUES (TRUE, gen_random_uuid()::text) "
                 "ON CONFLICT (singleton) DO NOTHING");
        return txn.exec("SELECT node_id FROM device_node WHERE singleton").one_field_ref().as<std::string>();
    });
}

}
