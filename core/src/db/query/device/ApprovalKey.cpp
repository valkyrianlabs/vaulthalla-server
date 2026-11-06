#include "db/query/device/ApprovalKey.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "ops/Error.hpp"

#include <pqxx/pqxx>

namespace vh::db::query::device {

namespace {

constexpr const char* kApprovalKeyColumns =
    "device_id, public_key_spki, spki_sha256, registered_via, EXTRACT(EPOCH FROM registered_at)::BIGINT AS "
    "registered_at, EXTRACT(EPOCH FROM revoked_at)::BIGINT AS revoked_at";

ApprovalKey approvalKeyFromRow(const pqxx::row_ref row) {
    ApprovalKey k;
    k.device_id = row["device_id"].as<uint32_t>();
    k.public_key_spki = db::encoding::from_hex_bytea(row["public_key_spki"].as<std::string>());
    k.spki_sha256 = row["spki_sha256"].as<std::string>();
    k.registered_via = row["registered_via"].as<std::string>();
    k.registered_at = static_cast<std::time_t>(row["registered_at"].as<int64_t>());
    if (!row["revoked_at"].is_null()) k.revoked_at = static_cast<std::time_t>(row["revoked_at"].as<int64_t>());
    return k;
}

}

std::optional<ApprovalKey> ApprovalKeys::forDevice(const uint32_t deviceId) {
    return Transactions::read("ApprovalKeys::forDevice", [&](pqxx::transaction_base& txn) -> std::optional<ApprovalKey> {
        const auto res = txn.exec(std::string("SELECT ") + kApprovalKeyColumns +
                                      " FROM device_approval_keys WHERE device_id = $1",
                                  pqxx::params{deviceId});
        if (res.empty()) return std::nullopt;
        return approvalKeyFromRow(res.one_row_ref());
    });
}

bool ApprovalKeys::known(const std::string& spkiSha256) {
    return Transactions::read("ApprovalKeys::known", [&](pqxx::transaction_base& txn) {
        return !txn.exec("SELECT 1 FROM device_approval_keys WHERE spki_sha256 = $1 "
                         "UNION ALL SELECT 1 FROM devices WHERE spki_sha256 = $1 OR previous_spki_sha256 = $1 LIMIT 1",
                         pqxx::params{spkiSha256})
                    .empty();
    });
}

ApprovalKey ApprovalKeys::registerKey(const uint32_t deviceId, const std::vector<uint8_t>& spkiDer,
                                      const std::string& spkiSha256, const std::string& via) {
    try {
        return Transactions::exec("ApprovalKeys::registerKey", [&](pqxx::work& txn) {
            // The device row is locked so a revocation can't slip between the check and the insert.
            if (txn.exec("SELECT 1 FROM devices WHERE id = $1 AND revoked_at IS NULL FOR UPDATE", pqxx::params{deviceId})
                    .empty())
                throw ops::Conflict("this device is not paired with this node");
            if (!txn.exec("SELECT 1 FROM devices WHERE spki_sha256 = $1 OR previous_spki_sha256 = $1",
                          pqxx::params{spkiSha256})
                     .empty())
                throw ops::Conflict("an approval key must not be a device key");
            const auto res = txn.exec(std::string("INSERT INTO device_approval_keys (device_id, public_key_spki, "
                                                  "spki_sha256, registered_via) VALUES ($1, $2, $3, $4) "
                                                  "ON CONFLICT DO NOTHING RETURNING ") +
                                          kApprovalKeyColumns,
                                      pqxx::params{deviceId, db::encoding::to_hex_bytea(spkiDer), spkiSha256, via});
            if (res.empty())
                throw ops::Conflict("this device already has an approval key, or the key is known to this node");
            return approvalKeyFromRow(res.one_row_ref());
        });
    } catch (const pqxx::unique_violation&) {
        throw ops::Conflict("this device already has an approval key, or the key is known to this node");
    }
}

bool ApprovalKeys::revoke(const uint32_t deviceId) {
    return Transactions::exec("ApprovalKeys::revoke", [&](pqxx::work& txn) {
        return txn.exec("UPDATE device_approval_keys SET revoked_at = NOW() WHERE device_id = $1 AND revoked_at IS NULL",
                        pqxx::params{deviceId})
                   .affected_rows() == 1;
    });
}

}
