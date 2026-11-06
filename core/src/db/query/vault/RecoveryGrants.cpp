#include "db/query/vault/RecoveryGrants.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"

#include <pqxx/pqxx>

namespace vh::db::query::vault {

namespace recovery_grants_detail {

constexpr const char* kColumns =
    "vault_id, grant_id, recipient_id, public_key, suite, class, label, "
    "EXTRACT(EPOCH FROM added_at)::bigint AS added_at, authorized_by, "
    "EXTRACT(EPOCH FROM revoked_at)::bigint AS revoked_at, revoked_by";

RecoveryGrant grantFrom(const pqxx::row_ref row) {
    RecoveryGrant g;
    g.vault_id = row["vault_id"].as<uint32_t>();
    g.grant_id = row["grant_id"].as<std::string>();
    g.recipient_id = row["recipient_id"].as<std::string>();
    g.public_key = encoding::from_hex_bytea(row["public_key"].as<std::string>());
    g.suite = row["suite"].as<uint16_t>();
    g.recipient_class = row["class"].as<std::string>();
    if (!row["label"].is_null()) g.label = row["label"].as<std::string>();
    g.added_at = row["added_at"].as<std::time_t>();
    g.authorized_by = row["authorized_by"].as<std::string>();
    if (!row["revoked_at"].is_null()) g.revoked_at = row["revoked_at"].as<std::time_t>();
    if (!row["revoked_by"].is_null()) g.revoked_by = row["revoked_by"].as<std::string>();
    return g;
}

std::string intArray(const std::vector<uint32_t>& values) {
    std::string out = "{";
    for (std::size_t i = 0; i < values.size(); ++i) out += (i ? "," : "") + std::to_string(values[i]);
    return out + "}";
}

}

std::vector<RecoveryGrant> RecoveryGrants::list(const uint32_t vaultId) {
    using namespace recovery_grants_detail;
    return Transactions::exec("RecoveryGrants::list", [&](pqxx::work& txn) {
        std::vector<RecoveryGrant> out;
        for (const auto row : txn.exec(std::string("SELECT ") + kColumns +
                                       " FROM vault_recovery_grant WHERE vault_id = $1 ORDER BY added_at, grant_id",
                                       pqxx::params{vaultId}))
            out.push_back(grantFrom(row));
        return out;
    });
}

std::vector<RecoveryGrant> RecoveryGrants::usable(const uint32_t vaultId) {
    auto all = list(vaultId);
    std::erase_if(all, [](const RecoveryGrant& g) { return !g.usable(); });
    return all;
}

std::optional<RecoveryGrant> RecoveryGrants::get(const uint32_t vaultId, const std::string& grantId) {
    using namespace recovery_grants_detail;
    return Transactions::exec("RecoveryGrants::get", [&](pqxx::work& txn) -> std::optional<RecoveryGrant> {
        const auto res = txn.exec(std::string("SELECT ") + kColumns +
                                  " FROM vault_recovery_grant WHERE vault_id = $1 AND grant_id = $2",
                                  pqxx::params{vaultId, grantId});
        if (res.empty()) return std::nullopt;
        return grantFrom(res[0]);
    });
}

bool RecoveryGrants::add(const RecoveryGrant& g) {
    return Transactions::exec("RecoveryGrants::add", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "INSERT INTO vault_recovery_grant (vault_id, grant_id, recipient_id, public_key, suite, class, label, "
            "  authorized_by) "
            "VALUES ($1, $2, $3, $4::bytea, $5, $6, $7, $8) "
            "ON CONFLICT (vault_id, recipient_id) WHERE revoked_at IS NULL DO NOTHING RETURNING 1",
            pqxx::params{g.vault_id, g.grant_id, g.recipient_id, encoding::to_hex_bytea(g.public_key),
                         static_cast<int>(g.suite), g.recipient_class, g.label, g.authorized_by});
        return !res.empty();
    });
}

bool RecoveryGrants::revoke(const uint32_t vaultId, const std::string& grantId, const std::string& revokedBy) {
    return Transactions::exec("RecoveryGrants::revoke", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "UPDATE vault_recovery_grant SET revoked_at = CURRENT_TIMESTAMP, revoked_by = $3 "
            "WHERE vault_id = $1 AND grant_id = $2 AND revoked_at IS NULL RETURNING 1",
            pqxx::params{vaultId, grantId, revokedBy});
        return !res.empty();
    });
}

std::vector<KeyEnvelope> RecoveryGrants::envelopes(const uint32_t vaultId) {
    return Transactions::exec("RecoveryGrants::envelopes", [&](pqxx::work& txn) {
        std::vector<KeyEnvelope> out;
        for (const auto row : txn.exec("SELECT grant_id, key_version, kid FROM vault_key_envelope WHERE vault_id = $1 "
                                       "ORDER BY key_version, kid",
                                       pqxx::params{vaultId}))
            out.push_back({row[0].as<std::string>(), row[1].as<uint32_t>(), row[2].as<std::string>()});
        return out;
    });
}

void RecoveryGrants::recordEnvelopes(const uint32_t vaultId, const uint32_t keyVersion,
                                     const std::vector<KeyEnvelope>& written) {
    if (written.empty()) return;
    Transactions::exec("RecoveryGrants::recordEnvelopes", [&](pqxx::work& txn) {
        for (const auto& e : written)
            txn.exec("INSERT INTO vault_key_envelope (vault_id, grant_id, key_version, kid) VALUES ($1, $2, $3, $4) "
                     "ON CONFLICT (vault_id, grant_id, key_version) DO NOTHING",
                     pqxx::params{vaultId, e.grant_id, keyVersion, e.kid});
    });
}

std::vector<RecoveryGrant> RecoveryGrants::missingFor(const uint32_t vaultId, const uint32_t keyVersion) {
    using namespace recovery_grants_detail;
    return Transactions::exec("RecoveryGrants::missingFor", [&](pqxx::work& txn) {
        std::vector<RecoveryGrant> out;
        for (const auto row : txn.exec(
                 std::string("SELECT ") + kColumns +
                     " FROM vault_recovery_grant g WHERE g.vault_id = $1 AND g.revoked_at IS NULL "
                     "AND g.class = 'customer' AND NOT EXISTS (SELECT 1 FROM vault_key_envelope e "
                     "  WHERE e.vault_id = g.vault_id AND e.grant_id = g.grant_id AND e.key_version = $2) "
                     "ORDER BY g.added_at, g.grant_id",
                 pqxx::params{vaultId, keyVersion}))
            out.push_back(grantFrom(row));
        return out;
    });
}

std::vector<uint32_t> RecoveryGrants::uncovered(const uint32_t vaultId, const std::vector<uint32_t>& versions) {
    using namespace recovery_grants_detail;
    if (versions.empty()) return {};
    return Transactions::exec("RecoveryGrants::uncovered", [&](pqxx::work& txn) {
        std::vector<uint32_t> out;
        for (const auto row : txn.exec(
                 "SELECT v FROM unnest($2::int[]) AS v WHERE NOT EXISTS (SELECT 1 FROM vault_key_envelope e "
                 "  JOIN vault_recovery_grant g ON g.grant_id = e.grant_id "
                 "  WHERE e.vault_id = $1 AND e.key_version = v AND g.revoked_at IS NULL AND g.class = 'customer') "
                 "ORDER BY v",
                 pqxx::params{vaultId, intArray(versions)}))
            out.push_back(row[0].as<uint32_t>());
        return out;
    });
}

bool RecoveryGrants::revokedWithAccess(const uint32_t vaultId, const std::vector<uint32_t>& versions) {
    using namespace recovery_grants_detail;
    if (versions.empty()) return false;
    return Transactions::exec("RecoveryGrants::revokedWithAccess", [&](pqxx::work& txn) {
        return !txn.exec("SELECT 1 FROM vault_key_envelope e JOIN vault_recovery_grant g ON g.grant_id = e.grant_id "
                         "WHERE e.vault_id = $1 AND g.revoked_at IS NOT NULL AND e.key_version = ANY($2::int[]) "
                         "LIMIT 1",
                         pqxx::params{vaultId, intArray(versions)})
                    .empty();
    });
}

}
