#include "db/query/vault/ReadGrants.hpp"

#include "db/Transactions.hpp"

#include <pqxx/pqxx>

#include <sstream>

namespace vh::db::query::vault {

namespace read_grants_detail {

constexpr const char* kRecipientColumns =
    "id, fingerprint, label, user_ids, algorithm, EXTRACT(EPOCH FROM key_created_at)::bigint AS key_created_at, "
    "EXTRACT(EPOCH FROM key_expires_at)::bigint AS key_expires_at, public_key, source, source_url, pinned_by, "
    "pinned_by_name, EXTRACT(EPOCH FROM pinned_at)::bigint AS pinned_at, "
    "EXTRACT(EPOCH FROM removed_at)::bigint AS removed_at, removed_by";

constexpr const char* kGrantColumns =
    "g.id, g.grant_id, g.vault_id, g.vault_name, g.state, g.gateway_only, g.gateway_credential_id, "
    "g.gateway_access_key, g.gateway_bucket, g.api_key_id, g.upstream_provider, g.upstream_endpoint, "
    "g.upstream_region, g.upstream_bucket, g.upstream_key_id, g.upstream_key_name, g.issued_by, g.issued_by_name, "
    "EXTRACT(EPOCH FROM g.issued_at)::bigint AS issued_at, EXTRACT(EPOCH FROM g.revoked_at)::bigint AS revoked_at, "
    "g.revoked_by, g.revocation_error, g.ciphertext, "
    "COALESCE((SELECT string_agg(r.fingerprint, ',' ORDER BY r.fingerprint) FROM vault_read_grant_recipient r "
    "          WHERE r.grant_row_id = g.id), '') AS recipients";

template<typename T>
std::optional<T> opt(const pqxx::row_ref row, const char* name) {
    if (row[name].is_null()) return std::nullopt;
    return row[name].as<T>();
}

std::vector<std::string> splitOn(const std::string& text, const char sep) {
    std::vector<std::string> out;
    std::string item;
    std::istringstream in(text);
    while (std::getline(in, item, sep))
        if (!item.empty()) out.push_back(item);
    return out;
}

std::string joinLines(const std::vector<std::string>& items) {
    std::string out;
    for (const auto& i : items) out += (out.empty() ? "" : "\n") + i;
    return out;
}

ReadGrantRecipient recipientFrom(const pqxx::row_ref row) {
    ReadGrantRecipient r;
    r.id = row["id"].as<uint32_t>();
    r.fingerprint = row["fingerprint"].as<std::string>();
    r.label = opt<std::string>(row, "label");
    r.user_ids = splitOn(row["user_ids"].as<std::string>(), '\n');
    r.algorithm = row["algorithm"].as<std::string>();
    r.key_created_at = opt<std::time_t>(row, "key_created_at");
    r.key_expires_at = opt<std::time_t>(row, "key_expires_at");
    r.public_key = row["public_key"].as<std::string>();
    r.source = row["source"].as<std::string>();
    r.source_url = opt<std::string>(row, "source_url");
    r.pinned_by = opt<uint32_t>(row, "pinned_by");
    r.pinned_by_name = row["pinned_by_name"].as<std::string>();
    r.pinned_at = row["pinned_at"].as<std::time_t>();
    r.removed_at = opt<std::time_t>(row, "removed_at");
    r.removed_by = opt<std::string>(row, "removed_by");
    return r;
}

ReadGrant grantFrom(const pqxx::row_ref row) {
    ReadGrant g;
    g.row_id = row["id"].as<uint32_t>();
    g.grant_id = row["grant_id"].as<std::string>();
    g.vault_id = opt<uint32_t>(row, "vault_id");
    g.vault_name = row["vault_name"].as<std::string>();
    g.state = row["state"].as<std::string>();
    g.gateway_only = row["gateway_only"].as<bool>();
    g.gateway_credential_id = opt<uint32_t>(row, "gateway_credential_id");
    g.gateway_access_key = opt<std::string>(row, "gateway_access_key");
    g.gateway_bucket = opt<std::string>(row, "gateway_bucket");
    g.api_key_id = opt<uint32_t>(row, "api_key_id");
    g.upstream_provider = opt<std::string>(row, "upstream_provider");
    g.upstream_endpoint = opt<std::string>(row, "upstream_endpoint");
    g.upstream_region = opt<std::string>(row, "upstream_region");
    g.upstream_bucket = opt<std::string>(row, "upstream_bucket");
    g.upstream_key_id = opt<std::string>(row, "upstream_key_id");
    g.upstream_key_name = opt<std::string>(row, "upstream_key_name");
    g.issued_by = opt<uint32_t>(row, "issued_by");
    g.issued_by_name = row["issued_by_name"].as<std::string>();
    g.issued_at = row["issued_at"].as<std::time_t>();
    g.revoked_at = opt<std::time_t>(row, "revoked_at");
    g.revoked_by = opt<std::string>(row, "revoked_by");
    g.revocation_error = opt<std::string>(row, "revocation_error");
    g.ciphertext = opt<std::string>(row, "ciphertext");
    g.recipients = splitOn(row["recipients"].as<std::string>(), ',');
    return g;
}

std::optional<std::string> epochParam(const std::optional<std::time_t>& t) {
    if (!t) return std::nullopt;
    return std::to_string(*t);
}

}

// ------------------------------------------------------------------------------------------------- recipients

std::optional<uint32_t> ReadGrants::pinRecipient(const ReadGrantRecipient& r) {
    using namespace read_grants_detail;
    return Transactions::exec("ReadGrants::pinRecipient", [&](pqxx::work& txn) -> std::optional<uint32_t> {
        const auto res = txn.exec(
            "INSERT INTO read_grant_recipient (fingerprint, label, user_ids, algorithm, key_created_at, key_expires_at, "
            "  public_key, source, source_url, pinned_by, pinned_by_name) "
            "VALUES ($1, $2, $3, $4, to_timestamp($5::bigint), to_timestamp($6::bigint), $7, $8, $9, $10, $11) "
            "ON CONFLICT (fingerprint) WHERE removed_at IS NULL DO NOTHING RETURNING id",
            pqxx::params{r.fingerprint, r.label, joinLines(r.user_ids), r.algorithm, epochParam(r.key_created_at),
                         epochParam(r.key_expires_at), r.public_key, r.source, r.source_url, r.pinned_by,
                         r.pinned_by_name});
        if (res.empty()) return std::nullopt;
        return res[0][0].as<uint32_t>();
    });
}

std::vector<ReadGrantRecipient> ReadGrants::listRecipients(const bool includeRemoved) {
    using namespace read_grants_detail;
    return Transactions::exec("ReadGrants::listRecipients", [&](pqxx::work& txn) {
        std::vector<ReadGrantRecipient> out;
        for (const auto row : txn.exec(std::string("SELECT ") + kRecipientColumns + " FROM read_grant_recipient" +
                                       (includeRemoved ? "" : " WHERE removed_at IS NULL") +
                                       " ORDER BY pinned_at, id"))
            out.push_back(recipientFrom(row));
        return out;
    });
}

std::optional<ReadGrantRecipient> ReadGrants::liveRecipient(const std::string& fingerprint) {
    using namespace read_grants_detail;
    return Transactions::exec("ReadGrants::liveRecipient", [&](pqxx::work& txn) -> std::optional<ReadGrantRecipient> {
        const auto res = txn.exec(std::string("SELECT ") + kRecipientColumns +
                                      " FROM read_grant_recipient WHERE fingerprint = $1 AND removed_at IS NULL",
                                  pqxx::params{fingerprint});
        if (res.empty()) return std::nullopt;
        return recipientFrom(res[0]);
    });
}

bool ReadGrants::removeRecipient(const std::string& fingerprint, const std::string& removedBy) {
    return Transactions::exec("ReadGrants::removeRecipient", [&](pqxx::work& txn) {
        return !txn.exec("UPDATE read_grant_recipient SET removed_at = CURRENT_TIMESTAMP, removed_by = $2 "
                         "WHERE fingerprint = $1 AND removed_at IS NULL RETURNING 1",
                         pqxx::params{fingerprint, removedBy})
                    .empty();
    });
}

// ------------------------------------------------------------------------------------------------- grants

std::optional<uint32_t> ReadGrants::reserve(const ReadGrant& g, const std::vector<uint32_t>& recipientIds,
                                            const uint32_t maxLive) {
    return Transactions::exec("ReadGrants::reserve", [&](pqxx::work& txn) -> std::optional<uint32_t> {
        // One issuer at a time per vault, so two concurrent requests can't both take the last slot.
        txn.exec("SELECT pg_advisory_xact_lock(hashtext('vault_read_grant'), $1::int)", pqxx::params{g.vault_id});
        const auto live = txn.exec("SELECT count(*) FROM vault_read_grant WHERE vault_id = $1 AND state <> 'revoked'",
                                   pqxx::params{g.vault_id})
                              .one_field_ref()
                              .as<uint32_t>();
        if (live >= maxLive) return std::nullopt;
        const auto id = txn.exec("INSERT INTO vault_read_grant (grant_id, vault_id, vault_name, state, gateway_only, "
                                 "  issued_by, issued_by_name) VALUES ($1, $2, $3, 'issuing', $4, $5, $6) RETURNING id",
                                 pqxx::params{g.grant_id, g.vault_id, g.vault_name, g.gateway_only, g.issued_by,
                                              g.issued_by_name})
                            .one_field_ref()
                            .as<uint32_t>();
        for (const auto rid : recipientIds)
            txn.exec("INSERT INTO vault_read_grant_recipient (grant_row_id, recipient_id, fingerprint) "
                     "SELECT $1, id, fingerprint FROM read_grant_recipient WHERE id = $2",
                     pqxx::params{id, rid});
        return id;
    });
}

uint32_t ReadGrants::liveCount(const uint32_t vaultId) {
    return Transactions::exec("ReadGrants::liveCount", [&](pqxx::work& txn) {
        return txn.exec("SELECT count(*) FROM vault_read_grant WHERE vault_id = $1 AND state <> 'revoked'",
                        pqxx::params{vaultId})
            .one_field_ref()
            .as<uint32_t>();
    });
}

uint32_t ReadGrants::liveCountForApiKey(const uint32_t apiKeyId) {
    return Transactions::exec("ReadGrants::liveCountForApiKey", [&](pqxx::work& txn) {
        return txn.exec("SELECT count(*) FROM vault_read_grant WHERE api_key_id = $1 AND state <> 'revoked'",
                        pqxx::params{apiKeyId})
            .one_field_ref()
            .as<uint32_t>();
    });
}

void ReadGrants::recordGateway(const uint32_t rowId, const uint32_t credentialId, const std::string& accessKey,
                               const std::string& bucket) {
    Transactions::exec("ReadGrants::recordGateway", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_read_grant SET gateway_credential_id = $2, gateway_access_key = $3, gateway_bucket = $4 "
                 "WHERE id = $1",
                 pqxx::params{rowId, credentialId, accessKey, bucket});
    });
}

void ReadGrants::recordUpstream(const uint32_t rowId, const uint32_t apiKeyId, const std::string& provider,
                                const std::string& endpoint, const std::string& region, const std::string& bucket,
                                const std::string& keyId, const std::string& keyName) {
    Transactions::exec("ReadGrants::recordUpstream", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_read_grant SET api_key_id = $2, upstream_provider = $3, upstream_endpoint = $4, "
                 "upstream_region = $5, upstream_bucket = $6, upstream_key_id = $7, upstream_key_name = $8 "
                 "WHERE id = $1",
                 pqxx::params{rowId, apiKeyId, provider, endpoint, region, bucket, keyId, keyName});
    });
}

void ReadGrants::activate(const uint32_t rowId, const std::string& ciphertext) {
    Transactions::exec("ReadGrants::activate", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_read_grant SET state = 'active', ciphertext = $2 WHERE id = $1 AND state = 'issuing'",
                 pqxx::params{rowId, ciphertext});
    });
}

void ReadGrants::discard(const uint32_t rowId) {
    Transactions::exec("ReadGrants::discard", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM vault_read_grant WHERE id = $1 AND state = 'issuing'", pqxx::params{rowId});
    });
}

void ReadGrants::clearGateway(const uint32_t rowId) {
    Transactions::exec("ReadGrants::clearGateway", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_read_grant SET gateway_credential_id = NULL WHERE id = $1", pqxx::params{rowId});
    });
}

void ReadGrants::clearUpstream(const uint32_t rowId) {
    Transactions::exec("ReadGrants::clearUpstream", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_read_grant SET upstream_key_id = NULL WHERE id = $1", pqxx::params{rowId});
    });
}

void ReadGrants::markRevoked(const uint32_t rowId, const std::string& revokedBy) {
    Transactions::exec("ReadGrants::markRevoked", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_read_grant SET state = 'revoked', revoked_at = CURRENT_TIMESTAMP, revoked_by = $2, "
                 "revocation_error = NULL WHERE id = $1",
                 pqxx::params{rowId, revokedBy});
    });
}

void ReadGrants::markRevocationIncomplete(const uint32_t rowId, const std::string& error) {
    Transactions::exec("ReadGrants::markRevocationIncomplete", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_read_grant SET state = 'revocation_incomplete', revocation_error = $2 WHERE id = $1",
                 pqxx::params{rowId, error});
    });
}

std::optional<ReadGrant> ReadGrants::get(const std::string& grantId) {
    using namespace read_grants_detail;
    return Transactions::exec("ReadGrants::get", [&](pqxx::work& txn) -> std::optional<ReadGrant> {
        const auto res = txn.exec(std::string("SELECT ") + kGrantColumns + " FROM vault_read_grant g WHERE g.grant_id = $1",
                                  pqxx::params{grantId});
        if (res.empty()) return std::nullopt;
        return grantFrom(res[0]);
    });
}

std::vector<ReadGrant> ReadGrants::list(const std::optional<uint32_t> vaultId, const bool includeRevoked) {
    using namespace read_grants_detail;
    return Transactions::exec("ReadGrants::list", [&](pqxx::work& txn) {
        std::vector<ReadGrant> out;
        std::string sql = std::string("SELECT ") + kGrantColumns + " FROM vault_read_grant g WHERE ($1::int IS NULL OR "
                          "g.vault_id = $1)";
        if (!includeRevoked) sql += " AND g.state <> 'revoked'";
        sql += " ORDER BY g.issued_at DESC, g.id DESC";
        for (const auto row : txn.exec(sql, pqxx::params{vaultId})) out.push_back(grantFrom(row));
        return out;
    });
}

}
