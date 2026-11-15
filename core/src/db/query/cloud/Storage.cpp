#include "db/query/cloud/Storage.hpp"

#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"

#include <vl/keykit/uid.hpp>

#include <pqxx/pqxx>

namespace vh::db::query::cloud {

// Named, not anonymous: the unity build joins this file with others.
namespace cloud_storage_detail {

std::string epoch(const char* column) {
    return std::string("EXTRACT(EPOCH FROM ") + column + ")::BIGINT AS " + column;
}

const std::string& vaultColumns() {
    static const std::string columns =
        "vault_id, vault_uid, switch, switch_by, " + epoch("switch_at") + ", state, reason, bucket, bucket_id, "
        "s3_endpoint, region, api_key_id, key_id, key_state, key_access, retention_days, retention_sent, "
        "label_generation, enrolled_version, " + epoch("enroll_behind_since") + ", attempts, " +
        epoch("next_attempt_at") + ", last_error, " + epoch("registered_at") + ", " + epoch("ready_at") + ", " +
        epoch("active_at") + ", " + epoch("moved_at") + ", " + epoch("ejected_at") + ", " + epoch("ended_at") + ", " +
        epoch("updated_at");
    return columns;
}

template <class T>
std::optional<T> opt(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return f.as<T>();
}

std::optional<std::time_t> optTime(const pqxx::field_ref f) {
    if (f.is_null()) return std::nullopt;
    return static_cast<std::time_t>(f.as<int64_t>());
}

VaultStorageRow rowOf(const pqxx::row_ref r) {
    VaultStorageRow row;
    row.vault_id = r["vault_id"].as<uint32_t>();
    row.vault_uid = r["vault_uid"].as<std::string>();
    row.switch_state = r["switch"].as<std::string>();
    row.switch_by = r["switch_by"].as<std::string>();
    row.switch_at = optTime(r["switch_at"]).value_or(0);
    row.state = r["state"].as<std::string>();
    row.reason = opt<std::string>(r["reason"]);
    row.bucket = opt<std::string>(r["bucket"]);
    row.bucket_id = opt<std::string>(r["bucket_id"]);
    row.s3_endpoint = opt<std::string>(r["s3_endpoint"]);
    row.region = opt<std::string>(r["region"]);
    row.api_key_id = opt<uint32_t>(r["api_key_id"]);
    row.key_id = opt<std::string>(r["key_id"]);
    row.key_state = r["key_state"].as<std::string>();
    row.key_access = opt<std::string>(r["key_access"]);
    row.retention_days = opt<uint32_t>(r["retention_days"]);
    row.retention_sent = opt<uint32_t>(r["retention_sent"]);
    row.label_generation = opt<uint32_t>(r["label_generation"]);
    row.enrolled_version = opt<uint32_t>(r["enrolled_version"]);
    row.enroll_behind_since = optTime(r["enroll_behind_since"]);
    row.attempts = r["attempts"].as<uint32_t>();
    row.next_attempt_at = optTime(r["next_attempt_at"]);
    row.last_error = opt<std::string>(r["last_error"]);
    row.registered_at = optTime(r["registered_at"]);
    row.ready_at = optTime(r["ready_at"]);
    row.active_at = optTime(r["active_at"]);
    row.moved_at = optTime(r["moved_at"]);
    row.ejected_at = optTime(r["ejected_at"]);
    row.ended_at = optTime(r["ended_at"]);
    row.updated_at = optTime(r["updated_at"]).value_or(0);
    return row;
}

std::optional<int64_t> t(const std::optional<std::time_t>& v) {
    return v ? std::optional<int64_t>(static_cast<int64_t>(*v)) : std::nullopt;
}

constexpr const char* kManagedStates = "('registered', 'waiting', 'keyed', 'attaching', 'active', 'detaching')";

}

std::optional<StorageAccountRow> CloudStorage::account() {
    namespace d = cloud_storage_detail;
    return Transactions::read("cloud::CloudStorage::account", [&](pqxx::transaction_base& txn) -> std::optional<StorageAccountRow> {
        const auto res = txn.exec("SELECT state, plan, quota_bytes, storage_access, cause, used_bytes, usage_day, "
                                  "account_key_confirmed, provider, ejection::text, billing::text, " + d::epoch("fetched_at") +
                                  ", fetch_error, new_vaults, " + d::epoch("enabled_at") + ", offer_open, " +
                                  d::epoch("fast_until") + " FROM cloud_storage_account");
        if (res.empty()) return std::nullopt;
        const auto& r = res[0];
        StorageAccountRow row;
        row.state = d::opt<std::string>(r[0]);
        row.plan = d::opt<std::string>(r[1]);
        if (const auto q = d::opt<int64_t>(r[2])) row.quota_bytes = static_cast<uint64_t>(*q);
        row.storage_access = d::opt<std::string>(r[3]);
        row.cause = d::opt<std::string>(r[4]);
        if (const auto u = d::opt<int64_t>(r[5])) row.used_bytes = static_cast<uint64_t>(*u);
        row.usage_day = d::opt<std::string>(r[6]);
        row.account_key_confirmed = d::opt<bool>(r[7]);
        row.provider = d::opt<std::string>(r[8]);
        if (!r[9].is_null()) row.ejection = nlohmann::json::parse(r[9].as<std::string>(), nullptr, false);
        if (!r[10].is_null()) row.billing = nlohmann::json::parse(r[10].as<std::string>(), nullptr, false);
        row.fetched_at = d::optTime(r[11]);
        row.fetch_error = d::opt<std::string>(r[12]);
        row.new_vaults = r[13].as<bool>();
        row.enabled_at = d::optTime(r[14]);
        row.offer_open = r[15].as<bool>();
        row.fast_until = d::optTime(r[16]);
        return row;
    });
}

void CloudStorage::saveFetched(const FetchedAccount& f) {
    Transactions::exec("cloud::CloudStorage::saveFetched", [&](pqxx::work& txn) {
        const auto ejection = f.ejection.is_null() ? std::optional<std::string>() : std::optional(f.ejection.dump());
        const auto billing = f.billing.is_null() ? std::optional<std::string>() : std::optional(f.billing.dump());
        txn.exec("INSERT INTO cloud_storage_account (singleton, state, plan, quota_bytes, storage_access, cause, used_bytes, "
                 "usage_day, account_key_confirmed, provider, ejection, billing, fetched_at, fetch_error, updated_at) "
                 "VALUES (TRUE, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10::jsonb, $11::jsonb, now(), NULL, now()) "
                 "ON CONFLICT (singleton) DO UPDATE SET state = EXCLUDED.state, plan = EXCLUDED.plan, quota_bytes = "
                 "EXCLUDED.quota_bytes, storage_access = EXCLUDED.storage_access, cause = EXCLUDED.cause, used_bytes = "
                 "EXCLUDED.used_bytes, usage_day = EXCLUDED.usage_day, account_key_confirmed = "
                 "EXCLUDED.account_key_confirmed, provider = EXCLUDED.provider, ejection = EXCLUDED.ejection, billing = "
                 "EXCLUDED.billing, fetched_at = now(), fetch_error = NULL, updated_at = now()",
                 pqxx::params{f.state, f.plan, static_cast<int64_t>(f.quota_bytes), f.storage_access, f.cause,
                              f.used_bytes ? std::optional<int64_t>(static_cast<int64_t>(*f.used_bytes)) : std::nullopt,
                              f.usage_day, f.account_key_confirmed, f.provider, ejection, billing});
    });
}

void CloudStorage::saveFetchError(const std::string& error) {
    Transactions::exec("cloud::CloudStorage::saveFetchError", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO cloud_storage_account (singleton, fetch_error) VALUES (TRUE, $1) ON CONFLICT (singleton) DO "
                 "UPDATE SET fetch_error = EXCLUDED.fetch_error, updated_at = now()",
                 pqxx::params{error.substr(0, 500)});
    });
}

void CloudStorage::setNewVaults(const bool on) {
    Transactions::exec("cloud::CloudStorage::setNewVaults", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO cloud_storage_account (singleton, new_vaults) VALUES (TRUE, $1) ON CONFLICT (singleton) DO "
                 "UPDATE SET new_vaults = EXCLUDED.new_vaults, updated_at = now()",
                 pqxx::params{on});
    });
}

bool CloudStorage::markEnabled() {
    return Transactions::exec("cloud::CloudStorage::markEnabled", [&](pqxx::work& txn) {
        return txn.exec("UPDATE cloud_storage_account SET enabled_at = now(), updated_at = now() WHERE enabled_at IS NULL")
                   .affected_rows() > 0;
    });
}

void CloudStorage::setOfferOpen(const bool open) {
    Transactions::exec("cloud::CloudStorage::setOfferOpen", [&](pqxx::work& txn) {
        txn.exec("UPDATE cloud_storage_account SET offer_open = $1, updated_at = now()", pqxx::params{open});
    });
}

void CloudStorage::setFastUntil(const std::time_t until) {
    Transactions::exec("cloud::CloudStorage::setFastUntil", [&](pqxx::work& txn) {
        txn.exec("UPDATE cloud_storage_account SET fast_until = to_timestamp($1), updated_at = now()",
                 pqxx::params{static_cast<int64_t>(until)});
    });
}

void CloudStorage::clearAccount() {
    Transactions::exec("cloud::CloudStorage::clearAccount", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM cloud_storage_account");
    });
}

std::vector<VaultStorageRow> CloudStorage::list() {
    namespace d = cloud_storage_detail;
    return Transactions::read("cloud::CloudStorage::list", [&](pqxx::transaction_base& txn) {
        std::vector<VaultStorageRow> out;
        for (const auto r : txn.exec("SELECT " + d::vaultColumns() + " FROM vault_cloud_storage ORDER BY vault_id"))
            out.push_back(d::rowOf(r));
        return out;
    });
}

std::optional<VaultStorageRow> CloudStorage::get(const uint32_t vaultId) {
    namespace d = cloud_storage_detail;
    return Transactions::read("cloud::CloudStorage::get", [&](pqxx::transaction_base& txn) -> std::optional<VaultStorageRow> {
        const auto res = txn.exec("SELECT " + d::vaultColumns() + " FROM vault_cloud_storage WHERE vault_id = $1",
                                  pqxx::params{vaultId});
        if (res.empty()) return std::nullopt;
        return d::rowOf(res[0]);
    });
}

bool CloudStorage::insert(const VaultStorageRow& row) {
    return Transactions::exec("cloud::CloudStorage::insert", [&](pqxx::work& txn) {
        return txn.exec("INSERT INTO vault_cloud_storage (vault_id, vault_uid, switch, switch_by, state, retention_days) "
                        "VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (vault_id) DO NOTHING",
                        pqxx::params{row.vault_id, row.vault_uid, row.switch_state, row.switch_by, row.state,
                                     row.retention_days})
                   .affected_rows() == 1;
    });
}

void CloudStorage::update(const VaultStorageRow& r) {
    namespace d = cloud_storage_detail;
    Transactions::exec("cloud::CloudStorage::update", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_cloud_storage SET switch = $2, switch_by = $3, switch_at = to_timestamp($4), state = $5, "
                 "reason = $6, bucket = $7, bucket_id = $8, s3_endpoint = $9, region = $10, api_key_id = $11, key_id = $12, "
                 "key_state = $13, key_access = $14, retention_days = $15, retention_sent = $16, label_generation = $17, "
                 "enrolled_version = $18, enroll_behind_since = to_timestamp($19), attempts = $20, next_attempt_at = "
                 "to_timestamp($21), last_error = $22, registered_at = to_timestamp($23), ready_at = to_timestamp($24), "
                 "active_at = to_timestamp($25), moved_at = to_timestamp($26), ejected_at = to_timestamp($27), ended_at = "
                 "to_timestamp($28), updated_at = now() WHERE vault_id = $1",
                 pqxx::params{r.vault_id, r.switch_state, r.switch_by, static_cast<int64_t>(r.switch_at), r.state, r.reason,
                              r.bucket, r.bucket_id, r.s3_endpoint, r.region, r.api_key_id, r.key_id, r.key_state,
                              r.key_access, r.retention_days, r.retention_sent, r.label_generation, r.enrolled_version,
                              d::t(r.enroll_behind_since), r.attempts, d::t(r.next_attempt_at),
                              r.last_error ? std::optional(r.last_error->substr(0, 1000)) : std::nullopt,
                              d::t(r.registered_at), d::t(r.ready_at), d::t(r.active_at), d::t(r.moved_at),
                              d::t(r.ejected_at), d::t(r.ended_at)});
    });
}

void CloudStorage::remove(const uint32_t vaultId) {
    Transactions::exec("cloud::CloudStorage::remove", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM vault_cloud_storage WHERE vault_id = $1", pqxx::params{vaultId});
    });
}

std::vector<CloudStorage::Candidate> CloudStorage::candidates() {
    return Transactions::read("cloud::CloudStorage::candidates", [&](pqxx::transaction_base& txn) {
        std::vector<Candidate> out;
        for (const auto r : txn.exec("SELECT v.id, v.uid::text, v.type, EXTRACT(EPOCH FROM v.created_at)::BIGINT FROM vault v "
                                     "WHERE v.deleted_at IS NULL AND v.uid IS NOT NULL AND NOT EXISTS (SELECT 1 FROM "
                                     "vault_cloud_storage c WHERE c.vault_id = v.id) ORDER BY v.id")) {
            const auto uid = crypto::id::fromUuid(r[1].as<std::string>());
            out.push_back({.vault_id = r[0].as<uint32_t>(), .vault_uid = vl::keykit::toBase32(uid),
                           .type = r[2].as<std::string>(), .created_at = static_cast<std::time_t>(r[3].as<int64_t>())});
        }
        return out;
    });
}

bool CloudStorage::hasContent(const uint32_t vaultId) {
    return Transactions::read("cloud::CloudStorage::hasContent", [&](pqxx::transaction_base& txn) {
        return !txn.exec("SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id WHERE e.vault_id = $1 AND "
                         "f.encryption_iv <> '' LIMIT 1",
                         pqxx::params{vaultId})
                    .empty();
    });
}

uint64_t CloudStorage::contentBytes(const uint32_t vaultId) {
    return Transactions::read("cloud::CloudStorage::contentBytes", [&](pqxx::transaction_base& txn) {
        return txn.exec("SELECT COALESCE(SUM(f.size_bytes), 0)::BIGINT FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                        "WHERE e.vault_id = $1 AND f.encryption_iv <> ''",
                        pqxx::params{vaultId})
            .one_field_ref()
            .as<uint64_t>();
    });
}

bool CloudStorage::anyManaged() {
    namespace d = cloud_storage_detail;
    return Transactions::read("cloud::CloudStorage::anyManaged", [&](pqxx::transaction_base& txn) {
        return !txn.exec(std::string("SELECT 1 FROM vault_cloud_storage WHERE state IN ") + d::kManagedStates + " LIMIT 1")
                    .empty();
    });
}

bool CloudStorage::managed(const uint32_t vaultId) {
    namespace d = cloud_storage_detail;
    return Transactions::read("cloud::CloudStorage::managed", [&](pqxx::transaction_base& txn) {
        return !txn.exec(std::string("SELECT 1 FROM vault_cloud_storage WHERE vault_id = $1 AND state IN ") + d::kManagedStates,
                         pqxx::params{vaultId})
                    .empty();
    });
}

void CloudStorage::markKeyCloud(const uint32_t apiKeyId, const std::string& access) {
    Transactions::exec("cloud::CloudStorage::markKeyCloud", [&](pqxx::work& txn) {
        txn.exec("UPDATE api_keys SET origin = 'cloud', cloud_access = $2 WHERE id = $1", pqxx::params{apiKeyId, access});
    });
}

bool CloudStorage::eject(const uint32_t vaultId) {
    return Transactions::exec("cloud::CloudStorage::eject", [&](pqxx::work& txn) {
        const auto row = txn.exec("SELECT api_key_id, state FROM vault_cloud_storage WHERE vault_id = $1 FOR UPDATE",
                                  pqxx::params{vaultId});
        if (row.empty() || row[0][1].as<std::string>() == "ejected") return false;
        if (!row[0][0].is_null())
            txn.exec("UPDATE api_keys SET origin = 'customer', cloud_access = NULL WHERE id = $1",
                     pqxx::params{row[0][0].as<uint32_t>()});
        txn.exec("UPDATE vault_cloud_storage SET state = 'ejected', reason = NULL, key_state = 'none', key_access = NULL, "
                 "ejected_at = now(), last_error = NULL, updated_at = now() WHERE vault_id = $1",
                 pqxx::params{vaultId});
        return true;
    });
}

void CloudStorage::bindManagedBucket(const uint32_t vaultId, const std::string& provider, const std::string& accountRef,
                                     const std::string& bucket, const std::optional<std::string>& region,
                                     const uint32_t apiKeyId, const uint32_t retentionDays) {
    Transactions::exec("cloud::CloudStorage::bindManagedBucket", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO upstream_bucket (provider, account_ref, bucket, region, vault_id, last_seen_api_key_id, "
                 "versioning_status, noncurrent_retention_mode, noncurrent_retention_days, noncurrent_retention_set_at) "
                 "VALUES ($1, $2, $3, $4, $5, $6, 'enabled', 'days', $7, now()) ON CONFLICT (provider, account_ref, bucket) "
                 "DO UPDATE SET vault_id = EXCLUDED.vault_id, last_seen_api_key_id = EXCLUDED.last_seen_api_key_id, "
                 "versioning_status = 'enabled', noncurrent_retention_mode = CASE WHEN "
                 "upstream_bucket.noncurrent_retention_mode = 'unset' THEN 'days' ELSE upstream_bucket.noncurrent_retention_mode "
                 "END, noncurrent_retention_days = CASE WHEN upstream_bucket.noncurrent_retention_mode = 'unset' THEN "
                 "EXCLUDED.noncurrent_retention_days ELSE upstream_bucket.noncurrent_retention_days END, updated_at = now()",
                 pqxx::params{provider, accountRef, bucket, region, vaultId, apiKeyId, static_cast<int>(retentionDays)});
        txn.exec("INSERT INTO vault_recovery_policy (vault_id, mode) VALUES ($1, 'provider_versioning') ON CONFLICT "
                 "(vault_id) DO UPDATE SET mode = 'provider_versioning', updated_at = now()",
                 pqxx::params{vaultId});
    });
}

std::optional<uint32_t> CloudStorage::desiredRetention(const uint32_t vaultId) {
    return Transactions::read("cloud::CloudStorage::desiredRetention", [&](pqxx::transaction_base& txn) -> std::optional<uint32_t> {
        const auto r = txn.exec("SELECT noncurrent_retention_mode, noncurrent_retention_days FROM upstream_bucket WHERE "
                                "vault_id = $1 ORDER BY updated_at DESC LIMIT 1",
                                pqxx::params{vaultId});
        if (r.empty()) return std::nullopt;
        const auto mode = r[0][0].as<std::string>();
        if (mode == "indefinite") return 36500u;
        if (mode == "days" && !r[0][1].is_null()) return r[0][1].as<uint32_t>();
        return std::nullopt;
    });
}

std::optional<uint32_t> CloudStorage::ownerOf(const uint32_t vaultId) {
    return Transactions::read("cloud::CloudStorage::ownerOf", [&](pqxx::transaction_base& txn) -> std::optional<uint32_t> {
        const auto r = txn.exec("SELECT owner_id FROM vault WHERE id = $1", pqxx::params{vaultId});
        if (r.empty() || r[0][0].is_null()) return std::nullopt;
        return r[0][0].as<uint32_t>();
    });
}

}
