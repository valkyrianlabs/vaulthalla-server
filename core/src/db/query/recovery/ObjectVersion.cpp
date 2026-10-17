#include "db/query/recovery/ObjectVersion.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/query/recovery/detail/Fields.hpp"

#include <pqxx/result>

#include <stdexcept>

namespace vh::db::query::recovery {

namespace {

ObjectVersionRow objectVersionFromRow(const pqxx::row_ref row) {
    ObjectVersionRow v;
    v.id = row["id"].as<int64_t>();
    v.vault_id = row["vault_id"].as<uint32_t>();
    v.object_key = row["object_key"].as<std::string>();
    v.version_id = row["version_id"].as<std::string>();
    v.is_delete_marker = row["is_delete_marker"].as<bool>();
    v.is_latest = row["is_latest"].as<bool>();
    v.etag = detail::opt<std::string>(row["etag"]);
    v.size_bytes = detail::optU64(row["size_bytes"]);
    v.storage_class = detail::opt<std::string>(row["storage_class"]);
    v.last_modified = detail::optTime(row["last_modified"]);
    v.origin = row["origin"].as<std::string>();
    v.encrypted = detail::opt<bool>(row["encrypted"]);
    v.encryption_iv = detail::opt<std::string>(row["encryption_iv"]);
    v.key_version = detail::opt<unsigned int>(row["key_version"]);
    v.content_hash = detail::opt<std::string>(row["content_hash"]);
    v.plaintext_bytes = detail::optU64(row["plaintext_bytes"]);
    v.became_noncurrent_at = detail::optTime(row["became_noncurrent_at"]);
    v.gone_at = detail::optTime(row["gone_at"]);
    v.first_seen_at = detail::timeOr0(row["first_seen_at"]);
    v.last_seen_at = detail::timeOr0(row["last_seen_at"]);
    return v;
}

std::optional<ObjectVersionRow> firstObjectVersion(const pqxx::result& res) {
    if (res.empty()) return std::nullopt;
    return objectVersionFromRow(res.one_row_ref());
}

double objectVersionEpoch(const ObjectVersion::TimePoint t) {
    return std::chrono::duration<double>(t.time_since_epoch()).count();
}

int64_t upsertObjectVersion(pqxx::work& txn, const ObjectVersionRow& r, const double seenAt) {
    if (r.origin != "vaulthalla" && r.origin != "observed")
        throw std::invalid_argument("object version origin must be vaulthalla or observed");
    const std::optional<int> keyVersion =
        r.key_version ? std::make_optional(static_cast<int>(*r.key_version)) : std::nullopt;
    const auto res = txn.exec(
        pqxx::prepped{"recovery_object_version_upsert"},
        pqxx::params{r.vault_id, r.object_key, r.version_id, r.is_delete_marker, r.is_latest, r.etag,
                     detail::optI64(r.size_bytes), r.storage_class, detail::optEpoch(r.last_modified), r.origin,
                     r.encrypted, r.encryption_iv, keyVersion, r.content_hash, detail::optI64(r.plaintext_bytes),
                     detail::optEpoch(r.became_noncurrent_at), seenAt});
    return res.one_row_ref()["id"].as<int64_t>();
}

}

int64_t ObjectVersion::upsert(const ObjectVersionRow& row, const TimePoint seenAt) {
    return Transactions::exec("recovery::ObjectVersion::upsert",
                              [&](pqxx::work& txn) { return upsertObjectVersion(txn, row, objectVersionEpoch(seenAt)); });
}

void ObjectVersion::upsertMany(const std::vector<ObjectVersionRow>& rows, const TimePoint seenAt) {
    if (rows.empty()) return;
    const auto seen = objectVersionEpoch(seenAt);
    Transactions::exec("recovery::ObjectVersion::upsertMany", [&](pqxx::work& txn) {
        for (const auto& r : rows) static_cast<void>(upsertObjectVersion(txn, r, seen));
    });
}

uint64_t ObjectVersion::markSuperseded(const uint32_t vaultId, const std::string& key, const std::string& currentVersionId,
                                       const std::time_t at) {
    return Transactions::exec("recovery::ObjectVersion::markSuperseded", [&](pqxx::work& txn) {
        const auto older = txn.exec(pqxx::prepped{"recovery_object_version_supersede"},
                                    pqxx::params{vaultId, key, currentVersionId, static_cast<double>(at)});
        const auto current = txn.exec(pqxx::prepped{"recovery_object_version_make_current"},
                                      pqxx::params{vaultId, key, currentVersionId});
        return static_cast<uint64_t>(older.affected_rows() + current.affected_rows());
    });
}

uint64_t ObjectVersion::markGoneUnder(const uint32_t vaultId, const std::string& prefix, const TimePoint listingStartedAt) {
    return Transactions::exec("recovery::ObjectVersion::markGoneUnder", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_object_version_mark_gone"},
                                  pqxx::params{vaultId, prefix, objectVersionEpoch(listingStartedAt)});
        return static_cast<uint64_t>(res.affected_rows());
    });
}

std::optional<ObjectVersionRow> ObjectVersion::get(const int64_t id) {
    return Transactions::read("recovery::ObjectVersion::get", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_object_version_get"}, pqxx::params{id});
        return firstObjectVersion(res);
    });
}

std::optional<ObjectVersionRow> ObjectVersion::find(const uint32_t vaultId, const std::string& key,
                                                    const std::string& versionId) {
    return Transactions::read("recovery::ObjectVersion::find", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_object_version_find"}, pqxx::params{vaultId, key, versionId});
        return firstObjectVersion(res);
    });
}

std::vector<ObjectVersionRow> ObjectVersion::listForKey(const uint32_t vaultId, const std::string& key,
                                                        const bool includeGone, const unsigned int limit) {
    return Transactions::read("recovery::ObjectVersion::listForKey", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_object_version_list_for_key"},
                                  pqxx::params{vaultId, key, includeGone, detail::clampLimit(limit)});
        return mapRows(res, objectVersionFromRow);
    });
}

std::vector<ObjectVersionRow> ObjectVersion::listUnderPrefix(const uint32_t vaultId, const std::string& prefix,
                                                             const bool includeGone, const unsigned int limit) {
    return Transactions::read("recovery::ObjectVersion::listUnderPrefix", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_object_version_list_under_prefix"},
                                  pqxx::params{vaultId, prefix, includeGone, detail::clampLimit(limit, 100000)});
        return mapRows(res, objectVersionFromRow);
    });
}

std::vector<ObjectVersionRow> ObjectVersion::listAsOf(const uint32_t vaultId, const std::string& prefix, const std::time_t at,
                                                      const unsigned int limit) {
    return Transactions::read("recovery::ObjectVersion::listAsOf", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_object_version_list_as_of"},
                                  pqxx::params{vaultId, prefix, static_cast<double>(at), detail::clampLimit(limit, 100000)});
        return mapRows(res, objectVersionFromRow);
    });
}

NoncurrentSummary ObjectVersion::noncurrentSummary(const uint32_t vaultId) {
    return Transactions::read("recovery::ObjectVersion::noncurrentSummary", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_object_version_noncurrent_summary"}, pqxx::params{vaultId});
        const auto row = res.one_row_ref();
        return NoncurrentSummary{.versions = detail::u64(row["versions"]),
                                 .bytes = detail::u64(row["bytes"]),
                                 .unknown_size = detail::u64(row["unknown_size"]),
                                 .delete_markers = detail::u64(row["delete_markers"]),
                                 .oldest_noncurrent_at = detail::optTime(row["oldest_noncurrent_at"]),
                                 .oldest_last_modified = detail::optTime(row["oldest_last_modified"])};
    });
}

ByteHours ObjectVersion::noncurrentByteHours(const uint32_t vaultId, const std::time_t from, const std::time_t to) {
    if (to <= from) return {};
    return Transactions::read("recovery::ObjectVersion::noncurrentByteHours", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_object_version_byte_hours"},
                                  pqxx::params{vaultId, static_cast<double>(from), static_cast<double>(to)});
        const auto row = res.one_row_ref();
        return ByteHours{.byte_hours = row["byte_hours"].is_null() ? "0" : row["byte_hours"].as<std::string>(),
                         .versions = detail::u64(row["versions"]),
                         .unknown_size = detail::u64(row["unknown_size"])};
    });
}

std::vector<unsigned int> ObjectVersion::keyVersions(const uint32_t vaultId) {
    return Transactions::read("recovery::ObjectVersion::keyVersions", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_object_version_key_versions"}, pqxx::params{vaultId});
        return mapRows(res, [](const pqxx::row_ref r) { return r[0].as<unsigned int>(); });
    });
}

}
