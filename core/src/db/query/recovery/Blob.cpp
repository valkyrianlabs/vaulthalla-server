#include "db/query/recovery/Blob.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"
#include "db/query/recovery/detail/Fields.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/result>

namespace vh::db::query::recovery {

namespace {

BlobRow blobFromRow(const pqxx::row_ref row) {
    BlobRow b;
    b.id = row["id"].as<int64_t>();
    b.vault_id = row["vault_id"].as<uint32_t>();
    b.storage_name = row["storage_name"].as<std::string>();
    b.encryption_iv = row["encryption_iv"].as<std::string>();
    b.key_version = row["key_version"].as<unsigned int>();
    b.cipher_bytes = detail::u64(row["cipher_bytes"]);
    b.plaintext_bytes = detail::u64(row["plaintext_bytes"]);
    b.content_hash = detail::opt<std::string>(row["content_hash"]);
    b.created_at = detail::timeOr0(row["created_at"]);
    return b;
}

std::optional<BlobRow> firstBlob(const pqxx::result& res) {
    if (res.empty()) return std::nullopt;
    return blobFromRow(res.one_row_ref());
}

}

std::optional<BlobRow> Blob::findByGeneration(pqxx::transaction_base& txn, const uint32_t vaultId, const std::string& iv,
                                              const unsigned int keyVersion) {
    if (iv.empty()) return std::nullopt;
    const auto res = txn.exec(pqxx::prepped{"recovery_blob_find_generation"}, pqxx::params{vaultId, iv, keyVersion});
    return firstBlob(res);
}

std::optional<BlobRow> Blob::findByGeneration(const uint32_t vaultId, const std::string& iv, const unsigned int keyVersion) {
    if (iv.empty()) return std::nullopt;
    return Transactions::read("recovery::Blob::findByGeneration", [&](pqxx::transaction_base& txn) {
        return findByGeneration(txn, vaultId, iv, keyVersion);
    });
}

InsertedBlob Blob::insert(pqxx::work& txn, const BlobRow& row) {
    const auto res = txn.exec(pqxx::prepped{"recovery_blob_insert"},
                              pqxx::params{row.vault_id, row.storage_name, row.encryption_iv, row.key_version,
                                           static_cast<int64_t>(row.cipher_bytes),
                                           static_cast<int64_t>(row.plaintext_bytes), row.content_hash});
    if (!res.empty())
        return {.id = res.one_row_ref()["id"].as<int64_t>(), .inserted = true, .storage_name = row.storage_name};
    // ON CONFLICT DO NOTHING waited for a concurrent insert of the same generation; this statement's snapshot sees it.
    const auto existing = findByGeneration(txn, row.vault_id, row.encryption_iv, row.key_version);
    if (!existing) throw std::runtime_error("recovery blob insert conflicted but no blob holds the generation");
    return {.id = existing->id, .inserted = false, .storage_name = existing->storage_name};
}

std::optional<BlobRow> Blob::get(pqxx::transaction_base& txn, const int64_t id) {
    const auto res = txn.exec(pqxx::prepped{"recovery_blob_get"}, pqxx::params{id});
    return firstBlob(res);
}

std::optional<BlobRow> Blob::get(const int64_t id) {
    return Transactions::read("recovery::Blob::get", [&](pqxx::transaction_base& txn) { return get(txn, id); });
}

std::optional<BlobRow> Blob::getByStorageName(const uint32_t vaultId, const std::string& storageName) {
    return Transactions::read("recovery::Blob::getByStorageName", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_blob_get_by_storage_name"}, pqxx::params{vaultId, storageName});
        return firstBlob(res);
    });
}

uint64_t Blob::refCount(const int64_t id) {
    return Transactions::read("recovery::Blob::refCount", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_blob_ref_count"}, pqxx::params{id});
        return detail::u64(res.one_row_ref()[0]);
    });
}

std::optional<BlobRow> Blob::deleteIfUnreferenced(pqxx::work& txn, const int64_t id) {
    const auto locked = txn.exec(pqxx::prepped{"recovery_blob_lock"}, pqxx::params{id});
    if (locked.empty()) return std::nullopt;
    const auto res = txn.exec(pqxx::prepped{"recovery_blob_delete_unreferenced"}, pqxx::params{id});
    return firstBlob(res);
}

std::optional<BlobRow> Blob::deleteIfUnreferenced(const int64_t id) {
    return Transactions::exec("recovery::Blob::deleteIfUnreferenced",
                              [&](pqxx::work& txn) { return deleteIfUnreferenced(txn, id); });
}

BlobUsage Blob::usage(const uint32_t vaultId) {
    return Transactions::read("recovery::Blob::usage", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_blob_usage"}, pqxx::params{vaultId});
        const auto row = res.one_row_ref();
        return BlobUsage{.blobs = detail::u64(row["blobs"]),
                         .bytes = detail::u64(row["bytes"]),
                         .plaintext_bytes = detail::u64(row["plaintext_bytes"]),
                         .snapshot_only_blobs = detail::u64(row["snapshot_only_blobs"]),
                         .snapshot_only_bytes = detail::u64(row["snapshot_only_bytes"]),
                         .version_blobs = detail::u64(row["version_blobs"]),
                         .version_bytes = detail::u64(row["version_bytes"]),
                         .unreferenced_blobs = detail::u64(row["unreferenced_blobs"]),
                         .unreferenced_bytes = detail::u64(row["unreferenced_bytes"])};
    });
}

uint64_t Blob::physicalBytes(const uint32_t vaultId) {
    return Transactions::read("recovery::Blob::physicalBytes", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_blob_physical_bytes"}, pqxx::params{vaultId});
        return detail::u64(res.one_row_ref()[0]);
    });
}

std::vector<BlobRow> Blob::listUnreferenced(const uint32_t vaultId, const int64_t minAgeSeconds, const unsigned int limit) {
    return Transactions::read("recovery::Blob::listUnreferenced", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_blob_list_unreferenced"},
                                  pqxx::params{vaultId, static_cast<double>(minAgeSeconds), detail::clampLimit(limit)});
        return mapRows(res, blobFromRow);
    });
}

std::vector<BlobRow> Blob::listByVault(const uint32_t vaultId, const int64_t afterId, const unsigned int limit) {
    return Transactions::read("recovery::Blob::listByVault", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_blob_list_by_vault"},
                                  pqxx::params{vaultId, afterId, detail::clampLimit(limit)});
        return mapRows(res, blobFromRow);
    });
}

std::vector<std::string> Blob::existingStorageNames(const uint32_t vaultId, const std::vector<std::string>& storageNames) {
    if (storageNames.empty()) return {};
    const auto names = nlohmann::json(storageNames).dump();
    return Transactions::read("recovery::Blob::existingStorageNames", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_blob_existing_names"}, pqxx::params{vaultId, names});
        return mapRows(res, [](const pqxx::row_ref r) { return r[0].as<std::string>(); });
    });
}

std::vector<unsigned int> Blob::keyVersions(const uint32_t vaultId) {
    return Transactions::read("recovery::Blob::keyVersions", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(pqxx::prepped{"recovery_blob_key_versions"}, pqxx::params{vaultId});
        return mapRows(res, [](const pqxx::row_ref r) { return r[0].as<unsigned int>(); });
    });
}

}
