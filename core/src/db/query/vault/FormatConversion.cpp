#include "db/query/vault/FormatConversion.hpp"

#include "db/Transactions.hpp"
#include "db/encoding/u8.hpp"
#include "fs/model/File.hpp"

#include <pqxx/result>

#include <stdexcept>

namespace vh::db::query::vault {

namespace {

namespace conv = ::vh::vault::conversion;

int64_t i64(const uint64_t v) { return static_cast<int64_t>(v); }

uint64_t u64(const pqxx::field_ref f) {
    if (f.is_null()) return 0;
    const auto v = f.as<int64_t>();
    return v < 0 ? 0 : static_cast<uint64_t>(v);
}

conv::Blob blobFrom(const pqxx::row_ref row) {
    conv::Blob b;
    b.id = row["id"].as<int64_t>();
    b.storageName = row["storage_name"].as<std::string>();
    b.generation = row["encryption_iv"].as<std::string>();
    b.keyVersion = row["key_version"].as<unsigned int>();
    b.cipherBytes = u64(row["cipher_bytes"]);
    b.plaintextBytes = u64(row["plaintext_bytes"]);
    if (const auto uid = row["object_uid"]; !uid.is_null()) b.objectUid = crypto::id::fromUuid(uid.as<std::string>());
    return b;
}

// The object uid of a live file the blob was captured from (any one: they all hold the same content).
constexpr const char* kBlobColumns =
    "b.id, b.storage_name, b.encryption_iv, b.key_version, b.cipher_bytes, b.plaintext_bytes, "
    "(SELECT f.object_uid::text FROM file_versions fv JOIN files f ON f.fs_entry_id = fv.file_id "
    " WHERE fv.blob_id = b.id ORDER BY fv.id LIMIT 1) AS object_uid";

bool swapBlob(pqxx::work& txn, const uint32_t vaultId, const conv::BlobSwap& s) {
    return txn.exec("UPDATE recovery_blob SET encryption_iv = $1, storage_name = $2, cipher_bytes = $3 "
                    "WHERE id = $4 AND vault_id = $5 AND encryption_iv = $6 AND key_version = $7 AND storage_name = $8",
                    pqxx::params{s.toGeneration, s.toStorageName, i64(s.cipherBytes), s.id, vaultId, s.fromGeneration,
                                 s.keyVersion, s.fromStorageName})
               .affected_rows() == 1;
}

}

std::vector<std::shared_ptr<::vh::fs::model::File>> FormatConversion::legacyFiles(const uint32_t vaultId,
                                                                          const unsigned int keyVersion,
                                                                          const uint32_t afterId,
                                                                          const std::size_t limit) {
    return Transactions::exec("FormatConversion::legacyFiles", [&](pqxx::work& txn) {
        const auto res = txn.exec(
            "SELECT fs.*, f.* FROM files f JOIN fs_entry fs ON f.fs_entry_id = fs.id "
            "WHERE f.content_format = 'gcm0' AND fs.vault_id = $1 AND f.encrypted_with_key_version = $2 "
            "AND f.fs_entry_id > $3 ORDER BY f.fs_entry_id LIMIT $4",
            pqxx::params{vaultId, keyVersion, afterId, i64(limit)});
        return ::vh::fs::model::files_from_pq_res(res);
    });
}

std::vector<conv::Blob> FormatConversion::legacyBlobs(const uint32_t vaultId, const int64_t afterId,
                                                      const std::size_t limit,
                                                      const std::optional<unsigned int> exceptLiveOn) {
    return Transactions::read("FormatConversion::legacyBlobs", [&](pqxx::transaction_base& txn) {
        const auto res = txn.exec(
            std::string("SELECT ") + kBlobColumns +
                " FROM recovery_blob b WHERE b.content_format = 'gcm0' AND b.vault_id = $1 AND b.id > $2 "
                "AND ($4::INTEGER IS NULL OR NOT EXISTS ("
                "  SELECT 1 FROM files f JOIN fs_entry fs ON fs.id = f.fs_entry_id "
                "  WHERE fs.vault_id = b.vault_id AND f.encryption_iv = b.encryption_iv "
                "    AND f.encrypted_with_key_version = b.key_version AND f.encrypted_with_key_version = $4)) "
                "ORDER BY b.id LIMIT $3",
            pqxx::params{vaultId, afterId, i64(limit), exceptLiveOn});
        std::vector<conv::Blob> out;
        out.reserve(res.size());
        for (const auto& row : res) out.push_back(blobFrom(row));
        return out;
    });
}

std::optional<conv::Blob> FormatConversion::blobByGeneration(const uint32_t vaultId, const std::string& generation,
                                                             const unsigned int keyVersion) {
    if (generation.empty()) return std::nullopt;
    return Transactions::read("FormatConversion::blobByGeneration", [&](pqxx::transaction_base& txn)
                                                                        -> std::optional<conv::Blob> {
        const auto res = txn.exec(std::string("SELECT ") + kBlobColumns +
                                      " FROM recovery_blob b WHERE b.vault_id = $1 AND b.encryption_iv = $2 "
                                      "AND b.key_version = $3",
                                  pqxx::params{vaultId, generation, keyVersion});
        if (res.empty()) return std::nullopt;
        return blobFrom(res[0]);
    });
}

conv::FileCommit FormatConversion::commitFile(const ::vh::fs::model::File& file, const std::string& expectedGeneration,
                                              const unsigned int expectedKeyVersion,
                                              const std::optional<conv::BlobSwap>& blob) {
    if (!file.vault_id) throw std::invalid_argument("FormatConversion::commitFile: file has no vault");
    return Transactions::exec("FormatConversion::commitFile", [&](pqxx::work& txn) {
        conv::FileCommit out;
        const pqxx::params p{*file.vault_id, encoding::to_utf8_string(file.path.u8string()), file.encryption_iv,
                             file.encrypted_with_key_version, expectedGeneration, expectedKeyVersion};
        out.file = txn.exec(pqxx::prepped{"compare_and_set_file_encryption_iv_and_version"}, p).affected_rows() == 1;
        if (out.file && blob) out.blob = swapBlob(txn, static_cast<uint32_t>(*file.vault_id), *blob);
        return out;
    });
}

bool FormatConversion::commitBlob(const uint32_t vaultId, const conv::BlobSwap& swap) {
    return Transactions::exec("FormatConversion::commitBlob",
                              [&](pqxx::work& txn) { return swapBlob(txn, vaultId, swap); });
}

FormatConversion::Remaining FormatConversion::remaining(const uint32_t vaultId, const unsigned int keyVersion) {
    return Transactions::read("FormatConversion::remaining", [&](pqxx::transaction_base& txn) {
        Remaining r;
        const auto filesRes = txn.exec(
            "SELECT count(*) FILTER (WHERE $2 = 0 OR f.encrypted_with_key_version = $2) AS n, "
            "       coalesce(sum(f.size_bytes + 16) FILTER (WHERE $2 = 0 OR f.encrypted_with_key_version = $2), 0) AS bytes, "
            "       count(*) FILTER (WHERE $2 <> 0 AND f.encrypted_with_key_version <> $2) AS other "
            "FROM files f JOIN fs_entry fs ON f.fs_entry_id = fs.id "
            "WHERE f.content_format = 'gcm0' AND fs.vault_id = $1",
            pqxx::params{vaultId, keyVersion});
        const auto files = filesRes.one_row_ref();
        r.files = u64(files["n"]);
        r.file_bytes = u64(files["bytes"]);
        r.files_other_versions = u64(files["other"]);
        const auto blobsRes = txn.exec("SELECT count(*) AS n, coalesce(sum(cipher_bytes), 0) AS bytes FROM recovery_blob "
                                    "WHERE content_format = 'gcm0' AND vault_id = $1",
                                    pqxx::params{vaultId});
        const auto blobs = blobsRes.one_row_ref();
        r.blobs = u64(blobs["n"]);
        r.blob_bytes = u64(blobs["bytes"]);
        return r;
    });
}

}
