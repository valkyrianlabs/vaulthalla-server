#pragma once

#include <pqxx/transaction>

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// recovery_blob (migration 111): one immutable sealed generation held locally. Dedupe key: (vault_id, encryption_iv,
// key_version) for a non-empty IV. Refcount = file_versions rows whose blob_id is the blob. The file itself lives in
// recovery::store; these are its rows only.
namespace vh::db::query::recovery {

struct BlobRow {
    int64_t id{};
    uint32_t vault_id{};
    std::string storage_name{};            // 32 [a-z0-9]
    std::string encryption_iv{};           // "" for an empty or legacy plaintext generation (never deduplicated)
    unsigned int key_version{};
    uint64_t cipher_bytes{};             // bytes on disk (body‖tag)
    uint64_t plaintext_bytes{};
    std::optional<std::string> content_hash{};
    std::time_t created_at{};
};

// Physical (deduplicated) bytes of a vault's blobs. A blob counts once whatever references it.
struct BlobUsage {
    uint64_t blobs{}, bytes{}, plaintext_bytes{};
    // Split by what references a blob: only snapshot members / at least one local version / nothing (garbage).
    uint64_t snapshot_only_blobs{}, snapshot_only_bytes{};
    uint64_t version_blobs{}, version_bytes{};
    uint64_t unreferenced_blobs{}, unreferenced_bytes{};
};

struct InsertedBlob {
    int64_t id{};
    bool inserted{false};                // false: a blob of the same generation existed; `id` is that one
    std::string storage_name{};            // of the row `id` names (the existing one when deduplicated)
};

class Blob {
public:
    // The blob holding (vault, iv, keyVersion), if any. An empty IV never matches (no dedupe for it).
    [[nodiscard]] static std::optional<BlobRow> findByGeneration(uint32_t vaultId, const std::string& iv,
                                                                 unsigned int keyVersion);
    [[nodiscard]] static std::optional<BlobRow> findByGeneration(pqxx::transaction_base& txn, uint32_t vaultId,
                                                                 const std::string& iv, unsigned int keyVersion);

    // Inserts `row` (id and created_at ignored) in the caller's transaction. When a blob of the same generation exists
    // (or one is inserted concurrently and committed first), nothing is inserted and that blob's id is returned with
    // inserted=false: the caller drops its own file once its transaction commits.
    [[nodiscard]] static InsertedBlob insert(pqxx::work& txn, const BlobRow& row);

    [[nodiscard]] static std::optional<BlobRow> get(int64_t id);
    [[nodiscard]] static std::optional<BlobRow> get(pqxx::transaction_base& txn, int64_t id);
    [[nodiscard]] static std::optional<BlobRow> getByStorageName(uint32_t vaultId, const std::string& storageName);

    // file_versions rows referencing the blob.
    [[nodiscard]] static uint64_t refCount(int64_t id);

    // Deletes the row only when nothing references it, under a row lock (a concurrent capture that reuses the blob
    // either commits first, and the blob stays, or fails its foreign key). Returns the deleted row (its storage_name
    // tells the store which file to unlink after commit), nullopt when referenced or absent.
    [[nodiscard]] static std::optional<BlobRow> deleteIfUnreferenced(pqxx::work& txn, int64_t id);
    [[nodiscard]] static std::optional<BlobRow> deleteIfUnreferenced(int64_t id);

    [[nodiscard]] static BlobUsage usage(uint32_t vaultId);
    // Total bytes only (one indexed aggregate).
    [[nodiscard]] static uint64_t physicalBytes(uint32_t vaultId);
    // What the store adds on disk beyond the vault's live backing files (what Engine::freeSpace charges): the bytes of
    // blobs that are not the live generation of a file they were captured from. A blob linked from a live file's
    // generation (same IV + key version, the file's row still describes it) shares that file's inode, which
    // getVaultSize already counts; once the file is replaced or deleted the blob is the only copy and is charged.
    // Derived from the rows (one pass over the vault's blobs, index lookups), no stat.
    [[nodiscard]] static uint64_t chargedBytes(uint32_t vaultId);

    // Rows nothing references, created before now - minAgeSeconds, oldest first.
    [[nodiscard]] static std::vector<BlobRow> listUnreferenced(uint32_t vaultId, int64_t minAgeSeconds, unsigned int limit);

    // Rows of the vault in id order after `afterId` (paging for the store's missing-file check).
    [[nodiscard]] static std::vector<BlobRow> listByVault(uint32_t vaultId, int64_t afterId, unsigned int limit);

    // Of `storageNames`, the ones that have a row in the vault.
    [[nodiscard]] static std::vector<std::string> existingStorageNames(uint32_t vaultId,
                                                                       const std::vector<std::string>& storageNames);

    // Key versions the vault's blobs were sealed with, ascending.
    [[nodiscard]] static std::vector<unsigned int> keyVersions(uint32_t vaultId);
};

}
