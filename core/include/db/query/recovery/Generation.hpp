#pragma once

#include "recovery/Model.hpp"

#include <pqxx/transaction>

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// file_versions as the retained-generation table (migration 111). One row = one retained sealed generation of a file:
// a snapshot member (origin 'snapshot', snapshot_id set) or a local version (origin 'version'). The row describes the
// retained content, current from source_updated_at until created_at. file_id is the live file while it exists and
// NULL after it is deleted (ON DELETE SET NULL): the generation outlives it and is found by (vault_id, path).
//
// version_number is unique per file_id and increases per "file key": the file_id, or for a row without one, the
// (vault, path). Inserts take a transaction-scoped advisory lock on the file key before reading MAX + 1, so concurrent
// captures of one file serialize and never collide (UNIQUE (file_id, version_number)).
namespace vh::db::query::recovery {

enum class Origin { Snapshot, Version };
[[nodiscard]] std::string to_string(Origin o);           // snapshot | version

enum class UpstreamState { None, Pending, Sent, Skipped };
[[nodiscard]] std::string to_string(UpstreamState s);    // none | pending | sent | skipped
[[nodiscard]] UpstreamState upstreamStateFromString(const std::string& s);

struct GenerationRow {
    int64_t id{};
    std::optional<uint32_t> vault_id{};
    std::optional<uint32_t> file_id{};
    std::optional<int64_t> snapshot_id{};
    std::optional<int64_t> blob_id{};
    int version_number{};
    std::optional<std::string> content_hash{};
    uint64_t size_bytes{};                        // plaintext bytes of the generation
    std::optional<std::string> mime_type{};
    std::string path{};                             // vault path when retained
    std::optional<std::string> rel_path{};          // snapshot members: path relative to the snapshot root
    std::optional<uint32_t> mode{};
    std::optional<std::time_t> source_updated_at{};
    std::time_t created_at{};
    std::optional<uint32_t> created_by{};
    Origin origin{Origin::Snapshot};
    std::optional<std::string> reason{};            // overwrite | truncate | delete | download | restore | conflict
    UpstreamState upstream_state{UpstreamState::None};
    std::optional<std::string> upstream_key{};
    std::optional<std::string> upstream_version_id{};
    unsigned int upstream_attempts{};
    std::optional<std::string> upstream_error{};
    std::optional<std::time_t> upstream_sent_at{};

    // The blob (LEFT JOIN): absent when the generation's body was released (sent upstream) or never held.
    std::optional<std::string> storage_name{};
    std::optional<std::string> encryption_iv{};
    std::optional<unsigned int> key_version{};
    std::optional<uint64_t> cipher_bytes{};
};

struct NewGeneration {
    uint32_t vault_id{};
    std::optional<uint32_t> file_id{};              // nullopt: the file no longer exists (numbered by path)
    std::optional<int64_t> blob_id{};
    std::optional<std::string> content_hash{};
    uint64_t size_bytes{};
    std::optional<std::string> mime_type{};
    std::string path{};
    std::optional<uint32_t> mode{};
    std::optional<std::time_t> source_updated_at{};
    std::optional<uint32_t> created_by{};
    // Snapshot members only:
    std::optional<int64_t> snapshot_id{};
    std::optional<std::string> rel_path{};
    // Local versions only:
    std::optional<std::string> reason{};
    UpstreamState upstream_state{UpstreamState::None};
    std::optional<std::string> upstream_key{};
};

struct InsertedGeneration {
    int64_t id{};
    int version_number{};
};

// The upstream backlog of a vault (pending local versions).
struct BacklogSummary {
    uint64_t pending{}, pending_bytes{};          // pending_bytes: plaintext bytes
    std::optional<std::time_t> oldest_pending_at{};
    uint64_t failing{};                           // pending with upstream_attempts > 0
    std::optional<std::string> last_error{};
};

// Physical, deduplicated bytes per kind (a blob shared by a snapshot member and a version counts in both).
struct GenerationUsage {
    vh::recovery::StoreUsage snapshots{}, versions{};
};

struct RetentionRule {
    std::optional<unsigned int> keep_last{};        // per file key
    std::optional<unsigned int> max_age_days{};     // created_at older than now - days
    std::optional<uint64_t> quota_bytes{};          // physical bytes of version blobs; oldest pruned first
};

class Generation {
public:
    // Snapshot member (origin 'snapshot', upstream 'none'); s.snapshot_id and s.rel_path are required.
    [[nodiscard]] static InsertedGeneration insertSnapshotMember(pqxx::work& txn, const NewGeneration& g);
    // Local version (origin 'version'); g.reason is required.
    [[nodiscard]] static InsertedGeneration insertLocalVersion(pqxx::work& txn, const NewGeneration& g);
    [[nodiscard]] static InsertedGeneration insertLocalVersion(const NewGeneration& g);

    [[nodiscard]] static std::optional<GenerationRow> get(int64_t id);
    [[nodiscard]] static std::optional<GenerationRow> get(pqxx::transaction_base& txn, int64_t id);

    // Generations of a live file, newest version first (snapshot members and versions).
    [[nodiscard]] static std::vector<GenerationRow> listByFile(uint32_t fileId, unsigned int limit);
    // History of a vault path, newest first, whether or not a file exists there now (deleted files included).
    // origin: nullopt = both.
    [[nodiscard]] static std::vector<GenerationRow> listByPath(uint32_t vaultId, const std::string& path,
                                                               std::optional<Origin> origin, unsigned int limit);
    // Local versions under a directory (path prefix), newest first.
    [[nodiscard]] static std::vector<GenerationRow> listVersionsUnder(uint32_t vaultId, const std::string& dirPath,
                                                                      unsigned int limit);
    // Members of a snapshot in rel_path order after `afterRelPath` (paging; "" = from the start).
    [[nodiscard]] static std::vector<GenerationRow> listSnapshotMembers(int64_t snapshotId, const std::string& afterRelPath,
                                                                        unsigned int limit);
    [[nodiscard]] static uint64_t countSnapshotMembers(int64_t snapshotId);

    // Deletes the row; returns its blob id if nothing references that blob any more (the store removes it after
    // commit). Callers refuse pending versions themselves (ops: Conflict).
    [[nodiscard]] static std::optional<int64_t> remove(pqxx::work& txn, int64_t id);
    [[nodiscard]] static std::optional<int64_t> remove(int64_t id);

    // Detaches the body (blob_id = NULL) of a generation the provider now holds; returns the blob id when nothing
    // else references it (the store removes it after commit). Snapshot members are never released.
    [[nodiscard]] static std::optional<int64_t> releaseBlob(pqxx::work& txn, int64_t id);

    // ---- upstream backlog ----
    // Pending local versions of the vault in replay order: per file key, version_number ascending.
    [[nodiscard]] static std::vector<GenerationRow> listPending(uint32_t vaultId, unsigned int limit);
    // Pending local versions of one live file, oldest first.
    [[nodiscard]] static std::vector<GenerationRow> listPendingForFile(uint32_t fileId);
    // pending → sent with the provider's version id (sent_at = now, error cleared). False when it wasn't pending.
    static bool markSent(int64_t id, const std::string& upstreamVersionId);
    static bool markSent(pqxx::work& txn, int64_t id, const std::string& upstreamVersionId);
    // pending → skipped (superseded without replay). Returns how many changed.
    static uint64_t markSkipped(const std::vector<int64_t>& ids);
    // A failed replay attempt: attempts + 1, error recorded, stays pending.
    static void recordFailure(int64_t id, const std::string& error);
    [[nodiscard]] static BacklogSummary backlog(uint32_t vaultId);

    // ---- usage and retention ----
    [[nodiscard]] static GenerationUsage usage(uint32_t vaultId);

    // Local versions the rule prunes, oldest first: never pending, never snapshot members. keep_last keeps the newest
    // n per file key; max_age_days prunes older ones; quota_bytes prunes the oldest remaining until the physical bytes
    // of version blobs (counting a blob as freed only when every row referencing it is pruned) fit. A rule with no
    // limits prunes nothing.
    [[nodiscard]] static std::vector<GenerationRow> listPrunable(uint32_t vaultId, const RetentionRule& rule,
                                                                 std::time_t now);
    // Deletes those rows (origin 'version' and not pending only, re-checked). Returns the blob ids nothing references
    // any more (the store removes them after commit).
    [[nodiscard]] static std::vector<int64_t> removeVersions(pqxx::work& txn, uint32_t vaultId,
                                                             const std::vector<int64_t>& ids);
    [[nodiscard]] static std::vector<int64_t> removeVersions(uint32_t vaultId, const std::vector<int64_t>& ids);
};

}
