#pragma once

#include "ops/Error.hpp"
#include "recovery/Model.hpp"

#include <pqxx/transaction>

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// recovery_snapshot (migration 111): an explicit recovery point of one file or directory tree.
//
//   create (state creating) ──► add members (Generation::insertSnapshotMember, same or later transactions)
//        ├──► finish (ready, counts)
//        └──► fail (failed, error)
//   ready ──► markDeleting (frees the name) ──► remove (members cascade; blobs are then garbage for the store)
namespace vh::db::query::recovery {

// The vault already has a snapshot of that name (not being deleted). An ops::Conflict, so it crosses the ops boundary
// as a refusal and Transactions::exec rolls back quietly.
struct SnapshotNameTaken : ops::Conflict {
    using ops::Conflict::Conflict;
};

struct SnapshotRow {
    int64_t id{};
    uint32_t vault_id{};
    std::optional<std::string> name{};
    std::string root_path{};                         // vault path, starts with '/'
    vh::recovery::PointKind root_type{vh::recovery::PointKind::File};
    std::optional<uint32_t> root_entry_id{};
    std::string state{"creating"};                 // creating | ready | deleting | failed
    uint64_t file_count{}, directory_count{}, plaintext_bytes{};
    std::vector<std::string> empty_directories{};    // vault paths of empty directories in the tree
    std::string skipped_json{"[]"};                // JSON array: entries not captured and why
    std::time_t created_at{};
    std::optional<std::time_t> completed_at{};
    std::optional<uint32_t> created_by{};
    std::optional<std::string> created_by_name{};
    std::optional<std::string> error{};
};

struct NewSnapshot {
    uint32_t vault_id{};
    std::optional<std::string> name{};
    std::string root_path{};
    vh::recovery::PointKind root_type{vh::recovery::PointKind::File};
    std::optional<uint32_t> root_entry_id{};
    std::optional<uint32_t> created_by{};
    std::optional<std::string> created_by_name{};
};

struct SnapshotTotals {
    uint64_t file_count{}, directory_count{}, plaintext_bytes{};
    std::vector<std::string> empty_directories{};
    std::string skipped_json{"[]"};
};

class Snapshot {
public:
    // Inserts a `creating` snapshot and returns its id. Throws SnapshotNameTaken on a name collision (the
    // transaction is unusable afterwards; the caller lets it roll back).
    [[nodiscard]] static int64_t create(pqxx::work& txn, const NewSnapshot& s);
    [[nodiscard]] static int64_t create(const NewSnapshot& s);

    // creating → ready with its totals and completed_at = now. False when it was not `creating`.
    static bool finish(pqxx::work& txn, int64_t id, const SnapshotTotals& totals);
    static bool finish(int64_t id, const SnapshotTotals& totals);
    // creating → failed with the error and completed_at = now. False when it was not `creating`.
    static bool fail(int64_t id, const std::string& error);

    [[nodiscard]] static std::optional<SnapshotRow> get(int64_t id);
    [[nodiscard]] static std::optional<SnapshotRow> get(pqxx::transaction_base& txn, int64_t id);
    [[nodiscard]] static std::optional<SnapshotRow> getByName(uint32_t vaultId, const std::string& name);

    // Newest first. `beforeId` > 0 pages (ids below it). Every state.
    [[nodiscard]] static std::vector<SnapshotRow> listByVault(uint32_t vaultId, unsigned int limit, int64_t beforeId = 0);
    // Snapshots whose root is `path` or lies under it (a directory listing), newest first.
    [[nodiscard]] static std::vector<SnapshotRow> listUnderPath(uint32_t vaultId, const std::string& path,
                                                               unsigned int limit);
    // Snapshots that hold `path`: a member with that path, or (for an empty directory or a directory) a root at or
    // above it. Newest first; ready ones only.
    [[nodiscard]] static std::vector<SnapshotRow> listContainingPath(uint32_t vaultId, const std::string& path,
                                                                     unsigned int limit);

    // ready|failed|creating → deleting (its name is free again). False when already deleting or absent.
    static bool markDeleting(int64_t id);
    // Deletes the snapshot and (cascade) its member rows. Returns the blob ids the members referenced that nothing
    // references any more: the store removes them (Store::removeBlob) after this transaction commits.
    [[nodiscard]] static std::vector<int64_t> remove(pqxx::work& txn, int64_t id);
    [[nodiscard]] static std::vector<int64_t> remove(int64_t id);

    // Snapshots left `creating` (a crash mid-create) older than minAgeSeconds.
    [[nodiscard]] static std::vector<SnapshotRow> listStaleCreating(int64_t minAgeSeconds);
};

}
