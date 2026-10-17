#pragma once

#include "db/query/recovery/Generation.hpp"
#include "fs/Fwd.hpp"
#include "recovery/Fwd.hpp"
#include "recovery/Model.hpp"
#include "recovery/Store.hpp"
#include "storage/Fwd.hpp"

#include <pqxx/transaction>

#include <cstddef>
#include <cstdint>
#include <ctime>
#include <functional>
#include <optional>
#include <string>
#include <vector>

// Local versioning (vault_recovery_policy.local_versioning): the opt-in harness that keeps the PRIOR sealed generation
// of a vault file on every content change (.claude/context/recovery.md, "Local storage", "Local versions as the
// upstream backlog").
//
// One helper, every writer. Whoever replaces or removes a vault file's content calls
//
//     auto kept = versions::retain(engine, priorRow, Reason::…);   // stages the blob (link) BEFORE the transaction
//     Transactions::exec(…, [&](pqxx::work& txn) {
//         kept.attach(txn);                                         // blob + file_versions rows, same transaction
//         …update / trash the files row…
//     });
//     kept.committed();                                             // after commit (abort() or the destructor otherwise)
//     …rename the new bytes over the backing file / unlink it…
//
// retain() returns an inactive Pending (attach/committed are no-ops) when the vault has local versioning off (decided
// from an in-memory policy cache: no query per write), when the prior generation is empty or legacy plaintext (counted
// as skipped: blobs are never plaintext), or when it has no local bytes (an index-only cloud file: the provider holds
// it). A failure to stage the blob is logged and counted and never fails the write.
//
// Never on: rename/move (no content change), copy (a new file), key rotation (same plaintext), hydrate, repairAtRest.
namespace vh::recovery::local {

enum class Reason : unsigned char { Overwrite, Truncate, Delete, Download, Restore, Conflict };

[[nodiscard]] std::string to_string(Reason r);              // overwrite | truncate | delete | download | restore | conflict
[[nodiscard]] Reason reasonFromString(const std::string& s); // throws std::invalid_argument

// The vault's local versioning policy, cached in memory (refreshed after kPolicyTtl as a safety net). Whoever changes
// vault_recovery_policy calls invalidatePolicy(vaultId) after the write commits.
[[nodiscard]] LocalVersioningPolicy versioningPolicy(uint32_t vaultId);
void invalidatePolicy(uint32_t vaultId) noexcept;
void invalidateAllPolicies() noexcept;

// Whether the vault may have an upstream backlog to replay. True while local versioning is on (its writes queue
// one); with it off, one EXISTS query per vault, remembered until the policy changes (invalidatePolicy, also every
// maintenance run): no new pending rows can appear while versioning is off, so uploads cost no backlog query.
[[nodiscard]] bool mayHaveBacklog(uint32_t vaultId);

}

namespace vh::recovery::local::versions {

// The upstream backlog a key keeps pending when the policy has no keep_last (with one, keep_last is the cap).
inline constexpr unsigned int kDefaultPendingCap = 32;
// Orphaned backlog rows (backlog::settleOrphaned) one maintenance run settles per vault.
inline constexpr std::size_t kOrphanedBacklogRowsPerRun = 256;

struct RetainOptions {
    std::optional<uint32_t> actor{};      // created_by
    // Queue the generation as upstream backlog ('pending') in an upstream-backed vault. retain() also turns it off
    // for content that never came from this side (download, conflict) and for deletes the vault's sync policy does
    // not propagate upstream.
    bool upstream{true};
};

// `prior` is the files row as it is before the change (IV, key version, sizes, hash, path, id); its sealed bytes are
// at prior.backing_path, which the caller replaces by rename or unlinks only after committed().
[[nodiscard]] Pending retain(const storage::Engine& engine, const fs::model::File& prior, Reason reason,
                             const RetainOptions& options = {});

class Pending {
public:
    Pending() = default;
    Pending(Pending&& other) noexcept;
    Pending& operator=(Pending&&) = delete;
    Pending(const Pending&) = delete;
    Pending& operator=(const Pending&) = delete;
    ~Pending() = default;                  // an unfinished capture aborts (its staged blob is removed)

    [[nodiscard]] bool active() const { return capture_.has_value(); }

    // In the caller's transaction, before the files row changes: the blob row and the file_versions row (origin
    // 'version'); a per-file keep_last overflow is pruned in the same transaction (bounded). No-op when inactive.
    // Never fails the caller's write: the rows go in under a savepoint, and a failure (the reused blob was removed
    // since retain(), a constraint) rolls back only them, is logged and counted, and leaves this Pending inactive.
    // Throws only when the caller's transaction itself is broken.
    void attach(pqxx::work& txn);
    // After the caller's transaction committed: finishes the capture and removes blobs the prune freed. Never throws.
    void committed() noexcept;
    // The caller's transaction failed: the staged blob goes, nothing else changed.
    void abort() noexcept;

    [[nodiscard]] std::optional<int64_t> versionId() const;
    [[nodiscard]] std::optional<int> versionNumber() const;

private:
    friend Pending retain(const storage::Engine& engine, const fs::model::File& prior, Reason reason,
                          const RetainOptions& options);

    void attachRows(pqxx::work& txn);

    store::VaultRef vault_{};
    std::optional<store::Capture> capture_;
    db::query::recovery::NewGeneration generation_{};
    std::optional<unsigned int> keepLast_;
    std::optional<db::query::recovery::InsertedGeneration> inserted_;
    std::vector<int64_t> freedBlobs_;
    uint64_t coalesced_{};
};

// Keeps the blob removals of the Pending objects committed on this thread while it lives (outermost scope only) and
// does them when it ends. Declared before a content lock, it moves those unlinks out of the lock's critical section
// (the FUSE seal, createFile's overwrite): the scope ends after the lock is released. Never throws.
class DeferBlobFrees {
public:
    DeferBlobFrees() noexcept;
    ~DeferBlobFrees();
    DeferBlobFrees(const DeferBlobFrees&) = delete;
    DeferBlobFrees& operator=(const DeferBlobFrees&) = delete;
};

// Tests: runs right before deferred blob removals (DeferBlobFrees) are carried out. Empty = none.
void setDeferredFreeHookForTesting(std::function<void()> hook);

// Tests: runs at the start of every attach(), inside its savepoint (a seam to remove a reused blob, or fail a statement,
// between retain() and attach()). Empty = none.
void setAttachHookForTesting(std::function<void(pqxx::work&)> hook);

// ---- retention -------------------------------------------------------------------------------------------------------

struct RetentionReport {
    uint64_t versions_removed{}, blobs_removed{};
    uint64_t pending_dropped{};   // unsent versions the quota removed (skipped 'quota' first, logged)
};

// The policy's keep_last / max_age_days / quota_bytes for one vault (oldest first; never pending, never a blob a
// snapshot still references). A policy without limits prunes nothing.
RetentionReport applyRetention(const store::VaultRef& vault, const LocalVersioningPolicy& policy, std::time_t now);

struct MaintenanceReport {
    uint64_t vaults{}, versions_removed{}, blobs_removed{}, backlog_skipped{}, pending_dropped{};
    uint64_t backlog_replayed{}, backlog_orphaned{};   // orphaned backlog (#249): replayed / skipped 'orphaned'
    uint64_t orphans_removed{}, unreferenced_removed{}, missing{};
    std::vector<std::string> errors{};
};

// Periodic maintenance (db::Janitor): retention for every vault with local versioning on; for upstream vaults, the
// orphaned backlog is settled (backlog::settleOrphaned, bounded) and, where the bucket keeps no history, the rest of the
// pending backlog is marked skipped. With sweepStores, also recovery::store::sweep for
// every vault that has a store directory (orphan blobs of crashed captures, unreferenced rows). Never throws.
MaintenanceReport maintain(std::time_t now, bool sweepStores);

// ---- observability (tests, status) ------------------------------------------------------------------------------------

struct Counters {
    uint64_t retained{};          // generations committed as local versions
    uint64_t skipped{};           // nothing to keep: empty / legacy plaintext / no local bytes
    uint64_t failed{};            // staging failed (logged; the write went ahead)
    uint64_t policy_loads{};      // vault_recovery_policy reads (cache misses)
    uint64_t coalesced{};         // older pending versions skipped to bound a key's backlog
    uint64_t backlog_checks{};    // backlog existence queries (mayHaveBacklog with versioning off)
};
[[nodiscard]] Counters counters();

}
