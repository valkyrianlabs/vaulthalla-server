#pragma once

#include "storage/upstream/model/InboxEvent.hpp"
#include "storage/upstream/model/WriteIntent.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// upstream_event_inbox: durable, deduplicated events.
//
// Lifecycle: pending (inserted) → applied (written to the remote object index) → done (a scoped sync pass reconciled
// it); or skipped (self-originated, superseded by a baseline, foreign object under `ignore`, …); or failed (gave up).
// Retries keep the state and set next_attempt_at. Callers process one vault at a time (the event service serializes
// per vault), so "claim" is an ordered read of due rows, not a lease.
namespace vh::db::query::upstream {

using InboxModel = storage::upstream::model::InboxEvent;

struct InboxCounts {
    uint64_t pending = 0, applied = 0, failed = 0, done_24h = 0, self_24h = 0;
    std::optional<std::time_t> last_event_at;   // newest event_time seen for the vault
};

class Inbox {
public:
    // One transaction: the durability point before a queue message is acknowledged. Duplicates of
    // (provider, account_ref, bucket, dedupe_key) are dropped. Returns how many rows were new.
    static uint64_t insertMany(const std::vector<InboxModel>& events);

    // Due pending rows of the vault (next_attempt_at absent or past), ordered by object_key, then sequencer
    // (length first, so hex sequencers compare numerically), event_time and id.
    [[nodiscard]] static std::vector<InboxModel> claimForVault(uint32_t vaultId, unsigned int limit);
    // Due applied rows (waiting for a scoped sync pass), oldest first.
    [[nodiscard]] static std::vector<InboxModel> listApplied(uint32_t vaultId, unsigned int limit);
    // Vaults with due pending or applied work.
    [[nodiscard]] static std::vector<uint32_t> listVaultsWithWork();

    // origin: nullopt keeps the stored one.
    static void markApplied(const std::vector<int64_t>& ids,
                            std::optional<storage::upstream::model::InboxOrigin> origin = std::nullopt);
    static void markDone(const std::vector<int64_t>& ids);
    static void markSkipped(const std::vector<int64_t>& ids, const std::string& note,
                            storage::upstream::model::InboxOrigin origin);
    // attempts + 1, last_error. With nextAttemptAt: stays pending, retried then. Without: terminal failed.
    static void markFailed(int64_t id, const std::string& error, std::optional<std::time_t> nextAttemptAt);
    // A scoped pass over these applied rows failed: attempts + 1, retried at nextAttemptAt (state stays applied).
    static void requeueApplied(uint32_t vaultId, const std::vector<int64_t>& ids, std::time_t nextAttemptAt,
                               const std::string& error = {});

    [[nodiscard]] static InboxCounts counts(uint32_t vaultId);

    // Events stored as unrouted (skipped, no vault) for a bucket while its subscription was being set up become pending
    // work of that vault: only keys under `prefix`, only received at or after `since` (epoch seconds).
    static uint64_t routeUnassigned(const std::string& provider, const std::string& accountRef, const std::string& bucket,
                                    uint32_t vaultId, int64_t subscriptionId, const std::string& prefix = {},
                                    std::time_t since = 0);
    // One transaction: consume a matching write intent of ours (WriteIntent::consumeMatching rules, plus the ETag when
    // both are known) and, when one matched, mark the row skipped with origin self. True when it was ours.
    [[nodiscard]] static bool settleOwnWrite(int64_t rowId, uint32_t vaultId, const std::string& key,
                                             storage::upstream::model::WriteOp op, std::optional<uint64_t> size,
                                             std::time_t eventTime, const std::optional<std::string>& etag,
                                             const std::string& note);
    // Deletes done/skipped rows finished before now - olderThan.
    static uint64_t sweepFinished(std::chrono::seconds olderThan);
    // The newest event for one key of the vault (sequencer, then event_time, then id), any state.
    [[nodiscard]] static std::optional<InboxModel> latestForKey(uint32_t vaultId, const std::string& key);
};

}
