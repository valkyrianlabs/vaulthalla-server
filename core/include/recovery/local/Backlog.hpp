#pragma once

#include "fs/Fwd.hpp"
#include "recovery/Model.hpp"
#include "storage/Fwd.hpp"
#include "sync/Fwd.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <vector>

// Local versions as the ordered upstream backlog (.claude/context/recovery.md). In an upstream vault with local
// versioning on, each retained generation starts 'pending' under its object key. Before Vaulthalla writes that key
// again (the sync upload of the file's current content) or deletes it upstream, the key's pending generations are
// replayed oldest first, each PUT carrying the generation's own IV / key version / hash, so the provider's history
// matches the local one; then the current content follows. Nothing here runs on a FUSE or HTTP write path.
//
//   bucket keeps history (versioning Enabled and settled)  replay → 'sent' (provider version id); a generation the
//                                                           provider already holds (same IV or hash among the key's
//                                                           known versions, or the content both sides last agreed
//                                                           on) is not sent again
//   anything else (unversioned, suspended, propagating,   'skipped': only the latest content matters there
//   R2, unknown)
//   a replay request fails                                 recordFailure, stop: the current content waits (order)
//   the generation can't be read (blob or key gone,        recordFailure + 'skipped': it can never be sent, and must
//   authentication fails)                                  not hold the file's uploads back forever
//
// Smart cache: in a `cache` strategy vault, a generation's local blob is released once the provider holds it (sent)
// unless a snapshot references it; the row stays (with its version id) as a provider-held version.
namespace vh::recovery::local::backlog {

struct ReplayReport {
    uint64_t sent{}, already_upstream{}, skipped{}, released{}, failed{};
    bool blocked{false};                     // a replay request failed: don't write the key now
    std::optional<std::string> error;
};

// Before the current content of `file` (a live file of the engine's vault) is uploaded. Pending generations of the
// file that were retained under another key (renamed since) are skipped.
ReplayReport replayBeforeUpload(const storage::CloudEngine& engine, const fs::model::File& file);

// Before Vaulthalla deletes the object at `vaultPath` upstream.
ReplayReport replayBeforeRemoteDelete(const storage::CloudEngine& engine, const std::filesystem::path& vaultPath);

// Price preflight / request planning: the replay PUTs and bytes the plan's uploads and remote deletes will send first
// (only while the bucket keeps history). Never throws (logged: the estimate then leaves the replays out).
void addPlannedReplays(uint32_t vaultId, const std::vector<sync::model::Action>& plan,
                       sync::model::S3CostEstimate& estimate) noexcept;

[[nodiscard]] Backlog summary(uint32_t vaultId);

}
