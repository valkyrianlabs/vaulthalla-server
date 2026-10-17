#pragma once

#include "ops/Recovery.hpp"
#include "recovery/Fwd.hpp"
#include "storage/Fwd.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// RecoveryPoints for the local backends: snapshots (snap-<id>), their members and local versions (lv-<id>).
// Unauthorized raw lists: every point carries its vault path (RecoveryPoint::path, the path when it was taken) so the
// dispatcher (ops/RecoveryPoints.cpp) filters by filesystem Read/List and merges provider points. Nothing here
// authorizes.
namespace vh::recovery::local::points {

// One snapshot. Restorable only when ready (unavailable_reason says the state otherwise). Snapshots span files sealed
// under different keys: encryption.key_version is 0 there and key_available says whether the vault still holds every
// key version its retained blobs use (the members carry the exact one).
[[nodiscard]] RecoveryPoint fromSnapshot(const db::query::recovery::SnapshotRow& row);

// One retained generation (a snapshot member or a local version). `engine` (the vault's) answers the key questions;
// without it key_available/key_current are false.
[[nodiscard]] RecoveryPoint fromGeneration(const db::query::recovery::GenerationRow& row,
                                           const db::query::recovery::PolicyRow& policy,
                                           const storage::Engine* engine);

struct Query {
    std::optional<std::string> path{};    // vault path; nullopt = the whole vault
    bool snapshots = true, versions = true;
    unsigned int limit = 200;             // per kind
};

// Points of a vault, newest first:
//   no path          every snapshot and every local version of the vault
//   a file path      its history whether or not a file is there now (deleted files included): every retained
//                    generation of that path (local versions and snapshot members), plus the snapshots holding it
//   a directory path the snapshots rooted at or under it and those holding something under it, and the local
//                    versions of files under it
[[nodiscard]] std::vector<RecoveryPoint> list(uint32_t vaultId, const Query& query);

// One point by id (snap- or lv-); nullopt when absent (pv- is never local: nullopt).
[[nodiscard]] std::optional<RecoveryPoint> get(const RecoveryId& id);

// A snapshot with a page of its members (rel_path order after `afterRelPath`), who took it and what it skipped
// ("<path>: <reason>[ (<detail>)]"); nullopt when absent. For lv-: the point alone.
[[nodiscard]] std::optional<ops::recovery::PointDetail> detail(const RecoveryId& id, const std::string& afterRelPath = "",
                                                               unsigned int memberLimit = 200);

}
