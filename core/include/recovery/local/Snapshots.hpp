#pragma once

#include "fs/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "ops/Error.hpp"
#include "storage/Fwd.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Local snapshots (recovery_snapshot + file_versions members → recovery_blob): explicit, named recovery points of one
// file or directory tree, taken only when a person asks (never on writes, rename, delete, sync or key rotation).
// Trusted primitives: nothing here authorizes (ops::recovery::createSnapshot / deletePoint do). See
// .claude/context/recovery.md.
//
// What a snapshot holds: per file, its last SEALED generation (the backing file and the files row read together under
// Filesystem::contentWriteMutex, the lock copy, overwrite, FUSE seal and rotation take), captured by link into the
// recovery store (an unchanged file already retained is free: one blob per generation). A file open through FUSE with
// unsealed changes contributes the generation its last flush/fsync/close sealed, never the working copy. Directories
// are recorded by their files; directories with no captured file under them are listed in empty_directories so a
// restore recreates them. Not captured, each recorded in skipped_json with its reason:
//   symlink              symlinks (the target is a path, not content)
//   upload_staging       in-flight HTTP upload staging (.upload-http-*.part)
//   content_unavailable  a cloud file with no local copy whose fetch the remote-read gate refused (price/request
//                        budget, remote policy off, archived object) or that failed; never an unbounded download
//   integrity_error      a remote object that failed authentication while being fetched
//   unsealed             a legacy file still stored in plaintext (repairAtRest seals it on the next pass)
//   vanished | moved     the file was deleted, or moved out of the tree, while the snapshot was being taken
namespace vh::recovery::local::snapshots {

struct SkippedEntry {
    std::string path;                    // vault path
    std::string reason;                  // see above
    std::optional<std::string> detail{};
};

// Called for every planned entry (the root first, then everything under it, shallowest first) before anything is
// written; throws to refuse the whole snapshot (the exception reaches the caller of create unchanged).
using Authorizer = std::function<void(const fs::model::Entry& entry)>;

struct Created {
    int64_t snapshot_id{};
    uint64_t file_count{}, directory_count{}, plaintext_bytes{};
    uint64_t new_bytes{};                // physical bytes the store gained (deduplicated generations are free)
    std::vector<SkippedEntry> skipped;
};

// Takes a snapshot of `vaultPath` (a file or directory; "/" is the vault root) in `engine`'s vault.
//   ops::Invalid    the vault's recovery mode is not local_snapshots (names the mode); a bad name
//   ops::NotFound   no such path
//   ops::Conflict   the name is taken (db::query::recovery::SnapshotNameTaken); the snapshot quota
//                   (vault_recovery_policy.snapshot_quota_bytes) or the vault quota (Engine::freeSpace) can't hold the
//                   new physical bytes (messages say how many bytes are needed and how many are left)
// Exceptions from `authorize` propagate before any row or blob exists. A failure after the snapshot row exists marks
// it failed (with the error) and releases whatever it had captured, then rethrows.
[[nodiscard]] Created create(const std::shared_ptr<storage::Engine>& engine,
                             const std::shared_ptr<identities::User>& actor, const std::string& vaultPath,
                             const std::optional<std::string>& name, const Authorizer& authorize = {});

// Startup: snapshots left `creating` by a crash (older than minAge; at startup nothing of this process is in flight,
// so 0 is right) become `failed` ("interrupted") and their members and now-unreferenced blobs are released. Returns
// how many were cleaned up. Never throws for a single snapshot (logged).
uint64_t cleanupInterrupted(std::chrono::seconds minAge = std::chrono::seconds(0)) noexcept;

// Deletes a snapshot: markDeleting (frees its name) → member rows → blobs nothing references any more.
// ops::NotFound when absent; ops::Conflict while it is still `creating` (cleanupInterrupted settles a crashed one).
// A snapshot left `deleting` by a crash is finished by deleting it again.
void remove(int64_t snapshotId);

}

namespace vh::recovery::local {

// A local version still waiting to be replayed upstream (upstream_state pending): deleting it would lose history the
// provider never got.
struct VersionPendingUpstream : ops::Conflict {
    using ops::Conflict::Conflict;
};

// A snapshot member is part of its snapshot: delete the snapshot instead.
struct SnapshotMemberNotDeletable : ops::Invalid {
    using ops::Invalid::Invalid;
};

// Deletes one local version (lv-<id>, origin 'version') and its blob when nothing else references it.
// ops::NotFound when absent; VersionPendingUpstream; SnapshotMemberNotDeletable.
void removeVersion(int64_t generationId);

}
