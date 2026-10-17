#pragma once

#include "identities/Fwd.hpp"
#include "recovery/Model.hpp"
#include "storage/Fwd.hpp"

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Restoring local generations (snapshot members and local versions, lv-<id>) and whole snapshots (snap-<id>).
// Trusted primitives: nothing here authorizes. The dispatcher (ops/RecoveryPoints.cpp) checks Read on every item's
// source_path at plan time and, at restore, Overwrite on an existing destination file, Write (upload) at the parent of
// a new file and Touch for every directory restore creates (the missing parents of a destination and the snapshot's
// empty directories). See .claude/context/recovery.md.
//
// Destinations: by default each generation goes back to its original vault path (the path it had when it was
// retained; a file renamed or moved since is left alone and the old path is created again). With an alternate
// destination D (a vault directory), the chosen point P (the snapshot root, the sub-path chosen in it, or the one file)
// is restored INTO D under its own name: P/x/y → D/<name of P>/x/y, a file P → D/<name of P>; the vault root ("/")
// maps its children straight under D.
namespace vh::recovery::local {

// What a local plan is. Items are files, plus (snapshots only) the directories the snapshot recorded as empty:
// a directory item has source_id "snap-<id>", method "none", the note kDirectoryNote, and no size.
inline constexpr const char* kDirectoryNote = "empty directory";

struct LocalPlan {
    uint32_t vault_id{};
    std::string source_label;                  // "snap-12", "snap-12:/docs/a", "lv-40"
    bool atomic{false};                        // true for snapshots
    std::string consistency_note;
    std::vector<PlanItem> items;
    uint64_t creates{}, overwrites{}, skips{}, conflicts{}, unavailable{};
    std::vector<std::string> warnings;
    std::vector<std::string> blockers;         // non-empty: the restore can't proceed (e.g. the vault quota)
};

// The plan for a local source (read-only; no bytes are touched).
//   source       snap-<id> or lv-<id> (pv-<id> is std::invalid_argument: not local)
//   subPath      snapshots only: restore just this vault path of the snapshot (a member file or a directory in it)
//   destination  nullopt: original paths; else a vault directory (see above)
// Per item: Create (destination missing), Overwrite (a file is there; destination_source_id = its current
// storage::Generation::sourceId()), Skip (it already holds this exact generation: same IV and key version, or both
// empty), Conflict (a directory where the file goes, a file where a directory goes or in its parent chain),
// Unavailable (blob missing, body held only by the provider, key version gone). Method local_copy (sealed under the
// current key: the bytes are reused) or local_reseal (an older key: re-sealed under the current one).
// Throws ops::NotFound (no such point / sub-path, or its vault has no engine), ops::Conflict (the snapshot isn't
// ready), ops::Invalid (a bad path or a subPath on lv-).
[[nodiscard]] LocalPlan planFor(const RecoveryId& source, const std::optional<std::string>& subPath = std::nullopt,
                                const std::optional<std::string>& destination = std::nullopt);

// Restores one planned item as a new current generation of its destination (method local_copy / local_reseal; a
// directory item creates the directory). Never overwrites anything the plan didn't see:
//   Create     the destination must still be absent (a file that appeared meanwhile is a conflict)
//   Overwrite  the destination must still be destination_source_id and not open through FUSE (CAS under the
//              content lock; anything else is a conflict and nothing is written)
//   Skip / Conflict / Unavailable  reported as planned (skipped / conflict / unavailable), nothing is touched
// The bytes: the blob is checked to authenticate under its key; same key → its sealed bytes are copied to the
// destination (same IV, same plaintext); older key → re-sealed under the current key with a fresh IV (the old tag
// verified first, no plaintext on disk). Missing parent directories are created. For a cloud vault the restored file
// is an ordinary local write (the next sync uploads it once). Outcome: restored | skipped | conflict | unavailable |
// failed (error says why). Never throws for an item-level failure.
[[nodiscard]] ItemOutcome restore(const std::shared_ptr<storage::Engine>& engine,
                                  const std::shared_ptr<identities::User>& actor, const PlanItem& item);

// The missing ancestors of an item's destination that restore(item) would create, shallowest first, for the
// dispatcher's Touch checks (a directory item also needs Touch on its own destination_path).
[[nodiscard]] std::vector<std::string> missingParents(const storage::Engine& engine, const PlanItem& item);

}
