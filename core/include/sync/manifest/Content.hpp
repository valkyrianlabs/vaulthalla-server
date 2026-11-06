#pragma once

#include "sync/manifest/Document.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <vector>

// What a vault's manifest says, independent of how it is cut into objects: the tree (directories, files, symlinks,
// trash, tombstones, versions, prior names), the snapshot records, the key history and the vault itself. The
// collector (db::query::sync::Manifest::collect) builds it from the database; the reader rebuilds it from the bucket;
// ManifestContent tests compare the two.
namespace vh::sync::manifest {

struct Content {
    Producer producer;
    std::optional<VaultInfo> vault;
    std::vector<KeyRecord> keys;                 // ascending by version
    std::optional<RecoveryPolicy> recovery_policy;
    std::vector<Entry> entries;                  // ascending by uid, unique
    std::vector<SnapshotRecord> snapshots;       // ascending by id, unique

    [[nodiscard]] bool operator==(const Content&) const = default;
};

// Sorts entries (by uid), keys (by version) and snapshots (by id). Throws std::invalid_argument on a duplicate uid,
// version or snapshot id.
void normalize(Content& content);

// files = live (not trashed) files, dirs = directories (the vault root included), bytes = the live files' sizes.
[[nodiscard]] Stats statsOf(const Content& content);

// §3.4 step 3, "merge our pending changes on top": `ours` is what this writer produces now, `oursBefore` what it
// produced for its previous publish (the base of its pending changes), `theirs` the newer root another writer
// published. An entry (by uid), key version or snapshot that we changed since oursBefore takes our value; one we
// deleted goes; everything else keeps theirs, including what they added. The producer, vault and recovery policy are
// ours. With oursBefore == theirs (nobody else wrote) the result is `ours`.
[[nodiscard]] Content mergePending(const Content& theirs, const Content& oursBefore, const Content& ours);

// History the database doesn't hold, carried from the previous root into the next one (`now` is the publish time):
//   - a file whose parent or name changed since `previous` gets its previous location prepended to `names`, which
//     keeps at most kMaxPriorNames, and only names newer than the file's oldest retained provider version (a file with
//     no retained versions has no older content to place, so none);
//   - a tombstone the collector built from provider versions alone gets its last parent and name from the file entry
//     it replaces, and that file's prior names.
void carryHistory(const Content& previous, Content& next, const std::string& now);

}
