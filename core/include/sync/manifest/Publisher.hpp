#pragma once

#include "sync/manifest/Content.hpp"
#include "sync/manifest/Objects.hpp"
#include "sync/manifest/Partition.hpp"
#include "sync/manifest/Reader.hpp"

#include <cstdint>
#include <ctime>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

// The publish protocol (spec 03 §3.4), copy-on-write:
//   1. the changed segments are PUT as new `seg/<sid>` objects (fresh random sid) with If-None-Match: *; unchanged
//      ones (same range, same plaintext) are reused by reference;
//   2. the root (epoch = known + 1, prev = known root hash) is sealed under the current key version and PUT with
//      If-Match: <known root ETag> (If-None-Match: * at epoch 1);
//   3. 412: another writer published. Its root is loaded and verified (chain rules against the root this writer last
//      saw), our pending changes are merged on top (Content.hpp mergePending), and the publish retries, bounded;
//      never a blind overwrite;
//   4. the caller records (epoch, root hash, ETag) and the root's sids (db::query::sync::Manifest);
//   5. collectGarbage deletes segments none of the last three roots name, once they are older than 24 h.
// Objects are always written before the root that names them: a crash leaves orphans, never a dangling reference.
//
// A one-file change of a vault that fits one segment costs one segment PUT and one root PUT, and no GET while the
// cache holds the previous publish (ManifestPublish.OneFileChangeCostsOneSegmentAndOneRootPut).
namespace vh::sync::manifest {

class PublishConflict : public std::runtime_error {
public:
    explicit PublishConflict(const std::string& message) : std::runtime_error(message) {}
};

// The bucket can't take this publish protocol: its stored capability (ObjectStore::mode()) is VersionLog or
// Insufficient, and the root publish without preconditions (design/encryption/06-publish-without-preconditions.md
// §5) is not implemented yet. Thrown before any request: nothing is written, never half a publish.
class PublishUnsupported : public std::runtime_error {
public:
    explicit PublishUnsupported(const std::string& message) : std::runtime_error(message) {}
};

// What is in the bucket after a publish, as this writer knows it.
struct Published {
    Known known;
    std::optional<std::string> etag;
    RootDocument root;
    Content content;
    std::map<Range, LoadedSegment> segments;
    std::map<uint64_t, LoadedSnapshot> snapshots;

    // Every segment and snapshot sid the root names (what GC must keep for it).
    [[nodiscard]] std::vector<std::string> sids() const;
};

// Kept by the caller between publishes (per vault, in memory): the last publish, so the next one needs no GET, and
// what this writer produced for it, the base of its pending changes.
struct PublisherCache {
    std::optional<Published> base;
    std::optional<Content> last_produced;
};

struct PublishOptions {
    std::string now;                 // published_at, and the `until` of prior names (isoTime(time(nullptr)))
    unsigned max_attempts{3};
    PartitionLimits limits{};
};

struct PublishReport {
    Published published;
    unsigned segments_written{};
    unsigned segments_reused{};
    unsigned snapshots_written{};
    unsigned attempts{1};
    bool merged{false};        // another writer's root was merged under ours
    bool gap{false};           // that root was accepted with a gap warning
    bool root_rebuilt{false};  // the bucket's root was missing or unreadable: rebuilt from our state, chain continued
};

// produced: the vault's content as this writer has it (the database). known: the last root this vault recorded
// (remote_manifest_state), nullopt before its first publish. keys opens roots and segments other writers sealed.
// Throws ChainRejected when the bucket's root is a rollback or fork against `known` (nothing is written then),
// PublishConflict after max_attempts conflicts, NoUsableRoot when the bucket holds a root this vault can't read and
// it has no state of its own to continue from, PublishUnsupported (before any request) when the store's mode()
// doesn't send preconditions, and ConditionsUnsupported when a bucket probed as conditional refuses a condition.
[[nodiscard]] PublishReport publish(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                                    const SealingKey& sealing, const Content& produced,
                                    const std::optional<Known>& known, PublisherCache& cache,
                                    const PublishOptions& options);

struct GcReport {
    std::vector<std::string> deleted;  // segment keys
    std::size_t retained{};            // named by one of the retained roots
    std::size_t young{};               // unnamed, but younger than the minimum age (or of unknown age)
};

// Deletes `.vaulthalla/seg/` objects that no retained root names (the current root and the previous two: a reader
// that loaded an older root a moment ago still finds its segments) and that are older than minAgeSeconds (24 h; an
// in-flight publish writes its segments before its root).
GcReport collectGarbage(ObjectStore& store, const std::set<std::string>& retainedSids, std::time_t now,
                        std::time_t minAgeSeconds = 24 * 60 * 60);

}
