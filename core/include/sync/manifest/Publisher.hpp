#pragma once

#include "sync/manifest/Content.hpp"
#include "sync/manifest/Objects.hpp"
#include "sync/manifest/Partition.hpp"
#include "sync/manifest/Reader.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <functional>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

// The publish protocol (spec 03 §3.4), copy-on-write, on a bucket that honours conditional writes:
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
//
// On a bucket without conditional writes that keeps versions (store.mode() VersionLog; design/encryption/
// 06-publish-without-preconditions.md §5.2) write-once objects are PUT plainly and the root too; then the root key's
// versions are listed and rule C1 decides (VersionLog.hpp): our root won when it is the earliest successor of the base
// (recorded with its version id and settle window, and every non-canonical version newer than the head is deleted
// by id: repair); it lost when another one is, and then our version is deleted by id and the publish merges onto the
// head and retries. A PUT whose outcome is unknown (transport error, 5xx) looks for our version by hash first. One
// LIST more than the conditional path when nobody else writes.
//
// Both modes: the root names its `publish` mode and `writers` (the base's set while it names this server, else this
// server alone: a restore takes the vault over). A head this server didn't write that names another mode is refused
// (PublishModeMismatch); a head newer than this server's last own root whose writers exclude it is refused
// (Superseded, spec 06 §5.5).
namespace vh::sync::manifest {

class PublishConflict : public std::runtime_error {
public:
    explicit PublishConflict(const std::string& message) : std::runtime_error(message) {}
};

// The bucket can't take a manifest at all: its stored capability (ObjectStore::mode()) is Insufficient, neither
// conditional writes nor object versions (design/encryption/06-publish-without-preconditions.md §7). Thrown before
// any request: nothing is written, never half a publish.
class PublishUnsupported : public std::runtime_error {
public:
    explicit PublishUnsupported(const std::string& message) : std::runtime_error(message) {}
};

// version_log: the published root's provider version, the version of its base and the ids listed between them when
// it settled (its settle window, spec 06 §5.3).
struct Settled {
    std::optional<std::string> version_id;
    std::optional<std::string> base_version_id;
    std::vector<std::string> window;
};

// What is in the bucket after a publish, as this writer knows it.
struct Published {
    Known known;
    std::optional<std::string> etag;
    RootDocument root;
    Content content;
    std::map<Range, LoadedSegment> segments;
    std::map<uint64_t, LoadedSnapshot> snapshots;
    Settled settled;   // version_log

    // Every segment and snapshot sid the root names (what GC must keep for it).
    [[nodiscard]] std::vector<std::string> sids() const;
};

// Kept by the caller between publishes (per vault, in memory): the last publish, so the next one needs no GET, and
// what this writer produced for it, the base of its pending changes; on version_log buckets the opened root versions.
struct PublisherCache {
    std::optional<Published> base;
    std::optional<Content> last_produced;
    RootCache roots;
};

struct PublishOptions {
    std::string now;                 // published_at, and the `until` of prior names (isoTime(time(nullptr)))
    unsigned max_attempts{3};
    PartitionLimits limits{};
    // spec 06 §5.5: this server's node id (the root's `writers`; empty: no writers member and no superseded check)
    // and the epoch of the last root it published itself (nullopt: none, e.g. a fresh restore).
    std::string self_node{};
    std::optional<uint64_t> own_epoch{};
    // version_log: the settled root's window (order_violation check), and how long to wait between listings while our
    // own version isn't listed yet (§5.2 step 3: 1, 2, 4, 8 s), through `sleep` (tests advance a fake clock instead).
    std::optional<SettledWindow> settled{};
    std::vector<std::chrono::milliseconds> listing_retries{std::chrono::seconds(1), std::chrono::seconds(2),
                                                           std::chrono::seconds(4), std::chrono::seconds(8)};
    std::function<void(std::chrono::milliseconds)> sleep{};
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
    // version_log
    Settled settled;
    std::vector<std::string> repaired;   // version ids deleted after the publish settled (stray newer versions)
    // Authentic roots above ours with a higher epoch, left in place (never repaired): the next read judges them.
    std::vector<std::string> ahead;
    unsigned lost{0};                    // rounds our root lost to another writer's
};

// spec 06 §5.5 and I9, for a head this server is about to build on or adopt: refused with PublishModeMismatch when
// another writer published it in a mode other than the bucket's (store.mode()), and with Superseded when it is newer
// than this server's last own root (ownEpoch) and its writers don't name selfNode. No check without a selfNode.
void checkHeadForWriter(const RootDocument& head, const std::string& rootSha256, const ObjectStore& store,
                        const std::string& selfNode, const std::optional<uint64_t>& ownEpoch);

// version_log: our root's version isn't listed yet after every retry (the listing lags behind the PUT). Nothing is
// recorded; the changes stay pending and the next publish settles or supersedes it.
class PublishUnsettled : public std::runtime_error {
public:
    explicit PublishUnsettled(const std::string& message) : std::runtime_error(message) {}
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

// version_log (spec 06 §5.4): when each unreferenced segment was first seen unreferenced (the database's
// remote_manifest_gc; a map in tests).
struct UnreferencedClock {
    std::function<std::time_t(const std::string& sid)> first;   // sets it to now once, returns it
    std::function<void(const std::string& sid)> forget;
};

// version_log GC: every version of a `.vaulthalla/seg/` key no retained root names, once it has been unreferenced for
// minAgeSeconds, is deleted by id (a DELETE by name would only hide the newest version on a bucket that keeps them).
GcReport collectGarbageVersionLog(ObjectStore& store, const std::set<std::string>& retainedSids, std::time_t now,
                                  const UnreferencedClock& clock, std::time_t minAgeSeconds = 24 * 60 * 60);

// version_log root janitor (spec 06 §5.4): deletes by id the versions of `.vaulthalla/root` older than the head's
// second canonical predecessor once older than supersededAge (7 days), the non-canonical versions between it and the
// head once older than strayAge (24 h), and older delete markers. Never the head or its two predecessors; versions
// newer than the head are repair's. headVersionId: the settled head.
struct JanitorReport {
    std::vector<std::string> deleted;
    std::size_t kept{};
};
JanitorReport collectRootVersions(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                                  RootCache& cache, const std::string& headVersionId, std::time_t now,
                                  std::time_t supersededAge = 7 * 24 * 60 * 60, std::time_t strayAge = 24 * 60 * 60);

// Deletes `.vaulthalla/seg/` objects that no retained root names (the current root and the previous two: a reader
// that loaded an older root a moment ago still finds its segments) and that are older than minAgeSeconds (24 h; an
// in-flight publish writes its segments before its root).
GcReport collectGarbage(ObjectStore& store, const std::set<std::string>& retainedSids, std::time_t now,
                        std::time_t minAgeSeconds = 24 * 60 * 60);

}
