#pragma once

#include "crypto/vhf1/Format.hpp"
#include "sync/manifest/Chain.hpp"
#include "sync/manifest/Content.hpp"
#include "sync/manifest/Store.hpp"
#include "sync/manifest/VersionLog.hpp"

#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// Loading a manifest from the bucket (spec 03 §4.1, §4.2) and the floor below it (§4.3).
//
// load(): GET the root, authenticate it (kind 3, object uid = vault uid, a held key), apply the chain rules against
// what the caller knows, then fetch and authenticate every segment it pins. Failures fall back in the spec's order:
//   root missing or not authentic   (a) the newest authentic root among the provider's versions of .vaulthalla/root,
//                                   chain rules applied to it; nothing usable throws NoUsableRoot, and the caller
//                                   rebuilds from its database (the daemon publishes) or blind (blindRebuild).
//   segment missing or mismatched   (a) a provider version of the segment that matches the pin; (b) the same uid
//                                   range from an older authentic root whose segment is intact (stale: the restore
//                                   reconciles it with the objects); (c) the range is left to a blind rebuild.
// Every fallback is reported (issues); none is silent. Rollback and fork always throw ChainRejected.
namespace vh::sync::manifest {

class NoUsableRoot : public std::runtime_error {
public:
    explicit NoUsableRoot(const std::string& message) : std::runtime_error(message) {}
};

enum class RootSource { Current, ProviderVersion };

enum class Resolution { ProviderVersion, OlderRoot, Blind };
[[nodiscard]] std::string_view to_string(Resolution resolution);

struct SegmentIssue {
    std::string sid;
    std::optional<Range> range;      // nullopt: a snapshot segment
    std::string problem;             // segment_missing | segment_mismatch | the reader error (bad_segment, ...)
    Resolution resolution{Resolution::Blind};
    std::optional<uint64_t> from_epoch;  // OlderRoot: the epoch of the root the range came from
};

// One segment as loaded: its pin and plaintext, which the publisher compares to reuse it unchanged, and its sealed
// bytes while this writer has them in hand (loaded or written by this call; empty in a cached base once recorded: the
// local base copy, migration 145, already holds them by sid).
struct LoadedSegment {
    SegmentRef ref;
    std::string plaintext;
    std::vector<uint8_t> sealed;
};

struct LoadedSnapshot {
    SnapshotRef ref;
    std::string plaintext;
    std::vector<uint8_t> sealed;
};

struct Loaded {
    RootDocument root;
    Acceptance acceptance;           // epoch, root hash, gap
    std::optional<std::string> etag;  // the current root's ETag (absent when the root came from a provider version)
    RootSource source{RootSource::Current};
    Content content;
    std::vector<SegmentIssue> issues;
    std::vector<Range> blind_ranges;  // uid ranges no intact segment covers
    std::map<Range, LoadedSegment> segments;          // the pinned segments that loaded as pinned
    std::map<std::string, LoadedSnapshot> snapshots;  // by snapshotKey
    std::vector<uint8_t> root_bytes;                  // the root object as read
    // version_log buckets (spec 06 §5.3): the canonical head's provider version, the version of the root before it on
    // the chain with the ids listed between the two (its settle window), the versions newer than the head that are
    // not on the chain (repair deletes them), and how many root versions this read fetched.
    std::optional<std::string> version_id;
    std::optional<std::string> base_version_id;
    std::vector<std::string> settle_window;
    std::vector<std::string> strays;
    unsigned root_gets{};

    [[nodiscard]] Known known() const { return {acceptance.epoch, acceptance.root_sha256, version_id}; }
};

// The settled root's window (spec 06 §5.3), checked before the anchor is trusted.
struct SettledWindow {
    std::string base_version_id;
    std::string version_id;
    std::vector<std::string> window;
};

struct LoadOptions {
    std::optional<Known> known;
    bool use_provider_versions{true};  // false: no ListObjectVersions / versioned GETs (no fallbacks, no gap walk)
    std::optional<StoredObject> root_object;  // the current root, when the caller already fetched it (saves a GET)
    // version_log buckets (store.mode()): the cache of opened root versions (kept across reads by the caller; a local
    // one otherwise) and the settled root's window. root_object and use_provider_versions don't apply there: the
    // listing is the log.
    RootCache* root_cache{nullptr};
    std::optional<SettledWindow> settled{};
};

// Throws ChainRejected (rollback, fork), NoUsableRoot, or the store's errors (transport, budget).
[[nodiscard]] Loaded load(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                          const LoadOptions& options = {});

// ---- the local base copy (design/sync/manifest-applier.md, "The merge base"; migration 145) ---------------------------

// The sealed bytes of the known root and of the segments and snapshot segments it names (by sid), kept in the
// database so the content of `known` is available after a restart and after the bucket collected that root.
struct BaseCopy {
    std::vector<uint8_t> root;
    std::map<std::string, std::vector<uint8_t>> objects;   // sid → sealed bytes
};

// The base copy of what `known` names: every sid the root names, from what this writer has in hand (sealed bytes
// loaded or written by this call). The store keeps the bytes of a named sid it already holds when `objects` lacks it.
// nullopt when the root's bytes aren't in hand (a synthetic base).
[[nodiscard]] std::optional<BaseCopy> baseCopyOf(const RootDocument& root, const std::vector<uint8_t>& rootBytes,
                                                 const std::map<Range, LoadedSegment>& segments,
                                                 const std::map<std::string, LoadedSnapshot>& snapshots);

// Opens a base copy with the reader's own checks: the root's bytes hash to known.root_sha256 and authenticate (kind 3,
// this vault, a held key), and every segment and snapshot segment it names is present, matches its pin (SHA-256,
// size) and authenticates. The content of `known`, or nullopt with the reason in *why (a copy written before an
// incomplete load, a key no longer held, a copy of another root): the caller then does what it did without one.
[[nodiscard]] std::optional<Content> openBaseCopy(const BaseCopy& copy, const Uid& vaultUid,
                                                  const crypto::vhf1::KeyLookup& keys, const Known& known,
                                                  std::string* why = nullptr);

// Content from loaded root + segments (entries in uid order).
[[nodiscard]] Content contentOf(const RootDocument& root, const std::vector<SegmentDocument>& segments,
                                const std::vector<SnapshotDocument>& snapshots);

// ---- blind rebuild (§4.3) ---------------------------------------------------------------------------------------

struct RecoveredObject {
    Uid uid{};
    std::string key;                 // o/<uid>
    std::string path;                // /Recovered/<uid>
    uint64_t object_size{};
    uint64_t plaintext_size{};
    uint32_t key_version{};
    std::string generation;          // hex salt
};

struct BlindReport {
    std::vector<RecoveredObject> recovered;
    std::vector<std::string> rejected;   // "o/<uid>: <reason>" for objects that did not authenticate
    uint64_t header_bytes{};             // bytes fetched: headers only
};

// Lists o/, reads each object's 120-byte header with one ranged GET, and keeps those that authenticate under a held
// key (kind 1, this vault, the uid the key names) as /Recovered/<uid> with their sizes, key versions and
// generations. Names and the tree are lost here; content is not. `only`, when set, limits it to uids in that range.
[[nodiscard]] BlindReport blindRebuild(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                                       const std::optional<Range>& only = std::nullopt);

// ---- freshness (§4.5) -------------------------------------------------------------------------------------------

// A customer checkpoint: recorded outside the bucket (Desktop, the recovery kit), the only thing that bounds replay.
struct Checkpoint {
    uint64_t epoch{};
    std::string root_sha256;
    std::optional<std::string> at;
};

enum class Freshness {
    Unverified,        // no checkpoint: this may be any earlier valid state
    Verified,          // at least as new as the checkpoint (still can't rule out a state between it and the latest)
    RollbackAccepted,  // older than the checkpoint, accepted on the operator's explicit request
};
[[nodiscard]] std::string_view to_string(Freshness freshness);

struct RestoreLoad {
    Loaded loaded;
    Freshness freshness{Freshness::Unverified};
    std::string report;  // the line a restore report carries
};

inline constexpr std::string_view kFreshnessUnverified = "freshness unverified: no checkpoint supplied";

// The restore's load: the checkpoint is `known`. Without one the result says kFreshnessUnverified. A root older than
// the checkpoint is ChainRejected(Rollback) unless acceptRollback, which loads it without the checkpoint and says so;
// a fork against the checkpoint is always refused.
[[nodiscard]] RestoreLoad loadForRestore(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                                         const std::optional<Checkpoint>& checkpoint, bool acceptRollback = false);

}
