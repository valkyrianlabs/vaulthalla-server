#pragma once

#include "sync/manifest/Publisher.hpp"

#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <vector>

// Manifest v2 for one opaque_v1 vault as a writer runs it (spec 03 §3.4, §4.1; spec 06 §5): publish what the vault
// holds on top of the bucket's root, record the chain position, verify roots other writers published, refuse and
// alert on a rollback or fork, repair stray root versions, and collect superseded segments once a day.
//
// The session is the decision logic and nothing else. What it remembers between runs is behind StateStore (the server:
// PostgreSQL, db::query::sync::Manifest), what it needs from its host behind SessionHost (the vault's content and
// keys, this writer's identity, the clock, where alerts and notices go). It includes nothing of the server: no
// database, no logging, no notification bus.
//
// A refused root (rollback, fork, order violation, superseded, publish mode mismatch) leaves the recorded state
// untouched and is recorded as refused; the host is alerted once per refused root. Nothing is published over it until
// the bucket's root is one the chain rules accept again.
namespace vh::sync::manifest {

// The chain position a vault recorded, as StateStore returns it.
struct ChainState {
    std::optional<uint64_t> epoch;
    std::optional<std::string> root_sha256;
    std::optional<std::string> etag;
    std::optional<std::string> refused_reason;   // rollback | fork | order_violation | superseded | publish_mode_mismatch
    std::optional<uint64_t> refused_epoch;
    std::optional<std::string> refused_root_sha256;
    std::optional<std::time_t> refused_at;
    std::optional<std::time_t> gc_at;
    // version_log buckets (design/encryption/06-publish-without-preconditions.md §5).
    std::optional<std::string> root_version_id;
    std::optional<std::string> base_version_id;
    std::vector<std::string> settle_window;
    std::optional<uint64_t> own_epoch;   // the last root this writer published itself
};

// One recorded root. version_id, base_version_id and the window on version_log buckets; own when this writer wrote it.
struct RootRecord {
    uint64_t epoch{};
    std::string root_sha256;
    std::optional<std::string> etag;
    std::vector<std::string> sids;
    std::optional<std::string> version_id;
    std::optional<std::string> base_version_id;
    std::vector<std::string> settle_window;
    bool own{false};
};

// What one vault keeps between runs. Every call is for that vault; implementations are durable before they return
// (a root counts as settled only once recordRoot returned).
class StateStore {
public:
    virtual ~StateStore() = default;

    [[nodiscard]] virtual ChainState state() = 0;
    // A root this writer published (or verified as the next one): its chain position, ETag and version ids, plus its
    // sids in the root history, which keeps the newest roots' (retainedSids). Clears a recorded refusal (the chain
    // moved on).
    virtual void recordRoot(const RootRecord& record) = 0;
    // A root the chain rules refused. True when it is not the root already recorded as refused: the session alerts
    // once per root, not once per pass.
    [[nodiscard]] virtual bool recordRefused(const std::string& reason, uint64_t epoch,
                                             const std::string& rootSha256) = 0;
    // Every sid the retained roots name.
    [[nodiscard]] virtual std::set<std::string> retainedSids() = 0;
    // Garbage was collected now (ChainState::gc_at).
    virtual void markCollected() = 0;
    // version_log GC (spec 06 §5.4): when a segment became unreferenced by the canonical chain. first sets it (now)
    // once and returns it; forget drops it (referenced again, or collected).
    [[nodiscard]] virtual std::time_t firstUnreferenced(const std::string& sid) = 0;
    virtual void forgetUnreferenced(const std::string& sid) = 0;
};

// A root the session refused, for the host's alert.
struct Refusal {
    ChainError reason{};
    uint64_t epoch{};
    std::string root_sha256;
    std::optional<Known> known;   // the chain position recorded when it was refused
};

enum class Notice { Info, Warning, Error };

// What a session needs from whoever runs it. collect, currentKey, keys, nodeId and now are required; alert and note
// may be empty (nothing is told).
struct SessionHost {
    std::function<Content()> collect;                 // what the vault holds now, as a manifest says it
    std::function<SealingKey()> currentKey;           // the key new documents are sealed under, with its version
    crypto::vhf1::KeyLookup keys;                     // every key version this writer holds
    std::function<std::string()> nodeId;              // this writer's name in a root's `writers`
    std::function<std::time_t()> now;                 // the clock a publish stamps its root with
    std::function<void(const Refusal&)> alert;        // a root was refused: called once per refused root
    std::function<void(Notice, const std::string&)> note;   // what happened, for a log (one sentence, no prefix)
};

class Session {
public:
    // Throws std::invalid_argument without a store, a state store or one of the host's required members.
    Session(const Uid& vaultUid, std::shared_ptr<ObjectStore> store, std::shared_ptr<StateStore> state,
            SessionHost host);

    // Collects, publishes, records. Rethrows ChainRejected (after recording and alerting), PublishConflict and the
    // store's errors.
    PublishReport publish();
    // publish() unless the vault holds exactly what this session's last publish produced and the bucket's root is
    // still that publish (a sync pass that changed nothing writes nothing, spec 01 §5): nullopt then.
    std::optional<PublishReport> publishIfChanged();

    // Checks the bucket's current root against the recorded state without loading segments: one GET of the root
    // when its ETag moved. An accepted newer root (another writer) becomes the known state; nullopt when there is no
    // root or it doesn't authenticate (the next publish rebuilds it). Rethrows ChainRejected after recording and
    // alerting.
    std::optional<Acceptance> verifyRemote();

    // GC when the last one was more than a day before `now` (ChainState::gc_at); nullopt when not due.
    std::optional<GcReport> collectGarbageIfDue(std::time_t now);

private:
    void refused(const ChainRejected& e, uint64_t epoch, const std::string& rootSha256);
    // verifyRemote on a version_log bucket (spec 06 §5.3, §5.4): rule C1 from the settled root, the settle window,
    // the writers and mode checks, and repair of stray versions above the head.
    std::optional<Acceptance> verifyRemoteVersionLog();
    PublishReport publishLocked(const Content& produced);
    [[nodiscard]] std::optional<Known> known() const;
    void note(Notice level, const std::string& message) const;

    Uid vaultUid_;
    std::shared_ptr<ObjectStore> store_;
    std::shared_ptr<StateStore> state_;
    SessionHost host_;
    std::mutex mutex_;
    PublisherCache cache_;
};

}
