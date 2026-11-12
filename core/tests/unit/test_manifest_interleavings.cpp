// The version_log publish protocol (design/encryption/06-publish-without-preconditions.md §5) under interleavings and
// faults (§8.2), DB-free, on the versioned fake bucket answering conditional PUTs as Backblaze B2 does (501).
//
// ManifestVersionLogInterleavings  every interleaving of two writers and a reader; every root-PUT-level interleaving
//                                   of three writers; seeded random schedules of three writers and a reader.
// ManifestVersionLogFaults         a crash before and after every step of one writer (restart from the database
//                                   only), raced by every order of the other writer's PUTs and by seeded schedules; a
//                                   lost PUT reply (a 5xx after the commit), a 5xx before it, failed DELETEs and
//                                   listings, at every step under every interleaving of two writers.
// ManifestVersionLogBrokenOrder    listings that lag (A3) and versions ordered by start (A4): every run keeps I3 or
//                                   ends in order_violation.
//
// The scheduler. Every actor (a writer publishing once, a reader loading once) runs on its own thread over a
// HookedStore whose `before` hook parks it at each *scheduling point*: a request on `.vaulthalla/root` that orders
// against other actors: the PUT, ListObjectVersions, and a DELETE by version id. Exactly one actor runs at a time: the
// controller grants a parked one, which runs until its next point or its end, and checks the invariants while every
// actor is parked. The other requests (segment, snapshot and layout-hint PUTs and GETs, root GETs by version id) run in
// the slot of the actor's preceding point.
//
// Why that bound is sound (every interleaving of all requests is equivalent to one enumerated here): segment keys are
// fresh random sids, written once and read only through a root naming them (I1), so their requests commute with every
// other actor's. A root GET by version id reads immutable bytes. It races only a DELETE of that same version, and
// Vaulthalla deletes only versions that are non-canonical in every listing that shows them (a loser's, a stray's: I6,
// checked below), so whether that GET finds the bytes or a 404 changes no C1 decision. What remains is the order of the
// root PUTs, listings and DELETEs, which the exhaustive runs enumerate in full (stateless depth-first search over the
// choice of the next actor; a run is deterministic given its choices, which the search asserts).
//
// Invariants (§6), after every step: I1 every authentic root's segments exist; I3 the canonical chain from the genesis
// only grows (a prefix of every later one); I5 a writer's recorded root and the reader's result are canonical; I6
// nothing Vaulthalla deleted was ever canonical; I9 every root names version_log. At quiescence: one head, nothing
// stray above it, every writer's changes in it.

#include "../helpers/hooked_store.hpp"
#include "../helpers/versioned_bucket.hpp"
#include "crypto/SecretKey.hpp"
#include "sync/manifest/Chain.hpp"
#include "sync/manifest/Content.hpp"
#include "sync/manifest/Document.hpp"
#include "sync/manifest/Objects.hpp"
#include "sync/manifest/Publisher.hpp"
#include "sync/manifest/Reader.hpp"
#include "sync/manifest/Store.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <condition_variable>
#include <exception>
#include <functional>
#include <mutex>
#include <random>
#include <set>
#include <thread>

namespace vh::sync::manifest::test_manifest_interleavings {

namespace interleaving_fixture {

using Bytes = std::vector<uint8_t>;
using test_support::manifest_store::HookedStore;
using test_support::manifest_store::StoreOp;
using test_support::versioned::VersionedBucket;
using test_support::versioned::Versioning;

constexpr std::time_t kStart = 1793880000;

crypto::SecretKeyPtr keyOf(const uint8_t seed) {
    Bytes k(32);
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed + i);
    return std::make_shared<const crypto::SecretKey>(k);
}

std::string uidT(const uint8_t first, const uint8_t fill) {
    Uid u{};
    u.fill(fill);
    u[0] = first;
    return uidText(u);
}

const std::string& rootUid() {
    static const std::string uid = uidT(0x01, 0x11);
    return uid;
}

Entry fileEntry(const std::string& uid, std::string name, const uint64_t size) {
    Entry e;
    e.uid = uid;
    e.kind = EntryKind::File;
    e.parent = rootUid();
    e.name = std::move(name);
    e.mode = 0644;
    e.mtime = "2026-11-05T12:01:00Z";
    e.size = size;
    e.format = 1;
    e.key_version = 1;
    e.object = ObjectRef{"\"etag-" + e.uid.substr(0, 6) + "\"", size + 136, std::nullopt, std::nullopt};
    return e;
}

Content baseContent() {
    Content c;
    c.producer = {"node-0", 1, "vaulthalla test"};
    c.recovery_policy = RecoveryPolicy{};
    c.keys = {KeyRecord{1, std::nullopt, std::nullopt, "2026-11-01T00:00:00Z", std::nullopt, std::nullopt, std::nullopt}};
    Entry root;
    root.uid = rootUid();
    root.kind = EntryKind::Dir;
    root.name = "";
    root.mode = 0755;
    root.mtime = "2026-11-05T12:00:00Z";
    c.entries.push_back(root);
    for (uint8_t i = 0; i < 3; ++i) c.entries.push_back(fileEntry(uidT(static_cast<uint8_t>(0x20 + i), i), "base-" + std::to_string(i), 100 + i));
    normalize(c);
    return c;
}

std::string nodeName(const std::size_t i) { return "node-" + std::to_string(i); }
std::string fileOf(const std::size_t i) { return "from-" + nodeName(i); }

// What writer i publishes: the base plus one file of its own (its pending change).
Content producedBy(const std::size_t i) {
    auto c = baseContent();
    c.producer.node_id = nodeName(i);
    c.entries.push_back(fileEntry(uidT(static_cast<uint8_t>(0x80 + i), 0x77), fileOf(i), 7));
    normalize(c);
    return c;
}

// A crash: not a std::exception, so no `catch (const std::exception&)` on the way out swallows it.
struct Crash {};

enum class Fault { None, CrashBefore, CrashAfter, LoseReply, FailBefore };

struct FaultPlan {
    std::size_t actor{};
    unsigned at{};                // the actor's at-th scheduling point (0-based, counted across restarts)
    Fault kind{Fault::None};
};

// Which root requests are scheduling points: every PUT, listing and DELETE of the root; only its PUTs; or every one of
// the faulty actor's and only the others' PUTs (a fault at every step of one actor, raced at the PUT level).
enum class Gating { RootOps, RootPutsOnly, FaultyActorFull };

struct Scenario {
    std::size_t writers{2};
    bool reader{true};
    Gating gating{Gating::RootOps};
    FaultPlan fault{};
    std::time_t listing_lag{0};
    bool order_by_start{false};
};

// The world one run shares.
struct World {
    std::shared_ptr<VersionedBucket> bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
    Uid vault = [] {
        Uid u{};
        u.fill(0x48);
        u[0] = 0x56;
        return u;
    }();
    std::map<uint32_t, crypto::SecretKeyPtr> keys{{1, keyOf(7)}};

    [[nodiscard]] crypto::vhf1::KeyLookup lookup() const {
        return [k = keys](const uint32_t v) -> crypto::SecretKeyPtr {
            const auto it = k.find(v);
            return it == k.end() ? nullptr : it->second;
        };
    }
    [[nodiscard]] SealingKey sealing() const { return {1, keys.at(1)}; }
    [[nodiscard]] std::shared_ptr<ObjectStore> plainStore() const {
        return std::make_shared<S3Store>(bucket, storage::s3::WriteCapability::VersionLog);
    }

    // Written by actors (one runs at a time), read by the controller while every actor is parked.
    std::set<std::string> deleted;           // root versions Vaulthalla deleted
    std::set<std::string> failed_deletes;    // root versions whose DELETE a fault refused
    bool free{false};                        // the final phase: hooks don't park
};

// What Service keeps in remote_manifest_state: all a restart has.
struct Db {
    std::optional<Known> known;
    std::optional<uint64_t> own_epoch;
    std::optional<SettledWindow> settled;
};

struct WriterState {
    std::size_t index{};
    Db db;
    PublisherCache cache;
    bool pending{true};
    unsigned crashes{0};
    unsigned lost{0};
    std::optional<ChainError> refused;
    std::string failure;
    std::vector<std::string> recorded;    // every root version this writer recorded as settled
    int clock{0};
};

struct ReaderState {
    std::optional<Known> anchor;
    std::optional<Known> result;
    std::optional<SettledWindow> settled;   // as verifyRemote records what it read
    std::optional<ChainError> refused;
    std::string failure;
};

// ---- the scheduler --------------------------------------------------------------------------------------------------

class Scheduler {
public:
    explicit Scheduler(const std::size_t actors) : state_(actors) {}

    // Actor side: park until granted.
    void park(const std::size_t a) {
        std::unique_lock l(m_);
        state_[a].parked = true;
        cv_.notify_all();
        cv_.wait(l, [&] { return state_[a].go; });
        state_[a].go = false;
    }
    void done(const std::size_t a) {
        std::scoped_lock l(m_);
        state_[a].done = true;
        state_[a].parked = false;
        cv_.notify_all();
    }

    // Controller side: wait until no actor runs, then the parked ones (ascending).
    std::vector<std::size_t> quiet() {
        std::unique_lock l(m_);
        cv_.wait(l, [&] { return std::ranges::all_of(state_, [](const S& s) { return s.parked || s.done; }); });
        std::vector<std::size_t> out;
        for (std::size_t i = 0; i < state_.size(); ++i)
            if (state_[i].parked) out.push_back(i);
        return out;
    }
    void grant(const std::size_t a) {
        std::scoped_lock l(m_);
        state_[a].parked = false;
        state_[a].go = true;
        cv_.notify_all();
    }

private:
    struct S {
        bool parked{false};
        bool go{false};
        bool done{false};
    };
    std::mutex m_;
    std::condition_variable cv_;
    std::vector<S> state_;
};

// Picks the next actor among n parked ones.
using Chooser = std::function<std::size_t(std::size_t n)>;

// Stateless depth-first search over the choices: run, then advance the last choice that has a sibling left.
class Dfs {
public:
    std::size_t choose(const std::size_t n) {
        std::size_t c = 0;
        if (depth_ < prefix_.size()) {
            c = prefix_[depth_];
            if (c >= n) nondeterministic_ = true;
            c = std::min(c, n - 1);
        }
        path_.emplace_back(c, n);
        ++depth_;
        return c;
    }
    bool next() {
        while (!path_.empty() && path_.back().first + 1 >= path_.back().second) path_.pop_back();
        if (path_.empty()) return false;
        prefix_.clear();
        for (const auto& [c, n] : path_) prefix_.push_back(c);
        ++prefix_.back();
        path_.clear();
        depth_ = 0;
        return true;
    }
    [[nodiscard]] bool nondeterministic() const { return nondeterministic_; }
    [[nodiscard]] std::size_t depth() const { return path_.size(); }

private:
    std::vector<std::size_t> prefix_;
    std::vector<std::pair<std::size_t, std::size_t>> path_;
    std::size_t depth_{0};
    bool nondeterministic_{false};
};

// ---- the truth: C1 on the bucket's actual history, without any listing -----------------------------------------------

struct Truth {
    std::vector<std::string> chain;    // canonical version ids from the genesis, oldest first
    std::vector<std::string> above;    // versions and delete markers newer than the head
    std::map<std::string, std::pair<RootDocument, std::string>> roots;   // authentic versions: root, SHA-256
};

// Opened roots by version id (a version's bytes never change; nullopt: doesn't authenticate).
using OpenedRoots = std::map<std::string, std::optional<std::pair<RootDocument, std::string>>>;

Truth truthOf(const World& w, OpenedRoots& cache) {
    auto history = w.bucket->history(std::string(kRootKey));
    std::ranges::reverse(history);
    Truth t;
    std::vector<std::optional<std::pair<RootDocument, std::string>>> opened(history.size());
    for (std::size_t i = 0; i < history.size(); ++i) {
        if (history[i].delete_marker) continue;
        auto it = cache.find(history[i].version_id);
        if (it == cache.end()) {
            std::optional<std::pair<RootDocument, std::string>> o;
            try {
                o = std::pair{openRoot(history[i].body, w.vault, w.lookup()), sha256Hex(history[i].body)};
            } catch (const std::exception&) {
            }
            it = cache.emplace(history[i].version_id, std::move(o)).first;
        }
        opened[i] = it->second;
        if (opened[i]) t.roots.emplace(history[i].version_id, *opened[i]);
    }
    std::optional<std::size_t> head;
    for (std::size_t i = 0; i < history.size(); ++i)
        if (opened[i] && opened[i]->first.epoch == 1 && !opened[i]->first.prev) {
            head = i;
            break;
        }
    if (!head) return t;
    t.chain.push_back(history[*head].version_id);
    for (std::size_t i = *head + 1; i < history.size(); ++i) {
        const auto& cur = *opened[*head];
        if (opened[i] && opened[i]->first.epoch == cur.first.epoch + 1 && opened[i]->first.prev == cur.second) {
            head = i;
            t.chain.push_back(history[i].version_id);
        }
    }
    for (std::size_t i = *head + 1; i < history.size(); ++i) t.above.push_back(history[i].version_id);
    return t;
}

bool onChain(const Truth& t, const std::optional<Known>& k) {
    if (!k || !k->version_id) return false;
    return std::ranges::find(t.chain, *k->version_id) != t.chain.end();
}

// ---- one run ----------------------------------------------------------------------------------------------------------

struct RunReport {
    std::vector<std::string> violations;   // invariant breaks (each a message)
    unsigned steps{0};
    unsigned lost_rounds{0};
    bool fault_fired{false};
    bool order_broken{false};               // the true chain lost an element (A4 broken)
    bool settled_displaced{false};          // a root a writer settled or the reader adopted left the chain
    bool order_violation_seen{false};
    bool reverted_by_restart{false};
};

class Run {
public:
    Run(const Scenario& sc, Chooser choose) : sc_(sc), choose_(std::move(choose)) {}

    RunReport go() {
        setUp();
        const std::size_t actors = sc_.writers + (sc_.reader ? 1 : 0);
        Scheduler sched(actors);
        std::vector<unsigned> points(actors, 0);
        std::vector<std::thread> threads;
        for (std::size_t a = 0; a < actors; ++a)
            threads.emplace_back([&, a] {
                sched.park(a);   // start parked: one actor at a time from the first request on
                try {
                    if (a < sc_.writers) runWriter(sched, a, points[a]);
                    else runReader(sched, a, points[a]);
                } catch (...) {
                    std::scoped_lock l(errorsMutex_);
                    report_.violations.push_back("actor " + std::to_string(a) + " escaped with an exception");
                }
                sched.done(a);
            });
        // Each actor runs to its first point in turn (no request before it is a scheduling point).
        (void)sched.quiet();
        for (std::size_t a = 0; a < actors; ++a) {
            sched.grant(a);
            (void)sched.quiet();
        }
        check();
        for (;;) {
            const auto enabled = sched.quiet();
            if (enabled.empty()) break;
            sched.grant(enabled[choose_(enabled.size())]);
            (void)sched.quiet();
            ++report_.steps;
            check();
        }
        for (auto& t : threads) t.join();
        finish();
        return report_;
    }

private:
    void setUp() {
        world_.bucket->conditionalPuts = VersionedBucket::ConditionalPuts::Reject501;
        world_.bucket->md5Etags = true;
        world_.bucket->setNow(kStart);
        // Node 0 published the genesis; a key holder then named every writer (the mirror join, not built here).
        auto store = world_.plainStore();
        PublisherCache cache;
        PublishOptions o;
        o.now = isoTime(kStart);
        o.self_node = nodeName(0);
        o.sleep = [b = world_.bucket](const std::chrono::milliseconds d) { b->advance(std::max<std::time_t>(1, d.count() / 1000)); };
        const auto first = publish(*store, world_.vault, world_.lookup(), world_.sealing(), baseContent(), std::nullopt, cache, o);
        auto named = first.published.root;
        named.epoch = 2;
        named.prev = first.published.known.root_sha256;
        std::vector<std::string> all;
        for (std::size_t i = 0; i < sc_.writers; ++i) all.push_back(nodeName(i));
        named.writers = all;
        const auto bytes = sealRoot(named, world_.vault, world_.sealing());
        const auto id = world_.bucket->seed(std::string(kRootKey), bytes);
        const Known base{2, sha256Hex(bytes), id};
        writers_.resize(sc_.writers);
        for (std::size_t i = 0; i < sc_.writers; ++i) {
            auto& w = writers_[i];
            w.index = i;
            w.db.known = base;
            if (i == 0) w.db.own_epoch = 1;
            w.cache.last_produced = baseContent();   // the base of its pending change: what it last saw
        }
        reader_.anchor = base;
        world_.bucket->advance(60);   // the setup is long settled: every listing shows it, however it lags
        if (sc_.listing_lag) world_.bucket->listingLag(sc_.listing_lag);
        if (sc_.order_by_start) world_.bucket->orderBy(VersionedBucket::Order::Start);
        prevChain_ = truthOf(world_, opened_).chain;
        everCanonical_.insert(prevChain_.begin(), prevChain_.end());
    }

    [[nodiscard]] bool gated(const std::size_t actor, const StoreOp op, const std::string& key) const {
        if (key != kRootKey) return false;
        if (sc_.gating == Gating::RootPutsOnly || (sc_.gating == Gating::FaultyActorFull && actor != sc_.fault.actor))
            return op == StoreOp::Put;
        return op == StoreOp::Put || op == StoreOp::Versions || op == StoreOp::RemoveVersion;
    }

    std::shared_ptr<HookedStore> hookedFor(Scheduler& sched, const std::size_t a, unsigned& points) {
        auto store = std::make_shared<HookedStore>(world_.plainStore());
        store->before = [&, a](const StoreOp op, const std::string& key, const std::string& versionId, bool) {
            if (world_.free || !gated(a, op, key)) return;
            const auto idx = points++;
            sched.park(a);
            if (sc_.order_by_start && op == StoreOp::Put) {
                // A PUT whose body stalls: ordered where it started (now), committed at a later point.
                world_.bucket->holdPut(key);
                sched.park(a);
            }
            if (sc_.fault.kind == Fault::None || sc_.fault.actor != a || sc_.fault.at != idx || faultFired_) return;
            if (sc_.fault.kind == Fault::CrashBefore) {
                faultFired_ = true;
                throw Crash{};
            }
            if (sc_.fault.kind == Fault::FailBefore) {
                faultFired_ = true;
                if (op == StoreOp::Put) throw PutOutcomeUnknown("HTTP 503 before the commit (test)");
                if (op == StoreOp::RemoveVersion) world_.failed_deletes.insert(versionId);
                throw std::runtime_error("HTTP 503 (test)");
            }
        };
        store->after = [&, a](const StoreOp op, const std::string& key, const std::string& versionId, const bool failed) {
            if (!failed && op == StoreOp::RemoveVersion && key == kRootKey) world_.deleted.insert(versionId);
            if (world_.free || failed || !gated(a, op, key)) return;
            if (sc_.fault.kind == Fault::None || sc_.fault.actor != a || sc_.fault.at + 1 != points || faultFired_) return;
            if (sc_.fault.kind == Fault::CrashAfter) {
                faultFired_ = true;
                throw Crash{};
            }
            if (sc_.fault.kind == Fault::LoseReply) {
                faultFired_ = true;
                if (op == StoreOp::Put) throw PutOutcomeUnknown("HTTP 503 after the commit (test)");
                throw std::runtime_error("the reply was lost (test)");
            }
        };
        return store;
    }

    PublishOptions optionsFor(WriterState& w) {
        PublishOptions o;
        o.now = isoTime(kStart + 600 + 60 * (++w.clock));
        o.self_node = nodeName(w.index);
        o.own_epoch = w.db.own_epoch;
        o.settled = w.db.settled;
        o.sleep = [b = world_.bucket](const std::chrono::milliseconds d) { b->advance(std::max<std::time_t>(1, d.count() / 1000)); };
        return o;
    }

    // One publish attempt sequence; false when it ended without settling (the changes stay pending).
    void publishOnce(ObjectStore& store, WriterState& w) {
        const auto produced = producedBy(w.index);
        try {
            const auto r = publish(store, world_.vault, world_.lookup(), world_.sealing(), produced, w.db.known, w.cache,
                                   optionsFor(w));
            w.lost += r.lost;
            w.db.known = r.published.known;
            w.db.own_epoch = r.published.known.epoch;
            if (r.settled.version_id && r.settled.base_version_id)
                w.db.settled = SettledWindow{*r.settled.base_version_id, *r.settled.version_id, r.settled.window};
            else w.db.settled.reset();
            if (r.settled.version_id) w.recorded.push_back(*r.settled.version_id);
            w.pending = false;
        } catch (const ChainRejected& e) {
            w.refused = e.code();
        } catch (const PublishUnsettled& e) {
            w.failure = e.what();
        } catch (const PublishConflict& e) {
            w.failure = e.what();
        } catch (const std::exception& e) {
            w.failure = e.what();   // a 5xx: nothing recorded, the next pass publishes
        }
    }

    void runWriter(Scheduler& sched, const std::size_t a, unsigned& points) {
        auto store = hookedFor(sched, a, points);
        auto& w = writers_[a];
        for (;;) {
            try {
                publishOnce(*store, w);
                return;
            } catch (const Crash&) {
                // Restart from the database only: the publisher's cache (its pending base among it) is gone.
                ++w.crashes;
                w.cache = {};
            }
        }
    }

    void runReader(Scheduler& sched, const std::size_t a, unsigned& points) {
        auto store = hookedFor(sched, a, points);
        LoadOptions o;
        o.known = reader_.anchor;
        RootCache roots;
        o.root_cache = &roots;
        try {
            const auto l = load(*store, world_.vault, world_.lookup(), o);
            reader_.result = l.known();
            if (l.version_id && l.base_version_id)
                reader_.settled = SettledWindow{*l.base_version_id, *l.version_id, l.settle_window};
        } catch (const ChainRejected& e) {
            reader_.refused = e.code();
        } catch (const std::exception& e) {
            reader_.failure = e.what();
        }
    }

    void violation(std::string m) { report_.violations.push_back(std::move(m)); }

    // The invariants after a step (every actor parked or done).
    void check() {
        const auto t = truthOf(world_, opened_);
        for (const auto& [id, root] : t.roots) {
            for (const auto& s : root.first.segments)
                if (!world_.bucket->current(segmentKey(s.sid))) violation("I1: root " + id + " names a missing segment");
            if (root.first.publish != std::string(kPublishVersionLog)) violation("I9: root " + id + " names another mode");
        }
        const bool prefix = t.chain.size() >= prevChain_.size() &&
                            std::equal(prevChain_.begin(), prevChain_.end(), t.chain.begin());
        if (!prefix) {
            if (sc_.order_by_start) report_.order_broken = true;
            else violation("I3: the canonical chain lost an element");
        }
        prevChain_ = t.chain;
        everCanonical_.insert(t.chain.begin(), t.chain.end());
        // I6 rests on A3 and A4: with versions ordered by their start, the writer whose stalled PUT displaced a settled
        // root repairs that root away as a stray above its head, and the displaced writer sees a fork (below).
        for (const auto& id : world_.deleted)
            if (everCanonical_.contains(id) && !sc_.order_by_start)
                violation("I6: deleted a version that was canonical: " + id);
        if (!brokenOrder())
            for (const auto& w : writers_)
                for (const auto& id : w.recorded)
                    if (std::ranges::find(t.chain, id) == t.chain.end())
                        violation("I5: " + nodeName(w.index) + " recorded a root that is not canonical");
        faultFired();
    }

    // A writer whose settled root left the chain is refused: order_violation while the root is still in the bucket
    // (its settle window shows the inserted version), fork once another writer's repair deleted it (its anchor is gone
    // and another root holds its epoch).
    static bool displacedRefusal(const std::optional<ChainError>& e) {
        return e == ChainError::OrderViolation || e == ChainError::Fork;
    }

    [[nodiscard]] bool brokenOrder() const { return sc_.order_by_start || sc_.listing_lag; }

    void faultFired() { report_.fault_fired = report_.fault_fired || faultFired_; }

    // The next pass of every server, in turn: pending changes published, then a verifying read (as verifyRemote).
    void finish() {
        world_.free = true;
        world_.bucket->listingLag(0);
        auto store = world_.plainStore();
        for (auto& w : writers_) report_.lost_rounds += w.lost;
        for (unsigned pass = 0; pass < 3; ++pass)
            for (auto& w : writers_)
                if (w.pending && !w.refused) {
                    w.failure.clear();
                    publishOnce(*store, w);
                }
        for (auto& w : writers_) {
            if (w.refused) continue;
            LoadOptions o;
            o.known = w.db.known;
            o.settled = w.db.settled;
            try {
                (void)load(*store, world_.vault, world_.lookup(), o);
            } catch (const ChainRejected& e) {
                w.refused = e.code();
            }
        }
        for (const auto& w : writers_)
            if (displacedRefusal(w.refused)) report_.order_violation_seen = true;
        bool readerDisplaced = false;
        if (reader_.result && !reader_.refused) {
            LoadOptions o;
            o.known = reader_.result;
            o.settled = reader_.settled;
            try {
                (void)load(*store, world_.vault, world_.lookup(), o);
            } catch (const ChainRejected& e) {
                readerDisplaced = displacedRefusal(e.code());
                if (!readerDisplaced) reader_.refused = e.code();
            }
        }
        const auto t = truthOf(world_, opened_);
        // I3 or order_violation: a writer whose recorded root left the chain must be the one refusing.
        for (const auto& w : writers_)
            for (const auto& id : w.recorded)
                if (std::ranges::find(t.chain, id) == t.chain.end()) {
                    report_.settled_displaced = true;
                    if (!displacedRefusal(w.refused))
                        violation("I3/I8: " + nodeName(w.index) + "'s settled root left the chain unnoticed");
                }
        if (reader_.result && !onChain(t, reader_.result)) {
            report_.settled_displaced = true;
            if (!readerDisplaced) violation("I5/I8: the reader adopted a root that left the chain unnoticed");
        }
        if (readerDisplaced) {
            report_.order_violation_seen = true;
            if (!sc_.order_by_start) violation("the reader's next read was refused");
        }
        // With the provider's order broken on purpose a refused vault is the expected end: nothing more holds. Anywhere
        // else a refusal is a failure (below).
        if (sc_.order_by_start && (report_.settled_displaced || report_.order_violation_seen)) return;

        for (const auto& w : writers_) {
            if (w.refused) violation(nodeName(w.index) + " was refused: " + std::string(chainErrorName(*w.refused)));
            if (w.pending) violation(nodeName(w.index) + " still has pending changes: " + w.failure);
            if (!onChain(t, w.db.known)) violation("I5: " + nodeName(w.index) + "'s known root is not canonical");
        }
        if (reader_.refused || !reader_.failure.empty())
            violation("the reader failed: " + (reader_.refused ? std::string(chainErrorName(*reader_.refused)) : reader_.failure));
        for (const auto& id : t.above)
            if (!world_.failed_deletes.contains(id)) violation("a stray version above the head: " + id);
        LoadOptions o;
        o.known = reader_.anchor;
        const auto head = load(*store, world_.vault, world_.lookup(), o);
        if (!t.chain.empty() && head.version_id != t.chain.back()) violation("the head read is not the canonical head");
        std::set<std::string> names;
        for (const auto& e : head.content.entries) names.insert(e.name);
        const bool restarted = sc_.fault.kind != Fault::None && writers_[sc_.fault.actor].crashes > 0;
        for (std::size_t i = 0; i < sc_.writers; ++i)
            if (!names.contains(fileOf(i))) {
                // spec 06 §5.5: a server restarted from its database alone (no pending base in memory) merges as if
                // the head were its base, so another writer's change its database lacks goes. Never its own change,
                // and nothing else can do it. Several writers of one vault need a database that takes in merged heads
                // (the mirror's sync, spec 06 §9 item 7); one writer, or a restore that took the vault over, has
                // nothing its database lacks.
                if (restarted && i != sc_.fault.actor) report_.reverted_by_restart = true;
                else violation("I4: " + fileOf(i) + " is not in the head");
            }
    }

    Scenario sc_;
    Chooser choose_;
    World world_;
    std::vector<WriterState> writers_;
    ReaderState reader_;
    RunReport report_;
    std::mutex errorsMutex_;
    std::vector<std::string> prevChain_;
    std::set<std::string> everCanonical_;
    bool faultFired_{false};
    OpenedRoots opened_;
};

struct Explored {
    unsigned runs{0};
    unsigned max_steps{0};
    unsigned with_lost_round{0};
    unsigned with_fault{0};
    unsigned order_broken{0};
    unsigned settled_displaced{0};
    unsigned order_violation{0};
    unsigned reverted_by_restart{0};
    bool nondeterministic{false};
    std::vector<std::string> first_violations;
};

void tally(Explored& e, const RunReport& r, const std::string& label) {
    ++e.runs;
    e.max_steps = std::max(e.max_steps, r.steps);
    if (r.lost_rounds) ++e.with_lost_round;
    if (r.fault_fired) ++e.with_fault;
    if (r.order_broken) ++e.order_broken;
    if (r.settled_displaced) ++e.settled_displaced;
    if (r.order_violation_seen) ++e.order_violation;
    if (r.reverted_by_restart) ++e.reverted_by_restart;
    if (!r.violations.empty() && e.first_violations.size() < 5)
        e.first_violations.push_back(label + ": " + r.violations.front());
}

constexpr unsigned kRunCap = 20000;   // a tree larger than this fails the test instead of running for minutes

Explored exhaust(const Scenario& sc, const std::string& label) {
    Explored e;
    Dfs dfs;
    do {
        const auto r = Run(sc, [&](const std::size_t n) { return dfs.choose(n); }).go();
        tally(e, r, label + " #" + std::to_string(e.runs));
        if (e.runs >= kRunCap) break;
    } while (dfs.next());
    e.nondeterministic = dfs.nondeterministic();
    return e;
}

Explored sample(const Scenario& sc, const unsigned seeds, const std::string& label) {
    Explored e;
    for (unsigned seed = 1; seed <= seeds; ++seed) {
        std::mt19937 rng(seed);
        const auto r = Run(sc, [&](const std::size_t n) {
                           return std::uniform_int_distribution<std::size_t>(0, n - 1)(rng);
                       }).go();
        tally(e, r, label + " seed " + std::to_string(seed));
    }
    return e;
}

void expectClean(const Explored& e) {
    EXPECT_LT(e.runs, kRunCap) << "the interleaving tree outgrew the bound";
    EXPECT_FALSE(e.nondeterministic) << "a run took another path for the same choices";
    for (const auto& v : e.first_violations) ADD_FAILURE() << v;
}

}

namespace f = interleaving_fixture;

TEST(ManifestVersionLogInterleavings, EveryInterleavingOfTwoWritersAndAReader) {
    const auto e = f::exhaust({}, "2w+r");
    f::expectClean(e);
    // Both orders of the race occur, and some runs make a writer lose a round and merge.
    EXPECT_GT(e.runs, 50u);
    EXPECT_GT(e.with_lost_round, 0u);
    RecordProperty("runs", static_cast<int>(e.runs));
    RecordProperty("lost_round_runs", static_cast<int>(e.with_lost_round));
}

TEST(ManifestVersionLogInterleavings, EveryRootPutLevelInterleavingOfThreeWriters) {
    const auto e = f::exhaust({.writers = 3, .reader = false, .gating = f::Gating::RootPutsOnly}, "3w puts");
    f::expectClean(e);
    EXPECT_GT(e.with_lost_round, 0u);
    RecordProperty("runs", static_cast<int>(e.runs));
}

TEST(ManifestVersionLogInterleavings, SeededRandomSchedulesOfThreeWritersAndAReader) {
    const auto e = f::sample({.writers = 3}, 200, "3w+r");
    f::expectClean(e);
    EXPECT_GT(e.with_lost_round, 0u);
}

TEST(ManifestVersionLogFaults, ACrashAtEveryStepRestartsFromTheDatabaseOnly) {
    // Writer 0 crashes before or after each of its root requests (8 cover a writer that loses a round) and restarts
    // from its database alone. Every interleaving with the other writer's PUTs, plus seeded schedules at every point.
    f::Explored all;
    for (const auto kind : {f::Fault::CrashBefore, f::Fault::CrashAfter})
        for (unsigned at = 0; at < 8; ++at) {
            const std::string label = std::string(kind == f::Fault::CrashBefore ? "crash before" : "crash after") +
                                      " point " + std::to_string(at);
            for (const auto& e : {f::exhaust({.reader = false, .gating = f::Gating::FaultyActorFull, .fault = {0, at, kind}}, label),
                                  f::sample({.reader = false, .fault = {0, at, kind}}, 30, label)}) {
                f::expectClean(e);
                all.runs += e.runs;
                all.with_fault += e.with_fault;
                all.reverted_by_restart += e.reverted_by_restart;
            }
        }
    EXPECT_GT(all.with_fault, 100u);
    // The one loss a restart may cause (spec 06 §5.5, several writers only): the other writer's change.
    EXPECT_GT(all.reverted_by_restart, 0u);
    RecordProperty("runs", static_cast<int>(all.runs));
    RecordProperty("reverted_by_restart", static_cast<int>(all.reverted_by_restart));
}

TEST(ManifestVersionLogFaults, LostRepliesAndFailuresBeforeTheCommitAtEveryStep) {
    f::Explored all;
    for (const auto kind : {f::Fault::LoseReply, f::Fault::FailBefore})
        for (unsigned at = 0; at < 8; ++at) {
            const auto e = f::exhaust({.reader = false, .fault = {1, at, kind}},
                                      std::string(kind == f::Fault::LoseReply ? "lost reply" : "fail before") +
                                          " point " + std::to_string(at));
            f::expectClean(e);
            all.runs += e.runs;
            all.with_fault += e.with_fault;
        }
    EXPECT_GT(all.with_fault, 100u);
    RecordProperty("runs", static_cast<int>(all.runs));
}

TEST(ManifestVersionLogBrokenOrder, ListingsThatLagKeepI3) {
    // The fake's lag hides the newest versions, so every listing is still a prefix of the order: a writer can miss its
    // own version (unsettled, published by the next pass) but never take a sibling for the successor.
    const auto e = f::sample({.writers = 2, .listing_lag = 3}, 200, "lag");
    f::expectClean(e);
    EXPECT_EQ(e.order_broken, 0u);
}

TEST(ManifestVersionLogBrokenOrder, VersionsOrderedByTheirStartKeepI3OrEndInOrderViolation) {
    const auto e = f::sample({.writers = 2, .order_by_start = true}, 300, "order by start");
    f::expectClean(e);
    // Per run (expectClean): every root a writer settled or the reader adopted that left the chain was refused by its
    // holder at its next listing (order_violation, or fork once another writer's repair deleted it).
    EXPECT_GT(e.settled_displaced, 0u) << "some schedule displaces a settled root";
    EXPECT_GE(e.order_violation, e.settled_displaced);
    RecordProperty("order_broken", static_cast<int>(e.order_broken));
    RecordProperty("settled_displaced", static_cast<int>(e.settled_displaced));
    RecordProperty("refused", static_cast<int>(e.order_violation));
}

}
