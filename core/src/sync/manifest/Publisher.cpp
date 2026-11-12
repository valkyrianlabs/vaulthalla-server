#include "sync/manifest/Publisher.hpp"

#include "crypto/id/ObjectUid.hpp"

#include <fmt/format.h>

#include <algorithm>
#include <thread>

namespace vh::sync::manifest {

namespace publisher_detail {

bool authenticates(const std::vector<uint8_t>& bytes, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys) {
    try {
        (void)openRoot(bytes, vaultUid, keys);
        return true;
    } catch (const crypto::vhf1::Error&) {
    } catch (const FormatError&) {
    }
    return false;
}

Published fromLoaded(Loaded&& l) {
    Published p;
    p.known = l.known();
    p.settled = Settled{l.version_id, l.base_version_id, l.settle_window};
    p.etag = l.etag;
    p.root = std::move(l.root);
    p.content = std::move(l.content);
    p.segments = std::move(l.segments);
    p.snapshots = std::move(l.snapshots);
    return p;
}

// The base to publish on: what the bucket holds now, verified against what this writer knows.
struct Base {
    std::optional<Published> published;  // nullopt: nothing to build on (first publish)
    bool merged{false};
    bool gap{false};
    bool rebuilt{false};
};

Base loadBase(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
              const std::optional<Known>& known, PublisherCache& cache, const PublishOptions& options) {
    Base out;
    if (store.mode() == storage::s3::WriteCapability::VersionLog) {
        // The canonical head by rule C1 from what this writer knows (spec 06 §5.3), not the current object.
        try {
            LoadOptions lo;
            lo.known = known;
            lo.root_cache = &cache.roots;
            if (known) lo.settled = options.settled;
            auto loaded = load(store, vaultUid, keys, lo);
            out.gap = loaded.acceptance.gap;
            out.merged = !known || loaded.known() != *known;
            out.published = fromLoaded(std::move(loaded));
            return out;
        } catch (const NoUsableRoot&) {
            if (!known) {
                for (const auto& v : store.versions(std::string(kRootKey)))
                    if (!v.delete_marker)
                        throw NoUsableRoot("the bucket holds a manifest root this vault can't read, and the vault has "
                                           "published none");
                return out;  // first publish
            }
        }
        Published synthetic;   // §4.2 (b), as below: no authentic root left, continue our chain
        synthetic.known = Known{known->epoch, known->root_sha256, std::nullopt};
        synthetic.root.epoch = known->epoch;
        out.published = std::move(synthetic);
        out.rebuilt = true;
        return out;
    }
    auto current = store.get(std::string(kRootKey));
    if (current && authenticates(current->bytes, vaultUid, keys)) {
        auto loaded = load(store, vaultUid, keys, {known, true, std::move(current)});
        out.gap = loaded.acceptance.gap;
        out.merged = !known || loaded.known() != *known;
        out.published = fromLoaded(std::move(loaded));
        return out;
    }
    if (!known) {
        if (current)
            throw NoUsableRoot("the bucket holds a manifest root this vault can't read, and the vault has published none");
        return out;  // first publish
    }
    // §4.2 (b): the root is missing or not authentic, and the daemon is alive: rebuild from our own state, continuing
    // our chain so a reader that knows `known` sees a successor, not a rollback.
    Published synthetic;
    synthetic.known = *known;
    synthetic.etag = current ? current->etag : std::nullopt;
    synthetic.root.epoch = known->epoch;
    out.published = std::move(synthetic);
    out.rebuilt = true;
    return out;
}

std::string_view modeName(const storage::s3::WriteCapability mode) {
    return mode == storage::s3::WriteCapability::VersionLog ? kPublishVersionLog : kPublishConditional;
}

void checkHead(const RootDocument& head, const std::string& rootSha, const ObjectStore& store,
               const PublishOptions& options) {
    checkHeadForWriter(head, rootSha, store, options.self_node, options.own_epoch);
}

// spec 06 §5.5: the base's writers carry over while they name this server. Otherwise the publish names this server
// alone: past checkHead that is a base without the member (a vault from before it) or a server that never published
// here (no own epoch: a restore, which takes the vault over and leaves the old node superseded). Adding a node to the
// set is the mirror join, not a publish.
std::vector<std::string> writersFor(const std::optional<Published>& base, const std::string& self) {
    if (base && base->root.writers && std::ranges::find(*base->root.writers, self) != base->root.writers->end())
        return *base->root.writers;
    return {self};
}

void sleepFor(const PublishOptions& options, const std::chrono::milliseconds d) {
    if (d.count() <= 0) return;
    if (options.sleep) options.sleep(d);
    else std::this_thread::sleep_for(d);
}

// version_log: where our root sits in the listing, by version id, or (outcome unknown) by its hash among the versions
// after the base.
std::optional<std::size_t> locateOurs(RootLog& log, const std::optional<std::string>& ourId, const std::string& ourSha,
                                      const std::size_t from) {
    if (ourId) return log.indexOf(*ourId);
    for (std::size_t i = from; i < log.versions().size(); ++i)
        if (const auto* r = log.open(i); r && r->sha256 == ourSha) return i;
    return std::nullopt;
}

std::vector<Range> rangesOf(const Published& p) {
    std::vector<Range> out;
    for (const auto& s : p.root.segments) out.push_back(s.range);
    return out;
}

}

void checkHeadForWriter(const RootDocument& head, const std::string& rootSha, const ObjectStore& store,
                        const std::string& selfNode, const std::optional<uint64_t>& ownEpoch) {
    using publisher_detail::modeName;
    const bool ours = !selfNode.empty() && head.producer.node_id == selfNode;
    const auto mode = modeName(store.mode());
    const auto named = head.publish.value_or(std::string(kPublishConditional));
    if (!ours && named != mode)
        throw ChainRejected(ChainError::PublishModeMismatch,
                            fmt::format("the bucket's head was published as {} by node {}; this bucket is {}", named,
                                        head.producer.node_id, mode),
                            head.epoch, rootSha);
    if (selfNode.empty() || !head.writers || !ownEpoch) return;
    if (std::ranges::find(*head.writers, selfNode) != head.writers->end()) return;
    if (head.epoch > *ownEpoch)
        throw ChainRejected(ChainError::Superseded,
                            fmt::format("the root of epoch {} names other writers, not this server (whose last root was "
                                        "epoch {})",
                                        head.epoch, *ownEpoch),
                            head.epoch, rootSha);
}

std::vector<std::string> Published::sids() const {
    std::vector<std::string> out;
    for (const auto& s : root.segments) out.push_back(s.sid);
    for (const auto& s : root.snapshots) out.push_back(s.sid);
    return out;
}

PublishReport publish(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                      const SealingKey& sealing, const Content& produced, const std::optional<Known>& known,
                      PublisherCache& cache, const PublishOptions& options) {
    using namespace publisher_detail;
    if (store.mode() == storage::s3::WriteCapability::Insufficient)
        throw PublishUnsupported(
            "the bucket neither honours conditional writes nor keeps object versions (or not If-Match on GET): nothing "
            "can arbitrate the manifest's root on it (design/encryption/06-publish-without-preconditions.md §7)");
    const bool versionLog = store.mode() == storage::s3::WriteCapability::VersionLog;
    const auto vaultUidText = uidText(vaultUid);
    if (cache.base && (!known || cache.base->known != *known)) cache.base.reset();

    PublishReport report;
    std::optional<Known> verifyAgainst = known;
    std::map<std::string, SegmentRef> writtenSegments;   // plaintext → ref, written by an earlier attempt
    std::map<std::string, SnapshotRef> writtenSnapshots;
    // The base of our pending changes: what we produced for our previous publish. A first publish that lost the race
    // to another writer's first root has produced nothing before: all of ours is pending, all of theirs kept.
    std::optional<Content> pendingBase = cache.last_produced;

    // spec 06 §5.2: max(3, writers + 1) attempts; each round has one winner (I7), so a loser retries at once.
    unsigned attempts = std::max(1u, options.max_attempts);
    for (unsigned attempt = 1; attempt <= attempts; ++attempt) {
        report.attempts = attempt;
        if (!cache.base) {
            auto base = loadBase(store, vaultUid, keys, verifyAgainst, cache, options);
            report.merged = report.merged || (base.merged && verifyAgainst.has_value());
            report.gap = report.gap || base.gap;
            report.root_rebuilt = report.root_rebuilt || base.rebuilt;
            cache.base = std::move(base.published);
            if (!cache.base) pendingBase = Content{};
        }
        const std::optional<Published>& base = cache.base;
        if (base && !base->root.vault_uid.empty()) checkHead(base->root, base->known.root_sha256, store, options);
        if (base && base->root.writers)
            attempts = std::max(attempts, static_cast<unsigned>(base->root.writers->size()) + 1);
        const Content empty{};
        const Content& theirs = base ? base->content : empty;
        const Content& before = pendingBase ? *pendingBase : theirs;

        Content merged = mergePending(theirs, before, produced);
        carryHistory(theirs, merged, options.now);

        RootDocument root;
        root.vault_uid = vaultUidText;
        root.epoch = base ? base->known.epoch + 1 : 1;
        if (base) root.prev = base->known.root_sha256;
        root.published_at = options.now;
        root.producer = merged.producer;
        root.vault = merged.vault;
        root.keys = merged.keys;
        root.recovery_policy = merged.recovery_policy;
        root.stats = statsOf(merged);
        root.publish = std::string(modeName(store.mode()));
        if (!options.self_node.empty()) root.writers = writersFor(base, options.self_node);

        Published next;
        next.content = merged;

        const auto plan = partition(merged.entries, base ? rangesOf(*base) : std::vector<Range>{}, vaultUidText,
                                    options.limits);
        for (const auto& p : plan) {
            SegmentRef ref;
            if (base)
                if (const auto it = base->segments.find(p.doc.range);
                    it != base->segments.end() && it->second.plaintext == p.plaintext)
                    ref = it->second.ref;
            if (ref.sid.empty())
                if (const auto it = writtenSegments.find(p.plaintext); it != writtenSegments.end()) ref = it->second;
            if (ref.sid.empty()) {
                const auto sid = crypto::id::newObjectUid();
                const auto bytes = sealDocument(Json::parse(p.plaintext), crypto::vhf1::Kind::ManifestSegment, vaultUid,
                                                sid, sealing);
                ref = {uidText(sid), p.doc.range, p.doc.entries.size(), sha256Hex(bytes), bytes.size()};
                (void)store.putOnce(segmentKey(ref.sid), bytes);  // a fresh 128-bit sid: never exists
                writtenSegments.emplace(p.plaintext, ref);
                ++report.segments_written;
            } else {
                ++report.segments_reused;
            }
            root.segments.push_back(ref);
            next.segments[p.doc.range] = {ref, p.plaintext};
        }

        for (const auto& snap : merged.snapshots) {
            const SnapshotDocument doc{vaultUidText, snap};
            auto plaintext = canonicalJson(toJson(doc));
            SnapshotRef ref;
            if (base)
                if (const auto it = base->snapshots.find(snap.id);
                    it != base->snapshots.end() && it->second.plaintext == plaintext)
                    ref = it->second.ref;
            if (ref.sid.empty())
                if (const auto it = writtenSnapshots.find(plaintext); it != writtenSnapshots.end()) ref = it->second;
            if (ref.sid.empty()) {
                const auto sid = crypto::id::newObjectUid();
                const auto bytes = sealSnapshot(doc, vaultUid, sid, sealing);
                ref = {uidText(sid), sha256Hex(bytes), bytes.size()};
                (void)store.putOnce(segmentKey(ref.sid), bytes);
                writtenSnapshots.emplace(plaintext, ref);
                ++report.snapshots_written;
            }
            root.snapshots.push_back(ref);
            next.snapshots[snap.id] = {ref, std::move(plaintext)};
        }

        if (!base) {
            // The cleartext layout hint, once (never trusted, §4.2): an existing one is left alone.
            const auto hint = layoutHint(vaultUid);
            try {
                (void)store.putOnce(std::string(kLayoutKey), std::vector<uint8_t>(hint.begin(), hint.end()));
            } catch (const PreconditionFailed&) {
            }
        }

        const auto rootBytes = sealRoot(root, vaultUid, sealing);
        if (versionLog) {
            const auto ourSha = sha256Hex(rootBytes);
            std::optional<std::string> ourId;
            std::optional<std::string> unknownOutcome;
            try {
                ourId = store.put(std::string(kRootKey), rootBytes).version_id;
                if (!ourId)
                    throw std::runtime_error("the bucket returned no version id for the manifest root: it doesn't keep "
                                             "versions, so the root can't be arbitrated (re-probe the bucket)");
                cache.roots.put(*ourId, OpenedRoot{root, ourSha});
            } catch (const PutOutcomeUnknown& e) {
                unknownOutcome = e.what();   // the PUT may have been applied: find our version before deciding
            }

            RootLog log(store, vaultUid, keys, cache.roots);
            std::optional<std::size_t> baseIdx;
            std::optional<std::size_t> ours;
            // The listing stops at the oldest version it needs: the settled root's base (the order check) or ours'.
            std::optional<std::string> stopAt;
            if (options.settled && known) stopAt = options.settled->base_version_id;
            else if (base && base->settled.version_id) stopAt = base->settled.version_id;
            for (std::size_t round = 0; round <= options.listing_retries.size(); ++round) {
                if (round) sleepFor(options, options.listing_retries[round - 1]);
                log.list(stopAt);
                if (stopAt && !log.partial()) stopAt.reset();   // gone from the bucket: the listing held everything
                if (options.settled && known &&
                    windowBroken(log, options.settled->base_version_id, options.settled->version_id,
                                 options.settled->window))
                    throw ChainRejected(ChainError::OrderViolation,
                                        "a version appeared between the settled root and its base",
                                        known->epoch, known->root_sha256);
                baseIdx.reset();
                if (base && base->settled.version_id) baseIdx = log.indexOf(*base->settled.version_id);
                if (base && !baseIdx && !report.root_rebuilt) baseIdx = log.findBySha(base->known.root_sha256);
                ours = locateOurs(log, ourId, ourSha, baseIdx ? *baseIdx + 1 : 0);
                if (ours) break;
                // Ours isn't listed. If the base already has a successor, ours lost and a repair removed it (or it
                // never landed); retrying the listing can't change that.
                const auto succ = successorOf(log, base ? base->known.epoch : 0,
                                              base ? std::optional<std::string>(base->known.root_sha256) : std::nullopt,
                                              baseIdx ? *baseIdx + 1 : 0);
                if (succ) break;
                if (unknownOutcome) break;   // not listed and nothing else: as far as the bucket shows, not applied
            }
            if (!ours) {
                if (unknownOutcome && !successorOf(log, base ? base->known.epoch : 0,
                                                   base ? std::optional<std::string>(base->known.root_sha256)
                                                        : std::nullopt,
                                                   baseIdx ? *baseIdx + 1 : 0))
                    throw std::runtime_error("the manifest root PUT failed and no version of it is listed: " +
                                             *unknownOutcome);
                if (!successorOf(log, base ? base->known.epoch : 0,
                                 base ? std::optional<std::string>(base->known.root_sha256) : std::nullopt,
                                 baseIdx ? *baseIdx + 1 : 0))
                    throw PublishUnsettled("the manifest root's version is not listed yet (listing_lag): the next "
                                           "publish settles it");
                ++report.lost;   // another writer's root is the successor and ours is gone
                if (base) verifyAgainst = base->known;
                cache.base.reset();
                continue;
            }
            if (!ourId) {
                ourId = log.versions()[*ours].version_id;
                cache.roots.put(*ourId, OpenedRoot{root, ourSha});
            }
            if (base && !baseIdx && !report.root_rebuilt) {
                // The base we built on is gone from the bucket since we loaded it: load the head again.
                verifyAgainst = base->known;
                cache.base.reset();
                continue;
            }
            const auto succ = successorOf(log, base ? base->known.epoch : 0,
                                          base ? std::optional<std::string>(base->known.root_sha256) : std::nullopt,
                                          baseIdx ? *baseIdx + 1 : 0);
            if (succ != ours) {
                // Rule C1: another root succeeded the base first. Ours goes; merge onto the head and retry.
                try {
                    store.removeVersion(std::string(kRootKey), *ourId);
                } catch (const std::exception&) {
                    // left for the next repair: a non-canonical version is ignored by every reader
                }
                ++report.lost;
                if (base) verifyAgainst = base->known;
                cache.base.reset();
                continue;
            }

            // Won. Repair: every version newer than the head that isn't on the chain (a crashed loser, a marker), never
            // an authentic root of a higher epoch than ours (the next read takes it, or refuses it).
            const auto w = walk(log, *ours);
            for (const auto i : w.ahead) report.ahead.push_back(log.versions()[i].version_id);
            for (const auto i : w.strays) {
                const auto& v = log.versions()[i];
                try {
                    store.removeVersion(std::string(kRootKey), v.version_id);
                    report.repaired.push_back(v.version_id);
                } catch (const std::exception&) {
                }
            }
            report.settled = Settled{ourId, baseIdx ? std::optional<std::string>(log.versions()[*baseIdx].version_id)
                                                    : std::nullopt,
                                     baseIdx ? idsBetween(log, *baseIdx, *ours) : std::vector<std::string>{}};
            next.etag = log.versions()[*ours].etag;
            next.known = Known{root.epoch, ourSha, ourId};
            next.settled = report.settled;
            next.root = std::move(root);
            cache.base = next;
            cache.last_produced = produced;
            report.published = std::move(next);
            return report;
        }
        try {
            next.etag = base && base->etag ? store.putIfMatch(std::string(kRootKey), rootBytes, *base->etag)
                                           : store.putIfAbsent(std::string(kRootKey), rootBytes);
        } catch (const PreconditionFailed&) {
            // Another writer published since `base`: verify its root against the one we built on, merge, retry.
            if (base) verifyAgainst = base->known;
            cache.base.reset();
            continue;
        }

        next.known = {root.epoch, sha256Hex(rootBytes)};
        next.root = std::move(root);
        cache.base = next;
        cache.last_produced = produced;
        report.published = std::move(next);
        return report;
    }
    throw PublishConflict(fmt::format("manifest publish conflict after {} attempts", report.attempts));
}

GcReport collectGarbage(ObjectStore& store, const std::set<std::string>& retainedSids, const std::time_t now,
                        const std::time_t minAgeSeconds) {
    GcReport report;
    for (const auto& o : store.list(std::string(kSegmentPrefix))) {
        const auto sid = sidOfKey(o.key);
        if (!sid) continue;  // not ours to judge
        if (retainedSids.contains(*sid)) {
            ++report.retained;
            continue;
        }
        if (!o.last_modified || now - *o.last_modified < minAgeSeconds) {
            ++report.young;
            continue;
        }
        store.remove(o.key);
        report.deleted.push_back(o.key);
    }
    return report;
}

GcReport collectGarbageVersionLog(ObjectStore& store, const std::set<std::string>& retainedSids, const std::time_t now,
                                  const UnreferencedClock& clock, const std::time_t minAgeSeconds) {
    GcReport report;
    std::map<std::string, std::vector<StoredVersion>> byKey;
    for (auto& v : store.versionsUnder(std::string(kSegmentPrefix))) byKey[v.key].push_back(std::move(v));
    for (const auto& [key, versions] : byKey) {
        const auto sid = sidOfKey(key);
        if (!sid) continue;  // not ours to judge
        if (retainedSids.contains(*sid)) {
            clock.forget(*sid);
            ++report.retained;
            continue;
        }
        if (now - clock.first(*sid) < minAgeSeconds) {
            ++report.young;
            continue;
        }
        for (const auto& v : versions) store.removeVersion(key, v.version_id);
        clock.forget(*sid);
        report.deleted.push_back(key);
    }
    return report;
}

JanitorReport collectRootVersions(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                                  RootCache& cache, const std::string& headVersionId, const std::time_t now,
                                  const std::time_t supersededAge, const std::time_t strayAge) {
    JanitorReport report;
    RootLog log(store, vaultUid, keys, cache);
    log.list();
    const auto head = log.indexOf(headVersionId);
    if (!head || !log.open(*head)) return report;   // not settled in this listing: nothing is judged

    // The head's two canonical predecessors, walking prev hashes back through the log.
    std::vector<std::size_t> keep{*head};
    std::size_t cur = *head;
    for (int step = 0; step < 2; ++step) {
        const auto* r = log.open(cur);
        if (!r || !r->root.prev) break;
        std::optional<std::size_t> pred;
        for (std::size_t i = cur; i-- > 0;)
            if (const auto* p = log.open(i); p && p->sha256 == *r->root.prev) {
                pred = i;
                break;
            }
        if (!pred) break;
        keep.push_back(*pred);
        cur = *pred;
    }
    const auto oldest = keep.back();
    const auto& versions = log.versions();
    for (std::size_t i = 0; i < *head; ++i) {
        if (std::ranges::find(keep, i) != keep.end()) {
            ++report.kept;
            continue;
        }
        const auto& v = versions[i];
        const auto age = v.last_modified ? now - *v.last_modified : 0;
        // Below the second predecessor: anything once superseded long enough (canonical or not); between it and the
        // head only non-canonical versions remain, after a day. Delete markers carry nothing.
        const bool due = v.delete_marker ? age >= strayAge : i < oldest ? age >= supersededAge : age >= strayAge;
        if (!v.last_modified || !due) {
            ++report.kept;
            continue;
        }
        // Never an authentic root of a higher epoch than the head (possible below it only when the provider's order
        // broke): it is the newest state, for the reads to judge.
        if (const auto* r = v.delete_marker ? nullptr : log.open(i); r && r->root.epoch > log.open(*head)->root.epoch) {
            ++report.kept;
            continue;
        }
        store.removeVersion(std::string(kRootKey), v.version_id);
        report.deleted.push_back(v.version_id);
    }
    return report;
}

}
