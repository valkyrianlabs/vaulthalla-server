#include "sync/manifest/Publisher.hpp"

#include "crypto/id/ObjectUid.hpp"

#include <fmt/format.h>

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
              const std::optional<Known>& known) {
    Base out;
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

std::vector<Range> rangesOf(const Published& p) {
    std::vector<Range> out;
    for (const auto& s : p.root.segments) out.push_back(s.range);
    return out;
}

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
    if (!storage::s3::sendsPreconditions(store.mode()))
        throw PublishUnsupported(fmt::format(
            "the bucket does not support conditional writes (capability {}): publishing the encrypted manifest on such "
            "a bucket is not implemented yet (design/encryption/06-publish-without-preconditions.md)",
            storage::s3::to_string(store.mode())));
    const auto vaultUidText = uidText(vaultUid);
    if (cache.base && (!known || cache.base->known != *known)) cache.base.reset();

    PublishReport report;
    std::optional<Known> verifyAgainst = known;
    std::map<std::string, SegmentRef> writtenSegments;   // plaintext → ref, written by an earlier attempt
    std::map<std::string, SnapshotRef> writtenSnapshots;
    // The base of our pending changes: what we produced for our previous publish. A first publish that lost the race
    // to another writer's first root has produced nothing before: all of ours is pending, all of theirs kept.
    std::optional<Content> pendingBase = cache.last_produced;

    for (unsigned attempt = 1; attempt <= std::max(1u, options.max_attempts); ++attempt) {
        report.attempts = attempt;
        if (!cache.base) {
            auto base = loadBase(store, vaultUid, keys, verifyAgainst);
            report.merged = report.merged || (base.merged && verifyAgainst.has_value());
            report.gap = report.gap || base.gap;
            report.root_rebuilt = report.root_rebuilt || base.rebuilt;
            cache.base = std::move(base.published);
            if (!cache.base) pendingBase = Content{};
        }
        const std::optional<Published>& base = cache.base;
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

}
