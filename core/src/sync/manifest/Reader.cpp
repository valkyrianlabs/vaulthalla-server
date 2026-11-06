#include "sync/manifest/Reader.hpp"

#include "sync/manifest/Objects.hpp"

#include <fmt/format.h>

#include <algorithm>

namespace vh::sync::manifest {

namespace reader_detail {

struct RootCandidate {
    RootDocument root;
    std::string sha;
    std::optional<std::string> etag;
};

std::optional<RootDocument> tryOpenRoot(const std::vector<uint8_t>& bytes, const Uid& vaultUid,
                                        const crypto::vhf1::KeyLookup& keys) {
    try {
        return openRoot(bytes, vaultUid, keys);
    } catch (const crypto::vhf1::Error&) {
    } catch (const FormatError&) {
    }
    return std::nullopt;
}

// Root versions read at most (newest first): bounds the GETs a fallback or gap walk costs on a bucket that keeps a long
// history.
constexpr std::size_t kMaxRetainedRootsScanned = 64;

// The authentic roots among the provider's versions of .vaulthalla/root, newest first; listed once, on first use.
class RetainedRoots {
public:
    RetainedRoots(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys, const bool enabled)
        : store_(store), vaultUid_(vaultUid), keys_(keys), enabled_(enabled) {}

    const std::vector<RootCandidate>& all() {
        if (listed_ || !enabled_) return roots_;
        listed_ = true;
        std::vector<StoredVersion> versions;
        try {
            versions = store_.versions(std::string(kRootKey));
        } catch (const std::exception&) {
            return roots_;  // the provider keeps no versions we can list: nothing retained
        }
        std::size_t scanned = 0;
        for (const auto& v : versions) {
            if (v.delete_marker) continue;
            if (++scanned > kMaxRetainedRootsScanned) break;  // newest first: older ones can't matter more
            const auto obj = store_.get(std::string(kRootKey), v.version_id);
            if (!obj) continue;
            if (auto root = tryOpenRoot(obj->bytes, vaultUid_, keys_))
                roots_.push_back({std::move(*root), sha256Hex(obj->bytes), std::nullopt});
        }
        return roots_;
    }

    std::optional<RootDocument> bySha(const std::string& sha) {
        for (const auto& r : all())
            if (r.sha == sha) return r.root;
        return std::nullopt;
    }

private:
    ObjectStore& store_;
    const Uid& vaultUid_;
    const crypto::vhf1::KeyLookup& keys_;
    bool enabled_;
    bool listed_{false};
    std::vector<RootCandidate> roots_;
};

// Fetches and opens the segment `ref` pins: the document, or the problem's name.
struct SegmentAttempt {
    std::optional<SegmentDocument> doc;
    std::string problem;
};

SegmentAttempt openPinned(const SegmentRef& ref, const std::optional<StoredObject>& obj, const Uid& vaultUid,
                          const crypto::vhf1::KeyLookup& keys) {
    try {
        checkSegment(ref, obj ? &obj->bytes : nullptr);
        auto doc = openSegment(obj->bytes, vaultUid, parseUid(ref.sid, "bad_root", "segment sid"), keys);
        if (doc.range != ref.range || doc.entries.size() != ref.count)
            return {std::nullopt, "bad_segment"};
        return {std::move(doc), {}};
    } catch (const ChainRejected& e) {
        return {std::nullopt, std::string(chainErrorName(e.code()))};
    } catch (const crypto::vhf1::Error& e) {
        return {std::nullopt, std::string(crypto::vhf1::errorCodeName(e.code()))};
    } catch (const FormatError& e) {
        return {std::nullopt, e.code()};
    }
}

struct SnapshotAttempt {
    std::optional<SnapshotDocument> doc;
    std::string problem;
};

SnapshotAttempt openPinnedSnapshot(const SnapshotRef& ref, const std::optional<StoredObject>& obj, const Uid& vaultUid,
                                   const crypto::vhf1::KeyLookup& keys) {
    try {
        checkSnapshot(ref, obj ? &obj->bytes : nullptr);
        return {openSnapshot(obj->bytes, vaultUid, parseUid(ref.sid, "bad_root", "snapshot sid"), keys), {}};
    } catch (const ChainRejected& e) {
        return {std::nullopt, std::string(chainErrorName(e.code()))};
    } catch (const crypto::vhf1::Error& e) {
        return {std::nullopt, std::string(crypto::vhf1::errorCodeName(e.code()))};
    } catch (const FormatError& e) {
        return {std::nullopt, e.code()};
    }
}

// (a) for any pinned object: a provider version whose bytes match the pin.
template <typename Attempt, typename Open>
Attempt fromVersions(ObjectStore& store, const std::string& key, const uint64_t size, Open&& open) {
    Attempt last{};
    try {
        for (const auto& v : store.versions(key)) {
            if (v.delete_marker || v.size != size) continue;
            auto attempt = open(store.get(key, v.version_id));
            if (attempt.doc) return attempt;
            last = std::move(attempt);
        }
    } catch (const std::exception&) {
    }
    return last;
}

}

std::string_view to_string(const Resolution resolution) {
    switch (resolution) {
    case Resolution::ProviderVersion: return "provider_version";
    case Resolution::OlderRoot: return "older_root";
    case Resolution::Blind: return "blind";
    }
    return "blind";
}

std::string_view to_string(const Freshness freshness) {
    switch (freshness) {
    case Freshness::Unverified: return "unverified";
    case Freshness::Verified: return "verified";
    case Freshness::RollbackAccepted: return "rollback_accepted";
    }
    return "unverified";
}

Content contentOf(const RootDocument& root, const std::vector<SegmentDocument>& segments,
                  const std::vector<SnapshotDocument>& snapshots) {
    Content c;
    c.producer = root.producer;
    c.vault = root.vault;
    c.keys = root.keys;
    c.recovery_policy = root.recovery_policy;
    for (const auto& s : segments) c.entries.insert(c.entries.end(), s.entries.begin(), s.entries.end());
    for (const auto& s : snapshots) c.snapshots.push_back(s.snapshot);
    normalize(c);
    return c;
}

Loaded load(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys, const LoadOptions& options) {
    using namespace reader_detail;
    RetainedRoots retained(store, vaultUid, keys, options.use_provider_versions);

    std::optional<RootCandidate> cand;
    RootSource source = RootSource::Current;
    const auto current = options.root_object ? options.root_object : store.get(std::string(kRootKey));
    if (current)
        if (auto root = tryOpenRoot(current->bytes, vaultUid, keys))
            cand = RootCandidate{std::move(*root), sha256Hex(current->bytes), current->etag};
    if (!cand) {
        if (const auto& all = retained.all(); !all.empty()) {
            cand = all.front();
            source = RootSource::ProviderVersion;
        }
    }
    if (!cand)
        throw NoUsableRoot(current ? "the manifest root does not authenticate, and no retained version does"
                                   : "the bucket has no manifest root");

    Loaded out;
    out.acceptance = checkChain(cand->root, cand->sha, options.known,
                                [&](const std::string& sha) { return retained.bySha(sha); });
    out.root = cand->root;
    out.etag = source == RootSource::Current ? cand->etag : std::nullopt;
    out.source = source;

    std::vector<SegmentDocument> docs;
    for (const auto& ref : out.root.segments) {
        const auto key = segmentKey(ref.sid);
        const auto open = [&](const std::optional<StoredObject>& obj) { return openPinned(ref, obj, vaultUid, keys); };
        auto attempt = open(store.get(key));
        if (attempt.doc) {
            out.segments[ref.range] = {ref, canonicalJson(toJson(*attempt.doc))};
            docs.push_back(std::move(*attempt.doc));
            continue;
        }
        SegmentIssue issue{ref.sid, ref.range, attempt.problem, Resolution::Blind, std::nullopt};

        if (options.use_provider_versions) {
            if (auto v = fromVersions<SegmentAttempt>(store, key, ref.size, open); v.doc) {
                issue.resolution = Resolution::ProviderVersion;
                out.issues.push_back(issue);
                out.segments[ref.range] = {ref, canonicalJson(toJson(*v.doc))};
                docs.push_back(std::move(*v.doc));
                continue;
            }
        }

        bool fromOlder = false;
        for (const auto& old : retained.all()) {
            if (old.root.epoch >= out.root.epoch) continue;
            for (const auto& oldRef : old.root.segments) {
                if (oldRef.range.lo > ref.range.lo || oldRef.range.hi < ref.range.hi) continue;
                auto older = openPinned(oldRef, store.get(segmentKey(oldRef.sid)), vaultUid, keys);
                if (!older.doc) continue;
                std::erase_if(older.doc->entries, [&](const Entry& e) {
                    return !ref.range.contains(parseUid(e.uid, "bad_segment", "entry uid"));
                });
                older.doc->range = ref.range;
                issue.resolution = Resolution::OlderRoot;
                issue.from_epoch = old.root.epoch;
                docs.push_back(std::move(*older.doc));
                fromOlder = true;
                break;
            }
            if (fromOlder) break;
        }
        if (!fromOlder) out.blind_ranges.push_back(ref.range);
        out.issues.push_back(issue);
    }

    std::vector<SnapshotDocument> snaps;
    for (const auto& ref : out.root.snapshots) {
        const auto key = segmentKey(ref.sid);
        const auto open = [&](const std::optional<StoredObject>& obj) {
            return openPinnedSnapshot(ref, obj, vaultUid, keys);
        };
        auto attempt = open(store.get(key));
        if (!attempt.doc && options.use_provider_versions) {
            auto v = fromVersions<SnapshotAttempt>(store, key, ref.size, open);
            if (v.doc) {
                out.issues.push_back({ref.sid, std::nullopt, attempt.problem, Resolution::ProviderVersion, {}});
                attempt = std::move(v);
            }
        }
        if (!attempt.doc) {
            out.issues.push_back({ref.sid, std::nullopt, attempt.problem, Resolution::Blind, {}});
            continue;
        }
        out.snapshots[attempt.doc->snapshot.id] = {ref, canonicalJson(toJson(*attempt.doc))};
        snaps.push_back(std::move(*attempt.doc));
    }

    out.content = contentOf(out.root, docs, snaps);
    return out;
}

BlindReport blindRebuild(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                         const std::optional<Range>& only) {
    BlindReport report;
    for (const auto& listed : store.list(std::string(kObjectPrefix))) {
        const auto uid = uidOfObjectKey(listed.key);
        if (!uid) {
            report.rejected.push_back(listed.key + ": not an o/<uid> key");
            continue;
        }
        if (only && !only->contains(*uid)) continue;
        const auto head = store.getRange(listed.key, 0, crypto::vhf1::kHeaderSize);
        if (!head) continue;  // deleted since the listing
        report.header_bytes += head->size();
        try {
            const auto header = crypto::vhf1::openHeader(
                *head, {crypto::vhf1::Kind::FileContent, vaultUid, *uid, std::nullopt}, keys);
            const auto layout = crypto::vhf1::layoutFor(listed.size, header.params().chunkLog2);
            RecoveredObject r;
            r.uid = *uid;
            r.key = listed.key;
            r.path = "/Recovered/" + uidText(*uid);
            r.object_size = listed.size;
            r.plaintext_size = layout.plaintextSize;
            r.key_version = header.params().keyVersion;
            for (const auto b : header.params().salt) r.generation += fmt::format("{:02x}", b);
            report.recovered.push_back(std::move(r));
        } catch (const crypto::vhf1::Error& e) {
            report.rejected.push_back(fmt::format("{}: {}", listed.key, crypto::vhf1::errorCodeName(e.code())));
        }
    }
    return report;
}

RestoreLoad loadForRestore(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                           const std::optional<Checkpoint>& checkpoint, const bool acceptRollback) {
    if (!checkpoint) return {load(store, vaultUid, keys, {}), Freshness::Unverified, std::string(kFreshnessUnverified)};
    try {
        LoadOptions options;
        options.known = Known{checkpoint->epoch, checkpoint->root_sha256};
        auto loaded = load(store, vaultUid, keys, options);
        auto report = fmt::format("freshness verified against the checkpoint of epoch {}: the root is epoch {}",
                                  checkpoint->epoch, loaded.root.epoch);
        return {std::move(loaded), Freshness::Verified, std::move(report)};
    } catch (const ChainRejected& e) {
        if (e.code() != ChainError::Rollback || !acceptRollback) throw;
    }
    auto loaded = load(store, vaultUid, keys, {});
    auto report = fmt::format("rollback accepted: the root is epoch {}, older than the checkpoint of epoch {}",
                              loaded.root.epoch, checkpoint->epoch);
    return {std::move(loaded), Freshness::RollbackAccepted, std::move(report)};
}

}
