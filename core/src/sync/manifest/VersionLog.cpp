#include "sync/manifest/VersionLog.hpp"

#include "sync/manifest/Objects.hpp"

#include <algorithm>
#include <set>

namespace vh::sync::manifest {

namespace version_log_detail {

std::optional<OpenedRoot> openBytes(const std::vector<uint8_t>& bytes, const Uid& vaultUid,
                                    const crypto::vhf1::KeyLookup& keys) {
    try {
        return OpenedRoot{openRoot(bytes, vaultUid, keys), sha256Hex(bytes)};
    } catch (const crypto::vhf1::Error&) {
    } catch (const FormatError&) {
    }
    return std::nullopt;
}

// Is version j succ(X) for the root X opened at i? (epoch + 1, prev = X's hash.)
bool follows(const OpenedRoot& x, const OpenedRoot& y) {
    return y.root.epoch == x.root.epoch + 1 && y.root.prev && *y.root.prev == x.sha256;
}

}

const OpenedRoot* RootCache::find(const std::string& versionId, bool* known) const {
    const auto it = roots_.find(versionId);
    if (known) *known = it != roots_.end();
    if (it == roots_.end() || !it->second) return nullptr;
    return &*it->second;
}

void RootCache::put(const std::string& versionId, std::optional<OpenedRoot> root) {
    roots_[versionId] = std::move(root);
}

RootLog::RootLog(ObjectStore& store, const Uid& vaultUid, const crypto::vhf1::KeyLookup& keys, RootCache& cache)
    : store_(store), vaultUid_(vaultUid), keys_(keys), cache_(cache) {}

void RootLog::list(const std::optional<std::string>& stopAt) {
    versions_ = stopAt ? store_.versionsSince(std::string(kRootKey), stopAt) : store_.versions(std::string(kRootKey));
    partial_ = stopAt && !versions_.empty() && versions_.back().version_id == *stopAt;   // newest first here
    std::ranges::reverse(versions_);
}

std::optional<std::size_t> RootLog::indexOf(const std::string& versionId) const {
    for (std::size_t i = 0; i < versions_.size(); ++i)
        if (versions_[i].version_id == versionId) return i;
    return std::nullopt;
}

const OpenedRoot* RootLog::open(const std::size_t i) {
    if (i >= versions_.size() || versions_[i].delete_marker) return nullptr;
    const auto& id = versions_[i].version_id;
    bool known = false;
    if (const auto* cached = cache_.find(id, &known); known) return cached;
    ++gets_;
    const auto obj = store_.get(std::string(kRootKey), id);
    if (!obj) return nullptr;   // gone since the listing: not cached, the next listing won't show it
    cache_.put(id, version_log_detail::openBytes(obj->bytes, vaultUid_, keys_));
    return cache_.find(id);
}

std::optional<std::size_t> RootLog::findBySha(const std::string& sha256) {
    std::size_t opened = 0;
    for (std::size_t n = versions_.size(); n-- > 0;) {
        if (versions_[n].delete_marker) continue;
        if (++opened > kMaxScanned) break;
        if (const auto* r = open(n); r && r->sha256 == sha256) return n;
    }
    return std::nullopt;
}

std::optional<std::size_t> RootLog::genesis() {
    for (std::size_t i = 0; i < versions_.size(); ++i)
        if (const auto* r = open(i); r && r->root.epoch == 1 && !r->root.prev) return i;
    return std::nullopt;
}

Walk walk(RootLog& log, const std::size_t anchor) {
    namespace d = version_log_detail;
    Walk w;
    w.anchor = anchor;
    w.head = anchor;
    w.chain.push_back(anchor);
    const auto& versions = log.versions();
    // Each successor sits after its predecessor (an honest writer read the predecessor before writing), so one scan
    // forward finds the earliest successor of each chain element in turn.
    for (std::size_t i = anchor + 1; i < versions.size(); ++i) {
        const auto* cur = log.open(w.head);
        const auto* next = log.open(i);
        if (!cur || !next) continue;
        if (d::follows(*cur, *next)) {
            w.head = i;
            w.chain.push_back(i);
        }
    }
    const auto headEpoch = log.open(w.head)->root.epoch;
    std::set<std::string> builtOn;   // prev hashes of the roots kept
    for (std::size_t i = versions.size(); i-- > w.head + 1;) {   // newest first: a prev always points further back
        const auto* r = log.open(i);
        // Kept: a root of a higher epoch than the head, and any root a kept one builds on (deleting it would cut the
        // newer chain from its history, and with it the evidence of a fork).
        if (r && (r->root.epoch > headEpoch || builtOn.contains(r->sha256))) {
            w.ahead.push_back(i);
            if (r->root.prev) builtOn.insert(*r->root.prev);
        } else {
            w.strays.push_back(i);
        }
    }
    std::ranges::reverse(w.ahead);
    std::ranges::reverse(w.strays);
    return w;
}

std::optional<Walk> walkBlind(RootLog& log) {
    namespace d = version_log_detail;
    const auto& versions = log.versions();
    // Chains start at versions that are nobody's canonical successor; the first root of each is its own anchor.
    std::set<std::size_t> successors;
    std::vector<std::size_t> authentic;
    for (std::size_t i = 0; i < versions.size(); ++i)
        if (log.open(i)) authentic.push_back(i);
    if (authentic.empty()) return std::nullopt;
    for (const auto i : authentic) {
        const auto* x = log.open(i);
        for (const auto j : authentic) {
            if (j <= i) continue;
            if (d::follows(*x, *log.open(j))) {
                successors.insert(j);
                break;   // the earliest successor only
            }
        }
    }
    std::optional<Walk> best;
    uint64_t bestEpoch = 0;
    for (const auto start : authentic) {
        if (successors.contains(start)) continue;
        auto w = walk(log, start);
        const auto epoch = log.open(w.head)->root.epoch;
        if (!best || epoch > bestEpoch ||
            (epoch == bestEpoch && (w.chain.size() > best->chain.size() ||
                                    (w.chain.size() == best->chain.size() && w.head < best->head)))) {
            best = std::move(w);
            bestEpoch = epoch;
        }
    }
    return best;
}

std::optional<std::size_t> successorOf(RootLog& log, const uint64_t epoch, const std::optional<std::string>& sha,
                                       const std::size_t from) {
    for (std::size_t i = from; i < log.versions().size(); ++i) {
        const auto* r = log.open(i);
        if (!r || r->root.epoch != epoch + 1) continue;
        if (!sha ? !r->root.prev : (r->root.prev && *r->root.prev == *sha)) return i;
    }
    return std::nullopt;
}

std::vector<std::string> idsBetween(const RootLog& log, const std::size_t a, const std::size_t b) {
    std::vector<std::string> out;
    for (std::size_t i = a + 1; i < b && i < log.versions().size(); ++i) out.push_back(log.versions()[i].version_id);
    return out;
}

bool windowBroken(const RootLog& log, const std::string& baseVersionId, const std::string& versionId,
                  const std::vector<std::string>& window) {
    const auto base = log.indexOf(baseVersionId);
    const auto root = log.indexOf(versionId);
    if (!base || !root || *base >= *root) return false;
    for (const auto& id : idsBetween(log, *base, *root))
        if (std::ranges::find(window, id) == window.end()) return true;
    return false;
}

}
