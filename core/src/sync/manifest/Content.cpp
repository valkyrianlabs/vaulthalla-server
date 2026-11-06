#include "sync/manifest/Content.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <stdexcept>

namespace vh::sync::manifest {

namespace content_detail {

template <typename T, typename Key>
std::map<Key, const T*> indexBy(const std::vector<T>& items, Key T::*member) {
    std::map<Key, const T*> out;
    for (const auto& item : items) out.emplace(item.*member, &item);
    return out;
}

// One keyed collection merged by the mergePending rule.
template <typename T, typename Key>
std::vector<T> mergeKeyed(const std::vector<T>& theirs, const std::vector<T>& before, const std::vector<T>& ours,
                          Key T::*member) {
    const auto t = indexBy(theirs, member);
    const auto b = indexBy(before, member);
    const auto o = indexBy(ours, member);
    std::set<Key> keys;
    for (const auto& [k, _] : t) keys.insert(k);
    for (const auto& [k, _] : o) keys.insert(k);

    std::vector<T> out;
    for (const auto& k : keys) {
        const auto ti = t.find(k);
        const auto bi = b.find(k);
        const auto oi = o.find(k);
        const T* tv = ti == t.end() ? nullptr : ti->second;
        const T* bv = bi == b.end() ? nullptr : bi->second;
        const T* ov = oi == o.end() ? nullptr : oi->second;
        if (ov) {
            // Unchanged by us since our previous publish while they changed it: theirs. Otherwise ours.
            if (bv && *bv == *ov && tv) out.push_back(*tv);
            else out.push_back(*ov);
        } else if (!bv && tv) {
            out.push_back(*tv);  // they added it
        }
        // we don't have it but had it before: we deleted it
    }
    return out;
}

const Entry* findEntry(const std::map<std::string, const Entry*>& index, const std::string& uid) {
    const auto it = index.find(uid);
    return it == index.end() ? nullptr : it->second;
}

void pruneNames(Entry& e) {
    if (e.versions.empty()) {
        e.names.clear();
        return;
    }
    std::optional<std::string> oldest;
    for (const auto& v : e.versions)
        if (v.last_modified && (!oldest || *v.last_modified < *oldest)) oldest = v.last_modified;
    if (oldest) std::erase_if(e.names, [&](const PriorName& n) { return n.until < *oldest; });
    if (e.names.size() > kMaxPriorNames) e.names.resize(kMaxPriorNames);
}

}

void normalize(Content& content) {
    std::ranges::sort(content.entries, {}, &Entry::uid);
    std::ranges::sort(content.keys, {}, &KeyRecord::version);
    std::ranges::sort(content.snapshots, {}, &SnapshotRecord::id);
    if (std::ranges::adjacent_find(content.entries, {}, &Entry::uid) != content.entries.end())
        throw std::invalid_argument("manifest content lists an entry uid twice");
    if (std::ranges::adjacent_find(content.keys, {}, &KeyRecord::version) != content.keys.end())
        throw std::invalid_argument("manifest content lists a key version twice");
    if (std::ranges::adjacent_find(content.snapshots, {}, &SnapshotRecord::id) != content.snapshots.end())
        throw std::invalid_argument("manifest content lists a snapshot twice");
}

Stats statsOf(const Content& content) {
    Stats s;
    for (const auto& e : content.entries) {
        if (e.kind == EntryKind::Dir) ++s.dirs;
        if (e.kind == EntryKind::File && !e.trashed) {
            ++s.files;
            s.bytes += e.size.value_or(0);
        }
    }
    return s;
}

Content mergePending(const Content& theirs, const Content& oursBefore, const Content& ours) {
    Content out;
    out.producer = ours.producer;
    out.vault = ours.vault;
    out.recovery_policy = ours.recovery_policy;
    out.entries = content_detail::mergeKeyed(theirs.entries, oursBefore.entries, ours.entries, &Entry::uid);
    out.keys = content_detail::mergeKeyed(theirs.keys, oursBefore.keys, ours.keys, &KeyRecord::version);
    out.snapshots = content_detail::mergeKeyed(theirs.snapshots, oursBefore.snapshots, ours.snapshots,
                                               &SnapshotRecord::id);
    normalize(out);
    return out;
}

void carryHistory(const Content& previous, Content& next, const std::string& now) {
    const auto before = content_detail::indexBy(previous.entries, &Entry::uid);
    for (auto& e : next.entries) {
        const Entry* p = content_detail::findEntry(before, e.uid);
        if (!p || (p->kind != EntryKind::File && p->kind != EntryKind::Tombstone)) {
            if (e.kind == EntryKind::File || e.kind == EntryKind::Tombstone) content_detail::pruneNames(e);
            continue;
        }
        if (e.kind == EntryKind::File) {
            if (e.names.empty()) e.names = p->names;
            if (p->kind == EntryKind::File && (p->parent != e.parent || p->name != e.name))
                e.names.insert(e.names.begin(), PriorName{now, p->parent, p->name});
            content_detail::pruneNames(e);
        } else if (e.kind == EntryKind::Tombstone) {
            if (!e.parent && e.name.empty()) {
                e.parent = p->parent;
                e.name = p->name;
            }
            if (e.names.empty()) e.names = p->names;
            content_detail::pruneNames(e);
        }
    }
}

}
