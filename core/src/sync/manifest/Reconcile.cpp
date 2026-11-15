#include "sync/manifest/Reconcile.hpp"

#include "sync/manifest/Objects.hpp"

#include <format>

#include <algorithm>
#include <functional>
#include <map>
#include <set>
#include <span>
#include <string>
#include <type_traits>
#include <tuple>
#include <utility>

namespace vh::sync::manifest {

namespace reconcile_detail {

using Index = std::map<std::string, const Entry*>;

Index indexOf(const Content& c) {
    Index out;
    for (const auto& e : c.entries) out.emplace(e.uid, &e);
    return out;
}

const Entry* find(const Index& index, const std::string& uid) {
    const auto it = index.find(uid);
    return it == index.end() ? nullptr : it->second;
}

bool exists(const Entry* e) { return e && e->kind != EntryKind::Tombstone; }
bool isLive(const Entry* e) { return exists(e) && !e->trashed; }
bool isTrashed(const Entry* e) { return exists(e) && e->trashed.has_value(); }
bool isLiveDir(const Entry* e) { return isLive(e) && e->kind == EntryKind::Dir; }

using Placement = std::pair<std::optional<std::string>, std::string>;
Placement placementOf(const Entry& e) { return {e.parent, e.name}; }
void setPlacement(Entry& e, const Placement& p) {
    e.parent = p.first;
    e.name = p.second;
}

auto contentOf(const Entry& e) {
    return std::tie(e.generation, e.key_version, e.size, e.content_hash, e.object, e.mime, e.format);
}
void takeContent(Entry& to, const Entry& from) {
    to.generation = from.generation;
    to.key_version = from.key_version;
    to.size = from.size;
    to.content_hash = from.content_hash;
    to.object = from.object;
    to.mime = from.mime;
    to.format = from.format;
    to.mtime = from.mtime;   // mtime follows content
}

auto attributesOf(const Entry& e) { return std::tie(e.mode, e.owner, e.target); }
void takeAttributes(Entry& to, const Entry& from) {
    to.mode = from.mode;
    to.owner = from.owner;
    to.target = from.target;
}

// "Edited since base": the content changed, or a restore (live now, not live in base). Only a live side can be.
bool edited(const Entry* side, const Entry* base) {
    if (!isLive(side)) return false;
    if (!isLive(base)) return true;
    return contentOf(*side) != contentOf(*base);
}

enum class Pick { Same, Theirs, Ours, Conflict };

// A three-way decision for one group; `base` nullopt: unknown (not in base, or base has no such group).
template <typename T>
Pick threeWay(const std::optional<T>& base, const T& theirs, const T& ours) {
    if (theirs == ours) return Pick::Same;
    if (base && *base == ours) return Pick::Theirs;
    if (base && *base == theirs) return Pick::Ours;
    return Pick::Conflict;
}

// History union: theirs' first, then ours' that theirs doesn't hold. A version both hold keeps when it became
// noncurrent if either side knows (the writer whose PUT replaced it does; the other learns it here).
void unionHistory(Entry& r, const Entry* t, const Entry* o) {
    std::vector<FileVersion> versions;
    std::vector<PriorName> names;
    for (const auto* side : {t, o}) {
        if (!side) continue;
        for (const auto& v : side->versions) {
            const auto held = std::ranges::find_if(versions, [&](const FileVersion& x) { return x.version_id == v.version_id; });
            if (held == versions.end()) versions.push_back(v);
            else if (!held->noncurrent_at && v.noncurrent_at) held->noncurrent_at = v.noncurrent_at;
        }
        for (const auto& n : side->names)
            if (std::ranges::find(names, n) == names.end()) names.push_back(n);
    }
    if (names.size() > kMaxPriorNames) names.resize(kMaxPriorNames);
    r.versions = std::move(versions);
    r.names = std::move(names);
}

// The history a database holds: provider versions, as a set (it lists them in its own order). Prior names and a
// tombstone's last place are not the database's: the publisher carries them from the previous root (carryHistory), so
// they never make an operation.
// A version that became noncurrent counts as history too (whether, not when: each writer dates what it observed).
bool sameHistory(const Entry& a, const Entry& b) {
    const auto ids = [](const Entry& e) {
        std::set<std::pair<std::string, bool>> out;
        for (const auto& v : e.versions) out.emplace(v.version_id, v.noncurrent_at.has_value());
        return out;
    };
    return ids(a) == ids(b);
}

struct Decided {
    std::optional<Entry> entry;
    bool placementFromTheirs{false};   // the result's placement is the head's and not ours (the cycle rule may undo it)
};

struct Context {
    std::vector<Conflict>& conflicts;
    void report(ConflictKind kind, const std::string& uid, const Entry* t, const Entry* o, std::string detail,
                const bool open = false) const {
        conflicts.push_back({kind, uid, open, t ? std::optional(*t) : std::nullopt, o ? std::optional(*o) : std::nullopt,
                             std::move(detail)});
    }
};

// Both live: group by group.
Decided mergeLive(const std::string& uid, const Entry* b, const Entry& t, const Entry& o, const Context& ctx) {
    Decided d;
    Entry r = o;
    r.trashed.reset();
    const auto basePlacement = exists(b) ? std::optional(placementOf(*b)) : std::nullopt;
    switch (threeWay(basePlacement, placementOf(t), placementOf(o))) {
    case Pick::Theirs:
        setPlacement(r, placementOf(t));
        d.placementFromTheirs = true;
        break;
    case Pick::Conflict:
        setPlacement(r, placementOf(t));
        d.placementFromTheirs = true;
        ctx.report(ConflictKind::Placement, uid, &t, &o, "renamed or moved on both sides: the head's placement");
        break;
    default: break;
    }
    using ContentKey = decltype(contentOf(t));
    using AttrKey = decltype(attributesOf(t));
    const auto baseContent = isLive(b) ? std::optional<ContentKey>(contentOf(*b)) : std::nullopt;
    const auto contentPick = threeWay(baseContent, contentOf(t), contentOf(o));
    switch (contentPick) {
    case Pick::Theirs: takeContent(r, t); break;
    case Pick::Conflict:
        ctx.report(ConflictKind::ContentEditEdit, uid, &t, &o, "content changed on both sides", true);
        break;
    default: break;
    }
    // mtime on its own (a rename or a chmod restamps a file here): theirs when only they changed it, the head's when
    // both did; under an open content conflict ours stays with our content. Never a directory's (each server's own).
    if (contentPick == Pick::Same && t.kind != EntryKind::Dir) {
        using Mtime = std::optional<std::string>;
        const auto baseMtime = isLive(b) ? std::optional<Mtime>(b->mtime) : std::nullopt;
        if (const auto pick = threeWay(baseMtime, t.mtime, o.mtime); pick == Pick::Theirs || pick == Pick::Conflict)
            r.mtime = t.mtime;
    }
    const auto baseAttrs = isLive(b) ? std::optional<AttrKey>(attributesOf(*b)) : std::nullopt;
    switch (threeWay(baseAttrs, attributesOf(t), attributesOf(o))) {
    case Pick::Theirs: takeAttributes(r, t); break;
    case Pick::Conflict:
        takeAttributes(r, t);
        ctx.report(ConflictKind::Attributes, uid, &t, &o, "attributes changed on both sides: the head's");
        break;
    default: break;
    }
    if (t.kind != o.kind) r.kind = t.kind;   // never legitimately (a uid is one entry): the head
    unionHistory(r, &t, &o);
    d.entry = std::move(r);
    return d;
}

Entry withHistory(const Entry& side, const Entry* t, const Entry* o) {
    Entry r = side;
    unionHistory(r, t, o);
    return r;
}

// Gone: a tombstone while any side has history (or is one), else nothing.
std::optional<Entry> gone(const std::string& uid, const Entry* t, const Entry* o) {
    const Entry* tomb = t && t->kind == EntryKind::Tombstone ? t : (o && o->kind == EntryKind::Tombstone ? o : nullptr);
    Entry r;
    if (tomb) r = *tomb;
    else {
        r.uid = uid;
        r.kind = EntryKind::Tombstone;
    }
    unionHistory(r, t, o);
    if (!tomb && r.versions.empty()) return std::nullopt;
    // A tombstone keeps only what the format gives it: history, and its last place.
    Entry out;
    out.uid = uid;
    out.kind = EntryKind::Tombstone;
    out.parent = r.parent;
    out.name = r.name;
    out.versions = std::move(r.versions);
    out.names = std::move(r.names);
    return out;
}

Decided decide(const std::string& uid, const Entry* b, const Entry* t, const Entry* o, const Context& ctx) {
    Decided d;
    if (!exists(b)) {
        if (exists(t) && exists(o)) {
            if (isLive(t) && isLive(o)) return mergeLive(uid, b, *t, *o, ctx);
            d.entry = withHistory(*t, t, o);   // both have it, one trashed, no base to say who acted: the head
            d.placementFromTheirs = placementOf(*t) != placementOf(*o);
            return d;
        }
        if (exists(t)) {
            d.entry = withHistory(*t, t, o);
            d.placementFromTheirs = true;
            return d;
        }
        if (exists(o)) {
            d.entry = withHistory(*o, t, o);
            return d;
        }
        d.entry = gone(uid, t, o);
        return d;
    }
    // In base (live or trashed).
    if (isLive(t) && isLive(o)) return mergeLive(uid, b, *t, *o, ctx);
    if (isLive(t) || isLive(o)) {
        const bool theirsLive = isLive(t);
        const Entry* live = theirsLive ? t : o;
        const Entry* other = theirsLive ? o : t;
        if (edited(live, b)) {
            d.entry = withHistory(*live, t, o);
            d.entry->trashed.reset();
            d.placementFromTheirs = theirsLive && (!exists(o) || placementOf(*t) != placementOf(*o));
            // A conflict only when the other side deleted or trashed it since base (not a plain restore of ours).
            if ((isTrashed(other) && isLive(b)) || !exists(other))
                ctx.report(isTrashed(other) ? ConflictKind::EditBeatsTrash : ConflictKind::EditBeatsDelete, uid, t, o,
                           theirsLive ? "edited by the head, deleted here: restored from the head"
                                      : "edited here, deleted by the head: kept");
            return d;
        }
        if (isTrashed(other)) {
            d.entry = withHistory(*other, t, o);
            return d;
        }
        d.entry = gone(uid, t, o);
        return d;
    }
    if (isTrashed(t) && isTrashed(o)) {
        d.entry = withHistory(*t, t, o);   // trash / trash: converged (the head's trash record)
        return d;
    }
    d.entry = gone(uid, t, o);   // trash / purge, purge / purge: gone
    return d;
}

std::optional<std::string> rootOf(const Content& c) {
    for (const auto& e : c.entries)
        if (isLiveDir(&e) && !e.parent) return e.uid;
    return std::nullopt;
}

using Result = std::map<std::string, Entry>;

const Entry* at(const Result& r, const std::string& uid) {
    const auto it = r.find(uid);
    return it == r.end() ? nullptr : &it->second;
}

bool parentIsLiveDir(const Result& r, const Entry& e) { return e.parent && isLiveDir(at(r, *e.parent)); }

// The first directory cycle among live directories (its members), or empty.
std::vector<std::string> findCycle(const Result& r) {
    std::map<std::string, int> state;   // 1 on the current walk, 2 done
    for (const auto& [uid, e] : r) {
        if (!isLiveDir(&e) || state[uid] == 2) continue;
        std::vector<std::string> walk;
        std::string cur = uid;
        for (;;) {
            if (state[cur] == 2) break;
            if (state[cur] == 1) {
                const auto from = std::ranges::find(walk, cur);
                std::vector<std::string> cycle(from, walk.end());
                for (const auto& w : walk) state[w] = 2;
                return cycle;
            }
            state[cur] = 1;
            walk.push_back(cur);
            const auto* node = at(r, cur);
            if (!node->parent || !isLiveDir(at(r, *node->parent))) break;
            cur = *node->parent;
        }
        for (const auto& w : walk) state[w] = 2;
    }
    return {};
}

Entry recoveredDir(const std::string& rootUid) {
    Entry e;
    e.uid = recoveredDirUid(rootUid);
    e.kind = EntryKind::Dir;
    e.parent = rootUid;
    e.name = std::string(kRecoveredName);
    e.mode = 0755;
    return e;
}

// The tree rules, in the design's order, on the per-entry result.
void repairTree(Result& r, const std::map<std::string, bool>& fromTheirs, const Index& t, const Index& o,
                const std::optional<std::string>& root, const Context& ctx) {
    // A folder deleted on one side lives on while the result puts a live entry in it.
    for (bool changed = true; changed;) {
        changed = false;
        for (const auto& [uid, e] : Result(r)) {
            if (!isLive(&e) || !e.parent || isLiveDir(at(r, *e.parent))) continue;
            const auto* keep = isLiveDir(find(o, *e.parent)) ? find(o, *e.parent)
                                                              : (isLiveDir(find(t, *e.parent)) ? find(t, *e.parent) : nullptr);
            if (!keep) continue;
            r[*e.parent] = withHistory(*keep, find(t, *e.parent), find(o, *e.parent));
            ctx.report(ConflictKind::FolderKept, *e.parent, find(t, *e.parent), find(o, *e.parent),
                       "deleted on one side, with live entries in it on the other: kept");
            changed = true;
        }
    }
    if (!root) return;
    // A move that would close a cycle is not applied; a cycle the head made alone goes under /Recovered.
    for (std::size_t guard = 0; guard <= r.size(); ++guard) {
        const auto cycle = findCycle(r);
        if (cycle.empty()) break;
        std::optional<std::string> undo;
        for (const auto& uid : cycle) {
            const auto it = fromTheirs.find(uid);
            if (it == fromTheirs.end() || !it->second || !isLive(find(o, uid))) continue;
            if (!undo || uid < *undo) undo = uid;
        }
        if (undo) {
            setPlacement(r[*undo], placementOf(*find(o, *undo)));
            ctx.report(ConflictKind::CycleNotApplied, *undo, find(t, *undo), find(o, *undo),
                       "the head's move would close a directory cycle: ours kept");
        } else {
            const auto least = *std::ranges::min_element(cycle);
            if (!r.contains(recoveredDirUid(*root))) r[recoveredDirUid(*root)] = recoveredDir(*root);
            r[least].parent = recoveredDirUid(*root);
            ctx.report(ConflictKind::Repaired, least, find(t, least), find(o, least),
                       "in a directory cycle the head made: under /Recovered");
        }
    }
    // Live entries whose folder is gone everywhere (or that name no folder) go under /Recovered.
    for (const auto& [uid, e] : Result(r)) {
        if (!isLive(&e) || uid == *root || parentIsLiveDir(r, e)) continue;
        if (!r.contains(recoveredDirUid(*root))) r[recoveredDirUid(*root)] = recoveredDir(*root);
        r[uid].parent = recoveredDirUid(*root);
        ctx.report(ConflictKind::Repaired, uid, find(t, uid), find(o, uid), "its folder is gone: under /Recovered");
    }
    // A trashed file names its folder only while that folder is live (as the collector says it).
    for (auto& [uid, e] : r)
        if (isTrashed(&e) && e.parent && !isLiveDir(at(r, *e.parent))) e.parent.reset();
    // Name clashes: every entry but the least uid gets its uid prefix appended (the rule of vault::recover::plan).
    for (std::size_t guard = 0; guard < 8; ++guard) {
        std::map<Placement, std::vector<std::string>> byName;
        for (const auto& [uid, e] : r)
            if (isLive(&e) && e.parent) byName[placementOf(e)].push_back(uid);
        bool clashed = false;
        for (const auto& [place, uids] : byName) {
            if (uids.size() < 2) continue;
            clashed = true;
            for (std::size_t i = 1; i < uids.size(); ++i) {
                auto& e = r[uids[i]];
                e.name += " (" + e.uid.substr(0, 8) + ")";
                ctx.report(ConflictKind::NameClash, e.uid, find(t, e.uid), find(o, e.uid),
                           std::format("another entry is named \"{}\" in its folder: renamed", place.second));
            }
        }
        if (!clashed) break;
    }
}

std::optional<VaultInfo> mergeVault(const Content& base, const Content& theirs, const Content& ours, const Context& ctx) {
    if (!ours.vault) return theirs.vault;
    if (!theirs.vault) return ours.vault;
    VaultInfo r = *ours.vault;
    const auto& t = *theirs.vault;
    const auto& b = base.vault;
    const auto field = [&](auto member, const char* name) {
        using V = std::remove_cvref_t<decltype(t.*member)>;
        std::optional<V> bv;
        if (b) bv = (*b).*member;
        switch (threeWay(bv, t.*member, r.*member)) {
        case Pick::Theirs: r.*member = t.*member; break;
        case Pick::Conflict:
            r.*member = t.*member;
            ctx.conflicts.push_back({ConflictKind::VaultSetting, name, false, std::nullopt, std::nullopt,
                                     "changed on both sides: the head's"});
            break;
        default: break;
        }
    };
    field(&VaultInfo::name, "name");
    field(&VaultInfo::quota_bytes, "quota_bytes");
    field(&VaultInfo::sync_strategy, "sync_strategy");
    field(&VaultInfo::recovery_policy, "recovery_policy");
    return r;
}

std::size_t depthIn(const Result& r, const std::string& uid) {
    std::size_t depth = 0;
    const Entry* e = at(r, uid);
    while (e && e->parent && depth <= r.size()) {
        e = at(r, *e->parent);
        ++depth;
    }
    return depth;
}

Result asMap(const Content& c) {
    Result out;
    for (const auto& e : c.entries) out.emplace(e.uid, e);
    return out;
}

}

std::string_view to_string(const OpKind kind) {
    switch (kind) {
    case OpKind::SetVault: return "set_vault";
    case OpKind::AddEnvelopes: return "add_envelopes";
    case OpKind::CreateDir: return "create_dir";
    case OpKind::Move: return "move";
    case OpKind::Create: return "create";
    case OpKind::Restore: return "restore";
    case OpKind::ReplaceContent: return "replace_content";
    case OpKind::SetAttributes: return "set_attributes";
    case OpKind::Trash: return "trash";
    case OpKind::Delete: return "delete";
    case OpKind::Purge: return "purge";
    case OpKind::AddHistory: return "add_history";
    case OpKind::CreateSnapshot: return "create_snapshot";
    case OpKind::DeleteSnapshot: return "delete_snapshot";
    }
    return "unknown";
}

Step stepOf(const OpKind kind) {
    switch (kind) {
    case OpKind::SetVault: return Step::VaultSettings;
    case OpKind::AddEnvelopes: return Step::Envelopes;
    case OpKind::CreateDir: return Step::CreateDirs;
    case OpKind::Move: return Step::Moves;
    case OpKind::Create:
    case OpKind::Restore: return Step::Creates;
    case OpKind::ReplaceContent:
    case OpKind::SetAttributes: return Step::Content;
    case OpKind::Trash:
    case OpKind::Delete:
    case OpKind::Purge: return Step::Deletes;
    case OpKind::AddHistory: return Step::History;
    case OpKind::CreateSnapshot:
    case OpKind::DeleteSnapshot: return Step::Snapshots;
    }
    return Step::Snapshots;
}

std::string_view to_string(const ConflictKind kind) {
    switch (kind) {
    case ConflictKind::ContentEditEdit: return "content_edit_edit";
    case ConflictKind::Placement: return "placement";
    case ConflictKind::Attributes: return "attributes";
    case ConflictKind::VaultSetting: return "vault_setting";
    case ConflictKind::EditBeatsDelete: return "edit_beats_delete";
    case ConflictKind::EditBeatsTrash: return "edit_beats_trash";
    case ConflictKind::FolderKept: return "folder_kept";
    case ConflictKind::CycleNotApplied: return "cycle_not_applied";
    case ConflictKind::Repaired: return "repaired";
    case ConflictKind::NameClash: return "name_clash";
    }
    return "unknown";
}

std::string recoveredDirUid(const std::string& rootUid) {
    const std::string label = "vh.manifest.recovered/" + rootUid;
    const auto hex = sha256Hex(std::span(reinterpret_cast<const uint8_t*>(label.data()), label.size()));
    Uid uid{};
    for (std::size_t i = 0; i < uid.size(); ++i) uid[i] = static_cast<uint8_t>(std::stoi(hex.substr(2 * i, 2), nullptr, 16));
    return uidText(uid);
}

Reconciliation reconcile(const Content& base, const Content& theirs, const Content& ours) {
    return reconcile(base, theirs, ours, {});
}

Reconciliation reconcile(const Content& base, const Content& theirs, const Content& ours, const SameKey& sameKey) {
    using namespace reconcile_detail;
    Reconciliation out;
    out.result = ours;

    // 3. Key records: checked, never applied.
    for (const auto& k : theirs.keys) {
        const auto held = std::ranges::find(ours.keys, k.version, &KeyRecord::version);
        if (held == ours.keys.end()) out.key_problems.push_back({k.version, "manifest_key_missing"});
        else if (k.key_check && held->key_check &&
                 !(sameKey ? sameKey(k, *held, theirs.producer) : *k.key_check == *held->key_check))
            out.key_problems.push_back({k.version, "manifest_key_mismatch"});
    }
    if (out.stopped()) return out;

    const Context ctx{out.conflicts};
    const auto b = indexOf(base), t = indexOf(theirs), o = indexOf(ours);

    // Entries, one by one.
    std::set<std::string> uids;
    for (const auto* index : {&t, &o}) for (const auto& [uid, _] : *index) uids.insert(uid);
    for (const auto& [uid, _] : b) uids.insert(uid);
    Result r;
    std::map<std::string, bool> fromTheirs;
    for (const auto& uid : uids) {
        auto d = decide(uid, find(b, uid), find(t, uid), find(o, uid), ctx);
        if (d.entry) r.emplace(uid, std::move(*d.entry));
        fromTheirs[uid] = d.placementFromTheirs;
    }
    auto root = rootOf(ours);
    if (!root) root = rootOf(theirs);
    repairTree(r, fromTheirs, t, o, root, ctx);

    // 1, 2: vault settings, envelopes (the recovery policy stays ours: never merged).
    out.result.vault = mergeVault(base, theirs, ours, ctx);
    if (theirs.recovery_policy && theirs.recovery_policy->account_policy &&
        (!ours.recovery_policy || ours.recovery_policy->account_policy != theirs.recovery_policy->account_policy))
        out.incoming_account_policy = theirs.recovery_policy->account_policy;
    std::vector<Op> envelopeOps;
    for (auto& k : out.result.keys) {
        const auto tk = std::ranges::find(theirs.keys, k.version, &KeyRecord::version);
        if (tk == theirs.keys.end() || !tk->envelopes) continue;
        std::vector<std::string> added;
        for (const auto& kid : *tk->envelopes)
            if (!k.envelopes || std::ranges::find(*k.envelopes, kid) == k.envelopes->end()) added.push_back(kid);
        if (added.empty()) continue;
        if (!k.envelopes) k.envelopes.emplace();
        k.envelopes->insert(k.envelopes->end(), added.begin(), added.end());
        Op op;
        op.kind = OpKind::AddEnvelopes;
        op.key_version = k.version;
        op.envelopes = std::move(added);
        envelopeOps.push_back(std::move(op));
    }

    // 10. Snapshot records by uid; records without one are left alone.
    std::vector<Op> snapshotOps;
    {
        std::map<std::string, const SnapshotRecord*> bs, ts;
        for (const auto& s : base.snapshots) if (!s.uid.empty()) bs.emplace(s.uid, &s);
        for (const auto& s : theirs.snapshots) if (!s.uid.empty()) ts.emplace(s.uid, &s);
        std::vector<SnapshotRecord> next;
        for (const auto& s : ours.snapshots) {
            if (!s.uid.empty() && !ts.contains(s.uid) && bs.contains(s.uid)) {
                Op op;
                op.kind = OpKind::DeleteSnapshot;
                op.uid = s.uid;
                op.snapshot = s;
                snapshotOps.push_back(std::move(op));
                continue;   // theirs deleted it; snapshots are never edited, so ours hasn't changed it
            }
            next.push_back(s);
        }
        for (const auto& [uid, s] : ts) {
            if (bs.contains(uid) || std::ranges::any_of(ours.snapshots, [&](const SnapshotRecord& x) { return x.uid == uid; }))
                continue;   // ours has it, or ours deleted it since base
            Op op;
            op.kind = OpKind::CreateSnapshot;
            op.uid = uid;
            op.snapshot = *s;
            snapshotOps.push_back(std::move(op));
            next.push_back(*s);
        }
        out.result.snapshots = std::move(next);
    }

    out.result.entries.clear();
    for (auto& [_, e] : r) out.result.entries.push_back(e);
    normalize(out.result);

    // The plan: what takes ours to the result, in step order.
    std::vector<Op> plan;
    if (out.result.vault != ours.vault) {
        Op op;
        op.kind = OpKind::SetVault;
        op.vault = out.result.vault;
        plan.push_back(std::move(op));
    }
    plan.insert(plan.end(), envelopeOps.begin(), envelopeOps.end());
    const auto oursMap = asMap(ours);
    std::set<std::string> all;
    for (const auto& [uid, _] : oursMap) all.insert(uid);
    for (const auto& [uid, _] : r) all.insert(uid);
    for (const auto& uid : all) {
        const Entry* oe = at(oursMap, uid);
        const Entry* re = at(r, uid);
        const auto add = [&](const OpKind kind) {
            Op op;
            op.kind = kind;
            op.uid = uid;
            if (oe) op.ours = *oe;
            if (re && kind != OpKind::Delete && kind != OpKind::Purge) op.target = *re;
            plan.push_back(std::move(op));
        };
        if (isLive(re)) {
            if (!exists(oe)) add(re->kind == EntryKind::Dir ? OpKind::CreateDir : OpKind::Create);
            else if (isTrashed(oe)) add(OpKind::Restore);
            else {
                if (placementOf(*oe) != placementOf(*re)) add(OpKind::Move);
                if (contentOf(*oe) != contentOf(*re)) add(OpKind::ReplaceContent);
                // An mtime alone travels with a move, else as an attribute (the executors write the target's mtime).
                const bool mtimeOnly = oe->mtime != re->mtime && contentOf(*oe) == contentOf(*re) &&
                                       placementOf(*oe) == placementOf(*re) && re->kind != EntryKind::Dir;
                if (attributesOf(*oe) != attributesOf(*re) || oe->kind != re->kind || oe->ctime != re->ctime || mtimeOnly)
                    add(OpKind::SetAttributes);
            }
        } else if (isTrashed(re)) {
            if (!exists(oe)) add(OpKind::Create);
            else if (isLive(oe)) add(OpKind::Trash);
            else {
                Entry a = *oe, z = *re;
                a.versions.clear();
                a.names.clear();
                z.versions.clear();
                z.names.clear();
                if (a != z) add(OpKind::Trash);
            }
        } else {
            if (isLive(oe)) add(OpKind::Delete);
            else if (isTrashed(oe)) add(OpKind::Purge);
        }
        // 9. History: only ever added.
        if (re) {
            const bool historyMoved = oe ? !sameHistory(*oe, *re) : !re->versions.empty();
            const bool tombstoneMoved = re->kind == EntryKind::Tombstone && (!oe || oe->kind != EntryKind::Tombstone);
            if (historyMoved || tombstoneMoved) add(OpKind::AddHistory);
        }
    }
    plan.insert(plan.end(), snapshotOps.begin(), snapshotOps.end());

    // An entry no operation touches stays as ours holds it: what differs is history the database doesn't hold (prior
    // names, a tombstone's last place), which the publisher carries from the root it builds on.
    {
        std::set<std::string> touched;
        for (const auto& op : plan) touched.insert(op.uid);
        for (auto& e : out.result.entries)
            if (!touched.contains(e.uid))
                if (const Entry* oe = at(oursMap, e.uid)) e = *oe;
    }

    // Order: by step; directories created parents first, moves directories first, deletes children first.
    const auto dirFirst = [&](const Op& op) { return op.target && op.target->kind == EntryKind::Dir ? 0 : 1; };
    std::ranges::stable_sort(plan, [&](const Op& x, const Op& y) {
        if (stepOf(x.kind) != stepOf(y.kind)) return stepOf(x.kind) < stepOf(y.kind);
        if (x.kind == OpKind::CreateDir && y.kind == OpKind::CreateDir) return depthIn(r, x.uid) < depthIn(r, y.uid);
        if (x.kind == OpKind::Move && y.kind == OpKind::Move) return dirFirst(x) < dirFirst(y);
        if (stepOf(x.kind) == Step::Deletes) return depthIn(oursMap, x.uid) > depthIn(oursMap, y.uid);
        return false;
    });
    out.plan = std::move(plan);
    return out;
}

Content applyPlan(const Content& ours, const std::vector<Op>& plan) {
    using namespace reconcile_detail;
    Content out = ours;
    Result entries = asMap(ours);
    for (const auto& op : plan) {
        switch (op.kind) {
        case OpKind::SetVault: out.vault = op.vault; break;
        case OpKind::AddEnvelopes:
            for (auto& k : out.keys)
                if (k.version == op.key_version) {
                    if (!k.envelopes) k.envelopes.emplace();
                    k.envelopes->insert(k.envelopes->end(), op.envelopes.begin(), op.envelopes.end());
                }
            break;
        case OpKind::CreateSnapshot: out.snapshots.push_back(*op.snapshot); break;
        case OpKind::DeleteSnapshot:
            std::erase_if(out.snapshots, [&](const SnapshotRecord& s) { return s.uid == op.uid; });
            break;
        default:
            if (op.target) entries[op.uid] = *op.target;
            else entries.erase(op.uid);
        }
    }
    out.entries.clear();
    for (auto& [_, e] : entries) out.entries.push_back(std::move(e));
    normalize(out);
    return out;
}

std::vector<std::string> treeProblems(const Content& content) {
    using namespace reconcile_detail;
    std::vector<std::string> out;
    const auto r = asMap(content);
    std::vector<std::string> roots;
    for (const auto& [uid, e] : r)
        if (isLiveDir(&e) && !e.parent) roots.push_back(uid);
    if (roots.size() != 1 && !r.empty()) out.push_back(std::format("{} roots", roots.size()));
    std::map<Placement, std::string> names;
    for (const auto& [uid, e] : r) {
        if (!isLive(&e) || !e.parent) continue;
        if (!isLiveDir(at(r, *e.parent))) out.push_back(uid + ": its parent is not a live directory");
        if (const auto [it, fresh] = names.emplace(placementOf(e), uid); !fresh)
            out.push_back(std::format("{} and {}: both named \"{}\" in one folder", it->second, uid, e.name));
    }
    if (const auto cycle = findCycle(r); !cycle.empty()) out.push_back("a directory cycle through " + cycle.front());
    return out;
}

}
