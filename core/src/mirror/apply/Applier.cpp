#include "mirror/apply/Applier.hpp"

#include "crypto/id/Generator.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/mirror/Apply.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/tree_apply/TreeApply.hpp"
#include "fuse/WorkingCopies.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "paths.h"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>
#include <pqxx/pqxx>

#include <algorithm>
#include <filesystem>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdexcept>
#include <system_error>
#include <utility>

namespace vh::mirror::apply {

namespace mq = vh::db::query::mirror;
namespace ta = vh::fs::tree_apply;
using json = nlohmann::json;

const char* toString(const Status s) {
    switch (s) {
    case Status::Applied: return "applied";
    case Status::AlreadyApplied: return "already_applied";
    case Status::Deferred: return "deferred";
    case Status::Diverged: return "diverged";
    case Status::Stopped: return "stopped";
    case Status::NotNext: return "not_next";
    case Status::Gone: return "gone";
    }
    return "unknown";
}

namespace mirror_apply_detail {

enum class Outcome { Live, Trashed, Gone };

// One uid's change in a page or a group: what the mirror must hold for it now, and what it must hold after.
struct Change {
    std::string uid;
    Outcome outcome{Outcome::Live};
    json state;
    std::string type;
    std::optional<vh::mirror::Hash> expect;       // the compare-and-set (none: nothing recorded)
    std::optional<vh::mirror::Hash> resultHash;   // the core's hash of the result (Live, Trashed)
    std::optional<vh::mirror::Hash> lastHash;     // within a group: the hash the chain is at
};

struct Batch {
    bool copy{false};
    std::vector<Change> changes;
    std::vector<json> vaultDocs, keyDocs;
};

// Thrown inside the transaction: everything rolls back, then the vault stops (Diverged, Stopped with a state) or the
// apply returns without recording anything. An ops::Error, so the transaction rolls back as a refusal (quietly).
struct Halt : vh::ops::Error {
    Status status;
    std::string state;   // diverged | stopped | expired: recorded; empty: nothing recorded
    std::string reason;
    json detail;
    Halt(const Status status_, std::string state_, std::string reason_, json detail_)
        : Error(reason_), status(status_), state(std::move(state_)), reason(std::move(reason_)),
          detail(std::move(detail_)) {}
};

[[noreturn]] void diverge(std::string reason, json detail) {
    throw Halt{Status::Diverged, "diverged", std::move(reason), std::move(detail)};
}

std::string hexOr(const std::optional<vh::mirror::Hash>& h) { return h ? vh::mirror::toHex(*h) : std::string("none"); }

std::optional<std::string> text(const json& j, const char* key) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_string()) return std::nullopt;
    return it->get<std::string>();
}

std::optional<int64_t> integer(const json& j, const char* key) {
    const auto it = j.find(key);
    if (it == j.end() || !it->is_number_integer()) return std::nullopt;
    return it->get<int64_t>();
}

// What this server must do after the commit, through the calls a local write uses.
struct Effects {
    struct Removed {
        uint32_t id{};
        ta::Located::Kind kind{};
        std::filesystem::path backing;
        std::string path;
        std::optional<uint32_t> parent;
    };
    struct Moved {
        uint32_t id{};
        ta::Located::Kind kind{};
        std::filesystem::path oldBacking;
        std::string oldPath;
        std::optional<uint32_t> oldParent;
    };
    std::vector<Removed> removed;
    std::vector<Moved> moved;
    std::vector<uint32_t> createdDirs;
    std::vector<uint32_t> contentChanged;
    std::vector<uint32_t> live;
    bool vaultChanged{false};
};

struct Committed {
    Result result;
    Effects effects;
};

// The accounts of one apply, mapped once each.
class Accounts {
public:
    Accounts(pqxx::work& txn, std::string ownNode) : txn_(txn), own_(std::move(ownNode)) {}

    std::optional<uint32_t> of(const json& who) {
        if (!who.is_object()) return std::nullopt;
        const auto node = text(who, "node");
        const auto id = integer(who, "id");
        if (!node || !id || *id < 0) return std::nullopt;
        const auto key = std::make_pair(*node, static_cast<uint32_t>(*id));
        if (const auto it = cache_.find(key); it != cache_.end()) return it->second;
        const auto mapped = mq::ApplyRows::account(txn_, own_, key.first, key.second);
        cache_.emplace(key, mapped);
        return mapped;
    }

private:
    pqxx::work& txn_;
    std::string own_;
    std::map<std::pair<std::string, uint32_t>, std::optional<uint32_t>> cache_;
};

mq::EntryFields fieldsOf(const json& s, Accounts& accounts) {
    mq::EntryFields f;
    f.mode = integer(s, "mode");
    f.hidden = s.value("hidden", false);
    f.owner_uid = integer(s, "owner_uid");
    f.owner_gid = integer(s, "owner_gid");
    f.created_at_us = integer(s, "created_at");
    f.modified_at_us = integer(s, "modified_at");
    if (s.contains("created_by")) f.created_by = accounts.of(s["created_by"]);
    if (s.contains("modified_by")) f.modified_by = accounts.of(s["modified_by"]);
    f.size = integer(s, "size");
    f.content_hash = text(s, "content_hash");
    f.mime = text(s, "mime");
    f.generation = text(s, "generation");
    f.key_version = integer(s, "key_version");
    f.target = text(s, "target");
    return f;
}

mq::TrashFields trashOf(const uint32_t vaultId, const Change& c, Accounts& accounts) {
    mq::TrashFields t;
    t.vault_id = vaultId;
    t.uid = c.uid;
    const auto& trashed = c.state.contains("trashed") ? c.state["trashed"] : json::object();
    t.path = text(trashed, "path").value_or("/" + c.uid);
    t.trashed_at_us = integer(trashed, "at");
    if (trashed.contains("by")) t.trashed_by = accounts.of(trashed["by"]);
    t.size = integer(c.state, "size").value_or(0);
    return t;
}

std::string freshAlias(const std::string& token) {
    return vh::crypto::id::Generator({.namespace_token = token}).generate();
}

std::string joinVaultPath(const std::string& parent, const std::string& name) {
    return parent == "/" ? "/" + name : parent + "/" + name;
}

// ---- building a batch ------------------------------------------------------------------------------------------------

Batch fromGroup(const LogGroup& g) {
    Batch b;
    std::map<std::string, std::size_t> index;
    for (const auto& row : g.rows) {
        if (row.op == "vault") {
            b.vaultDocs.push_back(row.state);
            continue;
        }
        if (row.op == "key") {
            b.keyDocs.push_back(row.state);
            continue;
        }
        if (row.op != "upsert" && row.op != "move" && row.op != "restore" && row.op != "trash" && row.op != "purge" &&
            row.op != "delete")
            throw Halt{Status::Stopped, "stopped", "mirror_unknown_op",
                       {{"op", row.op}, {"seq", row.seq}, {"why", "this server cannot apply this kind of change"}}};
        if (!row.uid) diverge("mirror_log_malformed", {{"seq", row.seq}, {"why", "a change without an entry uid"}});
        auto [it, fresh] = index.emplace(*row.uid, b.changes.size());
        if (fresh) {
            Change c;
            c.uid = *row.uid;
            c.expect = row.prev_hash;
            c.lastHash = row.prev_hash;
            b.changes.push_back(std::move(c));
        }
        auto& c = b.changes[it->second];
        // Rows of one entry within a group chain: each replaces the state the one before it left.
        if (!fresh && c.lastHash != row.prev_hash)
            diverge("mirror_log_chain", {{"uid", c.uid}, {"seq", row.seq}, {"expected", hexOr(c.lastHash)},
                                         {"prev_hash", hexOr(row.prev_hash)}});
        c.outcome = row.op == "delete" || row.op == "purge" ? Outcome::Gone
                    : row.op == "trash"                     ? Outcome::Trashed
                                                            : Outcome::Live;
        c.state = row.state;
        c.type = row.type.value_or(c.state.value("type", std::string("file")));
        c.resultHash = c.outcome == Outcome::Gone ? std::nullopt : row.entry_hash;
        c.lastHash = c.resultHash;
        if (c.outcome != Outcome::Gone && !c.resultHash)
            diverge("mirror_log_malformed", {{"uid", c.uid}, {"seq", row.seq}, {"why", "a change without its hash"}});
    }
    return b;
}

Batch fromPage(const TreePage& page, const uint64_t cursor) {
    Batch b;
    b.copy = true;
    for (const auto& item : page.items) {
        if (item.ord <= cursor) continue;
        const auto uid = text(item.state, "uid");
        if (!uid) diverge("mirror_tree_malformed", {{"ord", item.ord}, {"why", "an entry without a uid"}});
        Change c;
        c.uid = *uid;
        c.state = item.state;
        c.outcome = item.state.contains("trashed") ? Outcome::Trashed : Outcome::Live;
        c.type = item.state.value("type", std::string("file"));
        c.resultHash = vh::mirror::entryHash(item.state);
        b.changes.push_back(std::move(c));
    }
    return b;
}

// ---- the transaction -------------------------------------------------------------------------------------------------

struct Before {
    std::optional<ta::Located> located;
    std::shared_ptr<vh::fs::model::Entry> entry;   // a live entry's model: its backing and FUSE paths now
};

struct Run {
    uint32_t vaultId{};
    std::string vaultUid;
    std::string ownNode;
    const Batch* batch{};
    const TreePage* page{};
    const LogGroup* group{};
    std::map<std::string, Before> before;
    ta::Target target;
};

Committed applyInTransaction(pqxx::work& txn, Run& run) {
    Committed out;
    auto& result = out.result;
    auto& fx = out.effects;
    const auto& batch = *run.batch;
    const auto vaultId = run.vaultId;
    mq::ApplyRows::begin(txn);

    const auto mv = mq::ApplyRows::lock(txn, vaultId);
    if (!mv || mv->role != "mirror") throw Halt{Status::Gone, "", "mirror_gone", json::object()};
    if (mv->state != "live") throw Halt{Status::Stopped, "", "mirror_not_live", {{"state", mv->state}}};
    result.copy_cursor = mv->copy_cursor;
    result.copy_finished = mv->copy_finished;
    result.at = mv->position();
    result.digest = mv->digest;

    // ---- the order: the next page or group, exactly once
    uint64_t lastOrd = mv->copy_cursor;
    if (batch.copy) {
        if (mv->copy_finished) throw Halt{Status::AlreadyApplied, "", "mirror_copy_finished", json::object()};
        const auto& page = *run.page;
        if (!page.items.empty() && page.items.front().ord > mv->copy_cursor + 1)
            throw Halt{Status::NotNext, "", "mirror_copy_gap",
                       {{"cursor", mv->copy_cursor}, {"first", page.items.front().ord}}};
        for (const auto& item : page.items) lastOrd = std::max(lastOrd, item.ord);
        if (!page.items.empty() && batch.changes.empty())
            throw Halt{Status::AlreadyApplied, "", "mirror_copy_page_applied", json::object()};
        if (!mv->baseline) {
            mq::ApplyRows::recordBaseline(txn, vaultId, page.baseline, page.digest, page.rows);
        } else if (*mv->baseline != page.baseline || !mv->baseline_digest || *mv->baseline_digest != page.digest) {
            throw Halt{Status::Stopped, "expired", "mirror_baseline_changed",
                       {{"why", "the core's baseline is not the one this copy started from"},
                        {"recorded", {{"term", mv->baseline->term}, {"seq", mv->baseline->seq}}},
                        {"now", {{"term", page.baseline.term}, {"seq", page.baseline.seq}}}}};
        }
    } else {
        const auto& g = *run.group;
        if (!mv->copy_finished) throw Halt{Status::NotNext, "", "mirror_copy_unfinished", json::object()};
        if (g.term != mv->term)
            throw Halt{Status::Stopped, "stopped", "mirror_term_changed",
                       {{"term", mv->term}, {"group_term", g.term},
                        {"why", "the core's term moved; moving the core is not built"}}};
        if (g.last_seq <= mv->last_seq) throw Halt{Status::AlreadyApplied, "", "mirror_group_applied", json::object()};
        if (g.first_seq != mv->last_seq + 1)
            throw Halt{Status::NotNext, "", "mirror_group_gap", {{"last_seq", mv->last_seq}, {"first_seq", g.first_seq}}};
    }

    // ---- the compare-and-set, per uid against the hash this server recorded
    std::vector<std::string> uids, fileUids;
    for (const auto& c : batch.changes) {
        uids.push_back(c.uid);
        if (c.type == "file") fileUids.push_back(c.uid);
    }
    std::ranges::sort(fileUids);
    mq::ApplyRows::lockPending(txn, vaultId, fileUids);
    const auto recorded = mq::ApplyRows::recordedHashes(txn, vaultId, uids);
    for (const auto& c : batch.changes) {
        const auto it = recorded.find(c.uid);
        const std::optional<vh::mirror::Hash> held = it == recorded.end() ? std::nullopt
                                                                          : std::optional<vh::mirror::Hash>(it->second);
        if (held != c.expect)
            diverge("mirror_compare_mismatch",
                    {{"uid", c.uid}, {"expected", hexOr(c.expect)}, {"found", hexOr(held)},
                     {"why", "this server's copy of the entry is not the one the core changed"}});
    }

    // ---- keys: a version this server does not hold stops the vault (rotation over the link is not built)
    for (const auto& k : batch.keyDocs) {
        const auto version = integer(k, "version");
        if (!version || !mq::ApplyRows::keyHeld(txn, vaultId, static_cast<uint32_t>(*version)))
            throw Halt{Status::Stopped, "stopped", "mirror_key_missing",
                       {{"version", version ? json(*version) : json(nullptr)},
                        {"why", "the core uses a key version this server does not hold"}}};
    }
    for (const auto& c : batch.changes)
        if (c.outcome == Outcome::Live && c.type == "file" && !text(c.state, "generation").value_or("").empty()) {
            const auto version = integer(c.state, "key_version").value_or(0);
            if (!mq::ApplyRows::keyHeld(txn, vaultId, static_cast<uint32_t>(version)))
                throw Halt{Status::Stopped, "stopped", "mirror_key_missing",
                           {{"version", version}, {"uid", c.uid},
                            {"why", "a file is sealed under a key version this server does not hold"}}};
        }

    Accounts accounts(txn, run.ownNode);
    const auto root = mq::ApplyRows::rootOf(txn, vaultId);
    if (!root) throw Halt{Status::Gone, "", "mirror_vault_root_missing", json::object()};

    // ---- where each entry is now (in this transaction), against what was recorded
    struct Work {
        std::optional<ta::Located> cur;
        std::optional<uint32_t> liveId;
        bool remove{false}, place{false}, parked{false}, created{false};
    };
    std::vector<Work> work(batch.changes.size());
    for (std::size_t i = 0; i < batch.changes.size(); ++i) {
        const auto& c = batch.changes[i];
        auto& w = work[i];
        w.cur = ta::locate(txn, vaultId, c.uid);
        const bool held = recorded.contains(c.uid);
        if (held != w.cur.has_value())
            diverge(held ? "mirror_entry_missing" : "mirror_entry_unrecorded",
                    {{"uid", c.uid},
                     {"why", held ? "the entry this server recorded is not in its tables"
                                  : "this server's tables hold an entry it never recorded"}});
        if (w.cur && !w.cur->trashed) {
            w.liveId = w.cur->id;
            const auto kind = c.type == "directory" ? ta::Located::Kind::Directory
                              : c.type == "symlink" ? ta::Located::Kind::Symlink
                                                    : ta::Located::Kind::File;
            if (c.outcome == Outcome::Live && kind != w.cur->kind)
                diverge("mirror_type_mismatch", {{"uid", c.uid}, {"type", c.type}});
        }
    }

    const auto parentIdFor = [&](const json& state) -> std::optional<uint32_t> {
        const auto parent = text(state, "parent");
        if (!parent) return std::nullopt;
        if (*parent == run.vaultUid) return root;
        const auto p = ta::locate(txn, vaultId, *parent);
        if (!p || p->trashed || p->kind != ta::Located::Kind::Directory) return std::nullopt;
        return p->id;
    };

    // ---- the trash rows, and what has to be removed or placed
    std::size_t pending = 0;
    for (std::size_t i = 0; i < batch.changes.size(); ++i) {
        const auto& c = batch.changes[i];
        auto& w = work[i];
        const bool live = w.cur && !w.cur->trashed;
        const bool trashed = w.cur && w.cur->trashed;
        if (live && c.outcome != Outcome::Live) w.remove = true;
        if (trashed && c.outcome == Outcome::Gone) mq::ApplyRows::endTrash(txn, w.cur->id);
        if (trashed && c.outcome == Outcome::Trashed) mq::ApplyRows::updateTrash(txn, w.cur->id, trashOf(vaultId, c, accounts));
        if (!w.cur && c.outcome == Outcome::Trashed) {
            auto t = trashOf(vaultId, c, accounts);
            t.alias = freshAlias(t.path + ":" + c.uid);
            mq::ApplyRows::insertTrash(txn, t);
        }
        if (c.outcome == Outcome::Live) {
            if (!live) {
                if (trashed) mq::ApplyRows::endTrash(txn, w.cur->id);   // restored: its trash row ends
                w.place = w.created = true;
            } else if (w.cur->parent_uid != text(c.state, "parent") || w.cur->name != text(c.state, "name")) {
                w.place = true;
            }
        }
        pending += (w.remove ? 1 : 0) + (w.place ? 1 : 0);
    }

    const auto indexOfLive = [&](const uint32_t id) -> std::optional<std::size_t> {
        for (std::size_t j = 0; j < work.size(); ++j)
            if (work[j].liveId == id) return j;
        return std::nullopt;
    };

    std::vector<std::size_t> placed;
    while (pending > 0) {
        bool progress = false;
        for (std::size_t i = 0; i < batch.changes.size(); ++i) {
            const auto& c = batch.changes[i];
            auto& w = work[i];
            if (w.remove) {
                if (c.type == "directory" && mq::ApplyRows::childCount(txn, *w.liveId) > 0) continue;
                const auto& b = run.before[c.uid];
                const auto parent = w.cur->parent_id;
                std::filesystem::path backing;
                if (b.entry && b.located && b.located->id == *w.liveId) backing = b.entry->backing_path;
                mq::ApplyRows::removeEntry(txn, *w.liveId);
                if (c.outcome == Outcome::Trashed) {
                    auto t = trashOf(vaultId, c, accounts);
                    t.backing_path = backing.string();
                    t.alias = w.cur->base32_alias.empty() ? freshAlias(t.path + ":" + c.uid) : w.cur->base32_alias;
                    mq::ApplyRows::insertTrash(txn, t);
                }
                fx.removed.push_back({.id = *w.liveId, .kind = w.cur->kind, .backing = backing, .path = w.cur->path,
                                      .parent = parent});
                w.liveId.reset();
                w.remove = false;
                --pending;
                progress = true;
            } else if (w.place) {
                const auto pid = parentIdFor(c.state);
                if (!pid) continue;
                const auto name = text(c.state, "name").value_or("");
                if (name.empty()) diverge("mirror_tree_malformed", {{"uid", c.uid}, {"why", "an entry without a name"}});
                const auto occupant = mq::ApplyRows::named(txn, *pid, name);
                if (occupant && occupant != w.liveId) continue;
                if (w.created) {
                    const auto path = joinVaultPath(mq::ApplyRows::pathOf(txn, *pid), name);
                    mq::NewEntry e{.vault_id = vaultId,
                                   .parent_id = *pid,
                                   .name = name,
                                   .path = path,
                                   .type = c.type,
                                   .uid = c.uid,
                                   .alias = freshAlias(name),
                                   .fields = fieldsOf(c.state, accounts)};
                    if (run.target.cache) e.inode = run.target.cache->assignInode(run.target.fuse(path));
                    w.liveId = mq::ApplyRows::insertEntry(txn, e);
                    if (c.type == "directory") fx.createdDirs.push_back(*w.liveId);
                } else {
                    if (c.type == "directory" && mq::ApplyRows::within(txn, *pid, *w.liveId)) continue;
                    mq::ApplyRows::moveEntry(txn, *w.liveId, *pid, name);
                }
                placed.push_back(i);
                w.place = false;
                --pending;
                progress = true;
            }
        }
        if (progress || pending == 0) continue;
        // A swap or a cycle of names: one entry that is in the way and moves (or goes) in this group steps aside.
        for (std::size_t i = 0; i < batch.changes.size() && !progress; ++i) {
            if (!work[i].place) continue;
            const auto pid = parentIdFor(batch.changes[i].state);
            if (!pid) continue;
            const auto occupant = mq::ApplyRows::named(txn, *pid, text(batch.changes[i].state, "name").value_or(""));
            if (!occupant) continue;
            const auto j = indexOfLive(*occupant);
            if (!j || work[*j].parked || !(work[*j].place || work[*j].remove)) continue;
            const auto parent = db::query::fs::Directory::parentIdOf(txn, *occupant);
            if (!parent) continue;
            mq::ApplyRows::moveEntry(txn, *occupant, *parent, ".vh-mirror-" + batch.changes[*j].uid);
            work[*j].parked = true;
            placed.push_back(*j);
            progress = true;
        }
        if (progress) continue;
        for (std::size_t i = 0; i < batch.changes.size(); ++i)
            if (work[i].place || work[i].remove)
                diverge("mirror_cannot_apply",
                        {{"uid", batch.changes[i].uid},
                         {"why", work[i].remove ? "a folder the core removed still holds entries here"
                                                : "the entry's place does not exist here or is taken by an entry the "
                                                  "change does not move"},
                         {"parent", text(batch.changes[i].state, "parent").value_or("")},
                         {"name", text(batch.changes[i].state, "name").value_or("")}});
    }

    // ---- the replicated fields of every live result, the paths of what moved (folders first)
    for (std::size_t i = 0; i < batch.changes.size(); ++i) {
        const auto& c = batch.changes[i];
        if (c.outcome != Outcome::Live || !work[i].liveId) continue;
        mq::ApplyRows::updateEntry(txn, *work[i].liveId, c.type, fieldsOf(c.state, accounts));
    }
    std::vector<std::pair<uint32_t, uint32_t>> byDepth;   // (depth, id)
    std::set<uint32_t> seen;
    for (const auto i : placed)
        if (work[i].liveId && seen.insert(*work[i].liveId).second)
            byDepth.emplace_back(mq::ApplyRows::depthOf(txn, *work[i].liveId), *work[i].liveId);
    std::ranges::sort(byDepth);
    for (const auto& [depth, id] : byDepth) mq::ApplyRows::rewritePath(txn, id);
    for (std::size_t i = 0; i < batch.changes.size(); ++i) {
        const auto& c = batch.changes[i];
        const auto& w = work[i];
        if (!w.cur || w.cur->trashed || !w.liveId) continue;
        if (w.cur->parent_id && seen.contains(*w.liveId)) {
            const auto& b = run.before[c.uid];
            if (b.entry && b.located && b.located->id == *w.liveId)
                fx.moved.push_back({.id = *w.liveId, .kind = w.cur->kind, .oldBacking = b.entry->backing_path,
                                    .oldPath = w.cur->path, .oldParent = w.cur->parent_id});
        }
    }

    // ---- contents: a generation this server does not hold is expected (wave 2's lane fetches it)
    for (std::size_t i = 0; i < batch.changes.size(); ++i) {
        const auto& c = batch.changes[i];
        const auto& w = work[i];
        if (c.type != "file") continue;
        const auto objectUid = vh::crypto::id::fromUuid(c.uid);
        if (c.outcome != Outcome::Live) {
            vh::db::query::mirror::PendingContents::forget(txn, vaultId, objectUid);
            continue;
        }
        const auto generation = text(c.state, "generation").value_or("");
        const bool wasLive = w.cur && !w.cur->trashed;
        if (wasLive && w.cur->generation == generation) continue;   // the same bytes
        mq::Expected e;
        e.vault_id = vaultId;
        e.object_uid = objectUid;
        e.generation = generation;
        e.key_version = static_cast<uint32_t>(integer(c.state, "key_version").value_or(0));
        e.size_bytes = static_cast<uint64_t>(integer(c.state, "size").value_or(0));
        e.content_hash = text(c.state, "content_hash").value_or("");
        e.mtime_us = integer(c.state, "modified_at").value_or(0);
        try {
            vh::db::query::mirror::PendingContents::expect(txn, e);
        } catch (const ops::Invalid& why) {
            throw Halt{Status::Stopped, "stopped", "mirror_content_unexpected",
                       {{"uid", c.uid}, {"why", why.what()}}};
        }
        if (wasLive) fx.contentChanged.push_back(*w.liveId);
    }

    // ---- each entry's hash from this server's own tables: the core's, or the vault has diverged
    auto digest = mv->digest;
    for (std::size_t i = 0; i < batch.changes.size(); ++i) {
        const auto& c = batch.changes[i];
        const auto& w = work[i];
        std::optional<vh::mirror::Hash> own;
        if (c.outcome == Outcome::Live && w.liveId) own = mq::ApplyRows::liveHash(txn, *w.liveId);
        else if (c.outcome == Outcome::Trashed) own = mq::ApplyRows::trashHash(txn, vaultId, c.uid);
        if (own != c.resultHash)
            diverge("mirror_apply_mismatch",
                    {{"uid", c.uid}, {"core_hash", hexOr(c.resultHash)}, {"mirror_hash", hexOr(own)},
                     {"core_state", c.state},
                     {"mirror_state", w.liveId ? mq::ApplyRows::liveState(txn, *w.liveId) : json(nullptr)},
                     {"why", "this server's copy of the entry is not what the core holds after the change"}});
        if (const auto it = recorded.find(c.uid); it != recorded.end()) digest.remove(it->second);
        if (own) digest.add(*own);
        mq::ApplyRows::setRecordedHash(txn, vaultId, c.uid, own);
        if (w.liveId) fx.live.push_back(*w.liveId);
    }

    // ---- the vault's settings (recorded; name, description, quota and owner applied)
    const json* vaultDoc = !batch.vaultDocs.empty() ? &batch.vaultDocs.back()
                           : batch.copy && run.page && run.page->vault.is_object() && !run.page->vault.empty() &&
                                     mv->copy_cursor == 0
                               ? &run.page->vault
                               : nullptr;
    if (vaultDoc) {
        const auto owner = vaultDoc->contains("owner") ? accounts.of((*vaultDoc)["owner"]) : std::nullopt;
        for (const auto& note : mq::ApplyRows::applyVault(txn, vaultId, *vaultDoc, owner))
            log::Registry::sync()->info("[MirrorApply] Vault {}: {}", vaultId, note);
        fx.vaultChanged = true;
    }

    // ---- the position
    result.changes = batch.changes.size();
    result.digest = digest;
    if (batch.copy) {
        const auto& page = *run.page;
        const bool finished = !page.more;
        if (finished && digest != page.digest)
            diverge("mirror_copy_mismatch",
                    {{"baseline_digest", page.digest.hex()}, {"baseline_entries", page.digest.entries},
                     {"mirror_digest", digest.hex()}, {"mirror_entries", digest.entries},
                     {"why", "the first copy is not the core's tree as of its baseline"}});
        mq::ApplyRows::advanceCopy(txn, vaultId, lastOrd, digest, finished, page.baseline);
        result.copy_cursor = lastOrd;
        result.copy_finished = finished;
        result.at = finished ? page.baseline : mv->position();
    } else {
        const Position at{run.group->term, run.group->last_seq};
        mq::ApplyRows::advance(txn, vaultId, at, digest);
        result.at = at;
    }
    result.status = Status::Applied;
    return out;
}

// ---- after the commit ------------------------------------------------------------------------------------------------

void removeBacking(const std::filesystem::path& p, const bool tree) {
    if (p.empty()) return;
    std::error_code ec;
    if (tree) std::filesystem::remove_all(p, ec);
    else std::filesystem::remove(p, ec);
}

void afterCommit(const Run& run, const Effects& fx) {
    const auto& t = run.target;
    // Files and symlinks that left: their bytes, derived artifacts and cache entries.
    for (const auto& r : fx.removed) {
        if (r.kind == ta::Located::Kind::Directory) continue;
        if (r.kind == ta::Located::Kind::File) {
            std::scoped_lock lock(vh::fs::Filesystem::contentWriteMutex(r.id));
            removeBacking(r.backing, false);
            t.engine->purgeDerivedArtifacts(r.id);
        } else {
            removeBacking(r.backing, false);
        }
        ta::evicted(t, r.path, r.parent);
    }
    // Moves whose backing path changed (a new parent): out to a staging area deepest first, then in shallowest first,
    // so a folder and something that left it can both move.
    struct Relocation {
        uint32_t id;
        ta::Located::Kind kind;
        std::filesystem::path from, to, staged;
    };
    std::vector<Relocation> relocations;
    for (const auto& m : fx.moved) {
        const auto now = db::query::fs::Entry::getFSEntryById(m.id);
        if (!now) continue;
        ta::evicted(t, m.oldPath, m.oldParent);
        if (m.oldBacking.empty() || now->backing_path == m.oldBacking) continue;
        relocations.push_back({.id = m.id, .kind = m.kind, .from = m.oldBacking, .to = now->backing_path, .staged = {}});
    }
    if (!relocations.empty()) {
        const auto staging = vh::paths::getBackingPath() / (".vh-mirror-move-" + run.vaultUid);
        std::error_code ec;
        std::filesystem::create_directories(staging, ec);
        std::ranges::sort(relocations, [](const Relocation& a, const Relocation& b) {
            return std::distance(a.from.begin(), a.from.end()) > std::distance(b.from.begin(), b.from.end());
        });
        for (auto& r : relocations) {
            if (!std::filesystem::exists(r.from, ec)) continue;
            r.staged = staging / std::to_string(r.id);
            std::filesystem::rename(r.from, r.staged, ec);
            if (ec) {
                log::Registry::sync()->warn("[MirrorApply] Vault {}: could not move the backing of entry {}: {}",
                                            run.vaultId, r.id, ec.message());
                r.staged.clear();
            }
        }
        std::ranges::sort(relocations, [](const Relocation& a, const Relocation& b) {
            return std::distance(a.to.begin(), a.to.end()) < std::distance(b.to.begin(), b.to.end());
        });
        for (const auto& r : relocations) {
            if (r.staged.empty()) continue;
            std::filesystem::create_directories(r.to.parent_path(), ec);
            std::filesystem::rename(r.staged, r.to, ec);
            if (ec)
                log::Registry::sync()->warn("[MirrorApply] Vault {}: could not move the backing of entry {}: {}",
                                            run.vaultId, r.id, ec.message());
        }
        std::filesystem::remove_all(staging, ec);
    }
    // Folders that left, once what moved out of them has.
    for (const auto& r : fx.removed) {
        if (r.kind != ta::Located::Kind::Directory) continue;
        removeBacking(r.backing, true);
        ta::evicted(t, r.path, r.parent);
    }
    for (const auto id : fx.createdDirs)
        if (const auto e = db::query::fs::Entry::getFSEntryById(id)) ta::ensureBackingDirectory(e->backing_path);
    for (const auto id : fx.contentChanged) t.engine->purgeDerivedArtifacts(id);
    for (const auto id : fx.live) ta::cacheFresh(t, id);
    if (fx.vaultChanged)
        if (const auto& deps = runtime::Deps::get(); deps.storageManager)
            if (const auto v = db::query::vault::Vault::getVault(run.vaultId)) {
                try {
                    deps.storageManager->updateVault(v);   // the engine and the cache take the new name and quota
                } catch (const std::exception& e) {
                    log::Registry::sync()->warn("[MirrorApply] Vault {}: the engine did not take the core's settings: {}",
                                                run.vaultId, e.what());
                }
            }
}

bool openNow(const Options& options, const ta::Target& target, const Before& b) {
    if (!b.located || b.located->trashed || b.located->kind != ta::Located::Kind::File) return false;
    std::optional<uint64_t> inode = b.located->inode;
    if (!inode && target.cache)
        if (const auto cached = target.cache->getEntryById(b.located->id); cached && cached->inode) inode = cached->inode;
    if (!inode) return false;
    if (options.isOpen) return options.isOpen(*inode);
    return vh::fuse::WorkingCopies::instance().isOpen(*inode);
}

Result run(const uint32_t vaultId, const TreePage* page, const LogGroup* group, const Options& options) {
    Run r;
    r.vaultId = vaultId;
    r.page = page;
    r.group = group;
    const auto vaultUid = mq::MirrorVaults::vaultUidOf(vaultId);
    if (!vaultUid) return {.status = Status::Gone, .reason = "mirror_gone"};
    r.vaultUid = *vaultUid;
    try {
        r.target = ta::Target::of(vaultId);
    } catch (const std::exception&) {
        return {.status = Status::Gone, .reason = "mirror_vault_engine_missing"};
    }
    r.ownNode = vh::db::query::device::Devices::nodeId();

    Batch batch;
    try {
        if (page) {
            const auto mv = mq::MirrorVaults::get(vaultId);
            batch = fromPage(*page, mv ? mv->copy_cursor : 0);
        } else {
            batch = fromGroup(*group);
        }
    } catch (const Halt& h) {
        if (!h.state.empty()) (void)mq::MirrorVaults::stop(vaultId, h.state, h.reason, h.detail);
        return {.status = h.status, .reason = h.reason, .detail = h.detail};
    }
    r.batch = &batch;

    // What is there now, and a file open here that the group would change: the whole group waits.
    for (const auto& c : batch.changes) {
        Before b;
        b.located = ta::locate(vaultId, c.uid);
        if (b.located && !b.located->trashed) b.entry = db::query::fs::Entry::getFSEntryById(b.located->id);
        const bool replaces = c.outcome != Outcome::Live ||
                              (c.type == "file" && b.located && b.located->generation != text(c.state, "generation").value_or(""));
        if (replaces && openNow(options, r.target, b))
            return {.status = Status::Deferred, .reason = "mirror_file_open",
                    .detail = {{"uid", c.uid}, {"path", b.located->path}}};
        r.before.emplace(c.uid, std::move(b));
    }

    Committed done;
    try {
        done = db::Transactions::exec("mirror::apply", [&](pqxx::work& txn) { return applyInTransaction(txn, r); });
    } catch (const Halt& h) {
        if (!h.state.empty()) {
            (void)mq::MirrorVaults::stop(vaultId, h.state, h.reason, h.detail);
            log::Registry::sync()->warn("[MirrorApply] Vault {} stopped as {} ({}): {}", vaultId, h.state, h.reason,
                                        h.detail.value("why", std::string{}));
        }
        Result out{.status = h.status, .reason = h.reason, .detail = h.detail};
        if (const auto mv = mq::MirrorVaults::get(vaultId)) {
            out.at = mv->position();
            out.digest = mv->digest;
            out.copy_cursor = mv->copy_cursor;
            out.copy_finished = mv->copy_finished;
        }
        return out;
    }
    afterCommit(r, done.effects);
    return done.result;
}

}

Result applyTreePage(const uint32_t vaultId, const TreePage& page, const Options& options) {
    return mirror_apply_detail::run(vaultId, &page, nullptr, options);
}

Result applyGroup(const uint32_t vaultId, const LogGroup& group, const Options& options) {
    return mirror_apply_detail::run(vaultId, nullptr, &group, options);
}

}
