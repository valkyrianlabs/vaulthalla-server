#include "mirror/apply/Applier.hpp"

#include "crypto/id/Generator.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/mirror/Apply.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/Keys.hpp"
#include "db/query/mirror/Pending.hpp"
#include "db/query/mirror/Resync.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/tree_apply/TreeApply.hpp"
#include "fuse/WorkingCopies.hpp"
#include "log/Registry.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/submit/Local.hpp"
#include "mirror/versions/Versions.hpp"
#include "recovery/local/Versions.hpp"
#include "mirror/submit/Submit.hpp"
#include "ops/Error.hpp"
#include "paths.h"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
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
    // Not the core's change but this server's own entry brought into line (a change made here and still pending:
    // mirror::submit). revert: back to the state the core last confirmed for it (mirror_dirty), its hash the one
    // recorded; aside: renamed to its conflict name so that the core's entry can take the name (its fields, hash and
    // digest untouched: it stays pending).
    bool revert{false};
    bool aside{false};
};

struct Batch {
    bool copy{false};
    std::vector<Change> changes;
    std::vector<json> vaultDocs, keyDocs;
    std::optional<std::string> origin;   // the request id of a change this group carries out for a mirror
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
    std::vector<uint64_t> confirmed;   // pending changes confirmed: their sealed bytes leave the pending store
    bool vaultChanged{false};
    bool keysChanged{false};           // a delivered key version became the current one: the engine reloads its keys
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
        if (row.origin && !b.origin) b.origin = row.origin;
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
        if (row.origin && !b.origin) b.origin = row.origin;
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
    // Settling entries a pending change held (mirror::submit): no order, no position, no digest moves.
    const std::vector<std::string>* settle{};
    const std::function<void(pqxx::work&)>* also{};
    std::map<std::string, Before> before;
    ta::Target target;
};

// Where one change's entry is in this transaction, and what is left to do for it.
struct Work {
    std::optional<ta::Located> cur;
    std::optional<uint32_t> liveId;
    bool remove{false}, place{false}, parked{false}, created{false};
};

// One transaction's changes: the batch's, then this server's own entries brought into line as the work needs them
// (reverts, entries set aside), in one list so the placement loop sees them all.
struct Pass {
    pqxx::work& txn;
    Run& run;
    Accounts& accounts;
    uint32_t root{};
    Effects& fx;
    std::vector<Change> changes;
    std::vector<Work> work;
    std::map<std::string, vh::mirror::Hash> recorded;
    std::map<std::string, mq::DirtyEntry> dirty;
    std::set<std::string> listed;   // uids in `changes`
    std::vector<std::size_t> placed;
    // A resync's copy (migration 168): the person who started it, named on what it keeps as held changes.
    std::optional<mq::Account> resyncActor;

    Pass(pqxx::work& t, Run& r, Accounts& a, const uint32_t rootId, Effects& effects)
        : txn(t), run(r), accounts(a), root(rootId), fx(effects) {}

    [[nodiscard]] std::optional<vh::mirror::Hash> recordedOf(const std::string& uid) const {
        const auto it = recorded.find(uid);
        return it == recorded.end() ? std::nullopt : std::optional<vh::mirror::Hash>(it->second);
    }
};

ta::Located::Kind kindOfType(const std::string& type) {
    return type == "directory" ? ta::Located::Kind::Directory
           : type == "symlink" ? ta::Located::Kind::Symlink
                               : ta::Located::Kind::File;
}

std::string typeOfKind(const ta::Located::Kind k) {
    return k == ta::Located::Kind::Directory ? "directory" : k == ta::Located::Kind::Symlink ? "symlink" : "file";
}

// Where change `i` stands now, and the trash rows it ends, updates or writes; what is left to remove or place.
std::size_t setUp(Pass& p, const std::size_t i) {
    const auto& c = p.changes[i];
    auto& w = p.work[i];
    const auto vaultId = p.run.vaultId;
    w.cur = ta::locate(p.txn, vaultId, c.uid);
    const bool held = p.recorded.contains(c.uid);
    // A change made here and still pending may have created, removed or trashed the entry: its tables are this
    // server's own until the core's state replaces them.
    // A copy (a resync's: migration 168) takes an entry this server holds under the uid as it is: the copy brings it to
    // the core's state in place (a fresh mirror's vault holds none).
    const bool adopted = p.run.batch->copy && !held && w.cur.has_value();
    if (held != w.cur.has_value() && !p.dirty.contains(c.uid) && !c.aside && !adopted)
        diverge(held ? "mirror_entry_missing" : "mirror_entry_unrecorded",
                {{"uid", c.uid},
                 {"why", held ? "the entry this server recorded is not in its tables"
                              : "this server's tables hold an entry it never recorded"}});
    if (w.cur && !w.cur->trashed) {
        w.liveId = w.cur->id;
        if (c.outcome == Outcome::Live && kindOfType(c.type) != w.cur->kind)
            diverge("mirror_type_mismatch", {{"uid", c.uid}, {"type", c.type}});
    }
    const bool live = w.cur && !w.cur->trashed;
    const bool trashed = w.cur && w.cur->trashed;
    if (live && c.outcome != Outcome::Live) w.remove = true;
    if (trashed && c.outcome == Outcome::Gone) mq::ApplyRows::endTrash(p.txn, w.cur->id);
    if (trashed && c.outcome == Outcome::Trashed) mq::ApplyRows::updateTrash(p.txn, w.cur->id, trashOf(vaultId, c, p.accounts));
    if (!w.cur && c.outcome == Outcome::Trashed) {
        auto t = trashOf(vaultId, c, p.accounts);
        t.alias = freshAlias(t.path + ":" + c.uid);
        mq::ApplyRows::insertTrash(p.txn, t);
    }
    if (c.outcome == Outcome::Live) {
        if (!live) {
            if (trashed) mq::ApplyRows::endTrash(p.txn, w.cur->id);   // restored: its trash row ends
            w.place = w.created = true;
        } else if (w.cur->parent_uid != text(c.state, "parent") || w.cur->name != text(c.state, "name")) {
            w.place = true;
        }
    }
    return (w.remove ? 1 : 0) + (w.place ? 1 : 0);
}

// This server's entry `uid`, held dirty by a pending change and not part of the work yet, back to the state the core
// last confirmed for it. False when it is not dirty or already listed. `setUpNow`: the placement loop is running (it
// counts what is left in `pending`); otherwise the next placeAll sets it up.
bool addRevert(Pass& p, const std::string& uid, std::size_t& pending, const bool setUpNow = true) {
    if (p.listed.contains(uid)) return false;
    const auto d = p.dirty.find(uid);
    if (d == p.dirty.end()) return false;
    for (const auto& [u, h] : mq::ApplyRows::recordedHashes(p.txn, p.run.vaultId, {uid})) p.recorded[u] = h;
    Change c;
    c.uid = uid;
    c.revert = true;
    c.outcome = d->second.kind == "live" ? Outcome::Live : d->second.kind == "trashed" ? Outcome::Trashed : Outcome::Gone;
    c.state = d->second.confirmed.is_object() ? d->second.confirmed : json{{"uid", uid}};
    const auto now = ta::locate(p.txn, p.run.vaultId, uid);
    c.type = c.state.value("type", now ? typeOfKind(now->kind) : std::string("file"));
    c.expect = p.recordedOf(uid);
    c.resultHash = p.recordedOf(uid);
    p.changes.push_back(std::move(c));
    p.work.emplace_back();
    p.listed.insert(uid);
    if (setUpNow) pending += setUp(p, p.changes.size() - 1);
    return true;
}

// This server's entry `occupantId` (dirty, pending here, not part of the work) holds the name the core's entry needs:
// it steps aside to its conflict name in the same folder and stays pending (the core will refuse its change for the
// name, and mirror::submit then resubmits it under this name).
bool setAside(Pass& p, const uint32_t occupantId, std::size_t& pending) {
    const auto uid = mq::Pending::uidOfEntry(p.txn, occupantId);
    // In a resync's copy, an entry of this server's that the core's tree has not named (yet) steps aside too: a later
    // page takes it into place, or the copy's end keeps it as a held change.
    const bool unrecorded = p.run.batch->copy && uid && mq::ApplyRows::recordedHashes(p.txn, p.run.vaultId, {*uid}).empty();
    if (!uid || p.listed.contains(*uid) || !(p.dirty.contains(*uid) || unrecorded)) return false;
    const auto now = ta::locate(p.txn, p.run.vaultId, *uid);
    if (!now || now->trashed || !now->parent_uid) return false;
    const auto aside = vh::mirror::submit::conflictName(now->name, *uid, now->kind == ta::Located::Kind::Directory);
    if (aside == now->name || mq::ApplyRows::named(p.txn, *now->parent_id, aside)) return false;
    Change c;
    c.uid = *uid;
    c.aside = true;
    c.outcome = Outcome::Live;
    c.type = typeOfKind(now->kind);
    c.state = {{"uid", *uid}, {"type", c.type}, {"parent", *now->parent_uid}, {"name", aside}};
    p.changes.push_back(std::move(c));
    p.work.emplace_back();
    p.listed.insert(*uid);
    pending += setUp(p, p.changes.size() - 1);
    return true;
}

// ---- a resync's copy (migration 168; design/peers/mirror.md "As built: moving the core and resync") ----------------------

// This server's own version of an entry, kept as a held change (with its bytes when it has some here).
uint64_t resyncKeep(Pass& p, const std::string& uid, const std::string& op, json args, const std::string& path,
                    const std::string& code, const std::string& why, const std::filesystem::path& bytes) {
    mq::HeldChange h;
    h.vault_id = p.run.vaultId;
    h.kind = "held";
    h.request_id = vh::mirror::submit::newRequestId();
    h.op = op;
    h.entry_uid = uid;
    h.args = std::move(args);
    h.path = path;
    h.actor = *p.resyncActor;
    h.reason_code = code;
    h.reason = why;
    const auto id = mq::Pending::hold(p.txn, h);
    // The bytes get their second name now, inside the transaction and before anything removes or replaces them: a stop
    // between the commit and its effects must not leave a held change without its bytes. A transaction that rolls back
    // leaves a name no row uses, which housekeeping sweeps; one that cannot keep the bytes does not commit.
    std::error_code ec;
    if (!bytes.empty() && std::filesystem::is_regular_file(bytes, ec))
        vh::mirror::submit::contents::keep(bytes, vh::mirror::submit::contents::heldBlob(p.run.vaultId, id));
    return id;
}

// A file of this server's whose bytes the core's state replaces: this server's version is kept first (unless a
// change of its, held when the resync started, keeps it already).
void resyncKeepReplaced(Pass& p, const Change& c, const ta::Located& was) {
    if (!p.resyncActor || was.trashed || was.generation.empty()) return;
    if (mq::Resync::heldOpenFor(p.txn, p.run.vaultId, c.uid)) return;
    const auto b = p.run.before.find(c.uid);
    if (b == p.run.before.end() || !b->second.entry) return;
    const auto file = std::dynamic_pointer_cast<vh::fs::model::File>(b->second.entry);
    if (!file) return;
    json args{{"uid", c.uid},
              {"parent_uid", was.parent_id == p.root ? p.run.vaultUid : was.parent_uid.value_or("")},
              {"name", was.name},
              {"generation", was.generation},
              {"key_version", file->encrypted_with_key_version},
              {"size", file->size_bytes},
              {"content_hash", file->content_hash.value_or("")}};
    if (file->mime_type) args["mime"] = *file->mime_type;
    (void)resyncKeep(p, c.uid, "write", std::move(args), was.path, "mirror_resync_replaced",
                     "this server's version of the file when its copy started over; the core's replaced it",
                     file->backing_path);
}

// The copy is complete: every entry here the core's tree does not hold leaves the tree, kept as a held change.
void resyncKeepLeftovers(Pass& p) {
    auto& txn = p.txn;
    const auto vaultId = p.run.vaultId;
    for (const auto& l : mq::Resync::leftovers(txn, vaultId)) {
        if (!p.resyncActor)
            diverge("mirror_entry_unrecorded", {{"uid", l.uid}, {"path", l.path},
                                                {"why", "this server's tables hold an entry the core's tree does not"}});
        const auto parentUid = l.parent_uid.value_or("");
        // A change of its that was pending when the resync started is held already, with its bytes: it leaves the
        // tree all the same, kept once.
        const bool keptAlready = mq::Resync::heldOpenFor(txn, vaultId, l.uid);
        if (l.trashed) {
            if (!keptAlready)
                (void)resyncKeep(p, l.uid, "write",
                                 {{"uid", l.uid}, {"name", l.name}, {"size", l.size}, {"trashed", true}}, l.path,
                                 "mirror_resync_extra",
                                 "in this server's trash when its copy started over; the core's tree does not hold it",
                                 l.backing);
            mq::ApplyRows::endTrash(txn, l.id);
            vh::db::query::mirror::PendingContents::forget(txn, vaultId, vh::crypto::id::fromUuid(l.uid));
            continue;
        }
        const auto model = db::query::fs::Entry::getFSEntryById(l.id);
        const std::filesystem::path backing = model ? model->backing_path : std::filesystem::path{};
        json args{{"uid", l.uid}, {"parent_uid", parentUid}, {"name", l.name}};
        std::string op = "mkdir";
        auto kind = ta::Located::Kind::Directory;
        if (l.kind == "file") {
            op = "write";
            kind = ta::Located::Kind::File;
            args.update({{"generation", l.generation}, {"key_version", l.key_version}, {"size", l.size},
                         {"content_hash", l.content_hash}});
            vh::db::query::mirror::PendingContents::forget(txn, vaultId, vh::crypto::id::fromUuid(l.uid));
        } else if (l.kind == "symlink") {
            op = "symlink";
            kind = ta::Located::Kind::Symlink;
            args["target"] = l.target;
        }
        if (!keptAlready)
            (void)resyncKeep(p, l.uid, op, std::move(args), l.path, "mirror_resync_extra",
                             "this server held it when its copy started over; the core's tree does not",
                             kind == ta::Located::Kind::File ? backing : std::filesystem::path{});
        const auto parent = db::query::fs::Directory::parentIdOf(txn, l.id);
        mq::ApplyRows::removeEntry(txn, l.id);
        p.fx.removed.push_back({.id = l.id, .kind = kind, .backing = backing, .path = l.path, .parent = parent});
    }
}

// Removes and places every change from `from` on, repeating until done; a swap or a cycle of names goes through a
// temporary name; this server's pending entries in the way are brought back or set aside.
void placeAll(Pass& p, const std::size_t from) {
    auto& txn = p.txn;
    const auto vaultId = p.run.vaultId;
    std::size_t pending = 0;
    for (std::size_t i = from; i < p.changes.size(); ++i) pending += setUp(p, i);

    const auto parentIdFor = [&](const json& state) -> std::optional<uint32_t> {
        const auto parent = text(state, "parent");
        if (!parent) return std::nullopt;
        if (*parent == p.run.vaultUid) return p.root;
        const auto at = ta::locate(txn, vaultId, *parent);
        if (!at || at->trashed || at->kind != ta::Located::Kind::Directory) return std::nullopt;
        return at->id;
    };
    const auto indexOfLive = [&](const uint32_t id) -> std::optional<std::size_t> {
        for (std::size_t j = from; j < p.work.size(); ++j)
            if (p.work[j].liveId == id) return j;
        return std::nullopt;
    };

    while (pending > 0) {
        bool progress = false;
        for (std::size_t i = from; i < p.changes.size(); ++i) {
            // `p.changes` grows inside the loop (reverts, entries set aside): after one is added, `c` is not used again.
            const auto& c = p.changes[i];
            if (p.work[i].remove) {
                if (c.type == "directory" && mq::ApplyRows::childCount(txn, *p.work[i].liveId) > 0) {
                    // Entries made or moved in here by a change still pending here go back to where the core has them.
                    for (const auto child : mq::ApplyRows::children(txn, *p.work[i].liveId))
                        if (const auto uid = mq::Pending::uidOfEntry(txn, child))
                            progress = addRevert(p, *uid, pending) || progress;
                    continue;
                }
                auto& w = p.work[i];
                const auto& b = p.run.before[c.uid];
                const auto parent = w.cur->parent_id;
                std::filesystem::path backing;
                if (b.entry && b.located && b.located->id == *w.liveId) backing = b.entry->backing_path;
                mq::ApplyRows::removeEntry(txn, *w.liveId);
                if (c.outcome == Outcome::Trashed) {
                    auto t = trashOf(vaultId, c, p.accounts);
                    t.backing_path = backing.string();
                    t.alias = w.cur->base32_alias.empty() ? freshAlias(t.path + ":" + c.uid) : w.cur->base32_alias;
                    mq::ApplyRows::insertTrash(txn, t);
                }
                p.fx.removed.push_back({.id = *w.liveId, .kind = w.cur->kind, .backing = backing, .path = w.cur->path,
                                        .parent = parent});
                w.liveId.reset();
                w.remove = false;
                --pending;
                progress = true;
            } else if (p.work[i].place) {
                const auto pid = parentIdFor(c.state);
                if (!pid) {
                    // Its folder was removed here by a change still pending: the folder comes back as the core has it.
                    if (const auto parent = text(c.state, "parent")) progress = addRevert(p, *parent, pending) || progress;
                    continue;
                }
                const auto name = text(c.state, "name").value_or("");
                if (name.empty()) diverge("mirror_tree_malformed", {{"uid", c.uid}, {"why", "an entry without a name"}});
                const auto occupant = mq::ApplyRows::named(txn, *pid, name);
                if (occupant && occupant != p.work[i].liveId) {
                    if (!c.aside && !c.revert && !indexOfLive(*occupant)) progress = setAside(p, *occupant, pending) || progress;
                    continue;
                }
                auto& w = p.work[i];
                if (w.created) {
                    const auto path = joinVaultPath(mq::ApplyRows::pathOf(txn, *pid), name);
                    mq::NewEntry e{.vault_id = vaultId,
                                   .parent_id = *pid,
                                   .name = name,
                                   .path = path,
                                   .type = c.type,
                                   .uid = c.uid,
                                   .alias = freshAlias(name),
                                   .fields = fieldsOf(c.state, p.accounts)};
                    // The cache hands out inodes by path: an entry that stepped aside from this path in this
                    // transaction still holds the one it had, and this one is given its own after the commit.
                    if (p.run.target.cache)
                        if (const auto inode = p.run.target.cache->assignInode(p.run.target.fuse(path));
                            !mq::ApplyRows::inodeTaken(txn, inode))
                            e.inode = inode;
                    w.liveId = mq::ApplyRows::insertEntry(txn, e);
                    if (c.type == "directory") p.fx.createdDirs.push_back(*w.liveId);
                } else {
                    if (c.type == "directory" && mq::ApplyRows::within(txn, *pid, *w.liveId)) continue;
                    mq::ApplyRows::moveEntry(txn, *w.liveId, *pid, name);
                }
                p.placed.push_back(i);
                w.place = false;
                --pending;
                progress = true;
            }
        }
        if (progress || pending == 0) continue;
        // A swap or a cycle of names: one entry that is in the way and moves (or goes) in this group steps aside.
        for (std::size_t i = from; i < p.changes.size() && !progress; ++i) {
            if (!p.work[i].place) continue;
            const auto pid = parentIdFor(p.changes[i].state);
            if (!pid) continue;
            const auto occupant = mq::ApplyRows::named(txn, *pid, text(p.changes[i].state, "name").value_or(""));
            if (!occupant) continue;
            const auto j = indexOfLive(*occupant);
            if (!j || p.work[*j].parked || !(p.work[*j].place || p.work[*j].remove)) continue;
            const auto parent = db::query::fs::Directory::parentIdOf(txn, *occupant);
            if (!parent) continue;
            mq::ApplyRows::moveEntry(txn, *occupant, *parent, ".vh-mirror-" + p.changes[*j].uid);
            p.work[*j].parked = true;
            p.placed.push_back(*j);
            progress = true;
        }
        if (progress) continue;
        for (std::size_t i = from; i < p.changes.size(); ++i)
            if (p.work[i].place || p.work[i].remove)
                diverge("mirror_cannot_apply",
                        {{"uid", p.changes[i].uid},
                         {"why", p.work[i].remove ? "a folder the core removed still holds entries here"
                                                  : "the entry's place does not exist here or is taken by an entry the "
                                                    "change does not move"},
                         {"parent", text(p.changes[i].state, "parent").value_or("")},
                         {"name", text(p.changes[i].state, "name").value_or("")}});
    }
}

// The replicated fields, the paths of what moved, the contents expected and each entry's hash (the core's, or the
// vault has diverged), for every change from `from` on; the digest moves.
void finishAll(Pass& p, const std::size_t from, vh::mirror::Digest& digest) {
    auto& txn = p.txn;
    const auto vaultId = p.run.vaultId;
    for (std::size_t i = from; i < p.changes.size(); ++i) {
        const auto& c = p.changes[i];
        if (c.aside || c.outcome != Outcome::Live || !p.work[i].liveId) continue;
        mq::ApplyRows::updateEntry(txn, *p.work[i].liveId, c.type, fieldsOf(c.state, p.accounts));
    }
    std::vector<std::pair<uint32_t, uint32_t>> byDepth;   // (depth, id)
    std::set<uint32_t> seen;
    for (const auto i : p.placed)
        if (i >= from && p.work[i].liveId && seen.insert(*p.work[i].liveId).second)
            byDepth.emplace_back(mq::ApplyRows::depthOf(txn, *p.work[i].liveId), *p.work[i].liveId);
    std::ranges::sort(byDepth);
    for (const auto& [depth, id] : byDepth) mq::ApplyRows::rewritePath(txn, id);
    for (std::size_t i = from; i < p.changes.size(); ++i) {
        const auto& c = p.changes[i];
        const auto& w = p.work[i];
        if (!w.cur || w.cur->trashed || !w.liveId) continue;
        if (w.cur->parent_id && seen.contains(*w.liveId)) {
            const auto& b = p.run.before[c.uid];
            if (b.entry && b.located && b.located->id == *w.liveId)
                p.fx.moved.push_back({.id = *w.liveId, .kind = w.cur->kind, .oldBacking = b.entry->backing_path,
                                      .oldPath = w.cur->path, .oldParent = w.cur->parent_id});
        }
    }

    // ---- contents: a generation this server does not hold is expected (wave 2's lane fetches it)
    for (std::size_t i = from; i < p.changes.size(); ++i) {
        const auto& c = p.changes[i];
        const auto& w = p.work[i];
        if (c.type != "file" || c.aside) continue;
        const auto objectUid = vh::crypto::id::fromUuid(c.uid);
        if (c.outcome != Outcome::Live) {
            vh::db::query::mirror::PendingContents::forget(txn, vaultId, objectUid);
            continue;
        }
        const auto generation = text(c.state, "generation").value_or("");
        // The bytes on this disk are those of the entry as it was before this transaction (a revert or a pending entry
        // may have moved it within it).
        const auto b = p.run.before.find(c.uid);
        const auto& was = b != p.run.before.end() && b->second.located ? b->second.located : w.cur;
        const bool wasLive = was && !was->trashed;
        if (wasLive && was->generation == generation) continue;   // the same bytes
        if (p.run.batch->copy && wasLive) resyncKeepReplaced(p, c, *was);
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
        if (wasLive && w.liveId) p.fx.contentChanged.push_back(*w.liveId);
    }

    // ---- each entry's hash from this server's own tables: the core's, or the vault has diverged
    for (std::size_t i = from; i < p.changes.size(); ++i) {
        const auto& c = p.changes[i];
        const auto& w = p.work[i];
        if (c.aside) {
            if (w.liveId) p.fx.live.push_back(*w.liveId);
            continue;
        }
        std::optional<vh::mirror::Hash> own;
        if (c.outcome == Outcome::Live && w.liveId) own = mq::ApplyRows::liveHash(txn, *w.liveId);
        else if (c.outcome == Outcome::Trashed) own = mq::ApplyRows::trashHash(txn, vaultId, c.uid);
        if (own != c.resultHash)
            diverge(c.revert ? "mirror_revert_mismatch" : "mirror_apply_mismatch",
                    {{"uid", c.uid}, {"core_hash", hexOr(c.resultHash)}, {"mirror_hash", hexOr(own)},
                     {"core_state", c.state},
                     {"mirror_state", w.liveId ? mq::ApplyRows::liveState(txn, *w.liveId) : json(nullptr)},
                     {"why", c.revert ? "this server's entry did not come back to the state the core last confirmed"
                                      : "this server's copy of the entry is not what the core holds after the change"}});
        if (const auto prior = p.recordedOf(c.uid)) digest.remove(*prior);
        if (own) digest.add(*own);
        mq::ApplyRows::setRecordedHash(txn, vaultId, c.uid, own);
        if (own) p.recorded[c.uid] = *own;
        else p.recorded.erase(c.uid);
        // What the core confirmed for an entry a pending change holds: the state it now comes back to.
        if (!c.revert && p.dirty.contains(c.uid)) {
            const std::string kind = c.outcome == Outcome::Live ? "live" : c.outcome == Outcome::Trashed ? "trashed" : "none";
            const auto state = kind == "none" ? json(nullptr) : c.state;
            mq::Pending::confirm(txn, vaultId, c.uid, kind, state);
            p.dirty[c.uid].kind = kind;
            p.dirty[c.uid].confirmed = state;
        }
        if (w.liveId) p.fx.live.push_back(*w.liveId);
    }
}

// The entries of a settled change (confirmed, refused, or executed with nothing to apply) that no other pending change
// holds: each back to what the core confirmed, where its tables differ from it, then clean.
void settleAll(Pass& p, const std::vector<std::string>& uids, const uint64_t settledId, vh::mirror::Digest& digest) {
    std::vector<std::string> clean;
    for (const auto& uid : uids)
        if (p.dirty.contains(uid) && !mq::Pending::held(p.txn, p.run.vaultId, uid, settledId)) clean.push_back(uid);
    if (clean.empty()) return;
    const auto from = p.changes.size();
    std::size_t ignored = 0;
    for (const auto& uid : clean) {
        // Listed already in this transaction (the group just applied it): its tables are the core's state now.
        if (p.listed.contains(uid)) continue;
        for (const auto& [u, h] : mq::ApplyRows::recordedHashes(p.txn, p.run.vaultId, {uid})) p.recorded[u] = h;
        const auto at = ta::locate(p.txn, p.run.vaultId, uid);
        std::optional<vh::mirror::Hash> own;
        if (at && !at->trashed) own = mq::ApplyRows::liveHash(p.txn, at->id);
        else if (at) own = mq::ApplyRows::trashHash(p.txn, p.run.vaultId, uid);
        if (own == p.recordedOf(uid)) continue;
        (void)addRevert(p, uid, ignored, false);
    }
    if (p.changes.size() > from) {
        placeAll(p, from);
        finishAll(p, from, digest);
    }
    for (const auto& uid : clean) {
        if (mq::Pending::held(p.txn, p.run.vaultId, uid, settledId)) continue;
        mq::Pending::clean(p.txn, p.run.vaultId, uid);
        p.dirty.erase(uid);
    }
}

Committed applyInTransaction(pqxx::work& txn, Run& run) {
    Committed out;
    auto& result = out.result;
    auto& fx = out.effects;
    const auto& batch = *run.batch;
    const auto vaultId = run.vaultId;
    mq::ApplyRows::begin(txn);

    const auto mv = mq::ApplyRows::lock(txn, vaultId);
    if (!mv || mv->role != "mirror") throw Halt{Status::Gone, "", "mirror_gone", json::object()};
    // `switching`: a planned switch preparing here, which the follower catches up (mirror::switching::following).
    if (mv->state != "live" && mv->state != "switching")
        throw Halt{Status::Stopped, "", "mirror_not_live", {{"state", mv->state}}};
    result.copy_cursor = mv->copy_cursor;
    result.copy_finished = mv->copy_finished;
    result.at = mv->position();
    result.digest = mv->digest;

    // ---- the order: the next page or group, exactly once (a settle has none)
    uint64_t lastOrd = mv->copy_cursor;
    if (run.settle) {
        if (!mv->copy_finished) throw Halt{Status::NotNext, "", "mirror_copy_unfinished", json::object()};
    } else if (batch.copy) {
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
                        {"why", "the core's log is in another term than this copy follows"}}};
        if (g.last_seq <= mv->last_seq) throw Halt{Status::AlreadyApplied, "", "mirror_group_applied", json::object()};
        if (g.first_seq != mv->last_seq + 1)
            throw Halt{Status::NotNext, "", "mirror_group_gap", {{"last_seq", mv->last_seq}, {"first_seq", g.first_seq}}};
    }

    Accounts accounts(txn, run.ownNode);
    const auto root = mq::ApplyRows::rootOf(txn, vaultId);
    if (!root) throw Halt{Status::Gone, "", "mirror_vault_root_missing", json::object()};
    Pass p(txn, run, accounts, *root, fx);
    if (batch.copy && mv->resync_by) p.resyncActor = mq::Account{.node = run.ownNode, .id = *mv->resync_by};
    p.changes = batch.changes;
    p.work.resize(p.changes.size());
    for (const auto& c : p.changes) p.listed.insert(c.uid);

    // ---- the compare-and-set, per uid against the hash this server recorded (what the core last confirmed: a
    // change made here and still pending never moves it)
    std::vector<std::string> uids, fileUids;
    for (const auto& c : p.changes) {
        uids.push_back(c.uid);
        if (c.type == "file") fileUids.push_back(c.uid);
    }
    std::ranges::sort(fileUids);
    mq::ApplyRows::lockPending(txn, vaultId, fileUids);
    p.recorded = mq::ApplyRows::recordedHashes(txn, vaultId, uids);
    for (const auto& c : p.changes) {
        const auto held = p.recordedOf(c.uid);
        if (held != c.expect)
            diverge("mirror_compare_mismatch",
                    {{"uid", c.uid}, {"expected", hexOr(c.expect)}, {"found", hexOr(held)},
                     {"why", "this server's copy of the entry is not the one the core changed"}});
    }

    // ---- keys: a version this server does not hold stops the vault. A rotation on the core delivers its new version
    // first (mirror/rotate): held here, it becomes the current one when the core's log names it, with the core's key
    // check (another key under that version stops the vault).
    for (const auto& k : batch.keyDocs) {
        const auto version = integer(k, "version");
        if (!version || *version <= 0 || !mq::ApplyRows::keyHeld(txn, vaultId, static_cast<uint32_t>(*version)))
            throw Halt{Status::Stopped, "stopped", "mirror_key_missing",
                       {{"version", version ? json(*version) : json(nullptr)},
                        {"why", "the core uses a key version this server does not hold"}}};
        try {
            if (mq::MirrorKeys::promote(txn, vaultId, static_cast<uint32_t>(*version), text(k, "key_check")))
                fx.keysChanged = true;
        } catch (const ops::Conflict& e) {
            throw Halt{Status::Stopped, "stopped", "mirror_key_mismatch",
                       {{"version", *version}, {"why", std::string(e.what())}}};
        }
    }
    for (const auto& c : p.changes)
        if (c.outcome == Outcome::Live && c.type == "file" && !text(c.state, "generation").value_or("").empty()) {
            const auto version = integer(c.state, "key_version").value_or(0);
            if (!mq::ApplyRows::keyHeld(txn, vaultId, static_cast<uint32_t>(version)))
                throw Halt{Status::Stopped, "stopped", "mirror_key_missing",
                           {{"version", version}, {"uid", c.uid},
                            {"why", "a file is sealed under a key version this server does not hold"}}};
        }

    // ---- the entries changes made here and still pending hold, with what the core last confirmed for each
    if (mv->copy_finished) p.dirty = mq::Pending::dirty(txn, vaultId);

    auto digest = mv->digest;
    placeAll(p, 0);
    finishAll(p, 0, digest);

    // ---- a group that carries out one of this server's pending changes: confirmed once all of its groups are here
    // (the change is not applied a second time: the group's result is what the tables now hold), and the entries it
    // held settle
    if (run.group && batch.origin)
        if (const auto mine = mq::Pending::countApplied(txn, vaultId, *batch.origin); mine && mine->confirmed()) {
            mq::Pending::remove(txn, mine->id);
            fx.confirmed.push_back(mine->id);
            settleAll(p, mine->uids, mine->id, digest);
        }
    // ---- settling a change (refused, or executed with nothing to apply here)
    if (run.settle) {
        if (run.also && *run.also) (*run.also)(txn);
        settleAll(p, *run.settle, 0, digest);
        if (digest != mv->digest)
            diverge("mirror_settle_moved_digest",
                    {{"why", "bringing this server's own entries back to the core's state changed the digest"}});
        result.status = Status::Applied;
        result.digest = digest;
        return out;
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
        if (finished) resyncKeepLeftovers(p);
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
    for (const auto id : fx.confirmed)
        vh::mirror::submit::contents::dropBlob(vh::mirror::submit::contents::pendingBlob(run.vaultId, id));
    if (fx.keysChanged && t.engine && t.engine->encryptionManager) {
        try {
            t.engine->encryptionManager->load_key();
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[MirrorApply] Vault {}: the engine did not take the core's new key version: {}",
                                        run.vaultId, e.what());
        }
    }
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

// Versions on the mirror (wave 5, mirror/versions/Versions.hpp): before a group's transaction, the prior generation of
// each live file the core replaces (a new generation), trashes or removes, staged by the local versioning mechanism under
// this vault's mirror setting; attached in the transaction, finished after the commit, dropped with it otherwise.
// Only the core's own changes (never this server's entries brought back into line), only groups (a first copy replaces
// nothing anyone had here).
std::vector<vh::recovery::local::versions::Pending> keepVersions(const Run& r,
                                                                  const vh::recovery::LocalVersioningPolicy& policy) {
    namespace lv = vh::recovery::local;
    std::vector<lv::versions::Pending> kept;
    if (!r.target.engine) return kept;
    for (const auto& c : r.batch->changes) {
        if (c.type != "file" || c.revert || c.aside) continue;
        const auto it = r.before.find(c.uid);
        if (it == r.before.end() || !it->second.located) continue;
        const auto& at = *it->second.located;
        if (at.trashed || at.kind != ta::Located::Kind::File || at.generation.empty()) continue;
        const bool replaced = c.outcome == Outcome::Live && at.generation != text(c.state, "generation").value_or("");
        const bool removed = c.outcome != Outcome::Live;
        if (!replaced && !removed) continue;
        const auto prior = db::query::fs::File::getFileById(at.id);
        if (!prior) continue;
        // Contents of that generation that never arrived here: there is nothing of it to keep (the bytes on disk, if
        // any, are an older generation's).
        if (prior->object_uid)
            if (const auto waiting = mq::PendingContents::get(r.vaultId, *prior->object_uid);
                waiting && waiting->generation == at.generation)
                continue;
        auto p = lv::versions::retain(*r.target.engine, *prior, removed ? lv::Reason::Delete : lv::Reason::Overwrite,
                                      {.actor = std::nullopt, .upstream = false, .held_copy_policy = policy});
        if (p.active()) kept.push_back(std::move(p));
    }
    return kept;
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

Result run(const uint32_t vaultId, const TreePage* page, const LogGroup* group, const Options& options,
           const std::vector<std::string>* settle = nullptr, const std::function<void(pqxx::work&)>* also = nullptr) {
    // A change made here and a page or group from the core never interleave (mirror::submit::Local holds it too).
    std::scoped_lock local(vh::mirror::submit::vaultMutex(vaultId));
    Run r;
    r.vaultId = vaultId;
    r.page = page;
    r.group = group;
    r.settle = settle;
    r.also = also;
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
        } else if (group) {
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
    // The entries changes made here still hold: the apply may bring them back to the core's state or set them aside.
    for (const auto& uid : mq::Pending::dirtyUids(vaultId)) {
        if (r.before.contains(uid)) continue;
        Before b;
        b.located = ta::locate(vaultId, uid);
        if (b.located && !b.located->trashed) b.entry = db::query::fs::Entry::getFSEntryById(b.located->id);
        r.before.emplace(uid, std::move(b));
    }

    // What this vault's mirror setting keeps of the core's replacements and removals (nothing while it keeps none).
    std::vector<vh::recovery::local::versions::Pending> kept;
    if (group)
        if (const auto policy = vh::mirror::versions::policyFor(vaultId)) kept = keepVersions(r, *policy);

    Committed done;
    try {
        done = db::Transactions::exec("mirror::apply", [&](pqxx::work& txn) {
            for (auto& k : kept) k.attach(txn);
            return applyInTransaction(txn, r);
        });
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
    for (auto& k : kept) k.committed();
    afterCommit(r, done.effects);
    // The first copy is complete: the write gate's reason changes (mirror_first_copy no more) before this returns.
    if (page && done.result.copy_finished) vh::mirror::access::reload();
    return done.result;
}

}

Result applyTreePage(const uint32_t vaultId, const TreePage& page, const Options& options) {
    return mirror_apply_detail::run(vaultId, &page, nullptr, options);
}

Result applyGroup(const uint32_t vaultId, const LogGroup& group, const Options& options) {
    return mirror_apply_detail::run(vaultId, nullptr, &group, options);
}

Result settle(const uint32_t vaultId, const std::vector<std::string>& uids, const std::function<void(pqxx::work&)>& also) {
    return mirror_apply_detail::run(vaultId, nullptr, nullptr, {}, &uids, &also);
}

}
