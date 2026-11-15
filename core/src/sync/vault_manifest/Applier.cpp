#include "sync/vault_manifest/Applier.hpp"

#include "audit/Trail.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Symlink.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/sync/ManifestApply.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "fs/model/file/Trashed.hpp"
#include "fuse/WorkingCopies.hpp"
#include "log/Registry.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "storage/CloudEngine.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "recovery/local/Snapshots.hpp"
#include "recovery/local/Versions.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>

#include <vl/keykit/kev1.hpp>

#include <algorithm>
#include <set>
#include <filesystem>
#include <mutex>

namespace vh::sync::vault_manifest {

namespace applier_detail {

namespace mf = vh::sync::manifest;
using Q = db::query::sync::ManifestApply;
using db::query::sync::ApplyRow;

enum class Outcome { Applied, Skipped, Deferred, Kept };

std::string joinPath(const std::string& parent, const std::string& name) {
    return parent == "/" ? "/" + name : parent + "/" + name;
}

bool open(const ApplyOptions& options, const std::optional<uint64_t>& inode) {
    if (!inode) return false;
    if (options.isOpen) return options.isOpen(*inode);
    return fuse::WorkingCopies::instance().isOpen(*inode);
}

// Everything one apply needs from the server.
struct Ctx {
    uint32_t vaultId{};
    std::shared_ptr<storage::Engine> engine;
    std::shared_ptr<fs::cache::Registry> cache;
    unsigned int owner{};
    uint64_t epoch{};
    std::string rootSha;
    const ApplyOptions* options{};
    const mf::Content* result{};
    ApplyReport* report{};

    [[nodiscard]] std::filesystem::path fuse(const std::string& vaultPath) const {
        return engine->vaultPathToFusePath(vaultPath);
    }
    void note(std::string text) const { report->notes.push_back(std::move(text)); }
    void cacheFresh(const unsigned int id) const {
        if (!cache) return;
        if (const auto entry = db::query::fs::Entry::getFSEntryById(id)) {
            if (cache->entryExists(entry->fuse_path)) cache->updateEntry(entry);
            else cache->cacheEntry(entry);
            if (entry->parent_id) (void)cache->refreshDirStats(*entry->parent_id);
        }
    }
};

std::optional<std::pair<unsigned int, std::string>> liveDir(const Ctx& c, const std::optional<std::string>& uid) {
    if (!uid) return std::nullopt;
    const auto r = Q::row(c.vaultId, *uid);
    if (!r || r->trashed || r->kind != ApplyRow::Kind::Dir) return std::nullopt;
    return std::make_pair(r->id, r->path);
}

// The local copy is the generation the bucket's object holds (no change waiting for its upload).
bool inSync(const ApplyRow& r) { return r.files_generation == r.index_generation; }

// A content replacement of a closed, in-sync file: the row and index take the new generation, local versioning keeps
// the replaced one, the cached bytes go (the next open hydrates the new object).
Outcome replaceNow(const Ctx& c, const ApplyRow& cur, const mf::Entry& target) {
    std::scoped_lock lock(fs::Filesystem::contentWriteMutex(cur.id));
    const auto file = db::query::fs::File::getFileById(cur.id);
    if (!file) return Outcome::Skipped;
    auto kept = recovery::local::versions::retain(*c.engine, *file, recovery::local::Reason::Download,
                                                  {.actor = std::nullopt, .upstream = false});
    const bool done = db::Transactions::exec("ManifestApply::replaceContent", [&](pqxx::work& txn) {
        kept.attach(txn);
        if (!Q::replaceContent(txn, cur.id, target, cur.files_generation)) return false;
        Q::upsertIndex(txn, c.vaultId, target);
        return true;
    });
    if (!done) {
        kept.abort();
        return Outcome::Skipped;
    }
    kept.committed();
    std::error_code ec;
    if (!file->backing_path.empty()) std::filesystem::remove(file->backing_path, ec);
    c.engine->purgeDerivedArtifacts(cur.id);
    c.cacheFresh(cur.id);
    return Outcome::Applied;
}

Outcome replaceContent(const Ctx& c, const mf::Op& op) {
    const auto cur = Q::row(c.vaultId, op.uid);
    if (!cur || cur->trashed || cur->kind != ApplyRow::Kind::File) return Outcome::Skipped;
    if (cur->index_generation != op.ours->generation) return Outcome::Skipped;
    if (open(*c.options, cur->inode)) {
        db::Transactions::exec("ManifestApply::defer", [&](pqxx::work& txn) {
            Q::defer(txn, c.vaultId, {op.uid, "replace_content", op.target, cur->files_generation, c.epoch, c.rootSha});
        });
        return Outcome::Deferred;
    }
    if (!inSync(*cur)) {
        // A local change waits for its upload: the index takes the incoming object, the files row stays, and the
        // planner sees both sides changed (the existing conflict path, under the vault's policy).
        db::Transactions::exec("ManifestApply::index", [&](pqxx::work& txn) { Q::upsertIndex(txn, c.vaultId, *op.target); });
        return Outcome::Kept;
    }
    return replaceNow(c, *cur, *op.target);
}

Outcome create(const Ctx& c, const mf::Op& op) {
    const auto& t = *op.target;
    if (t.trashed) {
        if (const auto cur = Q::row(c.vaultId, op.uid)) return Outcome::Skipped;
        const auto parent = liveDir(c, t.parent);
        const auto path = t.trashed->path.value_or(joinPath(parent ? parent->second : "/", t.name));
        db::Transactions::exec("ManifestApply::createTrashed", [&](pqxx::work& txn) {
            Q::createTrashed(txn, c.vaultId, c.owner, t, path);
            Q::upsertIndex(txn, c.vaultId, t);
        });
        return Outcome::Applied;
    }
    const auto parent = liveDir(c, t.parent);
    if (!parent) return Outcome::Skipped;
    const auto path = joinPath(parent->second, t.name);
    std::optional<uint64_t> inode;
    if (c.cache) inode = c.cache->assignInode(c.fuse(path));
    const auto trash = op.kind == mf::OpKind::Restore ? Q::row(c.vaultId, op.uid) : std::nullopt;
    if (op.kind == mf::OpKind::Restore && (!trash || !trash->trashed)) return Outcome::Skipped;
    std::shared_ptr<vh::fs::model::file::Trashed> trashedFile;
    if (trash)
        for (const auto& f : db::query::fs::File::listTrashedFiles(c.vaultId))
            if (f && f->id == trash->id) trashedFile = f;
    const auto id = db::Transactions::exec("ManifestApply::create", [&](pqxx::work& txn) -> std::optional<unsigned int> {
        const auto made = Q::createEntry(txn, c.vaultId, c.owner, t, parent->first, path, inode);
        if (!made) return std::nullopt;
        if (t.kind == mf::EntryKind::File) Q::upsertIndex(txn, c.vaultId, t);
        // Our trash row ends with the restore: its purge would delete the object the live file now names.
        if (trash) txn.exec("UPDATE files_trashed SET deleted_at = NOW() WHERE id = $1", pqxx::params{trash->id});
        return made;
    });
    if (!id) return Outcome::Skipped;
    if (trashedFile) c.engine->removeLocally(trashedFile);   // the trashed generation's local bytes, as a purge would
    if (t.kind == mf::EntryKind::Dir)
        if (const auto entry = db::query::fs::Entry::getFSEntryById(*id)) {
            std::error_code ec;   // its backing directory, as a local mkdir makes it (files under it are hydrated there)
            std::filesystem::create_directories(entry->backing_path, ec);
        }
    c.cacheFresh(*id);
    return Outcome::Applied;
}

Outcome move(const Ctx& c, const mf::Op& op) {
    const auto cur = Q::row(c.vaultId, op.uid);
    if (!cur || cur->trashed) return Outcome::Skipped;
    if (cur->parent_uid != op.ours->parent || cur->name != op.ours->name) return Outcome::Skipped;
    const auto parent = liveDir(c, op.target->parent);
    if (!parent) return Outcome::Skipped;
    const auto to = joinPath(parent->second, op.target->name);
    const auto entry = db::query::fs::Entry::getFSEntryById(cur->id);
    if (!entry) return Outcome::Skipped;
    std::error_code ec;
    if (cur->kind == ApplyRow::Kind::File && !std::filesystem::exists(entry->backing_path, ec)) {
        // No local bytes (a remote-only file under cache): the rows move; the next open hydrates at the new place.
        if (!cur->parent_id) return Outcome::Skipped;
        const bool moved = db::Transactions::exec("ManifestApply::moveRow", [&](pqxx::work& txn) {
            return Q::moveRow(txn, cur->id, *cur->parent_id, cur->name, parent->first, op.target->name, to);
        });
        if (!moved) return Outcome::Skipped;
        if (c.cache) {
            c.cache->evictPath(c.fuse(cur->path));
            if (cur->parent_id) (void)c.cache->refreshDirStats(*cur->parent_id);
        }
        c.cacheFresh(cur->id);
        return Outcome::Applied;
    }
    // A folder another writer created here (or a restore did) may have no backing directory yet.
    if (cur->kind == ApplyRow::Kind::Dir) std::filesystem::create_directories(entry->backing_path, ec);
    const int rc = fs::Filesystem::rename(c.fuse(cur->path), c.fuse(to), nullptr, c.engine, fs::RenameMode::NoReplace);
    return rc == 0 ? Outcome::Applied : Outcome::Skipped;
}

Outcome setAttributes(const Ctx& c, const mf::Op& op) {
    const auto cur = Q::row(c.vaultId, op.uid);
    if (!cur || cur->trashed) return Outcome::Skipped;
    const bool done = db::Transactions::exec("ManifestApply::setAttributes", [&](pqxx::work& txn) {
        return Q::setAttributes(txn, cur->id, *op.ours, *op.target);
    });
    if (!done) return Outcome::Skipped;
    c.cacheFresh(cur->id);
    return Outcome::Applied;
}

Outcome deleteFile(const Ctx& c, const ApplyRow& cur, const std::string& uid) {
    c.engine->removeLocally(cur.path);   // local versioning keeps the last generation
    db::Transactions::exec("ManifestApply::deleteIndex", [&](pqxx::work& txn) { Q::deleteIndex(txn, c.vaultId, uid); });
    return Outcome::Applied;
}

Outcome remove(const Ctx& c, const mf::Op& op) {
    const auto cur = Q::row(c.vaultId, op.uid);
    if (!cur) return Outcome::Applied;   // gone already
    if (op.kind == mf::OpKind::Purge) {
        if (!cur->trashed) return Outcome::Skipped;
        for (const auto& f : db::query::fs::File::listTrashedFiles(c.vaultId))
            if (f && f->id == cur->id) c.engine->removeLocally(f);
        db::query::fs::File::markTrashedFileDeleted(cur->id);
        db::Transactions::exec("ManifestApply::deleteIndex", [&](pqxx::work& txn) { Q::deleteIndex(txn, c.vaultId, op.uid); });
        return Outcome::Applied;
    }
    if (cur->trashed) return op.kind == mf::OpKind::Trash ? Outcome::Kept : Outcome::Skipped;
    if (cur->parent_uid != op.ours->parent || cur->name != op.ours->name) return Outcome::Skipped;
    if (cur->kind == ApplyRow::Kind::Dir) {
        if (op.kind != mf::OpKind::Delete || !db::query::fs::Directory::isDirectoryEmpty(cur->id)) return Outcome::Skipped;
        if (!db::query::fs::Directory::deleteEmptyDirectory(cur->id)) return Outcome::Skipped;
        if (c.cache) {
            c.cache->evictPath(c.fuse(cur->path));
            if (cur->parent_id) (void)c.cache->refreshDirStats(*cur->parent_id);
        }
        return Outcome::Applied;
    }
    if (cur->kind == ApplyRow::Kind::Symlink) {
        if (const auto link = db::query::fs::Symlink::getSymlinkById(cur->id)) db::query::fs::Symlink::deleteSymlink(link);
        if (c.cache) c.cache->evictPath(c.fuse(cur->path));
        return Outcome::Applied;
    }
    if (cur->index_generation != op.ours->generation) return Outcome::Skipped;
    const auto kind = op.kind == mf::OpKind::Trash ? "trash" : "delete";
    if (open(*c.options, cur->inode)) {
        db::Transactions::exec("ManifestApply::defer", [&](pqxx::work& txn) {
            Q::defer(txn, c.vaultId, {op.uid, kind, op.kind == mf::OpKind::Trash ? op.target : std::nullopt,
                                      cur->files_generation, c.epoch, c.rootSha});
        });
        return Outcome::Deferred;
    }
    if (!inSync(*cur)) return Outcome::Kept;   // an edit not yet uploaded beats the delete; the next publish carries it
    if (op.kind == mf::OpKind::Trash) {
        fs::Filesystem::remove(c.fuse(cur->path), c.owner);
        return Outcome::Applied;
    }
    return deleteFile(c, *cur, op.uid);
}

Outcome snapshot(const Ctx& c, const mf::Op& op) {
    if (op.kind == mf::OpKind::CreateSnapshot) {
        db::Transactions::exec("ManifestApply::createSnapshot", [&](pqxx::work& txn) {
            Q::createSnapshot(txn, c.vaultId, c.owner, *op.snapshot, *c.result);
        });
        return Outcome::Applied;
    }
    const auto id = Q::snapshotId(c.vaultId, op.uid);
    if (!id) return Outcome::Applied;
    try {
        recovery::local::snapshots::remove(*id);
    } catch (const std::exception& e) {
        c.note(fmt::format("snapshot {} not deleted: {}", op.uid, e.what()));
        return Outcome::Skipped;
    }
    return Outcome::Applied;
}

Outcome execute(const Ctx& c, const mf::Op& op, const mf::Content& ours) {
    switch (op.kind) {
    case mf::OpKind::SetVault: {
        if (!op.vault || !ours.vault) return Outcome::Kept;
        const auto notes = db::Transactions::exec("ManifestApply::setVault", [&](pqxx::work& txn) {
            return Q::setVault(txn, c.vaultId, *ours.vault, *op.vault);
        });
        for (const auto& n : notes) c.note(n);
        return Outcome::Applied;
    }
    case mf::OpKind::AddEnvelopes:
        // Never grant or envelope rows (grants come only from the account's signed policy): the other writer's kids
        // were read into manifest_foreign_envelope before the first transaction (carryEnvelopes), and the collector
        // names those whose recipient one of this vault's grants has.
        return Outcome::Applied;
    case mf::OpKind::CreateDir:
    case mf::OpKind::Create:
    case mf::OpKind::Restore: return create(c, op);
    case mf::OpKind::Move: return move(c, op);
    case mf::OpKind::ReplaceContent: return replaceContent(c, op);
    case mf::OpKind::SetAttributes: return setAttributes(c, op);
    case mf::OpKind::Trash:
    case mf::OpKind::Delete:
    case mf::OpKind::Purge: return remove(c, op);
    case mf::OpKind::AddHistory:
        db::Transactions::exec("ManifestApply::addHistory", [&](pqxx::work& txn) { Q::addHistory(txn, c.vaultId, *op.target); });
        return Outcome::Applied;
    case mf::OpKind::CreateSnapshot:
    case mf::OpKind::DeleteSnapshot: return snapshot(c, op);
    }
    return Outcome::Skipped;
}

// Other writers' envelope kids (design: "Foreign envelopes"): each one this vault doesn't know is read once from the
// bucket and kept as a reference when it is an envelope of this vault and that key version whose kid is its hash. No
// grant row, no envelope row: what roots name is decided by the collector from this vault's grants.
void carryEnvelopes(const Ctx& c, const mf::Uid& vaultUid, const mf::Loaded& head, mf::ObjectStore* store) {
    if (!store) return;
    std::set<std::string> known;
    bool loaded = false;
    for (const auto& k : head.root.keys) {
        if (!k.envelopes) continue;
        for (const auto& kid : *k.envelopes) {
            if (!loaded) {
                known = Q::knownKids(c.vaultId);
                loaded = true;
            }
            if (known.contains(kid)) continue;
            try {
                const auto obj = store->get(".vaulthalla/key/" + kid);
                if (!obj) {
                    c.note("envelope " + kid + " is not in the bucket; not carried");
                    continue;
                }
                const auto digest = mf::sha256Hex(obj->bytes);
                mf::Uid first{};
                for (std::size_t i = 0; i < first.size(); ++i)
                    first[i] = static_cast<uint8_t>(std::stoi(digest.substr(2 * i, 2), nullptr, 16));
                const auto header = vl::keykit::kev1::inspect(obj->bytes);
                if (mf::uidText(first) != kid || header.key_version != k.version ||
                    !std::equal(header.vault_uid.begin(), header.vault_uid.end(), vaultUid.begin()) ||
                    header.recipient_class != 0) {
                    c.note("envelope " + kid + " is not an envelope of this vault and key version " +
                           std::to_string(k.version) + "; not carried");
                    continue;
                }
                static constexpr char kHex[] = "0123456789abcdef";
                std::string recipient;
                for (const auto b : header.recipient_id) {
                    recipient += kHex[b >> 4];
                    recipient += kHex[b & 0x0f];
                }
                Q::addForeignEnvelope(c.vaultId, kid, k.version, recipient);
            } catch (const std::exception& e) {
                c.note("envelope " + kid + " not carried: " + e.what());
            }
        }
    }
}

// The apply stops at this root (the pass stalls); the operator is alerted once per root and reason.
[[noreturn]] void stop(const uint32_t vaultId, const mf::Loaded& head, const std::string& reason, const std::string& why) {
    if (Q::noteStopped(vaultId, head.acceptance.epoch, head.acceptance.root_sha256, head.root.producer.node_id, reason)) {
        notifications::OperatorNotification n;
        n.eventKey = "manifest_apply_stopped";
        n.eventType = "sync";
        n.severity = "warning";
        n.recipientGroup = "security";
        n.fingerprint = fmt::format("manifest-apply:{}:{}:{}", vaultId, reason, head.acceptance.root_sha256);
        n.rendered.subject = fmt::format("[Vaulthalla] Vault {} can't take in a manifest root ({})", vaultId, reason);
        n.rendered.text = why + "\n\nThe vault's sync is stalled; nothing was changed.\n";
        n.rendered.html = "<p>" + why + "</p><p>The vault's sync is stalled; nothing was changed.</p>";
        n.tags = {{"event_type", "sync"}, {"severity", "warning"}, {"vault_id", std::to_string(vaultId)},
                  {"reason", reason}};
        if (!notifications::OperatorNotificationBus::instance().enqueue(std::move(n)))
            log::Registry::sync()->warn("[ManifestApply] Dropped the stopped-apply alert for vault {}", vaultId);
    }
    throw ApplyStopped(why);
}

Ctx contextFor(const uint32_t vaultId, const ApplyOptions& options, ApplyReport& report) {
    Ctx c;
    c.vaultId = vaultId;
    const auto& deps = runtime::Deps::get();
    if (deps.storageManager) c.engine = deps.storageManager->getEngine(vaultId);
    if (!c.engine) throw std::runtime_error(fmt::format("vault {} has no storage engine to apply a manifest to", vaultId));
    c.cache = deps.fsCache;
    c.owner = c.engine->vault->owner_id;
    c.options = &options;
    c.report = &report;
    return c;
}

}

std::size_t finishDeferred(const uint32_t vaultId, const ApplyOptions& options) {
    namespace d = applier_detail;
    const auto rows = d::Q::deferred(vaultId);
    if (rows.empty()) return 0;
    ApplyReport scratch;
    auto c = d::contextFor(vaultId, options, scratch);
    std::size_t finished = 0;
    for (const auto& row : rows) {
        const auto cur = d::Q::row(vaultId, row.uid);
        if (cur && !cur->trashed && d::open(options, cur->inode)) continue;   // still open
        const bool unchanged = cur && !cur->trashed && cur->files_generation == row.ours_generation;
        if (cur && !cur->trashed) {
            if (row.op == "replace_content" && row.target) {
                if (unchanged) (void)d::replaceNow(c, *cur, *row.target);
                else db::Transactions::exec("ManifestApply::index", [&](pqxx::work& txn) {
                    d::Q::upsertIndex(txn, vaultId, *row.target);   // the close sealed new bytes: edit / edit
                });
            } else if (unchanged && row.op == "delete") {
                (void)d::deleteFile(c, *cur, row.uid);
            } else if (unchanged && row.op == "trash") {
                fs::Filesystem::remove(c.fuse(cur->path), c.owner);
            }
            // a delete or trash of a file the close changed: the edit wins, the next publish carries it
        }
        db::Transactions::exec("ManifestApply::dropDeferred", [&](pqxx::work& txn) { d::Q::dropDeferred(txn, vaultId, row.uid); });
        ++finished;
    }
    return finished;
}

ApplyReport apply(const uint32_t vaultId, const manifest::Uid& vaultUid, const crypto::vhf1::KeyLookup& keys,
                  const manifest::Loaded& head, const std::string& selfNode, const ApplyOptions& options) {
    namespace d = applier_detail;
    namespace mf = vh::sync::manifest;
    ApplyReport report;
    report.epoch = head.acceptance.epoch;
    report.root_sha256 = head.acceptance.root_sha256;
    report.producer = head.root.producer.node_id;
    if (!head.issues.empty() || !head.blind_ranges.empty())
        d::stop(vaultId, head, "manifest_head_incomplete",
                fmt::format("the root of epoch {} did not load completely ({} segment issue(s)); applying it would delete "
                            "what it lost",
                            head.acceptance.epoch, head.issues.size()));

    auto c = d::contextFor(vaultId, options, report);
    const bool shared = head.root.writers && head.root.writers->size() > 1;
    if (shared) {
        const auto cloud = std::dynamic_pointer_cast<storage::CloudEngine>(c.engine);
        if (cloud && cloud->remote_policy()->strategy == sync::model::RemotePolicy::Strategy::Mirror)
            d::stop(vaultId, head, "manifest_mirror_shared",
                    fmt::format("the root of epoch {} names {} writers, and this vault syncs with the mirror strategy, "
                                "which deletes remote objects its database doesn't hold: another writer's would go",
                                head.acceptance.epoch, head.root.writers->size()));
    }
    if (kCarriesForeignEnvelopes) d::carryEnvelopes(c, vaultUid, head, options.store);

    (void)finishDeferred(vaultId, options);

    // The base: the content of `known`, from the local copy; without a usable one, none (a union: nothing deleted).
    const auto state = db::query::sync::Manifest::state(vaultId);
    std::optional<mf::Content> base;
    if (state.epoch && state.root_sha256)
        if (const auto copy = db::query::sync::Manifest::base(vaultId)) {
            std::string why;
            base = mf::openBaseCopy(*copy, vaultUid, keys, mf::Known{*state.epoch, *state.root_sha256}, &why);
            if (!base) report.notes.push_back("the local base copy is not usable (" + why + ")");
        }
    if (!base) {
        report.union_base = true;
        base = mf::Content{};
    }
    const auto ours = db::query::sync::Manifest::collect(vaultId);
    auto rec = mf::reconcile(*base, head.content, ours);
    if (rec.stopped()) {
        std::string codes;
        for (const auto& p : rec.key_problems) codes += fmt::format("{}{} (version {})", codes.empty() ? "" : ", ", p.code, p.version);
        d::stop(vaultId, head, rec.key_problems.front().code,
                "the root of epoch " + std::to_string(head.acceptance.epoch) + " can't be applied: " + codes);
    }
    report.conflicts = rec.conflicts;
    std::size_t openConflicts = 0;
    for (const auto& k : rec.conflicts) openConflicts += k.open ? 1 : 0;
    const auto save = [&] {
        d::Q::saveReport(vaultId, {.epoch = report.epoch, .root_sha256 = report.root_sha256, .producer = report.producer,
                                   .recorded = report.recorded, .union_base = report.union_base,
                                   .applied = report.applied, .skipped = report.skipped, .deferred = report.deferred,
                                   .kept = report.kept, .conflicts_decided = rec.conflicts.size() - openConflicts,
                                   .conflicts_open = openConflicts, .notes = report.notes});
    };

    c.epoch = head.acceptance.epoch;
    c.rootSha = head.acceptance.root_sha256;
    c.result = &rec.result;
    db::query::sync::Manifest::markApplying(vaultId, head.acceptance.epoch, head.acceptance.root_sha256);
    for (const auto& op : rec.plan) {
        if (options.beforeOp) options.beforeOp(op);
        switch (d::execute(c, op, ours)) {
        case d::Outcome::Applied: ++report.applied; break;
        case d::Outcome::Skipped:
            ++report.skipped;
            report.notes.push_back(fmt::format("{} {} skipped: the entry changed here since it was collected",
                                               mf::to_string(op.kind), op.uid));
            break;
        case d::Outcome::Deferred: ++report.deferred; break;
        case d::Outcome::Kept: ++report.kept; break;
        }
    }
    if (report.skipped) {
        log::Registry::sync()->info("[ManifestApply] Vault {}: {} change(s) of epoch {} skipped (local writes since the "
                                    "collect); the next pass applies the root again",
                                    vaultId, report.skipped, head.acceptance.epoch);
        save();
        return report;
    }

    db::Transactions::exec("ManifestApply::record", [&](pqxx::work& txn) {
        db::query::sync::Manifest::recordRoot(
            txn, vaultId,
            {.epoch = head.acceptance.epoch,
             .root_sha256 = head.acceptance.root_sha256,
             .etag = head.etag,
             .sids = [&] {
                 std::vector<std::string> sids;
                 for (const auto& s : head.root.segments) sids.push_back(s.sid);
                 for (const auto& s : head.root.snapshots) sids.push_back(s.sid);
                 return sids;
             }(),
             .version_id = head.version_id,
             .base_version_id = head.base_version_id,
             .settle_window = head.settle_window,
             .own = !selfNode.empty() && head.root.producer.node_id == selfNode,
             .base = mf::baseCopyOf(head.root, head.root_bytes, head.segments, head.snapshots),
             .writers = head.root.writers.value_or(std::vector<std::string>{})});
    });
    report.recorded = true;
    save();
    audit::record({.action = "manifest.applied", .outcome = audit::Outcome::Success, .actor_id = std::nullopt,
                   .actor = "ManifestApplier", .vault_id = vaultId, .entry_id = std::nullopt,
                   .details = {{"epoch", static_cast<int64_t>(report.epoch)},
                               {"producer", report.producer},
                               {"applied", static_cast<int64_t>(report.applied)},
                               {"deferred", static_cast<int64_t>(report.deferred)},
                               {"kept", static_cast<int64_t>(report.kept)},
                               {"conflicts_decided", static_cast<int64_t>(rec.conflicts.size() - openConflicts)},
                               {"conflicts_open", static_cast<int64_t>(openConflicts)},
                               {"union_base", report.union_base}}},
                  fmt::format("[ManifestApply] Vault {}: applied the manifest root of epoch {} from node {} ({} change(s), "
                              "{} deferred, {} left to the planner, {} conflict(s))",
                              vaultId, report.epoch, report.producer, report.applied, report.deferred, report.kept,
                              rec.conflicts.size()));
    return report;
}

}
