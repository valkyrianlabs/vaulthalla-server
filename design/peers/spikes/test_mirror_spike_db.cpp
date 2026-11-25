// vh-test-tier: db-only
// Feasibility spike for design/peers/mirror.md ("The old core returns"), kept as evidence. It is NOT part of the build:
// it lives outside core/tests, and its second test fails by design (see README.md here). It ran on dev at 5aa0b231.
// Does the three-way merge (Manifest::collect + vl::vaultfmt::manifest::reconcile + the applier) work on a LOCAL vault
// whose trees come from databases rather than a bucket?
//   MirrorSpikeDb.ReconcileOverLocalVaultCollects  base/ours from collect() on a local vault, theirs a hand-edited copy
//   MirrorSpikeDb.ApplierOnALocalVault             the existing applier entry point, with a fake bucket as carrier only

#include "../helpers/bytes.hpp"
#include "../helpers/db_suite.hpp"
#include "../helpers/versioned_bucket.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Symlink.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/sync/ManifestApply.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "ops/Vaults.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/ManifestStore.hpp"
#include "sync/vault_manifest/Applier.hpp"
#include "sync/vault_manifest/Service.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"
#include <vl/vaultfmt/manifest/Objects.hpp>
#include <vl/vaultfmt/manifest/Publisher.hpp>
#include <vl/vaultfmt/manifest/Reader.hpp>
#include <vl/vaultfmt/manifest/Reconcile.hpp>

#include <fmt/format.h>

#include <iostream>
#include <set>
#include <unistd.h>

namespace vh::test_mirror_spike_db {

namespace mf = vl::vaultfmt::manifest;
using EnginePtr = std::shared_ptr<storage::Engine>;
using vh::test::bin::bytes;

namespace {

std::string tagOf() {
    static int n = 0;
    return std::to_string(::getpid()) + "_" + std::to_string(++n);
}

std::string o(const std::optional<std::string>& s) { return s ? *s : "-"; }
template <typename T> std::string on(const std::optional<T>& v) { return v ? std::to_string(*v) : "-"; }

std::string describe(const mf::Entry& e) {
    return fmt::format("{:<9} {:<16} uid={} parent={} gen={} obj={} kv={} size={} hash={} mime={} mtime={} target={} "
                       "trashed={} versions={}",
                       mf::to_string(e.kind), e.name.empty() ? "<root>" : e.name, e.uid.substr(0, 8),
                       e.parent ? e.parent->substr(0, 8) : "-", o(e.generation), e.object ? "yes" : "-", on(e.key_version),
                       on(e.size), e.content_hash ? e.content_hash->substr(0, 12) : "-", o(e.mime), o(e.mtime), o(e.target),
                       e.trashed ? "yes" : "no", e.versions.size());
}

void dump(const std::string& label, const mf::Content& c) {
    std::cout << "[spike] ---- " << label << " (" << c.entries.size() << " entries, " << c.keys.size() << " keys, "
              << c.snapshots.size() << " snapshots)\n";
    for (const auto& e : c.entries) std::cout << "[spike]   " << describe(e) << "\n";
}

const mf::Entry* byName(const mf::Content& c, const std::string& name) {
    for (const auto& e : c.entries)
        if (e.name == name && e.kind != mf::EntryKind::Tombstone) return &e;
    return nullptr;
}

mf::Entry& at(mf::Content& c, const std::string& name) {
    for (auto& e : c.entries)
        if (e.name == name && e.kind != mf::EntryKind::Tombstone) return e;
    throw std::out_of_range("no entry " + name);
}

std::string rootUid(const mf::Content& c) {
    for (const auto& e : c.entries)
        if (e.kind == mf::EntryKind::Dir && !e.parent) return e.uid;
    throw std::out_of_range("no root");
}

std::string nameOf(const mf::Content& c, const std::string& uid) {
    for (const auto& e : c.entries)
        if (e.uid == uid) return e.name;
    return uid.substr(0, 8);
}

std::map<std::string, std::string> tree(const mf::Content& c) {
    std::map<std::string, std::string> out;
    for (const auto& e : c.entries) {
        if (e.kind == mf::EntryKind::Tombstone) continue;
        out[e.uid] = std::string(mf::to_string(e.kind)) + "|" + e.parent.value_or("-") + "|" + e.name + "|" +
                     std::to_string(e.size.value_or(0)) + "|" + e.content_hash.value_or("") + "|" +
                     e.target.value_or("") + "|" + (e.trashed ? "trashed" : "live");
    }
    return out;
}

}

class MirrorSpikeDb : public vh::test::db::Suite {
protected:
    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_mirror_spike_db")) return;
        if (!runtime::Deps::get().fsCache) runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
    }
    static void TearDownTestSuite() { tearDownDbSuite(); }

    EnginePtr engine;

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        const auto v = ops::vaults::create(superUser, {.name = "spike_" + tagOf(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(v->id);
        ASSERT_TRUE(engine);
    }

    [[nodiscard]] uint32_t id() const { return engine->vault->id; }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = bytes(content), .engine = engine, .user = superUser,
                                                .overwrite = true}));
    }
    void mkdir(const std::string& path) const { engine->mkdir(path, superUser); }
    void mv(const std::string& from, const std::string& to) const {
        ASSERT_EQ(fs::Filesystem::rename(engine->vaultPathToFusePath(from), engine->vaultPathToFusePath(to), superUser,
                                         engine),
                  0)
            << from << " -> " << to;
    }
    void rm(const std::string& path) const { fs::Filesystem::remove(engine->vaultPathToFusePath(path), superUser->id); }
    void symlink(const std::string& path, const std::string& target) const {
        const auto& cache = runtime::Deps::get().fsCache;
        const auto fusePath = engine->vaultPathToFusePath(path);
        const auto parent = cache->getEntry(engine->vaultPathToFusePath(std::filesystem::path(path).parent_path()));
        ASSERT_TRUE(parent);
        auto link = std::make_shared<fs::model::Symlink>();
        link->vault_id = engine->vault->id;
        link->parent_id = parent->id;
        link->name = fusePath.filename().string();
        link->path = path;
        link->fuse_path = fusePath;
        link->target = target;
        link->base32_alias = "link" + tagOf();
        link->backing_path = parent->backing_path / link->base32_alias;
        link->mode = 0777;
        link->created_by = link->last_modified_by = static_cast<int32_t>(superUser->id);
        link->inode = cache->getOrAssignInode(fusePath);
        link->size_bytes = target.size();
        std::filesystem::create_symlink(target, link->backing_path);
        link->id = db::query::fs::Symlink::upsertSymlink(link);
        cache->cacheEntry(link);
    }

    [[nodiscard]] std::string read(const std::string& path) const {
        const auto file = db::query::fs::File::getFileByPath(id(), path);
        if (!file) return "<no row>";
        try {
            const auto reader = engine->openPlaintextReader(file, {.integrity = storage::IntegrityPolicy::Strict});
            const auto b = storage::readAll(*reader, 1 << 20);
            return "\"" + std::string(b.begin(), b.end()) + "\"";
        } catch (const std::exception& e) {
            return std::string("<throws: ") + e.what() + ">";
        }
    }

    void row(const std::string& path) const {
        const auto file = db::query::fs::File::getFileByPath(id(), path);
        if (!file) {
            std::cout << "[spike]   " << path << ": no live files row\n";
            return;
        }
        std::error_code ec;
        std::cout << "[spike]   " << path << ": size=" << file->size_bytes << " iv=" << (file->encryption_iv.empty() ? "EMPTY" : "set")
                  << " kv=" << file->encrypted_with_key_version
                  << " backing=" << (std::filesystem::exists(file->backing_path, ec) ? "present" : "MISSING")
                  << " read=" << read(path) << "\n";
    }

    // /Docs (report.txt, notes.txt, latest -> report.txt), /Photos (a.jpg, b.jpg, c.jpg), /A, /B, /top.txt
    void seedTree() const {
        mkdir("/Docs");
        mkdir("/Photos");
        mkdir("/A");
        mkdir("/B");
        write("/Docs/report.txt", "report v1");
        write("/Docs/notes.txt", "notes");
        write("/Photos/a.jpg", "a");
        write("/Photos/b.jpg", "b");
        write("/Photos/c.jpg", "c");
        write("/top.txt", "top");
        symlink("/Docs/latest", "report.txt");
    }

    // The old core, after the forced promotion (changes the new core never saw).
    void mutateOurs() const {
        mv("/top.txt", "/top2.txt");                 // rename
        mv("/Docs/notes.txt", "/Photos/notes.txt");  // move
        rm("/Photos/b.jpg");                         // delete (trash)
        write("/new.txt", "ours new");               // new file
        write("/Docs/report.txt", "report v2 ours"); // edit
        mv("/A", "/B/A");                            // A under B (theirs puts B under A: a cycle)
    }

    // The new core's changes since the shared base, as its database would collect them.
    [[nodiscard]] static mf::Content theirsFrom(const mf::Content& base) {
        auto t = base;
        auto& a = at(t, "a.jpg");             // edit
        a.size = 11;
        a.content_hash = "theirs-a-hash";
        a.mtime = "2026-11-20T00:00:00Z";
        auto& b = at(t, "b.jpg");             // edit (ours deleted it: edit beats trash)
        b.size = 12;
        b.content_hash = "theirs-b-hash";
        const auto cUid = at(t, "c.jpg").uid;   // delete
        const auto reportUid = at(t, "report.txt").uid;   // delete (ours edited it: edit beats delete)
        std::erase_if(t.entries, [&](const mf::Entry& e) { return e.uid == cUid || e.uid == reportUid; });
        mf::Entry fresh = at(t, "top.txt");     // a new file at the root named like ours' new one: a name clash
        fresh.uid = mf::uidText(crypto::id::newObjectUid());
        fresh.name = "new.txt";
        fresh.size = 10;
        fresh.content_hash = "theirs-new-hash";
        t.entries.push_back(fresh);
        mf::Entry only = fresh;                 // a new file only they have
        only.uid = mf::uidText(crypto::id::newObjectUid());
        only.parent = at(t, "Docs").uid;
        only.name = "theirs-only.txt";
        t.entries.push_back(only);
        at(t, "B").parent = at(t, "A").uid;     // B under A
        at(t, "latest").target = "notes.txt";   // a symlink retargeted (attributes)
        mf::normalize(t);
        return t;
    }

    static void dumpPlan(const mf::Reconciliation& rec, const mf::Content& names) {
        std::cout << "[spike] ---- plan (" << rec.plan.size() << " ops)\n";
        for (const auto& op : rec.plan)
            std::cout << "[spike]   " << mf::to_string(op.kind) << " " << (op.uid.empty() ? "" : nameOf(names, op.uid))
                      << (op.target && op.ours && op.target->name != op.ours->name ? " -> " + op.target->name : "") << "\n";
        std::cout << "[spike] ---- conflicts (" << rec.conflicts.size() << ")\n";
        for (const auto& c : rec.conflicts)
            std::cout << "[spike]   " << mf::to_string(c.kind) << " " << nameOf(names, c.uid) << (c.open ? " OPEN" : "")
                      << ": " << c.detail << "\n";
    }
};

TEST_F(MirrorSpikeDb, ReconcileOverLocalVaultCollects) {
    seedTree();
    const auto base = db::query::sync::Manifest::collect(id());
    dump("base (local vault collect)", base);
    ASSERT_TRUE(engine->vault->uid) << "vault.uid";
    for (const auto& e : base.entries) EXPECT_EQ(e.uid.size(), 26u) << describe(e);   // base32 of 16 bytes
    EXPECT_EQ(tree(db::query::sync::Manifest::collect(id())), tree(base)) << "collect is stable (uids assigned once)";

    mutateOurs();
    const auto ours = db::query::sync::Manifest::collect(id());
    dump("ours (after local changes)", ours);
    const auto theirs = theirsFrom(base);
    dump("theirs (hand-edited base)", theirs);

    mf::Content names = ours;
    for (const auto& e : theirs.entries) names.entries.push_back(e);
    const auto rec = mf::reconcile(base, theirs, ours);
    ASSERT_FALSE(rec.stopped());
    dumpPlan(rec, names);
    dump("result", rec.result);

    std::multiset<std::string> kinds;
    for (const auto& op : rec.plan) kinds.insert(std::string(mf::to_string(op.kind)));
    for (const auto* k : {"restore", "replace_content", "delete", "create", "set_attributes"})
        EXPECT_TRUE(kinds.contains(k)) << k;
    std::set<std::string> conflicts;
    for (const auto& c : rec.conflicts) conflicts.insert(std::string(mf::to_string(c.kind)));
    for (const auto* k : {"edit_beats_delete", "edit_beats_trash", "name_clash", "cycle_not_applied"})
        EXPECT_TRUE(conflicts.contains(k)) << k;
    for (const auto& op : rec.plan)
        if (op.kind != mf::OpKind::SetVault && op.kind != mf::OpKind::AddEnvelopes) EXPECT_FALSE(op.uid.empty());
    EXPECT_TRUE(mf::treeProblems(rec.result).empty());
    for (const auto& p : mf::treeProblems(rec.result)) ADD_FAILURE() << p;
    EXPECT_EQ(tree(mf::applyPlan(ours, rec.plan)), tree(rec.result)) << "the model applier reaches the result";
    EXPECT_TRUE(mf::reconcile(base, theirs, rec.result).plan.empty()) << "idempotent";
    EXPECT_TRUE(byName(rec.result, "report.txt")) << "ours' edit beat their delete";
    ASSERT_TRUE(byName(rec.result, "b.jpg"));
    EXPECT_FALSE(byName(rec.result, "b.jpg")->trashed) << "their edit beat our trash";
    EXPECT_FALSE(byName(rec.result, "c.jpg"));
}

TEST_F(MirrorSpikeDb, ApplierOnALocalVault) {
    seedTree();
    auto bucket = std::make_shared<test_support::versioned::VersionedBucket>(test_support::versioned::Versioning::Enabled);
    auto store = std::make_shared<storage::s3::ManifestStore>(bucket);
    ASSERT_TRUE(engine->vault->uid);
    sync::vault_manifest::Service service(id(), *engine->vault->uid, store, engine->encryptionManager);
    try {
        (void)service.publish();
        std::cout << "[spike] publish of the local vault's collect as the base: ok\n";
    } catch (const std::exception& e) {
        FAIL() << "publishing the base: " << e.what();
    }
    const auto base = mf::load(*store, *engine->vault->uid, service.keyLookup()).content;

    mutateOurs();
    auto theirs = theirsFrom(base);
    theirs.producer.node_id = "the-new-core";
    {
        const auto state = db::query::sync::Manifest::state(id());
        ASSERT_TRUE(state.epoch);
        const auto k = engine->encryptionManager->currentKey();
        mf::PublisherCache cache;
        mf::PublishOptions po;
        po.now = mf::isoTime(std::time(nullptr));
        (void)mf::publish(*store, *engine->vault->uid, service.keyLookup(), {k.version, k.key}, theirs,
                          mf::Known{*state.epoch, *state.root_sha256, state.root_version_id}, cache, po);
    }

    sync::vault_manifest::ApplyOptions options;
    options.isOpen = [](uint64_t) { return false; };
    std::vector<std::string> ops;
    options.beforeOp = [&](const mf::Op& op) {
        ops.push_back(std::string(mf::to_string(op.kind)) + " " +
                      (op.target ? op.target->name : (op.ours ? op.ours->name : op.uid.substr(0, 8))));
    };
    try {
        const auto r = service.applyRemote(options);
        ASSERT_TRUE(r);
        std::cout << "[spike] apply: recorded=" << r->recorded << " union_base=" << r->union_base
                  << " applied=" << r->applied << " skipped=" << r->skipped << " deferred=" << r->deferred
                  << " kept=" << r->kept << " conflicts=" << r->conflicts.size() << "\n";
        for (const auto& n : r->notes) std::cout << "[spike]   note: " << n << "\n";
        for (const auto& c : r->conflicts)
            std::cout << "[spike]   conflict: " << mf::to_string(c.kind) << (c.open ? " OPEN" : "") << " " << c.detail << "\n";
    } catch (const std::exception& e) {
        std::cout << "[spike] apply threw: " << e.what() << "\n";
        ADD_FAILURE() << e.what();
    }
    for (const auto& op : ops) std::cout << "[spike]   op: " << op << "\n";

    std::cout << "[spike] ---- rows after the apply\n";
    for (const auto* p : {"/Photos/a.jpg", "/Photos/b.jpg", "/Photos/c.jpg", "/Docs/report.txt", "/new.txt",
                          "/Docs/theirs-only.txt", "/top2.txt", "/Photos/notes.txt"})
        row(p);
    for (const auto& e : db::query::sync::Manifest::collect(id()).entries)
        if (e.name.starts_with("new.txt (")) row("/" + e.name);
    const auto after = db::query::sync::Manifest::collect(id());
    dump("collect after the apply", after);
    std::cout << "[spike] trashed rows: "
              << db::Transactions::exec("t", [&](pqxx::work& txn) {
                     return txn.exec("SELECT count(*) FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL",
                                     pqxx::params{id()}).one_field_ref().as<int64_t>();
                 })
              << "\n";
    // Expected by the merge result: c.jpg gone, b.jpg live with their content, a.jpg their content.
    EXPECT_FALSE(db::query::fs::File::getFileByPath(id(), "/Photos/c.jpg")) << "their delete of c.jpg";
    const auto a = db::query::fs::File::getFileByPath(id(), "/Photos/a.jpg");
    ASSERT_TRUE(a);
    EXPECT_EQ(a->size_bytes, 11u) << "their edit of a.jpg";
}

}
