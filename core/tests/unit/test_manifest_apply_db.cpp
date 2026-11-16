// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The manifest applier (design/sync/manifest-applier.md, work items 4 and 5; sync/vault_manifest/Applier.hpp) on a real
// opaque_v1 cloud vault over the versioned fake bucket. "Another writer" is a publish of a changed copy of the head onto
// the same bucket under another node id (what a second server would publish), applied here by the vault's own pass or
// its manifest service:
//   ManifestApplyDb  every kind of change taken in (rows, index, journal, cache); the same head twice writes nothing and
//                    a solo pass costs one HEAD; a local write since the collect skips the record and the next apply
//                    converges; a crash between operations leaves applying_* set (nothing published) and re-applies;
//                    an open file is deferred, then applied or handed to the planner; real collector output with the
//                    real trash form; a lost publish round applies and republishes; no base copy merges as a union;
//                    share links follow a moved folder and go with a deleted one.

#include "../helpers/bytes.hpp"
#include "../helpers/db_suite.hpp"
#include "../helpers/versioned_bucket.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "fs/model/File.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/sync/ManifestApply.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include <vl/vaultfmt/vhf1/Format.hpp>
#include <vl/vaultfmt/vhf1/Writer.hpp>
#include <vl/vaultfmt/vhf1/Reader.hpp>
#include "vault/KeyCheck.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "storage/s3/ManifestStore.hpp"
#include <vl/vaultfmt/manifest/Objects.hpp>
#include <vl/vaultfmt/manifest/Publisher.hpp>
#include <vl/vaultfmt/manifest/Reader.hpp>
#include <vl/vaultfmt/manifest/Reconcile.hpp>
#include "sync/vault_manifest/Service.hpp"
#include "vault/EncryptionManager.hpp"
#include "ops/Error.hpp"
#include "ops/RecoveryRecipients.hpp"
#include "ops/VaultLayout.hpp"
#include "ops/Vaults.hpp"
#include "sync/vault_manifest/Replicas.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/seed.hpp>

#include <fmt/format.h>

#include <atomic>
#include <functional>
#include <chrono>
#include <set>
#include <thread>

namespace vh::test_manifest_apply_db {

namespace mf = vl::vaultfmt::manifest;
using test_support::versioned::Versioning;
using test_support::versioned::VersionedBucket;
using vh::test::bin::bytes;

namespace {

int64_t count(const std::string& sql, const uint32_t vaultId) {
    return db::Transactions::exec("count", [&](pqxx::work& txn) {
        return txn.exec(sql, pqxx::params{vaultId}).one_field_ref().as<int64_t>();
    });
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

std::string freshGeneration() {
    static const char* hex = "0123456789abcdef";
    std::string g;
    const auto raw = crypto::id::newObjectUid();
    for (int round = 0; round < 2; ++round)
        for (const auto b : raw) {
            g += hex[(b >> 4) ^ round];
            g += hex[b & 0x0f];
        }
    return g;   // 64 hex: a VHF1 salt
}

// What both servers must agree on, per uid: kind, placement, content, attributes and state.
std::map<std::string, std::string> tree(const mf::Content& c) {
    std::map<std::string, std::string> out;
    for (const auto& e : c.entries) {
        if (e.kind == mf::EntryKind::Tombstone) continue;
        if (e.trashed) {   // the trash form carries placement and size only
            out[e.uid] = "trashed|" + e.parent.value_or("-") + "|" + e.name + "|" + std::to_string(e.size.value_or(0));
            continue;
        }
        out[e.uid] = std::string(mf::to_string(e.kind)) + "|" + e.parent.value_or("-") + "|" + e.name + "|" +
                     e.generation.value_or("") + "|" + std::to_string(e.size.value_or(0)) + "|" +
                     std::to_string(e.mode.value_or(0)) + "|" + e.target.value_or("") + "|" +
                     (e.trashed ? "trashed" : "live");
    }
    return out;
}

}

class ManifestApplyDb : public vh::test::db::Suite {
protected:
    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_manifest_apply_db")) return;
        if (!runtime::Deps::get().fsCache) runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
    }
    static void TearDownTestSuite() { tearDownDbSuite(); }

    test_support::versioned::CloudVault v;
    std::shared_ptr<storage::s3::ManifestStore> store;
    std::unique_ptr<sync::vault_manifest::Service> service;

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        fresh();
    }

    // A new vault (and bucket) for this test, or for the next case of it.
    void fresh() {
        v = test_support::versioned::makeCloudVault(superUser, "ma", Versioning::Enabled, true,
                                                    sync::model::RemotePolicy::Strategy::Cache);
        store = std::make_shared<storage::s3::ManifestStore>(v.bucket);
        restart();
    }
    // A daemon restart: the manifest service's memory (its publisher cache) is gone, the database stays.
    void restart() {
        service = std::make_unique<sync::vault_manifest::Service>(v.id(), *v.engine->vault->uid, store,
                                                                   v.engine->encryptionManager);
    }

    [[nodiscard]] uint32_t id() const { return v.id(); }
    [[nodiscard]] const mf::Uid& uid() const { return *v.engine->vault->uid; }

    void write(const std::string& path, const std::string& content) const {
        (void)fs::Filesystem::createFile({.path = path, .fuse_path = v.engine->vaultPathToFusePath(path),
                                          .buffer = bytes(content), .engine = v.engine, .user = superUser,
                                          .overwrite = true});
    }
    void mkdir(const std::string& path) const { v.engine->mkdir(path, superUser); }
    void pass() const {
        (void)test_support::versioned::runSyncPass(v.engine, {.purgeTrash = false, .downloads = false, .expectOk = true});
    }

    // The bucket's head as this server's keys read it.
    [[nodiscard]] mf::Loaded head() const { return mf::load(*store, uid(), service->keyLookup()); }

    // Another server publishes `c` on the recorded root (its own cache, its own node id).
    // `shared`: the other writer is one of the root's writers (a replicated vault, see share()): it names itself and
    // keeps the base's writers. `on`: the root it builds on (default: the recorded one).
    mf::PublishReport publishAs(mf::Content c, const std::string& node = "another-node", const bool shared = false,
                                const std::optional<mf::Known>& on = std::nullopt) const {
        const auto state = db::query::sync::Manifest::state(id());
        c.producer.node_id = node;
        const auto k = v.engine->encryptionManager->currentKey();
        mf::PublisherCache cache;
        mf::PublishOptions o;
        o.now = mf::isoTime(std::time(nullptr));
        if (shared) o.self_node = node;
        return mf::publish(*store, uid(), service->keyLookup(), {k.version, k.key}, c,
                           on ? *on : mf::Known{*state.epoch, *state.root_sha256, state.root_version_id}, cache, o);
    }

    // A key holder names another writer beside this server (the join, done by hand): a root naming both, applied.
    void share() {
        const auto h = head();
        auto named = h.root;
        named.epoch = h.acceptance.epoch + 1;
        named.prev = h.acceptance.root_sha256;
        named.producer.node_id = "another-node";
        named.writers = std::vector<std::string>{db::query::device::Devices::nodeId(), "another-node"};
        const auto k = v.engine->encryptionManager->currentKey();
        (void)v.bucket->seed(std::string(mf::kRootKey), mf::sealRoot(named, uid(), {k.version, k.key}));
        const auto r = service->applyRemote();
        ASSERT_TRUE(r && r->recorded);
        ASSERT_EQ(db::query::sync::Manifest::state(id()).writers.size(), 2u);
    }

    // A vault the other writer and this one both hold: /Docs (report.pdf, notes.txt), /Photos (a.jpg, b.jpg, c.jpg),
    // /top.txt, uploaded and published (epoch 1 or later).
    void seed() {
        mkdir("/Docs");
        mkdir("/Photos");
        write("/Docs/report.pdf", "report v1");
        write("/Docs/notes.txt", "notes");
        write("/Photos/a.jpg", "a");
        write("/Photos/b.jpg", "b");
        write("/Photos/c.jpg", "c");
        write("/top.txt", "top");
        pass();
        ASSERT_TRUE(db::query::sync::Manifest::state(id()).epoch);
    }

    [[nodiscard]] int64_t journal() const {
        return count("SELECT COALESCE(max(id), 0) FROM fs_change_log WHERE vault_id = $1", id());
    }
};

// Every step's rows: directories, files and a symlink created (remote-only, bound to o/<uid>), a rename and a move,
// a content replacement (the cached bytes go), attributes, a trash, a delete, provider versions, a snapshot record;
// the journal says each, the cache resolves the new paths, and the head is recorded with its base copy.
TEST_F(ManifestApplyDb, EveryKindOfChangeIsTakenInJournaledAndCached) {
    seed();
    auto theirs = head().content;
    const auto root = rootUid(theirs);
    mf::Entry dir;
    dir.uid = mf::uidText(crypto::id::newObjectUid());
    dir.kind = mf::EntryKind::Dir;
    dir.parent = root;
    dir.name = "New";
    dir.mode = 0755;
    mf::Entry file = at(theirs, "report.pdf");   // the shape of a real file entry, with a fresh identity
    file.uid = mf::uidText(crypto::id::newObjectUid());
    file.parent = dir.uid;
    file.name = "remote.bin";
    file.generation = freshGeneration();
    file.object = mf::ObjectRef{"\"e-remote\"", 300, std::nullopt, std::nullopt};
    file.size = 164;
    file.versions.clear();
    mf::Entry link;
    link.uid = mf::uidText(crypto::id::newObjectUid());
    link.kind = mf::EntryKind::Symlink;
    link.parent = dir.uid;
    link.name = "latest";
    link.target = "remote.bin";
    link.mode = 0777;
    theirs.entries.push_back(dir);
    theirs.entries.push_back(file);
    theirs.entries.push_back(link);
    at(theirs, "top.txt").name = "renamed.txt";
    at(theirs, "notes.txt").parent = dir.uid;
    auto& report = at(theirs, "report.pdf");
    const auto reportUid = report.uid;   // `report` dangles once entries are erased below
    report.generation = freshGeneration();
    report.object = mf::ObjectRef{"\"e-report-2\"", 310, std::nullopt, std::nullopt};
    report.size = 174;
    report.versions.push_back(mf::FileVersion{"v-older", std::nullopt, 1, 140, "\"e-old\"", "2026-11-01T00:00:00Z",
                                              "2026-11-02T00:00:00Z", false, std::nullopt});
    at(theirs, "a.jpg").mode = 0600;
    at(theirs, "b.jpg").trashed = mf::Trashed{"2026-11-15T00:00:00Z", "admin", "/Photos/b.jpg"};
    const auto cUid = at(theirs, "c.jpg").uid;
    std::erase_if(theirs.entries, [&](const mf::Entry& e) { return e.uid == cUid; });
    theirs.snapshots.push_back(mf::SnapshotRecord{mf::uidText(crypto::id::newObjectUid()), std::nullopt, "theirs",
                                                  "2026-11-15T00:00:00Z", "/Docs",
                                                  {mf::SnapshotMember{reportUid, "/Docs/report.pdf", std::nullopt, 1,
                                                                      std::nullopt, false}}});
    mf::normalize(theirs);
    const auto reportBacking = db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")->backing_path;
    const auto published = publishAs(theirs);
    const auto since = journal();

    const auto r = service->applyRemote();
    ASSERT_TRUE(r);
    EXPECT_TRUE(r->recorded);
    EXPECT_FALSE(r->union_base);
    EXPECT_EQ(r->skipped, 0u);
    for (const auto& n : r->notes) ADD_FAILURE() << n;
    const auto state = db::query::sync::Manifest::state(id());
    EXPECT_EQ(state.epoch, published.published.known.epoch);
    EXPECT_FALSE(state.applying_epoch);
    ASSERT_TRUE(db::query::sync::Manifest::base(id())) << "the head's base copy, in the record's transaction";

    // The database says what the head says.
    const auto after = db::query::sync::Manifest::collect(id());
    auto expected = tree(head().content);
    auto got = tree(after);
    EXPECT_EQ(got, expected);
    EXPECT_TRUE(mf::treeProblems(after).empty());

    // Rows: the index binds the new and replaced objects; c.jpg's row is gone; the snapshot record has its uid.
    EXPECT_EQ(count("SELECT count(*) FROM remote_object_index WHERE vault_id = $1 AND object_key = 'o/" + file.uid +
                        "' AND source = 'manifest'", id()), 1);
    EXPECT_EQ(count("SELECT count(*) FROM remote_object_index WHERE vault_id = $1 AND object_key = 'o/" + cUid + "'", id()), 0);
    EXPECT_EQ(count("SELECT count(*) FROM recovery_snapshot WHERE vault_id = $1 AND name = 'theirs' AND uid IS NOT NULL",
                    id()), 1);
    EXPECT_EQ(count("SELECT count(*) FROM upstream_object_version WHERE vault_id = $1 AND version_id = 'v-older'", id()), 1);
    EXPECT_FALSE(std::filesystem::exists(reportBacking)) << "the replaced generation's cached bytes are gone";
    EXPECT_EQ(db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")->size_bytes, 174u);

    // The journal says every kind, in the writer's transactions.
    std::set<std::string> kinds;
    db::Transactions::exec("kinds", [&](pqxx::work& txn) {
        for (const auto row : txn.exec("SELECT DISTINCT kind FROM fs_change_log WHERE vault_id = $1 AND id > $2",
                                       pqxx::params{id(), since}))
            kinds.insert(row[0].as<std::string>());
    });
    for (const auto* k : {"create", "update", "rename", "move", "delete"}) EXPECT_TRUE(kinds.contains(k)) << k;

    // The cache resolves what was created and moved; FUSE sees it at the next lookup.
    const auto& cache = runtime::Deps::get().fsCache;
    EXPECT_TRUE(cache->getEntry(v.engine->vaultPathToFusePath("/New/remote.bin")));
    EXPECT_TRUE(cache->getEntry(v.engine->vaultPathToFusePath("/New/notes.txt")));
    EXPECT_TRUE(cache->getEntry(v.engine->vaultPathToFusePath("/renamed.txt")));
    EXPECT_FALSE(cache->getEntry(v.engine->vaultPathToFusePath("/top.txt")));

    // The next publish builds on the applied head and reverts nothing.
    write("/local-after.txt", "mine");
    pass();
    const auto next = head();
    EXPECT_EQ(next.acceptance.epoch, published.published.known.epoch + 1);
    auto later = tree(next.content);
    for (const auto& [u, line] : expected) EXPECT_EQ(later[u], line) << u;
}

// The same head again: one HEAD, nothing written. And the plain solo case: a pass that changed nothing costs exactly
// one HEAD and no other request (spec 06 §5.7), with the applier in place.
TEST_F(ManifestApplyDb, TheSameHeadTwiceWritesNothingAndASoloPassCostsOneHead) {
    seed();
    auto theirs = head().content;
    at(theirs, "top.txt").name = "renamed.txt";
    (void)publishAs(theirs);
    ASSERT_TRUE(service->applyRemote());
    const auto since = journal();
    v.bucket->resetCounters();
    EXPECT_FALSE(service->applyRemote()) << "recorded: nothing to apply";
    EXPECT_EQ(journal(), since);
    const auto c = v.bucket->counters();
    EXPECT_EQ(c.head, 1u);
    EXPECT_EQ(c.get + c.list + c.put + c.del + c.copy, 0u);

    // Through the vault's own pass (its own service): one HEAD.
    pass();   // the pass's service records nothing new; it publishes only if the database moved (it did not)
    v.bucket->resetCounters();
    pass();
    const auto p = v.bucket->counters();
    EXPECT_EQ(p.head, 1u) << "a solo pass that changed nothing: one HEAD of the root";
    EXPECT_EQ(p.get + p.put + p.del + p.copy, 0u);
}

// A row a local write changed between collect and its operation is skipped: the head is not recorded, applying_*
// stays (nothing is published from the partial state), and the next apply, from a fresh collect, converges.
TEST_F(ManifestApplyDb, ALocalWriteSinceTheCollectSkipsTheRecordAndTheNextApplyConverges) {
    seed();
    auto theirs = head().content;
    at(theirs, "top.txt").name = "renamed.txt";
    at(theirs, "a.jpg").mode = 0600;
    const auto published = publishAs(theirs);
    bool once = false;
    sync::vault_manifest::ApplyOptions o;
    o.beforeOp = [&](const mf::Op& op) {
        if (op.kind == mf::OpKind::Move && !once) {
            once = true;
            ASSERT_EQ(fs::Filesystem::rename(v.engine->vaultPathToFusePath("/top.txt"),
                                             v.engine->vaultPathToFusePath("/local.txt"), superUser), 0);
        }
    };
    const auto first = service->applyRemote(o);
    ASSERT_TRUE(first);
    EXPECT_FALSE(first->recorded);
    EXPECT_GE(first->skipped, 1u);
    const auto state = db::query::sync::Manifest::state(id());
    EXPECT_EQ(state.applying_epoch, published.published.known.epoch);
    EXPECT_THROW((void)service->publish(), mf::ApplyIncomplete);

    const auto second = service->applyRemote();
    ASSERT_TRUE(second);
    EXPECT_TRUE(second->recorded);
    EXPECT_EQ(db::query::fs::File::getFileByPath(id(), "/renamed.txt") != nullptr, true)
        << "placement changed on both sides: the head's";
    EXPECT_FALSE(db::query::sync::Manifest::state(id()).applying_epoch);
    EXPECT_NO_THROW((void)service->publish());
}

// A crash between any two operations: committed ones stay, `known` is the old root, applying_* is set; each next apply
// starts from a fresh collect and the same base copy, and the last one records the head.
TEST_F(ManifestApplyDb, ACrashBetweenOperationsLeavesApplyingSetAndTheNextApplyConverges) {
    seed();
    auto theirs = head().content;
    const auto root = rootUid(theirs);
    at(theirs, "top.txt").name = "renamed.txt";
    at(theirs, "notes.txt").parent = root;
    at(theirs, "a.jpg").mode = 0600;
    const auto cUid = at(theirs, "c.jpg").uid;
    std::erase_if(theirs.entries, [&](const mf::Entry& e) { return e.uid == cUid; });
    for (int i = 0; i < 3; ++i) {
        mf::Entry d;
        d.uid = mf::uidText(crypto::id::newObjectUid());
        d.kind = mf::EntryKind::Dir;
        d.parent = root;
        d.name = "made-" + std::to_string(i);
        d.mode = 0755;
        theirs.entries.push_back(d);
    }
    mf::normalize(theirs);
    const auto published = publishAs(theirs);
    const auto known = db::query::sync::Manifest::state(id()).epoch;
    struct Crash : std::runtime_error {
        using std::runtime_error::runtime_error;
    };
    unsigned crashes = 0;
    std::vector<std::string> lastNotes;
    for (unsigned attempt = 0; attempt < 20; ++attempt) {
        unsigned seen = 0;
        sync::vault_manifest::ApplyOptions o;
        o.beforeOp = [&](const mf::Op& op) {
            lastNotes.push_back(std::string(mf::to_string(op.kind)) + " " + op.uid);
            if (++seen == 2) throw Crash("crash before the second operation of this attempt");
        };
        try {
            const auto r = service->applyRemote(o);
            ASSERT_TRUE(r);
            if (r->recorded) break;
            lastNotes.insert(lastNotes.end(), r->notes.begin(), r->notes.end());
        } catch (const Crash&) {
            ++crashes;
            const auto s = db::query::sync::Manifest::state(id());
            EXPECT_EQ(s.epoch, known) << "known stays the old root";
            EXPECT_EQ(s.applying_epoch, published.published.known.epoch);
            EXPECT_THROW((void)service->publish(), mf::ApplyIncomplete);
        }
    }
    EXPECT_GE(crashes, 5u) << "a crash after every operation but the last";
    if (db::query::sync::Manifest::state(id()).epoch != published.published.known.epoch)
        for (const auto& n : lastNotes) ADD_FAILURE() << n;
    EXPECT_EQ(db::query::sync::Manifest::state(id()).epoch, published.published.known.epoch);
    EXPECT_EQ(tree(db::query::sync::Manifest::collect(id())), tree(head().content));
}

// A content replacement and a delete of open files are deferred: the collector reports the incoming values (a publish
// never reverts them) and the head is recorded. Once closed: the unchanged file takes the new generation; the one whose
// close sealed new bytes keeps them (an edit beats the delete).
TEST_F(ManifestApplyDb, AnOpenFileIsDeferredUntilItClosesThenAppliedOrKeptForTheEdit) {
    seed();
    auto theirs = head().content;
    auto& report = at(theirs, "report.pdf");
    const auto reportUid = report.uid;   // `report` dangles once notes.txt is erased below
    const auto newGen = freshGeneration();
    report.generation = newGen;
    report.object = mf::ObjectRef{"\"e-report-2\"", 310, std::nullopt, std::nullopt};
    report.size = 174;
    const auto notesUid = at(theirs, "notes.txt").uid;
    std::erase_if(theirs.entries, [&](const mf::Entry& e) { return e.uid == notesUid; });
    (void)publishAs(theirs);

    std::set<uint64_t> open;
    for (const auto* p : {"/Docs/report.pdf", "/Docs/notes.txt"})
        open.insert(*db::query::fs::File::getFileByPath(id(), p)->inode);
    sync::vault_manifest::ApplyOptions o;
    o.isOpen = [&](const uint64_t ino) { return open.contains(ino); };
    const auto r = service->applyRemote(o);
    ASSERT_TRUE(r);
    EXPECT_TRUE(r->recorded);
    EXPECT_EQ(r->deferred, 2u);
    EXPECT_EQ(count("SELECT count(*) FROM manifest_apply_deferred WHERE vault_id = $1", id()), 2);
    const auto collected = db::query::sync::Manifest::collect(id());
    EXPECT_EQ(byName(collected, "report.pdf")->generation, newGen) << "the collector reports the incoming value";
    EXPECT_FALSE(byName(collected, "notes.txt")) << "and the incoming delete";
    (void)service->publish();
    EXPECT_EQ(byName(head().content, "report.pdf")->generation, newGen) << "no publish reverts it";

    // notes.txt's close sealed new bytes; report.pdf closed unchanged.
    db::Transactions::exec("seal", [&](pqxx::work& txn) {
        txn.exec("UPDATE files f SET encryption_iv = $2 FROM fs_entry e WHERE e.id = f.fs_entry_id AND e.vault_id = $1 "
                 "AND e.path = '/Docs/notes.txt'",
                 pqxx::params{id(), *db::query::sync::ManifestApply::b64OfHex(freshGeneration())});
    });
    open.clear();
    EXPECT_EQ(sync::vault_manifest::finishDeferred(id(), o), 2u);
    EXPECT_EQ(count("SELECT count(*) FROM manifest_apply_deferred WHERE vault_id = $1", id()), 0);
    const auto reportRow = db::query::sync::ManifestApply::row(id(), reportUid);
    ASSERT_TRUE(reportRow);
    EXPECT_EQ(reportRow->files_generation, newGen);
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/Docs/notes.txt")) << "the edit beats the delete";
}

// reconcile on real collector output, with the real trash form (no generation, key version or mode): ours trashed a
// file, theirs edited it. The file is restored to its incoming place with theirs' content, our trash row ends (its
// purge would delete the object the live file names), and reconcile of the same head on the result plans nothing.
TEST_F(ManifestApplyDb, RealCollectorOutputWithTheRealTrashFormRestoresAnEditedFile) {
    seed();
    const auto base = head().content;
    fs::Filesystem::remove(v.engine->vaultPathToFusePath("/Docs/notes.txt"), superUser->id);
    const auto ours = db::query::sync::Manifest::collect(id());
    const auto* trashed = byName(ours, "notes.txt");
    ASSERT_TRUE(trashed && trashed->trashed);
    EXPECT_FALSE(trashed->generation) << "the collector's trash form";
    auto theirs = base;
    auto& notes = at(theirs, "notes.txt");
    const auto newGen = freshGeneration();
    notes.generation = newGen;
    notes.object = mf::ObjectRef{"\"e-notes-2\"", 300, std::nullopt, std::nullopt};
    (void)publishAs(theirs);

    const auto planned = mf::reconcile(base, head().content, ours);
    EXPECT_EQ(std::ranges::count(planned.conflicts, mf::ConflictKind::EditBeatsTrash, &mf::Conflict::kind), 1);
    const auto r = service->applyRemote();
    ASSERT_TRUE(r);
    EXPECT_TRUE(r->recorded);
    const auto row = db::query::sync::ManifestApply::row(id(), notes.uid);
    ASSERT_TRUE(row);
    EXPECT_FALSE(row->trashed);
    EXPECT_EQ(row->files_generation, newGen);
    EXPECT_EQ(count("SELECT count(*) FROM files_trashed WHERE vault_id = $1 AND deleted_at IS NULL", id()), 0);
    const auto again = mf::reconcile(head().content, head().content, db::query::sync::Manifest::collect(id()));
    EXPECT_TRUE(again.plan.empty()) << (again.plan.empty() ? "" : std::string(mf::to_string(again.plan[0].kind)));
}

// Item 5: a publish that meets another writer's root applies it and publishes on it (no in-memory merge), and `known`
// advances only by that apply or the own publish: a read alone records nothing.
TEST_F(ManifestApplyDb, ALostRoundAppliesTheHeadAndPublishesOnIt) {
    seed();
    const auto epoch = *db::query::sync::Manifest::state(id()).epoch;
    auto theirs = head().content;
    at(theirs, "top.txt").name = "theirs.txt";
    (void)publishAs(theirs);
    ASSERT_TRUE(service->verifyRemote());
    EXPECT_EQ(db::query::sync::Manifest::state(id()).epoch, epoch) << "a read records nothing";

    write("/mine.txt", "a local change");
    const auto r = service->publish();   // meets the moved head (HeadMoved), applies it, publishes on it
    EXPECT_EQ(r.published.known.epoch, epoch + 2);
    const auto h = head();
    EXPECT_EQ(h.acceptance.epoch, epoch + 2);
    EXPECT_TRUE(byName(h.content, "theirs.txt"));
    EXPECT_TRUE(byName(h.content, "mine.txt"));
    EXPECT_FALSE(byName(h.content, "top.txt"));
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/theirs.txt"));
}

// Without a usable base copy (a state from before migration 145, an attach, a restore) the apply merges without a base:
// a union, which deletes nothing; additions and the head's renames still apply.
TEST_F(ManifestApplyDb, WithoutABaseCopyTheApplyIsAUnionThatDeletesNothing) {
    seed();
    db::Transactions::exec("pre-145", [&](pqxx::work& txn) {
        txn.exec("UPDATE remote_manifest_state SET base_root = NULL WHERE vault_id = $1", pqxx::params{id()});
        txn.exec("DELETE FROM remote_manifest_base WHERE vault_id = $1", pqxx::params{id()});
    });
    auto theirs = head().content;
    const auto cUid = at(theirs, "c.jpg").uid;
    std::erase_if(theirs.entries, [&](const mf::Entry& e) { return e.uid == cUid; });
    at(theirs, "top.txt").name = "renamed.txt";
    (void)publishAs(theirs);
    const auto r = service->applyRemote();
    ASSERT_TRUE(r);
    EXPECT_TRUE(r->union_base);
    EXPECT_TRUE(r->recorded);
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/Photos/c.jpg")) << "nothing is deleted without a base";
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/renamed.txt"));
    EXPECT_TRUE(db::query::sync::Manifest::base(id())) << "the record writes the copy";
}

// Moves keep identity (the fs_entry id): a share link follows a moved folder; a deleted folder takes its links along
// (ON DELETE CASCADE), as after a local delete.
TEST_F(ManifestApplyDb, ShareLinksFollowAMovedFolderAndGoWithADeletedOne) {
    seed();
    mkdir("/Old");
    pass();
    const auto docs = db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")->parent_id;
    const auto old = db::Transactions::exec("old", [&](pqxx::work& txn) {
        return txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = '/Old'", pqxx::params{id()})
            .one_field_ref().as<unsigned int>();
    });
    for (const unsigned int entry : {static_cast<unsigned int>(*docs), old})
        db::Transactions::exec("link", [&](pqxx::work& txn) {
            txn.exec("INSERT INTO share_link (token_lookup_id, token_hash, created_by, vault_id, root_entry_id, root_path, "
                     "  target_type, link_type, access_mode, allowed_ops) VALUES (gen_random_uuid(), '\\x00', $1, $2, $3, "
                     "  (SELECT path FROM fs_entry WHERE id = $3), 'directory', 'download', 'public', 1)",
                     pqxx::params{superUser->id, id(), entry});
        });
    auto theirs = head().content;
    at(theirs, "Docs").parent = at(theirs, "Photos").uid;
    const auto oldUid = at(theirs, "Old").uid;
    std::erase_if(theirs.entries, [&](const mf::Entry& e) { return e.uid == oldUid; });
    (void)publishAs(theirs);
    const auto r = service->applyRemote();
    ASSERT_TRUE(r && r->recorded);
    EXPECT_EQ(count("SELECT count(*) FROM share_link WHERE vault_id = $1 AND root_entry_id = " + std::to_string(*docs), id()), 1)
        << "the moved folder keeps its id and its link";
    EXPECT_EQ(count("SELECT count(*) FROM share_link WHERE vault_id = $1 AND root_entry_id = " + std::to_string(old), id()), 0);
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/Photos/Docs/report.pdf"));
}


// ── This server's own roots (review of items 4-5) ──────────────────────────────────────────────────────────────────

namespace {

// recordRoot fails for this vault (a transient database failure after the PUT): any update that moves the root.
void failRecords(const uint32_t vaultId, const bool on) {
    db::Transactions::exec("failRecords", [&](pqxx::work& txn) {
        txn.exec("CREATE OR REPLACE FUNCTION vh_test_fail_record() RETURNS trigger AS $$ BEGIN "
                 "RAISE EXCEPTION 'recordRoot fails (test)'; END $$ LANGUAGE plpgsql");
        txn.exec("DROP TRIGGER IF EXISTS vh_test_fail_record ON remote_manifest_state");
        if (on)
            txn.exec("CREATE TRIGGER vh_test_fail_record BEFORE UPDATE ON remote_manifest_state FOR EACH ROW WHEN "
                     "(NEW.root_sha256 IS DISTINCT FROM OLD.root_sha256 AND NEW.vault_id = " + std::to_string(vaultId) +
                     ") EXECUTE FUNCTION vh_test_fail_record()");
    });
}

}

// A root this server PUT and never recorded (recordRoot failed, or the daemon crashed between the two) is its own past
// state: the database is at it or past it. It is adopted (recorded as own, with its base copy) and nothing is
// reconciled: local changes made since (a rename, an edit, a delete, a create) are neither reverted, re-created nor
// reported as conflicts, and the next publish carries them. The same with no base copy.
TEST_F(ManifestApplyDb, AnOwnRootLeftUnrecordedIsAdoptedNotApplied) {
    for (const auto* variant : {"record failed", "crash", "crash, no base copy"}) {
        SCOPED_TRACE(variant);
        fresh();
        seed();
        write("/doomed.txt", "created before the unrecorded publish");
        const auto known = *db::query::sync::Manifest::state(id()).epoch;
        failRecords(id(), true);
        EXPECT_ANY_THROW((void)service->publish());
        failRecords(id(), false);
        const auto unrecorded = head();
        ASSERT_EQ(unrecorded.acceptance.epoch, known + 1) << "the root was PUT";
        ASSERT_EQ(db::query::sync::Manifest::state(id()).epoch, known) << "and not recorded";
        if (std::string(variant) != "record failed") restart();
        if (std::string(variant).ends_with("no base copy"))
            db::Transactions::exec("pre-145", [&](pqxx::work& txn) {
                txn.exec("UPDATE remote_manifest_state SET base_root = NULL WHERE vault_id = $1", pqxx::params{id()});
            });

        // Local changes since that publish.
        ASSERT_EQ(fs::Filesystem::rename(v.engine->vaultPathToFusePath("/top.txt"),
                                         v.engine->vaultPathToFusePath("/moved.txt"), superUser), 0);
        const auto beforeEdit = db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")->encryption_iv;
        write("/Docs/report.pdf", "edited since");
        const auto edited = db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")->encryption_iv;
        ASSERT_NE(edited, beforeEdit);
        fs::Filesystem::remove(v.engine->vaultPathToFusePath("/doomed.txt"), superUser->id);
        write("/created.txt", "new");

        const auto since = journal();
        v.bucket->resetCounters();
        EXPECT_FALSE(service->applyRemote()) << "adopted: nothing to apply";
        const auto c = v.bucket->counters();
        EXPECT_EQ(c.put + c.del + c.copy, 0u) << "the verify and the record only";
        EXPECT_EQ(journal(), since) << "no entry was written";
        const auto state = db::query::sync::Manifest::state(id());
        EXPECT_EQ(state.epoch, unrecorded.acceptance.epoch);
        EXPECT_EQ(state.own_epoch, unrecorded.acceptance.epoch) << "recorded as this server's own";
        EXPECT_FALSE(state.applying_epoch);
        EXPECT_TRUE(db::query::sync::Manifest::base(id())) << "with its base copy";

        EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/moved.txt"));
        EXPECT_FALSE(db::query::fs::File::getFileByPath(id(), "/top.txt"));
        EXPECT_EQ(db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")->encryption_iv, edited);
        EXPECT_FALSE(db::query::fs::File::getFileByPath(id(), "/doomed.txt")) << "not re-created";
        EXPECT_EQ(count("SELECT count(*) FROM sync_conflicts WHERE vault_id = $1", id()), 0);

        const auto next = service->publish();
        EXPECT_EQ(next.published.known.epoch, unrecorded.acceptance.epoch + 1);
        const auto h = head().content;
        EXPECT_TRUE(byName(h, "moved.txt"));
        EXPECT_FALSE(byName(h, "top.txt"));
        EXPECT_TRUE(byName(h, "created.txt"));
        ASSERT_TRUE(byName(h, "doomed.txt"));
        EXPECT_TRUE(byName(h, "doomed.txt")->trashed) << "the delete is carried (to the trash)";
    }
}

// Only the root this server last PUT is its own: one that merely names this node and vault as its producer (a
// cloned database publishing under this identity) is refused, and one from this node for another vault id (a restore
// beside the original on one server) is another writer's and is applied.
TEST_F(ManifestApplyDb, ARootThatOnlyNamesThisNodeIsNotTakenForItsOwn) {
    seed();
    auto clone = head().content;
    at(clone, "top.txt").name = "clone.txt";
    (void)publishAs(clone, db::query::device::Devices::nodeId());
    EXPECT_THROW((void)service->applyRemote(), sync::vault_manifest::ApplyStopped);
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/top.txt")) << "nothing applied";

    fresh();
    seed();
    auto beside = head().content;
    at(beside, "top.txt").name = "beside.txt";
    beside.producer.vault_id = id() + 100000;
    for (auto& key : beside.keys)   // its key checks are over its own vault id (vault/KeyCheck.hpp)
        if (const auto held = v.engine->encryptionManager->historicalKeySnapshot(key.version))
            key.key_check = vault::keyCheck(held->bytes(), id() + 100000, key.version);
    (void)publishAs(beside, db::query::device::Devices::nodeId());
    const auto r = service->applyRemote();
    ASSERT_TRUE(r);
    EXPECT_TRUE(r->recorded);
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/beside.txt"));
}

// Two applies of one vault never overlap: a publish that met HeadMoved on another thread waits for the pass's apply,
// then finds the head recorded and applies nothing. Without the service's apply mutex the second apply runs its own
// operations while the first is between two of them.
TEST_F(ManifestApplyDb, TwoAppliesOfOneVaultRunOneAfterTheOther) {
    seed();
    auto theirs = head().content;
    at(theirs, "top.txt").name = "renamed.txt";
    at(theirs, "a.jpg").mode = 0600;
    (void)publishAs(theirs);
    std::atomic<int> inside{0}, most{0};
    std::atomic<bool> secondStarted{false};
    sync::vault_manifest::ApplyOptions o;
    o.beforeOp = [&](const mf::Op&) {
        const int now = ++inside;
        most = std::max(most.load(), now);
        if (!secondStarted) {
            for (int i = 0; i < 50 && !secondStarted; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(10));
            std::this_thread::sleep_for(std::chrono::milliseconds(200));   // room for the second apply to start
        }
        --inside;
    };
    std::optional<sync::vault_manifest::ApplyReport> first, second;
    std::thread a([&] { first = service->applyRemote(o); });
    std::thread b([&] {
        for (int i = 0; i < 100 && inside == 0; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(5));
        secondStarted = true;
        second = service->applyRemote(o);
    });
    a.join();
    b.join();
    EXPECT_EQ(most.load(), 1) << "the applies overlapped";
    ASSERT_TRUE(first);
    EXPECT_TRUE(first->recorded);
    EXPECT_FALSE(second) << "the second found the head recorded";
}

// ── Lost replies: every root PUT since the record is this server's own (review of 188f2377) ─────────────────────────

namespace {

// The bucket's store, except that the next root PUT's reply is lost before it lands (its bytes kept: they reach the
// provider later), and that those bytes can be made to land just before the following root PUT.
class LateRootStore final : public mf::ObjectStore {
public:
    LateRootStore(std::shared_ptr<mf::ObjectStore> inner, std::shared_ptr<VersionedBucket> bucket)
        : inner_(std::move(inner)), bucket_(std::move(bucket)) {}

    bool loseNextRootReply{false};
    bool landBeforeNextRootPut{false};
    std::optional<std::vector<uint8_t>> late;

    std::optional<mf::StoredObject> get(const std::string& k, const std::optional<std::string>& v) override { return inner_->get(k, v); }
    std::optional<std::vector<uint8_t>> getRange(const std::string& k, uint64_t o, uint64_t n) override { return inner_->getRange(k, o, n); }
    std::optional<std::string> headEtag(const std::string& k) override { return inner_->headEtag(k); }
    std::string putIfAbsent(const std::string& k, const std::vector<uint8_t>& b) override {
        if (rootPut(k, b, false)) return {};
        return inner_->putIfAbsent(k, b);
    }
    std::string putIfMatch(const std::string& k, const std::vector<uint8_t>& b, const std::string& e) override {
        if (rootPut(k, b, false)) return {};
        return inner_->putIfMatch(k, b, e);
    }
    mf::PutResult put(const std::string& k, const std::vector<uint8_t>& b) override {
        if (rootPut(k, b, true)) return {};
        return inner_->put(k, b);
    }
    std::vector<mf::ListedObject> list(const std::string& p) override { return inner_->list(p); }
    std::vector<mf::StoredVersion> versions(const std::string& k) override { return inner_->versions(k); }
    std::vector<mf::StoredVersion> versionsSince(const std::string& k, const std::optional<std::string>& s) override {
        return inner_->versionsSince(k, s);
    }
    std::vector<mf::StoredVersion> versionsUnder(const std::string& p) override { return inner_->versionsUnder(p); }
    void remove(const std::string& k) override { inner_->remove(k); }
    void removeVersion(const std::string& k, const std::string& v) override { inner_->removeVersion(k, v); }
    [[nodiscard]] mf::WriteCapability mode() const override { return inner_->mode(); }

private:
    // true: the PUT was swallowed (its reply lost). Throws as the real store does for a lost reply.
    bool rootPut(const std::string& key, const std::vector<uint8_t>& bytes, const bool plain) {
        if (key != mf::kRootKey) return false;
        if (landBeforeNextRootPut && late) {
            landBeforeNextRootPut = false;
            (void)bucket_->seed(std::string(mf::kRootKey), *late);   // the earlier PUT reaches the provider now
        }
        if (!loseNextRootReply) return false;
        loseNextRootReply = false;
        late = bytes;
        if (plain) throw mf::PutOutcomeUnknown("the reply was lost (test)");
        throw std::runtime_error("the reply was lost (test)");
    }

    std::shared_ptr<mf::ObjectStore> inner_;
    std::shared_ptr<VersionedBucket> bucket_;
};

}

// Conditional PUTs: pass 1's root R1 loses its reply and lands after pass 2 verified; pass 2's root R2 is refused (412)
// because R1 is the head now. R1 is this server's own (it was noted before its PUT, as R2 was): adopted, and pass 2
// publishes on it. No stall, no apply, nothing local undone.
TEST_F(ManifestApplyDb, AnOwnRootThatLandsLateIsAdoptedOnConditionalPuts) {
    seed();
    const auto known = *db::query::sync::Manifest::state(id()).epoch;
    auto late = std::make_shared<LateRootStore>(store, v.bucket);
    service = std::make_unique<sync::vault_manifest::Service>(id(), uid(), late, v.engine->encryptionManager);
    write("/first.txt", "in R1");
    late->loseNextRootReply = true;
    EXPECT_ANY_THROW((void)service->publish());
    ASSERT_TRUE(late->late);
    EXPECT_EQ(head().acceptance.epoch, known) << "R1 has not landed yet";
    EXPECT_EQ(db::query::sync::Manifest::state(id()).publishing_roots.size(), 2u) << "the recorded root and R1";

    ASSERT_EQ(fs::Filesystem::rename(v.engine->vaultPathToFusePath("/top.txt"),
                                     v.engine->vaultPathToFusePath("/moved.txt"), superUser), 0);
    const auto since = journal();
    late->landBeforeNextRootPut = true;
    const auto r = service->publish();   // R2 412s on R1, R1 is adopted, the publish runs again on it
    EXPECT_EQ(journal(), since) << "nothing was applied";
    EXPECT_EQ(r.published.known.epoch, known + 2);
    const auto state = db::query::sync::Manifest::state(id());
    EXPECT_EQ(state.own_epoch, known + 2);
    EXPECT_EQ(state.publishing_roots, std::vector<std::string>{r.published.known.root_sha256}) << "reset by the record";
    const auto h = head().content;
    EXPECT_TRUE(byName(h, "first.txt"));
    EXPECT_TRUE(byName(h, "moved.txt"));
    EXPECT_FALSE(byName(h, "top.txt"));
    EXPECT_EQ(count("SELECT count(*) FROM sync_conflicts WHERE vault_id = $1", id()), 0);
}

// version_log: R1's outcome is unknown and the publish's own search doesn't find it (it hasn't landed); it lands just
// before R2. Both are own versions at one epoch: rule C1 takes the earlier (R1) as the head, R2 loses and is deleted
// (repaired), R1 is adopted, and the publish runs again on it.
TEST_F(ManifestApplyDb, TwoOwnVersionsAtOneEpochOnVersionLogTheHeadIsAdoptedTheOtherRepaired) {
    seed();
    const auto known = *db::query::sync::Manifest::state(id()).epoch;
    auto plain = std::make_shared<storage::s3::ManifestStore>(v.bucket, mf::WriteCapability::VersionLog);
    auto late = std::make_shared<LateRootStore>(plain, v.bucket);
    store = plain;
    service = std::make_unique<sync::vault_manifest::Service>(id(), uid(), late, v.engine->encryptionManager);
    write("/first.txt", "in R1");
    late->loseNextRootReply = true;
    EXPECT_ANY_THROW((void)service->publish());
    ASSERT_TRUE(late->late);

    ASSERT_EQ(fs::Filesystem::rename(v.engine->vaultPathToFusePath("/top.txt"),
                                     v.engine->vaultPathToFusePath("/moved.txt"), superUser), 0);
    const auto since = journal();
    late->landBeforeNextRootPut = true;
    const auto r = service->publish();
    EXPECT_EQ(journal(), since) << "nothing was applied";
    EXPECT_EQ(r.published.known.epoch, known + 2);
    unsigned atKnownPlusOne = 0;
    for (const auto& ver : v.bucket->history(std::string(mf::kRootKey)))
        if (!ver.delete_marker)
            try {
                if (mf::openRoot(ver.body, uid(), service->keyLookup()).epoch == known + 1) ++atKnownPlusOne;
            } catch (const std::exception&) {
            }
    EXPECT_EQ(atKnownPlusOne, 1u) << "the losing own version was deleted";
    const auto h = head().content;
    EXPECT_TRUE(byName(h, "first.txt"));
    EXPECT_TRUE(byName(h, "moved.txt"));
    EXPECT_FALSE(byName(h, "top.txt"));
}


// ── Replica prerequisites (design: "As built: replica prerequisites and status") ──────────────────────────────────────

namespace {

std::string hexOf(const std::span<const uint8_t> bytes) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string out;
    for (const auto b : bytes) {
        out += kHex[b >> 4];
        out += kHex[b & 0x0f];
    }
    return out;
}

// A KEV1 envelope another writer wrote (for a test, any 32 bytes stand in for the vault key: only the header is read).
struct Envelope {
    std::vector<uint8_t> bytes;
    std::string kid;
};
Envelope envelopeFor(const mf::Uid& vault, const uint32_t version, const std::vector<uint8_t>& recipientPublicKey) {
    const std::vector<uint8_t> key(32, 0x42);
    Envelope e;
    e.bytes = vl::keykit::kev1::wrap(key, vl::keykit::kev1::Suite::X25519, version, vault, recipientPublicKey);
    const auto digest = mf::sha256Hex(e.bytes);
    mf::Uid first{};
    for (std::size_t i = 0; i < first.size(); ++i) first[i] = static_cast<uint8_t>(std::stoi(digest.substr(2 * i, 2), nullptr, 16));
    e.kid = mf::uidText(first);
    return e;
}

std::vector<uint8_t> recipientKey() {
    return vl::keykit::RecoverySeed::parse(vl::keykit::RecoverySeed::generate().text()).x25519PublicKey();
}

std::string readAllOf(const std::shared_ptr<storage::Engine>& engine, const std::string& path) {
    const auto f = db::query::fs::File::getFileByPath(engine->vault->id, path);
    if (!f) throw std::runtime_error("no file " + path);
    const auto reader = engine->openPlaintextReader(f);
    const auto bytes = storage::readAll(*reader, 64 << 20);
    return {bytes.begin(), bytes.end()};
}

}

// A head naming two writers is applied now, and the other writer's envelope kids are carried: kept as references
// (never grant or envelope rows), named by this server's roots for a recipient one of its grants has (revoked or not, as
// it lists its own), at their key version. The root then names both writers' kids, sorted, and stays the same from one
// publish to the next. Negatives: a recipient this server holds no grant for, an envelope missing from the bucket, one
// of another vault or key version, and a kid that isn't its bytes' hash are not carried.
TEST_F(ManifestApplyDb, AnotherWritersEnvelopeKidsAreCarriedForTheGrantsThisServerHolds) {
    seed();
    share();
    const auto version = v.engine->encryptionManager->currentKey().version;
    const auto held = recipientKey(), notHeld = recipientKey();
    db::Transactions::exec("grant", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO vault_recovery_grant (vault_id, grant_id, recipient_id, public_key, suite, authorized_by) "
                 "VALUES ($1, $2, $3, $4::bytea, 1, 'test')",
                 pqxx::params{id(), mf::uidText(crypto::id::newObjectUid()), hexOf(vl::keykit::kev1::recipientId(held)),
                              "\\x" + hexOf(held)});
    });
    const auto grants = count("SELECT count(*) FROM vault_recovery_grant WHERE vault_id = $1", id());
    const auto envelopes = count("SELECT count(*) FROM vault_key_envelope WHERE vault_id = $1", id());

    const auto good = envelopeFor(uid(), version, held);
    const auto stranger = envelopeFor(uid(), version, notHeld);
    const auto missing = envelopeFor(uid(), version, held);
    const auto otherVault = envelopeFor(mf::parseUid(mf::uidText(crypto::id::newObjectUid()), "x", "x"), version, held);
    const auto otherVersion = envelopeFor(uid(), version + 7, held);
    auto mislabeled = envelopeFor(uid(), version, held);
    for (const auto* e : {&good, &stranger, &otherVault, &otherVersion})
        (void)v.bucket->seed(".vaulthalla/key/" + e->kid, e->bytes);
    const auto wrongKid = mf::uidText(crypto::id::newObjectUid());
    (void)v.bucket->seed(".vaulthalla/key/" + wrongKid, mislabeled.bytes);

    auto theirs = head().content;
    auto& key = *std::ranges::find(theirs.keys, version, &mf::KeyRecord::version);
    key.envelopes = std::vector<std::string>{good.kid, stranger.kid, missing.kid, otherVault.kid, otherVersion.kid, wrongKid};
    (void)publishAs(theirs, "another-node", true);
    const auto r = service->applyRemote();
    ASSERT_TRUE(r && r->recorded);
    EXPECT_EQ(count("SELECT count(*) FROM vault_recovery_grant WHERE vault_id = $1", id()), grants) << "no grant rows";
    EXPECT_EQ(count("SELECT count(*) FROM vault_key_envelope WHERE vault_id = $1", id()), envelopes) << "no envelope rows";
    EXPECT_EQ(count("SELECT count(*) FROM manifest_foreign_envelope WHERE vault_id = $1", id()), 2) << "good and stranger";
    EXPECT_GE(r->notes.size(), 4u) << "missing, other vault, other version, wrong kid";

    const auto listed = [&](const mf::Content& c) {
        const auto& k = *std::ranges::find(c.keys, version, &mf::KeyRecord::version);
        return k.envelopes.value_or(std::vector<std::string>{});
    };
    EXPECT_EQ(listed(db::query::sync::Manifest::collect(id())), std::vector<std::string>{good.kid})
        << "only the recipient this server holds a grant for";
    write("/after.txt", "a change to publish");
    const auto first = service->publish();
    EXPECT_EQ(listed(head().content), std::vector<std::string>{good.kid});
    write("/after-2.txt", "another");
    (void)service->publish();
    EXPECT_EQ(listed(head().content), listed(first.published.content)) << "stable from one publish to the next";
}

// A vault on the mirror strategy deletes remote objects its database doesn't hold: with another writer it refuses the
// head (the pass stalls), and the operator is alerted once for that root. The last apply's stop is in the status.
TEST_F(ManifestApplyDb, AMirrorVaultRefusesASharedHeadAndAlertsOnce) {
    seed();
    v.engine->remote_policy()->strategy = sync::model::RemotePolicy::Strategy::Mirror;
    (void)notifications::OperatorNotificationBus::instance().drain(512);
    const auto h = head();
    auto named = h.root;
    named.epoch = h.acceptance.epoch + 1;
    named.prev = h.acceptance.root_sha256;
    named.producer.node_id = "another-node";
    named.writers = std::vector<std::string>{db::query::device::Devices::nodeId(), "another-node"};
    const auto k = v.engine->encryptionManager->currentKey();
    (void)v.bucket->seed(std::string(mf::kRootKey), mf::sealRoot(named, uid(), {k.version, k.key}));
    EXPECT_THROW((void)service->applyRemote(), sync::vault_manifest::ApplyStopped);
    EXPECT_THROW((void)service->applyRemote(), sync::vault_manifest::ApplyStopped);
    std::size_t alerts = 0;
    for (const auto& n : notifications::OperatorNotificationBus::instance().drain(512))
        if (n.eventKey == "manifest_apply_stopped") ++alerts;
    EXPECT_EQ(alerts, 1u) << "once per root";
    const auto st = db::query::sync::ManifestApply::status(id());
    EXPECT_EQ(st["last_apply"]["stopped"], "manifest_mirror_shared");
    EXPECT_EQ(db::query::sync::Manifest::state(id()).epoch, h.acceptance.epoch);
}

// Another writer built on our own root that was PUT and not recorded: that root (its pending base copy, kept before
// the PUT) is adopted first and is the apply's base, so a file created in it and deleted here since stays deleted, and
// one created in it and renamed here since keeps its new name (with `known` as the base both read as theirs).
TEST_F(ManifestApplyDb, AnUnrecordedOwnRootAnotherWriterBuiltOnIsTheBaseOfTheApply) {
    seed();
    share();
    write("/doomed.txt", "in our unrecorded root");
    write("/renamed-later.txt", "in our unrecorded root too");
    failRecords(id(), true);
    EXPECT_ANY_THROW((void)service->publish());
    failRecords(id(), false);
    const auto ours = head();
    ASSERT_EQ(ours.acceptance.epoch, *db::query::sync::Manifest::state(id()).epoch + 1);

    auto theirs = ours.content;   // the other writer applied our root and adds a file on top
    mf::Entry added = *byName(theirs, "top.txt");
    added.uid = mf::uidText(crypto::id::newObjectUid());
    added.name = "from-the-other.txt";
    added.versions.clear();
    theirs.entries.push_back(added);
    mf::normalize(theirs);
    (void)publishAs(theirs, "another-node", true, ours.known());

    fs::Filesystem::remove(v.engine->vaultPathToFusePath("/doomed.txt"), superUser->id);
    ASSERT_EQ(fs::Filesystem::rename(v.engine->vaultPathToFusePath("/renamed-later.txt"),
                                     v.engine->vaultPathToFusePath("/renamed-now.txt"), superUser), 0);
    restart();
    const auto r = service->applyRemote();
    ASSERT_TRUE(r && r->recorded);
    EXPECT_FALSE(r->union_base);
    EXPECT_EQ(std::ranges::count(r->conflicts, mf::ConflictKind::Placement, &mf::Conflict::kind), 0);
    EXPECT_FALSE(db::query::fs::File::getFileByPath(id(), "/doomed.txt")) << "not re-created";
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/renamed-now.txt"));
    EXPECT_FALSE(db::query::fs::File::getFileByPath(id(), "/renamed-later.txt"));
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/from-the-other.txt"));
    EXPECT_EQ(count("SELECT count(*) FROM remote_manifest_pending WHERE vault_id = $1", id()), 0) << "cleared by the record";
}

// With another writer, a trash is purged here locally only: that writer may restore the file and name the same object
// live again, and a remote DELETE would remove it. (A vault this server writes alone keeps purging remotely.)
TEST_F(ManifestApplyDb, WithAnotherWriterATrashIsPurgedWithoutARemoteDelete) {
    seed();
    share();
    const auto reportUid = byName(head().content, "report.pdf")->uid;
    auto theirs = head().content;
    at(theirs, "report.pdf").trashed = mf::Trashed{"2026-11-15T00:00:00Z", "admin", "/Docs/report.pdf"};
    (void)publishAs(theirs, "another-node", true);
    ASSERT_TRUE(service->applyRemote());
    ASSERT_FALSE(db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")) << "trashed here";
    auto restored = head().content;   // the other writer restores it before our next pass
    at(restored, "report.pdf").trashed.reset();
    (void)publishAs(restored, "another-node", true);

    v.bucket->clearRequests();
    (void)test_support::versioned::runSyncPass(v.engine, {.purgeTrash = true, .downloads = false, .expectOk = false});
    for (const auto& req : v.bucket->requests())
        if (req.op == VersionedBucket::Op::Delete) { EXPECT_NE(req.key, "o/" + reportUid) << "no remote DELETE of it"; }
    EXPECT_TRUE(v.bucket->current("o/" + reportUid)) << "the object the restored file names is there";
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")) << "restored here too";
}

// Remote-only files (no local bytes, as under cache) after an applied move and an applied content replacement: the
// next read hydrates the right object at the right place.
// Found by the drill: a file whose group is unset (NULL) collects as owner {uid, 0}, and the attribute write's
// compare-and-set compared that 0 with NULL: the root was skipped on every pass and never recorded.
TEST_F(ManifestApplyDb, AnAttributeChangeAppliesToAFileWithoutAGroup) {
    seed();
    db::Transactions::exec("no group", [&](pqxx::work& txn) {
        txn.exec("UPDATE fs_entry SET owner_uid = 1000, group_gid = NULL WHERE vault_id = $1 AND path = '/Photos/a.jpg'",
                 pqxx::params{id()});
    });
    auto theirs = head().content;
    at(theirs, "a.jpg").owner = mf::Owner{1000, 0};
    at(theirs, "a.jpg").mode = 0600;
    (void)publishAs(theirs);
    const auto r = service->applyRemote();
    ASSERT_TRUE(r);
    EXPECT_EQ(r->skipped, 0u);
    EXPECT_TRUE(r->recorded);
    EXPECT_EQ(db::query::fs::Entry::getFSEntryByPath(id(), "/Photos/a.jpg")->mode.value_or(0) & 0777, 0600u);
}

// Found by the drill: an empty folder a restore created has no backing directory, and moving it through FUSE failed
// with ENOENT ("source backing path does not exist").
TEST_F(ManifestApplyDb, AFolderWithoutABackingDirectoryMovesThroughTheFilesystem) {
    seed();
    mkdir("/Empty");
    const auto entry = db::query::fs::Entry::getFSEntryByPath(id(), "/Empty");
    ASSERT_TRUE(entry);
    std::filesystem::remove(entry->backing_path);   // as a restore leaves it
    ASSERT_EQ(fs::Filesystem::rename(v.engine->vaultPathToFusePath("/Empty"), v.engine->vaultPathToFusePath("/Docs/Empty"),
                                     nullptr, v.engine, fs::RenameMode::NoReplace), 0);
    EXPECT_TRUE(db::query::fs::Entry::getFSEntryByPath(id(), "/Docs/Empty"));
    EXPECT_FALSE(db::query::fs::Entry::getFSEntryByPath(id(), "/Empty"));
}

TEST_F(ManifestApplyDb, RemoteOnlyFilesHydrateAfterAnAppliedMoveAndReplacement) {
    seed();
    for (const auto* p : {"/Docs/report.pdf", "/Docs/notes.txt"}) {
        const auto f = db::query::fs::File::getFileByPath(id(), p);
        std::error_code ec;
        std::filesystem::remove(f->backing_path, ec);   // evicted: the bucket holds the bytes
    }
    const auto k = v.engine->encryptionManager->currentKey();
    auto theirs = head().content;
    at(theirs, "notes.txt").parent = at(theirs, "Photos").uid;   // a move
    auto& report = at(theirs, "report.pdf");                      // and new content, sealed as its writer seals it
    const std::string v2 = "report v2, written by the other server";
    vl::vaultfmt::vhf1::HeaderParams hp;
    hp.kind = vl::vaultfmt::vhf1::Kind::FileContent;
    hp.keyVersion = k.version;
    hp.vaultUid = uid();
    hp.objectUid = mf::parseUid(report.uid, "x", "x");
    hp.salt = vl::vaultfmt::vhf1::freshSalt();
    const auto sealed = vl::vaultfmt::vhf1::seal(std::vector<uint8_t>(v2.begin(), v2.end()), hp, *k.key);
    (void)v.bucket->seed("o/" + report.uid, sealed);
    report.generation = hexOf(hp.salt);
    report.key_version = k.version;
    report.size = v2.size();
    report.content_hash.reset();
    report.object = mf::ObjectRef{v.bucket->current("o/" + report.uid)->etag, sealed.size(), std::nullopt, std::nullopt};
    (void)publishAs(theirs);
    const auto r = service->applyRemote();
    ASSERT_TRUE(r && r->recorded);
    EXPECT_EQ(readAllOf(v.engine, "/Photos/notes.txt"), "notes");
    EXPECT_EQ(readAllOf(v.engine, "/Docs/report.pdf"), v2);
}


// ── The mirror drill's findings and the shared-vault rules (design: "As built: the mirror drill") ───────────────────

namespace {

// Theirs' new content for `uid`, sealed as its writer seals it and stored in the bucket; the entry says so.
std::vector<uint8_t> sealTheirs(test_support::versioned::CloudVault& v, mf::Entry& e, const std::string& text) {
    const auto k = v.engine->encryptionManager->currentKey();
    vl::vaultfmt::vhf1::HeaderParams hp;
    hp.kind = vl::vaultfmt::vhf1::Kind::FileContent;
    hp.keyVersion = k.version;
    hp.vaultUid = *v.engine->vault->uid;
    hp.objectUid = mf::parseUid(e.uid, "x", "x");
    hp.salt = vl::vaultfmt::vhf1::freshSalt();
    auto sealed = vl::vaultfmt::vhf1::seal(std::vector<uint8_t>(text.begin(), text.end()), hp, *k.key);
    (void)v.bucket->seed("o/" + e.uid, sealed);
    e.generation = hexOf(hp.salt);
    e.key_version = k.version;
    e.size = text.size();
    e.content_hash.reset();
    e.object = mf::ObjectRef{v.bucket->current("o/" + e.uid)->etag, sealed.size(), std::nullopt, std::nullopt};
    return sealed;
}

std::string openSealed(test_support::versioned::CloudVault& v, const std::vector<uint8_t>& object, const std::string& uid) {
    vl::vaultfmt::vhf1::Expectation ex;
    ex.vaultUid = *v.engine->vault->uid;
    ex.objectUid = mf::parseUid(uid, "x", "x");
    const auto keys = [em = v.engine->encryptionManager](const uint32_t ver) -> vl::vaultfmt::vhf1::KeyPtr {
        return em->historicalKeySnapshot(ver);
    };
    const auto plain = vl::vaultfmt::vhf1::open(object, ex, keys);
    return {reinterpret_cast<const char*>(plain.data()), plain.size()};
}

}

// Found by the drill: a key check is computed over the producing server's vault id, so a replica's root carries other
// checks than this server's for the same key. They are recomputed with this server's key and the producer's vault id:
// the same key is accepted, another key is still a mismatch (the apply stops).
TEST_F(ManifestApplyDb, AnotherServersKeyChecksAreRecomputedOverItsVaultId) {
    seed();
    const auto k = v.engine->encryptionManager->currentKey();
    auto theirs = head().content;
    const unsigned otherVault = id() + 4242;
    theirs.producer.vault_id = otherVault;
    for (auto& key : theirs.keys)
        if (const auto held = v.engine->encryptionManager->historicalKeySnapshot(key.version))
            key.key_check = vault::keyCheck(held->bytes(), otherVault, key.version);
    at(theirs, "top.txt").name = "renamed.txt";
    {   // without the recompute (the plain text comparison) the same key under another vault id is a mismatch
        const auto ours = head().content;
        const auto plain = mf::reconcile(ours, theirs, ours);
        ASSERT_TRUE(plain.stopped());
        EXPECT_EQ(plain.key_problems.front().code, "manifest_key_mismatch");
    }
    (void)publishAs(theirs);
    const auto r = service->applyRemote();
    ASSERT_TRUE(r && r->recorded) << "the same key under another vault id";

    fresh();
    seed();
    auto wrong = head().content;
    wrong.producer.vault_id = otherVault;
    for (auto& key : wrong.keys) key.key_check = std::string(32, 'a');
    at(wrong, "top.txt").name = "wrong.txt";
    (void)publishAs(wrong);
    EXPECT_THROW((void)service->applyRemote(), sync::vault_manifest::ApplyStopped);
    EXPECT_EQ(db::query::sync::ManifestApply::status(id())["last_apply"]["stopped"], "manifest_key_mismatch");
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/top.txt") != nullptr) << "nothing of the wrong-key root applied";
    EXPECT_TRUE(db::query::fs::File::getFileByPath(id(), "/wrong.txt") == nullptr);
    (void)k;
}

// Found by the drill: after applying another writer's root that already says what this server holds, a pass
// published anyway (its producer, key checks and attestations are this server's), the other writer applied that and
// did the same: two writers alternating roots every pass. Nothing changed: nothing is published, until a change.
// Both under another vault id and under the same one (independent servers may well share an id): another node.
TEST_F(ManifestApplyDb, AnotherWritersRootThatSaysWhatThisServerHoldsIsNotRestamped) {
    for (const bool sameId : {false, true}) {
        SCOPED_TRACE(sameId ? "the same vault id" : "another vault id");
        if (sameId) fresh();
        seed();
        share();
        auto theirs = head().content;
        const unsigned otherVault = sameId ? id() : id() + 4242;
        theirs.producer.vault_id = otherVault;
        for (auto& key : theirs.keys) {
            if (const auto held = v.engine->encryptionManager->historicalKeySnapshot(key.version))
                key.key_check = vault::keyCheck(held->bytes(), otherVault, key.version);
            key.attestation.reset();   // its own TPM's, or none
        }
        (void)publishAs(theirs, "another-node", true);
        ASSERT_TRUE(service->applyRemote());
        const auto applied = db::query::sync::Manifest::state(id()).epoch;
        EXPECT_FALSE(service->publishIfChanged()) << "nothing to say: no root";
        EXPECT_FALSE(service->publishIfChanged());
        EXPECT_EQ(head().acceptance.epoch, *applied);
        EXPECT_EQ(db::query::sync::Manifest::state(id()).epoch, applied);

        mkdir("/Later");
        const auto r = service->publishIfChanged();
        ASSERT_TRUE(r) << "a change here: published";
        EXPECT_EQ(head().acceptance.epoch, *applied + 1);
        EXPECT_TRUE(byName(head().content, "Later"));
        EXPECT_TRUE(byName(head().content, "top.txt")) << "built on the applied root";
        EXPECT_FALSE(service->publishIfChanged()) << "its own publish: unchanged after it";
    }
}

// Found by the drill: another writer's edit, applied, lost its mtime three ways (the fs_entry trigger stamped every
// update, the apply's cache refresh wrote the row back, a download stamped the download's time); the two writers'
// roots then differed on it every pass. The row keeps the mtime the manifest gave it, downloaded too.
TEST_F(ManifestApplyDb, ADownloadKeepsTheMtimeTheManifestGaveTheFile) {
    seed();
    auto theirs = head().content;
    auto& report = at(theirs, "report.pdf");
    (void)sealTheirs(v, report, "theirs, dated in January");
    report.mtime = "2026-01-02T03:04:05Z";
    (void)publishAs(theirs);
    ASSERT_TRUE(service->applyRemote());
    EXPECT_EQ(db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")->updated_at, 1767323045);
    v.engine->remote_policy()->strategy = sync::model::RemotePolicy::Strategy::Sync;
    (void)test_support::versioned::runSyncPass(v.engine, {.purgeTrash = false, .downloads = true, .expectOk = true});
    EXPECT_EQ(readAllOf(v.engine, "/Docs/report.pdf"), "theirs, dated in January");
    EXPECT_EQ(db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf")->updated_at, 1767323045) << "downloaded";
    EXPECT_EQ(byName(db::query::sync::Manifest::collect(id()), "report.pdf")->mtime, "2026-01-02T03:04:05Z");
}

// Found by the edit/edit test: the collector took a file's size and content hash from the files row and its object
// from the index, so a local edit not uploaded yet read as a change of ours to the object, the root that replaced the
// object as an edit/edit already decided for ours, and the planner saw only a local change (its upload overwrote
// theirs). An entry describes the object it names: size, hash and key version come from the index row.
TEST_F(ManifestApplyDb, TheCollectorDescribesTheObjectNotALocalEditWaitingForUpload) {
    seed();
    const auto before = *byName(db::query::sync::Manifest::collect(id()), "report.pdf");
    write("/Docs/report.pdf", "edited here, not uploaded");
    const auto local = db::query::fs::File::getFileByPath(id(), "/Docs/report.pdf");
    ASSERT_NE(local->size_bytes, before.size);
    const auto after = *byName(db::query::sync::Manifest::collect(id()), "report.pdf");
    EXPECT_EQ(after.generation, before.generation);
    EXPECT_EQ(after.size, before.size) << "the object's plaintext size, not the local edit's";
    EXPECT_EQ(after.content_hash, before.content_hash);
    EXPECT_EQ(after.object, before.object);
    pass();
    const auto uploaded = *byName(db::query::sync::Manifest::collect(id()), "report.pdf");
    EXPECT_NE(uploaded.generation, before.generation) << "uploaded: the new object";
    EXPECT_EQ(uploaded.size, local->size_bytes);
    EXPECT_EQ(uploaded.content_hash, local->content_hash);
}

// Content edit/edit with another writer: never decided by a policy that would lose a side. Unversioned bucket (the
// loser would be overwritten): the conflict stays open whatever the policy (keep_local here), ours is the local copy
// (read through the engine), theirs the bucket's current object (read back and opened). A bucket that keeps versions:
// the policy decides (keep_local uploads ours) and theirs survives as the object's previous version, read back too.
TEST_F(ManifestApplyDb, AContentEditOnBothSidesWithAnotherWriterKeepsBothGenerations) {
    for (const bool versioned : {false, true}) {
        SCOPED_TRACE(versioned ? "a bucket that keeps versions" : "an unversioned bucket");
        v = test_support::versioned::makeCloudVault(superUser, "ma", versioned ? Versioning::Enabled : Versioning::Unversioned,
                                                    true, sync::model::RemotePolicy::Strategy::Cache);
        store = std::make_shared<storage::s3::ManifestStore>(v.bucket);
        restart();
        if (versioned)
            db::Transactions::exec("versions", [&](pqxx::work& txn) {
                txn.exec("INSERT INTO vault_recovery_policy (vault_id, mode) VALUES ($1, 'provider_versioning') "
                         "ON CONFLICT (vault_id) DO UPDATE SET mode = 'provider_versioning'",
                         pqxx::params{id()});
            });
        seed();
        share();
        v.engine->remote_policy()->conflict_policy = sync::model::RemotePolicy::ConflictPolicy::KeepLocal;
        write("/Docs/report.pdf", "ours, edited here");
        auto theirs = head().content;
        auto& report = at(theirs, "report.pdf");
        const auto uid = report.uid;
        const auto sealed = sealTheirs(v, report, "theirs, edited there");
        (void)publishAs(theirs, "another-node", true);
        (void)test_support::versioned::runSyncPass(v.engine, {.purgeTrash = false, .downloads = false, .expectOk = false});

        const auto open = count("SELECT count(*) FROM sync_conflicts WHERE vault_id = $1 AND resolved_at IS NULL", id());
        if (!versioned) {
            EXPECT_EQ(open, 1) << "recorded and open, whatever the policy";
            EXPECT_EQ(readAllOf(v.engine, "/Docs/report.pdf"), "ours, edited here") << "ours: the local copy";
            const auto current = v.bucket->current("o/" + uid);
            ASSERT_TRUE(current);
            EXPECT_EQ(current->body, sealed) << "theirs: the bucket's object, not overwritten";
            EXPECT_EQ(openSealed(v, current->body, uid), "theirs, edited there");
        } else {
            EXPECT_EQ(open, 0) << "the policy decides: the loser survives as a provider version";
            bool theirsKept = false;
            for (const auto& ver : v.bucket->history("o/" + uid))
                if (!ver.delete_marker && ver.body == sealed) theirsKept = openSealed(v, ver.body, uid) == "theirs, edited there";
            EXPECT_TRUE(theirsKept) << "theirs: a provider version of the object, read back";
            EXPECT_EQ(readAllOf(v.engine, "/Docs/report.pdf"), "ours, edited here");
        }
    }
}

// Orphan collection for shared-vault trash: an object this server purged locally is deleted from the bucket after the
// grace period when no root names it; one the other writer restored in between is kept (and forgotten); one named
// again between the checks and the DELETE is kept (the head is read again right before it).
TEST_F(ManifestApplyDb, SharedTrashObjectsAreCollectedOnlyAfterTheGraceAndWhenNoRootNamesThem) {
    seed();
    share();
    const auto now = std::time(nullptr);
    const auto week = sync::vault_manifest::Service::kSharedOrphanGrace;
    const auto purgeHere = [&](const std::string& name) {
        auto theirs = head().content;
        at(theirs, name).trashed = mf::Trashed{"2026-11-15T00:00:00Z", "admin", std::nullopt};
        (void)publishAs(theirs, "another-node", true);
        ASSERT_TRUE(service->applyRemote());
        (void)test_support::versioned::runSyncPass(v.engine, {.purgeTrash = true, .downloads = false, .expectOk = false});
    };
    const auto aUid = byName(head().content, "a.jpg")->uid, bUid = byName(head().content, "b.jpg")->uid;
    const mf::Entry bLive = *byName(head().content, "b.jpg");   // this server's purge drops it from its next root
    purgeHere("a.jpg");
    purgeHere("b.jpg");
    EXPECT_EQ(count("SELECT count(*) FROM manifest_shared_purge WHERE vault_id = $1", id()), 2);
    // The other writer purged a.jpg too (its root drops it); b.jpg it restored.
    auto theirs = head().content;
    std::erase_if(theirs.entries, [&](const mf::Entry& e) { return e.uid == aUid; });
    ASSERT_FALSE(byName(theirs, "b.jpg")) << "purged here: no longer named by this server's root";
    std::erase_if(theirs.entries, [&](const mf::Entry& e) { return e.uid == bUid; });
    theirs.entries.push_back(bLive);
    mf::normalize(theirs);
    (void)publishAs(theirs, "another-node", true);
    ASSERT_TRUE(service->applyRemote());

    EXPECT_EQ(service->collectSharedOrphans(now), 0u) << "within the grace period";
    EXPECT_TRUE(v.bucket->current("o/" + aUid));

    // Named again between the checks and the DELETE: the head moved, nothing goes.
    const auto again = service->collectSharedOrphans(now + week + 60, week, [&](const std::string&) {
        auto named = head().content;
        const auto* live = byName(named, "b.jpg");
        ASSERT_TRUE(live);
        mf::Entry back = *live;
        back.uid = aUid;
        back.name = "a-again.jpg";
        named.entries.push_back(back);
        mf::normalize(named);
        (void)publishAs(named, "another-node", true);
    });
    EXPECT_EQ(again, 0u);
    EXPECT_TRUE(v.bucket->current("o/" + aUid));
    ASSERT_TRUE(service->applyRemote());
    EXPECT_EQ(service->collectSharedOrphans(now + week + 60), 0u) << "named live again: forgotten, not deleted";
    EXPECT_TRUE(v.bucket->current("o/" + aUid));
    EXPECT_TRUE(v.bucket->current("o/" + bUid)) << "restored in between: kept";
    EXPECT_EQ(count("SELECT count(*) FROM manifest_shared_purge WHERE vault_id = $1", id()), 0);

    // Unnamed after the grace: deleted.
    auto gone = head().content;
    std::erase_if(gone.entries, [&](const mf::Entry& e) { return e.uid == aUid; });
    (void)publishAs(gone, "another-node", true);
    ASSERT_TRUE(service->applyRemote());
    db::query::sync::ManifestApply::notePurgedLocally(id(), "o/" + aUid);
    EXPECT_EQ(service->collectSharedOrphans(now + week + 60), 1u);
    EXPECT_FALSE(v.bucket->current("o/" + aUid));
}


// ── Replicated vaults: writers changes and refusals (design/sync/manifest-applier.md, "As built: the join") ──────────

namespace {

std::string refusalCode(const std::function<void()>& f) {
    try {
        f();
    } catch (const ops::Refused& e) {
        return e.code;
    } catch (const std::exception& e) {
        return std::string("other: ") + e.what();
    }
    return "ok";
}

}

// A replica removal and a leave: the publish carries the change until the recorded root shows it, then it is cleared;
// a server that left is superseded (its next publish is refused).
TEST_F(ManifestApplyDb, ARemovalOrALeaveIsPublishedOnceAndClearedByTheRootThatShowsIt) {
    seed();
    share();
    const auto self = db::query::device::Devices::nodeId();
    ASSERT_TRUE(sync::replicas::replicated(id()));
    db::query::sync::Manifest::setWritersChange(id(), mf::WritersChange{mf::WritersChange::Kind::Remove, "another-node"});
    EXPECT_TRUE(db::query::sync::ManifestApply::status(id())["behind"].get<bool>()) << "a change not published yet";
    EXPECT_TRUE(service->publishIfChanged()) << "a pending change publishes even with nothing else changed";
    EXPECT_EQ(head().root.writers, std::vector<std::string>{self});
    EXPECT_FALSE(db::query::sync::Manifest::state(id()).writers_change) << "shown by the recorded root: cleared";
    EXPECT_FALSE(sync::replicas::replicated(id())) << "solo again";
    EXPECT_FALSE(service->publishIfChanged());

    fresh();
    seed();
    share();
    db::query::sync::Manifest::setWritersChange(id(), mf::WritersChange{mf::WritersChange::Kind::Remove, self});
    (void)service->publish();
    EXPECT_EQ(head().root.writers, std::vector<std::string>{"another-node"}) << "left: the other writer stays";
    mkdir("/AfterLeaving");
    auto later = head().content;
    (void)publishAs(later, "another-node", true);
    EXPECT_NE(refusalCode([&] { (void)service->applyRemote(); (void)service->publish(); }), "ok")
        << "a server that left publishes nothing over the others";
}

// At most three writers: a fourth is refused by the publish itself, and nothing is written.
TEST_F(ManifestApplyDb, AFourthWriterIsRefusedByThePublish) {
    seed();
    const auto h = head();
    auto named = h.root;
    named.epoch = h.acceptance.epoch + 1;
    named.prev = h.acceptance.root_sha256;
    named.producer.node_id = "node-2";
    named.writers = std::vector<std::string>{db::query::device::Devices::nodeId(), "node-2", "node-3"};
    const auto k = v.engine->encryptionManager->currentKey();
    (void)v.bucket->seed(std::string(mf::kRootKey), mf::sealRoot(named, uid(), {k.version, k.key}));
    ASSERT_TRUE(service->applyRemote());
    const auto epoch = head().acceptance.epoch;
    db::query::sync::Manifest::setWritersChange(id(), mf::WritersChange{mf::WritersChange::Kind::Add, "node-4"});
    EXPECT_THROW((void)service->publish(), mf::WritersRefused);
    EXPECT_EQ(head().acceptance.epoch, epoch);
    const auto st = db::query::sync::ManifestApply::status(id());
    ASSERT_EQ(st["replicas"].size(), 3u);
    EXPECT_TRUE(st["replicas"][0]["self"].get<bool>());
    EXPECT_FALSE(st["replicas"][1]["last_epoch"].is_null()) << "node-2's root was recorded here";
    EXPECT_TRUE(st["replicas"][2]["last_epoch"].is_null()) << "node-3 published nothing this server recorded";
}

// What a replicated vault refuses (design/cloud/mirrors.md, as amended): every path that mints a key version, the
// mirror strategy, a local-only recovery recipient, a layout migration; and once solo again, a rotation works.
TEST_F(ManifestApplyDb, AReplicatedVaultRefusesWhatWouldMakeTheReplicasDiffer) {
    seed();
    share();
    EXPECT_EQ(refusalCode([&] { v.engine->encryptionManager->prepare_key_rotation(); }), "vault_replicated");
    EXPECT_EQ(refusalCode([&] { (void)vault::EncryptionManager::mintSalvageKey(id(), 9, false); }), "vault_replicated");
    ops::vaults::SyncPatch mirror;
    mirror.strategy = "mirror";
    EXPECT_EQ(refusalCode([&] { (void)ops::vaults::updateSync(superUser, id(), mirror); }), "vault_replicated");
    const auto pk = vl::keykit::RecoverySeed::generate().x25519PublicKey();
    std::string hex;
    for (const auto b : pk) hex += fmt::format("{:02x}", b);
    EXPECT_EQ(refusalCode([&] {
                  (void)ops::recovery_recipients::add(superUser, {.vault_id = id(), .public_key = hex},
                                                      ops::vault_keys::Channel::Cli);
              }),
              "vault_replicated");
    EXPECT_EQ(refusalCode([&] { (void)ops::vault_layout::start(superUser, {.vault_id = id()}); }), "vault_replicated");

    db::query::sync::Manifest::setWritersChange(id(), mf::WritersChange{mf::WritersChange::Kind::Remove, "another-node"});
    (void)service->publish();
    const auto before = v.engine->encryptionManager->get_key_version();
    EXPECT_EQ(refusalCode([&] { v.engine->encryptionManager->prepare_key_rotation(); }), "ok") << "solo: rotates";
    EXPECT_EQ(v.engine->encryptionManager->get_key_version(), before + 1);
}

}
