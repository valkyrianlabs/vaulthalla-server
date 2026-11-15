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
#include "db/query/fs/File.hpp"
#include "fs/model/File.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/sync/ManifestApply.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "storage/s3/ManifestStore.hpp"
#include "sync/manifest/Objects.hpp"
#include "sync/manifest/Publisher.hpp"
#include "sync/manifest/Reader.hpp"
#include "sync/manifest/Reconcile.hpp"
#include "sync/vault_manifest/Service.hpp"
#include "vault/EncryptionManager.hpp"

#include <atomic>
#include <chrono>
#include <set>
#include <thread>

namespace vh::test_manifest_apply_db {

namespace mf = vh::sync::manifest;
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
    mf::PublishReport publishAs(mf::Content c, const std::string& node = "another-node") const {
        const auto state = db::query::sync::Manifest::state(id());
        c.producer.node_id = node;
        const auto k = v.engine->encryptionManager->currentKey();
        mf::PublisherCache cache;
        mf::PublishOptions o;
        o.now = mf::isoTime(std::time(nullptr));
        return mf::publish(*store, uid(), service->keyLookup(), {k.version, k.key}, c,
                           mf::Known{*state.epoch, *state.root_sha256, state.root_version_id}, cache, o);
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

// Replicated vaults stay refused while another writer's recovery envelope kids are dropped from this server's roots
// (design item 6 prerequisite; Applier.hpp kCarriesForeignEnvelopes): a head naming several writers is not applied.
// Removing the refusal without the carry-forward fails here.
TEST_F(ManifestApplyDb, AReplicatedHeadIsRefusedWhileForeignEnvelopesAreNotCarried) {
    static_assert(!sync::vault_manifest::kCarriesForeignEnvelopes,
                  "with the carry-forward built, replace this test by one of the carry-forward");
    seed();
    const auto h = head();
    auto named = h.root;
    named.epoch = h.acceptance.epoch + 1;
    named.prev = h.acceptance.root_sha256;
    named.producer.node_id = "another-node";
    named.writers = std::vector<std::string>{db::query::device::Devices::nodeId(), "another-node"};
    const auto k = v.engine->encryptionManager->currentKey();
    (void)v.bucket->seed(std::string(mf::kRootKey), mf::sealRoot(named, uid(), {k.version, k.key}));
    try {
        (void)service->applyRemote();
        ADD_FAILURE() << "a replicated head was applied";
    } catch (const sync::vault_manifest::ApplyStopped& e) {
        EXPECT_NE(std::string(e.what()).find("envelope"), std::string::npos) << e.what();
    }
    EXPECT_EQ(db::query::sync::Manifest::state(id()).epoch, h.acceptance.epoch);
}

}
