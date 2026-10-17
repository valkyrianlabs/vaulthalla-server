// Restoring local generations (recovery::local::planFor / restore, Filesystem's pre-sealed commit): to the original
// paths after the file and its folder were deleted, to an alternate destination, over a changed file (Overwrite, and
// a conflict when it changed again after the plan), Skip when identical, after a rename, across finished and
// interrupted key rotations (re-seal), after a daemon restart, empty files and directories, missing blobs and
// destination conflicts. DB-backed; skipped without the VH_TEST_DB_* environment.

#include "../helpers/recovery_local.hpp"

#include "db/query/fs/File.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/ops/file.hpp"
#include "ops/Error.hpp"
#include "runtime/Deps.hpp"

#include <algorithm>
#include <fstream>
#include <iterator>

namespace vh::test_recovery_local_restore {

using namespace vh::test_support::recovery_local;
namespace store = vh::recovery::store;

class RecoveryLocalRestoreTest : public LocalRecoveryFixture {
protected:
    static void SetUpTestSuite() { setUpSuite("recovery_local_restore"); }
    static void TearDownTestSuite() { tearDownSuite(); }

    [[nodiscard]] static std::size_t countOutcome(const std::vector<vh::recovery::ItemOutcome>& outcomes,
                                                  const std::string& outcome) {
        return static_cast<std::size_t>(std::ranges::count_if(outcomes, [&](const auto& o) { return o.outcome == outcome; }));
    }

    void buildTree() const {
        mkdir("/proj");
        mkdir("/proj/sub/deep");
        mkdir("/proj/empty");
        write("/proj/a.txt", "alpha\n");
        write("/proj/sub/b.bin", std::string(70'001, 'b'));
        write("/proj/sub/deep/c.txt", "gamma\n");
        write("/proj/zero.txt", "");
    }

    void expectTree(const std::string& at) const {
        EXPECT_EQ(plaintext(at + "/a.txt"), "alpha\n");
        EXPECT_EQ(plaintext(at + "/sub/b.bin"), std::string(70'001, 'b'));
        EXPECT_EQ(plaintext(at + "/sub/deep/c.txt"), "gamma\n");
        EXPECT_TRUE(exists(at + "/zero.txt"));
        EXPECT_EQ(file(at + "/zero.txt")->size_bytes, 0u);
        EXPECT_TRUE(isDir(at + "/empty"));
    }
};

TEST_F(RecoveryLocalRestoreTest, ASnapshotRestoresTheTreeAfterTheFilesAndTheFolderWereDeleted) {
    buildTree();
    const auto snap = snapshot("/proj", "tree");
    remove("/proj");
    EXPECT_FALSE(exists("/proj"));
    EXPECT_FALSE(exists("/proj/sub/deep")) << "a deleted folder's subfolders leave the metadata cache too";
    EXPECT_FALSE(exists("/proj/empty"));
    for (const auto& m : members(snap.snapshot_id)) EXPECT_FALSE(m.file_id) << m.path << ": the live file is gone";

    const auto plan = local::planFor(snapId(snap.snapshot_id));
    EXPECT_TRUE(plan.atomic);
    EXPECT_FALSE(plan.consistency_note.empty());
    EXPECT_EQ(plan.vault_id, vaultId());
    EXPECT_EQ(plan.creates, 5u) << "four files and the empty directory";
    EXPECT_EQ(plan.overwrites + plan.skips + plan.conflicts + plan.unavailable, 0u);
    EXPECT_TRUE(plan.blockers.empty());
    const auto* dirItem = itemFor(plan, "/proj/empty");
    ASSERT_TRUE(dirItem);
    EXPECT_EQ(dirItem->method, "none");
    EXPECT_EQ(dirItem->source_id, "snap-" + std::to_string(snap.snapshot_id));
    const auto* fileItem = itemFor(plan, "/proj/sub/deep/c.txt");
    ASSERT_TRUE(fileItem);
    EXPECT_EQ(fileItem->method, "local_copy");
    EXPECT_EQ(local::missingParents(*engine, *fileItem),
              (std::vector<std::string>{"/proj", "/proj/sub", "/proj/sub/deep"}));

    const auto outcomes = restoreAll(plan);
    EXPECT_EQ(countOutcome(outcomes, "restored"), 5u);
    for (const auto& o : outcomes) EXPECT_EQ(o.outcome, "restored") << o.destination_path << ": " << o.error.value_or("");
    expectTree("/proj");
    const auto restored = file("/proj/a.txt");
    EXPECT_EQ(restored->encryption_iv, member(snap.snapshot_id, "/proj/a.txt")->encryption_iv)
        << "same key: the sealed bytes (and IV) are reused";

    // Restoring again: everything is already there.
    const auto again = local::planFor(snapId(snap.snapshot_id));
    EXPECT_EQ(again.skips, 5u);
    EXPECT_EQ(countOutcome(restoreAll(again), "skipped"), 5u);
}

TEST_F(RecoveryLocalRestoreTest, AnAlternateDestinationReceivesThePointUnderItsOwnName) {
    buildTree();
    const auto snap = snapshot("/proj");
    write("/proj/a.txt", "changed\n");

    const auto plan = local::planFor(snapId(snap.snapshot_id), std::nullopt, "/restored");
    EXPECT_EQ(plan.creates, 5u);
    EXPECT_TRUE(itemFor(plan, "/restored/proj/sub/deep/c.txt"));
    for (const auto& o : restoreAll(plan)) EXPECT_EQ(o.outcome, "restored") << o.destination_path;
    expectTree("/restored/proj");
    EXPECT_EQ(plaintext("/proj/a.txt"), "changed\n") << "the original is untouched";

    // A sub-path of the snapshot, into another root.
    const auto sub = local::planFor(snapId(snap.snapshot_id), "/proj/sub", "/other");
    EXPECT_EQ(sub.items.size(), 2u);
    EXPECT_EQ(sub.source_label, "snap-" + std::to_string(snap.snapshot_id) + ":/proj/sub");
    for (const auto& o : restoreAll(sub)) EXPECT_EQ(o.outcome, "restored") << o.destination_path;
    EXPECT_EQ(plaintext("/other/sub/deep/c.txt"), "gamma\n");
    EXPECT_FALSE(exists("/other/a.txt"));
    EXPECT_THROW((void)local::planFor(snapId(snap.snapshot_id), "/elsewhere"), ops::NotFound);
    EXPECT_THROW((void)local::planFor(snapId(snap.snapshot_id + 1000)), ops::NotFound);
}

TEST_F(RecoveryLocalRestoreTest, OverwriteIsACompareAndSetOnThePlannedGeneration) {
    write("/o.txt", "original");
    const auto snap = snapshot("/o.txt");
    const auto m = *member(snap.snapshot_id, "/o.txt");

    write("/o.txt", "edited");
    const auto plan = local::planFor(lvId(m.id));
    ASSERT_EQ(plan.items.size(), 1u);
    EXPECT_FALSE(plan.atomic);
    EXPECT_EQ(plan.items[0].action, ItemAction::Overwrite);
    EXPECT_EQ(plan.items[0].destination_source_id, storage::generationOf(*file("/o.txt")).sourceId());
    EXPECT_EQ(restoreAll(plan)[0].outcome, "restored");
    EXPECT_EQ(plaintext("/o.txt"), "original");

    // A write between plan and restore: the restore must not overwrite it.
    write("/o.txt", "edited again");
    const auto stale = local::planFor(lvId(m.id));
    ASSERT_EQ(stale.items[0].action, ItemAction::Overwrite);
    write("/o.txt", "written after the plan");
    const auto outcome = restoreAll(stale)[0];
    EXPECT_EQ(outcome.outcome, "conflict") << outcome.error.value_or("");
    EXPECT_EQ(plaintext("/o.txt"), "written after the plan");

    // A file that appears where the plan wanted to create one is a conflict too.
    remove("/o.txt");
    const auto create = local::planFor(lvId(m.id));
    ASSERT_EQ(create.items[0].action, ItemAction::Create);
    write("/o.txt", "someone else's");
    EXPECT_EQ(restoreAll(create)[0].outcome, "conflict");
    EXPECT_EQ(plaintext("/o.txt"), "someone else's");
}

TEST_F(RecoveryLocalRestoreTest, AnIdenticalDestinationIsSkipped) {
    write("/same.txt", "same");
    const auto snap = snapshot("/same.txt");
    const auto plan = local::planFor(snapId(snap.snapshot_id));
    ASSERT_EQ(plan.items.size(), 1u);
    EXPECT_EQ(plan.items[0].action, ItemAction::Skip);
    EXPECT_EQ(plan.skips, 1u);
    const auto iv = file("/same.txt")->encryption_iv;
    EXPECT_EQ(restoreAll(plan)[0].outcome, "skipped");
    EXPECT_EQ(file("/same.txt")->encryption_iv, iv) << "nothing was written";
}

TEST_F(RecoveryLocalRestoreTest, RestoringToTheOriginalPathAfterAMoveCreatesItThereAndLeavesTheMovedFileAlone) {
    mkdir("/docs");
    write("/docs/a.txt", "contents");
    const auto snap = snapshot("/docs/a.txt");
    engine->rename("/docs/a.txt", "/docs/b.txt", superUser);
    ASSERT_FALSE(exists("/docs/a.txt"));
    const auto moved = file("/docs/b.txt");
    ASSERT_TRUE(moved);

    const auto plan = local::planFor(snapId(snap.snapshot_id));
    ASSERT_EQ(plan.items.size(), 1u);
    EXPECT_EQ(plan.items[0].destination_path, "/docs/a.txt");
    EXPECT_EQ(plan.items[0].action, ItemAction::Create);
    EXPECT_EQ(restoreAll(plan)[0].outcome, "restored");
    EXPECT_EQ(plaintext("/docs/a.txt"), "contents");
    EXPECT_EQ(plaintext("/docs/b.txt"), "contents");
    const auto after = file("/docs/b.txt");
    EXPECT_EQ(after->id, moved->id);
    EXPECT_EQ(after->encryption_iv, moved->encryption_iv) << "the moved file is untouched";
}

TEST_F(RecoveryLocalRestoreTest, AGenerationUnderARetiredKeyIsResealedUnderTheCurrentOne) {
    write("/k.txt", "sealed under the first key");
    const auto snap = snapshot("/k.txt");
    const auto m = *member(snap.snapshot_id, "/k.txt");
    const auto em = engine->encryptionManager;
    const auto first = em->get_key_version();
    ASSERT_EQ(m.key_version, first);

    em->prepare_key_rotation();
    em->finish_key_rotation();
    const auto current = em->get_key_version();
    ASSERT_GT(current, first);
    ASSERT_TRUE(em->hasKeyVersion(first)) << "retained for recovery";

    const auto point = local::points::get(lvId(m.id));
    ASSERT_TRUE(point);
    EXPECT_TRUE(point->restorable);
    EXPECT_TRUE(point->encryption.key_available);
    EXPECT_FALSE(point->encryption.key_current);

    const auto plan = local::planFor(lvId(m.id), std::nullopt, "/rotated");
    ASSERT_EQ(plan.items.size(), 1u);
    EXPECT_EQ(plan.items[0].method, "local_reseal");
    EXPECT_FALSE(plan.warnings.empty());
    const auto outcome = restoreAll(plan)[0];
    EXPECT_EQ(outcome.outcome, "restored") << outcome.error.value_or("");
    const auto restored = file("/rotated/k.txt");
    EXPECT_EQ(restored->encrypted_with_key_version, current);
    EXPECT_NE(restored->encryption_iv, m.encryption_iv) << "a fresh IV under the new key";
    EXPECT_EQ(plaintext("/rotated/k.txt"), "sealed under the first key");
}

TEST_F(RecoveryLocalRestoreTest, AnInterruptedRotationStillRestoresUnderTheNewKey) {
    write("/i.txt", "before rotation");
    const auto snap = snapshot("/i.txt");
    const auto m = *member(snap.snapshot_id, "/i.txt");
    const auto em = engine->encryptionManager;
    em->prepare_key_rotation();   // never finished: both keys stay loaded
    ASSERT_TRUE(em->rotation_in_progress());
    ASSERT_NE(em->get_key_version(), *m.key_version);

    const auto plan = local::planFor(lvId(m.id), std::nullopt, "/mid");
    ASSERT_EQ(plan.items[0].method, "local_reseal");
    EXPECT_EQ(restoreAll(plan)[0].outcome, "restored");
    EXPECT_EQ(file("/mid/i.txt")->encrypted_with_key_version, em->get_key_version());
    EXPECT_EQ(plaintext("/mid/i.txt"), "before rotation");
    em->finish_key_rotation();
}

TEST_F(RecoveryLocalRestoreTest, RestoreWorksAfterADaemonRestart) {
    buildTree();
    const auto snap = snapshot("/proj");
    remove("/proj/sub/deep/c.txt");

    // A restart: engines, keys and the metadata cache rebuilt from the database.
    runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
    runtime::Deps::get().storageManager->initStorageEngines();
    engine = runtime::Deps::get().storageManager->getEngine(vaultId());
    ASSERT_TRUE(engine);
    EXPECT_EQ(local::snapshots::cleanupInterrupted(), 0u) << "nothing was interrupted";

    const auto plan = local::planFor(snapId(snap.snapshot_id), "/proj/sub/deep/c.txt");
    ASSERT_EQ(plan.items.size(), 1u);
    EXPECT_EQ(plan.items[0].action, ItemAction::Create);
    EXPECT_EQ(restoreAll(plan)[0].outcome, "restored");
    EXPECT_EQ(plaintext("/proj/sub/deep/c.txt"), "gamma\n");
}

TEST_F(RecoveryLocalRestoreTest, MissingBlobsAndDestinationConflictsAreReportedNotWritten) {
    mkdir("/m");
    write("/m/lost.txt", "lost");
    write("/m/dir-later.txt", "file");
    const auto snap = snapshot("/m");
    const auto lost = *member(snap.snapshot_id, "/m/lost.txt");
    std::filesystem::remove(store::open(store::vaultRef(*engine->vault), *lost.blob_id)->path);
    remove("/m/lost.txt");
    remove("/m/dir-later.txt");
    mkdir("/m/dir-later.txt");   // a directory where the file goes

    const auto plan = local::planFor(snapId(snap.snapshot_id));
    const auto* lostItem = itemFor(plan, "/m/lost.txt");
    ASSERT_TRUE(lostItem);
    EXPECT_EQ(lostItem->action, ItemAction::Unavailable);
    EXPECT_NE(std::ranges::find(lostItem->notes, std::string("blob missing")), lostItem->notes.end());
    const auto* dirItem = itemFor(plan, "/m/dir-later.txt");
    ASSERT_TRUE(dirItem);
    EXPECT_EQ(dirItem->action, ItemAction::Conflict);
    EXPECT_EQ(plan.unavailable, 1u);
    EXPECT_EQ(plan.conflicts, 1u);

    const auto outcomes = restoreAll(plan);
    EXPECT_EQ(outcomeFor(outcomes, "/m/lost.txt")->outcome, "unavailable");
    EXPECT_EQ(outcomeFor(outcomes, "/m/dir-later.txt")->outcome, "conflict");
    EXPECT_FALSE(exists("/m/lost.txt"));
    EXPECT_TRUE(isDir("/m/dir-later.txt"));

    const auto point = local::points::get(lvId(lost.id));
    ASSERT_TRUE(point);
    EXPECT_FALSE(point->restorable);
    EXPECT_EQ(point->unavailable_reason, "blob missing");
}

TEST_F(RecoveryLocalRestoreTest, PreSealedContentCommitsThroughCreateFileWithItsRefusals) {
    write("/p.txt", "live");
    const auto live = file("/p.txt");
    // Wrong expected generation: refused, nothing written, the writer never runs.
    bool ran = false;
    const auto writer = [&](const std::filesystem::path& dst) -> fs::SealedContent {
        ran = true;
        std::filesystem::copy_file(live->backing_path, dst);
        return {.encryption_iv = live->encryption_iv, .key_version = live->encrypted_with_key_version,
                .plaintext_size = live->size_bytes, .mime_type = "text/plain"};
    };
    EXPECT_THROW((void)fs::Filesystem::createFile({.path = "/p.txt", .fuse_path = engine->vaultPathToFusePath("/p.txt"),
                                                   .engine = engine, .user = superUser, .overwrite = true,
                                                   .expected_source_id = "not-this-one", .sealed = writer}),
                 fs::ContentConflict);
    EXPECT_FALSE(ran);
    EXPECT_THROW((void)fs::Filesystem::createFile({.path = "/p.txt", .fuse_path = engine->vaultPathToFusePath("/p.txt"),
                                                   .engine = engine, .user = superUser, .overwrite = true,
                                                   .expected_source_id = "", .sealed = writer}),
                 fs::ContentConflict)
        << "\"\" means: only if absent";

    // A new file from sealed bytes: readable at once, same IV, nothing re-encrypted.
    const auto created = fs::Filesystem::createFile({.path = "/p-copy.txt",
                                                     .fuse_path = engine->vaultPathToFusePath("/p-copy.txt"),
                                                     .engine = engine, .user = superUser, .overwrite = true,
                                                     .expected_source_id = "", .sealed = writer});
    ASSERT_TRUE(created);
    EXPECT_TRUE(ran);
    EXPECT_EQ(created->encryption_iv, live->encryption_iv);
    EXPECT_EQ(created->mime_type, "text/plain");
    EXPECT_EQ(plaintext("/p-copy.txt"), "live");

    // A writer that fails leaves the destination as it was.
    const auto failing = [](const std::filesystem::path& dst) -> fs::SealedContent {
        std::ofstream(dst) << "partial";
        throw std::runtime_error("refused");
    };
    EXPECT_THROW((void)fs::Filesystem::createFile({.path = "/p.txt", .fuse_path = engine->vaultPathToFusePath("/p.txt"),
                                                   .engine = engine, .user = superUser, .overwrite = true,
                                                   .expected_source_id = storage::generationOf(*file("/p.txt")).sourceId(),
                                                   .sealed = failing}),
                 std::runtime_error);
    EXPECT_EQ(plaintext("/p.txt"), "live");
    EXPECT_FALSE(std::filesystem::exists(fs::ops::contentSidecarPath(file("/p.txt")->backing_path)));
}

}
