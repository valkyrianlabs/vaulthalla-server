// #158: directory size_bytes / file_count / subdirectory_count are subtree totals kept on every ancestor. Upload and
// mkdir maintained them; move, cross-directory rename, copy and delete did not, so a folder that received a file by
// move showed "0 items" and its old parent still counted the file.

#include "db/Transactions.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/identities/User.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace vh::test_fs_dir_stats {

using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;

std::string dsTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

struct DirStats {
    int64_t size = 0;
    int64_t files = 0;
    int64_t subdirs = 0;

    DirStats operator-(const DirStats& o) const { return {size - o.size, files - o.files, subdirs - o.subdirs}; }
    bool operator==(const DirStats&) const = default;
};

std::ostream& operator<<(std::ostream& os, const DirStats& s) {
    return os << "{size=" << s.size << ", files=" << s.files << ", subdirs=" << s.subdirs << "}";
}

class FsDirStatsDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;

    EnginePtr engine;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_fs_dir_stats] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_fs_dir_stats_" + dsTag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        superUser = vh::identities::manager().userByName("admin");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        const auto vault = ops::vaults::create(superUser, {.name = "ds_" + dsTag(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);
    }

    [[nodiscard]] DirStats stats(const std::string& path) const {
        const auto dir = db::query::fs::Directory::getDirectoryByPath(engine->vault->id, path);
        return {static_cast<int64_t>(dir->size_bytes), static_cast<int64_t>(dir->file_count),
                static_cast<int64_t>(dir->subdirectory_count)};
    }

    void mkdir(const std::string& path) const { engine->mkdir(path, superUser); }

    void write(const std::string& path, const std::size_t bytes) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(bytes, 'd'),
                                                .engine = engine,
                                                .user = superUser}));
    }

    // The totals a directory should carry, recomputed from the entries under it.
    [[nodiscard]] DirStats recomputed(const std::string& path) const {
        DirStats out;
        for (const auto& f : db::query::fs::File::listFilesInDir(engine->vault->id, path, true)) {
            out.size += static_cast<int64_t>(f->size_bytes);
            ++out.files;
        }
        const auto dirId = db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, path);
        out.subdirs = static_cast<int64_t>(db::query::fs::Directory::listDirectoriesInDir(*dirId, true).size());
        return out;
    }

    // fs.dir.list serves directory totals from the fs cache.
    [[nodiscard]] DirStats cachedStats(const std::string& path) const {
        const auto entry = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path));
        if (!entry || !entry->isDirectory()) return {-1, -1, -1};
        const auto dir = std::static_pointer_cast<fs::model::Directory>(entry);
        return {static_cast<int64_t>(dir->size_bytes), static_cast<int64_t>(dir->file_count),
                static_cast<int64_t>(dir->subdirectory_count)};
    }

    void expectConsistent(const std::vector<std::string>& paths) const {
        for (const auto& p : paths) {
            EXPECT_EQ(stats(p), recomputed(p)) << p;
            EXPECT_EQ(cachedStats(p), stats(p)) << p << " (cache)";
        }
    }
};

TEST_F(FsDirStatsDbTest, MovingAFileUpdatesBothParentChains) {
    mkdir("/src");
    mkdir("/dst");
    write("/src/notes.txt", 17);
    const auto rootBefore = stats("/");
    ASSERT_EQ(stats("/src"), (DirStats{17, 1, 0}));
    ASSERT_EQ(stats("/dst"), (DirStats{0, 0, 0}));

    engine->move("/src/notes.txt", "/dst/notes.txt", superUser);

    EXPECT_EQ(stats("/src"), (DirStats{0, 0, 0}));
    EXPECT_EQ(stats("/dst"), (DirStats{17, 1, 0}));
    EXPECT_EQ(stats("/"), rootBefore) << "a move inside the vault doesn't change the root's totals";
    expectConsistent({"/", "/src", "/dst"});
}

TEST_F(FsDirStatsDbTest, RenamingAFileAcrossDirectoriesUpdatesBothChainsAndInPlaceRenameChangesNothing) {
    mkdir("/a");
    mkdir("/a/deep");
    mkdir("/b");
    write("/a/deep/f.bin", 40);
    const auto rootBefore = stats("/");

    engine->rename("/a/deep/f.bin", "/a/deep/g.bin", superUser);
    EXPECT_EQ(stats("/a/deep"), (DirStats{40, 1, 0}));
    EXPECT_EQ(stats("/a"), (DirStats{40, 1, 1}));

    engine->rename("/a/deep/g.bin", "/b/g.bin", superUser);
    EXPECT_EQ(stats("/a/deep"), (DirStats{0, 0, 0}));
    EXPECT_EQ(stats("/a"), (DirStats{0, 0, 1}));
    EXPECT_EQ(stats("/b"), (DirStats{40, 1, 0}));
    EXPECT_EQ(stats("/"), rootBefore);
    expectConsistent({"/", "/a", "/a/deep", "/b"});
}

TEST_F(FsDirStatsDbTest, MovingADirectoryMovesItsSubtreeTotals) {
    mkdir("/from");
    mkdir("/from/sibling");
    mkdir("/from/proj");
    mkdir("/from/proj/inner");
    write("/from/proj/a.txt", 10);
    write("/from/proj/inner/b.txt", 5);
    write("/from/sibling/c.txt", 3);
    mkdir("/to");
    const auto rootBefore = stats("/");
    ASSERT_EQ(stats("/from"), (DirStats{18, 3, 3}));

    engine->move("/from/proj", "/to/proj", superUser);

    EXPECT_EQ(stats("/from"), (DirStats{3, 1, 1}));
    EXPECT_EQ(stats("/to"), (DirStats{15, 2, 2}));
    EXPECT_EQ(stats("/to/proj"), (DirStats{15, 2, 1}));
    EXPECT_EQ(stats("/to/proj/inner"), (DirStats{5, 1, 0}));
    EXPECT_EQ(stats("/"), rootBefore);

    // The subtree itself moved: paths and backing files follow the directory.
    const auto moved = db::query::fs::File::listFilesInDir(engine->vault->id, "/to/proj", true);
    ASSERT_EQ(moved.size(), 2u);
    for (const auto& f : moved) {
        EXPECT_TRUE(f->path.string().starts_with("/to/proj/")) << f->path;
        EXPECT_TRUE(std::filesystem::exists(f->backing_path)) << f->backing_path;
    }
    EXPECT_TRUE(db::query::fs::File::listFilesInDir(engine->vault->id, "/from/proj", true).empty());
    expectConsistent({"/", "/from", "/from/sibling", "/to", "/to/proj", "/to/proj/inner"});
}

TEST_F(FsDirStatsDbTest, CopyAddsToTheDestinationChain) {
    mkdir("/orig");
    mkdir("/copies");
    write("/orig/x.txt", 21);
    const auto rootBefore = stats("/");

    engine->copy("/orig/x.txt", "/copies/x.txt", superUser->id);

    EXPECT_EQ(stats("/orig"), (DirStats{21, 1, 0}));
    EXPECT_EQ(stats("/copies"), (DirStats{21, 1, 0}));
    EXPECT_EQ(stats("/") - rootBefore, (DirStats{21, 1, 0}));
    expectConsistent({"/", "/orig", "/copies"});
}

TEST_F(FsDirStatsDbTest, DeleteRemovesFromTheParentChain) {
    mkdir("/keep");
    mkdir("/keep/trash");
    mkdir("/keep/trash/empty");
    write("/keep/stay.txt", 5);
    write("/keep/one.txt", 7);
    write("/keep/trash/two.txt", 9);
    write("/keep/trash/three.txt", 11);
    const auto rootBefore = stats("/");
    ASSERT_EQ(stats("/keep"), (DirStats{32, 4, 2}));

    engine->remove("/keep/one.txt", superUser->id);
    EXPECT_EQ(stats("/keep"), (DirStats{25, 3, 2}));
    EXPECT_EQ(stats("/") - rootBefore, (DirStats{-7, -1, 0}));

    // The directory and the empty one under it both go.
    engine->remove("/keep/trash", superUser->id);
    EXPECT_FALSE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/keep/trash"));
    EXPECT_EQ(stats("/keep"), (DirStats{5, 1, 0}));
    EXPECT_EQ(stats("/") - rootBefore, (DirStats{-27, -3, -2}));
    expectConsistent({"/", "/keep"});
}

// A directory without files used to stay in the database after fs.entry.delete removed its backing directory.
TEST_F(FsDirStatsDbTest, DeletingEmptyDirectoriesRemovesThemAndTheirCounts) {
    mkdir("/holder");
    mkdir("/holder/empty");
    mkdir("/holder/nest");
    mkdir("/holder/nest/inner");
    write("/holder/keep.txt", 3);
    const auto rootBefore = stats("/");

    engine->remove("/holder/empty", superUser->id);
    EXPECT_FALSE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/holder/empty"));
    EXPECT_EQ(stats("/holder"), (DirStats{3, 1, 2}));

    engine->remove("/holder/nest", superUser->id);
    EXPECT_FALSE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/holder/nest/inner"));
    EXPECT_EQ(stats("/holder"), (DirStats{3, 1, 0}));
    EXPECT_EQ(stats("/") - rootBefore, (DirStats{0, 0, -3}));
    expectConsistent({"/", "/holder"});
}

// fs.entry.copy of a directory copies everything under it (#167), so the copy carries the source's totals, built up
// entry by entry (it used to copy only the folder row, which then had to start at zero).
TEST_F(FsDirStatsDbTest, DirectoryCopyCarriesItsSubtreeTotals) {
    mkdir("/srcdir");
    mkdir("/srcdir/inner");
    write("/srcdir/f.txt", 12);
    write("/srcdir/inner/g.txt", 30);
    const auto rootBefore = stats("/");

    engine->copy("/srcdir", "/dircopy", superUser->id);

    EXPECT_EQ(stats("/dircopy"), (DirStats{42, 2, 1}));
    EXPECT_EQ(stats("/dircopy/inner"), (DirStats{30, 1, 0}));
    EXPECT_EQ(stats("/") - rootBefore, (DirStats{42, 2, 2}));
    expectConsistent({"/", "/srcdir", "/dircopy", "/dircopy/inner"});
}

// #168: deleting a file never removes the folder it was in, nor that folder's ancestors, including folders the user
// made. It used to remove every ancestor left without a file (ws, gateway and sync deletes; FUSE unlink did not), so
// the console and the mount disagreed.
TEST_F(FsDirStatsDbTest, DeletingTheLastFileKeepsItsFolders) {
    mkdir("/Projects");
    mkdir("/Projects/2026");
    write("/Projects/2026/report.txt", 9);
    const auto rootBefore = stats("/");

    engine->remove("/Projects/2026/report.txt", superUser->id);

    ASSERT_TRUE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/Projects/2026"));
    ASSERT_TRUE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/Projects"));
    EXPECT_EQ(stats("/Projects/2026"), (DirStats{0, 0, 0}));
    EXPECT_EQ(stats("/Projects"), (DirStats{0, 0, 1}));
    EXPECT_EQ(stats("/") - rootBefore, (DirStats{-9, -1, 0}));
    const auto folder = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath("/Projects/2026"));
    ASSERT_TRUE(folder);
    EXPECT_TRUE(std::filesystem::is_directory(folder->backing_path)) << "its backing directory stays too";
    expectConsistent({"/", "/Projects", "/Projects/2026"});

    // A folder still goes when it is what's deleted.
    engine->remove("/Projects", superUser->id);
    EXPECT_FALSE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/Projects/2026"));
    EXPECT_EQ(stats("/") - rootBefore, (DirStats{-9, -1, -2}));
    expectConsistent({"/"});
}

// FUSE unlink trashes through File::markFileAsTrashed and rmdir through Directory::deleteEmptyDirectory.
TEST_F(FsDirStatsDbTest, FuseUnlinkKeepsFoldersAndRmdirRefusesANonEmptyOne) {
    mkdir("/a");
    mkdir("/a/b");
    mkdir("/a/b/c");
    write("/a/b/c/f.txt", 4);
    const auto rootBefore = stats("/");

    db::query::fs::File::markFileAsTrashed(superUser->id, engine->vault->id, "/a/b/c/f.txt");
    ASSERT_TRUE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/a/b/c"));
    EXPECT_EQ(stats("/a"), (DirStats{0, 0, 2}));

    // rmdir of a folder with something under it is ENOTEMPTY; it used to drop the folder and all it held.
    const auto b = db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/a/b");
    const auto c = db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/a/b/c");
    ASSERT_TRUE(b && c);
    EXPECT_FALSE(db::query::fs::Directory::deleteEmptyDirectory(*b));
    EXPECT_TRUE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/a/b/c"));

    // An empty one goes, off every ancestor's count (it used to decrement only its parent).
    EXPECT_TRUE(db::query::fs::Directory::deleteEmptyDirectory(*c));
    EXPECT_FALSE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/a/b/c"));
    EXPECT_EQ(stats("/a"), (DirStats{0, 0, 1}));
    EXPECT_EQ(stats("/") - rootBefore, (DirStats{-4, -1, -1}));
    for (const std::string p : {"/", "/a", "/a/b"}) EXPECT_EQ(stats(p), recomputed(p)) << p;
}

// The sync pass (cloud DeleteLocal / mirror) and the S3 gateway's local purge delete files the same way.
TEST_F(FsDirStatsDbTest, SyncAndGatewayDeletesKeepFolders) {
    mkdir("/m");
    mkdir("/m/n");
    write("/m/n/one.txt", 6);
    write("/m/n/two.txt", 8);
    const auto one = db::query::fs::File::getFileByPath(engine->vault->id, "/m/n/one.txt");
    ASSERT_TRUE(one && std::filesystem::exists(one->backing_path));

    engine->removeLocally("/m/n/one.txt");
    EXPECT_FALSE(std::filesystem::exists(one->backing_path)) << "the file's own (alias) backing path is removed";
    EXPECT_EQ(db::query::fs::File::getFileByPath(engine->vault->id, "/m/n/one.txt"), nullptr);

    protocols::s3::ObjectStore().purgeLocalObjectState(engine, "/m/n/two.txt", superUser->id);

    ASSERT_TRUE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/m/n"));
    EXPECT_TRUE(std::filesystem::is_directory(one->backing_path.parent_path()));
    EXPECT_EQ(stats("/m"), (DirStats{0, 0, 1}));
    expectConsistent({"/", "/m", "/m/n"});
}

// The ancestor walk is one statement now; an overwrite that shrinks a file must still take the (signed) difference
// off every level, not just the parent.
TEST_F(FsDirStatsDbTest, ShrinkingOverwriteTakesTheDifferenceOffEveryAncestor) {
    mkdir("/s1");
    mkdir("/s1/s2");
    mkdir("/s1/s2/s3");
    write("/s1/s2/s3/f.bin", 100);
    const auto rootBefore = stats("/");
    ASSERT_EQ(stats("/s1"), (DirStats{100, 1, 2}));

    ASSERT_TRUE(fs::Filesystem::createFile({.path = "/s1/s2/s3/f.bin",
                                            .fuse_path = engine->vaultPathToFusePath("/s1/s2/s3/f.bin"),
                                            .buffer = std::vector<uint8_t>(30, 's'),
                                            .engine = engine,
                                            .user = superUser,
                                            .overwrite = true}));
    EXPECT_EQ(stats("/s1/s2/s3"), (DirStats{30, 1, 0}));
    EXPECT_EQ(stats("/s1/s2"), (DirStats{30, 1, 1}));
    EXPECT_EQ(stats("/s1"), (DirStats{30, 1, 2}));
    EXPECT_EQ(stats("/") - rootBefore, (DirStats{-70, 0, 0}));
    expectConsistent({"/", "/s1", "/s1/s2", "/s1/s2/s3"});
}

// readdir serves a directory from the fs cache's parent->children index when it accounts for every entry the
// database holds there; after a move each side lists exactly what the database does.
TEST_F(FsDirStatsDbTest, CachedListingMatchesTheDatabaseAcrossMoves) {
    mkdir("/l1");
    mkdir("/l2");
    mkdir("/l1/sub");
    write("/l1/a.txt", 3);
    write("/l1/b.txt", 4);
    write("/l1/sub/c.txt", 5);

    const auto cache = runtime::Deps::get().fsCache;
    const auto idsOf = [](const std::vector<std::shared_ptr<fs::model::Entry>>& entries) {
        std::vector<unsigned int> ids;
        for (const auto& e : entries) ids.push_back(e->id);
        std::ranges::sort(ids);
        return ids;
    };
    const auto check = [&](const std::string& path) {
        const auto dirId = db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, path);
        ASSERT_TRUE(dirId) << path;
        EXPECT_EQ(idsOf(cache->listDir(*dirId)), idsOf(db::query::fs::Entry::listDir(*dirId, false))) << path;
        EXPECT_EQ(idsOf(cache->listDir(*dirId, true)), idsOf(db::query::fs::Entry::listSubtree(*dirId))) << path << " (recursive)";
    };

    check("/l1");
    check("/l2");
    engine->move("/l1/a.txt", "/l2/a.txt", superUser);
    check("/l1");
    check("/l2");
    engine->rename("/l1/sub", "/l2/sub", superUser);
    check("/l1");
    check("/l2");
    EXPECT_THROW((void)cache->listDir(db::query::fs::File::getFileByPath(engine->vault->id, "/l1/b.txt")->id),
                 std::runtime_error) << "a file is not a directory";
}

}
