// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// A FUSE rename onto an existing name (how vim, LibreOffice and most IDEs save: write a temp file, rename(2) it over
// the target) failed with EIO: Filesystem::rename updated the source row onto (parent_id, name) the target still held
// and hit UNIQUE(parent_id, name), after already mutating the cached source entry in place. The target is now
// replaced the way POSIX rename replaces it: its old content goes exactly as an unlink would take it (trashed, backing
// bytes and derived artifacts removed), and the source takes its place, in one transaction.

#include "db/Transactions.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "fs/model/file/Trashed.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Controller.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <ostream>
#include <string>
#include <vector>

namespace vh::test_fs_rename {

using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;

std::string rnTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "r" + std::to_string(n.fetch_add(1));
}

struct Totals {
    int64_t size = 0;
    int64_t files = 0;
    int64_t subdirs = 0;

    Totals operator-(const Totals& o) const { return {size - o.size, files - o.files, subdirs - o.subdirs}; }
    bool operator==(const Totals&) const = default;
};

std::ostream& operator<<(std::ostream& os, const Totals& s) {
    return os << "{size=" << s.size << ", files=" << s.files << ", subdirs=" << s.subdirs << "}";
}

class FsRenameDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    EnginePtr engine;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_fs_rename] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_fs_rename_" + rnTag());
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
        // Earlier suites in this binary used their own schema: start from a fresh cache and fresh engines.
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = vh::identities::manager().userByName("admin");

        previousController = runtime::Deps::get().syncController;
        runtime::Deps::setSyncController(std::make_shared<sync::Controller>());
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        runtime::Deps::setSyncController(previousController);
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        const auto vault = ops::vaults::create(superUser, {.name = "rn_" + rnTag(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);
    }

    [[nodiscard]] std::filesystem::path fuseAt(const std::string& path) const { return engine->vaultPathToFusePath(path); }

    void mkdir(const std::string& path) const { engine->mkdir(path, superUser); }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = fuseAt(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    // Exactly what the FUSE rename handler calls for rename(2) without flags once the caller may delete the existing
    // destination (Bridge.cpp checks Delete on it, as unlink does).
    [[nodiscard]] int fuseRename(const std::string& from, const std::string& to) const {
        return fs::Filesystem::rename(fuseAt(from), fuseAt(to), superUser, nullptr, fs::RenameMode::Replace);
    }

    // ws rename/move and uploads: no mode, so an existing destination is refused.
    [[nodiscard]] int plainRename(const std::string& from, const std::string& to) const {
        return fs::Filesystem::rename(fuseAt(from), fuseAt(to), superUser);
    }

    [[nodiscard]] std::shared_ptr<fs::model::File> file(const std::string& path) const {
        return db::query::fs::File::getFileByPath(engine->vault->id, path);
    }

    [[nodiscard]] std::shared_ptr<fs::model::Entry> cached(const std::string& path) const {
        return runtime::Deps::get().fsCache->getEntry(fuseAt(path));
    }

    [[nodiscard]] bool exists(const std::string& path) const {
        return runtime::Deps::get().fsCache->entryExists(fuseAt(path));
    }

    [[nodiscard]] std::string plaintext(const std::string& path) const {
        const auto f = file(path);
        if (!f) return "<missing>";
        auto reader = engine->openPlaintextReader(f);
        const auto bytes = storage::readAll(*reader, 64u << 20);
        return {bytes.begin(), bytes.end()};
    }

    [[nodiscard]] Totals totals(const std::string& path) const {
        const auto dir = db::query::fs::Directory::getDirectoryByPath(engine->vault->id, path);
        return {static_cast<int64_t>(dir->size_bytes), static_cast<int64_t>(dir->file_count),
                static_cast<int64_t>(dir->subdirectory_count)};
    }

    [[nodiscard]] Totals cachedTotals(const std::string& path) const {
        const auto entry = cached(path);
        if (!entry || !entry->isDirectory()) return {-1, -1, -1};
        const auto dir = std::static_pointer_cast<fs::model::Directory>(entry);
        return {static_cast<int64_t>(dir->size_bytes), static_cast<int64_t>(dir->file_count),
                static_cast<int64_t>(dir->subdirectory_count)};
    }

    [[nodiscard]] std::size_t rowsNamed(const std::string& path) const {
        std::size_t n = 0;
        for (const auto& e : db::query::fs::Entry::listSubtree(cached("/")->id))
            if (e->path == path) ++n;
        return n;
    }

    [[nodiscard]] std::size_t trashedAt(const std::string& path, const std::string& alias) const {
        std::size_t n = 0;
        for (const auto& t : db::query::fs::File::listTrashedFiles(engine->vault->id))
            if (t->path == path && t->base32_alias == alias) ++n;
        return n;
    }

    [[nodiscard]] static std::size_t entriesUnder(const std::filesystem::path& dir) {
        std::size_t n = 0;
        std::error_code ec;
        for (auto it = std::filesystem::recursive_directory_iterator(dir, ec);
             !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
            ++n;
        return n;
    }

    // Everything the replace must leave true, for `from` renamed over `to` in folders `fromDir` / `toDir`.
    void expectReplaced(const std::shared_ptr<fs::model::File>& source, const std::shared_ptr<fs::model::File>& target,
                        const std::string& to, const std::string& content) const {
        // The source took the target's name: same row, same inode, same sealed bytes.
        const auto now = file(to);
        ASSERT_TRUE(now);
        EXPECT_EQ(now->id, source->id);
        EXPECT_EQ(plaintext(to), content);
        EXPECT_EQ(now->size_bytes, content.size());
        EXPECT_EQ(rowsNamed(to), 1u) << "exactly one entry at " << to;

        // The target's old content went the way unlink takes it: row gone, trashed, bytes gone.
        EXPECT_FALSE(db::query::fs::File::getFileById(target->id)) << "the replaced row must be gone";
        EXPECT_EQ(trashedAt(to, target->base32_alias), 1u) << "the replaced file is in the trash, like an unlink";
        EXPECT_FALSE(std::filesystem::exists(target->backing_path)) << "no orphan backing file";
        ASSERT_TRUE(std::filesystem::exists(now->backing_path));

        // The cache answers with the moved entry, at the new path, for both the path and the inode.
        const auto entry = cached(to);
        ASSERT_TRUE(entry);
        EXPECT_EQ(entry->id, source->id);
        EXPECT_EQ(entry->fuse_path, fuseAt(to));
        EXPECT_EQ(entry->backing_path, now->backing_path);
        ASSERT_TRUE(source->inode);
        const auto byInode = runtime::Deps::get().fsCache->getEntry(static_cast<fs::Inode>(*source->inode));
        ASSERT_TRUE(byInode);
        EXPECT_EQ(byInode->fuse_path, fuseAt(to));
    }
};

TEST_F(FsRenameDbTest, RenameOverAnExistingFileReplacesItLikeAnEditorSave) {
    write("/a.txt", "alpha original\n");
    write("/b.txt", "bravo\n");
    const auto a = file("/a.txt");
    const auto b = file("/b.txt");
    ASSERT_TRUE(a && b);
    const auto rootBefore = totals("/");
    const auto onDiskBefore = entriesUnder(cached("/")->backing_path);

    ASSERT_EQ(fuseRename("/b.txt", "/a.txt"), 0);

    expectReplaced(b, a, "/a.txt", "bravo\n");
    EXPECT_FALSE(file("/b.txt"));
    EXPECT_FALSE(exists("/b.txt"));
    EXPECT_EQ(totals("/") - rootBefore, (Totals{-static_cast<int64_t>(a->size_bytes), -1, 0}));
    EXPECT_EQ(cachedTotals("/"), totals("/"));
    EXPECT_EQ(entriesUnder(cached("/")->backing_path), onDiskBefore - 1);

    // The new content is a regular file again: it can be replaced the same way (a second save).
    write("/a.txt.swp", "third\n");
    ASSERT_EQ(fuseRename("/a.txt.swp", "/a.txt"), 0);
    EXPECT_EQ(plaintext("/a.txt"), "third\n");
    EXPECT_EQ(rowsNamed("/a.txt"), 1u);
    EXPECT_EQ(cachedTotals("/"), totals("/"));
}

TEST_F(FsRenameDbTest, RenameOverAnExistingFileInAnotherFolder) {
    mkdir("/src");
    mkdir("/dst");
    write("/src/x.txt", "new bytes, longer\n");
    write("/dst/x.txt", "old\n");
    const auto source = file("/src/x.txt");
    const auto target = file("/dst/x.txt");
    ASSERT_TRUE(source && target);
    const auto srcBefore = totals("/src");
    const auto dstBefore = totals("/dst");
    const auto rootBefore = totals("/");

    ASSERT_EQ(fuseRename("/src/x.txt", "/dst/x.txt"), 0);

    expectReplaced(source, target, "/dst/x.txt", "new bytes, longer\n");
    EXPECT_FALSE(exists("/src/x.txt"));
    EXPECT_EQ(totals("/src") - srcBefore, (Totals{-static_cast<int64_t>(source->size_bytes), -1, 0}));
    EXPECT_EQ(totals("/dst") - dstBefore,
              (Totals{static_cast<int64_t>(source->size_bytes) - static_cast<int64_t>(target->size_bytes), 0, 0}));
    EXPECT_EQ(totals("/") - rootBefore, (Totals{-static_cast<int64_t>(target->size_bytes), -1, 0}));
    for (const std::string p : {"/", "/src", "/dst"}) EXPECT_EQ(cachedTotals(p), totals(p)) << p << " (cache)";
}

TEST_F(FsRenameDbTest, WithoutReplaceAnExistingDestinationIsRefusedAndNothingChanges) {
    mkdir("/src");
    write("/a.txt", "alpha\n");
    write("/src/a.txt", "other\n");
    const auto rootBefore = totals("/");

    EXPECT_EQ(plainRename("/src/a.txt", "/a.txt"), -EEXIST);
    EXPECT_EQ(plaintext("/a.txt"), "alpha\n");
    EXPECT_EQ(plaintext("/src/a.txt"), "other\n");
    EXPECT_EQ(cached("/src/a.txt")->fuse_path, fuseAt("/src/a.txt")) << "the cached source is untouched";
    EXPECT_EQ(totals("/"), rootBefore);
}

// rename(2)'s type rules, checked before anything changes; an empty folder is replaced like rmdir would remove it.
TEST_F(FsRenameDbTest, ReplacingFollowsRenameTypeRules) {
    mkdir("/dir");
    mkdir("/full");
    mkdir("/empty");
    write("/full/x.txt", "x\n");
    write("/dir/y.txt", "y\n");
    write("/f.txt", "f\n");

    EXPECT_EQ(fuseRename("/f.txt", "/dir"), -EISDIR);
    EXPECT_EQ(fuseRename("/dir", "/f.txt"), -ENOTDIR);
    EXPECT_EQ(fuseRename("/dir", "/full"), -ENOTEMPTY);
    EXPECT_EQ(fuseRename("/dir", "/dir/inner"), -EINVAL);
    EXPECT_EQ(plaintext("/f.txt"), "f\n");
    EXPECT_EQ(plaintext("/full/x.txt"), "x\n");
    EXPECT_EQ(plaintext("/dir/y.txt"), "y\n");

    const auto rootBefore = totals("/");
    const auto emptyDir = cached("/empty");
    ASSERT_TRUE(emptyDir);
    ASSERT_EQ(fuseRename("/dir", "/empty"), 0);
    EXPECT_EQ(plaintext("/empty/y.txt"), "y\n");
    EXPECT_FALSE(exists("/dir"));
    EXPECT_FALSE(exists("/dir/y.txt"));
    EXPECT_EQ(rowsNamed("/empty"), 1u);
    EXPECT_EQ(cached("/empty")->id, cached("/empty/y.txt")->parent_id.value_or(0));
    EXPECT_FALSE(std::filesystem::exists(emptyDir->backing_path));
    EXPECT_EQ(totals("/") - rootBefore, (Totals{0, 0, -1}));
    for (const std::string p : {"/", "/empty"}) EXPECT_EQ(cachedTotals(p), totals(p)) << p << " (cache)";
}

// A rename that fails part-way changes nothing: the transaction rolls back and so do the backing moves, and the
// cached entries never saw the new paths. It used to leave a file's bytes at the destination (unreadable at its
// recorded path) and the cached source claiming the destination path.
TEST_F(FsRenameDbTest, AFailedRenameLeavesEverythingWhereItWas) {
    mkdir("/d");
    mkdir("/d/sub");
    write("/d/one.txt", "one\n");
    write("/d/sub/two.txt", "two\n");
    const auto rootBacking = cached("/")->backing_path;
    // The deeper file's bytes are gone: the rename reaches it after moving the folder and one.txt.
    std::filesystem::remove(file("/d/sub/two.txt")->backing_path);
    const auto onDiskBefore = entriesUnder(rootBacking);
    const auto rootBefore = totals("/");

    EXPECT_EQ(fuseRename("/d/sub", "/moved"), -ENOENT);
    EXPECT_EQ(fuseRename("/d", "/d2"), -ENOENT);

    EXPECT_EQ(plaintext("/d/one.txt"), "one\n");
    EXPECT_EQ(cached("/d/one.txt")->fuse_path, fuseAt("/d/one.txt"));
    EXPECT_EQ(cached("/d")->fuse_path, fuseAt("/d"));
    EXPECT_FALSE(exists("/d2"));
    EXPECT_FALSE(exists("/moved"));
    EXPECT_FALSE(file("/d2/one.txt"));
    EXPECT_EQ(entriesUnder(rootBacking), onDiskBefore) << "no folder or file left behind at the destination";
    EXPECT_EQ(totals("/"), rootBefore);
    EXPECT_EQ(cachedTotals("/"), totals("/"));
}

}
