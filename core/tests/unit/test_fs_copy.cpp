// #167: fs.entry.copy of a directory copied only the folder row, and a copied file got a row but no bytes: the sync
// pass meant to write them was never queued (the operations table only records activity) and looked in the
// pre-alias BACKING_VAULT_ROOT/<vault path> layout anyway. A copy is now deep, readable at once at the alias backing
// layout every other path uses, checked per entry, and all-or-nothing.

#include "db/Transactions.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Symlink.hpp"
#include "db/query/identities/User.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Controller.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <ostream>
#include <random>
#include <stdexcept>
#include <string>
#include <vector>

namespace vh::test_fs_copy {

using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;

std::string cpTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "c" + std::to_string(n.fetch_add(1));
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

std::string randomText(const std::size_t n, const unsigned seed) {
    std::mt19937 rng(seed);
    std::string out(n, '\0');
    for (auto& c : out) c = static_cast<char>('a' + rng() % 26);
    return out;
}

class FsCopyDbTest : public ::testing::Test {
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
            std::cout << "[test_fs_copy] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_fs_copy_" + cpTag());
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
        // Earlier suites in this binary used their own schema: their cached entries and engines (ids reused after the
        // reset) would answer for ours, and the sync controller asserts on engines of vaults that no longer exist.
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = vh::identities::manager().userByName("admin");

        // The ws handler asks the sync controller for an early pass; an unstarted one just queues it.
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
        const auto vault = ops::vaults::create(superUser, {.name = "cp_" + cpTag(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);
    }

    void mkdir(const std::string& path) const { engine->mkdir(path, superUser); }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    // A symlink as FUSE symlink(2) records it: a row plus a backing symlink at the alias layout.
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
        link->base32_alias = "link" + cpTag();
        link->backing_path = parent->backing_path / link->base32_alias;
        link->mode = 0777;
        link->created_by = link->last_modified_by = static_cast<int32_t>(superUser->id);
        link->inode = cache->getOrAssignInode(fusePath);
        link->size_bytes = target.size();
        std::filesystem::create_symlink(target, link->backing_path);
        link->id = db::query::fs::Symlink::upsertSymlink(link);
        cache->cacheEntry(link);
    }

    [[nodiscard]] std::shared_ptr<fs::model::File> file(const std::string& path) const {
        return db::query::fs::File::getFileByPath(engine->vault->id, path);
    }

    [[nodiscard]] bool exists(const std::string& path) const {
        return runtime::Deps::get().fsCache->entryExists(engine->vaultPathToFusePath(path));
    }

    // What every byte consumer (download, preview, FUSE open) reads: authenticated plaintext from the backing file.
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
        const auto entry = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path));
        if (!entry || !entry->isDirectory()) return {-1, -1, -1};
        const auto dir = std::static_pointer_cast<fs::model::Directory>(entry);
        return {static_cast<int64_t>(dir->size_bytes), static_cast<int64_t>(dir->file_count),
                static_cast<int64_t>(dir->subdirectory_count)};
    }

    [[nodiscard]] std::shared_ptr<fs::model::Entry> entry(const std::string& path) const {
        return runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path));
    }

    [[nodiscard]] static std::size_t entriesUnder(const std::filesystem::path& dir) {
        std::size_t n = 0;
        std::error_code ec;
        for (auto it = std::filesystem::recursive_directory_iterator(dir, ec);
             !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
            ++n;
        return n;
    }

    // The nested fixture the acceptance test copies: files at three depths, an empty folder, a hidden file and a
    // symlink, plus a file large enough to span many GCM blocks.
    void buildTree() const {
        mkdir("/proj");
        mkdir("/proj/sub");
        mkdir("/proj/sub/deep");
        mkdir("/proj/empty");
        write("/proj/a.txt", "alpha\n");
        write("/proj/sub/b.bin", randomText(70'001, 7));
        write("/proj/sub/deep/c.txt", "gamma\n");
        write("/proj/sub/.hidden", "dot\n");
        write("/proj/zero.txt", "");
        symlink("/proj/link", "a.txt");
    }

    static std::shared_ptr<protocols::ws::Session> wsAs(const UserPtr& user) {
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->user = user;
        return session;
    }

    [[nodiscard]] nlohmann::json copyPayload(const std::string& from, const std::string& to) const {
        return {{"vault_id", engine->vault->id}, {"from", from}, {"to", to}};
    }

    [[nodiscard]] UserPtr userWithVaultRole(const std::string& role) const {
        const auto created = ops::users::create(superUser, {.name = "cp_user_" + cpTag(), .role = "unprivileged",
                                                            .password = std::string("Copy-Test-Pass-123")});
        (void)ops::roles::assignVaultRole(superUser, {.target = {.vault_id = engine->vault->id,
                                                                 .subject = {.type = "user", .id = created.user->id}},
                                                      .role = role});
        return vh::identities::manager().user(created.user->id);
    }
};

TEST_F(FsCopyDbTest, FileCopyIsReadableAtOnceAtTheAliasLayout) {
    mkdir("/orig");
    mkdir("/dst");
    write("/orig/x.txt", "hello copy\n");
    const auto original = file("/orig/x.txt");
    ASSERT_TRUE(original);
    ASSERT_FALSE(original->encryption_iv.empty()) << "bytes are sealed at rest";

    engine->copy("/orig/x.txt", "/dst/x.txt", superUser->id);

    const auto copied = file("/dst/x.txt");
    ASSERT_TRUE(copied);
    EXPECT_NE(copied->id, original->id);
    EXPECT_NE(copied->base32_alias, original->base32_alias);

    // Bytes on disk now, at <destination folder backing>/<alias>, like every other file (no sync pass needed).
    const auto dstDir = entry("/dst");
    ASSERT_TRUE(dstDir);
    EXPECT_EQ(copied->backing_path, dstDir->backing_path / copied->base32_alias);
    ASSERT_TRUE(std::filesystem::is_regular_file(copied->backing_path));
    EXPECT_EQ(std::filesystem::file_size(copied->backing_path), std::filesystem::file_size(original->backing_path));
    EXPECT_EQ(plaintext("/dst/x.txt"), "hello copy\n");
    EXPECT_EQ(copied->size_bytes, original->size_bytes);
    EXPECT_EQ(copied->content_hash, original->content_hash);
    EXPECT_EQ(copied->encryption_iv, original->encryption_iv) << "the sealed bytes travel with their IV";
    EXPECT_EQ(copied->encrypted_with_key_version, original->encrypted_with_key_version);

    // The cached entry (what FUSE and listings use) carries the same row.
    const auto cached = std::dynamic_pointer_cast<fs::model::File>(entry("/dst/x.txt"));
    ASSERT_TRUE(cached);
    EXPECT_EQ(cached->backing_path, copied->backing_path);
    EXPECT_EQ(cached->encryption_iv, copied->encryption_iv);

    // A write to either file draws a fresh IV: the shared (key, IV) pair only ever sealed this one plaintext.
    write("/dst/x.txt", "changed\n");
    EXPECT_NE(file("/dst/x.txt")->encryption_iv, original->encryption_iv);
    EXPECT_EQ(plaintext("/dst/x.txt"), "changed\n");
    EXPECT_EQ(plaintext("/orig/x.txt"), "hello copy\n");
}

// The acceptance shape at the unit level: copy a nested folder, then read every file of the copy.
TEST_F(FsCopyDbTest, DirectoryCopyCopiesTheWholeSubtreeWithItsTotals) {
    buildTree();
    const auto rootBefore = totals("/");
    const auto source = totals("/proj");
    ASSERT_EQ(source.subdirs, 3);

    engine->copy("/proj", "/copy", superUser->id);

    for (const std::string rel : {"/a.txt", "/sub/b.bin", "/sub/deep/c.txt", "/sub/.hidden", "/zero.txt"}) {
        ASSERT_TRUE(file("/copy" + rel)) << rel;
        EXPECT_EQ(plaintext("/copy" + rel), plaintext("/proj" + rel)) << rel;
        EXPECT_NE(file("/copy" + rel)->id, file("/proj" + rel)->id) << rel;
    }
    EXPECT_TRUE(db::query::fs::Directory::getDirectoryIdByPath(engine->vault->id, "/copy/empty")) << "empty folders too";
    const auto link = std::dynamic_pointer_cast<fs::model::Symlink>(entry("/copy/link"));
    ASSERT_TRUE(link);
    EXPECT_EQ(link->target, "a.txt");
    EXPECT_EQ(std::filesystem::read_symlink(link->backing_path), "a.txt");

    // Every copied entry sits at its destination parent's backing path / its own alias.
    for (const std::string rel : {"/a.txt", "/sub", "/sub/b.bin", "/sub/deep", "/sub/deep/c.txt", "/empty", "/link"}) {
        const auto e = entry("/copy" + rel);
        ASSERT_TRUE(e) << rel;
        const auto parent = entry(std::filesystem::path("/copy" + rel).parent_path().string());
        ASSERT_TRUE(parent) << rel;
        EXPECT_EQ(e->backing_path, parent->backing_path / e->base32_alias) << rel;
        EXPECT_TRUE(std::filesystem::exists(std::filesystem::symlink_status(e->backing_path))) << rel;
    }

    // Totals: the copy holds what the source holds, and every ancestor gained exactly that plus the folder itself.
    EXPECT_EQ(totals("/copy"), source);
    EXPECT_EQ(totals("/copy/sub"), totals("/proj/sub"));
    EXPECT_EQ(totals("/copy/sub/deep"), totals("/proj/sub/deep"));
    EXPECT_EQ(totals("/") - rootBefore, (Totals{source.size, source.files, source.subdirs + 1}));
    for (const std::string p : {"/", "/copy", "/copy/sub", "/copy/sub/deep", "/copy/empty"})
        EXPECT_EQ(cachedTotals(p), totals(p)) << p << " (cache)";

    // The source is untouched, and the copy is independent of it.
    EXPECT_EQ(totals("/proj"), source);
    engine->remove("/proj", superUser->id);
    EXPECT_EQ(plaintext("/copy/sub/deep/c.txt"), "gamma\n");
}

// What the copy plans from, and what the cache falls back to for a recursive listing (a directory rename): every
// depth. Entry::listDir(id, true) recursed through files and returned only direct child files and symlinks, and the
// cache's own recursive walk stopped at grandchildren.
TEST_F(FsCopyDbTest, SubtreeListingsReachEveryDepth) {
    buildTree();
    const auto proj = entry("/proj");
    ASSERT_TRUE(proj);

    const auto names = [](const std::vector<std::shared_ptr<fs::model::Entry>>& entries) {
        std::vector<std::string> out;
        for (const auto& e : entries) out.push_back(e->path.string());
        std::ranges::sort(out);
        return out;
    };
    const std::vector<std::string> expected{"/proj/a.txt", "/proj/empty", "/proj/link", "/proj/sub", "/proj/sub/.hidden",
                                            "/proj/sub/b.bin", "/proj/sub/deep", "/proj/sub/deep/c.txt", "/proj/zero.txt"};
    EXPECT_EQ(names(db::query::fs::Entry::listSubtree(proj->id)), expected);
    EXPECT_EQ(names(runtime::Deps::get().fsCache->listDir(proj->id, true)), expected);
    for (const auto& e : db::query::fs::Entry::listSubtree(proj->id))
        EXPECT_EQ(e->fuse_path, engine->vaultPathToFusePath(e->path)) << e->path;
}

TEST_F(FsCopyDbTest, AuthorizerSeesEveryEntryAndItsDestinationBeforeAnythingIsWritten) {
    buildTree();
    std::map<std::string, std::string> seen;  // source vault path -> destination vault path
    bool destinationExistedDuringAuthorization = false;
    engine->copy("/proj", "/seen", superUser->id, [&](const fs::model::Entry& source, const std::filesystem::path& dest) {
        seen[source.path.string()] = engine->fusePathToVaultPath(dest).string();
        destinationExistedDuringAuthorization |= exists("/seen");
    });

    EXPECT_FALSE(destinationExistedDuringAuthorization);
    EXPECT_EQ(seen.size(), 10u);  // the folder, 3 subfolders, 5 files, 1 symlink
    EXPECT_EQ(seen["/proj"], "/seen");
    EXPECT_EQ(seen["/proj/sub/deep/c.txt"], "/seen/sub/deep/c.txt");
    EXPECT_EQ(seen["/proj/empty"], "/seen/empty");
    EXPECT_EQ(seen["/proj/link"], "/seen/link");
}

TEST_F(FsCopyDbTest, RefusalsLeaveNothingBehind) {
    buildTree();
    const auto rootBefore = totals("/");
    const auto rootBacking = entry("/")->backing_path;
    const auto onDiskBefore = entriesUnder(rootBacking);

    // Into itself.
    EXPECT_THROW(engine->copy("/proj", "/proj/sub/again", superUser->id), std::runtime_error);
    EXPECT_FALSE(exists("/proj/sub/again"));

    // Onto an existing name.
    EXPECT_THROW(engine->copy("/proj/a.txt", "/proj/zero.txt", superUser->id), std::runtime_error);
    EXPECT_EQ(plaintext("/proj/zero.txt"), "");

    // One entry deep inside refused: the whole copy is refused, before anything is written.
    struct Refused : std::runtime_error { using std::runtime_error::runtime_error; };
    EXPECT_THROW(engine->copy("/proj", "/denied", superUser->id, [](const fs::model::Entry& source, const std::filesystem::path&) {
        if (source.path == "/proj/sub/deep/c.txt") throw Refused("no");
    }), Refused);
    EXPECT_FALSE(exists("/denied"));

    // Over the vault's quota: refused up front, with the reason.
    const auto quota = engine->vault->quota;
    engine->vault->quota = 1;
    try {
        engine->copy("/proj", "/full", superUser->id);
        ADD_FAILURE() << "a copy over quota must be refused";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("quota"), std::string::npos) << e.what();
    }
    engine->vault->quota = quota;
    EXPECT_FALSE(exists("/full"));

    // A symlink whose relative target would leave the vault from its new depth.
    mkdir("/l1");
    mkdir("/l1/l2");
    symlink("/l1/l2/up", "../../a.txt");
    EXPECT_NO_THROW(engine->copy("/l1/l2/up", "/l1/l2/up2", superUser->id));
    EXPECT_THROW(engine->copy("/l1/l2/up", "/up3", superUser->id), std::runtime_error);
    EXPECT_FALSE(exists("/up3"));

    EXPECT_EQ(totals("/") - rootBefore, (Totals{static_cast<int64_t>(std::string("../../a.txt").size()) * 2, 2, 2}))
        << "only /l1, /l1/l2 and the two links were added";
    EXPECT_EQ(entriesUnder(rootBacking), onDiskBefore + 4) << "no staged bytes left behind";
}

// fs.entry.copy checks every entry the way a single one is checked: Copy and (for a file) Read on the source, and
// creating it at the destination (Write for a file, Touch for a folder).
TEST_F(FsCopyDbTest, WsCopyAuthorizesEveryEntryForTheCaller) {
    buildTree();

    // Admin: allowed, deep.
    (void)protocols::ws::handler::fs::Storage::copy(copyPayload("/proj", "/by_admin"), wsAs(superUser));
    EXPECT_EQ(plaintext("/by_admin/sub/deep/c.txt"), "gamma\n");

    // reader: may copy and download but not create anything, so it can't copy anywhere.
    const auto reader = userWithVaultRole("reader");
    EXPECT_THROW((void)protocols::ws::handler::fs::Storage::copy(copyPayload("/proj/a.txt", "/by_reader.txt"), wsAs(reader)),
                 std::runtime_error);
    EXPECT_FALSE(exists("/by_reader.txt"));

    // power_user: every entry passes (files, folders, the symlink and the empty folder).
    const auto plainPower = userWithVaultRole("power_user");
    (void)protocols::ws::handler::fs::Storage::copy(copyPayload("/proj", "/by_plain_power"), wsAs(plainPower));
    EXPECT_EQ(plaintext("/by_plain_power/sub/deep/c.txt"), "gamma\n");
    EXPECT_TRUE(exists("/by_plain_power/link"));

    // power_user with a download deny on one subfolder: copying the parent would route around it, so it is refused
    // as a whole; the rest can still be copied.
    const auto power = userWithVaultRole("power_user");
    (void)ops::roles::addVaultRoleOverrides(superUser, {
        .target = {.vault_id = engine->vault->id, .subject = {.type = "user", .id = power->id}},
        .permissions = {.changes = {{"vault.fs.files.download", false}}},
        .pattern = "/proj/sub/deep/**"});
    const auto restricted = vh::identities::manager().user(power->id);
    EXPECT_THROW((void)protocols::ws::handler::fs::Storage::copy(copyPayload("/proj", "/by_power"), wsAs(restricted)),
                 std::runtime_error);
    EXPECT_FALSE(exists("/by_power"));
    (void)protocols::ws::handler::fs::Storage::copy(copyPayload("/proj/a.txt", "/by_power_a.txt"), wsAs(restricted));
    EXPECT_EQ(plaintext("/by_power_a.txt"), "alpha\n");
}

}
