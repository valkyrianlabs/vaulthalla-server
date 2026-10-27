// Entry versions for sync clients (#257, valkyrianlabs/vaulthalla-desktop#1): every entry carries `metadata_version` and every file
// `content_version`, the strong generation ETag GET /download/content serves for its bytes. The ids clients key items
// by survive rename and move. Through the real ws handlers (fs.metadata, fs.dir.list, fs.entry.rename, fs.entry.move),
// the FUSE rename call and the HTTP download lane.

#include "db/Transactions.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/Router.hpp"
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

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace vh::protocols::http::test_entry_versions {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using Storage = protocols::ws::handler::fs::Storage;

namespace {

std::string evTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "v" + std::to_string(n.fetch_add(1));
}

std::string header(const model::preview::Response& r, const field name) {
    return std::visit([&](const auto& res) -> std::string {
        const auto it = res.find(name);
        return it == res.end() ? std::string{} : std::string(it->value());
    }, r);
}

status statusOf(const model::preview::Response& r) {
    return std::visit([](const auto& res) { return res.result(); }, r);
}

std::string encodePath(const std::string& path) {
    std::string out;
    for (const char c : path) {
        if (c == '/') out += "%2F";
        else if (c == ' ') out += "%20";
        else out.push_back(c);
    }
    return out;
}

}

class FsEntryVersionsDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr admin;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    std::shared_ptr<storage::Engine> engine;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_fs_entry_versions] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_entry_versions_" + evTag());
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
        admin = vh::identities::manager().userByName("admin");

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
        access::clearCachesForTesting();
        const auto vault = ops::vaults::create(admin, {.name = "ev_" + evTag(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);
        auto session = wsSession();
        Router::setPreviewSessionResolverForTesting([session](const request&) { return session; });
    }

    void TearDown() override {
        if (!skipTests) Router::resetPreviewSessionResolverForTesting();
    }

    [[nodiscard]] static std::shared_ptr<protocols::ws::Session> wsSession() {
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->user = admin;
        return session;
    }

    [[nodiscard]] uint32_t vaultId() const { return engine->vault->id; }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = admin,
                                                .overwrite = true}));
    }

    [[nodiscard]] json metadata(const std::string& path) const {
        return Storage::metadata({{"vault_id", vaultId()}, {"path", path}}, wsSession()).at("entry");
    }

    [[nodiscard]] json listed(const std::string& dir, const std::string& name) const {
        const auto listing = Storage::listDir({{"vault_id", vaultId()}, {"path", dir}}, wsSession());
        for (const auto& f : listing.at("files"))
            if (f.at("name") == name) return f;
        return json{};
    }

    void wsRename(const std::string& from, const std::string& to) const {
        (void)Storage::rename({{"vault_id", vaultId()}, {"from", from}, {"to", to}}, wsSession());
    }

    void wsMove(const std::string& from, const std::string& to) const {
        (void)Storage::move({{"vault_id", vaultId()}, {"from", from}, {"to", to}}, wsSession());
    }

    // The ETag GET and HEAD /download/content answer with for this path.
    [[nodiscard]] std::string downloadEtag(const std::string& path, const verb method = verb::head) const {
        request req{method, "/download/content?vault_id=" + std::to_string(vaultId()) + "&path=" + encodePath(path), 11};
        req.keep_alive(true);
        const auto res = Router::route(std::move(req));
        EXPECT_EQ(statusOf(res), status::ok) << path;
        return header(res, field::etag);
    }
};

TEST_F(FsEntryVersionsDbTest, ContentVersionIsTheDownloadEtagEverywhereAnEntryIsServed) {
    engine->mkdir("/docs", admin);
    write("/docs/a.txt", "first generation");

    const auto meta = metadata("/docs/a.txt");
    ASSERT_TRUE(meta.contains("content_version"));
    const auto version = meta.at("content_version").get<std::string>();
    EXPECT_EQ(version, downloadEtag("/docs/a.txt"));
    EXPECT_EQ(version, downloadEtag("/docs/a.txt", verb::get));
    EXPECT_EQ(listed("/docs", "a.txt").at("content_version"), version);
    EXPECT_EQ(listed("/docs", "a.txt").at("metadata_version"), meta.at("metadata_version"));

    // Exactly the generation tag (one scheme, not a second one).
    const auto file = std::dynamic_pointer_cast<fs::model::File>(
        runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath("/docs/a.txt")));
    ASSERT_TRUE(file);
    EXPECT_EQ(version, storage::generationOf(*file).etag());

    // Folders have no content version; every entry has a metadata version.
    const auto folder = metadata("/docs");
    EXPECT_FALSE(folder.contains("content_version"));
    EXPECT_TRUE(folder.at("metadata_version").is_string());
    EXPECT_FALSE(listed("/", "docs").contains("content_version"));
    EXPECT_TRUE(listed("/", "docs").at("metadata_version").is_string());

    // The validator round-trips: the download answers 304 to the entry's content_version.
    request conditional{verb::get, "/download/content?vault_id=" + std::to_string(vaultId()) + "&path=%2Fdocs%2Fa.txt", 11};
    conditional.set(field::if_none_match, version);
    EXPECT_EQ(statusOf(Router::route(std::move(conditional))), status::not_modified);
}

TEST_F(FsEntryVersionsDbTest, OverwriteChangesTheContentVersionAndRenameAndMoveKeepIt) {
    engine->mkdir("/docs", admin);
    engine->mkdir("/archive", admin);
    write("/docs/a.txt", "one");

    const auto v0 = metadata("/docs/a.txt");
    const auto id = v0.at("id").get<uint32_t>();

    write("/docs/a.txt", "two");  // an overwrite reseals the bytes: a new generation
    const auto v1 = metadata("/docs/a.txt");
    EXPECT_EQ(v1.at("id"), id);
    EXPECT_NE(v1.at("content_version"), v0.at("content_version"));
    EXPECT_EQ(v1.at("content_version"), downloadEtag("/docs/a.txt"));

    wsRename("/docs/a.txt", "/docs/b.txt");
    const auto v2 = metadata("/docs/b.txt");
    EXPECT_EQ(v2.at("id"), id) << "fs.entry.rename keeps the entry id";
    EXPECT_EQ(v2.at("content_version"), v1.at("content_version")) << "a rename does not touch the bytes";
    EXPECT_NE(v2.at("metadata_version"), v1.at("metadata_version")) << "a rename is a metadata change";
    EXPECT_EQ(v2.at("content_version"), downloadEtag("/docs/b.txt"));

    wsMove("/docs/b.txt", "/archive/b.txt");
    const auto v3 = metadata("/archive/b.txt");
    EXPECT_EQ(v3.at("id"), id) << "fs.entry.move keeps the entry id";
    EXPECT_EQ(v3.at("parent_id"), metadata("/archive").at("id"));
    EXPECT_EQ(v3.at("content_version"), v1.at("content_version")) << "a move does not touch the bytes";
    EXPECT_NE(v3.at("metadata_version"), v2.at("metadata_version")) << "a move is a metadata change";
    EXPECT_EQ(v3.at("content_version"), downloadEtag("/archive/b.txt"));

    // The FUSE rename (rename(2) without flags) keeps the id too, also onto an existing name (editor saves).
    write("/archive/c.txt", "three");
    ASSERT_EQ(fs::Filesystem::rename(engine->vaultPathToFusePath("/archive/b.txt"),
                                     engine->vaultPathToFusePath("/archive/c.txt"), admin, nullptr,
                                     fs::RenameMode::Replace), 0);
    const auto v4 = metadata("/archive/c.txt");
    EXPECT_EQ(v4.at("id"), id) << "a FUSE rename over another file keeps the moved entry's id";
    EXPECT_EQ(v4.at("content_version"), v1.at("content_version"));
}

TEST_F(FsEntryVersionsDbTest, MovingAFolderKeepsTheIdsOfEverythingInIt) {
    engine->mkdir("/projects", admin);
    engine->mkdir("/projects/alpha", admin);
    engine->mkdir("/done", admin);
    write("/projects/alpha/plan.md", "# plan");

    const auto folderId = metadata("/projects/alpha").at("id");
    const auto child = metadata("/projects/alpha/plan.md");

    wsMove("/projects/alpha", "/done/alpha");
    EXPECT_EQ(metadata("/done/alpha").at("id"), folderId);
    const auto moved = metadata("/done/alpha/plan.md");
    EXPECT_EQ(moved.at("id"), child.at("id"));
    EXPECT_EQ(moved.at("parent_id"), folderId);
    EXPECT_EQ(moved.at("content_version"), child.at("content_version"));
    EXPECT_EQ(moved.at("content_version"), downloadEtag("/done/alpha/plan.md"));

    wsRename("/done/alpha", "/done/alpha-final");
    EXPECT_EQ(metadata("/done/alpha-final").at("id"), folderId);
    EXPECT_EQ(metadata("/done/alpha-final/plan.md").at("id"), child.at("id"));
    EXPECT_EQ(metadata("/done/alpha-final/plan.md").at("content_version"), child.at("content_version"));
}

TEST_F(FsEntryVersionsDbTest, AnEmptyFileKeepsItsContentVersionAcrossRename) {
    write("/empty.txt", "");
    const auto before = metadata("/empty.txt");
    EXPECT_EQ(before.at("content_version"), downloadEtag("/empty.txt"));

    wsRename("/empty.txt", "/still-empty.txt");
    const auto after = metadata("/still-empty.txt");
    EXPECT_EQ(after.at("id"), before.at("id"));
    EXPECT_EQ(after.at("content_version"), before.at("content_version"));
    EXPECT_EQ(after.at("content_version"), downloadEtag("/still-empty.txt"));

    write("/still-empty.txt", "now with bytes");
    EXPECT_NE(metadata("/still-empty.txt").at("content_version"), before.at("content_version"));
}

}

// DB-free: what metadata_version covers.
namespace vh::fs::model::test_entry_versions {

namespace {

File sample() {
    File f;
    f.id = 42;
    f.vault_id = 3;
    f.parent_id = 7;
    f.name = "report.pdf";
    f.mode = 0644;
    f.owner_uid = 1000;
    f.group_gid = 1000;
    f.updated_at = 1760003600;
    f.size_bytes = 10;
    f.encryption_iv = "aXYtb25l";
    return f;
}

}

TEST(FsEntryMetadataVersion, ChangesWithNameParentModeOwnerAndUpdatedAtOnly) {
    const auto base = metadataVersion(sample());
    EXPECT_TRUE(base.starts_with("m42-"));
    EXPECT_EQ(base.size(), std::string("m42-").size() + 16);
    EXPECT_EQ(metadataVersion(sample()), base) << "deterministic";

    const auto changed = [&](auto&& edit) {
        auto f = sample();
        edit(f);
        return metadataVersion(f);
    };
    EXPECT_NE(changed([](File& f) { f.name = "report-final.pdf"; }), base);
    EXPECT_NE(changed([](File& f) { f.parent_id = 8; }), base);
    EXPECT_NE(changed([](File& f) { f.parent_id.reset(); }), base);
    EXPECT_NE(changed([](File& f) { f.mode = 0600; }), base);
    EXPECT_NE(changed([](File& f) { f.owner_uid = 1001; }), base);
    EXPECT_NE(changed([](File& f) { f.group_gid = 1001; }), base);
    EXPECT_NE(changed([](File& f) { f.updated_at += 1; }), base);
    EXPECT_NE(changed([](File& f) { f.vault_id = 4; }), base);

    // Content and derived members belong to content_version, and the path follows from parent + name.
    EXPECT_EQ(changed([](File& f) { f.size_bytes = 99; }), base);
    EXPECT_EQ(changed([](File& f) { f.encryption_iv = "aXYtdHdv"; }), base);
    EXPECT_EQ(changed([](File& f) { f.path = "/elsewhere/report.pdf"; }), base);
    EXPECT_EQ(changed([](File& f) { f.fuse_path = "/mnt/x/report.pdf"; }), base);

    // The name is length-prefixed: no two field sets serialize alike.
    auto a = sample();
    a.name = "a|1";
    auto b = sample();
    b.name = "a";
    EXPECT_NE(metadataVersion(a), metadataVersion(b));
}

TEST(FsEntryContentVersion, IsTheGenerationEtagAndAnEmptyFileHasOne) {
    auto f = sample();
    const nlohmann::json j = f;
    EXPECT_EQ(j.at("content_version"), storage::generationOf(f).etag());
    EXPECT_EQ(j.at("metadata_version"), metadataVersion(f));

    // An empty file's generation doesn't depend on updated_at (renaming or touching it keeps its validator).
    File empty;
    empty.id = 5;
    empty.updated_at = 100;
    const auto e0 = storage::generationOf(empty).etag();
    empty.updated_at = 200;
    EXPECT_EQ(storage::generationOf(empty).etag(), e0);
    EXPECT_NE(storage::generationOf(empty).etag(), storage::generationOf(f).etag());

    // A legacy plaintext file with bytes still changes with updated_at (nothing else tracks its content).
    File legacy;
    legacy.id = 6;
    legacy.size_bytes = 3;
    legacy.updated_at = 100;
    const auto l0 = storage::generationOf(legacy).etag();
    legacy.updated_at = 200;
    EXPECT_NE(storage::generationOf(legacy).etag(), l0);

    // Directories carry no content version.
    Directory d;
    d.id = 7;
    const nlohmann::json dj = static_cast<const Entry&>(d);
    EXPECT_FALSE(dj.contains("content_version"));
    EXPECT_TRUE(dj.contains("metadata_version"));
}

}
