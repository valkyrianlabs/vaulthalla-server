// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// #366 (WS1-a): every path that creates a files row assigns an object uid (uploads' createFile, which sync downloads
// also use; FUSE create; copy), rename, move and overwrite keep it, a copy gets its own; vaults get a uid when they are
// created; s3.storage_layout follows encrypt_upstream: a new encrypting vault is opaque_v1 (since #371), an existing
// vault that starts encrypting is path_v0 (the layout migration, WS1-c, moves it on).

#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fuse/resolver/Resolved.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/model/S3Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

namespace vh::test_object_uid_db {

using json = nlohmann::json;
using crypto::id::ObjectUid;

std::string uidTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "u" + std::to_string(n.fetch_add(1));
}

class ObjectUidDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> superUser;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    std::shared_ptr<storage::Engine> engine;
    uint32_t vaultId{};

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_object_uid_db] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_object_uid_" + uidTag());
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
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = identities::manager().userByName("admin");

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
        const auto vault = ops::vaults::create(superUser, {.name = "uid_" + uidTag(), .type = vault::model::VaultType::Local});
        vaultId = vault->id;
        engine = runtime::Deps::get().storageManager->getEngine(vaultId);
        ASSERT_TRUE(engine);
    }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    [[nodiscard]] json ws(const std::string& command, json payload) const {
        namespace h = protocols::ws::handler::fs;
        payload["vault_id"] = vaultId;
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->user = superUser;
        if (command == "rename") return h::Storage::rename(payload, session);
        if (command == "move") return h::Storage::move(payload, session);
        if (command == "copy") return h::Storage::copy(payload, session);
        if (command == "mkdir") return h::Storage::mkdir(payload, session);
        ADD_FAILURE() << "unknown command " << command;
        return {};
    }

    // The stored object uid of the file at `path` (and the cached model agrees with it).
    [[nodiscard]] std::optional<ObjectUid> storedUid(const std::string& path) const {
        const auto file = db::query::fs::File::getFileByPath(vaultId, path);
        EXPECT_TRUE(file) << path;
        if (!file) return std::nullopt;
        EXPECT_TRUE(file->object_uid) << path;
        const auto cached = std::dynamic_pointer_cast<fs::model::File>(
            runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path)));
        if (cached) {
            EXPECT_EQ(cached->object_uid, file->object_uid) << path << ": cache and row disagree";
        }
        return file->object_uid;
    }

    [[nodiscard]] uint32_t apiKey() const {
        const auto tag = uidTag();
        return db::Transactions::exec("ObjectUidDbTest::apiKey", [&](pqxx::work& txn) {
            return txn.exec("INSERT INTO api_keys (user_id, name, provider, access_key, encrypted_secret_access_key, iv, "
                            "region, endpoint) VALUES ($1, $2, 'AWS', $3, decode('00','hex'), decode('00','hex'), "
                            "'us-east-1', 'https://s3.example.com') RETURNING id",
                            pqxx::params{superUser->id, "uid-key-" + tag, "uid-key-" + tag}).one_field_ref().as<uint32_t>();
        });
    }

    [[nodiscard]] static std::string storedLayout(const uint32_t id) {
        return db::Transactions::exec("ObjectUidDbTest::storedLayout", [&](pqxx::work& txn) {
            return txn.exec("SELECT storage_layout FROM s3 WHERE vault_id = $1", pqxx::params{id})
                .one_field_ref().as<std::string>();
        });
    }
};

TEST_F(ObjectUidDbTest, EveryFileCreationPathAssignsAnObjectUidAndOnlyACopyChangesIt) {
    // Uploads (createFile: HTTP, ws and share uploads, S3 gateway PUTs and sync downloads of new keys all end here).
    write("/a.txt", "first");
    const auto a = storedUid("/a.txt");
    ASSERT_TRUE(a);

    // Overwrite and an empty rewrite keep it: same file, new content.
    write("/a.txt", "second, longer");
    EXPECT_EQ(storedUid("/a.txt"), a);

    // FUSE create.
    const auto parent = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath("/"));
    ASSERT_TRUE(parent);
    fuse::resolver::Resolved resolved;
    resolved.user = superUser;
    resolved.parentEntry = parent;
    resolved.path = engine->vaultPathToFusePath("/fuse.txt");
    resolved.engine = engine;
    const auto [err, created] = fs::Filesystem::createFile(fs::FuseCreateFileContext{.resolved = resolved});
    ASSERT_EQ(err, 0);
    ASSERT_TRUE(created);
    const auto fuseUid = storedUid("/fuse.txt");
    ASSERT_TRUE(fuseUid);
    EXPECT_NE(fuseUid, a);

    // Rename and move keep it; a copy is a new file with its own.
    (void)ws("mkdir", {{"path", "/box"}});
    (void)ws("rename", {{"from", "/a.txt"}, {"to", "/b.txt"}});
    EXPECT_EQ(storedUid("/b.txt"), a);
    (void)ws("move", {{"from", "/b.txt"}, {"to", "/box/b.txt"}});
    EXPECT_EQ(storedUid("/box/b.txt"), a);
    (void)ws("copy", {{"from", "/box/b.txt"}, {"to", "/c.txt"}});
    const auto copied = storedUid("/c.txt");
    ASSERT_TRUE(copied);
    EXPECT_NE(copied, a);
    EXPECT_EQ(storedUid("/box/b.txt"), a);

    // A copied folder: every file inside gets its own uid too.
    write("/box/d.txt", "d");
    const auto d = storedUid("/box/d.txt");
    (void)ws("copy", {{"from", "/box"}, {"to", "/box2"}});
    EXPECT_NE(storedUid("/box2/b.txt"), a);
    EXPECT_NE(storedUid("/box2/d.txt"), d);
    EXPECT_NE(storedUid("/box2/b.txt"), storedUid("/box2/d.txt"));
}

TEST_F(ObjectUidDbTest, VaultsGetAUidAndALayoutThatFollowsEncryption) {
    const auto local = db::query::vault::Vault::getVault(vaultId);
    ASSERT_TRUE(local && local->uid);
    EXPECT_EQ(engine->vault->uid, local->uid);

    const auto key = apiKey();
    const auto create = [&](const bool encrypt, const vault::model::StorageLayout asked) {
        auto s3 = std::make_shared<vault::model::S3Vault>("uid_s3_" + uidTag(), key, "uid-bucket-" + uidTag());
        s3->owner_id = superUser->id;
        s3->mount_point = "uid_s3_" + uidTag();
        s3->encrypt_upstream = encrypt;
        s3->storage_layout = asked;
        s3->id = db::query::vault::Vault::upsertVault(s3, std::make_shared<sync::model::RemotePolicy>());
        return s3;
    };
    using vault::model::StorageLayout;

    // A request can't pick the layout: it follows encrypt_upstream.
    // The path_v0 data plane's seam (test mode only): new encrypting vaults otherwise get opaque_v1, below.
    vault::model::setNewEncryptingLayoutForTesting(StorageLayout::PathV0);
    const auto encrypting = create(true, StorageLayout::Transparent);
    vault::model::setNewEncryptingLayoutForTesting(std::nullopt);
    EXPECT_EQ(storedLayout(encrypting->id), "path_v0");
    EXPECT_EQ(encrypting->storage_layout, StorageLayout::PathV0);
    ASSERT_TRUE(encrypting->uid);
    EXPECT_NE(encrypting->uid, local->uid);
    const auto plain = create(false, StorageLayout::PathV0);
    EXPECT_EQ(storedLayout(plain->id), "transparent");

    // Re-reading gives the stored layout and uid; an update keeps the uid.
    const auto reread = std::dynamic_pointer_cast<vault::model::S3Vault>(db::query::vault::Vault::getVault(encrypting->id));
    ASSERT_TRUE(reread);
    EXPECT_EQ(reread->storage_layout, StorageLayout::PathV0);
    EXPECT_EQ(reread->uid, encrypting->uid);
    EXPECT_NE(vault::model::to_string(*reread).find("Storage Layout: path (v0)"), std::string::npos);
    EXPECT_EQ(json(*reread).at("storage_layout"), "path_v0");

    // Flipping encryption moves between transparent and path_v0; the uid stays.
    reread->encrypt_upstream = false;
    (void)db::query::vault::Vault::upsertVault(reread, nullptr);
    EXPECT_EQ(storedLayout(reread->id), "transparent");
    EXPECT_EQ(db::query::vault::Vault::getVault(reread->id)->uid, encrypting->uid);
    reread->encrypt_upstream = true;
    reread->storage_layout = StorageLayout::OpaqueV1;   // ignored: an existing vault keeps its layout
    (void)db::query::vault::Vault::upsertVault(reread, nullptr);
    EXPECT_EQ(storedLayout(reread->id), "path_v0");

    // A new encrypting vault is opaque_v1 (#371), and its encryption can't be turned off here.
    const auto opaque = create(true, StorageLayout::Transparent);
    EXPECT_EQ(storedLayout(opaque->id), "opaque_v1");
    opaque->encrypt_upstream = false;
    EXPECT_THROW((void)db::query::vault::Vault::upsertVault(opaque, nullptr), std::invalid_argument);
    EXPECT_EQ(storedLayout(opaque->id), "opaque_v1");

    paths::testMode = false;
    EXPECT_EQ(storedLayout(create(true, StorageLayout::PathV0)->id), "opaque_v1") << "outside test mode too";
    vault::model::setNewEncryptingLayoutForTesting(StorageLayout::PathV0);
    EXPECT_EQ(storedLayout(create(true, StorageLayout::PathV0)->id), "opaque_v1") << "the seam is test mode's only";
    vault::model::setNewEncryptingLayoutForTesting(std::nullopt);
    paths::testMode = true;
}

}
