// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
#include "db/Transactions.hpp"
#include "config/Registry.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/identities/User.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "storage/Engine.hpp"
#include "vault/model/Vault.hpp"
#include "identities/Manager.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace {

struct SeedIds {
    uint32_t userId{};
    uint32_t rootId{};
    uint32_t vaultId{};
    uint32_t vaultRootId{};
};

std::string aliasFor(const char c) {
    return std::string(33, c);
}

uint32_t ensureFsCacheUnprivilegedAdminRole(pqxx::work& txn) {
    const auto role = vh::rbac::role::Admin::None();
    return txn.exec(
        R"SQL(
            INSERT INTO admin_role (
                name,
                description,
                identity_permissions,
                audit_permissions,
                settings_permissions,
                roles_permissions,
                vaults_permissions,
                keys_permissions
            )
            VALUES ($1, $2, $3::bit(32), $4::bit(8), $5::bit(64), $6::bit(16), $7::bit(32), $8::bit(32))
            ON CONFLICT (name) DO UPDATE SET
                description = EXCLUDED.description,
                identity_permissions = EXCLUDED.identity_permissions,
                audit_permissions = EXCLUDED.audit_permissions,
                settings_permissions = EXCLUDED.settings_permissions,
                roles_permissions = EXCLUDED.roles_permissions,
                vaults_permissions = EXCLUDED.vaults_permissions,
                keys_permissions = EXCLUDED.keys_permissions
            RETURNING id
        )SQL",
        pqxx::params{
            role.name,
            role.description,
            role.identities.toBitString(),
            role.audits.toBitString(),
            role.settings.toBitString(),
            role.roles.toBitString(),
            role.vaults.toBitString(),
            role.keys.toBitString()
        }).one_field_ref().as<uint32_t>();
}

uint32_t insertFsCacheHydratableTestUser(pqxx::work& txn, const std::string& name, const std::string& email) {
    const auto userId = txn.exec(
        "INSERT INTO users (name, email, password_hash) VALUES ($1, $2, $3) RETURNING id",
        pqxx::params{name, email, "hash"}
    ).one_field_ref().as<uint32_t>();
    const auto roleId = ensureFsCacheUnprivilegedAdminRole(txn);
    txn.exec(
        "INSERT INTO admin_role_assignments (user_id, role_id) VALUES ($1, $2)",
        pqxx::params{userId, roleId});
    return userId;
}

class FsCacheDeleteTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static SeedIds ids{};

    std::shared_ptr<vh::fs::cache::Registry> previousCache;
    std::filesystem::path oldBackingPath;
    std::filesystem::path oldMountPath;
    std::filesystem::path testRoot;
    bool installedCache{false};

    static bool hasDbEnv() {
        return std::getenv("VH_TEST_DB_USER") &&
               std::getenv("VH_TEST_DB_PASS") &&
               std::getenv("VH_TEST_DB_HOST") &&
               std::getenv("VH_TEST_DB_PORT") &&
               std::getenv("VH_TEST_DB_NAME");
    }

    static void SetUpTestSuite() {
        if (!hasDbEnv()) {
            skipTests = true;
            std::cout << "[test_fs_cache_delete] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }

        vh::paths::enableTestMode();
        vh::db::Transactions::init();
        vh::db::seed::nuke_and_recreate_schema_public();
        vh::db::Transactions::dbPool_->initPreparedStatements();

        ids = vh::db::Transactions::exec("FsCacheDeleteTest::seed", [](pqxx::work& txn) {
            SeedIds seeded;
            seeded.userId = insertFsCacheHydratableTestUser(
                txn,
                "fs_cache_delete_user",
                "fs-cache-delete@vaulthalla.test");

            seeded.vaultId = txn.exec(
                "INSERT INTO vault (type, name, owner_id, mount_point) VALUES ($1, $2, $3, $4) RETURNING id",
                pqxx::params{"local", "Cache Delete Vault", seeded.userId, "cache_delete_vault"}
            ).one_field_ref().as<uint32_t>();

            seeded.rootId = txn.exec(
                "INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, inode, is_system) "
                "VALUES (NULL, NULL, $1, $2, $3, $3, $4, $5, TRUE) RETURNING id",
                pqxx::params{"/", aliasFor('R'), seeded.userId, "/", 1}
            ).one_field_ref().as<uint32_t>();
            txn.exec(
                "INSERT INTO directories (fs_entry_id, subdirectory_count) VALUES ($1, $2)",
                pqxx::params{seeded.rootId, 1}
            );

            seeded.vaultRootId = txn.exec(
                "INSERT INTO fs_entry (vault_id, parent_id, name, base32_alias, created_by, last_modified_by, path, inode) "
                "VALUES ($1, $2, $3, $4, $5, $5, $6, $7) RETURNING id",
                pqxx::params{seeded.vaultId, seeded.rootId, "cache_vault", aliasFor('V'), seeded.userId, "/", 2}
            ).one_field_ref().as<uint32_t>();
            txn.exec("INSERT INTO directories (fs_entry_id) VALUES ($1)", pqxx::params{seeded.vaultRootId});

            return seeded;
        });
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";

        oldBackingPath = vh::paths::backingPath;
        oldMountPath = vh::paths::mountPath;
        testRoot = std::filesystem::temp_directory_path() / "vh_fs_cache_delete_unit";
        std::filesystem::remove_all(testRoot);
        vh::paths::backingPath = testRoot / "backing";
        vh::paths::mountPath = testRoot / "mount";
        std::filesystem::create_directories(vh::paths::backingPath);
        std::filesystem::create_directories(vh::paths::mountPath);
        vh::config::Registry::set(vh::config::Config{});

        previousCache = vh::runtime::Deps::get().fsCache;
        vh::runtime::Deps::get().fsCache = std::make_shared<vh::fs::cache::Registry>();
        installedCache = true;
    }

    void TearDown() override {
        if (installedCache) {
            vh::runtime::Deps::get().fsCache = std::move(previousCache);
            std::filesystem::remove_all(testRoot);
            vh::paths::backingPath = oldBackingPath;
            vh::paths::mountPath = oldMountPath;
        }
    }

    std::shared_ptr<vh::fs::model::Directory> vaultRoot() const {
        auto entry = vh::runtime::Deps::get().fsCache->getEntry("/cache_vault");
        if (!entry || !entry->isDirectory()) throw std::runtime_error("Seeded vault root missing from fs cache");
        return std::static_pointer_cast<vh::fs::model::Directory>(entry);
    }

    std::shared_ptr<vh::fs::model::Directory> makeDirectory(
        const std::filesystem::path& fusePath,
        const std::string& base32Alias
    ) const {
        auto parent = vaultRoot();
        auto dir = std::make_shared<vh::fs::model::Directory>();
        dir->vault_id = ids.vaultId;
        dir->parent_id = ids.vaultRootId;
        dir->name = fusePath.filename().string();
        dir->base32_alias = base32Alias;
        dir->created_by = ids.userId;
        dir->last_modified_by = ids.userId;
        dir->path = "/" / fusePath.filename();
        dir->fuse_path = fusePath;
        dir->backing_path = parent->backing_path / base32Alias;
        dir->inode = vh::runtime::Deps::get().fsCache->assignInode(fusePath);
        dir->mode = 0755;
        return dir;
    }

    std::shared_ptr<vh::fs::model::File> makeFile(
        const std::filesystem::path& fusePath,
        const std::string& base32Alias
    ) const {
        auto parent = vaultRoot();
        auto file = std::make_shared<vh::fs::model::File>();
        file->vault_id = ids.vaultId;
        file->parent_id = ids.vaultRootId;
        file->name = fusePath.filename().string();
        file->base32_alias = base32Alias;
        file->created_by = ids.userId;
        file->last_modified_by = ids.userId;
        file->path = "/" / fusePath.filename();
        file->fuse_path = fusePath;
        file->backing_path = parent->backing_path / base32Alias;
        file->inode = vh::runtime::Deps::get().fsCache->assignInode(fusePath);
        file->mode = 0644;
        file->size_bytes = 4;
        file->mime_type = "text/plain";
        file->content_hash = "hash";
        return file;
    }
};

TEST_F(FsCacheDeleteTest, EvictedDirectoryPathCanBeRecreatedWithFreshMetadata) {
    const std::filesystem::path path = "/cache_vault/reupload";

    auto first = makeDirectory(path, aliasFor('A'));
    first->id = vh::db::query::fs::Directory::upsertDirectory(first);
    vh::runtime::Deps::get().fsCache->cacheEntry(first);

    ASSERT_TRUE(vh::runtime::Deps::get().fsCache->entryExists(path));
    const auto firstId = first->id;

    EXPECT_TRUE(vh::db::query::fs::Directory::deleteEmptyDirectory(first->id));
    ASSERT_TRUE(vh::runtime::Deps::get().fsCache->entryExists(path));

    vh::runtime::Deps::get().fsCache->evictPath(path);
    EXPECT_FALSE(vh::runtime::Deps::get().fsCache->entryExists(path));

    auto second = makeDirectory(path, aliasFor('B'));
    second->id = vh::db::query::fs::Directory::upsertDirectory(second);
    vh::runtime::Deps::get().fsCache->cacheEntry(second);

    const auto recreated = vh::runtime::Deps::get().fsCache->getEntry(path);
    ASSERT_NE(recreated, nullptr);
    EXPECT_TRUE(recreated->isDirectory());
    EXPECT_EQ(recreated->id, second->id);
    EXPECT_NE(recreated->id, firstId);
    EXPECT_EQ(recreated->fuse_path, path);
    EXPECT_EQ(recreated->base32_alias, aliasFor('B'));
}

TEST_F(FsCacheDeleteTest, DeleteFileTrashesAndMarksDeletedWithRegisteredStatements) {
    const std::filesystem::path path = "/cache_vault/delete-me.txt";
    auto file = makeFile(path, aliasFor('F'));
    file->id = vh::db::query::fs::File::upsertFile(file);
    vh::runtime::Deps::get().fsCache->cacheEntry(file);

    ASSERT_NO_THROW(vh::db::query::fs::File::deleteFile(ids.userId, file));

    struct DeletedRow {
        uint32_t liveCount{};
        uint32_t trashedCount{};
        std::string backingPath;
        bool markedDeleted{};
    };

    const auto row = vh::db::Transactions::exec("FsCacheDeleteTest::assertDeletedFile", [&](pqxx::work& txn) {
        DeletedRow out;
        out.liveCount = txn.exec(
            "SELECT COUNT(*) FROM fs_entry WHERE id = $1",
            pqxx::params{file->id}
        ).one_field_ref().as<uint32_t>();
        const auto trashed = txn.exec(
            "SELECT backing_path, deleted_at IS NOT NULL AS marked_deleted "
            "FROM files_trashed WHERE base32_alias = $1",
            pqxx::params{file->base32_alias}
        );
        out.trashedCount = static_cast<uint32_t>(trashed.size());
        if (!trashed.empty()) {
            out.backingPath = trashed.one_row_ref()["backing_path"].as<std::string>();
            out.markedDeleted = trashed.one_row_ref()["marked_deleted"].as<bool>();
        }
        return out;
    });

    EXPECT_EQ(row.liveCount, 0u);
    EXPECT_EQ(row.trashedCount, 1u);
    EXPECT_EQ(row.backingPath, file->backing_path.string());
    EXPECT_TRUE(row.markedDeleted);
}

TEST_F(FsCacheDeleteTest, DeleteAndEvictFileClearsPathInodeAndIdCacheMaps) {
    const std::filesystem::path path = "/cache_vault/delete-evict-me.txt";
    auto file = makeFile(path, aliasFor('E'));
    file->id = vh::db::query::fs::File::upsertFile(file);
    vh::runtime::Deps::get().fsCache->cacheEntry(file);

    const auto oldInode = file->inode;
    const auto oldId = file->id;
    ASSERT_TRUE(oldInode.has_value());

    ASSERT_NE(vh::runtime::Deps::get().fsCache->getEntry(path), nullptr);
    ASSERT_NE(vh::runtime::Deps::get().fsCache->getEntry(*oldInode), nullptr);
    ASSERT_NE(vh::runtime::Deps::get().fsCache->getEntryById(oldId), nullptr);

    ASSERT_NO_THROW(vh::db::query::fs::File::deleteFile(ids.userId, file));
    vh::runtime::Deps::get().fsCache->evictPath(path);
    vh::runtime::Deps::get().fsCache->evictIno(*oldInode);

    EXPECT_EQ(vh::runtime::Deps::get().fsCache->getEntry(path), nullptr);
    EXPECT_EQ(vh::runtime::Deps::get().fsCache->getEntry(*oldInode), nullptr);
    EXPECT_EQ(vh::runtime::Deps::get().fsCache->getEntryById(oldId), nullptr);
    EXPECT_EQ(vh::db::query::fs::File::getFileByPath(ids.vaultId, "/delete-evict-me.txt"), nullptr);
}

TEST_F(FsCacheDeleteTest, EvictIdClearsPathInodeAndIdCacheMaps) {
    const std::filesystem::path path = "/cache_vault/delete-by-id.txt";
    auto file = makeFile(path, aliasFor('I'));
    file->id = vh::db::query::fs::File::upsertFile(file);
    vh::runtime::Deps::get().fsCache->cacheEntry(file);

    const auto oldInode = file->inode;
    const auto oldId = file->id;
    ASSERT_TRUE(oldInode.has_value());

    ASSERT_NE(vh::runtime::Deps::get().fsCache->getEntry(path), nullptr);
    ASSERT_NE(vh::runtime::Deps::get().fsCache->getEntry(*oldInode), nullptr);
    ASSERT_NE(vh::runtime::Deps::get().fsCache->getEntryById(oldId), nullptr);

    ASSERT_NO_THROW(vh::db::query::fs::File::deleteFile(ids.userId, file));
    ASSERT_NO_THROW(vh::runtime::Deps::get().fsCache->evictId(oldId));

    EXPECT_EQ(vh::runtime::Deps::get().fsCache->getEntry(path), nullptr);
    EXPECT_EQ(vh::runtime::Deps::get().fsCache->getEntry(*oldInode), nullptr);
    EXPECT_EQ(vh::runtime::Deps::get().fsCache->getEntryById(oldId), nullptr);
}

TEST_F(FsCacheDeleteTest, GatewayPurgeLocalObjectStateClearsStaleCacheAndBackingBytes) {
    const std::filesystem::path path = "/cache_vault/s3-delete-me.txt";
    auto file = makeFile(path, aliasFor('G'));
    file->id = vh::db::query::fs::File::upsertFile(file);
    vh::runtime::Deps::get().fsCache->cacheEntry(file);

    std::filesystem::create_directories(file->backing_path.parent_path());
    {
        std::ofstream out(file->backing_path, std::ios::binary);
        out << "test";
    }

    auto vault = std::make_shared<vh::vault::model::Vault>();
    vault->id = ids.vaultId;
    vault->name = "Cache Delete Vault";
    vault->mount_point = "cache_delete_vault";

    auto engine = std::make_shared<vh::storage::Engine>();
    engine->vault = vault;
    engine->paths = std::make_shared<vh::fs::model::Path>("/cache_vault", "cache_delete_vault");

    // Derived artifacts are keyed by file id (preview::cache::Store), never by path.
    const auto derivedDir = engine->paths->cacheRoot / "derived" / std::to_string(file->id);
    std::filesystem::create_directories(derivedDir);
    std::ofstream(derivedDir / "thumbnail.128.vhd") << "sealed";

    const auto oldInode = file->inode;
    const auto oldId = file->id;
    ASSERT_TRUE(oldInode.has_value());

    vh::protocols::s3::ObjectStore store;
    ASSERT_NO_THROW(store.purgeLocalObjectState(engine, file->path, ids.userId));

    EXPECT_EQ(vh::runtime::Deps::get().fsCache->getEntry(path), nullptr);
    EXPECT_EQ(vh::runtime::Deps::get().fsCache->getEntry(*oldInode), nullptr);
    EXPECT_EQ(vh::runtime::Deps::get().fsCache->getEntryById(oldId), nullptr);
    EXPECT_EQ(vh::db::query::fs::File::getFileByPath(ids.vaultId, "/s3-delete-me.txt"), nullptr);
    EXPECT_FALSE(std::filesystem::exists(file->backing_path));
    EXPECT_FALSE(std::filesystem::exists(derivedDir));
}

TEST_F(FsCacheDeleteTest, CachedNewFileAndDirectoryHaveNonZeroTimestamps) {
    const std::filesystem::path dirPath = "/cache_vault/timestamps";
    auto dir = makeDirectory(dirPath, aliasFor('T'));
    dir->id = vh::db::query::fs::Directory::upsertDirectory(dir);
    vh::runtime::Deps::get().fsCache->cacheEntry(dir);

    EXPECT_GT(dir->created_at, 0);
    EXPECT_GT(dir->updated_at, 0);

    const std::filesystem::path filePath = "/cache_vault/timestamped.txt";
    auto file = makeFile(filePath, aliasFor('U'));
    file->id = vh::db::query::fs::File::upsertFile(file);
    vh::runtime::Deps::get().fsCache->cacheEntry(file);

    EXPECT_GT(file->created_at, 0);
    EXPECT_GT(file->updated_at, 0);

    const auto listed = vh::runtime::Deps::get().fsCache->listDir(ids.vaultRootId);
    auto listedFile = std::ranges::find_if(listed, [](const auto& entry) {
        return entry && entry->name == "timestamped.txt";
    });
    ASSERT_NE(listedFile, listed.end());
    EXPECT_GT((*listedFile)->updated_at, 0);
}

TEST_F(FsCacheDeleteTest, FileUpdateTouchesFsEntryUpdatedAt) {
    const std::filesystem::path path = "/cache_vault/update-time.txt";
    auto file = makeFile(path, aliasFor('W'));
    file->id = vh::db::query::fs::File::upsertFile(file);
    vh::runtime::Deps::get().fsCache->cacheEntry(file);

    file->updated_at = 1;
    file->size_bytes = 8;
    file->last_modified_by = ids.userId;
    vh::db::query::fs::File::updateFile(file);

    EXPECT_GT(file->updated_at, 1);

    const auto reloaded = vh::db::query::fs::Entry::getFSEntryById(file->id);
    ASSERT_TRUE(reloaded);
    EXPECT_GT(reloaded->updated_at, 1);
}

TEST_F(FsCacheDeleteTest, CreateFileOverwriteWithEmptyBufferTruncatesExistingBackingBytes) {
    const std::filesystem::path path = "/cache_vault/empty-overwrite.txt";
    auto file = makeFile(path, aliasFor('Z'));
    file->id = vh::db::query::fs::File::upsertFile(file);
    vh::runtime::Deps::get().fsCache->cacheEntry(file);

    std::filesystem::create_directories(file->backing_path.parent_path());
    {
        std::ofstream out(file->backing_path, std::ios::binary);
        out << "stale";
    }
    ASSERT_EQ(std::filesystem::file_size(file->backing_path), 5u);

    auto vault = std::make_shared<vh::vault::model::Vault>();
    vault->id = ids.vaultId;
    vault->name = "Cache Delete Vault";
    vault->mount_point = "cache_delete_vault";

    auto engine = std::make_shared<vh::storage::Engine>();
    engine->vault = vault;
    engine->paths = std::make_shared<vh::fs::model::Path>("/cache_vault", "cache_delete_vault");

    const auto user = vh::identities::manager().user(ids.userId);
    ASSERT_TRUE(user);

    const auto overwritten = vh::fs::Filesystem::createFile({
        .path = file->path,
        .fuse_path = path,
        .buffer = {},
        .engine = engine,
        .user = user,
        .overwrite = true
    });

    ASSERT_TRUE(overwritten);
    EXPECT_EQ(overwritten->size_bytes, 0u);
    EXPECT_TRUE(overwritten->encryption_iv.empty());
    EXPECT_EQ(overwritten->encrypted_with_key_version, 0u);
    EXPECT_EQ(std::filesystem::file_size(file->backing_path), 0u);

    const auto reloaded = vh::db::query::fs::File::getFileByPath(ids.vaultId, "/empty-overwrite.txt");
    ASSERT_TRUE(reloaded);
    EXPECT_EQ(reloaded->size_bytes, 0u);
}

} // namespace
