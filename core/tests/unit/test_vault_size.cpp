// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// #161: every vault reported (and was quota-checked against) the size of the whole shared backing root, so an empty
// vault showed the default vault's bytes. A vault's physical size is now its own backing tree only.

#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "stats/model/StorageBackendStats.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Capacity.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_vault_size {

using UserPtr = std::shared_ptr<identities::User>;

std::string vsTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

class VaultSizeDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_vault_size] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_vault_size_" + vsTag());
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
    }

    static std::shared_ptr<storage::Engine> newLocalVault(const std::string& prefix, const uintmax_t quota = 0) {
        const auto vault = ops::vaults::create(superUser, {.name = prefix + "_" + vsTag(),
                                                           .type = vault::model::VaultType::Local, .quota = quota});
        return runtime::Deps::get().storageManager->getEngine(vault->id);
    }

    static std::shared_ptr<fs::model::File> write(const std::shared_ptr<storage::Engine>& engine,
                                                  const std::string& vaultPath, const std::size_t bytes) {
        return fs::Filesystem::createFile({.path = vaultPath,
                                           .fuse_path = engine->vaultPathToFusePath(vaultPath),
                                           .buffer = std::vector<uint8_t>(bytes, 'v'),
                                           .engine = engine,
                                           .user = superUser});
    }
};

TEST_F(VaultSizeDbTest, EachVaultReportsItsOwnPhysicalSize) {
    const auto big = newLocalVault("vs_big");
    const auto small = newLocalVault("vs_small");
    const auto empty = newLocalVault("vs_empty");
    ASSERT_TRUE(big && small && empty);

    const auto bigFile = write(big, "/big.bin", 256 * 1024);
    const auto smallFile = write(small, "/small.bin", 100);
    ASSERT_TRUE(bigFile && smallFile);

    // Ciphertext on disk, so compare with the backing files themselves.
    const auto bigBytes = std::filesystem::file_size(bigFile->backing_path);
    const auto smallBytes = std::filesystem::file_size(smallFile->backing_path);
    ASSERT_GT(bigBytes, smallBytes);

    EXPECT_EQ(big->getVaultSize(), bigBytes);
    EXPECT_EQ(small->getVaultSize(), smallBytes);
    EXPECT_EQ(empty->getVaultSize(), 0u);

    // stats.vault capacity and stats.system.storage read the same per-vault number.
    EXPECT_EQ(vault::model::Capacity(big->vault->id).physical_size, bigBytes);
    EXPECT_EQ(vault::model::Capacity(small->vault->id).physical_size, smallBytes);
    EXPECT_EQ(vault::model::Capacity(empty->vault->id).physical_size, 0u);

    const auto storage = stats::model::StorageBackendStats::snapshotForVault(small->vault->id);
    ASSERT_EQ(storage.vaults.size(), 1u);
    ASSERT_TRUE(storage.vaults.front().vaultSizeBytes);
    EXPECT_EQ(*storage.vaults.front().vaultSizeBytes, smallBytes);
}

// Quota enforcement (uploads, share uploads, sync) reads freeSpace(), which used to charge every quota'd vault for
// the bytes of all the others.
TEST_F(VaultSizeDbTest, QuotaFreeSpaceCountsOnlyThisVault) {
    const auto other = newLocalVault("vs_other");
    ASSERT_TRUE(other);
    ASSERT_TRUE(write(other, "/other.bin", 512 * 1024));

    constexpr uintmax_t quota = storage::Engine::MIN_FREE_SPACE + 4 * 1024 * 1024;
    const auto quotad = newLocalVault("vs_quota", quota);
    ASSERT_TRUE(quotad);
    ASSERT_EQ(quotad->vault->quota, quota);
    const auto file = write(quotad, "/mine.bin", 1000);
    ASSERT_TRUE(file);

    const auto used = quotad->getVaultSize() + quotad->getCacheSize() + storage::Engine::MIN_FREE_SPACE;
    EXPECT_EQ(quotad->getVaultSize(), std::filesystem::file_size(file->backing_path));
    EXPECT_EQ(quotad->freeSpace(), quota - used);
    EXPECT_GT(quotad->freeSpace(), 3u * 1024 * 1024) << "another vault's 512 KiB must not count against this quota";
}

// storage.vault.list rows carry the owner's name next to owner_id.
TEST_F(VaultSizeDbTest, VaultListRowsCarryTheOwnerName) {
    const auto engine = newLocalVault("vs_list");
    ASSERT_TRUE(engine);

    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    session->user = superUser;
    const auto out = protocols::ws::handler::Vaults::list(session);
    ASSERT_TRUE(out.at("vaults").is_array());
    bool sawNew = false;
    for (const auto& row : out.at("vaults")) {
        ASSERT_TRUE(row.contains("owner_id"));
        ASSERT_TRUE(row.contains("owner")) << row.dump();
        const auto owner = vh::identities::manager().user(row.at("owner_id").get<uint32_t>());
        ASSERT_TRUE(owner);
        EXPECT_EQ(row.at("owner").get<std::string>(), owner->name());
        if (row.at("id").get<uint32_t>() == engine->vault->id) {
            sawNew = true;
            EXPECT_EQ(row.at("owner").get<std::string>(), superUser->name());
        }
    }
    EXPECT_TRUE(sawNew);
}

}
