// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The DB-backed suites' shared setup (tests/helpers/db_suite.hpp). A schema reset restarts every id sequence, so the
// process-wide state keyed by database ids (the fs cache, the storage engines) must start over with it. Before, 36
// suites kept the previous suite's fs cache and engines (`freshEngines = false`): a File cached under an id that the
// new schema gave a Directory was static-cast and written as one by fs::cache::Registry::cacheEntry, and a later
// suite crashed (VaultRecoverDb under ASan, in Registry::evictVault).

#include "../helpers/db_suite.hpp"

#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>

#include <string>
#include <vector>

namespace vh::test_db_suite {

class DbSuiteIsolation : public vh::test::db::Suite {
protected:
    static void SetUpTestSuite() { (void)setUpDbSuite("test_db_suite"); }
    static void TearDownTestSuite() { tearDownDbSuite(); }
};

TEST_F(DbSuiteIsolation, ASchemaResetDropsEveryCacheKeyedByTheOldSchemasIds) {
    // State of a "previous suite": a vault with an engine and a cached file.
    const auto vault = ops::vaults::create(superUser, {.name = "isolation_" + test::uniqueTag('i'),
                                                       .type = vault::model::VaultType::Local});
    const auto engine = runtime::Deps::get().storageManager->getEngine(vault->id);
    ASSERT_TRUE(engine);
    const std::string content = "cached before the reset";
    const auto file = fs::Filesystem::createFile({.path = "/f.txt",
                                                        .fuse_path = engine->vaultPathToFusePath("/f.txt"),
                                                        .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                        .engine = engine,
                                                        .user = superUser,
                                                        .overwrite = true});
    ASSERT_TRUE(file);
    const auto fileId = file->id;
    const auto cached = runtime::Deps::get().fsCache->getEntryById(fileId);
    ASSERT_TRUE(cached);

    // The next suite's schema: the same ids belong to other rows now (or to none).
    test::db::freshSchema();
    // Whatever answers for the old ids now comes from the new schema (or nothing does), never the old objects.
    EXPECT_NE(runtime::Deps::get().fsCache->getEntryById(fileId), cached)
        << "a cached entry of the dropped schema would answer for the new row that takes its id";
    EXPECT_NE(runtime::Deps::get().storageManager->getEngine(vault->id), engine)
        << "an engine of the dropped schema would answer for the new vault that takes its id";
}

}
