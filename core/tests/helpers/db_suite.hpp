#pragma once

// The DB-backed suite setup every `*Db*` fixture repeated: skip without VH_TEST_DB_*, a fresh schema with the seeded
// install (admin, roles, root), runtime::Deps and the filesystem, and a private scratch root for backing/mount.
//
//   class FooDbTest : public vh::test::db::Suite {
//       static void SetUpTestSuite() { if (!setUpDbSuite("foo")) return; ...suite-specific setup... }
//       static void TearDownTestSuite() { tearDownDbSuite(); }
//   };
//
// Suite::SetUp skips every test when the suite was skipped; a fixture that overrides SetUp calls Suite::SetUp()
// first and returns if IsSkipped().

#include "../helpers/temp_dir.hpp"

#include "db/Transactions.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Manager.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

namespace vh::test::db {

// All five VH_TEST_DB_* settings are present (bin/tests/run_unit.sh sets them; CI never does).
inline bool available() {
    for (const char* name : {"VH_TEST_DB_USER", "VH_TEST_DB_PASS", "VH_TEST_DB_HOST", "VH_TEST_DB_PORT", "VH_TEST_DB_NAME"})
        if (!std::getenv(name)) return false;
    return true;
}

// Every process-wide cache keyed by database ids, started over: the fs cache (entries by id, inode and path) and the
// storage engines (by vault id). A schema reset restarts every id sequence, so an entry left from the dropped schema
// would answer for whatever row of the new one takes its id: a File cached under an id that is a Directory now was
// static-cast and written as one (fs::cache::Registry, the parent stats of cacheEntry), corrupting the heap of a later
// suite (VaultRecoverDb under ASan, 2026-11-12). An unseeded schema has no root entry for a cache to start from, so
// it gets none: its suites build one once they have written their rows (FsCacheDeleteTest) or need none.
inline void resetIdKeyedState(const bool seeded = true) {
    auto& deps = vh::runtime::Deps::get();
    deps.fsCache = seeded ? std::make_shared<vh::fs::cache::Registry>() : nullptr;
    if (deps.storageManager) deps.storageManager->initStorageEngines();
}

// A fresh `public` schema (every migration), prepared statements and, with `seed`, the seeded install; then the
// id-keyed process state is reset to match it (resetIdKeyedState).
inline void freshSchema(const bool seed = true) {
    vh::db::Transactions::init();
    vh::db::seed::nuke_and_recreate_schema_public();
    vh::db::Transactions::dbPool_->initPreparedStatements();
    if (seed) vh::seed::seed_database();
    resetIdKeyedState(seed);
}

struct Options {
    bool seed = true;         // seed::seed_database()
    bool runtime = true;      // runtime::Deps + fs::Filesystem
};

class Suite : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<vh::identities::User> superUser;
    inline static std::filesystem::path root;  // backing/ and mount/ live here, removed by tearDownDbSuite

    // False (and every test of the suite skips) without VH_TEST_DB_*.
    static bool setUpDbSuite(const std::string& name, const Options options = {}) {
        skipTests = !available();
        if (skipTests) {
            std::cout << "[" << name << "] Skipping db tests due to missing environment variables." << std::endl;
            return false;
        }
        vh::paths::enableTestMode();
        root = vh::test::uniqueTempRoot("vh_" + name);
        vh::paths::backingPath = root / "backing";
        vh::paths::mountPath = root / "mount";
        std::filesystem::create_directories(vh::paths::backingPath);
        std::filesystem::create_directories(vh::paths::mountPath);

        freshSchema(options.seed);
        if (options.runtime) {
            vh::runtime::Deps::init();
            vh::fs::Filesystem::init(vh::runtime::Deps::get().storageManager);
            resetIdKeyedState(options.seed);   // the first suite of a process has no storage manager before Deps::init
        }
        if (options.seed) superUser = vh::identities::manager().userByName("admin");
        return true;
    }

    static void tearDownDbSuite() {
        if (skipTests) return;
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }
};

}
