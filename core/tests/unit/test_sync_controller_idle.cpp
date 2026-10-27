// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The sync controller must sleep while no sync is due. It used to pop the earliest task and push it straight back
// in a tight loop whenever that task was scheduled in the future, which is always once a vault has synced: one
// core at 100% for the daemon's whole life (seen on vh-storage: 1d 4h of CPU in 28.6h of uptime).

#include "concurrency/ThreadPoolManager.hpp"
#include "db/Transactions.hpp"
#include "fs/Filesystem.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "sync/Local.hpp"

#include <gtest/gtest.h>
#include <paths.h>
#include <sys/resource.h>

#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <thread>

namespace vh::test_sync_controller_idle {

double processCpuSeconds() {
    rusage usage{};
    getrusage(RUSAGE_SELF, &usage);
    return static_cast<double>(usage.ru_utime.tv_sec + usage.ru_stime.tv_sec) +
           static_cast<double>(usage.ru_utime.tv_usec + usage.ru_stime.tv_usec) / 1e6;
}

TEST(SyncControllerIdle, SleepsWhileNoSyncIsDue) {
    if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
          std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME")))
        GTEST_SKIP() << "Skipping db test due to missing environment variables.";

    paths::enableTestMode();
    const auto root = std::filesystem::temp_directory_path() / "vh_sync_idle";
    std::filesystem::remove_all(root);
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
    runtime::Deps::get().storageManager->initStorageEngines();   // as the daemon does at startup

    auto& pools = concurrency::ThreadPoolManager::instance();
    pools.init();
    struct PoolShutdown { ~PoolShutdown() { concurrency::ThreadPoolManager::instance().shutdown(); } } poolShutdown;

    // The seeded admin vault is a local vault that syncs every 10 minutes: the controller always holds its task.
    const auto controller = std::make_shared<sync::Controller>();
    runtime::Deps::setSyncController(controller);
    controller->start();
    struct Stop { std::shared_ptr<sync::Controller> c; ~Stop() { c->stop(); } } stop{controller};

    std::this_thread::sleep_for(std::chrono::seconds(2));   // let the first (immediately due) sync start

    // A daemon's steady state: a vault whose next sync is an hour away.
    const auto engines = runtime::Deps::get().storageManager->getEngines();
    ASSERT_FALSE(engines.empty()) << "the seed should load the admin default vault";
    const auto future = std::make_shared<sync::Local>(engines.front());
    future->next_run = std::chrono::system_clock::now() + std::chrono::hours(1);
    controller->requeue(future);
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    const double before = processCpuSeconds();
    std::this_thread::sleep_for(std::chrono::seconds(2));
    const double used = processCpuSeconds() - before;
    std::cout << "[sync idle] process CPU over 2s with no sync due: " << used << "s" << std::endl;
    EXPECT_LT(used, 0.5) << "the sync controller is spinning instead of waiting for the next sync";

    const auto stopStarted = std::chrono::steady_clock::now();
    controller->stop();
    EXPECT_LT(std::chrono::steady_clock::now() - stopStarted, std::chrono::seconds(2)) << "stop must wake the wait";
}

}
