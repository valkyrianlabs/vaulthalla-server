#include "../helpers/temp_dir.hpp"
#include "concurrency/ThreadPool.hpp"
#include "fs/model/Path.hpp"
#include "fs/model/file/Trashed.hpp"
#include "storage/Engine.hpp"
#include "sync/Local.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/Throughput.hpp"
#include "sync/tasks/Delete.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <future>
#include <memory>
#include <string>
#include <variant>
#include <vector>

namespace vh::sync::test {

class SyncThroughputTest : public ::testing::Test {
protected:
    std::filesystem::path oldBackingPath;
    std::filesystem::path oldMountPath;
    std::filesystem::path testRoot;
    std::shared_ptr<vh::storage::Engine> engine;

    void SetUp() override {
        oldBackingPath = vh::paths::backingPath;
        oldMountPath = vh::paths::mountPath;
        testRoot = vh::test::uniqueTempRoot("vh_sync_throughput_unit");
        std::filesystem::remove_all(testRoot);
        vh::paths::backingPath = testRoot / "backing";
        vh::paths::mountPath = testRoot / "mount";
        std::filesystem::create_directories(vh::paths::backingPath);
        std::filesystem::create_directories(vh::paths::mountPath);

        auto vault = std::make_shared<vh::vault::model::Vault>();
        vault->id = 101;
        vault->owner_id = 202;
        vault->name = "sync throughput unit";
        vault->mount_point = "sync-throughput-unit";

        engine = std::make_shared<vh::storage::Engine>();
        engine->vault = vault;
        engine->paths = std::make_shared<vh::fs::model::Path>(
            "sync-throughput-unit",
            "sync-throughput-unit"
        );
        std::filesystem::create_directories(engine->paths->backingVaultRoot / "trash");
        std::filesystem::create_directories(engine->paths->vaultRoot / "deleted");
        std::filesystem::create_directories(engine->paths->cacheRoot);
    }

    void TearDown() override {
        vh::paths::backingPath = oldBackingPath;
        vh::paths::mountPath = oldMountPath;
        std::filesystem::remove_all(testRoot);
    }
};

TEST_F(SyncThroughputTest, DeleteTasksKeepStableScopedOpsAcrossThroughputGrowth) {
    constexpr auto kDeleteTasks = 96u;
    constexpr auto kExtraOps = 2048u;

    vh::sync::model::Throughput throughput;
    throughput.metric_type = vh::sync::model::Throughput::DELETE;

    vh::concurrency::ThreadPool pool(4);
    std::vector<std::future<ExpectedFuture>> futures;
    std::vector<std::shared_ptr<vh::sync::model::ScopedOp>> deleteOps;
    futures.reserve(kDeleteTasks);
    deleteOps.reserve(kDeleteTasks);

    for (auto i = 0u; i < kDeleteTasks; ++i) {
        const auto name = "deleted-" + std::to_string(i) + ".dat";
        auto trashed = std::make_shared<vh::fs::model::file::Trashed>();
        trashed->id = i + 1;
        trashed->vault_id = engine->vault->id;
        trashed->path = engine->paths->absPath("/deleted/" + name, vh::fs::model::PathType::FUSE_ROOT);
        trashed->backing_path = std::filesystem::path("sync-throughput-unit") / "trash" / name;
        trashed->size_bytes = 8;

        const auto absBackingPath = engine->paths->absPath(
            trashed->backing_path,
            vh::fs::model::PathType::BACKING_ROOT
        );
        std::filesystem::create_directories(absBackingPath.parent_path());
        std::ofstream(absBackingPath, std::ios::binary) << "contents";

        auto op = throughput.newOp();
        auto task = std::make_shared<vh::sync::tasks::Delete>(
            engine,
            trashed,
            op,
            vh::sync::tasks::Delete::Type::LOCAL
        );
        futures.push_back(task->getFuture().value());
        deleteOps.push_back(op);
        pool.submit(task);
    }

    for (auto i = 0u; i < kExtraOps; ++i) {
        auto op = throughput.newOp();
        op->success = true;
    }

    for (auto& future : futures)
        EXPECT_TRUE(std::get<bool>(future.get()));

    for (const auto& op : deleteOps) {
        ASSERT_TRUE(op);
        EXPECT_TRUE(op->success);
        EXPECT_EQ(8u, op->size_bytes);
        EXPECT_NE(0, op->timestamp_begin);
        EXPECT_NE(0, op->timestamp_end);
    }

    throughput.computeDashboardStats();
    EXPECT_EQ(kDeleteTasks + kExtraOps, throughput.num_ops);
    EXPECT_EQ(0u, throughput.failed_ops);
    EXPECT_EQ(kDeleteTasks * 8u, throughput.size_bytes);
}

TEST_F(SyncThroughputTest, FailedFuturesMarkEventError) {
    vh::sync::Local task;
    task.event = std::make_shared<vh::sync::model::Event>();

    std::promise<ExpectedFuture> failedPromise;
    auto failedFuture = failedPromise.get_future();
    failedPromise.set_value(false);
    task.futures.push_back(std::move(failedFuture));

    task.processFutures();

    EXPECT_TRUE(task.futures.empty());
    EXPECT_EQ(vh::sync::model::Event::Status::ERROR, task.event->status);
    EXPECT_EQ("1 async sync operation(s) failed", task.event->error_message);
}

} // namespace vh::sync::test
