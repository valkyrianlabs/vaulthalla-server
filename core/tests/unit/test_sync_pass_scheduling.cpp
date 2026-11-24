// Sync passes: where they run, how they end and when they run again (production, 2026-11-24: nine S3 mirror vaults on
// a 12-core host stopped syncing for good whenever about six passes were due together, after every start included).
//
//   SyncPassPool*        passes run on a pool of their own (ThreadPoolManager::syncPassPool), never on the pool of
//                        the operations they wait for; with one pool, six waiting passes held every worker.
//   SyncPoolSizing.*, DbPoolSize.*, SyncRetryDelay.*   the sizes and the backoff, DB-free.
//   SyncPassSchedulingDb.*   real passes (sync::Cloud / sync::Local) on in-memory buckets: every outcome reschedules a
//                        regular task (SUCCESS and STALLED at the interval, ERROR with backoff), never a scoped or an
//                        interrupted one, also when startTask or the event save throws; a failed stage ends the pass;
//                        the uploads that succeeded are recorded when another failed; byte counters above 2^31 are
//                        stored; database.pool_size reaches the pool; listings hold one connection, not two.

#include "../helpers/db_suite.hpp"
#include "../helpers/temp_dir.hpp"
#include "../helpers/versioned_bucket.hpp"

#include "concurrency/Task.hpp"
#include "concurrency/ThreadPool.hpp"
#include "concurrency/ThreadPoolManager.hpp"
#include "config/Config.hpp"
#include "db/DBPool.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/Event.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/RemoteAccess.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/Cloud.hpp"
#include "sync/Controller.hpp"
#include "sync/Local.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/Scope.hpp"
#include "sync/model/Throughput.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_sync_pass_scheduling {

using Status = sync::model::Event::Status;
using concurrency::ThreadPoolManager;
using std::chrono::seconds;
using std::chrono::system_clock;
using test_support::versioned::CloudVault;
using test_support::versioned::Versioning;

bool waitUntil(const std::function<bool()>& done, const std::chrono::milliseconds timeout) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (!done()) {
        if (std::chrono::steady_clock::now() > deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    return true;
}

// The process-wide pools, sized for one test and put back to the defaults after it.
struct PoolSizing {
    explicit PoolSizing(const ThreadPoolManager::Sizing sizing) {
        ThreadPoolManager::instance().shutdown();
        ThreadPoolManager::instance().init(sizing);
    }
    PoolSizing(const PoolSizing&) = delete;
    PoolSizing& operator=(const PoolSizing&) = delete;
    ~PoolSizing() {
        ThreadPoolManager::instance().shutdown();
        ThreadPoolManager::instance().init();
    }
};

// A pass's operation (an upload, say): a short piece of work that reports success.
struct Operation final : concurrency::PromisedTask {
    void operator()() override {
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
        promise.set_value(true);
    }
};

// A pass as sync::Local runs one: its operations go to the sync pool (Local::push) and it waits for all of them
// (Local::processFutures) on whatever thread runs the pass.
struct WaitingPass final : sync::Local {
    unsigned operations;
    std::atomic<unsigned>* finished;
    WaitingPass(const unsigned ops, std::atomic<unsigned>* done) : operations(ops), finished(done) {}
    void operator()() override {
        for (unsigned i = 0; i < operations; ++i) push(std::make_shared<Operation>());
        processFutures();
        if (futureOutcomes.size() == operations && std::ranges::all_of(futureOutcomes, [](const bool ok) { return ok; }))
            ++*finished;
    }
};

// ---------------------------------------------------------------------------------------------------- DB-free

TEST(SyncPoolSizing, OperationWorkersFollowTheCoresAndPassesHaveTheirOwnPool) {
    using M = ThreadPoolManager;
    EXPECT_EQ(M::syncWorkersFor(0, 12), 12u) << "a 12-core host: one operation worker per core (1.25.0: 6 for everything)";
    EXPECT_EQ(M::syncWorkersFor(0, 18), 18u);
    EXPECT_EQ(M::syncWorkersFor(0, 2), 4u);
    EXPECT_EQ(M::syncWorkersFor(0, 0), 4u);
    EXPECT_EQ(M::syncWorkersFor(0, 200), 64u);
    EXPECT_EQ(M::syncWorkersFor(8, 12), 8u);
    EXPECT_EQ(M::syncWorkersFor(1, 12), 1u);
    EXPECT_EQ(M::syncWorkersFor(100000, 12), 256u);
    EXPECT_EQ(M::syncPassesFor(0), 4u);
    EXPECT_EQ(M::syncPassesFor(6), 6u);
    EXPECT_EQ(M::syncPassesFor(1000), 64u);

    const PoolSizing sizing({.syncWorkers = 5, .syncPasses = 3});
    auto& pools = ThreadPoolManager::instance();
    EXPECT_EQ(pools.syncPool()->workerCount(), 5u);
    EXPECT_EQ(pools.syncPassPool()->workerCount(), 3u);
    EXPECT_NE(pools.syncPool(), pools.syncPassPool());
    const auto snapshots = pools.snapshotPools();
    EXPECT_TRUE(std::ranges::any_of(snapshots, [](const auto& s) { return s.name == "sync_pass" && s.present; }));
}

TEST(DbPoolSize, ConfiguredSizesAreKeptWithinBounds) {
    std::string warning = "stale";
    EXPECT_EQ(db::DBPool::resolveSize(10, &warning), 10u);
    EXPECT_TRUE(warning.empty());
    EXPECT_EQ(db::DBPool::resolveSize(config::DatabaseConfig{}.pool_size, &warning), 24u) << "the default";
    EXPECT_TRUE(warning.empty());
    for (const long long nonsense : {0LL, -5LL, 1LL, 3LL}) {
        EXPECT_EQ(db::DBPool::resolveSize(nonsense, &warning), db::DBPool::kMinPoolSize) << nonsense;
        EXPECT_NE(warning.find("database.pool_size " + std::to_string(nonsense)), std::string::npos) << warning;
    }
    EXPECT_EQ(db::DBPool::resolveSize(100000, &warning), db::DBPool::kMaxPoolSize);
    EXPECT_NE(warning.find("using 256"), std::string::npos) << warning;
}

TEST(SyncRetryDelay, FailuresBackOffFromTheIntervalUpToTheCap) {
    const auto delay = [](const Status s, const seconds interval, const unsigned failures) {
        return sync::Local::retryDelay(static_cast<uint8_t>(s), interval, failures);
    };
    EXPECT_EQ(delay(Status::SUCCESS, seconds(300), 0), seconds(300));
    EXPECT_EQ(delay(Status::STALLED, seconds(300), 3), seconds(300)) << "a stall is not a failure";
    EXPECT_EQ(delay(Status::ERROR, seconds(300), 1), seconds(300));
    EXPECT_EQ(delay(Status::ERROR, seconds(300), 2), seconds(600));
    EXPECT_EQ(delay(Status::ERROR, seconds(300), 3), seconds(1200));
    EXPECT_EQ(delay(Status::ERROR, seconds(300), 4), seconds(2400));
    EXPECT_EQ(delay(Status::ERROR, seconds(300), 5), seconds(3600)) << "capped at an hour";
    EXPECT_EQ(delay(Status::ERROR, seconds(300), 1000), seconds(3600));
    EXPECT_EQ(delay(Status::CANCELLED, seconds(300), 2), seconds(600));
    EXPECT_EQ(delay(Status::RUNNING, seconds(300), 1), seconds(300)) << "a pass that never got its status";
    EXPECT_EQ(delay(Status::ERROR, seconds(7200), 4), seconds(7200)) << "never sooner than the vault's own interval";
}

// The 1.25.0 layout, for the record: passes and their operations on one pool of 6 workers. Six passes take every
// worker and wait on operations queued behind them; nothing finishes until the pool is stopped (the "Broken promise"
// errors seen at shutdown).
TEST(SyncPassPool, PassesWaitingOnTheirOwnPoolHang) {
    constexpr unsigned kWorkers = 6;
    const auto shared = std::make_shared<concurrency::ThreadPool>(kWorkers);
    std::atomic<unsigned> started{0}, finished{0};

    struct SharedPoolPass final : concurrency::Task {
        concurrency::ThreadPool* pool = nullptr;
        std::atomic<unsigned>* started = nullptr;
        std::atomic<unsigned>* finished = nullptr;
        void operator()() override {
            ++*started;
            while (started->load() < kWorkers) std::this_thread::sleep_for(std::chrono::milliseconds(1));
            std::vector<std::future<ExpectedFuture>> pending;
            for (int i = 0; i < 3; ++i) {
                auto op = std::make_shared<Operation>();
                pending.push_back(op->getFuture().value());
                pool->submit(op);
            }
            for (auto& f : pending) {
                try {
                    (void)f.get();
                } catch (...) {
                }
            }
            ++*finished;
        }
    };
    for (unsigned i = 0; i < kWorkers; ++i) {
        auto pass = std::make_shared<SharedPoolPass>();
        pass->pool = shared.get();
        pass->started = &started;
        pass->finished = &finished;
        shared->submit(pass);
    }
    ASSERT_TRUE(waitUntil([&] { return started.load() == kWorkers; }, std::chrono::seconds(10)));
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    EXPECT_EQ(finished.load(), 0u) << "every worker holds a pass; the operations they wait for never run";
    EXPECT_EQ(shared->queueDepth(), 3u * kWorkers);

    shared->requestStop();   // drops the queued operations: the waiting passes see broken promises and end
    EXPECT_EQ(shared->join(std::chrono::steady_clock::now() + std::chrono::seconds(10)), 0u);
    EXPECT_EQ(finished.load(), kWorkers);
}

// Nine vaults due together (production) on a 12-core host's sizes: 12 operation workers, 4 passes at a time.
TEST(SyncPassPool, NinePassesDueTogetherCompleteOnA12CoreHost) {
    const PoolSizing sizing({.syncWorkers = ThreadPoolManager::syncWorkersFor(0, 12), .syncPasses = 0});
    std::atomic<unsigned> finished{0};
    for (int i = 0; i < 9; ++i)
        ThreadPoolManager::instance().syncPassPool()->submit(std::make_shared<WaitingPass>(8, &finished));
    EXPECT_TRUE(waitUntil([&] { return finished.load() == 9; }, std::chrono::seconds(60)))
        << finished.load() << " of 9 passes finished";
}

// However few operation workers there are, passes can't take them: six passes, one worker, all complete.
TEST(SyncPassPool, MorePassesThanOperationWorkersStillComplete) {
    const PoolSizing sizing({.syncWorkers = 1, .syncPasses = 6});
    std::atomic<unsigned> finished{0};
    for (int i = 0; i < 6; ++i)
        ThreadPoolManager::instance().syncPassPool()->submit(std::make_shared<WaitingPass>(3, &finished));
    EXPECT_TRUE(waitUntil([&] { return finished.load() == 6; }, std::chrono::seconds(60)))
        << finished.load() << " of 6 passes finished";
}

// ---------------------------------------------------------------------------------------------------- DB-backed

class SyncPassSchedulingDb : public vh::test::db::Suite {
protected:
    // Never started: what the passes queue stays in its run queue, where the tests look.
    inline static std::shared_ptr<sync::Controller> controller;
    inline static std::shared_ptr<sync::Controller> previousController;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_sync_pass_scheduling")) return;
        ThreadPoolManager::instance().shutdown();
        ThreadPoolManager::instance().init();
        previousController = runtime::Deps::get().syncController;
        controller = std::make_shared<sync::Controller>();
        runtime::Deps::setSyncController(controller);
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        sync::Cloud::setEventHooks({});
        storage::remote_access::clear();
        runtime::Deps::setSyncController(previousController);
        controller.reset();
        ThreadPoolManager::instance().shutdown();
        tearDownDbSuite();
    }

    void TearDown() override { sync::Cloud::setEventHooks({}); }

    static CloudVault vault() {
        return test_support::versioned::makeCloudVault(superUser, "sps", Versioning::Unversioned, false);
    }

    static void write(const CloudVault& v, const std::string& path, const std::string& text) {
        (void)fs::Filesystem::createFile({.path = path, .fuse_path = v.engine->vaultPathToFusePath(path),
                                          .buffer = std::vector<uint8_t>(text.begin(), text.end()), .engine = v.engine,
                                          .user = superUser, .overwrite = true});
    }

    static seconds intervalOf(const std::shared_ptr<storage::Engine>& engine) {
        return seconds(engine->sync->interval.count());
    }

    static std::size_t timesQueued(const std::shared_ptr<sync::Local>& task) {
        const auto queued = controller->queuedTasks();
        return static_cast<std::size_t>(std::ranges::count(queued, task));
    }

    // Not running, queued once more than before, and due no sooner than `delay` after `before`.
    static void expectRescheduled(const std::shared_ptr<sync::Local>& task, const std::size_t queuedBefore,
                                  const system_clock::time_point before, const seconds delay) {
        EXPECT_FALSE(task->isRunning()) << "a finished pass must not stay marked running";
        EXPECT_EQ(timesQueued(task), queuedBefore + 1) << "the regular task is queued again";
        EXPECT_GT(task->next_run, system_clock::now()) << "and due in the future";
        EXPECT_GE(task->next_run, before + delay - seconds(2));
        EXPECT_LE(task->next_run, system_clock::now() + delay + seconds(2));
    }

    // What a pass of the vault would upload now (the real planner, nothing executed).
    static std::vector<std::string> plannedUploads(const CloudVault& v) {
        auto cloud = std::make_shared<sync::Cloud>(v.engine);
        cloud->event = std::make_shared<sync::model::Event>();
        cloud->event->vault_id = v.id();
        cloud->event->timestamp_begin = std::time(nullptr);
        db::query::sync::Event::create(cloud->event);
        cloud->initBins();
        std::vector<std::string> out;
        for (const auto& a : cloud->planPass())
            if (a.type == sync::model::ActionType::Upload && a.local) out.push_back(a.local->path.string());
        cloud->clearBins();
        return out;
    }

    static bool indexed(const CloudVault& v, const std::string& path) {
        const auto rows = db::query::sync::RemoteObjectIndex::listFilesForVault(v.id());
        return std::ranges::any_of(rows, [&](const auto& f) { return f && f->path == path; });
    }

    static std::shared_ptr<storage::Engine> localEngine() {
        for (const auto& engine : runtime::Deps::get().storageManager->getEngines())
            if (engine && engine->type() == storage::StorageType::Local && engine->sync) return engine;
        return nullptr;
    }
};

// One upload fails (its local copy is gone): the pass is an ERROR, the upload that succeeded is still recorded, so
// the next pass plans only the failure; the task backs off from the interval and is back to it after a success.
TEST_F(SyncPassSchedulingDb, AFailedUploadIsRetriedAloneAndTheTaskBacksOff) {
    const auto v = vault();
    const auto task = std::make_shared<sync::Cloud>(v.engine);
    const auto interval = intervalOf(v.engine);

    auto queued = timesQueued(task);
    auto before = system_clock::now();
    (*task)();
    ASSERT_EQ(task->event->status, Status::SUCCESS) << task->event->error_message;
    expectRescheduled(task, queued, before, interval);

    write(v, "/a.txt", "alpha");
    write(v, "/b.txt", "bravo");
    const auto b = db::query::fs::File::getFileByPath(v.id(), "/b.txt");
    ASSERT_TRUE(b);
    const auto saved = std::filesystem::temp_directory_path() / ("vh_sps_b_" + vh::test::uniqueTag('s'));
    std::filesystem::copy_file(b->backing_path, saved);
    ASSERT_TRUE(std::filesystem::remove(b->backing_path));

    queued = timesQueued(task);
    before = system_clock::now();
    (*task)();
    EXPECT_EQ(task->event->status, Status::ERROR);
    EXPECT_EQ(task->event->num_failed_ops, 1u);
    EXPECT_EQ(task->consecutiveFailures, 1u);
    expectRescheduled(task, queued, before, interval);
    EXPECT_TRUE(indexed(v, "/a.txt")) << "the upload that succeeded is recorded in the remote index";
    EXPECT_FALSE(indexed(v, "/b.txt"));
    EXPECT_EQ(plannedUploads(v), std::vector<std::string>{"/b.txt"}) << "the next pass retries only the failure";

    queued = timesQueued(task);
    before = system_clock::now();
    (*task)();
    EXPECT_EQ(task->event->status, Status::ERROR);
    EXPECT_EQ(task->consecutiveFailures, 2u);
    expectRescheduled(task, queued, before, 2 * interval);

    std::filesystem::copy_file(saved, b->backing_path);
    std::filesystem::remove(saved);
    queued = timesQueued(task);
    before = system_clock::now();
    (*task)();
    EXPECT_EQ(task->event->status, Status::SUCCESS) << task->event->error_message;
    EXPECT_EQ(task->consecutiveFailures, 0u);
    expectRescheduled(task, queued, before, interval);
    EXPECT_TRUE(indexed(v, "/b.txt"));
    EXPECT_TRUE(plannedUploads(v).empty());
}

// A stage that fails ends the pass: nothing after it runs.
TEST_F(SyncPassSchedulingDb, AStageThatFailsEndsThePass) {
    const auto v = vault();
    const auto task = std::make_shared<sync::Cloud>(v.engine);
    task->startTask();
    bool later = false;
    const sync::Stage stages[] = {
        {"fails", [&] { task->handleError("stage failed (test)"); }},
        {"later", [&] { later = true; }},
    };
    task->runStages(stages);
    EXPECT_FALSE(later) << "a stage after a failed one ran";
    EXPECT_EQ(task->event->status, Status::ERROR);
    task->finishRun();
    EXPECT_FALSE(task->isRunning());
}

// The same through a real pass: initBins throws, so nothing is planned or uploaded, and the task is rescheduled.
TEST_F(SyncPassSchedulingDb, AFailedStageIsRescheduledWithoutRunningTheRest) {
    const auto v = vault();
    write(v, "/pending.txt", "waits for the next pass");
    sync::Cloud::setEventHooks({.baselineNeeded = [](uint32_t) -> bool { throw std::runtime_error("initBins failed (test)"); },
                                .baselineListed = {},
                                .indexFresh = {}});
    const auto task = std::make_shared<sync::Cloud>(v.engine);
    const auto queued = timesQueued(task);
    const auto before = system_clock::now();
    (*task)();
    sync::Cloud::setEventHooks({});
    EXPECT_EQ(task->event->status, Status::ERROR);
    EXPECT_NE(task->event->error_message.find("initBins failed (test)"), std::string::npos) << task->event->error_message;
    expectRescheduled(task, queued, before, intervalOf(v.engine));
    EXPECT_FALSE(indexed(v, "/pending.txt")) << "the sync stage ran after initBins failed";
}

// A request budget and a restricted remote stall the pass: rescheduled at the interval, not counted as a failure.
TEST_F(SyncPassSchedulingDb, StallsAreRescheduledAtTheInterval) {
    const auto v = vault();
    const auto task = std::make_shared<sync::Cloud>(v.engine);
    const auto interval = intervalOf(v.engine);
    (*task)();
    ASSERT_EQ(task->event->status, Status::SUCCESS) << task->event->error_message;

    write(v, "/over-budget.txt", "one PUT too many");
    v.engine->remote_policy()->s3_request_budget.max_put_requests = 0;
    auto queued = timesQueued(task);
    auto before = system_clock::now();
    (*task)();
    v.engine->remote_policy()->s3_request_budget.max_put_requests.reset();
    EXPECT_EQ(task->event->status, Status::STALLED) << task->event->error_message;
    EXPECT_NE(task->event->stall_reason.find("budget"), std::string::npos) << task->event->stall_reason;
    EXPECT_EQ(task->consecutiveFailures, 0u);
    expectRescheduled(task, queued, before, interval);

    (void)storage::remote_access::set(v.id(), storage::remote_access::Mode::ReadOnly, std::string("test"), "system:test");
    queued = timesQueued(task);
    before = system_clock::now();
    (*task)();
    (void)storage::remote_access::set(v.id(), storage::remote_access::Mode::Full, std::nullopt, "system:test");
    EXPECT_EQ(task->event->status, Status::STALLED);
    EXPECT_EQ(task->consecutiveFailures, 0u);
    expectRescheduled(task, queued, before, interval);
}

// startTask throws (here: no statement is prepared on the pool's connections), after the task was marked running.
// It used to be dropped silently with runningFlag set, and every later trigger answered "already running".
TEST_F(SyncPassSchedulingDb, AThrowInStartTaskLeavesTheTaskRescheduledAndNotRunning) {
    const auto v = vault();
    const auto task = std::make_shared<sync::Cloud>(v.engine);
    const auto saved = db::Transactions::dbPool_;
    struct Restore {
        std::shared_ptr<db::DBPool> pool;
        ~Restore() { db::Transactions::dbPool_ = pool; }
    } restore{saved};
    db::Transactions::dbPool_ = std::make_shared<db::DBPool>(2, std::chrono::seconds(5));

    const auto queued = timesQueued(task);
    const auto before = system_clock::now();
    EXPECT_NO_THROW((*task)());
    db::Transactions::dbPool_ = saved;
    EXPECT_EQ(task->event->status, Status::ERROR);
    EXPECT_EQ(task->consecutiveFailures, 1u);
    expectRescheduled(task, queued, before, intervalOf(v.engine));
    EXPECT_FALSE(controller->passRunning(v.id())) << "the pass lease was released";

    (*task)();
    EXPECT_EQ(task->event->status, Status::SUCCESS) << task->event->error_message;
    EXPECT_EQ(task->consecutiveFailures, 0u);
}

// The event can't be saved when the pass ends (it once overflowed an integer column): the task is still rescheduled
// and not running, and the next pass, which saves the previous event once more first, runs normally.
TEST_F(SyncPassSchedulingDb, AThrowInTheEventSaveNeitherDropsTheTaskNorPoisonsTheNextPass) {
    const auto v = vault();
    const auto task = std::make_shared<sync::Cloud>(v.engine);
    task->startTask();
    ASSERT_TRUE(task->isRunning());
    ASSERT_EQ(task->event, v.engine->latestSyncEvent);
    task->event->run_uuid = "not-a-uuid";   // every upsert of this event fails

    const auto queued = timesQueued(task);
    const auto before = system_clock::now();
    EXPECT_NO_THROW(task->finishRun());
    expectRescheduled(task, queued, before, intervalOf(v.engine));

    (*task)();
    EXPECT_EQ(task->event->status, Status::SUCCESS) << task->event->error_message;
    EXPECT_NE(task->event->run_uuid, "not-a-uuid");
}

// Only the vault's regular task is rescheduled: a scoped (event) pass runs once, an interrupted or replaced task
// leaves the queue to its successor, before it starts or mid-pass.
TEST_F(SyncPassSchedulingDb, ScopedAndInterruptedPassesAreNotRescheduled) {
    const auto v = vault();

    auto scope = std::make_shared<sync::model::PassScope>();
    scope->keys.insert(u8"/scoped.txt");
    std::atomic<int> finished{0};
    scope->on_finish = [&](bool, const std::string&) { ++finished; };
    const auto scoped = std::make_shared<sync::Cloud>(v.engine, scope);
    ASSERT_TRUE(controller->tryAcquirePass(v.id()));   // as runScoped does
    scoped->adoptPassLease();
    (*scoped)();
    EXPECT_EQ(finished.load(), 1);
    EXPECT_FALSE(scoped->isRunning());
    EXPECT_EQ(timesQueued(scoped), 0u);
    EXPECT_FALSE(controller->passRunning(v.id()));

    const auto replaced = std::make_shared<sync::Cloud>(v.engine);
    replaced->interrupt();
    (*replaced)();
    EXPECT_FALSE(replaced->isRunning());
    EXPECT_EQ(timesQueued(replaced), 0u);
    EXPECT_EQ(replaced->event->timestamp_begin, 0) << "an interrupted task never starts";

    const auto midPass = std::make_shared<sync::Cloud>(v.engine);
    sync::Cloud::setEventHooks({.baselineNeeded = [midPass](uint32_t) { midPass->interrupt(); return false; },
                                .baselineListed = {},
                                .indexFresh = {}});
    (*midPass)();
    sync::Cloud::setEventHooks({});
    EXPECT_TRUE(midPass->isInterrupted());
    EXPECT_FALSE(midPass->isRunning());
    EXPECT_EQ(timesQueued(midPass), 0u);
}

// sync::Local (a local vault's pass) runs under the same guard.
TEST_F(SyncPassSchedulingDb, ALocalVaultPassIsRescheduled) {
    const auto engine = localEngine();
    ASSERT_TRUE(engine) << "the seed has a local vault";
    const auto task = std::make_shared<sync::Local>(engine);
    const auto queued = timesQueued(task);
    const auto before = system_clock::now();
    (*task)();
    EXPECT_EQ(task->event->status, Status::SUCCESS) << task->event->error_message;
    expectRescheduled(task, queued, before, intervalOf(engine));
    EXPECT_GE(engine->sync->last_sync_at, system_clock::to_time_t(before)) << "the engine's copy follows the sync table";
    EXPECT_GE(engine->sync->last_success_at, system_clock::to_time_t(before));
}

// "value "2862478462" is out of range for type integer": COALESCE($n, 0) made every counter an integer parameter.
TEST_F(SyncPassSchedulingDb, ByteCountsAbove2GiBAreStored) {
    const auto v = vault();
    auto event = std::make_shared<sync::model::Event>();
    event->vault_id = v.id();
    event->timestamp_begin = std::time(nullptr);
    db::query::sync::Event::create(event);

    event->status = Status::SUCCESS;
    event->timestamp_end = std::time(nullptr);
    event->bytes_up = 2'862'478'462ULL;
    event->bytes_down = 5'000'000'000ULL;
    event->num_ops_total = 3'000'000'000ULL;
    event->s3_downloaded_bytes = 6'000'000'000ULL;
    event->s3_estimated_body_download_bytes = 7'000'000'000ULL;
    event->s3_estimated_upload_bytes = 8'000'000'000ULL;
    event->s3_archive_downloads_skipped = 4'294'967'296ULL;
    auto& up = event->getOrCreateThroughput(sync::model::Throughput::Metric::UPLOAD);
    up.size_bytes = 9'000'000'000ULL;
    up.num_ops = 3'000'000'000ULL;
    up.failed_ops = 2'500'000'000ULL;
    up.duration_ms = 4'000'000'000ULL;
    ASSERT_NO_THROW(db::query::sync::Event::upsert(event));

    const auto stored = db::query::sync::Event::getLatest(v.id());
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->run_uuid, event->run_uuid);
    EXPECT_EQ(stored->bytes_up, 2'862'478'462ULL);
    EXPECT_EQ(stored->bytes_down, 5'000'000'000ULL);
    EXPECT_EQ(stored->num_ops_total, 3'000'000'000ULL);
    EXPECT_EQ(stored->s3_downloaded_bytes, 6'000'000'000ULL);
    EXPECT_EQ(stored->s3_estimated_body_download_bytes, 7'000'000'000ULL);
    EXPECT_EQ(stored->s3_estimated_upload_bytes, 8'000'000'000ULL);
    EXPECT_EQ(stored->s3_archive_downloads_skipped, 4'294'967'296ULL);
    const auto it = std::ranges::find_if(stored->throughputs, [](const auto& t) {
        return t && t->metric_type == sync::model::Throughput::Metric::UPLOAD;
    });
    ASSERT_NE(it, stored->throughputs.end());
    EXPECT_EQ((*it)->size_bytes, 9'000'000'000ULL);
    EXPECT_EQ((*it)->num_ops, 3'000'000'000ULL);
    EXPECT_EQ((*it)->failed_ops, 2'500'000'000ULL);
    EXPECT_EQ((*it)->duration_ms, 4'000'000'000ULL);
}

// database.pool_size was parsed and then ignored: every install got 4 connections.
TEST_F(SyncPassSchedulingDb, PoolSizeFromTheConfigReachesThePool) {
    const vh::test::TempDir dir("vh_sps_config");
    const auto path = dir.path() / "config.yaml";
    std::ofstream(path) << "database:\n  pool_size: 7\n";
    const auto cfg = config::loadConfig(path.string());
    ASSERT_EQ(cfg.database.pool_size, 7);

    const auto defaults = dir.path() / "defaults.yaml";
    std::ofstream(defaults) << "database:\n  host: localhost\n";
    EXPECT_EQ(config::loadConfig(defaults.string()).database.pool_size, 24);

    const auto saved = db::Transactions::dbPool_;
    struct Restore {
        std::shared_ptr<db::DBPool> pool;
        ~Restore() { db::Transactions::dbPool_ = pool; }
    } restore{saved};
    db::Transactions::initFromConfig(cfg.database.pool_size);
    ASSERT_TRUE(db::Transactions::dbPool_);
    EXPECT_NE(db::Transactions::dbPool_, saved);
    EXPECT_EQ(db::Transactions::dbPool_->stats().size, 7u);
    db::Transactions::initFromConfig(0);
    EXPECT_EQ(db::Transactions::dbPool_->stats().size, db::DBPool::kMinPoolSize);
}

// A listing reads every row's parent chain in its own transaction: with one pooled connection it completes (it used
// to wait for a second connection while holding the only one, until the acquire timeout).
TEST_F(SyncPassSchedulingDb, ListingsHoldOneConnection) {
    const auto v = vault();
    ASSERT_EQ(fs::Filesystem::mkdir({.path = v.engine->vaultPathToFusePath("/d1"), .engine = v.engine, .user = superUser}), 0);
    ASSERT_EQ(fs::Filesystem::mkdir({.path = v.engine->vaultPathToFusePath("/d1/d2"), .engine = v.engine, .user = superUser}), 0);
    write(v, "/d1/one.txt", "one");
    write(v, "/d1/d2/two.txt", "two");
    write(v, "/d1/d2/three.txt", "three");
    const auto d1 = db::query::fs::Directory::getDirectoryIdByPath(v.id(), "/d1");
    ASSERT_TRUE(d1);

    const auto saved = db::Transactions::dbPool_;
    struct Restore {
        std::shared_ptr<db::DBPool> pool;
        ~Restore() { db::Transactions::dbPool_ = pool; }
    } restore{saved};
    const auto one = std::make_shared<db::DBPool>(1, std::chrono::seconds(3));
    one->initPreparedStatements();
    db::Transactions::dbPool_ = one;

    std::vector<std::shared_ptr<fs::model::File>> files;
    ASSERT_NO_THROW(files = db::query::fs::File::listFilesInDir(v.id()));
    EXPECT_EQ(files.size(), 3u);
    for (const auto& f : files) EXPECT_EQ(f->fuse_path.filename(), f->path.filename()) << f->path;
    EXPECT_NO_THROW((void)db::query::fs::File::getAllFiles(v.id()));
    EXPECT_NO_THROW((void)db::query::fs::Directory::listDirectoriesInDir(*d1, true));
    EXPECT_NO_THROW((void)db::query::fs::Entry::listDir(*d1, true));
    std::vector<std::shared_ptr<fs::model::Entry>> subtree;
    EXPECT_NO_THROW(subtree = db::query::fs::Entry::listSubtree(*d1));
    EXPECT_EQ(subtree.size(), 4u) << "d2 and the three files";
    EXPECT_EQ(one->stats().acquireTimeouts, 0u);
}

// The production hang end to end: seven S3 vaults with files to upload and the seeded local vault, all due at once,
// run by a started sync::Controller with the sync pool of 1.25.0 on a 12-core host (6 workers) for the operations
// and 4 pass threads, over this suite's 4 database connections. Every pass finishes.
TEST_F(SyncPassSchedulingDb, SevenVaultsDueTogetherAllSyncThroughTheController) {
    const PoolSizing sizing({.syncWorkers = 6, .syncPasses = 0});
    std::vector<CloudVault> vaults;
    for (int i = 0; i < 7; ++i) {
        vaults.push_back(vault());
        for (int f = 0; f < 3; ++f) write(vaults.back(), "/f" + std::to_string(f) + ".txt", "file " + std::to_string(f));
    }

    const auto running = std::make_shared<sync::Controller>();
    runtime::Deps::setSyncController(running);
    running->start();
    struct Stop {
        std::shared_ptr<sync::Controller> running;
        ~Stop() {
            running->stop();
            (void)ThreadPoolManager::instance().syncPassPool()->waitIdle(std::chrono::steady_clock::now() + seconds(60));
            runtime::Deps::setSyncController(controller);
        }
    } stop{running};

    const auto synced = [&](const CloudVault& v) {
        const auto latest = db::query::sync::Event::getLatest(v.id());
        return latest && latest->status == Status::SUCCESS &&
               db::query::sync::RemoteObjectIndex::listFilesForVault(v.id()).size() == 3;
    };
    const bool all = waitUntil([&] { return std::ranges::all_of(vaults, synced); }, std::chrono::seconds(240));
    for (const auto& v : vaults) {
        const auto latest = db::query::sync::Event::getLatest(v.id());
        EXPECT_TRUE(synced(v)) << "vault " << v.id() << ": "
                               << (latest ? std::string(sync::model::Event::toString(latest->status)) + " " +
                                                latest->error_message
                                          : std::string("no sync event"));
    }
    EXPECT_TRUE(all);
}

}
