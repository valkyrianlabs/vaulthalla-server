// Regression guards for daemon shutdown latency. `systemctl stop|restart` used to take ~3s on a healthy daemon (every
// service waited out its own sleep tick in turn, the watchdog its 2s sleep) and 30s plus a SIGKILL once the thread pool
// manager had lent a worker between pools: stopping the borrower joined a thread still parked on the lender's queue.
// Each case bounds wall-clock time, so a regression fails here instead of on an operator's `apt upgrade`.

#include "concurrency/AsyncService.hpp"
#include "concurrency/Task.hpp"
#include "concurrency/ThreadPool.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <future>
#include <memory>
#include <thread>
#include <vector>

namespace vh::concurrency::test_shutdown {

using namespace std::chrono_literals;
using Clock = std::chrono::steady_clock;

namespace {

template <class Fn>
Clock::duration timed(Fn&& fn) {
    const auto start = Clock::now();
    fn();
    return Clock::now() - start;
}

struct FnTask final : Task {
    std::function<void()> fn;
    explicit FnTask(std::function<void()> f) : fn(std::move(f)) {}
    void operator()() override { fn(); }
};

struct PromiseTask final : PromisedTask {
    void operator()() override { promise.set_value(true); }
};

class SleepyService final : public AsyncService {
public:
    SleepyService() : AsyncService("SleepyService") {}
    std::atomic<bool> fullSleep{true};

protected:
    void runLoop() override {
        while (!shouldStop()) fullSleep = lazySleep(std::chrono::hours(1));
    }
};

}

TEST(ShutdownBounds, IdlePoolsStopAtOnce) {
    ThreadPool pool(8);
    EXPECT_EQ(pool.workerCount(), 8u);
    unsigned int detached = 99;
    EXPECT_LT(timed([&] { detached = pool.stop(5s); }), 50ms);
    EXPECT_EQ(detached, 0u);
    EXPECT_EQ(pool.workerCount(), 0u);
}

// The old deadlock: stopping one pool while another pool's worker is parked. Pools no longer share workers, and a
// worker is only ever woken by its own pool's stop.
TEST(ShutdownBounds, StoppingPoolsInAnyOrderNeverWaitsOnAnotherPool) {
    std::vector<std::shared_ptr<ThreadPool>> pools;
    for (int i = 0; i < 6; ++i) pools.push_back(std::make_shared<ThreadPool>(4));
    const auto elapsed = timed([&] {
        for (const auto& pool : pools) pool->requestStop();
        const auto deadline = Clock::now() + 5s;
        for (const auto& pool : pools) EXPECT_EQ(pool->join(deadline), 0u);
    });
    EXPECT_LT(elapsed, 1s);
}

TEST(ShutdownBounds, ATaskThatNeverReturnsCostsTheDeadlineNotForever) {
    auto release = std::make_shared<std::promise<void>>();
    auto started = std::make_shared<std::promise<void>>();
    {
        ThreadPool pool(2);
        pool.submit(std::make_shared<FnTask>([release, started, gate = release->get_future().share()] {
            started->set_value();
            gate.wait();
        }));
        started->get_future().wait();

        unsigned int detached = 0;
        const auto elapsed = timed([&] { detached = pool.stop(200ms); });
        EXPECT_GE(elapsed, 190ms);
        EXPECT_LT(elapsed, 1s);
        EXPECT_EQ(detached, 1u) << "the stuck worker is detached, the idle one joined";
    }
    // The detached worker owns the pool's shared state: finishing its task after the ThreadPool is gone is safe.
    release->set_value();
    std::this_thread::sleep_for(50ms);
}

TEST(ShutdownBounds, QueuedWorkIsDroppedOnStopAndItsWaitersAreReleased) {
    ThreadPool pool(1);
    auto gate = std::make_shared<std::promise<void>>();
    pool.submit(std::make_shared<FnTask>([g = gate->get_future().share()] { g.wait(); }));

    auto queued = std::make_shared<PromiseTask>();
    auto future = *queued->getFuture();
    pool.submit(std::move(queued));

    pool.requestStop();
    EXPECT_THROW(static_cast<void>(future.get()), std::future_error) << "a dropped task's promise is broken, not left hanging";
    gate->set_value();
    EXPECT_EQ(pool.join(Clock::now() + 2s), 0u);

    pool.submit(std::make_shared<PromiseTask>());  // after stop: dropped, never runs
    EXPECT_EQ(pool.queueDepth(), 0u);
}

TEST(ShutdownBounds, WaitIdleReturnsWhenInFlightWorkFinishes) {
    ThreadPool pool(2);
    std::atomic<int> done{0};
    for (int i = 0; i < 4; ++i)
        pool.submit(std::make_shared<FnTask>([&] { std::this_thread::sleep_for(20ms); ++done; }));
    EXPECT_TRUE(pool.waitIdle(Clock::now() + 2s));
    EXPECT_EQ(done.load(), 4);
}

TEST(ShutdownBounds, AServiceSleepingForAnHourStopsAtOnce) {
    SleepyService service;
    service.start();
    std::this_thread::sleep_for(20ms);  // inside lazySleep(1h)
    EXPECT_LT(timed([&] { service.stop(); }), 100ms);
    EXPECT_FALSE(service.isRunning());
    EXPECT_FALSE(service.fullSleep.load()) << "lazySleep reports the interrupted sleep";
}

TEST(ShutdownBounds, RequestStopIsNonBlockingAndIdempotent) {
    SleepyService a, b;
    a.start();
    b.start();
    std::this_thread::sleep_for(20ms);
    EXPECT_LT(timed([&] {
        a.requestStop();
        b.requestStop();
        a.requestStop();
    }), 20ms);
    a.join();
    b.join();
    EXPECT_FALSE(a.isRunning());
    EXPECT_FALSE(b.isRunning());
}

}
