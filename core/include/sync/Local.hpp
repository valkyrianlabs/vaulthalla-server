#pragma once

#include "concurrency/Task.hpp"
#include "sync/model/Throughput.hpp"
#include "storage/Fwd.hpp"
#include "sync/Fwd.hpp"

#include <memory>
#include <chrono>
#include <future>
#include <functional>
#include <atomic>
#include <exception>
#include <span>
#include <mutex>
#include <vector>

namespace vh::services {
class SyncController;
}

namespace vh::sync {

struct Stage {
    const char* name;
    std::function<void()> fn;
};

struct Local : concurrency::Task, std::enable_shared_from_this<Local> {
    std::chrono::system_clock::time_point next_run;
    std::shared_ptr<storage::Engine> engine;
    std::vector<std::future<ExpectedFuture>> futures;
    std::atomic<bool> runningFlag{false};
    bool runNowFlag{false};
    std::atomic<bool> interruptFlag{false};
    std::shared_ptr<model::Event> event;
    uint8_t trigger{3};
    mutable std::mutex runNowMutex_;
    // What processFutures() saw of each future it last waited on, in push order (true: the operation succeeded).
    std::vector<bool> futureOutcomes;
    // Regular passes in a row that ended in ERROR (reset by a SUCCESS): the next one backs off (retryDelay).
    unsigned int consecutiveFailures{0};

    // Longest wait after failed passes, unless the vault's own interval is longer.
    static constexpr std::chrono::hours kErrorBackoffCap{1};
    // When the next regular pass runs after one that ended with `status`: the interval after SUCCESS and STALLED (a
    // request budget, a stale index, a skipped vault), interval x 2^(failures - 1) after anything else, up to
    // max(interval, kErrorBackoffCap).
    [[nodiscard]] static std::chrono::seconds retryDelay(uint8_t status, std::chrono::seconds interval,
                                                         unsigned int consecutiveFailures);

    Local() = default;
    ~Local() override = default;

    explicit Local(const std::shared_ptr<storage::Engine>& engine);

    void operator()() override;

    // A scoped (event) pass runs once; only the vault's regular task is rescheduled after it runs.
    [[nodiscard]] virtual bool requeueAfterRun() const { return true; }

    [[nodiscard]] unsigned int vaultId() const;

    [[nodiscard]] bool isRunning() const;

    void interrupt();

    [[nodiscard]] bool isInterrupted() const;

    void requeue();

    void runNow(uint8_t trigger = 3);  // sync::Event::Trigger::WEBHOOK

    [[nodiscard]] bool hasPendingRunNow() const;

    [[nodiscard]] bool consumePendingRunNow(uint8_t& trigger);

    std::shared_ptr<model::ScopedOp> op(const model::Throughput::Metric& metric) const;

    virtual void processFutures();

    void push(const std::shared_ptr<Task>& task);
    void handleInterrupt() const;
    void repairAtRestOnce() const;

    void handleVaultKeyRotation();
    void removeTrashedFiles();

    void startTask();
    void processSharedOps();
    [[nodiscard]] bool markBudgetExceededIfAny() const;
    void handleError(const std::string& message) const;
    // An exception that escaped the pass's stages (startTask included): logged and recorded as the pass's error.
    void recordEscapedException(std::exception_ptr error) const;
    // The end of every run, however it ended (RunGuard): not running any more, the event saved, the outcome reported,
    // and a regular task that was not interrupted or replaced rescheduled (rescheduleAfterRun). Never throws.
    void finishRun() noexcept;
    void rescheduleAfterRun();
    void noteSyncTimes(bool success) const;
    void newEvent();
    // Runs the stages in order and stops at the first that fails or stalls (an exception, or the event left in
    // ERROR, STALLED or CANCELLED), or once the task is no longer running.
    void runStages(std::span<const Stage> stages) const;
    [[nodiscard]] bool passEnded() const;

    // Calls finishRun() when a run's scope ends, on every path.
    struct RunGuard {
        Local& task;
        explicit RunGuard(Local& t) : task(t) {}
        RunGuard(const RunGuard&) = delete;
        RunGuard& operator=(const RunGuard&) = delete;
        ~RunGuard() { task.finishRun(); }
    };
};

}
