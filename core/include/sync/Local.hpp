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
    void shutdown();
    void newEvent();
    void runStages(std::span<const Stage> stages) const;
};

}
