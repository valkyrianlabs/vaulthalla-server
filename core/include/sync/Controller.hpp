#pragma once

#include "concurrency/AsyncService.hpp"
#include "storage/Fwd.hpp"
#include "sync/Fwd.hpp"

#include <condition_variable>
#include <memory>
#include <queue>
#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include <shared_mutex>

namespace vh::sync {

struct Local;

struct FSTaskCompare {
    bool operator()(const std::shared_ptr<Local>& a, const std::shared_ptr<Local>& b) const;
};

class Controller final : public concurrency::AsyncService, std::enable_shared_from_this<Controller> {
public:
    Controller();
    ~Controller() override = default;

    void requeue(const std::shared_ptr<Local>& task);

    void interruptTask(unsigned int vaultId);

    // What an early-sync request actually did, so callers can report it truthfully.
    enum class RunNowResult {
        Started,      // a fresh sync task was scheduled to run immediately
        Rerun,        // a sync was already running; an immediate rerun was queued behind it
        NoTask        // no sync task exists for the vault (unknown vault, or its engine isn't loaded)
    };

    RunNowResult runNow(unsigned int vaultId, uint8_t trigger = 3); // Event::Trigger::WEBHOOK

    // Event-driven sync (#96): reconcile only the keys in `scope` on the sync pool, recorded as a webhook-triggered
    // sync event. Busy while another pass of the vault runs (the caller retries; nothing is lost); Disabled when the
    // vault's sync is off; NoEngine for unknown or non-S3 vaults.
    enum class ScopedResult { Started, Busy, Disabled, NoEngine };
    ScopedResult runScoped(unsigned int vaultId, std::shared_ptr<model::PassScope> scope);

    // One pass per vault at a time, regular or scoped. Regular Cloud passes take it when they start; runScoped takes
    // it before submitting. Released by the pass when it ends.
    [[nodiscard]] bool tryAcquirePass(unsigned int vaultId);
    void releasePass(unsigned int vaultId);
    [[nodiscard]] bool passRunning(unsigned int vaultId) const;

    void refreshEngines();

protected:
    void runLoop() override;
    void onStop() override;

private:
    friend struct Local;
    friend struct Cloud;

    std::priority_queue<std::shared_ptr<Local>,
                    std::vector<std::shared_ptr<Local>>,
                    FSTaskCompare> pq;

    mutable std::mutex pqMutex_;
    // Signalled whenever a task is queued and on stop, so runLoop can sleep until the earliest task is due.
    std::condition_variable pqCv_;
    mutable std::shared_mutex taskMapMutex_;

    std::unordered_map<unsigned int, std::shared_ptr<Local>> taskMap_{};

    mutable std::mutex passMutex_;
    std::unordered_set<unsigned int> activePasses_;

    void pruneStaleTasks(const std::vector<std::shared_ptr<storage::Engine>>& engines);

    void processTask(const std::shared_ptr<storage::Engine>& engine);

    std::shared_ptr<Local> createTask(const std::shared_ptr<storage::Engine>& engine);

    template <typename T>
    std::shared_ptr<T> createTask(const std::shared_ptr<storage::Engine>& engine) {
        auto task = std::make_shared<T>(engine);
        return task;
    }
};

}
