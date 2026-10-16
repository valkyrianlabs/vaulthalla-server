#include "sync/Controller.hpp"
#include "storage/Manager.hpp"
#include "concurrency/ThreadPoolManager.hpp"
#include "sync/Local.hpp"
#include "sync/Cloud.hpp"
#include "sync/model/Policy.hpp"
#include "concurrency/ThreadPool.hpp"
#include "storage/CloudEngine.hpp"
#include "db/query/vault/Vault.hpp"
#include "vault/model/Vault.hpp"
#include "runtime/Deps.hpp"
#include "log/Registry.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/Scope.hpp"

#include <unordered_set>
#include <thread>

namespace vh::sync {

namespace {
// Upper bound on one idle wait, so shouldStop() and the periodic engine refresh are honored even without a notify.
constexpr std::chrono::seconds kMaxIdleWait{1};
}

using vh::concurrency::AsyncService;
using vh::concurrency::ThreadPoolManager;
using vh::storage::Engine;
using vh::storage::StorageType;

bool FSTaskCompare::operator()(const std::shared_ptr<Local>& a, const std::shared_ptr<Local>& b) const {
    return a->next_run > b->next_run; // Min-heap based on next_run time
}

Controller::Controller()
    : AsyncService("SyncController") {}

void Controller::requeue(const std::shared_ptr<Local>& task) {
    {
        std::scoped_lock lock(pqMutex_);
        pq.push(task);
    }
    pqCv_.notify_one();
    log::Registry::sync()->debug("[SyncController] Requeued task for vault ID: {}", task->vaultId());
}

void Controller::onStop() {
    // Under the lock: the run loop re-checks shouldStop() while holding it before it waits, so this can't be lost.
    std::scoped_lock lock(pqMutex_);
    pqCv_.notify_all();
}

void Controller::interruptTask(const unsigned int vaultId) {
    std::scoped_lock lock(taskMapMutex_, pqMutex_);

    if (!taskMap_.contains(vaultId)) {
        log::Registry::sync()->error("[SyncController] No task found for vault ID: {}", vaultId);
        return;
    }

    if (const auto& task = taskMap_[vaultId]) {
        task->interrupt();
        log::Registry::sync()->info("[SyncController] Interrupted task for vault ID: {}", vaultId);
    } else log::Registry::sync()->error("[SyncController] Task for vault ID: {} is null", vaultId);
}

void Controller::runLoop() {
    refreshEngines();
    std::chrono::system_clock::time_point lastRefresh = std::chrono::system_clock::now();
    unsigned int refreshTries = 0;

    while (!shouldStop()) {
        if (std::chrono::system_clock::now() - lastRefresh > std::chrono::minutes(5)) {
            log::Registry::sync()->debug("[SyncController] Refreshing sync engines...");
            refreshEngines();
            lastRefresh = std::chrono::system_clock::now();
        }

        bool pqIsEmpty = false;
        {
            std::scoped_lock lock(pqMutex_);
            pqIsEmpty = pq.empty();
        }

        if (pqIsEmpty) {
            if (++refreshTries > 3) lazySleep(std::chrono::seconds(3));
            refreshEngines();
            continue;
        }

        refreshTries = 0;
        std::shared_ptr<Local> task;

        {
            std::unique_lock lock(pqMutex_);
            if (shouldStop()) break;
            if (pq.empty()) continue;
            const auto& top = pq.top();
            const auto now = std::chrono::system_clock::now();
            if (top && !top->isInterrupted() && top->next_run > now) {
                // Not due yet: sleep until it is, until a task is queued, or until stop. This used to pop and
                // re-push the task in a tight loop, which kept one core at 100% whenever a sync was scheduled.
                pqCv_.wait_until(lock, std::min(top->next_run, now + kMaxIdleWait));
                continue;
            }
            task = top;
            pq.pop();
        }

        if (!task || task->isInterrupted()) continue;
        ThreadPoolManager::instance().syncPool()->submit(task);
    }
}

Controller::RunNowResult Controller::runNow(const unsigned int vaultId, const uint8_t trigger) {
    log::Registry::sync()->debug("[SyncController] Early sync request for vault ID: {}", vaultId);

    std::shared_ptr<Local> task;

    {
        std::scoped_lock lock(taskMapMutex_);
        if (!taskMap_.contains(vaultId)) {
            log::Registry::sync()->warn("[SyncController] No task found for vault ID: {}, refreshing sync engines", vaultId);
        } else {
            task = taskMap_[vaultId];
        }
    }

    if (!task) {
        refreshEngines();

        std::scoped_lock lock(taskMapMutex_);
        if (!taskMap_.contains(vaultId)) {
            log::Registry::sync()->error("[SyncController] No task found for vault ID: {} after refresh", vaultId);
            return RunNowResult::NoTask;
        }
        task = taskMap_[vaultId];
    }

    if (task->isRunning()) {
        task->runNow(trigger);
        log::Registry::sync()->debug(
            "[SyncController] Sync already running for vault ID: {}; queued immediate rerun",
            vaultId);
        return RunNowResult::Rerun;
    }

    task->interrupt();

    task = createTask(task->engine);
    task->runNow(trigger);

    {
        std::scoped_lock lock(taskMapMutex_, pqMutex_);
        taskMap_[vaultId] = task;
        pq.push(task);
    }
    pqCv_.notify_one();

    return RunNowResult::Started;
}

Controller::ScopedResult Controller::runScoped(const unsigned int vaultId, std::shared_ptr<model::PassScope> scope) {
    if (!scope) return ScopedResult::NoEngine;
    const auto& storage = runtime::Deps::get().storageManager;
    const auto engine = storage ? storage->getEngine(vaultId) : nullptr;
    if (!engine || engine->type() != StorageType::Cloud) return ScopedResult::NoEngine;
    {
        std::shared_lock lock(engine->mutex);
        if (!engine->sync || !engine->sync->enabled) return ScopedResult::Disabled;
    }
    if (!tryAcquirePass(vaultId)) return ScopedResult::Busy;

    try {
        auto task = std::make_shared<Cloud>(engine, std::move(scope));
        task->runNow(static_cast<uint8_t>(model::Event::Trigger::WEBHOOK));
        // The task owns the lease from here: it releases it when it runs, or when it is destroyed unrun (a pool that
        // drops queued work while stopping).
        task->adoptPassLease();
        ThreadPoolManager::instance().syncPool()->submit(task);
    } catch (...) {
        releasePass(vaultId);
        throw;
    }
    log::Registry::sync()->debug("[SyncController] Scoped (event) sync started for vault ID: {}", vaultId);
    return ScopedResult::Started;
}

bool Controller::tryAcquirePass(const unsigned int vaultId) {
    std::scoped_lock lock(passMutex_);
    return activePasses_.insert(vaultId).second;
}

void Controller::releasePass(const unsigned int vaultId) {
    std::scoped_lock lock(passMutex_);
    activePasses_.erase(vaultId);
}

bool Controller::passRunning(const unsigned int vaultId) const {
    std::scoped_lock lock(passMutex_);
    return activePasses_.contains(vaultId);
}

void Controller::markRegularWaiting(const unsigned int vaultId) {
    std::scoped_lock lock(passMutex_);
    regularWaiting_.try_emplace(vaultId, std::chrono::steady_clock::now());
}

void Controller::clearRegularWaiting(const unsigned int vaultId) {
    std::scoped_lock lock(passMutex_);
    regularWaiting_.erase(vaultId);
}

bool Controller::regularWaiting(const unsigned int vaultId) const {
    std::scoped_lock lock(passMutex_);
    const auto it = regularWaiting_.find(vaultId);
    return it != regularWaiting_.end() && std::chrono::steady_clock::now() - it->second < kRegularWaitBound;
}

void Controller::refreshEngines() {
    const auto latestEngines = runtime::Deps::get().storageManager->getEngines();
    pruneStaleTasks(latestEngines);
    for (const auto& engine : latestEngines) processTask(engine);
}

void Controller::pruneStaleTasks(const std::vector<std::shared_ptr<Engine> >& engines) {
    // The live vault ids. A bitset sized by MAX(vault.id) asserted (or read out of bounds) for an engine or task whose
    // vault row was gone, e.g. a vault purged by the retention service (#162).
    std::unordered_set<unsigned int> live;
    for (const auto& engine : engines)
        if (engine && engine->vault) live.insert(engine->vault->id);

    {
        std::unique_lock lock(taskMapMutex_);

        // Remove engines that are no longer present
        std::vector<unsigned int> staleIds;

        for (const auto& [id, task] : taskMap_)
            if (!live.contains(task->vaultId())) staleIds.push_back(id);

        for (auto id : staleIds) taskMap_.erase(id);
    }
}


void Controller::processTask(const std::shared_ptr<Engine>& engine) {
    // Wakes runLoop after any push below (taken after the locks are released: the destructor runs last).
    struct Notify { std::condition_variable& cv; ~Notify() { cv.notify_one(); } } notify{pqCv_};
    std::scoped_lock lock(taskMapMutex_, pqMutex_);

    if (!engine || !engine->sync || !engine->sync->enabled) {
        if (engine && taskMap_.contains(engine->vault->id)) {
            if (const auto& task = taskMap_[engine->vault->id]) task->interrupt();
            taskMap_.erase(engine->vault->id);
        }
        return;
    }

    const auto existing = taskMap_.find(engine->vault->id);
    if (existing == taskMap_.end()) {
        const auto task = createTask(engine);
        taskMap_[engine->vault->id] = task;
        pq.push(task);
        return;
    }

    if (!existing->second || existing->second->engine != engine) {
        if (existing->second) existing->second->interrupt();
        const auto task = createTask(engine);
        taskMap_[engine->vault->id] = task;
        pq.push(task);
    }
}

std::shared_ptr<Local> Controller::createTask(const std::shared_ptr<Engine>& engine) {
    if (engine->type() == StorageType::Local) return createTask<Local>(engine);
    if (engine->type() == StorageType::Cloud) return createTask<Cloud>(engine);
    throw std::runtime_error("Unsupported StorageType: " + std::to_string(static_cast<int>(engine->type())));
}

}
