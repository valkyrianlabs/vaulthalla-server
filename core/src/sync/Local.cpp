#include "sync/Local.hpp"
#include "concurrency/ThreadPoolManager.hpp"
#include "concurrency/ThreadPool.hpp"
#include "sync/Controller.hpp"
#include "storage/Engine.hpp"
#include "storage/CloudEngine.hpp"
#include "sync/model/Policy.hpp"
#include "vault/model/Vault.hpp"
#include "fs/model/File.hpp"
#include "fs/model/file/Trashed.hpp"
#include "fs/model/Path.hpp"
#include "fs/ops/file.hpp"
#include "db/query/fs/File.hpp"
#include "vault/EncryptionManager.hpp"
#include "fs/Filesystem.hpp"
#include "runtime/Deps.hpp"
#include "log/Registry.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/Throughput.hpp"
#include "sync/model/ScopedOp.hpp"
#include "db/query/sync/Policy.hpp"
#include "sync/tasks/RotateKey.hpp"
#include "sync/rotation/Rotation.hpp"
#include "sync/rotation/Runtime.hpp"
#include "sync/tasks/Delete.hpp"
#include "storage/s3/Controller.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "preview/cache/Store.hpp"

#include <algorithm>
#include <mutex>
#include <set>
#include <thread>

using namespace vh::sync;
using namespace vh::sync::model;
using namespace vh::storage;
using namespace vh::services;
using namespace vh::vault::model;
using namespace vh::concurrency;
using namespace std::chrono;
using namespace vh::fs;
using namespace vh::fs::model;
using namespace vh::fs::ops;

Local::Local(const std::shared_ptr<Engine>& engine)
    : engine(engine),
      event(std::make_shared<Event>()) {
    if (!engine || !engine->sync) {
        next_run = system_clock::now() + Policy::DEFAULT_SYNC_INTERVAL;
        return;
    }

    engine->sync->interval = Policy::clampInterval(engine->sync->interval);
    next_run = system_clock::from_time_t(engine->sync->last_sync_at) + seconds(engine->sync->interval.count());
}

void Local::operator()() {
    startTask();

    const Stage stages[] = {
        {"shared",   [this]{ processSharedOps(); }}
    };

    runStages(stages);
    shutdown();
}

void Local::handleInterrupt() const { if (isInterrupted()) throw std::runtime_error("Sync task interrupted"); }

bool Local::isRunning() const { return runningFlag.load(); }

void Local::interrupt() { interruptFlag.store(true); }

bool Local::isInterrupted() const { return interruptFlag.load(); }

void Local::runStages(const std::span<const Stage> stages) const {
    for (const auto& [name, fn] : stages) {
        if (!isRunning()) break;
        try {
            fn();
            if (markBudgetExceededIfAny()) break;
            handleInterrupt();
            if (event) event->heartbeat();
        } catch (const vh::storage::s3::RequestBudgetExceeded& e) {
            event->status = Event::Status::STALLED;
            event->stall_reason = e.what();
            break;
        } catch (const SyncStalled& e) {
            event->status = Event::Status::STALLED;
            event->stall_reason = e.what();
            break;
        } catch (const std::exception& e) {
            handleError(fmt::format("[FSTask:{}] {}", std::string(name), e.what()));
            break;
        } catch (...) {
            handleError(fmt::format("[FSTask:{}] Unknown exception", std::string(name)));
            break;
        }
    }
}

void Local::startTask() {
    if (!engine) {
        log::Registry::sync()->error("[FSTask] Engine is null, cannot proceed with sync.");
        return;
    }

    log::Registry::sync()->debug("[FSTask] Starting sync for vault '{}'", engine->vault->id);

    runningFlag = true;
    db::query::sync::Policy::reportSyncStarted(engine->sync->id);

    newEvent();
    event = engine->latestSyncEvent;
    event->status = Event::Status::RUNNING;
    engine->saveSyncEvent();
    event->start();
}

void Local::processSharedOps() {
    struct NamedOp { const char* name; std::function<void()> fn; };

    const std::vector<NamedOp> ops = {
        {"repairAtRest", [this]{ repairAtRestOnce(); }},
        {"removeTrashedFiles", [this]{ removeTrashedFiles(); }},
        {"handleVaultKeyRotation", [this]{ handleVaultKeyRotation(); }},
      };

    for (const auto& [name, op] : ops) {
        if (!isRunning()) break;

        try {
            op();
            if (markBudgetExceededIfAny()) break;
            handleInterrupt();
            event->heartbeat();
        } catch (const vh::storage::s3::RequestBudgetExceeded& e) {
            event->status = Event::Status::STALLED;
            event->stall_reason = e.what();
            break;
        } catch (const SyncStalled& e) {
            event->status = Event::Status::STALLED;
            event->stall_reason = e.what();
            break;
        } catch (const std::exception& e) {
            handleError(fmt::format("[FSTask] Exception during {}: {}", name, e.what()));
            break;
        }
    }
}

bool Local::markBudgetExceededIfAny() const {
    if (!engine || !event || engine->type() != StorageType::Cloud) return false;

    const auto cloud = std::static_pointer_cast<CloudEngine>(engine);
    const auto metrics = cloud->s3RequestMetrics();
    event->applyS3RequestMetrics(metrics);
    if (!metrics.budget_exceeded) return false;

    event->status = Event::Status::STALLED;
    event->stall_reason = metrics.budget_exceeded_reason;
    event->error_code.clear();
    event->error_message.clear();
    return true;
}

void Local::handleError(const std::string& message) const {
    log::Registry::sync()->error("[FSTask] {}", message);
    event->error_message = message;
    event->status = Event::Status::ERROR;
}

void Local::shutdown() {
    runningFlag = false;
    futures.clear();
    event->stop();
    event->parseCurrentStatus();
    engine->saveSyncEvent();
    if (event->status == Event::Status::SUCCESS) {
        db::query::sync::Policy::reportSyncSuccess(engine->sync->id);
        if (requeueAfterRun()) {
            next_run = hasPendingRunNow()
                ? system_clock::now()
                : system_clock::now() + seconds(engine->sync->interval.count());
            requeue();
            log::Registry::sync()->debug("[FSTask] Sync task requeued for vault '{}'", engine->vault->id);
        }
        log::Registry::sync()->info("[FSTask] Sync completed for vault '{}' in {}s",
                              engine->vault->id, event->durationSeconds());
    } else {
        log::Registry::sync()->error("[FSTask] Sync failed for vault '{}': {}", engine->vault->id, event->error_message);
    }
}

void Local::newEvent() {
    uint8_t runNowTrigger = 3;
    if (consumePendingRunNow(runNowTrigger)) engine->newSyncEvent(runNowTrigger);
    else engine->newSyncEvent();
}

void Local::processFutures() {
    std::size_t failed = 0;
    for (auto& f : futures) {
        try {
            const auto result = f.get();
            const auto* ok = std::get_if<bool>(&result);
            if (ok && !*ok) {
                ++failed;
                log::Registry::sync()->error("[FSTask] Future failed");
            }
        } catch (const std::exception& e) {
            ++failed;
            log::Registry::sync()->error("[FSTask] Future failed: {}", e.what());
        } catch (...) {
            ++failed;
            log::Registry::sync()->error("[FSTask] Future failed");
        }
    }
    futures.clear();

    if (failed > 0 && event && event->status != Event::Status::ERROR &&
        event->status != Event::Status::STALLED &&
        event->status != Event::Status::CANCELLED) {
        handleError(fmt::format("{} async sync operation(s) failed", failed));
    }
}

unsigned int Local::vaultId() const { return engine->vault->id; }

void Local::requeue() {
    runtime::Deps::get().syncController->requeue(shared_from_this());
}

void Local::runNow(const uint8_t trigger) {
    std::scoped_lock lock(runNowMutex_);
    runNowFlag = true;
    this->trigger = trigger;
    next_run = system_clock::now();
}

bool Local::hasPendingRunNow() const {
    std::scoped_lock lock(runNowMutex_);
    return runNowFlag;
}

bool Local::consumePendingRunNow(uint8_t& pendingTrigger) {
    std::scoped_lock lock(runNowMutex_);
    if (!runNowFlag) return false;
    pendingTrigger = trigger;
    runNowFlag = false;
    return true;
}

void Local::push(const std::shared_ptr<Task>& task) {
    futures.push_back(task->getFuture().value());
    concurrency::ThreadPoolManager::instance().syncPool()->submit(task);
}

std::shared_ptr<ScopedOp> Local::op(const Throughput::Metric& metric) const {
    return event->getOrCreateThroughput(metric).newOp();
}

// Copy, move and rename write their bytes themselves, at the alias backing layout (fs::Filesystem). A sync pass
// used to replay 'pending' operation rows by re-encrypting into BACKING_VAULT_ROOT/<vault path>, the layout from
// before alias backing paths; nothing has queued such a row since Filesystem became the primary handler, and the
// operations table now only records activity (#167).

// Once per vault per daemon start: files older builds left in plaintext (or with ciphertext sizes) are brought to
// the at-rest format before anything else reads them (#173).
void Local::repairAtRestOnce() const {
    static std::mutex mutex;
    static std::set<unsigned int> repaired;
    {
        std::scoped_lock lock(mutex);
        if (!repaired.insert(engine->vault->id).second) return;
    }

    // Settle what an interrupted key rotation left behind (`<backing>.vh-rotate`) before anything reads those files.
    if (engine->encryptionManager) {
        try {
            (void)rotation::recoverVault(engine, rotation::runtimeDeps(engine));
        } catch (const std::exception& e) {
            log::Registry::sync()->error("[FSTask] Key rotation sidecar recovery failed for vault '{}': {}",
                                         engine->vault->id, e.what());
        }
    }

    (void)fs::Filesystem::repairAtRest(engine);
}

namespace {

// Rotates files on the sync pool, one RotateKey task per contiguous range, and waits for all of them.
vh::sync::rotation::BatchResult rotateFilesOnSyncPool(const std::shared_ptr<const vh::sync::rotation::Deps>& deps,
                                                     const std::vector<std::shared_ptr<File>>& files) {
    const auto shared = std::make_shared<const vh::sync::tasks::RotateKey::Files>(files);
    const std::size_t workers = std::max(1u, std::thread::hardware_concurrency());
    const auto ranges = vh::sync::rotation::splitRanges(files.size(), std::min(workers, std::max<std::size_t>(1, files.size() / 2)));

    std::vector<std::shared_ptr<vh::sync::tasks::RotateKey>> tasks;
    std::vector<std::future<ExpectedFuture>> pending;
    tasks.reserve(ranges.size());
    pending.reserve(ranges.size());
    for (const auto& [begin, end] : ranges) {
        auto task = std::make_shared<vh::sync::tasks::RotateKey>(deps, shared, begin, end);
        pending.push_back(task->getFuture().value());
        tasks.push_back(task);
        ThreadPoolManager::instance().syncPool()->submit(task);
    }

    vh::sync::rotation::BatchResult total;
    for (std::size_t i = 0; i < tasks.size(); ++i) {
        try {
            (void)pending[i].get();
            total.merge(tasks[i]->result);
        } catch (const std::exception& e) {
            total.failures.push_back({{}, std::string("rotation task did not report: ") + e.what()});
        }
    }
    return total;
}

}

// A rotation finishes (and the previous key is dropped) only when every file on an older key version was re-encrypted
// and committed, nothing an interrupted pass left behind is unresolved, and re-querying the files table finds none
// left. Anything less keeps the rotation in progress with both keys loaded, so every file stays readable, and the
// next sync pass retries (see sync/rotation/Rotation.hpp for the per-file protocol and crash recovery).
void Local::handleVaultKeyRotation() {
    try {
        const auto em = engine->encryptionManager;
        if (!em || !em->rotation_in_progress()) return;

        const auto vaultId = engine->vault->id;
        const auto deps = std::make_shared<const rotation::Deps>(rotation::runtimeDeps(engine));

        rotation::PassDeps pass;
        pass.inProgress = [&em] { return em->rotation_in_progress(); };
        pass.keyVersion = [&em] { return em->get_key_version(); };
        pass.recover = [this, &deps] { return rotation::recoverVault(engine, *deps); };
        pass.pending = [vaultId](const unsigned int keyVersion) {
            return db::query::fs::File::getFilesOlderThanKeyVersion(vaultId, keyVersion);
        };
        pass.rotateAll = [&deps](const std::vector<std::shared_ptr<File>>& files) {
            return rotateFilesOnSyncPool(deps, files);
        };
        if (engine->type() == StorageType::Cloud)
            pass.reconcile = [this, &em] { rotation::reconcileRemoteIndex(engine, em->get_key_version()); };
        pass.finish = [&em] { em->finish_key_rotation(); };

        const auto result = rotation::runPass(pass);
        if (result.status == rotation::PassStatus::Idle) return;

        if (result.status == rotation::PassStatus::Finished) {
            log::Registry::audit()->info(
                "[FSTask] Vault key rotation finished for vault '{}' (key version {}): {} file(s) re-encrypted, {} "
                "rotation sidecar(s) recovered",
                vaultId, result.keyVersion, result.batch.rotated, result.recovery.promoted + result.recovery.discarded);
            // Derived artifacts sealed under the retired key can never be opened again: drop them now rather than
            // one lookup at a time.
            try {
                if (const auto purged = vh::preview::cache::Store::purgeRetiredKeys(engine); purged > 0)
                    log::Registry::sync()->info("[FSTask] Dropped {} derived artifact(s) sealed under a retired key "
                                                "of vault '{}'", purged, vaultId);
            } catch (const std::exception& e) {
                log::Registry::sync()->warn("[FSTask] Failed to drop retired-key derived artifacts of vault '{}': {}",
                                            vaultId, e.what());
            }
            return;
        }

        const auto message = fmt::format(
            "Vault key rotation for vault '{}' is not finished (key version {}): {} of {} file(s) re-encrypted, {} "
            "failed, {} deferred (open), {} changed mid-rotation, {} still on an older key, {} unresolved rotation "
            "sidecar(s){}{}. The previous key stays loaded, so every file remains readable; the next sync pass retries.",
            vaultId, result.keyVersion, result.batch.rotated, result.attempted, result.batch.failures.size(),
            result.batch.deferred, result.batch.conflicts, result.remaining, result.recovery.unresolved,
            result.batch.aborted ? ", stopped early (S3 request budget)" : "",
            result.reconcileError.empty() ? "" : ", remote index not updated: " + result.reconcileError);

        if (result.batch.failures.empty() && result.recovery.unresolved == 0 && result.reconcileError.empty() &&
            !result.batch.aborted) {
            log::Registry::sync()->warn("[FSTask] {}", message);
            return;
        }

        log::Registry::audit()->warn("[FSTask] {}", message);
        handleError(message);
    } catch (const std::exception& e) {
        log::Registry::sync()->error("[FSTask] Exception during vault key rotation for vault '{}': {}", engine->vault->id, e.what());
        runningFlag = false;
    } catch (...) {
        log::Registry::sync()->error("[FSTask] Unknown exception during vault key rotation for vault '{}'", engine->vault->id);
        runningFlag = false;
    }
}

void Local::removeTrashedFiles() {
    const auto files = db::query::fs::File::listTrashedFiles(engine->vault->id);
    if (files.empty()) return;

    if (engine->type() == StorageType::Cloud) {
        const auto cloud = std::static_pointer_cast<CloudEngine>(engine);
        struct PurgedTrash {
            std::shared_ptr<vh::fs::model::file::Trashed> file;
            std::shared_ptr<ScopedOp> scoped;
        };

        std::vector<PurgedTrash> purged;
        purged.reserve(files.size());
        bool remoteIndexMutated = false;
        std::size_t failed = 0;

        for (const auto& file : files) {
            auto scoped = op(Throughput::Metric::DELETE);
            bool purgeSucceeded = false;
            try {
                if (!file) throw std::runtime_error("null trashed file");
                scoped->start(file->size_bytes);
                cloud->purge(file);
                db::query::sync::RemoteObjectIndex::deleteKey(file->vault_id, file->path);
                purged.push_back({file, scoped});
                remoteIndexMutated = true;
                purgeSucceeded = true;
            } catch (const std::exception& e) {
                ++failed;
                log::Registry::sync()->error(
                    "[FSTask] Failed to purge trashed file {}: {}",
                    file ? file->path.string() : std::string{"<null>"},
                    e.what());
            } catch (...) {
                ++failed;
                log::Registry::sync()->error(
                    "[FSTask] Failed to purge trashed file {}: unknown error",
                    file ? file->path.string() : std::string{"<null>"});
            }
            if (!purgeSucceeded) scoped->stop();
        }

        bool manifestPublished = true;
        if (remoteIndexMutated) {
            try {
                cloud->publishRemoteIndexManifestWithRetry();
            } catch (const std::exception& e) {
                ++failed;
                manifestPublished = false;
                log::Registry::sync()->error(
                    "[FSTask] Failed to publish remote index manifest after trash purge: {}",
                    e.what());
            } catch (...) {
                ++failed;
                manifestPublished = false;
                log::Registry::sync()->error(
                    "[FSTask] Failed to publish remote index manifest after trash purge: unknown error");
            }
        }

        for (const auto& done : purged) {
            if (manifestPublished) {
                try {
                    db::query::fs::File::markTrashedFileDeleted(done.file->id);
                    done.scoped->success = true;
                } catch (const std::exception& e) {
                    ++failed;
                    log::Registry::sync()->error(
                        "[FSTask] Failed to mark trashed file {} deleted: {}",
                        done.file ? done.file->path.string() : std::string{"<null>"},
                        e.what());
                } catch (...) {
                    ++failed;
                    log::Registry::sync()->error(
                        "[FSTask] Failed to mark trashed file {} deleted: unknown error",
                        done.file ? done.file->path.string() : std::string{"<null>"});
                }
            }
            done.scoped->stop();
        }

        if (failed > 0) {
            handleError(fmt::format("{} trashed cloud file purge(s) failed", failed));
            runningFlag = false;
        }

        return;
    }

    futures.reserve(files.size());
    for (const auto& file : files)
        push(std::make_shared<tasks::Delete>(engine, file, op(Throughput::Metric::DELETE), tasks::Delete::Type::LOCAL));

    processFutures();
}
