#include "vault/RemoteAttachService.hpp"

#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/RemoteDetach.hpp"
#include "log/Registry.hpp"
#include "recovery/Store.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/RemoteAttach.hpp"
#include "vault/RemoteDetach.hpp"

#include <filesystem>
#include <system_error>

namespace vh::vault {

namespace remote_service_detail {

using Q = db::query::vault::RemoteAttach;

// A rotation asked for while the attach ran (remote::queueRotation): started now that it ended.
void startQueuedRotation(const uint32_t vaultId) {
    if (!Q::takeQueuedRotation(vaultId)) return;
    const auto& manager = runtime::Deps::get().storageManager;
    const auto engine = manager ? manager->getEngine(vaultId) : nullptr;
    if (!engine || !engine->encryptionManager) {
        log::Registry::crypto()->warn("[RemoteAttach] Vault {}: the queued key rotation was not started (the vault's "
                                      "keys are not loaded); run vh vault keys rotate {}", vaultId, vaultId);
        return;
    }
    engine->encryptionManager->prepare_key_rotation();
    log::Registry::crypto()->info("[RemoteAttach] Vault {}: started the key rotation that waited for the attach",
                                  vaultId);
}

}

RemoteAttachService::RemoteAttachService() : AsyncService("RemoteAttachService") {}

void RemoteAttachService::runOnce() {
    namespace d = remote_service_detail;
    using remote::State;
    // Called directly (tests, ops) the service isn't running and nothing asks it to stop; on its own thread a stop
    // request ends the pass between objects.
    const auto stop = [this] { return isRunning() && shouldStop(); };
    for (const auto& row : d::Q::list()) {
        if (stop()) return;
        try {
            const bool terminal = row.state == State::Done || row.state == State::Failed || row.state == State::Aborted;
            if (row.abort_requested_at && remote::beforeCutover(row.state)) {
                const auto now = std::time(nullptr);
                const auto tried = abortTried_.find(row.vault_id);
                const auto retry = std::chrono::duration_cast<std::chrono::seconds>(kAbortRetry).count();
                if (tried != abortTried_.end() && now - tried->second < retry && tried->second >= *row.abort_requested_at)
                    continue;
                const auto result = remote::runAbort(row.vault_id, stop);
                if (result.state == State::Aborted) {
                    abortTried_.erase(row.vault_id);
                    log::Registry::cloud()->info("[RemoteAttach] Vault {}: aborted; {} recorded object(s) deleted, the "
                                                 "vault was never changed", row.vault_id, result.deleted);
                    d::startQueuedRotation(row.vault_id);
                } else {
                    abortTried_[row.vault_id] = now;
                    log::Registry::cloud()->warn("[RemoteAttach] Vault {}: abort left {} object(s) the provider would "
                                                 "not delete; retried later", row.vault_id, result.remaining);
                }
                continue;
            }
            if (terminal) {
                if (row.rotation_queued_at) d::startQueuedRotation(row.vault_id);
                continue;
            }
            auto deps = remote::runtimeRunDeps();
            deps.stop = stop;
            const auto result = remote::run(row.vault_id, deps);
            if (result.state == State::Failed)
                log::Registry::cloud()->error("[RemoteAttach] Vault {}: attaching the remote failed; the vault is still "
                                              "local and untouched: {}", row.vault_id, result.error.value_or("?"));
            if (result.state == State::Done || result.state == State::Failed) d::startQueuedRotation(row.vault_id);
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[RemoteAttach] Vault {}: {}", row.vault_id, e.what());
            try {
                d::Q::setError(row.vault_id, e.what());
            } catch (const std::exception&) {
            }
        }
    }

    // Detaches (vault/RemoteDetach.hpp): nothing in the bucket is written or deleted, so an abort needs no retry.
    using DetachQ = db::query::vault::RemoteDetach;
    namespace rd = remote::detach;
    for (const auto& row : DetachQ::list()) {
        if (stop()) return;
        try {
            if (row.abort_requested_at && rd::beforeCutover(row.state)) {
                const auto result = rd::runAbort(row.vault_id);
                log::Registry::cloud()->info("[RemoteDetach] Vault {}: aborted; the vault is still an S3 vault ({} "
                                             "copied envelope(s) cleared, {} kept)", row.vault_id,
                                             result.envelopes_cleared, result.envelopes_kept);
                continue;
            }
            if (!rd::running(row.state)) continue;
            auto deps = rd::runtimeRunDeps();
            deps.stop = stop;
            const auto result = rd::run(row.vault_id, deps);
            if (result.state == rd::State::Failed)
                log::Registry::cloud()->error("[RemoteDetach] Vault {}: detaching the remote failed; the vault is still "
                                              "an S3 vault: {}", row.vault_id, result.error.value_or("?"));
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[RemoteDetach] Vault {}: {}", row.vault_id, e.what());
            try {
                DetachQ::setError(row.vault_id, e.what());
            } catch (const std::exception&) {
            }
        }
    }
}

void RemoteAttachService::runLoop() {
    // Temp files of runs a crash interrupted (hard links of sealed backing files, objects read back): nothing
    // references them.
    std::error_code ec;
    std::filesystem::remove_all(recovery::store::root().parent_path() / ".vh-attach", ec);
    while (!shouldStop()) {
        try {
            runOnce();
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[RemoteAttach] Pass failed: {}", e.what());   // the database may be down
        }
        (void)lazySleep(kPollInterval);
    }
}

}
