#include "vault/LayoutMigrationService.hpp"

#include "db/query/vault/LayoutMigration.hpp"
#include "log/Registry.hpp"
#include "recovery/Store.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "vault/LayoutMigration.hpp"
#include "vault/model/Vault.hpp"

#include <ctime>
#include <filesystem>
#include <system_error>

namespace vh::vault {

namespace layout_service_detail {

std::shared_ptr<storage::CloudEngine> cloudEngine(const uint32_t vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    return manager ? std::dynamic_pointer_cast<storage::CloudEngine>(manager->getEngine(vaultId)) : nullptr;
}

// Temp files of runs a crash interrupted (sealed bytes only): nothing references them.
void sweepTemps() {
    std::error_code ec;
    std::filesystem::remove_all(recovery::store::root().parent_path() / ".vh-layout", ec);
}

}

LayoutMigrationService::LayoutMigrationService() : AsyncService("LayoutMigrationService") {}

void LayoutMigrationService::runOnce() {
    namespace d = layout_service_detail;
    using layout::State;
    const auto stop = [this] { return shouldStop(); };
    for (const auto& row : db::query::vault::LayoutMigration::list()) {
        if (shouldStop()) return;
        const auto engine = d::cloudEngine(row.vault_id);
        if (!engine) continue;
        try {
            const bool run = row.state == State::Copying || row.state == State::Verifying ||
                             (row.state == State::CutOver && !row.manifest_verified_at);
            if (run) {
                auto deps = layout::runtimeRunDeps();
                deps.stop = stop;
                const auto result = layout::run(engine, deps);
                if (result.state == State::Failed)
                    log::Registry::cloud()->error("[LayoutMigration] Vault {}: migration failed, still path_v0, nothing "
                                                  "deleted: {}", row.vault_id, result.error.value_or("?"));
                continue;
            }
            const bool confirmed = row.cleanup_confirmed_at.has_value();
            const bool cleanupDue =
                confirmed && (row.state == State::Cleanup ||
                              (row.state == State::CleanupBlocked &&
                               (!row.cleanup_run_at ||
                                std::time(nullptr) - *row.cleanup_run_at >=
                                    std::chrono::duration_cast<std::chrono::seconds>(kBlockedRetry).count())));
            if (cleanupDue) {
                const auto result = layout::runCleanup(*engine, {.stop = stop});
                log::Registry::cloud()->info("[LayoutMigration] Vault {}: cleanup deleted {} legacy version(s); {} "
                                             "blocked, {} failed; {}", row.vault_id, result.deleted, result.blocked,
                                             result.failed, layout::to_string(result.state));
            }
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[LayoutMigration] Vault {}: {}", row.vault_id, e.what());
            try {
                db::query::vault::LayoutMigration::setError(row.vault_id, e.what());
            } catch (const std::exception&) {
            }
        }
    }
}

void LayoutMigrationService::runLoop() {
    layout_service_detail::sweepTemps();
    while (!shouldStop()) {
        try {
            runOnce();
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[LayoutMigration] Pass failed: {}", e.what());   // the database may be down
        }
        (void)lazySleep(kPollInterval);
    }
}

}
