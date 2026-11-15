#include "cloud/StorageService.hpp"

#include "log/Registry.hpp"
#include "ops/CloudStorage.hpp"

namespace vh::cloud {

StorageService::StorageService() : AsyncService("CloudStorageService") { ops::cloud_storage::installHooks(); }

void StorageService::runLoop() {
    constexpr auto look = std::chrono::milliseconds(250);
    while (!shouldStop()) {
        const bool woken = ops::cloud_storage::takeWake();
        try {
            (void)ops::cloud_storage::tick(woken);
        } catch (const std::exception& e) {
            // tick() records its own failures; the database may be down. The next pass retries.
            log::Registry::cloud()->warn("[CloudStorageService] Pass failed: {}", e.what());
        }
        for (auto waited = std::chrono::milliseconds(0); waited < kTick && !shouldStop(); waited += look) {
            if (ops::cloud_storage::takeWakePeek()) break;
            lazySleep(look);
        }
    }
}

}
