#include "vault/RetentionService.hpp"
#include "vault/Retention.hpp"
#include "recovery/usage/Ledger.hpp"
#include "log/Registry.hpp"

#include <thread>

namespace vh::vault {

RetentionService::RetentionService() : AsyncService("VaultRetentionService") {}

void RetentionService::runLoop() {
    constexpr auto tick = std::chrono::milliseconds(250);
    while (!shouldStop()) {
        try {
            const auto result = retention::runPass(std::chrono::system_clock::now(), [this] { return shouldStop(); });
            if (result.purged || result.failed || result.keys_expired)
                log::Registry::vaulthalla()->info("[VaultRetention] Pass: {} purged, {} failed, {} continuing, {} key(s) expired",
                                                  result.purged, result.failed, result.deferred, result.keys_expired);
            // An upstream purge that used up this pass's share continues right away (bounded per pass).
            if (result.deferred) retention::requestPass();
        } catch (const std::exception& e) {
            // The database may be down; the next pass retries. Purges are resumable from any point.
            log::Registry::vaulthalla()->warn("[VaultRetention] Retention pass failed: {}", e.what());
        }

        // File recovery's local usage ledger rides on this loop: flushed every 60 s, cost alerts at most hourly.
        recovery::usage::tick(std::chrono::system_clock::now());

        for (auto waited = std::chrono::milliseconds(0); waited < kInterval && !shouldStop(); waited += tick) {
            if (retention::takePassRequest()) break;
            lazySleep(tick);  // a stop request wakes it at once
        }
    }
}

}
