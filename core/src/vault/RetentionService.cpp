#include "vault/RetentionService.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/Retention.hpp"
#include "recovery/usage/Ledger.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"

#include <thread>

namespace vh::vault {

namespace {

// Retired vault keys unsealed for recovery leave memory once idle, whether or not anything asks for them again.
void retentionEvictIdleKeys() noexcept {
    try {
        const auto& manager = runtime::Deps::get().storageManager;
        if (!manager) return;
        std::size_t evicted = 0;
        for (const auto& engine : manager->getEngines())
            if (engine && engine->encryptionManager) evicted += engine->encryptionManager->evictIdleHistoricalKeys();
        if (evicted)
            log::Registry::crypto()->debug("[VaultRetention] Dropped {} idle retired key(s) from memory", evicted);
    } catch (const std::exception& e) {
        log::Registry::vaulthalla()->warn("[VaultRetention] Idle key eviction failed: {}", e.what());
    }
}

}

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
        retentionEvictIdleKeys();

        for (auto waited = std::chrono::milliseconds(0); waited < kInterval && !shouldStop(); waited += tick) {
            if (retention::takePassRequest()) break;
            lazySleep(tick);  // a stop request wakes it at once
        }
    }
}

}
