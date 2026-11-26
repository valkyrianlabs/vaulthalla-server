#include "mirror/start/BackgroundContents.hpp"

#include "concurrency/Backoff.hpp"
#include "config/Registry.hpp"
#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "log/Registry.hpp"
#include "mirror/Contents.hpp"
#include "mirror/start/Start.hpp"
#include "peer/Links.hpp"

#include <thread>
#include <vector>

namespace vh::mirror::start {

BackgroundContents::BackgroundContents() : AsyncService("MirrorContents") {}

const std::shared_ptr<BackgroundContents>& BackgroundContents::instance() {
    static const auto service = std::make_shared<BackgroundContents>();
    return service;
}

void BackgroundContents::resetForTesting() {
    std::scoped_lock lock(shared_->mutex);
    shared_->vaults.clear();
}

bool BackgroundContents::waitIdleForTesting(const std::chrono::milliseconds timeout) {
    const auto end = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        {
            std::scoped_lock lock(shared_->mutex);
            bool any = false;
            for (const auto& [_, v] : shared_->vaults) any = any || v.running;
            if (!any) return true;
        }
        if (std::chrono::steady_clock::now() >= end) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
}

std::size_t BackgroundContents::tick() {
    using vh::db::query::mirror::MirrorVaults;
    using vh::db::query::mirror::PendingContents;
    if (!config::Registry::get().peers.experimental) return 0;
    const auto links = vh::peer::linkService();
    if (!links || links->transfers().stopping()) return 0;
    const auto t = transport();
    const auto now = std::chrono::steady_clock::now();
    std::size_t started = 0;
    for (const auto& row : MirrorVaults::list()) {
        if (row.role != "mirror") continue;
        {
            std::scoped_lock lock(shared_->mutex);
            const auto& v = shared_->vaults[row.vault_id];
            if (v.running || now < v.notBefore) continue;
        }
        if (!t.upSince || !t.upSince(row.peer_id)) continue;  // stops with the link
        if (!PendingContents::mayHavePending(row.vault_id) || PendingContents::countOutstanding(row.vault_id) == 0)
            continue;
        {
            std::scoped_lock lock(shared_->mutex);
            shared_->vaults[row.vault_id].running = true;
        }
        const auto shared = shared_;
        const auto vaultId = row.vault_id;
        const bool spawned = links->transfers().spawn([shared, vaultId] {
            std::size_t received = 0;
            try {
                received = vh::mirror::contents::fetchOutstanding(vaultId, kBatch);
            } catch (const std::exception& e) {
                log::Registry::sync()->warn("[MirrorContents] Vault {}: a background fetch failed: {}", vaultId, e.what());
            }
            std::scoped_lock lock(shared->mutex);
            auto& v = shared->vaults[vaultId];
            v.running = false;
            if (received > 0) {
                v.failures = 0;
                v.notBefore = {};
            } else {
                v.notBefore = std::chrono::steady_clock::now() +
                              vh::concurrency::jitteredBackoff(v.failures++, kBackoffFloor, kBackoffCap);
            }
        });
        if (spawned) {
            ++started;
        } else {
            std::scoped_lock lock(shared_->mutex);
            shared_->vaults[row.vault_id].running = false;
        }
    }
    return started;
}

void BackgroundContents::runLoop() {
    while (!shouldStop()) {
        try {
            (void)tick();
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[MirrorContents] {}", e.what());
        }
        lazySleep(kInterval);
    }
}

}
