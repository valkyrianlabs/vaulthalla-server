#include "cloud/KeyService.hpp"

#include "db/query/cloud/Link.hpp"
#include "log/Registry.hpp"
#include "ops/CloudKeys.hpp"

#include <atomic>
#include <ctime>

namespace vh::cloud {

// Named, not anonymous: the unity build joins this file with others.
namespace key_service_detail {

std::atomic<bool> requested{false};

// Whether the linked row's last check is old enough for another (none recorded: now).
bool due(const db::query::cloud::LinkRow& row) {
    if (!row.key_checked_at) return true;
    const bool settled = row.key_check == "ok" || row.key_check == "none";
    const auto wait = settled ? KeyService::kInterval : KeyService::kRetry;
    return std::time(nullptr) - *row.key_checked_at >= std::chrono::duration_cast<std::chrono::seconds>(wait).count();
}

}

KeyService::KeyService() : AsyncService("CloudKeyService") {}

void KeyService::requestCheck() { key_service_detail::requested = true; }

void KeyService::runLoop() {
    constexpr auto tick = std::chrono::milliseconds(250);
    constexpr auto look = std::chrono::seconds(60);
    while (!shouldStop()) {
        try {
            const auto row = db::query::cloud::Link::get();
            const bool linked = row && row->status == "linked";
            const bool asked = key_service_detail::requested.exchange(false);
            if (linked && (asked || key_service_detail::due(*row)))
                (void)ops::cloud_keys::check(asked ? "requested" : "scheduled");
        } catch (const std::exception& e) {
            // The database or the cloud may be down: nothing changed, and the next tick retries.
            log::Registry::vaulthalla()->warn("[CloudKeyService] Account recovery key check failed: {}", e.what());
        }
        for (auto waited = std::chrono::milliseconds(0); waited < look && !shouldStop(); waited += tick) {
            if (key_service_detail::requested) break;
            lazySleep(tick);
        }
    }
}

}
