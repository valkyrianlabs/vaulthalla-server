#pragma once

#include "concurrency/AsyncService.hpp"

#include <chrono>

// The managed-storage service (design/cloud/managed-remotes.md, "The cloud storage service"): while this server is
// linked it runs ops::cloud_storage::tick on its own thread, never a FUSE, sync or ws thread and never inside a
// transaction. A pass fetches the account's storage state when due (cloud.storage.poll_minutes; every 15 s for five
// minutes after a switch or a billing handoff), hosts the account recovery key check (daily, hourly after a failure,
// at once when asked: it replaces the earlier key-only service) and moves each managed vault one step. Unlinked, it does
// nothing and contacts nobody; without a confirmed account key it only runs the key check.
namespace vh::cloud {

class StorageService final : public concurrency::AsyncService {
public:
    static constexpr auto kTick = std::chrono::seconds(30);

    StorageService();
    ~StorageService() override = default;

protected:
    void runLoop() override;
};

}
