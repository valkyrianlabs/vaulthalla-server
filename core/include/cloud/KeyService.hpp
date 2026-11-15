#pragma once

#include "concurrency/AsyncService.hpp"

#include <chrono>

// The background check of the linked account's recovery key (design/cloud/key-manager.md, "Fetch"): while this server
// is linked, ops::cloud_keys::check runs daily (hourly after a check that couldn't reach the cloud), and at once when
// requestCheck() asks (the ws cloud.key.refresh). Its own thread: never a FUSE, sync or ws thread, never inside a
// transaction. Unlinked, it does nothing and contacts nobody. The managed-storage service (managed-remotes.md) is meant
// to host this check later.
namespace vh::cloud {

class KeyService final : public concurrency::AsyncService {
public:
    static constexpr auto kInterval = std::chrono::hours(24);
    static constexpr auto kRetry = std::chrono::hours(1);

    KeyService();
    ~KeyService() override = default;

    // Asks for a check on the next tick (a few seconds at most).
    static void requestCheck();

protected:
    void runLoop() override;
};

}
