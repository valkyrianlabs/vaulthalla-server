#pragma once

#include "concurrency/AsyncService.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>

namespace vh::vault {

// Runs the bucket layout migrations operators started (vault/LayoutMigration.hpp, #373) on its own thread, never a FUSE
// or request thread: a vault in copying or verifying runs until it cut over or failed (resumed after a restart), a cut
// over vault's manifest check is retried until it passes, a confirmed cleanup runs, and a cleanup_blocked vault is tried
// again once a day. Nothing starts without an operator: a vault without a vault_layout_migration row is never touched.
class LayoutMigrationService final : public concurrency::AsyncService {
public:
    static constexpr auto kPollInterval = std::chrono::seconds(10);
    static constexpr auto kBusyRetry = std::chrono::seconds(30);       // the vault's sync pass held the lease
    static constexpr auto kBlockedRetry = std::chrono::hours(24);      // cleanup_blocked: retried daily

    LayoutMigrationService();
    ~LayoutMigrationService() override = default;

    // One pass over the migration rows (what runLoop does every kPollInterval). Public for tests and ops.
    void runOnce();

protected:
    void runLoop() override;
};

}
