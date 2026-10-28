#pragma once

#include "concurrency/AsyncService.hpp"

#include <chrono>
#include <cstdint>

namespace vh::stats {

namespace detail { struct RuntimeWindowAccumulator; }

class SnapshotService final : public concurrency::AsyncService {
public:
    SnapshotService();

    // Deletes history past stats_snapshots' retention: snapshots and raw samples after retention_days, each rollup
    // tier after its own rollup_*_retention_days. Runs once a day from runLoop(); public for the tests.
    static void purgeOldSnapshots();

protected:
    void runLoop() override;

private:
    void collectRuntimeSnapshots(detail::RuntimeWindowAccumulator& accumulator);
    void collectVaultSnapshots();

    std::chrono::steady_clock::time_point lastRuntimeCollection_{};
    std::chrono::steady_clock::time_point lastVaultCollection_{};
    std::chrono::steady_clock::time_point lastPurge_{};
};

}
