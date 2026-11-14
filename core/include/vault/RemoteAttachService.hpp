#pragma once

#include "concurrency/AsyncService.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <map>

namespace vh::vault {

// Runs the remote attaches operators started (vault/RemoteAttach.hpp, design/storage/attach-remote.md) on its own
// thread, never a FUSE, sync or request thread: an attach before its cutover runs until it cut over or failed (resumed
// after a restart), a cut over one finishes (engine swap, orphan cleanup, first pass), a requested abort deletes what
// the attach recorded (retried while the provider refuses a delete), and a key rotation that was asked for meanwhile
// starts once the attach ended. Nothing starts without an operator: a vault without a vault_remote_attach row is never
// touched.
class RemoteAttachService final : public concurrency::AsyncService {
public:
    static constexpr auto kPollInterval = std::chrono::seconds(5);
    static constexpr auto kAbortRetry = std::chrono::minutes(10);   // a delete the provider refused: tried again

    RemoteAttachService();
    ~RemoteAttachService() override = default;

    // One pass over the attach rows (what runLoop does every kPollInterval). Public for tests and ops.
    void runOnce();

protected:
    void runLoop() override;

private:
    std::map<uint32_t, std::time_t> abortTried_;   // vault -> the last abort attempt that left objects behind
};

}
