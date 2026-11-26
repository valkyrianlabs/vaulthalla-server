#pragma once

#include "concurrency/AsyncService.hpp"
#include "db/query/mirror/Log.hpp"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <memory>

// Numbers the replication log of every vault this server is the core of (design/peers/mirror.md "The replication
// log"; db::query::mirror::Log::sequence), so that each change is readable soon after it commits. Registered with
// runtime::Manager as "MirrorSequencer". With no vault mirrored, a pass is one read of the log's (empty) pending index.
// What a pass numbered is where `peer.mirror.notify` will come from (a later piece).
namespace vh::mirror {

class Sequencer : public concurrency::AsyncService {
public:
    static constexpr std::chrono::milliseconds kPollInterval{250};

    Sequencer();

    static const std::shared_ptr<Sequencer>& instance();

    // One pass (the loop calls it; tests call it directly).
    vh::db::query::mirror::Sequenced tick();

    [[nodiscard]] uint64_t passes() const { return passes_.load(std::memory_order_relaxed); }

protected:
    void runLoop() override;

private:
    std::atomic<uint64_t> passes_{0};
};

}
