#pragma once

#include "concurrency/AsyncService.hpp"

#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>

// The mirror's background contents (design/peers/mirror.md "Contents" 6: "fetched in the background, files a person
// opens first"): for every vault this server holds as a mirror whose link is up, the files whose contents have not
// arrived are fetched in the order PendingContents gives (priority, then the order they were expected), on the link's
// background transfer slots, which a person's open always comes before (peer::Transfers keeps one slot for it and
// grants it first). Bounded: one batch of kBatch files per vault at a time, on a transfer thread the link service joins
// when it stops (so a stop never waits for a transfer here). A pass that received nothing (the files failed, or no slot
// was free) backs off that vault with jitter, up to kBackoffCap; a file fails for good after three attempts
// (PendingContents::kMaxAttempts) and is not fetched again until retried, so failed rows never keep it busy. Nothing
// runs while the link is down or on a server that has linked nothing. Piece B's applier only inserts the pending rows.
// Registered with runtime::Manager as "MirrorContents", after the link service.
namespace vh::mirror::start {

class BackgroundContents final : public concurrency::AsyncService {
public:
    static constexpr std::chrono::seconds kInterval{2};
    static constexpr std::size_t kBatch = 16;
    static constexpr std::chrono::seconds kBackoffFloor{5};
    static constexpr std::chrono::minutes kBackoffCap{10};

    BackgroundContents();
    static const std::shared_ptr<BackgroundContents>& instance();

    // One pass: starts a batch for each vault that has something to fetch and no batch running (the loop; tests).
    // Returns how many batches it started.
    std::size_t tick();
    // Tests: waits until no batch runs (at most `timeout`); true when none does.
    bool waitIdleForTesting(std::chrono::milliseconds timeout);
    void resetForTesting();

protected:
    void runLoop() override;

private:
    struct VaultState {
        bool running{false};
        unsigned failures{0};
        std::chrono::steady_clock::time_point notBefore{};
    };
    struct Shared {
        std::mutex mutex;
        std::map<uint32_t, VaultState> vaults;
    };
    std::shared_ptr<Shared> shared_{std::make_shared<Shared>()};
};

}
