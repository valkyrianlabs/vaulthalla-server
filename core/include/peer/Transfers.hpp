#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

// Bulk transfers to and from linked servers (design/peers/mirror.md "Slots and pressure"): a fixed number of transfers
// per peer, shared by both directions (only fetching exists yet), with a person's open ahead of background work. A
// slot is held for the whole of one file's transfer; the transfer itself reads at the pace its sink writes (TCP's
// back-pressure), so a slow disk slows the sender instead of filling memory. Owned by peer::LinkService, which stops
// every transfer and joins its threads when it stops.
namespace vh::peer {

enum class TransferPriority {
    Interactive,  // a person is waiting (an open through the mount, a download, a preview)
    Background,   // contents fetched ahead of anyone asking
};

// Transfers one linked server may have in flight at once, both directions together.
inline constexpr unsigned kTransfersPerPeer = 4;
// Of those, how many background work may never take, so an open never waits behind a full queue of background files.
inline constexpr unsigned kReservedForInteractive = 1;

class Transfers {
public:
    // A held slot; released when it goes out of scope.
    class Slot {
    public:
        Slot() = default;
        ~Slot();
        Slot(Slot&& other) noexcept;
        Slot& operator=(Slot&& other) noexcept;
        Slot(const Slot&) = delete;
        Slot& operator=(const Slot&) = delete;

        [[nodiscard]] explicit operator bool() const noexcept { return owner_ != nullptr; }
        [[nodiscard]] uint32_t peerId() const noexcept { return peer_; }

    private:
        friend class Transfers;
        Slot(Transfers* owner, uint32_t peer) : owner_(owner), peer_(peer) {}
        void release() noexcept;
        Transfers* owner_{nullptr};
        uint32_t peer_{0};
    };

    Transfers() = default;
    ~Transfers();
    Transfers(const Transfers&) = delete;
    Transfers& operator=(const Transfers&) = delete;

    // Waits until `deadline` for a slot to `peerId`. Interactive requests are granted before any waiting background
    // one and may use every slot; background ones never use the last kReservedForInteractive and never go ahead of a
    // waiting interactive one. An empty slot when the deadline passes or the service is stopping.
    [[nodiscard]] Slot acquire(uint32_t peerId, TransferPriority priority,
                               std::chrono::steady_clock::time_point deadline);
    [[nodiscard]] unsigned inFlight(uint32_t peerId) const;

    // Runs `job` on a thread of its own, joined by shutdown() (a transfer outlives the request that started it: an
    // open that stopped waiting still gets its file). False, and nothing runs, while stopping.
    bool spawn(std::function<void()> job);

    // Tells every transfer to stop (stopping() turns true at once), wakes every waiter without a slot, then joins every
    // spawned thread. Transfers end within their client's cancellation slice (protocols: a fraction of a second).
    void shutdown();
    // After shutdown(): accepts work again (the link service restarted).
    void resume();
    [[nodiscard]] bool stopping() const noexcept { return stopping_.load(std::memory_order_acquire); }
    [[nodiscard]] const std::atomic<bool>& stopFlag() const noexcept { return stopping_; }

private:
    struct PeerSlots {
        unsigned busy{0};
        unsigned interactiveWaiting{0};
    };
    struct Worker {
        std::thread thread;
        std::shared_ptr<std::atomic<bool>> done;
    };

    void releaseSlot(uint32_t peerId) noexcept;
    void reapFinishedLocked(std::vector<std::thread>& out);

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    std::map<uint32_t, PeerSlots> peers_;
    std::atomic<bool> stopping_{false};

    std::mutex workersMutex_;
    std::vector<Worker> workers_;
};

}
