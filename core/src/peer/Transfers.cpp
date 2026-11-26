#include "peer/Transfers.hpp"

#include "log/Registry.hpp"

#include <exception>
#include <utility>

namespace vh::peer {

Transfers::Slot::~Slot() { release(); }

Transfers::Slot::Slot(Slot&& other) noexcept
    : owner_(std::exchange(other.owner_, nullptr)), peer_(other.peer_) {}

Transfers::Slot& Transfers::Slot::operator=(Slot&& other) noexcept {
    if (this != &other) {
        release();
        owner_ = std::exchange(other.owner_, nullptr);
        peer_ = other.peer_;
    }
    return *this;
}

void Transfers::Slot::release() noexcept {
    if (const auto owner = std::exchange(owner_, nullptr)) owner->releaseSlot(peer_);
}

Transfers::~Transfers() { shutdown(); }

Transfers::Slot Transfers::acquire(const uint32_t peerId, const TransferPriority priority,
                                   const std::chrono::steady_clock::time_point deadline) {
    const bool interactive = priority == TransferPriority::Interactive;
    const unsigned limit = interactive ? kTransfersPerPeer : kTransfersPerPeer - kReservedForInteractive;
    std::unique_lock lock(mutex_);
    auto& slots = peers_[peerId];
    if (interactive) ++slots.interactiveWaiting;
    const auto ready = [&] {
        if (stopping()) return true;
        if (slots.busy >= limit) return false;
        return interactive || slots.interactiveWaiting == 0;
    };
    const bool got = cv_.wait_until(lock, deadline, ready) && !stopping();
    if (interactive) --slots.interactiveWaiting;
    if (!got) {
        // A background waiter may have been held back by this interactive one.
        if (interactive) cv_.notify_all();
        return {};
    }
    ++slots.busy;
    return Slot(this, peerId);
}

unsigned Transfers::inFlight(const uint32_t peerId) const {
    std::scoped_lock lock(mutex_);
    const auto it = peers_.find(peerId);
    return it == peers_.end() ? 0 : it->second.busy;
}

void Transfers::releaseSlot(const uint32_t peerId) noexcept {
    {
        std::scoped_lock lock(mutex_);
        if (const auto it = peers_.find(peerId); it != peers_.end() && it->second.busy > 0) --it->second.busy;
    }
    cv_.notify_all();
}

void Transfers::reapFinishedLocked(std::vector<std::thread>& out) {
    for (auto it = workers_.begin(); it != workers_.end();) {
        if (it->done->load(std::memory_order_acquire)) {
            out.push_back(std::move(it->thread));
            it = workers_.erase(it);
        } else {
            ++it;
        }
    }
}

bool Transfers::spawn(std::function<void()> job) {
    if (stopping()) return false;
    std::vector<std::thread> finished;
    {
        std::scoped_lock lock(workersMutex_);
        if (stopping()) return false;
        reapFinishedLocked(finished);
        auto done = std::make_shared<std::atomic<bool>>(false);
        workers_.push_back(Worker{std::thread([job = std::move(job), done] {
                                      try {
                                          job();
                                      } catch (const std::exception& e) {
                                          log::Registry::runtime()->error("[PeerTransfers] A transfer failed: {}", e.what());
                                      } catch (...) {
                                          log::Registry::runtime()->error("[PeerTransfers] A transfer failed");
                                      }
                                      done->store(true, std::memory_order_release);
                                  }),
                                  done});
    }
    for (auto& t : finished)
        if (t.joinable()) t.join();
    return true;
}

void Transfers::shutdown() {
    {
        std::scoped_lock lock(mutex_);
        stopping_.store(true, std::memory_order_release);
    }
    cv_.notify_all();
    std::vector<Worker> workers;
    {
        std::scoped_lock lock(workersMutex_);
        workers.swap(workers_);
    }
    for (auto& w : workers)
        if (w.thread.joinable()) w.thread.join();
}

void Transfers::resume() {
    std::scoped_lock lock(mutex_);
    stopping_.store(false, std::memory_order_release);
}

}
