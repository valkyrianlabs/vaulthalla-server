#include "crypto/IntegrityRegistry.hpp"

#include "log/Registry.hpp"

#include <fmt/format.h>

namespace vh::crypto {

std::string IntegrityKey::str() const {
    return fmt::format("{}|{}|{}|{}:{}|{}|{}", domain, iv_b64, key_version, dev, ino, size, mtime_ns);
}

IntegrityState IntegrityTicket::wait(const std::chrono::milliseconds timeout) {
    std::unique_lock lock(mutex_);
    const auto settled = [this] {
        const auto s = state();
        return s != IntegrityState::Unknown && s != IntegrityState::Verifying;
    };
    if (timeout == std::chrono::milliseconds::max()) cv_.wait(lock, settled);
    else cv_.wait_for(lock, timeout, settled);
    return state();
}

void IntegrityTicket::settle(const IntegrityState s) {
    {
        std::scoped_lock lock(mutex_);
        state_.store(s, std::memory_order_release);
    }
    cv_.notify_all();
}

IntegrityRegistry& IntegrityRegistry::instance() {
    static IntegrityRegistry registry;
    return registry;
}

IntegrityRegistry::IntegrityRegistry(const std::size_t workers, const std::size_t capacity) : capacity_(capacity) {
    workers_.reserve(workers);
    for (std::size_t i = 0; i < workers; ++i)
        workers_.emplace_back([this](const std::stop_token& stop) { workerLoop(stop); });
}

IntegrityRegistry::~IntegrityRegistry() {
    for (auto& worker : workers_) worker.request_stop();
    queueCv_.notify_all();
    workers_.clear();  // joins
    std::scoped_lock lock(mutex_);
    for (auto& job : queue_) job.ticket->settle(IntegrityState::Unknown);
}

std::shared_ptr<IntegrityTicket> IntegrityRegistry::ensure(const IntegrityKey& key, Verifier verify,
                                                           CurrentCheck current) {
    const auto id = key.str();
    std::shared_ptr<IntegrityTicket> ticket;
    {
        std::scoped_lock lock(mutex_);
        if (const auto it = tickets_.find(id); it != tickets_.end()) {
            ++stats_.cacheHits;
            return it->second;
        }
        ticket = std::make_shared<IntegrityTicket>();
        ticket->state_.store(IntegrityState::Verifying, std::memory_order_release);
        tickets_.emplace(id, ticket);
        order_.push_back(id);
        evictLocked();
        queue_.push_back(Job{ticket, std::move(verify), std::move(current), key.domain});
        ++stats_.scheduled;
    }
    queueCv_.notify_one();
    return ticket;
}

void IntegrityRegistry::record(const IntegrityKey& key, const bool verified) {
    const auto id = key.str();
    std::shared_ptr<IntegrityTicket> ticket;
    {
        std::scoped_lock lock(mutex_);
        auto& slot = tickets_[id];
        if (!slot) {
            slot = std::make_shared<IntegrityTicket>();
            order_.push_back(id);
            evictLocked();
        }
        ticket = slot;
        if (verified) ++stats_.verified;
        else ++stats_.failed;
    }
    // A recorded failure always wins; a recorded success never overrides an earlier failure.
    if (!verified) ticket->settle(IntegrityState::Failed);
    else if (!ticket->failed()) ticket->settle(IntegrityState::Verified);
}

std::optional<IntegrityState> IntegrityRegistry::peek(const IntegrityKey& key) const {
    std::scoped_lock lock(mutex_);
    const auto it = tickets_.find(key.str());
    if (it == tickets_.end() || !it->second) return std::nullopt;
    return it->second->state();
}

IntegrityRegistry::Stats IntegrityRegistry::stats() const {
    std::scoped_lock lock(mutex_);
    return stats_;
}

void IntegrityRegistry::clearForTesting() {
    std::scoped_lock lock(mutex_);
    tickets_.clear();
    order_.clear();
    stats_ = {};
}

void IntegrityRegistry::evictLocked() {
    // Bounded memory: drop the oldest settled verdicts. Live readers keep their ticket alive through their own
    // shared_ptr; an evicted generation is simply verified again by its next new reader. In-flight verifications are
    // kept, so one pass visits each entry at most once (the map may briefly exceed capacity while all are in flight).
    for (auto budget = order_.size(); tickets_.size() > capacity_ && budget > 0 && !order_.empty(); --budget) {
        const auto oldest = order_.front();
        order_.pop_front();
        const auto it = tickets_.find(oldest);
        if (it == tickets_.end()) continue;
        if (it->second->state() == IntegrityState::Verifying) {
            order_.push_back(oldest);
            continue;
        }
        tickets_.erase(it);
    }
}

void IntegrityRegistry::workerLoop(const std::stop_token& stop) {
    while (!stop.stop_requested()) {
        Job job;
        {
            std::unique_lock lock(mutex_);
            queueCv_.wait(lock, stop, [this] { return !queue_.empty(); });
            if (stop.stop_requested()) return;
            job = std::move(queue_.front());
            queue_.pop_front();
        }

        bool ok = false;
        std::string error;
        try {
            ok = job.verify ? job.verify() : false;
        } catch (const std::exception& e) {
            error = e.what();
        }

        IntegrityState verdict = IntegrityState::Verified;
        if (!ok) {
            bool stillCurrent = true;
            try {
                if (job.current) stillCurrent = job.current();
            } catch (...) {
                stillCurrent = true;
            }
            verdict = stillCurrent ? IntegrityState::Failed : IntegrityState::Superseded;
        }

        {
            std::scoped_lock lock(mutex_);
            if (verdict == IntegrityState::Verified) ++stats_.verified;
            else if (verdict == IntegrityState::Failed) ++stats_.failed;
            else ++stats_.superseded;
        }

        if (verdict == IntegrityState::Failed)
            log::Registry::crypto()->error("[IntegrityRegistry] AES-GCM verification FAILED for {}{}{} — streams aborted",
                                           job.label, error.empty() ? "" : ": ", error);
        else if (verdict == IntegrityState::Superseded)
            log::Registry::crypto()->info("[IntegrityRegistry] {} was replaced during verification; readers restart",
                                          job.label);

        job.ticket->settle(verdict);
    }
}

}
