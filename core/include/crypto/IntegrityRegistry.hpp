#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace vh::crypto {

// The exact bytes one AES-GCM message lives in. Any change (new IV on reseal, key rotation, file replaced on
// disk) is a different key, so a verdict can never be applied to bytes it was not computed over.
struct IntegrityKey {
    std::string domain;         // "file:<vault_id>:<file_id>" or "artifact:<vault_id>:<canonical>"
    std::string iv_b64;
    uint32_t key_version{};
    uint64_t dev{}, ino{}, size{};
    int64_t mtime_ns{};

    [[nodiscard]] bool operator==(const IntegrityKey&) const = default;
    [[nodiscard]] std::string str() const;
};

enum class IntegrityState { Unknown, Verifying, Verified, Failed, Superseded };

// Shared verdict for one IntegrityKey. Readers poll failed() between reads (optimistic) or wait() (strict).
class IntegrityTicket {
public:
    [[nodiscard]] IntegrityState state() const { return state_.load(std::memory_order_acquire); }
    [[nodiscard]] bool failed() const {
        const auto s = state();
        return s == IntegrityState::Failed || s == IntegrityState::Superseded;
    }
    // Blocks until the verdict is in (or timeout). Returns the state at return.
    IntegrityState wait(std::chrono::milliseconds timeout = std::chrono::milliseconds::max());

private:
    friend class IntegrityRegistry;
    void settle(IntegrityState s);

    std::atomic<IntegrityState> state_{IntegrityState::Unknown};
    std::mutex mutex_;
    std::condition_variable cv_;
};

// Verify-once registry for whole-message AES-GCM authentication of positioned (CTR) reads. The first reader of
// a generation schedules one streaming tag verification on a small bounded worker pool; every reader of that
// generation shares the verdict. Failure is sticky for the key and aborts all live readers on their next read.
class IntegrityRegistry {
public:
    // Runs the full verification. Returns true when the tag matched.
    using Verifier = std::function<bool()>;
    // On a mismatch: is this still the file's current generation? false ⇒ the file was replaced while we were
    // verifying (a race, not corruption) and the verdict is Superseded instead of Failed.
    using CurrentCheck = std::function<bool()>;

    struct Stats {
        uint64_t verified{}, failed{}, superseded{}, scheduled{}, cacheHits{};
    };

    static IntegrityRegistry& instance();

    IntegrityRegistry(std::size_t workers = 2, std::size_t capacity = 8192);
    ~IntegrityRegistry();
    IntegrityRegistry(const IntegrityRegistry&) = delete;
    IntegrityRegistry& operator=(const IntegrityRegistry&) = delete;

    // Returns the shared ticket, scheduling verification if this key has never been seen (or was evicted).
    std::shared_ptr<IntegrityTicket> ensure(const IntegrityKey& key, Verifier verify, CurrentCheck current = {});

    // Records an out-of-band verdict (e.g. a full authenticated read that just checked the tag).
    void record(const IntegrityKey& key, bool verified);

    // The verdict recorded for key, if any (never schedules a verification): VHF1 readers authenticate per chunk
    // themselves and only consult and record verdicts.
    [[nodiscard]] std::optional<IntegrityState> peek(const IntegrityKey& key) const;

    [[nodiscard]] Stats stats() const;
    void clearForTesting();

private:
    struct Job {
        std::shared_ptr<IntegrityTicket> ticket;
        Verifier verify;
        CurrentCheck current;
        std::string label;
    };

    void workerLoop(const std::stop_token& stop);
    void evictLocked();

    mutable std::mutex mutex_;
    std::condition_variable_any queueCv_;
    std::deque<Job> queue_;
    std::unordered_map<std::string, std::shared_ptr<IntegrityTicket>> tickets_;
    std::deque<std::string> order_;  // insertion order for bounded eviction
    std::size_t capacity_;
    Stats stats_;
    std::vector<std::jthread> workers_;
};

}
