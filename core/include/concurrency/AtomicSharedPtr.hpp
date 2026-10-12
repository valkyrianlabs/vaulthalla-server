#pragma once

#include <atomic>
#include <memory>
#include <thread>
#include <utility>
#include <version>

namespace vh::concurrency {

#if defined(__cpp_lib_atomic_shared_ptr)

// libstdc++ (Linux): the standard type itself, so nothing changes where it exists.
template <class T>
using AtomicSharedPtr = std::atomic<std::shared_ptr<T>>;

#else

// libc++ (macOS) doesn't implement std::atomic<std::shared_ptr> (P0718) yet. The same interface for the operations
// Vaulthalla uses (load, store, exchange), with every operation sequentially consistent. A spinlock guards the
// shared_ptr copy: the critical section is one reference-count update, so it is held for nanoseconds and never
// across a call that can block. Readers of identity state take it once per check (identities::User::state()).
template <class T>
class AtomicSharedPtr {
public:
    AtomicSharedPtr() noexcept = default;
    AtomicSharedPtr(std::shared_ptr<T> desired) noexcept : value_(std::move(desired)) {}  // NOLINT(google-explicit-constructor)

    AtomicSharedPtr(const AtomicSharedPtr&) = delete;
    AtomicSharedPtr& operator=(const AtomicSharedPtr&) = delete;

    [[nodiscard]] std::shared_ptr<T> load(std::memory_order = std::memory_order_seq_cst) const noexcept {
        const Guard guard(lock_);
        return value_;
    }

    void store(std::shared_ptr<T> desired, std::memory_order = std::memory_order_seq_cst) noexcept {
        std::shared_ptr<T> previous;  // released after unlocking: a last reference may run a destructor
        {
            const Guard guard(lock_);
            previous = std::exchange(value_, std::move(desired));
        }
    }

    [[nodiscard]] std::shared_ptr<T> exchange(std::shared_ptr<T> desired,
                                              std::memory_order = std::memory_order_seq_cst) noexcept {
        const Guard guard(lock_);
        return std::exchange(value_, std::move(desired));
    }

    operator std::shared_ptr<T>() const noexcept { return load(); }  // NOLINT(google-explicit-constructor)

    static constexpr bool is_always_lock_free = false;

private:
    class Guard {
    public:
        explicit Guard(std::atomic_flag& flag) noexcept : flag_(flag) {
            for (unsigned spins = 0; flag_.test_and_set(std::memory_order_acquire); ++spins)
                if (spins >= 64) std::this_thread::yield();
        }
        ~Guard() { flag_.clear(std::memory_order_release); }

        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;

    private:
        std::atomic_flag& flag_;
    };

    mutable std::atomic_flag lock_{};
    std::shared_ptr<T> value_;
};

#endif

}
