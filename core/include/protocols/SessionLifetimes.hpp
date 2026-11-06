#pragma once

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <memory>
#include <mutex>
#include <vector>

namespace vh::protocols {

// Counts the live session objects of one kind. HTTP and S3 sessions run on pool threads with a socket bound to their
// service's io_context, and destroying a socket touches that context, so a service must not free the io_context while
// any session object still exists. A session holds a Token as its first member: members are destroyed in reverse
// order, so the count drops only after the socket is gone.
class SessionLifetimes {
public:
    class Token {
    public:
        explicit Token(SessionLifetimes& owner) noexcept : owner_(owner) { owner_.add(); }
        ~Token() { owner_.remove(); }
        Token(const Token&) = delete;
        Token& operator=(const Token&) = delete;

    private:
        SessionLifetimes& owner_;
    };

    [[nodiscard]] uint64_t live() const noexcept {
        std::scoped_lock lock(mutex_);
        return live_;
    }

    // True once none are alive; false if the timeout passed first.
    [[nodiscard]] bool waitUntilNoneAlive(const std::chrono::milliseconds timeout) {
        std::unique_lock lock(mutex_);
        return cv_.wait_for(lock, timeout, [this] { return live_ == 0; });
    }

private:
    void add() noexcept {
        std::scoped_lock lock(mutex_);
        ++live_;
    }

    void remove() noexcept {
        {
            std::scoped_lock lock(mutex_);
            --live_;
        }
        cv_.notify_all();
    }

    mutable std::mutex mutex_;
    std::condition_variable cv_;
    uint64_t live_{0};
};

// For a service whose sessions outlived its shutdown deadline: their sockets still point into this object, so it is
// kept for the life of the process instead of being freed under them. Never destroyed, not even by static
// destruction: the sessions holding those sockets can be destroyed then (a process-wide cache, a handler still queued
// on the stopped io_context), and a function-local container would be freed before them (#397).
inline void retainForProcessLifetime(std::shared_ptr<void> object) {
    struct Retained {
        std::mutex mutex;
        std::vector<std::shared_ptr<void>> objects;
    };
    static auto* const retained = new Retained;  // intentionally never deleted
    std::scoped_lock lock(retained->mutex);
    retained->objects.push_back(std::move(object));
}

}
