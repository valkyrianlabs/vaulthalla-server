#pragma once

#include "DBConnection.hpp"
#include "log/Registry.hpp"

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <mutex>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

namespace vh::db {

// Thrown when no connection frees up within the pool's acquire timeout. Callers get an error instead of
// parking forever on the pool.
struct PoolAcquireTimeout : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Thrown when a leased connection is broken and could not be replaced (server down, or still inside the
// reconnect backoff window). The slot stays in the pool and is retried on a later acquire().
struct DatabaseUnavailable : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct PoolStats {
    std::size_t size = 0;
    std::size_t idle = 0;
    std::size_t inUse = 0;
    std::size_t brokenIdle = 0;                   // idle connections known dead, replaced on next acquire
    std::uint64_t reconnects = 0;
    std::uint64_t reconnectFailures = 0;
    std::uint32_t consecutiveReconnectFailures = 0;
    std::uint64_t acquireTimeouts = 0;
};

class DBPool {
  public:
    static constexpr std::chrono::milliseconds DEFAULT_ACQUIRE_TIMEOUT{std::chrono::seconds(30)};

    // database.pool_size bounds. Below kMinPoolSize a sync pass, FUSE and the listeners queue on each other; above
    // kMaxPoolSize is a typo, not a deployment (PostgreSQL's default max_connections is 100).
    static constexpr std::size_t kMinPoolSize = 4, kMaxPoolSize = 256;
    // The pool size for a configured database.pool_size: kept within the bounds above. `warning` says what was
    // changed and why (empty when the value is used as is).
    [[nodiscard]] static std::size_t resolveSize(long long configured, std::string* warning = nullptr) {
        const auto clamped = static_cast<std::size_t>(std::clamp<long long>(
            configured, static_cast<long long>(kMinPoolSize), static_cast<long long>(kMaxPoolSize)));
        if (warning) {
            if (static_cast<long long>(clamped) == configured) warning->clear();
            else *warning = "database.pool_size " + std::to_string(configured) + " is outside " +
                            std::to_string(kMinPoolSize) + ".." + std::to_string(kMaxPoolSize) + "; using " +
                            std::to_string(clamped);
        }
        return clamped;
    }
    static constexpr std::chrono::milliseconds RECONNECT_BACKOFF_BASE{250};
    static constexpr std::chrono::milliseconds RECONNECT_BACKOFF_MAX{std::chrono::seconds(5)};

    // Move-only RAII handle for a pooled connection. Destruction always hands the connection back to the
    // pool (healthy or not), so a slot can't leak on any path, including exceptions thrown while a
    // transaction is being opened on a dead connection.
    class Lease {
      public:
        Lease() = default;
        Lease(const Lease&) = delete;
        Lease& operator=(const Lease&) = delete;

        Lease(Lease&& other) noexcept
            : pool_(std::exchange(other.pool_, nullptr)), conn_(std::move(other.conn_)) {}

        Lease& operator=(Lease&& other) noexcept {
            if (this != &other) {
                reset();
                pool_ = std::exchange(other.pool_, nullptr);
                conn_ = std::move(other.conn_);
            }
            return *this;
        }

        ~Lease() { reset(); }

        [[nodiscard]] Connection* operator->() const noexcept { return conn_.get(); }
        [[nodiscard]] Connection& operator*() const noexcept { return *conn_; }
        [[nodiscard]] explicit operator bool() const noexcept { return static_cast<bool>(conn_); }

        void reset() noexcept {
            if (pool_ && conn_) pool_->release(std::move(conn_));
            pool_ = nullptr;
            conn_.reset();
        }

      private:
        friend class DBPool;

        Lease(DBPool* pool, std::unique_ptr<Connection> conn) noexcept
            : pool_(pool), conn_(std::move(conn)) {}

        DBPool* pool_ = nullptr;
        std::unique_ptr<Connection> conn_;
    };

    explicit DBPool(const size_t size = 4,
                    const std::chrono::milliseconds acquireTimeout = DEFAULT_ACQUIRE_TIMEOUT)
        : size_(size), acquireTimeout_(acquireTimeout) {
        // Reserved up front so release() never allocates and can stay noexcept.
        idle_.reserve(size);
        for (size_t i = 0; i < size; ++i) idle_.push_back(std::make_unique<Connection>());
    }

    DBPool(const DBPool&) = delete;
    DBPool& operator=(const DBPool&) = delete;

    // Leases must be returned before the pool is destroyed (Transactions::exec holds a shared_ptr copy of
    // the pool for the lifetime of its lease).
    [[nodiscard]] Lease acquire() { return acquire(acquireTimeout_); }

    [[nodiscard]] Lease acquire(const std::chrono::milliseconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        std::unique_ptr<Connection> conn;

        {
            std::unique_lock lock(mtx_);
            if (!cv_.wait_until(lock, deadline, [&]() { return !idle_.empty(); })) {
                ++acquireTimeouts_;
                const auto msg = "Timed out after " + std::to_string(timeout.count()) +
                                 "ms waiting for a database connection (all " + std::to_string(size_) +
                                 " pool connections in use)";
                lock.unlock();
                log::Registry::db()->error("[DBPool] {}", msg);
                throw PoolAcquireTimeout(msg);
            }
            // FIFO, so every connection is exercised and one the server dropped is found (and replaced) promptly.
            conn = std::move(idle_.front());
            idle_.erase(idle_.begin());
        }

        // From here on the lease owns the slot; any throw below hands it straight back.
        Lease lease(this, std::move(conn));
        if (!lease->healthy()) replaceBroken(*lease);
        return lease;
    }

    // Replaces the leased connection with a fresh session. For callers that discovered the connection is dead
    // only by using it (the server dropped it while idle). Throws DatabaseUnavailable if that fails.
    void repair(Lease& lease) { replaceBroken(*lease); }

    [[nodiscard]] PoolStats stats() const {
        std::lock_guard lock(mtx_);
        PoolStats out;
        out.size = size_;
        out.idle = idle_.size();
        out.inUse = size_ - idle_.size();
        out.brokenIdle = static_cast<std::size_t>(std::ranges::count_if(
            idle_, [](const std::unique_ptr<Connection>& c) { return !c->healthy(); }));
        out.reconnects = reconnects_;
        out.reconnectFailures = reconnectFailures_;
        out.consecutiveReconnectFailures = consecutiveReconnectFailures_;
        out.acquireTimeouts = acquireTimeouts_;
        return out;
    }

    void initPreparedStatements() {
        std::lock_guard lock(mtx_);
        for (auto& conn : idle_) conn->initPrepared();
    }

  private:
    const size_t size_;
    const std::chrono::milliseconds acquireTimeout_;
    std::vector<std::unique_ptr<Connection>> idle_;
    mutable std::mutex mtx_;
    std::condition_variable cv_;

    std::uint64_t reconnects_ = 0;
    std::uint64_t reconnectFailures_ = 0;
    std::uint32_t consecutiveReconnectFailures_ = 0;
    std::uint64_t acquireTimeouts_ = 0;
    std::chrono::steady_clock::time_point reconnectNotBefore_{};

    // Broken connections go back like any other; the next acquire() replaces them. Never drops a slot.
    void release(std::unique_ptr<Connection> conn) noexcept {
        {
            std::lock_guard lock(mtx_);
            idle_.push_back(std::move(conn));
        }
        cv_.notify_one();
    }

    // Runs outside the pool lock. While the server is unreachable, attempts are spaced by an exponential
    // backoff shared across the pool (RECONNECT_BACKOFF_BASE doubling up to RECONNECT_BACKOFF_MAX), and
    // callers inside the window fail fast instead of each hammering connect().
    void replaceBroken(Connection& conn);
};

}
