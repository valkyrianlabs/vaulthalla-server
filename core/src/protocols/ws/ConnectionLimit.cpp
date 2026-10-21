#include "protocols/ws/ConnectionLimit.hpp"

#include <boost/asio/buffer.hpp>
#include <boost/asio/write.hpp>

#include <algorithm>
#include <atomic>
#include <string_view>

namespace vh::protocols::ws {

namespace {
struct Counters {
    std::atomic<unsigned int> active{0};
    std::atomic<uint64_t> refused{0};
};

Counters& counters(const ConnectionSlot::Pool pool) {
    static Counters webSocket, device;
    return pool == ConnectionSlot::Pool::Device ? device : webSocket;
}
}

std::unique_ptr<ConnectionSlot> ConnectionSlot::tryAcquire(const unsigned int limit, const Pool pool) {
    auto& c = counters(pool);
    const auto cap = std::max(1u, limit);
    auto current = c.active.load(std::memory_order_relaxed);
    do {
        if (current >= cap) {
            c.refused.fetch_add(1, std::memory_order_relaxed);
            return nullptr;
        }
    } while (!c.active.compare_exchange_weak(current, current + 1, std::memory_order_acq_rel,
                                             std::memory_order_relaxed));
    return std::unique_ptr<ConnectionSlot>(new ConnectionSlot(pool));
}

unsigned int ConnectionSlot::active(const Pool pool) noexcept { return counters(pool).active.load(std::memory_order_relaxed); }

uint64_t ConnectionSlot::refused(const Pool pool) noexcept { return counters(pool).refused.load(std::memory_order_relaxed); }

ConnectionSlot::~ConnectionSlot() { counters(pool_).active.fetch_sub(1, std::memory_order_acq_rel); }

void refuseOverCapacity(boost::asio::ip::tcp::socket& socket) {
    static constexpr std::string_view kBusy =
        "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nRetry-After: 1\r\nConnection: close\r\n\r\n";
    boost::system::error_code ec;
    // A fresh socket's send buffer takes these few bytes at once, so the blocking write can't stall the acceptor.
    boost::asio::write(socket, boost::asio::buffer(kBusy.data(), kBusy.size()), ec);
    socket.shutdown(boost::asio::ip::tcp::socket::shutdown_both, ec);
    socket.close(ec);
}

}
