#pragma once

#include <boost/asio/ip/tcp.hpp>

#include <cstdint>
#include <memory>

// websocket_server.max_connections (#164). ws::Server takes a slot for each accepted TCP connection before it
// becomes a Session; the Session gives it back when it closes (or is destroyed). Over the cap, the connection is
// answered with a plain HTTP 503 and closed without reading the upgrade request, like the HTTP preview server.
namespace vh::protocols::ws {

class ConnectionSlot {
public:
    // Each listener counts its own connections: the console's ws server, and the device listener
    // (device_server.max_connections).
    enum class Pool { WebSocket, Device };

    // A slot when fewer than `limit` are held, else null. A limit of 0 is treated as 1.
    [[nodiscard]] static std::unique_ptr<ConnectionSlot> tryAcquire(unsigned int limit, Pool pool = Pool::WebSocket);
    [[nodiscard]] static unsigned int active(Pool pool = Pool::WebSocket) noexcept;
    // Connections refused since the daemon started.
    [[nodiscard]] static uint64_t refused(Pool pool = Pool::WebSocket) noexcept;

    ~ConnectionSlot();
    ConnectionSlot(const ConnectionSlot&) = delete;
    ConnectionSlot& operator=(const ConnectionSlot&) = delete;

private:
    explicit ConnectionSlot(const Pool pool) : pool_(pool) {}
    Pool pool_;
};

// Writes "503 Service Unavailable" with Retry-After and closes the socket. Never throws.
void refuseOverCapacity(boost::asio::ip::tcp::socket& socket);

}
