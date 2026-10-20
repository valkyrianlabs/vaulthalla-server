#pragma once

#include "device/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>

namespace boost::asio::ssl { class context; }

// The device listener (docs/pairing.md §2): TLS 1.3 only, a client certificate required, authorization by the
// certificate's key at handshake time, then path dispatch. `/ws` is the console's ws Router in a Device or
// pairing-only session; every other path is 404 for now. The HTTP lanes (/preview, /download, /upload) and /mcp are
// the next step (S1b): they slot into Connection::dispatch with the same Authorization.
namespace vh::protocols::device {

namespace asio = boost::asio;
using tcp = asio::ip::tcp;

// The TLS context for an identity: TLS 1.3 only, no session tickets or cache (every connection presents its
// certificate and is authorized afresh), client certificate required and accepted whatever its chain (the key is
// what is checked, after the handshake), client signatures limited to ECDSA P-256 / SHA-256.
[[nodiscard]] std::shared_ptr<asio::ssl::context> makeServerContext(const vh::device::ServerIdentity& identity);

class Listener : public std::enable_shared_from_this<Listener> {
public:
    Listener(asio::io_context& ioc, std::shared_ptr<asio::ssl::context> tls, std::shared_ptr<ws::Router> router,
             unsigned int maxConnections);

    // Opens, binds and listens; throws (leaving it closed) when the address can't be bound.
    void listen(const tcp::endpoint& endpoint);
    void close() noexcept;
    [[nodiscard]] tcp::endpoint localEndpoint() const;
    void setMaxConnections(unsigned int max) noexcept { maxConnections_.store(max, std::memory_order_relaxed); }

    // How long a client gets for the TLS handshake and for its HTTP request after it.
    static constexpr auto kHandshakeTimeout = std::chrono::seconds(10);

private:
    void doAccept();

    asio::io_context& ioc_;
    tcp::acceptor acceptor_;
    std::shared_ptr<asio::ssl::context> tls_;
    std::shared_ptr<ws::Router> router_;
    std::atomic<unsigned int> maxConnections_;
    std::atomic<bool> closed_{true};
};

}
