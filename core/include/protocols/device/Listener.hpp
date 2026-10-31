#pragma once

#include "device/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <string>
#include <vector>

namespace boost::asio::ssl { class context; }

// The device listener (docs/pairing.md §2): TLS 1.3 only, a client certificate required, authorization by the
// certificate's key at handshake time, then path dispatch. `/ws` is the console's ws Router in a Device or
// pairing-only session; the HTTP lanes (/preview, /download, /upload, /transfer) and /mcp are an HTTP session as the
// device's user; every other path is 404.
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

    // Opens, binds and listens on `endpoint` alone (closing whatever it listened on); throws (leaving it closed) when
    // the address can't be bound. An IPv6 wildcard (`[::]`) is bound dual-stack (IPV6_V6ONLY off); if the system
    // refuses that, so does this.
    void listen(const tcp::endpoint& endpoint);
    // Also listens on `endpoint` (loopback-only binds 127.0.0.1 and [::1]); throws, keeping the others, when it
    // can't be bound.
    void listenAlso(const tcp::endpoint& endpoint);
    void close() noexcept;
    // The first bound endpoint (a default endpoint when closed), and all of them.
    [[nodiscard]] tcp::endpoint localEndpoint() const;
    [[nodiscard]] std::vector<tcp::endpoint> localEndpoints() const;
    void setMaxConnections(unsigned int max) noexcept { maxConnections_.store(max, std::memory_order_relaxed); }

    // How long a client gets for the TLS handshake and for its HTTP request after it.
    static constexpr auto kHandshakeTimeout = std::chrono::seconds(10);

private:
    void doAccept(const std::shared_ptr<tcp::acceptor>& acceptor);

    asio::io_context& ioc_;
    // Each pending accept holds its acceptor, so a rebind never frees one under an accept in flight.
    std::vector<std::shared_ptr<tcp::acceptor>> acceptors_;
    std::shared_ptr<asio::ssl::context> tls_;
    std::shared_ptr<ws::Router> router_;
    std::atomic<unsigned int> maxConnections_;
    std::atomic<bool> closed_{true};
};

}
