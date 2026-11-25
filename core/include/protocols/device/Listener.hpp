#pragma once

#include "device/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>

#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
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

// The dialling end of a link between two servers (design/peers/link.md): TLS 1.3 only, no session tickets or cache,
// presenting this server's identity certificate as the client certificate, and signatures limited to ECDSA P-256 /
// SHA-256 both ways. The trust store is never consulted: a connection sets its own verify callback that compares the
// server key's SPKI hash with the pin (protocols::ws::client::dial).
[[nodiscard]] std::shared_ptr<asio::ssl::context> makeClientContext(const vh::device::ServerIdentity& identity);

// ---- relayed streams (design/cloud/relay.md: the Vaulthalla Cloud relay, option (c)) --------------------------------
//
// The second way to authenticate a peer, used only for a stream the relay service (cloud/RelayService) accepted after
// re-checking its browser ticket. It is never reachable from a Listener: the network listener's connections always use
// makeServerContext (a client certificate required) and have no RelayedOrigin; only startRelayedConnection takes one.

// What the relay service knows of one relayed stream, from its re-checked browser ticket.
struct RelayedOrigin {
    std::string address;      // the browser's address as the relay reports it (display and limits; never loopback)
    std::string jti;          // the ticket's jti: bound into the proof
    std::string spki_sha256;  // the ticket's spki: the key the browser must prove
    std::string key_id;       // the cloud's browser key id (logs)
    // Called at most once, on the listener's strand, when the stream is refused after the ticket (bad or missing proof,
    // over the connection cap); the relay service then sends CLOSE refused. Never called once the proof passed.
    std::function<void(std::string_view why)> refused;
    // Called at most once, on the listener's strand, when the proof passed (the stream is now a listener connection).
    std::function<void()> proven;
};

// The TLS context for relayed streams: the same identity, TLS 1.3 only, no tickets or cache, and no client
// certificate (the browser proves its key inside the stream instead).
[[nodiscard]] std::shared_ptr<asio::ssl::context> makeRelayedServerContext(const vh::device::ServerIdentity& identity);

// Runs the listener's connection over `socket` (one end of a local socketpair whose other end the relay service
// pumps): TLS, the browser's key proof (cloud/RelayProtocol.hpp), then authorization by the proven key as a relayed peer
// (held to the read-only set) and the usual HTTP dispatch. Takes a device connection slot; over the cap it is refused.
void startRelayedConnection(tcp::socket&& socket, std::shared_ptr<asio::ssl::context> tls,
                            std::shared_ptr<ws::Router> router, unsigned int maxConnections, RelayedOrigin origin);

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
    // The TLS context new connections handshake with (a rotated server identity, #353). Connections already open keep
    // theirs, which stays alive: a connection only borrows its context.
    void setTls(std::shared_ptr<asio::ssl::context> tls);

    // How long a client gets for the TLS handshake and for its HTTP request after it.
    static constexpr auto kHandshakeTimeout = std::chrono::seconds(10);

private:
    void doAccept(const std::shared_ptr<tcp::acceptor>& acceptor);

    asio::io_context& ioc_;
    // Each pending accept holds its acceptor, so a rebind never frees one under an accept in flight.
    std::vector<std::shared_ptr<tcp::acceptor>> acceptors_;
    mutable std::mutex tlsMutex_;
    std::shared_ptr<asio::ssl::context> tls_;
    std::vector<std::shared_ptr<asio::ssl::context>> retiredTls_;  // contexts open connections may still borrow
    std::shared_ptr<ws::Router> router_;
    std::atomic<unsigned int> maxConnections_;
    std::atomic<bool> closed_{true};
};

}
