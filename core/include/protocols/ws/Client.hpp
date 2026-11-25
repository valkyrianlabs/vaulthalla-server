#pragma once

#include "protocols/ws/Fwd.hpp"

#include <boost/asio/io_context.hpp>

#include <openssl/types.h>

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>

namespace boost::asio::ssl { class context; }

// An outbound websocket over TLS (the server link, design/peers/link.md): resolve, connect, the TLS client handshake
// with a certificate check the caller decides, then the websocket upgrade, each under one deadline. What it hands back
// is a TlsTransport in the client role, ready for ws::Session::attachPeer (or for the caller's own reads and writes).
// The cloud relay's link (cloud/RelayService) keeps its own client: it also speaks plain ws to a loopback relay in
// development, over a beast::tcp_stream.
namespace vh::protocols::ws::client {

struct DialOptions {
    std::string host{};
    uint16_t port{};
    std::string target{"/ws"};
    // The context the handshake runs with (it must outlive the transport): protocols::device::makeClientContext.
    std::shared_ptr<boost::asio::ssl::context> tls{};
    // Decides the server's certificate (the leaf: depth 0); false aborts the handshake. Required: without it nothing
    // is accepted (the trust store is never consulted).
    std::function<bool(X509* leaf)> acceptCertificate{};
    std::chrono::milliseconds timeout{std::chrono::seconds(10)};
    std::string userAgent{"vaulthalla-server"};
};

struct DialResult {
    std::shared_ptr<TlsTransport> transport{};  // null on failure
    std::string error{};                        // why it failed, for status and logs (no secrets)
    std::string address{};                      // the remote endpoint connected to ("host:port")
};

// Dials on `ioc` (the socket lives on a strand of it); `done` runs once, on that strand, with the outcome. SNI is sent
// for a DNS name (an SNI passthrough routes by it), never for an IP literal.
void dial(boost::asio::io_context& ioc, DialOptions options, std::function<void(DialResult)> done);

}
