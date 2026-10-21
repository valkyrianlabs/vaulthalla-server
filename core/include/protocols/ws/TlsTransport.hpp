#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl/stream.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>

// A websocket over TLS (the device listener). ws::Session runs the same protocol over this or a plain TCP socket;
// the listener does the TLS handshake and reads the upgrade request on next_layer() before handing it over.
// Kept out of Session.hpp so only the code that touches TLS pulls in Asio's SSL headers.
namespace vh::protocols::ws {

struct TlsTransport {
    using SslStream = boost::asio::ssl::stream<boost::asio::ip::tcp::socket>;
    using WebSocket = boost::beast::websocket::stream<SslStream>;

    TlsTransport(boost::asio::ip::tcp::socket&& socket, boost::asio::ssl::context& context)
        : ws(std::move(socket), context) {}

    WebSocket ws;
};

}
