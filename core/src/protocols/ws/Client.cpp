#include "protocols/ws/Client.hpp"

#include "protocols/ws/TlsTransport.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include "compat/beast_websocket.hpp"

#include <openssl/ssl.h>
#include <openssl/x509.h>

namespace vh::protocols::ws::client {

namespace {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace ssl = asio::ssl;
namespace websocket = beast::websocket;
using tcp = asio::ip::tcp;

bool isIpLiteral(const std::string& host) {
    boost::system::error_code ec;
    (void)asio::ip::make_address(host, ec);
    return !ec;
}

class Dial : public std::enable_shared_from_this<Dial> {
public:
    Dial(asio::io_context& ioc, DialOptions options, std::function<void(DialResult)> done)
        : strand_(asio::make_strand(ioc)), resolver_(strand_), timer_(strand_), options_(std::move(options)),
          done_(std::move(done)) {}

    [[nodiscard]] asio::strand<asio::io_context::executor_type> executor() const { return strand_; }

    void start() {
        if (!options_.tls || !options_.acceptCertificate) return fail("no TLS context or certificate check");
        auto self = shared_from_this();
        timer_.expires_after(options_.timeout);
        timer_.async_wait([self](const boost::system::error_code& ec) {
            if (!ec) self->fail("timed out");
        });
        resolver_.async_resolve(options_.host, std::to_string(options_.port),
                                [self](const boost::system::error_code& ec, const tcp::resolver::results_type& results) {
                                    if (self->finished_) return;
                                    if (ec) return self->fail("cannot resolve " + self->options_.host + ": " + ec.message());
                                    self->onResolved(results);
                                });
    }

private:
    tcp::socket& socket() { return beast::get_lowest_layer(transport_->ws); }

    void onResolved(const tcp::resolver::results_type& results) {
        transport_ = std::make_shared<TlsTransport>(tcp::socket(strand_), *options_.tls);
        auto self = shared_from_this();
        asio::async_connect(socket(), results, [self](const boost::system::error_code& ec, const tcp::endpoint& ep) {
            if (self->finished_) return;
            if (ec) return self->fail("cannot connect: " + ec.message());
            const auto host = ep.address().is_v6() ? "[" + ep.address().to_string() + "]" : ep.address().to_string();
            self->address_ = host + ":" + std::to_string(ep.port());
            self->onConnected();
        });
    }

    void onConnected() {
        boost::system::error_code ignored;
        socket().set_option(tcp::no_delay(true), ignored);
        socket().set_option(asio::socket_base::keep_alive(true), ignored);
        auto& stream = transport_->ws.next_layer();
        if (!isIpLiteral(options_.host) && !SSL_set_tlsext_host_name(stream.native_handle(), options_.host.c_str()))
            return fail("cannot set the server name");
        stream.set_verify_mode(ssl::verify_peer);
        // The pin, not the trust store: chain errors (self-signed, dates, EKU) are not errors here.
        stream.set_verify_callback([accept = options_.acceptCertificate](bool, ssl::verify_context& ctx) {
            X509_STORE_CTX* store = ctx.native_handle();
            if (X509_STORE_CTX_get_error_depth(store) > 0) return true;
            X509* leaf = X509_STORE_CTX_get_current_cert(store);
            return leaf != nullptr && accept(leaf);
        });
        auto self = shared_from_this();
        stream.async_handshake(ssl::stream_base::client, [self](const boost::system::error_code& ec) {
            if (self->finished_) return;
            if (ec) return self->fail("TLS handshake failed: " + ec.message());
            self->onTls();
        });
    }

    void onTls() {
        // Whatever the callback saw, the certificate the session ended up with is checked again.
        X509* leaf = SSL_get1_peer_certificate(transport_->ws.next_layer().native_handle());
        const bool accepted = leaf != nullptr && options_.acceptCertificate(leaf);
        X509_free(leaf);
        if (!accepted) return fail("the server's key is not the expected one");
        auto& ws = transport_->ws;
        websocket::stream_base::timeout t = websocket::stream_base::timeout::suggested(beast::role_type::client);
        t.handshake_timeout = options_.timeout;
        ws.set_option(t);
        ws.set_option(websocket::stream_base::decorator(
            [ua = options_.userAgent](websocket::request_type& req) { req.set(beast::http::field::user_agent, ua); }));
        auto self = shared_from_this();
        ws.async_handshake(options_.host, options_.target, [self](const boost::system::error_code& ec) {
            if (self->finished_) return;
            if (ec) return self->fail("websocket upgrade refused: " + ec.message());
            self->succeed();
        });
    }

    void succeed() {
        finished_ = true;
        timer_.cancel();
        done_(DialResult{.transport = std::move(transport_), .error = {}, .address = address_});
    }

    void fail(const std::string& why) {
        if (finished_) return;
        finished_ = true;
        timer_.cancel();
        resolver_.cancel();
        if (transport_) {
            boost::system::error_code ignored;
            socket().shutdown(tcp::socket::shutdown_both, ignored);
            socket().close(ignored);
        }
        done_(DialResult{.transport = nullptr, .error = why, .address = address_});
    }

    asio::strand<asio::io_context::executor_type> strand_;
    tcp::resolver resolver_;
    asio::steady_timer timer_;
    DialOptions options_;
    std::function<void(DialResult)> done_;
    std::shared_ptr<TlsTransport> transport_;
    std::string address_;
    bool finished_ = false;
};

}

void dial(asio::io_context& ioc, DialOptions options, std::function<void(DialResult)> done) {
    auto d = std::make_shared<Dial>(ioc, std::move(options), std::move(done));
    asio::dispatch(d->executor(), [d] { d->start(); });
}

}
