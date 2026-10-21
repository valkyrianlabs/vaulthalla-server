#include "protocols/device/Listener.hpp"

#include "auth/session/Manager.hpp"
#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "log/Registry.hpp"
#include "protocols/device/Mcp.hpp"
#include "protocols/http/Session.hpp"
#include "protocols/ws/ConnectionLimit.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/TlsTransport.hpp"
#include "runtime/Deps.hpp"

#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/asio/strand.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <algorithm>
#include <atomic>
#include <limits>
#include <thread>
#include <string_view>

namespace vh::protocols::device {

namespace beast = boost::beast;
namespace bhttp = beast::http;
namespace ssl = asio::ssl;

namespace {

// Chain errors (self-signed, dates, EKU) are not errors here: TLS 1.3's CertificateVerify proves the client holds
// the key, and the key is what gets authorized after the handshake (spec §2).
int acceptAnyChain(int /*preverifyOk*/, X509_STORE_CTX* /*ctx*/) { return 1; }

void warnRefused(const unsigned int limit) {
    static std::atomic<int64_t> lastWarnSeconds{0};
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    auto last = lastWarnSeconds.load(std::memory_order_relaxed);
    if (last != 0 && now - last < 60) return;
    if (!lastWarnSeconds.compare_exchange_strong(last, now, std::memory_order_relaxed)) return;
    log::Registry::ws()->warn(
        "[DeviceServer] Connection limit (device_server.max_connections = {}) reached: {} refused so far", limit,
        ws::ConnectionSlot::refused(ws::ConnectionSlot::Pool::Device));
}

bool isPath(const std::string_view target, const std::string_view path) {
    return target == path || (target.starts_with(path) && target.size() > path.size() && target[path.size()] == '?');
}

// The HTTP routes served on the listener: the lanes nginx forwards on the web side, and MCP.
bool isHttpLane(const std::string_view target) {
    for (const std::string_view prefix : {"/preview", "/download", "/upload"})
        if (target.starts_with(prefix) && (target.size() == prefix.size() || target[prefix.size()] == '/' ||
                                           target[prefix.size()] == '?'))
            return true;
    return isPath(target, "/mcp");
}

// One accepted TCP connection until it is a ws::Session (or refused): TLS handshake, authorization by the client
// key, the HTTP request, path dispatch. Everything runs on the socket's strand.
class Connection : public std::enable_shared_from_this<Connection> {
public:
    Connection(tcp::socket&& socket, ssl::context& tls, std::shared_ptr<ws::Router> router,
               std::unique_ptr<ws::ConnectionSlot> slot)
        : transport_(std::make_shared<ws::TlsTransport>(std::move(socket), tls)),
          timer_(transport_->ws.get_executor()),
          router_(std::move(router)),
          slot_(std::move(slot)) {}

    void start() {
        armTimer();
        transport_->ws.next_layer().async_handshake(
            ssl::stream_base::server,
            [self = shared_from_this()](const beast::error_code& ec) { self->onHandshake(ec); });
    }

private:
    tcp::socket& socket() { return beast::get_lowest_layer(transport_->ws); }

    void armTimer() {
        timer_.expires_after(Listener::kHandshakeTimeout);
        timer_.async_wait([weak = weak_from_this()](const beast::error_code& ec) {
            if (ec) return;  // cancelled
            if (const auto self = weak.lock()) self->abort("timed out");
        });
    }

    void abort(const std::string_view why) {
        log::Registry::ws()->debug("[DeviceServer] Dropping a connection from {}: {}", address_, why);
        beast::error_code ignored;
        socket().shutdown(tcp::socket::shutdown_both, ignored);
        socket().close(ignored);
    }

    void onHandshake(const beast::error_code& ec) {
        if (ec) return abort("TLS handshake failed: " + ec.message());
        try {
            address_ = socket().remote_endpoint().address().to_string();
        } catch (...) {
            return abort("peer vanished");
        }

        const auto key = vh::device::crypto::p256KeyOf(SSL_get0_peer_certificate(transport_->ws.next_layer().native_handle()));
        if (!key) return abort("client certificate is not ECDSA P-256");

        try {
            authorization_ = vh::device::authorize(*key, address_);
        } catch (const std::exception& e) {
            log::Registry::ws()->error("[DeviceServer] Refusing a connection from {}: authorization failed: {}", address_,
                                       e.what());
            return abort("authorization failed");
        }

        // The header only: an upload's body is the HTTP session's to stream.
        parser_ = std::make_unique<protocols::http::HeaderParser>();
        parser_->body_limit(std::numeric_limits<uint64_t>::max());
        bhttp::async_read_header(transport_->ws.next_layer(), buffer_, *parser_,
                                [self = shared_from_this()](const beast::error_code& ec2, std::size_t) {
                                    self->onRequest(ec2);
                                });
    }

    void onRequest(const beast::error_code& ec) {
        if (ec) return abort("no HTTP request: " + ec.message());
        timer_.cancel();
        dispatch();
    }

    // The one place a path picks its handler: /ws (the console's Router), the HTTP lanes and /mcp (an HTTP session
    // on its own thread, as the device's user). A pairing-only connection gets only /ws.
    void dispatch() {
        const auto& header = parser_->get();
        const std::string target{header.target()};
        if (isPath(target, "/ws")) {
            request_ = std::make_shared<RequestType>(header.method(), header.target(), header.version());
            for (const auto& f : header) request_->insert(f.name_string(), f.value());
            if (!beast::websocket::is_upgrade(*request_)) return respond(bhttp::status::upgrade_required, "websocket only");
            const auto session = std::make_shared<ws::Session>(router_);
            session->holdConnectionSlot(std::move(slot_));
            session->acceptDevice(transport_, *request_, authorization_.peer, authorization_.user);
            return;
        }
        if (isHttpLane(target)) {
            if (!authorization_.user) return respond(bhttp::status::forbidden, "device_unknown");
            auto session = protocols::http::Session::openDevice(
                protocols::http::DeviceConnection{.transport = transport_, .peer = authorization_.peer,
                                                  .user = authorization_.user, .slot = std::move(slot_),
                                                  .mcp = &protocols::device::mcp::handle},
                std::move(parser_), std::move(buffer_));
            try {
                std::thread([session = std::move(session)] {
                    try {
                        session->run();
                    } catch (const std::exception& e) {
                        log::Registry::http()->error("[DeviceServer] HTTP session ended: {}", e.what());
                    }
                }).detach();
            } catch (const std::exception& e) {
                log::Registry::http()->error("[DeviceServer] Could not start a connection thread: {}", e.what());
            }
            return;
        }
        respond(bhttp::status::not_found, "not found");
    }

    void respond(const bhttp::status status, const std::string_view body) {
        auto res = std::make_shared<bhttp::response<bhttp::string_body>>(status, parser_->get().version());
        res->set(bhttp::field::server, "Vaulthalla");
        res->set(bhttp::field::content_type, "text/plain");
        res->keep_alive(false);
        res->body() = std::string(body);
        res->prepare_payload();
        armTimer();
        bhttp::async_write(transport_->ws.next_layer(), *res,
                          [self = shared_from_this(), res](const beast::error_code&, std::size_t) {
                              self->transport_->ws.next_layer().async_shutdown(
                                  [self](const beast::error_code&) { self->abort("response sent"); });
                          });
    }

    std::shared_ptr<ws::TlsTransport> transport_;
    asio::steady_timer timer_;
    std::shared_ptr<ws::Router> router_;
    std::unique_ptr<ws::ConnectionSlot> slot_;
    beast::flat_buffer buffer_{16384};
    std::unique_ptr<protocols::http::HeaderParser> parser_;
    std::shared_ptr<RequestType> request_;
    std::string address_{"unknown"};
    vh::device::Authorization authorization_;
};

}

std::shared_ptr<ssl::context> makeServerContext(const vh::device::ServerIdentity& identity) {
    auto ctx = std::make_shared<ssl::context>(ssl::context::tls_server);
    SSL_CTX* native = ctx->native_handle();
    if (SSL_CTX_set_min_proto_version(native, TLS1_3_VERSION) != 1 ||
        SSL_CTX_set_max_proto_version(native, TLS1_3_VERSION) != 1)
        throw std::runtime_error("device listener: cannot restrict TLS to 1.3");
    SSL_CTX_set_options(native, SSL_OP_NO_TICKET | SSL_OP_NO_COMPRESSION);
    SSL_CTX_set_num_tickets(native, 0);
    SSL_CTX_set_session_cache_mode(native, SSL_SESS_CACHE_OFF);
    if (SSL_CTX_use_certificate(native, identity.certificate()) != 1 ||
        SSL_CTX_use_PrivateKey(native, identity.key()) != 1 || SSL_CTX_check_private_key(native) != 1)
        throw std::runtime_error("device listener: cannot load the server identity");
    // Devices sign with Secure Enclave P-256 keys, which sign nothing else (spec §2).
    if (SSL_CTX_set1_client_sigalgs_list(native, "ECDSA+SHA256") != 1)
        throw std::runtime_error("device listener: cannot set the client signature algorithms");
    SSL_CTX_set_verify(native, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, acceptAnyChain);
    return ctx;
}

Listener::Listener(asio::io_context& ioc, std::shared_ptr<ssl::context> tls, std::shared_ptr<ws::Router> router,
                   const unsigned int maxConnections)
    : ioc_(ioc), acceptor_(ioc), tls_(std::move(tls)), router_(std::move(router)), maxConnections_(maxConnections) {}

void Listener::listen(const tcp::endpoint& endpoint) {
    close();
    beast::error_code ec;
    acceptor_.open(endpoint.protocol(), ec);
    if (!ec) acceptor_.set_option(asio::socket_base::reuse_address(true), ec);
    if (!ec) acceptor_.bind(endpoint, ec);
    if (!ec) acceptor_.listen(asio::socket_base::max_listen_connections, ec);
    if (ec) {
        beast::error_code ignored;
        acceptor_.close(ignored);
        throw std::runtime_error("cannot listen on " + endpoint.address().to_string() + ":" +
                                 std::to_string(endpoint.port()) + ": " + ec.message());
    }
    closed_.store(false, std::memory_order_release);
    doAccept();
}

void Listener::close() noexcept {
    closed_.store(true, std::memory_order_release);
    beast::error_code ec;
    acceptor_.cancel(ec);
    acceptor_.close(ec);
}

tcp::endpoint Listener::localEndpoint() const {
    beast::error_code ec;
    auto ep = acceptor_.local_endpoint(ec);
    return ec ? tcp::endpoint{} : ep;
}

void Listener::doAccept() {
    if (closed_.load(std::memory_order_acquire) || !acceptor_.is_open()) return;
    acceptor_.async_accept(asio::make_strand(ioc_), [self = shared_from_this()](const beast::error_code& ec,
                                                                                tcp::socket socket) mutable {
        if (ec) {
            if (ec == asio::error::operation_aborted || self->closed_.load(std::memory_order_acquire)) return;
            log::Registry::ws()->debug("[DeviceServer] accept error: {}", ec.message());
            return self->doAccept();
        }
        const auto limit = self->maxConnections_.load(std::memory_order_relaxed);
        if (auto slot = ws::ConnectionSlot::tryAcquire(limit, ws::ConnectionSlot::Pool::Device)) {
            beast::error_code ignored;
            socket.set_option(tcp::no_delay(true), ignored);
            socket.set_option(asio::socket_base::keep_alive(true), ignored);
            std::make_shared<Connection>(std::move(socket), *self->tls_, self->router_, std::move(slot))->start();
        } else {
            // A TLS client can't read a plaintext 503: over the cap the connection is simply closed.
            warnRefused(std::max(1u, limit));
            beast::error_code ignored;
            socket.close(ignored);
        }
        self->doAccept();
    });
}

}
