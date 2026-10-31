#pragma once

// A Vaulthalla Desktop stand-in for tests: a P-256 client identity and a websocket client over TLS 1.3 speaking the ws
// envelope to the device listener. Every operation is async with a deadline (io_context::run_for), so a test never
// hangs on a listener that misbehaves.

#include "device/Crypto.hpp"
#include "device/ServerIdentity.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <nlohmann/json.hpp>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vh::test::device {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace ssl = asio::ssl;
using json = nlohmann::json;
using tcp = asio::ip::tcp;

// A device key and its self-signed certificate. The listener checks the key, never the chain or the EKU, so the
// daemon's own certificate issuer serves for test clients too.
struct ClientIdentity {
    std::shared_ptr<const vh::device::ServerIdentity> id = vh::device::ServerIdentity::generate();

    [[nodiscard]] vh::device::crypto::PublicKey publicKey() const { return *vh::device::crypto::p256KeyOf(id->certificate()); }
    [[nodiscard]] std::string deviceId() const { return vh::device::crypto::toHex(publicKey().spkiSha256); }
    [[nodiscard]] std::vector<uint8_t> certificateDer() const {
        unsigned char* der = nullptr;
        const int len = i2d_X509(id->certificate(), &der);
        std::vector<uint8_t> out(der, der + len);
        OPENSSL_free(der);
        return out;
    }
    // ECDSA-P256-SHA256, DER signature.
    [[nodiscard]] std::vector<uint8_t> sign(const std::vector<uint8_t>& message) const {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::size_t len = 0;
        EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, id->key());
        EVP_DigestSign(ctx, nullptr, &len, message.data(), message.size());
        std::vector<uint8_t> sig(len);
        EVP_DigestSign(ctx, sig.data(), &len, message.data(), message.size());
        sig.resize(len);
        EVP_MD_CTX_free(ctx);
        return sig;
    }
};

class Client {
public:
    struct Options {
        bool presentCertificate = true;
        int maxTlsVersion = TLS1_3_VERSION;
        EVP_PKEY* overrideKey = nullptr;     // a non-P-256 client (with overrideCert)
        X509* overrideCert = nullptr;
    };

    Client(const uint16_t port, const ClientIdentity& identity) : Client(port, identity, Options{}) {}

    Client(const uint16_t port, const ClientIdentity& identity, const Options& options)
        : port_(port), tls_(ssl::context::tls_client) {
        SSL_CTX* native = tls_.native_handle();
        SSL_CTX_set_max_proto_version(native, options.maxTlsVersion);
        SSL_CTX_set_verify(native, SSL_VERIFY_NONE, nullptr);
        if (options.presentCertificate) {
            SSL_CTX_use_certificate(native, options.overrideCert ? options.overrideCert : identity.id->certificate());
            SSL_CTX_use_PrivateKey(native, options.overrideKey ? options.overrideKey : identity.id->key());
        }
        ws_ = std::make_unique<Ws>(ioc_, tls_);
    }

    // TCP + TLS + the websocket upgrade on /ws (or `target`). False when any step fails or times out.
    bool connect(const std::string& target = "/ws") {
        auto& lowest = beast::get_lowest_layer(*ws_);
        beast::error_code ec;
        lowest.connect(tcp::endpoint(asio::ip::make_address("127.0.0.1"), port_), ec);
        if (ec) return false;
        bool ok = false;
        ws_->next_layer().async_handshake(ssl::stream_base::client, [&](const beast::error_code& e) { ok = !e; });
        if (!run() || !ok) return false;
        if (SSL* ssl = ws_->next_layer().native_handle()) {
            if (const X509* server = SSL_get0_peer_certificate(ssl))
                serverSpki_ = vh::device::crypto::p256KeyOf(server);
        }
        ok = false;
        ws_->async_handshake("127.0.0.1", target, [&](const beast::error_code& e) { ok = !e; });
        return run() && ok;
    }

    // Sends {command, payload, requestId} and returns the matching response envelope (nullopt on timeout/close).
    std::optional<json> call(const std::string& command, const json& payload = json::object()) {
        const auto id = "r" + std::to_string(++counter_);
        if (!send(json{{"command", command}, {"payload", payload}, {"requestId", id}}.dump())) return std::nullopt;
        for (int i = 0; i < 8; ++i) {
            auto frame = read();
            if (!frame) return std::nullopt;
            if (frame->value("requestId", "") == id) return frame;
        }
        return std::nullopt;
    }

    // True when the server closes the connection within `within` (frames before the close are skipped).
    bool closedByServer(const std::chrono::milliseconds within = std::chrono::seconds(5)) {
        const auto deadline = std::chrono::steady_clock::now() + within;
        while (std::chrono::steady_clock::now() < deadline) {
            bool done = false;
            beast::error_code err;
            buffer_.consume(buffer_.size());
            ws_->async_read(buffer_, [&](const beast::error_code& e, std::size_t) {
                done = true;
                err = e;
            });
            ioc_.restart();
            ioc_.run_for(deadline - std::chrono::steady_clock::now());
            if (!done) return false;
            if (err) return true;
        }
        return false;
    }

    [[nodiscard]] const std::optional<vh::device::crypto::PublicKey>& serverKey() const { return serverSpki_; }

private:
    using Ws = beast::websocket::stream<ssl::stream<tcp::socket>>;

    bool run(const std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
        ioc_.restart();
        ioc_.run_for(timeout);
        return ioc_.stopped();
    }

    bool send(const std::string& text) {
        bool ok = false;
        ws_->async_write(asio::buffer(text), [&](const beast::error_code& e, std::size_t) { ok = !e; });
        return run() && ok;
    }

    std::optional<json> read() {
        buffer_.consume(buffer_.size());
        bool ok = false;
        ws_->async_read(buffer_, [&](const beast::error_code& e, std::size_t) { ok = !e; });
        if (!run() || !ok) return std::nullopt;
        return json::parse(beast::buffers_to_string(buffer_.data()), nullptr, false);
    }

    uint16_t port_;
    asio::io_context ioc_;
    ssl::context tls_;
    std::unique_ptr<Ws> ws_;
    beast::flat_buffer buffer_;
    std::optional<vh::device::crypto::PublicKey> serverSpki_;
    int counter_ = 0;
};

// HTTP/1.1 over the same TLS profile (the device listener's /preview, /download, /upload, /transfer and /mcp lanes),
// keep-alive.
class HttpClient {
public:
    using Response = beast::http::response<beast::http::string_body>;

    HttpClient(const uint16_t port, const ClientIdentity& identity) : port_(port), tls_(ssl::context::tls_client) {
        SSL_CTX* native = tls_.native_handle();
        SSL_CTX_set_verify(native, SSL_VERIFY_NONE, nullptr);
        SSL_CTX_use_certificate(native, identity.id->certificate());
        SSL_CTX_use_PrivateKey(native, identity.id->key());
        stream_ = std::make_unique<ssl::stream<tcp::socket>>(ioc_, tls_);
    }

    bool connect(const std::string& host = "127.0.0.1") {
        beast::error_code ec;
        stream_->lowest_layer().connect(tcp::endpoint(asio::ip::make_address(host), port_), ec);
        if (ec) return false;
        bool ok = false;
        stream_->async_handshake(ssl::stream_base::client, [&](const beast::error_code& e) { ok = !e; });
        return run() && ok;
    }

    // nullopt when the connection fails or closes before a full response.
    std::optional<Response> request(const beast::http::verb method, const std::string& target, std::string body = {},
                                    const std::vector<std::pair<std::string, std::string>>& headers = {}) {
        beast::http::request<beast::http::string_body> req{method, target, 11};
        req.set(beast::http::field::host, "127.0.0.1");
        for (const auto& [k, v] : headers) req.set(k, v);
        req.body() = std::move(body);
        req.prepare_payload();
        bool ok = false;
        beast::http::async_write(*stream_, req, [&](const beast::error_code& e, std::size_t) { ok = !e; });
        if (!run() || !ok) return std::nullopt;
        Response res;
        ok = false;
        beast::http::response_parser<beast::http::string_body> parser;
        parser.body_limit(64u * 1024u * 1024u);
        if (method == beast::http::verb::head) parser.skip(true);
        beast::http::async_read(*stream_, buffer_, parser, [&](const beast::error_code& e, std::size_t) { ok = !e; });
        if (!run() || !ok) return std::nullopt;
        return parser.release();
    }

    std::optional<json> mcp(const json& message, const std::vector<std::pair<std::string, std::string>>& extra = {}) {
        std::vector<std::pair<std::string, std::string>> headers{{"Content-Type", "application/json"},
                                                                 {"Accept", "application/json, text/event-stream"}};
        headers.insert(headers.end(), extra.begin(), extra.end());
        const auto res = request(beast::http::verb::post, "/mcp", message.dump(), headers);
        if (!res || res->body().empty()) return std::nullopt;
        return json::parse(res->body(), nullptr, false);
    }

private:
    bool run(const std::chrono::milliseconds timeout = std::chrono::seconds(20)) {
        ioc_.restart();
        ioc_.run_for(timeout);
        return ioc_.stopped();
    }

    uint16_t port_;
    asio::io_context ioc_;
    ssl::context tls_;
    std::unique_ptr<ssl::stream<tcp::socket>> stream_;
    beast::flat_buffer buffer_;
};

}
