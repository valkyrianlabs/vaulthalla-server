#pragma once

// A browser stand-in for the Vaulthalla Cloud relay's streams (design/cloud/relay.md, option (c)): a P-256 key, a TLS 1.3
// client WITHOUT a certificate that authenticates the server by its pin, the key proof inside the stream
// (cloud/RelayProtocol.hpp), then the device listener's /ws or an HTTP lane. It runs over any connected stream socket
// (one end of a socketpair the test or a fake relay pumps). Every operation is async with a deadline.

#include "cloud/RelayProtocol.hpp"
#include "device/Crypto.hpp"
#include "device/ServerIdentity.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/read.hpp>
#include <boost/asio/read_until.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/write.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include "compat/beast_websocket.hpp"
#include <nlohmann/json.hpp>
#include <openssl/bn.h>
#include <openssl/ecdsa.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace vh::test::relay {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace ssl = asio::ssl;
using json = nlohmann::json;
using tcp = asio::ip::tcp;

// A local socketpair: {listener's end, the browser's end}.
inline std::pair<int, int> socketPair() {
    int fds[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) return {-1, -1};
#ifdef SO_NOSIGPIPE
    const int on = 1;
    for (const int fd : fds) ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#endif
    return {fds[0], fds[1]};
}

// The browser's key (WebCrypto would make it with generateKey(..., false, ["sign"])).
struct BrowserKey {
    std::shared_ptr<const vh::device::ServerIdentity> id = vh::device::ServerIdentity::generate();

    [[nodiscard]] vh::device::crypto::PublicKey publicKey() const { return *vh::device::crypto::p256KeyOf(id->certificate()); }
    [[nodiscard]] std::string spkiHex() const { return vh::device::crypto::toHex(publicKey().spkiSha256); }
    // ECDSA P-256 / SHA-256 in WebCrypto's raw r ‖ s form.
    [[nodiscard]] std::vector<uint8_t> signRaw(const std::string& message) const {
        EVP_MD_CTX* ctx = EVP_MD_CTX_new();
        std::size_t len = 0;
        EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, id->key());
        EVP_DigestSign(ctx, nullptr, &len, reinterpret_cast<const unsigned char*>(message.data()), message.size());
        std::vector<uint8_t> der(len);
        EVP_DigestSign(ctx, der.data(), &len, reinterpret_cast<const unsigned char*>(message.data()), message.size());
        der.resize(len);
        EVP_MD_CTX_free(ctx);
        const unsigned char* p = der.data();
        ECDSA_SIG* sig = d2i_ECDSA_SIG(nullptr, &p, static_cast<long>(der.size()));
        std::vector<uint8_t> raw(64, 0);
        BN_bn2binpad(ECDSA_SIG_get0_r(sig), raw.data(), 32);
        BN_bn2binpad(ECDSA_SIG_get0_s(sig), raw.data() + 32, 32);
        ECDSA_SIG_free(sig);
        return raw;
    }
};

// How the proof is made (the refusal tests bend one thing each).
struct Proof {
    const BrowserKey* key = nullptr;                    // whose key is proven (default: the browser's own)
    std::optional<std::string> jti{};                   // another ticket's jti
    std::optional<std::vector<uint8_t>> exporter{};     // another session's exporter
    std::optional<std::vector<uint8_t>> record{};       // send these bytes as the proof, verbatim
    bool send = true;                                   // false: send nothing (the listener times out)
};

class Browser {
public:

    Browser(const int fd, const BrowserKey& key, std::string jti)
        : key_(key), jti_(std::move(jti)), tls_(ssl::context::tls_client) {
        SSL_CTX* native = tls_.native_handle();
        SSL_CTX_set_min_proto_version(native, TLS1_3_VERSION);
        SSL_CTX_set_verify(native, SSL_VERIFY_NONE, nullptr);  // the pin is checked below, like Desktop's verify block
        tcp::socket socket(ioc_);
        boost::system::error_code ec;
        socket.assign(tcp::v4(), fd, ec);
        ws_ = std::make_unique<Ws>(std::move(socket), tls_);
    }

    // TLS (no client certificate), then the challenge; false when either fails.
    bool handshake() {
        bool ok = false;
        stream().async_handshake(ssl::stream_base::client, [&](const beast::error_code& e) { ok = !e; });
        if (!run() || !ok) return false;
        if (const X509* server = SSL_get0_peer_certificate(stream().native_handle())) serverKey_ = vh::device::crypto::p256KeyOf(server);
        exporter_.resize(cloud::relay::kExporterBytes);
        if (SSL_export_keying_material(stream().native_handle(), exporter_.data(), exporter_.size(),
                                       cloud::relay::kExporterLabel.data(), cloud::relay::kExporterLabel.size(), nullptr, 0,
                                       0) != 1)
            return false;
        ok = false;
        asio::async_read(stream(), asio::buffer(challenge_), [&](const beast::error_code& e, std::size_t) { ok = !e; });
        return run() && ok && challenge_[0] == cloud::relay::kProofVersion;
    }

    [[nodiscard]] std::vector<uint8_t> nonce() const { return {challenge_.begin() + 1, challenge_.end()}; }
    [[nodiscard]] const std::vector<uint8_t>& exporter() const { return exporter_; }
    [[nodiscard]] const std::optional<vh::device::crypto::PublicKey>& serverKey() const { return serverKey_; }

    // The proof record as the browser makes it.
    [[nodiscard]] std::vector<uint8_t> proofRecord(const Proof& p = {}) const {
        const auto& key = p.key ? *p.key : key_;
        const auto spki = key.publicKey().spkiDer;
        const auto message = cloud::relay::proofMessage(p.jti.value_or(jti_), nonce(), p.exporter.value_or(exporter_));
        std::vector<uint8_t> out{cloud::relay::kProofVersion};
        out.insert(out.end(), spki.begin(), spki.end());
        const auto sig = key.signRaw(message);
        out.insert(out.end(), sig.begin(), sig.end());
        return out;
    }

    bool prove(const Proof& p = {}) {
        if (!p.send) return true;
        const auto record = p.record.value_or(proofRecord(p));
        bool ok = false;
        asio::async_write(stream(), asio::buffer(record), [&](const beast::error_code& e, std::size_t) { ok = !e; });
        return run() && ok;
    }

    // The websocket upgrade on /ws.
    bool upgrade() {
        bool ok = false;
        ws_->async_handshake("vaulthalla", "/ws", [&](const beast::error_code& e) { ok = !e; });
        return run() && ok;
    }

    bool connect(const Proof& p = {}) { return handshake() && prove(p) && upgrade(); }

    // The upgrade exactly as the portal writes it (vaulthalla-cloud-portal src/relay/ws.ts): raw bytes on the inner
    // TLS stream; the answer's head as text (empty when none came).
    std::string rawUpgrade(const std::string& key, const bool withProof = false) {
        std::string req;
        if (withProof) {  // the proof and the upgrade in one write, as a browser may send them
            const auto record = proofRecord();
            req.assign(record.begin(), record.end());
        }
        req += "GET /ws HTTP/1.1\r\nHost: vaulthalla\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
                                "Sec-WebSocket-Key: " + key + "\r\nSec-WebSocket-Version: 13\r\n\r\n";
        bool ok = false;
        asio::async_write(stream(), asio::buffer(req), [&](const beast::error_code& e, std::size_t) { ok = !e; });
        if (!run() || !ok) return {};
        std::string head;
        asio::async_read_until(stream(), asio::dynamic_buffer(head), "\r\n\r\n",
                               [&](const beast::error_code&, std::size_t) {});
        (void)run();
        return head;
    }

    std::optional<json> call(const std::string& command, const json& payload = json::object()) {
        const auto id = "r" + std::to_string(++counter_);
        const auto text = json{{"command", command}, {"payload", payload}, {"requestId", id}}.dump();
        bool ok = false;
        ws_->text(true);
        ws_->async_write(asio::buffer(text), [&](const beast::error_code& e, std::size_t) { ok = !e; });
        if (!run() || !ok) return std::nullopt;
        for (int i = 0; i < 8; ++i) {
            buffer_.consume(buffer_.size());
            ok = false;
            ws_->async_read(buffer_, [&](const beast::error_code& e, std::size_t) { ok = !e; });
            if (!run() || !ok) return std::nullopt;
            auto frame = json::parse(beast::buffers_to_string(buffer_.data()), nullptr, false);
            if (frame.is_object() && frame.value("requestId", "") == id) return frame;
        }
        return std::nullopt;
    }

    // One HTTP request on the TLS stream after the proof (instead of /ws): the status, 0 when none came.
    unsigned httpStatus(const beast::http::verb method, const std::string& target) {
        beast::http::request<beast::http::empty_body> req{method, target, 11};
        req.set(beast::http::field::host, "vaulthalla");
        bool ok = false;
        beast::http::async_write(stream(), req, [&](const beast::error_code& e, std::size_t) { ok = !e; });
        if (!run() || !ok) return 0;
        beast::http::response<beast::http::string_body> res;
        ok = false;
        beast::http::async_read(stream(), buffer_, res, [&](const beast::error_code& e, std::size_t) { ok = !e; });
        if (!run() || !ok) return 0;
        lastBody_ = res.body();
        return res.result_int();
    }
    [[nodiscard]] const std::string& lastBody() const { return lastBody_; }

    // True once the other end closes the stream (a refused proof) within `within`.
    bool closedByServer(const std::chrono::milliseconds within = std::chrono::seconds(5)) {
        std::array<uint8_t, 64> scratch{};
        bool done = false;
        beast::error_code err;
        stream().async_read_some(asio::buffer(scratch), [&](const beast::error_code& e, std::size_t) {
            done = true;
            err = e;
        });
        ioc_.restart();
        ioc_.run_for(within);
        return done && err;
    }

private:
    using Ws = beast::websocket::stream<ssl::stream<tcp::socket>>;
    ssl::stream<tcp::socket>& stream() { return ws_->next_layer(); }

    bool run(const std::chrono::milliseconds timeout = std::chrono::seconds(10)) {
        ioc_.restart();
        ioc_.run_for(timeout);
        return ioc_.stopped();
    }

    const BrowserKey& key_;
    std::string jti_;
    asio::io_context ioc_;
    ssl::context tls_;
    std::unique_ptr<Ws> ws_;
    beast::flat_buffer buffer_;
    std::array<uint8_t, cloud::relay::kChallengeRecordBytes> challenge_{};
    std::vector<uint8_t> exporter_;
    std::optional<vh::device::crypto::PublicKey> serverKey_;
    std::string lastBody_;
    int counter_ = 0;
};

}
