// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The Vaulthalla Cloud relay end to end (design/cloud/relay.md). Relayed streams on the device listener over real TLS
// 1.3 without a client certificate: the key proof (the ticket's key, another key, a proof from another TLS session, a
// proof replayed into a new stream), pairing-only until paired, pairing through the relay (via relay, paired_via, no
// approval key), the read-only set on ws and the HTTP lanes, revocation; the network listener never accepts a peer
// without a certificate. Then CloudRelayService against a fake relay and a fake cloud: the signed ticket, TICKET /
// CHALLENGE / PROOF checked with the installation key / WELCOME, a browser stream carried in DATA and CREDIT frames,
// refused OPENs (another server's ticket, an expired one, an unknown ticket key, a replayed jti), RENEW, the switch
// off closing everything, and a 401 stopping the service.

#include "../helpers/db_suite.hpp"
#include "../helpers/device_client.hpp"
#include "../helpers/identities.hpp"
#include "../helpers/relay_browser.hpp"
#include "auth/stepup/StepUp.hpp"
#include "cloud/Identity.hpp"
#include "cloud/RelayProtocol.hpp"
#include "cloud/RelayService.hpp"
#include "cloud/Signing.hpp"
#include "config/Registry.hpp"
#include "db/query/cloud/Link.hpp"
#include "db/query/cloud/Relay.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Crypto.hpp"
#include "device/Pairing.hpp"
#include "device/ServerIdentity.hpp"
#include "identities/User.hpp"
#include "ops/CloudRelay.hpp"
#include "ops/Devices.hpp"
#include "ops/Error.hpp"
#include "protocols/device/Listener.hpp"
#include "protocols/device/Service.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Devices.hpp"
#include "runtime/Deps.hpp"
#include "storage/s3/curl/Http.hpp"

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/ssl/context.hpp>
#include <gtest/gtest.h>
#include <sodium.h>
#include <vl/keykit/base64url.hpp>

#include <spawn.h>
#include <sys/wait.h>

#include <condition_variable>
#include <csignal>
#include <deque>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <thread>

extern char** environ;

namespace vh::test_cloud_relay_db {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
namespace relay = cloud::relay;
namespace crypto = vh::device::crypto;
namespace handler = protocols::ws::handler;
namespace http = storage::s3::curl::http;
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
using test::relay::Browser;
using test::relay::BrowserKey;
using test::relay::Proof;
using namespace std::chrono_literals;

constexpr const char* kAccount = "0b5f6d2e-8c1a-4b7e-9f00-1234567890ab";
constexpr const char* kDeployment = "d3p1qymnt00000000000000000";
constexpr const char* kInstallation = "1n5ta11at10n00000000000000";
constexpr const char* kAudience = "relay-1";

std::span<const uint8_t> bytesOf(const std::string& s) { return {reinterpret_cast<const uint8_t*>(s.data()), s.size()}; }
int64_t now() { return std::time(nullptr); }

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "r" + std::to_string(n.fetch_add(1));
}

std::string code(const std::optional<json>& reply) {
    if (!reply || !reply->contains("data") || !reply->at("data").is_object()) return "";
    return reply->at("data").value("code", "");
}
bool ok(const std::optional<json>& reply) { return reply && reply->value("status", "") == "OK"; }

std::string randomJti() {
    std::array<uint8_t, 16> b{};
    randombytes_buf(b.data(), b.size());
    return vl::keykit::base64UrlEncode(b);
}

struct TicketSigner {
    std::array<uint8_t, crypto_sign_PUBLICKEYBYTES> pk{};
    std::array<uint8_t, crypto_sign_SECRETKEYBYTES> sk{};
    TicketSigner() { crypto_sign_keypair(pk.data(), sk.data()); }
    [[nodiscard]] std::string publicKey() const { return vl::keykit::base64UrlEncode(pk); }
    [[nodiscard]] relay::TicketKey key() const {
        relay::TicketKey k{};
        std::ranges::copy(pk, k.begin());
        return k;
    }
    [[nodiscard]] std::string sign(const json& claims) const {
        const auto c = vl::keykit::base64UrlEncode(bytesOf(claims.dump()));
        const auto input = "vhc-relay-ticket-v1\n" + c;
        std::array<uint8_t, crypto_sign_BYTES> sig{};
        crypto_sign_detached(sig.data(), nullptr, reinterpret_cast<const unsigned char*>(input.data()), input.size(), sk.data());
        return "vhr1." + c + "." + vl::keykit::base64UrlEncode(sig);
    }
    [[nodiscard]] std::string browser(const std::string& spki, const int64_t at = now(), const std::string& dep = kDeployment,
                                      const std::string& jti = randomJti()) const {
        return sign({{"typ", "browser"}, {"aud", kAudience}, {"acct", kAccount}, {"dep", dep}, {"iat", at},
                     {"exp", at + 60}, {"jti", jti}, {"renew", 600}, {"kid", "k3ymd00000000000000000000g"},
                     {"spki", spki},
                     {"lim", {{"stream_bytes", 1LL << 31}, {"day_bytes", 1LL << 33}, {"day_used", 0}, {"day", "2026-11-15"}}}});
    }
    [[nodiscard]] std::string server(const std::string& installationKey, const int64_t at = now()) const {
        return sign({{"typ", "server"}, {"aud", kAudience}, {"acct", kAccount}, {"dep", kDeployment}, {"iat", at},
                     {"exp", at + 60}, {"jti", randomJti()}, {"renew", 600}, {"inst", kInstallation},
                     {"key", installationKey}});
    }
};

std::string jtiOf(const std::string& ticket) { return *relay::unverifiedJti(ticket); }

// ---- a fake relay: one server connection, frames queued for the test, browser streams pumped through socketpairs -----

class FakeRelay {
public:
    FakeRelay() : acceptor_(io_, asio::ip::tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)) {
        port_ = acceptor_.local_endpoint().port();
        accept();
        thread_ = std::thread([this] { io_.run(); });
    }
    ~FakeRelay() {
        asio::post(io_, [this] {
            boost::system::error_code ignored;
            acceptor_.close(ignored);
            if (ws_) beast::get_lowest_layer(*ws_).socket().close(ignored);
            for (auto& [_, p] : pumps_) p->close(ignored);
            work_.reset();
        });
        thread_.join();
    }

    [[nodiscard]] uint16_t port() const { return port_; }
    std::array<uint8_t, 32> installationKey{};  // checks PROOF
    std::atomic<int> renewals{0};
    std::atomic<bool> admitted{false};

    // The next frame the server sent (DATA and CREDIT of pumped streams are consumed by the pump): {type, stream, payload}.
    struct In {
        uint8_t type{};
        uint32_t stream{};
        std::string payload;
    };
    std::optional<In> next(const std::chrono::milliseconds timeout = 5s) {
        std::unique_lock lock(mutex_);
        cv_.wait_for(lock, timeout, [this] { return !in_.empty() || closed_; });
        if (in_.empty()) return std::nullopt;
        auto m = std::move(in_.front());
        in_.pop_front();
        return m;
    }
    // The next CLOSE for `stream` (skipping other frames).
    std::optional<std::string> closeOf(const uint32_t stream, const std::chrono::milliseconds timeout = 5s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            const auto f = next(std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now()));
            if (!f) return std::nullopt;
            if (f->type == 0x13 && f->stream == stream) return f->payload;
        }
        return std::nullopt;
    }
    bool waitClosed(const std::chrono::milliseconds timeout = 5s) {
        std::unique_lock lock(mutex_);
        return cv_.wait_for(lock, timeout, [this] { return closed_; });
    }
    bool waitAdmitted(const std::chrono::milliseconds timeout = 10s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (!admitted && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(20ms);
        return admitted;
    }

    // OPEN a stream; with `fd`, its DATA and CREDIT are pumped to and from that socket (the browser's side).
    void open(const uint32_t stream, const std::string& ticket, const int fd = -1) {
        asio::post(io_, [this, stream, ticket, fd] {
            if (fd >= 0) {
                auto s = std::make_shared<asio::local::stream_protocol::socket>(io_);
                s->assign(asio::local::stream_protocol(), fd);
                pumps_[stream] = s;
                pumpRead(stream, s);
            }
            const auto body = json{{"ticket", ticket}, {"remote", "198.51.100.7"}}.dump();
            send(relay::encodeForTesting({.type = relay::FrameType::Open, .stream = stream,
                                          .payload = {body.begin(), body.end()}, .credit = 0}));
        });
    }
    void closeServer(const uint16_t code) {
        asio::post(io_, [this, code] {
            if (ws_) ws_->async_close(websocket::close_reason(static_cast<websocket::close_code>(code)), [](beast::error_code) {});
        });
    }

private:
    using Ws = websocket::stream<beast::tcp_stream>;

    void accept() {
        acceptor_.async_accept([this](const boost::system::error_code& ec, asio::ip::tcp::socket socket) {
            if (ec) return;
            {
                const std::scoped_lock lock(mutex_);
                closed_ = false;
                in_.clear();
            }
            admitted = false;
            state_ = 0;
            ws_ = std::make_unique<Ws>(std::move(socket));
            ws_->binary(true);
            ws_->read_message_max(relay::kMaxMessage);
            ws_->async_accept([this](const boost::system::error_code& e) {
                if (e) return;
                read();
            });
            accept();  // a reconnect replaces this one
        });
    }

    void read() {
        ws_->async_read(buffer_, [this](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                // The server's connection is gone: its streams end `offline` (the browsers' sockets close).
                for (auto& [_, pump] : pumps_) {
                    boost::system::error_code ignored;
                    pump->close(ignored);
                }
                pumps_.clear();
                const std::scoped_lock lock(mutex_);
                closed_ = true;
                cv_.notify_all();
                return;
            }
            const auto d = buffer_.cdata();
            const std::string m(static_cast<const char*>(d.data()), d.size());
            buffer_.clear();
            onMessage(m);
            if (ws_) read();
        });
    }

    void onMessage(const std::string& m) {
        const auto type = static_cast<uint8_t>(m[0]);
        if (state_ == 0 && type == 0x01) {
            jti_ = jtiOf(m.substr(1));
            randombytes_buf(challenge_.data(), challenge_.size());
            state_ = 1;
            return send(relay::control(relay::FrameType::Challenge, challenge_));
        }
        if (state_ == 1 && type == 0x03) {
            const auto msg = relay::connectMessage(jti_, challenge_);
            if (m.size() != 65 || crypto_sign_verify_detached(reinterpret_cast<const unsigned char*>(m.data() + 1),
                                                              reinterpret_cast<const unsigned char*>(msg.data()), msg.size(),
                                                              installationKey.data()) != 0) {
                ws_->async_close(websocket::close_reason(static_cast<websocket::close_code>(4001)), [](beast::error_code) {});
                return;
            }
            state_ = 2;
            admitted = true;
            return send(relay::control(relay::FrameType::Welcome,
                                       json{{"renew_by", now() + 600}, {"window", 262144}, {"max_data", 65536},
                                            {"streams_per_deployment", 16}}.dump()));
        }
        if (state_ == 2 && type == 0x05) {
            ++renewals;
            return send(relay::control(relay::FrameType::Renewed, json{{"renew_by", now() + 600}}.dump()));
        }
        In in{.type = type, .stream = 0, .payload = {}};
        if (type >= 0x10 && m.size() >= 5) {
            in.stream = static_cast<uint32_t>(static_cast<uint8_t>(m[1])) << 24 | static_cast<uint32_t>(static_cast<uint8_t>(m[2])) << 16 |
                        static_cast<uint32_t>(static_cast<uint8_t>(m[3])) << 8 | static_cast<uint32_t>(static_cast<uint8_t>(m[4]));
            in.payload = m.substr(5);
        }
        if (const auto it = pumps_.find(in.stream); it != pumps_.end()) {
            if (type == 0x11) {  // DATA toward the browser: write it, then credit it to the server
                auto buf = std::make_shared<std::string>(in.payload);
                asio::async_write(*it->second, asio::buffer(*buf), [this, buf, stream = in.stream](const boost::system::error_code& e, std::size_t n) {
                    if (!e) send(relay::credit(stream, static_cast<uint32_t>(n)));
                });
                return;
            }
            if (type == 0x12) return;  // the server consumed what the browser sent
            if (type == 0x13) {
                boost::system::error_code ignored;
                it->second->close(ignored);
                pumps_.erase(it);
            }
        }
        const std::scoped_lock lock(mutex_);
        in_.push_back(std::move(in));
        cv_.notify_all();
    }

    void pumpRead(const uint32_t stream, const std::shared_ptr<asio::local::stream_protocol::socket>& s) {
        auto buf = std::make_shared<std::array<uint8_t, 16384>>();
        s->async_read_some(asio::buffer(*buf), [this, stream, s, buf](const boost::system::error_code& ec, const std::size_t n) {
            if (ec) {
                if (pumps_.contains(stream)) {
                    pumps_.erase(stream);
                    send(relay::closeStream(stream, "done"));  // the browser closed: done
                }
                return;
            }
            send(relay::data(stream, std::span<const uint8_t>(buf->data(), n)));
            pumpRead(stream, s);
        });
    }

    void send(std::vector<uint8_t> frame) {
        out_.push_back(std::move(frame));
        if (out_.size() == 1) write();
    }
    void write() {
        if (!ws_) return;
        ws_->async_write(asio::buffer(out_.front()), [this](const boost::system::error_code& ec, std::size_t) {
            out_.pop_front();
            if (!ec && !out_.empty()) write();
        });
    }

    asio::io_context io_;
    std::optional<asio::executor_work_guard<asio::io_context::executor_type>> work_{asio::make_work_guard(io_)};
    asio::ip::tcp::acceptor acceptor_;
    uint16_t port_ = 0;
    std::unique_ptr<Ws> ws_;
    beast::flat_buffer buffer_;
    std::deque<std::vector<uint8_t>> out_;
    int state_ = 0;
    std::string jti_;
    std::array<uint8_t, 32> challenge_{};
    std::map<uint32_t, std::shared_ptr<asio::local::stream_protocol::socket>> pumps_;
    std::mutex mutex_;
    std::condition_variable cv_;
    std::deque<In> in_;
    bool closed_ = false;
    std::thread thread_;
};

// ---- the suite --------------------------------------------------------------------------------------------------------

class CloudRelayTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<asio::io_context> ioc;
    inline static std::vector<std::thread> threads;
    inline static std::shared_ptr<const vh::device::ServerIdentity> server;
    inline static std::shared_ptr<asio::ssl::context> relayedTls;
    inline static std::shared_ptr<protocols::ws::Router> router;
    inline static UserPtr owner;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("cloud_relay")) return;
        server = vh::device::ServerIdentity::generate();
        vh::device::setCurrentServerIdentity(server);
        relayedTls = protocols::device::makeRelayedServerContext(*server);
        ioc = std::make_shared<asio::io_context>();
        router = std::make_shared<protocols::ws::Router>();
        protocols::ws::Handler::registerAllHandlers(router);
        auto guard = std::make_shared<asio::executor_work_guard<asio::io_context::executor_type>>(asio::make_work_guard(*ioc));
        for (int i = 0; i < 2; ++i) threads.emplace_back([guard] { ioc->run(); });
        owner = test::identities::createUser("relay_owner_" + tag(), db::query::rbac::role::Admin::get("super_admin"),
                                             "relay_owner_" + tag() + "@vaulthalla.test");
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        protocols::device::closeAllDeviceListenerSessions();
        std::this_thread::sleep_for(100ms);
        ioc->stop();
        for (auto& t : threads) t.join();
        threads.clear();
        (void)runtime::Deps::releaseSessions();
        ioc.reset();
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        vh::device::Pairing::instance().resetForTesting();
    }

    // The relay service's acceptor: the stream on this suite's io_context.
    static bool accept(const int fd, protocols::device::RelayedOrigin origin) {
        asio::ip::tcp::socket socket(asio::make_strand(*ioc));
        boost::system::error_code ec;
        socket.assign(asio::ip::tcp::v4(), fd, ec);
        if (ec) return false;
        protocols::device::startRelayedConnection(std::move(socket), relayedTls, router, 64, std::move(origin));
        return true;
    }

    // A relayed stream straight into the listener (no relay): the browser's end, and what the listener called back.
    struct Direct {
        std::shared_ptr<std::string> refused = std::make_shared<std::string>();
        std::shared_ptr<std::atomic<bool>> proven = std::make_shared<std::atomic<bool>>(false);
        std::unique_ptr<Browser> browser;
    };
    static Direct direct(const BrowserKey& key, const std::string& jti, const std::string& spki) {
        Direct d;
        const auto [listenerEnd, browserEnd] = test::relay::socketPair();
        protocols::device::RelayedOrigin origin{.address = "198.51.100.7", .jti = jti, .spki_sha256 = spki,
                                                .key_id = "k3ymd00000000000000000000g",
                                                .refused = [r = d.refused](std::string_view why) { *r = std::string(why); },
                                                .proven = [p = d.proven] { *p = true; }};
        EXPECT_TRUE(accept(listenerEnd, std::move(origin)));
        d.browser = std::make_unique<Browser>(browserEnd, key, jti);
        return d;
    }
    static Direct direct(const BrowserKey& key) {
        const auto jti = randomJti();
        return direct(key, jti, key.spkiHex());
    }

    static std::shared_ptr<protocols::ws::Session> console(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    // Pairs `key` through a relayed stream; the devices row.
    static vh::device::Device pair(const BrowserKey& key, const UserPtr& user) {
        (void)handler::Devices::pairingOpen(console(user));
        auto d = direct(key);
        EXPECT_TRUE(d.browser->connect());
        const auto nonceDevice = crypto::randomNonce();
        const auto request = d.browser->call("device.pair.request",
                                             {{"name", "Chrome on a laptop"}, {"platform", "web"}, {"app_version", "1.0.0"},
                                              {"commitment", crypto::toHex(crypto::commitment(key.publicKey().spkiSha256, nonceDevice))}});
        EXPECT_TRUE(ok(request)) << (request ? request->dump() : "no reply");
        const auto requestId = request->at("data").at("request_id").get<std::string>();
        const auto nonceServer = *crypto::hashFromHex(request->at("data").at("nonce_server").get<std::string>());
        EXPECT_TRUE(ok(d.browser->call("device.pair.confirm", {{"request_id", requestId}, {"nonce_device", crypto::toHex(nonceDevice)}})));
        const auto pending = handler::Devices::pairingPending(console(user));
        EXPECT_EQ(pending.at("requests").at(0).at("via"), "relay") << "from the connection, not the platform it names";
        const auto sas = crypto::sasCode(crypto::sasDigest(d.browser->serverKey()->spkiSha256, key.publicKey().spkiSha256,
                                                           nonceDevice, nonceServer));
        const auto approved = handler::Devices::pairingApprove({{"request_id", requestId}, {"code", sas}}, console(user));
        (void)handler::Devices::pairingClose(json::object(), console(user));
        return *db::query::device::Devices::byId(approved.at("device").at("id").get<uint32_t>());
    }
};

// ---- relayed streams on the listener ----------------------------------------------------------------------------------

TEST_F(CloudRelayTest, AProvenKeyIsPairingOnlyUntilPairedAndTheServerShowsItsPin) {
    const BrowserKey key;
    auto d = direct(key);
    ASSERT_TRUE(d.browser->connect());
    ASSERT_TRUE(d.browser->serverKey());
    EXPECT_EQ(d.browser->serverKey()->spkiSha256, server->spkiSha256()) << "the same certificate and pin a Desktop sees";
    EXPECT_TRUE(ok(d.browser->call("meta.hello", {{"client", {{"name", "portal"}, {"version", "1.0.0"}}}})));
    EXPECT_EQ(code(d.browser->call("fs.list", {{"vault_id", 1}, {"path", "/"}})), "device_unknown");
    EXPECT_TRUE(*d.proven);
    EXPECT_TRUE(d.refused->empty());
}

TEST_F(CloudRelayTest, AKeyThatIsNotTheTicketsIsRefused) {
    const BrowserKey key, other;
    auto d = direct(key);
    ASSERT_TRUE(d.browser->handshake());
    ASSERT_TRUE(d.browser->prove(Proof{.key = &other}));
    EXPECT_TRUE(d.browser->closedByServer());
    EXPECT_EQ(*d.refused, "key_mismatch");
    EXPECT_FALSE(*d.proven);
}

TEST_F(CloudRelayTest, AProofFromAnotherTlsSessionOrReplayedIntoANewStreamIsRefused) {
    const BrowserKey key;
    const auto jti = randomJti();
    // Session A: the browser's real proof, recorded.
    auto a = direct(key, jti, key.spkiHex());
    ASSERT_TRUE(a.browser->handshake());
    const auto recorded = a.browser->proofRecord();
    // Session B, for the same ticket: the recorded proof replayed (another nonce, another exporter).
    auto b = direct(key, jti, key.spkiHex());
    ASSERT_TRUE(b.browser->handshake());
    ASSERT_TRUE(b.browser->prove(Proof{.record = recorded}));
    EXPECT_TRUE(b.browser->closedByServer());
    EXPECT_EQ(*b.refused, "bad_proof_signature");
    // Session C: signed over this nonce but another session's exporter (a relay forwarding a proof between sessions).
    auto c = direct(key, jti, key.spkiHex());
    ASSERT_TRUE(c.browser->handshake());
    ASSERT_TRUE(c.browser->prove(Proof{.exporter = a.browser->exporter()}));
    EXPECT_TRUE(c.browser->closedByServer());
    EXPECT_EQ(*c.refused, "bad_proof_signature");
    // A malformed record.
    auto e = direct(key, jti, key.spkiHex());
    ASSERT_TRUE(e.browser->handshake());
    ASSERT_TRUE(e.browser->prove(Proof{.record = std::vector<uint8_t>(relay::kProofRecordBytes, 0x01)}));
    EXPECT_TRUE(e.browser->closedByServer());
    EXPECT_EQ(*e.refused, "malformed_proof");
    // Session A still proves itself.
    ASSERT_TRUE(a.browser->prove() && a.browser->upgrade());
    EXPECT_TRUE(ok(a.browser->call("meta.hello", {{"client", {{"name", "portal"}, {"version", "1.0.0"}}}})));
}

// The portal's upgrade, written by its own small WebSocket client (which checks Sec-WebSocket-Accept): the answer
// carries RFC 6455's accept for the key, also when the proof and the request arrive together.
TEST_F(CloudRelayTest, AnUpgradeAsThePortalWritesItGetsTheAcceptOfItsOwnKey) {
    const BrowserKey key;
    auto d = direct(key);
    ASSERT_TRUE(d.browser->handshake() && d.browser->prove());
    const std::string wsKey = "dGhlIHNhbXBsZSBub25jZQ==";  // RFC 6455's own example: accept s3pPLMBiTxaQ9kYGzzhZRbK+xOo=
    const auto head = d.browser->rawUpgrade(wsKey);
    EXPECT_TRUE(head.starts_with("HTTP/1.1 101")) << head;
    EXPECT_NE(head.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), std::string::npos) << head;
    // The proof and the upgrade arriving together.
    auto e = direct(key);
    ASSERT_TRUE(e.browser->handshake());
    const auto together = e.browser->rawUpgrade(wsKey, true);
    EXPECT_NE(together.find("Sec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n"), std::string::npos) << together;
}

TEST_F(CloudRelayTest, ABrowserPairsThroughTheRelayAndIsHeldToTheReadOnlySet) {
    const BrowserKey key;
    const auto device = pair(key, owner);
    EXPECT_EQ(device.paired_via, "relay");
    EXPECT_EQ(device.platform, "web");

    auto d = direct(key);
    ASSERT_TRUE(d.browser->connect());
    const auto list = d.browser->call("device.list");
    ASSERT_TRUE(ok(list)) << (list ? list->dump() : "no reply");
    // Reading is allowed (the RBAC answer is the user's own); every change is refused, even for a super admin.
    EXPECT_NE(code(d.browser->call("storage.vault.list")), "relay_read_only");
    EXPECT_EQ(code(d.browser->call("fs.dir.create", {{"vault_id", 1}, {"path", "/x"}})), "relay_read_only");
    EXPECT_EQ(code(d.browser->call("device.pairing.open")), "relay_read_only");
    EXPECT_EQ(code(d.browser->call("vault.keys.export", {{"vault_id", 1}})), "relay_read_only");
    EXPECT_EQ(code(d.browser->call("cloud.relay.disable")), "relay_read_only");

    // The HTTP lanes: reading only, on the first request and every later one.
    {
        auto h = direct(key);
        ASSERT_TRUE(h.browser->handshake() && h.browser->prove());
        EXPECT_EQ(h.browser->httpStatus(beast::http::verb::post, "/upload/content?vault_id=1&path=/x"), 403u);
        EXPECT_NE(h.browser->lastBody().find("relay_read_only"), std::string::npos);
    }
    for (const auto* lane : {"/mcp", "/transfer/probe"}) {
        auto h = direct(key);
        ASSERT_TRUE(h.browser->handshake() && h.browser->prove());
        EXPECT_EQ(h.browser->httpStatus(beast::http::verb::get, lane), 403u) << lane;
    }
    {
        auto h = direct(key);
        ASSERT_TRUE(h.browser->handshake() && h.browser->prove());
        const auto status = h.browser->httpStatus(beast::http::verb::get, "/download/content?vault_id=999999&path=/nope");
        EXPECT_NE(status, 0u);
        EXPECT_EQ(h.browser->lastBody().find("relay_read_only"), std::string::npos) << "a download is a read";
    }

    // Revoked: the live session closes, and the key is pairing-only from then on.
    (void)ops::devices::revoke(owner, std::to_string(device.id));
    EXPECT_FALSE(ok(d.browser->call("device.list")));
    auto again = direct(key);
    ASSERT_TRUE(again.browser->connect());
    EXPECT_EQ(code(again.browser->call("device.list")), "device_unknown");
}

TEST_F(CloudRelayTest, ARelayedPairingRequestCarriesNoApprovalKey) {
    (void)handler::Devices::pairingOpen(console(owner));
    const BrowserKey key, approval;
    auto d = direct(key);
    ASSERT_TRUE(d.browser->connect());
    const auto request = d.browser->call(
        "device.pair.request",
        {{"name", "Browser"}, {"platform", "web"}, {"app_version", "1"},
         {"commitment", crypto::toHex(crypto::commitment(key.publicKey().spkiSha256, crypto::randomNonce()))},
         {"approval_key", crypto::toBase64(approval.publicKey().spkiDer)}});
    EXPECT_EQ(code(request), "invalid");
    (void)handler::Devices::pairingClose(json::object(), console(owner));
}

TEST_F(CloudRelayTest, TheNetworkListenerNeverAdmitsAPeerWithoutACertificate) {
    // Whatever the configuration, the network listener's context requires a client certificate: the browser's client
    // (no certificate, a proof after the handshake) can't get past TLS there.
    auto listener = std::make_shared<protocols::device::Listener>(*ioc, protocols::device::makeServerContext(*server), router, 8);
    listener->listen({asio::ip::make_address("127.0.0.1"), 0});
    const BrowserKey key;
    asio::io_context io;
    asio::ip::tcp::socket socket(io);
    socket.connect({asio::ip::make_address("127.0.0.1"), listener->localEndpoint().port()});
    Browser b(socket.release(), key, randomJti());
    EXPECT_FALSE(b.handshake()) << "no certificate, no TLS session";
    listener->close();
}

// ---- CloudRelayService against a fake relay and a fake cloud ------------------------------------------------------------

class CloudRelayServiceTest : public CloudRelayTest {
protected:
    TicketSigner signer;
    std::unique_ptr<FakeRelay> fake;
    std::string installationKey;  // base64url
    std::atomic<int> ticketCalls{0};
    std::atomic<long> ticketStatus{200};
    std::atomic<int64_t> renewAfterOffset{300};
    std::string previousEndpoint;

    void SetUp() override {
        CloudRelayTest::SetUp();
        if (IsSkipped()) return;
        fake = std::make_unique<FakeRelay>();
        previousEndpoint = config::Registry::get().cloud.endpoint;
        auto cfg = config::Registry::get();
        cfg.cloud.endpoint = "https://api.vaulthalla.test";
        cfg.device_server.enabled = true;
        config::Registry::set(cfg);
        db::query::cloud::Link::clear();
        cloud::identity::destroy();
        const auto seed = cloud::identity::create();
        const auto pub = cloud::publicKeyOf(seed.bytes());
        std::ranges::copy(pub, fake->installationKey.begin());
        installationKey = vl::keykit::base64UrlEncode(pub);
        db::query::cloud::LinkRow row{.endpoint = "https://api.vaulthalla.test", .status = "pending", .public_key = pub,
                                      .name = "test", .request_id = std::string("0123456789abcdefghjkmnpqrs"),
                                      .request_expires_at = 0, .installation_id = std::nullopt, .account_id = std::nullopt,
                                      .requested_by = "admin", .requested_at = 0, .linked_at = std::nullopt};
        ASSERT_TRUE(db::query::cloud::Link::putPending(row));
        ASSERT_TRUE(db::query::cloud::Link::markLinked("0123456789abcdefghjkmnpqrs", kInstallation, 7,
                                                       std::string(kDeployment), std::string(kAccount)));
        http::setTransportForTesting([this](const http::Request& r) {
            http::Response res;
            if (r.method != "POST" || !r.url.ends_with("/v1/relay/server-tickets") ||
                r.headers.empty()) {
                res.status = 404;
                return res;
            }
            ++ticketCalls;
            res.status = ticketStatus.load();
            if (res.status != 200) {
                res.body = json{{"error", {{"code", res.status == 403 ? "relay_disabled" : "unauthorized"}, {"message", "no"}}}}.dump();
                return res;
            }
            const auto t = now();
            res.body = json{{"ticket", signer.server(installationKey, t)},
                            {"relay_url", "ws://127.0.0.1:" + std::to_string(fake->port())},
                            {"audience", kAudience}, {"deployment_id", kDeployment}, {"expires_at", t + 60},
                            {"renew_after", t + renewAfterOffset.load()}, {"renew_by", t + 600},
                            {"ticket_public_keys", json::array({signer.publicKey()})}}.dump();
            return res;
        });
    }
    void TearDown() override {
        if (!IsSkipped()) {
            fake.reset();
            http::setTransportForTesting(std::nullopt);
            (void)db::query::cloud::RelaySwitch::disable();
            db::query::cloud::Link::clear();
            cloud::identity::destroy();
            auto cfg = config::Registry::get();
            cfg.cloud.endpoint = previousEndpoint;
            config::Registry::set(cfg);
        }
        CloudRelayTest::TearDown();
    }

    std::unique_ptr<cloud::RelayService> startService() {
        auto s = std::make_unique<cloud::RelayService>();
        s->setAcceptorForTesting([](const int fd, protocols::device::RelayedOrigin origin) { return accept(fd, std::move(origin)); });
        s->start();
        return s;
    }

    static bool waitFor(const std::function<bool()>& f, const std::chrono::milliseconds timeout = 10s) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            if (f()) return true;
            std::this_thread::sleep_for(25ms);
        }
        return f();
    }
};

TEST_F(CloudRelayServiceTest, NothingRunsUntilTheSwitchIsOnThenItConnectsAndCarriesAStream) {
    auto service = startService();
    std::this_thread::sleep_for(600ms);
    EXPECT_EQ(ticketCalls.load(), 0) << "off by default: nobody is contacted";
    EXPECT_EQ(service->snapshot().state, "off");

    const auto enabled = ops::cloud_relay::enable(owner, ops::cloud_relay::Channel::Cli);
    EXPECT_TRUE(enabled.enabled);
    ASSERT_TRUE(fake->waitAdmitted()) << "TICKET, CHALLENGE, PROOF by the installation key, WELCOME";
    ASSERT_TRUE(waitFor([&] { return service->snapshot().state == "connected"; }));
    EXPECT_TRUE(service->snapshot().connected_since);

    // A browser stream through the relay's frames: TLS, the proof, /ws.
    const BrowserKey key;
    const auto ticket = signer.browser(key.spkiHex());
    const auto [relayEnd, browserEnd] = test::relay::socketPair();
    fake->open(1, ticket, relayEnd);
    Browser browser(browserEnd, key, jtiOf(ticket));
    ASSERT_TRUE(browser.connect());
    EXPECT_TRUE(ok(browser.call("meta.hello", {{"client", {{"name", "portal"}, {"version", "1.0.0"}}}})));
    EXPECT_EQ(code(browser.call("fs.list", {{"vault_id", 1}, {"path", "/"}})), "device_unknown");
    EXPECT_TRUE(waitFor([&] { return service->snapshot().streams == 1; }));

    // Refused OPENs, each with CLOSE refused: another server's ticket, an expired one, an unknown ticket key, a replay.
    fake->open(2, signer.browser(key.spkiHex(), now(), "an0therdep10yment000000000"));
    EXPECT_EQ(fake->closeOf(2), "refused");
    fake->open(3, signer.browser(key.spkiHex(), now() - 600));
    EXPECT_EQ(fake->closeOf(3), "refused");
    fake->open(4, TicketSigner{}.browser(key.spkiHex()));
    EXPECT_EQ(fake->closeOf(4), "refused");
    fake->open(5, ticket);
    EXPECT_EQ(fake->closeOf(5), "refused") << "the jti was spent by stream 1";
    EXPECT_GE(service->snapshot().streams_refused, 4u);

    // Switched off: the connection and the relayed session end at once.
    const auto off = ops::cloud_relay::disable(owner, ops::cloud_relay::Channel::Cli);
    EXPECT_EQ(off.state, "off");
    EXPECT_TRUE(fake->waitClosed());
    EXPECT_FALSE(ok(browser.call("meta.hello", {{"client", {{"name", "portal"}, {"version", "1.0.0"}}}})));
    service->stop();
}

TEST_F(CloudRelayServiceTest, ItRenewsAtTheMidpointAndAnUnknownInstallationStopsIt) {
    renewAfterOffset = 0;  // renew at once
    db::query::cloud::RelaySwitch::enable(kInstallation, "test");
    auto service = startService();
    ASSERT_TRUE(fake->waitAdmitted());
    ASSERT_TRUE(waitFor([&] { return fake->renewals.load() >= 1; })) << "RENEW with a fresh ticket";
    EXPECT_GE(ticketCalls.load(), 2);

    // The relay drops the connection: the service reconnects with a fresh ticket.
    renewAfterOffset = 300;
    fake->closeServer(4009);
    ASSERT_TRUE(waitFor([&] { return fake->admitted.load() == false || service->snapshot().state == "backoff"; }));
    ASSERT_TRUE(fake->waitAdmitted(15s)) << "reconnected after backoff";

    // The cloud no longer knows this installation: stopped, until the switch is toggled.
    ticketStatus = 401;
    fake->closeServer(4001);
    ASSERT_TRUE(waitFor([&] { return service->snapshot().state == "stopped"; }, 15s)) << service->snapshot().state;
    const auto calls = ticketCalls.load();
    std::this_thread::sleep_for(1500ms);
    EXPECT_EQ(ticketCalls.load(), calls) << "a stopped service asks nothing";
    EXPECT_TRUE(service->snapshot().last_error);

    // Off at the cloud: waiting, retried later (not stopped).
    ticketStatus = 403;
    (void)ops::cloud_relay::disable(owner, ops::cloud_relay::Channel::Cli);
    (void)ops::cloud_relay::enable(owner, ops::cloud_relay::Channel::Cli);
    ASSERT_TRUE(waitFor([&] { return service->snapshot().state == "waiting"; }));
    service->stop();
}

// ---- against the cloud's real relay binary (VH_TEST_CLOUD_RELAY_BINARY: vaulthalla-cloud-relay, built from
// valkyrianlabs/vaulthalla-cloud) ----------------------------------------------------------------------------------------

// The browser's end at the relay: wss /v1/browser, TICKET, WELCOME, then DATA and CREDIT (no stream id) pumped to and
// from a socketpair the test's Browser speaks TLS on; the stream's end is the WebSocket close code.
class RelayBrowserSocket {
public:
    RelayBrowserSocket(const uint16_t port, const std::string& ticket, const int fd) : ws_(io_), pump_(io_) {
        pump_.assign(asio::local::stream_protocol(), fd);
        beast::get_lowest_layer(ws_).connect({asio::ip::make_address("127.0.0.1"), port});
        ws_.set_option(websocket::stream_base::decorator(
            [](websocket::request_type& req) { req.set(beast::http::field::origin, "https://app.vaulthalla.test"); }));
        ws_.read_message_max(relay::kMaxMessage);
        ws_.handshake("127.0.0.1", "/v1/browser");
        ws_.binary(true);
        send(relay::control(relay::FrameType::Ticket, ticket));
        read();
        thread_ = std::thread([this] { io_.run(); });
    }
    ~RelayBrowserSocket() {
        asio::post(io_, [this] {
            boost::system::error_code ignored;
            beast::get_lowest_layer(ws_).socket().close(ignored);
            pump_.close(ignored);
            work_.reset();
        });
        thread_.join();
    }
    std::optional<uint16_t> closedWith(const std::chrono::milliseconds timeout = 10s) {
        std::unique_lock lock(mutex_);
        if (!cv_.wait_for(lock, timeout, [this] { return closed_; })) return std::nullopt;
        return code_;
    }
    std::atomic<bool> welcomed{false};

private:
    void read() {
        ws_.async_read(buffer_, [this](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                const std::scoped_lock lock(mutex_);
                closed_ = true;
                code_ = static_cast<uint16_t>(ws_.reason().code);
                boost::system::error_code ignored;
                pump_.close(ignored);
                cv_.notify_all();
                return;
            }
            const auto d = buffer_.cdata();
            const std::string m(static_cast<const char*>(d.data()), d.size());
            buffer_.clear();
            if (!m.empty() && static_cast<uint8_t>(m[0]) == 0x04 && !welcomed.exchange(true)) pumpRead();
            if (!m.empty() && static_cast<uint8_t>(m[0]) == 0x11) {
                auto buf = std::make_shared<std::string>(m.substr(1));
                asio::async_write(pump_, asio::buffer(*buf), [this, buf](const boost::system::error_code& e, std::size_t n) {
                    if (e) return;
                    std::vector<uint8_t> credit{0x12, static_cast<uint8_t>(n >> 24), static_cast<uint8_t>(n >> 16),
                                                static_cast<uint8_t>(n >> 8), static_cast<uint8_t>(n)};
                    send(std::move(credit));
                });
            }
            read();
        });
    }
    void pumpRead() {
        pump_.async_read_some(asio::buffer(chunk_), [this](const boost::system::error_code& ec, const std::size_t n) {
            if (ec) return ws_.async_close(websocket::close_code::normal, [](beast::error_code) {});
            std::vector<uint8_t> frame{0x11};
            frame.insert(frame.end(), chunk_.begin(), chunk_.begin() + static_cast<std::ptrdiff_t>(n));
            send(std::move(frame));
            pumpRead();
        });
    }
    void send(std::vector<uint8_t> m) {
        asio::post(io_, [this, m = std::move(m)]() mutable {
            out_.push_back(std::move(m));
            if (out_.size() == 1) write();
        });
    }
    void write() {
        ws_.async_write(asio::buffer(out_.front()), [this](const boost::system::error_code& ec, std::size_t) {
            out_.pop_front();
            if (!ec && !out_.empty()) write();
        });
    }

    asio::io_context io_;
    std::optional<asio::executor_work_guard<asio::io_context::executor_type>> work_{asio::make_work_guard(io_)};
    websocket::stream<beast::tcp_stream> ws_;
    asio::local::stream_protocol::socket pump_;
    beast::flat_buffer buffer_;
    std::array<uint8_t, 16384> chunk_{};
    std::deque<std::vector<uint8_t>> out_;
    std::mutex mutex_;
    std::condition_variable cv_;
    bool closed_ = false;
    uint16_t code_ = 0;
    std::thread thread_;
};

uint16_t freePort() {
    asio::io_context io;
    asio::ip::tcp::acceptor a(io, {asio::ip::make_address("127.0.0.1"), 0});
    return a.local_endpoint().port();
}

std::string utcToday() {
    const auto t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char out[16];
    std::strftime(out, sizeof out, "%Y-%m-%d", &tm);
    return out;
}

TEST_F(CloudRelayServiceTest, AgainstTheRealRelay) {
    const char* binary = std::getenv("VH_TEST_CLOUD_RELAY_BINARY");
    if (!binary || !*binary) GTEST_SKIP() << "VH_TEST_CLOUD_RELAY_BINARY is not set (the cloud's vaulthalla-cloud-relay)";
    const auto port = freePort();
    const auto dir = std::filesystem::temp_directory_path() / ("vh-relay-" + tag());
    std::filesystem::create_directories(dir);
    const auto config = dir / "relay.yaml";
    std::ofstream(config) << "listen:\n  bind: 127.0.0.1\n  port: " << port
                          << "\ntrust_forwarded_for: false\nid: " << kAudience << "\nticket_public_keys: [" << signer.publicKey()
                          << "]\nbrowser_origins: [https://app.vaulthalla.test]\nlog_level: warn\n";
    const std::string configPath = config.string();
    char* argv[] = {const_cast<char*>(binary), const_cast<char*>(configPath.c_str()), nullptr};
    pid_t pid = 0;
    ASSERT_EQ(posix_spawn(&pid, binary, nullptr, nullptr, argv, environ), 0);
    struct Reap {
        pid_t pid;
        std::filesystem::path dir;
        ~Reap() {
            ::kill(pid, SIGTERM);
            int status = 0;
            ::waitpid(pid, &status, 0);
            std::error_code ec;
            std::filesystem::remove_all(dir, ec);
        }
    } reap{pid, dir};
    ASSERT_TRUE(waitFor([&] {
        asio::io_context io;
        asio::ip::tcp::socket s(io);
        boost::system::error_code ec;
        s.connect({asio::ip::make_address("127.0.0.1"), port}, ec);
        return !ec;
    })) << "the relay listens";

    // The service's ticket names the real relay.
    http::setTransportForTesting([this, port](const http::Request& r) {
        http::Response res;
        ++ticketCalls;
        const auto t = now();
        res.status = 200;
        res.body = json{{"ticket", signer.server(installationKey, t)}, {"relay_url", "ws://127.0.0.1:" + std::to_string(port)},
                        {"audience", kAudience}, {"deployment_id", kDeployment}, {"expires_at", t + 60},
                        {"renew_after", t + 300}, {"renew_by", t + 600},
                        {"ticket_public_keys", json::array({signer.publicKey()})}}.dump();
        (void)r;
        return res;
    });
    db::query::cloud::RelaySwitch::enable(kInstallation, "test");
    auto service = startService();
    ASSERT_TRUE(waitFor([&] { return service->snapshot().state == "connected"; }, 15s)) << service->snapshot().state << ": "
                                                                                         << service->snapshot().last_error.value_or("");

    const auto lim = [&](const std::string& spki) {
        const auto at = now();
        return signer.sign({{"typ", "browser"}, {"aud", kAudience}, {"acct", kAccount}, {"dep", kDeployment}, {"iat", at},
                            {"exp", at + 60}, {"jti", randomJti()}, {"renew", 600}, {"kid", "k3ymd00000000000000000000g"},
                            {"spki", spki},
                            {"lim", {{"stream_bytes", 1LL << 31}, {"day_bytes", 1LL << 33}, {"day_used", 0}, {"day", utcToday()}}}});
    };

    // A browser stream end to end: relay, the server's re-check, TLS with the pin, the proof, /ws.
    const BrowserKey key;
    {
        const auto ticket = lim(key.spkiHex());
        const auto [pumpEnd, browserEnd] = test::relay::socketPair();
        RelayBrowserSocket socket(port, ticket, pumpEnd);
        Browser browser(browserEnd, key, jtiOf(ticket));
        ASSERT_TRUE(browser.connect());
        EXPECT_EQ(browser.serverKey()->spkiSha256, server->spkiSha256());
        EXPECT_TRUE(ok(browser.call("meta.hello", {{"client", {{"name", "portal"}, {"version", "1.0.0"}}}})));
        EXPECT_EQ(code(browser.call("fs.list", {{"vault_id", 1}, {"path", "/"}})), "device_unknown");
    }
    // A proof by another key than the ticket's: the server refuses the stream, the relay closes it 4007 refused.
    {
        const BrowserKey other;
        const auto ticket = lim(key.spkiHex());
        const auto [pumpEnd, browserEnd] = test::relay::socketPair();
        RelayBrowserSocket socket(port, ticket, pumpEnd);
        Browser browser(browserEnd, other, jtiOf(ticket));
        ASSERT_TRUE(browser.handshake());
        ASSERT_TRUE(browser.prove());
        EXPECT_EQ(socket.closedWith(), 4007);
    }
    EXPECT_GE(service->snapshot().streams_refused, 1u);
    EXPECT_GE(service->snapshot().streams_accepted, 2u);
    service->stop();
}

TEST_F(CloudRelayServiceTest, SwitchingItOnFromTheConsoleIsAStepUp) {
    // A request in scope (here a paired Desktop's session, with no approval key or grant) is refused the device.trust
    // step-up, like remote device connections; the daemon's own callers (no scope) are not asked.
    auto peer = std::make_shared<vh::device::Peer>();
    peer->spki.fill(0x5c);
    peer->spkiHex = crypto::toHex(peer->spki);
    peer->address = "127.0.0.1";
    peer->deviceRowId = 1;
    const auto s = protocols::ws::Session::devicePrincipal(std::move(peer), owner, [] {});
    {
        const auth::stepup::Scope scope(s);
        try {
            (void)ops::cloud_relay::enable(owner, ops::cloud_relay::Channel::Web);
            ADD_FAILURE() << "enabled without a step-up";
        } catch (const ops::Refused& e) {
            EXPECT_TRUE(e.code == "step_up_required" || e.code == "console_approval_required") << e.code;
        }
    }
    EXPECT_FALSE(db::query::cloud::RelaySwitch::get());
    s->close();
    (void)runtime::Deps::releaseSessions();
}

TEST_F(CloudRelayServiceTest, OnlyASuperAdminSwitchesItAndNeverAnAgent) {
    const auto plain = test::identities::createUser("relay_plain_" + tag(), db::query::rbac::role::Admin::get("unprivileged"),
                                                    "relay_plain_" + tag() + "@vaulthalla.test");
    EXPECT_THROW((void)ops::cloud_relay::enable(plain, ops::cloud_relay::Channel::Cli), ops::Denied);
    EXPECT_THROW((void)ops::cloud_relay::status(plain), ops::Denied);
    EXPECT_THROW((void)ops::cloud_relay::enable(owner, ops::cloud_relay::Channel::Agent), ops::Denied);
    EXPECT_EQ(ops::cloud_relay::status(owner).state, "off");
    db::query::cloud::Link::clear();
    EXPECT_THROW((void)ops::cloud_relay::enable(owner, ops::cloud_relay::Channel::Cli), ops::Conflict);
}

}
