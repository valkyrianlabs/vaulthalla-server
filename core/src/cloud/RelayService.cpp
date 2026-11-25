#include "cloud/RelayService.hpp"

#include "audit/Trail.hpp"
#include "cloud/Client.hpp"
#include "cloud/RelayProtocol.hpp"
#include "cloud/Signing.hpp"
#include "cloud/Storage.hpp"
#include "concurrency/Backoff.hpp"
#include "config/Registry.hpp"
#include "db/query/cloud/Link.hpp"
#include "db/query/cloud/Relay.hpp"
#include "log/Registry.hpp"
#include "protocols/device/Service.hpp"
#include "runtime/Manager.hpp"
#include "storage/s3/curl/Http.hpp"

#include <boost/asio/connect.hpp>
#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/local/stream_protocol.hpp>
#include <boost/asio/post.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/steady_timer.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <nlohmann/json.hpp>
#include <sodium.h>
#include <vl/keykit/base64url.hpp>

#include <fcntl.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <ctime>
#include <deque>
#include <map>
#include <mutex>
#include <thread>
#include <variant>

namespace vh::cloud {

// Named, not anonymous: RelayService::Impl derives from Engine (GCC -Wsubobject-linkage), and the unity build joins
// this file with others of vh::cloud.
namespace relay_detail {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;
using local = asio::local::stream_protocol;
using json = nlohmann::json;
using Clock = std::chrono::steady_clock;

constexpr auto kLook = std::chrono::milliseconds(250);
constexpr auto kDesiredEvery = std::chrono::seconds(10);
constexpr auto kWaitingRetry = std::chrono::minutes(5);
constexpr auto kBackoffCap = std::chrono::minutes(5);
constexpr auto kRenewRetry = std::chrono::seconds(30);
constexpr auto kAdmissionDeadline = std::chrono::seconds(15);
constexpr auto kHealthyAfter = std::chrono::seconds(60);
constexpr std::size_t kMaxStreams = 64;
constexpr unsigned kAuditsPerMinute = 20;

int64_t unixNow() { return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count(); }

// Where the relay is: wss://host[:port], or ws:// to a loopback host (development and tests), no path.
struct Target {
    bool tls = true;
    std::string host;
    std::string port;
};

std::optional<Target> targetOf(const std::string& url) {
    Target t;
    std::string rest;
    if (url.starts_with("wss://")) rest = url.substr(6);
    else if (url.starts_with("ws://")) {
        t.tls = false;
        rest = url.substr(5);
    } else return std::nullopt;
    if (rest.ends_with("/")) rest.pop_back();
    if (rest.empty() || rest.find_first_of("/?#@ ") != std::string::npos) return std::nullopt;
    std::string host = rest, port = t.tls ? "443" : "80";
    if (rest.front() == '[') {
        const auto close = rest.find(']');
        if (close == std::string::npos) return std::nullopt;
        host = rest.substr(1, close - 1);
        if (close + 1 < rest.size()) {
            if (rest[close + 1] != ':') return std::nullopt;
            port = rest.substr(close + 2);
        }
    } else if (const auto colon = rest.rfind(':'); colon != std::string::npos) {
        host = rest.substr(0, colon);
        port = rest.substr(colon + 1);
    }
    if (host.empty() || port.empty() || port.size() > 5 || !std::ranges::all_of(port, [](const char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    std::ranges::transform(host, host.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (!t.tls) {
        boost::system::error_code ec;
        const auto a = asio::ip::make_address(host, ec);
        if (host != "localhost" && (ec || !a.is_loopback())) return std::nullopt;
    }
    t.host = std::move(host);
    t.port = std::move(port);
    return t;
}

// The answer to POST /v1/relay/server-tickets, checked.
struct Admission {
    std::string ticket, jti, relay_url, audience;
    Target target;
    std::vector<relay::TicketKey> keys;
    int64_t renew_after = 0, renew_by = 0;
};

// Why a ticket fetch failed, and what to do about it.
struct TicketFailure {
    enum class Kind { Retry, Waiting, Stopped } kind = Kind::Retry;
    std::string message;
    std::chrono::seconds floor{0};
};

// ---- the shared state between the service thread and the I/O thread ------------------------------------------------

struct Shared {
    mutable std::mutex mutex;
    enum class Phase { Idle, Connecting, Admitted, Ended } phase = Phase::Idle;
    std::optional<relay::Reason> endedWith;
    std::string endedDetail;
    std::optional<int64_t> admittedAt;
    std::optional<int64_t> renewBy;
    unsigned streams = 0;
    uint64_t accepted = 0, refused = 0;
    // Refusal audits this minute (a relay can send any number of bad OPENs).
    int64_t auditMinute = 0;
    unsigned audits = 0, auditsDropped = 0;
};

// The stream's view of the link it belongs to (what a Stream calls back on, on the I/O thread).
class Link;

class Stream : public std::enable_shared_from_this<Stream> {
public:
    Stream(asio::io_context& ioc, const uint32_t id, const uint32_t window, std::weak_ptr<Link> link)
        : id_(id), window_(window), sendCredit_(window), socket_(ioc), link_(std::move(link)) {}

    local::socket& socket() { return socket_; }
    [[nodiscard]] uint32_t id() const { return id_; }

    std::string spki;   // the ticket's, for the failure limiter
    std::string keyId;  // the ticket's kid, for logs and the audit
    std::string remote;
    bool proven = false;
    bool refusedByListener = false;

    void startReading();
    // DATA from the relay; false when it overruns the window (the caller ends the stream `protocol`).
    bool fromRelay(std::vector<uint8_t> bytes);
    // CREDIT from the relay; false when it exceeds what is outstanding.
    bool credited(uint32_t n);
    // The stream is over (the relay closed it, or we did): drop the socket.
    void end() {
        if (ended_) return;
        ended_ = true;
        boost::system::error_code ignored;
        socket_.shutdown(local::socket::shutdown_both, ignored);
        socket_.close(ignored);
    }
    [[nodiscard]] bool ended() const { return ended_; }

private:
    void write();
    void onSocketEnded();

    uint32_t id_;
    uint32_t window_;
    uint64_t sendCredit_;       // bytes we may still send toward the browser
    uint64_t unconsumed_ = 0;   // bytes the relay sent that are not yet written to the socket and credited
    local::socket socket_;
    std::weak_ptr<Link> link_;
    std::deque<std::vector<uint8_t>> toSocket_;
    bool writing_ = false, reading_ = false, ended_ = false;
    std::array<uint8_t, relay::kMaxData> readBuffer_{};
};

// One connection to the relay: admission, then the streams on it. Every member runs on the I/O thread.
class Link : public std::enable_shared_from_this<Link> {
public:
    struct Params {
        Admission admission;
        std::string account, deployment;
        vl::keykit::SecretBytes seed;
        RelayService::Acceptor acceptor;
    };

    Link(std::shared_ptr<asio::io_context> ioc, Params params, std::shared_ptr<Shared> shared,
         std::shared_ptr<relay::JtiLedger> jtis, std::shared_ptr<relay::FailureLimiter> failures)
        : ioc_(std::move(ioc)), p_(std::move(params)), shared_(std::move(shared)), jtis_(std::move(jtis)),
          failures_(std::move(failures)), resolver_(*ioc_), deadline_(*ioc_) {}

    void start();
    void renew(std::string ticket, std::vector<relay::TicketKey> keys);
    void shutdown(relay::Reason why);

    // From a Stream.
    void send(std::vector<uint8_t> frame);
    void streamEnded(uint32_t id, relay::Reason reason);
    void listenerRefused(const std::shared_ptr<Stream>& s, std::string why);

private:
    using PlainWs = websocket::stream<beast::tcp_stream>;
    using TlsWs = websocket::stream<beast::ssl_stream<beast::tcp_stream>>;

    template <class F> void withWs(F&& f) {
        std::visit([&](auto& ws) { if (ws) f(*ws); }, ws_);
    }

    void onResolved(const tcp::resolver::results_type& results);
    void onConnected();
    void onUpgraded();
    void read();
    void onMessage(std::span<const uint8_t> m);
    void onOpen(const relay::Frame& f);
    // CLOSE refused, audited. `countAgainst`: a failure for the limiter (a browser key hash, or "" for one that counts
    // in the total only); nullopt for a refusal that is ours (no socketpair, listener off) or the limiter's own.
    void refuse(uint32_t stream, const std::string& why, const std::string& keyId, const std::string& remote,
                const std::optional<std::string>& countAgainst);
    void write();
    void end(std::optional<relay::Reason> reason, const std::string& detail);
    void audit(const std::string& why, const std::string& keyId, const std::string& remote);

    enum class State { Connecting, Challenge, Welcome, Admitted, Ended };

    std::shared_ptr<asio::io_context> ioc_;
    Params p_;
    std::shared_ptr<Shared> shared_;
    std::shared_ptr<relay::JtiLedger> jtis_;
    std::shared_ptr<relay::FailureLimiter> failures_;
    tcp::resolver resolver_;
    asio::steady_timer deadline_;
    std::shared_ptr<ssl::context> tls_;
    std::variant<std::unique_ptr<PlainWs>, std::unique_ptr<TlsWs>> ws_;
    beast::flat_buffer buffer_;
    std::deque<std::vector<uint8_t>> out_;
    bool writing_ = false;
    State state_ = State::Connecting;
    uint32_t window_ = 262144;
    std::map<uint32_t, std::shared_ptr<Stream>> streams_;
    bool renewing_ = false;
};

// ---- Stream -----------------------------------------------------------------------------------------------------------

void Stream::startReading() {
    if (ended_ || reading_ || sendCredit_ == 0) return;
    reading_ = true;
    const auto n = static_cast<std::size_t>(std::min<uint64_t>(relay::kMaxData, sendCredit_));
    socket_.async_read_some(asio::buffer(readBuffer_.data(), n),
                            [self = shared_from_this()](const boost::system::error_code& ec, const std::size_t got) {
                                self->reading_ = false;
                                if (self->ended_) return;
                                if (ec || got == 0) return self->onSocketEnded();
                                const auto link = self->link_.lock();
                                if (!link) return self->end();
                                self->sendCredit_ -= got;
                                link->send(relay::data(self->id_, std::span<const uint8_t>(self->readBuffer_.data(), got)));
                                self->startReading();
                            });
}

bool Stream::fromRelay(std::vector<uint8_t> bytes) {
    if (ended_) return true;  // a stream that just ended: its CLOSE is on the way
    if (unconsumed_ + bytes.size() > window_) return false;
    unconsumed_ += bytes.size();
    toSocket_.push_back(std::move(bytes));
    if (!writing_) write();
    return true;
}

bool Stream::credited(const uint32_t n) {
    if (ended_) return true;
    if (sendCredit_ + n > window_) return false;
    sendCredit_ += n;
    startReading();
    return true;
}

void Stream::write() {
    if (ended_ || toSocket_.empty()) {
        writing_ = false;
        return;
    }
    writing_ = true;
    asio::async_write(socket_, asio::buffer(toSocket_.front()),
                      [self = shared_from_this()](const boost::system::error_code& ec, const std::size_t n) {
                          if (self->ended_) return;
                          if (ec) return self->onSocketEnded();
                          self->toSocket_.pop_front();
                          self->unconsumed_ -= n;
                          // The listener took the bytes: the browser may send that much more.
                          if (const auto link = self->link_.lock())
                              link->send(relay::credit(self->id_, static_cast<uint32_t>(n)));
                          self->write();
                      });
}

void Stream::onSocketEnded() {
    if (ended_) return;
    const auto link = link_.lock();
    // Ended before its proof passed: the listener refused it (it calls back with why, which audits it).
    const auto reason = proven ? relay::Reason::Done : relay::Reason::Refused;
    end();
    if (link) link->streamEnded(id_, reason);
}

// ---- Link -------------------------------------------------------------------------------------------------------------

void Link::start() {
    {
        const std::scoped_lock lock(shared_->mutex);
        shared_->phase = Shared::Phase::Connecting;
    }
    deadline_.expires_after(kAdmissionDeadline);
    deadline_.async_wait([weak = weak_from_this()](const boost::system::error_code& ec) {
        if (ec) return;
        if (const auto self = weak.lock(); self && self->state_ != State::Admitted && self->state_ != State::Ended)
            self->end(std::nullopt, "the relay didn't admit this server in time");
    });
    if (p_.admission.target.tls) {
        tls_ = std::make_shared<ssl::context>(ssl::context::tls_client);
        tls_->set_default_verify_paths();
        tls_->set_verify_mode(ssl::verify_peer);
        SSL_CTX_set_min_proto_version(tls_->native_handle(), TLS1_2_VERSION);
        ws_ = std::make_unique<TlsWs>(*ioc_, *tls_);
    } else {
        ws_ = std::make_unique<PlainWs>(*ioc_);
    }
    resolver_.async_resolve(p_.admission.target.host, p_.admission.target.port,
                            [self = shared_from_this()](const boost::system::error_code& ec,
                                                        const tcp::resolver::results_type& results) {
                                if (self->state_ == State::Ended) return;
                                if (ec) return self->end(std::nullopt, "cannot resolve the relay: " + ec.message());
                                self->onResolved(results);
                            });
}

void Link::onResolved(const tcp::resolver::results_type& results) {
    withWs([&](auto& ws) {
        beast::get_lowest_layer(ws).expires_after(kAdmissionDeadline);
        beast::get_lowest_layer(ws).async_connect(
            results, [self = shared_from_this()](const boost::system::error_code& ec, const tcp::endpoint&) {
                if (self->state_ == State::Ended) return;
                if (ec) return self->end(std::nullopt, "cannot connect to the relay: " + ec.message());
                self->onConnected();
            });
    });
}

void Link::onConnected() {
    auto upgrade = [self = shared_from_this()](auto& ws) {
        beast::get_lowest_layer(ws).expires_never();
        websocket::stream_base::timeout t{};
        t.handshake_timeout = std::chrono::seconds(15);
        t.idle_timeout = std::chrono::seconds(40);  // a ping after 20 s of silence; dropped after 40
        t.keep_alive_pings = true;
        ws.set_option(t);
        ws.set_option(websocket::stream_base::decorator(
            [](websocket::request_type& req) { req.set(beast::http::field::user_agent, "vaulthalla-server"); }));
        ws.read_message_max(relay::kMaxMessage);
        ws.binary(true);
        ws.async_handshake(self->p_.admission.target.host, "/v1/server", [self](const boost::system::error_code& ec) {
            if (self->state_ == State::Ended) return;
            if (ec) return self->end(std::nullopt, "WebSocket upgrade refused: " + ec.message());
            self->onUpgraded();
        });
    };
    if (auto* tlsWs = std::get_if<std::unique_ptr<TlsWs>>(&ws_); tlsWs && *tlsWs) {
        auto& ws = **tlsWs;
        auto& stream = ws.next_layer();
        if (!SSL_set_tlsext_host_name(stream.native_handle(), p_.admission.target.host.c_str()))
            return end(std::nullopt, "cannot set the relay's server name");
        stream.set_verify_callback(ssl::host_name_verification(p_.admission.target.host));
        beast::get_lowest_layer(ws).expires_after(kAdmissionDeadline);
        stream.async_handshake(ssl::stream_base::client, [self = shared_from_this(), upgrade](const boost::system::error_code& ec) {
            if (self->state_ == State::Ended) return;
            if (ec) return self->end(std::nullopt, "TLS to the relay failed: " + ec.message());
            upgrade(**std::get_if<std::unique_ptr<TlsWs>>(&self->ws_));
        });
        return;
    }
    upgrade(*std::get<std::unique_ptr<PlainWs>>(ws_));
}

void Link::onUpgraded() {
    state_ = State::Challenge;
    send(relay::control(relay::FrameType::Ticket, p_.admission.ticket));
    read();
}

void Link::read() {
    withWs([&](auto& ws) {
        ws.async_read(buffer_, [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
            if (self->state_ == State::Ended) return;
            if (ec) {
                std::optional<relay::Reason> reason;
                std::string detail = ec.message();
                self->withWs([&](auto& w) {
                    if (const auto code = w.reason().code; code != 0) {
                        reason = relay::reasonOfCode(static_cast<uint16_t>(code));
                        detail = "the relay closed the connection (" + std::to_string(code) +
                                 (reason ? " " + std::string(relay::toString(*reason)) : std::string()) + ")";
                    }
                });
                return self->end(reason, detail);
            }
            bool text = false;
            self->withWs([&](auto& w) { text = w.got_text(); });
            if (text) return self->end(relay::Reason::Protocol, "the relay sent a text message");
            const auto d = self->buffer_.cdata();
            const std::vector<uint8_t> m(static_cast<const uint8_t*>(d.data()), static_cast<const uint8_t*>(d.data()) + d.size());
            self->buffer_.clear();
            self->onMessage(m);
            if (self->state_ != State::Ended) self->read();
        });
    });
}

void Link::onMessage(const std::span<const uint8_t> m) {
    const auto f = relay::decode(m);
    if (!f) return end(relay::Reason::Protocol, "a malformed frame from the relay");
    switch (state_) {
        case State::Challenge: {
            if (f->type != relay::FrameType::Challenge) return end(relay::Reason::Protocol, "expected CHALLENGE");
            const auto message = relay::connectMessage(p_.admission.jti, f->payload);
            const auto sig = vl::keykit::base64UrlDecode(signDetached(message, p_.seed.bytes()));
            p_.seed = vl::keykit::SecretBytes{};  // the installation key is needed for this one signature only
            if (!sig) return end(std::nullopt, "cannot sign the relay's challenge");
            state_ = State::Welcome;
            return send(relay::control(relay::FrameType::Proof, *sig));
        }
        case State::Welcome: {
            if (f->type != relay::FrameType::Welcome) return end(relay::Reason::Protocol, "expected WELCOME");
            const auto j = json::parse(f->text(), nullptr, false);
            if (!j.is_object() || !j.contains("renew_by") || !j["renew_by"].is_number_integer())
                return end(relay::Reason::Protocol, "a malformed WELCOME");
            if (j.contains("window") && j["window"].is_number_unsigned()) {
                const auto w = j["window"].get<uint64_t>();
                if (w == 0 || w > (1u << 24)) return end(relay::Reason::Protocol, "an unusable window");
                window_ = static_cast<uint32_t>(w);
            }
            deadline_.cancel();
            state_ = State::Admitted;
            const std::scoped_lock lock(shared_->mutex);
            shared_->phase = Shared::Phase::Admitted;
            shared_->admittedAt = unixNow();
            shared_->renewBy = j["renew_by"].get<int64_t>();
            log::Registry::cloud()->info("[CloudRelay] Connected to {} (renew by {})", p_.admission.relay_url,
                                         *shared_->renewBy);
            return;
        }
        case State::Admitted: break;
        default: return;
    }
    const auto stream = [&]() -> std::shared_ptr<Stream> {
        const auto it = streams_.find(f->stream);
        return it == streams_.end() ? nullptr : it->second;
    };
    switch (f->type) {
        case relay::FrameType::Renewed: {
            const auto j = json::parse(f->text(), nullptr, false);
            if (!renewing_ || !j.is_object() || !j.contains("renew_by") || !j["renew_by"].is_number_integer())
                return end(relay::Reason::Protocol, "an unexpected RENEWED");
            renewing_ = false;
            const std::scoped_lock lock(shared_->mutex);
            shared_->renewBy = j["renew_by"].get<int64_t>();
            return;
        }
        case relay::FrameType::Open: return onOpen(*f);
        case relay::FrameType::Data:
            if (const auto s = stream(); s && !s->fromRelay(std::move(f->payload))) {
                log::Registry::cloud()->warn("[CloudRelay] Stream {} overran its window", f->stream);
                send(relay::closeStream(f->stream, relay::toString(relay::Reason::Protocol)));
                s->end();
                streamEnded(f->stream, relay::Reason::Protocol);
            }
            return;
        case relay::FrameType::Credit:
            if (const auto s = stream(); s && !s->credited(f->credit)) {
                send(relay::closeStream(f->stream, relay::toString(relay::Reason::Protocol)));
                s->end();
                streamEnded(f->stream, relay::Reason::Protocol);
            }
            return;
        case relay::FrameType::Close:
            if (const auto s = stream()) {
                s->end();
                streams_.erase(f->stream);
                const std::scoped_lock lock(shared_->mutex);
                shared_->streams = static_cast<unsigned>(streams_.size());
            }
            return;
        default: return end(relay::Reason::Protocol, "an unexpected frame");
    }
}

void Link::onOpen(const relay::Frame& f) {
    if (streams_.contains(f.stream)) return end(relay::Reason::Protocol, "a stream id used twice");
    const auto j = json::parse(f.text(), nullptr, false);
    std::string ticket, remote = "unknown";
    if (j.is_object() && j.contains("ticket") && j["ticket"].is_string()) ticket = j["ticket"].get<std::string>();
    if (j.is_object() && j.contains("remote") && j["remote"].is_string()) {
        const auto r = j["remote"].get<std::string>();
        boost::system::error_code ec;
        const auto a = asio::ip::make_address(r, ec);
        // Display and limits only, and never loopback: a relay can claim any address.
        if (!ec && !a.is_loopback() && !a.is_unspecified()) remote = a.to_string();
    }
    const auto now = unixNow();
    const auto check = relay::verifyBrowserTicket(ticket, p_.admission.keys, p_.admission.audience, p_.account,
                                                  p_.deployment, now);
    if (!check.ok()) return refuse(f.stream, std::string(relay::toString(check.refusal)), "", remote, std::string());
    const auto& t = *check.ticket;
    if (!failures_->allowed(t.spki_sha256, now)) return refuse(f.stream, "rate_limited", t.key_id, remote, std::nullopt);
    if (!jtis_->spend(t.jti, t.expires_at, now))
        return refuse(f.stream, std::string(relay::toString(relay::TicketRefusal::Replayed)), t.key_id, remote,
                      t.spki_sha256);
    if (streams_.size() >= kMaxStreams) {
        send(relay::closeStream(f.stream, relay::toString(relay::Reason::Limit)));
        return;
    }

    int fds[2] = {-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0)
        return refuse(f.stream, "no socketpair", t.key_id, remote, std::nullopt);
    for (const int fd : fds) {
        ::fcntl(fd, F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
        const int on = 1;
        ::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
#endif
    }
    auto s = std::make_shared<Stream>(*ioc_, f.stream, window_, weak_from_this());
    s->spki = t.spki_sha256;
    s->keyId = t.key_id;
    s->remote = remote;
    boost::system::error_code ec;
    s->socket().assign(local(), fds[0], ec);
    if (ec) {
        ::close(fds[0]);
        ::close(fds[1]);
        return refuse(f.stream, "no socketpair", t.key_id, remote, std::nullopt);
    }
    streams_[f.stream] = s;

    protocols::device::RelayedOrigin origin;
    origin.address = remote;
    origin.jti = t.jti;
    origin.spki_sha256 = t.spki_sha256;
    origin.key_id = t.key_id;
    // Both run on the listener's strand: hop back to this thread. The io_context outlives a post (shared).
    origin.refused = [ioc = ioc_, weakLink = weak_from_this(), weakStream = std::weak_ptr<Stream>(s)](const std::string_view why) {
        asio::post(*ioc, [weakLink, weakStream, why = std::string(why)] {
            const auto link = weakLink.lock();
            const auto stream = weakStream.lock();
            if (link && stream) link->listenerRefused(stream, why);
        });
    };
    origin.proven = [ioc = ioc_, weakStream = std::weak_ptr<Stream>(s)] {
        asio::post(*ioc, [weakStream] {
            if (const auto stream = weakStream.lock()) stream->proven = true;
        });
    };
    if (!p_.acceptor || !p_.acceptor(fds[1], std::move(origin))) {
        s->end();
        streams_.erase(f.stream);
        return refuse(f.stream, "listener_unavailable", t.key_id, remote, std::nullopt);
    }
    {
        const std::scoped_lock lock(shared_->mutex);
        shared_->streams = static_cast<unsigned>(streams_.size());
        ++shared_->accepted;
    }
    s->startReading();
}

void Link::listenerRefused(const std::shared_ptr<Stream>& s, std::string why) {
    if (s->refusedByListener) return;
    s->refusedByListener = true;
    // A key that fails its proof (or anything else before it) counts against that key and in all.
    failures_->fail(s->spki, unixNow());
    audit(why, s->keyId, s->remote);
    {
        const std::scoped_lock lock(shared_->mutex);
        ++shared_->refused;
    }
    if (!s->ended()) {
        s->end();
        streamEnded(s->id(), relay::Reason::Refused);
    }
}

void Link::refuse(const uint32_t stream, const std::string& why, const std::string& keyId, const std::string& remote,
                  const std::optional<std::string>& countAgainst) {
    {
        // Counted before the CLOSE goes out: whoever sees the CLOSE sees the count.
        const std::scoped_lock lock(shared_->mutex);
        ++shared_->refused;
    }
    if (countAgainst) failures_->fail(*countAgainst, unixNow());
    audit(why, keyId, remote);
    send(relay::closeStream(stream, relay::toString(relay::Reason::Refused)));
}

void Link::audit(const std::string& why, const std::string& keyId, const std::string& remote) {
    const auto now = unixNow();
    {
        const std::scoped_lock lock(shared_->mutex);
        if (now / 60 != shared_->auditMinute) {
            if (shared_->auditsDropped > 0)
                log::Registry::cloud()->warn("[CloudRelay] {} more refused stream(s) not audited in the last minute",
                                             shared_->auditsDropped);
            shared_->auditMinute = now / 60;
            shared_->audits = 0;
            shared_->auditsDropped = 0;
        }
        if (shared_->audits >= kAuditsPerMinute) {
            ++shared_->auditsDropped;
            return;
        }
        ++shared_->audits;
    }
    json details = {{"reason", why}, {"remote", remote}};
    if (!keyId.empty()) details["browser_key"] = keyId;
    ::vh::audit::record({.action = "cloud.relay.refused", .outcome = ::vh::audit::Outcome::Denied, .actor_id = std::nullopt,
                         .actor = "system", .details = std::move(details)},
                        "[CloudRelay] Refused a relayed stream from " + remote + ": " + why);
}

void Link::streamEnded(const uint32_t id, const relay::Reason reason) {
    if (!streams_.contains(id)) return;
    streams_.erase(id);
    if (state_ == State::Admitted) send(relay::closeStream(id, relay::toString(reason)));
    const std::scoped_lock lock(shared_->mutex);
    shared_->streams = static_cast<unsigned>(streams_.size());
}

void Link::renew(std::string ticket, std::vector<relay::TicketKey> keys) {
    if (state_ != State::Admitted) return;
    p_.admission.keys = std::move(keys);  // the newest ticket keys check the OPENs from now on
    renewing_ = true;
    send(relay::control(relay::FrameType::Renew, ticket));
}

void Link::send(std::vector<uint8_t> frame) {
    if (state_ == State::Ended) return;
    out_.push_back(std::move(frame));
    if (!writing_) write();
}

void Link::write() {
    if (out_.empty() || state_ == State::Ended) {
        writing_ = false;
        return;
    }
    writing_ = true;
    withWs([&](auto& ws) {
        ws.async_write(asio::buffer(out_.front()), [self = shared_from_this()](const boost::system::error_code& ec, std::size_t) {
            if (self->state_ == State::Ended) return;
            if (ec) return self->end(std::nullopt, "writing to the relay failed: " + ec.message());
            self->out_.pop_front();
            self->write();
        });
    });
}

void Link::shutdown(const relay::Reason why) {
    if (state_ == State::Ended) return;
    const auto streams = std::exchange(streams_, {});
    for (const auto& [_, s] : streams) s->end();
    state_ = State::Ended;
    deadline_.cancel();
    resolver_.cancel();
    {
        const std::scoped_lock lock(shared_->mutex);
        shared_->phase = Shared::Phase::Ended;
        shared_->endedWith = why;
        shared_->endedDetail = "switched off";
        shared_->streams = 0;
        shared_->admittedAt.reset();
        shared_->renewBy.reset();
    }
    // A close frame, best effort; the socket goes with the last handler.
    withWs([&](auto& ws) {
        ws.async_close(websocket::close_reason(static_cast<websocket::close_code>(relay::closeCode(why))),
                       [self = shared_from_this()](const boost::system::error_code&) {
                           self->withWs([](auto& w) {
                               boost::system::error_code ignored;
                               beast::get_lowest_layer(w).socket().close(ignored);
                           });
                       });
    });
}

void Link::end(const std::optional<relay::Reason> reason, const std::string& detail) {
    if (state_ == State::Ended) return;
    const bool wasAdmitted = state_ == State::Admitted;
    state_ = State::Ended;
    deadline_.cancel();
    resolver_.cancel();
    const auto streams = std::exchange(streams_, {});
    for (const auto& [_, s] : streams) s->end();
    withWs([](auto& ws) {
        boost::system::error_code ignored;
        beast::get_lowest_layer(ws).socket().close(ignored);
    });
    {
        const std::scoped_lock lock(shared_->mutex);
        shared_->phase = Shared::Phase::Ended;
        shared_->endedWith = reason;
        shared_->endedDetail = detail;
        shared_->streams = 0;
        shared_->admittedAt.reset();
        shared_->renewBy.reset();
    }
    if (wasAdmitted) log::Registry::cloud()->info("[CloudRelay] Disconnected: {}", detail);
    else log::Registry::cloud()->warn("[CloudRelay] Not admitted: {}", detail);
}

// ---- the ticket -------------------------------------------------------------------------------------------------------

std::variant<Admission, TicketFailure> fetchTicket(const storage::Linked& link, const std::string& deployment) {
    const auto r = signedCall(link.endpoint, link.installation, link.seed.bytes(), "POST", "/v1/relay/server-tickets");
    std::string code;
    if (r.body.is_object() && r.body.contains("error") && r.body["error"].is_object() && r.body["error"].contains("code") &&
        r.body["error"]["code"].is_string())
        code = r.body["error"]["code"].get<std::string>();
    using Kind = TicketFailure::Kind;
    if (r.status == 0) return TicketFailure{Kind::Retry, "Vaulthalla Cloud is unreachable: " + r.error, {}};
    if (r.status == 401 || r.status == 404)
        return TicketFailure{Kind::Stopped, "Vaulthalla Cloud no longer knows this installation (HTTP " +
                                                std::to_string(r.status) + "): it was unlinked, revoked or its deployment removed", {}};
    if (r.status == 403 && code == "relay_disabled")
        return TicketFailure{Kind::Waiting, "the relay is off for this server at Vaulthalla Cloud: the account holder switches it on there", {}};
    if (r.status == 403) return TicketFailure{Kind::Stopped, "Vaulthalla Cloud refused this installation a relay ticket (HTTP 403" + (code.empty() ? std::string() : " " + code) + ")", {}};
    if (r.status == 402) return TicketFailure{Kind::Waiting, "the account's plan is not active (HTTP 402)", {}};
    if (r.status == 503) return TicketFailure{Kind::Waiting, "Vaulthalla Cloud has no relay configured (HTTP 503)", {}};
    if (r.status == 429) return TicketFailure{Kind::Retry, "Vaulthalla Cloud is rate limiting relay tickets (HTTP 429)", std::chrono::seconds(60)};
    if (!r.ok()) return TicketFailure{Kind::Retry, "Vaulthalla Cloud answered HTTP " + std::to_string(r.status), {}};

    const auto& b = r.body;
    auto str = [&](const char* k) -> std::string {
        return b.is_object() && b.contains(k) && b[k].is_string() ? b[k].get<std::string>() : std::string();
    };
    auto num = [&](const char* k) -> int64_t {
        return b.is_object() && b.contains(k) && b[k].is_number_integer() ? b[k].get<int64_t>() : 0;
    };
    Admission a;
    a.ticket = str("ticket");
    a.relay_url = str("relay_url");
    a.audience = str("audience");
    a.renew_after = num("renew_after");
    a.renew_by = num("renew_by");
    const auto jti = relay::unverifiedJti(a.ticket);
    const auto target = targetOf(a.relay_url);
    if (a.ticket.empty() || a.ticket.size() > relay::kMaxTicketBytes || !jti || !target || a.audience.empty() ||
        str("deployment_id") != deployment)
        return TicketFailure{Kind::Retry, "Vaulthalla Cloud's ticket answer is unusable", {}};
    a.jti = *jti;
    a.target = *target;
    if (b.contains("ticket_public_keys") && b["ticket_public_keys"].is_array())
        for (const auto& k : b["ticket_public_keys"]) {
            if (!k.is_string()) continue;
            const auto raw = vl::keykit::base64UrlDecode(k.get<std::string>());
            if (!raw || raw->size() != 32) continue;
            relay::TicketKey key{};
            std::ranges::copy(*raw, key.begin());
            a.keys.push_back(key);
        }
    if (a.keys.empty()) return TicketFailure{Kind::Retry, "Vaulthalla Cloud's ticket answer lists no ticket keys", {}};
    return a;
}

std::chrono::milliseconds jittered(const unsigned attempt) {
    // Full jitter between 1 s and the cap (1 s, 2 s, 4 s ... 5 min).
    return concurrency::jitteredBackoff(attempt, std::chrono::seconds(1), kBackoffCap);
}

std::mutex gLiveMutex;
RelayService* gLive = nullptr;



// ---- the service ------------------------------------------------------------------------------------------------------

struct Engine {
    mutable std::mutex mutex;  // status_ and the decision state below
    RelayStatus status;
    std::atomic<bool> wake{true};
    std::atomic<bool> reset{false};  // the switch went on: a stopped service tries again
    RelayService::Acceptor acceptor;

    std::shared_ptr<asio::io_context> ioc;
    std::thread ioThread;
    std::shared_ptr<Shared> shared = std::make_shared<Shared>();
    std::shared_ptr<relay::JtiLedger> jtis = std::make_shared<relay::JtiLedger>();
    std::shared_ptr<relay::FailureLimiter> failures = std::make_shared<relay::FailureLimiter>();
    std::shared_ptr<Link> link;

    // Decisions (service thread only).
    unsigned attempt = 0;
    Clock::time_point nextAttempt{};
    Clock::time_point nextDesired{};
    std::optional<int64_t> renewAt;
    std::optional<std::string> stoppedFor;  // the installation a terminal refusal applies to
    struct Desired {
        bool on = false;
        std::string state;
        std::string installation, account, deployment;
        std::optional<std::string> enabledBy;
        std::optional<std::time_t> enabledAt;
    } desired;

    void startIo() {
        if (ioc) return;
        ioc = std::make_shared<asio::io_context>();
        ioThread = std::thread([ctx = ioc] {
            auto guard = asio::make_work_guard(*ctx);
            for (;;) {
                try {
                    ctx->run();
                    return;
                } catch (const std::exception& e) {
                    log::Registry::cloud()->error("[CloudRelay] Unhandled exception: {}", e.what());
                }
            }
        });
    }

    void stopIo() {
        if (!ioc) return;
        if (link) {
            asio::post(*ioc, [l = link] { l->shutdown(relay::Reason::Shutdown); });
            link.reset();
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(200));  // the close frame goes out
        ioc->stop();
        if (ioThread.joinable()) ioThread.join();
        ioc.reset();
    }

    void dropLink(const relay::Reason why) {
        if (!link) return;
        asio::post(*ioc, [l = link, why] { l->shutdown(why); });
        link.reset();
        renewAt.reset();
        const auto closed = protocols::device::closeRelayedDeviceSessions();
        if (closed) log::Registry::cloud()->info("[CloudRelay] Closed {} relayed session(s)", closed);
        const std::scoped_lock lock(shared->mutex);
        shared->phase = Shared::Phase::Idle;
        shared->endedWith.reset();
    }

    void setState(const std::string& state, const std::optional<std::string>& error = std::nullopt) {
        const std::scoped_lock lock(mutex);
        status.state = state;
        if (error) status.last_error = error;
    }

    void readDesired() {
        Desired d;
        const auto row = db::query::cloud::Link::get();
        const bool linked = row && row->status == "linked" && row->installation_id && row->deployment_id &&
                            row->account_public_id;
        const auto sw = db::query::cloud::RelaySwitch::get();
        const bool on = linked && sw && sw->installation_id == *row->installation_id;
        if (on) {
            d.enabledBy = sw->enabled_by;
            d.enabledAt = sw->enabled_at;
        }
        if (!on) d.state = linked ? "off" : "not_linked";
        else if (!config::Registry::get().device_server.enabled) d.state = "listener_off";
        else {
            d.on = true;
            d.installation = *row->installation_id;
            d.account = *row->account_public_id;
            d.deployment = *row->deployment_id;
        }
        if (stoppedFor && (!d.on || *stoppedFor != d.installation)) stoppedFor.reset();
        desired = std::move(d);
        const std::scoped_lock lock(mutex);
        status.enabled = on;
        status.enabled_by = desired.enabledBy;
        status.enabled_at = desired.enabledAt;
    }

    void tick(const std::function<bool()>& stopping, const std::atomic<bool>* cancel);
};

void Engine::tick(const std::function<bool()>& stopping, const std::atomic<bool>* cancel) {
    // A ticket request in flight ends within ~100 ms of a stop (the daemon's shutdown is bounded).
    const ::vh::storage::s3::curl::http::ScopedCancellation cancellation(cancel);
    const auto now = Clock::now();
    if (reset.exchange(false)) {
        stoppedFor.reset();
        attempt = 0;
        nextAttempt = {};
    }
    if (wake.exchange(false) || now >= nextDesired) {
        try {
            const bool wasStopped = stoppedFor.has_value();
            readDesired();
            if (wasStopped && !stoppedFor) attempt = 0;
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[CloudRelay] Cannot read the relay switch: {}", e.what());
        }
        nextDesired = now + kDesiredEvery;
    }
    if (!desired.on) {
        if (link) {
            dropLink(relay::Reason::Done);
            log::Registry::cloud()->info("[CloudRelay] Relay connection closed ({})", desired.state);
        }
        attempt = 0;
        nextAttempt = {};
        const std::scoped_lock lock(mutex);
        status.state = desired.state;
        status.relay_url.reset();
        status.connected_since.reset();
        status.renew_by.reset();
        status.next_attempt_at.reset();
        status.streams = 0;
        return;
    }
    if (stoppedFor) return;

    Shared::Phase phase;
    std::optional<relay::Reason> endedWith;
    std::string endedDetail;
    std::optional<int64_t> admittedAt, renewBy;
    unsigned streams = 0;
    uint64_t accepted = 0, refused = 0;
    {
        const std::scoped_lock lock(shared->mutex);
        phase = shared->phase;
        endedWith = shared->endedWith;
        endedDetail = shared->endedDetail;
        admittedAt = shared->admittedAt;
        renewBy = shared->renewBy;
        streams = shared->streams;
        accepted = shared->accepted;
        refused = shared->refused;
    }
    {
        const std::scoped_lock lock(mutex);
        status.streams = streams;
        status.streams_accepted = accepted;
        status.streams_refused = refused;
    }

    if (link && phase == Shared::Phase::Ended) {
        // The socket ended: back off and reconnect with a fresh ticket (after `unauthorized` the next ticket is fresh
        // anyway). A connection that stayed up a while starts the backoff over.
        link.reset();
        renewAt.reset();
        protocols::device::closeRelayedDeviceSessions();
        const auto delay = jittered(attempt++);
        nextAttempt = now + delay;
        const std::scoped_lock lock(mutex);
        status.state = "backoff";
        status.last_error = endedDetail;
        status.connected_since.reset();
        status.renew_by.reset();
        status.next_attempt_at = std::time(nullptr) + std::chrono::duration_cast<std::chrono::seconds>(delay).count() + 1;
        return;
    }

    if (link && phase == Shared::Phase::Admitted) {
        if (admittedAt && unixNow() - *admittedAt >= kHealthyAfter.count()) attempt = 0;
        {
            const std::scoped_lock lock(mutex);
            status.state = "connected";
            status.connected_since = admittedAt;
            status.renew_by = renewBy;
            status.next_attempt_at.reset();
        }
        if (!renewAt || unixNow() < *renewAt || stopping()) return;
        // The renewal midpoint: a fresh ticket in a RENEW frame, retried until renew_by (the relay closes us then).
        auto linkedNow = storage::linked();
        if (!linkedNow) {
            renewAt = unixNow() + kRenewRetry.count();
            return;
        }
        auto r = fetchTicket(*linkedNow, desired.deployment);
        if (auto* a = std::get_if<Admission>(&r)) {
            renewAt = a->renew_after;
            asio::post(*ioc, [l = link, t = a->ticket, k = a->keys]() mutable { l->renew(std::move(t), std::move(k)); });
            const std::scoped_lock lock(mutex);
            status.last_ticket_at = std::time(nullptr);
            return;
        }
        const auto& failure = std::get<TicketFailure>(r);
        log::Registry::cloud()->warn("[CloudRelay] Renewal failed: {}", failure.message);
        if (failure.kind == TicketFailure::Kind::Stopped) {
            dropLink(relay::Reason::Done);
            stoppedFor = desired.installation;
            setState("stopped", failure.message);
            return;
        }
        renewAt = unixNow() + kRenewRetry.count();
        setState("connected", failure.message);
        return;
    }

    if (link) return;  // connecting
    if (now < nextAttempt) return;

    {
        const std::scoped_lock lock(mutex);
        status.state = "connecting";
        status.next_attempt_at.reset();
    }
    auto linkedNow = storage::linked();
    if (!linkedNow) {
        setState("backoff", std::string("this server's cloud identity can't be unsealed"));
        nextAttempt = now + jittered(attempt++);
        return;
    }
    auto r = fetchTicket(*linkedNow, desired.deployment);
    if (auto* failure = std::get_if<TicketFailure>(&r)) {
        log::Registry::cloud()->warn("[CloudRelay] No relay ticket: {}", failure->message);
        switch (failure->kind) {
            case TicketFailure::Kind::Stopped:
                stoppedFor = desired.installation;
                setState("stopped", failure->message);
                return;
            case TicketFailure::Kind::Waiting:
                nextAttempt = now + kWaitingRetry;
                break;
            case TicketFailure::Kind::Retry:
                nextAttempt = now + std::max<std::chrono::milliseconds>(jittered(attempt++), failure->floor);
                break;
        }
        const std::scoped_lock lock(mutex);
        status.state = failure->kind == TicketFailure::Kind::Waiting ? "waiting" : "backoff";
        status.last_error = failure->message;
        status.next_attempt_at = std::time(nullptr) +
            std::chrono::duration_cast<std::chrono::seconds>(nextAttempt - now).count() + 1;
        return;
    }
    auto& a = std::get<Admission>(r);
    renewAt = a.renew_after;
    {
        const std::scoped_lock lock(mutex);
        status.relay_url = a.relay_url;
        status.last_ticket_at = std::time(nullptr);
    }
    {
        const std::scoped_lock lock(shared->mutex);
        shared->phase = Shared::Phase::Connecting;
        shared->endedWith.reset();
    }
    startIo();
    link = std::make_shared<Link>(ioc,
                                  Link::Params{.admission = std::move(a), .account = desired.account,
                                               .deployment = desired.deployment, .seed = std::move(linkedNow->seed),
                                               .acceptor = acceptor},
                                  shared, jtis, failures);
    asio::post(*ioc, [l = link] { l->start(); });
}

}

struct RelayService::Impl : relay_detail::Engine {};

RelayService::RelayService() : AsyncService("CloudRelayService"), impl_(std::make_shared<Impl>()) {
    impl_->acceptor = [](const int fd, protocols::device::RelayedOrigin origin) {
        const auto server = runtime::Manager::instance().getDeviceServer();
        if (!server) {
            ::close(fd);
            return false;
        }
        return server->acceptRelayed(fd, std::move(origin));
    };
    const std::scoped_lock lock(relay_detail::gLiveMutex);
    relay_detail::gLive = this;
}

RelayService::~RelayService() {
    {
        const std::scoped_lock lock(relay_detail::gLiveMutex);
        if (relay_detail::gLive == this) relay_detail::gLive = nullptr;
    }
    stop();
    impl_->stopIo();
}

RelayStatus RelayService::snapshot() const {
    RelayStatus out;
    {
        const std::scoped_lock lock(impl_->mutex);
        out = impl_->status;
    }
    {
        // The counters as the I/O thread keeps them (the service thread copies them only every pass).
        const std::scoped_lock lock(impl_->shared->mutex);
        out.streams_accepted = impl_->shared->accepted;
        out.streams_refused = impl_->shared->refused;
        if (out.state == "connected") out.streams = impl_->shared->streams;
    }
    if (!isRunning() && out.state != "off" && out.state != "not_linked") out.state = "stopped";
    return out;
}

void RelayService::wake(const bool reset) {
    if (reset) impl_->reset.store(true);
    impl_->wake.store(true);
}

void RelayService::setAcceptorForTesting(Acceptor acceptor) { impl_->acceptor = std::move(acceptor); }

void RelayService::runLoop() {
    while (!shouldStop()) {
        try {
            impl_->tick([this] { return shouldStop(); }, &interruptFlag_);
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[CloudRelay] Pass failed: {}", e.what());
        }
        lazySleep(relay_detail::kLook);
    }
    if (impl_->link) protocols::device::closeRelayedDeviceSessions();
    impl_->stopIo();
    const std::scoped_lock lock(impl_->mutex);
    impl_->status.streams = 0;
    impl_->status.connected_since.reset();
}

void RelayService::onStop() {}

std::optional<RelayStatus> relaySnapshot() {
    const std::scoped_lock lock(relay_detail::gLiveMutex);
    if (!relay_detail::gLive) return std::nullopt;
    return relay_detail::gLive->snapshot();
}

void wakeRelay(const bool reset) {
    const std::scoped_lock lock(relay_detail::gLiveMutex);
    if (relay_detail::gLive) relay_detail::gLive->wake(reset);
}

}
