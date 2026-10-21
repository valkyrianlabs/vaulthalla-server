#include "protocols/http/Session.hpp"

#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "protocols/http/Router.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/upload/Coordinator.hpp"
#include "protocols/ws/ConnectionLimit.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/TlsTransport.hpp"
#include "device/Peer.hpp"
#include "identities/User.hpp"
#include "log/AuditOrigin.hpp"
#include "storage/PlaintextReader.hpp"

#include <boost/asio/dispatch.hpp>
#include <boost/asio/post.hpp>
#include <condition_variable>

#include <algorithm>
#include <array>
#include <boost/system/system_error.hpp>
#include <chrono>
#include <limits>
#include <mutex>
#include <string>
#include <poll.h>
#include <sys/socket.h>
#include <variant>
#include <vector>

namespace vh::protocols::http {
namespace {
constexpr std::size_t kReadBufferBytes = 64u * 1024u;
// Buffered (non-upload-stream) bodies: batch JSON, upload-session JSON, text saves. Never more than these need.
[[nodiscard]] std::size_t maxBufferedBodyBytes() {
    const auto text = static_cast<std::size_t>(config::Registry::get().preview.text.max_edit_bytes);
    return std::max<std::size_t>(4u * 1024u * 1024u, text + 64u * 1024u);
}

// Every route that takes a body needs a session; refuse cookieless bodies before reading a byte of them.
[[nodiscard]] bool carriesSessionCookie(const boost::beast::http::request_parser<boost::beast::http::buffer_body>& parser) {
    const auto it = parser.get().find(boost::beast::http::field::cookie);
    if (it == parser.get().end()) return false;
    const std::string_view cookies(it->value().data(), it->value().size());
    return cookies.find("refresh=") != std::string_view::npos;  // also matches share_refresh=
}
constexpr std::size_t kStreamChunkBytes = 256u * 1024u;
// Keep-alive wait for the next request, and per-operation inactivity limits once a request is in flight. A slow
// but progressing client (media over a weak uplink) is fine; a stalled one is dropped and frees its thread.
std::atomic<int64_t> idleTimeoutMs{20'000};
std::atomic<int64_t> readTimeoutMs{60'000};
std::atomic<int64_t> writeTimeoutMs{60'000};

[[nodiscard]] SessionLifetimes& sessionLifetimes() {
    static SessionLifetimes value;
    return value;
}

[[nodiscard]] SessionLifetimes& deviceSessionLifetimes() {
    static SessionLifetimes value;
    return value;
}

// The device listener's routes over HTTP: the human lanes nginx forwards on the web side, and /mcp.
[[nodiscard]] bool isDeviceLaneTarget(const std::string_view target) {
    for (const std::string_view prefix : {"/preview", "/download", "/upload"})
        if (target.starts_with(prefix) && (target.size() == prefix.size() || target[prefix.size()] == '/' ||
                                           target[prefix.size()] == '?'))
            return true;
    return false;
}

[[nodiscard]] bool isMcpTarget(const std::string_view target) {
    return target == "/mcp" || target.starts_with("/mcp?");
}

// TLS on the device listener: the stream is Asio's async ssl::stream on the device listener's io_context, so each
// blocking call starts one async op on the stream's strand and waits for it against the deadline (cancelling the
// socket's I/O when it passes). The bytes go through buffers owned by the op, never the caller's, so an op that
// outlives an abandoned wait can't touch freed memory.
class TlsStream final : public ByteStream {
public:
    explicit TlsStream(std::shared_ptr<ws::TlsTransport> transport) : transport_(std::move(transport)) {}

protected:
    std::size_t readSome(boost::asio::mutable_buffer buffer, boost::system::error_code& ec) override {
        auto op = std::make_shared<Op>();
        op->data.resize(std::min<std::size_t>(buffer.size(), kOpBufferBytes));
        start(op, [op](ws::TlsTransport& t, auto&& done) {
            t.ws.next_layer().async_read_some(boost::asio::buffer(op->data), std::forward<decltype(done)>(done));
        });
        const auto n = wait(op, ec);
        if (n) std::memcpy(buffer.data(), op->data.data(), n);
        return n;
    }

    std::size_t writeSome(boost::asio::const_buffer buffer, boost::system::error_code& ec) override {
        auto op = std::make_shared<Op>();
        const auto* bytes = static_cast<const uint8_t*>(buffer.data());
        op->data.assign(bytes, bytes + std::min<std::size_t>(buffer.size(), kOpBufferBytes));
        start(op, [op](ws::TlsTransport& t, auto&& done) {
            t.ws.next_layer().async_write_some(boost::asio::buffer(op->data), std::forward<decltype(done)>(done));
        });
        return wait(op, ec);
    }

private:
    static constexpr std::size_t kOpBufferBytes = 256u * 1024u;
    static constexpr auto kCancelGrace = std::chrono::seconds(5);

    struct Op {
        std::mutex mutex;
        std::condition_variable cv;
        bool done = false;
        std::size_t n = 0;
        boost::system::error_code ec{};
        std::vector<uint8_t> data;
    };

    template<class Start>
    void start(const std::shared_ptr<Op>& op, Start&& begin) {
        auto transport = transport_;
        boost::asio::dispatch(transport->ws.get_executor(), [transport, op, begin = std::forward<Start>(begin)] {
            begin(*transport, [op](const boost::system::error_code& e, const std::size_t n) {
                std::scoped_lock lock(op->mutex);
                op->ec = e;
                op->n = n;
                op->done = true;
                op->cv.notify_all();
            });
        });
    }

    std::size_t wait(const std::shared_ptr<Op>& op, boost::system::error_code& ec) {
        std::unique_lock lock(op->mutex);
        if (op->cv.wait_for(lock, timeout_, [&] { return op->done; })) {
            ec = op->ec;
            return op->n;
        }
        lock.unlock();
        auto transport = transport_;
        boost::asio::post(transport->ws.get_executor(), [transport] {
            boost::system::error_code ignored;
            boost::beast::get_lowest_layer(transport->ws).cancel(ignored);
        });
        lock.lock();
        (void)op->cv.wait_for(lock, kCancelGrace, [&] { return op->done; });
        ec = boost::asio::error::timed_out;
        return 0;
    }

    std::shared_ptr<ws::TlsTransport> transport_;
};

[[nodiscard]] std::mutex& activeSessionsMutex() {
    static std::mutex value;
    return value;
}

[[nodiscard]] std::vector<std::weak_ptr<Session>>& activeSessions() {
    static std::vector<std::weak_ptr<Session>> value;
    return value;
}

void pruneActiveSessionsLocked() {
    auto& sessions = activeSessions();
    sessions.erase(
        std::remove_if(sessions.begin(), sessions.end(), [](const std::weak_ptr<Session>& item) {
            return item.expired();
        }),
        sessions.end()
    );
}

void registerActiveSession(const std::shared_ptr<Session>& session) {
    std::scoped_lock lock(activeSessionsMutex());
    pruneActiveSessionsLocked();
    activeSessions().push_back(session);
}

void unregisterActiveSession(const Session* session) {
    std::scoped_lock lock(activeSessionsMutex());
    auto& sessions = activeSessions();
    sessions.erase(
        std::remove_if(sessions.begin(), sessions.end(), [session](const std::weak_ptr<Session>& item) {
            const auto locked = item.lock();
            return !locked || locked.get() == session;
        }),
        sessions.end()
    );
}

[[nodiscard]] status statusForException(const std::exception& e) {
    const std::string message = e.what();
    if (message.contains("token") || message.contains("Unauthorized") || message.contains("requires a ready share session") ||
        message.contains("requires a user session"))
        return status::unauthorized;
    if (message.contains("denied") || message.contains("Permission")) return status::forbidden;
    if (message.contains("not found")) return status::not_found;
    if (message.contains("exceeds") || message.contains("too large")) return status::payload_too_large;
    return status::bad_request;
}
} // namespace

std::size_t TimedStream::readSome(const boost::asio::mutable_buffer buffer, boost::system::error_code& ec) {
    return io(true, [&](boost::system::error_code& e) { return socket_.read_some(buffer, e); }, ec);
}

std::size_t TimedStream::writeSome(const boost::asio::const_buffer buffer, boost::system::error_code& ec) {
    return io(false, [&](boost::system::error_code& e) { return socket_.write_some(buffer, e); }, ec);
}

std::size_t TimedStream::io(const bool reading, const std::function<std::size_t(boost::system::error_code&)>& op,
                           boost::system::error_code& ec) {
    const auto deadline = std::chrono::steady_clock::now() + timeout_;
    for (;;) {
        const auto n = op(ec);
        if (ec != boost::asio::error::would_block && ec != boost::asio::error::try_again) return n;
        ec.clear();

        const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(
            deadline - std::chrono::steady_clock::now());
        if (remaining.count() <= 0) {
            ec = boost::asio::error::timed_out;
            return 0;
        }
        pollfd pfd{.fd = socket_.native_handle(), .events = static_cast<short>(reading ? POLLIN : POLLOUT), .revents = 0};
        const int ready = ::poll(&pfd, 1, static_cast<int>(std::min<int64_t>(remaining.count(), 60'000)));
        if (ready < 0) {
            if (errno == EINTR) continue;
            ec = boost::system::error_code(errno, boost::system::system_category());
            return 0;
        }
        if (ready == 0 && std::chrono::steady_clock::now() >= deadline) {
            ec = boost::asio::error::timed_out;
            return 0;
        }
        // Readable/writable (or hung up: the next op reports EOF/EPIPE): retry.
    }
}

void Session::setTimeoutsForTesting(const std::chrono::milliseconds idle, const std::chrono::milliseconds io) {
    idleTimeoutMs.store(idle.count());
    readTimeoutMs.store(io.count());
    writeTimeoutMs.store(io.count());
}

struct Session::Device {
    DeviceConnection connection;
    std::shared_ptr<ws::Session> principal;  // null on a pairing-only connection
    std::unique_ptr<HeaderParser> first;     // the request the listener already read the header of
};

Session::Session(tcp::socket socket) : lifetime_(sessionLifetimes()), socket_(std::move(socket)) {
    buffer_.max_size(8192);
    stream_ = std::make_unique<TimedStream>(*socket_);
    nativeHandle_.store(socket_->native_handle(), std::memory_order_release);
    boost::system::error_code ec;
    socket_->non_blocking(true, ec);
    socket_->set_option(tcp::no_delay(true), ec);
}

Session::Session(DeviceConnection connection, std::unique_ptr<HeaderParser> first, beast::flat_buffer buffer)
    : lifetime_(sessionLifetimes()), buffer_(std::move(buffer)) {
    deviceLifetime_.emplace(deviceSessionLifetimes());
    if (!connection.transport || !connection.peer) throw std::invalid_argument("device HTTP session needs its transport");
    buffer_.max_size(std::max<std::size_t>(8192, buffer_.size()));
    stream_ = std::make_unique<TlsStream>(connection.transport);
    nativeHandle_.store(beast::get_lowest_layer(connection.transport->ws).native_handle(), std::memory_order_release);
    device_ = std::make_unique<Device>(Device{.connection = std::move(connection), .principal = nullptr,
                                              .first = std::move(first)});
}

Session::~Session() {
    if (device_ && device_->principal) device_->principal->close();
}

std::shared_ptr<Session> Session::open(tcp::socket socket) {
    auto session = std::make_shared<Session>(std::move(socket));
    registerActiveSession(session);
    return session;
}

std::shared_ptr<Session> Session::openDevice(DeviceConnection connection, std::unique_ptr<HeaderParser> first,
                                             beast::flat_buffer buffer) {
    auto user = connection.user;
    auto peer = connection.peer;
    auto session = std::make_shared<Session>(std::move(connection), std::move(first), std::move(buffer));
    if (user) {
        // Revocation, revokeSessions and the sweeper close the principal; that ends this connection too.
        session->device_->principal = ws::Session::devicePrincipal(
            std::move(peer), std::move(user), [weak = std::weak_ptr<Session>(session)] {
                if (const auto s = weak.lock()) s->cancel();
            });
    }
    registerActiveSession(session);
    return session;
}

bool Session::waitUntilNoDeviceSessionsAlive(const std::chrono::milliseconds timeout) {
    return deviceSessionLifetimes().waitUntilNoneAlive(timeout);
}

bool Session::stopping() const noexcept {
    if (stopRequested_.load(std::memory_order_acquire)) return true;
    return device_ && device_->principal && device_->principal->closing();
}

bool Session::waitUntilNoneAlive(const std::chrono::milliseconds timeout) {
    return sessionLifetimes().waitUntilNoneAlive(timeout);
}

void Session::run() {
    const auto self = shared_from_this();
    while (!stopping() && read_one()) {}
    do_close();
    if (device_ && device_->principal) device_->principal->close();
    unregisterActiveSession(this);
}

void Session::cancel() noexcept {
    stopRequested_.store(true, std::memory_order_release);
    std::scoped_lock lock(socketMutex_);
    const auto fd = nativeHandle_.load(std::memory_order_acquire);
    if (fd >= 0) (void)::shutdown(fd, SHUT_RDWR);
}

void Session::cancelAllActive() noexcept {
    std::vector<std::shared_ptr<Session>> sessions;
    {
        std::scoped_lock lock(activeSessionsMutex());
        pruneActiveSessionsLocked();
        sessions.reserve(activeSessions().size());
        for (const auto& item : activeSessions()) {
            if (auto session = item.lock()) sessions.push_back(std::move(session));
        }
    }

    for (const auto& session : sessions) {
        if (session) session->cancel();
    }
}

request Session::make_request_from_parser(
    const boost::beast::http::request_parser<boost::beast::http::buffer_body>& parser,
    std::string body
) {
    const auto& src = parser.get();
    request req{src.method(), src.target(), src.version()};
    for (const auto& field : src)
        req.insert(field.name_string(), field.value());
    req.keep_alive(src.keep_alive());
    req.body() = std::move(body);
    return req;
}

bool Session::read_one() {
    if (stopping()) return false;

    if (device_ && device_->first) {
        const auto first = std::move(device_->first);  // the listener read this header already
        stream_->setTimeout(std::chrono::milliseconds(readTimeoutMs.load()));
        return serve(*first);
    }

    HeaderParser parser;
    parser.body_limit(std::numeric_limits<uint64_t>::max());

    beast::error_code ec;
    stream_->setTimeout(std::chrono::milliseconds(idleTimeoutMs.load()));
    boost::beast::http::read_header(*stream_, buffer_, parser, ec);
    if (ec == boost::beast::http::error::end_of_stream || ec == boost::asio::error::eof ||
        ec == boost::asio::error::timed_out) return false;
    stream_->setTimeout(std::chrono::milliseconds(readTimeoutMs.load()));
    if (ec) {
        if (!stopping() && ec != boost::asio::ssl::error::stream_truncated)
            log::Registry::http()->error("[Session] Header read error: {}", ec.message());
        return false;
    }
    return serve(parser);
}

model::preview::Response Session::route(request&& req) {
    if (device_ && isMcpTarget(std::string_view(req.target().data(), req.target().size()))) {
        if (!device_->connection.mcp) return Router::makeErrorResponse(req, "Not found", status::not_found);
        return device_->connection.mcp(std::move(req), device_->principal);
    }
    return Router::route(std::move(req));
}

bool Session::serve(HeaderParser& parser) {
    log::Registry::http()->debug("[Session] Request headers: {}", parser.get().target());

    // The device listener: only its lanes, only for a paired device, always as that device's user.
    std::optional<access::DevicePrincipalScope> principalScope;
    std::optional<log::AuditOrigin> origin;
    if (device_) {
        const std::string_view target(parser.get().target().data(), parser.get().target().size());
        auto refuse = [&](const std::string& msg, const status code) {
            auto req = make_request_from_parser(parser);
            auto response = Router::makeErrorResponse(req, msg, code);
            std::visit([](auto& res) { res.keep_alive(false); }, response);
            (void)write_response(std::move(response));
            return false;
        };
        if (!isDeviceLaneTarget(target) && !isMcpTarget(target)) return refuse("Not found", status::not_found);
        if (!device_->principal) return refuse("device_unknown: this device is not paired with this node", status::forbidden);
        if (stopping()) return false;
        const auto& peer = *device_->connection.peer;
        ::vh::device::touch(peer);
        principalScope.emplace(device_->principal);
        origin.emplace("device " + peer.shortId());
    }

    try {
        if (upload::Coordinator::isUploadFileRequest(parser.get().method(), parser.get().target()))
            return handle_streaming_upload(parser);
        const bool hasBody = parser.chunked() || (parser.content_length() && *parser.content_length() > 0);
        if (hasBody && !device_ && !carriesSessionCookie(parser)) {
            auto req = make_request_from_parser(parser);
            auto response = Router::makeErrorResponse(req, "Unauthorized: requires a session", status::unauthorized);
            std::visit([](auto& res) { res.keep_alive(false); }, response);
            (void)write_response(std::move(response));
            return false;
        }
        if (parser.content_length() && *parser.content_length() > maxBufferedBodyBytes()) {
            auto req = make_request_from_parser(parser);
            auto response = Router::makeErrorResponse(req, "Request body exceeds maximum buffered size",
                                                      status::payload_too_large);
            std::visit([](auto& res) { res.keep_alive(false); }, response);
            (void)write_response(std::move(response));
            return false;
        }
        return handle_buffered_request(parser);
    } catch (const std::exception& e) {
        if (stopping()) return false;
        log::Registry::http()->error("[Session] Exception during request handling: {}", e.what());
        auto req = make_request_from_parser(parser);
        return write_response(Router::makeErrorResponse(req, e.what(), statusForException(e))) && req.keep_alive();
    }
}

bool Session::handle_buffered_request(
    boost::beast::http::request_parser<boost::beast::http::buffer_body>& parser
) {
    std::string body;
    std::array<char, kReadBufferBytes> storage{};
    beast::error_code ec;

    while (!parser.is_done() && !stopping()) {
        parser.get().body().data = storage.data();
        parser.get().body().size = storage.size();
        boost::beast::http::read(*stream_, buffer_, parser, ec);

        const auto used = storage.size() - parser.get().body().size;
        if (used > 0) {
            if (body.size() + used > maxBufferedBodyBytes())
                throw std::runtime_error("Request body exceeds maximum buffered size");
            body.append(storage.data(), used);
        }

        if (ec == boost::beast::http::error::need_buffer) {
            ec = {};
            continue;
        }
        if (ec) throw boost::system::system_error(ec);
    }
    if (stopping()) return false;

    auto req = make_request_from_parser(parser, std::move(body));
    const auto keepAlive = req.keep_alive();
    const bool head = req.method() == verb::head;
    auto response = route(std::move(req));
    return write_response(std::move(response), head) && keepAlive;
}

bool Session::handle_streaming_upload(
    boost::beast::http::request_parser<boost::beast::http::buffer_body>& parser
) {
    auto req = make_request_from_parser(parser);
    const auto keepAlive = req.keep_alive();

    upload::Coordinator::FileStream stream;
    try {
        const auto contentLength = parser.content_length();
        stream = upload::Coordinator::instance().beginFile(
            req,
            contentLength ? std::make_optional(static_cast<uint64_t>(*contentLength)) : std::nullopt
        );

        std::array<char, kReadBufferBytes> storage{};
        beast::error_code ec;
        while (!parser.is_done() && !stopping()) {
            parser.get().body().data = storage.data();
            parser.get().body().size = storage.size();
            boost::beast::http::read(*stream_, buffer_, parser, ec);

            const auto used = storage.size() - parser.get().body().size;
            if (used > 0) stream.write(storage.data(), used);

            if (ec == boost::beast::http::error::need_buffer) {
                ec = {};
                continue;
            }
            if (ec) throw boost::system::system_error(ec);
        }
        if (stopping()) throw std::runtime_error("http_session_cancelled");

        auto data = stream.finish();
        return write_response(Router::makeJsonResponse(req, data)) && keepAlive;
    } catch (const std::exception& e) {
        stream.fail(e.what());
        if (stopping()) return false;
        auto response = Router::makeErrorResponse(req, e.what(), statusForException(e));
        std::visit([](auto& res) { res.keep_alive(false); }, response);
        (void)write_response(std::move(response));
        return false;
    }
}

bool Session::write_response(model::preview::Response&& response, const bool headRequest) {
    if (stopping()) return false;

    if (auto* streaming = std::get_if<model::preview::StreamResponse>(&response))
        return write_stream(std::move(*streaming));

    stream_->setTimeout(std::chrono::milliseconds(writeTimeoutMs.load()));
    beast::error_code ec;
    std::visit([this, &ec, headRequest](auto&& res) {
        using T = std::decay_t<decltype(res)>;
        if constexpr (!std::is_same_v<T, model::preview::StreamResponse>) {
            if (headRequest) {
                // HEAD: the same status and headers (including Content-Length) as GET, no body.
                boost::beast::http::serializer<false, typename T::body_type, typename T::fields_type> sr{res};
                boost::beast::http::write_header(*stream_, sr, ec);
            } else {
                boost::beast::http::write(*stream_, res, ec);
            }
        }
    }, response);

    if (ec) {
        log::Registry::http()->debug("[Session] Write error: {}", ec.message());
        return false;
    }
    return true;
}

bool Session::write_stream(model::preview::StreamResponse&& response) {
    namespace bhttp = boost::beast::http;
    auto onFinish = std::move(response.onFinish);
    const auto finish = [&onFinish](const uint64_t sent, const bool complete) {
        if (!onFinish) return;
        try {
            onFinish(sent, complete);
        } catch (const std::exception& e) {
            log::Registry::http()->warn("[Session] Stream completion hook failed: {}", e.what());
        }
    };

    const auto reader = std::move(response.reader);
    const auto offset = response.offset;
    const auto length = response.length;
    const auto headOnly = response.headOnly;
    const bool keepAlive = response.keepAlive;

    bhttp::response<bhttp::buffer_body> res{std::move(static_cast<bhttp::response_header<>&>(response))};
    res.keep_alive(keepAlive);
    const bool hasBody = !headOnly && reader && length > 0;
    if (res.result() != status::not_modified) res.content_length(length);
    res.body().data = nullptr;
    res.body().size = 0;
    res.body().more = hasBody;

    bhttp::response_serializer<bhttp::buffer_body> serializer{res};
    stream_->setTimeout(std::chrono::milliseconds(writeTimeoutMs.load()));
    beast::error_code ec;

    if (!hasBody) {
        if (headOnly) bhttp::write_header(*stream_, serializer, ec);
        else bhttp::write(*stream_, serializer, ec);
        finish(0, !ec);
        return !ec;
    }

    bhttp::write_header(*stream_, serializer, ec);
    if (ec) {
        finish(0, false);
        return false;
    }

    std::vector<uint8_t> chunk(static_cast<std::size_t>(std::min<uint64_t>(kStreamChunkBytes, length)));
    uint64_t sent = 0;
    bool failed = false;
    try {
        while (sent < length) {
            if (stopping()) {
                failed = true;
                break;
            }
            const auto want = static_cast<std::size_t>(std::min<uint64_t>(chunk.size(), length - sent));
            const auto n = reader->read(offset + sent, std::span<uint8_t>(chunk.data(), want));
            if (n == 0) throw std::runtime_error("content ended before its declared length");

            res.body().data = chunk.data();
            res.body().size = n;
            res.body().more = sent + n < length;
            bhttp::write(*stream_, serializer, ec);
            if (ec == bhttp::error::need_buffer) ec = {};
            if (ec) {
                failed = true;  // client went away or stalled past the deadline: stop reading/decrypting
                break;
            }
            sent += n;
        }
    } catch (const std::exception& e) {
        // The status line is already out: the only honest signal left is a truncated body + closed connection.
        log::Registry::http()->warn("[Session] Aborting stream after {} of {} bytes: {}", sent, length, e.what());
        failed = true;
    }
    std::fill(chunk.begin(), chunk.end(), uint8_t{0});

    const bool complete = !failed && sent == length;
    finish(sent, complete);
    return complete;
}

void Session::do_close() {
    stopRequested_.store(true, std::memory_order_release);
    std::scoped_lock lock(socketMutex_);
    nativeHandle_.store(-1, std::memory_order_release);
    beast::error_code ec;
    if (socket_) {
        socket_->shutdown(tcp::socket::shutdown_both, ec);
        ec.clear();
        socket_->close(ec);
        return;
    }
    if (device_ && device_->connection.transport) {
        // No op is in flight (each call waited for its own); the socket is closed on its strand.
        auto transport = device_->connection.transport;
        boost::asio::dispatch(transport->ws.get_executor(), [transport] {
            boost::system::error_code ignored;
            auto& socket = beast::get_lowest_layer(transport->ws);
            socket.shutdown(tcp::socket::shutdown_both, ignored);
            socket.close(ignored);
        });
    }
}

} // namespace vh::protocols::http
