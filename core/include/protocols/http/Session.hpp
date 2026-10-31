#pragma once

#include "device/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "protocols/http/Router.hpp"
#include "protocols/SessionLifetimes.hpp"
#include "protocols/ws/Fwd.hpp"

#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/asio.hpp>
#include <atomic>
#include <chrono>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>

namespace vh::protocols::http {

namespace beast = boost::beast;
namespace http = beast::http;
using tcp = boost::asio::ip::tcp;

// Blocking I/O with real deadlines over a connection's byte stream: plain TCP (TimedStream) or TLS on the device
// listener. Satisfies Beast's SyncReadStream/SyncWriteStream; each call moves at most one buffer of the sequence
// (read_some/write_some may be partial).
class ByteStream {
public:
    virtual ~ByteStream() = default;

    void setTimeout(const std::chrono::milliseconds timeout) { timeout_ = timeout; }

    template<class MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers, boost::system::error_code& ec) {
        for (auto it = boost::asio::buffer_sequence_begin(buffers); it != boost::asio::buffer_sequence_end(buffers); ++it)
            if (const boost::asio::mutable_buffer b(*it); b.size() > 0) return readSome(b, ec);
        ec = {};
        return 0;
    }
    template<class MutableBufferSequence>
    std::size_t read_some(const MutableBufferSequence& buffers) {
        boost::system::error_code ec;
        const auto n = read_some(buffers, ec);
        if (ec) throw boost::system::system_error(ec);
        return n;
    }
    template<class ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers, boost::system::error_code& ec) {
        for (auto it = boost::asio::buffer_sequence_begin(buffers); it != boost::asio::buffer_sequence_end(buffers); ++it)
            if (const boost::asio::const_buffer b(*it); b.size() > 0) return writeSome(b, ec);
        ec = {};
        return 0;
    }
    template<class ConstBufferSequence>
    std::size_t write_some(const ConstBufferSequence& buffers) {
        boost::system::error_code ec;
        const auto n = write_some(buffers, ec);
        if (ec) throw boost::system::system_error(ec);
        return n;
    }

protected:
    virtual std::size_t readSome(boost::asio::mutable_buffer buffer, boost::system::error_code& ec) = 0;
    virtual std::size_t writeSome(boost::asio::const_buffer buffer, boost::system::error_code& ec) = 0;

    std::chrono::milliseconds timeout_{std::chrono::seconds(30)};
};

// The accepted socket, non-blocking, every read/write waiting with poll() bounded by the current deadline
// (SO_RCVTIMEO/SO_SNDTIMEO are ignored by Asio's blocking ops).
class TimedStream final : public ByteStream {
public:
    explicit TimedStream(tcp::socket& socket) : socket_(socket) {}

protected:
    std::size_t readSome(boost::asio::mutable_buffer buffer, boost::system::error_code& ec) override;
    std::size_t writeSome(boost::asio::const_buffer buffer, boost::system::error_code& ec) override;

private:
    std::size_t io(bool reading, const std::function<std::size_t(boost::system::error_code&)>& op,
                   boost::system::error_code& ec);

    tcp::socket& socket_;
};

using HeaderParser = boost::beast::http::request_parser<boost::beast::http::buffer_body>;

// An HTTP connection on the device listener (/preview, /download, /upload, /transfer, /mcp): TLS is up, the first request's
// header is read, and who this is was settled by the client key. Requests run as the device's user (a Device
// principal, never a cookie); the share lanes are refused.
struct DeviceConnection {
    std::shared_ptr<ws::TlsTransport> transport;
    std::shared_ptr<const ::vh::device::Peer> peer;
    std::shared_ptr<identities::User> user;
    std::unique_ptr<ws::ConnectionSlot> slot;
    // POST /mcp (Streamable HTTP) for the principal; null answers 404.
    std::function<model::preview::Response(request&&, const std::shared_ptr<ws::Session>&)> mcp;
};

class Session : public std::enable_shared_from_this<Session> {
public:
    explicit Session(tcp::socket socket);

    Session(DeviceConnection connection, std::unique_ptr<HeaderParser> first, beast::flat_buffer buffer);
    ~Session();

    // A session for an accepted socket, registered so cancelAllActive() reaches it even before a pool thread runs it.
    [[nodiscard]] static std::shared_ptr<Session> open(tcp::socket socket);
    // The same for a device-listener connection; its principal joins the session manager.
    [[nodiscard]] static std::shared_ptr<Session> openDevice(DeviceConnection connection,
                                                             std::unique_ptr<HeaderParser> first,
                                                             beast::flat_buffer buffer);

    void run();
    void cancel() noexcept;

    static void cancelAllActive() noexcept;
    // Defaults: 20 s keep-alive idle, 60 s read/write inactivity.
    static void setTimeoutsForTesting(std::chrono::milliseconds idle, std::chrono::milliseconds io);
    // True once every session object (and so every socket) is gone; false if the timeout passed first.
    [[nodiscard]] static bool waitUntilNoneAlive(std::chrono::milliseconds timeout);
    // Device-listener sessions only (their sockets belong to the device listener's io_context).
    [[nodiscard]] static bool waitUntilNoDeviceSessionsAlive(std::chrono::milliseconds timeout);

private:
    struct Device;

    bool read_one();
    bool serve(HeaderParser& parser);
    [[nodiscard]] bool stopping() const noexcept;
    model::preview::Response route(request&& req);
    bool handle_buffered_request(boost::beast::http::request_parser<boost::beast::http::buffer_body>& parser);
    bool handle_streaming_upload(boost::beast::http::request_parser<boost::beast::http::buffer_body>& parser);
    bool handle_streaming_content(boost::beast::http::request_parser<boost::beast::http::buffer_body>& parser);
    // The device listener's /transfer calibration lanes (protocols/device/Transfer.hpp).
    bool handle_transfer(HeaderParser& parser);
    bool handle_resumable_part(boost::beast::http::request_parser<boost::beast::http::buffer_body>& parser);
    bool write_response(model::preview::Response&& response, bool headRequest = false);
    bool write_stream(model::preview::StreamResponse&& response);
    void do_close();

    static request make_request_from_parser(
        const boost::beast::http::request_parser<boost::beast::http::buffer_body>& parser,
        std::string body = {}
    );

    SessionLifetimes::Token lifetime_;   // first: released after the socket is destroyed
    std::optional<SessionLifetimes::Token> deviceLifetime_;
    std::optional<tcp::socket> socket_;  // plain connections
    std::unique_ptr<Device> device_;     // device-listener connections (TLS transport, principal, slot)
    std::unique_ptr<ByteStream> stream_;
    beast::flat_buffer buffer_;
    std::atomic<bool> stopRequested_{false};
    std::atomic<int> nativeHandle_{-1};
    std::mutex socketMutex_;
};

}
