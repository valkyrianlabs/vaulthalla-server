#pragma once

#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>

#include "WsProtocol.hpp"
#include "rbac/Actor.hpp"
#include "device/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "protocols/ws/Fwd.hpp"
#include "share/Fwd.hpp"

#include <atomic>
#include <functional>
#include <deque>
#include <memory>
#include <mutex>
#include <nlohmann/json.hpp>
#include <string>
#include <fstream>

struct UploadContext {
    std::string path;
    uint64_t expectedSize = 0;
    uint64_t bytesReceived = 0;
    std::ofstream file;
};

using RequestType = boost::beast::http::request<boost::beast::http::string_body>;

namespace vh::auth::model { struct TokenPair; }

namespace vh::protocols::ws {

namespace handler::fs { class Upload; }

namespace beast     = boost::beast;
namespace websocket = beast::websocket;
namespace asio      = boost::asio;
using tcp           = asio::ip::tcp;
using json          = nlohmann::json;

// Device and DevicePairing exist only on the device listener (mutual TLS, docs/pairing.md): a Device session is a
// paired device acting as its user (no tokens; authorized at the TLS handshake), a DevicePairing one a connection
// whose key is not a live device and may only pair.
enum class SessionMode { Unauthenticated, Human, SharePending, Share, Device, DevicePairing };

class Session : public std::enable_shared_from_this<Session> {
public:
    const std::string uuid{generateUUIDv4()};
    std::shared_ptr<identities::User> user{nullptr};
    std::shared_ptr<auth::model::TokenPair> tokens;
    // True once the websocket handshake finished. Until then the session is still being set up (tokens included).
    [[nodiscard]] bool handshakeComplete() const noexcept { return handshakeComplete_.load(std::memory_order_acquire); }

    std::string userAgent, ipAddress;
    // Who is on the other end for rate limiting: the forwarded client behind the local proxy, else the peer.
    // ipAddress stays the TCP peer (refresh tokens are bound to it).
    std::string clientAddress;
    const std::chrono::system_clock::time_point connectionOpenedAt = std::chrono::system_clock::now();

    explicit Session(const std::shared_ptr<Router>& router);
    ~Session();

    void accept(tcp::socket&& socket);
    // The device listener's /ws: TLS is up and the upgrade request read. `user` (the canonical object) makes a Device
    // session, null a pairing-only one.
    void acceptDevice(std::shared_ptr<TlsTransport> transport, const RequestType& req,
                      std::shared_ptr<const ::vh::device::Peer> peer, std::shared_ptr<identities::User> deviceUser);
    // A Device session with no websocket: the principal of a device-listener HTTP connection (/preview, /download,
    // /upload, /mcp). It is registered with the session manager like any device session, so revocation,
    // revokeSessions and the sweeper close it; `onClose` then ends the HTTP connection.
    [[nodiscard]] static std::shared_ptr<Session> devicePrincipal(std::shared_ptr<const ::vh::device::Peer> peer,
                                                                  std::shared_ptr<identities::User> deviceUser,
                                                                  std::function<void()> onClose);
    void send(json message);
    void close();
    // Closes once the reply to the command being handled has gone out (a device unpairing itself gets its answer).
    void closeAfterReply();

    void setAuthenticatedUser(const std::shared_ptr<identities::User>& u);
    void setPendingShareSession(std::string sessionId, std::string sessionToken);
    void setSharePrincipal(std::shared_ptr<vh::share::Principal> principal, std::string sessionToken);
    void clearShareSession();
    void setHandshakeRequest(const RequestType& req);
    // The server's connection-cap slot; released when the session closes (close() or destruction).
    void holdConnectionSlot(std::unique_ptr<ConnectionSlot> slot);

    void sendAccessTokenOnNextResponse() { sendAccessToken_ = true; }

    std::shared_ptr<handler::fs::Upload> getUploadHandler();
    [[nodiscard]] SessionMode mode() const noexcept { return mode_; }
    [[nodiscard]] bool isSharePending() const noexcept { return mode_ == SessionMode::SharePending; }
    [[nodiscard]] bool isShareMode() const noexcept { return mode_ == SessionMode::Share; }
    [[nodiscard]] bool isShareSession() const noexcept { return isSharePending() || isShareMode(); }
    [[nodiscard]] bool isDeviceSession() const noexcept { return mode_ == SessionMode::Device; }
    [[nodiscard]] bool isDevicePairing() const noexcept { return mode_ == SessionMode::DevicePairing; }
    // Either of the device listener's modes.
    [[nodiscard]] bool onDeviceListener() const noexcept { return isDeviceSession() || isDevicePairing(); }
    // The connection's device identity (device listener only, else null).
    [[nodiscard]] const std::shared_ptr<const ::vh::device::Peer>& devicePeer() const noexcept { return devicePeer_; }
    // True from the first close() on: nothing more is run for this session.
    [[nodiscard]] bool closing() const noexcept { return closing_.load(std::memory_order_acquire); }
    [[nodiscard]] std::shared_ptr<vh::share::Principal> sharePrincipal() const noexcept { return sharePrincipal_; }
    [[nodiscard]] vh::rbac::Actor rbacActor() const;
    [[nodiscard]] const std::string& shareSessionId() const noexcept { return shareSessionId_; }
    [[nodiscard]] const std::string& shareSessionToken() const noexcept { return shareSessionToken_; }

    // meta.hello (core/usage WsProtocol.hpp): the protocol version this session speaks, contract::kProtocolMin until the
    // client says hello. A handler that changes an answer's shape in a later protocol answers older sessions in the
    // shape they know.
    [[nodiscard]] int protocolVersion() const noexcept { return protocolVersion_.load(std::memory_order_acquire); }
    // What the client said it is in meta.hello (validated printable ASCII; empty when it didn't say), for the logs.
    struct ClientInfo {
        std::string name{}, version{};
    };
    [[nodiscard]] ClientInfo clientInfo() const;
    void setHello(int protocolVersion, ClientInfo client);

    static std::string generateUUIDv4();

private:
    // ---- lifecycle / io
    void startReadLoop();
    void doRead();
    void onRead(const beast::error_code& ec, std::size_t bytesRead);

    void maybeStartWrite();
    void doWrite();
    void onWrite(const beast::error_code& ec, std::size_t bytesWritten);
    void closeOnStrand();

    // ---- handshake helpers
    void onHeadersRead(const std::shared_ptr<RequestType>& req, const beast::error_code& ec, std::size_t bytesRead);
    void onHandshakeAccepted(const beast::error_code& ec);
    void hydrateFromRequest(const RequestType& req);
    void installHandshakeDecorator() const;

    // ---- misc helpers
    static void logFail(std::string_view where, const beast::error_code& ec);
    void sendParseError(std::string_view msg, const json& requestId = nullptr);
    void sendInternalError();
    [[nodiscard]] std::string getUserAgent() const;
    [[nodiscard]] std::string getIPAddress() const;

    // The websocket, over TCP (ws::Server) or TLS (the device listener); Session.cpp defines it.
    struct Stream;
    std::shared_ptr<Stream> stream_;
    asio::any_io_executor strand_;

    beast::flat_buffer buffer_{8192};
    beast::flat_buffer tmpBuffer_{4096}; // used during HTTP header read/handshake
    RequestType handshakeRequest_;

    std::shared_ptr<handler::fs::Upload> uploadHandler_{nullptr};

    std::shared_ptr<Router> router_;
    SessionMode mode_{SessionMode::Unauthenticated};
    std::shared_ptr<vh::share::Principal> sharePrincipal_{nullptr};
    std::string shareSessionId_;
    std::string shareSessionToken_;
    bool shareHandshake_{false};
    std::shared_ptr<const ::vh::device::Peer> devicePeer_;
    std::function<void()> onClose_;  // run once by the first close() (device HTTP principals)

    std::atomic_bool closing_{false};
    std::unique_ptr<ConnectionSlot> connectionSlot_;  // set before accept(); reset by the first close()

    bool writing_ = false;                 // only touched on strand
    std::deque<std::string> writeQueue_;   // only touched on strand
    bool closeAfterWrite_ = false;         // only touched on strand
    bool closeStarted_ = false;            // only touched on strand
    bool handshakeDone_ = false;           // only touched on strand
    std::atomic<bool> handshakeComplete_{false};  // the same fact, readable off the strand (the sweeper)
    bool externallyHttps_ = false;         // set during handshake hydration (cookie Secure flag)

    bool sendAccessToken_{false};

    std::atomic<int> protocolVersion_{contract::kProtocolMin};
    mutable std::mutex clientInfoMutex_;
    ClientInfo clientInfo_;
};

}
