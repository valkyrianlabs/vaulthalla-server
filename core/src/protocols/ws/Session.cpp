#include "protocols/ws/Session.hpp"

#include "auth/Manager.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "log/Registry.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/ConnectionLimit.hpp"
#include "protocols/ws/CookiePolicy.hpp"
#include "protocols/ws/Envelope.hpp"
#include "crypto/util/hash.hpp"
#include "protocols/ws/handler/fs/Upload.hpp"
#include "runtime/Deps.hpp"
#include "identities/User.hpp"
#include "protocols/cookie.hpp"
#include "rbac/Actor.hpp"
#include "share/Principal.hpp"
#include "device/Peer.hpp"
#include "protocols/ws/TlsTransport.hpp"

#include <boost/beast/http.hpp>
#include <boost/uuid/uuid.hpp>
#include <boost/uuid/uuid_generators.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <boost/asio.hpp>
#include <cstddef>
#include <string_view>

#include "config/Registry.hpp"

namespace {
namespace beast      = boost::beast;
namespace beast_http = boost::beast::http;
namespace websocket  = beast::websocket;
namespace asio       = boost::asio;

constexpr std::size_t kWebSocketReadBufferMaxBytes = 1024u * 1024u;

bool isShareHandshakeTarget(const std::string_view target) {
    constexpr std::string_view sharePath{"/ws/share"};
    return target == sharePath ||
           (target.starts_with(sharePath) && target.size() > sharePath.size() && target[sharePath.size()] == '?');
}
} // namespace

using vh::identities::User;
using vh::identities::Group;
using namespace vh::protocols;

namespace vh::protocols::ws {

// The websocket over plain TCP or over TLS. Session code is written once against either: visit() hands the concrete
// websocket::stream to a generic lambda, and both stream types share Beast's async API.
struct Session::Stream {
    using Plain = websocket::stream<tcp::socket>;

    std::shared_ptr<Plain> plain;
    std::shared_ptr<TlsTransport> tls;

    template<class F>
    decltype(auto) visit(F&& f) {
        if (tls) return std::forward<F>(f)(tls->ws);
        return std::forward<F>(f)(*plain);
    }

    tcp::socket& socket() {
        if (tls) return beast::get_lowest_layer(tls->ws);
        return beast::get_lowest_layer(*plain);
    }
};

Session::Session(const std::shared_ptr<Router>& router)
    : tokens(std::make_shared<auth::model::TokenPair>()), router_(router) {
    buffer_.max_size(kWebSocketReadBufferMaxBytes);
}

Session::~Session() {
    close();
    log::Registry::ws()->debug("[ws::Session] Session destroyed for IP: {}", getIPAddress());
}

std::string Session::getIPAddress() const {
    try {
        if (!stream_ || !stream_->socket().is_open()) return "unknown";
        return stream_->socket().remote_endpoint().address().to_string();
    } catch (...) {
        return "unknown";
    }
}

std::string Session::getUserAgent() const {
    if (const auto it = handshakeRequest_.find(beast_http::field::user_agent);
        it != handshakeRequest_.end()) return std::string(it->value());
    return  "unknown";
}

void Session::setAuthenticatedUser(const std::shared_ptr<User>& u) {
    if (!u) throw std::invalid_argument("Cannot set null authenticated user");
    if (u->systemOnly()) throw std::runtime_error("System-only users cannot authenticate WebSocket sessions");

    clearShareSession();
    user = u;
    mode_ = SessionMode::Human;
    if (!tokens->refreshToken) throw std::runtime_error("Cannot set authenticated user without a refresh token in session");
    tokens->refreshToken->userId = user->id;
}

void Session::setPendingShareSession(std::string sessionId, std::string sessionToken) {
    if (user) throw std::runtime_error("Cannot attach share session to authenticated user session");
    if (sessionId.empty()) throw std::invalid_argument("Share session id is required");
    if (sessionToken.empty()) throw std::invalid_argument("Share session token is required");

    sharePrincipal_.reset();
    shareSessionId_ = std::move(sessionId);
    shareSessionToken_ = std::move(sessionToken);
    mode_ = SessionMode::SharePending;
}

void Session::setSharePrincipal(std::shared_ptr<vh::share::Principal> principal, std::string sessionToken) {
    if (user) throw std::runtime_error("Cannot attach share principal to authenticated user session");
    if (!principal) throw std::invalid_argument("Share principal is required");
    if (sessionToken.empty()) throw std::invalid_argument("Share session token is required");

    shareSessionId_ = principal->share_session_id;
    shareSessionToken_ = std::move(sessionToken);
    sharePrincipal_ = std::move(principal);
    mode_ = SessionMode::Share;
}

void Session::clearShareSession() {
    sharePrincipal_.reset();
    shareSessionId_.clear();
    shareSessionToken_.clear();
    mode_ = user ? SessionMode::Human : SessionMode::Unauthenticated;
}

void Session::setHandshakeRequest(const RequestType& req) { handshakeRequest_ = req; }

void Session::holdConnectionSlot(std::unique_ptr<ConnectionSlot> slot) { connectionSlot_ = std::move(slot); }

std::shared_ptr<handler::fs::Upload> Session::getUploadHandler() {
    if (!uploadHandler_) uploadHandler_ = std::make_shared<handler::fs::Upload>(shared_from_this());
    return uploadHandler_;
}

vh::rbac::Actor Session::rbacActor() const {
    if (user) return vh::rbac::Actor::human(user);
    if (mode_ == SessionMode::Share && sharePrincipal_) return vh::rbac::Actor::share(sharePrincipal_);
    throw std::runtime_error("Unauthorized");
}

void Session::logFail(std::string_view where, const beast::error_code& ec) {
    if (!ec) return;
    log::Registry::ws()->debug("[ws::Session] {}: {}", where, ec.message());
}

void Session::accept(tcp::socket&& socket) {
    uploadHandler_ = std::make_shared<handler::fs::Upload>(shared_from_this());

    stream_ = std::make_shared<Stream>();
    stream_->plain = std::make_shared<Stream::Plain>(std::move(socket));
    strand_ = asio::make_strand(stream_->plain->get_executor());

    auto req = std::make_shared<RequestType>();
    auto self = shared_from_this();

    beast_http::async_read(
        stream_->plain->next_layer(),
        tmpBuffer_,
        *req,
        asio::bind_executor(
            strand_,
            [self, req](const beast::error_code& ec, std::size_t bytesRead) {
                self->onHeadersRead(req, ec, bytesRead);
            }));
}

void Session::onHeadersRead(const std::shared_ptr<RequestType>& req, const beast::error_code& ec, std::size_t) {
    // A connection that never became a websocket is closed (and leaves the session manager) right away instead of
    // waiting for the lifecycle sweep; until then it would hold a websocket_server.max_connections slot.
    if (ec) {
        logFail("Error reading HTTP headers", ec);
        return close();
    }
    if (closing_.load(std::memory_order_acquire)) return;

    // Hydration touches the DB and the secrets manager; a failure there must reject this one connection,
    // never escape into the shared io_context (which used to terminate the daemon, taking FUSE with it).
    try {
        hydrateFromRequest(*req);
    } catch (const std::exception& e) {
        log::Registry::ws()->error("[ws::Session] Rejecting handshake from IP {}: session hydration failed: {}",
                                   getIPAddress(), e.what());
        return close();  // pre-handshake: closeOnStrand shuts the TCP socket
    }
    if (closing_.load(std::memory_order_acquire)) return;  // closed during hydration (e.g. by the sweeper)

    auto self = shared_from_this();
    stream_->plain->async_accept(
        *req,
        asio::bind_executor(
            strand_,
            [self](const beast::error_code& ec2) {
                self->onHandshakeAccepted(ec2);
            }));
}

void Session::acceptDevice(std::shared_ptr<TlsTransport> transport, const RequestType& req,
                           std::shared_ptr<const ::vh::device::Peer> peer, std::shared_ptr<identities::User> deviceUser) {
    if (!transport || !peer) throw std::invalid_argument("device session needs its transport and peer");
    if (deviceUser && deviceUser->systemOnly()) throw std::runtime_error("System-only users cannot own devices");

    uploadHandler_ = std::make_shared<handler::fs::Upload>(shared_from_this());
    stream_ = std::make_shared<Stream>();
    stream_->tls = std::move(transport);
    strand_ = asio::make_strand(stream_->tls->ws.get_executor());

    // No cookies, tokens or forwarded headers here: who this is was settled by the client certificate.
    handshakeRequest_ = req;
    ipAddress = peer->address;
    clientAddress = peer->address;
    userAgent = getUserAgent();
    devicePeer_ = std::move(peer);
    user = std::move(deviceUser);
    mode_ = user ? SessionMode::Device : SessionMode::DevicePairing;

    auto& ws = stream_->tls->ws;
    // A paired Desktop keeps its connection open indefinitely; pings find the dead ones.
    auto timeouts = websocket::stream_base::timeout::suggested(beast::role_type::server);
    timeouts.idle_timeout = std::chrono::minutes(2);
    timeouts.keep_alive_pings = true;
    ws.set_option(timeouts);
    ws.set_option(websocket::stream_base::decorator([](websocket::response_type& res) {
        res.set(beast_http::field::server, "Vaulthalla");
    }));

    if (const auto manager = runtime::Deps::get().sessionManager) manager->cache(shared_from_this());

    auto self = shared_from_this();
    asio::dispatch(strand_, [self, req = std::make_shared<RequestType>(req)] {
        if (self->closing_.load(std::memory_order_acquire)) return self->closeOnStrand();
        self->stream_->tls->ws.async_accept(
            *req,
            asio::bind_executor(self->strand_, [self, req](const beast::error_code& ec) {
                self->onHandshakeAccepted(ec);
            }));
    });
}

Session::ClientInfo Session::clientInfo() const {
    std::scoped_lock lock(clientInfoMutex_);
    return clientInfo_;
}

void Session::setHello(const int protocolVersion, ClientInfo client) {
    {
        std::scoped_lock lock(clientInfoMutex_);
        clientInfo_ = std::move(client);
    }
    protocolVersion_.store(protocolVersion, std::memory_order_release);
}

std::shared_ptr<Session> Session::devicePrincipal(std::shared_ptr<const ::vh::device::Peer> peer,
                                                  std::shared_ptr<identities::User> deviceUser,
                                                  std::function<void()> onClose) {
    if (!peer || !deviceUser) throw std::invalid_argument("a device principal needs a paired device and its user");
    if (deviceUser->systemOnly()) throw std::runtime_error("System-only users cannot own devices");
    auto session = std::make_shared<Session>(std::make_shared<Router>());
    session->ipAddress = peer->address;
    session->clientAddress = peer->address;
    session->userAgent = "device-http";
    session->devicePeer_ = std::move(peer);
    session->user = std::move(deviceUser);
    session->mode_ = SessionMode::Device;
    session->onClose_ = std::move(onClose);
    session->handshakeComplete_.store(true, std::memory_order_release);  // nothing to hand-shake: the sweeper may judge it
    if (const auto manager = runtime::Deps::get().sessionManager) manager->cache(session);
    return session;
}

void Session::hydrateFromRequest(const RequestType& req) {
    log::Registry::ws()->debug("[ws::Session] Handshake request received from IP: {}", getIPAddress());

    handshakeRequest_ = req;
    ipAddress = getIPAddress();
    clientAddress = cookie_policy::clientAddress(
        ipAddress,
        std::string_view{req["X-Real-IP"].data(), req["X-Real-IP"].size()},
        std::string_view{req["X-Forwarded-For"].data(), req["X-Forwarded-For"].size()});
    userAgent = getUserAgent();
    shareHandshake_ = isShareHandshakeTarget(std::string_view{req.target().data(), req.target().size()});
    externallyHttps_ = cookie_policy::isExternallyHttps(
        ipAddress,
        std::string_view{req["X-Forwarded-Proto"].data(), req["X-Forwarded-Proto"].size()},
        std::string_view{req["Forwarded"].data(), req["Forwarded"].size()});

    log::Registry::ws()->debug(
        "[ws::Session] Attempting to hydrate {} session from request. IP: {}, User-Agent: {}",
        shareHandshake_ ? "share" : "human",
        ipAddress,
        userAgent
    );

    if (shareHandshake_) {
        auth::model::RefreshToken::addShareToSession(shared_from_this(), extractCookie(req, "share_refresh"));
        runtime::Deps::get().sessionManager->tryRehydrateShareRefresh(shared_from_this());
        log::Registry::ws()->debug("[ws::Session] Share refresh cookie {} present", tokens->shareRefreshToken && !tokens->shareRefreshToken->rawToken.empty() ? "is" : "is not");
        installHandshakeDecorator();
        return;
    }

    auth::model::RefreshToken::addToSession(shared_from_this(), extractCookie(req, "refresh"));
    log::Registry::ws()->debug("[ws::Session] Human refresh cookie {} present", tokens->refreshToken && !tokens->refreshToken->rawToken.empty() ? "is" : "is not");
    runtime::Deps::get().sessionManager->tryRehydrate(shared_from_this());

    if (user) log::Registry::ws()->debug("[ws::Session] Session hydrated with user: {} (ID: {})", user->name(), user->id);
    else {
        // The normal state of a connection before login: a fresh refresh token, no user yet. (This was logged as
        // critical for every anonymous connection.) What must hold is that the token exists and is valid.
        log::Registry::ws()->debug("[ws::Session] Anonymous session bootstrapped with a fresh refresh token");

        if (!tokens || !tokens->refreshToken) {
            // Reject this connection; a client request must never be able to exit the daemon.
            throw std::runtime_error("invariant violation: refresh token missing after hydration/bootstrap");
        }

        if (!tokens->refreshToken->isValid()) {
            throw std::runtime_error("invariant violation: refresh token invalid after hydration/bootstrap");
        }

        installHandshakeDecorator();
    }
}

void Session::installHandshakeDecorator() const {
    const auto token = shareHandshake_
                           ? (tokens ? tokens->shareRefreshToken : nullptr)
                           : (tokens ? tokens->refreshToken : nullptr);

    if (!token) {
        log::Registry::ws()->debug("[ws::Session] No refresh token available, skipping handshake decorator installation");
        return;
    }

    if (!stream_ || !stream_->plain) return;
    const auto& ws = stream_->plain;
    const auto t = token->rawToken;
    const auto cookieName = shareHandshake_ ? std::string{"share_refresh"} : std::string{"refresh"};
    const bool secureCookie = externallyHttps_;
    ws->set_option(websocket::stream_base::timeout::suggested(beast::role_type::server));
    ws->set_option(websocket::stream_base::decorator(
        [t, cookieName, secureCookie](websocket::response_type& res) {
            res.set(beast_http::field::server, "Vaulthalla");

            const bool isDev = config::Registry::get().dev.enabled;
            const std::string sameSite = isDev ? "Lax" : "Lax"; // keep Lax unless *need* Strict

            std::string cookie = cookieName + "=" + t +
                "; Path=/" +
                "; HttpOnly" +
                "; SameSite=" + sameSite +
                "; Max-Age=604800";

            if (secureCookie) cookie += "; Secure";

            // IMPORTANT: use insert to avoid clobbering other Set-Cookie headers
            res.insert(beast_http::field::set_cookie, cookie);
        }
    ));
}

void Session::onHandshakeAccepted(const beast::error_code& ec) {
    if (ec) {
        logFail("Handshake error", ec);
        return close();
    }
    handshakeDone_ = true;
    handshakeComplete_.store(true, std::memory_order_release);
    if (closing_.load(std::memory_order_acquire)) {
        // close() arrived mid-handshake; finish it now that a proper websocket close is possible.
        closeStarted_ = false;
        if (!writing_) closeOnStrand();
        return;
    }

    log::Registry::ws()->debug("[ws::Session] Handshake accepted from IP: {}", getIPAddress());
    maybeStartWrite();  // flush anything queued while the handshake was in flight
    startReadLoop();
}

void Session::startReadLoop() {
    doRead();
}

void Session::close() {
    if (closing_.exchange(true)) return;
    // Only the first close() gets here: give the connection-cap slot back now, not when the last handler lets go.
    connectionSlot_.reset();
    if (onClose_) {
        const auto hook = std::move(onClose_);
        try {
            hook();
        } catch (...) {
            log::Registry::ws()->debug("[ws::Session] close hook failed");
        }
    }

    auto self = weak_from_this().lock();
    if (self) {
        if (const auto manager = runtime::Deps::get().sessionManager)
            manager->remove(self);
    }

    if (uploadHandler_)
        uploadHandler_->abortActiveUpload("websocket_session_closed");

    auto stream = stream_;
    if (!stream) {
        buffer_.consume(buffer_.size());
        return;
    }

    if (!self) {
        // Destruction: nothing can be pending (every async op holds a reference), so the socket just goes.
        boost::system::error_code ec;
        stream->socket().shutdown(tcp::socket::shutdown_both, ec);
        stream->socket().close(ec);
        stream_.reset();
        buffer_.consume(buffer_.size());
        return;
    }

    asio::post(strand_, [self]() mutable {
        self->closeAfterWrite_ = true;
        if (self->writing_) return;
        self->writeQueue_.clear();
        self->closeOnStrand();
    });
}

void Session::closeAfterReply() {
    auto self = weak_from_this().lock();
    if (!self || !stream_) return close();
    // The handler's reply is posted to the strand after this returns; posting the close from a strand handler puts it
    // behind that reply, and close() then waits for the write in flight (closeAfterWrite_).
    asio::post(strand_, [self] { asio::post(self->strand_, [self] { self->close(); }); });
}

void Session::send(json message) {
    if (closing_.load(std::memory_order_acquire)) return;

    if (sendAccessToken_) {
        if (!tokens || !tokens->accessToken) {
            log::Registry::ws()->debug("[ws::Session] Attempted to send access token, but no access token is available in session");
            throw std::runtime_error("No access token available in session");
        }

        message["token"] = tokens->accessToken->rawToken;
        sendAccessToken_ = false;
    }

    auto payload = message.dump();
    auto self = shared_from_this();

    asio::post(strand_, [self, payload = std::move(payload)]() mutable {
        if (self->closing_.load(std::memory_order_acquire) || !self->stream_) return;
        self->writeQueue_.push_back(std::move(payload));
        self->maybeStartWrite();
    });
}

void Session::closeOnStrand() {
    // The stream lives as long as the Session: pending async ops hold `self`, and resetting ws_ under
    // them left handlers dereferencing a null stream (vh-storage SIGSEGV in installHandshakeDecorator
    // under connection churn) and reads running on a destroyed socket.
    if (!stream_ || closeStarted_) {
        buffer_.consume(buffer_.size());
        return;
    }
    if (writing_) {  // never overlap the close with an in-flight write; onWrite comes back here
        closeAfterWrite_ = true;
        return;
    }
    closeStarted_ = true;

    if (!handshakeDone_ || !stream_->visit([](auto& ws) { return ws.is_open(); })) {
        // No websocket session yet (still reading the upgrade request or mid-handshake): closing the TCP
        // socket cancels the pending op, whose handler sees closing_ and stops.
        beast::error_code ignored;
        stream_->socket().shutdown(tcp::socket::shutdown_both, ignored);
        stream_->socket().close(ignored);
        buffer_.consume(buffer_.size());
        log::Registry::ws()->debug("[ws::Session] Closed pre-handshake connection for IP: {}", ipAddress);
        return;
    }

    // Never the synchronous close(): it writes the close frame and then *reads* until the peer answers,
    // racing this session's always-pending async_read and corrupting Beast's op locks (soft_mutex abort,
    // "server must not mask frames" in browsers). async_close is the one close op allowed alongside a
    // pending read; callers only get here once no write is in flight (closeAfterWrite_).
    stream_->visit([this](auto& ws) {
        ws.async_close(
            websocket::close_code::normal,
            asio::bind_executor(
                strand_,
                [self = shared_from_this()](const beast::error_code& ec) {
                    if (ec) log::Registry::ws()->debug("[ws::Session] ws close error: {}", ec.message());
                    self->buffer_.consume(self->buffer_.size());
                    log::Registry::ws()->debug("[ws::Session] Closed session for IP: {}", self->ipAddress);
                }));
    });
}

void Session::maybeStartWrite() {
    // Writes wait for the websocket handshake: async_accept is itself writing the 101 response, and Beast
    // allows a single write op per stream. Sessions are reachable (sweeper, broadcasts) before they finish
    // the handshake; starting an async_write then tripped Beast's soft_mutex assertion (vh-storage churn).
    if (writing_ || writeQueue_.empty() || !handshakeDone_ || closeStarted_) return;
    writing_ = true;
    doWrite();
}

void Session::doWrite() {
    if (!stream_ || closeStarted_) {
        writing_ = false;
        writeQueue_.clear();
        return;
    }

    stream_->visit([this](auto& ws) {
        ws.async_write(
            asio::buffer(writeQueue_.front()),
            asio::bind_executor(
                strand_,
                [self = shared_from_this()](const beast::error_code& ec, std::size_t bytesWritten) {
                    self->onWrite(ec, bytesWritten);
                }));
    });
}

void Session::onWrite(const beast::error_code& ec, std::size_t) {
    if (ec) {
        logFail("Write error", ec);
        writing_ = false;
        writeQueue_.clear();
        if (closeAfterWrite_) closeOnStrand();
        return;
    }

    if (!writeQueue_.empty()) writeQueue_.pop_front();
    if (closeAfterWrite_) {
        writing_ = false;
        writeQueue_.clear();
        closeOnStrand();
        return;
    }

    if (writeQueue_.empty()) {
        writing_ = false;
        return;
    }

    doWrite();
}

void Session::doRead() {
    if (!stream_) return;

    stream_->visit([this](auto& ws) {
        ws.async_read(
            buffer_,
            asio::bind_executor(
                strand_,
                [self = shared_from_this()](const beast::error_code& ec, const std::size_t bytesRead) {
                    self->onRead(ec, bytesRead);
                }));
    });
}

void Session::sendParseError(const std::string_view msg, const json& requestId) {
    send(envelope::parseError(msg, requestId));
}

void Session::sendInternalError() {
    send(envelope::internalError());
}

void Session::onRead(const beast::error_code& ec, std::size_t) {
    if (ec == websocket::error::closed) {
        log::Registry::ws()->debug("[ws::Session] WebSocket closed gracefully by peer");
        return close();
    }
    if (ec == asio::error::eof) {
        log::Registry::ws()->debug("[ws::Session] WebSocket peer vanished (EOF)");
        return close();
    }
    if (ec) {
        logFail("Read error", ec);
        return close();
    }

    if (stream_->visit([](auto& ws) { return ws.got_binary(); })) {
        try {
            uploadHandler_->handleBinaryFrame(buffer_);
        } catch (const std::exception& ex) {
            log::Registry::ws()->debug("[ws::Session] Error processing binary upload frame: {}", ex.what());
            sendInternalError();
        } catch (...) {
            log::Registry::ws()->debug("[ws::Session] Unknown error while processing binary upload frame");
            sendInternalError();
        }
    } else {
        // A bad frame gets a parse_error answer (with the frame's requestId when it has one the client can match)
        // and the session keeps reading.
        json message;
        bool parsed = false;
        try {
            message = json::parse(beast::buffers_to_string(buffer_.data()));
            parsed = true;
        } catch (const std::exception& ex) {
            log::Registry::ws()->debug("[ws::Session] Error parsing message: {}", ex.what());
            sendParseError(std::string("Failed to parse message: ") + ex.what());
        }
        if (parsed) {
            if (const auto problem = envelope::problem(message)) {
                log::Registry::ws()->debug("[ws::Session] Unroutable message: {}", *problem);
                sendParseError(*problem, envelope::requestId(message));
            } else {
                try {
                    router_->routeMessage(std::move(message), shared_from_this());
                } catch (const std::exception& ex) {
                    log::Registry::ws()->debug("[ws::Session] Error processing message: {}", ex.what());
                    sendInternalError();
                } catch (...) {
                    log::Registry::ws()->debug("[ws::Session] Unknown error while processing message");
                    sendInternalError();
                }
            }
        }
    }

    buffer_.consume(buffer_.size());
    doRead();
}

std::string Session::generateUUIDv4() {
    static boost::uuids::random_generator generator;
    const boost::uuids::uuid uuid = generator();
    return boost::uuids::to_string(uuid);
}

}
