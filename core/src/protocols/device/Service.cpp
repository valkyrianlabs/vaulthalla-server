#include "protocols/device/Service.hpp"

#include "auth/session/Manager.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "log/Registry.hpp"
#include "protocols/device/Listener.hpp"
#include "protocols/http/Session.hpp"
#include "protocols/SessionLifetimes.hpp"
#include "protocols/ws/ConnectionLimit.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"

#include <boost/asio/executor_work_guard.hpp>
#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ssl/context.hpp>

#include <chrono>
#include <functional>

namespace vh::protocols::device {

namespace asio = boost::asio;

namespace {

constexpr unsigned kIoThreads = 4;
constexpr auto kRetryBind = std::chrono::seconds(30);
// Close frames of the sessions closed at shutdown get this long to go out before the io_context stops.
constexpr auto kCloseGrace = std::chrono::milliseconds(200);
constexpr auto kHttpDrainTimeout = std::chrono::seconds(3);

using WorkGuard = asio::executor_work_guard<asio::io_context::executor_type>;

std::size_t closeIf(const std::function<bool(const ws::Session&)>& pred) {
    const auto manager = runtime::Deps::get().sessionManager;
    if (!manager) return 0;
    std::size_t closed = 0;
    for (const auto& [_, session] : manager->getActive()) {
        if (!session || !session->onDeviceListener() || !pred(*session)) continue;
        session->close();
        ++closed;
    }
    return closed;
}

bool isLoopback(const std::string& address) {
    boost::system::error_code ec;
    const auto parsed = asio::ip::make_address(address, ec);
    if (ec) return false;
    if (parsed.is_v6() && parsed.to_v6().is_v4_mapped())
        return asio::ip::make_address_v4(asio::ip::v4_mapped, parsed.to_v6()).is_loopback();
    return parsed.is_loopback();
}

}

std::size_t closeDeviceSessions(const uint32_t deviceRowId, const vh::device::Peer* spare) {
    return closeIf([&](const ws::Session& s) {
        return s.devicePeer() && s.devicePeer()->deviceRowId == deviceRowId && s.devicePeer().get() != spare;
    });
}

std::size_t closeRemoteDeviceSessions() {
    return closeIf([](const ws::Session& s) { return !s.devicePeer() || !isLoopback(s.devicePeer()->address); });
}

std::size_t closeAllDeviceListenerSessions() {
    return closeIf([](const ws::Session&) { return true; });
}

Service::Service() : AsyncService("DeviceServer") {}

Service::~Service() { stop(); }

ListenerStatus Service::listenerStatus() const {
    std::scoped_lock lock(mutex_);
    const auto cfg = config::Registry::get().device_server;
    ListenerStatus out{.enabled = cfg.enabled, .remote = cfg.remote, .port = cfg.port};
    out.listening = !bound_.empty();
    if (out.listening) {
        out.address = bound_.front();
        out.bind = bound_;
        out.bound_port = boundPort_;
        out.ipv6 = boundIpv6_;
    }
    out.error = error_;
    if (const auto identity = vh::device::currentServerIdentity()) out.server_spki_sha256 = identity->spkiHex();
    out.connections = ws::ConnectionSlot::active(ws::ConnectionSlot::Pool::Device);
    return out;
}

void Service::setIdentityForTesting(std::shared_ptr<const vh::device::ServerIdentity> identity) {
    std::scoped_lock lock(mutex_);
    identity_ = std::move(identity);
    vh::device::setCurrentServerIdentity(identity_);
    tls_.reset();
}

void Service::ensureIdentityLocked() {
    if (!identity_) {
        identity_ = vh::device::loadOrCreateServerIdentity();
        vh::device::setCurrentServerIdentity(identity_);
        log::Registry::runtime()->info("[DeviceServer] Server identity loaded (SPKI sha256 {})", identity_->spkiHex());
    }
    if (!tls_) tls_ = makeServerContext(*identity_);
    if (!router_) {
        router_ = std::make_shared<ws::Router>();
        ws::Handler::registerAllHandlers(router_);
    }
    if (!ioc_) {
        ioc_ = std::make_shared<asio::io_context>();
        // The work guard keeps the threads up while the listener is closed between two binds.
        auto guard = std::make_shared<WorkGuard>(asio::make_work_guard(*ioc_));
        threads_.reserve(kIoThreads);
        for (unsigned i = 0; i < kIoThreads; ++i)
            threads_.emplace_back([ctx = ioc_, guard] {
                for (;;) {
                    try {
                        ctx->run();
                        return;
                    } catch (const std::exception& e) {
                        log::Registry::runtime()->error("[DeviceServer] Unhandled exception in a handler: {}", e.what());
                    } catch (...) {
                        log::Registry::runtime()->error("[DeviceServer] Unhandled non-standard exception in a handler");
                    }
                }
            });
    }
}

void Service::bindLocked(const bool logFailure) {
    const auto cfg = config::Registry::get().device_server;
    if (!listener_) listener_ = std::make_shared<Listener>(*ioc_, tls_, router_, cfg.max_connections);
    listener_->setMaxConnections(cfg.max_connections);
    std::vector<std::string> notes;  // what was tried and given up on, for the log
    try {
        if (cfg.remote) {
            try {
                listener_->listen({asio::ip::address_v6::any(), cfg.port});
            } catch (const std::exception& e) {
                // IPv6 disabled (or no dual-stack sockets): IPv4 on every interface still serves every client.
                notes.emplace_back(e.what());
                listener_->listen({asio::ip::address_v4::any(), cfg.port});
            }
        } else {
            listener_->listen({asio::ip::address_v4::loopback(), cfg.port});
            try {
                listener_->listenAlso({asio::ip::address_v6::loopback(), listener_->localEndpoint().port()});
            } catch (const std::exception& e) {
                notes.emplace_back(e.what());
            }
        }
    } catch (const std::exception& e) {
        bound_.clear();
        error_ = e.what();
        if (logFailure)
            log::Registry::runtime()->warn("[DeviceServer] {} (retrying every {}s; `vh device remote status` shows it)",
                                           e.what(), kRetryBind.count());
        return;
    }
    bound_.clear();
    boundIpv6_ = false;
    for (const auto& ep : listener_->localEndpoints()) {
        const auto host = ep.address().is_v6() ? "[" + ep.address().to_string() + "]" : ep.address().to_string();
        bound_.push_back(host + ":" + std::to_string(ep.port()));
        boundIpv6_ = boundIpv6_ || ep.address().is_v6();
    }
    boundPort_ = listener_->localEndpoint().port();
    boundRemote_ = cfg.remote;
    error_.reset();
    std::string joined;
    for (const auto& b : bound_) joined += (joined.empty() ? "" : ", ") + b;
    log::Registry::runtime()->info("[DeviceServer] Listening on {} ({})", joined,
                                   cfg.remote ? "remote connections on" : "loopback only");
    for (const auto& note : notes) log::Registry::runtime()->info("[DeviceServer] Not listening on IPv6: {}", note);
}

ListenerStatus Service::applyConfig() {
    bool closeRemote = false;
    {
        std::scoped_lock lock(mutex_);
        const auto cfg = config::Registry::get().device_server;
        closeRemote = !cfg.remote;
        if (isRunning()) {
            const bool wanted = cfg.enabled;
            const bool bound = !bound_.empty();
            const bool same = bound && boundRemote_ == cfg.remote && (cfg.port == 0 || boundPort_ == cfg.port);
            if (!wanted) {
                if (listener_) listener_->close();
                bound_.clear();
                error_.reset();
            } else if (!same) {
                if (listener_) listener_->close();
                bound_.clear();
                try {
                    ensureIdentityLocked();
                    bindLocked(true);
                } catch (const std::exception& e) {
                    error_ = e.what();
                    log::Registry::runtime()->error("[DeviceServer] {}", e.what());
                }
            }
        }
    }
    if (closeRemote) {
        if (const auto n = closeRemoteDeviceSessions())
            log::Registry::runtime()->info("[DeviceServer] Remote connections off: closed {} remote device session(s)", n);
    }
    if (!config::Registry::get().device_server.enabled) closeAllDeviceListenerSessions();
    return listenerStatus();
}

void Service::runLoop() {
    auto nextAttempt = std::chrono::steady_clock::now();
    bool failureLogged = false;
    while (!shouldStop()) {
        {
            std::scoped_lock lock(mutex_);
            const auto cfg = config::Registry::get().device_server;
            const auto now = std::chrono::steady_clock::now();
            if (cfg.enabled && bound_.empty() && now >= nextAttempt) {
                try {
                    ensureIdentityLocked();
                    bindLocked(!failureLogged);
                } catch (const std::exception& e) {
                    error_ = e.what();
                    if (!failureLogged)
                        log::Registry::runtime()->error("[DeviceServer] Cannot start: {} (retrying every {}s)", e.what(),
                                                        kRetryBind.count());
                }
                failureLogged = bound_.empty();
                if (failureLogged) nextAttempt = now + kRetryBind;
            }
        }
        lazySleep(std::chrono::seconds(1));
    }
    shutdown();
}

void Service::onStop() {}

void Service::shutdown() noexcept {
    try {
        std::scoped_lock lock(mutex_);
        if (listener_) listener_->close();
        listener_.reset();
        bound_.clear();
        if (ioc_) {
            closeAllDeviceListenerSessions();  // HTTP connections end with their principals
            std::this_thread::sleep_for(kCloseGrace);
            // HTTP sessions run on their own threads with sockets on this io_context: it outlives every one of them.
            const bool drained = protocols::http::Session::waitUntilNoDeviceSessionsAlive(kHttpDrainTimeout);
            ioc_->stop();
            for (auto& t : threads_)
                if (t.joinable()) t.join();
            threads_.clear();
            if (!drained) {
                log::Registry::runtime()->error("[DeviceServer] HTTP sessions still running {}s after shutdown; keeping "
                                                "their io_context", kHttpDrainTimeout.count());
                retainForProcessLifetime(std::move(ioc_));
            }
            ioc_.reset();
        }
    } catch (const std::exception& e) {
        log::Registry::runtime()->error("[DeviceServer] Shutdown failed: {}", e.what());
    }
}

}
