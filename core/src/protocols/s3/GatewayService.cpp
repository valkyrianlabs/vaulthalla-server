#include "protocols/s3/GatewayService.hpp"

#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "protocols/s3/MultipartStore.hpp"
#include "protocols/s3/RequestBody.hpp"
#include "protocols/s3/Server.hpp"
#include "protocols/s3/Session.hpp"
#include "protocols/SessionLifetimes.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/system/error_code.hpp>
#include <chrono>
#include <stdexcept>

namespace vh::protocols::s3 {

namespace asio = boost::asio;

namespace {
// Sessions are cancelled before the drain; one still alive after this is stuck in a slow call.
constexpr std::chrono::seconds kSessionDrainTimeout{3};

asio::ip::address bindAddressForHost(const std::string& host) {
    if (host.empty() || host == "*") return asio::ip::make_address("0.0.0.0");
    if (host == "localhost") return asio::ip::make_address("127.0.0.1");

    boost::system::error_code ec;
    const auto address = asio::ip::make_address(host, ec);
    if (!ec) return address;

    throw std::runtime_error("S3 gateway host must be an IP address, localhost, or '*': " + host);
}
}

void sweepStagingAtStartup() noexcept {
    (void)sweepRequestBodiesAtStartup();
    try {
        (void)MultipartStore{}.sweepAtStartup();
    } catch (const std::exception& e) {
        log::Registry::runtime()->error("[S3Gateway] Multipart part store sweep failed (nothing removed): {}", e.what());
    }
}

GatewayService::GatewayService() : AsyncService("S3GatewayService") {}

GatewayService::RuntimeStatus GatewayService::gatewayStatus() const noexcept {
    const auto metrics = Session::metrics();
    return {
        .running = isRunning(),
        .configured = configured_.load(std::memory_order_acquire),
        .ready = ready_.load(std::memory_order_acquire),
        .host = host_,
        .port = port_,
        .activeSessions = metrics.activeSessions,
        .totalRequests = metrics.totalRequests,
        .failedRequests = metrics.failedRequests
    };
}

void GatewayService::runLoop() {
    try {
        const auto& cfg = config::Registry::get().s3_gateway;
        host_ = cfg.host;
        port_ = cfg.port;
        configured_.store(cfg.enabled, std::memory_order_release);
        ready_.store(false, std::memory_order_release);

        if (!cfg.enabled) {
            log::Registry::runtime()->info("[S3GatewayService] Disabled in configuration.");
            while (!shouldStop()) lazySleep(std::chrono::seconds(1));
            return;
        }

        initGateway();

        while (!shouldStop())
            lazySleep(std::chrono::seconds(1));

        shutdownGateway();
    } catch (const std::exception& e) {
        log::Registry::runtime()->error("[S3GatewayService] Exception in run loop: {}", e.what());
        shutdownGateway();
        throw;
    } catch (...) {
        log::Registry::runtime()->error("[S3GatewayService] Unknown exception in run loop");
        shutdownGateway();
        throw;
    }
}

void GatewayService::onStop() {
    shutdownGateway();
}

void GatewayService::initGateway() {
    std::scoped_lock lock(lifecycleMutex_);
    const auto& cfg = config::Registry::get().s3_gateway;

    ioContext_ = std::make_shared<asio::io_context>();
    const auto address = bindAddressForHost(cfg.host);
    const auto endpoint = asio::ip::tcp::endpoint(address, cfg.port);

    server_ = std::make_shared<Server>(*ioContext_, endpoint, 1);
    server_->run();
    ready_.store(true, std::memory_order_release);

    ioThread_ = std::thread([ctx = ioContext_] {
        ctx->run();
    });

    log::Registry::runtime()->info("[S3GatewayService] Ready on {}:{}", cfg.host, cfg.port);
}

void GatewayService::shutdownGateway() noexcept {
    std::scoped_lock lock(lifecycleMutex_);
    try {
        ready_.store(false, std::memory_order_release);
        if (!server_ && !ioContext_ && !ioThread_.joinable()) return;

        if (server_) server_->close();
        if (ioContext_) ioContext_->stop();
        if (ioThread_.joinable() && std::this_thread::get_id() != ioThread_.get_id()) ioThread_.join();
        // No accepts after the join, so this reaches every session, queued ones included.
        Session::cancelAllActive();
    } catch (const std::exception& e) {
        log::Registry::runtime()->error("[S3GatewayService] Shutdown failed: {}", e.what());
    } catch (...) {
        log::Registry::runtime()->error("[S3GatewayService] Shutdown failed: unknown exception");
    }

    server_.reset();
    // Sessions run on pool threads with sockets bound to ioContext_; it outlives every one of them.
    if (ioContext_ && !Session::waitUntilNoneAlive(kSessionDrainTimeout)) {
        log::Registry::runtime()->error("[S3GatewayService] {} session(s) still running {}s after shutdown; keeping their io_context",
                                        Session::metrics().activeSessions, kSessionDrainTimeout.count());
        protocols::retainForProcessLifetime(std::move(ioContext_));
    }
    ioContext_.reset();
}

} // namespace vh::protocols::s3
