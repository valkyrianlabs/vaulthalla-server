#include "protocols/ProtocolService.hpp"
#include "crypto/password/Strength.hpp"
#include "config/Registry.hpp"
#include "config/Config.hpp"
#include "protocols/ws/Server.hpp"
#include "protocols/http/Server.hpp"
#include "protocols/http/Session.hpp"
#include "protocols/http/upload/Coordinator.hpp"
#include "protocols/http/upload/Resumable.hpp"
#include "protocols/SessionLifetimes.hpp"
#include "log/Registry.hpp"

#include <boost/asio/io_context.hpp>
#include <algorithm>
#include <chrono>
#include <sodium.h>

namespace vh::protocols {

namespace {
// Sessions are cancelled before the drain; one still alive after this is stuck in a slow call.
constexpr std::chrono::seconds kHttpSessionDrainTimeout{3};
}

ProtocolService::ProtocolService() : AsyncService("ProtocolService") {}

ProtocolService::RuntimeStatus ProtocolService::protocolStatus() const noexcept {
    return {
        .running = isRunning(),
        .ioContextInitialized = ioContextInitialized_.load(std::memory_order_acquire),
        .websocketConfigured = websocketConfigured_.load(std::memory_order_acquire),
        .websocketReady = websocketReady_.load(std::memory_order_acquire),
        .httpPreviewConfigured = httpPreviewConfigured_.load(std::memory_order_acquire),
        .httpPreviewReady = httpPreviewReady_.load(std::memory_order_acquire)
    };
}

void ProtocolService::runLoop() {
    try {
        if (sodium_init() < 0) throw std::runtime_error("libsodium initialization failed");
        initThreatIntelligence();
        initProtocols();

        while (!shouldStop()) lazySleep(std::chrono::seconds(1));

        shutdownProtocols();
    } catch (const std::exception& e) {
        log::Registry::runtime()->error("[ProtocolService] Exception in run loop: {}", e.what());
        shutdownProtocols();
    } catch (...) {
        log::Registry::runtime()->error("[ProtocolService] Unknown exception in run loop");
        shutdownProtocols();
    }
}

void ProtocolService::onStop() {
    shutdownProtocols();
}

void ProtocolService::initProtocols() {
    std::scoped_lock lock(lifecycleMutex_);
    const auto& cfg = vh::config::Registry::get();
    ioContextInitialized_.store(false, std::memory_order_release);
    websocketConfigured_.store(cfg.websocket.enabled, std::memory_order_release);
    httpPreviewConfigured_.store(cfg.http_preview.enabled, std::memory_order_release);
    websocketReady_.store(false, std::memory_order_release);
    httpPreviewReady_.store(false, std::memory_order_release);

    if (!cfg.websocket.enabled && !cfg.http_preview.enabled) {
        log::Registry::runtime()->warn(
            "[ProtocolService] Both WebSocket and HTTP preview servers are disabled in configuration. Nothing to start.");
        return;
    }

    ioContext_ = std::make_shared<asio::io_context>();
    ioContextInitialized_.store(true, std::memory_order_release);

    initWebsocketServer();
    initHttpServer();

    const auto threads = std::clamp(std::thread::hardware_concurrency(), 2u, 8u);
    ioThreads_.reserve(threads);
    for (unsigned i = 0; i < threads; ++i)
        ioThreads_.emplace_back([ctx = ioContext_] {
            // Exceptions thrown by completion handlers propagate out of run(); an uncaught one would terminate
            // the whole daemon (FUSE included). Log it and keep serving: run() can be called again.
            for (;;) {
                try {
                    ctx->run();
                    return;
                } catch (const std::exception& e) {
                    log::Registry::runtime()->error("[ProtocolService] Unhandled exception in a protocol handler: {}", e.what());
                } catch (...) {
                    log::Registry::runtime()->error("[ProtocolService] Unhandled non-standard exception in a protocol handler");
                }
            }
        });
    log::Registry::runtime()->info("[ProtocolService] Serving protocols on {} io threads", threads);
}


void ProtocolService::initWebsocketServer() {
    const auto& cfg = vh::config::Registry::get().websocket;
    if (!cfg.enabled) {
        log::Registry::runtime()->info("[ProtocolService] WebSocket server is disabled in configuration.");
        return;
    }

    const auto endpoint = asio::ip::tcp::endpoint(asio::ip::make_address(cfg.host), cfg.port);
    wsServer_ = std::make_shared<ws::Server>(*ioContext_, endpoint);
    wsServer_->run();
    websocketReady_.store(true, std::memory_order_release);
}

void ProtocolService::initHttpServer() {
    const auto& cfg = vh::config::Registry::get().http_preview;
    if (!cfg.enabled) {
        log::Registry::runtime()->info("[ProtocolService] HTTP preview server is disabled in configuration.");
        return;
    }

    const auto endpoint = asio::ip::tcp::endpoint(asio::ip::make_address(cfg.host), cfg.port);
    httpServer_ = std::make_shared<http::Server>(*ioContext_, endpoint);
    httpServer_->run();
    httpPreviewReady_.store(true, std::memory_order_release);
}

void ProtocolService::shutdownProtocols() noexcept {
    std::scoped_lock lock(lifecycleMutex_);
    try {
        websocketReady_.store(false, std::memory_order_release);
        httpPreviewReady_.store(false, std::memory_order_release);

        if (!httpServer_ && !wsServer_ && !ioContext_ && ioThreads_.empty()) {
            ioContextInitialized_.store(false, std::memory_order_release);
            return;
        }

        if (httpServer_) httpServer_->close();
        if (wsServer_) wsServer_->close();
        http::Session::cancelAllActive();
        http::upload::Coordinator::instance().abortAll("http_service_stopping");
        // Sealing and commit steps finish the step they are in; resumable sessions themselves survive the restart.
        http::upload::resumable::Service::shutdown();
        if (ioContext_) ioContext_->stop();
        for (auto& thread : ioThreads_) {
            if (!thread.joinable()) continue;
            // Stopping from inside a handler can't join its own thread; let it finish on its own.
            if (std::this_thread::get_id() == thread.get_id()) thread.detach();
            else thread.join();
        }
        ioThreads_.clear();
        // Again for any accepted before the stop; there are no accepts after the joins.
        http::Session::cancelAllActive();
    } catch (const std::exception& e) {
        log::Registry::runtime()->error("[ProtocolService] Shutdown failed: {}", e.what());
    } catch (...) {
        log::Registry::runtime()->error("[ProtocolService] Shutdown failed: unknown exception");
    }

    wsServer_.reset();
    httpServer_.reset();
    // Preview sessions run on pool threads with sockets bound to ioContext_; it outlives every one of them.
    if (ioContext_ && !http::Session::waitUntilNoneAlive(kHttpSessionDrainTimeout)) {
        log::Registry::runtime()->error("[ProtocolService] HTTP sessions still running {}s after shutdown; keeping their io_context",
                                        kHttpSessionDrainTimeout.count());
        retainForProcessLifetime(std::move(ioContext_));
    }
    ioContext_.reset();
    ioContextInitialized_.store(false, std::memory_order_release);
}

void ProtocolService::initThreatIntelligence() {
    vh::crypto::password::Strength::loadCommonWeakPasswordsFromURLs(
            {"https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/"
             "100k-most-used-passwords-NCSC.txt",
             "https://raw.githubusercontent.com/danielmiessler/SecLists/refs/heads/master/Passwords/Common-Credentials/"
             "probable-v2_top-12000.txt"});

    vh::crypto::password::Strength::loadDictionaryFromURL(
        "https://raw.githubusercontent.com/dolph/dictionary/refs/heads/master/popular.txt");
}

}
