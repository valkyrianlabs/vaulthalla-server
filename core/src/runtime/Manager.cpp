#include "runtime/Manager.hpp"

#include "concurrency/AsyncService.hpp"
#include "db/Janitor.hpp"
#include "fuse/Service.hpp"
#include "identities/Manager.hpp"
#include "log/Registry.hpp"
#include "log/RotationService.hpp"
#include "notifications/OperatorEmailService.hpp"
#include "protocols/ProtocolService.hpp"
#include "protocols/s3/GatewayService.hpp"
#include "protocols/shell/Server.hpp"
#include "protocols/ws/ConnectionLifecycleManager.hpp"
#include "runtime/Deps.hpp"
#include "stats/SnapshotService.hpp"
#include "sync/Controller.hpp"
#include "vault/RetentionService.hpp"
#include "sync/events/Service.hpp"

#include <array>
#include <chrono>
#include <cstdlib>
#include <paths.h>
#include <string_view>
#include <utility>

namespace vh::runtime {

namespace {
constexpr auto kRestartDelay = std::chrono::milliseconds(500);
constexpr auto kWatchdogInterval = std::chrono::seconds(2);

constexpr std::array kBaseStartOrder{
    "FUSE",
    "IdentityWatcher",
    "SyncController",
    "UpstreamEventService",
    "DBJanitor",
    "VaultRetentionService",
    "LogRotationService",
    "StatsSnapshotService",
    "OperatorEmailService",
    "ConnectionLifecycleManager",
    "ProtocolService",
    "S3GatewayService"
};

constexpr std::array kBaseStopOrder{
    "S3GatewayService",
    "ProtocolService",
    "ShellServer",
    "ConnectionLifecycleManager",
    "OperatorEmailService",
    "StatsSnapshotService",
    "VaultRetentionService",
    "DBJanitor",
    "IdentityWatcher",
    "LogRotationService",
    "UpstreamEventService",
    "SyncController",
    "FUSE"
};
}

Manager& Manager::instance() {
    static Manager instance;
    return instance;
}

Manager::Manager()
    : syncController(std::make_shared<sync::Controller>()),
      fuseService(fuse::makeService()),
      protocolService(std::make_shared<protocols::ProtocolService>()),
      s3GatewayService(std::make_shared<protocols::s3::GatewayService>()),
      connectionLifecycleManager(std::make_shared<protocols::ws::ConnectionLifecycleManager>()),
      logRotationService(std::make_shared<log::RotationService>()),
      dbSweeperService(std::make_shared<db::Janitor>()),
      identityWatcher(std::make_shared<identities::RevisionWatcher>()),
      vaultRetentionService(std::make_shared<vault::RetentionService>()),
      statsSnapshotService(std::make_shared<stats::SnapshotService>()),
      operatorEmailService(std::make_shared<notifications::OperatorEmailService>()),
      upstreamEventService(std::make_shared<sync::events::Service>()) {

    services_["SyncController"] = syncController;
    if (fuseService) services_["FUSE"] = fuseService;  // null: built without the kernel FUSE bridge
    services_["ProtocolService"] = protocolService;
    services_["S3GatewayService"] = s3GatewayService;
    services_["ConnectionLifecycleManager"] = connectionLifecycleManager;
    services_["LogRotationService"] = logRotationService;
    services_["DBJanitor"] = dbSweeperService;
    services_["IdentityWatcher"] = identityWatcher;
    services_["VaultRetentionService"] = vaultRetentionService;
    services_["StatsSnapshotService"] = statsSnapshotService;
    services_["OperatorEmailService"] = operatorEmailService;
    services_["UpstreamEventService"] = upstreamEventService;

    // A test instance serves `vh` only on a private socket (VH_TEST_CLI_SOCKET), never the system one.
    if (!paths::testMode || paths::testCliSocket) {
        shellServer = std::make_shared<protocols::shell::Server>();
        services_["ShellServer"] = shellServer;
    }
}

std::vector<std::string> Manager::serviceStartOrder(const bool includeShellServer) {
    std::vector<std::string> names;
    names.reserve(kBaseStartOrder.size() + 1);
    for (const auto* name : kBaseStartOrder)
        names.emplace_back(name);
    if (includeShellServer)
        names.emplace_back("ShellServer");
    return names;
}

std::vector<std::string> Manager::serviceStopOrder(const bool includeShellServer) {
    std::vector<std::string> names;
    names.reserve(kBaseStopOrder.size());
    for (const auto* name : kBaseStopOrder) {
        if (!includeShellServer && std::string_view{name} == "ShellServer")
            continue;
        names.emplace_back(name);
    }
    return names;
}

std::vector<Manager::ServiceEntry> Manager::serviceEntriesInOrder(const std::vector<std::string>& names) const {
    std::vector<ServiceEntry> entries;
    entries.reserve(names.size());

    for (const auto& name : names) {
        const auto it = services_.find(name);
        if (it != services_.end())
            entries.push_back({it->first, it->second});
    }

    return entries;
}

std::vector<Manager::ServiceEntry> Manager::serviceStartEntries() const {
    return serviceEntriesInOrder(serviceStartOrder(static_cast<bool>(shellServer)));
}

std::vector<Manager::ServiceEntry> Manager::serviceStopEntries() const {
    return serviceEntriesInOrder(serviceStopOrder(static_cast<bool>(shellServer)));
}

void Manager::startAll() {
    log::Registry::runtime()->debug("[ServiceManager] Starting all services...");

    const auto entries = [&] {
        std::scoped_lock lock(mutex_);
        return serviceStartEntries();
    }();

    for (const auto& entry : entries) {
        tryStart(entry);
        if (entry.name == "FUSE" && fuseService)
            Deps::get().setFuseSession(fuseService->session());
    }

    startWatchdog();
    log::Registry::runtime()->debug("[ServiceManager] All services started.");
}

void Manager::startTestServices() {
    const auto entries = [&] {
        std::scoped_lock lock(mutex_);
        std::vector<ServiceEntry> selected;

        if (fuseService) selected.push_back({"FUSE", fuseService});
        if (shellServer) selected.push_back({"ShellServer", shellServer});

        return selected;
    }();

    for (const auto& entry : entries)
        tryStart(entry);
}

void Manager::stopAll(const int signal) {
    log::Registry::runtime()->debug("[ServiceManager] Stopping all services...");

    stopWatchdog();

    const auto entries = [&] {
        std::scoped_lock lock(mutex_);
        return serviceStopEntries();
    }();

    // Every service but FUSE is asked to stop at once and then joined, so shutdown takes as long as the slowest
    // service instead of the sum of all of them (each used to wait out its own sleep in turn). FUSE goes last, on
    // its own: HTTP upload staging and other services read and write through the mount until they have stopped.
    const auto start = std::chrono::steady_clock::now();
    for (const auto& entry : entries)
        if (entry.service && entry.name != "FUSE") entry.service->requestStop();
    for (const auto& entry : entries)
        if (entry.name != "FUSE") stopService(entry, signal);
    for (const auto& entry : entries)
        if (entry.name == "FUSE") stopService(entry, signal);

    log::Registry::runtime()->info("[ServiceManager] All services stopped in {} ms.",
                                   std::chrono::duration_cast<std::chrono::milliseconds>(
                                       std::chrono::steady_clock::now() - start).count());
}

void Manager::restartService(const std::string& name) {
    std::shared_ptr<concurrency::AsyncService> service;

    {
        std::scoped_lock lock(mutex_);
        const auto it = services_.find(name);
        if (it == services_.end() || !it->second) return;
        service = it->second;
    }

    log::Registry::runtime()->warn("[ServiceManager] Restarting service: {}", name);

    stopService({name, service}, SIGTERM);
    std::this_thread::sleep_for(kRestartDelay);
    tryStart({name, service});

    if (name == "FUSE" && fuseService)
        Deps::get().setFuseSession(fuseService->session());
}

bool Manager::allRunning() const {
    const auto entries = [&] {
        std::scoped_lock lock(mutex_);
        return serviceStartEntries();
    }();

    for (const auto& entry : entries)
        if (!entry.service || !entry.service->isRunning())
            return false;

    return true;
}

Manager::Status Manager::status() const {
    const auto entries = [&] {
        std::scoped_lock lock(mutex_);
        return serviceStartEntries();
    }();

    Status out;
    out.allRunning = true;
    out.services.reserve(entries.size());

    for (const auto& entry : entries) {
        ServiceStatus s{};
        s.entryName = entry.name;

        if (entry.service) {
            const auto base = entry.service->status();
            s.serviceName = base.name;
            s.running = base.running;
            s.interrupted = base.interrupted;
            if (!base.running) out.allRunning = false;
        } else {
            s.serviceName = "uninitialized";
            s.running = false;
            s.interrupted = false;
            out.allRunning = false;
        }

        out.services.push_back(std::move(s));
    }

    if (out.services.empty()) out.allRunning = false;
    return out;
}

void Manager::tryStart(const ServiceEntry& entry) {
    if (!entry.service) return;

    log::Registry::runtime()->debug("[ServiceManager] Starting service: {}", entry.name);

    try {
        entry.service->start();
    } catch (const std::exception& e) {
        log::Registry::runtime()->error(
            "[ServiceManager] Failed to start {}: {}",
            entry.name,
            e.what()
        );
        hardFail();
    }
}

void Manager::stopService(const ServiceEntry& entry, const int signal) {
    if (!entry.service) return;

    log::Registry::runtime()->debug("[ServiceManager] Stopping service: {}", entry.name);

    try {
        entry.service->stop();
        log::Registry::runtime()->debug("[ServiceManager] Service stopped: {}", entry.name);
    } catch (...) {
        log::Registry::runtime()->error(
            "[ServiceManager] Failed to stop {} gracefully, escalating with signal {}.",
            entry.name,
            signal
        );
        std::raise(signal);
    }
}

void Manager::startWatchdog() {
    if (watchdogRunning.exchange(true)) return;

    watchdogThread = std::thread([this]() {
        log::Registry::runtime()->info("[ServiceManager] Watchdog started.");

        while (watchdogRunning) {
            std::vector<std::string> downServices;

            {
                std::scoped_lock lock(mutex_);
                for (const auto& [name, service] : services_)
                    if (service && !service->isRunning())
                        downServices.push_back(name);
            }

            for (const auto& name : downServices) {
                log::Registry::runtime()->warn("[Watchdog] {} is down, restarting...", name);

                if (name == "FUSE")
                    if (const int rc = std::system(fmt::format(
                            "fusermount3 -u {} > /dev/null 2>&1 || fusermount -u {} > /dev/null 2>&1",
                            paths::getMountPath().string(),
                            paths::getMountPath().string()
                        ).c_str()); rc != 0)
                        log::Registry::runtime()->warn("[Watchdog] Unmounting {} before restarting FUSE failed (status {})",
                                                       paths::getMountPath().string(), rc);

                restartService(name);
            }

            std::unique_lock lock(watchdogMutex_);
            watchdogCv_.wait_for(lock, kWatchdogInterval, [this] { return !watchdogRunning.load(); });
        }

        log::Registry::runtime()->info("[ServiceManager] Watchdog stopped.");
    });
}

void Manager::stopWatchdog() {
    {
        std::scoped_lock lock(watchdogMutex_);
        if (!watchdogRunning.exchange(false)) return;
    }
    watchdogCv_.notify_all();
    if (watchdogThread.joinable()) watchdogThread.join();
}

[[noreturn]] void Manager::hardFail() {
    log::Registry::runtime()->error("[ServiceManager] Critical failure, cannot continue.");
    stopAll(SIGTERM);
    std::_Exit(EXIT_FAILURE);
}

}
