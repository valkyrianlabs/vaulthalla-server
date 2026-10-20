#pragma once

#include "identities/Fwd.hpp"
#include "log/Registry.hpp"
#include "sync/Fwd.hpp"
#include "vault/Fwd.hpp"

#include <atomic>
#include <condition_variable>
#include <csignal>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace vh::protocols {
class ProtocolService;
namespace s3 { class GatewayService; }
namespace shell { class Server; }
namespace ws { class ConnectionLifecycleManager; }
namespace device { class Service; }
}

namespace vh::concurrency { class AsyncService; }
namespace vh::db { class Janitor; }
namespace vh::fuse { class Service; }
namespace vh::log { class RotationService; }
namespace vh::notifications { class OperatorEmailService; }
namespace vh::stats { class SnapshotService; }

namespace vh::runtime {

class Manager {
public:
    struct ServiceStatus {
        std::string entryName;
        std::string serviceName;
        bool running = false;
        bool interrupted = false;
    };

    struct Status {
        bool allRunning = false;
        std::vector<ServiceStatus> services;
    };

    static Manager& instance();
    [[nodiscard]] static std::vector<std::string> serviceStartOrder(bool includeShellServer);
    [[nodiscard]] static std::vector<std::string> serviceStopOrder(bool includeShellServer);

    void startAll();
    void stopAll(int signal = SIGTERM);
    void restartService(const std::string& name);
    void startTestServices();

    [[nodiscard]] bool allRunning() const;
    [[nodiscard]] Status status() const;
    [[nodiscard]] std::shared_ptr<sync::Controller> getSyncController() const { return syncController; }
    [[nodiscard]] std::shared_ptr<protocols::ProtocolService> getProtocolService() const { return protocolService; }
    [[nodiscard]] std::shared_ptr<protocols::s3::GatewayService> getS3GatewayService() const { return s3GatewayService; }
    [[nodiscard]] std::shared_ptr<protocols::device::Service> getDeviceServer() const { return deviceServer; }
    [[nodiscard]] std::shared_ptr<protocols::shell::Server> getShellServer() const { return shellServer; }
    [[nodiscard]] std::shared_ptr<protocols::ws::ConnectionLifecycleManager> getConnectionLifecycleManager() const { return connectionLifecycleManager; }

    Manager(const Manager&) = delete;
    Manager& operator=(const Manager&) = delete;

private:
    struct ServiceEntry {
        std::string name;
        std::shared_ptr<concurrency::AsyncService> service;
    };

    Manager();

    [[nodiscard]] std::vector<ServiceEntry> serviceEntriesInOrder(const std::vector<std::string>& names) const;
    [[nodiscard]] std::vector<ServiceEntry> serviceStartEntries() const;
    [[nodiscard]] std::vector<ServiceEntry> serviceStopEntries() const;
    void tryStart(const ServiceEntry& entry);
    static void stopService(const ServiceEntry& entry, int signal);

    void startWatchdog();
    void stopWatchdog();
    [[noreturn]] void hardFail();

    std::shared_ptr<sync::Controller> syncController;
    std::shared_ptr<fuse::Service> fuseService;
    std::shared_ptr<protocols::ProtocolService> protocolService;
    std::shared_ptr<protocols::s3::GatewayService> s3GatewayService;
    std::shared_ptr<protocols::device::Service> deviceServer;
    std::shared_ptr<protocols::shell::Server> shellServer;
    std::shared_ptr<protocols::ws::ConnectionLifecycleManager> connectionLifecycleManager;
    std::shared_ptr<log::RotationService> logRotationService;
    std::shared_ptr<db::Janitor> dbSweeperService;
    std::shared_ptr<identities::RevisionWatcher> identityWatcher;
    std::shared_ptr<vault::RetentionService> vaultRetentionService;
    std::shared_ptr<stats::SnapshotService> statsSnapshotService;
    std::shared_ptr<notifications::OperatorEmailService> operatorEmailService;
    std::shared_ptr<sync::events::Service> upstreamEventService;

    mutable std::mutex mutex_;
    std::map<std::string, std::shared_ptr<concurrency::AsyncService>> services_;

    std::thread watchdogThread;
    std::atomic<bool> watchdogRunning{false};
    std::mutex watchdogMutex_;
    std::condition_variable watchdogCv_;
};

}
