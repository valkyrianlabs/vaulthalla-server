#pragma once

#include "concurrency/AsyncService.hpp"
#include "protocols/shell/Fwd.hpp"

#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <list>
#include <mutex>
#include <memory>
#include <string>
#include <thread>

namespace vh::protocols::shell {

// Serves `vh` over /run/vaulthalla/cli.sock (a test instance: VH_TEST_CLI_SOCKET). Each client runs on its own thread (bounded by
// kMaxConcurrentClients), so a slow command, a DB stall, or a user sitting at an interactive prompt never blocks
// other `vh` invocations. Every client read has a timeout.
class Server final : public concurrency::AsyncService {
public:
    static constexpr std::size_t kMaxConcurrentClients = 16;
    // Time a client has to send its request frame after connecting.
    static constexpr std::chrono::seconds kRequestTimeout{10};
    // Time a user has to answer an interactive prompt before the command is aborted.
    static constexpr std::chrono::minutes kPromptTimeout{15};
    // Time a client has to drain output before the daemon gives up on it.
    static constexpr std::chrono::seconds kSendTimeout{30};
    // How often the accept loop checks that the socket path still points at this listener.
    static constexpr std::chrono::milliseconds kListenerCheckInterval{1000};

    Server();
    ~Server() override;

    [[nodiscard]] std::shared_ptr<Router> get_router() const { return router_; }

    void setSocketPath(const std::string& path) { socketPath_ = path; }
    [[nodiscard]] const std::string& socketPath() const noexcept { return socketPath_; }

    [[nodiscard]] bool adminUIDSet() const noexcept { return adminUIDSet_.load(); }

    [[nodiscard]] std::size_t activeClients() const;
    [[nodiscard]] std::uint64_t listenerRebinds() const noexcept { return listenerRebinds_.load(); }

protected:
    void runLoop() override;
    void onStop() override;

private:
    static constexpr std::string_view kVerifyInAdminGroup = R"(id -Gn {} | grep -qw vaulthalla)";

    struct ClientSlot {
        std::thread thread;
        int fd = -1;        // -1 once the client thread has closed it
        bool done = false;
    };

    std::shared_ptr<Router> router_;
    std::string socketPath_;
    unsigned adminGid_;

    mutable std::mutex fdMutex_;
    int listenFd_ = -1;
    dev_t listenDev_ = 0;
    ino_t listenIno_ = 0;

    mutable std::mutex clientsMutex_;
    std::list<ClientSlot> clients_;

    std::mutex adminInitMutex_;
    std::atomic<bool> adminUIDSet_;
    std::atomic<bool> adminStateKnown_{false}; // false until the 'admin' row was actually read from the DB
    std::atomic<std::uint64_t> listenerRebinds_{0};

    int bindListener();
    [[nodiscard]] bool listenerPathIsOurs() const;
    void closeListener(bool unlinkPath);
    void shutdownClients();
    void reapFinishedClients(bool joinAll);
    void handleClient(int cfd);
    void initAdminUid(uid_t uid);
};

}
