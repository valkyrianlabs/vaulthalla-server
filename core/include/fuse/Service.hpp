#pragma once

#include "concurrency/AsyncService.hpp"
#include "storage/Fwd.hpp"

#include <atomic>
#include <memory>

struct fuse_session;  // libfuse's opaque session handle

namespace vh::fuse {

// The kernel FUSE bridge is a build capability: Linux always builds it; a build without it (`-Dfuse=disabled`,
// the macOS default until a Finder backend is chosen) serves vaults over HTTP/WS/CLI only.
// makeService() returns nullptr there and kernelBridgeBuilt() is false; nothing ever claims a mount.
[[nodiscard]] bool kernelBridgeBuilt() noexcept;

class Service;
[[nodiscard]] std::shared_ptr<Service> makeService();

class Service final : public concurrency::AsyncService {
    friend class ServiceManager;

public:

    explicit Service();

    [[nodiscard]] fuse_session* session() const noexcept { return session_; }

protected:
    void runLoop() override;
    // Lazily unmounts, ends the session and, if the receive loop is still blocked after a grace period (something
    // holds the mount open), aborts the kernel connection so the loop and the stop can never hang.
    void onStop() override;

private:
    fuse_session* session_{nullptr};
    std::atomic<bool> loopActive_{false};
};

}
