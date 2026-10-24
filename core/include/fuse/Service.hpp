#pragma once

#include "concurrency/AsyncService.hpp"
#include "storage/Fwd.hpp"

#include <atomic>
#include <memory>
#include <string>

struct fuse_session;  // libfuse's opaque session handle

namespace vh::fuse {

// The kernel FUSE bridge is a build capability: Linux always builds it; a build without it (macOS, always: the
// server never mounts there and Finder access is Vaulthalla Desktop's, #262; or `-Dfuse=disabled`) serves vaults
// over HTTP/WS/CLI/S3 only. makeService() returns nullptr there and kernelBridgeBuilt() is false; nothing ever
// claims a mount.
[[nodiscard]] bool kernelBridgeBuilt() noexcept;

class Service;
// The FUSE service for the configured mount mode, or nullptr when nothing is to be mounted: the mode is disabled,
// this build/platform can't provide it, or the platform has no FUSE runtime. mountStatus() says which; nothing ever
// mounts a different mode than the one configured.
[[nodiscard]] std::shared_ptr<Service> makeService();

// The mount mode config.yaml asks for (mount.mode), or this build's default (platform/Mount.hpp).
[[nodiscard]] std::string configuredMountMode();

// What the mount is configured to be and what it actually is right now, for health and `vh status`. A configured
// mount that isn't mounted reports why; configuration alone never reads as "mounted".
struct MountStatus {
    std::string configuredMode;  // disabled | service_private | multiuser
    std::string backend;         // the platform's FUSE implementation, or "none"
    std::string state;           // disabled | mounted | not_mounted | unavailable | unsupported
    std::string isolation;       // enforced | unproven | not_applicable
    std::string detail;          // why the configured mount isn't mounted, when it isn't
};
[[nodiscard]] MountStatus mountStatus();

class Service final : public concurrency::AsyncService {
    friend class ServiceManager;

public:

    explicit Service();

    [[nodiscard]] fuse_session* session() const noexcept { return session_; }
    [[nodiscard]] bool mounted() const noexcept { return loopActive_.load(); }

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
