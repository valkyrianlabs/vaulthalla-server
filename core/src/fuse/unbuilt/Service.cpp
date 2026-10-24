// Compiled instead of the kernel bridge (Bridge/Service/Resolver/Reply.cpp) when the build has no FUSE: always on
// macOS, `-Dfuse=disabled` elsewhere. See fuse/Service.hpp.
#include "fuse/Service.hpp"
#include "platform/Mount.hpp"

namespace vh::fuse {

bool kernelBridgeBuilt() noexcept { return false; }

std::shared_ptr<Service> makeService() { return nullptr; }

MountStatus mountStatus() {
    MountStatus status;
    status.configuredMode = configuredMountMode();
    status.backend = "none";
    status.isolation = "not_applicable";
    status.state = status.configuredMode == "disabled" ? "disabled" : "unavailable";
    // config load already ran any configured mode as disabled on a platform with no FUSE runtime (macOS).
    if (!platform::mount::fuseRuntimeAvailable())
        status.detail = "the server never mounts on this platform; Finder access is provided by Vaulthalla Desktop";
    else if (status.state != "disabled")
        status.detail = "this build has no kernel FUSE bridge (-Dfuse)";
    return status;
}

}
