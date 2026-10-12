#include "fuse/Service.hpp"
#include "config/Registry.hpp"
#include "platform/Mount.hpp"

namespace vh::fuse {

std::string configuredMountMode() {
    const auto& mode = config::Registry::get().mount.mode;
    return mode.empty() ? std::string(platform::mount::defaultMode()) : mode;
}

}
