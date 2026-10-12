// Compiled instead of the kernel bridge (Bridge/Service/Resolver/Reply.cpp) when the build has no FUSE
// (`-Dfuse=disabled`). See fuse/Service.hpp.
#include "fuse/Service.hpp"

namespace vh::fuse {

bool kernelBridgeBuilt() noexcept { return false; }

std::shared_ptr<Service> makeService() { return nullptr; }

}
