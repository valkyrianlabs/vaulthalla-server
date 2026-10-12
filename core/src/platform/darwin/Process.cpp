#include "platform/Process.hpp"

#include <cerrno>
#include <sys/resource.h>

namespace vh::platform::process {

int disableCoreDumps() noexcept {
    constexpr rlimit none{0, 0};
    return ::setrlimit(RLIMIT_CORE, &none) == 0 ? 0 : errno;
}

}
