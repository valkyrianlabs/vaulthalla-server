#include "platform/Process.hpp"

#include <cerrno>
#include <sys/prctl.h>

namespace vh::platform::process {

int disableCoreDumps() noexcept {
    return ::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 ? 0 : errno;
}

}
