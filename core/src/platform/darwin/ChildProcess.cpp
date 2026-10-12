#include "platform/ChildProcess.hpp"

#include <libproc.h>
#include <sys/proc_info.h>
#include <unistd.h>

namespace vh::platform::child {

pid_t forkForExec() noexcept { return ::fork(); }

int armChild(const pid_t parent) noexcept {
    return ::getppid() == parent ? 0 : -1;
}

int limitAddressSpace(const struct rlimit&) noexcept { return 0; }

bool addressSpaceLimitEnforced() noexcept { return false; }

void closeFrom(const int lowest, const int loopLimit) noexcept {
    for (int fd = lowest; fd < loopLimit; ++fd) ::close(fd);
}

int exitWatchFd(pid_t) noexcept { return -1; }

long threadCount(const pid_t pid) noexcept {
    proc_taskinfo info{};
    if (::proc_pidinfo(pid, PROC_PIDTASKINFO, 0, &info, sizeof info) != static_cast<int>(sizeof info)) return -1;
    return info.pti_threadnum;
}

}
