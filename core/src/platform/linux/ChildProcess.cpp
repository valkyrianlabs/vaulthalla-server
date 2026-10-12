#include "platform/ChildProcess.hpp"

#include <array>
#include <cerrno>
#include <csignal>
#include <string>
#include <string_view>
#include <fcntl.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace vh::platform::child {

pid_t forkForExec() noexcept { return ::_Fork(); }

int armChild(const pid_t parent) noexcept {
    if (::prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) != 0) return errno;
    if (::getppid() != parent) return -1;   // the parent died before PDEATHSIG was armed
    if (::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) return errno;
    return 0;
}

int limitAddressSpace(const struct rlimit& limit) noexcept {
    return ::setrlimit(RLIMIT_AS, &limit) == 0 ? 0 : errno;
}

bool addressSpaceLimitEnforced() noexcept { return true; }

void closeFrom(const int lowest, const int loopLimit) noexcept {
    if (::syscall(SYS_close_range, static_cast<unsigned>(lowest), ~0u, 0u) != 0)
        for (int fd = lowest; fd < loopLimit; ++fd) ::close(fd);
}

int exitWatchFd(const pid_t pid) noexcept {
    const long fd = ::syscall(SYS_pidfd_open, pid, 0);
    return fd >= 0 ? static_cast<int>(fd) : -1;
}

// /proc/<pid>/stat field 20.
long threadCount(const pid_t pid) noexcept {
    const std::string path = "/proc/" + std::to_string(pid) + "/stat";
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    std::array<char, 4096> buf{};
    ssize_t n = 0;
    do n = ::read(fd, buf.data(), buf.size());
    while (n < 0 && errno == EINTR);
    ::close(fd);
    if (n <= 0) return -1;
    std::string_view stat(buf.data(), static_cast<std::size_t>(n));
    // comm (field 2) may contain spaces and parentheses: fields 3.. start after the last ')'.
    const auto close = stat.rfind(')');
    if (close == std::string_view::npos) return -1;
    stat.remove_prefix(close + 1);
    for (int field = 3; field < 20; ++field) {
        const auto start = stat.find_first_not_of(' ');
        if (start == std::string_view::npos) return -1;
        const auto end = stat.find(' ', start);
        if (end == std::string_view::npos) return -1;
        stat.remove_prefix(end);
    }
    const auto start = stat.find_first_not_of(' ');
    if (start == std::string_view::npos) return -1;
    long value = 0;
    bool any = false;
    for (auto i = start; i < stat.size() && stat[i] >= '0' && stat[i] <= '9'; ++i, any = true)
        value = value * 10 + (stat[i] - '0');
    return any ? value : -1;
}

}
