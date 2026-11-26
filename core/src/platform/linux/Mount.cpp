#include "platform/Mount.hpp"

#include <cerrno>
#include <cstdlib>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <sys/mount.h>  // umount2, MNT_DETACH
#include <sys/socket.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <spawn.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <thread>
#include <vector>

extern char** environ;

namespace vh::platform::mount {

std::string_view defaultMode() noexcept { return "multiuser"; }

bool supportsMode(const std::string_view mode) noexcept { return mode == "multiuser"; }

bool fuseRuntimeAvailable() noexcept { return true; }

std::string_view backend() noexcept { return "linux-fuse"; }

std::string_view isolation(std::string_view) noexcept { return "enforced"; }  // Tier A (make itest) proves it

std::vector<std::string> fuseOptions(std::string_view) {
    return {"-o", "allow_other", "-o", "auto_unmount"};
}

namespace mount_helper_detail {

// The /dev/fuse descriptor fusermount3 sends (SCM_RIGHTS), or -1 when it sent none (it failed and exited).
int receiveFuseFd(const int sock) {
    char byte = 0;
    iovec iov{.iov_base = &byte, .iov_len = 1};
    alignas(cmsghdr) char control[CMSG_SPACE(sizeof(int))]{};
    msghdr msg{};
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control;
    msg.msg_controllen = sizeof(control);
    ssize_t got = 0;
    do got = ::recvmsg(sock, &msg, MSG_CMSG_CLOEXEC);
    while (got < 0 && errno == EINTR);
    if (got <= 0) return -1;
    for (cmsghdr* c = CMSG_FIRSTHDR(&msg); c; c = CMSG_NXTHDR(&msg, c))
        if (c->cmsg_level == SOL_SOCKET && c->cmsg_type == SCM_RIGHTS && c->cmsg_len == CMSG_LEN(sizeof(int))) {
            int fd = -1;
            std::memcpy(&fd, CMSG_DATA(c), sizeof(int));
            return fd;
        }
    return -1;
}

void reap(const int pid, const int waitMs) noexcept {
    if (pid <= 0) return;
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(waitMs);
    for (;;) {
        int status = 0;
        const pid_t r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid || (r < 0 && errno != EINTR)) return;
        if (std::chrono::steady_clock::now() >= end) return;  // still unmounting: init reaps it after we exit
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

}

HelperMount mountWithHelper(const std::filesystem::path& mountpoint, const std::string& options) {
    namespace d = mount_helper_detail;
    HelperMount out;
    int fds[2]{-1, -1};
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, fds) != 0) {
        out.error = std::string("socketpair: ") + std::strerror(errno);
        return out;
    }
    // The helper's end is descriptor 3 in the helper, and nothing else of this process is: stdin/stdout/stderr stay
    // (its messages land in the daemon's log), every other descriptor is closed in the child, so the helper (alive as
    // long as the mount, with auto_unmount) never holds a listening socket or a file of the daemon's.
    constexpr int kChildFd = 3;
    const std::string commEnv = "_FUSE_COMMFD=" + std::to_string(kChildFd);
    std::vector<std::string> envStore;
    for (char** e = environ; e && *e; ++e)
        if (std::strncmp(*e, "_FUSE_COMMFD=", 13) != 0) envStore.emplace_back(*e);
    envStore.push_back(commEnv);
    std::vector<char*> envp;
    for (auto& e : envStore) envp.push_back(e.data());
    envp.push_back(nullptr);
    std::string prog = "fusermount3", dashO = "-o", opts = options, dashes = "--", mp = mountpoint.string();
    std::vector<char*> argv{prog.data(), dashO.data(), opts.data(), dashes.data(), mp.data(), nullptr};

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fds[1], kChildFd);   // a dup2 to itself clears FD_CLOEXEC (glibc)
    posix_spawn_file_actions_addclosefrom_np(&actions, kChildFd + 1);
    pid_t pid = -1;
    int rc = ::posix_spawn(&pid, "/usr/bin/fusermount3", &actions, nullptr, argv.data(), envp.data());
    if (rc == ENOENT) rc = ::posix_spawnp(&pid, "fusermount3", &actions, nullptr, argv.data(), envp.data());
    posix_spawn_file_actions_destroy(&actions);
    ::close(fds[1]);
    if (rc != 0) {
        ::close(fds[0]);
        out.error = std::string("fusermount3: ") + std::strerror(rc);
        return out;
    }
    const int fuseFd = d::receiveFuseFd(fds[0]);
    if (fuseFd < 0) {
        ::close(fds[0]);
        d::reap(pid, 2000);
        out.error = "fusermount3 did not mount " + mp + " (its message is in the log)";
        return out;
    }
    out.fuse_fd = fuseFd;
    out.comm_fd = fds[0];
    out.pid = pid;
    return out;
}

void releaseHelper(HelperMount& helper, const int waitMs) noexcept {
    if (helper.comm_fd >= 0) ::close(helper.comm_fd);
    helper.comm_fd = -1;
    mount_helper_detail::reap(helper.pid, waitMs);
    helper.pid = -1;
}

bool isMountedOrStale(const std::filesystem::path& p) {
    // If lstat returns ENOTCONN, it's a stale FUSE endpoint => treat as mounted.
    struct stat st{}, pst{};
    if (::lstat(p.c_str(), &st) != 0) return (errno == ENOTCONN);
    const auto parent = p.parent_path().empty() ? std::filesystem::path("/") : p.parent_path();

    // If parent can't be stat'ed, be conservative.
    if (::lstat(parent.c_str(), &pst) != 0) return true;

    // Different st_dev than parent => mountpoint boundary
    return st.st_dev != pst.st_dev;
}

void detachStale(const std::filesystem::path&) noexcept {}

void detach(const std::filesystem::path& path) noexcept {
    // 1) Try kernel lazy detach
    if (::umount2(path.c_str(), MNT_DETACH) == 0) return;

    // 2) Fallbacks (some distros prefer fusermount3), stopping at the first that works
    for (const auto* command : {"fusermount3 -uz ", "fusermount -uz ", "umount -l "})
        if (std::system((command + path.string() + " >/dev/null 2>&1").c_str()) == 0) return;
}

std::optional<std::string> fuseConnection(const std::filesystem::path& path) {
    std::ifstream mountinfo("/proc/self/mountinfo");
    std::string line;
    while (std::getline(mountinfo, line)) {
        // <id> <parent> <major>:<minor> <root> <mount point> ... - <fstype> ...
        std::istringstream fields(line);
        std::string id, parent, dev, root, mountPoint;
        if (!(fields >> id >> parent >> dev >> root >> mountPoint)) continue;
        if (mountPoint != path.string() || line.find(" - fuse.") == std::string::npos) continue;
        if (const auto colon = dev.find(':'); colon != std::string::npos) return dev.substr(colon + 1);
    }
    return std::nullopt;
}

bool abortConnection(const std::string& connection) noexcept {
    std::ofstream abort("/sys/fs/fuse/connections/" + connection + "/abort");
    abort << "1" << std::flush;
    return static_cast<bool>(abort);
}

}
