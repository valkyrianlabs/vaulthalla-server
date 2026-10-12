#include "platform/Mount.hpp"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <dlfcn.h>
#include <fcntl.h>
#include <spawn.h>
#include <thread>
#include <unistd.h>
#include <sys/wait.h>
#include <cstring>
#include <string_view>
#include <vector>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/ucred.h>

namespace vh::platform::mount {

std::string_view defaultMode() noexcept { return "disabled"; }

bool supportsMode(const std::string_view mode) noexcept { return mode == "disabled" || mode == "service_private"; }

bool fuseRuntimeAvailable() noexcept {
    // libfuse3 is weak-linked: without macFUSE installed the library isn't loaded and its symbols resolve to nothing.
    return ::dlsym(RTLD_DEFAULT, "fuse_session_mount") != nullptr;
}

std::string_view backend() noexcept { return "macfuse-kernel"; }

std::string_view isolation(std::string_view) noexcept { return "unproven"; }  // until gate K1 (#221) passes

std::vector<std::string> fuseOptions(std::string_view) {
    // macFUSE kernel backend. No allow_other: the mount answers only the daemon's own uid (service-private).
    // novncache/noattrcache: every lookup and getattr reaches the daemon (entry_timeout is not honored on macOS).
    return {"-o", "volname=Vaulthalla", "-o", "nobrowse", "-o", "noappledouble", "-o", "noapplexattr",
            "-o", "novncache", "-o", "noattrcache"};
}

namespace {

// The kernel's mount table (MNT_NOWAIT: its cached copy, never a round trip into a possibly wedged file system).
std::vector<struct statfs> mountTable() {
    const int count = ::getfsstat(nullptr, 0, MNT_NOWAIT);
    if (count <= 0) return {};
    std::vector<struct statfs> mounts(static_cast<std::size_t>(count) + 8);
    const int got = ::getfsstat(mounts.data(), static_cast<int>(mounts.size() * sizeof(struct statfs)), MNT_NOWAIT);
    mounts.resize(got > 0 ? static_cast<std::size_t>(got) : 0);
    return mounts;
}

const struct statfs* mountedAt(const std::vector<struct statfs>& mounts, const std::filesystem::path& path) {
    for (const auto& m : mounts)
        if (path.string() == m.f_mntonname) return &m;
    return nullptr;
}

// Runs argv[0] with argv (no shell), waits at most `limit`, then SIGKILLs it. True when it exited 0.
bool runBounded(std::vector<std::string> argv, const std::chrono::seconds limit) {
    std::vector<char*> args;
    for (auto& a : argv) args.push_back(a.data());
    args.push_back(nullptr);
    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_addopen(&actions, STDOUT_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, args[0], &actions, nullptr, args.data(), nullptr);
    posix_spawn_file_actions_destroy(&actions);
    if (rc != 0) return false;
    const auto deadline = std::chrono::steady_clock::now() + limit;
    int status = 0;
    while (::waitpid(pid, &status, WNOHANG) == 0) {
        if (std::chrono::steady_clock::now() >= deadline) {
            ::kill(pid, SIGKILL);
            ::waitpid(pid, &status, 0);
            return false;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

}

bool isMountedOrStale(const std::filesystem::path& path) {
    return mountedAt(mountTable(), path) != nullptr;
}

void detachStale(const std::filesystem::path& path) noexcept {
    if (isMountedOrStale(path)) detach(path);
}

void detach(const std::filesystem::path& path) noexcept {
    if (::unmount(path.c_str(), MNT_FORCE) == 0) return;
    // diskutil also handles volumes unmount(2) refuses; argv, no shell: the path is never parsed as shell syntax.
    (void)runBounded({"/usr/sbin/diskutil", "unmount", "force", path.string()}, std::chrono::seconds(10));
}

std::optional<std::string> fuseConnection(const std::filesystem::path& path) {
    const auto mounts = mountTable();
    const auto* m = mountedAt(mounts, path);
    if (!m) return std::nullopt;
    const std::string_view type = m->f_fstypename;
    if (!type.starts_with("macfuse") && !type.starts_with("fuse")) return std::nullopt;
    return std::to_string(m->f_fsid.val[0]) + ":" + std::to_string(m->f_fsid.val[1]);
}

bool abortConnection(const std::string&) noexcept {
    return false;  // no fusectl on macOS
}

}
