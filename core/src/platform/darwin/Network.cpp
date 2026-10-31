#include "platform/Network.hpp"

#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <chrono>
#include <string>

extern char** environ;

namespace vh::platform::network {

namespace {

constexpr auto kQueryTimeout = std::chrono::seconds(2);

// `socketfilterfw --getglobalstate` answers any user ("Firewall is enabled. (State = 1)"); the old
// com.apple.alf.plist is gone on current macOS. Bounded: killed after kQueryTimeout. nullopt when it can't be told.
std::optional<int> applicationFirewallState(const std::filesystem::path& root) {
    const auto tool = (root / "usr/libexec/ApplicationFirewall/socketfilterfw").string();
    if (::access(tool.c_str(), X_OK) != 0) return std::nullopt;

    int fds[2];
    if (::pipe(fds) != 0) return std::nullopt;
    (void)::fcntl(fds[0], F_SETFD, FD_CLOEXEC);

    posix_spawn_file_actions_t actions;
    posix_spawn_file_actions_init(&actions);
    posix_spawn_file_actions_adddup2(&actions, fds[1], STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&actions, STDERR_FILENO, "/dev/null", O_WRONLY, 0);
    posix_spawn_file_actions_addclose(&actions, fds[1]);
    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    // Never inherit the daemon's other descriptors.
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_CLOEXEC_DEFAULT);

    std::string arg0 = tool;
    std::string arg1 = "--getglobalstate";
    char* argv[] = {arg0.data(), arg1.data(), nullptr};
    pid_t pid = -1;
    const int spawned = ::posix_spawn(&pid, tool.c_str(), &actions, &attr, argv, environ);
    posix_spawn_file_actions_destroy(&actions);
    posix_spawnattr_destroy(&attr);
    ::close(fds[1]);
    if (spawned != 0) {
        ::close(fds[0]);
        return std::nullopt;
    }

    std::string out;
    const auto deadline = std::chrono::steady_clock::now() + kQueryTimeout;
    bool timedOut = false;
    for (;;) {
        const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - std::chrono::steady_clock::now());
        if (left.count() <= 0) {
            timedOut = true;
            break;
        }
        pollfd pfd{.fd = fds[0], .events = POLLIN, .revents = 0};
        const int ready = ::poll(&pfd, 1, static_cast<int>(left.count()));
        if (ready < 0 && errno == EINTR) continue;
        if (ready <= 0) {
            timedOut = ready == 0;
            break;
        }
        std::array<char, 256> buf{};
        const auto n = ::read(fds[0], buf.data(), buf.size());
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        if (out.size() < 4096) out.append(buf.data(), static_cast<std::size_t>(n));
    }
    ::close(fds[0]);
    if (timedOut) (void)::kill(pid, SIGKILL);
    int status = 0;
    while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    if (timedOut || !WIFEXITED(status)) return std::nullopt;

    const auto at = out.find("(State = ");
    if (at == std::string::npos || at + 9 >= out.size()) return std::nullopt;
    const char c = out[at + 9];
    if (c < '0' || c > '9') return std::nullopt;
    return c - '0';
}

}

FirewallState detectFirewall(const uint16_t port, const std::filesystem::path& root) {
    (void)port;  // the application firewall filters by program, not by port
    // pf's state needs root (pfctl): never reported.
    const auto state = applicationFirewallState(root);
    if (!state) return {};
    if (*state == 0) return {.detected = "alf", .active = false, .hint = std::nullopt};
    return {.detected = "alf", .active = true,
            .hint = "System Settings > Network > Firewall > Options: allow incoming connections for vaulthalla-server"};
}

bool mdnsResponderAvailable(const std::filesystem::path& /*root*/) { return true; }

}
