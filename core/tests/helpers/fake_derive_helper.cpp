// Test-only converter for preview::derive::Runner (core/tests/unit/test_derive_runner.cpp). Speaks the helper
// protocol by hand (no sandbox, no core/tools dependency) and misbehaves on request.
//
//   echo        pull the whole input, write it to stdout
//   ranges      pull --count random ranges (--seed); stdout gets "u64 offset, u32 asked, u32 got, bytes" per range
//   flood       write to stdout forever
//   sleep       block forever
//   crash       SIGSEGV
//   alloc       allocate and touch 16 MiB blocks until allocation fails (reports how far it got)
//   inspect     report environment, open fds, cwd, rlimits, session and no_new_privs
//   badproto    send a request with a non-zero reserved field
//   bigrequest  request more than the daemon allows
//   exit        exit with --code without a result
//   stderr      write --bytes of stderr, then succeed
//   stall-read  pull one range and then stop reading replies while the daemon has more to send
//   stderr-flood  write to stderr forever from --writers threads (a 1 MiB pipe when the kernel allows it)
//   threads     start --count threads that never return, then block

#include <nlohmann/json.hpp>

#include <dirent.h>
#include <fcntl.h>
#if defined(__linux__)
#include <sys/prctl.h>
#endif
#include <sys/resource.h>
#include <sys/socket.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <climits>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

extern char** environ;

namespace {

constexpr int kRangeFd = 3;
constexpr int kResultFd = 4;

void writeAll(const int fd, const void* data, std::size_t size) {
    const auto* p = static_cast<const uint8_t*>(data);
    while (size > 0) {
        const ssize_t n = ::write(fd, p, size);
        if (n < 0) {
            if (errno == EINTR) continue;
            std::_Exit(10);
        }
        p += n;
        size -= static_cast<std::size_t>(n);
    }
}

bool readExact(const int fd, void* data, const std::size_t size) {
    auto* p = static_cast<uint8_t*>(data);
    std::size_t got = 0;
    while (got < size) {
        const ssize_t n = ::read(fd, p + got, size - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        got += static_cast<std::size_t>(n);
    }
    return true;
}

void sendRequest(const uint64_t offset, const uint32_t length, const uint32_t reserved = 0) {
    std::array<uint8_t, 16> frame{};
    for (int i = 0; i < 8; ++i) frame[static_cast<std::size_t>(i)] = static_cast<uint8_t>(offset >> (8 * i));
    for (int i = 0; i < 4; ++i) frame[static_cast<std::size_t>(8 + i)] = static_cast<uint8_t>(length >> (8 * i));
    for (int i = 0; i < 4; ++i) frame[static_cast<std::size_t>(12 + i)] = static_cast<uint8_t>(reserved >> (8 * i));
    writeAll(kRangeFd, frame.data(), frame.size());
}

std::vector<uint8_t> pull(const uint64_t offset, const uint32_t length) {
    sendRequest(offset, length);
    std::array<uint8_t, 4> header{};
    if (!readExact(kRangeFd, header.data(), header.size())) std::_Exit(11);
    const uint32_t n = header[0] | (header[1] << 8) | (header[2] << 16) | (static_cast<uint32_t>(header[3]) << 24);
    if (n > length) std::_Exit(12);
    std::vector<uint8_t> data(n);
    if (n > 0 && !readExact(kRangeFd, data.data(), n)) std::_Exit(13);
    return data;
}

void result(const nlohmann::json& json) {
    const auto line = json.dump() + "\n";
    writeAll(kResultFd, line.data(), line.size());
    ::close(kResultFd);
}

#if defined(__linux__)
constexpr const char* kOwnFdDir = "/proc/self/fd";
#else
constexpr const char* kOwnFdDir = "/dev/fd";
#endif

// Linux-only process properties the runner arms (PR_SET_NO_NEW_PRIVS, PR_SET_PDEATHSIG); null where the OS has none.
nlohmann::json noNewPrivs() {
#if defined(__linux__)
    return ::prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0);
#else
    return nullptr;
#endif
}

nlohmann::json parentDeathSignal() {
#if defined(__linux__)
    int sig = 0;
    ::prctl(PR_GET_PDEATHSIG, &sig, 0, 0, 0);
    return sig;
#else
    return nullptr;
#endif
}

std::string stdinTarget() {
#if defined(__linux__)
    std::array<char, 256> target{};
    const ssize_t n = ::readlink("/proc/self/fd/0", target.data(), target.size() - 1);
    return std::string(target.data(), n > 0 ? static_cast<std::size_t>(n) : 0);
#else
    std::array<char, PATH_MAX> target{};
    return ::fcntl(0, F_GETPATH, target.data()) == 0 ? std::string(target.data()) : std::string();
#endif
}

bool emptySigset(const sigset_t& mask) {
    for (int sig = 1; sig < NSIG; ++sig)
        if (sigismember(&mask, sig) == 1) return false;
    return true;
}

nlohmann::json inspect() {
    nlohmann::json env = nlohmann::json::array();
    for (char** e = environ; e && *e; ++e) env.push_back(*e);

    nlohmann::json fds = nlohmann::json::array();
    if (DIR* dir = ::opendir(kOwnFdDir)) {
        const int own = ::dirfd(dir);
        while (const dirent* entry = ::readdir(dir)) {
            if (entry->d_name[0] == '.') continue;
            const int fd = std::atoi(entry->d_name);
            if (fd != own) fds.push_back(fd);
        }
        ::closedir(dir);
    }

    const auto limit = [](const int resource) {
        rlimit rl{};
        ::getrlimit(resource, &rl);
        return nlohmann::json{{"soft", rl.rlim_cur == RLIM_INFINITY ? -1.0 : static_cast<double>(rl.rlim_cur)},
                              {"hard", rl.rlim_max == RLIM_INFINITY ? -1.0 : static_cast<double>(rl.rlim_max)}};
    };

    std::array<char, 4096> cwd{};
    const char* dir = ::getcwd(cwd.data(), cwd.size());

    sigset_t mask;
    sigemptyset(&mask);
    ::sigprocmask(SIG_SETMASK, nullptr, &mask);
    struct sigaction pipeAction{};
    ::sigaction(SIGPIPE, nullptr, &pipeAction);

    return {
        {"ok", true},
        {"env", env},
        {"fds", fds},
        {"cwd", dir ? dir : ""},
        {"no_new_privs", noNewPrivs()},
        {"session_leader", ::getsid(0) == ::getpid()},
        {"pdeathsig", parentDeathSignal()},
        {"sigmask_empty", emptySigset(mask)},
        {"sigpipe_default", pipeAction.sa_handler == SIG_DFL},
        {"stdin", stdinTarget()},
        {"rlimit_as", limit(RLIMIT_AS)},
        {"rlimit_cpu", limit(RLIMIT_CPU)},
        {"rlimit_fsize", limit(RLIMIT_FSIZE)},
        {"rlimit_nofile", limit(RLIMIT_NOFILE)},
        {"rlimit_core", limit(RLIMIT_CORE)},
    };
}

}

int main(int argc, char** argv) {
    if (argc < 2) return 1;
    const std::string command = argv[1];
    std::unordered_map<std::string, std::string> options;
    for (int i = 2; i + 1 < argc; i += 2) options[std::string(argv[i]).substr(2)] = argv[i + 1];
    const auto u64 = [&](const std::string& key, const uint64_t fallback) -> uint64_t {
        const auto it = options.find(key);
        return it == options.end() ? fallback : std::strtoull(it->second.c_str(), nullptr, 10);
    };
    const uint64_t inputSize = u64("input-size", 0);

    // Stand-ins for the real converter commands (preview::derive::Queue tests). Behaviour follows the input's first
    // line: "FAKE-INVALID" (invalid_input, exit 2), "FAKE-INTERNAL" (internal, exit 1), "FAKE-CRASH" (SIGSEGV),
    // "FAKE-NOSANDBOX" (sandbox_unavailable, exit 5), "FAKE-SLEEP <ms>" (pause, then succeed); anything else
    // succeeds. Success writes "CMD <argv[1..]>\n" and then the whole input to stdout.
    if (command == "convert-step" || command == "poster" || command == "probe" || command == "transcode") {
        std::vector<uint8_t> input;
        for (uint64_t offset = 0; offset < inputSize;) {
            const auto chunk = pull(offset, 1u << 20);
            if (chunk.empty()) break;
            input.insert(input.end(), chunk.begin(), chunk.end());
            offset += chunk.size();
        }
        const std::string head(input.begin(), input.begin() + static_cast<std::ptrdiff_t>(std::min<std::size_t>(input.size(), 64)));
        if (head.starts_with("FAKE-INVALID")) {
            result({{"ok", false}, {"error", "invalid_input"}, {"message", "not a model"}});
            return 2;
        }
        if (head.starts_with("FAKE-INTERNAL")) {
            result({{"ok", false}, {"error", "internal"}, {"message", "transient trouble"}});
            return 1;
        }
        if (head.starts_with("FAKE-NOSANDBOX")) {   // what a real helper reports on a host without Landlock
            result({{"ok", false}, {"error", "sandbox_unavailable"}, {"message", "sandbox unavailable: test"},
                    {"sandbox", {{"landlock", false}, {"seccomp", true}, {"detail", "test"}}}});
            return 5;
        }
        if (head.starts_with("FAKE-CRASH")) {
            ::raise(SIGSEGV);
            return 99;
        }
        if (head.starts_with("FAKE-SLEEP ")) ::usleep(static_cast<useconds_t>(std::strtoul(head.c_str() + 11, nullptr, 10) * 1000));

        std::string line = "CMD";
        for (int i = 1; i < argc; ++i) line += std::string(" ") + argv[i];
        line += "\n";
        writeAll(1, line.data(), line.size());
        writeAll(1, input.data(), input.size());
        result({{"ok", true}, {"bytes", input.size()}});
        return 0;
    }
    if (command == "echo") {
        uint64_t total = 0;
        for (uint64_t offset = 0; offset < inputSize;) {
            const auto chunk = pull(offset, 1u << 20);
            if (chunk.empty()) break;
            writeAll(1, chunk.data(), chunk.size());
            offset += chunk.size();
            total += chunk.size();
        }
        result({{"ok", true}, {"bytes", total}});
        return 0;
    }
    if (command == "ranges") {
        std::mt19937_64 rng(u64("seed", 1));
        const uint64_t count = u64("count", 100);
        for (uint64_t i = 0; i < count; ++i) {
            const uint64_t offset = rng() % (inputSize + 4096);   // sometimes past EOF
            const auto length = static_cast<uint32_t>(rng() % (3u << 20));
            const auto data = pull(offset, length);
            std::array<uint8_t, 16> header{};
            for (int b = 0; b < 8; ++b) header[static_cast<std::size_t>(b)] = static_cast<uint8_t>(offset >> (8 * b));
            for (int b = 0; b < 4; ++b) header[static_cast<std::size_t>(8 + b)] = static_cast<uint8_t>(length >> (8 * b));
            const auto got = static_cast<uint32_t>(data.size());
            for (int b = 0; b < 4; ++b) header[static_cast<std::size_t>(12 + b)] = static_cast<uint8_t>(got >> (8 * b));
            writeAll(1, header.data(), header.size());
            writeAll(1, data.data(), data.size());
        }
        result({{"ok", true}, {"ranges", count}});
        return 0;
    }
    if (command == "flood") {
        std::vector<uint8_t> block(1u << 16, 0x5a);
        while (true) writeAll(1, block.data(), block.size());
    }
    if (command == "sleep") {
        while (true) ::pause();
    }
    if (command == "crash") {
        ::raise(SIGSEGV);
        return 99;
    }
    if (command == "alloc") {
        std::vector<void*> blocks;
        uint64_t total = 0;
        while (true) {
            void* block = std::malloc(16u << 20);
            if (!block) break;
            std::memset(block, 1, 16u << 20);
            blocks.push_back(block);
            total += 16u << 20;
            if (total > (64ull << 30)) break;   // never on a sane limit
        }
        result({{"ok", false}, {"error", "limit_exceeded"}, {"message", "allocation failed"}, {"allocated", total}});
        return 3;
    }
    if (command == "inspect") {
        result(inspect());
        return 0;
    }
    if (command == "badproto") {
        sendRequest(0, 16, 7);
        std::array<uint8_t, 4> header{};
        readExact(kRangeFd, header.data(), header.size());
        ::pause();
        return 0;
    }
    if (command == "bigrequest") {
        sendRequest(0, 64u << 20);
        std::array<uint8_t, 4> header{};
        readExact(kRangeFd, header.data(), header.size());
        ::pause();
        return 0;
    }
    if (command == "exit") {
        return static_cast<int>(u64("code", 0));
    }
    if (command == "stderr") {
        const uint64_t bytes = u64("bytes", 1u << 20);
        std::vector<char> block(4096, 'e');
        for (uint64_t written = 0; written < bytes; written += block.size()) writeAll(2, block.data(), block.size());
        const char tail[] = "\nEND-OF-STDERR\n";
        writeAll(2, tail, sizeof tail - 1);
        result({{"ok", true}});
        return 0;
    }
    if (command == "stderr-flood") {
#if defined(F_SETPIPE_SZ)  // Linux: a bigger pipe floods faster; macOS pipes are fixed-size
        (void)::fcntl(2, F_SETPIPE_SZ, 1 << 20);
#endif
        const auto flood = [] {
            std::vector<char> block(1u << 16, 'f');
            while (true) writeAll(2, block.data(), block.size());
        };
        for (uint64_t i = 1; i < u64("writers", 4); ++i) std::thread(flood).detach();
        flood();
    }
    if (command == "threads") {
        const uint64_t count = u64("count", 100);
        uint64_t started = 0;
        for (; started < count; ++started) {
            try {
                std::thread([] { while (true) ::pause(); }).detach();
            } catch (const std::exception&) {
                break;
            }
        }
        while (true) ::pause();
    }
    if (command == "stall-read") {
        sendRequest(0, 4u << 20);   // a reply larger than the socket buffer, never read
        ::pause();
        return 0;
    }
    return 1;
}
