#include "platform/Sealer.hpp"

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <thread>
#include <vector>

extern char** environ;

// Named, not anonymous: unity builds merge the test files' anonymous namespaces.
namespace tpm_sealer_test {

namespace fs = std::filesystem;

std::optional<fs::path> findOnPath(const std::string& name) {
    const char* path = std::getenv("PATH");
    if (!path) return std::nullopt;
    std::string entries(path);
    std::size_t start = 0;
    while (start <= entries.size()) {
        const auto end = entries.find(':', start);
        const auto dir = entries.substr(start, end == std::string::npos ? std::string::npos : end - start);
        if (!dir.empty()) {
            const auto candidate = fs::path(dir) / name;
            if (::access(candidate.c_str(), X_OK) == 0) return candidate;
        }
        if (end == std::string::npos) break;
        start = end + 1;
    }
    return std::nullopt;
}

bool loopbackPortFree(const uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    const bool ok = ::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    ::close(fd);
    return ok;
}

// The swtpm TCTI always finds the control channel on the next port up, so both must be free.
uint16_t freeLoopbackPortPair() {
    for (uint16_t port = 41000 + static_cast<uint16_t>(::getpid() % 2000) * 2; port < 64000; port += 2)
        if (loopbackPortFree(port) && loopbackPortFree(static_cast<uint16_t>(port + 1))) return port;
    return 0;
}

bool portAccepts(const uint16_t port) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    const bool ok = ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0;
    ::close(fd);
    return ok;
}

// swtpm's control channel: CMD_SHUTDOWN (3) makes it exit. Signals are not enough: inside the CI container kill(2) on swtpm
// fails with EPERM (its confinement), so a SIGTERM + blocking waitpid teardown hung the whole suite.
#if defined(MSG_NOSIGNAL)
constexpr int kSendFlags = MSG_NOSIGNAL;
#else
constexpr int kSendFlags = 0;
#endif

void shutdownViaControlChannel(const uint16_t ctrlPort) {
    const int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return;
    timeval timeout{.tv_sec = 2, .tv_usec = 0};
    (void)::setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(ctrlPort);
    if (::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        constexpr unsigned char cmdShutdown[4] = {0, 0, 0, 3};
        if (::send(fd, cmdShutdown, sizeof(cmdShutdown), kSendFlags) == static_cast<ssize_t>(sizeof(cmdShutdown))) {
            unsigned char result[4];
            (void)::recv(fd, result, sizeof(result), 0);
        }
    }
    ::close(fd);
}

// Reaps pid within the deadline; false if it is still running.
bool reapWithin(const pid_t pid, const std::chrono::milliseconds deadline) {
    const auto until = std::chrono::steady_clock::now() + deadline;
    do {
        int status = 0;
        const auto r = ::waitpid(pid, &status, WNOHANG);
        if (r == pid || r < 0) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
    } while (std::chrono::steady_clock::now() < until);
    return false;
}

// A private swtpm the way vaulthalla-swtpm.service runs one (socket TCTI, no resource manager), on free loopback ports
// with its own state directory, and VH_TPM_TCTI pointed at it for the test's lifetime.
class PrivateSwtpm {
public:
    PrivateSwtpm() {
        const auto swtpm = findOnPath("swtpm");
        if (!swtpm) return;

        state_ = fs::temp_directory_path() / ("vh-test-swtpm-" + std::to_string(::getpid()));
        fs::remove_all(state_);
        fs::create_directories(state_);
        port_ = freeLoopbackPortPair();
        if (port_ == 0) return;
        ctrlPort_ = static_cast<uint16_t>(port_ + 1);
        const auto ctrl = ctrlPort_;

        std::vector<std::string> args{
            swtpm->string(), "socket", "--tpm2",
            "--tpmstate", "dir=" + state_.string(),
            "--server", "type=tcp,port=" + std::to_string(port_) + ",bindaddr=127.0.0.1",
            "--ctrl", "type=tcp,port=" + std::to_string(ctrl) + ",bindaddr=127.0.0.1",
            "--flags", "not-need-init,startup-clear"
        };
        std::vector<char*> argv;
        for (auto& a : args) argv.push_back(a.data());
        argv.push_back(nullptr);
        if (::posix_spawn(&pid_, argv[0], nullptr, nullptr, argv.data(), environ) != 0) {
            pid_ = -1;
            return;
        }

        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!portAccepts(port_) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        if (!portAccepts(port_)) return;

        if (const char* prev = std::getenv("VH_TPM_TCTI")) previousTcti_ = prev;
        ::setenv("VH_TPM_TCTI", ("swtpm:host=127.0.0.1,port=" + std::to_string(port_)).c_str(), 1);
        ready_ = true;
    }

    ~PrivateSwtpm() {
        if (ready_) {
            if (previousTcti_) ::setenv("VH_TPM_TCTI", previousTcti_->c_str(), 1);
            else ::unsetenv("VH_TPM_TCTI");
        }
        // Never block the suite on teardown: ask swtpm to exit, then signal it, and give up after a bounded wait.
        if (pid_ > 0) {
            shutdownViaControlChannel(ctrlPort_);
            if (!reapWithin(pid_, std::chrono::seconds(5))) {
                ::kill(pid_, SIGKILL);
                (void)reapWithin(pid_, std::chrono::seconds(2));
            }
        }
        std::error_code ec;
        fs::remove_all(state_, ec);
    }

    PrivateSwtpm(const PrivateSwtpm&) = delete;
    PrivateSwtpm& operator=(const PrivateSwtpm&) = delete;

    [[nodiscard]] bool ready() const { return ready_; }
    [[nodiscard]] const fs::path& stateDir() const { return state_; }

private:
    fs::path state_;
    pid_t pid_{-1};
    uint16_t port_{};
    uint16_t ctrlPort_{};
    bool ready_{};
    std::optional<std::string> previousTcti_;
};

} // namespace tpm_sealer_test

using tpm_sealer_test::PrivateSwtpm;

// Parallel unseals (DB pool connections opening together under parallel S3 multipart uploads) used to interleave on the
// TPM and exhaust its three transient object slots: Esys_Load failed with TPM_RC_OBJECT_MEMORY. They are serialized now.
TEST(TpmSealerTest, ConcurrentSealAndUnsealOnSwtpmNeverRunOutOfObjectContexts) {
    if (vh::platform::sealer::backend() != "tpm2") GTEST_SKIP() << "not the TPM backend on this platform";
    PrivateSwtpm tpm;
    if (!tpm.ready()) GTEST_SKIP() << "swtpm is not installed or did not start";

    const auto dir = tpm.stateDir() / "sealed";
    const std::vector<uint8_t> secret{'v', 'h', '-', 't', 'p', 'm', '-', 't', 'e', 's', 't'};
    vh::platform::sealer::seal(dir, "concurrent", secret);
    ASSERT_TRUE(vh::platform::sealer::complete(dir, "concurrent"));

    constexpr int kThreads = 6;
    std::atomic<int> unsealed{0};
    std::atomic<int> resealed{0};
    std::vector<std::string> errors(kThreads);
    std::vector<std::thread> threads;
    std::atomic<bool> go{false};
    for (int i = 0; i < kThreads; ++i) {
        threads.emplace_back([&, i] {
            while (!go.load()) std::this_thread::yield();
            try {
                if (vh::platform::sealer::unseal(dir, "concurrent") == secret) ++unsealed;
                // Seals interleave with the unseals too (a key rotation while connections open).
                const auto own = "own-" + std::to_string(i);
                vh::platform::sealer::seal(dir, own, secret);
                if (vh::platform::sealer::unseal(dir, own) == secret) ++resealed;
            } catch (const std::exception& e) {
                errors[static_cast<std::size_t>(i)] = e.what();
            }
        });
    }
    go.store(true);
    for (auto& t : threads) t.join();

    for (int i = 0; i < kThreads; ++i)
        EXPECT_TRUE(errors[static_cast<std::size_t>(i)].empty()) << "thread " << i << ": " << errors[static_cast<std::size_t>(i)];
    EXPECT_EQ(unsealed.load(), kThreads);
    EXPECT_EQ(resealed.load(), kThreads);
}

// A blob that is not this TPM's fails at once: only transient TPM warnings are retried.
TEST(TpmSealerTest, CorruptBlobFailsWithoutRetrying) {
    if (vh::platform::sealer::backend() != "tpm2") GTEST_SKIP() << "not the TPM backend on this platform";
    PrivateSwtpm tpm;
    if (!tpm.ready()) GTEST_SKIP() << "swtpm is not installed or did not start";

    const auto dir = tpm.stateDir() / "sealed";
    vh::platform::sealer::seal(dir, "corrupt", {1, 2, 3, 4});
    {
        std::ofstream priv(dir / "corrupt.priv", std::ios::binary | std::ios::trunc);
        priv << "not a TPM private blob";
    }

    try {
        (void)vh::platform::sealer::unseal(dir, "corrupt");
        ADD_FAILURE() << "a corrupt blob unsealed";
    } catch (const std::runtime_error& e) {
        EXPECT_NE(std::string(e.what()).find("Esys_Load failed"), std::string::npos) << e.what();
    }
}
