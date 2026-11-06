#include "platform/Sealer.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/secrets/Reseal.hpp"
#include "db/Transactions.hpp"
#include "db/query/crypto/SecretExport.hpp"
#include <pqxx/pqxx>
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/MasterSecrets.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"

#include <paths.h>

#include <tss2/tss2_esys.h>
#include <tss2/tss2_tctildr.h>

#include <gtest/gtest.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/time.h>
#include <signal.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <map>
#include <memory>
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
        if (!spawn()) return;

        if (const char* prev = std::getenv("VH_TPM_TCTI")) previousTcti_ = prev;
        ::setenv("VH_TPM_TCTI", ("swtpm:host=127.0.0.1,port=" + std::to_string(port_)).c_str(), 1);
        ready_ = true;
    }

    // Starts swtpm on this instance's ports and state directory; true once it accepts connections.
    bool spawn() {
        std::vector<std::string> args{
            findOnPath("swtpm")->string(), "socket", "--tpm2",
            "--tpmstate", "dir=" + state_.string(),
            "--server", "type=tcp,port=" + std::to_string(port_) + ",bindaddr=127.0.0.1",
            "--ctrl", "type=tcp,port=" + std::to_string(ctrlPort_) + ",bindaddr=127.0.0.1",
            "--flags", "not-need-init,startup-clear"
        };
        std::vector<char*> argv;
        for (auto& a : args) argv.push_back(a.data());
        argv.push_back(nullptr);
        if (::posix_spawn(&pid_, argv[0], nullptr, nullptr, argv.data(), environ) != 0) {
            pid_ = -1;
            return false;
        }
        const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
        while (!portAccepts(port_) && std::chrono::steady_clock::now() < deadline)
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        return portAccepts(port_);
    }

    // A reboot: swtpm exits and starts again on the same state (same seeds, so blobs still load), and every PCR is back
    // to its initial value (TPM2_Startup(CLEAR)).
    bool reboot() {
        shutdownViaControlChannel(ctrlPort_);
        if (!reapWithin(pid_, std::chrono::seconds(5))) {
            ::kill(pid_, SIGKILL);
            (void)reapWithin(pid_, std::chrono::seconds(2));
        }
        pid_ = -1;
        return spawn();
    }

    // Extends PCR 7 (what a firmware, Secure Boot key or boot configuration change does to it).
    [[nodiscard]] bool extendPcr7() const {
        const auto tcti = "swtpm:host=127.0.0.1,port=" + std::to_string(port_);
        TSS2_TCTI_CONTEXT* ctx = nullptr;
        ESYS_CONTEXT* esys = nullptr;
        bool ok = false;
        if (Tss2_TctiLdr_Initialize(tcti.c_str(), &ctx) == TSS2_RC_SUCCESS &&
            Esys_Initialize(&esys, ctx, nullptr) == TSS2_RC_SUCCESS) {
            TPML_DIGEST_VALUES digests{};
            digests.count = 1;
            digests.digests[0].hashAlg = TPM2_ALG_SHA256;
            for (auto& b : digests.digests[0].digest.sha256) b = 0x5a;
            ok = Esys_PCR_Extend(esys, ESYS_TR_PCR7, ESYS_TR_PASSWORD, ESYS_TR_NONE, ESYS_TR_NONE, &digests) ==
                 TSS2_RC_SUCCESS;
        }
        if (esys) Esys_Finalize(&esys);
        if (ctx) Tss2_TctiLdr_Finalize(&ctx);
        return ok;
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
    vh::platform::sealer::seal(dir, "corrupt", std::vector<uint8_t>{1, 2, 3, 4});
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

// ---- the PCR 7 policy (#351) ---------------------------------------------------------------------------------------
//
// All on a private swtpm (skipped where there is none, or where the TPM can't unseal what it seals: the CI container's).
// "A firmware or Secure Boot change" is PCR_Extend on PCR 7; "a recovery boot" is restarting swtpm on the same state.

namespace tpm_pcr7_test {

namespace sealer = vh::platform::sealer;
namespace fs = std::filesystem;
using vh::platform::sealer::Policy;

const std::vector<uint8_t> kSecret{'p', 'c', 'r', '7', '-', 's', 'e', 'c', 'r', 'e', 't', '-', '0', '1', '2', '3'};

// Whether this TPM unseals what it seals at all (CI's container TPM answers Esys_Load with 0x1d5): the probe the other
// sealing tests use.
std::optional<std::string> sealingUnusable(const fs::path& dir) {
    try {
        sealer::seal(dir, "probe", kSecret);
        if (sealer::unseal(dir, "probe") != kSecret) return std::string("the backend returned a different secret");
        return std::nullopt;
    } catch (const std::exception& e) {
        return std::string(e.what());
    }
}

// Sets secrets.tpm_pcr_policy for a test and restores the config after.
struct PolicyConfig {
    vh::config::Config previous = vh::config::Registry::get();
    explicit PolicyConfig(const std::string& policy) {
        auto cfg = previous;
        cfg.secrets.tpm_pcr_policy = policy;
        vh::config::Registry::set(cfg);
    }
    ~PolicyConfig() { vh::config::Registry::set(previous); }
};

struct CrashHere {
    inline static std::string stage;
    static void hook(const std::string_view s) {
        if (s == stage) throw std::runtime_error("simulated crash at " + std::string(s));
    }
};

bool blobFileExists(const fs::path& p) { return fs::exists(p); }

}

namespace pcr7_sealer = vh::platform::sealer;
namespace pcr7_fs = std::filesystem;
using Pcr7Policy = vh::platform::sealer::Policy;

class TpmPcr7Test : public ::testing::Test {
protected:
    std::unique_ptr<PrivateSwtpm> tpm;
    pcr7_fs::path dir;

    void SetUp() override {
        if (vh::platform::sealer::backend() != "tpm2") GTEST_SKIP() << "not the TPM backend on this platform";
        tpm = std::make_unique<PrivateSwtpm>();
        if (!tpm->ready()) GTEST_SKIP() << "swtpm is not installed or did not start";
        dir = tpm->stateDir() / "sealed";
        if (const auto why = tpm_pcr7_test::sealingUnusable(dir)) GTEST_SKIP() << "sealing doesn't round-trip here: " << *why;
    }
    void TearDown() override { vh::platform::sealer::setResealHookForTesting(nullptr); }
};

TEST_F(TpmPcr7Test, ABoundBlobUnsealsWhilePcr7MatchesAndFailsClosedAfterItChanges) {
    using namespace tpm_pcr7_test;
    pcr7_sealer::seal(dir, "bound", kSecret, Pcr7Policy::Pcr7);
    pcr7_sealer::seal(dir, "plain", kSecret);
    EXPECT_EQ(pcr7_sealer::policyOf(dir, "bound"), Pcr7Policy::Pcr7);
    EXPECT_EQ(pcr7_sealer::policyOf(dir, "plain"), Pcr7Policy::None);
    EXPECT_EQ(pcr7_sealer::unseal(dir, "bound"), kSecret);

    ASSERT_TRUE(tpm->extendPcr7());

    try {
        (void)pcr7_sealer::unseal(dir, "bound");
        FAIL() << "a PCR 7-bound blob unsealed after PCR 7 changed";
    } catch (const pcr7_sealer::PolicyUnsatisfied& e) {
        const std::string what = e.what();
        EXPECT_NE(what.find("PCR 7"), std::string::npos);
        EXPECT_NE(what.find("vh secret reseal"), std::string::npos);
        EXPECT_NE(what.find("vh secret export"), std::string::npos);
        EXPECT_NE(what.find("vh vault keys import"), std::string::npos);
    }
    // The blob is untouched, and an unbound one never cared.
    EXPECT_EQ(pcr7_sealer::policyOf(dir, "bound"), Pcr7Policy::Pcr7);
    EXPECT_EQ(pcr7_sealer::unseal(dir, "plain"), kSecret);
}

TEST_F(TpmPcr7Test, TheBoundBlobHasNoPasswordPath) {
    // Without the policy session the empty password must not open it (USERWITHAUTH is off).
    using namespace tpm_pcr7_test;
    pcr7_sealer::seal(dir, "bound", kSecret, Pcr7Policy::Pcr7);
    const auto policyDigestPresent = pcr7_sealer::policyOf(dir, "bound") == Pcr7Policy::Pcr7;
    EXPECT_TRUE(policyDigestPresent);
    // Same TPM, same PCRs: unseal through the policy works; changing PCR 7 is the only thing that closes it, which the
    // previous test proves. Here: the blob's public part carries a non-empty auth policy and the attributes lack
    // USERWITHAUTH.
    std::ifstream pub(dir / "bound.pub", std::ios::binary);
    std::vector<char> raw((std::istreambuf_iterator<char>(pub)), {});
    TPMT_PUBLIC t{};
    ASSERT_GE(raw.size(), sizeof(t));
    std::memcpy(&t, raw.data(), sizeof(t));
    EXPECT_NE(t.authPolicy.size, 0);
    EXPECT_FALSE(t.objectAttributes & TPMA_OBJECT_USERWITHAUTH);
}

TEST_F(TpmPcr7Test, ResealRebindsAtTheCurrentPcrValuesWithoutChangingTheSecret) {
    using namespace tpm_pcr7_test;
    pcr7_sealer::seal(dir, "a", kSecret);
    auto r = pcr7_sealer::reseal(dir, "a", Pcr7Policy::Pcr7);
    EXPECT_TRUE(r.changed);
    EXPECT_EQ(r.from, Pcr7Policy::None);
    EXPECT_EQ(pcr7_sealer::policyOf(dir, "a"), Pcr7Policy::Pcr7);
    EXPECT_EQ(pcr7_sealer::unseal(dir, "a"), kSecret);
    EXPECT_FALSE(blobFileExists(dir / "a.staged.priv")) << "no staged leftovers";
    EXPECT_FALSE(blobFileExists(dir / "a.prev.priv")) << "no kept copy left";
    EXPECT_FALSE(blobFileExists(dir / "a.staged.pub"));
    EXPECT_FALSE(blobFileExists(dir / "a.prev.pub"));

    // Already at this policy and these PCR values: nothing to do.
    r = pcr7_sealer::reseal(dir, "a", Pcr7Policy::Pcr7);
    EXPECT_FALSE(r.changed);

    // PCR 7 changed on purpose (a planned update, resealed before the reboot would be the same call): the old binding
    // can't be opened any more, so the reseal refuses, typed, and leaves the blob alone.
    ASSERT_TRUE(tpm->extendPcr7());
    EXPECT_THROW(pcr7_sealer::reseal(dir, "a", Pcr7Policy::Pcr7), pcr7_sealer::PolicyUnsatisfied);
    EXPECT_EQ(pcr7_sealer::policyOf(dir, "a"), Pcr7Policy::Pcr7);
    EXPECT_FALSE(blobFileExists(dir / "a.prev.priv"));

    // A secret bound to the new value reseals again at the next change: the refresh an operator runs before a reboot.
    pcr7_sealer::seal(dir, "b", kSecret, Pcr7Policy::Pcr7);
    r = pcr7_sealer::reseal(dir, "b", Pcr7Policy::Pcr7);
    EXPECT_FALSE(r.changed);
    ASSERT_TRUE(tpm->extendPcr7());
    EXPECT_THROW((void)pcr7_sealer::unseal(dir, "b"), pcr7_sealer::PolicyUnsatisfied);
}

TEST_F(TpmPcr7Test, ResealToNoneRemovesTheBindingFromARecoveryBoot) {
    using namespace tpm_pcr7_test;
    pcr7_sealer::seal(dir, "a", kSecret, Pcr7Policy::Pcr7);
    ASSERT_TRUE(tpm->extendPcr7());
    EXPECT_THROW((void)pcr7_sealer::unseal(dir, "a"), pcr7_sealer::PolicyUnsatisfied);

    ASSERT_TRUE(tpm->reboot()) << "the recovery boot (PCR 7 back to its original value)";
    EXPECT_EQ(pcr7_sealer::unseal(dir, "a"), kSecret);
    const auto r = pcr7_sealer::reseal(dir, "a", Pcr7Policy::None);
    EXPECT_TRUE(r.changed);
    EXPECT_EQ(pcr7_sealer::policyOf(dir, "a"), Pcr7Policy::None);

    ASSERT_TRUE(tpm->extendPcr7());
    EXPECT_EQ(pcr7_sealer::unseal(dir, "a"), kSecret) << "no longer bound to PCR 7";
}

// A crash at every stage of the staged reseal leaves a pair that unseals or one recover() puts right, and the secret is
// the same afterwards. The kinds of stage: before anything is written, with the new blob beside the old, with the old
// kept, between the two renames (a torn pair), and after.
TEST_F(TpmPcr7Test, AResealCrashAtAnyStageLeavesTheSecretRecoverable) {
    using namespace tpm_pcr7_test;
    for (const char* stage : {"begin", "staged", "verified", "prev_kept", "pub_replaced", "priv_replaced", "installed", "done"}) {
        SCOPED_TRACE(stage);
        const std::string name = std::string("crash_") + stage;
        pcr7_sealer::seal(dir, name, kSecret);
        CrashHere::stage = stage;
        pcr7_sealer::setResealHookForTesting(&CrashHere::hook);
        EXPECT_THROW(pcr7_sealer::reseal(dir, name, Pcr7Policy::Pcr7), std::runtime_error);
        pcr7_sealer::setResealHookForTesting(nullptr);

        // What the daemon does at its next start (KeyProvider::init): recover, then unseal.
        pcr7_sealer::recover(dir, name);
        EXPECT_EQ(pcr7_sealer::unseal(dir, name), kSecret);
        EXPECT_FALSE(blobFileExists(dir / (name + ".staged.priv")));
        EXPECT_FALSE(blobFileExists(dir / (name + ".staged.pub")));
        EXPECT_FALSE(blobFileExists(dir / (name + ".prev.priv")));
        EXPECT_FALSE(blobFileExists(dir / (name + ".prev.pub")));

        // And the reseal can be run again to completion.
        (void)pcr7_sealer::reseal(dir, name, Pcr7Policy::Pcr7);
        EXPECT_EQ(pcr7_sealer::policyOf(dir, name), Pcr7Policy::Pcr7);
        EXPECT_EQ(pcr7_sealer::unseal(dir, name), kSecret);
    }
}

TEST_F(TpmPcr7Test, ATornPairIsRolledBackToTheKeptOldBlob) {
    using namespace tpm_pcr7_test;
    pcr7_sealer::seal(dir, "torn", kSecret);
    CrashHere::stage = "pub_replaced";  // new .pub over the old .priv: neither loads
    pcr7_sealer::setResealHookForTesting(&CrashHere::hook);
    EXPECT_THROW(pcr7_sealer::reseal(dir, "torn", Pcr7Policy::Pcr7), std::runtime_error);
    pcr7_sealer::setResealHookForTesting(nullptr);

    EXPECT_ANY_THROW((void)pcr7_sealer::unseal(dir, "torn")) << "the torn pair does not load";
    pcr7_sealer::recover(dir, "torn");
    EXPECT_EQ(pcr7_sealer::unseal(dir, "torn"), kSecret);
    EXPECT_EQ(pcr7_sealer::policyOf(dir, "torn"), Pcr7Policy::None) << "rolled back, not forward";
}

TEST_F(TpmPcr7Test, RecoverLeavesEverythingAloneWhilePcr7DoesNotMatch) {
    // After a crash, a PCR 7 that no longer matches means the live pair can't be judged: nothing is deleted.
    using namespace tpm_pcr7_test;
    pcr7_sealer::seal(dir, "x", kSecret, Pcr7Policy::Pcr7);
    CrashHere::stage = "installed";
    pcr7_sealer::setResealHookForTesting(&CrashHere::hook);
    EXPECT_THROW(pcr7_sealer::reseal(dir, "x", Pcr7Policy::None), std::runtime_error);
    pcr7_sealer::setResealHookForTesting(nullptr);
    ASSERT_TRUE(blobFileExists(dir / "x.prev.priv"));
    // The live blob is now unbound, so it still unseals after PCR 7 moves: recover just cleans.
    ASSERT_TRUE(tpm->extendPcr7());
    pcr7_sealer::recover(dir, "x");
    EXPECT_FALSE(blobFileExists(dir / "x.prev.priv"));
    EXPECT_EQ(pcr7_sealer::unseal(dir, "x"), kSecret);

    // A bound live blob with a kept copy and PCR 7 moved: keep every file.
    pcr7_sealer::seal(dir, "y", kSecret);
    CrashHere::stage = "installed";
    pcr7_sealer::setResealHookForTesting(&CrashHere::hook);
    EXPECT_THROW(pcr7_sealer::reseal(dir, "y", Pcr7Policy::Pcr7), std::runtime_error);
    pcr7_sealer::setResealHookForTesting(nullptr);
    ASSERT_TRUE(tpm->extendPcr7());
    pcr7_sealer::recover(dir, "y");
    EXPECT_TRUE(blobFileExists(dir / "y.prev.priv")) << "the kept copy survives while the live blob can't be judged";
    EXPECT_THROW((void)pcr7_sealer::unseal(dir, "y"), pcr7_sealer::PolicyUnsatisfied);
}

// The recovery drill (#351): enable the policy, seal, take the exports, change PCR 7 (a firmware update), watch the
// daemon's secrets fail closed with the typed error and mint nothing, then recover both documented ways.
class PcrDrillTest : public TpmPcr7Test {
protected:
    pcr7_fs::path oldBacking;
    void SetUp() override {
        TpmPcr7Test::SetUp();
        if (IsSkipped()) return;
        vh::paths::enableTestMode();
        oldBacking = vh::paths::backingPath;
        vh::paths::backingPath = tpm->stateDir() / "backing";
        pcr7_fs::create_directories(vh::paths::backingPath);
    }
    void TearDown() override {
        if (!oldBacking.empty()) vh::paths::backingPath = oldBacking;
        TpmPcr7Test::TearDown();
    }
};

TEST_F(PcrDrillTest, ConfigBindsNewSecretsAndNeverRebindsExistingOnes) {
    using vh::crypto::secrets::KeyProvider;
    std::vector<uint8_t> first;
    {
        KeyProvider before("test_drill_old");  // sealed with the policy off (the default)
        before.init();
        EXPECT_EQ(before.policy(), Pcr7Policy::None);
    }
    tpm_pcr7_test::PolicyConfig on("pcr7");
    KeyProvider fresh("test_drill_new");
    fresh.init();
    EXPECT_EQ(fresh.policy(), Pcr7Policy::Pcr7) << "a secret sealed now is bound";
    KeyProvider again("test_drill_old");
    again.init();
    EXPECT_EQ(again.policy(), Pcr7Policy::None) << "the setting alone never rebinds an existing blob";
}

TEST_F(PcrDrillTest, FirmwareChangeFailsClosedAndBothDocumentedRecoveriesWork) {
    using vh::crypto::secrets::KeyProvider;
    using vh::crypto::secrets::MasterSecretLost;
    tpm_pcr7_test::PolicyConfig on("pcr7");

    // 1. Seal with the policy on; the operator takes the export (here: the secret bytes `vh secret export` would hold).
    std::vector<uint8_t> exported;
    {
        KeyProvider master("test_drill_master");
        master.init();
        exported.assign(master.getMasterKey().begin(), master.getMasterKey().end());
    }
    ASSERT_EQ(exported.size(), 32u);
    {
        KeyProvider second("test_drill_second");  // also bound to the original PCR 7, for the recovery boot below
        second.init();
    }

    // 2. The firmware changes PCR 7.
    ASSERT_TRUE(tpm->extendPcr7());

    // 3. Fails closed, typed, with the recovery paths named; the blob stays and nothing new is minted over it.
    const auto blob = vh::paths::backingPath / ".sealed_test_drill_master.blob" / "test_drill_master.priv";
    std::error_code ec;
    const auto before = pcr7_fs::file_size(blob, ec);
    KeyProvider locked("test_drill_master");
    EXPECT_THROW(locked.init(), pcr7_sealer::PolicyUnsatisfied);
    EXPECT_THROW(locked.initGuarded([]() -> std::optional<std::string> { return std::string("3 vault key version(s)"); }),
                 pcr7_sealer::PolicyUnsatisfied);
    EXPECT_TRUE(locked.getMasterKey().empty());
    EXPECT_EQ(pcr7_fs::file_size(blob, ec), before);
    EXPECT_THROW(locked.reseal(Pcr7Policy::None), pcr7_sealer::PolicyUnsatisfied) << "a reseal can't open it either";

    // 4a. Recovery from the exports: set the unusable state aside (a new installation), the dependents make the daemon
    // say MasterSecretLost, and the restored secret (`vh secret set` / the vault key imports) is sealed under the new
    // PCR 7. The secret is the same one, so everything it wraps opens again.
    {
        KeyProvider gone("test_drill_master");
        gone.destroySealed();
        EXPECT_THROW(gone.initGuarded([]() -> std::optional<std::string> { return std::string("3 vault key version(s)"); }),
                     MasterSecretLost);
        gone.init(exported);
        EXPECT_TRUE(std::ranges::equal(gone.getMasterKey(), exported));
        EXPECT_EQ(gone.policy(), Pcr7Policy::Pcr7);
    }
    KeyProvider restored("test_drill_master");
    restored.init();
    EXPECT_TRUE(std::ranges::equal(restored.getMasterKey(), exported));

    // 4b. Recovery from a recovery boot: the original boot configuration returns (PCR 7 as it was), the secrets bound to
    // it open again, the policy is turned off and they are resealed.
    ASSERT_TRUE(tpm->reboot());  // back to the original PCR 7: the pre-change blobs open again
    KeyProvider boot("test_drill_second");
    boot.init();
    const auto bootSecret = std::vector<uint8_t>(boot.getMasterKey().begin(), boot.getMasterKey().end());
    EXPECT_EQ(boot.reseal(Pcr7Policy::None).to, Pcr7Policy::None);
    ASSERT_TRUE(tpm->extendPcr7());
    KeyProvider afterChange("test_drill_second");
    afterChange.init();  // no longer bound: unaffected by the next change
    EXPECT_TRUE(std::ranges::equal(afterChange.getMasterKey(), bootSecret));
}

TEST_F(PcrDrillTest, ResealRunRebindsEveryNameIsIdempotentAndStopsAtABrokenBlob) {
    using vh::crypto::secrets::KeyProvider;
    namespace reseal = vh::crypto::secrets::reseal;
    std::map<std::string, std::vector<uint8_t>> secrets;
    for (const char* n : {"test_rs_a", "test_rs_b", "test_rs_c"}) {
        KeyProvider p(n);
        p.init();
        secrets[n].assign(p.getMasterKey().begin(), p.getMasterKey().end());
    }
    ASSERT_EQ(KeyProvider::sealedNames().size(), 3u);

    auto report = reseal::run(Pcr7Policy::Pcr7);
    EXPECT_EQ(report.items.size(), 3u);
    EXPECT_EQ(report.changed(), 3u);
    for (const auto& e : reseal::inventory()) EXPECT_EQ(e.policy, Pcr7Policy::Pcr7) << e.name;
    for (const auto& [n, bytes] : secrets) {  // the secrets did not change
        KeyProvider p(n);
        p.init();
        EXPECT_TRUE(std::ranges::equal(p.getMasterKey(), bytes)) << n;
    }
    EXPECT_EQ(reseal::run(Pcr7Policy::Pcr7).changed(), 0u) << "already bound at these PCR values";

    EXPECT_EQ(reseal::run(Pcr7Policy::None).changed(), 3u);
    // A blob that no longer loads stops the run at its name; the ones before it stay resealed, the ones after untouched.
    {
        std::ofstream priv(vh::paths::backingPath / ".sealed_test_rs_b.blob" / "test_rs_b.priv", std::ios::binary | std::ios::trunc);
        priv << "garbage";
    }
    try {
        (void)reseal::run(Pcr7Policy::Pcr7);
        FAIL() << "a broken blob must stop the reseal";
    } catch (const std::runtime_error& e) {
        const std::string what = e.what();
        EXPECT_NE(what.find("test_rs_b"), std::string::npos) << what;
        EXPECT_NE(what.find("1 secret(s) resealed"), std::string::npos) << what;
    }
    std::map<std::string, Pcr7Policy> now;
    for (const auto& e : reseal::inventory()) now[e.name] = e.policy;
    EXPECT_EQ(now["test_rs_a"], Pcr7Policy::Pcr7);
    EXPECT_EQ(now["test_rs_c"], Pcr7Policy::None);
}

// `vh secret reseal` through the ops layer against a real database: the refusals, the confirmation, the audit-sensitive
// export record, and the reseal itself on swtpm (posture forced to "hardware", which swtpm can't be).
class PcrResealOpsTest : public PcrDrillTest {
protected:
    inline static bool dbReady = false;
    inline static bool dbTried = false;
    std::shared_ptr<vh::identities::User> admin;

    void SetUp() override {
        PcrDrillTest::SetUp();
        if (IsSkipped()) return;
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME")))
            GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        if (!dbTried) {
            dbTried = true;
            vh::db::Transactions::init();
            vh::db::seed::nuke_and_recreate_schema_public();
            vh::db::Transactions::dbPool_->initPreparedStatements();
            vh::seed::seed_database();
            vh::runtime::Deps::init();
            dbReady = true;
        }
        ASSERT_TRUE(dbReady);
        admin = vh::identities::manager().userByName("admin");
        ASSERT_TRUE(admin);
        vh::db::query::crypto::SecretExport::clearForTesting();
        vh::crypto::secrets::KeyProvider::setPostureForTesting("hardware");
    }
    void TearDown() override {
        vh::crypto::secrets::KeyProvider::setPostureForTesting(nullptr);
        PcrDrillTest::TearDown();
    }
};

TEST_F(PcrResealOpsTest, BindingIsRefusedWithoutAnExportThenConfirmedThenDone) {
    namespace ms = vh::ops::master_secrets;
    using vh::crypto::secrets::KeyProvider;
    {
        KeyProvider p("test_ops_a");
        p.init();
    }
    tpm_pcr7_test::PolicyConfig on("pcr7");

    // No export on record: refused, with the reason, and nothing changed.
    try {
        (void)ms::reseal(admin, {.expect = Pcr7Policy::Pcr7, .confirmed = true});
        FAIL() << "resealed without an export";
    } catch (const vh::ops::Refused& e) {
        EXPECT_EQ(e.code, "reseal_refused");
        EXPECT_NE(std::string(e.what()).find("vh secret export all"), std::string::npos) << e.what();
    }
    EXPECT_EQ(KeyProvider("test_ops_a").policy(), Pcr7Policy::None);

    // A stale one (older than 24 hours) is refused too.
    ms::recordSecretsExport(admin, {"db-password", "jwt-secret"});
    vh::db::query::crypto::SecretExport::ageForTesting(25 * 3600);
    EXPECT_THROW((void)ms::reseal(admin, {.expect = Pcr7Policy::Pcr7, .confirmed = true}), vh::ops::Refused);

    // A fresh export is not enough while a vault's key has no confirmed backup.
    ms::recordSecretsExport(admin, {"db-password", "jwt-secret"});
    try {
        (void)ms::reseal(admin, {.expect = Pcr7Policy::Pcr7, .confirmed = true});
        FAIL() << "resealed with an unbacked vault key";
    } catch (const vh::ops::Refused& e) {
        EXPECT_NE(std::string(e.what()).find("without a confirmed backup"), std::string::npos) << e.what();
    }
    // The seeded default vault has no key record at all (no engine ran): its key can't be backed up, so drop it for
    // the rest of this test and the gate sees a host whose vault keys are all backed up.
    vh::db::Transactions::exec("test::drop_vaults", [](pqxx::work& txn) { txn.exec("DELETE FROM vault"); });

    // Backed up and exported: the operation asks to confirm.
    EXPECT_THROW((void)ms::reseal(admin, {.expect = Pcr7Policy::Pcr7, .confirmed = false}), vh::ops::NeedsConfirmation);
    EXPECT_EQ(KeyProvider("test_ops_a").policy(), Pcr7Policy::None) << "asking changes nothing";

    // The flag must match the config the daemon read.
    EXPECT_THROW((void)ms::reseal(admin, {.expect = Pcr7Policy::None, .confirmed = true}), vh::ops::Invalid);

    const auto report = ms::reseal(admin, {.expect = Pcr7Policy::Pcr7, .confirmed = true});
    EXPECT_GE(report.changed(), 1u);
    EXPECT_EQ(report.changed(), report.items.size()) << "every sealed secret of the host, not just one";
    EXPECT_EQ(KeyProvider("test_ops_a").policy(), Pcr7Policy::Pcr7);

    // Policy status and the health warning see it.
    const auto status = ms::policyStatus(admin);
    EXPECT_EQ(status.bound, status.secrets.size());
    EXPECT_GE(status.bound, 1u);
    EXPECT_EQ(status.configured, "pcr7");
    EXPECT_FALSE(status.warning) << "an export from just now";
    vh::db::query::crypto::SecretExport::ageForTesting(31 * 24 * 3600);
    ASSERT_TRUE(ms::policyStatus(admin).warning);
}

TEST_F(PcrResealOpsTest, BindingIsRefusedWithoutHardwareAndRemovingItNeedsNoExport) {
    namespace ms = vh::ops::master_secrets;
    using vh::crypto::secrets::KeyProvider;
    vh::crypto::secrets::KeyProvider::setPostureForTesting("software");
    ms::recordSecretsExport(admin, {"db-password"});
    {
        tpm_pcr7_test::PolicyConfig on("pcr7");
        try {
            (void)ms::reseal(admin, {.confirmed = true});
            FAIL() << "swtpm must not be bound";
        } catch (const vh::ops::Refused& e) {
            EXPECT_NE(std::string(e.what()).find("no hardware TPM"), std::string::npos) << e.what();
        }
    }
    {
        KeyProvider p("test_ops_b");
        tpm_pcr7_test::PolicyConfig on("pcr7");
        p.init();
        EXPECT_EQ(p.policy(), Pcr7Policy::Pcr7);
    }
    vh::db::query::crypto::SecretExport::clearForTesting();
    tpm_pcr7_test::PolicyConfig off("none");
    const auto report = ms::reseal(admin, {.expect = Pcr7Policy::None, .confirmed = true});
    EXPECT_GE(report.changed(), 1u);
    EXPECT_EQ(KeyProvider("test_ops_b").policy(), Pcr7Policy::None);
}

TEST_F(PcrResealOpsTest, OnlyASuperAdminMayResealOrSeeThePolicy) {
    namespace ms = vh::ops::master_secrets;
    EXPECT_THROW((void)ms::policyStatus(nullptr), vh::ops::Error);
}
