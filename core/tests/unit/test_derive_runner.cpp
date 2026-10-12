#include "config/Config.hpp"
#include "platform/ChildProcess.hpp"
#include "config/Registry.hpp"
#include "ops/Config.hpp"
#include "ops/Error.hpp"
#include "preview/derive/Runner.hpp"
#include "preview/derive/Sandbox.hpp"
#include "storage/PlaintextReader.hpp"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <csignal>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <random>
#include <stdexcept>
#include <stop_token>
#include <string>
#include <thread>
#include <vector>

namespace vh::preview::derive::test_runner {

namespace fs = std::filesystem;

// In-memory PlaintextReader: the Runner only needs size() and read().
class MemoryReader final : public storage::PlaintextReader {
public:
    explicit MemoryReader(std::vector<uint8_t> data) : data_(std::move(data)) { generation_.size = data_.size(); }

    [[nodiscard]] uint64_t size() const override { return data_.size(); }

    std::size_t read(const uint64_t offset, std::span<uint8_t> out) override {
        reads.fetch_add(1);
        if (failAt && offset + out.size() > *failAt) throw storage::IntegrityError("tag mismatch");
        if (offset >= data_.size()) return 0;
        const auto n = std::min<std::size_t>(out.size(), data_.size() - offset);
        std::memcpy(out.data(), data_.data() + offset, n);
        return n;
    }

    [[nodiscard]] const storage::Generation& generation() const override { return generation_; }

    std::optional<uint64_t> failAt;
    std::atomic<uint64_t> reads{0};

private:
    std::vector<uint8_t> data_;
    storage::Generation generation_;
};

std::vector<uint8_t> randomBytes(const std::size_t size, const uint64_t seed) {
    std::mt19937_64 rng(seed);
    std::vector<uint8_t> data(size);
    for (auto& b : data) b = static_cast<uint8_t>(rng());
    return data;
}

uint64_t le(const uint8_t* p, const std::size_t bytes) {
    uint64_t v = 0;
    for (std::size_t i = bytes; i > 0; --i) v = (v << 8) | p[i - 1];
    return v;
}

class DeriveRunnerTest : public ::testing::Test {
protected:
    void SetUp() override {
        helper_ = VH_TEST_FAKE_HELPER;
        ASSERT_TRUE(Runner::isExecutable(helper_)) << helper_;
    }

    RunRequest request(const std::string& command, storage::PlaintextReader* input = nullptr) {
        RunRequest r;
        r.executable = helper_;
        r.command = command;
        r.input = input;
        r.limits.wallTimeout = std::chrono::seconds(30);
        r.sink = [this](std::span<const uint8_t> bytes) { output_.insert(output_.end(), bytes.begin(), bytes.end()); };
        return r;
    }

    static void expectNoChildren() {
        // Every helper was reaped: nothing left to wait for.
        errno = 0;
        EXPECT_EQ(::waitpid(-1, nullptr, WNOHANG), -1);
        EXPECT_EQ(errno, ECHILD);
    }

    fs::path helper_;
    std::vector<uint8_t> output_;
};

TEST_F(DeriveRunnerTest, StreamsInputThroughTheHelperAndParsesTheResult) {
    MemoryReader reader(randomBytes((3u << 20) + 12345, 7));
    const auto res = Runner::run(request("echo", &reader));

    EXPECT_TRUE(res.ok()) << res.failureMessage() << " stderr: " << res.stderrTail;
    EXPECT_EQ(res.exitCode, 0);
    EXPECT_FALSE(res.signal);
    EXPECT_EQ(res.result.value("bytes", 0ull), reader.size());
    EXPECT_EQ(res.outputBytes, reader.size());
    EXPECT_EQ(res.inputBytesServed, reader.size());
    std::vector<uint8_t> expected(reader.size());
    reader.read(0, expected);
    EXPECT_TRUE(output_ == expected);
    EXPECT_EQ(res.failureReason(), "");
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, RangePullsAtRandomOffsetsMatchTheReader) {
    const auto data = randomBytes((5u << 20) + 77, 99);
    MemoryReader reader(data);
    auto r = request("ranges", &reader);
    r.args = {"--count", "150", "--seed", "4242"};
    const auto res = Runner::run(r);
    ASSERT_TRUE(res.ok()) << res.failureMessage() << " stderr: " << res.stderrTail;

    std::size_t pos = 0, ranges = 0;
    while (pos + 16 <= output_.size()) {
        const uint64_t offset = le(&output_[pos], 8);
        const uint64_t asked = le(&output_[pos + 8], 4);
        const uint64_t got = le(&output_[pos + 12], 4);
        pos += 16;
        const uint64_t expectedLen = offset >= data.size() ? 0 : std::min<uint64_t>(asked, data.size() - offset);
        ASSERT_EQ(got, expectedLen) << "range " << ranges << " at " << offset;
        ASSERT_LE(pos + got, output_.size());
        ASSERT_TRUE(std::equal(output_.begin() + static_cast<std::ptrdiff_t>(pos),
                               output_.begin() + static_cast<std::ptrdiff_t>(pos + got),
                               data.begin() + static_cast<std::ptrdiff_t>(std::min<uint64_t>(offset, data.size()))))
            << "range " << ranges << " at " << offset;
        pos += got;
        ++ranges;
    }
    EXPECT_EQ(pos, output_.size());
    EXPECT_EQ(ranges, 150u);
}

TEST_F(DeriveRunnerTest, OutputCapKillsTheHelper) {
    auto r = request("flood");
    r.limits.maxOutputBytes = 1u << 20;
    const auto res = Runner::run(r);
    EXPECT_FALSE(res.ok());
    EXPECT_TRUE(res.outputLimitExceeded);
    EXPECT_EQ(res.signal, SIGKILL);
    EXPECT_LE(res.outputBytes, 1u << 20);
    EXPECT_LE(output_.size(), 1u << 20);
    EXPECT_EQ(res.failureReason(), "limit_exceeded");
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, WallClockTimeoutKillsTheProcessGroup) {
    auto r = request("sleep");
    r.limits.wallTimeout = std::chrono::milliseconds(300);
    const auto start = std::chrono::steady_clock::now();
    const auto res = Runner::run(r);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(res.timedOut);
    EXPECT_EQ(res.signal, SIGKILL);
    EXPECT_EQ(res.failureReason(), "timeout");
    EXPECT_LT(elapsed, std::chrono::seconds(5));
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, AStopRequestKillsTheProcessGroupLongBeforeTheTimeout) {
    std::stop_source stop;
    auto r = request("sleep");
    r.stop = stop.get_token();
    std::jthread canceller([&stop] {
        std::this_thread::sleep_for(std::chrono::milliseconds(200));
        stop.request_stop();
    });
    const auto start = std::chrono::steady_clock::now();
    const auto res = Runner::run(r);
    EXPECT_LT(std::chrono::steady_clock::now() - start, std::chrono::seconds(5));   // wall timeout is 30 s
    EXPECT_FALSE(res.ok());
    EXPECT_FALSE(res.timedOut);
    EXPECT_EQ(res.signal, SIGKILL);
    EXPECT_EQ(res.failureReason(), "cancelled");
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, ACrashIsReportedNotThrown) {
    RunResult res;
    ASSERT_NO_THROW(res = Runner::run(request("crash")));
    EXPECT_EQ(res.signal, SIGSEGV);
    EXPECT_EQ(res.exitCode, -1);
    EXPECT_EQ(res.failureReason(), "crashed");
    EXPECT_NE(res.failureMessage().find("signal"), std::string::npos);

    // The daemon (this process) carries on and the next run works.
    MemoryReader reader(randomBytes(1000, 1));
    EXPECT_TRUE(Runner::run(request("echo", &reader)).ok());
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, AddressSpaceLimitStopsAllocation) {
    if (!vh::platform::child::addressSpaceLimitEnforced())
        GTEST_SKIP() << "no RLIMIT_AS on this platform; the daemon-side memory cap is roadmap #218";
    auto r = request("alloc");
    r.limits.maxAddressSpaceBytes = 256ull << 20;
    const auto res = Runner::run(r);
    EXPECT_FALSE(res.ok());
    const auto reason = res.failureReason();
    EXPECT_TRUE(reason == "limit_exceeded" || reason == "crashed") << reason;
    if (res.result.is_object()) {
        EXPECT_LT(res.result.value("allocated", 0ull), 256ull << 20);
    }
}

TEST_F(DeriveRunnerTest, ChildGetsAnEmptyEnvironmentOnlyProtocolFdsAndLimits) {
    // A non-close-on-exec descriptor in the daemon must not reach the helper.
    const int leaky = ::open("/dev/null", O_RDONLY);
    ASSERT_GE(leaky, 0);
    auto r = request("inspect");
    r.limits.maxAddressSpaceBytes = 1ull << 30;
    r.limits.maxCpuSeconds = 17;
    const auto res = Runner::run(r);
    ::close(leaky);
    ASSERT_TRUE(res.ok()) << res.failureMessage() << " stderr: " << res.stderrTail;
    const auto& j = res.result;

    EXPECT_EQ(j["env"], nlohmann::json::array({"LANG=C.UTF-8"}));
    EXPECT_EQ(j["fds"], nlohmann::json::array({0, 1, 2, 3, 4})) << j["fds"].dump();
    EXPECT_EQ(j["stdin"], "/dev/null");
    EXPECT_EQ(j["cwd"], "/");
#if defined(__linux__)
    EXPECT_EQ(j["no_new_privs"], 1);
    EXPECT_EQ(j["pdeathsig"], SIGKILL);
#else
    // macOS has neither (platform/ChildProcess.hpp): the daemon kills the process group itself.
    EXPECT_TRUE(j["no_new_privs"].is_null());
    EXPECT_TRUE(j["pdeathsig"].is_null());
#endif
    EXPECT_EQ(j["session_leader"], true);
    EXPECT_EQ(j["sigmask_empty"], true);
    EXPECT_EQ(j["sigpipe_default"], true);
    if (vh::platform::child::addressSpaceLimitEnforced())
        EXPECT_EQ(j["rlimit_as"]["soft"].get<double>(), static_cast<double>(1ull << 30));
    EXPECT_EQ(j["rlimit_cpu"]["soft"].get<double>(), 17.0);
    EXPECT_EQ(j["rlimit_cpu"]["hard"].get<double>(), 22.0);
    EXPECT_EQ(j["rlimit_fsize"]["soft"].get<double>(), 0.0);
    EXPECT_EQ(j["rlimit_nofile"]["soft"].get<double>(), 64.0);
    EXPECT_EQ(j["rlimit_core"]["hard"].get<double>(), 0.0);
}

TEST_F(DeriveRunnerTest, ProtocolViolationsKillTheHelper) {
    MemoryReader reader(randomBytes(4096, 3));
    for (const char* command : {"badproto", "bigrequest"}) {
        const auto res = Runner::run(request(command, &reader));
        EXPECT_FALSE(res.ok()) << command;
        EXPECT_EQ(res.failureReason(), "protocol") << command << ": " << res.error;
        EXPECT_EQ(res.signal, SIGKILL) << command;
    }
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, ReaderFailureIsRethrownAfterTheHelperIsReaped) {
    MemoryReader reader(randomBytes(4u << 20, 5));
    reader.failAt = 2u << 20;
    EXPECT_THROW(Runner::run(request("echo", &reader)), storage::IntegrityError);
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, SinkFailureIsRethrownAfterTheHelperIsReaped) {
    MemoryReader reader(randomBytes(2u << 20, 6));
    auto r = request("echo", &reader);
    r.sink = [](std::span<const uint8_t>) { throw std::runtime_error("disk full"); };
    EXPECT_THROW(Runner::run(r), std::runtime_error);
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, AHelperThatStopsReadingRepliesCannotWedgeTheDaemon) {
    MemoryReader reader(randomBytes(8u << 20, 8));
    auto r = request("stall-read", &reader);
    r.limits.wallTimeout = std::chrono::milliseconds(500);
    const auto res = Runner::run(r);
    EXPECT_TRUE(res.timedOut);
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, ExitCodesWithoutAResultMapToReasons) {
    const std::vector<std::pair<std::string, std::string>> cases{
        {"2", "invalid_input"}, {"3", "limit_exceeded"}, {"4", "unsupported"}, {"5", "sandbox_unavailable"},
        {"1", "internal"}, {"0", "internal"}};
    for (const auto& [code, reason] : cases) {
        auto r = request("exit");
        r.args = {"--code", code};
        const auto res = Runner::run(r);
        EXPECT_FALSE(res.ok()) << code;   // exit 0 without a result is not success
        EXPECT_EQ(res.failureReason(), reason) << code;
        EXPECT_TRUE(res.result.is_null()) << code;
    }
}

TEST_F(DeriveRunnerTest, StderrIsCapturedAndTruncatedToTheTail) {
    auto r = request("stderr");
    r.args = {"--bytes", std::to_string(1u << 20)};
    const auto res = Runner::run(r);
    EXPECT_TRUE(res.ok()) << res.failureMessage();
    EXPECT_EQ(res.stderrTail.size(), 64u * 1024u);
    EXPECT_TRUE(res.stderrTail.ends_with("END-OF-STDERR\n"));
}

// A helper writing stderr as fast as it can (several threads, a 1 MiB pipe) used to keep readStderr looping until
// EAGAIN, so serve() never got back to its deadline check.
TEST_F(DeriveRunnerTest, AStderrFloodCannotOutrunTheWallTimeout) {
    auto r = request("stderr-flood");
    r.args = {"--writers", "8"};
    r.limits.wallTimeout = std::chrono::milliseconds(300);
    const auto start = std::chrono::steady_clock::now();
    const auto res = Runner::run(r);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(res.timedOut);
    EXPECT_EQ(res.failureReason(), "timeout");
    EXPECT_LT(elapsed, std::chrono::seconds(5));
    EXPECT_LE(res.stderrTail.size(), 64u * 1024u);
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, AThreadBombIsKilledAtTheThreadCap) {
    auto r = request("threads");
    r.args = {"--count", "500"};
    r.limits.maxThreads = 16;
    r.limits.wallTimeout = std::chrono::seconds(20);
    const auto start = std::chrono::steady_clock::now();
    const auto res = Runner::run(r);
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_TRUE(res.threadLimitExceeded);
    EXPECT_FALSE(res.timedOut);
    EXPECT_EQ(res.signal, SIGKILL);
    EXPECT_EQ(res.failureReason(), "limit_exceeded");
    EXPECT_NE(res.failureMessage().find("thread limit"), std::string::npos) << res.failureMessage();
    EXPECT_LT(elapsed, std::chrono::seconds(5));
    expectNoChildren();

    // Within the cap nothing fires (the run ends at its wall timeout instead).
    r.args = {"--count", "4"};
    r.limits.wallTimeout = std::chrono::milliseconds(400);
    const auto calm = Runner::run(r);
    EXPECT_FALSE(calm.threadLimitExceeded);
    EXPECT_TRUE(calm.timedOut);
    expectNoChildren();
}

// gtest_main switches the trust checks off for build-tree helpers; this test turns them back on.
class TrustChecksOn {
public:
    TrustChecksOn() { Runner::setTrustChecksForTesting(true); }
    ~TrustChecksOn() { Runner::setTrustChecksForTesting(false); }
    TrustChecksOn(const TrustChecksOn&) = delete;
    TrustChecksOn& operator=(const TrustChecksOn&) = delete;
};

TEST_F(DeriveRunnerTest, HelpersMustBeRootOwnedAndNotWritableByOthers) {
    const TrustChecksOn on;
    // Under /tmp, the sticky world-writable directory the checks below rely on ($TMPDIR on macOS is a private 0700
    // directory), canonical because macOS's /tmp is a symlink to /private/tmp and problems name the real path.
    const auto dir = fs::canonical("/tmp") / ("vh-derive-trust-" + std::to_string(::getpid()));
    fs::remove_all(dir);
    fs::create_directories(dir);
    fs::permissions(dir, fs::perms::owner_all);

    // Root-owned binary in root-owned directories: trusted, also behind a symlink (the canonical path is checked
    // and executed).
    ASSERT_TRUE(fs::is_regular_file("/usr/bin/true"));
    EXPECT_EQ(Runner::helperTrustProblem("/usr/bin/true"), "");
    fs::create_symlink("/usr/bin/true", dir / "true-link");
    EXPECT_EQ(Runner::helperTrustProblem(dir / "true-link"), "");

    // The developer's build tree is not root-owned: refused by run() and by helperAvailable().
    if (::geteuid() != 0) {
        const auto problem = Runner::helperTrustProblem(helper_);
        EXPECT_NE(problem.find("not root"), std::string::npos) << problem;
        EXPECT_THROW(Runner::run(request("echo")), HelperUnavailable);
        const auto saved = config::Registry::get();
        auto cfg = saved;
        cfg.preview.derive.helper_dir = helper_.parent_path();
        config::Registry::set(cfg);
        EXPECT_FALSE(Runner::helperAvailable("vh_fake_derive_helper"));
        config::Registry::set(saved);
    }

    // Permission checks, trusting this test's uid for ownership: a group/world-writable file or ancestor directory
    // (here the sticky, world-writable temp directory) is refused.
    const auto file = dir / "helper";
    std::ofstream(file) << "#!/bin/sh\nexit 0\n";
    fs::permissions(file, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec);
    auto problem = Runner::helperTrustProblem(file, ::geteuid());
    EXPECT_NE(problem.find("writable by group or others"), std::string::npos) << problem;
    EXPECT_EQ(problem.find(file.string()), std::string::npos) << "the file itself is fine: " << problem;
    fs::permissions(file, fs::perms::group_write, fs::perm_options::add);
    problem = Runner::helperTrustProblem(file, ::geteuid());
    EXPECT_EQ(problem, file.string() + " is writable by group or others");
    EXPECT_NE(Runner::helperTrustProblem(dir / "missing"), "");
    EXPECT_NE(Runner::helperTrustProblem(dir), "");   // not a regular file

    fs::remove_all(dir);
}

TEST_F(DeriveRunnerTest, MissingOrNonExecutableHelpersAreUnavailable) {
    const auto dir = fs::temp_directory_path() / ("vh-derive-runner-" + std::to_string(::getpid()));
    fs::create_directories(dir);
    const auto plain = dir / "not-executable";
    std::ofstream(plain) << "#!/bin/sh\nexit 0\n";
    fs::permissions(plain, fs::perms::owner_read | fs::perms::owner_write);

    auto r = request("echo");
    r.executable = dir / "missing";
    EXPECT_THROW(Runner::run(r), HelperUnavailable);
    r.executable = plain;
    EXPECT_THROW(Runner::run(r), HelperUnavailable);
    r.executable = dir;
    EXPECT_THROW(Runner::run(r), HelperUnavailable);
    EXPECT_FALSE(Runner::isExecutable(plain));

    // Executable but exec fails (missing interpreter): reported, not thrown.
    const auto broken = dir / "broken-interpreter";
    std::ofstream(broken) << "#!/nonexistent/interpreter\n";
    fs::permissions(broken, fs::perms::owner_all);
    r.executable = broken;
    const auto res = Runner::run(r);
    EXPECT_FALSE(res.ok());
    EXPECT_EQ(res.exitCode, 127);
    EXPECT_NE(res.error.find("exec"), std::string::npos) << res.error;
    EXPECT_EQ(res.failureReason(), "internal");

    fs::remove_all(dir);
    expectNoChildren();
}

TEST_F(DeriveRunnerTest, HelperPathResolvesUnderTheConfiguredDirectory) {
    const auto saved = config::Registry::get();
    auto cfg = saved;
    cfg.preview.derive.helper_dir = fs::path(VH_TEST_FAKE_HELPER).parent_path();
    config::Registry::set(cfg);
    EXPECT_EQ(Runner::helperPath("vh_fake_derive_helper"), fs::path(VH_TEST_FAKE_HELPER));
    EXPECT_TRUE(Runner::helperAvailable("vh_fake_derive_helper"));
    EXPECT_FALSE(Runner::helperAvailable("vaulthalla-no-such-helper"));
    EXPECT_THROW((void)Runner::helperPath("../etc/passwd"), std::invalid_argument);
    EXPECT_THROW((void)Runner::helperPath(".."), std::invalid_argument);
    EXPECT_THROW((void)Runner::helperPath(""), std::invalid_argument);
    config::Registry::set(saved);
}

TEST_F(DeriveRunnerTest, ConcurrentRunsKeepTheirChannelsApart) {
    std::vector<std::thread> threads;
    std::atomic<int> okCount{0};
    for (int i = 0; i < 6; ++i) {
        threads.emplace_back([&, i] {
            MemoryReader reader(randomBytes(static_cast<std::size_t>(300000 + i * 7919), static_cast<uint64_t>(i)));
            std::vector<uint8_t> out;
            RunRequest r;
            r.executable = helper_;
            r.command = "echo";
            r.input = &reader;
            r.limits.wallTimeout = std::chrono::seconds(30);
            r.sink = [&out](std::span<const uint8_t> b) { out.insert(out.end(), b.begin(), b.end()); };
            const auto res = Runner::run(r);
            std::vector<uint8_t> expected(reader.size());
            reader.read(0, expected);
            if (res.ok() && out == expected) okCount.fetch_add(1);
        });
    }
    for (auto& t : threads) t.join();
    EXPECT_EQ(okCount.load(), 6);
    expectNoChildren();
}

// ── preview.* config ────────────────────────────────────────────────────────────────────────────────────────

class PreviewConfigTest : public ::testing::Test {
protected:
    fs::path write(const std::string& yaml) {
        path_ = fs::temp_directory_path() / ("vh-preview-config-" + std::to_string(::getpid()) + ".yaml");
        std::ofstream(path_) << yaml;
        return path_;
    }
    void TearDown() override {
        if (!path_.empty()) fs::remove(path_);
    }
    fs::path path_;
};

TEST_F(PreviewConfigTest, MissingSectionKeepsEveryDefault) {
    const auto cfg = config::loadConfig(write("sharing:\n  enabled: true\n").string());
    const auto& p = cfg.preview;
    EXPECT_EQ(p.media.integrity, config::PreviewIntegrityMode::Optimistic);
    EXPECT_EQ(p.media.remote, config::PreviewRemoteMode::Hydrate);
    EXPECT_EQ(p.media.hwaccel, config::PreviewHwaccel::Auto);
    EXPECT_EQ(p.media.transcode, config::PreviewTranscodeMode::OnDemand);
    EXPECT_EQ(p.derive.helper_dir, fs::path("/usr/lib/vaulthalla/helpers"));
    EXPECT_EQ(p.derive.max_concurrency, 2u);
    EXPECT_EQ(p.derive.max_queue, 64u);
    EXPECT_EQ(p.derive.max_ram_mb, 2048u);
    EXPECT_EQ(p.derive.max_cpu_seconds, 300u);
    EXPECT_EQ(p.derive.wall_timeout_seconds, 600u);
    EXPECT_EQ(p.derive.max_output_mb, 512u);
    EXPECT_EQ(p.derive.failure_ttl_hours, 24u);
    EXPECT_EQ(p.text.max_edit_bytes, 2u * 1024u * 1024u);
    EXPECT_EQ(p.max_render_pixels, 64'000'000u);
}

TEST_F(PreviewConfigTest, PartialSectionOverridesOnlyTheGivenKeys) {
    const auto cfg = config::loadConfig(write(R"(preview:
  media:
    integrity: strict
    hwaccel: vaapi
  derive:
    helper_dir: /opt/vh/helpers
    max_ram_mb: 4096
    max_concurrency: 0
)").string());
    const auto& p = cfg.preview;
    EXPECT_EQ(p.media.integrity, config::PreviewIntegrityMode::Strict);
    EXPECT_EQ(p.media.remote, config::PreviewRemoteMode::Hydrate);
    EXPECT_EQ(p.media.hwaccel, config::PreviewHwaccel::Vaapi);
    EXPECT_EQ(p.derive.helper_dir, fs::path("/opt/vh/helpers"));
    EXPECT_EQ(p.derive.max_ram_mb, 4096u);
    EXPECT_EQ(p.derive.max_concurrency, 1u);   // clamped
    EXPECT_EQ(p.derive.max_queue, 64u);
    EXPECT_EQ(p.text.max_edit_bytes, 2u * 1024u * 1024u);
}

// settings.update (console) and the CLI settings writes go through ops::config::validateSettings: which helper
// executables the daemon runs is config.yaml-only.
TEST_F(PreviewConfigTest, HelperDirIsReadOnlyThroughSettingsWrites) {
    nlohmann::json doc = config::Registry::get();
    EXPECT_NO_THROW(ops::config::validateSettings(doc));
    doc["preview"]["derive"]["helper_dir"] = "/tmp/elsewhere";
    EXPECT_THROW(ops::config::validateSettings(doc), ops::Invalid);
    nlohmann::json other = config::Registry::get();
    other["preview"]["derive"]["max_concurrency"] = 3;   // the rest of the section stays editable
    EXPECT_NO_THROW(ops::config::validateSettings(other));
}

TEST_F(PreviewConfigTest, UnknownEnumValuesAreRejected) {
    EXPECT_THROW(config::loadConfig(write("preview:\n  media:\n    remote: sometimes\n").string()), std::invalid_argument);
}

TEST_F(PreviewConfigTest, ShippedDefaultConfigLoadsWithDefaults) {
    const auto shipped = fs::path(VH_TEST_ASSETS_DIR).parent_path().parent_path() / "deploy/config/config.yaml";
    const auto cfg = config::loadConfig(shipped.string());
    EXPECT_EQ(cfg.preview.derive.helper_dir, fs::path("/usr/lib/vaulthalla/helpers"));
    EXPECT_EQ(cfg.preview.derive.max_output_mb, 512u);
}

TEST_F(PreviewConfigTest, ShippedCommentedDefaultsMatchTheBuiltInDefaults) {
    // deploy/config/config.yaml documents the preview section commented out; uncommented it must change nothing.
    const auto shipped = fs::path(VH_TEST_ASSETS_DIR).parent_path().parent_path() / "deploy/config/config.yaml";
    std::ifstream in(shipped);
    std::string line, yaml;
    bool inBlock = false;
    while (std::getline(in, line)) {
        if (line == "#preview:") inBlock = true;
        else if (inBlock && !line.starts_with("#")) break;
        if (inBlock) yaml += line.substr(1) + "\n";
    }
    ASSERT_FALSE(yaml.empty());
    const auto documented = config::loadConfig(write(yaml).string()).preview;
    const config::PreviewConfig builtIn;
    EXPECT_EQ(nlohmann::json(documented), nlohmann::json(builtIn)) << yaml;
}

TEST_F(PreviewConfigTest, JsonRoundTripAndLimitsFromConfig) {
    config::Config cfg;
    cfg.preview.derive.max_ram_mb = 1024;
    cfg.preview.derive.max_cpu_seconds = 42;
    cfg.preview.derive.wall_timeout_seconds = 7;
    cfg.preview.derive.max_output_mb = 3;
    cfg.preview.media.remote = config::PreviewRemoteMode::Off;
    nlohmann::json j = cfg.preview;
    config::PreviewConfig back;
    j.get_to(back);
    EXPECT_EQ(back.derive.max_cpu_seconds, 42u);
    EXPECT_EQ(back.media.remote, config::PreviewRemoteMode::Off);

    const auto saved = config::Registry::get();
    auto updated = saved;
    updated.preview = cfg.preview;
    config::Registry::set(updated);
    const auto limits = limitsFromConfig();
    config::Registry::set(saved);
    EXPECT_EQ(limits.maxAddressSpaceBytes, 1024ull << 20);
    EXPECT_EQ(limits.maxCpuSeconds, 42u);
    EXPECT_EQ(limits.wallTimeout, std::chrono::seconds(7));
    EXPECT_EQ(limits.maxOutputBytes, 3ull << 20);
}

}
