#include "preview/derive/Runner.hpp"

#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "platform/ChildProcess.hpp"
#include "platform/Fd.hpp"

#include <paths.h>

#include <fcntl.h>
#include <poll.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstring>
#include <exception>
#include <functional>
#include <mutex>
#include <set>
#include <string_view>
#include <system_error>
#include <thread>
#include <utility>

namespace vh::preview::derive {

// Named (not anonymous): Runner.cpp shares unity chunks with the rest of preview::derive.
namespace runner_impl {

constexpr std::size_t kStderrCap = 64 * 1024;
constexpr std::size_t kResultCap = 64 * 1024;
constexpr std::size_t kPipeChunk = 64 * 1024;
constexpr std::size_t kRangeRequestBytes = 16;
constexpr int kChildFdCount = 6;                       // 0..4 protocol fds, 5 = exec status (close-on-exec)
constexpr int kChildHighFdBase = 16;
constexpr auto kPollTick = std::chrono::milliseconds(20);   // stop requests and the thread-count watchdog
constexpr std::size_t kOutputChunksPerTick = 16;           // 1 MiB of artifact per poll iteration
constexpr auto kDrainGrace = std::chrono::seconds(2);  // pipes after the helper exited
constexpr auto kReapGrace = std::chrono::seconds(10);  // exit after SIGKILL (uninterruptible sleep)
constexpr uint64_t kCpuHardSlackSeconds = 5;

using Clock = std::chrono::steady_clock;

std::atomic<bool> gTrustChecksSkippedForTesting{false};

bool trustChecksEnforced() { return !(paths::testMode && gTrustChecksSkippedForTesting.load()); }

// Logs once per key for the daemon's lifetime: the queue runs the same helper for every job.
void logOnce(const std::string& key, const std::function<void()>& emit) {
    static std::mutex mutex;
    static std::set<std::string> logged;
    if (!log::Registry::isInitialized()) return;
    {
        const std::scoped_lock lock(mutex);
        if (!logged.insert(key).second) return;
    }
    emit();
}

class Fd {
public:
    Fd() = default;
    explicit Fd(const int fd) : fd_(fd) {}
    ~Fd() { reset(); }
    Fd(Fd&& other) noexcept : fd_(other.release()) {}
    Fd& operator=(Fd&& other) noexcept {
        if (this != &other) {
            reset();
            fd_ = other.release();
        }
        return *this;
    }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;

    [[nodiscard]] int get() const { return fd_; }
    [[nodiscard]] bool open() const { return fd_ >= 0; }
    int release() { return std::exchange(fd_, -1); }
    void reset() {
        if (fd_ >= 0) ::close(fd_);
        fd_ = -1;
    }

private:
    int fd_ = -1;
};

std::system_error sysError(const char* what) { return {errno, std::generic_category(), what}; }

void makePipe(Fd& readEnd, Fd& writeEnd) {
    std::array<int, 2> fds{};
    if (!platform::fd::pipe(fds.data())) throw sysError("pipe");
    readEnd = Fd(fds[0]);
    writeEnd = Fd(fds[1]);
}

void setNonBlocking(const Fd& fd) {
    const int flags = ::fcntl(fd.get(), F_GETFL);
    if (flags < 0 || ::fcntl(fd.get(), F_SETFL, flags | O_NONBLOCK) < 0) throw sysError("fcntl(O_NONBLOCK)");
}

void putLe(uint8_t* out, uint64_t value, const std::size_t bytes) {
    for (std::size_t i = 0; i < bytes; ++i, value >>= 8) out[i] = static_cast<uint8_t>(value & 0xffu);
}

uint64_t getLe(const uint8_t* in, const std::size_t bytes) {
    uint64_t value = 0;
    for (std::size_t i = bytes; i > 0; --i) value = (value << 8) | in[i - 1];
    return value;
}

// Everything the child needs, prepared before fork: after fork the child may only make async-signal-safe calls.
struct ChildPlan {
    const char* path = nullptr;
    char* const* argv = nullptr;
    char* const* envp = nullptr;
    std::array<int, kChildFdCount> fds{};   // sources for child fds 0..5
    rlimit as{}, cpu{}, fsize{}, nofile{}, core{};
    pid_t parent = 0;
    int closeLoopLimit = 1024;              // fallback when close_range(2) is unavailable (always on macOS)
};

[[noreturn]] void childExec(const ChildPlan& plan) noexcept {
    int statusFd = plan.fds[5];
    const auto fail = [&statusFd](const int err) {
        const ssize_t ignored = ::write(statusFd, &err, sizeof err);
        (void)ignored;
        ::_exit(127);
    };

    if (::setsid() < 0) fail(errno);
    if (const int armed = platform::child::armChild(plan.parent); armed < 0) ::_exit(127);   // the daemon died
    else if (armed != 0) fail(armed);

    sigset_t none;
    sigemptyset(&none);  // a macro on macOS: no ::
    ::sigprocmask(SIG_SETMASK, &none, nullptr);
    struct sigaction defaults{};
    defaults.sa_handler = SIG_DFL;
    for (int sig = 1; sig < NSIG; ++sig)
        if (sig != SIGKILL && sig != SIGSTOP) ::sigaction(sig, &defaults, nullptr);   // EINVAL for libc-reserved

    // Move every source above the target range first, so no dup2 clobbers a source that is still needed.
    std::array<int, kChildFdCount> high{};
    for (int i = 0; i < kChildFdCount; ++i) {
        high[static_cast<std::size_t>(i)] = ::fcntl(plan.fds[static_cast<std::size_t>(i)], F_DUPFD, kChildHighFdBase);
        if (high[static_cast<std::size_t>(i)] < 0) fail(errno);
    }
    statusFd = high[5];
    for (int i = 0; i < kChildFdCount; ++i)
        if (::dup2(high[static_cast<std::size_t>(i)], i) < 0) fail(errno);
    statusFd = 5;
    if (::fcntl(5, F_SETFD, FD_CLOEXEC) < 0) fail(errno);
    platform::child::closeFrom(6, plan.closeLoopLimit);

    if (const int err = platform::child::limitAddressSpace(plan.as); err != 0) fail(err);
    if (::setrlimit(RLIMIT_CPU, &plan.cpu) != 0 ||
        ::setrlimit(RLIMIT_FSIZE, &plan.fsize) != 0 || ::setrlimit(RLIMIT_NOFILE, &plan.nofile) != 0 ||
        ::setrlimit(RLIMIT_CORE, &plan.core) != 0)
        fail(errno);
    if (::chdir("/") != 0) fail(errno);

    ::execve(plan.path, plan.argv, plan.envp);
    fail(errno);
    ::_exit(127);   // unreachable; fail() does not return
}

rlimit limitOf(const uint64_t soft, const uint64_t hard) {
    return {static_cast<rlim_t>(soft), static_cast<rlim_t>(hard)};
}

// One helper process from spawn to reap.
class Session {
public:
    Session(const RunRequest& request, RunResult& result) : request_(request), result_(result) {}

    ~Session() {
        // Never leave an unreaped child behind, whatever unwound us.
        if (pid_ > 0 && !reaped_) {
            killGroup();
            reapBounded();
        }
    }

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    void run();

private:
    const RunRequest& request_;
    RunResult& result_;

    pid_t pid_ = -1;
    bool exited_ = false;   // exit observed (zombie), not necessarily reaped
    bool reaped_ = false;
    bool killed_ = false;
    Fd pidfd_, out_, err_, res_, range_;
    std::exception_ptr pending_;   // reader/sink failure, rethrown after reaping

    std::array<uint8_t, kRangeRequestBytes> request_buf_{};
    std::size_t request_have_ = 0;
    std::vector<uint8_t> reply_;
    std::size_t reply_sent_ = 0;
    std::string result_line_;

    void spawn();
    void serve();
    void killGroup();
    bool pollExited();
    void reap(int status);
    void reapBounded();
    void readOutput();
    void readStderr();
    void readResult();
    void readRangeRequest();
    void checkThreads();
    void writeRangeReply();
    void handleRangeRequest();
    void protocolViolation(const std::string& message);
    void finish();
};

void Session::spawn() {
    const auto& limits = request_.limits;
    const uint64_t inputSize = request_.input ? request_.input->size() : 0;

    std::vector<std::string> args{request_.executable.string(), request_.command,
                                  "--input-size", std::to_string(inputSize),
                                  "--max-output-bytes", std::to_string(limits.maxOutputBytes)};
    args.insert(args.end(), request_.args.begin(), request_.args.end());
    std::vector<char*> argv;
    argv.reserve(args.size() + 1);
    for (auto& arg : args) argv.push_back(arg.data());
    argv.push_back(nullptr);
    std::string lang = "LANG=C.UTF-8";
    std::array<char*, 2> envp{lang.data(), nullptr};

    Fd devnull(::open("/dev/null", O_RDONLY | O_CLOEXEC));
    if (!devnull.open()) throw sysError("open /dev/null");
    Fd outW, errW, resW, statusR, statusW;
    makePipe(out_, outW);
    makePipe(err_, errW);
    makePipe(res_, resW);
    makePipe(statusR, statusW);
    std::array<int, 2> sp{};
    if (platform::fd::socketpair(AF_UNIX, SOCK_STREAM, 0, sp.data()) != 0) throw sysError("socketpair");
    range_ = Fd(sp[0]);
    Fd rangeChild(sp[1]);

    ChildPlan plan;
    plan.path = args.front().c_str();
    plan.argv = argv.data();
    plan.envp = envp.data();
    plan.fds = {devnull.get(), outW.get(), errW.get(), rangeChild.get(), resW.get(), statusW.get()};
    plan.as = limitOf(limits.maxAddressSpaceBytes, limits.maxAddressSpaceBytes);
    plan.cpu = limitOf(limits.maxCpuSeconds, limits.maxCpuSeconds + kCpuHardSlackSeconds);
    plan.fsize = limitOf(0, 0);
    plan.nofile = limitOf(limits.maxOpenFiles, limits.maxOpenFiles);
    plan.core = limitOf(0, 0);
    plan.parent = ::getpid();
    if (rlimit current{}; ::getrlimit(RLIMIT_NOFILE, &current) == 0 && current.rlim_cur != RLIM_INFINITY)
        plan.closeLoopLimit = static_cast<int>(std::min<rlim_t>(current.rlim_cur, 1u << 20));

    // Linux _Fork: no atfork handlers run in the child (it only execs), async-signal-safe.
    pid_ = platform::child::forkForExec();
    if (pid_ < 0) throw sysError("fork");
    if (pid_ == 0) childExec(plan);

    devnull.reset();
    outW.reset();
    errW.reset();
    resW.reset();
    statusW.reset();
    rangeChild.reset();

    int execErr = 0;
    ssize_t got = 0;
    do got = ::read(statusR.get(), &execErr, sizeof execErr);
    while (got < 0 && errno == EINTR);
    if (got == static_cast<ssize_t>(sizeof execErr)) {
        result_.error = "exec " + request_.executable.string() + ": " + std::strerror(execErr);
        int status = 0;
        while (::waitpid(pid_, &status, 0) < 0 && errno == EINTR) {}
        reap(status);
        return;
    }

    if (const int fd = platform::child::exitWatchFd(pid_); fd >= 0) pidfd_ = Fd(fd);
    setNonBlocking(out_);
    setNonBlocking(err_);
    setNonBlocking(res_);
    setNonBlocking(range_);
}

void Session::killGroup() {
    if (pid_ <= 0 || reaped_) return;
    // The (possibly zombie) leader keeps the process-group id reserved until it is reaped.
    ::kill(-pid_, SIGKILL);
    ::kill(pid_, SIGKILL);
    killed_ = true;
}

bool Session::pollExited() {
    if (exited_ || reaped_) return true;
    siginfo_t info{};
    if (::waitid(P_PID, static_cast<id_t>(pid_), &info, WEXITED | WNOHANG | WNOWAIT) == 0 && info.si_pid == pid_)
        exited_ = true;
    return exited_;
}

void Session::reap(const int status) {
    reaped_ = true;
    exited_ = true;
    if (WIFEXITED(status)) result_.exitCode = WEXITSTATUS(status);
    else if (WIFSIGNALED(status)) {
        result_.exitCode = -1;
        result_.signal = WTERMSIG(status);
    }
}

void Session::reapBounded() {
    const auto deadline = Clock::now() + kReapGrace;
    while (true) {
        int status = 0;
        const pid_t got = ::waitpid(pid_, &status, WNOHANG);
        if (got == pid_) {
            reap(status);
            return;
        }
        if (got < 0 && errno != EINTR) {
            reaped_ = true;   // not our child any more (should not happen); nothing to wait for
            return;
        }
        if (Clock::now() >= deadline) break;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    // Stuck in uninterruptible sleep despite SIGKILL: reap it in the background rather than block the caller.
    result_.error = result_.error.empty() ? "helper did not exit after SIGKILL" : result_.error;
    std::thread([pid = pid_] {
        int status = 0;
        while (::waitpid(pid, &status, 0) < 0 && errno == EINTR) {}
    }).detach();
    reaped_ = true;
}

void Session::protocolViolation(const std::string& message) {
    if (result_.error.empty()) result_.error = "protocol: " + message;
    range_.reset();
    killGroup();
}

// At most kOutputChunksPerTick chunks per poll iteration (see readStderr).
void Session::readOutput() {
    std::array<uint8_t, kPipeChunk> buf{};
    for (std::size_t chunk = 0; chunk < kOutputChunksPerTick && out_.open(); ++chunk) {
        const ssize_t n = ::read(out_.get(), buf.data(), buf.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) return;
            out_.reset();
            return;
        }
        if (n == 0) {
            out_.reset();
            return;
        }
        const auto count = static_cast<uint64_t>(n);
        if (killed_ || pending_) continue;   // draining a run that is already failing
        if (count > request_.limits.maxOutputBytes - result_.outputBytes) {
            result_.outputLimitExceeded = true;
            killGroup();
            continue;
        }
        try {
            if (request_.sink) request_.sink(std::span<const uint8_t>(buf.data(), count));
            result_.outputBytes += count;
        } catch (...) {
            pending_ = std::current_exception();
            killGroup();
        }
    }
}

// One chunk per poll iteration: a helper flooding stderr must not keep serve() from its deadline checks.
void Session::readStderr() {
    std::array<char, kPipeChunk> buf{};
    if (err_.open()) {
        ssize_t n = 0;
        do n = ::read(err_.get(), buf.data(), buf.size());
        while (n < 0 && errno == EINTR);
        if (n < 0) {
            if (errno != EAGAIN) err_.reset();
            return;
        }
        if (n == 0) {
            err_.reset();
            return;
        }
        auto& tail = result_.stderrTail;
        tail.append(buf.data(), static_cast<std::size_t>(n));
        if (tail.size() > 2 * kStderrCap) tail.erase(0, tail.size() - kStderrCap);
    }
}

// One chunk per poll iteration (see readStderr).
void Session::readResult() {
    std::array<char, 4096> buf{};
    if (res_.open()) {
        ssize_t n = 0;
        do n = ::read(res_.get(), buf.data(), buf.size());
        while (n < 0 && errno == EINTR);
        if (n < 0) {
            if (errno != EAGAIN) res_.reset();
            return;
        }
        if (n == 0) {
            res_.reset();
            return;
        }
        const auto room = kResultCap - std::min(kResultCap, result_line_.size());
        result_line_.append(buf.data(), std::min(room, static_cast<std::size_t>(n)));
    }
}

void Session::checkThreads() {
    if (exited_ || killed_ || request_.limits.maxThreads == 0) return;
    const long threads = platform::child::threadCount(pid_);
    if (threads > 0 && static_cast<uint64_t>(threads) > request_.limits.maxThreads) {
        result_.threadLimitExceeded = true;
        killGroup();
    }
}

void Session::handleRangeRequest() {
    const uint64_t offset = getLe(request_buf_.data(), 8);
    const auto length = static_cast<uint32_t>(getLe(request_buf_.data() + 8, 4));
    const auto reserved = static_cast<uint32_t>(getLe(request_buf_.data() + 12, 4));
    request_have_ = 0;
    if (reserved != 0) return protocolViolation("reserved field is not zero");
    if (length > kMaxRangeRequest) return protocolViolation("range request of " + std::to_string(length) + " bytes");

    reply_.assign(4 + static_cast<std::size_t>(length), 0);
    std::size_t served = 0;
    if (request_.input && offset < request_.input->size()) {
        try {
            while (served < length) {
                const auto got = request_.input->read(offset + served,
                                                      std::span<uint8_t>(reply_.data() + 4 + served, length - served));
                if (got == 0) break;
                served += got;
            }
        } catch (...) {
            pending_ = std::current_exception();
            reply_.clear();
            range_.reset();
            killGroup();
            return;
        }
    }
    putLe(reply_.data(), served, 4);
    reply_.resize(4 + served);
    reply_sent_ = 0;
    result_.inputBytesServed += served;
}

void Session::readRangeRequest() {
    while (range_.open() && reply_.empty()) {
        const ssize_t n = ::recv(range_.get(), request_buf_.data() + request_have_,
                                 request_buf_.size() - request_have_, MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno != EAGAIN) range_.reset();
            return;
        }
        if (n == 0) {
            range_.reset();   // the helper is done pulling (or gone)
            return;
        }
        request_have_ += static_cast<std::size_t>(n);
        if (request_have_ == request_buf_.size()) handleRangeRequest();
    }
}

void Session::writeRangeReply() {
    while (range_.open() && reply_sent_ < reply_.size()) {
        const ssize_t n = ::send(range_.get(), reply_.data() + reply_sent_, reply_.size() - reply_sent_,
                                 MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN) return;
            range_.reset();   // EPIPE/ECONNRESET: the helper went away
            break;
        }
        reply_sent_ += static_cast<std::size_t>(n);
    }
    if (!range_.open() || reply_sent_ == reply_.size()) {
        reply_.clear();
        reply_sent_ = 0;
    }
}

void Session::serve() {
    const auto deadline = Clock::now() + request_.limits.wallTimeout;
    std::optional<Clock::time_point> drainDeadline;

    while (true) {
        if (exited_ && !reaped_) {
            killGroup();   // sweep anything left in the group while the zombie still holds the pgid
            int status = 0;
            pid_t got = 0;
            do got = ::waitpid(pid_, &status, 0);
            while (got < 0 && errno == EINTR);
            if (got == pid_) reap(status);
            else reaped_ = true;
            drainDeadline = Clock::now() + kDrainGrace;
            range_.reset();
        }
        if (reaped_ && !out_.open() && !err_.open() && !res_.open()) break;

        const auto now = Clock::now();
        if (drainDeadline && now >= *drainDeadline) break;
        if (!exited_ && !killed_ && request_.stop.stop_requested()) {
            if (result_.error.empty()) result_.error = "cancelled";
            killGroup();
        }
        if (!exited_ && now >= deadline && !result_.timedOut) {
            result_.timedOut = true;
            killGroup();
        }
        if (killed_ && !exited_ && now >= deadline + kReapGrace) {
            // SIGKILLed long ago and still not gone (uninterruptible sleep): stop serving, reap in the background.
            reapBounded();
            break;
        }

        std::vector<pollfd> fds;
        const auto watch = [&fds](const Fd& fd, const short events) {
            if (fd.open()) fds.push_back({fd.get(), events, 0});
        };
        watch(out_, POLLIN);
        watch(err_, POLLIN);
        watch(res_, POLLIN);
        if (!exited_) {
            watch(range_, reply_.empty() ? POLLIN : POLLOUT);
            watch(pidfd_, POLLIN);
        }

        auto wait = std::chrono::duration_cast<std::chrono::milliseconds>(
            (drainDeadline ? *drainDeadline : (result_.timedOut ? deadline + kReapGrace : deadline)) - now);
        // The thread watchdog (and stop requests, and exit detection without a pidfd) need a regular tick.
        if (!exited_) wait = std::min(wait, std::chrono::duration_cast<std::chrono::milliseconds>(kPollTick));
        wait = std::max(wait, std::chrono::milliseconds(1));
        const int ready = ::poll(fds.data(), fds.size(), static_cast<int>(wait.count()));
        if (ready < 0 && errno != EINTR) throw sysError("poll");

        // Serve the helper first: replies unblock it, and draining stdout keeps it from stalling.
        if (range_.open()) {
            if (!reply_.empty()) writeRangeReply();
            if (reply_.empty()) readRangeRequest();
            if (!reply_.empty()) writeRangeReply();
        }
        readOutput();
        readStderr();
        readResult();
        if (!exited_) pollExited();
        checkThreads();
    }
}

void Session::finish() {
    if (result_.stderrTail.size() > kStderrCap) result_.stderrTail.erase(0, result_.stderrTail.size() - kStderrCap);

    const auto newline = result_line_.find('\n');
    const std::string line = result_line_.substr(0, newline);
    if (!line.empty()) {
        auto parsed = nlohmann::json::parse(line, nullptr, false);
        if (!parsed.is_discarded() && parsed.is_object()) result_.result = std::move(parsed);
    }

    // A helper that refused to run unconfined (no Landlock or no seccomp on this host) is an operator problem worth
    // one error per binary; every job with it reports converter_unavailable.
    if (result_.failureReason() == "sandbox_unavailable") {
        std::string detail = "no detail";
        if (result_.result.is_object()) {
            const auto sandbox = result_.result.find("sandbox");
            if (sandbox != result_.result.end() && sandbox->is_object())
                detail = sandbox->value("detail", std::string{});
        }
        const auto exe = request_.executable.string();
        logOnce("sandbox:" + exe, [&] {
            log::Registry::thumb()->error(
                "[preview::derive] {} refuses to run: its sandbox is unavailable on this host ({}); conversions "
                "report converter_unavailable until Landlock and seccomp are available", exe, detail);
        });
    }
}

void Session::run() {
    spawn();
    if (!reaped_) serve();
    finish();
    if (pending_) std::rethrow_exception(pending_);
}

} // namespace runner_impl

// ── RunResult ───────────────────────────────────────────────────────────────────────────────────────────────

bool RunResult::ok() const {
    return exitCode == 0 && !signal && !timedOut && !outputLimitExceeded && error.empty() && result.is_object() &&
           result.value("ok", false);
}

std::string RunResult::failureReason() const {
    if (ok()) return "";
    if (timedOut) return "timeout";
    if (outputLimitExceeded || threadLimitExceeded) return "limit_exceeded";
    if (error == "cancelled") return "cancelled";
    if (!error.empty()) return error.starts_with("protocol:") ? "protocol" : "internal";
    if (signal) return *signal == SIGXCPU || *signal == SIGXFSZ ? "limit_exceeded" : "crashed";
    if (result.is_object()) {
        if (const auto it = result.find("error"); it != result.end() && it->is_string()) {
            const auto reason = it->get<std::string>();
            if (reason == "invalid_input" || reason == "limit_exceeded" || reason == "unsupported" ||
                reason == "sandbox_unavailable" || reason == "internal")
                return reason;
        }
    }
    switch (exitCode) {
        case 2: return "invalid_input";
        case 3: return "limit_exceeded";
        case 4: return "unsupported";
        case 5: return "sandbox_unavailable";
        default: return "internal";
    }
}

std::string RunResult::failureMessage() const {
    const auto reason = failureReason();
    if (reason.empty()) return "";
    std::string detail;
    if (timedOut) detail = "wall-clock timeout";
    else if (outputLimitExceeded) detail = "output limit exceeded";
    else if (threadLimitExceeded) detail = "thread limit exceeded";
    else if (!error.empty()) detail = error;
    else if (signal) detail = std::string("killed by signal ") + std::to_string(*signal) + " (" + ::strsignal(*signal) + ")";
    else if (result.is_object() && result.contains("message") && result["message"].is_string())
        detail = result["message"].get<std::string>();
    else detail = "exit code " + std::to_string(exitCode);
    return reason + ": " + detail;
}

// ── Runner ──────────────────────────────────────────────────────────────────────────────────────────────────

RunResult Runner::run(const RunRequest& request) {
    if (!isExecutable(request.executable))
        throw HelperUnavailable("converter helper not available: " + request.executable.string());
    if (!platform::child::addressSpaceLimitEnforced())
        runner_impl::logOnce("no-as-limit", [] {
            log::Registry::thumb()->warn("[preview::derive] This platform cannot cap a converter helper's address space "
                                           "(RLIMIT_AS); helpers run without the memory limit");
        });
    RunRequest resolved = request;
    if (runner_impl::trustChecksEnforced()) {
        // Resolve once, check that, execute that: every component of the canonical path is root-owned and not
        // group/world-writable, so it cannot change between the check and the exec (a symlink could).
        std::error_code ec;
        resolved.executable = std::filesystem::canonical(request.executable, ec);
        if (ec) throw HelperUnavailable("converter helper not available: " + request.executable.string());
        if (const auto problem = helperTrustProblem(resolved.executable); !problem.empty()) {
            const auto exe = request.executable.string();
            runner_impl::logOnce("trust:" + exe, [&] {
                log::Registry::thumb()->error("[preview::derive] refusing to run converter helper {}: {}", exe,
                                              problem);
            });
            throw HelperUnavailable("converter helper not trusted: " + exe + ": " + problem);
        }
    }
    RunResult result;
    runner_impl::Session session(resolved, result);
    session.run();
    return result;
}

std::filesystem::path Runner::helperPath(const std::string_view name) {
    if (name.empty() || name == "." || name == ".." || name.find('/') != std::string_view::npos ||
        name.find('\0') != std::string_view::npos)
        throw std::invalid_argument("invalid helper name");
    return config::Registry::get().preview.derive.helper_dir / std::string(name);
}

bool Runner::helperAvailable(const std::string_view name) {
    const auto path = helperPath(name);
    return isExecutable(path) && (!runner_impl::trustChecksEnforced() || helperTrustProblem(path).empty());
}

bool Runner::isExecutable(const std::filesystem::path& path) {
    struct stat st{};
    return ::stat(path.c_str(), &st) == 0 && S_ISREG(st.st_mode) &&
           ::faccessat(AT_FDCWD, path.c_str(), X_OK, AT_EACCESS) == 0;
}

std::string Runner::helperTrustProblem(const std::filesystem::path& path, const uid_t alsoTrustedOwner) {
    std::error_code ec;
    const auto canonical = std::filesystem::canonical(path, ec);
    if (ec) return "cannot resolve " + path.string() + ": " + ec.message();

    const auto check = [alsoTrustedOwner](const std::filesystem::path& p, const bool directory) -> std::string {
        struct stat st{};
        if (::lstat(p.c_str(), &st) != 0) return "cannot stat " + p.string() + ": " + std::strerror(errno);
        if (directory ? !S_ISDIR(st.st_mode) : !S_ISREG(st.st_mode))
            return p.string() + (directory ? " is not a directory" : " is not a regular file");
        if (st.st_uid != 0 && (alsoTrustedOwner == 0 || st.st_uid != alsoTrustedOwner))
            return p.string() + " is owned by uid " + std::to_string(st.st_uid) + ", not root";
        if ((st.st_mode & (S_IWGRP | S_IWOTH)) != 0) return p.string() + " is writable by group or others";
        return {};
    };

    if (auto problem = check(canonical, false); !problem.empty()) return problem;
    for (auto dir = canonical.parent_path();; dir = dir.parent_path()) {
        if (auto problem = check(dir, true); !problem.empty()) return problem;
        if (dir.parent_path() == dir) break;   // "/"
    }
    return {};
}

void Runner::setTrustChecksForTesting(const bool enforce) {
    if (paths::testMode) runner_impl::gTrustChecksSkippedForTesting.store(!enforce);
}

}
