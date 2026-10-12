#include "fuse/Actor.hpp"

#include <paths.h>

#include <atomic>
#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <poll.h>
#include <spawn.h>
#include <sstream>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

#ifndef VH_FS_ACTOR_DEFAULT
#define VH_FS_ACTOR_DEFAULT ""
#endif

extern char** environ;

namespace vh::test::integration::fuse {

namespace {

using Clock = std::chrono::steady_clock;

constexpr auto kReapBound = std::chrono::milliseconds(2000);
constexpr auto kShutdownBound = std::chrono::milliseconds(1000);

std::atomic<int> g_wedges{0};
std::mutex g_unreapedMutex;
std::vector<pid_t> g_unreaped;

int remainingMs(const Clock::time_point deadline) {
    const auto left = std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
    return left <= 0 ? 0 : static_cast<int>(std::min<long long>(left, 60'000));
}

std::string stderrSink() {
    if (const char* dir = std::getenv("VH_TEST_REPORT_DIR"); dir && *dir) {
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);
        return (std::filesystem::path(dir) / "fs_actor.stderr.log").string();
    }
    return "/dev/null";
}

}

std::chrono::milliseconds opTimeout() {
    if (const char* v = std::getenv("VH_TEST_FS_OP_TIMEOUT_MS"); v && *v) {
        try {
            const auto ms = std::stol(v);
            if (ms > 0) return std::chrono::milliseconds(ms);
        } catch (...) {}
    }
    return std::chrono::milliseconds(10'000);
}

std::string actorPath() {
    if (const char* v = std::getenv("VH_FS_ACTOR"); v && *v) return v;
    return VH_FS_ACTOR_DEFAULT;
}

int wedgeCount() { return g_wedges.load(); }

std::vector<pid_t> unreapedActors() {
    std::scoped_lock lock(g_unreapedMutex);
    return g_unreaped;
}

std::string abortOwnFuseConnection() {
    const auto mount = std::filesystem::path(paths::getMountPath()).lexically_normal().string();
    std::ifstream in("/proc/self/mountinfo");
    std::string line;
    while (std::getline(in, line)) {
        std::istringstream fields(line);
        std::string id, parent, devno, root, mountPoint;
        if (!(fields >> id >> parent >> devno >> root >> mountPoint)) continue;
        if (mountPoint != mount) continue;
        const auto colon = devno.find(':');
        if (colon == std::string::npos) return "fusectl abort skipped: unreadable device id " + devno;
        const auto major = std::stoul(devno.substr(0, colon));
        const auto minor = std::stoul(devno.substr(colon + 1));
        const auto conn = std::to_string((major << 20) | minor);
        const auto abortPath = "/sys/fs/fuse/connections/" + conn + "/abort";
        const int fd = ::open(abortPath.c_str(), O_WRONLY | O_CLOEXEC);
        if (fd < 0) return "fusectl abort of connection " + conn + " failed: " + std::strerror(errno);
        const ssize_t w = ::write(fd, "abort\n", 6);
        const int err = w < 0 ? errno : 0;
        ::close(fd);
        if (err) return "fusectl abort of connection " + conn + " failed: " + std::strerror(err);
        return "aborted FUSE connection " + conn + " (" + mount + ")";
    }
    return "fusectl abort skipped: " + mount + " is not mounted";
}

FsActor::FsActor(const uid_t uid, const gid_t gid, std::vector<gid_t> groups) : uid_(uid), gid_(gid) {
    const auto path = actorPath();
    if (path.empty()) {
        startError_ = "no vh_fs_actor binary (set VH_FS_ACTOR)";
        return;
    }

    int sv[2];
    if (::socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0, sv) != 0) {
        startError_ = std::string("socketpair: ") + std::strerror(errno);
        return;
    }

    std::vector<std::string> args{path, "--uid", std::to_string(uid), "--gid", std::to_string(gid)};
    if (!groups.empty()) {
        std::string list;
        for (const auto g : groups) list += (list.empty() ? "" : ",") + std::to_string(g);
        args.emplace_back("--groups");
        args.push_back(list);
    }
    std::vector<char*> argv;
    for (auto& a : args) argv.push_back(a.data());
    argv.push_back(nullptr);

    const auto sink = stderrSink();
    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_adddup2(&fa, sv[1], STDIN_FILENO);
    posix_spawn_file_actions_adddup2(&fa, sv[1], STDOUT_FILENO);
    posix_spawn_file_actions_addopen(&fa, STDERR_FILENO, sink.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    // Nothing else of the daemon's leaks into the actor (above all not /dev/fuse).
    posix_spawn_file_actions_addclosefrom_np(&fa, 3);

    posix_spawnattr_t attr;
    posix_spawnattr_init(&attr);
    sigset_t none, defaults;
    sigemptyset(&none);
    sigfillset(&defaults);
    sigdelset(&defaults, SIGKILL);
    sigdelset(&defaults, SIGSTOP);
    posix_spawnattr_setsigmask(&attr, &none);
    posix_spawnattr_setsigdefault(&attr, &defaults);
    posix_spawnattr_setpgroup(&attr, 0);  // its own group: a kill reaches anything it started (cp -a)
    posix_spawnattr_setflags(&attr, POSIX_SPAWN_SETSIGMASK | POSIX_SPAWN_SETSIGDEF | POSIX_SPAWN_SETPGROUP);

    pid_t pid = -1;
    const int rc = ::posix_spawn(&pid, path.c_str(), &fa, &attr, argv.data(), environ);
    posix_spawn_file_actions_destroy(&fa);
    posix_spawnattr_destroy(&attr);
    ::close(sv[1]);
    if (rc != 0) {
        ::close(sv[0]);
        startError_ = "posix_spawn " + path + ": " + std::strerror(rc);
        return;
    }
    pid_ = pid;
    fd_ = sv[0];

    std::string line, why;
    const auto deadline = Clock::now() + opTimeout();
    const int got = readLine(line, deadline, why);
    if (got != 1) {
        startError_ = got == 0 ? "vh_fs_actor did not get ready in time" : "vh_fs_actor exited before ready: " + why;
        shutdown();
        return;
    }
    try {
        const auto ready = nlohmann::json::parse(line);
        if (!ready.value("ready", false)) {
            startError_ = "vh_fs_actor refused: " + ready.value("error", line);
            shutdown();
        }
    } catch (const std::exception& e) {
        startError_ = std::string("vh_fs_actor sent a bad ready line: ") + e.what();
        shutdown();
    }
}

FsActor::~FsActor() { shutdown(); }

void FsActor::closeFd() {
    if (fd_ >= 0) ::close(fd_);
    fd_ = -1;
}

bool FsActor::reapWithin(const std::chrono::milliseconds bound, int* status) {
    if (pid_ <= 0) return true;
    const auto deadline = Clock::now() + bound;
    for (;;) {
        int st = 0;
        const pid_t w = ::waitpid(pid_, &st, WNOHANG);
        if (w == pid_ || (w < 0 && errno == ECHILD)) {
            if (status) *status = st;
            pid_ = -1;
            return true;
        }
        if (Clock::now() >= deadline) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
}

void FsActor::shutdown() {
    if (pid_ <= 0) {
        closeFd();
        return;
    }
    if (fd_ >= 0) {
        std::string why;
        (void)sendLine(R"({"id":0,"op":"exit"})", Clock::now() + kShutdownBound, why);
        closeFd();  // EOF ends the actor's read loop too
    }
    if (reapWithin(kShutdownBound)) return;
    ::kill(-pid_, SIGKILL);
    ::kill(pid_, SIGKILL);
    if (reapWithin(kReapBound)) return;
    std::scoped_lock lock(g_unreapedMutex);
    g_unreaped.push_back(pid_);
    pid_ = -1;
}

bool FsActor::sendLine(const std::string& line, const Clock::time_point deadline, std::string& why) {
    const std::string framed = line + "\n";
    std::size_t off = 0;
    while (off < framed.size()) {
        pollfd pfd{fd_, POLLOUT, 0};
        const int prc = ::poll(&pfd, 1, remainingMs(deadline));
        if (prc < 0) {
            if (errno == EINTR) continue;
            why = std::string("poll: ") + std::strerror(errno);
            return false;
        }
        if (prc == 0) {
            why = "deadline";
            return false;
        }
        const ssize_t n = ::send(fd_, framed.data() + off, framed.size() - off, MSG_NOSIGNAL | MSG_DONTWAIT);
        if (n < 0) {
            if (errno == EINTR || errno == EAGAIN) continue;
            why = std::string("send: ") + std::strerror(errno);
            return false;
        }
        off += static_cast<std::size_t>(n);
    }
    return true;
}

int FsActor::readLine(std::string& line, const Clock::time_point deadline, std::string& why) {
    for (;;) {
        if (const auto nl = buffer_.find('\n'); nl != std::string::npos) {
            line = buffer_.substr(0, nl);
            buffer_.erase(0, nl + 1);
            return 1;
        }
        pollfd pfd{fd_, POLLIN, 0};
        const int prc = ::poll(&pfd, 1, remainingMs(deadline));
        if (prc < 0) {
            if (errno == EINTR) continue;
            why = std::string("poll: ") + std::strerror(errno);
            return -1;
        }
        if (prc == 0) return 0;
        char buf[65536];
        const ssize_t n = ::recv(fd_, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) {
            buffer_.append(buf, static_cast<std::size_t>(n));
            continue;
        }
        if (n == 0) {
            why = "the actor closed its end";
            return -1;
        }
        if (errno == EINTR || errno == EAGAIN) continue;
        why = std::string("recv: ") + std::strerror(errno);
        return -1;
    }
}

ActorReply FsActor::onDeadline(const std::string& what) {
    g_wedges.fetch_add(1);
    std::string detail = "wedge: " + what + " exceeded the " + std::to_string(opTimeout().count()) +
                         " ms deadline (uid " + std::to_string(uid_) + "); killed the actor";
    const pid_t pid = pid_;
    closeFd();
    if (pid > 0) {
        ::kill(-pid, SIGKILL);
        ::kill(pid, SIGKILL);
        if (!reapWithin(kReapBound)) {
            // Stuck in a FUSE request the daemon never answers: SIGKILL can't land until the request ends.
            detail += "; it did not exit, " + abortOwnFuseConnection();
            if (!reapWithin(kReapBound)) {
                detail += "; still not reaped (pid " + std::to_string(pid) + "), continuing without it";
                std::scoped_lock lock(g_unreapedMutex);
                g_unreaped.push_back(pid);
                pid_ = -1;
            }
        }
    }
    std::cerr << "[fs_actor] " << detail << std::endl;
    return {.err = ETIMEDOUT, .error = detail, .body = {}, .wedge = true};
}

ActorReply FsActor::onBroken(const std::string& what) {
    closeFd();
    int status = 0;
    std::string detail = "vh_fs_actor failed: " + what;
    if (pid_ > 0) {
        ::kill(-pid_, SIGKILL);
        ::kill(pid_, SIGKILL);
        if (reapWithin(kReapBound, &status)) {
            if (WIFSIGNALED(status)) detail += " (killed by signal " + std::to_string(WTERMSIG(status)) + ")";
            else if (WIFEXITED(status)) detail += " (exit " + std::to_string(WEXITSTATUS(status)) + ")";
        }
    }
    return {.err = EIO, .error = detail, .body = {}, .wedge = false};
}

ActorReply FsActor::call(nlohmann::json request) {
    if (!startError_.empty()) return {.err = ENOEXEC, .error = startError_, .body = {}, .wedge = false};
    if (!alive()) return {.err = EIO, .error = "vh_fs_actor is gone (an earlier op killed it)", .body = {}, .wedge = false};

    const long id = nextId_++;
    request["id"] = id;
    const auto what = request.value("op", std::string("?")) + " " + request.value("path", std::string());
    const auto deadline = Clock::now() + opTimeout();

    std::string why;
    if (!sendLine(request.dump(), deadline, why)) return why == "deadline" ? onDeadline(what) : onBroken(why);

    for (;;) {
        std::string line;
        const int got = readLine(line, deadline, why);
        if (got == 0) return onDeadline(what);
        if (got < 0) return onBroken(why);
        nlohmann::json reply;
        try {
            reply = nlohmann::json::parse(line);
        } catch (const std::exception& e) {
            return onBroken(std::string("bad reply line: ") + e.what());
        }
        if (!reply.contains("id") || reply["id"] != id) continue;  // a stale reply from an earlier request
        ActorReply out;
        out.err = reply.value("errno", EIO);
        out.error = reply.value("error", std::string());
        out.body = std::move(reply);
        return out;
    }
}

FsActor& ActorPool::get(const uid_t uid, const gid_t gid) {
    std::scoped_lock lock(mutex_);
    auto& slot = actors_[{uid, gid}];
    if (!slot || !slot->alive()) slot = std::make_unique<FsActor>(uid, gid);
    return *slot;
}

void ActorPool::reset() {
    std::scoped_lock lock(mutex_);
    actors_.clear();
}

ActorPool& actors() {
    static ActorPool pool;
    return pool;
}

}
