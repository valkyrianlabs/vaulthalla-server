#pragma once

#include <nlohmann/json.hpp>

#include <chrono>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <sys/types.h>
#include <utility>
#include <vector>

// Filesystem probes run in vh_fs_actor (core/tests/helpers/fs_actor.cpp), a separate single-threaded process started
// with posix_spawn and switched to the probe's uid/gid before it reads anything. The harness talks to it one JSON line
// per request over a socketpair and enforces a deadline per operation. On expiry it kills the actor's process group
// and, if the actor doesn't exit within a short bound (stuck in a FUSE request the daemon never answers), aborts this
// run's own FUSE connection through fusectl and records a wedge. It never waits without a bound.
namespace vh::test::integration::fuse {

struct ActorReply {
    int err = 0;              // errno from the actor; ETIMEDOUT on a wedge, EIO/ENOEXEC when the actor failed
    std::string error;        // strerror text or why the harness gave up
    nlohmann::json body;      // the full reply line
    bool wedge = false;       // the per-op deadline expired
};

class FsActor {
public:
    FsActor(uid_t uid, gid_t gid, std::vector<gid_t> groups = {});
    ~FsActor();

    FsActor(const FsActor&) = delete;
    FsActor& operator=(const FsActor&) = delete;

    // One request, one reply, within the per-op deadline (VH_TEST_FS_OP_TIMEOUT_MS).
    ActorReply call(nlohmann::json request);

    [[nodiscard]] bool alive() const { return pid_ > 0 && fd_ >= 0; }
    [[nodiscard]] pid_t pid() const { return pid_; }

    // Asks the actor to exit and reaps it, all within a short bound.
    void shutdown();

private:
    uid_t uid_;
    gid_t gid_;
    pid_t pid_ = -1;
    int fd_ = -1;
    long nextId_ = 1;
    std::string buffer_;
    std::string startError_;

    bool sendLine(const std::string& line, std::chrono::steady_clock::time_point deadline, std::string& why);
    // 1 = line read, 0 = deadline expired, -1 = the actor closed its end / errored.
    int readLine(std::string& line, std::chrono::steady_clock::time_point deadline, std::string& why);
    ActorReply onDeadline(const std::string& what);
    ActorReply onBroken(const std::string& what);
    bool reapWithin(std::chrono::milliseconds bound, int* status = nullptr);
    void closeFd();
};

// One actor per (uid, gid) per scenario: FUSE scenarios reset the pool when they finish.
class ActorPool {
public:
    FsActor& get(uid_t uid, gid_t gid);
    void reset();

private:
    std::mutex mutex_;
    std::map<std::pair<uid_t, gid_t>, std::unique_ptr<FsActor>> actors_;
};

ActorPool& actors();

[[nodiscard]] std::chrono::milliseconds opTimeout();
[[nodiscard]] std::string actorPath();

// Wedges recorded this run (each one is also a failed test) and actors that could not be reaped at all.
[[nodiscard]] int wedgeCount();
[[nodiscard]] std::vector<pid_t> unreapedActors();

// Writes `abort` to /sys/fs/fuse/connections/<id>/abort for this run's own mount (found in /proc/self/mountinfo by
// mount point). Returns what happened, for the failure message.
std::string abortOwnFuseConnection();

}
