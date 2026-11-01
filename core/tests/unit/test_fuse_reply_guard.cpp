// #263: a FUSE op that threw before replying (a DB pool timeout, an unknown inode in rename) left its kernel request
// unanswered, so the caller hung. Every op is now registered through fuse::task::Guard, which answers it.
//
// These tests drive the daemon's real lowlevel ops through a real libfuse session: requests are written to one end of
// a socketpair (fuse_session_custom_io instead of /dev/fuse), processed by fuse::task::Request exactly as the mount
// loop does, and the replies read back from the other end with a deadline. The pool timeout is real too: the
// Transactions pool is swapped for one with no connections and a 50 ms acquire timeout, so the first database access
// an op makes throws db::PoolAcquireTimeout. No database server is needed.

#include "db/DBPool.hpp"
#include "db/Transactions.hpp"
#include "fuse/Bridge.hpp"
#include "fuse/task/Request.hpp"
#include "runtime/Deps.hpp"
#include "stats/model/FuseStats.hpp"

#include <gtest/gtest.h>
#include <linux/fuse.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

namespace vh::test_fuse_reply_guard {

using stats::model::FuseOperation;

constexpr int kReplyDeadlineMs = 10'000;

// Linux uids no identity is ever loaded for, so the identity index misses and goes to the database.
std::atomic<uint32_t> nextUid{0x7ff00000};

ssize_t ioWritev(const int fd, iovec* iov, const int count, void*) { return ::writev(fd, iov, count); }
ssize_t ioRead(const int fd, void* buf, const size_t len, void*) { return ::read(fd, buf, len); }

struct Reply {
    uint64_t unique{};
    int error{};  // positive errno, 0 for success
};

// One libfuse session over a socketpair, initialised (FUSE_INIT answered) and ready for requests.
class Session {
public:
    explicit Session(const fuse_lowlevel_ops& ops) {
        if (::socketpair(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0, fds_) != 0) throw std::system_error(errno, std::generic_category());
        char arg0[] = "vh_test_fuse_reply_guard";
        char* argv[] = {arg0, nullptr};
        fuse_args args = FUSE_ARGS_INIT(1, argv);
        session_ = fuse_session_new(&args, &ops, sizeof(ops), nullptr);
        fuse_opt_free_args(&args);
        if (!session_) throw std::runtime_error("fuse_session_new failed");
        const fuse_custom_io io{.writev = ioWritev, .read = ioRead, .splice_receive = nullptr, .splice_send = nullptr};
        if (fuse_session_custom_io(session_, &io, fds_[1]) != 0) throw std::runtime_error("fuse_session_custom_io failed");
        fds_[1] = -1;  // the session owns it now

        fuse_init_in init{};
        init.major = FUSE_KERNEL_VERSION;
        init.minor = 31;
        init.max_readahead = 128 * 1024;
        const auto reply = roundTrip(FUSE_INIT, 0, 0, {reinterpret_cast<const char*>(&init), sizeof(init)});
        if (!reply || reply->error != 0) throw std::runtime_error("FUSE_INIT was not accepted");
    }

    ~Session() {
        if (session_) fuse_session_destroy(session_);
        if (fds_[0] >= 0) ::close(fds_[0]);
        if (fds_[1] >= 0) ::close(fds_[1]);
    }

    Session(const Session&) = delete;
    Session& operator=(const Session&) = delete;

    // Sends one request, lets the daemon's task::Request process it, and returns its reply; nullopt when none came
    // within the deadline (the #263 hang).
    std::optional<Reply> roundTrip(const uint32_t opcode, const uint64_t nodeid, const uint32_t uid,
                                   const std::string_view payload, const int deadlineMs = kReplyDeadlineMs) {
        fuse_in_header in{};
        in.len = static_cast<uint32_t>(sizeof(in) + payload.size());
        in.opcode = opcode;
        in.unique = ++unique_;
        in.nodeid = nodeid;
        in.uid = uid;
        in.gid = uid;
        in.pid = static_cast<uint32_t>(::getpid());
        std::string message(reinterpret_cast<const char*>(&in), sizeof(in));
        message.append(payload);
        if (::write(fds_[0], message.data(), message.size()) != static_cast<ssize_t>(message.size()))
            throw std::system_error(errno, std::generic_category(), "write request");

        fuse_buf buf{};
        if (fuse_session_receive_buf(session_, &buf) <= 0) throw std::runtime_error("fuse_session_receive_buf failed");
        fuse::task::Request(session_, buf)();

        pollfd p{.fd = fds_[0], .events = POLLIN, .revents = 0};
        if (::poll(&p, 1, deadlineMs) != 1) return std::nullopt;
        std::vector<char> out(64 * 1024);
        const auto n = ::read(fds_[0], out.data(), out.size());
        if (n < static_cast<ssize_t>(sizeof(fuse_out_header))) throw std::runtime_error("short reply");
        fuse_out_header header{};
        std::memcpy(&header, out.data(), sizeof(header));
        if (header.unique != in.unique) throw std::runtime_error("reply to another request");
        if (static_cast<ssize_t>(header.len) != n) throw std::runtime_error("reply length mismatch");
        return Reply{header.unique, -header.error};
    }

    // Whether nothing more was answered.
    bool quiet(const int ms) const {
        pollfd p{.fd = fds_[0], .events = POLLIN, .revents = 0};
        return ::poll(&p, 1, ms) == 0;
    }

private:
    int fds_[2]{-1, -1};
    fuse_session* session_ = nullptr;
    uint64_t unique_ = 0;
};

std::string names(const std::initializer_list<std::string_view> parts) {
    std::string out;
    for (const auto part : parts) {
        out.append(part);
        out.push_back('\0');
    }
    return out;
}

std::string renamePayload(const uint64_t newdir, const std::string_view from, const std::string_view to) {
    fuse_rename_in in{};
    in.newdir = newdir;
    return std::string(reinterpret_cast<const char*>(&in), sizeof(in)) + names({from, to});
}

// The database is unreachable for the duration of a test: every acquire times out after 50 ms.
class FuseReplyGuardTest : public ::testing::Test {
protected:
    void SetUp() override {
        savedPool_ = db::Transactions::dbPool_;
        pool_ = std::make_shared<db::DBPool>(0, std::chrono::milliseconds(50));
        db::Transactions::dbPool_ = pool_;
        savedStats_ = runtime::Deps::get().fuseStats;
        stats_ = std::make_shared<stats::model::FuseStats>();
        runtime::Deps::get().fuseStats = stats_;
    }

    void TearDown() override {
        db::Transactions::dbPool_ = savedPool_;
        runtime::Deps::get().fuseStats = savedStats_;
    }

    [[nodiscard]] stats::model::FuseOpStatsSnapshot opStats(const FuseOperation op) const {
        const auto snap = stats_->snapshot();
        for (const auto& s : snap.ops)
            if (s.op == stats::model::to_string(op)) return s;
        return {};
    }

    std::shared_ptr<db::DBPool> pool_;
    std::shared_ptr<stats::model::FuseStats> stats_;

private:
    std::shared_ptr<db::DBPool> savedPool_;
    std::shared_ptr<stats::model::FuseStats> savedStats_;
};

TEST_F(FuseReplyGuardTest, UnlinkRmdirAndRenameAnswerAPoolTimeoutWithEagain) {
    Session session(fuse::getOperations());

    const auto unlink = session.roundTrip(FUSE_UNLINK, FUSE_ROOT_ID, nextUid++, names({"note.txt"}));
    ASSERT_TRUE(unlink) << "unlink was never answered";
    EXPECT_EQ(unlink->error, EAGAIN);

    const auto rmdir = session.roundTrip(FUSE_RMDIR, FUSE_ROOT_ID, nextUid++, names({"docs"}));
    ASSERT_TRUE(rmdir) << "rmdir was never answered";
    EXPECT_EQ(rmdir->error, EAGAIN);

    const auto rename = session.roundTrip(FUSE_RENAME, FUSE_ROOT_ID, nextUid++,
                                          renamePayload(987654321, "a.txt", "b.txt"));
    ASSERT_TRUE(rename) << "rename was never answered";
    EXPECT_EQ(rename->error, EAGAIN);

    // Each was a real pool timeout, and the stats count them as failures with the errno the caller got.
    EXPECT_GE(pool_->stats().acquireTimeouts, 3u);
    for (const auto op : {FuseOperation::Unlink, FuseOperation::RmDir, FuseOperation::Rename}) {
        const auto s = opStats(op);
        EXPECT_EQ(s.count, 1u) << stats::model::to_string(op);
        EXPECT_EQ(s.errors, 1u) << stats::model::to_string(op);
        EXPECT_EQ(s.successes, 0u) << stats::model::to_string(op);
    }
    const auto snap = stats_->snapshot();
    ASSERT_FALSE(snap.topErrors.empty());
    EXPECT_EQ(snap.topErrors.front().errnoValue, EAGAIN);
    EXPECT_EQ(snap.topErrors.front().count, 3u);
}

TEST_F(FuseReplyGuardTest, EveryPathOpAnswersAPoolTimeout) {
    Session session(fuse::getOperations());
    const auto expectEagain = [&](const char* what, const uint32_t opcode, const uint64_t nodeid,
                                  const std::string& payload) {
        const auto reply = session.roundTrip(opcode, nodeid, nextUid++, payload);
        ASSERT_TRUE(reply) << what << " was never answered";
        EXPECT_EQ(reply->error, EAGAIN) << what;
    };

    fuse_getattr_in getattr{};
    expectEagain("getattr", FUSE_GETATTR, FUSE_ROOT_ID, {reinterpret_cast<const char*>(&getattr), sizeof(getattr)});
    expectEagain("lookup", FUSE_LOOKUP, FUSE_ROOT_ID, names({"vault"}));
    fuse_mkdir_in mkdir{};
    mkdir.mode = 0755;
    expectEagain("mkdir", FUSE_MKDIR, FUSE_ROOT_ID,
                 std::string(reinterpret_cast<const char*>(&mkdir), sizeof(mkdir)) + names({"new"}));
    fuse_access_in access{};
    access.mask = R_OK;
    expectEagain("access", FUSE_ACCESS, FUSE_ROOT_ID, {reinterpret_cast<const char*>(&access), sizeof(access)});
    expectEagain("symlink", FUSE_SYMLINK, FUSE_ROOT_ID, names({"link", "target"}));
}

namespace {

int forgets = 0;

void throwsPoolTimeout(fuse_req_t, fuse_ino_t, const char*) { throw db::PoolAcquireTimeout("injected"); }
void throwsUnavailable(fuse_req_t, fuse_ino_t, const char*) { throw db::DatabaseUnavailable("injected"); }
void throwsSystemError(fuse_req_t, fuse_ino_t, const char*) { throw std::system_error(ENOSPC, std::generic_category()); }
void throwsRuntimeError(fuse_req_t, fuse_ino_t, const char*) { throw std::runtime_error("injected"); }
void throwsNonException(fuse_req_t, fuse_ino_t, const char*) { throw 42; }
void throwsInForget(fuse_req_t, fuse_ino_t, uint64_t) { ++forgets; throw std::runtime_error("injected"); }

// Replies, then returns normally: the guard must not answer it a second time.
void repliesEnotempty(const fuse_req_t req, fuse_ino_t, const char*) { fuse_reply_err(req, ENOTEMPTY); }

}

TEST_F(FuseReplyGuardTest, GuardMapsWhatAnOpThrowsToOneErrno) {
    const auto check = [](void (*op)(fuse_req_t, fuse_ino_t, const char*), const int expected) {
        fuse_lowlevel_ops ops{};
        ops.unlink = op;
        Session session(ops);
        const auto reply = session.roundTrip(FUSE_UNLINK, FUSE_ROOT_ID, 1000, names({"x"}));
        ASSERT_TRUE(reply);
        EXPECT_EQ(reply->error, expected);
        EXPECT_TRUE(session.quiet(50)) << "answered more than once";
    };
    // fuse::task::Guard is what getOperations registers; the ops here are injected straight into it.
    check(fuse::task::guarded<&throwsPoolTimeout>, EAGAIN);
    check(fuse::task::guarded<&throwsUnavailable>, EAGAIN);
    check(fuse::task::guarded<&throwsSystemError>, ENOSPC);
    check(fuse::task::guarded<&throwsRuntimeError>, EIO);
    check(fuse::task::guarded<&throwsNonException>, EIO);
    check(fuse::task::guarded<&repliesEnotempty>, ENOTEMPTY);
}

TEST_F(FuseReplyGuardTest, AThrowingForgetGetsNoReply) {
    fuse_lowlevel_ops ops{};
    ops.forget = fuse::task::guardedForget<&throwsInForget>;
    Session session(ops);
    fuse_forget_in forget{};
    forget.nlookup = 1;
    forgets = 0;
    EXPECT_FALSE(session.roundTrip(FUSE_FORGET, 42, 1000, {reinterpret_cast<const char*>(&forget), sizeof(forget)}, 200));
    EXPECT_EQ(forgets, 1);
}

}
