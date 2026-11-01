#pragma once

#include "concurrency/Task.hpp"
#include "db/DBPool.hpp"
#include "log/Registry.hpp"
#include "stats/model/FuseStats.hpp"

#include <fuse3/fuse_lowlevel.h>
#include <cerrno>
#include <cstdlib>
#include <exception>
#include <system_error>
#include <unistd.h>

namespace vh::fuse::task {

// The errno a request gets when its op threw instead of replying (#263). A database that can't be reached right now
// (pool exhausted past its acquire timeout, connection down) is EAGAIN: nothing changed, try again. A system_error
// keeps its errno; anything else is EIO.
inline int unansweredErrno(const std::exception_ptr& thrown) noexcept {
    try {
        std::rethrow_exception(thrown);
    } catch (const db::PoolAcquireTimeout&) {
        return EAGAIN;
    } catch (const db::DatabaseUnavailable&) {
        return EAGAIN;
    } catch (const std::system_error& e) {
        return e.code().value() > 0 ? e.code().value() : EIO;
    } catch (...) {
        return EIO;
    }
}

// The reply guard every Bridge op is registered through (fuse::getOperations). The kernel waits for an answer to each
// request, so one that is never answered hangs its caller (and anything waiting on the inode) for good. Ops reply as
// their last action, so an exception that escapes one was thrown before any reply: the guard answers it, exactly once,
// and nothing unwinds through libfuse's C frames. Forget-style ops (no reply but none) use `forget`.
template <auto Op> struct Guard;

template <typename... Args, void (*Op)(fuse_req_t, Args...)>
struct Guard<Op> {
    static void reply(const fuse_req_t req, Args... args) noexcept {
        try {
            Op(req, args...);
        } catch (...) {
            const auto errnum = unansweredErrno(std::current_exception());
            logUnanswered(errnum);
            fuse_reply_err(req, errnum);
            stats::model::ScopedFuseOpTimer::recordUnanswered(errnum);
        }
    }

    static void forget(const fuse_req_t req, Args... args) noexcept {
        try {
            Op(req, args...);
        } catch (...) {
            logUnanswered(0);
            fuse_reply_none(req);
            stats::model::ScopedFuseOpTimer::recordUnanswered(EIO);
        }
    }

private:
    static void logUnanswered(const int errnum) noexcept {
        try {
            try {
                std::rethrow_exception(std::current_exception());
            } catch (const std::exception& e) {
                log::Registry::fuse()->error("[fuse] op threw before replying (answered errno {}): {}", errnum, e.what());
            } catch (...) {
                log::Registry::fuse()->error("[fuse] op threw a non-exception before replying (answered errno {})", errnum);
            }
        } catch (...) {} // the reply still goes out
    }
};

template <auto Op> inline constexpr auto guarded = &Guard<Op>::reply;
template <auto Op> inline constexpr auto guardedForget = &Guard<Op>::forget;

class Request final : public concurrency::Task {
public:
    Request(fuse_session* session, const fuse_buf& buf) : session_(session), buf_(buf) {}
    ~Request() override { releaseBuf(); }

    Request(const Request&) = delete;
    Request& operator=(const Request&) = delete;
    Request(Request&&) = delete;
    Request& operator=(Request&&) = delete;

    // Ops answer their own exceptions (Guard); this only catches what libfuse itself might throw while dispatching.
    void operator()() override {
        try {
            fuse_session_process_buf(session_, &buf_);
        } catch (const std::exception& ex) {
            log::Registry::fuse()->critical("[fuse::task::Request] Unhandled exception: {}", ex.what());
        } catch (...) {
            log::Registry::fuse()->critical("[fuse::task::Request] Unhandled unknown exception");
        }

        releaseBuf();
    }

private:
    void releaseBuf() {
        if (released_) return;

        if ((buf_.flags & FUSE_BUF_IS_FD) != 0) {
            if (buf_.fd >= 0) ::close(buf_.fd);
        } else if (buf_.mem) {
            std::free(buf_.mem);
        }

        buf_.mem = nullptr;
        buf_.size = 0;
        buf_.fd = -1;
        buf_.pos = 0;
        buf_.flags = static_cast<fuse_buf_flags>(0);
        released_ = true;
    }

    fuse_session* session_;
    fuse_buf buf_;
    bool released_ = false;
};

}
