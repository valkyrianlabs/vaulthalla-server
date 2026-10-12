#include "fuse/Service.hpp"
#include "fuse/Bridge.hpp"
#include "fuse/WorkingCopies.hpp"
#include "runtime/Manager.hpp"
#include "runtime/Deps.hpp"
#include "concurrency/ThreadPool.hpp"
#include "concurrency/ThreadPoolManager.hpp"
#include "fuse/task/Request.hpp"
#include "log/Registry.hpp"
#include "platform/Mount.hpp"

#include <cstring>
#include <fstream>
#include <optional>
#include <sstream>
#include <thread>
#include <atomic>
#include <utility>
#include <paths.h>
#include <sys/stat.h>     // lstat
#include <unistd.h>       // close
#include <chrono>
#include <thread>
#include <cstdlib>

namespace stdfs = std::filesystem;

namespace vh::fuse {

bool kernelBridgeBuilt() noexcept { return true; }

std::shared_ptr<Service> makeService() { return std::make_shared<Service>(); }

using vh::concurrency::AsyncService;
using vh::concurrency::ThreadPoolManager;

// Best-effort guard: only allow nuking test mountpoints under /tmp
static bool isSafeTestMountpoint(const stdfs::path& p) {
    const auto s = p.string();
    return s.rfind("/tmp/", 0) == 0; // starts_with("/tmp/")
}

static bool isMountedOrStale(const stdfs::path& p) {
    // If lstat returns ENOTCONN, it’s a stale FUSE endpoint => treat as mounted.
    struct stat st{}, pst{};
    if (::lstat(p.c_str(), &st) != 0) return (errno == ENOTCONN);
    const auto parent = p.parent_path().empty() ? stdfs::path("/") : p.parent_path();

    // If parent can't be stat'ed, be conservative.
    if (::lstat(parent.c_str(), &pst) != 0) return true;

    // Different st_dev than parent => mountpoint boundary
    return st.st_dev != pst.st_dev;
}

static void waitUnmounted(const stdfs::path& p, std::chrono::milliseconds timeout = std::chrono::milliseconds(1500)) {
    const auto deadline = std::chrono::steady_clock::now() + timeout;
    while (std::chrono::steady_clock::now() < deadline) {
        if (!isMountedOrStale(p)) return;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

static void releaseReceivedBuf(fuse_buf& buf) {
    if ((buf.flags & FUSE_BUF_IS_FD) != 0) {
        if (buf.fd >= 0) ::close(buf.fd);
    } else if (buf.mem) {
        std::free(buf.mem);
    }

    buf.mem = nullptr;
    buf.size = 0;
    buf.fd = -1;
    buf.pos = 0;
    buf.flags = static_cast<fuse_buf_flags>(0);
}

static void ensureFreshMountpoint() {
    const auto mountPath = vh::paths::getMountPath();
    std::error_code ec;

    if (vh::paths::testMode) {
        if (!isSafeTestMountpoint(mountPath)) {
            throw std::runtime_error("Refusing to clear non-/tmp mount in test mode: " + mountPath.string());
        }

        if (stdfs::exists(mountPath, ec)) {
            // If it’s a mountpoint (or stale), detach it first.
            if (isMountedOrStale(mountPath)) {
                platform::mount::detach(mountPath);
                waitUnmounted(mountPath);
            }

            // Now it should be a normal dir entry; remove it entirely.
            ec.clear();
            stdfs::remove_all(mountPath, ec);
            if (ec && ec.value() != ENOENT) {
                vh::log::Registry::fuse()->warn(
                    "[FUSE] Failed to remove old mount dir {}: {}", mountPath.string(), ec.message());
                ec.clear();
            }
        }
    }

    // Create fresh directory (handle ENOTCONN paranoia: retry once after forced detach)
    stdfs::create_directories(mountPath, ec);
    if (ec) {
        if (ec.value() == ENOTCONN || ec == std::errc::not_connected) {
            // One more forceful pass if a stale endpoint just got noticed late
            platform::mount::detach(mountPath);
            waitUnmounted(mountPath);
            ec.clear();
            stdfs::remove_all(mountPath, ec); // ignore errors
            ec.clear();
            stdfs::create_directories(mountPath, ec);
        }
    }
    if (ec) {
        throw std::runtime_error("Failed to create mountpoint " + mountPath.string() + ": " + ec.message());
    }

    if (vh::paths::testMode) {
        stdfs::permissions(mountPath,
                        stdfs::perms::owner_all | stdfs::perms::group_all | stdfs::perms::others_all,
                        stdfs::perm_options::replace,
                        ec);
        if (ec) {
            throw std::runtime_error("Failed to chmod mountpoint " + mountPath.string() + ": " + ec.message());
        }
    }
}

// -- FUSE class implementation --

Service::Service() : AsyncService("FUSE") {}

void fuse_ll_init(void* userdata, fuse_conn_info* conn) {
    (void)userdata;
    vh::log::Registry::fuse()->debug("[FUSE] Initializing FUSE connection...");

    constexpr uintmax_t MB = 1024 * 1024;

    conn->want |= FUSE_CAP_ASYNC_READ;
    // No writeback cache: with it the kernel owns a regular file's size and ignores the size in getattr replies, so
    // anything that changes a file outside the mount (web uploads, sync downloads, the at-rest repair) left `stat`
    // reporting the old size until the kernel dropped the inode. Every handle is direct_io, so it cached no data
    // anyway; it also made the kernel turn O_WRONLY opens into O_RDWR, asking write-only users for Read.
    conn->want &= ~FUSE_CAP_WRITEBACK_CACHE;
    conn->max_readahead = MB;
    conn->max_write = MB;

    vh::log::Registry::fuse()->debug("[FUSE] Connection initialized with max_readahead={} bytes, max_write={} bytes",
                              conn->max_readahead, conn->max_write);
}

void Service::onStop() {
    const auto mountPath = paths::getMountPath();
    const auto connection = platform::mount::fuseConnection(mountPath);
    if (!loopActive_.load() && !connection) return;  // never mounted (or already gone)

    // New lookups fail at once; the kernel ends the connection (and fuse_session_receive_buf() returns) when the
    // last reference to the mount goes away.
    platform::mount::detach(mountPath);
    if (session_) fuse_session_exit(session_);

    using namespace std::chrono_literals;
    const auto deadline = std::chrono::steady_clock::now() + 1s;
    while (loopActive_.load() && std::chrono::steady_clock::now() < deadline) std::this_thread::sleep_for(10ms);
    if (!loopActive_.load() || !connection) return;

    // Something (an open file, a shell's cwd) still holds the detached mount, so the receive loop would block
    // forever. Aborting the connection fails its requests and wakes the loop. The mounting user owns the file.
    const bool aborted = platform::mount::abortConnection(*connection);
    log::Registry::fuse()->warn("[FUSE] Mount still referenced 1s after unmount; aborted FUSE connection {}{}",
                                *connection, aborted ? "" : " (failed or unsupported on this platform)");
}

void Service::runLoop() {
    log::Registry::fuse()->debug("[FUSE] Running FUSE service");

    ensureFreshMountpoint();

    std::vector<std::string> argsStr = {"vaulthalla-fuse", "-f"};
    for (auto& option : platform::mount::fuseOptions()) argsStr.push_back(std::move(option));
    argsStr.push_back(paths::getMountPath());

    std::vector<std::unique_ptr<char[]>> ownedCStrs;
    std::vector<char*> argsCStr;
    for (const auto& str : argsStr) {
        auto buf = std::make_unique<char[]>(str.size() + 1);
        std::memcpy(buf.get(), str.c_str(), str.size() + 1);
        argsCStr.push_back(buf.get());
        ownedCStrs.push_back(std::move(buf));
    }

    fuse_args args = FUSE_ARGS_INIT(static_cast<int>(argsCStr.size()), argsCStr.data());

    if (fuse_opt_parse(&args, nullptr, nullptr, nullptr) == -1) {
        log::Registry::fuse()->error("[FUSE] Failed to parse FUSE options");
        return;
    }

    fuse_cmdline_opts opts{};
    if (fuse_parse_cmdline(&args, &opts) != 0) {
        log::Registry::fuse()->error("[FUSE] Failed to parse FUSE options");
        return;
    }

    fuse_lowlevel_ops ops = getOperations();
    ops.init = fuse_ll_init;

    session_ = fuse_session_new(&args, &ops, sizeof(ops), nullptr);
    if (!session_) {
        log::Registry::fuse()->error("[FUSE] Failed to create FUSE session");
        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return;
    }

    // Working copies from a previous run hold plaintext and are no longer open anywhere.
    try {
        WorkingCopies::instance().clearStale();
    } catch (const std::exception& e) {
        log::Registry::fuse()->warn("[FUSE] Could not clear stale working copies: {}", e.what());
    }

    if (fuse_session_mount(session_, opts.mountpoint) != 0) {
        log::Registry::fuse()->error("[FUSE] Failed to mount FUSE filesystem at {}", opts.mountpoint);
        fuse_session_destroy(session_);
        free(opts.mountpoint);
        fuse_opt_free_args(&args);
        return;
    }

    log::Registry::fuse()->info("[FUSE] Mounted FUSE filesystem at {}", opts.mountpoint);
    runtime::Deps::get().setFuseSession(session_);
    loopActive_.store(true);

    while (!fuse_session_exited(session_) && !shouldStop()) {
        fuse_buf buf{};
        const int res = fuse_session_receive_buf(session_, &buf);
        if (res == -EINTR) {
            releaseReceivedBuf(buf);
            continue;
        }
        if (res <= 0) {
            releaseReceivedBuf(buf);
            break;
        }

        try {
            ThreadPoolManager::instance().fusePool()->submit(std::make_shared<task::Request>(session_, buf));
        } catch (const std::exception& e) {
            releaseReceivedBuf(buf);
            log::Registry::fuse()->error("[FUSE] Failed to dispatch request task: {}", e.what());
            break;
        } catch (...) {
            releaseReceivedBuf(buf);
            log::Registry::fuse()->error("[FUSE] Failed to dispatch request task: unknown error");
            break;
        }
    }

    loopActive_.store(false);
    log::Registry::fuse()->info("[FUSE] FUSE service loop exiting");

    fuse_session_unmount(session_);
    runtime::Deps::get().setFuseSession(nullptr);
    // Dispatched requests reply on this session: let them finish before it is freed.
    if (const auto& pool = ThreadPoolManager::instance().fusePool();
        pool && !pool->waitIdle(std::chrono::steady_clock::now() + std::chrono::seconds(2)))
        log::Registry::fuse()->warn("[FUSE] FUSE requests still running 2s after the loop ended");
    fuse_session_destroy(session_);
    session_ = nullptr;

    free(opts.mountpoint);
    fuse_opt_free_args(&args);

    log::Registry::fuse()->info("[FUSE] FUSE service stopped successfully");
}

}
