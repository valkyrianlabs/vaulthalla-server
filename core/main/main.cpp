// Services
#include "identities/Manager.hpp"
#include "../include/protocols/ProtocolService.hpp"
#include "runtime/Manager.hpp"
#include "runtime/Deps.hpp"
#include "runtime/TestInstance.hpp"

// Database
#include "db/Transactions.hpp"
#include "auth/Bootstrap.hpp"
#include "db/query/identities/User.hpp"

// Storage
#include "storage/Manager.hpp"
#include "fs/Filesystem.hpp"

// Previews
#include "preview/cache/Maintenance.hpp"
#include "preview/derive/Queue.hpp"
#include "preview/render/Raster.hpp"

// Seed
#include "seed/include/seed_db.hpp"
#include "seed/include/init_db_tables.hpp"

// Misc
#include "config/Registry.hpp"
#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <paths.h>
#include "concurrency/ThreadPoolManager.hpp"
#include "log/Registry.hpp"

// Libraries
#include <atomic>
#include <chrono>
#include <csignal>
#include <thread>
#include <cstdint>
#include <execinfo.h>
#include <sys/eventfd.h>
#include <sys/prctl.h>
#include <unistd.h>

using namespace vh::config;
using namespace vh::concurrency;
using namespace vh::storage;
using namespace vh::fs;

namespace {
// systemd SIGKILLs after TimeoutStopSec (30s). An orderly shutdown that hasn't finished by this deadline ends the
// process itself, which also closes /dev/fuse and so aborts the mount.
constexpr auto kShutdownDeadline = std::chrono::seconds(10);

std::atomic<bool> shouldExit{false};
std::atomic<int> receivedSignal{0};
int signalWakeFd = -1;

// Async-signal-safe only (atomics, write, _exit): logging from here could deadlock on a lock the interrupted
// thread holds. The main thread reports the signal. A second SIGTERM/SIGINT during shutdown exits at once.
void signalHandler(const int signum) {
    if (shouldExit.exchange(true)) ::_exit(128 + signum);
    receivedSignal.store(signum);
    const std::uint64_t one = 1;
    (void)!::write(signalWakeFd, &one, sizeof one);
}

// A crashing FUSE daemon must die at once. A core dump first waits for every thread to stop, but a thread in close()
// on a file of our own mount (HTTP upload staging goes through FUSE) waits for a FUSE reply this process can no
// longer send: the dump never finishes, the mount hangs and so does everything touching it, apt included, while
// Restart=on-failure never fires. Not being dumpable skips the dump (and keeps decrypted bytes out of cores, as
// LimitCORE=0 intends), so the kernel kills the process, the mount aborts and systemd restarts the daemon. The
// handler leaves a backtrace in the journal in place of the core.
void fatalSignalHandler(const int signum) {
    static constexpr char kHeader[] = "[vaulthalla] fatal signal, backtrace:\n";
    (void)!::write(STDERR_FILENO, kHeader, sizeof(kHeader) - 1);
    void* frames[64];
    const int depth = ::backtrace(frames, 64);
    ::backtrace_symbols_fd(frames, depth, STDERR_FILENO);
    // SA_RESETHAND restored the default action: re-raise to terminate with the original signal.
    ::raise(signum);
}

void installCrashGuard() {
    if (::prctl(PR_SET_DUMPABLE, 0, 0, 0, 0) != 0)
        std::fprintf(stderr, "[vaulthalla] could not disable core dumps: %s\n", std::strerror(errno));

    // backtrace() loads libgcc on first use, which allocates: do it now, never from a handler on a broken heap.
    void* warm[1];
    (void)::backtrace(warm, 1);

    struct sigaction action{};
    action.sa_handler = fatalSignalHandler;
    action.sa_flags = SA_RESETHAND | SA_NODEFER;
    sigemptyset(&action.sa_mask);
    for (const int sig : {SIGSEGV, SIGBUS, SIGILL, SIGFPE, SIGABRT})
        ::sigaction(sig, &action, nullptr);
}

// Installs the SIGTERM/SIGINT handler and starts the shutdown watcher, before anything else. From the first signal
// on, the process has kShutdownDeadline to exit, whatever main is doing: still starting up (a database that never
// answers), or stuck shutting down. The watcher also wakes main, which the handler itself can't safely do.
void startShutdownWatcher() {
    signalWakeFd = ::eventfd(0, EFD_CLOEXEC);
    if (signalWakeFd < 0) throw std::runtime_error(std::string("eventfd: ") + std::strerror(errno));

    struct sigaction action{};
    action.sa_handler = signalHandler;
    action.sa_flags = SA_RESTART;
    sigemptyset(&action.sa_mask);
    for (const int sig : {SIGINT, SIGTERM}) ::sigaction(sig, &action, nullptr);

    std::thread([] {
        std::uint64_t count = 0;
        while (::read(signalWakeFd, &count, sizeof count) < 0)
            if (errno != EINTR) {
                // Not expected for an eventfd; fall back to polling the flag the handler sets.
                while (!shouldExit.load()) std::this_thread::sleep_for(std::chrono::milliseconds(100));
                break;
            }
        shouldExit.notify_all();

        std::this_thread::sleep_for(kShutdownDeadline);
        static constexpr char kMessage[] = "[vaulthalla] shutdown did not finish within 10s; exiting now\n";
        (void)!::write(STDERR_FILENO, kMessage, sizeof(kMessage) - 1);
        std::_Exit(EXIT_FAILURE);
    }).detach();
}

// Blocks until SIGTERM/SIGINT (no polling interval to wait out).
void waitForShutdownSignal() {
    while (!shouldExit.load()) shouldExit.wait(false);
    vh::log::Registry::vaulthalla()->info("[!] Signal {} received. Shutting down gracefully...", receivedSignal.load());
}

// --- Core Init ---

void initDB() {
    vh::db::Transactions::init();
    vh::db::seed::init_tables_if_not_exists();
    vh::db::Transactions::dbPool_->initPreparedStatements();

    if (!vh::db::query::identities::User::adminUserExists())
        vh::seed::seed_database();

    vh::seed::reconcileSystemPrincipals();
    vh::auth::bootstrap::retireLegacyDefaultPassword();
    vh::seed::reconcileGlobalVaultPolicies();
}

void initDeps() {
    vh::runtime::Deps::init();

    // Every account and group in one snapshot: FUSE, HTTP, S3 and session checks answer identity lookups from memory
    // from here on. A failure is not fatal: lookups then load (and remember) what they need on first use.
    try {
        vh::identities::manager().preload();
    } catch (const std::exception& e) {
        vh::log::Registry::vaulthalla()->warn("[!] Identity preload failed, loading on demand: {}", e.what());
    }
    vh::runtime::Deps::setSyncController(
        vh::runtime::Manager::instance().getSyncController()
    );
}

// --- Wiring ---

void wireStorage() {
    Filesystem::init(vh::runtime::Deps::get().storageManager);
    vh::runtime::Deps::get().storageManager->initStorageEngines();

    // Every start (so every upgraded install): legacy plaintext thumbnails and orphaned artifacts go away before
    // anything can serve them.
    vh::preview::cache::sweepAtStartup(vh::runtime::Deps::get().storageManager->getEngines());
}

// --- Runtime ---

void startRuntime() {
    vh::runtime::Manager::instance().startAll();
}

void stopRuntime() {
    vh::runtime::Manager::instance().stopAll(SIGTERM);
}

// --- Orchestration ---

void startVaulthalla() {
    const auto log = vh::log::Registry::vaulthalla();

    ThreadPoolManager::instance().init();

    // Reader policies (preview.media.*) and the derived-artifact negative-cache TTL.
    vh::preview::cache::applyConfig();

    log->info("[*] Initializing database...");
    initDB();

    log->info("[*] Initializing runtime dependencies...");
    initDeps();

    log->info("[*] Wiring storage layer...");
    wireStorage();

    log->info("[*] Starting runtime...");
    startRuntime();

    log->info("[✓] Started Vaulthalla - The Final Cloud.");
}

void shutdownVaulthalla() {
    auto log = vh::log::Registry::vaulthalla();

    log->info("[*] Shutting down Vaulthalla services...");

    stopRuntime();
    // No request can enqueue any more: SIGKILL running converter helpers and join the derive workers while the
    // storage engines and the DB pool they use are still up.
    vh::preview::derive::Queue::instance().shutdown();
    ThreadPoolManager::instance().shutdown();

    log->info("[✓] Vaulthalla services shut down cleanly.");
}

// VH_TEST_MODE=1: a private instance for the integration engine (tools/harness). Refuses to start unless every
// path, the CLI socket and the database are private; never falls back to a real install's state.
constexpr int kExitConfig = 78;  // EX_CONFIG

bool enterTestInstanceMode() {
    const auto env = [](const char* key) { return std::getenv(key); };
    if (!vh::runtime::test_instance::requested(env)) return true;
    if (const auto why = vh::runtime::test_instance::refusal(env)) {
        std::fprintf(stderr, "[-] Refusing to start a test instance: %s\n", why->c_str());
        return false;
    }
    vh::paths::enableTestMode();
    std::fprintf(stderr, "[*] Test instance: config %s, CLI socket %s\n", vh::paths::getConfigPath().c_str(),
                 vh::paths::getCliSocketPath().c_str());
    return true;
}
}

int main() {
    installCrashGuard();
    if (!enterTestInstanceMode()) return kExitConfig;

    try {
        Registry::init();
        vh::log::Registry::init();
        for (const auto& deprecation : Registry::deprecations())
            vh::log::Registry::vaulthalla()->warn("[config] {}", deprecation);

        vh::preview::render::PdfiumLibrary pdfium;

        startShutdownWatcher();  // first: its deadline also covers startup and static destruction after main
        startVaulthalla();

        waitForShutdownSignal();
        shutdownVaulthalla();
        return EXIT_SUCCESS;

    } catch (const std::exception& e) {
        // Config is loaded before logging, so a malformed or missing config.yaml lands here with no logger;
        // calling it would throw again and abort with a core dump instead of this message (vh-storage).
        try {
            vh::log::Registry::vaulthalla()->error("[-] Failed to initialize Vaulthalla: {}", e.what());
        } catch (...) {
            std::fprintf(stderr, "[-] Failed to initialize Vaulthalla: %s\n", e.what());
        }
        return EXIT_FAILURE;
    }
}
