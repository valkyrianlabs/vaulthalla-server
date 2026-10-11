#include "IntegrationsTestRunner.hpp"
#include "RunOptions.hpp"
#include "cmd/generators.hpp"
#include "fuse/Actor.hpp"
#include "seed/H64.hpp"
#include "seed/Stream.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "concurrency/ThreadPoolManager.hpp"
#include "runtime/Manager.hpp"
#include "runtime/Deps.hpp"
#include "runtime/TestInstance.hpp"
#include "fs/Filesystem.hpp"
#include "storage/Manager.hpp"

#include <nlohmann/json.hpp>

#include <iostream>
#include <string>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <paths.h>
#include <sys/mount.h>
#include <unistd.h>

using namespace vh::test::integration;
using namespace vh::protocols::shell;
using namespace vh::concurrency;
using namespace vh::storage;
using namespace vh::fs;

namespace {

// EX_CONFIG, like vaulthalla-server's own test-instance guard: refuse before touching any state.
constexpr int kExitRefused = 78;
constexpr int kExitUsage = 2;

uid_t integrationAdminUid() {
    if (const auto* forced = std::getenv("VH_TEST_ADMIN_UID"); forced && *forced)
        return static_cast<uid_t>(std::stoul(forced));

    const auto current = getuid();
    if (current != 0) return current;

    if (const auto* sudoUid = std::getenv("SUDO_UID"); sudoUid && *sudoUid)
        return static_cast<uid_t>(std::stoul(sudoUid));

    return current;
}

void initBase() {
    vh::paths::enableTestMode();
    std::filesystem::remove_all(vh::paths::getBackingPath());
    std::filesystem::create_directories(vh::paths::getBackingPath());
    std::filesystem::create_directories(vh::paths::getMountPath());
    std::filesystem::create_directories(vh::paths::getRuntimePath());
    std::ofstream(vh::paths::getRuntimePath() / "superadmin_uid") << integrationAdminUid() << '\n';
    vh::config::Registry::init();
    vh::log::Registry::init();
    ThreadPoolManager::instance().init();
}

void initDB() {
    vh::db::Transactions::init();
    vh::db::seed::wipe_all_data_restart_identity();
    vh::db::seed::init_tables_if_not_exists();
    vh::db::Transactions::dbPool_->initPreparedStatements();
    vh::seed::seed_database();
}

void initServices() {
    vh::runtime::Deps::init();
    vh::runtime::Deps::setSyncController(vh::runtime::Manager::instance().getSyncController());
    Filesystem::init(vh::runtime::Deps::get().storageManager);
    vh::runtime::Deps::get().storageManager->initStorageEngines();
    vh::runtime::Manager::instance().startTestServices();
}

void ensureAdminExists() {
    if (!vh::db::query::identities::User::adminUserExists())
        throw std::runtime_error("no admin user after seeding; cannot run CLI tests");
}

// The run identity, printed before anything else so even a crash leaves the seed in the log.
void printHeader(const RunOptions& o) {
    std::cout << "== vh_integration_tests ==\n"
              << "  seed          " << seed::fmtSeed(o.seed) << (o.seedFromEnv ? " (VH_TEST_SEED)" : " (random)") << "\n"
              << "  config        " << o.configName << "\n"
              << "  stages        " << o.stagesText() << "\n"
              << "  negative ctl  " << o.negativeControlText() << "\n"
              << "  uid base      " << o.uidBase
              << (o.uidBase > kLargestStorableLinuxId - kLinuxIdSpan
                      ? " (WARNING: above what users.linux_uid INTEGER can store; scenario users will fail to insert)"
                      : "")
              << "\n"
              << "  seed threads  " << o.seedThreads << (o.seedThreads > 1 ? " (DB ids can interleave)" : "") << "\n"
              << "  fs op timeout " << fuse::opTimeout().count() << " ms\n"
              << "  fs actor      " << (fuse::actorPath().empty() ? "(none)" : fuse::actorPath()) << "\n"
              << "  environment   " << (o.legacySharedEnv ? "legacy shared (make run_test)" : "private instance") << "\n"
              << "  reports       " << (o.reportDir.empty() ? "(VH_TEST_REPORT_DIR not set)" : o.reportDir) << "\n"
              << std::endl;
}

// A setup failure still leaves a report saying so (no tests ran, the run failed).
void writeSetupFailureReport(const RunOptions& o, const std::string& why) {
    if (o.reportDir.empty()) return;
    std::error_code ec;
    std::filesystem::create_directories(o.reportDir, ec);
    std::ofstream(std::filesystem::path(o.reportDir) / "report.json")
        << nlohmann::json{{"schema", "vh-integration-report/1"},
                          {"seed", seed::fmtSeed(o.seed)},
                          {"config", {{"name", o.configName}}},
                          {"setup_error", why},
                          {"summary", {{"total", 0}, {"passed", 0}, {"failed", 0}, {"wedges", 0}}},
                          {"exit_code", 1},
                          {"stages", nlohmann::json::array()}}
               .dump(2)
        << "\n";
}

}

int main() {
    const auto env = [](const char* key) { return std::getenv(key); };

    // A private instance (bin/tests/run_proof.sh) or nothing: every path, the CLI socket and the database must come
    // from the environment and be private. Only the legacy `make run_test` env (install_core.sh) opts out.
    const char* legacy = std::getenv("VH_TEST_LEGACY_SHARED_ENV");
    const bool legacyShared = legacy && std::string(legacy) == "1";
    if (!legacyShared) {
        if (const auto why = vh::runtime::test_instance::refusal(env)) {
            std::fprintf(stderr,
                         "[-] vh_integration_tests refuses to run: %s\n"
                         "    Run it through bin/tests/run_proof.sh (a per-run DB and private /tmp paths), or set\n"
                         "    VH_TEST_LEGACY_SHARED_ENV=1 for the shared make run_test environment.\n",
                         why->c_str());
            return kExitRefused;
        }
    }

    std::string error;
    auto options = RunOptions::fromEnv(error);
    if (!options) {
        std::fprintf(stderr, "[-] vh_integration_tests: %s\n", error.c_str());
        return kExitUsage;
    }

    try {
        setLinuxIdBase(options->uidBase);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[-] vh_integration_tests: %s\n", e.what());
        return kExitUsage;
    }
    seed::setRoot(options->seed);
    printHeader(*options);

    int exitStatus = 1;
    try {
        initBase();
        initDB();
        initServices();
        ensureAdminExists();

        const auto start = std::chrono::steady_clock::now();
        IntegrationsTestRunner runner(*options);
        exitStatus = runner();
        const auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();
        std::cout << "CLI tests completed in " << static_cast<double>(ms) / 1000.0 << " seconds" << std::endl;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[-] vh_integration_tests: setup failed: %s\n", e.what());
        writeSetupFailureReport(*options, e.what());
        exitStatus = 1;
    }

    fuse::actors().reset();

    // A private instance detaches its own mount on the way out (non-blocking; run_proof.sh confirms it is gone).
    if (!legacyShared) (void)::umount2(vh::paths::getMountPath().c_str(), MNT_DETACH);

    // No orderly shutdown: stopping every service here SIGTERMs threads and exits 1 (the shutdown path has its own
    // tests); the exit status is the verdict.
    std::_Exit(exitStatus);
}
