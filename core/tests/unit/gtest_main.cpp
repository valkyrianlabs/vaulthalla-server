#include <gtest/gtest.h>
#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <optional>
#include <stdexcept>
#include <paths.h>
#include <string>
#include <utility>
#include <vector>

#include "auth/session/Manager.hpp"
#include "config/Registry.hpp"
#include "crypto/util/hash.hpp"
#include "log/Registry.hpp"
#include "preview/derive/Runner.hpp"
#include "protocols/http/upload/Resumable.hpp"
#include "runtime/Deps.hpp"
#include "vault/model/S3Vault.hpp"

namespace fs = std::filesystem;

namespace {

// runtime::Deps lives until static destruction, and a ws session destroyed there runs after the state it needs (its
// socket's io_context, the session counters, the passkey registry, logging) may be gone: an exit-time SIGSEGV on
// Linux (#397), "mutex lock failed" on macOS (#385). So no suite may leave sessions in the process-wide session
// manager: one that does fails at its own end (not at exit, long after), and they are dropped before the next suite.
class SessionLeakGuard final : public ::testing::EmptyTestEventListener {
    void OnTestSuiteEnd(const ::testing::TestSuite& suite) override {
        const auto manager = vh::runtime::Deps::get().sessionManager;
        if (!manager) return;
        if (const auto leaked = manager->size(); leaked > 0) {
            ADD_FAILURE() << suite.name() << " left " << leaked << " ws session(s) in runtime::Deps' session manager: "
                          << "remove what the suite registered (runtime::Deps::releaseSessions()) in its TearDown, "
                          << "before anything they use (an io_context) goes away";
            (void)vh::runtime::Deps::releaseSessions();
        }
    }
};

// Parallel DB-backed runs: bin/tests/run_unit.sh -j N starts one process per shard, each with its own database.
// VH_UNIT_SHARD=<index>/<count> runs whole suites, so a suite's fixture (a fresh schema) is set up once, in one
// process. (CI's DB-free run shards by test case instead: GTEST_TOTAL_SHARDS, tools/dev/ci-test.sh.) Every process computes the same split: suites by test count (most first), each to the least
// loaded shard; the shard's suites are intersected with --gtest_filter.
struct Shard {
    int index = 0;
    int count = 1;
};

std::optional<Shard> shardFromEnv() {
    const char* v = std::getenv("VH_UNIT_SHARD");
    if (!v || !*v) return std::nullopt;
    Shard s;
    if (std::sscanf(v, "%d/%d", &s.index, &s.count) != 2 || s.count < 1 || s.index < 0 || s.index >= s.count)
        throw std::runtime_error(std::string("VH_UNIT_SHARD must be <index>/<count>, got '") + v + "'");
    return s;
}

void restrictToShard(const Shard& shard) {
    const auto* unit = ::testing::UnitTest::GetInstance();
    std::vector<std::pair<int, std::string>> suites;
    for (int i = 0; i < unit->total_test_suite_count(); ++i) {
        const auto* suite = unit->GetTestSuite(i);
        suites.emplace_back(suite->total_test_count(), suite->name());
    }
    std::stable_sort(suites.begin(), suites.end(), [](const auto& a, const auto& b) { return a.first > b.first; });
    std::vector<long> load(static_cast<std::size_t>(shard.count), 0);
    std::string others;
    for (const auto& [tests, name] : suites) {
        const auto least = static_cast<int>(std::min_element(load.begin(), load.end()) - load.begin());
        load[static_cast<std::size_t>(least)] += tests + 5;  // + a suite's own setup
        if (least != shard.index) others += (others.empty() ? "" : ":") + name + ".*";
    }
    if (others.empty()) return;
    std::string filter = GTEST_FLAG_GET(filter);
    filter += (filter.find('-') == std::string::npos ? "-" : ":") + others;
    GTEST_FLAG_SET(filter, filter);
}

// --gtest_output=json:<file> (or xml:) names one file per shard, <file>.shard<i>: rewritten before InitGoogleTest,
// which opens the report.
void nameReportPerShard(const int argc, char** argv, std::vector<std::string>& storage, const Shard& shard) {
    storage.reserve(static_cast<std::size_t>(argc));
    for (int i = 1; i < argc; ++i) {
        const std::string arg = argv[i];
        if (!arg.starts_with("--gtest_output=") || arg.find(':') == std::string::npos || arg.back() == '/') continue;
        storage.push_back(arg + ".shard" + std::to_string(shard.index));
        argv[i] = storage.back().data();
    }
}

// Each process gets a private temporary directory (TMPDIR), removed when it ends: the suites' fixed scratch names,
// the test-mode default paths (/tmp/vh_backing, vh_log, ...) and helper processes never meet another process's.
// Under /tmp on macOS too, so unix socket paths stay short.
std::optional<fs::path> usePrivateTempDir() {
    std::string tmpl = "/tmp/vh-unit-XXXXXX";
    if (!::mkdtemp(tmpl.data())) return std::nullopt;
    ::setenv("TMPDIR", tmpl.c_str(), 1);
    return fs::path(tmpl);
}

}

int main(int argc, char** argv) {
    std::optional<Shard> shard;
    std::vector<std::string> shardArgs;
    try {
        shard = shardFromEnv();
        if (shard) nameReportPerShard(argc, argv, shardArgs, *shard);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return 1;
    }
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new SessionLeakGuard);
    const auto privateTmp = usePrivateTempDir();

    try {
        if (shard) restrictToShard(*shard);
        vh::paths::enableTestMode();
        // Argon2id at MODERATE cost took ~0.5 s per password hash; suites that check hashing itself still verify
        // real Argon2id strings. Production parameters are unchanged (crypto/util/hash.cpp).
        vh::crypto::hash::setMinimalPasswordCostForTesting();
        // Converter helpers run from the build tree (owned by the developer, not root); the trust checks have
        // their own tests, which re-enable them.
        vh::preview::derive::Runner::setTrustChecksForTesting(false);
        // New encrypting vaults are opaque_v1 (#371). Most suites here fake buckets keyed by vault path and test the
        // path_v0 data plane, which existing vaults keep until the layout migration (WS1-c), so this binary creates
        // path_v0 vaults by default; opaque_v1 suites set their layout themselves, and
        // ObjectUidDbTest.VaultsGetAUidAndALayoutThatFollowsEncryption pins the product's default.
        vh::vault::model::setNewEncryptingLayoutForTesting(vh::vault::model::StorageLayout::PathV0);
        if (const auto* configPath = std::getenv("VH_PATH_TO_CONFIG")) {
            vh::paths::configPath = configPath;
        }
        vh::config::Registry::init();
        vh::log::Registry::init();

    } catch (const std::exception& e) {
        std::cerr << "Failed to initialize Vaulthalla test environment: " << e.what() << std::endl;
        return 1;
    }

    const int result = RUN_ALL_TESTS();
    // As the daemon does before main returns: join the resumable-upload workers (a joinable thread in their static
    // registry aborts the process at exit, #389) and drop cached sessions (the guard already did after every suite).
    vh::protocols::http::upload::resumable::Service::shutdown();
    (void)vh::runtime::Deps::releaseSessions();
    if (privateTmp) {
        std::error_code ec;
        fs::remove_all(*privateTmp, ec);
    }
    return result;
}
