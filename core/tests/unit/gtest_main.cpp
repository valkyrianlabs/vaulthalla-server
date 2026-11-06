#include <gtest/gtest.h>
#include <cstdlib>
#include <filesystem>
#include <paths.h>

#include "auth/session/Manager.hpp"
#include "config/Registry.hpp"
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

}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    ::testing::UnitTest::GetInstance()->listeners().Append(new SessionLeakGuard);

    try {
        vh::paths::enableTestMode();
        // Converter helpers run from the build tree (owned by the developer, not root); the trust checks have
        // their own tests, which re-enable them.
        vh::preview::derive::Runner::setTrustChecksForTesting(false);
        // New encrypting vaults are opaque_v1 (#371). Most suites here fake buckets keyed by vault path and test the
        // path_v0 data plane, which existing vaults keep until the layout migration (WS1-c), so this binary creates
        // path_v0 vaults by default; opaque_v1 suites set their layout themselves, and
        // OpaqueLayoutTest.NewEncryptingVaultsAreOpaqueV1 pins the product's default.
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
    return result;
}
