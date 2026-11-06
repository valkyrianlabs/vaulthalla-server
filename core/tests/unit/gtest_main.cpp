#include <gtest/gtest.h>
#include <cstdlib>
#include <filesystem>
#include <paths.h>

#include "config/Registry.hpp"
#include "log/Registry.hpp"
#include "preview/derive/Runner.hpp"
#include "vault/model/S3Vault.hpp"

namespace fs = std::filesystem;

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);

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

    return RUN_ALL_TESTS();
}
