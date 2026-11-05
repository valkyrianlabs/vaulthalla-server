#include "config/Registry.hpp"
#include "crypto/secrets/KeyProvider.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <chrono>
#include <filesystem>
#include <string>
#include <unistd.h>

// #326: a master secret that wraps stored records is never silently replaced, and secrets.require_hardware refuses
// anything but hardware sealing.

namespace secrets = vh::crypto::secrets;

class MasterSecretGuardTest : public ::testing::Test {
protected:
    std::filesystem::path oldBacking, root;

    void SetUp() override {
        vh::paths::enableTestMode();
        oldBacking = vh::paths::backingPath;
        root = std::filesystem::temp_directory_path() /
               ("vh_master_guard_" + std::to_string(::getpid()) + "_" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(root);
        vh::paths::backingPath = root;
    }

    void TearDown() override {
        vh::paths::backingPath = oldBacking;
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    static secrets::DependentsCheck records(const int n) {
        return [n]() -> std::optional<std::string> {
            if (n == 0) return std::nullopt;
            return std::to_string(n) + " vault key version(s)";
        };
    }
};

TEST_F(MasterSecretGuardTest, RefusesToReplaceASecretThatWrapsRecords) {
    secrets::KeyProvider provider("test_guard_lost");
    try {
        provider.initGuarded(records(3));
        FAIL() << "a missing master with dependents must not be regenerated";
    } catch (const secrets::MasterSecretLost& e) {
        const std::string what = e.what();
        EXPECT_NE(what.find("test_guard_lost"), std::string::npos);
        EXPECT_NE(what.find("3 vault key version(s)"), std::string::npos);
        EXPECT_NE(what.find("vh vault keys import"), std::string::npos);
    }
    EXPECT_FALSE(provider.sealedExists()) << "nothing may be sealed in its place";
    EXPECT_TRUE(provider.getMasterKey().empty());
}

TEST_F(MasterSecretGuardTest, GeneratesOnlyWhenNothingDependsOnIt) {
    if (secrets::KeyProvider::posture() == "unknown") GTEST_SKIP() << "no sealing backend on this host";
    std::vector<uint8_t> first;
    {
        secrets::KeyProvider provider("test_guard_fresh");
        provider.initGuarded(records(0));
        first = provider.getMasterKey();
        EXPECT_EQ(first.size(), 32u);
        EXPECT_TRUE(provider.sealedExists());
    }
    // Once sealed, records depending on it are the normal case: it unseals, the same secret.
    secrets::KeyProvider again("test_guard_fresh");
    again.initGuarded(records(5));
    EXPECT_EQ(again.getMasterKey(), first);
}

TEST_F(MasterSecretGuardTest, PostureIsOneOfTheReportedValues) {
    const auto p = secrets::KeyProvider::posture();
    EXPECT_TRUE(p == "hardware" || p == "software" || p == "development" || p == "unknown") << p;
}

TEST_F(MasterSecretGuardTest, RequireHardwareRefusesSoftwareSealing) {
    const auto saved = vh::config::Registry::get();
    auto strict = saved;
    strict.secrets.require_hardware = true;
    vh::config::Registry::set(strict);
    secrets::KeyProvider provider("test_guard_strict");
    if (secrets::KeyProvider::posture() == "hardware") {
        EXPECT_NO_THROW(provider.init());
    } else {
        try {
            provider.init();
            ADD_FAILURE() << "require_hardware must refuse '" << secrets::KeyProvider::posture() << "' sealing";
        } catch (const std::runtime_error& e) {
            EXPECT_NE(std::string(e.what()).find("require_hardware"), std::string::npos) << e.what();
        }
        EXPECT_FALSE(provider.sealedExists());
    }
    vh::config::Registry::set(saved);
}
