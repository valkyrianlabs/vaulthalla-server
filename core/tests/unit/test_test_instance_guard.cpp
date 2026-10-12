// The daemon's VH_TEST_MODE=1 guard (runtime/TestInstance): a test instance launched by tools/harness starts only
// when every path, the CLI socket and the database are private. Anything else refuses (fail closed).

#include "runtime/TestInstance.hpp"

#include <gtest/gtest.h>

#include <map>
#include <string>

namespace vh::test_test_instance_guard {

using Env = std::map<std::string, std::string>;

Env privateEnv() {
    return {
        {"VH_TEST_MODE", "1"},
        {"VH_TEST_DB_USER", "vh_harness"},
        {"VH_TEST_DB_PASS", "x"},
        {"VH_TEST_DB_HOST", "localhost"},
        {"VH_TEST_DB_PORT", "5432"},
        {"VH_TEST_DB_NAME", "vh_harness_run1"},
        {"VH_TEST_BACKING_PATH", "/tmp/vhh_run1/backing"},
        {"VH_TEST_MOUNT_PATH", "/tmp/vhh_run1/mnt"},
        {"VH_TEST_LOG_PATH", "/tmp/vhh_run1/log"},
        {"VH_PATH_TO_SUPERADMIN_UID", "/tmp/vhh_run1/run"},
        {"VH_PATH_TO_CONFIG", "/tmp/vhh_run1/config.yaml"},
        {"VH_TEST_CLI_SOCKET", "/tmp/vhh_run1/cli.sock"},
    };
}

runtime::test_instance::EnvLookup lookup(const Env& env) {
    return [&env](const char* key) -> const char* {
        const auto it = env.find(key);
        return it == env.end() ? nullptr : it->second.c_str();
    };
}

TEST(TestInstanceGuard, OnlyVhTestModeOneRequestsATestInstance) {
    Env env;
    EXPECT_FALSE(runtime::test_instance::requested(lookup(env)));
    env["VH_TEST_MODE"] = "0";
    EXPECT_FALSE(runtime::test_instance::requested(lookup(env)));
    env["VH_TEST_MODE"] = "1";
    EXPECT_TRUE(runtime::test_instance::requested(lookup(env)));
}

TEST(TestInstanceGuard, AFullyPrivateEnvironmentIsAccepted) {
    const auto env = privateEnv();
    EXPECT_EQ(runtime::test_instance::refusal(lookup(env)), std::nullopt);
}

TEST(TestInstanceGuard, EveryRequiredVariableIsRequired) {
    for (const auto& [key, value] : privateEnv()) {
        if (key == "VH_TEST_MODE") continue;
        auto env = privateEnv();
        env.erase(key);
        EXPECT_NE(runtime::test_instance::refusal(lookup(env)), std::nullopt) << key << " missing was accepted";
        env[key] = "";
        EXPECT_NE(runtime::test_instance::refusal(lookup(env)), std::nullopt) << key << " empty was accepted";
    }
}

TEST(TestInstanceGuard, SystemPathsAndSocketsAreRefused) {
    const std::map<std::string, std::string> unsafe{
        {"VH_TEST_BACKING_PATH", "/var/lib/vaulthalla"},
        {"VH_TEST_MOUNT_PATH", "/mnt/vaulthalla"},
        {"VH_TEST_LOG_PATH", "/var/log/vaulthalla"},
        {"VH_PATH_TO_CONFIG", "/etc/vaulthalla/config.yaml"},
        {"VH_TEST_CLI_SOCKET", "/run/vaulthalla/cli.sock"},
        {"VH_PATH_TO_SUPERADMIN_UID", "/run/vaulthalla"},
        {"VH_TEST_MOUNT_PATH", "/tmp/../mnt/vaulthalla"},
        {"VH_TEST_BACKING_PATH", "/tmp"},
        {"VH_TEST_BACKING_PATH", "relative/backing"},
    };
    for (const auto& [key, value] : unsafe) {
        auto env = privateEnv();
        env[key] = value;
        EXPECT_NE(runtime::test_instance::refusal(lookup(env)), std::nullopt) << key << "=" << value << " was accepted";
    }
}

TEST(TestInstanceGuard, MountAndBackingMustDiffer) {
    auto env = privateEnv();
    env["VH_TEST_MOUNT_PATH"] = env["VH_TEST_BACKING_PATH"];
    EXPECT_NE(runtime::test_instance::refusal(lookup(env)), std::nullopt);
}

TEST(TestInstanceGuard, RealDatabasesAreRefused) {
    for (const auto* name : {"vaulthalla", "postgres", "template1", "prod_db"}) {
        auto env = privateEnv();
        env["VH_TEST_DB_NAME"] = name;
        EXPECT_NE(runtime::test_instance::refusal(lookup(env)), std::nullopt) << name << " was accepted";
    }
    for (const auto* name : {"vh_harness_abc", "vh_cli_test"}) {
        auto env = privateEnv();
        env["VH_TEST_DB_NAME"] = name;
        EXPECT_EQ(runtime::test_instance::refusal(lookup(env)), std::nullopt) << name << " was refused";
    }
}

TEST(TestInstanceGuard, TheLabAndThePackagedServiceNeverRunATestInstance) {
    using runtime::test_instance::hostRefusal;
    EXPECT_NE(hostRefusal("vh-storage", "0::/user.slice\n"), std::nullopt);
    EXPECT_NE(hostRefusal("vh-storage-2", "0::/user.slice\n"), std::nullopt);
    EXPECT_NE(hostRefusal("dev", "0::/system.slice/vaulthalla.service\n"), std::nullopt);
    EXPECT_NE(hostRefusal("dev", "12:pids:/system.slice/vaulthalla.service\n0::/system.slice/vaulthalla.service"),
              std::nullopt);
    EXPECT_EQ(hostRefusal("dev", "0::/user.slice/user-1000.slice/session-3.scope\n"), std::nullopt);
    EXPECT_EQ(hostRefusal("dev", "0::/system.slice/vaulthalla-price-bot.service\n"), std::nullopt);
    EXPECT_EQ(hostRefusal("dev", "0::/system.slice/actions.runner.vaulthalla.service\n"), std::nullopt);
}

TEST(TestInstanceGuard, OnlyTestDatabasesCanBeWiped) {
    using runtime::test_instance::isTestDatabaseName;
    for (const auto* name : {"vaulthalla", "postgres", "template0", "template1", "", "prod", "vaulthalla_prod"})
        EXPECT_FALSE(isTestDatabaseName(name)) << name;
    for (const auto* name : {"vh_harness_proof_1", "vh_harness_unit_x", "vh_cli_test", "test_db"})
        EXPECT_TRUE(isTestDatabaseName(name)) << name;
}

}
