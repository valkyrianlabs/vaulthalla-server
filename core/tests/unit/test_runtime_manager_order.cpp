#include "runtime/Manager.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <iterator>
#include <string>
#include <vector>

namespace {

std::ptrdiff_t indexOf(const std::vector<std::string>& names, const std::string& name) {
    const auto it = std::ranges::find(names, name);
    if (it == names.end()) return -1;
    return std::distance(names.begin(), it);
}

}

TEST(RuntimeManagerOrderTest, StopOrderClosesProtocolSocketsBeforeFuse) {
    const auto names = vh::runtime::Manager::serviceStopOrder(true);

    EXPECT_LT(indexOf(names, "ProtocolService"), indexOf(names, "FUSE"));
    EXPECT_LT(indexOf(names, "S3GatewayService"), indexOf(names, "ProtocolService"));
    EXPECT_LT(indexOf(names, "ShellServer"), indexOf(names, "FUSE"));
    EXPECT_LT(indexOf(names, "ConnectionLifecycleManager"), indexOf(names, "FUSE"));
    // The audit trail outlives everything it records (#323).
    EXPECT_EQ(names.back(), "AuditTrail");
    EXPECT_EQ(names[names.size() - 2], "FUSE");
}

TEST(RuntimeManagerOrderTest, StartOrderIsExplicitAndDependencyAware) {
    const auto names = vh::runtime::Manager::serviceStartOrder(true);

    EXPECT_EQ(names.front(), "AuditTrail");
    EXPECT_EQ(names[1], "FUSE");
    EXPECT_LT(indexOf(names, "ConnectionLifecycleManager"), indexOf(names, "ProtocolService"));
    EXPECT_LT(indexOf(names, "ProtocolService"), indexOf(names, "S3GatewayService"));
    EXPECT_LT(indexOf(names, "S3GatewayService"), indexOf(names, "ShellServer"));
    // Purges run against the storage the FUSE service and sync controller already hold (#162).
    EXPECT_LT(indexOf(names, "SyncController"), indexOf(names, "VaultRetentionService"));
    EXPECT_NE(indexOf(vh::runtime::Manager::serviceStopOrder(true), "VaultRetentionService"), -1);
}

TEST(RuntimeManagerOrderTest, TestModeOrderOmitsShellServerWhenRequested) {
    const auto startNames = vh::runtime::Manager::serviceStartOrder(false);
    const auto stopNames = vh::runtime::Manager::serviceStopOrder(false);

    EXPECT_EQ(indexOf(startNames, "ShellServer"), -1);
    EXPECT_EQ(indexOf(stopNames, "ShellServer"), -1);
    EXPECT_EQ(stopNames.back(), "AuditTrail");
}
