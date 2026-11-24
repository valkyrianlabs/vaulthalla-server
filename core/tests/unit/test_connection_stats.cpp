// Connection health counts (stats::model::ConnectionStats): which session modes count as unauthenticated, and when
// unauthenticated sessions are a finding.

#include "protocols/ws/Session.hpp"
#include "stats/model/ConnectionStats.hpp"

#include <gtest/gtest.h>

using vh::protocols::ws::SessionMode;
using vh::stats::model::ConnectionStats;
using vh::stats::model::sessionModeName;

TEST(ConnectionStats, EverySessionModeHasItsOwnName) {
    EXPECT_EQ(sessionModeName(SessionMode::Unauthenticated), "unauthenticated");
    EXPECT_EQ(sessionModeName(SessionMode::Human), "human");
    EXPECT_EQ(sessionModeName(SessionMode::SharePending), "share_pending");
    EXPECT_EQ(sessionModeName(SessionMode::Share), "share");
    // A paired device (the desktop app) and a device in the middle of pairing are not unauthenticated sockets.
    EXPECT_EQ(sessionModeName(SessionMode::Device), "device");
    EXPECT_EQ(sessionModeName(SessionMode::DevicePairing), "device_pairing");
}

TEST(ConnectionStats, DeviceSessionsAreNotCountedAsUnauthenticated) {
    ConnectionStats stats;
    stats.count("device", 120);
    stats.count("device", 30);
    stats.count("device_pairing", 5);
    stats.count("human", 60);
    stats.finalize();

    EXPECT_EQ(stats.activeWsSessionsTotal, 4u);
    EXPECT_EQ(stats.activeHumanSessions, 1u);
    EXPECT_EQ(stats.activeUnauthenticatedSessions, 0u);
    EXPECT_FALSE(stats.oldestUnauthenticatedSessionAgeSeconds.has_value());
    EXPECT_EQ(stats.oldestSessionAgeSeconds, 120u);
    EXPECT_EQ(stats.sessionsByMode.at("device"), 2u);
    EXPECT_EQ(stats.sessionsByMode.at("device_pairing"), 1u);
    EXPECT_EQ(stats.sessionsByMode.at("unauthenticated"), 0u);
    EXPECT_EQ(stats.status, "healthy");
}

TEST(ConnectionStats, UnauthenticatedSessionsAreOnlyAFindingWhenTheyPileUp) {
    // A socket that has not signed in yet is how every connection starts; the sweep closes the ones that never do.
    ConnectionStats few;
    few.unauthenticatedTimeoutSeconds = 30;
    few.count("unauthenticated", 2);
    few.count("unauthenticated", 300);   // even one past the timeout: the sweep's job, not an operator's
    few.finalize();
    EXPECT_EQ(few.activeUnauthenticatedSessions, 2u);
    EXPECT_EQ(few.oldestUnauthenticatedSessionAgeSeconds, 300u);
    EXPECT_EQ(few.status, "healthy");

    ConnectionStats flood;
    for (std::uint64_t i = 0; i < ConnectionStats::kUnauthenticatedFlood; ++i) flood.count("unauthenticated", i);
    flood.finalize();
    EXPECT_EQ(flood.status, "critical");

    ConnectionStats devices;
    for (std::uint64_t i = 0; i < 2 * ConnectionStats::kUnauthenticatedFlood; ++i) devices.count("device", i);
    devices.finalize();
    EXPECT_EQ(devices.status, "healthy");
}
