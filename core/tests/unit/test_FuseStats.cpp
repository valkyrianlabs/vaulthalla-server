#include "runtime/Deps.hpp"
#include "stats/model/DashboardOverview.hpp"
#include "stats/model/DbStats.hpp"
#include "stats/model/FuseStats.hpp"

#include <cerrno>
#include <gtest/gtest.h>

#include <memory>
#include <optional>
#include <string>
#include <utility>

namespace {

using vh::stats::model::DashboardCardSummary;
using vh::stats::model::DashboardOverview;
using vh::stats::model::DashboardOverviewRequest;
using vh::stats::model::FuseOperation;
using vh::stats::model::FuseOpStatsSnapshot;
using vh::stats::model::FuseStats;

const FuseOpStatsSnapshot* findOp(const vh::stats::model::FuseStatsSnapshot& snapshot, const std::string& name) {
    for (const auto& op : snapshot.ops) {
        if (op.op == name) return &op;
    }
    return nullptr;
}

const DashboardCardSummary* findCard(const DashboardOverview& overview, const std::string& id) {
    for (const auto& card : overview.cards) {
        if (card.id == id) return &card;
    }
    return nullptr;
}

std::optional<std::string> metricTone(const DashboardCardSummary& card, const std::string& key) {
    for (const auto& metric : card.metrics) {
        if (metric.key == key) return metric.tone;
    }
    return std::nullopt;
}

std::optional<double> metricValue(const DashboardCardSummary& card, const std::string& key) {
    for (const auto& metric : card.metrics) {
        if (metric.key == key) return metric.numericValue;
    }
    return std::nullopt;
}

class FuseStatsDepsGuard {
public:
    explicit FuseStatsDepsGuard(std::shared_ptr<FuseStats> stats)
        : previous_(vh::runtime::Deps::get().fuseStats) {
        vh::runtime::Deps::get().fuseStats = std::move(stats);
    }

    ~FuseStatsDepsGuard() {
        vh::runtime::Deps::get().fuseStats = std::move(previous_);
    }

private:
    std::shared_ptr<FuseStats> previous_;
};

DashboardOverviewRequest fuseCardRequest() {
    DashboardOverviewRequest request;
    request.cards.push_back({.id = "system.fuse", .variant = "tiles", .size = "2x1"});
    return request;
}

}

TEST(FuseStatsTest, LookupEnoentIsExpectedButNotAlertable) {
    FuseStats stats;
    stats.record_success(FuseOperation::GetAttr, 100);
    stats.record_error(FuseOperation::Lookup, ENOENT, 250);

    const auto snapshot = stats.snapshot();
    EXPECT_EQ(snapshot.totalOps, 2u);
    EXPECT_EQ(snapshot.totalSuccesses, 1u);
    EXPECT_EQ(snapshot.totalErrors, 1u);
    EXPECT_EQ(snapshot.expectedErrors, 1u);
    EXPECT_EQ(snapshot.alertableErrors, 0u);
    EXPECT_DOUBLE_EQ(snapshot.errorRate, 0.5);
    EXPECT_DOUBLE_EQ(snapshot.expectedErrorRate, 0.5);
    EXPECT_DOUBLE_EQ(snapshot.alertableErrorRate, 0.0);

    const auto* lookup = findOp(snapshot, "lookup");
    ASSERT_NE(lookup, nullptr);
    EXPECT_EQ(lookup->count, 1u);
    EXPECT_EQ(lookup->errors, 1u);
    EXPECT_EQ(lookup->expectedErrors, 1u);
    EXPECT_EQ(lookup->alertableErrors, 0u);
    EXPECT_DOUBLE_EQ(lookup->errorRate, 1.0);
    EXPECT_DOUBLE_EQ(lookup->expectedErrorRate, 1.0);
    EXPECT_DOUBLE_EQ(lookup->alertableErrorRate, 0.0);
}

TEST(FuseStatsTest, StatFsEaccesIsExpectedButOtherStatFsErrorsAreAlertable) {
    FuseStats stats;
    stats.record_error(FuseOperation::StatFs, EACCES, 10);
    stats.record_error(FuseOperation::StatFs, EIO, 20);

    const auto snapshot = stats.snapshot();
    EXPECT_EQ(snapshot.totalOps, 2u);
    EXPECT_EQ(snapshot.totalErrors, 2u);
    EXPECT_EQ(snapshot.expectedErrors, 1u);
    EXPECT_EQ(snapshot.alertableErrors, 1u);
    EXPECT_DOUBLE_EQ(snapshot.errorRate, 1.0);
    EXPECT_DOUBLE_EQ(snapshot.expectedErrorRate, 0.5);
    EXPECT_DOUBLE_EQ(snapshot.alertableErrorRate, 0.5);

    const auto* statfs = findOp(snapshot, "statfs");
    ASSERT_NE(statfs, nullptr);
    EXPECT_EQ(statfs->count, 2u);
    EXPECT_EQ(statfs->errors, 2u);
    EXPECT_EQ(statfs->expectedErrors, 1u);
    EXPECT_EQ(statfs->alertableErrors, 1u);
    EXPECT_DOUBLE_EQ(statfs->errorRate, 1.0);
    EXPECT_DOUBLE_EQ(statfs->expectedErrorRate, 0.5);
    EXPECT_DOUBLE_EQ(statfs->alertableErrorRate, 0.5);
}

TEST(FuseStatsTest, NonLookupAndPermissionErrorsAreAlertable) {
    FuseStats stats;
    stats.record_error(FuseOperation::Lookup, ENOENT, 10);
    stats.record_error(FuseOperation::Read, EIO, 20);
    stats.record_error(FuseOperation::Open, EACCES, 30);
    stats.record_error(FuseOperation::Write, EBADF, 40);
    stats.record_success(FuseOperation::ReadDir, 50);
    stats.record_success(FuseOperation::StatFs, 60);

    const auto snapshot = stats.snapshot();
    EXPECT_EQ(snapshot.totalOps, 6u);
    EXPECT_EQ(snapshot.totalErrors, 4u);
    EXPECT_EQ(snapshot.expectedErrors, 1u);
    EXPECT_EQ(snapshot.alertableErrors, 3u);
    EXPECT_DOUBLE_EQ(snapshot.errorRate, 4.0 / 6.0);
    EXPECT_DOUBLE_EQ(snapshot.expectedErrorRate, 1.0 / 6.0);
    EXPECT_DOUBLE_EQ(snapshot.alertableErrorRate, 3.0 / 6.0);

    const auto* open = findOp(snapshot, "open");
    ASSERT_NE(open, nullptr);
    EXPECT_EQ(open->expectedErrors, 0u);
    EXPECT_EQ(open->alertableErrors, 1u);
    EXPECT_DOUBLE_EQ(open->alertableErrorRate, 1.0);
}

TEST(FuseStatsTest, PermissionDenialsAreExpectedForEveryOp) {
    // A uid with no Vaulthalla user (a MOTD script stat'ing every mount) or an RBAC refusal: the mount doing its job.
    FuseStats stats;
    stats.record_error(FuseOperation::GetAttr, EACCES, 10, true);
    stats.record_error(FuseOperation::Open, ENOENT, 20, true);
    stats.record_error(FuseOperation::GetAttr, EACCES, 30);

    const auto snapshot = stats.snapshot();
    EXPECT_EQ(snapshot.totalErrors, 3u);
    EXPECT_EQ(snapshot.expectedErrors, 2u);
    EXPECT_EQ(snapshot.alertableErrors, 1u);

    const auto* getattr = findOp(snapshot, "getattr");
    ASSERT_NE(getattr, nullptr);
    EXPECT_EQ(getattr->expectedErrors, 1u);
    EXPECT_EQ(getattr->alertableErrors, 1u);
    EXPECT_EQ(snapshot.alertableErrnoTypes, 1u);
}

TEST(FuseStatsTest, TimerRecordsADenialAsExpected) {
    FuseStats stats;
    {
        vh::stats::model::ScopedFuseOpTimer timer(&stats, FuseOperation::GetAttr);
        timer.denied(EACCES);
    }
    const auto snapshot = stats.snapshot();
    EXPECT_EQ(snapshot.totalErrors, 1u);
    EXPECT_EQ(snapshot.expectedErrors, 1u);
    EXPECT_EQ(snapshot.alertableErrors, 0u);
}

TEST(FuseStatsTest, DashboardIgnoresPermissionDenialsForFuseSeverity) {
    auto stats = std::make_shared<FuseStats>();
    for (int i = 0; i < 3; ++i) stats->record_error(FuseOperation::GetAttr, EACCES, 10, true);
    FuseStatsDepsGuard guard(stats);

    const auto overview = DashboardOverview::snapshot(fuseCardRequest());
    const auto* card = findCard(overview, "system.fuse");
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card->severity, "info");
    EXPECT_TRUE(card->errors.empty());
    ASSERT_TRUE(metricValue(*card, "alertable_error_rate"));
    EXPECT_DOUBLE_EQ(*metricValue(*card, "alertable_error_rate"), 0.0);
}

TEST(FuseStatsTest, UnlinkEnoentRemainsAlertable) {
    FuseStats stats;
    stats.record_error(FuseOperation::Unlink, ENOENT, 10);

    const auto snapshot = stats.snapshot();
    EXPECT_EQ(snapshot.totalOps, 1u);
    EXPECT_EQ(snapshot.expectedErrors, 0u);
    EXPECT_EQ(snapshot.alertableErrors, 1u);

    const auto* unlink = findOp(snapshot, "unlink");
    ASSERT_NE(unlink, nullptr);
    EXPECT_EQ(unlink->errors, 1u);
    EXPECT_EQ(unlink->expectedErrors, 0u);
    EXPECT_EQ(unlink->alertableErrors, 1u);
}

TEST(FuseStatsTest, DashboardIgnoresExpectedLookupMissesForFuseSeverity) {
    auto stats = std::make_shared<FuseStats>();
    for (int i = 0; i < 100; ++i) stats->record_error(FuseOperation::Lookup, ENOENT, 10);
    FuseStatsDepsGuard guard(stats);

    const auto overview = DashboardOverview::snapshot(fuseCardRequest());
    const auto* card = findCard(overview, "system.fuse");
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card->severity, "info");
    EXPECT_TRUE(card->warnings.empty());
    EXPECT_TRUE(card->errors.empty());
    ASSERT_TRUE(metricValue(*card, "error_rate"));
    ASSERT_TRUE(metricValue(*card, "alertable_error_rate"));
    EXPECT_DOUBLE_EQ(*metricValue(*card, "error_rate"), 1.0);
    EXPECT_DOUBLE_EQ(*metricValue(*card, "alertable_error_rate"), 0.0);
}

TEST(FuseStatsTest, DashboardIgnoresExpectedStatFsPermissionProbesForFuseSeverity) {
    auto stats = std::make_shared<FuseStats>();
    for (int i = 0; i < 100; ++i) stats->record_error(FuseOperation::StatFs, EACCES, 10);
    FuseStatsDepsGuard guard(stats);

    const auto overview = DashboardOverview::snapshot(fuseCardRequest());
    const auto* card = findCard(overview, "system.fuse");
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card->severity, "info");
    EXPECT_TRUE(card->warnings.empty());
    EXPECT_TRUE(card->errors.empty());
    ASSERT_TRUE(metricValue(*card, "error_rate"));
    ASSERT_TRUE(metricValue(*card, "alertable_error_rate"));
    EXPECT_DOUBLE_EQ(*metricValue(*card, "error_rate"), 1.0);
    EXPECT_DOUBLE_EQ(*metricValue(*card, "alertable_error_rate"), 0.0);
}

TEST(FuseStatsTest, DashboardWarnsAndErrorsOnAlertableFuseErrors) {
    auto warningStats = std::make_shared<FuseStats>();
    for (int i = 0; i < 97; ++i) warningStats->record_success(FuseOperation::Lookup, 10);
    for (int i = 0; i < 3; ++i) warningStats->record_error(FuseOperation::Read, EIO, 10);
    FuseStatsDepsGuard warningGuard(warningStats);

    const auto warningOverview = DashboardOverview::snapshot(fuseCardRequest());
    const auto* warningCard = findCard(warningOverview, "system.fuse");
    ASSERT_NE(warningCard, nullptr);
    EXPECT_EQ(warningCard->severity, "warning");
    EXPECT_EQ(warningCard->warnings.size(), 1u);
    EXPECT_TRUE(warningCard->errors.empty());
    ASSERT_TRUE(metricValue(*warningCard, "alertable_error_rate"));
    EXPECT_DOUBLE_EQ(*metricValue(*warningCard, "alertable_error_rate"), 0.03);

    auto errorStats = std::make_shared<FuseStats>();
    for (int i = 0; i < 89; ++i) errorStats->record_success(FuseOperation::Lookup, 10);
    for (int i = 0; i < 11; ++i) errorStats->record_error(FuseOperation::Write, EIO, 10);
    vh::runtime::Deps::get().fuseStats = errorStats;

    const auto errorOverview = DashboardOverview::snapshot(fuseCardRequest());
    const auto* errorCard = findCard(errorOverview, "system.fuse");
    ASSERT_NE(errorCard, nullptr);
    EXPECT_EQ(errorCard->severity, "error");
    EXPECT_EQ(errorCard->errors.size(), 1u);
    EXPECT_TRUE(errorCard->warnings.empty());
    ASSERT_TRUE(metricValue(*errorCard, "alertable_error_rate"));
    EXPECT_DOUBLE_EQ(*metricValue(*errorCard, "alertable_error_rate"), 0.11);
}

// #159: an errno that only ever came back where it is expected (lookup ENOENT, statfs EACCES) is not a warning.
TEST(FuseStatsTest, ErrnoTypesCountOnlyAlertableOccurrencesAsAlertable) {
    FuseStats stats;
    stats.record_error(FuseOperation::Lookup, ENOENT, 10);
    stats.record_error(FuseOperation::Lookup, ENOENT, 10);
    stats.record_error(FuseOperation::Unlink, ENOENT, 10);
    stats.record_error(FuseOperation::StatFs, EACCES, 10);

    const auto snapshot = stats.snapshot();
    ASSERT_EQ(snapshot.topErrors.size(), 2u);
    EXPECT_EQ(snapshot.alertableErrnoTypes, 1u);
    for (const auto& err : snapshot.topErrors) {
        if (err.errnoValue == ENOENT) {
            EXPECT_EQ(err.count, 3u);
            EXPECT_EQ(err.alertableCount, 1u);
        } else {
            EXPECT_EQ(err.errnoValue, EACCES);
            EXPECT_EQ(err.alertableCount, 0u);
        }
    }
}

TEST(FuseStatsTest, DashboardErrnoTypesDoNotWarnOnExpectedErrnos) {
    auto stats = std::make_shared<FuseStats>();
    for (int i = 0; i < 50; ++i) stats->record_error(FuseOperation::Lookup, ENOENT, 10);
    for (int i = 0; i < 5; ++i) stats->record_error(FuseOperation::StatFs, EACCES, 10);
    FuseStatsDepsGuard guard(stats);

    const auto overview = DashboardOverview::snapshot(fuseCardRequest());
    const auto* card = findCard(overview, "system.fuse");
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(metricTone(*card, "errno_types"), "info");
    EXPECT_TRUE(card->warnings.empty());
}

TEST(FuseStatsTest, DashboardErrnoTypesFollowCardSeverityOnAlertableErrnos) {
    auto stats = std::make_shared<FuseStats>();
    for (int i = 0; i < 97; ++i) stats->record_success(FuseOperation::Read, 10);
    for (int i = 0; i < 3; ++i) stats->record_error(FuseOperation::Read, EIO, 10);
    FuseStatsDepsGuard guard(stats);

    const auto overview = DashboardOverview::snapshot(fuseCardRequest());
    const auto* card = findCard(overview, "system.fuse");
    ASSERT_NE(card, nullptr);
    EXPECT_EQ(card->severity, "warning");
    EXPECT_EQ(metricTone(*card, "errno_types"), "warning");

    // Below the alertable-rate threshold an alertable errno is visible but not a warning.
    auto quiet = std::make_shared<FuseStats>();
    for (int i = 0; i < 999; ++i) quiet->record_success(FuseOperation::Read, 10);
    quiet->record_error(FuseOperation::Read, EIO, 10);
    vh::runtime::Deps::get().fuseStats = quiet;
    const auto quietOverview = DashboardOverview::snapshot(fuseCardRequest());
    const auto* quietCard = findCard(quietOverview, "system.fuse");
    ASSERT_NE(quietCard, nullptr);
    EXPECT_EQ(metricTone(*quietCard, "errno_types"), "info");
}

// #159: unmeasured values are unknown, never healthy; oldest_tx compares the age with real thresholds.
TEST(DashboardToneTest, UnmeasuredCountsAreUnknownNotHealthy) {
    namespace tone = vh::stats::model::dashboard_tone;
    EXPECT_EQ(tone::zeroIsHealthy(std::nullopt), "unknown");
    EXPECT_EQ(tone::zeroIsHealthy(0u), "healthy");
    EXPECT_EQ(tone::zeroIsHealthy(3u), "warning");
    EXPECT_EQ(tone::zeroIsHealthy(3u, "error"), "error");
}

TEST(DashboardToneTest, OldestTransactionUsesThresholdsAndIsUnknownWhenUnmeasured) {
    namespace tone = vh::stats::model::dashboard_tone;
    using vh::stats::model::kDbOldestTransactionCriticalSeconds;
    using vh::stats::model::kDbOldestTransactionWarningSeconds;
    EXPECT_EQ(tone::dbOldestTransaction(false, std::nullopt), "unknown");
    EXPECT_EQ(tone::dbOldestTransaction(false, 0u), "unknown");
    EXPECT_EQ(tone::dbOldestTransaction(true, std::nullopt), "healthy");
    EXPECT_EQ(tone::dbOldestTransaction(true, 0u), "healthy");
    EXPECT_EQ(tone::dbOldestTransaction(true, kDbOldestTransactionWarningSeconds - 1), "healthy");
    EXPECT_EQ(tone::dbOldestTransaction(true, kDbOldestTransactionWarningSeconds), "warning");
    EXPECT_EQ(tone::dbOldestTransaction(true, kDbOldestTransactionCriticalSeconds), "error");
}

TEST(DashboardToneTest, ErrnoTypesToneOnlyEscalatesOnAlertableErrnos) {
    namespace tone = vh::stats::model::dashboard_tone;
    EXPECT_EQ(tone::fuseErrnoTypes(0, 0, "healthy"), "healthy");
    EXPECT_EQ(tone::fuseErrnoTypes(2, 0, "info"), "info");
    EXPECT_EQ(tone::fuseErrnoTypes(2, 1, "warning"), "warning");
    EXPECT_EQ(tone::fuseErrnoTypes(2, 1, "error"), "error");
}
