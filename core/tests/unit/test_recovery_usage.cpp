// The local upstream usage ledger (recovery::usage, vault_upstream_usage_daily): every metered request of a vault's
// controller feeds per-vault UTC-day counters (request tags split multipart, version listings and restores); every
// successful upstream write is classified first put / overwrite / delete with the replaced object's bytes from the
// remote index; flushes are additive across flushes and day boundaries, and nothing is lost when a flush fails.

#include "../helpers/sync_conflict_harness.hpp"

#include "db/query/recovery/Usage.hpp"
#include "recovery/Hooks.hpp"
#include "recovery/usage/Ledger.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/upstream/Guard.hpp"

#include <gtest/gtest.h>

#include <algorithm>

namespace vh::test_recovery_usage {

namespace usage = vh::recovery::usage;
namespace rq = db::query::recovery;
using namespace test_support::sync_conflicts;

constexpr std::time_t kDay1 = 1792065600;            // 2026-10-15T12:00:00Z
constexpr std::time_t kDay1Late = 1792108799;        // 2026-10-15T23:59:59Z
constexpr std::time_t kDay2 = 1792108800;            // 2026-10-16T00:00:00Z

// A controller whose metering the test drives directly (no network).
class MeteredController final : public storage::s3::Controller {
public:
    MeteredController() : Controller(fakeKey(), "usage-bucket") {}
    void meter(const RequestKind kind, const uint64_t amount = 1) const { recordRequest(kind, amount); }
    void meterUpload(const uint64_t bytes) const { recordUploadBytes(bytes); }
    using Controller::RequestKind;
};

rq::UsageCounters pendingFor(const uint32_t vaultId, const std::string& day) {
    rq::UsageCounters c;
    for (const auto& d : usage::pendingForTesting())
        if (d.vault_id == vaultId && d.day == day) c += d.counters;
    return c;
}

class RecoveryUsageLedger : public ::testing::Test {
protected:
    void SetUp() override {
        storage::upstream::guard::setForTesting({});
        usage::resetForTesting();
        usage::setClockForTesting([] { return kDay1; });
    }
    void TearDown() override {
        usage::setClockForTesting({});
        usage::resetForTesting();
        storage::upstream::guard::clearForTesting();
    }
};

TEST_F(RecoveryUsageLedger, UtcDaysAreCalendarDaysInUtc) {
    EXPECT_EQ(usage::utcDay(kDay1), "2026-10-15");
    EXPECT_EQ(usage::utcDay(kDay1Late), "2026-10-15");
    EXPECT_EQ(usage::utcDay(kDay2), "2026-10-16");
}

TEST_F(RecoveryUsageLedger, ControllerRequestsFeedTheirVaultsCounters) {
    MeteredController c;
    using K = MeteredController::RequestKind;
    c.meter(K::Put);   // no vault yet: not counted
    EXPECT_TRUE(usage::pendingForTesting().empty());

    c.setUsageVault(4242);
    c.meter(K::List);
    c.meter(K::Head, 2);
    c.meter(K::Get);
    c.meter(K::Put);
    c.meter(K::Copy);
    c.meter(K::Delete);
    c.meter(K::DownloadBytes, 1000);
    c.meterUpload(700);
    {
        const usage::ScopedRequestTag tag(usage::RequestTag::MultipartInitiate);
        c.meter(K::Put);
    }
    {
        const usage::ScopedRequestTag tag(usage::RequestTag::MultipartPart);
        c.meter(K::Put);
        c.meter(K::Put);
    }
    {
        const usage::ScopedRequestTag tag(usage::RequestTag::VersionList);
        c.meter(K::List);
    }
    {
        const usage::ScopedRequestTag restore(usage::RequestTag::VersionRestore);
        c.meter(K::Copy);
        c.meter(K::Get);
        c.meter(K::DownloadBytes, 300);
        {
            const usage::ScopedRequestTag inner(usage::RequestTag::None);   // tags nest
            c.meter(K::Get);
        }
    }
    EXPECT_EQ(usage::currentRequestTag(), usage::RequestTag::None);

    const auto got = pendingFor(4242, "2026-10-15");
    EXPECT_EQ(got.list_requests, 2u);
    EXPECT_EQ(got.version_list_requests, 1u);
    EXPECT_EQ(got.head_requests, 2u);
    EXPECT_EQ(got.get_requests, 3u);
    EXPECT_EQ(got.put_requests, 4u);
    EXPECT_EQ(got.multipart_uploads, 1u);
    EXPECT_EQ(got.multipart_parts, 2u);
    EXPECT_EQ(got.copy_requests, 2u);
    EXPECT_EQ(got.delete_requests, 1u);
    EXPECT_EQ(got.downloaded_bytes, 1300u);
    EXPECT_EQ(got.uploaded_bytes, 700u);
    EXPECT_EQ(got.version_restore_requests, 2u) << "the restore's COPY and GET, not the untagged GET";
    EXPECT_EQ(got.version_restore_bytes, 300u);
}

TEST_F(RecoveryUsageLedger, CountersAreDatedInUtcAtTheMomentOfTheRequest) {
    MeteredController c;
    c.setUsageVault(4243);
    usage::setClockForTesting([] { return kDay1Late; });
    c.meter(MeteredController::RequestKind::Put);
    usage::setClockForTesting([] { return kDay2; });
    c.meter(MeteredController::RequestKind::Put);
    EXPECT_EQ(pendingFor(4243, "2026-10-15").put_requests, 1u);
    EXPECT_EQ(pendingFor(4243, "2026-10-16").put_requests, 1u);
}

TEST_F(RecoveryUsageLedger, AFailedFlushKeepsTheCounts) {
    // No database in this suite: the flush fails and the deltas stay for the next one.
    if (db::Transactions::dbPool_) GTEST_SKIP() << "a database is initialized in this process";
    usage::noteRequest(4244, usage::Request::Put, 3);
    const auto r = usage::flush();
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(pendingFor(4244, "2026-10-15").put_requests, 3u);
}

// ---- DB-backed: the write hook and the flush ------------------------------------------------------------------------

class RecoveryUsageDbTest : public Harness {
protected:
    void SetUp() override {
        Harness::SetUp();
        if (skipTests) return;
        usage::resetForTesting();
        usage::setClockForTesting([] { return kDay1; });
    }
    void TearDown() override {
        usage::setClockForTesting({});
        usage::resetForTesting();
    }

    static void indexObject(const uint32_t vaultId, const std::string& key, const uint64_t size, const std::string& etag) {
        db::Transactions::exec("test::indexObject", [&](pqxx::work& txn) {
            txn.exec("INSERT INTO remote_object_index (vault_id, object_key, size_bytes, etag) VALUES ($1, $2, $3, $4) "
                     "ON CONFLICT (vault_id, object_key) DO UPDATE SET size_bytes = EXCLUDED.size_bytes, etag = EXCLUDED.etag",
                     pqxx::params{vaultId, key, static_cast<int64_t>(size), etag});
        });
    }
};

TEST_F(RecoveryUsageDbTest, TheWriteHookClassifiesFirstPutsOverwritesAndDeletes) {
    const auto f = remoteVault(superUser);
    const auto v = f.vault->id;
    indexObject(v, "docs/old.txt", 500, "\"etag-a\"");
    indexObject(v, "docs/gone.txt", 700, "\"etag-g\"");
    indexObject(v, "docs/same.txt", 900, "\"etag-s\"");

    using W = vh::recovery::hooks::UpstreamWrite;
    usage::noteUpstreamWrite(W{.vault_id = v, .key = "docs/new.txt", .is_delete = false, .object_size = 100,
                               .etag = "\"etag-n\"", .version_id = std::nullopt, .file = nullptr});
    usage::noteUpstreamWrite(W{.vault_id = v, .key = "docs/old.txt", .is_delete = false, .object_size = 120,
                               .etag = "\"etag-b\"", .version_id = std::nullopt, .file = nullptr});
    usage::noteUpstreamWrite(W{.vault_id = v, .key = "docs/gone.txt", .is_delete = true, .object_size = std::nullopt,
                               .etag = std::nullopt, .version_id = std::nullopt, .file = nullptr});
    usage::noteUpstreamWrite(W{.vault_id = v, .key = "docs/never-indexed.txt", .is_delete = true,
                               .object_size = std::nullopt, .etag = std::nullopt, .version_id = std::nullopt, .file = nullptr});
    // The index already shows this very write: what it replaced is unknown, nothing is guessed.
    usage::noteUpstreamWrite(W{.vault_id = v, .key = "docs/same.txt", .is_delete = false, .object_size = 900,
                               .etag = "etag-s", .version_id = std::nullopt, .file = nullptr});
    // Vaulthalla's own manifest is priced separately.
    usage::noteUpstreamWrite(W{.vault_id = v, .key = ".vaulthalla/index-v1.json", .is_delete = false, .object_size = 50,
                               .etag = "\"m\"", .version_id = std::nullopt, .file = nullptr});

    const auto got = pendingFor(v, "2026-10-15");
    EXPECT_EQ(got.first_put_objects, 1u);
    EXPECT_EQ(got.first_put_bytes, 100u);
    EXPECT_EQ(got.overwrite_objects, 1u);
    EXPECT_EQ(got.overwritten_bytes, 500u) << "the replaced object's bytes, not the new one's";
    EXPECT_EQ(got.deleted_objects, 2u) << "every delete leaves a delete marker on a versioned bucket";
    EXPECT_EQ(got.deleted_bytes, 700u);
}

TEST_F(RecoveryUsageDbTest, FlushesAreAdditiveAcrossFlushesAndDays) {
    const auto f = remoteVault(superUser);
    const auto v = f.vault->id;
    (void)usage::flush();   // whatever other suites left behind
    usage::resetForTesting();

    usage::noteRequest(v, usage::Request::Put, 2);
    usage::noteUploadedBytes(v, 1000);
    auto r = usage::flush();
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.rows, 1u);
    EXPECT_TRUE(usage::pendingForTesting().empty());

    usage::noteRequest(v, usage::Request::Put, 3);
    usage::setClockForTesting([] { return kDay2; });
    usage::noteRequest(v, usage::Request::Delete, 1);
    r = usage::flush();
    ASSERT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.rows, 2u);

    const auto rows = rq::Usage::range(v, "2026-10-15", "2026-10-16");
    ASSERT_EQ(rows.size(), 2u);
    EXPECT_EQ(rows[0].day, "2026-10-15");
    EXPECT_EQ(rows[0].counters.put_requests, 5u);
    EXPECT_EQ(rows[0].counters.uploaded_bytes, 1000u);
    EXPECT_EQ(rows[1].day, "2026-10-16");
    EXPECT_EQ(rows[1].counters.delete_requests, 1u);
    EXPECT_EQ(rows[1].counters.put_requests, 0u);

    // A vault that went away meanwhile: its counts are dropped, the others still land.
    usage::noteRequest(v, usage::Request::Get, 1);
    usage::noteRequest(999'999, usage::Request::Get, 1);
    r = usage::flush();
    EXPECT_TRUE(r.ok) << r.error;
    EXPECT_EQ(r.rows, 1u);
    EXPECT_EQ(r.dropped, 1u);
    EXPECT_EQ(rq::Usage::range(v, "2026-10-16", "2026-10-16").at(0).counters.get_requests, 1u);
}

TEST_F(RecoveryUsageDbTest, TickFlushesEveryMinuteAndRunsAlertsHourly) {
    const auto f = remoteVault(superUser);
    const auto v = f.vault->id;
    (void)usage::flush();
    usage::resetForTesting();
    unsigned alertRuns = 0;
    usage::setAlertJobForTesting([&] { ++alertRuns; });

    const auto t0 = std::chrono::system_clock::from_time_t(kDay1);
    usage::noteRequest(v, usage::Request::List, 1);
    usage::tick(t0);
    EXPECT_TRUE(usage::pendingForTesting().empty());
    EXPECT_EQ(alertRuns, 1u);

    usage::noteRequest(v, usage::Request::List, 1);
    usage::tick(t0 + std::chrono::seconds(30));
    EXPECT_FALSE(usage::pendingForTesting().empty()) << "not a minute yet";
    usage::tick(t0 + std::chrono::seconds(61));
    EXPECT_TRUE(usage::pendingForTesting().empty());
    EXPECT_EQ(alertRuns, 1u);
    usage::tick(t0 + std::chrono::hours(1) + std::chrono::seconds(1));
    EXPECT_EQ(alertRuns, 2u);
    usage::setAlertJobForTesting({});
    EXPECT_EQ(rq::Usage::range(v, "2026-10-15", "2026-10-15").at(0).counters.list_requests, 2u);
}

}
