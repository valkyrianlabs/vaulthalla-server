// File recovery, provider versions (.claude/context/recovery.md, "Provider versioning"): the version index from our
// own writes and from listings, recovery points, point-in-time plans and version-aware restore (provider copy or
// bounded transfer) on the VersionedBucket fake. DB-backed (bin/tests/run_unit.sh).

#include "../helpers/recovery_provider_harness.hpp"
#include "../helpers/upstream_event_fakes.hpp"

#include "db/query/upstream/Channel.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/events/Applier.hpp"
#include "sync/events/Event.hpp"
#include "sync/events/Ingest.hpp"
#include "sync/events/Subscriptions.hpp"

#include <gtest/gtest.h>

namespace vh::test_recovery_provider {

using namespace test_support::recovery_provider;
namespace rp = recovery::provider;
using recovery::ItemAction;

constexpr uint64_t kTag = 16;

class RecoveryProviderTest : public ProviderHarness {
protected:
    void TearDown() override {
        test_support::upstream_events::removeFakeProvider();
        storage::upstream::guard::clearForTesting();
    }

    // A file written, then rewritten, each followed by a pass: one provider version per content.
    static std::vector<VersionRow> generations(const VFixture& f, const std::string& path,
                                               const std::vector<std::string>& contents) {
        for (const auto& c : contents) {
            put(f, path, c);
            const auto plan = runPass(f);
            EXPECT_EQ(transfers(plan), 1u) << path << " <- " << c;
        }
        auto rows = history(f, path);
        std::ranges::reverse(rows);   // oldest first
        return rows;
    }

    static unsigned restoreTemps(const VFixture& f, const std::string& path) {
        unsigned n = 0;
        const auto dir = backingOf(f, path).parent_path();
        std::error_code ec;
        for (const auto& e : std::filesystem::directory_iterator(dir, ec))
            if (e.path().filename().string().starts_with(".vh-restore-")) ++n;
        return n;
    }
};

// ---- the index -------------------------------------------------------------------------------------------------------

TEST_F(RecoveryProviderTest, OwnWritesIndexEachVersionWithItsIvAndKey) {
    auto f = versionedVault();
    const auto rows = generations(f, "/own/a.txt", {"first", "second generation"});
    ASSERT_EQ(rows.size(), 2u);
    const auto local = db::query::fs::File::getFileByPath(f.vault->id, "/own/a.txt");
    const auto keyVersion = f.engine->encryptionManager->get_key_version();

    const auto& older = rows[0];
    const auto& newer = rows[1];
    EXPECT_EQ(older.origin, "vaulthalla");
    EXPECT_FALSE(older.is_latest);
    EXPECT_TRUE(older.became_noncurrent_at.has_value());
    EXPECT_EQ(older.plaintext_bytes, 5u);
    EXPECT_EQ(older.size_bytes, 5u + kTag);
    EXPECT_EQ(older.encrypted, true);
    EXPECT_EQ(older.key_version, keyVersion);
    ASSERT_TRUE(older.encryption_iv.has_value());

    EXPECT_TRUE(newer.is_latest);
    EXPECT_FALSE(newer.became_noncurrent_at.has_value());
    EXPECT_EQ(newer.encryption_iv, local->encryption_iv);
    EXPECT_EQ(newer.content_hash, local->content_hash);
    EXPECT_NE(newer.encryption_iv, older.encryption_iv);
    // The bucket agrees: each version carries the IV the index recorded for it.
    EXPECT_EQ(f.bucket->version("own/a.txt", older.version_id)->meta.at("vh-iv"), *older.encryption_iv);
    EXPECT_EQ(f.bucket->current("own/a.txt")->etag, newer.etag);

    // Vaulthalla's index manifest is never a recovery point.
    EXPECT_FALSE(f.bucket->history(sync::model::remote_manifest::INDEX_V1_KEY).empty());
    EXPECT_TRUE(db::query::recovery::ObjectVersion::listUnderPrefix(f.vault->id, ".vaulthalla/", true, 100).empty());
}

TEST_F(RecoveryProviderTest, UnversionedBucketIndexesNothing) {
    auto f = versionedVault(Strategy::Cache, true, Versioning::Unversioned);
    (void)generations(f, "/plain/u.txt", {"one", "two"});
    EXPECT_TRUE(history(f, "/plain/u.txt", true).empty());
}

TEST_F(RecoveryProviderTest, ListingLearnsVersionsAndMarkersWithoutBodies) {
    auto f = versionedVault();
    (void)generations(f, "/list/own.txt", {"ours"});
    const auto ownBefore = history(f, "/list/own.txt").front();
    // Someone else's history: three keys, two versions each, and a delete marker over one of them.
    for (const auto* k : {"list/x.bin", "list/y.bin", "list/z.bin"}) {
        f.bucket->seed(k, std::string("old ") + k);
        f.bucket->seed(k, std::string("new ") + k);
    }
    const auto markerId = f.bucket->seedDeleteMarker("list/y.bin");
    f.bucket->resetCounters();

    const auto result = rp::versions::refresh(f.engine, "list/", {.max_requests = 20, .page_size = 2});
    EXPECT_TRUE(result.complete);
    EXPECT_FALSE(result.stopped_reason.has_value());
    EXPECT_EQ(result.versions, 7u);
    EXPECT_EQ(result.delete_markers, 1u);
    EXPECT_EQ(result.requests, 4u);   // 8 entries, pages of 2
    const auto c = f.bucket->counters();
    EXPECT_EQ(c.list, 4u);
    EXPECT_EQ(c.get, 0u);
    EXPECT_EQ(c.head, 0u);
    EXPECT_EQ(c.body_gets, 0u);
    EXPECT_EQ(result.usage.list_requests, 4u);
    EXPECT_EQ(result.usage.source, "recovery_version_list");

    // Our own row keeps its origin and its encryption metadata.
    const auto own = history(f, "/list/own.txt").front();
    EXPECT_EQ(own.id, ownBefore.id);
    EXPECT_EQ(own.origin, "vaulthalla");
    EXPECT_EQ(own.encryption_iv, ownBefore.encryption_iv);

    const auto y = history(f, "/list/y.bin");
    ASSERT_EQ(y.size(), 3u);
    EXPECT_TRUE(y[0].is_delete_marker);
    EXPECT_EQ(y[0].version_id, markerId);
    EXPECT_TRUE(y[0].is_latest);
    EXPECT_EQ(y[1].origin, "observed");
    EXPECT_FALSE(y[1].is_latest);
    // A noncurrent version stopped being current when the next newer one was written.
    EXPECT_EQ(y[1].became_noncurrent_at, y[0].last_modified);

    // Points: a marker is "absent", the current version has nothing to restore, an older one is restorable.
    const auto pts = rp::points::forPath(f.engine, "/list/y.bin", false);
    ASSERT_EQ(pts.size(), 3u);
    EXPECT_TRUE(pts[0].is_delete_marker);
    EXPECT_FALSE(pts[0].restorable);
    EXPECT_TRUE(pts[1].restorable);
    EXPECT_EQ(pts[1].origin, "observed");
    EXPECT_EQ(pts[1].retention.policy, "unknown");
    const auto x = rp::points::forPath(f.engine, "/list/x.bin", false);
    ASSERT_EQ(x.size(), 2u);
    EXPECT_TRUE(x[0].is_current);
    EXPECT_FALSE(x[0].restorable);
    const auto dir = rp::points::forPath(f.engine, "/list", true,
                                         {.kind = rp::points::RetentionInfo::Kind::Days, .days = 30});
    EXPECT_EQ(dir.size(), 8u);   // own.txt, x ×2, y ×2 + marker, z ×2
    EXPECT_EQ(dir.back().retention.policy, "provider_days:30");

    // A version the provider no longer holds is marked gone after the next complete listing.
    ASSERT_TRUE(f.bucket->purgeVersion("list/x.bin", history(f, "/list/x.bin")[1].version_id));
    const auto again = rp::versions::refresh(f.engine, "list/", {.max_requests = 20});
    EXPECT_TRUE(again.complete);
    EXPECT_EQ(again.marked_gone, 1u);
    EXPECT_EQ(history(f, "/list/x.bin").size(), 1u);
    EXPECT_EQ(history(f, "/list/x.bin", true).size(), 2u);

    // A capped listing keeps what it learned and marks nothing gone.
    f.bucket->purgeVersion("list/z.bin", history(f, "/list/z.bin")[1].version_id);
    const auto capped = rp::versions::refresh(f.engine, "list/", {.max_requests = 1, .page_size = 1});
    EXPECT_FALSE(capped.complete);
    EXPECT_TRUE(capped.stopped_reason.has_value());
    EXPECT_EQ(capped.marked_gone, 0u);
    EXPECT_EQ(history(f, "/list/z.bin").size(), 2u);
}

// ---- point-in-time plans ---------------------------------------------------------------------------------------------

TEST_F(RecoveryProviderTest, PointInTimePlanAcrossThreeObjectsWithADeleteMarker) {
    auto f = versionedVault();
    const std::time_t t0 = std::time(nullptr) - 7200;
    f.bucket->setNow(t0);
    f.bucket->seed("pit/a.txt", "a1");
    f.bucket->seed("pit/b.txt", "b1");
    f.bucket->setNow(t0 + 1000);
    f.bucket->seed("pit/a.txt", "a2");
    f.bucket->seed("pit/c.txt", "c1");
    f.bucket->seedDeleteMarker("pit/b.txt");
    ASSERT_TRUE(rp::versions::refresh(f.engine, "pit/").complete);
    put(f, "/pit/c.txt", "local c");   // exists now, did not exist at t0 + 500

    const auto plan = rp::planAt(f.engine, "/pit", t0 + 500);
    EXPECT_TRUE(plan.point_in_time);
    EXPECT_FALSE(plan.atomic);
    EXPECT_NE(plan.consistency_note.find("not a transactionally consistent snapshot"), std::string::npos);
    ASSERT_EQ(plan.items.size(), 2u);
    EXPECT_EQ(plan.items[0].destination_path, "/pit/a.txt");
    EXPECT_EQ(plan.items[0].action, ItemAction::Create);
    EXPECT_EQ(plan.items[1].destination_path, "/pit/b.txt");
    EXPECT_EQ(plan.items[1].action, ItemAction::Create);
    EXPECT_EQ(plan.creates, 2u);
    EXPECT_EQ(plan.removals, 0u);
    EXPECT_FALSE(plan.warnings.empty());   // /pit/c.txt kept (prune off) + unverified versions
    for (const auto& item : plan.items) EXPECT_EQ(item.method, "provider_copy");

    const auto pruned = rp::planAt(f.engine, "/pit", t0 + 500, std::nullopt, true);
    EXPECT_EQ(pruned.removals, 1u);
    const auto removal = std::ranges::find_if(pruned.items, [](const auto& i) { return i.action == ItemAction::Remove; });
    ASSERT_NE(removal, pruned.items.end());
    EXPECT_EQ(removal->destination_path, "/pit/c.txt");
    EXPECT_EQ(removal->destination_source_id, sourceIdOf(f, "/pit/c.txt"));

    // Later: a is at a2 (current → skip), b was deleted (marker: absent), c exists.
    const auto later = rp::planAt(f.engine, "/pit", t0 + 5000, std::nullopt, false);
    ASSERT_EQ(later.items.size(), 2u);
    EXPECT_EQ(later.items[0].destination_path, "/pit/a.txt");
    EXPECT_EQ(later.items[0].action, ItemAction::Skip);
    EXPECT_EQ(later.items[1].destination_path, "/pit/c.txt");

    // Re-rooted to another destination.
    const auto elsewhere = rp::planAt(f.engine, "/pit", t0 + 500, std::filesystem::path("/restored"));
    ASSERT_EQ(elsewhere.items.size(), 2u);
    EXPECT_EQ(elsewhere.items[0].destination_path, "/restored/a.txt");
    EXPECT_EQ(elsewhere.items[0].method, "provider_transfer");
}

// ---- restore -----------------------------------------------------------------------------------------------------------

TEST_F(RecoveryProviderTest, RestoreByProviderCopyUnderTheSameKey) {
    auto f = versionedVault();
    const auto rows = generations(f, "/copy/doc.txt", {"version one", "version two!"});
    f.bucket->resetCounters();
    const auto manifestBefore = manifestVersions(f);

    const auto item = rp::planFor(f.engine, rows[0]);
    EXPECT_EQ(item.action, ItemAction::Overwrite);
    EXPECT_EQ(item.method, "provider_copy");
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(out.method, "provider_copy");
    EXPECT_TRUE(out.provider_changed);
    EXPECT_EQ(out.usage.source, "recovery_restore");
    EXPECT_EQ(out.usage.copy_requests, 1u);
    EXPECT_GE(out.usage.head_requests, 1u);   // the version HEAD (+ the index manifest publish's)
    EXPECT_EQ(out.usage.get_requests, 0u);
    EXPECT_EQ(out.usage.downloaded_bytes, 0u);

    const auto c = f.bucket->counters();
    EXPECT_EQ(c.copy, 1u);
    EXPECT_EQ(c.body_gets, 0u);
    EXPECT_EQ(c.put, manifestVersions(f) - manifestBefore);   // only the index manifest was PUT
    const auto bucketHistory = f.bucket->history("copy/doc.txt");
    ASSERT_EQ(bucketHistory.size(), 3u);
    EXPECT_EQ(bucketHistory[0].meta.at("vh-iv"), *rows[0].encryption_iv);

    // Index: the copy is the new current version (ours, with the restored generation's IV); v2 is noncurrent.
    const auto now = history(f, "/copy/doc.txt");
    ASSERT_EQ(now.size(), 3u);
    EXPECT_TRUE(now[0].is_latest);
    EXPECT_EQ(now[0].origin, "vaulthalla");
    EXPECT_EQ(now[0].version_id, out.new_version_id);
    EXPECT_EQ(now[0].encryption_iv, rows[0].encryption_iv);
    EXPECT_FALSE(now[1].is_latest);

    // Cache vault: the row adopted the generation index-only and reads hydrate it.
    const auto local = db::query::fs::File::getFileByPath(f.vault->id, "/copy/doc.txt");
    EXPECT_EQ(local->encryption_iv, *rows[0].encryption_iv);
    EXPECT_EQ(local->size_bytes, 11u);
    EXPECT_FALSE(std::filesystem::exists(local->backing_path));
    EXPECT_EQ(readVia(f, "/copy/doc.txt"), "version one");

    // The next pass agrees with both sides: nothing to transfer.
    f.bucket->resetCounters();
    EXPECT_EQ(transfers(runPass(f)), 0u);
    EXPECT_EQ(f.bucket->counters().put, 0u);
    EXPECT_EQ(f.bucket->counters().copy, 0u);
}

TEST_F(RecoveryProviderTest, RestoreByTransferReSealsAVersionUnderARetiredKey) {
    auto f = versionedVault();
    const auto first = generations(f, "/rot/a.txt", {"sealed under the first key"});
    const auto oldKey = f.engine->encryptionManager->get_key_version();
    f.engine->encryptionManager->prepare_key_rotation();
    f.engine->encryptionManager->finish_key_rotation();
    const auto newKey = f.engine->encryptionManager->get_key_version();
    ASSERT_GT(newKey, oldKey);
    (void)generations(f, "/rot/a.txt", {"sealed under the second key"});
    const auto old = *rowFor(f, "/rot/a.txt", first[0].version_id);
    EXPECT_EQ(old.key_version, oldKey);

    const auto item = rp::planFor(f.engine, old);
    EXPECT_EQ(item.method, "provider_transfer");
    f.bucket->resetCounters();
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(out.method, "provider_transfer");
    EXPECT_EQ(f.bucket->counters().copy, 0u);
    EXPECT_EQ(f.bucket->counters().body_gets, 1u);

    const auto local = db::query::fs::File::getFileByPath(f.vault->id, "/rot/a.txt");
    EXPECT_EQ(local->encrypted_with_key_version, newKey);
    EXPECT_NE(local->encryption_iv, *old.encryption_iv);
    EXPECT_EQ(readVia(f, "/rot/a.txt"), "sealed under the first key");
    const auto current = f.bucket->current("rot/a.txt");
    EXPECT_EQ(current->meta.at("vh-key-version"), std::to_string(newKey));
    EXPECT_EQ(current->meta.at("vh-iv"), local->encryption_iv);
    EXPECT_EQ(history(f, "/rot/a.txt").front().encryption_iv, local->encryption_iv);
    EXPECT_EQ(restoreTemps(f, "/rot/a.txt"), 0u);

    f.bucket->resetCounters();
    EXPECT_EQ(transfers(runPass(f)), 0u);
    EXPECT_EQ(f.bucket->counters().put, 0u);
}

TEST_F(RecoveryProviderTest, AVersionTooLargeForOneCopyIsTransferred) {
    auto f = versionedVault();
    const auto rows = generations(f, "/big/v.bin", {"small body"});
    const auto src = *f.bucket->version("big/v.bin", rows[0].version_id);
    // The same sealed bytes, reported as 6 GiB (the fake holds no such body).
    f.bucket->seed("big/v.bin", src.body, src.meta, std::nullopt, 6ull * 1024 * 1024 * 1024);
    put(f, "/big/v.bin", "newest");
    (void)runPass(f);
    ASSERT_TRUE(rp::versions::refresh(f.engine, "big/").complete);
    const auto bigRow = history(f, "/big/v.bin")[1];
    ASSERT_EQ(bigRow.size_bytes, 6ull * 1024 * 1024 * 1024);
    const auto before = sourceIdOf(f, "/big/v.bin");

    const auto item = rp::planFor(f.engine, bigRow);
    EXPECT_EQ(item.method, "provider_transfer");
    f.bucket->resetCounters();
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions(true));
    // Never a CopyObject; the transfer GETs it and refuses the short body: nothing committed.
    EXPECT_EQ(f.bucket->counters().copy, 0u);
    EXPECT_EQ(f.bucket->counters().get, 1u);
    EXPECT_EQ(out.outcome, "failed");
    EXPECT_EQ(sourceIdOf(f, "/big/v.bin"), before);
    EXPECT_EQ(restoreTemps(f, "/big/v.bin"), 0u);
}

TEST_F(RecoveryProviderTest, RestoringTheCurrentVersionIsSkipped) {
    auto f = versionedVault();
    const auto rows = generations(f, "/cur/a.txt", {"one", "two"});
    f.bucket->resetCounters();
    const auto item = rp::planFor(f.engine, rows[1]);
    EXPECT_EQ(item.action, ItemAction::Skip);
    auto forced = item;
    forced.action = ItemAction::Overwrite;
    const auto out = rp::restore(f.engine, forced, item.destination_source_id, restoreOptions());
    EXPECT_EQ(out.outcome, "skipped");
    const auto c = f.bucket->counters();
    EXPECT_EQ(c.head + c.get + c.put + c.copy, 0u);
}

TEST_F(RecoveryProviderTest, AStaleDestinationIsAConflictAndNothingIsOverwritten) {
    auto f = versionedVault();
    const auto rows = generations(f, "/stale/a.txt", {"one", "two"});
    const auto item = rp::planFor(f.engine, rows[0]);
    put(f, "/stale/a.txt", "edited after the plan");
    f.bucket->resetCounters();
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
    EXPECT_EQ(out.outcome, "conflict");
    EXPECT_EQ(f.bucket->counters().copy, 0u);
    EXPECT_EQ(f.bucket->counters().head, 0u);
    EXPECT_EQ(readVia(f, "/stale/a.txt"), "edited after the plan");
    EXPECT_EQ(f.bucket->history("stale/a.txt").size(), 2u);

    // Planned now, the unsynced local edit is a conflict (it would be lost).
    EXPECT_EQ(rp::planFor(f.engine, rows[0]).action, ItemAction::Conflict);
}

TEST_F(RecoveryProviderTest, ABusyPassLeaseIsARetryableRefusal) {
    auto f = versionedVault();
    const auto rows = generations(f, "/lease/a.txt", {"one", "two"});
    const auto item = rp::planFor(f.engine, rows[0]);
    ASSERT_TRUE(leases().tryAcquirePass(f.vault->id));
    f.bucket->resetCounters();
    EXPECT_THROW((void)rp::restore(f.engine, item, item.destination_source_id, restoreOptions()), rp::PassBusy);
    EXPECT_EQ(f.bucket->counters().head, 0u);
    leases().releasePass(f.vault->id);
    EXPECT_EQ(rp::restore(f.engine, item, item.destination_source_id, restoreOptions()).outcome, "restored");
    EXPECT_FALSE(leases().passRunning(f.vault->id));
}

TEST_F(RecoveryProviderTest, BudgetExhaustionMidTransferCommitsNothingAndARetrySucceeds) {
    auto f = versionedVault();
    const std::string big(100 * 1024, 'x');
    const auto first = generations(f, "/budget/a.bin", {big});
    f.engine->encryptionManager->prepare_key_rotation();
    f.engine->encryptionManager->finish_key_rotation();
    (void)generations(f, "/budget/a.bin", {"replaced"});
    const auto item = rp::planFor(f.engine, *rowFor(f, "/budget/a.bin", first[0].version_id));
    ASSERT_EQ(item.method, "provider_transfer");
    const auto before = sourceIdOf(f, "/budget/a.bin");

    const auto policy = f.engine->remote_policy();
    const auto saved = policy->s3_request_budget;
    policy->s3_request_budget.max_downloaded_bytes = 20 * 1024;   // stops the body mid-stream
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
    policy->s3_request_budget = saved;
    EXPECT_EQ(out.outcome, "failed");
    EXPECT_TRUE(out.retryable);
    EXPECT_EQ(sourceIdOf(f, "/budget/a.bin"), before);
    EXPECT_EQ(readVia(f, "/budget/a.bin"), "replaced");
    EXPECT_EQ(restoreTemps(f, "/budget/a.bin"), 0u);
    EXPECT_EQ(f.bucket->history("budget/a.bin").size(), 2u);

    const auto retry = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
    ASSERT_EQ(retry.outcome, "restored") << retry.error.value_or("");
    EXPECT_EQ(readVia(f, "/budget/a.bin"), big);
}

TEST_F(RecoveryProviderTest, AFailedCopyIsRetriedOnceAndARepeatIsSkipped) {
    auto f = versionedVault();
    const auto rows = generations(f, "/retry/a.txt", {"one", "two"});
    const auto item = rp::planFor(f.engine, rows[0]);
    const auto before = sourceIdOf(f, "/retry/a.txt");
    f.bucket->failNext(VersionedBucket::Op::Copy, VersionedBucket::Failure::Http503);
    const auto failed = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
    EXPECT_EQ(failed.outcome, "failed");
    EXPECT_TRUE(failed.retryable);
    EXPECT_EQ(sourceIdOf(f, "/retry/a.txt"), before);
    EXPECT_EQ(f.bucket->history("retry/a.txt").size(), 2u);

    ASSERT_EQ(rp::restore(f.engine, item, item.destination_source_id, restoreOptions()).outcome, "restored");
    EXPECT_EQ(f.bucket->history("retry/a.txt").size(), 3u);
    // The same item again (a resumed plan): the destination already is that generation.
    f.bucket->resetCounters();
    EXPECT_EQ(rp::restore(f.engine, item, item.destination_source_id, restoreOptions()).outcome, "skipped");
    EXPECT_EQ(f.bucket->counters().copy, 0u);
    EXPECT_EQ(f.bucket->history("retry/a.txt").size(), 3u);
}

TEST_F(RecoveryProviderTest, ArchivedVersionsAreUnavailable) {
    auto f = versionedVault();
    const auto rows = generations(f, "/arch/a.txt", {"one"});
    const auto src = *f.bucket->version("arch/a.txt", rows[0].version_id);
    f.bucket->seed("arch/a.txt", src.body, src.meta, std::string("GLACIER"));
    put(f, "/arch/a.txt", "two");
    (void)runPass(f);
    ASSERT_TRUE(rp::versions::refresh(f.engine, "arch/").complete);
    const auto archived = history(f, "/arch/a.txt")[1];
    ASSERT_EQ(archived.storage_class, "GLACIER");

    const auto point = rp::points::byId(f.engine, static_cast<uint64_t>(archived.id));
    ASSERT_TRUE(point.has_value());
    EXPECT_FALSE(point->restorable);
    EXPECT_NE(point->unavailable_reason->find("archived"), std::string::npos);
    const auto item = rp::planFor(f.engine, archived);
    EXPECT_EQ(item.action, ItemAction::Unavailable);
    auto forced = item;
    forced.action = ItemAction::Overwrite;
    f.bucket->resetCounters();
    EXPECT_EQ(rp::restore(f.engine, forced, item.destination_source_id, restoreOptions(true)).outcome, "unavailable");
    EXPECT_EQ(f.bucket->counters().copy + f.bucket->counters().get, 0u);
}

TEST_F(RecoveryProviderTest, AVersionVaulthallaDidNotWriteNeedsAnAcceptance) {
    auto f = versionedVault();
    const auto rows = generations(f, "/foreign/a.txt", {"ours"});
    const auto src = *f.bucket->version("foreign/a.txt", rows[0].version_id);
    // Another tool wrote these bytes (here: a copy of ours with our metadata) — only a listing knows the version.
    const auto foreignId = f.bucket->seed("foreign/a.txt", src.body, src.meta);
    put(f, "/foreign/a.txt", "ours again");
    (void)runPass(f);
    ASSERT_TRUE(rp::versions::refresh(f.engine, "foreign/").complete);
    const auto observed = *rowFor(f, "/foreign/a.txt", foreignId);
    EXPECT_EQ(observed.origin, "observed");

    const auto item = rp::planFor(f.engine, observed);
    EXPECT_TRUE(std::ranges::any_of(item.notes, [](const auto& n) { return n.starts_with("unverified"); }));
    f.bucket->resetCounters();
    EXPECT_THROW((void)rp::restore(f.engine, item, item.destination_source_id, restoreOptions()), rp::UnverifiedVersion);
    EXPECT_EQ(f.bucket->counters().head, 0u);
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions(true));
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(readVia(f, "/foreign/a.txt"), "ours");
}

// Anyone who can write to the bucket can add a version without Vaulthalla's metadata. In a vault that encrypts
// upstream such a version is not this vault's content (the sync engine's rule): even an accepted unverified restore
// refuses it, unless the vault's event subscription imports foreign objects.
TEST_F(RecoveryProviderTest, APlaintextVersionInAnEncryptingVaultIsRefusedUnlessForeignObjectsAreImported) {
    using namespace test_support::upstream_events;
    auto f = versionedVault();
    const auto rows = generations(f, "/inject/a.txt", {"ours"});
    const auto bare = f.bucket->seed("inject/a.txt", std::string("injected without metadata"));
    const auto labelled = f.bucket->seed("inject/a.txt", std::string("injected, labelled plaintext"),
                                         {{"vh-encrypted", "false"}});
    // Our content is current again on top (same bytes, same ETag): the local file and the index stay in agreement.
    const auto src = *f.bucket->version("inject/a.txt", rows[0].version_id);
    (void)f.bucket->seed("inject/a.txt", src.body, src.meta);
    ASSERT_TRUE(rp::versions::refresh(f.engine, "inject/").complete);

    for (const auto& id : {bare, labelled}) {
        const auto observed = *rowFor(f, "/inject/a.txt", id);
        EXPECT_EQ(observed.origin, "observed");
        const auto item = rp::planFor(f.engine, observed);
        f.bucket->resetCounters();
        const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions(true));
        EXPECT_EQ(out.outcome, "unavailable") << id;
        EXPECT_NE(out.error.value_or("").find("plaintext"), std::string::npos) << out.error.value_or("");
        EXPECT_FALSE(out.provider_changed);
        EXPECT_EQ(f.bucket->counters().copy + f.bucket->counters().put + f.bucket->counters().body_gets, 0u);
        EXPECT_EQ(readVia(f, "/inject/a.txt"), "ours");
    }

    // The vault's active subscription imports foreign objects: then such a version is content (sealed on the way in).
    installFakeProvider();
    storage::upstream::guard::clearForTesting();
    sync::events::subscriptions::invalidateCache();
    const auto s3 = std::static_pointer_cast<vault::model::S3Vault>(f.vault);
    runtime::Deps::get().apiKeyManager->setAdmin(s3->api_key_id, true, providerState()->account, "{}", std::time(nullptr));
    const auto status = sync::events::subscriptions::enable(
        {.vault_id = f.vault->id, .prefix = "", .foreign_objects = "import", .baseline_required = false});
    ASSERT_EQ(status.state, "active");
    sync::events::subscriptions::invalidateCache();
    ASSERT_TRUE(sync::events::subscriptions::importsForeignObjects(f.vault->id));

    const auto observed = *rowFor(f, "/inject/a.txt", bare);
    const auto item = rp::planFor(f.engine, observed);
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions(true));
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(out.method, "provider_transfer");
    EXPECT_EQ(readVia(f, "/inject/a.txt"), "injected without metadata");
    const auto local = db::query::fs::File::getFileByPath(f.vault->id, "/inject/a.txt");
    EXPECT_FALSE(local->encryption_iv.empty()) << "sealed locally";
}

// A version Vaulthalla wrote is restored only while the provider's copy still matches the row recorded from our own
// write (IV, key version, size): anything else is unavailable, never restored silently.
TEST_F(RecoveryProviderTest, AVersionThatDiffersFromWhatVaulthallaWroteIsUnavailable) {
    auto f = versionedVault();
    const auto rows = generations(f, "/own/a.txt", {"version one", "version two"});
    ASSERT_EQ(rows[0].origin, "vaulthalla");
    const auto setColumn = [&](const std::string& assignment) {
        db::Transactions::exec("RecoveryProviderTest::tamper", [&](pqxx::work& txn) {
            txn.exec("UPDATE upstream_object_version SET " + assignment + " WHERE id = $1", pqxx::params{rows[0].id});
        });
    };
    // Planned while the row is intact; the restore re-reads it.
    const auto item = rp::planFor(f.engine, *rowFor(f, "/own/a.txt", rows[0].version_id));
    ASSERT_EQ(item.method, "provider_copy");
    const auto attempt = [&](const std::string& what) {
        f.bucket->resetCounters();
        const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
        EXPECT_EQ(out.outcome, "unavailable") << what;
        EXPECT_NE(out.error.value_or("").find("differs from what Vaulthalla wrote"), std::string::npos)
            << what << ": " << out.error.value_or("");
        EXPECT_EQ(f.bucket->counters().copy + f.bucket->counters().put + f.bucket->counters().body_gets, 0u) << what;
        EXPECT_EQ(readVia(f, "/own/a.txt"), "version two") << what;
    };

    setColumn("encryption_iv = 'AAAAAAAAAAAAAAAA'");
    attempt("another IV");
    setColumn("encryption_iv = " + db::Transactions::exec("RecoveryProviderTest::quote", [&](pqxx::work& txn) {
                  return txn.quote(*rows[0].encryption_iv);
              }));
    setColumn("key_version = key_version + 7");
    attempt("another key version");
    setColumn("key_version = key_version - 7");
    setColumn("size_bytes = size_bytes + 1");
    attempt("another size");
    setColumn("size_bytes = size_bytes - 1");

    // As recorded: restored.
    const auto out = restoreVersion(f, *rowFor(f, "/own/a.txt", rows[0].version_id));
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(readVia(f, "/own/a.txt"), "version one");
}

TEST_F(RecoveryProviderTest, RestoreWorksAfterTheEnginesAreRebuilt) {
    auto f = versionedVault();
    const auto rows = generations(f, "/restart/a.txt", {"one", "two", "three"});
    runtime::Deps::get().storageManager->reloadEngine(f.vault->id);
    attach(f);
    const auto out = restoreVersion(f, *rowFor(f, "/restart/a.txt", rows[1].version_id));
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(readVia(f, "/restart/a.txt"), "two");
    runtime::Deps::get().storageManager->reloadEngine(f.vault->id);
    attach(f);
    ASSERT_EQ(restoreVersion(f, *rowFor(f, "/restart/a.txt", rows[0].version_id)).outcome, "restored");
    EXPECT_EQ(readVia(f, "/restart/a.txt"), "one");
    EXPECT_EQ(transfers(runPass(f)), 0u);
}

TEST_F(RecoveryProviderTest, SyncStrategyHydratesTheRestoredGenerationAtOnce) {
    auto f = versionedVault(Strategy::Sync);
    const auto rows = generations(f, "/sync/a.txt", {"first", "second"});
    const auto out = restoreVersion(f, rows[0]);
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(out.method, "provider_copy");
    EXPECT_TRUE(std::filesystem::exists(backingOf(f, "/sync/a.txt")));
    f.bucket->resetCounters();
    EXPECT_EQ(readVia(f, "/sync/a.txt"), "first");
    EXPECT_EQ(f.bucket->counters().body_gets, 0u);   // already local
    EXPECT_EQ(transfers(runPass(f)), 0u);
}

TEST_F(RecoveryProviderTest, PlaintextUpstreamVersionsAreCopiedAndSealedOnRead) {
    auto f = versionedVault(Strategy::Cache, false);
    const auto rows = generations(f, "/clear/a.txt", {"plain one", "plain two"});
    EXPECT_EQ(rows[0].encrypted, false);
    const auto out = restoreVersion(f, rows[0]);
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(out.method, "provider_copy");
    EXPECT_EQ(readVia(f, "/clear/a.txt"), "plain one");
    EXPECT_EQ(transfers(runPass(f)), 0u);
}

TEST_F(RecoveryProviderTest, ADeletedFileIsRestoredFromTheVersionItsDeleteMarkerHid) {
    auto f = versionedVault();
    const auto rows = generations(f, "/gone/a.txt", {"keep me", "keep me too"});
    f.engine->purge(std::filesystem::path("/gone/a.txt"));   // local + remote delete: a delete marker upstream
    EXPECT_FALSE(f.bucket->current("gone/a.txt").has_value());
    // Our own delete already took the latest version off "current", before any listing.
    EXPECT_TRUE(std::ranges::none_of(history(f, "/gone/a.txt"), [](const auto& r) { return r.is_latest; }));
    ASSERT_TRUE(rp::versions::refresh(f.engine, "gone/").complete);
    const auto listed = history(f, "/gone/a.txt");
    ASSERT_EQ(listed.size(), 3u);
    EXPECT_TRUE(listed[0].is_delete_marker);
    EXPECT_TRUE(listed[0].is_latest);

    const auto item = rp::planFor(f.engine, *rowFor(f, "/gone/a.txt", rows[1].version_id));
    EXPECT_EQ(item.action, ItemAction::Create);
    EXPECT_EQ(item.method, "provider_copy");
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(readVia(f, "/gone/a.txt"), "keep me too");
    EXPECT_EQ(f.bucket->history("gone/a.txt").size(), 4u);
    EXPECT_EQ(transfers(runPass(f)), 0u);
}

TEST_F(RecoveryProviderTest, ARestoreToAnotherPathCreatesTheFile) {
    auto f = versionedVault();
    const auto rows = generations(f, "/orig/a.txt", {"one", "two"});
    const auto item = rp::planFor(f.engine, rows[0], std::filesystem::path("/elsewhere/deep/a.txt"));
    EXPECT_EQ(item.action, ItemAction::Create);
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    EXPECT_EQ(readVia(f, "/elsewhere/deep/a.txt"), "one");
    EXPECT_EQ(readVia(f, "/orig/a.txt"), "two");
    EXPECT_EQ(transfers(runPass(f)), 0u);
}

TEST_F(RecoveryProviderTest, TheCopysNotificationSettlesAsOurOwnWrite) {
    using namespace test_support::upstream_events;
    installFakeProvider();
    storage::upstream::guard::clearForTesting();
    sync::events::subscriptions::invalidateCache();
    auto f = versionedVault();
    const auto s3 = std::static_pointer_cast<vault::model::S3Vault>(f.vault);
    runtime::Deps::get().apiKeyManager->setAdmin(s3->api_key_id, true, providerState()->account, "{}", std::time(nullptr));
    const auto status = sync::events::subscriptions::enable(
        {.vault_id = f.vault->id, .prefix = "", .foreign_objects = "ignore", .baseline_required = false});
    ASSERT_EQ(status.state, "active");
    sync::events::subscriptions::invalidateCache();

    const auto rows = generations(f, "/ev/a.txt", {"one", "two"});
    const auto out = restoreVersion(f, rows[0]);
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    const auto size = f.bucket->current("ev/a.txt")->size();
    const auto unquotedEtag = out.new_etag->substr(1, out.new_etag->size() - 2);
    // The copy's write intent carries the stored object's ETag (and size), so only this object's event matches it.
    const auto intents = db::Transactions::exec("RecoveryProviderTest::intents", [&](pqxx::work& txn) {
        return txn.exec("SELECT COUNT(*) FROM upstream_write_intent WHERE vault_id = $1 AND object_key = 'ev/a.txt' "
                        "AND op = 'put' AND etag = $2 AND expected_size = $3",
                        pqxx::params{f.vault->id, unquotedEtag, static_cast<int64_t>(size)})
            .one_field_ref().as<int64_t>();
    });
    EXPECT_GE(intents, 1);

    // S3 tells us about the CopyObject: it is ours (the intent carries the object's ETag and size).
    auto decoded = sync::events::decodeAwsMessage(
        awsBody(s3->bucket, "ObjectCreated:Copy", "ev/a.txt", "00000000000000FF", size,
                unquotedEtag, nowIso()),
        "copy-msg");
    ASSERT_TRUE(decoded.error.empty()) << decoded.error;
    for (auto& e : decoded.events) e.version_id = out.new_version_id;
    (void)sync::events::ingest(decoded.events, std::nullopt, f.vault->id, s3->bucket);
    sync::events::Applier applier({
        .tryAcquirePass = [](const uint32_t v) { return leases().tryAcquirePass(v); },
        .releasePass = [](const uint32_t v) { leases().releasePass(v); },
        .runScoped = [](uint32_t, std::shared_ptr<sync::model::PassScope>) { return sync::Controller::ScopedResult::Started; },
    });
    const auto applied = applier.applyVault(f.vault->id);
    EXPECT_EQ(applied.self, 1u);
    EXPECT_EQ(applied.applied, 0u);
    const auto indexed = db::query::sync::RemoteObjectIndex::getFile(f.vault->id, "/ev/a.txt");
    ASSERT_NE(indexed, nullptr);
    EXPECT_EQ(indexed->remote_version_id, out.new_version_id);
    EXPECT_EQ(indexed->encryption_iv, *rows[0].encryption_iv);
}

}
