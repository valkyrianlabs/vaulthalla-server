// File recovery, release-blocking acceptance scenario (.claude/context/recovery.md, "Smart cache" and "Provider
// versioning"): a `cache` strategy S3 vault that encrypts upstream, on a bucket with versioning enabled (the
// VersionedBucket fake behind the real s3::Controller metering). History lives in the provider only; Vaulthalla
// indexes it, restores a chosen generation without a second upload and keeps no local duplicate. DB-backed.

#include "../helpers/recovery_provider_harness.hpp"
#include "sync/model/RemoteManifest.hpp"

#include <gtest/gtest.h>

#include <numeric>
#include <set>

namespace vh::test_recovery_smart_cache {

using namespace test_support::recovery_provider;
namespace rp = recovery::provider;

class RecoverySmartCacheTest : public ProviderHarness {
protected:
    static uint64_t recoveryBlobRows(const uint32_t vaultId) {
        return db::Transactions::exec("RecoverySmartCacheTest::blobs", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM recovery_blob WHERE vault_id = $1", pqxx::params{vaultId})
                .one_field_ref().as<uint64_t>();
        });
    }

    static std::vector<std::filesystem::path> regularFilesUnder(const std::filesystem::path& dir) {
        std::vector<std::filesystem::path> out;
        std::error_code ec;
        for (auto it = std::filesystem::recursive_directory_iterator(dir, ec);
             !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
            if (it->is_regular_file()) out.push_back(it->path());
        return out;
    }
};

TEST_F(RecoverySmartCacheTest, HistoryStaysUpstreamAndARestoreIsOneCopyWithNoSecondUpload) {
    auto f = versionedVault(Strategy::Cache, true, Versioning::Enabled);
    const std::string path = "/smart/report.txt";
    const std::string key = "smart/report.txt";
    const std::vector<std::string> contents = {"generation zero: the draft", "generation one: the reviewed text",
                                               "generation two: an accidental overwrite", "generation three: worse"};

    // 1. Upload a file (sync pass) and 2. replace it several times, each followed by a pass.
    std::vector<std::string> ivs;
    for (const auto& c : contents) {
        put(f, path, c);
        const auto plan = runPass(f);
        ASSERT_EQ(transfers(plan), 1u) << c;
        ivs.push_back(db::query::fs::File::getFileByPath(f.vault->id, path)->encryption_iv);
    }
    ASSERT_EQ(f.bucket->history(key).size(), contents.size());
    auto rows = history(f, path);
    ASSERT_EQ(rows.size(), contents.size());
    std::ranges::reverse(rows);   // oldest first
    for (size_t i = 0; i < rows.size(); ++i) {
        EXPECT_EQ(rows[i].origin, "vaulthalla");
        EXPECT_EQ(rows[i].encryption_iv, ivs[i]) << "generation " << i << " indexed with its own IV";
        EXPECT_EQ(f.bucket->version(key, rows[i].version_id)->meta.at("vh-iv"), ivs[i]);
        EXPECT_EQ(rows[i].is_latest, i + 1 == rows.size());
    }
    EXPECT_EQ(std::set<std::string>(ivs.begin(), ivs.end()).size(), ivs.size());

    // 3. Evict the local cached content: the row is index-only.
    evict(f, path);
    const auto backing = backingOf(f, path);
    ASSERT_FALSE(std::filesystem::exists(backing));

    // 4. Enumerate the historical versions without downloading a single body.
    f.bucket->resetCounters();
    const auto listed = rp::versions::refresh(f.engine, rp::versions::objectKeyOf(path));
    EXPECT_TRUE(listed.complete);
    EXPECT_EQ(listed.versions, contents.size());
    const auto points = rp::points::forPath(f.engine, path, false);
    ASSERT_EQ(points.size(), contents.size());
    EXPECT_TRUE(points.front().is_current);
    for (size_t i = 1; i < points.size(); ++i) EXPECT_TRUE(points[i].restorable) << points[i].id;
    {
        const auto c = f.bucket->counters();
        EXPECT_EQ(c.body_gets, 0u);
        EXPECT_EQ(c.get, 0u);
        EXPECT_EQ(c.head, 0u);
        EXPECT_EQ(c.put + c.copy + c.del, 0u);
    }

    // 5. Restore a selected historical generation (generation one).
    const auto& chosen = rows[1];
    const auto item = rp::planFor(f.engine, chosen);
    ASSERT_EQ(item.action, recovery::ItemAction::Overwrite);
    ASSERT_EQ(item.method, "provider_copy");
    const auto manifestBefore = manifestVersions(f);
    f.bucket->resetCounters();
    const auto out = rp::restore(f.engine, item, item.destination_source_id, restoreOptions());
    ASSERT_EQ(out.outcome, "restored") << out.error.value_or("");
    const auto restoreCounters = f.bucket->counters();
    EXPECT_EQ(restoreCounters.copy, 1u);
    EXPECT_EQ(restoreCounters.body_gets, 0u);
    // The only PUTs were Vaulthalla's index manifest (no object upload).
    EXPECT_EQ(restoreCounters.put, manifestVersions(f) - manifestBefore);
    EXPECT_FALSE(std::filesystem::exists(backing)) << "a cache vault adopts the generation index-only";

    // 6. The restored current file decrypts through the normal read path (hydrate) and is that generation.
    EXPECT_EQ(readVia(f, path), contents[1]);
    EXPECT_EQ(f.bucket->counters().body_gets, 1u);

    // 7. Upstream history is all still there, plus one new version.
    const auto after = f.bucket->history(key);
    ASSERT_EQ(after.size(), contents.size() + 1);
    for (const auto& r : rows) EXPECT_TRUE(f.bucket->version(key, r.version_id).has_value()) << r.version_id;
    EXPECT_EQ(after.front().meta.at("vh-iv"), ivs[1]);
    const auto indexed = history(f, path);
    ASSERT_EQ(indexed.size(), contents.size() + 1);
    EXPECT_TRUE(indexed.front().is_latest);
    EXPECT_EQ(indexed.front().version_id, out.new_version_id);
    EXPECT_EQ(std::ranges::count_if(indexed, [](const auto& r) { return r.is_latest; }), 1);

    // 8. No duplicate upload: the next full sync pass transfers nothing and PUTs nothing...
    f.bucket->resetCounters();
    const auto next = runPass(f);
    EXPECT_EQ(transfers(next), 0u);
    EXPECT_EQ(f.bucket->counters().put, 0u);
    EXPECT_EQ(f.bucket->counters().copy, 0u);
    EXPECT_EQ(f.bucket->history(key).size(), contents.size() + 1);
    // ...and no retained local historical copy: no recovery blobs, only the hydrated current copy on disk.
    EXPECT_EQ(recoveryBlobRows(f.vault->id), 0u);
    const auto files = regularFilesUnder(backing.parent_path());
    EXPECT_EQ(files.size(), 1u);
    if (!files.empty()) {
        EXPECT_EQ(files.front(), backing);
    }

    // 9. Cost inputs see the extra historical objects: every superseded version and its bytes.
    const auto summary = db::query::recovery::ObjectVersion::noncurrentSummary(f.vault->id);
    EXPECT_EQ(summary.versions, contents.size());
    const uint64_t expectedBytes = std::accumulate(contents.begin(), contents.end(), uint64_t{0},
                                                   [](const uint64_t acc, const std::string& c) { return acc + c.size() + 16; });
    EXPECT_EQ(summary.bytes, expectedBytes);
    EXPECT_EQ(summary.unknown_size, 0u);
    EXPECT_EQ(summary.delete_markers, 0u);
    EXPECT_TRUE(summary.oldest_noncurrent_at.has_value());
}


// ---- the index manifest (#248) -------------------------------------------------------------------------------------

namespace manifest = sync::model::remote_manifest;

std::vector<std::string> manifestKeys(const VersionedBucket& bucket, const uint32_t vaultId) {
    const auto current = bucket.current(manifest::INDEX_V1_KEY);
    if (!current) return {};
    std::vector<std::string> keys;
    for (const auto& file : manifest::parseIndexV1(std::string(current->body.begin(), current->body.end()), vaultId))
        keys.push_back(file->path.string());
    std::ranges::sort(keys);
    return keys;
}

// A vault's first pass (no manifest yet: full LIST, then uploads) used to PUT the manifest twice: right after the
// LIST and again after the uploads (PUT 3 = object + 2 manifests). Now the pass publishes once, with its changes.
TEST_F(RecoverySmartCacheTest, AVaultsFirstPassPublishesTheIndexManifestOnce) {
    auto f = versionedVault(Strategy::Cache, false, Versioning::Enabled);
    f.bucket->seed("already/there.txt", std::string("foreign object"));
    put(f, "/first/report.txt", "the first file of a new vault");
    f.bucket->resetCounters();

    const auto plan = runPass(f);
    ASSERT_EQ(transfers(plan), 1u);
    EXPECT_EQ(manifestVersions(f), 1u) << "one manifest publish per pass";
    const auto c = f.bucket->counters();
    EXPECT_EQ(c.put, 2u) << "the object and one manifest";
    EXPECT_EQ(c.list, 1u);
    EXPECT_FALSE(f.engine->remoteIndexPublishPending());
    // The one manifest carries both the LIST and the pass's upload, and its ETag is the one Vaulthalla recorded (the
    // next pass must not reload it).
    EXPECT_EQ(manifestKeys(*f.bucket, f.vault->id),
              (std::vector<std::string>{"/already/there.txt", "/first/report.txt"}));
    EXPECT_EQ(db::query::sync::RemoteObjectIndex::getManifestETag(f.vault->id, manifest::INDEX_V1_KEY),
              std::optional<std::string>(f.bucket->current(manifest::INDEX_V1_KEY)->etag));

    // Nothing changed: the next pass reads the manifest's HEAD and publishes nothing.
    f.bucket->resetCounters();
    const auto next = runPass(f);
    EXPECT_EQ(transfers(next), 0u);
    EXPECT_EQ(manifestVersions(f), 1u);
    EXPECT_EQ(f.bucket->counters().put, 0u);
    EXPECT_EQ(f.bucket->counters().list, 0u);
}

// A first pass that changes nothing still publishes the listed index (once), and one that stops before publishing
// (failed operations, an error after the LIST) publishes it on the way out, never twice.
TEST_F(RecoverySmartCacheTest, AListedIndexIsPublishedOnceEvenWhenThePassStopsEarly) {
    {
        auto f = versionedVault(Strategy::Cache, false, Versioning::Enabled);
        f.bucket->seed("listed/only.txt", std::string("foreign object"));
        f.bucket->resetCounters();
        (void)runPass(f);
        EXPECT_EQ(manifestVersions(f), 1u);
        EXPECT_EQ(f.bucket->counters().put, 1u);
        EXPECT_EQ(manifestKeys(*f.bucket, f.vault->id), (std::vector<std::string>{"/listed/only.txt"}));
    }
    {
        auto f = versionedVault(Strategy::Cache, false, Versioning::Enabled);
        f.bucket->seed("listed/only.txt", std::string("foreign object"));
        auto cloud = std::make_shared<sync::Cloud>(f.engine);
        cloud->event = std::make_shared<sync::model::Event>();
        cloud->event->vault_id = f.vault->id;
        cloud->event->timestamp_begin = std::time(nullptr);
        db::query::sync::Event::create(cloud->event);
        cloud->initBins();
        EXPECT_EQ(manifestVersions(f), 0u) << "the LIST no longer publishes on its own";
        EXPECT_TRUE(f.engine->remoteIndexPublishPending());
        // Cloud::operator() after a pass that never reached applyRemoteIndexMutation:
        f.engine->publishPendingRemoteIndexManifest();
        EXPECT_EQ(manifestVersions(f), 1u);
        EXPECT_FALSE(f.engine->remoteIndexPublishPending());
        f.engine->publishPendingRemoteIndexManifest();
        EXPECT_EQ(manifestVersions(f), 1u) << "nothing pending: no second publish";
        cloud->clearBins();
    }
}

// Invariant (upstream-control-plane.md): a stale manifest resurrects deleted objects. When another writer's manifest
// appears between the LIST and the pass's publish, the listed index wins (ETag refreshed, overwritten), as the
// post-LIST publish did; it is never reloaded from that manifest.
TEST_F(RecoverySmartCacheTest, AManifestWrittenAfterTheListNeverReplacesTheListedIndex) {
    auto f = versionedVault(Strategy::Cache, false, Versioning::Enabled);
    f.bucket->seed("live/a.txt", std::string("still here"));
    auto cloud = std::make_shared<sync::Cloud>(f.engine);
    cloud->event = std::make_shared<sync::model::Event>();
    cloud->event->vault_id = f.vault->id;
    cloud->event->timestamp_begin = std::time(nullptr);
    db::query::sync::Event::create(cloud->event);
    cloud->initBins();

    auto ghost = std::make_shared<fs::model::File>(std::string("ghost/deleted.txt"), 5, std::time(nullptr));
    ghost->remote_etag = "\"ghost\"";
    const auto stale = manifest::buildIndexV1(f.vault->id, {ghost});
    (void)f.bucket->seed(manifest::INDEX_V1_KEY, std::vector<uint8_t>(stale.begin(), stale.end()));

    f.engine->applyRemoteIndexMutation(cloud->planPass());
    cloud->clearBins();
    EXPECT_EQ(manifestKeys(*f.bucket, f.vault->id), (std::vector<std::string>{"/live/a.txt"}));
    EXPECT_FALSE(db::query::sync::RemoteObjectIndex::getFile(f.vault->id, "/ghost/deleted.txt"));
    EXPECT_TRUE(db::query::sync::RemoteObjectIndex::getFile(f.vault->id, "/live/a.txt"));
    EXPECT_EQ(manifestVersions(f), 2u) << "the stale one + ours";
}

}
