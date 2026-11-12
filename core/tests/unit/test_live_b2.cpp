// Live Backblaze B2 tests (design/encryption/06-publish-without-preconditions.md §8.3) and the self-tests of the B2
// guard (tests/helpers/live_bucket.hpp; testing.md "Live provider tests").
//
//  - LiveB2Guard.*: no credentials, no DB, always run (CI too): GuardedB2 refuses every bucket that isn't a vh-test-*
//    test bucket before any request, and the endpoint's region is read from b2_authorize_account's s3ApiUrl.
//  - LiveB2.*: opt-in (VH_LIVE_TESTS=1 + VH_B2_TEST_KEY_ID, VH_B2_TEST_APP_KEY). One bucket per run, created through
//    B2's native API on the first live test and emptied of every version and deleted after the last, also when tests
//    fail. One consolidated test: the version_log manifest against the real S3 adapter.
//
// Run: (eval "$(grep -E '^export VH_B2_TEST_' <repo>/.bashrc)"; VH_LIVE_TESTS=1 build/core/vh_unit_tests --gtest_filter='LiveB2*')

#include "../helpers/hooked_store.hpp"
#include "../helpers/live_bucket.hpp"

#include "crypto/SecretKey.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "storage/s3/Capability.hpp"
#include "sync/manifest/Content.hpp"
#include "sync/manifest/Document.hpp"
#include "sync/manifest/Objects.hpp"
#include "sync/manifest/Publisher.hpp"
#include "sync/manifest/Reader.hpp"
#include "sync/manifest/Store.hpp"

#include <sodium.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <set>

namespace vh::test_live_b2 {

namespace live = test_support::live;
namespace mf = sync::manifest;
namespace http = storage::s3::curl::http;
using storage::s3::WriteCapability;

[[maybe_unused]] const auto* const kRunB2BucketEnvironment =
    ::testing::AddGlobalTestEnvironment(new live::RunB2BucketEnvironment);

// ---- the guard (no provider involved) ---------------------------------------------------------------------------------

class LiveB2Guard : public ::testing::Test {
protected:
    void SetUp() override { (void)live::takeViolations(); }
    void TearDown() override { (void)live::takeViolations(); }
};

TEST_F(LiveB2Guard, RefusesEveryBucketThatIsNotATestBucketBeforeAnyRequest) {
    std::vector<std::string> sent;
    live::GuardedB2 b2(live::B2Account{.account_id = "acct", .api_url = "https://api000.backblazeb2.com",
                                       .token = "token", .s3_url = "https://s3.us-west-004.backblazeb2.com",
                                       .region = "us-west-004"},
                       [&](const http::Request& r) {
                           sent.push_back(r.url);
                           http::Response out;
                           out.status = 200;
                           out.body = R"({"buckets":[],"files":[]})";
                           return out;
                       });
    for (const auto* b : {"vaulthalla", "vaulthalla-database-backups", "portfolio", "vh-test", "vh-test-foo",
                          "vh-test-host-1-1700000000x", "VH-TEST-host-1-1700000000"}) {
        EXPECT_THROW(b2.createBucket(b), live::GuardViolation) << b;
        EXPECT_THROW(b2.removeBucket(b), live::GuardViolation) << b;
        EXPECT_THROW((void)b2.bucketId(b), live::GuardViolation) << b;
        EXPECT_THROW((void)b2.versionsUnder(b, ""), live::GuardViolation) << b;
        EXPECT_THROW(b2.deleteVersion(b, {"k", "id", "upload"}), live::GuardViolation) << b;
        EXPECT_THROW((void)live::emptyB2Under(b2, b, ""), live::GuardViolation) << b;
        EXPECT_THROW(live::emptyAndDeleteB2Bucket(b2, b), live::GuardViolation) << b;
    }
    EXPECT_TRUE(sent.empty()) << "a refused call reached B2: " << sent.front();
    EXPECT_EQ(live::takeViolations().size(), 7u * 7u);

    // A run bucket goes through; the account listing is a read.
    b2.createBucket(live::runBucketName());
    (void)b2.listBucketNames();
    EXPECT_EQ(sent.size(), 2u);
    EXPECT_TRUE(live::takeViolations().empty());
}

TEST_F(LiveB2Guard, TheS3RegionComesFromTheAuthorizedEndpoint) {
    EXPECT_EQ(live::b2RegionOf("https://s3.us-west-004.backblazeb2.com"), "us-west-004");
    EXPECT_EQ(live::b2RegionOf("https://s3.eu-central-003.backblazeb2.com/"), "eu-central-003");
    EXPECT_THROW((void)live::b2RegionOf("https://s3.amazonaws.com"), std::runtime_error);
    EXPECT_THROW((void)live::b2RegionOf("http://s3.us-west-004.backblazeb2.com"), std::runtime_error);
}

// ---- live (opt-in) ----------------------------------------------------------------------------------------------------

class LiveB2 : public live::LiveB2Test {};

mf::Entry fileEntry(const std::string& uid, const std::string& parent, std::string name, const uint64_t size) {
    mf::Entry e;
    e.uid = uid;
    e.kind = mf::EntryKind::File;
    e.parent = parent;
    e.name = std::move(name);
    e.mode = 0644;
    e.mtime = "2026-11-12T12:00:00Z";
    e.size = size;
    e.format = 1;
    e.key_version = 1;
    e.object = mf::ObjectRef{"\"etag-" + e.uid.substr(0, 6) + "\"", size + 136, std::nullopt, std::nullopt};
    return e;
}

// The version_log manifest on Backblaze B2 through the production S3 adapter: the probe says version_log; publishes
// settle on the root's versions; a reader with nothing but the bucket finds the head; a losing sibling that lands
// after our PUT is repaired; GC deletes every version of a collected segment; a recovery envelope is written plainly
// and read back. Everything under .vaulthalla/ is deleted again (and the bucket with it, after the run).
TEST_F(LiveB2, TheManifestPublishesAsVersionsOfItsRoot) {
    ASSERT_GE(sodium_init(), 0);
    auto& b2 = this->b2();
    struct Cleanup {
        std::function<void()> fn;
        ~Cleanup() {
            try {
                fn();
            } catch (const std::exception& e) {
                ADD_FAILURE() << "[live] cleanup of .vaulthalla/: " << e.what();
            }
        }
    } cleanup{[&] {
        const auto removed = live::emptyB2Under(b2, bucket(), ".vaulthalla/");
        std::cout << "[live] removed " << removed << " version(s) under .vaulthalla/" << std::endl;
        EXPECT_TRUE(b2.versionsUnder(bucket(), ".vaulthalla/").empty());
    }};

    // (1) The probe: conditional PUTs rejected, versions kept, GET If-Match honoured.
    const auto probe = storage::s3::probeBucket(controller());
    EXPECT_EQ(probe.capability, WriteCapability::VersionLog) << probe.reason;
    EXPECT_EQ(probe.conditional_put, "rejected");
    EXPECT_TRUE(probe.versioning);
    EXPECT_TRUE(probe.get_if_match);
    EXPECT_EQ(probe.leftover_versions, 0u);
    std::cout << "[live] probe: " << storage::s3::to_string(probe.capability) << ", MD5 ETags " << probe.md5_etags
              << std::endl;

    // (2) The manifest through the real S3Store.
    const auto s3 = std::make_shared<mf::S3Store>(sharedController(), WriteCapability::VersionLog);
    const auto store = std::make_shared<test_support::manifest_store::HookedStore>(s3);
    std::vector<uint8_t> keyBytes(32);
    randombytes_buf(keyBytes.data(), keyBytes.size());
    const auto key = std::make_shared<const crypto::SecretKey>(keyBytes);
    const auto vault = crypto::id::newObjectUid();
    const auto lookup = [key](const uint32_t v) -> crypto::SecretKeyPtr { return v == 1 ? key : nullptr; };
    const mf::SealingKey sealing{1, key};
    const auto rootUid = mf::uidText(crypto::id::newObjectUid());
    mf::Content content;
    content.producer = {"live-b2-node", 1, "vaulthalla live test"};
    content.recovery_policy = mf::RecoveryPolicy{};
    content.keys = {mf::KeyRecord{1, std::nullopt, std::nullopt, "2026-11-12T00:00:00Z", std::nullopt, std::nullopt,
                                  std::nullopt}};
    mf::Entry root;
    root.uid = rootUid;
    root.kind = mf::EntryKind::Dir;
    root.name = "";
    root.mode = 0755;
    root.mtime = "2026-11-12T12:00:00Z";
    content.entries.push_back(root);
    for (int i = 0; i < 3; ++i)
        content.entries.push_back(fileEntry(mf::uidText(crypto::id::newObjectUid()), rootUid, "file-" + std::to_string(i),
                                            100 + i));
    mf::normalize(content);

    mf::PublisherCache cache;
    std::optional<mf::Known> known;
    std::optional<uint64_t> ownEpoch;
    std::optional<mf::SettledWindow> settled;
    std::vector<std::vector<std::string>> sids;
    const auto publish = [&](const mf::Content& c) {
        mf::PublishOptions o;
        o.now = mf::isoTime(std::time(nullptr));
        o.self_node = "live-b2-node";
        o.own_epoch = ownEpoch;
        o.settled = settled;
        auto r = mf::publish(*store, vault, lookup, sealing, c, known, cache, o);
        known = r.published.known;
        ownEpoch = r.published.known.epoch;
        if (r.settled.version_id && r.settled.base_version_id)
            settled = mf::SettledWindow{*r.settled.base_version_id, *r.settled.version_id, r.settled.window};
        sids.push_back(r.published.sids());
        return r;
    };
    for (uint64_t epoch = 1; epoch <= 4; ++epoch) {
        content.entries.back().size = 1000 + epoch;
        controller().resetRequestMetrics();
        const auto r = publish(content);
        const auto m = controller().requestMetrics();
        EXPECT_EQ(r.published.known.epoch, epoch);
        ASSERT_TRUE(r.settled.version_id);
        EXPECT_EQ(r.lost, 0u);
        EXPECT_TRUE(r.settled.window.empty()) << "nothing between the base and ours";
        const auto listed = s3->versions(std::string(mf::kRootKey));
        ASSERT_FALSE(listed.empty());
        EXPECT_EQ(listed.front().version_id, *r.settled.version_id) << "ours is the newest version";
        std::cout << "[live] publish " << epoch << ": " << m.put_requests << " PUT, " << m.list_requests << " LIST, "
                  << m.get_requests << " GET, " << m.head_requests << " HEAD, " << m.delete_requests << " DELETE"
                  << std::endl;
        if (epoch > 1) {
            EXPECT_EQ(m.put_requests, 2u) << "the changed segment and the root";
            EXPECT_EQ(m.list_requests, 1u) << "the listing that settles the root";
            EXPECT_EQ(m.get_requests + m.delete_requests, 0u);
        }
    }

    // (3) A reader with nothing but the bucket finds the head.
    {
        mf::RootCache fresh;
        mf::LoadOptions o;
        o.root_cache = &fresh;
        const auto loaded = mf::load(*s3, vault, lookup, o);
        EXPECT_EQ(loaded.known(), *known);
        EXPECT_EQ(loaded.content.entries.size(), content.entries.size());
        EXPECT_TRUE(loaded.strays.empty());
    }

    // (4) A losing sibling of the head lands right after our next root PUT: above the new head, repaired by id.
    std::string siblingId;
    {
        auto sibling = cache.base->root;   // epoch 4 again (same prev): a sibling of the canonical epoch 4
        sibling.published_at = "2031-01-01T00:00:00Z";
        sibling.producer.node_id = "a-crashed-writer";
        const auto bytes = mf::sealRoot(sibling, vault, sealing);
        store->after = [&](const test_support::manifest_store::StoreOp op, const std::string& k, const std::string&,
                           const bool failed) {
            if (op != test_support::manifest_store::StoreOp::Put || k != mf::kRootKey || failed || !siblingId.empty()) return;
            siblingId = s3->put(std::string(mf::kRootKey), bytes).version_id.value_or("");
        };
        content.entries.back().size = 2000;
        const auto r = publish(content);
        store->after = {};
        ASSERT_FALSE(siblingId.empty()) << "B2 returned no version id for the sibling";
        EXPECT_EQ(r.published.known.epoch, 5u);
        EXPECT_EQ(r.repaired, std::vector<std::string>{siblingId});
        const auto listed = s3->versions(std::string(mf::kRootKey));
        EXPECT_TRUE(std::ranges::none_of(listed, [&](const auto& v) { return v.version_id == siblingId; }))
            << "the sibling's version is gone";
        EXPECT_EQ(listed.front().version_id, *r.settled.version_id) << "the head is the current version again";
    }

    // (5) GC: a segment no longer referenced by the last three roots goes with every version (B2 DELETE by name only
    // hides). Give the oldest one a second version first.
    {
        std::set<std::string> retained;
        for (std::size_t i = sids.size() - 3; i < sids.size(); ++i) retained.insert(sids[i].begin(), sids[i].end());
        std::string collected;
        for (const auto& sid : sids.front())
            if (!retained.contains(sid)) collected = sid;
        ASSERT_FALSE(collected.empty());
        const auto segKey = mf::segmentKey(collected);
        const auto again = s3->get(segKey, std::nullopt);
        ASSERT_TRUE(again);
        (void)s3->put(segKey, again->bytes);
        ASSERT_GE(s3->versions(segKey).size(), 2u);
        const auto now = std::time(nullptr);
        const mf::UnreferencedClock clock{.first = [&](const std::string&) { return now - 2 * 24 * 60 * 60; },
                                          .forget = [](const std::string&) {}};
        const auto report = mf::collectGarbageVersionLog(*s3, retained, now, clock);
        EXPECT_TRUE(std::ranges::find(report.deleted, collected) != report.deleted.end());
        EXPECT_TRUE(s3->versions(segKey).empty()) << "every version deleted by id, no hide marker left";
        for (const auto& sid : retained) EXPECT_TRUE(s3->get(mf::segmentKey(sid), std::nullopt)) << sid;
        mf::LoadOptions o;
        o.known = known;
        o.settled = settled;
        EXPECT_TRUE(mf::load(*s3, vault, lookup, o).issues.empty()) << "the head still loads whole";
    }

    // (6) A recovery envelope (named by its own hash) is written without a condition and read back.
    {
        const auto envelopeKey = std::string(".vaulthalla/key/") + crypto::id::toBase32(crypto::id::newObjectUid());
        const std::vector<uint8_t> envelope{0x89, 'V', 'H', 'K', 0x01, 0x02, 0x03};
        (void)s3->putOnce(envelopeKey, envelope);
        const auto back = s3->get(envelopeKey, std::nullopt);
        ASSERT_TRUE(back);
        EXPECT_EQ(back->bytes, envelope);
        EXPECT_EQ(s3->versions(envelopeKey).size(), 1u);
    }
}

}
