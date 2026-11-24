// Live Backblaze B2 tests (design/encryption/06-publish-without-preconditions.md §8.3) and the self-tests of the B2
// guard (tests/helpers/live_bucket.hpp; testing.md "Live provider tests").
//
//  - LiveB2Guard.*: no credentials, no DB, always run (CI too): GuardedB2 refuses every bucket that isn't a vh-test-*
//    test bucket before any request, and the endpoint's region is read from b2_authorize_account's s3ApiUrl.
//  - LiveB2.*: opt-in (VH_LIVE_TESTS=1 + VH_B2_TEST_KEY_ID, VH_B2_TEST_APP_KEY). One bucket per run, created through
//    B2's native API on the first live test and emptied of every version and deleted after the last, also when tests
//    fail. Two tests: the version_log manifest against the real S3 adapter, and the product's B2 admin adapter
//    (B2Admin, which also creates the run bucket) against the run bucket.
//
// Run: (eval "$(grep -E '^export VH_B2_TEST_' <repo>/.bashrc)"; VH_LIVE_TESTS=1 build/core/vh_unit_tests --gtest_filter='LiveB2*')

#include <vl/vaultfmt/testing/hooked_store.hpp>
#include "../helpers/live_bucket.hpp"

#include "crypto/SecretKey.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "storage/s3/Capability.hpp"
#include "storage/s3/ManifestStore.hpp"
#include "recovery/provider/Capabilities.hpp"
#include "recovery/provider/Policy.hpp"
#include "vault/model/S3Vault.hpp"
#include <vl/vaultfmt/manifest/Content.hpp>
#include <vl/vaultfmt/manifest/Document.hpp>
#include <vl/vaultfmt/manifest/Objects.hpp>
#include <vl/vaultfmt/manifest/Publisher.hpp>
#include <vl/vaultfmt/manifest/Reader.hpp>
#include <vl/vaultfmt/manifest/Store.hpp>

#include <sodium.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <set>

namespace vh::test_live_b2 {

namespace live = test_support::live;
namespace mf = vl::vaultfmt::manifest;
namespace http = storage::s3::curl::http;
using vl::vaultfmt::manifest::WriteCapability;

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

// The product's Backblaze B2 admin adapter against the real S3-compatible API. The run bucket was created through it
// (RunB2Bucket: CreateBucket with x-amz-acl: private and the endpoint's region). Here: the account listing shows it,
// HeadBucket tells present from absent, a second CreateBucket of the same name is a collision the provisioner
// recognises, inspect reads versioning and object lock over the S3 API and lifecycle rules over the native API (never
// B2's S3 lifecycle or notification calls), the file-history rule round-trips (b2_update_bucket with ifRevisionIs and
// the bucketInfo record), the version listing sees every version of an overwritten key, and the probe reports what
// is missing.
TEST_F(LiveB2, TheAdminAdapterAdministersTheRunBucket) {
    namespace padmin = storage::s3::provider::admin;
    auto& admin = this->admin();
    const auto region = b2().account().region;
    EXPECT_EQ(admin.providerId(), "backblaze-b2");
    EXPECT_FALSE(admin.supportsLifecycle());

    // vh upstream buckets
    const auto page = admin.listBuckets({}, 1000);
    EXPECT_TRUE(page.next_token.empty());
    EXPECT_TRUE(std::ranges::any_of(page.buckets, [&](const auto& b) { return b.name == bucket(); }))
        << "ListBuckets does not show " << bucket() << " among " << page.buckets.size() << " bucket(s)";

    // HeadBucket: present, and absent for a test name nobody created.
    EXPECT_EQ(admin.headBucket(bucket()), std::optional<std::string>(region));
    auto absent = bucket();
    absent.back() = absent.back() == '9' ? '8' : '9';
    ASSERT_TRUE(live::isRunBucketName(absent));
    EXPECT_EQ(admin.headBucket(absent), std::nullopt);

    // A name this account already holds.
    try {
        admin.createBucket({.name = bucket(), .region = std::nullopt});
        ADD_FAILURE() << "creating the run bucket a second time must be refused";
    } catch (const padmin::ProviderError& e) {
        std::cout << "[live] CreateBucket on an existing own bucket: HTTP " << e.http_status << " " << e.code << std::endl;
        EXPECT_EQ(e.http_status, 409);
        EXPECT_EQ(e.code, "BucketAlreadyOwnedByYou");
    }

    // vh upstream inspect
    const auto config = admin.inspect(bucket());
    EXPECT_EQ(config.region, std::optional<std::string>(region));
    EXPECT_EQ(config.versioning, padmin::Versioning::Enabled) << "B2 buckets are always versioned";
    ASSERT_TRUE(config.object_lock.has_value()) << "Get Object Lock Configuration was not readable";
    EXPECT_FALSE(*config.object_lock);
    EXPECT_TRUE(config.lifecycle_readable) << "lifecycle rules come from B2's native API (b2_list_buckets)";
    EXPECT_FALSE(config.notifications_readable);
    for (const auto& w : config.warnings) std::cout << "[live] inspect warning: " << w << std::endl;
    EXPECT_EQ(config.warnings.size(), 1u);
    EXPECT_EQ(admin.versioning(bucket()).status, padmin::Versioning::Enabled);
    EXPECT_NO_THROW(admin.putVersioning(bucket(), padmin::Versioning::Enabled));
    EXPECT_THROW(admin.putVersioning(bucket(), padmin::Versioning::Suspended), padmin::CapabilityMissing);

    // The file-history rule round trip (b2_update_bucket with ifRevisionIs, the bucketInfo record): keep only the
    // latest version under o/, read it back as Vaulthalla's, then remove it again (indefinite = no rule of ours).
    {
        namespace pol = vh::recovery::provider::policy;
        const auto scope = vh::recovery::provider::ruleScopeFor("backblaze-b2", vault::model::StorageLayout::OpaqueV1);
        const auto latest = pol::applyLatestOnly(admin, bucket(), scope);
        EXPECT_TRUE(latest.written);
        ASSERT_EQ(latest.vaulthalla_rules.size(), 1u);
        std::cout << "[live] B2 rule: " << latest.vaulthalla_rules[0] << std::endl;
        const auto reread = admin.inspect(bucket());
        const auto ours = std::ranges::find_if(reread.lifecycle, [](const padmin::LifecycleRule& r) { return !r.foreign; });
        ASSERT_NE(ours, reread.lifecycle.end()) << "the bucketInfo record makes the rule recognizable";
        EXPECT_EQ(ours->prefix, "o/");
        EXPECT_EQ(ours->expire_noncurrent_days.value_or(0), 1u);
        (void)pol::applyRetention(admin, bucket(), {.indefinite = true, .days = 0}, true, scope);
        EXPECT_TRUE(std::ranges::none_of(admin.inspect(bucket()).lifecycle,
                                         [](const padmin::LifecycleRule& r) { return !r.foreign; }));
    }

    // The emptiness check and cleanup: one current object, two versions of it.
    const auto key = prefix() + "admin-adapter.txt";
    const auto bytes = [](const std::string& text) { return std::vector<uint8_t>(text.begin(), text.end()); };
    controller().uploadBufferWithMetadata(key, bytes("first"), std::unordered_map<std::string, std::string>{});
    controller().uploadBufferWithMetadata(key, bytes("second"), std::unordered_map<std::string, std::string>{});
    const auto current = admin.objectsUnder(bucket(), prefix());
    ASSERT_EQ(current.size(), 1u);
    EXPECT_EQ(current[0].key, key);
    std::size_t versions = 0, latest = 0;
    std::string token;
    do {
        const auto listing = admin.listObjectVersions(bucket(), token, 1000);
        for (const auto& o : listing.objects) {
            if (o.key != key) continue;
            ++versions;
            if (o.latest) ++latest;
            EXPECT_TRUE(o.version_id && !o.version_id->empty());
        }
        token = listing.next_token;
    } while (!token.empty());
    EXPECT_EQ(versions, 2u);
    EXPECT_EQ(latest, 1u);

    // vh upstream admin status --probe
    const auto caps = admin.probe();
    for (const auto& c : caps.items)
        std::cout << "[live] probe " << (c.ok ? "[ok]      " : "[missing] ") << c.name << std::endl;
    EXPECT_EQ(caps.identity.provider, "backblaze-b2");
    EXPECT_EQ(caps.identity.account_ref, "s3." + region + ".backblazeb2.com");
    EXPECT_TRUE(caps.has("buckets.list"));
    EXPECT_TRUE(caps.has("buckets.create"));
    EXPECT_TRUE(caps.has("lifecycle")) << "the run key holds listBuckets and writeBuckets";
    EXPECT_TRUE(caps.has("versioning")) << "always on";
    for (const char* missing : {"events.queues", "events.notifications"}) EXPECT_FALSE(caps.has(missing)) << missing;
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
    std::cout << "[live] probe: " << vl::vaultfmt::manifest::to_string(probe.capability) << ", MD5 ETags " << probe.md5_etags
              << std::endl;

    // (2) The manifest through the real storage::s3::ManifestStore.
    const auto s3 = std::make_shared<storage::s3::ManifestStore>(sharedController(), WriteCapability::VersionLog);
    const auto store = std::make_shared<vl::vaultfmt::test_support::HookedStore>(s3);
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
        store->after = [&](const vl::vaultfmt::test_support::StoreOp op, const std::string& k, const std::string&,
                           const bool failed) {
            if (op != vl::vaultfmt::test_support::StoreOp::Put || k != mf::kRootKey || failed || !siblingId.empty()) return;
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
        EXPECT_TRUE(std::ranges::find(report.deleted, segKey) != report.deleted.end()) << "the report names keys";
        EXPECT_TRUE(s3->versions(segKey).empty()) << "every version deleted by id, no hide marker left";
        for (const auto& sid : retained) EXPECT_TRUE(s3->get(mf::segmentKey(sid), std::nullopt)) << sid;
        mf::LoadOptions o;
        o.known = known;
        o.settled = settled;
        EXPECT_TRUE(mf::load(*s3, vault, lookup, o).issues.empty()) << "the head still loads whole";
    }

    // (6) A recovery envelope (named by its own hash) is written without a condition and read back.
    {
        const auto envelopeKey = std::string(".vaulthalla/key/") + vl::keykit::toBase32(crypto::id::newObjectUid());
        const std::vector<uint8_t> envelope{0x89, 'V', 'H', 'K', 0x01, 0x02, 0x03};
        (void)s3->putOnce(envelopeKey, envelope);
        const auto back = s3->get(envelopeKey, std::nullopt);
        ASSERT_TRUE(back);
        EXPECT_EQ(back->bytes, envelope);
        EXPECT_EQ(s3->versions(envelopeKey).size(), 1u);
    }
}

}
