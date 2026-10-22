// Live provider tests in the one shared test bucket (tests/helpers/live_bucket.hpp; testing.md "Live provider tests"),
// and the self-tests of the guard that keeps every live test inside it.
//
//  - LiveBucketGuard.*: DB-free and credential-free, always run (CI too): the guarded admin client refuses bucket
//    creation, deletion and configuration, account listings, other buckets and deletes outside the test's prefix;
//    run prefixes and the stale-run rule.
//  - Live/LiveObjects.*/{r2,aws}: object-level checks against the real bucket, each under its own
//    vh-test-runs/<run>/<test>/ prefix that TearDown empties. Skip without VAULTHALLA_TEST_R2_* / VAULTHALLA_TEST_S3_*.
//
// Run: (eval "$(grep -E '^export VAULTHALLA_TEST_R2_' <repo>/.bashrc)"; build/core/vh_unit_tests --gtest_filter='Live*')

#include "../helpers/live_bucket.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <regex>
#include <set>

namespace vh::test_live_bucket {

namespace live = test_support::live;
namespace padmin = storage::s3::provider::admin;
using live::Provider;

std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

// ---- the guard (no provider involved) ---------------------------------------------------------------------------------

// Records every call that reaches it; the guard must stop the forbidden ones before they get here.
class RecordingAdmin final : public padmin::AdminClient {
public:
    std::vector<std::string> calls;
    std::vector<padmin::ObjectSummary> objects;

    [[nodiscard]] std::string providerId() const override { return "cloudflare-r2"; }
    [[nodiscard]] padmin::AccountIdentity identity() override { return {"cloudflare-r2", "acct", "r2-token"}; }
    [[nodiscard]] padmin::Capabilities probe() override { calls.emplace_back("probe"); return {}; }
    [[nodiscard]] padmin::BucketPage listBuckets(const std::string&, unsigned int) override {
        calls.emplace_back("listBuckets");
        return {};
    }
    [[nodiscard]] std::optional<std::string> headBucket(const std::string& b) override {
        calls.push_back("head " + b);
        return "auto";
    }
    void createBucket(const padmin::CreateBucketRequest& r) override { calls.push_back("create " + r.name); }
    void deleteBucket(const std::string& b) override { calls.push_back("deleteBucket " + b); }
    [[nodiscard]] padmin::BucketConfiguration inspect(const std::string& b) override {
        calls.push_back("inspect " + b);
        return {};
    }
    void putLifecycle(const std::string& b, const std::vector<padmin::LifecycleRule>&) override {
        calls.push_back("lifecycle " + b);
    }
    [[nodiscard]] bool supportsVersioning() const override { return false; }
    [[nodiscard]] padmin::VersioningState versioning(const std::string& b) override {
        calls.push_back("versioning " + b);
        return {};
    }
    void putVersioning(const std::string& b, padmin::Versioning) override { calls.push_back("putVersioning " + b); }
    [[nodiscard]] padmin::ObjectPage listObjects(const std::string& b, const std::string&, unsigned int) override {
        calls.push_back("list " + b);
        return {.objects = objects, .next_token = {}};
    }
    [[nodiscard]] padmin::ObjectPage listObjectVersions(const std::string& b, const std::string& t, unsigned int m) override {
        return listObjects(b, t, m);
    }
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> deleteObjects(
        const std::string& b, const std::vector<padmin::ObjectSummary>& o) override {
        calls.push_back("delete " + b + " x" + std::to_string(o.size()));
        return {};
    }
    [[nodiscard]] padmin::Metrics metrics() const override { return {}; }
};

class LiveBucketGuard : public ::testing::Test {
protected:
    void SetUp() override { (void)live::takeViolations(); }
    void TearDown() override { (void)live::takeViolations(); }

    const std::string prefix = std::string(live::kRunsRoot) + "host-1-1700000000/Suite.Test/";

    std::pair<std::unique_ptr<live::GuardedAdmin>, RecordingAdmin*> guarded(const std::string& deletable) const {
        auto inner = std::make_unique<RecordingAdmin>();
        auto* raw = inner.get();
        return {std::make_unique<live::GuardedAdmin>(std::move(inner), "vh-test", deletable), raw};
    }
};

TEST_F(LiveBucketGuard, RefusesBucketProvisioningConfigurationAndAccountListings) {
    auto [admin, inner] = guarded(prefix);
    EXPECT_THROW(admin->createBucket({.name = "vh-test", .region = std::nullopt}), live::GuardViolation);
    EXPECT_THROW(admin->createBucket({.name = "vaulthalla-test-1-abc", .region = std::nullopt}), live::GuardViolation);
    EXPECT_THROW(admin->deleteBucket("vh-test"), live::GuardViolation);
    EXPECT_THROW(admin->putLifecycle("vh-test", {}), live::GuardViolation);
    EXPECT_THROW(admin->putVersioning("vh-test", padmin::Versioning::Enabled), live::GuardViolation);
    EXPECT_THROW((void)admin->listBuckets({}, 1000), live::GuardViolation);
    EXPECT_THROW((void)admin->probe(), live::GuardViolation);
    EXPECT_TRUE(inner->calls.empty()) << "a refused call reached the provider: " << inner->calls.front();
    // Recorded even if the code under test swallowed the exceptions: the fixture fails the test on these.
    EXPECT_EQ(live::takeViolations().size(), 7u);
}

TEST_F(LiveBucketGuard, OnlyTheConfiguredBucket) {
    auto [admin, inner] = guarded(prefix);
    EXPECT_TRUE(admin->headBucket("vh-test").has_value());
    (void)admin->listObjects("vh-test", {}, 10);
    (void)admin->inspect("vh-test");
    EXPECT_EQ(inner->calls.size(), 3u);
    EXPECT_THROW((void)admin->headBucket("vaulthalla-test"), live::GuardViolation);
    EXPECT_THROW((void)admin->listObjects("other", {}, 10), live::GuardViolation);
    EXPECT_THROW((void)admin->inspect("other"), live::GuardViolation);
    EXPECT_THROW((void)admin->versioning("other"), live::GuardViolation);
    EXPECT_THROW((void)admin->deleteObjects("other", {{.key = prefix + "a"}}), live::GuardViolation);
    EXPECT_EQ(inner->calls.size(), 3u);
    EXPECT_EQ(live::takeViolations().size(), 5u);
}

TEST_F(LiveBucketGuard, DeletesOnlyUnderItsPrefixAndNeverOutsideTheRunsRoot) {
    auto [admin, inner] = guarded(prefix);
    EXPECT_TRUE(admin->deleteObjects("vh-test", {{.key = prefix + "a"}, {.key = prefix + "b/c"}}).empty());
    ASSERT_EQ(inner->calls.size(), 1u);
    EXPECT_EQ(inner->calls[0], "delete vh-test x2");
    const std::vector<padmin::ObjectSummary> mixed{{.key = prefix + "a"}, {.key = "data/report.txt"}};
    EXPECT_THROW((void)admin->deleteObjects("vh-test", mixed), live::GuardViolation) << "one bad key refuses the batch";
    EXPECT_THROW((void)admin->deleteObjects("vh-test", {{.key = std::string(live::kRunsRoot) + "other-run/x"}}),
                 live::GuardViolation);
    EXPECT_THROW((void)admin->deleteObjects("vh-test", {{.key = ".vaulthalla/index-v1.json"}}), live::GuardViolation);
    EXPECT_EQ(inner->calls.size(), 1u);

    // The sweep's client may delete any run, still nothing outside vh-test-runs/.
    auto [sweeper, sweptInner] = guarded(std::string(live::kRunsRoot));
    EXPECT_TRUE(sweeper->deleteObjects("vh-test", {{.key = std::string(live::kRunsRoot) + "other-run/x"}}).empty());
    EXPECT_THROW((void)sweeper->deleteObjects("vh-test", {{.key = "vh-test-runsX/x"}}), live::GuardViolation);
    EXPECT_THROW((void)sweeper->deleteObjects("vh-test", {{.key = "x"}}), live::GuardViolation);
    EXPECT_EQ(sweptInner->calls.size(), 1u);
    EXPECT_THROW((void)live::GuardedAdmin(std::make_unique<RecordingAdmin>(), "vh-test", "data/"), std::logic_error);
    EXPECT_THROW((void)live::LivePrefix(live::Target{}, "data/x/"), std::logic_error);
}

TEST_F(LiveBucketGuard, RemovalDeletesOnlyWhatItSelectsUnderThePrefix) {
    auto inner = std::make_unique<RecordingAdmin>();
    auto* raw = inner.get();
    raw->objects = {{.key = prefix + "a"}, {.key = std::string(live::kRunsRoot) + "other-run/b"}, {.key = "outside"}};
    live::GuardedAdmin admin(std::move(inner), "vh-test", prefix);
    EXPECT_EQ(admin.listUnder(prefix).size(), 1u) << "listings stay inside the prefix";
    EXPECT_TRUE(admin.uploadsUnder(prefix).empty());
}

TEST_F(LiveBucketGuard, FactoryHandsOutOnlyTheGuardedClientForTheTestCredential) {
    live::Target t;
    t.access = "AKIDLIVE";
    t.endpoint = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com";
    t.region = "auto";
    t.bucket = "vh-test";
    const auto factory = live::guardedFactory(t, prefix);
    auto mine = std::make_shared<vault::model::APIKey>(0, "k", vault::model::S3Provider::CloudflareR2, "AKIDLIVE",
                                                       "secret-0000000000000000000000", "auto", t.endpoint);
    const auto client = factory.admin(mine);
    ASSERT_NE(dynamic_cast<live::GuardedAdmin*>(client.get()), nullptr);
    EXPECT_THROW(client->createBucket({.name = "vh-test", .region = std::nullopt}), live::GuardViolation);
    auto other = std::make_shared<vault::model::APIKey>(*mine);
    other->access_key = "AKIDADMIN";
    EXPECT_THROW((void)factory.admin(other), live::GuardViolation);
    EXPECT_THROW((void)factory.events(mine), live::GuardViolation);
    EXPECT_EQ(live::takeViolations().size(), 3u);
}

TEST_F(LiveBucketGuard, RunPrefixesAndStaleRuns) {
    EXPECT_TRUE(std::regex_match(live::runId(), std::regex(R"([a-z0-9._-]+-[0-9]+-[0-9]+)"))) << live::runId();
    EXPECT_EQ(live::testPrefix(),
              std::string(live::kRunsRoot) + live::runId() + "/LiveBucketGuard.RunPrefixesAndStaleRuns/");
    EXPECT_EQ(live::runStartOf(live::testPrefix() + "x"), std::optional<std::time_t>(live::runStarted()));
    EXPECT_EQ(live::runStartOf("vh-test-runs/my-host-12-1700000000/T.t/k"), std::optional<std::time_t>(1700000000));
    EXPECT_EQ(live::runStartOf("vh-test-runs/garbage/k"), std::nullopt);
    EXPECT_EQ(live::runStartOf("other/h-1-1700000000/k"), std::nullopt);

    const std::time_t now = 1700000000 + 24 * 3600;
    const std::time_t old = now - 7 * 3600, recent = now - 3600;
    EXPECT_TRUE(live::isStale("vh-test-runs/h-1-1700000000/T.t/k", std::nullopt, now));
    EXPECT_TRUE(live::isStale("vh-test-runs/h-1-1700000000/T.t/k", old, now));
    EXPECT_TRUE(live::isStale("vh-test-runs/h-1-1700000000/T.t/k", recent, now)) << "the run's start decides";
    EXPECT_FALSE(live::isStale("vh-test-runs/h-1-" + std::to_string(recent) + "/T.t/k", old, now));
    EXPECT_FALSE(live::isStale(live::testPrefix() + "k", old, std::time(nullptr))) << "never this run";
    EXPECT_TRUE(live::isStale("vh-test-runs/garbage/k", old, now));
    EXPECT_FALSE(live::isStale("vh-test-runs/garbage/k", std::nullopt, now)) << "no known age: kept";
    EXPECT_FALSE(live::isStale("data/h-1-1700000000/k", old, now)) << "never outside vh-test-runs/";
    EXPECT_FALSE(live::isStale(".vaulthalla/index-v1.json", old, now));
}

// ---- live: the shared bucket ------------------------------------------------------------------------------------------

class LiveObjects : public live::LiveBucketTest {};

// The admin adapter's object calls, the protection lock and the version listing, inside the test prefix.
TEST_P(LiveObjects, AdminObjectCallsStayInsideTheTestPrefix) {
    auto& data = live().controller();
    auto& admin = live().admin();
    EXPECT_TRUE(admin.headBucket(liveTarget().bucket).has_value());
    data.uploadBufferWithMetadata(live().key("a/one.txt"), bytes("1"), std::unordered_map<std::string, std::string>{});
    data.uploadBufferWithMetadata(live().key("two.txt"), bytes("22"), std::unordered_map<std::string, std::string>{});

    const auto listed = admin.listUnder(live().prefix());
    std::set<std::string> keys;
    for (const auto& o : listed)
        if (!o.delete_marker) keys.insert(o.key);
    EXPECT_EQ(keys, (std::set<std::string>{live().key("a/one.txt"), live().key("two.txt")}));
    EXPECT_TRUE(admin.deleteObjects(liveTarget().bucket, listed).empty());
    std::vector<padmin::ObjectSummary> current;
    for (const auto& o : admin.listUnder(live().prefix()))
        if (!o.delete_marker) current.push_back(o);
    EXPECT_TRUE(current.empty());

    // A protected bucket: nothing bucket-scoped goes out, through either client.
    const auto before = admin.metrics().requests;
    const auto metered = data.requestMetrics().put_requests;
    storage::upstream::guard::setForTesting({storage::upstream::identityFor(*live().apiKey(), liveTarget().bucket)});
    EXPECT_THROW((void)admin.inspect(liveTarget().bucket), storage::upstream::BucketProtected);
    EXPECT_THROW(data.uploadBufferWithMetadata(live().key("locked.txt"), bytes("x"),
                                               std::unordered_map<std::string, std::string>{}),
                 storage::upstream::BucketProtected);
    storage::upstream::guard::clearForTesting();
    EXPECT_EQ(admin.metrics().requests, before);
    EXPECT_EQ(data.requestMetrics().put_requests, metered);
}

// The data-plane signer signs the query in SigV4 order on every page: page 2+ of a ListObjectsV2 carries
// ?list-type=2&max-keys=…&continuation-token=…, out of order as written. Small pages over the bucket force that.
TEST_P(LiveObjects, ListingPagesAreSignedOnEveryPage) {
    auto& data = live().controller();
    std::set<std::string> expected;
    for (int i = 0; i < 5; ++i) {
        const auto k = live().key("page/" + std::to_string(i) + ".txt");
        data.uploadBufferWithMetadata(k, bytes("x"), std::unordered_map<std::string, std::string>{});
        expected.insert(k);
    }

    std::set<std::string> seen;
    std::string token;
    int pages = 0;
    try {
        do {
            const auto page = data.listObjectKeysPage(token, 2);
            ++pages;
            seen.insert(page.keys.begin(), page.keys.end());
            token = page.next_continuation_token;
        } while (!token.empty() && pages < 500);
    } catch (const std::exception& e) {
        ADD_FAILURE() << "listObjectKeysPage page " << pages + 1 << ": " << e.what();
    }
    EXPECT_GE(pages, 3);
    for (const auto& k : expected) EXPECT_TRUE(seen.contains(k)) << k;

    // The legacy whole listing (concatenated ListObjectsV2 XML), confined to the prefix.
    const auto xml = data.listObjects(live().key("page/"));
    const std::string raw(reinterpret_cast<const char*>(xml.data()), xml.size());
    std::set<std::string> listed;
    for (auto pos = raw.find("<Key>"); pos != std::string::npos; pos = raw.find("<Key>", pos)) {
        pos += 5;
        listed.insert(raw.substr(pos, raw.find("</Key>", pos) - pos));
    }
    EXPECT_EQ(raw.find("<Error>"), std::string::npos);
    EXPECT_EQ(listed, expected);
}

// File recovery's provider data plane (recovery.md, "Provider versioning"), inside the prefix and without touching the
// bucket's configuration. R2 has no versions: ListObjectVersions is refused (501 NotImplemented). On a versioned AWS
// test bucket: two PUTs are two versions, HEAD ?versionId reads the old one's metadata and CopyObject restores it.
TEST_P(LiveObjects, ProviderVersionsInsideThePrefix) {
    auto& data = live().controller();
    const auto key = live().key("v/report.txt");
    data.uploadBufferWithMetadata(key, bytes("first"), std::unordered_map<std::string, std::string>{{"vh-iv", "one"}});
    data.uploadBufferWithMetadata(key, bytes("second!"), std::unordered_map<std::string, std::string>{{"vh-iv", "two"}});

    if (liveTarget().provider == Provider::R2) {
        try {
            (void)data.listObjectVersionsPage(live().prefix());
            ADD_FAILURE() << "R2 answered ListObjectVersions";
        } catch (const std::runtime_error& e) {
            std::cout << "[live] r2 ListObjectVersions: " << e.what() << std::endl;
            EXPECT_NE(std::string(e.what()).find("501"), std::string::npos) << e.what();
        }
        EXPECT_FALSE(live().admin().supportsVersioning());
        return;
    }

    auto versions = data.listObjectVersionsPage(live().prefix()).versions;
    ASSERT_FALSE(versions.empty());
    if (versions.size() == 1 || versions.front().version_id == "null")
        GTEST_SKIP() << "the AWS test bucket is unversioned: nothing more to check without changing it";
    ASSERT_EQ(versions.size(), 2u);
    const auto old = *std::ranges::find_if(versions, [](const auto& v) { return !v.is_latest; });
    const auto head = data.headObjectVersion(key, old.version_id);
    ASSERT_TRUE(head.has_value());
    EXPECT_EQ(head->metadata.at("vh-iv"), "one");
    (void)data.copyObjectVersion(key, old.version_id, key, old.size, storage::s3::RequestOptions{});
    versions = data.listObjectVersionsPage(live().prefix()).versions;
    EXPECT_EQ(versions.size(), 3u);
    std::vector<uint8_t> body;
    data.downloadToBuffer(key, body);
    EXPECT_EQ(std::string(body.begin(), body.end()), "first");
}

// The cleanup guard itself on the real bucket: a scope that throws half-way (objects written, a multipart upload left
// open) still leaves nothing behind.
TEST_P(LiveObjects, ACleanupGuardRemovesEverythingWhenItsScopeThrows) {
    const auto nested = live().key("nested/");
    try {
        test_support::live::LivePrefix scope(liveTarget(), nested);
        auto& data = scope.controller();
        data.uploadBufferWithMetadata(scope.key("a.txt"), bytes("a"), std::unordered_map<std::string, std::string>{});
        data.uploadBufferWithMetadata(scope.key("deep/b.txt"), bytes("b"), std::unordered_map<std::string, std::string>{});
        const auto uploadId = data.initiateMultipartUpload(scope.key("open-upload.bin"));
        ASSERT_FALSE(uploadId.empty());
        const auto during = scope.contents();
        EXPECT_EQ(during.objects.size(), 2u);
        EXPECT_EQ(during.uploads.size(), 1u) << "ListMultipartUploads sees the open upload";
        throw std::runtime_error("simulated failure mid-test");
    } catch (const std::runtime_error& e) {
        EXPECT_STREQ(e.what(), "simulated failure mid-test");
    }
    const auto after = test_support::live::contentsUnder(live().admin(), nested);
    EXPECT_TRUE(after.objects.empty()) << after.objects.size() << " object(s) left";
    EXPECT_TRUE(after.uploads.empty()) << after.uploads.size() << " upload(s) left";
}

INSTANTIATE_TEST_SUITE_P(Live, LiveObjects, ::testing::Values(Provider::R2, Provider::Aws), live::providerName);

}
