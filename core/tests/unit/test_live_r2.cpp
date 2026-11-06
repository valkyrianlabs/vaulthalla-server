// Live Cloudflare R2 tests and the self-tests of the guard around them (tests/helpers/live_bucket.hpp; testing.md
// "Live provider tests").
//
//  - LiveBucketGuard.*: no credentials, no DB, always run (CI too): the guarded clients refuse every bucket and queue
//    that isn't a vh-test-<host>-<pid>-<start> test bucket, the orphan sweep selects only old test buckets, and the
//    provider factory hands out guarded clients for the live credential only.
//  - LiveR2.*: opt-in (VH_LIVE_TESTS=1 + VH_R2_ADMIN_*). One bucket per run, created by the real adapter on the first
//    live test and deleted after the last; each test under its own prefix. Lifecycle rules, locks, versions, paging
//    edge cases and recovery stay with the fakes.
//
// Run: (eval "$(grep -E '^export VH_R2_ADMIN_' <repo>/.bashrc)"; VH_LIVE_TESTS=1 build/core/vh_unit_tests --gtest_filter='Live*')

#include "../helpers/live_bucket.hpp"

#include "fs/model/File.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/ObjectKeys.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/LayoutMigration.hpp"
#include "vault/model/S3Vault.hpp"

#include <sodium.h>
#include <unistd.h>

#include <filesystem>
#include <fstream>
#include <random>

#include <gtest/gtest.h>

#include <algorithm>
#include <functional>
#include <regex>
#include <set>
#include <span>
#include <thread>
#include <unordered_map>

namespace vh::test_live_r2 {

namespace live = test_support::live;
namespace padmin = storage::s3::provider::admin;

[[maybe_unused]] const auto* const kRunBucketEnvironment =
    ::testing::AddGlobalTestEnvironment(new live::RunBucketEnvironment);

std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }

padmin::ObjectSummary obj(const std::string& key) {
    padmin::ObjectSummary o;
    o.key = key;
    return o;
}

// ---- the guard (no provider involved) ---------------------------------------------------------------------------------

// Records every call that reaches it; the guard must stop the refused ones before they get here.
class RecordingAdmin final : public padmin::AdminClient {
public:
    std::vector<std::string> calls;

    [[nodiscard]] std::string providerId() const override { return "cloudflare-r2"; }
    [[nodiscard]] padmin::AccountIdentity identity() override { return {"cloudflare-r2", "acct", "r2-token"}; }
    [[nodiscard]] padmin::Capabilities probe() override {
        calls.emplace_back("probe");
        return {};
    }
    [[nodiscard]] padmin::BucketPage listBuckets(const std::string&, unsigned int) override {
        calls.emplace_back("listBuckets");
        return {};
    }
    [[nodiscard]] std::optional<std::string> headBucket(const std::string& b) override {
        calls.push_back("head " + b);
        return "auto";
    }
    void createBucket(const padmin::CreateBucketRequest& r) override { calls.push_back("create " + r.name); }
    void deleteBucket(const std::string& b) override { calls.push_back("delete " + b); }
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
        return {};
    }
    [[nodiscard]] padmin::ObjectPage listObjectVersions(const std::string& b, const std::string& t, unsigned int m) override {
        return listObjects(b, t, m);
    }
    [[nodiscard]] std::vector<std::pair<std::string, std::string>> deleteObjects(
        const std::string& b, const std::vector<padmin::ObjectSummary>&) override {
        calls.push_back("deleteObjects " + b);
        return {};
    }
    [[nodiscard]] padmin::Metrics metrics() const override { return {}; }
};

class RecordingEvents final : public padmin::EventsClient {
public:
    std::vector<std::string> calls;

    [[nodiscard]] std::string providerId() const override { return "cloudflare-r2"; }
    [[nodiscard]] padmin::ChannelRef ensureChannel(const padmin::ChannelSpec& s) override {
        calls.push_back("ensure " + s.queue_name);
        padmin::ChannelRef c;
        c.queue_name = s.queue_name;
        return c;
    }
    [[nodiscard]] std::vector<std::string> subscribe(const padmin::ChannelRef&, const padmin::SubscriptionSpec& s) override {
        calls.push_back("subscribe " + s.bucket);
        return {"rule"};
    }
    void unsubscribe(const padmin::ChannelRef&, const padmin::SubscriptionSpec& s, const std::vector<std::string>&) override {
        calls.push_back("unsubscribe " + s.bucket);
    }
    [[nodiscard]] std::vector<padmin::NotificationRule> rules(const std::string& b) override {
        calls.push_back("rules " + b);
        return {};
    }
    void removeChannel(const padmin::ChannelRef& c) override { calls.push_back("remove " + c.queue_name); }
    [[nodiscard]] padmin::PollResult poll(const padmin::ChannelRef& c, unsigned int, std::chrono::seconds,
                                          std::chrono::seconds) override {
        calls.push_back("poll " + c.queue_name);
        return {};
    }
    void ack(const padmin::ChannelRef& c, const std::vector<std::string>&) override { calls.push_back("ack " + c.queue_name); }
    void retry(const padmin::ChannelRef& c, const std::vector<std::string>&, std::chrono::seconds) override {
        calls.push_back("retry " + c.queue_name);
    }
    [[nodiscard]] std::optional<uint64_t> backlog(const padmin::ChannelRef& c) override {
        calls.push_back("backlog " + c.queue_name);
        return std::nullopt;
    }
    [[nodiscard]] padmin::Metrics metrics() const override { return {}; }
};

// Real account buckets and near misses: none of them may ever be touched.
const std::vector<std::string> kNotTestBuckets = {
    "vh-test", "vh-test-", "vaulthalla", "vaulthalla-database-backups", "portfolio", "docs-valkyrian-labs",
    "vh-test-foo", "vh-test-host-1-170000000", "vh-test-host-1-17000000000", "VH-TEST-host-1-1700000000",
    "vh-test-host-1-1700000000x", "xvh-test-host-1-1700000000", "vh-test-ho_st-1-1700000000",
    "vh-test-runs", "vaulthalla-test-1700000000-abcd", "vh-test-gateway", "vh-test-gateway-smoke2",
    "vh-test-gateway-smoke-1-1700000000x"};

class LiveBucketGuard : public ::testing::Test {
protected:
    void SetUp() override { (void)live::takeViolations(); }
    void TearDown() override { (void)live::takeViolations(); }
};

TEST_F(LiveBucketGuard, RefusesEveryBucketThatIsNotATestBucket) {
    auto inner = std::make_unique<RecordingAdmin>();
    auto* calls = &inner->calls;
    live::GuardedAdmin admin(std::move(inner));
    for (const auto& b : kNotTestBuckets) {
        EXPECT_THROW(admin.createBucket({.name = b, .region = std::nullopt}), live::GuardViolation) << b;
        EXPECT_THROW(admin.deleteBucket(b), live::GuardViolation) << b;
        EXPECT_THROW(admin.putLifecycle(b, {}), live::GuardViolation) << b;
        EXPECT_THROW(admin.putVersioning(b, padmin::Versioning::Enabled), live::GuardViolation) << b;
        EXPECT_THROW((void)admin.headBucket(b), live::GuardViolation) << b;
        EXPECT_THROW((void)admin.inspect(b), live::GuardViolation) << b;
        EXPECT_THROW((void)admin.versioning(b), live::GuardViolation) << b;
        EXPECT_THROW((void)admin.listObjects(b, {}, 10), live::GuardViolation) << b;
        EXPECT_THROW((void)admin.listObjectVersions(b, {}, 10), live::GuardViolation) << b;
        EXPECT_THROW((void)admin.deleteObjects(b, {obj("x")}), live::GuardViolation) << b;
        EXPECT_THROW((void)admin.objectsUnder(b, ""), live::GuardViolation) << b;
        EXPECT_THROW((void)admin.uploadsUnder(b, ""), live::GuardViolation) << b;
    }
    EXPECT_TRUE(calls->empty()) << "a refused call reached the provider: " << calls->front();
    // Recorded as well as thrown: the fixture fails a test whose code swallowed one of these.
    EXPECT_EQ(live::takeViolations().size(), kNotTestBuckets.size() * 12);
}

TEST_F(LiveBucketGuard, ForwardsTestBucketsAndAccountReads) {
    auto inner = std::make_unique<RecordingAdmin>();
    auto* calls = &inner->calls;
    live::GuardedAdmin admin(std::move(inner));
    const auto mine = live::runBucketName();
    const std::string other = "vh-test-otherhost-42-1700000000";
    admin.createBucket({.name = mine, .region = std::nullopt});
    (void)admin.headBucket(mine);
    (void)admin.deleteObjects(mine, {obj("a")});
    admin.deleteBucket(other);
    admin.createBucket({.name = "vh-test-gateway-smoke", .region = std::nullopt});   // the fixed tooling bucket
    (void)admin.listBuckets({}, 1000);
    (void)admin.probe();
    EXPECT_EQ(*calls, (std::vector<std::string>{"create " + mine, "head " + mine, "deleteObjects " + mine,
                                                "delete " + other, "create vh-test-gateway-smoke", "listBuckets",
                                                "probe"}));
    EXPECT_TRUE(live::takeViolations().empty());
}

TEST_F(LiveBucketGuard, EventsTouchOnlyTestBucketsAndTestQueues) {
    auto inner = std::make_unique<RecordingEvents>();
    auto* calls = &inner->calls;
    live::GuardedEvents events(std::move(inner));
    const auto mine = live::runBucketName();
    padmin::ChannelSpec spec{.account_ref = "acct", .region = "", .queue_name = "vaulthalla-events-r2",
                             .retention_seconds = 60, .visibility_timeout_seconds = 30, .max_receive_count = 3};
    EXPECT_THROW((void)events.ensureChannel(spec), live::GuardViolation);
    padmin::ChannelRef theirs;
    theirs.queue_name = "vaulthalla-events-r2";
    padmin::ChannelRef ours;
    ours.queue_name = mine;
    EXPECT_THROW(events.removeChannel(theirs), live::GuardViolation);
    EXPECT_THROW((void)events.poll(theirs, 1, std::chrono::seconds{0}, std::chrono::seconds{0}), live::GuardViolation);
    EXPECT_THROW((void)events.subscribe(ours, {.bucket = "vaulthalla", .rule_id = "r", .prefix = ""}), live::GuardViolation);
    EXPECT_THROW(events.unsubscribe(ours, {.bucket = "vh-test", .rule_id = "r", .prefix = ""}, {}), live::GuardViolation);
    EXPECT_THROW((void)events.rules("portfolio"), live::GuardViolation);
    EXPECT_TRUE(calls->empty());
    spec.queue_name = mine;
    (void)events.ensureChannel(spec);
    (void)events.subscribe(ours, {.bucket = mine, .rule_id = "r", .prefix = "p/"});
    events.removeChannel(ours);
    EXPECT_EQ(calls->size(), 3u);
    EXPECT_EQ(live::takeViolations().size(), 6u);
}

TEST_F(LiveBucketGuard, NamesAndTheOrphanSweep) {
    const auto& mine = live::runBucketName();
    EXPECT_TRUE(mine.starts_with("vh-test-"));
    EXPECT_LE(mine.size(), 63u);
    EXPECT_TRUE(std::regex_match(mine, std::regex(live::kRunBucketPattern))) << mine;
    EXPECT_EQ(live::runStartOf(mine), std::optional<std::time_t>(live::runStarted()));
    for (const auto& b : kNotTestBuckets) EXPECT_FALSE(live::isTestBucketName(b)) << b;
    EXPECT_EQ(live::fixedTestBuckets(), (std::vector<std::string>{"vh-test-gateway-smoke", "vh-test-recover-drill"}));
    EXPECT_TRUE(live::isTestBucketName("vh-test-gateway-smoke"));
    EXPECT_FALSE(live::isRunBucketName("vh-test-gateway-smoke")) << "the sweep never considers the fixed bucket";

    const std::time_t now = live::runStarted() + 60;
    const auto old = std::to_string(now - 7 * 3600), recent = std::to_string(now - 3600);
    std::vector<std::string> account = kNotTestBuckets;
    account.insert(account.end(), {mine, "vh-test-crashed-7-" + old, "vh-test-busy-8-" + recent,
                                   "vh-test-crashed-7-" + old + "-x", "vh-test-crashed-" + old, "vh-test-gateway-smoke"});
    EXPECT_EQ(live::RunBucket::orphans(account, now), (std::vector<std::string>{"vh-test-crashed-7-" + old}));
}

TEST_F(LiveBucketGuard, TheFactoryHandsOutGuardedClientsForTheLiveCredentialOnly) {
    live::Target t;
    t.access = "AKIDLIVE0000000000000000";
    t.secret = "secret-0000000000000000000000000000";
    t.endpoint = "https://0123456789abcdef0123456789abcdef.r2.cloudflarestorage.com";
    t.region = "auto";
    const auto factory = live::guardedFactory(t);
    const auto mine = live::apiKey(t);
    const auto admin = factory.admin(mine);
    ASSERT_NE(dynamic_cast<live::GuardedAdmin*>(admin.get()), nullptr);
    EXPECT_THROW(admin->createBucket({.name = "vaulthalla", .region = std::nullopt}), live::GuardViolation);
    EXPECT_THROW((void)factory.events(mine), padmin::CapabilityMissing) << "R2 events need VH_CF_API_TOKEN";
    auto withToken = live::apiKey(t);
    withToken->provider_token = "cf-token";
    EXPECT_NE(dynamic_cast<live::GuardedEvents*>(factory.events(withToken).get()), nullptr);

    // Queues are deleted by name: only the run's queue and its -dlq, refused before any request.
    const auto& run = live::runBucketName();
    EXPECT_TRUE(live::isRunQueueName(run));
    EXPECT_TRUE(live::isRunQueueName(run + "-dlq"));
    for (const auto* q : {"vaulthalla-events-r2", "vaulthalla-events-r2-dlq", "vh-test-gateway-smoke-dlq", "vh-test-dlq"})
        EXPECT_FALSE(live::isRunQueueName(q)) << q;
    live::QueueAdmin queues(withToken);
    EXPECT_THROW((void)queues.remove("vaulthalla-events-r2"), live::GuardViolation);
    EXPECT_THROW(queues.removeUntilGone({run, "other-app"}), live::GuardViolation);
    auto other = live::apiKey(t);
    other->access_key = "AKIDSOMEONEELSE000000000";
    EXPECT_THROW((void)factory.admin(other), live::GuardViolation);
    EXPECT_THROW((void)factory.events(other), live::GuardViolation);
    EXPECT_EQ(live::takeViolations().size(), 5u);
}

// ---- live (opt-in) ----------------------------------------------------------------------------------------------------

class LiveR2 : public live::LiveR2Test {};

std::optional<std::string> header(const std::unordered_map<std::string, std::string>& headers, const std::string& name) {
    for (const auto& [k, v] : headers) {
        std::string lower = k;
        std::ranges::transform(lower, lower.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower == name) return v;
    }
    return std::nullopt;
}

// The run's bucket was made by the real adapter (and is deleted by it after the last test): it exists, the account
// listing shows it, a second CreateBucket is a non-destructive 409, and R2 refuses versioning without a request.
TEST_F(LiveR2, TheRunBucketCameFromTheAdapter) {
    auto& admin = this->admin();
    EXPECT_EQ(admin.identity().account_ref.size(), 32u);
    EXPECT_TRUE(admin.headBucket(bucket()).has_value());
    bool listed = false;
    std::string token;
    for (int page = 0; page < 10 && !listed; ++page) {
        const auto p = admin.listBuckets(token, 1000);
        listed = std::ranges::any_of(p.buckets, [&](const auto& b) { return b.name == bucket(); });
        token = p.next_token;
        if (token.empty()) break;
    }
    EXPECT_TRUE(listed) << "ListBuckets doesn't show " << bucket();
    try {
        admin.createBucket({.name = bucket(), .region = std::nullopt});
        ADD_FAILURE() << "a second CreateBucket of the run bucket succeeded";
    } catch (const padmin::ProviderError& e) {
        EXPECT_EQ(e.http_status, 409) << e.what();
        EXPECT_TRUE(e.code == "BucketAlreadyOwnedByYou" || e.code == "BucketAlreadyExists") << e.code;
    }
    EXPECT_FALSE(admin.supportsVersioning());
    const auto before = admin.metrics().requests;
    EXPECT_THROW(admin.putVersioning(bucket(), padmin::Versioning::Enabled), padmin::CapabilityMissing);
    EXPECT_EQ(admin.metrics().requests, before);
}

// put (with metadata, a unicode key), get, ranged get, head, list with paging, delete, multipart (complete + abort).
TEST_F(LiveR2, DataPlaneRoundTrip) {
    auto& data = controller();
    const std::string body = "hello, live r2: the quick brown fox";
    const auto k = key("a/hello.txt");
    data.uploadBufferWithMetadata(k, bytes(body),
                                  std::unordered_map<std::string, std::string>{{"vh-iv", "aXYtMTI="}, {"content-hash", "h1"}});
    const auto unicode = key("unicode \xE2\x80\xAF n\xC3\xA4me.txt");
    data.uploadBufferWithMetadata(unicode, bytes("u"), std::unordered_map<std::string, std::string>{});

    std::vector<uint8_t> got;
    data.downloadToBuffer(k, got);
    EXPECT_EQ(std::string(got.begin(), got.end()), body);
    got.clear();
    data.downloadToBuffer(unicode, got);
    EXPECT_EQ(std::string(got.begin(), got.end()), "u");

    storage::s3::GetObjectOptions range;
    range.range = std::pair<uint64_t, uint64_t>{7, 13};
    std::string ranged;
    const auto r = data.streamObject(k, range, [&](const std::span<const uint8_t> chunk) { ranged.append(chunk.begin(), chunk.end()); });
    EXPECT_EQ(r.http_status, 206);
    EXPECT_EQ(ranged, body.substr(7, 7));

    const auto head = data.getHeadObject(k);
    ASSERT_TRUE(head.has_value());
    EXPECT_EQ(header(*head, "x-amz-meta-vh-iv"), std::optional<std::string>("aXYtMTI="));
    EXPECT_EQ(header(*head, "content-length"), std::optional<std::string>(std::to_string(body.size())));

    // Paging: pages of 2 over the bucket (only this test's keys are in it now), every page signed.
    std::set<std::string> expected{k, unicode};
    for (int i = 0; i < 4; ++i) {
        const auto p = key("page/" + std::to_string(i));
        data.uploadBufferWithMetadata(p, bytes("p"), std::unordered_map<std::string, std::string>{});
        expected.insert(p);
    }
    std::set<std::string> seen;
    std::string token;
    int pages = 0;
    do {
        const auto page = data.listObjectKeysPage(token, 2);
        ++pages;
        seen.insert(page.keys.begin(), page.keys.end());
        token = page.next_continuation_token;
    } while (!token.empty() && pages < 50);
    EXPECT_GE(pages, 3);
    for (const auto& e : expected) EXPECT_TRUE(seen.contains(e)) << e;
    const auto xml = data.listObjects(key("page/"));
    const std::string raw(reinterpret_cast<const char*>(xml.data()), xml.size());
    std::size_t listed = 0;
    for (auto pos = raw.find("<Key>"); pos != std::string::npos; pos = raw.find("<Key>", pos + 1)) ++listed;
    EXPECT_EQ(listed, 4u);

    data.deleteObject(k);
    EXPECT_FALSE(data.getHeadObject(k).has_value());

    // Multipart: two 5 MiB parts and a tail, completed; another one aborted.
    std::vector<uint8_t> big(11 * 1024 * 1024);
    for (std::size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i * 31 + 7);
    data.uploadLargeObject(key("mp.bin"), big, storage::s3::Controller::MIN_PART_SIZE);
    got.clear();
    data.downloadToBuffer(key("mp.bin"), got);
    EXPECT_EQ(got.size(), big.size());
    EXPECT_TRUE(got == big);
    const auto uploadId = data.initiateMultipartUpload(key("aborted.bin"));
    std::string etag;
    data.uploadPart(key("aborted.bin"), uploadId, 1, std::string(storage::s3::Controller::MIN_PART_SIZE, 'z'), etag);
    data.abortMultipartUpload(key("aborted.bin"), uploadId);
    EXPECT_TRUE(admin().uploadsUnder(bucket(), prefix()).empty());
}

// Per-test cleanup removes objects AND unfinished multipart uploads (what a failed test leaves behind).
TEST_F(LiveR2, CleanupRemovesObjectsAndOpenUploads) {
    auto& data = controller();
    data.uploadBufferWithMetadata(key("x/1"), bytes("1"), std::unordered_map<std::string, std::string>{});
    data.uploadBufferWithMetadata(key("x/2"), bytes("2"), std::unordered_map<std::string, std::string>{});
    ASSERT_FALSE(data.initiateMultipartUpload(key("open.bin")).empty());
    ASSERT_EQ(admin().objectsUnder(bucket(), prefix()).size(), 2u);
    ASSERT_EQ(admin().uploadsUnder(bucket(), prefix()).size(), 1u);
    EXPECT_EQ(live::emptyUnder(admin(), apiKey(), bucket(), prefix()), 3u);
    EXPECT_TRUE(admin().objectsUnder(bucket(), prefix()).empty());
    EXPECT_TRUE(admin().uploadsUnder(bucket(), prefix()).empty());
}

// Event notifications on the run's bucket (Cloudflare Queues: needs VH_CF_API_TOKEN): a queue named like the bucket,
// a rule on this test's prefix, an upload seen within 120 s; rule and queue removed again, even on failure.
TEST_F(LiveR2, EventNotificationsOnTheRunBucket) {
    if (liveTarget().token.empty())
        GTEST_SKIP() << "VH_CF_API_TOKEN not set: R2 event notifications need a Cloudflare API token "
                        "(Queues: Edit, Workers R2 Storage: Edit)";
    auto events = live::guardedEvents(apiKey());
    std::optional<padmin::ChannelRef> channel;
    std::vector<std::string> ruleIds;
    const padmin::SubscriptionSpec spec{.bucket = bucket(), .rule_id = "vaulthalla-live-1", .prefix = prefix()};
    // The queue (and its <queue>-dlq) is named like the run bucket: vh-test-<host>-<pid>-<start>.
    const padmin::ChannelSpec channelSpec{.account_ref = admin().identity().account_ref, .region = "",
                                          .queue_name = bucket(), .retention_seconds = 3600,
                                          .visibility_timeout_seconds = 30, .max_receive_count = 3};
    struct Teardown {
        std::function<void()> fn;
        ~Teardown() {
            try {
                fn();
            } catch (const std::exception& e) {
                ADD_FAILURE() << "[live] events teardown: " << e.what();
            }
        }
    } teardown{[&] {
        // Rules first (R2 refuses to delete a queue a rule targets), then both queues BY NAME: ensureChannel or
        // subscribe may have failed after creating them, and the Queues listing lags, so nothing here relies on the
        // ChannelRef. The run bucket's environment teardown repeats both as a safety net.
        live::removeEventRules(*events, bucket());
        live::QueueAdmin(apiKey()).removeUntilGone({bucket(), bucket() + "-dlq"});
        std::cout << "[live] removed queues " << bucket() << " and " << bucket() << "-dlq" << std::endl;
    }};
    channel = events->ensureChannel(channelSpec);
    ruleIds = events->subscribe(*channel, spec);
    ASSERT_FALSE(ruleIds.empty());
    // A new rule takes effect a little after R2 lists it (seen live: an upload right after subscribe produced no
    // event), so upload a fresh object every 15 s until one is delivered.
    bool seen = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{120};
    auto nextUpload = std::chrono::steady_clock::now();
    int uploads = 0, notPullable = 0;
    while (!seen && std::chrono::steady_clock::now() < deadline) {
        if (std::chrono::steady_clock::now() >= nextUpload) {
            controller().uploadBufferWithMetadata(key("events/hello-" + std::to_string(uploads++) + ".txt"), bytes("hi"),
                                                  std::unordered_map<std::string, std::string>{});
            nextUpload = std::chrono::steady_clock::now() + std::chrono::seconds{15};
        }
        padmin::PollResult result;
        try {
            result = events->poll(*channel, 10, std::chrono::seconds{10}, std::chrono::seconds{30});
        } catch (const padmin::ProviderError& e) {
            // Seen live: a pull right after the http_pull consumer was added answers 405 "http_pull mode not enabled",
            // and Cloudflare answers the odd 504 (7009 "Upstream service unavailable"). Both pass; retry until the deadline.
            if (e.http_status != 405 && e.http_status < 500) throw;
            if (notPullable++ == 0) std::cout << "[live] pull not answered yet: " << e.what() << std::endl;
            std::this_thread::sleep_for(std::chrono::seconds{3});
            continue;
        }
        std::vector<std::string> receipts;
        for (const auto& m : result.messages) {
            receipts.push_back(m.receipt);
            if (m.body.find("events/hello-") != std::string::npos) seen = true;
        }
        if (!receipts.empty()) events->ack(*channel, receipts);
    }
    EXPECT_TRUE(seen) << "no event for " << uploads << " upload(s) within 120 s (" << notPullable
                      << " pull(s) answered 405/5xx)";
    std::cout << "[live] event delivered after " << uploads << " upload(s)" << std::endl;
}

// ---- opaque_v1 on R2 (#369, design/encryption/01 §5, §8) ------------------------------------------------------------

// The opaque_v1 data plane against the run bucket: o/<uid> objects (at the bucket root, which the run bucket's
// deletion empties), sent under the controller's opaque_v1 request rules. Each object carries no x-amz-meta-*, is
// application/octet-stream and exactly its VHF1 size; the requests are what spec 01 §5 says (1 PUT per small object,
// initiate + parts + complete for a multipart one, 1 GET per read, no HEAD for metadata).
TEST_F(LiveR2, OpaqueObjectsCarryNoMetadataAndCostWhatSpec01Says) {
    ASSERT_GE(sodium_init(), 0);
    constexpr unsigned kVault = 990'369;
    constexpr unsigned kKeyVersion = 1;
    std::vector<uint8_t> vaultKey(32);
    randombytes_buf(vaultKey.data(), vaultKey.size());
    const auto em = std::make_shared<vault::EncryptionManager>(vault::EncryptionManager::ForTesting{}, kVault, vaultKey,
                                                               kKeyVersion);
    auto s3 = std::make_shared<vault::model::S3Vault>();
    s3->id = kVault;
    s3->encrypt_upstream = true;
    s3->storage_layout = vault::model::StorageLayout::OpaqueV1;
    const auto cloud = std::make_shared<storage::CloudEngine>();
    cloud->vault = s3;
    cloud->encryptionManager = em;
    const auto data = sharedController();
    cloud->setS3ControllerForTesting(data);
    ASSERT_TRUE(data->opaqueLayout());

    const auto dir = std::filesystem::temp_directory_path() / ("vh_live_opaque_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    std::mt19937 rng(369);
    struct Case {
        std::shared_ptr<fs::model::File> file;
        std::vector<uint8_t> plaintext;
        uint64_t puts;
    };
    std::vector<Case> cases;
    unsigned id = 0;
    for (const auto& [size, puts] : {std::pair<std::size_t, uint64_t>{0, 1}, {300 * 1024, 1}, {11 * 1024 * 1024, 1 + 3 + 1}}) {
        Case c;
        c.plaintext.resize(size);
        for (auto& b : c.plaintext) b = static_cast<uint8_t>(rng());
        c.puts = puts;
        c.file = std::make_shared<fs::model::File>();
        c.file->id = ++id;
        c.file->vault_id = kVault;
        c.file->path = "/live-" + std::to_string(id);
        c.file->object_uid = crypto::id::newObjectUid();
        c.file->backing_path = dir / std::to_string(id);
        c.file->size_bytes = size;
        c.file->content_hash = "live";
        std::ofstream out(c.file->backing_path, std::ios::binary | std::ios::trunc);
        if (size > 0) {
            const auto sealed = em->encrypt(c.plaintext, c.file);
            out.write(reinterpret_cast<const char*>(sealed.data()), static_cast<std::streamsize>(sealed.size()));
        }
        out.close();
        cases.push_back(std::move(c));
    }

    std::vector<std::string> written;
    try {
        for (auto& c : cases) {
            data->resetRequestMetrics();
            cloud->upload(c.file);
            const auto key = storage::object_keys::contentKey(*c.file->object_uid);
            written.push_back(key);
            const auto m = data->requestMetrics();
            EXPECT_EQ(m.put_requests, c.puts) << key;
            EXPECT_EQ(m.head_requests + m.get_requests + m.list_requests + m.copy_requests + m.delete_requests, 0u);
            EXPECT_TRUE(c.file->remote_etag) << "the PUT's ETag, for the index and the manifest";
        }
        for (const auto& c : cases) {
            const auto key = storage::object_keys::contentKey(*c.file->object_uid);
            const auto head = data->getHeadObject(key);
            ASSERT_TRUE(head) << key;
            for (const auto& [name, value] : *head) {
                std::string lower = name;
                std::ranges::transform(lower, lower.begin(), [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                EXPECT_FALSE(lower.starts_with("x-amz-meta-")) << key << ": " << name;
                if (lower == "content-type") {
                    EXPECT_EQ(value, "application/octet-stream") << key;
                }
                if (lower == "content-length") {
                    EXPECT_EQ(value, std::to_string(vault::content::newSealedSize(c.plaintext.size()))) << key;
                }
            }
            data->resetRequestMetrics();
            std::vector<uint8_t> payload;
            data->downloadToBuffer(key, payload);
            auto remote = std::make_shared<fs::model::File>(*c.file);
            if (c.plaintext.empty()) {
                remote->encryption_iv.clear();   // the empty file's object: its header names the generation
                remote->encrypted_with_key_version = 0;
            }
            EXPECT_EQ(cloud->decryptRemotePayload(c.file->path, payload, remote,
                                                  {/*trustFileEncryptionMetadata=*/true, /*allowLocalDbRecovery=*/false}),
                      c.plaintext);
            const auto m = data->requestMetrics();
            EXPECT_EQ(m.get_requests, 1u);
            EXPECT_EQ(m.head_requests, 0u);
        }
        // A name never goes up: the controller refuses it before sending.
        EXPECT_THROW(data->uploadBufferWithMetadata(key("not-allowed.txt"), {1, 2, 3}, storage::s3::RequestOptions{}),
                     storage::s3::OpaqueRequestRefused);
    } catch (...) {
        for (const auto& k : written) data->deleteObject(k);
        std::filesystem::remove_all(dir);
        throw;
    }
    for (const auto& k : written) {
        data->deleteObject(k);
        EXPECT_FALSE(data->getHeadObject(k)) << k;
    }
    std::filesystem::remove_all(dir);
}

// The bucket layout migration's provider assumptions on real R2 (#373): a strict ListObjectsV2 page names each
// object's ETag and size; a re-sealed object PUT without metadata gets the ETag the migration predicts (the MD5 of a
// single PUT, the multipart MD5 of its parts), so no read-back is needed on R2; and once the vault is opaque_v1 its
// controller refuses every legacy key except the cleanup's HEAD and DELETE inside ScopedLegacyLayoutCleanup, never a
// PUT. Everything written is deleted again (and the run bucket with it).
TEST_F(LiveR2, LayoutMigrationPrimitives) {
    ASSERT_GE(sodium_init(), 0);
    constexpr unsigned kVault = 990'373;
    std::vector<uint8_t> vaultKey(32);
    randombytes_buf(vaultKey.data(), vaultKey.size());
    const auto em = std::make_shared<vault::EncryptionManager>(vault::EncryptionManager::ForTesting{}, kVault, vaultKey, 1u);
    auto s3 = std::make_shared<vault::model::S3Vault>();
    s3->id = kVault;
    s3->encrypt_upstream = true;
    s3->storage_layout = vault::model::StorageLayout::PathV0;
    const auto cloud = std::make_shared<storage::CloudEngine>();
    cloud->vault = s3;
    cloud->encryptionManager = em;
    const auto data = sharedController();
    cloud->setS3ControllerForTesting(data);
    ASSERT_FALSE(data->opaqueLayout()) << "path_v0 until the cutover";

    const auto dir = std::filesystem::temp_directory_path() / ("vh_live_layout_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    const std::string legacyKey = "lm-legacy/report 2026.txt";
    std::vector<std::string> written;
    try {
        // A path_v0 object: the path as its key, the encryption metadata on it.
        const std::vector<uint8_t> legacyBody(4321, 0x5a);
        data->uploadBufferWithMetadata(legacyKey, legacyBody,
                                       storage::s3::RequestOptions{.system_headers = {},
                                                                   .metadata = {{"vh-encrypted", "true"},
                                                                                {"vh-iv", "AAAAAAAAAAAAAAAA"},
                                                                                {"vh-key-version", "1"}}});
        written.push_back(legacyKey);
        bool listed = false;
        std::string token;
        do {
            const auto page = data->listObjectKeysPage(token, 1000);
            ASSERT_EQ(page.keys.size(), page.objects.size());
            for (const auto& o : page.objects)
                if (o.key == legacyKey) {
                    listed = true;
                    EXPECT_EQ(o.size, legacyBody.size());
                    EXPECT_FALSE(o.etag.empty());
                    EXPECT_TRUE(o.last_modified);
                }
            token = page.next_continuation_token;
        } while (!token.empty());
        EXPECT_TRUE(listed) << "the strict listing carries the inventory's fields";

        // Re-sealed objects (single PUT and multipart): no metadata, and the ETag the migration predicts.
        std::mt19937 rng(373);
        for (const std::size_t size : {std::size_t{300 * 1024}, std::size_t{11 * 1024 * 1024}}) {
            std::vector<uint8_t> plain(size);
            for (auto& b : plain) b = static_cast<uint8_t>(rng());
            const auto uid = crypto::id::newObjectUid();
            const auto sealed = vault::content::sealBuffer(plain, *em->keySnapshot(1), 1, em->vaultUid(), uid);
            const auto path = dir / ("o-" + std::to_string(size));
            {
                std::ofstream out(path, std::ios::binary | std::ios::trunc);
                out.write(reinterpret_cast<const char*>(sealed.bytes.data()), static_cast<std::streamsize>(sealed.bytes.size()));
            }
            auto generation = std::make_shared<fs::model::File>();
            generation->object_uid = uid;
            generation->encryption_iv = sealed.generation;
            generation->encrypted_with_key_version = 1;
            generation->size_bytes = size;
            const auto key = storage::object_keys::contentKey(uid);
            const auto put = cloud->putMigratedObject(key, path, sealed.bytes.size(), generation);
            written.push_back(key);
            std::string etag = put.etag;
            if (etag.size() >= 2 && etag.front() == '"') etag = etag.substr(1, etag.size() - 2);
            EXPECT_EQ(etag, vault::layout::s3EtagOf(path, sealed.bytes.size()))
                << "R2's ETag is the predicted MD5: the migration needs no read-back here (" << size << " bytes)";
            const auto head = data->getHeadObject(key);
            ASSERT_TRUE(head);
            for (const auto& [name, value] : *head) {
                std::string lower = name;
                std::ranges::transform(lower, lower.begin(), [](const unsigned char ch) { return static_cast<char>(std::tolower(ch)); });
                EXPECT_FALSE(lower.starts_with("x-amz-meta-")) << key << ": " << name;
            }
        }

        // The cutover: the controller holds the opaque_v1 rules; the cleanup reaches legacy keys inside its scope only.
        data->setOpaqueLayout(true);
        EXPECT_THROW((void)data->getHeadObject(legacyKey), storage::s3::OpaqueRequestRefused);
        EXPECT_THROW(data->deleteObject(legacyKey), storage::s3::OpaqueRequestRefused);
        {
            const storage::s3::ScopedLegacyLayoutCleanup scope;
            EXPECT_TRUE(data->getHeadObject(legacyKey));
            EXPECT_THROW(data->uploadBufferWithMetadata(legacyKey, legacyBody, storage::s3::RequestOptions{}),
                         storage::s3::OpaqueRequestRefused)
                << "never a write to a legacy key";
            data->deleteObject(legacyKey);
            EXPECT_FALSE(data->getHeadObject(legacyKey)) << "deleted by its key (R2 keeps no versions)";
        }
        written.erase(written.begin());
        data->setOpaqueLayout(false);
    } catch (...) {
        data->setOpaqueLayout(false);
        for (const auto& k : written) data->deleteObject(k);
        std::filesystem::remove_all(dir);
        throw;
    }
    for (const auto& k : written) data->deleteObject(k);
    std::filesystem::remove_all(dir);
}

}
