// Live provider checks for the upstream admin/events adapters (#237, #96). Never part of CI: every test skips unless
// VH_LIVE_UPSTREAM=1. They create ONLY buckets/queues named vaulthalla-test-<unix time>-<random> and remove them again,
// even on failure. Nothing else in the accounts is read at object level, changed or deleted.
//
//   AWS:  VH_AWS_ADMIN_API_KEY, VH_AWS_ADMIN_SECRET_KEY            (buckets in us-east-2)
//   R2:   VH_R2_ADMIN_ACCESS_KEY, VH_R2_ADMIN_SECRET_KEY, VH_R2_ADMIN_ENDPOINT, optional VH_CF_API_TOKEN (events)
//
// Run: (set -a; . ./.bashrc; VH_LIVE_UPSTREAM=1 build/core/vh_unit_tests --gtest_filter='UpstreamLive*')
// Versioning: UpstreamLive.AwsVersioning (a new bucket: unversioned → enabled → retention rule → suspended).

#include "storage/s3/Controller.hpp"
#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Lifecycle.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <random>
#include <thread>

namespace {

namespace admin = vh::storage::s3::provider::admin;
using vh::vault::model::APIKey;
using vh::vault::model::S3Provider;

std::string liveEnv(const char* name) {
    const auto* v = std::getenv(name);
    return v ? std::string(v) : std::string{};
}

bool liveEnabled() { return liveEnv("VH_LIVE_UPSTREAM") == "1"; }

std::string liveTestName(const std::string& suffix = {}) {
    std::mt19937_64 rng(std::random_device{}());
    char rand[9];
    std::snprintf(rand, sizeof(rand), "%08x", static_cast<unsigned int>(rng()));
    return "vaulthalla-test-" + std::to_string(std::time(nullptr)) + "-" + rand + suffix;
}

struct LiveCleanup {
    std::function<void()> fn;
    ~LiveCleanup() {
        try {
            if (fn) fn();
        } catch (const std::exception& e) {
            std::cerr << "[live cleanup] " << e.what() << std::endl;
            ADD_FAILURE() << "cleanup failed: " << e.what();
        }
    }
};

// Empties and deletes a test bucket (all versions). Refuses any name that isn't ours.
void liveDestroyTestBucket(admin::AdminClient& client, const std::string& bucket) {
    if (!bucket.starts_with("vaulthalla-test-")) throw std::logic_error("refusing to delete a non-test bucket");
    if (!client.headBucket(bucket)) return;
    for (int round = 0; round < 20; ++round) {
        const auto page = client.listObjectVersions(bucket, {}, 1000);
        if (page.objects.empty()) break;
        const auto failed = client.deleteObjects(bucket, page.objects);
        if (!failed.empty()) throw std::runtime_error("could not delete " + std::to_string(failed.size()) + " test object(s)");
    }
    client.deleteBucket(bucket);
    std::cout << "[live] deleted " << bucket << std::endl;
}

std::vector<admin::LifecycleRule> liveForeignRule() {
    return admin::detail::parseLifecycle(R"(<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Rule><ID>other-app-expire-tmp</ID><Filter><Prefix>tmp/</Prefix></Filter><Status>Enabled</Status>
      <Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>)");
}

void liveExerciseBucket(admin::AdminClient& client, const std::shared_ptr<APIKey>& key,
                        const std::optional<std::string>& region, const bool versioned) {
    const auto bucket = liveTestName();
    std::cout << "[live] " << client.providerId() << " test bucket " << bucket << std::endl;
    LiveCleanup cleanup{[&] { liveDestroyTestBucket(client, bucket); }};

    ASSERT_EQ(client.headBucket(bucket), std::nullopt);
    client.createBucket({.name = bucket, .region = region});
    ASSERT_TRUE(client.headBucket(bucket).has_value());

    // A second create of the same name is a non-destructive collision.
    try {
        client.createBucket({.name = bucket, .region = region});
        // AWS us-east-1 would answer 200 here; outside it, and on R2, the provider refuses.
        ADD_FAILURE() << "second CreateBucket of the same name succeeded";
    } catch (const admin::ProviderError& e) {
        std::cout << "[live] collision code: " << e.code << " (HTTP " << e.http_status << ")" << std::endl;
        EXPECT_EQ(e.http_status, 409);
        EXPECT_TRUE(e.code == "BucketAlreadyOwnedByYou" || e.code == "BucketAlreadyExists") << e.code;
    }
    EXPECT_TRUE(client.listObjects(bucket, {}, 1).objects.empty());

    auto config = client.inspect(bucket);
    for (const auto& w : config.warnings) std::cout << "[live] inspect warning: " << w << std::endl;
    if (versioned) {
        EXPECT_EQ(config.versioning, admin::Versioning::Unversioned);
    }
    // Whatever the provider put on a new bucket (R2 adds a default multipart-abort rule) is someone else's.
    const auto baseline = config.lifecycle;
    for (const auto& r : baseline) {
        std::cout << "[live] provider default lifecycle rule: '" << r.id << "'" << std::endl;
        EXPECT_TRUE(r.foreign);
    }
    const auto findRule = [](const std::vector<admin::LifecycleRule>& rules, const std::string& id) {
        return std::ranges::find_if(rules, [&](const auto& r) { return r.id == id; });
    };

    // Lifecycle: our rule next to foreign ones; then ours removed, theirs kept verbatim.
    auto rules = baseline;
    const auto other = liveForeignRule();
    rules.insert(rules.end(), other.begin(), other.end());
    admin::LifecycleRule ours;
    ours.id = "vaulthalla-managed";
    ours.abort_incomplete_multipart_days = 2;
    rules.push_back(ours);
    client.putLifecycle(bucket, rules);
    config = client.inspect(bucket);
    ASSERT_EQ(config.lifecycle.size(), baseline.size() + 2);
    const auto foreign = findRule(config.lifecycle, "other-app-expire-tmp");
    ASSERT_NE(foreign, config.lifecycle.end());
    EXPECT_TRUE(foreign->foreign);
    EXPECT_EQ(foreign->expire_current_days, std::optional<unsigned int>(30));
    const auto mine = findRule(config.lifecycle, "vaulthalla-managed");
    ASSERT_NE(mine, config.lifecycle.end());
    EXPECT_FALSE(mine->foreign);
    EXPECT_EQ(mine->abort_incomplete_multipart_days, std::optional<unsigned int>(2));
    for (const auto& b : baseline) {
        const auto kept = findRule(config.lifecycle, b.id);
        ASSERT_NE(kept, config.lifecycle.end()) << b.id;
        EXPECT_EQ(kept->abort_incomplete_multipart_days, b.abort_incomplete_multipart_days);
        EXPECT_EQ(kept->expire_current_days, b.expire_current_days);
    }

    auto withoutOurs = baseline;
    withoutOurs.push_back(*foreign);
    client.putLifecycle(bucket, withoutOurs);
    config = client.inspect(bucket);
    ASSERT_EQ(config.lifecycle.size(), baseline.size() + 1);
    EXPECT_EQ(findRule(config.lifecycle, "vaulthalla-managed"), config.lifecycle.end());
    EXPECT_NE(findRule(config.lifecycle, "other-app-expire-tmp"), config.lifecycle.end());
    client.putLifecycle(bucket, baseline);
    EXPECT_EQ(client.inspect(bucket).lifecycle.size(), baseline.size());

    // Objects (written through the vault data path) list and batch-delete.
    vh::storage::s3::Controller data(key, bucket);
    data.uploadBufferWithMetadata("a/one.txt", std::vector<uint8_t>{'1'}, std::unordered_map<std::string, std::string>{});
    data.uploadBufferWithMetadata("two.txt", std::vector<uint8_t>{'2', '2'}, std::unordered_map<std::string, std::string>{});
    const auto listed = client.listObjects(bucket, {}, 1000);
    ASSERT_EQ(listed.objects.size(), 2u);
    EXPECT_TRUE(client.deleteObjects(bucket, client.listObjectVersions(bucket, {}, 1000).objects).empty());
    EXPECT_TRUE(client.listObjects(bucket, {}, 1000).objects.empty());

    // Protection: once locked, nothing bucket-scoped goes out.
    vh::storage::upstream::guard::setForTesting(
        {{.provider = admin::providerIdentity(key->provider), .account_ref = client.identity().account_ref, .bucket = bucket}});
    EXPECT_THROW((void)client.inspect(bucket), vh::storage::upstream::BucketProtected);
    EXPECT_THROW(data.uploadBufferWithMetadata("x", std::vector<uint8_t>{'x'}, std::unordered_map<std::string, std::string>{}), vh::storage::upstream::BucketProtected);
    vh::storage::upstream::guard::clearForTesting();
}

std::shared_ptr<APIKey> liveAwsKey() {
    return std::make_shared<APIKey>(0, "live-aws", S3Provider::AWS, liveEnv("VH_AWS_ADMIN_API_KEY"),
                                    liveEnv("VH_AWS_ADMIN_SECRET_KEY"), "us-east-2", "https://s3.us-east-2.amazonaws.com");
}

std::shared_ptr<APIKey> liveR2Key() {
    auto key = std::make_shared<APIKey>(0, "live-r2", S3Provider::CloudflareR2, liveEnv("VH_R2_ADMIN_ACCESS_KEY"),
                                        liveEnv("VH_R2_ADMIN_SECRET_KEY"), "auto", liveEnv("VH_R2_ADMIN_ENDPOINT"));
    key->provider_token = liveEnv("VH_CF_API_TOKEN");
    return key;
}

void livePrintCapabilities(const admin::Capabilities& caps) {
    for (const auto& c : caps.items)
        std::cout << "[live] capability " << c.name << ": " << (c.ok ? "ok" : "MISSING") << (c.probed ? "" : " (not probed)")
                  << (c.detail.empty() ? "" : " - " + c.detail) << std::endl;
}

}

TEST(UpstreamLive, AwsBuckets) {
    if (!liveEnabled()) GTEST_SKIP() << "set VH_LIVE_UPSTREAM=1 to run live provider tests";
    if (liveEnv("VH_AWS_ADMIN_API_KEY").empty()) GTEST_SKIP() << "VH_AWS_ADMIN_* not set";
    const auto key = liveAwsKey();
    admin::AwsAdmin aws(key);
    const auto id = aws.identity();
    EXPECT_EQ(id.account_ref.size(), 12u);
    key->provider_account_id = id.account_ref;
    livePrintCapabilities(aws.probe());
    EXPECT_FALSE(aws.listBuckets({}, 1000).buckets.empty());
    liveExerciseBucket(aws, key, std::string("us-east-2"), true);
}

TEST(UpstreamLive, R2Buckets) {
    if (!liveEnabled()) GTEST_SKIP() << "set VH_LIVE_UPSTREAM=1 to run live provider tests";
    if (liveEnv("VH_R2_ADMIN_ACCESS_KEY").empty()) GTEST_SKIP() << "VH_R2_ADMIN_* not set";
    const auto key = liveR2Key();
    admin::R2Admin r2(key);
    EXPECT_EQ(r2.identity().account_ref.size(), 32u);
    livePrintCapabilities(r2.probe());
    EXPECT_FALSE(r2.listBuckets({}, 1000).buckets.empty());
    liveExerciseBucket(r2, key, std::nullopt, false);

    // R2 has no object versioning: refused locally, nothing is sent (the name is a fresh test name, never created).
    EXPECT_FALSE(r2.supportsVersioning());
    const auto before = r2.metrics().requests;
    EXPECT_THROW(r2.putVersioning(liveTestName(), admin::Versioning::Enabled), admin::CapabilityMissing);
    EXPECT_EQ(r2.versioning(liveTestName()).status, admin::Versioning::Unversioned);
    EXPECT_EQ(r2.metrics().requests, before);
}

namespace {

// Re-reads GetBucketVersioning until it says `want` (AWS applies a change eventually). Returns the reads it took.
int liveAwaitVersioning(admin::AdminClient& client, const std::string& bucket, const admin::Versioning want,
                        const std::chrono::seconds limit) {
    const auto start = std::chrono::steady_clock::now();
    int reads = 0;
    for (;;) {
        ++reads;
        if (client.versioning(bucket).status == want) {
            std::cout << "[live] versioning settled after " << reads << " read(s), "
                      << std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count()
                      << " ms" << std::endl;
            return reads;
        }
        if (std::chrono::steady_clock::now() - start > limit) return -1;
        std::this_thread::sleep_for(std::chrono::seconds{2});
    }
}

}

// Provider versioning on a NEW test bucket only: unversioned → enabled → retention lifecycle next to a foreign
// noncurrent rule → versions listed → suspended; cleanup deletes every version and the bucket.
TEST(UpstreamLive, AwsVersioning) {
    if (!liveEnabled()) GTEST_SKIP() << "set VH_LIVE_UPSTREAM=1 to run live provider tests";
    if (liveEnv("VH_AWS_ADMIN_API_KEY").empty()) GTEST_SKIP() << "VH_AWS_ADMIN_* not set";
    const auto key = liveAwsKey();
    admin::AwsAdmin aws(key);
    key->provider_account_id = aws.identity().account_ref;
    ASSERT_TRUE(aws.supportsVersioning());

    const auto bucket = liveTestName();
    std::cout << "[live] aws-s3 versioning test bucket " << bucket << std::endl;
    LiveCleanup cleanup{[&] { liveDestroyTestBucket(aws, bucket); }};
    ASSERT_EQ(aws.headBucket(bucket), std::nullopt);
    aws.createBucket({.name = bucket, .region = std::string("us-east-2")});

    const auto initial = aws.versioning(bucket);
    EXPECT_EQ(initial.status, admin::Versioning::Unversioned);
    EXPECT_EQ(initial.mfa_delete, std::nullopt);

    aws.putVersioning(bucket, admin::Versioning::Enabled);
    ASSERT_GT(liveAwaitVersioning(aws, bucket, admin::Versioning::Enabled, std::chrono::seconds{60}), 0)
        << "versioning not Enabled within 60 s";
    const auto config = aws.inspect(bucket);
    for (const auto& w : config.warnings) std::cout << "[live] inspect warning: " << w << std::endl;
    EXPECT_EQ(config.versioning, admin::Versioning::Enabled);
    EXPECT_NE(config.mfa_delete, std::optional<bool>(true));

    // Retention: a foreign noncurrent rule (with NewerNoncurrentVersions, outside our model) and our owned rule.
    auto rules = config.lifecycle;
    const auto foreign = admin::detail::parseLifecycle(R"(<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Rule><ID>other-app-noncurrent</ID><Filter><Prefix>other/</Prefix></Filter><Status>Enabled</Status>
      <NoncurrentVersionExpiration><NoncurrentDays>7</NoncurrentDays><NewerNoncurrentVersions>2</NewerNoncurrentVersions></NoncurrentVersionExpiration>
      </Rule></LifecycleConfiguration>)");
    rules.insert(rules.end(), foreign.begin(), foreign.end());
    aws.putLifecycle(bucket, rules);
    const auto withForeign = aws.inspect(bucket).lifecycle;
    const auto findRule = [](const std::vector<admin::LifecycleRule>& rs, const std::string& id) {
        return std::ranges::find_if(rs, [&](const auto& r) { return r.id == id; });
    };
    const auto theirs = findRule(withForeign, "other-app-noncurrent");
    ASSERT_NE(theirs, withForeign.end());
    EXPECT_TRUE(theirs->foreign);

    const auto merged = vh::storage::upstream::lifecycle::mergeOwnedRule(withForeign, {.expire_noncurrent_days = 30}, true);
    EXPECT_TRUE(merged.destructive);
    aws.putLifecycle(bucket, merged.rules);
    const auto after = aws.inspect(bucket).lifecycle;
    ASSERT_EQ(after.size(), withForeign.size() + 1);
    const auto theirsAfter = findRule(after, "other-app-noncurrent");
    ASSERT_NE(theirsAfter, after.end());
    EXPECT_EQ(theirsAfter->raw_xml, theirs->raw_xml) << "the foreign rule must round-trip unchanged";
    const auto ours = findRule(after, "vaulthalla-managed");
    ASSERT_NE(ours, after.end());
    EXPECT_FALSE(ours->foreign);
    EXPECT_EQ(ours->expire_noncurrent_days, std::optional<unsigned int>(30));
    EXPECT_EQ(vh::storage::upstream::lifecycle::effectiveNoncurrentDays(after, "vault/"), std::optional<unsigned int>(30));
    EXPECT_EQ(vh::storage::upstream::lifecycle::effectiveNoncurrentDays(after, "other/x/"), std::optional<unsigned int>(7));

    // Two writes of one key are two versions.
    vh::storage::s3::Controller data(key, bucket);
    data.uploadBufferWithMetadata("v/one.txt", std::vector<uint8_t>{'1'}, std::unordered_map<std::string, std::string>{});
    data.uploadBufferWithMetadata("v/one.txt", std::vector<uint8_t>{'2', '2'}, std::unordered_map<std::string, std::string>{});
    const auto versions = aws.listObjectVersions(bucket, {}, 1000).objects;
    EXPECT_EQ(versions.size(), 2u);
    EXPECT_EQ(std::ranges::count_if(versions, [](const auto& o) { return o.latest; }), 1);
    for (const auto& v : versions) EXPECT_TRUE(v.version_id && !v.version_id->empty() && *v.version_id != "null");

    aws.putVersioning(bucket, admin::Versioning::Suspended);
    EXPECT_GT(liveAwaitVersioning(aws, bucket, admin::Versioning::Suspended, std::chrono::seconds{60}), 0)
        << "versioning not Suspended within 60 s";
    EXPECT_THROW(aws.putVersioning(bucket, admin::Versioning::Unversioned), std::invalid_argument);
}

namespace {

// Bucket → queue → poll → ack → teardown, on a dedicated test bucket and test queue.
void liveExerciseEvents(admin::AdminClient& client, admin::EventsClient& events, const std::shared_ptr<APIKey>& key,
                        const std::string& region, const std::string& accountRef) {
    const auto bucket = liveTestName();
    const auto queue = liveTestName("-q");
    std::optional<admin::ChannelRef> channel;
    std::vector<std::string> ruleIds;
    const admin::SubscriptionSpec spec{.bucket = bucket, .rule_id = "vaulthalla-live-1", .prefix = ""};
    LiveCleanup cleanup{[&] {
        if (channel) {
            try {
                events.unsubscribe(*channel, spec, ruleIds);
            } catch (const std::exception& e) {
                std::cerr << "[live cleanup] unsubscribe: " << e.what() << std::endl;
            }
            events.removeChannel(*channel);
            std::cout << "[live] removed queue " << queue << std::endl;
        }
        liveDestroyTestBucket(client, bucket);
    }};

    client.createBucket({.name = bucket, .region = region.empty() ? std::nullopt : std::make_optional(region)});
    try {
        channel = events.ensureChannel({.account_ref = accountRef, .region = region, .queue_name = queue,
                                        .retention_seconds = 3600, .visibility_timeout_seconds = 30, .max_receive_count = 3});
    } catch (const admin::CapabilityMissing& e) {
        GTEST_SKIP() << "event provisioning not permitted for this credential: " << e.what();
    }
    std::cout << "[live] queue " << queue << (channel->created ? " created" : " reused") << std::endl;
    ruleIds = events.subscribe(*channel, spec);
    ASSERT_FALSE(ruleIds.empty());

    vh::storage::s3::Controller data(key, bucket);
    data.uploadBufferWithMetadata("events/hello.txt", std::vector<uint8_t>{'h', 'i'}, std::unordered_map<std::string, std::string>{});

    bool seen = false;
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds{120};
    while (!seen && std::chrono::steady_clock::now() < deadline) {
        const auto result = events.poll(*channel, 10, std::chrono::seconds{10}, std::chrono::seconds{30});
        std::vector<std::string> receipts;
        for (const auto& m : result.messages) {
            receipts.push_back(m.receipt);
            if (m.body.find("events/hello.txt") != std::string::npos) seen = true;
        }
        if (!receipts.empty()) events.ack(*channel, receipts);
        if (!seen) std::this_thread::sleep_for(std::chrono::seconds{2});
    }
    EXPECT_TRUE(seen) << "no event for the uploaded object within 120 s";
    data.deleteObject("events/hello.txt");
}

}

TEST(UpstreamLive, AwsEvents) {
    if (!liveEnabled()) GTEST_SKIP() << "set VH_LIVE_UPSTREAM=1 to run live provider tests";
    if (liveEnv("VH_AWS_ADMIN_API_KEY").empty()) GTEST_SKIP() << "VH_AWS_ADMIN_* not set";
    const auto key = liveAwsKey();
    admin::AwsAdmin aws(key);
    key->provider_account_id = aws.identity().account_ref;
    admin::AwsEvents events(key);
    liveExerciseEvents(aws, events, key, "us-east-2", *key->provider_account_id);
}

TEST(UpstreamLive, R2Events) {
    if (!liveEnabled()) GTEST_SKIP() << "set VH_LIVE_UPSTREAM=1 to run live provider tests";
    if (liveEnv("VH_R2_ADMIN_ACCESS_KEY").empty()) GTEST_SKIP() << "VH_R2_ADMIN_* not set";
    const auto key = liveR2Key();
    if (key->provider_token.empty())
        GTEST_SKIP() << "VH_CF_API_TOKEN not set: " << admin::kCloudflareTokenHint;
    admin::R2Admin r2(key);
    admin::R2Events events(key);
    liveExerciseEvents(r2, events, key, "", r2.identity().account_ref);
}
