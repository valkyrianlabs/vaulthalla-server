// Live provider checks for the upstream admin/events adapters (#237, #96). Never part of CI: every test skips unless
// VH_LIVE_UPSTREAM=1. They create ONLY buckets/queues named vaulthalla-test-<unix time>-<random> and remove them again,
// even on failure. Nothing else in the accounts is read at object level, changed or deleted.
//
//   AWS:  VH_AWS_ADMIN_API_KEY, VH_AWS_ADMIN_SECRET_KEY            (buckets in us-east-2)
//   R2:   VH_R2_ADMIN_ACCESS_KEY, VH_R2_ADMIN_SECRET_KEY, VH_R2_ADMIN_ENDPOINT, optional VH_CF_API_TOKEN (events)
//
// Run: (set -a; . ./.bashrc; VH_LIVE_UPSTREAM=1 build/core/vh_unit_tests --gtest_filter='UpstreamLive*')

#include "storage/s3/Controller.hpp"
#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <random>
#include <set>
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

// The legacy data-plane signer must sign the query in SigV4 order: page 2 of a ListObjectsV2 carries
// ?list-type=2&max-keys=…&continuation-token=…, which is out of order as written.
TEST(UpstreamLive, AwsDataPlaneListsBeyondOnePage) {
    if (!liveEnabled()) GTEST_SKIP() << "set VH_LIVE_UPSTREAM=1 to run live provider tests";
    if (liveEnv("VH_AWS_ADMIN_API_KEY").empty()) GTEST_SKIP() << "VH_AWS_ADMIN_* not set";
    const auto key = liveAwsKey();
    admin::AwsAdmin aws(key);
    const auto bucket = liveTestName();
    std::cout << "[live] aws data-plane listing bucket " << bucket << std::endl;
    LiveCleanup cleanup{[&] {
        // 1001 objects are worth a retry: a DNS blip during teardown must not strand the bucket.
        for (int attempt = 1;; ++attempt) {
            try {
                liveDestroyTestBucket(aws, bucket);
                return;
            } catch (const std::exception& e) {
                if (attempt == 5) throw;
                std::cerr << "[live cleanup] attempt " << attempt << ": " << e.what() << std::endl;
                std::this_thread::sleep_for(std::chrono::seconds{5});
            }
        }
    }};
    aws.createBucket({.name = bucket, .region = std::string("us-east-2")});

    constexpr int kObjects = 1001;   // one more than a full ListObjectsV2 page
    const auto keyName = [](const int i) {
        char name[32];
        std::snprintf(name, sizeof(name), "page/%04d.txt", i);
        return std::string(name);
    };
    std::set<std::string> expected;
    for (int i = 0; i < kObjects; ++i) expected.insert(keyName(i));

    std::atomic<int> next{0};
    std::atomic<int> failures{0};
    std::vector<std::thread> workers;
    for (int t = 0; t < 8; ++t)
        workers.emplace_back([&] {
            const vh::storage::s3::Controller data(key, bucket);
            for (int i = next++; i < kObjects; i = next++) {
                try {
                    data.uploadBufferWithMetadata(keyName(i), std::vector<uint8_t>{'x'},
                                                  std::unordered_map<std::string, std::string>{});
                } catch (const std::exception& e) {
                    if (failures++ == 0) std::cerr << "[live] upload " << keyName(i) << ": " << e.what() << std::endl;
                }
            }
        });
    for (auto& w : workers) w.join();
    ASSERT_EQ(failures.load(), 0);

    const vh::storage::s3::Controller data(key, bucket);

    // Paged listing: never partial, so a bad signature on page 2 throws.
    std::set<std::string> paged;
    std::string token;
    int pages = 0;
    try {
        do {
            auto page = data.listObjectKeysPage(token, 1000);
            ++pages;
            paged.insert(page.keys.begin(), page.keys.end());
            token = page.next_continuation_token;
        } while (!token.empty() && pages < 10);
    } catch (const std::exception& e) {
        ADD_FAILURE() << "listObjectKeysPage page " << pages + 1 << ": " << e.what();
    }
    EXPECT_EQ(pages, 2);
    EXPECT_EQ(paged.size(), expected.size());
    EXPECT_TRUE(paged == expected);

    // Legacy whole-bucket listing: concatenated ListObjectsV2 XML.
    const auto xml = data.listObjects();
    const std::string raw(reinterpret_cast<const char*>(xml.data()), xml.size());
    std::set<std::string> listed;
    for (auto pos = raw.find("<Key>"); pos != std::string::npos; pos = raw.find("<Key>", pos)) {
        pos += 5;
        listed.insert(raw.substr(pos, raw.find("</Key>", pos) - pos));
    }
    EXPECT_EQ(raw.find("<Error>"), std::string::npos) << raw.substr(raw.find("<Error>"), 512);
    EXPECT_EQ(listed.size(), expected.size()) << "listObjects keys";
    EXPECT_TRUE(listed == expected);
}
