// Provider-contract tests for the AWS S3 / Cloudflare R2 admin and events adapters (#237, #96), DB-free: every
// request goes through curl::http's test transport, which answers like the provider would and records what was sent.

#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/s3/curl/Http.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Lifecycle.hpp"
#include "storage/upstream/Names.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace {

namespace admin = vh::storage::s3::provider::admin;
namespace http = vh::storage::s3::curl::http;
namespace guard = vh::storage::upstream::guard;
using vh::vault::model::APIKey;
using vh::vault::model::S3Provider;

constexpr const char* kUpAwsSecret = "AwsSecretKeyValueForTests0123456789abcdef";
constexpr const char* kUpR2Secret = "r2secret0123456789abcdef0123456789abcdef0123456789abcdef01234567";
constexpr const char* kUpCfToken = "cfToken_SECRET_value_0123456789";
constexpr const char* kUpR2Account = "0123456789abcdef0123456789abcdef";

std::shared_ptr<APIKey> upAwsKey() {
    auto key = std::make_shared<APIKey>(1, "aws-admin", S3Provider::AWS, "AKIAEXAMPLEEXAMPLE00", kUpAwsSecret, "us-east-2",
                                        "https://s3.us-east-2.amazonaws.com");
    key->provider_account_id = "111122223333";
    return key;
}

std::shared_ptr<APIKey> upR2Key(const bool withToken = true) {
    auto key = std::make_shared<APIKey>(1, "r2-admin", S3Provider::CloudflareR2, "0123456789abcdef0123456789abcdef",
                                        kUpR2Secret, "wnam",
                                        std::string("https://") + kUpR2Account + ".r2.cloudflarestorage.com");
    if (withToken) key->provider_token = kUpCfToken;
    return key;
}

std::string upHeader(const http::Request& r, const std::string& name) {
    for (const auto& [k, v] : r.headers) {
        std::string lk = k;
        for (auto& c : lk) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        if (lk == name) return v;
    }
    return {};
}

http::Response upRespond(const long status, std::string body = {},
                         std::vector<std::pair<std::string, std::string>> headers = {}) {
    http::Response r;
    r.status = status;
    r.body = std::move(body);
    r.headers = std::move(headers);
    return r;
}

std::string upCfOk(const nlohmann::json& result, const nlohmann::json& info = nullptr) {
    nlohmann::json j = {{"success", true}, {"errors", nlohmann::json::array()}, {"result", result}};
    if (!info.is_null()) j["result_info"] = info;
    return j.dump();
}

}  // namespace

// Records every request and answers through `handler`.
class UpstreamProviderTest : public ::testing::Test {
protected:
    std::vector<http::Request> sent;
    std::function<http::Response(const http::Request&)> handler;

    void SetUp() override {
        guard::setForTesting({});
        http::setTransportForTesting([this](const http::Request& r) {
            sent.push_back(r);
            if (!handler) return upRespond(500, "no handler");
            return handler(r);
        });
    }

    void TearDown() override {
        http::setTransportForTesting(std::nullopt);
        guard::clearForTesting();
    }

    [[nodiscard]] std::vector<http::Request> matching(const std::string& method, const std::string& urlPart) const {
        std::vector<http::Request> out;
        for (const auto& r : sent)
            if (r.method == method && r.url.find(urlPart) != std::string::npos) out.push_back(r);
        return out;
    }
};

namespace {

const char* kUpForeignNotification = R"(<?xml version="1.0" encoding="UTF-8"?>
<NotificationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <QueueConfiguration><Id>other-app-logs</Id><Queue>arn:aws:sqs:us-east-2:111122223333:other</Queue><Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>prefix</Name><Value>logs/</Value></FilterRule></S3Key></Filter></QueueConfiguration>
  <TopicConfiguration><Id>billing-topic</Id><Topic>arn:aws:sns:us-east-2:111122223333:billing</Topic><Event>s3:ReducedRedundancyLostObject</Event><Filter><S3Key><FilterRule><Name>suffix</Name><Value>.csv</Value></FilterRule></S3Key></Filter></TopicConfiguration>
  <QueueConfiguration><Id>vaulthalla-7</Id><Queue>arn:aws:sqs:us-east-2:111122223333:vaulthalla-events-us-east-2</Queue><Event>s3:ObjectCreated:*</Event><Filter><S3Key><FilterRule><Name>prefix</Name><Value>vault/</Value></FilterRule></S3Key></Filter></QueueConfiguration>
  <EventBridgeConfiguration></EventBridgeConfiguration>
</NotificationConfiguration>)";

const char* kUpQueueUrl = "https://sqs.us-east-2.amazonaws.com/111122223333/vaulthalla-events-us-east-2";
const char* kUpQueueArn = "arn:aws:sqs:us-east-2:111122223333:vaulthalla-events-us-east-2";

admin::ChannelRef upAwsChannel() {
    return {.queue_name = "vaulthalla-events-us-east-2", .queue_ref = kUpQueueUrl, .queue_arn = kUpQueueArn,
            .dlq_ref = {}, .dlq_arn = {}, .created = false};
}

std::string upForeignPolicy() {
    return nlohmann::json{{"Version", "2012-10-17"},
                          {"Statement",
                           {{{"Sid", "someone-else"}, {"Effect", "Allow"}, {"Principal", {{"AWS", "arn:aws:iam::111122223333:root"}}},
                             {"Action", "sqs:*"}, {"Resource", kUpQueueArn}}}}}
        .dump();
}

// A fake AWS account: one bucket in us-east-2 with a mutable notification document and one queue with a policy.
struct UpFakeAws {
    std::string notification = kUpForeignNotification;
    std::string policy = upForeignPolicy();

    http::Response operator()(const http::Request& r) {
        const auto target = upHeader(r, "x-amz-target");
        if (!target.empty()) {
            const auto body = nlohmann::json::parse(r.body);
            if (target == "AmazonSQS.GetQueueAttributes") {
                nlohmann::json attrs = nlohmann::json::object();
                for (const auto& n : body["AttributeNames"]) {
                    if (n == "Policy" && !policy.empty()) attrs["Policy"] = policy;
                    if (n == "QueueArn") attrs["QueueArn"] = kUpQueueArn;
                }
                return upRespond(200, nlohmann::json{{"Attributes", attrs}}.dump());
            }
            if (target == "AmazonSQS.SetQueueAttributes") {
                policy = body["Attributes"].value("Policy", policy);
                return upRespond(200, "{}");
            }
            return upRespond(400, R"({"__type":"com.amazonaws.sqs#InvalidAction","message":"unexpected"})");
        }
        if (r.method == "HEAD") return upRespond(200, {}, {{"x-amz-bucket-region", "us-east-2"}});
        if (r.url.find("?notification") != std::string::npos) {
            if (r.method == "GET") return upRespond(200, notification);
            if (r.method == "PUT") {
                notification = r.body;
                return upRespond(200);
            }
        }
        return upRespond(400, "<Error><Code>Unexpected</Code></Error>");
    }
};

}

// ---- AWS notifications --------------------------------------------------------------------------------------------

TEST_F(UpstreamProviderTest, NotificationMergeKeepsForeignRulesVerbatim) {
    namespace d = admin::detail;
    const auto elements = d::parseNotification(kUpForeignNotification);
    ASSERT_EQ(elements.size(), 4u);
    admin::NotificationRule ours{.id = "vaulthalla-9", .destination = kUpQueueArn, .destination_name = {},
                                 .events = d::awsEventTypes(), .prefix = "", .suffix = {}, .foreign = false, .raw = {}};
    const auto merged = d::parseNotification(d::buildNotification(elements, {"vaulthalla-7"}, {ours}));
    ASSERT_EQ(merged.size(), 4u);   // other-app, billing, EventBridge kept; vaulthalla-7 replaced by vaulthalla-9
    for (const auto& original : elements) {
        if (original.rule.id == "vaulthalla-7") continue;
        const auto it = std::ranges::find_if(merged, [&](const auto& e) { return e.kind == original.kind && e.rule.id == original.rule.id; });
        ASSERT_NE(it, merged.end()) << original.rule.id;
        EXPECT_EQ(it->rule.raw, original.rule.raw);
        EXPECT_TRUE(it->rule.foreign);
    }
    const auto ourIt = std::ranges::find_if(merged, [](const auto& e) { return e.rule.id == "vaulthalla-9"; });
    ASSERT_NE(ourIt, merged.end());
    EXPECT_FALSE(ourIt->rule.foreign);
    EXPECT_EQ(ourIt->rule.destination, kUpQueueArn);
    EXPECT_EQ(ourIt->rule.events, d::awsEventTypes());
}

TEST_F(UpstreamProviderTest, AwsSubscribeMergesPolicyAndNotification) {
    UpFakeAws aws;
    handler = std::ref(aws);
    admin::AwsEvents events(upAwsKey());
    const auto ids = events.subscribe(upAwsChannel(), {.bucket = "vh-bucket", .rule_id = "vaulthalla-9", .prefix = "photos/"});
    EXPECT_EQ(ids, std::vector<std::string>{"vaulthalla-9"});

    // The queue policy keeps the foreign statement and grants the bucket.
    const auto policy = nlohmann::json::parse(aws.policy);
    ASSERT_EQ(policy["Statement"].size(), 2u);
    EXPECT_EQ(policy["Statement"][0]["Sid"], "someone-else");
    EXPECT_EQ(admin::detail::policyBuckets(aws.policy), std::vector<std::string>{"vh-bucket"});
    EXPECT_EQ(policy["Statement"][1]["Condition"]["StringEquals"]["aws:SourceAccount"], "111122223333");

    // The bucket keeps every foreign rule and the old vaulthalla-7 (another subscription's) alongside ours.
    const auto after = admin::detail::parseNotification(aws.notification);
    std::vector<std::string> ids2;
    for (const auto& e : after) ids2.push_back(e.rule.id);
    EXPECT_NE(std::ranges::find(ids2, "other-app-logs"), ids2.end());
    EXPECT_NE(std::ranges::find(ids2, "billing-topic"), ids2.end());
    EXPECT_NE(std::ranges::find(ids2, "vaulthalla-7"), ids2.end());
    EXPECT_NE(std::ranges::find(ids2, "vaulthalla-9"), ids2.end());
    EXPECT_EQ(std::ranges::count(ids2, std::string{}), 1);   // EventBridgeConfiguration
    const auto puts = matching("PUT", "?notification");
    ASSERT_EQ(puts.size(), 1u);
    EXPECT_FALSE(upHeader(puts[0], "content-md5").empty());

    // Idempotent: subscribing again sends no PUT.
    sent.clear();
    (void)events.subscribe(upAwsChannel(), {.bucket = "vh-bucket", .rule_id = "vaulthalla-9", .prefix = "photos/"});
    EXPECT_TRUE(matching("PUT", "?notification").empty());
}

TEST_F(UpstreamProviderTest, AwsSubscribeRefusesOverlapWithForeignRule) {
    UpFakeAws aws;
    handler = std::ref(aws);
    admin::AwsEvents events(upAwsKey());
    // other-app-logs covers logs/ for ObjectCreated: a subscription on logs/2026/ overlaps it.
    try {
        (void)events.subscribe(upAwsChannel(), {.bucket = "vh-bucket", .rule_id = "vaulthalla-9", .prefix = "logs/2026/"});
        FAIL() << "expected an overlap refusal";
    } catch (const admin::ProviderError& e) {
        EXPECT_EQ(e.code, "OverlappingNotification");
        EXPECT_NE(std::string(e.what()).find("other-app-logs"), std::string::npos);
    }
    EXPECT_TRUE(matching("PUT", "?notification").empty());
    EXPECT_EQ(aws.notification, kUpForeignNotification);
}

TEST_F(UpstreamProviderTest, AwsUnsubscribeRemovesOnlyOurRuleAndGrant) {
    UpFakeAws aws;
    handler = std::ref(aws);
    admin::AwsEvents events(upAwsKey());
    (void)events.subscribe(upAwsChannel(), {.bucket = "vh-bucket", .rule_id = "vaulthalla-9", .prefix = "photos/"});
    events.unsubscribe(upAwsChannel(), {.bucket = "vh-bucket", .rule_id = "vaulthalla-9", .prefix = "photos/"},
                       {"vaulthalla-9", "other-app-logs"});   // a foreign id passed in is ignored

    std::vector<std::string> ids;
    for (const auto& e : admin::detail::parseNotification(aws.notification)) ids.push_back(e.rule.id);
    EXPECT_EQ(std::ranges::find(ids, "vaulthalla-9"), ids.end());
    EXPECT_NE(std::ranges::find(ids, "other-app-logs"), ids.end());
    EXPECT_NE(std::ranges::find(ids, "billing-topic"), ids.end());
    EXPECT_NE(std::ranges::find(ids, "vaulthalla-7"), ids.end());
    const auto policy = nlohmann::json::parse(aws.policy);
    ASSERT_EQ(policy["Statement"].size(), 1u);
    EXPECT_EQ(policy["Statement"][0]["Sid"], "someone-else");
}

TEST_F(UpstreamProviderTest, QueuePolicyMerge) {
    namespace d = admin::detail;
    auto p = d::mergeQueuePolicy("", kUpQueueArn, "111122223333", "vh-aaa", true);
    p = d::mergeQueuePolicy(p, kUpQueueArn, "111122223333", "vh-bbb", true);
    p = d::mergeQueuePolicy(p, kUpQueueArn, "111122223333", "vh-aaa", true);   // no duplicate
    EXPECT_EQ(d::policyBuckets(p), (std::vector<std::string>{"vh-aaa", "vh-bbb"}));
    p = d::mergeQueuePolicy(p, kUpQueueArn, "111122223333", "vh-aaa", false);
    EXPECT_EQ(d::policyBuckets(p), std::vector<std::string>{"vh-bbb"});
    EXPECT_EQ(d::mergeQueuePolicy(p, kUpQueueArn, "111122223333", "vh-bbb", false), "");
    const auto foreign = upForeignPolicy();
    const auto withOurs = d::mergeQueuePolicy(foreign, kUpQueueArn, "111122223333", "vh-aaa", true);
    EXPECT_EQ(nlohmann::json::parse(d::mergeQueuePolicy(withOurs, kUpQueueArn, "111122223333", "vh-aaa", false)),
              nlohmann::json::parse(foreign));
    // ArnLike wildcards can't be smuggled in through a bucket name, nor a non-account through the account id.
    EXPECT_THROW((void)d::mergeQueuePolicy("", kUpQueueArn, "111122223333", "vh-*", true), std::invalid_argument);
    EXPECT_THROW((void)d::mergeQueuePolicy("", kUpQueueArn, "*", "vh-aaa", true), std::invalid_argument);
}

// ---- SQS ------------------------------------------------------------------------------------------------------

TEST_F(UpstreamProviderTest, SqsReceiveAckAndRetry) {
    nlohmann::json lastBody;
    std::string lastTarget;
    handler = [&](const http::Request& r) {
        lastTarget = upHeader(r, "x-amz-target");
        lastBody = nlohmann::json::parse(r.body);
        EXPECT_EQ(upHeader(r, "content-type"), "application/x-amz-json-1.0");
        EXPECT_EQ(r.url, "https://sqs.us-east-2.amazonaws.com/");
        if (lastTarget == "AmazonSQS.ReceiveMessage")
            return upRespond(200, R"({"Messages":[{"MessageId":"m-1","ReceiptHandle":"rh-1","Body":"{\"Records\":[]}",
                "Attributes":{"ApproximateReceiveCount":"3","SentTimestamp":"1760000000123"}}]})");
        if (lastTarget == "AmazonSQS.DeleteMessageBatch") {
            if (lastBody["Entries"].size() == 2)
                return upRespond(200, R"({"Successful":[{"Id":"m0"}],"Failed":[{"Id":"m1","Code":"ReceiptHandleIsInvalid","Message":"x","SenderFault":true}]})");
            return upRespond(200, R"({"Successful":[{"Id":"m0"}]})");
        }
        return upRespond(200, "{}");
    };
    admin::AwsEvents events(upAwsKey());
    const auto result = events.poll(upAwsChannel(), 50, std::chrono::seconds{40}, std::chrono::seconds{120});
    EXPECT_EQ(lastTarget, "AmazonSQS.ReceiveMessage");
    EXPECT_EQ(lastBody["MaxNumberOfMessages"], 10);
    EXPECT_EQ(lastBody["WaitTimeSeconds"], 20);
    EXPECT_EQ(lastBody["VisibilityTimeout"], 120);
    ASSERT_EQ(result.messages.size(), 1u);
    EXPECT_EQ(result.messages[0].receipt, "rh-1");
    EXPECT_EQ(result.messages[0].message_id, "m-1");
    EXPECT_EQ(result.messages[0].body, R"({"Records":[]})");
    EXPECT_EQ(result.messages[0].attempts, 3u);
    EXPECT_EQ(result.messages[0].sent_at, std::optional<std::time_t>(1760000000));

    events.ack(upAwsChannel(), {"rh-1"});
    EXPECT_EQ(lastTarget, "AmazonSQS.DeleteMessageBatch");
    EXPECT_EQ(lastBody["Entries"][0]["ReceiptHandle"], "rh-1");
    EXPECT_THROW(events.ack(upAwsChannel(), {"rh-1", "rh-2"}), admin::ProviderError);

    events.retry(upAwsChannel(), {"rh-1"}, std::chrono::seconds{90});
    EXPECT_EQ(lastTarget, "AmazonSQS.ChangeMessageVisibilityBatch");
    EXPECT_EQ(lastBody["Entries"][0]["VisibilityTimeout"], 90);
}

TEST_F(UpstreamProviderTest, AwsEnsureChannelAccessDeniedIsCapabilityMissing) {
    handler = [](const http::Request&) {
        return upRespond(400, R"({"__type":"com.amazon.coral.service#AccessDeniedException","message":"User is not authorized to perform: sqs:getqueueurl"})",
                         {{"x-amzn-query-error", "AWS.SimpleQueueService.AccessDenied;Sender"}});
    };
    admin::AwsEvents events(upAwsKey());
    try {
        (void)events.ensureChannel({.account_ref = "111122223333", .region = "us-east-2", .queue_name = "vaulthalla-events-us-east-2",
                                    .retention_seconds = 345600, .visibility_timeout_seconds = 120, .max_receive_count = 8});
        FAIL() << "expected CapabilityMissing";
    } catch (const admin::CapabilityMissing& e) {
        EXPECT_EQ(e.capability, "events.queues");
        EXPECT_NE(std::string(e.what()).find("sqs:CreateQueue"), std::string::npos);
        EXPECT_NE(std::string(e.what()).find("arn:aws:sqs:*:111122223333:vaulthalla-*"), std::string::npos);
    }
}

TEST_F(UpstreamProviderTest, AwsEnsureChannelCreatesQueueAndDlq) {
    std::vector<nlohmann::json> creates;
    handler = [&](const http::Request& r) {
        const auto target = upHeader(r, "x-amz-target");
        const auto body = nlohmann::json::parse(r.body);
        if (target == "AmazonSQS.GetQueueUrl")
            return upRespond(400, R"({"__type":"com.amazonaws.sqs#QueueDoesNotExist","message":"The specified queue does not exist."})");
        if (target == "AmazonSQS.CreateQueue") {
            creates.push_back(body);
            return upRespond(200, nlohmann::json{{"QueueUrl", "https://sqs.us-east-2.amazonaws.com/111122223333/" +
                                                                   body["QueueName"].get<std::string>()}}.dump());
        }
        if (target == "AmazonSQS.GetQueueAttributes") {
            const auto url = body["QueueUrl"].get<std::string>();
            nlohmann::json attrs = {{"QueueArn", "arn:aws:sqs:us-east-2:111122223333:" + url.substr(url.rfind('/') + 1)}};
            if (url.ends_with("us-east-2")) attrs["RedrivePolicy"] = "{}";
            return upRespond(200, nlohmann::json{{"Attributes", attrs}}.dump());
        }
        return upRespond(200, "{}");
    };
    admin::AwsEvents events(upAwsKey());
    const auto ref = events.ensureChannel({.account_ref = "111122223333", .region = "us-east-2",
                                           .queue_name = "vaulthalla-events-us-east-2", .retention_seconds = 345600,
                                           .visibility_timeout_seconds = 120, .max_receive_count = 8});
    EXPECT_TRUE(ref.created);
    EXPECT_EQ(ref.queue_ref, kUpQueueUrl);
    EXPECT_EQ(ref.dlq_arn, "arn:aws:sqs:us-east-2:111122223333:vaulthalla-events-us-east-2-dlq");
    ASSERT_EQ(creates.size(), 2u);
    EXPECT_EQ(creates[0]["QueueName"], "vaulthalla-events-us-east-2-dlq");
    const auto redrive = nlohmann::json::parse(creates[1]["Attributes"]["RedrivePolicy"].get<std::string>());
    EXPECT_EQ(redrive["deadLetterTargetArn"], ref.dlq_arn);
    EXPECT_EQ(redrive["maxReceiveCount"], 8);
    EXPECT_EQ(creates[1]["Attributes"]["MessageRetentionPeriod"], "345600");
}

// ---- AWS buckets --------------------------------------------------------------------------------------------------

TEST_F(UpstreamProviderTest, CreateBucketCollisionCodes) {
    for (const auto* code : {"BucketAlreadyOwnedByYou", "BucketAlreadyExists"}) {
        handler = [code](const http::Request&) {
            return upRespond(409, std::string("<Error><Code>") + code + "</Code><Message>taken</Message></Error>");
        };
        admin::AwsAdmin aws(upAwsKey());
        try {
            aws.createBucket({.name = "vh-taken", .region = std::string("us-east-2")});
            FAIL() << "expected a collision";
        } catch (const admin::ProviderError& e) {
            EXPECT_EQ(e.code, code);
            EXPECT_EQ(e.http_status, 409);
        }
    }
}

TEST_F(UpstreamProviderTest, CreateBucketLocationConstraint) {
    handler = [](const http::Request&) { return upRespond(200); };
    admin::AwsAdmin aws(upAwsKey());
    aws.createBucket({.name = "vh-east1", .region = std::string("us-east-1")});
    aws.createBucket({.name = "vh-east2", .region = std::string("us-east-2")});
    ASSERT_EQ(sent.size(), 2u);
    EXPECT_EQ(sent[0].url, "https://s3.us-east-1.amazonaws.com/vh-east1");
    EXPECT_TRUE(sent[0].body.empty());
    EXPECT_EQ(sent[1].url, "https://s3.us-east-2.amazonaws.com/vh-east2");
    EXPECT_NE(sent[1].body.find("<LocationConstraint>us-east-2</LocationConstraint>"), std::string::npos);
}

TEST_F(UpstreamProviderTest, HeadBucketOutcomes) {
    admin::AwsAdmin aws(upAwsKey());
    handler = [](const http::Request&) { return upRespond(404); };
    EXPECT_EQ(aws.headBucket("vh-missing"), std::nullopt);

    handler = [](const http::Request&) { return upRespond(403); };
    try {
        (void)aws.headBucket("someone-elses");
        FAIL() << "403 must throw";
    } catch (const admin::ProviderError& e) {
        EXPECT_TRUE(e.accessDenied());
    }

    // A bucket outside the key's region: the key's regional endpoint redirects with the region, one more HEAD there.
    sent.clear();
    handler = [](const http::Request& r) {
        if (!r.url.starts_with("https://s3.us-west-2.amazonaws.com/"))
            return upRespond(301, {}, {{"x-amz-bucket-region", "us-west-2"}});
        return upRespond(200, {}, {{"x-amz-bucket-region", "us-west-2"}});
    };
    EXPECT_EQ(aws.headBucket("vh-west"), std::optional<std::string>("us-west-2"));
    ASSERT_EQ(sent.size(), 2u);
    EXPECT_EQ(sent[0].url, "https://s3.us-east-2.amazonaws.com/vh-west");
    EXPECT_EQ(sent[1].url, "https://s3.us-west-2.amazonaws.com/vh-west");
    EXPECT_EQ(aws.regionOf("vh-west"), "us-west-2");   // cached: no third request
    EXPECT_EQ(sent.size(), 2u);
    (void)aws.headBucket("vh-west");                   // the cached region: straight there
    ASSERT_EQ(sent.size(), 3u);
    EXPECT_EQ(sent[2].url, "https://s3.us-west-2.amazonaws.com/vh-west");
}

// #247: HeadBucket used to probe the global endpoint and then the bucket's region on every call (2 HEADs outside
// us-east-1, 12 of the 29 requests of a live recovery enable). A known region is one HEAD.
TEST_F(UpstreamProviderTest, HeadBucketGoesStraightToAKnownRegion) {
    // The fake account: buckets answer only at their own regional endpoint; elsewhere a 301 names the region.
    const std::map<std::string, std::string> where{{"vh-east2", "us-east-2"}, {"vh-west", "us-west-2"},
                                                   {"vh-virginia", "us-east-1"}};
    const auto account = [&](const http::Request& r) {
        for (const auto& [bucket, region] : where) {
            if (!r.url.ends_with("/" + bucket) && r.url.find("/" + bucket + "?") == std::string::npos) continue;
            const auto host = region == "us-east-1" ? std::string("https://s3.amazonaws.com/")
                                                    : "https://s3." + region + ".amazonaws.com/";
            if (!r.url.starts_with(host)) return upRespond(301, {}, {{"x-amz-bucket-region", region}});
            if (r.method == "HEAD") return upRespond(200, {}, {{"x-amz-bucket-region", region}});
            if (r.url.find("?versioning") != std::string::npos)
                return upRespond(200, "<VersioningConfiguration/>");
            if (r.url.find("?object-lock") != std::string::npos)
                return upRespond(404, "<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>");
            if (r.url.find("?lifecycle") != std::string::npos)
                return upRespond(404, "<Error><Code>NoSuchLifecycleConfiguration</Code></Error>");
            return upRespond(200, "<NotificationConfiguration/>");
        }
        return upRespond(404);
    };
    handler = account;

    // The key's region (us-east-2) is right: exactly one HEAD, to the regional endpoint, for headBucket and inspect.
    {
        admin::AwsAdmin aws(upAwsKey());
        EXPECT_EQ(aws.headBucket("vh-east2"), std::optional<std::string>("us-east-2"));
        ASSERT_EQ(sent.size(), 1u);
        EXPECT_EQ(sent[0].url, "https://s3.us-east-2.amazonaws.com/vh-east2");
        EXPECT_EQ(aws.metrics().head, 1u);
    }
    {
        sent.clear();
        admin::AwsAdmin aws(upAwsKey());
        (void)aws.inspect("vh-east2");
        const auto heads = matching("HEAD", "");
        ASSERT_EQ(heads.size(), 1u) << "inspect HEADs once, at the bucket's region";
        EXPECT_EQ(heads[0].url, "https://s3.us-east-2.amazonaws.com/vh-east2");
        for (const auto& r : sent) EXPECT_TRUE(r.url.starts_with("https://s3.us-east-2.amazonaws.com/")) << r.url;
    }

    // A recorded region (upstream_bucket.region) beats the key's region: one HEAD to us-west-2.
    {
        sent.clear();
        admin::AwsAdmin aws(upAwsKey());
        aws.setKnownRegion("vh-west", "us-west-2");
        EXPECT_EQ(aws.headBucket("vh-west"), std::optional<std::string>("us-west-2"));
        ASSERT_EQ(sent.size(), 1u);
        EXPECT_EQ(sent[0].url, "https://s3.us-west-2.amazonaws.com/vh-west");
    }

    // A stale or malformed hint never misroutes: the redirect names the region, one more HEAD; garbage is ignored.
    {
        sent.clear();
        admin::AwsAdmin aws(upAwsKey());
        aws.setKnownRegion("vh-west", "eu-central-1");
        aws.setKnownRegion("vh-east2", "evil.example/#");
        EXPECT_EQ(aws.headBucket("vh-west"), std::optional<std::string>("us-west-2"));
        ASSERT_EQ(sent.size(), 2u);
        EXPECT_EQ(sent[0].url, "https://s3.eu-central-1.amazonaws.com/vh-west");
        EXPECT_EQ(sent[1].url, "https://s3.us-west-2.amazonaws.com/vh-west");
        EXPECT_EQ(aws.headBucket("vh-east2"), std::optional<std::string>("us-east-2"));
        ASSERT_EQ(sent.size(), 3u);
        EXPECT_EQ(sent[2].url, "https://s3.us-east-2.amazonaws.com/vh-east2");
    }

    // No region known (key region "auto"): the global endpoint first, as before.
    {
        sent.clear();
        auto key = upAwsKey();
        key->region = "auto";
        admin::AwsAdmin aws(key);
        EXPECT_EQ(aws.headBucket("vh-virginia"), std::optional<std::string>("us-east-1"));
        ASSERT_EQ(sent.size(), 1u);
        EXPECT_EQ(sent[0].url, "https://s3.amazonaws.com/vh-virginia");
        EXPECT_EQ(aws.headBucket("vh-west"), std::optional<std::string>("us-west-2"));
        ASSERT_EQ(sent.size(), 3u);
        EXPECT_EQ(sent[1].url, "https://s3.amazonaws.com/vh-west");
        EXPECT_EQ(sent[2].url, "https://s3.us-west-2.amazonaws.com/vh-west");
    }

    // A redirect that names no region falls back to the global endpoint once.
    {
        sent.clear();
        handler = [](const http::Request& r) {
            if (r.url.starts_with("https://s3.amazonaws.com/")) return upRespond(200, {}, {{"x-amz-bucket-region", "us-east-1"}});
            return upRespond(301);
        };
        admin::AwsAdmin aws(upAwsKey());
        EXPECT_EQ(aws.headBucket("vh-virginia"), std::optional<std::string>("us-east-1"));
        ASSERT_EQ(sent.size(), 2u);
        EXPECT_EQ(sent[1].url, "https://s3.amazonaws.com/vh-virginia");
    }

    // Name validation and the protection lock still come before any request, hint or not.
    {
        sent.clear();
        handler = account;
        admin::AwsAdmin aws(upAwsKey());
        aws.setKnownRegion("locked", "us-east-2");
        guard::setForTesting({{.provider = "aws-s3", .account_ref = std::string("111122223333"), .bucket = "locked"}});
        EXPECT_THROW((void)aws.headBucket("locked"), vh::storage::upstream::BucketProtected);
        EXPECT_THROW((void)aws.headBucket("Not_A_Bucket"), std::invalid_argument);
        EXPECT_TRUE(sent.empty());
    }
}

TEST_F(UpstreamProviderTest, StsIdentity) {
    handler = [](const http::Request& r) {
        EXPECT_NE(r.url.find("https://sts.amazonaws.com/?Action=GetCallerIdentity&Version=2011-06-15"), std::string::npos);
        return upRespond(200, R"(<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult>
            <Arn>arn:aws:iam::111122223333:user/vh</Arn><UserId>AIDA</UserId><Account>111122223333</Account>
            </GetCallerIdentityResult></GetCallerIdentityResponse>)");
    };
    auto key = upAwsKey();
    key->provider_account_id.reset();
    admin::AwsAdmin aws(key);
    const auto id = aws.identity();
    EXPECT_EQ(id.account_ref, "111122223333");
    EXPECT_EQ(id.principal, "arn:aws:iam::111122223333:user/vh");
    EXPECT_EQ(id.provider, "aws-s3");
}

// ---- lifecycle ----------------------------------------------------------------------------------------------------

TEST_F(UpstreamProviderTest, LifecycleRoundTripKeepsForeignRule) {
    namespace d = admin::detail;
    const std::string xml = R"(<LifecycleConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
      <Rule><ID>archive-old</ID><Filter><Prefix>archive/</Prefix></Filter><Status>Enabled</Status>
        <Transition><Days>30</Days><StorageClass>GLACIER</StorageClass></Transition></Rule>
      <Rule><ID>vaulthalla-managed</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>
        <AbortIncompleteMultipartUpload><DaysAfterInitiation>7</DaysAfterInitiation></AbortIncompleteMultipartUpload></Rule>
    </LifecycleConfiguration>)";
    auto rules = d::parseLifecycle(xml);
    ASSERT_EQ(rules.size(), 2u);
    EXPECT_TRUE(rules[0].foreign);
    EXPECT_EQ(rules[0].prefix, "archive/");
    EXPECT_FALSE(rules[1].foreign);
    EXPECT_EQ(rules[1].abort_incomplete_multipart_days, std::optional<unsigned int>(7));

    rules[1].abort_incomplete_multipart_days = 3;
    rules[1].expire_current_days = 365;
    const auto rebuilt = d::parseLifecycle(d::buildLifecycle(rules, true));
    ASSERT_EQ(rebuilt.size(), 2u);
    EXPECT_EQ(rebuilt[0].raw_xml, rules[0].raw_xml);   // the foreign rule (with its Transition) is untouched
    EXPECT_NE(rebuilt[0].raw_xml.find("<StorageClass>GLACIER</StorageClass>"), std::string::npos);
    EXPECT_EQ(rebuilt[1].abort_incomplete_multipart_days, std::optional<unsigned int>(3));
    EXPECT_EQ(rebuilt[1].expire_current_days, std::optional<unsigned int>(365));
    EXPECT_TRUE(rebuilt[1].destructive());

    auto noncurrent = rules;
    noncurrent[1].expire_noncurrent_days = 30;
    EXPECT_THROW((void)d::buildLifecycle(noncurrent, false), std::invalid_argument);
    auto empty = rules;
    empty[1].abort_incomplete_multipart_days.reset();
    empty[1].expire_current_days.reset();
    EXPECT_THROW((void)d::buildLifecycle(empty, true), std::invalid_argument);
}

TEST_F(UpstreamProviderTest, PutLifecycleSendsContentMd5AndR2RefusesNoncurrent) {
    handler = [](const http::Request&) { return upRespond(200); };
    admin::R2Admin r2(upR2Key());
    admin::LifecycleRule rule;
    rule.id = "vaulthalla-managed";
    rule.abort_incomplete_multipart_days = 1;
    r2.putLifecycle("vh-r2", {rule});
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_EQ(sent[0].method, "PUT");
    EXPECT_EQ(sent[0].url, std::string("https://") + kUpR2Account + ".r2.cloudflarestorage.com/vh-r2?lifecycle=");
    EXPECT_FALSE(upHeader(sent[0], "content-md5").empty());
    EXPECT_NE(upHeader(sent[0], "authorization").find("/auto/s3/aws4_request"), std::string::npos);

    rule.expire_noncurrent_days = 5;
    EXPECT_THROW(r2.putLifecycle("vh-r2", {rule}), std::invalid_argument);
    EXPECT_EQ(sent.size(), 1u);

    r2.putLifecycle("vh-r2", {});   // no rules left: the configuration is deleted
    EXPECT_EQ(sent.back().method, "DELETE");
}

// ---- Cloudflare R2 events -----------------------------------------------------------------------------------------

namespace {

// A fake Cloudflare account: one queue, a bucket rule list it mutates on PUT/DELETE.
struct UpFakeCloudflare {
    nlohmann::json rules = nlohmann::json::array();
    nlohmann::json lastPut, lastDelete;
    int deletes = 0;
    bool workerConsumer = false;
    // How the bucket's notification configuration spells q-1's id: live R2 lists another form than the Queues API's
    // queue_id, so rules must match by queue name too.
    std::string listedQueueId = "q-1";
    int consumersNotFound = 0;   // consumers lookups answering 404 (a just-created queue, seen live)
    bool queuesExist = true;     // false: the listing is empty and POST /queues creates them

    http::Response operator()(const http::Request& r) {
        EXPECT_EQ(upHeader(r, "authorization"), std::string("Bearer ") + kUpCfToken);
        const auto path = r.url.substr(std::string("https://api.cloudflare.com/client/v4").size());
        const auto acct = std::string("/accounts/") + kUpR2Account;
        if (path.starts_with(acct + "/event_notifications/r2/vh-r2/configuration/queues/q-1")) {
            if (r.method == "PUT") {
                lastPut = nlohmann::json::parse(r.body);
                for (auto rule : lastPut["rules"]) {
                    rule["ruleId"] = "rule-" + std::to_string(rules.size() + 1);
                    rules.push_back(rule);
                }
                return upRespond(200, upCfOk(nullptr));
            }
            if (r.method == "DELETE") {
                ++deletes;
                lastDelete = r.body.empty() ? nlohmann::json() : nlohmann::json::parse(r.body);
                nlohmann::json kept = nlohmann::json::array();
                for (const auto& rule : rules) {
                    const bool drop = lastDelete.is_null() ||
                        std::ranges::find(lastDelete["ruleIds"], rule["ruleId"]) != lastDelete["ruleIds"].end();
                    if (!drop) kept.push_back(rule);
                }
                rules = kept;
                return upRespond(200, upCfOk(nullptr));
            }
        }
        if (path == acct + "/event_notifications/r2/vh-r2/configuration" && r.method == "GET") {
            nlohmann::json q1 = {{"queueId", listedQueueId}, {"queueName", "vaulthalla-events-r2"}, {"rules", nlohmann::json::array()}};
            nlohmann::json q2 = {{"queueId", "q-other"}, {"queueName", "other-app"}, {"rules", nlohmann::json::array()}};
            for (const auto& rule : rules) (rule.value("queue", "q-1") == "q-other" ? q2 : q1)["rules"].push_back(rule);
            return upRespond(200, upCfOk({{"bucketName", "vh-r2"}, {"queues", {q1, q2}}}));
        }
        if (path == acct + "/queues" && r.method == "POST") {
            const auto name = nlohmann::json::parse(r.body).value("queue_name", "");
            return upRespond(200, upCfOk({{"queue_id", name.ends_with("-dlq") ? "q-dlq" : "q-1"}, {"queue_name", name}}));
        }
        if (path.starts_with(acct + "/queues?page=") && !queuesExist)
            return upRespond(200, upCfOk(nlohmann::json::array(), {{"page", 1}, {"total_pages", 1}}));
        if (path.starts_with(acct + "/queues?page=")) {
            return upRespond(200, upCfOk({{{"queue_id", "q-dlq"}, {"queue_name", "vaulthalla-events-r2-dlq"}},
                                          {{"queue_id", "q-1"}, {"queue_name", "vaulthalla-events-r2"}}},
                                         {{"page", 1}, {"total_pages", 1}}));
        }
        if (path == acct + "/queues/q-1/consumers" && r.method == "GET" && consumersNotFound > 0) {
            --consumersNotFound;
            return upRespond(404, R"({"success":false,"errors":[{"code":11000,"message":"Queue not found"}]})");
        }
        if (path == acct + "/queues/q-1/consumers" && r.method == "GET") {
            if (workerConsumer) return upRespond(200, upCfOk({{{"type", "worker"}, {"script_name", "their-worker"}}}));
            return upRespond(200, upCfOk(nlohmann::json::array()));
        }
        if (path == acct + "/queues/q-1/consumers" && r.method == "POST") return upRespond(200, upCfOk({{"consumer_id", "c-1"}}));
        if (path == acct + "/queues/q-1/messages/pull") {
            const auto raw = R"({"account":"x","action":"PutObject","bucket":"vh-r2","object":{"key":"a.txt","size":3,"eTag":"e"},"eventTime":"2026-10-15T00:00:00Z"})";
            return upRespond(200, upCfOk({{"message_backlog_count", 42},
                                          {"messages",
                                           {{{"id", "msg-1"}, {"lease_id", "lease-1"}, {"attempts", 2}, {"timestamp_ms", 1760000000999LL},
                                             {"body", raw}, {"metadata", {{"CF-Content-Type", "json"}}}},
                                            {{"id", "msg-2"}, {"lease_id", "lease-2"}, {"attempts", 1}, {"timestamp_ms", 1760000001000LL},
                                             {"body", "eyJrIjoxfQ=="}, {"metadata", {{"CF-Content-Type", "bytes"}}}}}}}));
        }
        if (path == acct + "/queues/q-1/messages/ack") {
            lastPut = nlohmann::json::parse(r.body);
            return upRespond(200, upCfOk(nullptr));
        }
        return upRespond(404, R"({"success":false,"errors":[{"code":7000,"message":"No route"}]})");
    }
};

admin::ChannelRef upR2Channel() {
    return {.queue_name = "vaulthalla-events-r2", .queue_ref = "q-1", .queue_arn = {}, .dlq_ref = "q-dlq", .dlq_arn = {},
            .created = false};
}

}

TEST_F(UpstreamProviderTest, R2SubscribeMarksOurRuleAndDeletesOnlyByRuleId) {
    UpFakeCloudflare cf;
    cf.rules.push_back({{"ruleId", "foreign-1"}, {"queue", "q-other"}, {"actions", {"PutObject"}}, {"prefix", "logs/"},
                        {"description", "their rule"}});
    handler = std::ref(cf);
    admin::R2Events events(upR2Key());
    const auto ids = events.subscribe(upR2Channel(), {.bucket = "vh-r2", .rule_id = "vaulthalla-5", .prefix = "vault/"});
    ASSERT_EQ(ids.size(), 1u);
    EXPECT_EQ(cf.lastPut["rules"][0]["description"], "vaulthalla-5");
    EXPECT_EQ(cf.lastPut["rules"][0]["prefix"], "vault/");
    EXPECT_EQ(cf.lastPut["rules"][0]["actions"].size(), 5u);

    // Idempotent.
    EXPECT_EQ(events.subscribe(upR2Channel(), {.bucket = "vh-r2", .rule_id = "vaulthalla-5", .prefix = "vault/"}), ids);

    const auto all = events.rules("vh-r2");
    ASSERT_EQ(all.size(), 2u);
    for (const auto& r : all) {
        EXPECT_EQ(r.foreign, r.id == "foreign-1");
    }

    events.unsubscribe(upR2Channel(), {.bucket = "vh-r2", .rule_id = "vaulthalla-5", .prefix = "vault/"}, {});
    EXPECT_EQ(cf.deletes, 1);
    ASSERT_TRUE(cf.lastDelete.contains("ruleIds"));
    EXPECT_EQ(cf.lastDelete["ruleIds"], nlohmann::json(ids));
    ASSERT_EQ(cf.rules.size(), 1u);
    EXPECT_EQ(cf.rules[0]["ruleId"], "foreign-1");

    // Nothing of ours left: no DELETE at all (a body-less DELETE would remove every rule of the queue).
    events.unsubscribe(upR2Channel(), {.bucket = "vh-r2", .rule_id = "vaulthalla-5", .prefix = "vault/"}, {});
    EXPECT_EQ(cf.deletes, 1);
    for (const auto& r : sent) {
        if (r.method == "DELETE") {
            EXPECT_FALSE(r.body.empty());
        }
    }
}

// Seen live: the bucket's notification configuration names the queue by an id spelled unlike the Queues API's
// queue_id, so subscribe found its own new rule "missing". Rules match by the queue's id (dashes and case ignored) or
// name; another queue's rule with our marker is still not ours.
TEST_F(UpstreamProviderTest, R2RulesMatchTheQueueByNameWhenTheListedIdDiffers) {
    UpFakeCloudflare cf;
    cf.listedQueueId = "0f-q1-listed-form";
    cf.rules.push_back({{"ruleId", "foreign-7"}, {"queue", "q-other"}, {"actions", {"PutObject"}}, {"prefix", "x/"},
                        {"description", "vaulthalla-7"}});
    handler = std::ref(cf);
    admin::R2Events events(upR2Key());
    const auto ids = events.subscribe(upR2Channel(), {.bucket = "vh-r2", .rule_id = "vaulthalla-7", .prefix = "v/"});
    EXPECT_EQ(ids, (std::vector<std::string>{"rule-2"}));
    EXPECT_EQ(events.subscribe(upR2Channel(), {.bucket = "vh-r2", .rule_id = "vaulthalla-7", .prefix = "v/"}), ids)
        << "idempotent: the existing rule is found again";
    events.unsubscribe(upR2Channel(), {.bucket = "vh-r2", .rule_id = "vaulthalla-7", .prefix = "v/"}, {});
    EXPECT_EQ(cf.lastDelete["ruleIds"], nlohmann::json::array({"rule-2"}));

    cf.listedQueueId = "Q-1";   // the same id with other case/dashes still matches
    auto renamed = upR2Channel();
    renamed.queue_name.clear();
    EXPECT_EQ(events.subscribe(renamed, {.bucket = "vh-r2", .rule_id = "vaulthalla-8", .prefix = "w/"}).size(), 1u);
}

TEST_F(UpstreamProviderTest, R2SubscribeRefusesOverlappingForeignRule) {
    UpFakeCloudflare cf;
    cf.rules.push_back({{"ruleId", "foreign-1"}, {"queue", "q-other"}, {"actions", {"PutObject"}}, {"description", "all objects"}});
    handler = std::ref(cf);
    admin::R2Events events(upR2Key());
    try {
        (void)events.subscribe(upR2Channel(), {.bucket = "vh-r2", .rule_id = "vaulthalla-5", .prefix = ""});
        FAIL() << "expected an overlap refusal";
    } catch (const admin::ProviderError& e) {
        EXPECT_EQ(e.code, "OverlappingRule");
    }
    EXPECT_TRUE(cf.lastPut.is_null());
}

TEST_F(UpstreamProviderTest, R2PullDecodesBodiesAndAcks) {
    UpFakeCloudflare cf;
    handler = std::ref(cf);
    admin::R2Events events(upR2Key());
    const auto result = events.poll(upR2Channel(), 500, std::chrono::seconds{0}, std::chrono::seconds{60});
    EXPECT_EQ(result.backlog, std::optional<uint64_t>(42));
    ASSERT_EQ(result.messages.size(), 2u);
    EXPECT_EQ(nlohmann::json::parse(result.messages[0].body)["action"], "PutObject");
    EXPECT_EQ(result.messages[0].receipt, "lease-1");
    EXPECT_EQ(result.messages[0].attempts, 2u);
    EXPECT_EQ(result.messages[0].sent_at, std::optional<std::time_t>(1760000000));
    EXPECT_EQ(result.messages[1].body, R"({"k":1})");
    const auto pull = matching("POST", "/messages/pull");
    ASSERT_EQ(pull.size(), 1u);
    EXPECT_EQ(nlohmann::json::parse(pull[0].body)["batch_size"], 100);
    EXPECT_EQ(nlohmann::json::parse(pull[0].body)["visibility_timeout_ms"], 60000);

    events.ack(upR2Channel(), {"lease-1"});
    EXPECT_EQ(cf.lastPut["acks"][0]["lease_id"], "lease-1");
    events.retry(upR2Channel(), {"lease-2"}, std::chrono::seconds{30});
    EXPECT_EQ(cf.lastPut["retries"][0]["lease_id"], "lease-2");
    EXPECT_EQ(cf.lastPut["retries"][0]["delay_seconds"], 30);
}

// Seen live: right after POST /queues, the new queue's consumers lookup can answer 404. ensureChannel waits for a queue
// it created; a 404 for a queue that already existed is still an error.
TEST_F(UpstreamProviderTest, R2EnsureChannelWaitsForAQueueItJustCreated) {
    UpFakeCloudflare cf;
    cf.queuesExist = false;
    cf.consumersNotFound = 2;
    handler = std::ref(cf);
    admin::R2Events events(upR2Key());
    const admin::ChannelSpec spec{.account_ref = kUpR2Account, .region = "", .queue_name = "vaulthalla-events-r2",
                                  .retention_seconds = 345600, .visibility_timeout_seconds = 120, .max_receive_count = 8};
    const auto ref = events.ensureChannel(spec);
    EXPECT_TRUE(ref.created);
    EXPECT_EQ(ref.queue_ref, "q-1");
    EXPECT_EQ(matching("POST", "/queues/q-1/consumers").size(), 1u);

    cf.queuesExist = true;
    cf.consumersNotFound = 1;
    EXPECT_THROW((void)events.ensureChannel(spec), admin::ProviderError) << "an existing queue's 404 is not waited for";
}

TEST_F(UpstreamProviderTest, R2EnsureChannelReusesQueueAndRefusesWorkerConsumer) {
    UpFakeCloudflare cf;
    handler = std::ref(cf);
    admin::R2Events events(upR2Key());
    const admin::ChannelSpec spec{.account_ref = kUpR2Account, .region = "", .queue_name = "vaulthalla-events-r2",
                                  .retention_seconds = 345600, .visibility_timeout_seconds = 120, .max_receive_count = 8};
    const auto ref = events.ensureChannel(spec);
    EXPECT_FALSE(ref.created);
    EXPECT_EQ(ref.queue_ref, "q-1");
    EXPECT_EQ(ref.dlq_ref, "q-dlq");
    const auto consumers = matching("POST", "/queues/q-1/consumers");
    ASSERT_EQ(consumers.size(), 1u);
    const auto body = nlohmann::json::parse(consumers[0].body);
    EXPECT_EQ(body["type"], "http_pull");
    EXPECT_EQ(body["dead_letter_queue"], "vaulthalla-events-r2-dlq");

    sent.clear();
    cf.workerConsumer = true;
    try {
        (void)events.ensureChannel(spec);
        FAIL() << "expected a Worker-consumer refusal";
    } catch (const admin::ProviderError& e) {
        EXPECT_EQ(e.code, "WorkerConsumer");
    }
    EXPECT_TRUE(matching("POST", "/consumers").empty());
    EXPECT_TRUE(matching("DELETE", "/consumers").empty());
}

TEST_F(UpstreamProviderTest, R2WithoutProviderTokenIsCapabilityMissing) {
    handler = [](const http::Request&) {
        return upRespond(200, R"(<ListAllMyBucketsResult><Buckets><Bucket><Name>b1</Name></Bucket></Buckets></ListAllMyBucketsResult>)");
    };
    const auto key = upR2Key(false);
    EXPECT_THROW((void)admin::eventsFor(key), admin::CapabilityMissing);
    admin::R2Admin r2(key);
    const auto caps = r2.probe();
    EXPECT_EQ(caps.identity.account_ref, kUpR2Account);
    EXPECT_TRUE(caps.has("buckets.list"));
    EXPECT_FALSE(caps.has("events.queues"));
    EXPECT_FALSE(caps.has("events.notifications"));
    for (const auto& c : caps.items) {
        if (c.name.starts_with("events.")) {
            EXPECT_NE(c.detail.find("Queues: Edit"), std::string::npos);
        }
    }
    // Only the S3 ListBuckets went out, never the Cloudflare API.
    for (const auto& r : sent) EXPECT_EQ(r.url.find("api.cloudflare.com"), std::string::npos);
}

TEST_F(UpstreamProviderTest, R2LocationHintAndUnsupportedProviders) {
    handler = [](const http::Request&) { return upRespond(200); };
    admin::R2Admin r2(upR2Key());
    r2.createBucket({.name = "vh-r2-new", .region = std::nullopt});   // the key's hint (wnam)
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_NE(sent[0].body.find("<LocationConstraint>wnam</LocationConstraint>"), std::string::npos);
    EXPECT_THROW(r2.createBucket({.name = "vh-r2-bad", .region = std::string("mars")}), std::invalid_argument);

    const auto minio = std::make_shared<APIKey>(1, "minio", S3Provider::MinIO, "minioaccesskey00000", "miniosecretkey000000",
                                                "auto", "https://minio.local:9000");
    EXPECT_EQ(admin::adminFor(minio), nullptr);
    EXPECT_EQ(admin::eventsFor(minio), nullptr);
}

// ---- protection locks -------------------------------------------------------------------------------------------

TEST_F(UpstreamProviderTest, ProtectedBucketRefusesEveryBucketCallWithoutSending) {
    guard::setForTesting({{.provider = "aws-s3", .account_ref = std::string("111122223333"), .bucket = "locked"},
                          {.provider = "cloudflare-r2", .account_ref = std::string(kUpR2Account), .bucket = "locked"}});
    handler = [](const http::Request&) {
        return upRespond(200, R"(<ListAllMyBucketsResult><Buckets><Bucket><Name>locked</Name></Bucket></Buckets></ListAllMyBucketsResult>)");
    };

    admin::AwsAdmin aws(upAwsKey());
    admin::R2Admin r2(upR2Key());
    admin::AwsEvents awsEvents(upAwsKey());
    admin::R2Events r2Events(upR2Key());
    const admin::SubscriptionSpec spec{.bucket = "locked", .rule_id = "vaulthalla-1", .prefix = ""};

    for (admin::AdminClient* client : std::initializer_list<admin::AdminClient*>{&aws, &r2}) {
        EXPECT_THROW((void)client->headBucket("locked"), vh::storage::upstream::BucketProtected);
        EXPECT_THROW(client->createBucket({.name = "locked", .region = std::nullopt}), vh::storage::upstream::BucketProtected);
        EXPECT_THROW(client->deleteBucket("locked"), vh::storage::upstream::BucketProtected);
        EXPECT_THROW((void)client->inspect("locked"), vh::storage::upstream::BucketProtected);
        EXPECT_THROW(client->putLifecycle("locked", {}), vh::storage::upstream::BucketProtected);
        EXPECT_THROW((void)client->versioning("locked"), vh::storage::upstream::BucketProtected);
        EXPECT_THROW(client->putVersioning("locked", admin::Versioning::Enabled), vh::storage::upstream::BucketProtected);
        EXPECT_THROW(client->putVersioning("locked", admin::Versioning::Suspended), vh::storage::upstream::BucketProtected);
        EXPECT_THROW((void)client->listObjects("locked", {}, 10), vh::storage::upstream::BucketProtected);
        EXPECT_THROW((void)client->listObjectVersions("locked", {}, 10), vh::storage::upstream::BucketProtected);
        EXPECT_THROW((void)client->deleteObjects("locked", {{.key = "a", .size = 0, .etag = {}, .last_modified = {},
                                                             .version_id = {}, .delete_marker = false, .latest = true}}),
                     vh::storage::upstream::BucketProtected);
    }
    EXPECT_THROW((void)awsEvents.subscribe(upAwsChannel(), spec), vh::storage::upstream::BucketProtected);
    EXPECT_THROW(awsEvents.unsubscribe(upAwsChannel(), spec, {"vaulthalla-1"}), vh::storage::upstream::BucketProtected);
    EXPECT_THROW((void)awsEvents.rules("locked"), vh::storage::upstream::BucketProtected);
    EXPECT_THROW((void)r2Events.subscribe(upR2Channel(), spec), vh::storage::upstream::BucketProtected);
    EXPECT_THROW(r2Events.unsubscribe(upR2Channel(), spec, {"r"}), vh::storage::upstream::BucketProtected);
    EXPECT_THROW((void)r2Events.rules("locked"), vh::storage::upstream::BucketProtected);
    EXPECT_TRUE(sent.empty()) << sent.size() << " request(s) reached the provider";

    // Account-level listing still shows the name.
    EXPECT_EQ(aws.listBuckets({}, 100).buckets.front().name, "locked");
    // Another bucket of the same accounts is unaffected.
    EXPECT_FALSE(guard::isProtected(aws.bucketIdentity("open")));
}

TEST_F(UpstreamProviderTest, UnknownAccountFailsClosed) {
    guard::setForTesting({{.provider = "aws-s3", .account_ref = std::string("999999999999"), .bucket = "shared-name"}});
    // STS fails, so the account is unknown: a lock on the name in any account applies.
    handler = [](const http::Request&) { return upRespond(500, "<Error><Code>InternalError</Code></Error>"); };
    auto key = upAwsKey();
    key->provider_account_id.reset();
    admin::AwsAdmin aws(key);
    EXPECT_THROW((void)aws.headBucket("shared-name"), vh::storage::upstream::BucketProtected);
}

// ---- secrets -------------------------------------------------------------------------------------------------------

TEST_F(UpstreamProviderTest, ErrorsNeverCarrySecrets) {
    const std::string body = std::string("<Error><Code>SignatureDoesNotMatch</Code><Message>bad secret ") + kUpAwsSecret +
                             " Authorization: AWS4-HMAC-SHA256 Credential=AKIAEXAMPLE/20261015/us-east-2/s3, "
                             "Signature=0123456789abcdef0123456789abcdef Bearer abc.def.ghi</Message>"
                             "<StringToSign>AWS4-HMAC-SHA256 secret-bits</StringToSign></Error>";
    handler = [&](const http::Request&) { return upRespond(403, body); };
    admin::AwsAdmin aws(upAwsKey());
    try {
        aws.createBucket({.name = "vh-x", .region = std::nullopt});
        FAIL() << "expected an error";
    } catch (const admin::ProviderError& e) {
        const std::string what = e.what();
        EXPECT_EQ(what.find(kUpAwsSecret), std::string::npos);
        EXPECT_EQ(what.find(kUpCfToken), std::string::npos);
        EXPECT_EQ(what.find("0123456789abcdef0123456789abcdef"), std::string::npos);
        EXPECT_EQ(what.find("abc.def.ghi"), std::string::npos);
        EXPECT_EQ(what.find("secret-bits"), std::string::npos);
        EXPECT_EQ(e.code, "SignatureDoesNotMatch");
        EXPECT_LE(what.size(), 420u);
    }

    namespace d = admin::detail;
    const auto redacted = d::redact(std::string(2000, 'x') + kUpAwsSecret, {kUpAwsSecret});
    EXPECT_LE(redacted.size(), 404u);
    EXPECT_EQ(d::redact(std::string("token=") + kUpCfToken, {kUpCfToken}), "token=[redacted]");
    EXPECT_EQ(d::redact("Bearer sk_live_123", {}), "Bearer [redacted]");

    // Cloudflare: the bearer token must not survive into the message either.
    handler = [&](const http::Request&) {
        return upRespond(400, nlohmann::json{{"success", false},
                                             {"errors", {{{"code", 10000}, {"message", std::string("Authentication error for ") + kUpCfToken}}}}}
                                  .dump());
    };
    admin::R2Events r2(upR2Key());
    try {
        (void)r2.api("GET", std::string("/accounts/") + kUpR2Account + "/queues?per_page=1");
        FAIL() << "expected an error";
    } catch (const admin::ProviderError& e) {
        EXPECT_EQ(std::string(e.what()).find(kUpCfToken), std::string::npos);
        EXPECT_TRUE(e.accessDenied());
        EXPECT_EQ(e.code, "10000");
    }
}

TEST_F(UpstreamProviderTest, ListingsParse) {
    namespace d = admin::detail;
    const auto buckets = d::parseListBuckets(R"(<ListAllMyBucketsResult><Buckets>
        <Bucket><Name>a</Name><CreationDate>2026-01-02T03:04:05.000Z</CreationDate><BucketRegion>us-east-2</BucketRegion></Bucket>
        <Bucket><Name>b</Name></Bucket></Buckets><ContinuationToken>next</ContinuationToken></ListAllMyBucketsResult>)");
    ASSERT_EQ(buckets.buckets.size(), 2u);
    EXPECT_EQ(buckets.buckets[0].region, std::optional<std::string>("us-east-2"));
    EXPECT_EQ(buckets.buckets[0].created_at, std::optional<std::time_t>(1767323045));
    EXPECT_EQ(buckets.next_token, "next");

    const auto objects = d::parseListObjectsV2(R"(<ListBucketResult><IsTruncated>true</IsTruncated>
        <Contents><Key>k 1</Key><Size>12</Size><ETag>&quot;abc&quot;</ETag></Contents>
        <NextContinuationToken>tok</NextContinuationToken></ListBucketResult>)");
    ASSERT_EQ(objects.objects.size(), 1u);
    EXPECT_EQ(objects.objects[0].etag, "abc");
    EXPECT_EQ(objects.objects[0].size, 12u);
    EXPECT_EQ(objects.next_token, "tok");

    const auto versions = d::parseListObjectVersions(R"(<ListVersionsResult><IsTruncated>true</IsTruncated>
        <Version><Key>k</Key><VersionId>v2</VersionId><IsLatest>true</IsLatest><Size>5</Size><ETag>"e"</ETag></Version>
        <DeleteMarker><Key>k</Key><VersionId>v1</VersionId><IsLatest>false</IsLatest></DeleteMarker>
        <NextKeyMarker>k</NextKeyMarker><NextVersionIdMarker>v1</NextVersionIdMarker></ListVersionsResult>)");
    ASSERT_EQ(versions.objects.size(), 2u);
    EXPECT_FALSE(versions.objects[0].delete_marker);
    EXPECT_TRUE(versions.objects[1].delete_marker);
    EXPECT_EQ(versions.next_token, "k\nv1");

    EXPECT_EQ(d::parseDeleteObjectsErrors(R"(<DeleteResult><Error><Key>k</Key><VersionId>v</VersionId><Code>AccessDenied</Code></Error></DeleteResult>)"),
              (std::vector<std::pair<std::string, std::string>>{{"k?versionId=v", "AccessDenied"}}));
    EXPECT_NE(d::buildDeleteObjects({{.key = "a&b", .size = 0, .etag = {}, .last_modified = {}, .version_id = std::string("v1"),
                                      .delete_marker = false, .latest = true}})
                  .find("<Key>a&amp;b</Key><VersionId>v1</VersionId>"),
              std::string::npos);
}

// FX-2 (security review #1/#5): names that would change what a URL addresses never reach a provider, and the
// bearer-token Cloudflare paths (no signature covers them) carry the bucket encoded.
TEST_F(UpstreamProviderTest, InvalidBucketNamesNeverReachAProvider) {
    handler = [](const http::Request&) { return upRespond(200, "{}"); };
    admin::AwsAdmin aws(upAwsKey());
    admin::AwsEvents awsEvents(upAwsKey());
    admin::R2Events r2Events(upR2Key());
    for (const std::string bad : {"x/../prod", "prod/configuration?", "Prod", "ab", "prod%2F..", "bucket*", "a b",
                                  "prod#frag", "../prod"}) {
        EXPECT_THROW((void)aws.headBucket(bad), std::invalid_argument) << bad;
        EXPECT_THROW((void)aws.inspect(bad), std::invalid_argument) << bad;
        EXPECT_THROW((void)aws.listObjects(bad, {}, 1000), std::invalid_argument) << bad;
        EXPECT_THROW(aws.createBucket({.name = bad, .region = std::string("us-east-2")}), std::invalid_argument) << bad;
        EXPECT_THROW((void)awsEvents.subscribe(upAwsChannel(), {.bucket = bad, .rule_id = "vaulthalla-1", .prefix = ""}),
                     std::invalid_argument) << bad;
        EXPECT_THROW((void)r2Events.rules(bad), std::invalid_argument) << bad;
        EXPECT_THROW((void)r2Events.subscribe(upR2Channel(), {.bucket = bad, .rule_id = "vaulthalla-1", .prefix = ""}),
                     std::invalid_argument) << bad;
        EXPECT_THROW(r2Events.unsubscribe(upR2Channel(), {.bucket = bad, .rule_id = "vaulthalla-1", .prefix = ""}, {"r1"}),
                     std::invalid_argument) << bad;
    }
    EXPECT_TRUE(sent.empty()) << "a refused name must not cost a single request";
}

TEST_F(UpstreamProviderTest, CloudflarePathsEncodeTheirSegments) {
    UpFakeCloudflare cf;
    handler = std::ref(cf);
    admin::R2Events events(upR2Key());
    (void)events.rules("vh-r2.with.dots");
    ASSERT_FALSE(sent.empty());
    EXPECT_NE(sent.back().url.find("/event_notifications/r2/vh-r2.with.dots/configuration"), std::string::npos);
    EXPECT_EQ(vh::storage::upstream::encodePathSegment("a/b?c#d e%"), "a%2Fb%3Fc%23d%20e%25");
}

TEST_F(UpstreamProviderTest, RegionsThatAreNotRegionsAreRefusedBeforeAnyRequest) {
    handler = [](const http::Request&) { return upRespond(200); };
    admin::AwsAdmin aws(upAwsKey());
    for (const std::string bad : {"evil.example/#", "us-east-1.evil.com", "US-EAST-1", "us east 1"})
        EXPECT_THROW(aws.createBucket({.name = "vh-good-name", .region = bad}), std::invalid_argument) << bad;
    EXPECT_TRUE(sent.empty());
    for (const std::string good : {"us-east-2", "eu-central-1", "ap-southeast-4", "us-gov-west-1", "cn-northwest-1"})
        EXPECT_TRUE(vh::storage::upstream::validAwsRegion(good)) << good;
    EXPECT_TRUE(vh::storage::upstream::validR2LocationHint("wnam"));
    EXPECT_FALSE(vh::storage::upstream::validR2LocationHint("wnam/../x"));

    // The CreateBucket body is built as XML, not by splicing strings.
    aws.createBucket({.name = "vh-good-name", .region = std::string("us-east-2")});
    ASSERT_EQ(sent.size(), 1u);
    EXPECT_NE(sent[0].body.find("<LocationConstraint>us-east-2</LocationConstraint>"), std::string::npos);
}

// FX-2 (security review #2, data-safety #9): identity follows the endpoint, not the provider label.
TEST_F(UpstreamProviderTest, IdentityFollowsTheEndpointWhateverTheProviderLabel) {
    const auto r2AsOther = std::make_shared<APIKey>(1, "mislabelled", S3Provider::Other, "0123456789abcdef0123456789abcdef",
                                                   kUpR2Secret, "auto",
                                                   std::string("https://") + kUpR2Account + ".r2.cloudflarestorage.com");
    const auto id = vh::storage::upstream::identityFor(*r2AsOther, "prod");
    EXPECT_EQ(id.provider, "cloudflare-r2");
    EXPECT_EQ(id.account_ref.value_or(""), kUpR2Account);
    guard::setForTesting({{.provider = "cloudflare-r2", .account_ref = std::string(kUpR2Account), .bucket = "prod"}});
    EXPECT_TRUE(guard::isProtected(id)) << "a cloudflare-r2 lock covers the bucket however the key is labelled";

    const auto awsAsMinio = std::make_shared<APIKey>(1, "mislabelled-aws", S3Provider::MinIO, "AKIAEXAMPLEEXAMPLE00",
                                                    kUpAwsSecret, "us-east-2", "https://s3.us-east-2.amazonaws.com");
    const auto awsId = vh::storage::upstream::identityFor(*awsAsMinio, "prod-aws");
    EXPECT_EQ(awsId.provider, "aws-s3");
    EXPECT_FALSE(awsId.account_ref.has_value()) << "no resolved account: fail closed";
    guard::setForTesting({{.provider = "aws-s3", .account_ref = std::string("111122223333"), .bucket = "prod-aws"}});
    EXPECT_TRUE(guard::isProtected(awsId)) << "an unknown account matches any aws-s3 lock on the name";

    EXPECT_TRUE(admin::providerEndpointMismatch(*r2AsOther).has_value());
    EXPECT_TRUE(admin::providerEndpointMismatch(*awsAsMinio).has_value());
    EXPECT_FALSE(admin::providerEndpointMismatch(*upAwsKey()).has_value());
    EXPECT_FALSE(admin::providerEndpointMismatch(*upR2Key()).has_value());
    const auto minio = std::make_shared<APIKey>(1, "minio", S3Provider::MinIO, "minioaccesskey00000000",
                                               "miniosecret0000000000", "us-east-1", "https://minio.lan:9000");
    EXPECT_EQ(vh::storage::upstream::identityFor(*minio, "b").provider, "s3:minio");
    EXPECT_FALSE(admin::providerEndpointMismatch(*minio).has_value());
}

// ---- provider versioning (file recovery) --------------------------------------------------------------------------

namespace {

constexpr const char* kUpVerNs = R"( xmlns="http://s3.amazonaws.com/doc/2006-03-01/")";

std::string upVerXml(const std::string& inner) {
    return std::string("<?xml version=\"1.0\" encoding=\"UTF-8\"?><VersioningConfiguration") + kUpVerNs + ">" + inner +
           "</VersioningConfiguration>";
}

http::Response upVerHeadOr(const http::Request& r, http::Response otherwise) {
    if (r.method == "HEAD") return upRespond(200, {}, {{"x-amz-bucket-region", "us-east-2"}});
    return otherwise;
}

}  // namespace

TEST_F(UpstreamProviderTest, GetVersioningParsesStatusAndMfaDelete) {
    namespace d = admin::detail;
    EXPECT_EQ(d::parseVersioningState(upVerXml("<Status>Enabled</Status>")).status, admin::Versioning::Enabled);
    EXPECT_EQ(d::parseVersioningState(upVerXml("<Status>Suspended</Status>")).status, admin::Versioning::Suspended);
    const auto never = d::parseVersioningState(std::string("<VersioningConfiguration") + kUpVerNs + "/>");
    EXPECT_EQ(never.status, admin::Versioning::Unversioned) << "never configured: no Status element";
    EXPECT_EQ(never.mfa_delete, std::nullopt);
    const auto mfaOn = d::parseVersioningState(upVerXml("<Status>Enabled</Status><MfaDelete>Enabled</MfaDelete>"));
    EXPECT_EQ(mfaOn.mfa_delete, std::optional<bool>(true));
    const auto mfaOff = d::parseVersioningState(upVerXml("<Status>Suspended</Status><MfaDelete>Disabled</MfaDelete>"));
    EXPECT_EQ(mfaOff.status, admin::Versioning::Suspended);
    EXPECT_EQ(mfaOff.mfa_delete, std::optional<bool>(false));

    // Through the adapter: HEAD (region) then GET ?versioning on the bucket's regional endpoint.
    handler = [](const http::Request& r) {
        return upVerHeadOr(r, upRespond(200, upVerXml("<Status>Enabled</Status><MfaDelete>Disabled</MfaDelete>")));
    };
    admin::AwsAdmin aws(upAwsKey());
    const auto state = aws.versioning("vh-ver");
    EXPECT_EQ(state.status, admin::Versioning::Enabled);
    EXPECT_EQ(state.mfa_delete, std::optional<bool>(false));
    const auto gets = matching("GET", "?versioning");
    ASSERT_EQ(gets.size(), 1u);
    EXPECT_EQ(gets[0].url, "https://s3.us-east-2.amazonaws.com/vh-ver?versioning=");
    EXPECT_TRUE(gets[0].body.empty());

    // inspect carries MFA delete next to the status.
    handler = [](const http::Request& r) {
        if (r.url.find("?versioning") != std::string::npos)
            return upRespond(200, upVerXml("<Status>Suspended</Status><MfaDelete>Enabled</MfaDelete>"));
        if (r.url.find("?object-lock") != std::string::npos)
            return upRespond(404, "<Error><Code>ObjectLockConfigurationNotFoundError</Code></Error>");
        if (r.url.find("?lifecycle") != std::string::npos)
            return upRespond(404, "<Error><Code>NoSuchLifecycleConfiguration</Code></Error>");
        return upVerHeadOr(r, upRespond(200, "<NotificationConfiguration/>"));
    };
    const auto config = aws.inspect("vh-ver");
    EXPECT_EQ(config.versioning, admin::Versioning::Suspended);
    EXPECT_EQ(config.mfa_delete, std::optional<bool>(true));
    EXPECT_EQ(config.object_lock, std::optional<bool>(false));

    // A refusal is an error from versioning(), never a guessed status; inspect turns it into Unknown + a warning.
    handler = [](const http::Request& r) {
        return upVerHeadOr(r, upRespond(403, "<Error><Code>AccessDenied</Code><Message>no s3:GetBucketVersioning</Message></Error>"));
    };
    try {
        (void)aws.versioning("vh-ver");
        FAIL() << "AccessDenied must throw";
    } catch (const admin::ProviderError& e) {
        EXPECT_TRUE(e.accessDenied());
        EXPECT_NE(std::string(e.what()).find("GetBucketVersioning"), std::string::npos);
    }
    const auto denied = aws.inspect("vh-ver");
    EXPECT_EQ(denied.versioning, admin::Versioning::Unknown);
    EXPECT_EQ(denied.mfa_delete, std::nullopt);
    EXPECT_FALSE(denied.warnings.empty());
}

TEST_F(UpstreamProviderTest, PutVersioningSendsStatusWithIntegrityHeaderAndNeverMfa) {
    handler = [](const http::Request& r) { return upVerHeadOr(r, upRespond(200)); };
    admin::AwsAdmin aws(upAwsKey());
    aws.putVersioning("vh-ver", admin::Versioning::Enabled);
    auto puts = matching("PUT", "?versioning");
    ASSERT_EQ(puts.size(), 1u);
    const auto& put = puts[0];
    EXPECT_EQ(put.url, "https://s3.us-east-2.amazonaws.com/vh-ver?versioning=");
    EXPECT_NE(put.body.find("<VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">"), std::string::npos);
    EXPECT_NE(put.body.find("<Status>Enabled</Status>"), std::string::npos);
    EXPECT_EQ(put.body.find("MfaDelete"), std::string::npos);
    EXPECT_EQ(upHeader(put, "content-md5"), admin::detail::md5Base64(put.body)) << "AWS requires an integrity header";
    EXPECT_TRUE(upHeader(put, "x-amz-mfa").empty());
    EXPECT_EQ(upHeader(put, "x-amz-expected-bucket-owner"), "111122223333") << "never another account's bucket";
    EXPECT_EQ(upHeader(put, "content-type"), "application/xml");
    EXPECT_NE(upHeader(put, "authorization").find("/us-east-2/s3/aws4_request"), std::string::npos);

    sent.clear();
    aws.putVersioning("vh-ver", admin::Versioning::Suspended);
    puts = matching("PUT", "?versioning");
    ASSERT_EQ(puts.size(), 1u);
    EXPECT_NE(puts[0].body.find("<Status>Suspended</Status>"), std::string::npos);

    // A bucket can never be put back to unversioned: refused before anything is sent.
    sent.clear();
    EXPECT_THROW(aws.putVersioning("vh-ver", admin::Versioning::Unversioned), std::invalid_argument);
    EXPECT_THROW(aws.putVersioning("vh-ver", admin::Versioning::Unknown), std::invalid_argument);
    EXPECT_THROW(aws.putVersioning("Not_A_Bucket", admin::Versioning::Enabled), std::invalid_argument);
    EXPECT_TRUE(sent.empty());

    // Provider refusals surface as ProviderError (Object Lock suspension, missing permission).
    handler = [](const http::Request& r) {
        return upVerHeadOr(r, upRespond(409, "<Error><Code>InvalidBucketState</Code><Message>An Object Lock "
                                             "configuration is present</Message></Error>"));
    };
    try {
        aws.putVersioning("vh-ver", admin::Versioning::Suspended);
        FAIL() << "409 must throw";
    } catch (const admin::ProviderError& e) {
        EXPECT_EQ(e.code, "InvalidBucketState");
        EXPECT_EQ(e.http_status, 409);
    }

    // Without a known account no expected-owner header is invented.
    sent.clear();
    handler = [](const http::Request& r) {
        if (r.url.find("sts.amazonaws.com") != std::string::npos) return upRespond(500);
        return upVerHeadOr(r, upRespond(200));
    };
    auto anonymous = upAwsKey();
    anonymous->provider_account_id.reset();
    admin::AwsAdmin awsNoAccount(anonymous);
    awsNoAccount.putVersioning("vh-ver", admin::Versioning::Enabled);
    puts = matching("PUT", "?versioning");
    ASSERT_EQ(puts.size(), 1u);
    EXPECT_TRUE(upHeader(puts[0], "x-amz-expected-bucket-owner").empty());
}

TEST_F(UpstreamProviderTest, R2HasNoVersioningAndSendsNothing) {
    handler = [](const http::Request&) { return upRespond(200); };
    admin::R2Admin r2(upR2Key());
    EXPECT_FALSE(r2.supportsVersioning());
    EXPECT_TRUE(admin::AwsAdmin(upAwsKey()).supportsVersioning());

    const auto state = r2.versioning("vh-r2");
    EXPECT_EQ(state.status, admin::Versioning::Unversioned) << "R2 never claims a versioned bucket";
    EXPECT_EQ(state.mfa_delete, std::nullopt);
    try {
        r2.putVersioning("vh-r2", admin::Versioning::Enabled);
        FAIL() << "R2 must refuse versioning";
    } catch (const admin::CapabilityMissing& e) {
        EXPECT_EQ(e.capability, "versioning");
        EXPECT_NE(std::string(e.what()).find("R2"), std::string::npos);
    }
    EXPECT_THROW(r2.putVersioning("vh-r2", admin::Versioning::Suspended), admin::CapabilityMissing);
    EXPECT_THROW(r2.putVersioning("vh-r2", admin::Versioning::Unversioned), std::invalid_argument);
    EXPECT_TRUE(sent.empty()) << sent.size() << " request(s) reached R2";
}

TEST_F(UpstreamProviderTest, ProbeReportsVersioningCapability) {
    handler = [](const http::Request& r) {
        if (r.url.find("sts.amazonaws.com") != std::string::npos)
            return upRespond(200, R"(<GetCallerIdentityResponse><GetCallerIdentityResult><Arn>arn:aws:iam::111122223333:user/vh</Arn>
                <Account>111122223333</Account></GetCallerIdentityResult></GetCallerIdentityResponse>)");
        if (!upHeader(r, "x-amz-target").empty())
            return upRespond(400, R"({"__type":"com.amazonaws.sqs#AccessDenied","message":"denied"})");
        return upRespond(200, R"(<ListAllMyBucketsResult><Buckets><Bucket><Name>b1</Name></Bucket></Buckets></ListAllMyBucketsResult>)");
    };
    const auto find = [](const admin::Capabilities& caps) -> std::optional<admin::Capability> {
        for (const auto& c : caps.items)
            if (c.name == "versioning") return c;
        return std::nullopt;
    };

    admin::AwsAdmin aws(upAwsKey());
    const auto awsCap = find(aws.probe());
    ASSERT_TRUE(awsCap.has_value());
    EXPECT_TRUE(awsCap->ok);
    EXPECT_FALSE(awsCap->probed) << "checking PutBucketVersioning would change a bucket";
    for (const char* action : {"s3:GetBucketVersioning", "s3:PutBucketVersioning", "s3:ListBucketVersions", "s3:GetObjectVersion"})
        EXPECT_NE(awsCap->detail.find(action), std::string::npos) << action;
    EXPECT_TRUE(matching("PUT", "?versioning").empty());

    admin::R2Admin r2(upR2Key(false));
    const auto r2Caps = r2.probe();
    const auto r2Cap = find(r2Caps);
    ASSERT_TRUE(r2Cap.has_value());
    EXPECT_FALSE(r2Cap->ok);
    EXPECT_EQ(r2Cap->detail, admin::kR2VersioningUnsupported);
    EXPECT_FALSE(r2Caps.has("versioning"));
}

TEST_F(UpstreamProviderTest, R2InspectSendsNoVersioningRequest) {
    handler = [](const http::Request& r) {
        if (r.url.find("?lifecycle") != std::string::npos)
            return upRespond(404, "<Error><Code>NoSuchLifecycleConfiguration</Code></Error>");
        return upRespond(200);
    };
    admin::R2Admin r2(upR2Key(false));
    const auto config = r2.inspect("vh-r2");
    EXPECT_EQ(config.versioning, admin::Versioning::Unversioned);
    EXPECT_EQ(config.mfa_delete, std::nullopt);
    EXPECT_TRUE(matching("GET", "?versioning").empty());
}

// ---- noncurrent retention already on a bucket ------------------------------------------------------------------------

namespace {

std::vector<admin::LifecycleRule> upVerRules() {
    return admin::detail::parseLifecycle(std::string("<LifecycleConfiguration") + kUpVerNs + R"(>
      <Rule><ID>backup-tool-keep-90</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>
        <NoncurrentVersionExpiration><NoncurrentDays>90</NoncurrentDays></NoncurrentVersionExpiration></Rule>
      <Rule><ID>keep-three-newest</ID><Filter><Prefix>vaults/</Prefix></Filter><Status>Enabled</Status>
        <NoncurrentVersionExpiration><NoncurrentDays>14</NoncurrentDays><NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule>
      <Rule><ID>disabled-aggressive</ID><Filter><Prefix></Prefix></Filter><Status>Disabled</Status>
        <NoncurrentVersionExpiration><NoncurrentDays>1</NoncurrentDays></NoncurrentVersionExpiration></Rule>
      <Rule><ID>tagged-scratch</ID><Filter><And><Prefix>vaults/</Prefix><Tag><Key>scratch</Key><Value>1</Value></Tag></And></Filter><Status>Enabled</Status>
        <NoncurrentVersionExpiration><NoncurrentDays>2</NoncurrentDays></NoncurrentVersionExpiration></Rule>
      <Rule><ID>other-prefix</ID><Prefix>logs/</Prefix><Status>Enabled</Status>
        <NoncurrentVersionExpiration><NoncurrentDays>3</NoncurrentDays></NoncurrentVersionExpiration></Rule>
      <Rule><ID>vault-subtree</ID><Filter><Prefix>vaults/photos/raw/</Prefix></Filter><Status>Enabled</Status>
        <NoncurrentVersionExpiration><NoncurrentDays>5</NoncurrentDays></NoncurrentVersionExpiration></Rule>
      <Rule><ID>current-only</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>
        <Expiration><Days>365</Days></Expiration></Rule>
      <Rule><ID>vaulthalla-managed</ID><Filter><Prefix>vaults/photos/</Prefix></Filter><Status>Enabled</Status>
        <NoncurrentVersionExpiration><NoncurrentDays>30</NoncurrentDays></NoncurrentVersionExpiration></Rule>
    </LifecycleConfiguration>)");
}

}  // namespace

TEST_F(UpstreamProviderTest, NoncurrentExpirationsReadForeignAndOwnedRules) {
    namespace lc = vh::storage::upstream::lifecycle;
    const auto rules = upVerRules();
    const auto all = lc::noncurrentExpirations(rules);
    ASSERT_EQ(all.size(), 7u) << "every rule with NoncurrentVersionExpiration, not the current-only one";

    EXPECT_EQ(all[0].rule_id, "backup-tool-keep-90");
    EXPECT_TRUE(all[0].foreign);
    EXPECT_EQ(all[0].days, std::optional<unsigned int>(90));
    EXPECT_EQ(all[0].newer_noncurrent_versions, std::nullopt);

    EXPECT_EQ(all[1].rule_id, "keep-three-newest");
    EXPECT_TRUE(rules[1].unmodeled) << "NewerNoncurrentVersions is outside the rule model";
    EXPECT_EQ(all[1].days, std::optional<unsigned int>(14));
    EXPECT_EQ(all[1].newer_noncurrent_versions, std::optional<unsigned int>(3));
    EXPECT_EQ(all[1].prefix, "vaults/");

    EXPECT_FALSE(all[2].enabled);
    EXPECT_TRUE(all[3].conditional);
    EXPECT_EQ(all[3].prefix, "vaults/");
    EXPECT_EQ(all[4].prefix, "logs/") << "legacy top-level Prefix";
    EXPECT_FALSE(all[6].foreign);
    EXPECT_EQ(all[6].rule_id, "vaulthalla-managed");

    using lc::Coverage;
    const std::string vault = "vaults/photos/";
    EXPECT_EQ(lc::coverage(all[0], vault), Coverage::Whole);
    EXPECT_EQ(lc::coverage(all[1], vault), Coverage::Whole);
    EXPECT_EQ(lc::coverage(all[2], vault), Coverage::None) << "disabled";
    EXPECT_EQ(lc::coverage(all[3], vault), Coverage::Partial) << "tag filter";
    EXPECT_EQ(lc::coverage(all[4], vault), Coverage::None) << "disjoint prefix";
    EXPECT_EQ(lc::coverage(all[5], vault), Coverage::Partial) << "a subtree of the vault";
    EXPECT_EQ(lc::coverage(all[6], vault), Coverage::Whole);

    // Shortest whole-prefix expiration: the NewerNoncurrentVersions rule (14) beats ours (30) and the backup tool (90).
    EXPECT_EQ(lc::effectiveNoncurrentDays(rules, vault), std::optional<unsigned int>(14));
    EXPECT_EQ(lc::effectiveNoncurrentDays(rules, "other/"), std::optional<unsigned int>(90));
    EXPECT_EQ(lc::effectiveNoncurrentDays(rules, "logs/x/"), std::optional<unsigned int>(3));

    // Nothing that covers the vault prefix: no retention (versions are kept until something deletes them).
    const std::vector<admin::LifecycleRule> narrow{rules[3], rules[4], rules[5], rules[2]};
    EXPECT_EQ(lc::effectiveNoncurrentDays(narrow, vault), std::nullopt);
    EXPECT_EQ(lc::effectiveNoncurrentDays({}, vault), std::nullopt);

    // Our rule as mergeOwnedRule rebuilds it (no raw XML) is read from its fields.
    const auto merged = lc::mergeOwnedRule({}, {.expire_noncurrent_days = 21, .prefix = std::string("vaults/")}, true);
    EXPECT_EQ(lc::effectiveNoncurrentDays(merged.rules, vault), std::optional<unsigned int>(21));
}

TEST_F(UpstreamProviderTest, OwnedNoncurrentRuleKeepsForeignNoncurrentRulesVerbatim) {
    namespace lc = vh::storage::upstream::lifecycle;
    namespace d = admin::detail;
    const auto current = d::parseLifecycle(std::string("<LifecycleConfiguration") + kUpVerNs + R"(>
      <Rule><ID>keep-three-newest</ID><Filter><Prefix>vaults/</Prefix></Filter><Status>Enabled</Status>
        <NoncurrentVersionExpiration><NoncurrentDays>14</NoncurrentDays><NewerNoncurrentVersions>3</NewerNoncurrentVersions></NoncurrentVersionExpiration></Rule>
      <Rule><ID>markers</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status>
        <Expiration><ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker></Expiration></Rule>
    </LifecycleConfiguration>)");
    ASSERT_EQ(current.size(), 2u);

    const auto merged = lc::mergeOwnedRule(current, {.expire_noncurrent_days = 30}, true);
    EXPECT_TRUE(merged.changed);
    EXPECT_TRUE(merged.destructive) << "a new noncurrent expiration deletes old versions";
    const auto written = d::parseLifecycle(d::buildLifecycle(merged.rules, true));
    ASSERT_EQ(written.size(), 3u);
    EXPECT_EQ(written[0].raw_xml, current[0].raw_xml);
    EXPECT_EQ(written[1].raw_xml, current[1].raw_xml);
    EXPECT_NE(written[0].raw_xml.find("<NewerNoncurrentVersions>3</NewerNoncurrentVersions>"), std::string::npos);
    EXPECT_NE(written[1].raw_xml.find("<ExpiredObjectDeleteMarker>true</ExpiredObjectDeleteMarker>"), std::string::npos);
    EXPECT_FALSE(written[2].foreign);
    EXPECT_EQ(written[2].expire_noncurrent_days, std::optional<unsigned int>(30));
    EXPECT_EQ(lc::effectiveNoncurrentDays(written, "vaults/a/"), std::optional<unsigned int>(14));

    // Lengthening ours is not destructive; R2 can't carry it at all.
    EXPECT_FALSE(lc::mergeOwnedRule(written, {.expire_noncurrent_days = 60}, true).destructive);
    EXPECT_THROW((void)lc::mergeOwnedRule(current, {.expire_noncurrent_days = 30}, false), std::invalid_argument);
}
