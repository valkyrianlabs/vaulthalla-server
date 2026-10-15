// Provider-contract tests for the AWS S3 / Cloudflare R2 admin and events adapters (#237, #96), DB-free: every
// request goes through curl::http's test transport, which answers like the provider would and records what was sent.

#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/s3/curl/Http.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <functional>
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
    auto p = d::mergeQueuePolicy("", kUpQueueArn, "111122223333", "a", true);
    p = d::mergeQueuePolicy(p, kUpQueueArn, "111122223333", "b", true);
    p = d::mergeQueuePolicy(p, kUpQueueArn, "111122223333", "a", true);   // no duplicate
    EXPECT_EQ(d::policyBuckets(p), (std::vector<std::string>{"a", "b"}));
    p = d::mergeQueuePolicy(p, kUpQueueArn, "111122223333", "a", false);
    EXPECT_EQ(d::policyBuckets(p), std::vector<std::string>{"b"});
    EXPECT_EQ(d::mergeQueuePolicy(p, kUpQueueArn, "111122223333", "b", false), "");
    const auto foreign = upForeignPolicy();
    const auto withOurs = d::mergeQueuePolicy(foreign, kUpQueueArn, "111122223333", "a", true);
    EXPECT_EQ(nlohmann::json::parse(d::mergeQueuePolicy(withOurs, kUpQueueArn, "111122223333", "a", false)),
              nlohmann::json::parse(foreign));
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

    sent.clear();
    handler = [](const http::Request& r) {
        if (r.url.starts_with("https://s3.amazonaws.com/")) return upRespond(301, {}, {{"x-amz-bucket-region", "us-west-2"}});
        return upRespond(200, {}, {{"x-amz-bucket-region", "us-west-2"}});
    };
    EXPECT_EQ(aws.headBucket("vh-west"), std::optional<std::string>("us-west-2"));
    ASSERT_EQ(sent.size(), 2u);
    EXPECT_EQ(sent[1].url, "https://s3.us-west-2.amazonaws.com/vh-west");
    EXPECT_EQ(aws.regionOf("vh-west"), "us-west-2");   // cached: no third request
    EXPECT_EQ(sent.size(), 2u);
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
            nlohmann::json q1 = {{"queueId", "q-1"}, {"queueName", "vaulthalla-events-r2"}, {"rules", nlohmann::json::array()}};
            nlohmann::json q2 = {{"queueId", "q-other"}, {"queueName", "other-app"}, {"rules", nlohmann::json::array()}};
            for (const auto& rule : rules) (rule.value("queue", "q-1") == "q-other" ? q2 : q1)["rules"].push_back(rule);
            return upRespond(200, upCfOk({{"bucketName", "vh-r2"}, {"queues", {q1, q2}}}));
        }
        if (path.starts_with(acct + "/queues?page=")) {
            return upRespond(200, upCfOk({{{"queue_id", "q-dlq"}, {"queue_name", "vaulthalla-events-r2-dlq"}},
                                          {{"queue_id", "q-1"}, {"queue_name", "vaulthalla-events-r2"}}},
                                         {{"page", 1}, {"total_pages", 1}}));
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
