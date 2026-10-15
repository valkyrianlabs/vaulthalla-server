// Upstream event decoding (#96): AWS S3 → SQS bodies and Cloudflare R2 → Queues bodies into UpstreamEvent. DB-free.

#include "sync/events/Event.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

namespace {

using vh::sync::events::decodeAwsMessage;
using vh::sync::events::decodeR2Message;
using vh::sync::events::Kind;
using vh::sync::events::newerOrEqual;
using vh::sync::events::UpstreamEvent;

std::string awsRecord(const std::string& eventName, const std::string& key, const std::string& sequencer,
                      const std::string& extraObject = R"("size":1024,"eTag":"d41d8cd98f00b204e9800998ecf8427e",)") {
    return R"({"eventVersion":"2.6","eventSource":"aws:s3","awsRegion":"us-east-2",)"
           R"("eventTime":"2026-10-15T12:00:01.250Z","eventName":")" + eventName + R"(",)"
           R"("s3":{"s3SchemaVersion":"1.0","configurationId":"vaulthalla-7",)"
           R"("bucket":{"name":"vaulthalla-test-bucket","arn":"arn:aws:s3:::vaulthalla-test-bucket"},)"
           R"("object":{"key":")" + key + R"(",)" + extraObject + R"("sequencer":")" + sequencer + R"("}}})";
}

}

TEST(UpstreamEventDecode, AwsPutIsDecodedWithKeyEncodingSequencerAndRule) {
    const auto d = decodeAwsMessage(R"({"Records":[)" + awsRecord("ObjectCreated:Put", "photos/red+flower%26co.jpg", "0055AED6DCD90281E5") + "]}", "m-1");
    ASSERT_TRUE(d.error.empty()) << d.error;
    ASSERT_EQ(d.events.size(), 1u);
    const auto& e = d.events[0];
    EXPECT_EQ(e.provider, "aws-s3");
    EXPECT_EQ(e.bucket, "vaulthalla-test-bucket");
    EXPECT_EQ(e.key, "photos/red flower&co.jpg");
    EXPECT_EQ(e.kind, Kind::Created);
    EXPECT_EQ(e.sequencer.value_or(""), "0055AED6DCD90281E5");
    EXPECT_EQ(e.etag.value_or(""), "d41d8cd98f00b204e9800998ecf8427e");
    EXPECT_EQ(e.size.value_or(0), 1024u);
    EXPECT_EQ(e.rule_id, "vaulthalla-7");
    EXPECT_EQ(e.message_id, "m-1");
    EXPECT_EQ(e.event_time_ms % 1000, 250);
    EXPECT_FALSE(e.dedupe_key.empty());
}

TEST(UpstreamEventDecode, AwsRemovalsAndLifecycleExpirationAreRemovals) {
    for (const auto* name : {"ObjectRemoved:Delete", "ObjectRemoved:DeleteMarkerCreated", "LifecycleExpiration:Delete"}) {
        const auto d = decodeAwsMessage(R"({"Records":[)" + awsRecord(name, "a.txt", "01", "") + "]}", "m");
        ASSERT_TRUE(d.error.empty()) << name << ": " << d.error;
        ASSERT_EQ(d.events.size(), 1u) << name;
        EXPECT_EQ(d.events[0].kind, Kind::Removed) << name;
        EXPECT_FALSE(d.events[0].size.has_value());
    }
}

TEST(UpstreamEventDecode, AwsTestEventAndNonContentEventsAreIgnorable) {
    const auto test = decodeAwsMessage(
        R"({"Service":"Amazon S3","Event":"s3:TestEvent","Time":"2014-10-13T15:57:02.089Z","Bucket":"b"})", "m");
    EXPECT_TRUE(test.ignorable);
    EXPECT_TRUE(test.error.empty());
    EXPECT_TRUE(test.events.empty());

    const auto tagging = decodeAwsMessage(R"({"Records":[)" + awsRecord("ObjectTagging:Put", "a", "02") + "]}", "m");
    EXPECT_TRUE(tagging.ignorable);
    EXPECT_TRUE(tagging.events.empty());
}

TEST(UpstreamEventDecode, AwsSnsEnvelopeIsUnwrapped) {
    nlohmann::json inner = nlohmann::json::parse(R"({"Records":[)" + awsRecord("ObjectCreated:Copy", "k", "03") + "]}");
    nlohmann::json sns = {{"Type", "Notification"}, {"Message", inner.dump()}};
    const auto d = decodeAwsMessage(sns.dump(), "m");
    ASSERT_TRUE(d.error.empty()) << d.error;
    ASSERT_EQ(d.events.size(), 1u);
    EXPECT_EQ(d.events[0].key, "k");
}

TEST(UpstreamEventDecode, AwsMalformedMessagesAreErrorsNotPartialBatches) {
    EXPECT_FALSE(decodeAwsMessage("not json", "m").error.empty());
    EXPECT_FALSE(decodeAwsMessage(R"({"hello":1})", "m").error.empty());
    // One good record and one without a key: the whole message is refused (it goes to the DLQ, never half-applied).
    const auto mixed = decodeAwsMessage(R"({"Records":[)" + awsRecord("ObjectCreated:Put", "ok", "04") +
        R"(,{"eventName":"ObjectCreated:Put","s3":{"bucket":{"name":"b"},"object":{}}}]})", "m");
    EXPECT_FALSE(mixed.error.empty());
    EXPECT_TRUE(mixed.events.empty());
}

TEST(UpstreamEventDecode, AwsDuplicateDeliveriesShareADedupeKey) {
    const auto body = R"({"Records":[)" + awsRecord("ObjectCreated:Put", "dup", "0A") + "]}";
    EXPECT_EQ(decodeAwsMessage(body, "m-1").events.at(0).dedupe_key, decodeAwsMessage(body, "m-2").events.at(0).dedupe_key);
    const auto other = R"({"Records":[)" + awsRecord("ObjectCreated:Put", "dup", "0B") + "]}";
    EXPECT_NE(decodeAwsMessage(body, "m").events.at(0).dedupe_key, decodeAwsMessage(other, "m").events.at(0).dedupe_key);
}

TEST(UpstreamEventDecode, R2ActionsMapToKinds) {
    for (const auto* action : {"PutObject", "CopyObject", "CompleteMultipartUpload"}) {
        const auto d = decodeR2Message(std::string(R"({"account":"0123456789abcdef0123456789abcdef","action":")") + action +
            R"(","bucket":"vh-b","object":{"key":"dir/a b.txt","size":12,"eTag":"abc"},"eventTime":"2026-10-15T12:00:00.123Z"})", "r-1");
        ASSERT_TRUE(d.error.empty()) << d.error;
        ASSERT_EQ(d.events.size(), 1u);
        EXPECT_EQ(d.events[0].kind, Kind::Created);
        EXPECT_EQ(d.events[0].key, "dir/a b.txt");   // not URL-decoded: R2 sends keys as stored
        EXPECT_EQ(d.events[0].account_ref, "0123456789abcdef0123456789abcdef");
        EXPECT_EQ(d.events[0].size.value_or(0), 12u);
        EXPECT_EQ(d.events[0].event_time_ms % 1000, 123);
    }
    for (const auto* action : {"DeleteObject", "LifecycleDeletion"}) {
        const auto d = decodeR2Message(std::string(R"({"account":"a","action":")") + action +
            R"(","bucket":"vh-b","object":{"key":"k"},"eventTime":"2026-10-15T12:00:00Z"})", "r");
        ASSERT_EQ(d.events.size(), 1u);
        EXPECT_EQ(d.events[0].kind, Kind::Removed);
    }
}

TEST(UpstreamEventDecode, R2UnknownActionIsIgnorableAndGarbageIsAnError) {
    EXPECT_TRUE(decodeR2Message(R"({"action":"SomethingNew","bucket":"b","object":{"key":"k"}})", "r").ignorable);
    EXPECT_FALSE(decodeR2Message("{", "r").error.empty());
    EXPECT_FALSE(decodeR2Message(R"({"action":"PutObject","bucket":"b"})", "r").error.empty());
}

TEST(UpstreamEventDecode, OrderingUsesSequencerThenTime) {
    UpstreamEvent a, b;
    a.sequencer = "00FF";
    b.sequencer = "0100";   // greater once left-padded
    EXPECT_TRUE(newerOrEqual(b, a));
    EXPECT_FALSE(newerOrEqual(a, b));

    UpstreamEvent c, d;
    c.event_time_ms = 1000;
    d.event_time_ms = 1001;
    EXPECT_TRUE(newerOrEqual(d, c));
    EXPECT_FALSE(newerOrEqual(c, d));
}

TEST(UpstreamEventDecode, EventTimeParsesMilliseconds) {
    EXPECT_EQ(vh::sync::events::parseEventTimeMs("1970-01-01T00:00:01.5Z").value_or(-1), 1500);
    EXPECT_EQ(vh::sync::events::parseEventTimeMs("1970-01-01T00:00:02Z").value_or(-1), 2000);
    EXPECT_FALSE(vh::sync::events::parseEventTimeMs("yesterday").has_value());
}
