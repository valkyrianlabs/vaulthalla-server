#pragma once

// In-memory provider for the event pipeline tests (#96): an AdminClient and an EventsClient sharing one state
// object, installed through storage::s3::provider::admin::setFactoryForTesting.

#include "storage/s3/curl/Http.hpp"
#include "storage/s3/provider/admin/Admin.hpp"

#include <atomic>
#include <chrono>
#include <ctime>
#include <deque>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_support::upstream_events {

namespace padmin = storage::s3::provider::admin;

struct FakeProviderState {
    std::mutex mutex;
    std::string account = "123456789012";
    std::string region = "us-east-1";
    unsigned int identityCalls = 0;

    std::deque<padmin::ReceivedMessage> queue;
    std::vector<std::string> acked;
    std::optional<std::string> pollError;        // poll throws ProviderError with this message
    std::optional<std::string> capabilityMissing;  // eventsFor throws CapabilityMissing
    unsigned int subscribeFailures = 0;           // the next N subscribe calls throw
    unsigned int ensureCalls = 0, subscribeCalls = 0, removeChannelCalls = 0;
    std::vector<std::string> unsubscribed;        // rule ids handed to unsubscribe
    std::vector<padmin::NotificationRule> foreignRules;
    std::atomic<bool> blockPolls{false};          // poll blocks until the HTTP layer reports cancellation
    std::atomic<bool> pollEntered{false};
    unsigned int nextReceipt = 0;

    void push(const std::string& body) {
        std::scoped_lock lock(mutex);
        padmin::ReceivedMessage m;
        m.receipt = "r-" + std::to_string(++nextReceipt);
        m.message_id = "m-" + std::to_string(nextReceipt);
        m.body = body;
        queue.push_back(std::move(m));
    }
};

inline std::shared_ptr<FakeProviderState>& providerState() {
    static auto s = std::make_shared<FakeProviderState>();
    return s;
}

class FakeAdmin final : public padmin::AdminClient {
public:
    explicit FakeAdmin(std::shared_ptr<FakeProviderState> s) : s_(std::move(s)) {}
    std::string providerId() const override { return "aws-s3"; }
    padmin::AccountIdentity identity() override {
        std::scoped_lock lock(s_->mutex);
        ++s_->identityCalls;
        return {.provider = "aws-s3", .account_ref = s_->account, .principal = "arn:aws:iam::" + s_->account + ":user/t"};
    }
    padmin::Capabilities probe() override { return {}; }
    padmin::BucketPage listBuckets(const std::string&, unsigned int) override { return {}; }
    std::optional<std::string> headBucket(const std::string&) override { return s_->region; }
    void createBucket(const padmin::CreateBucketRequest&) override {}
    void deleteBucket(const std::string&) override {}
    padmin::BucketConfiguration inspect(const std::string& bucket) override {
        padmin::BucketConfiguration config;
        config.bucket = bucket;
        return config;
    }
    void putLifecycle(const std::string&, const std::vector<padmin::LifecycleRule>&) override {}
    padmin::ObjectPage listObjects(const std::string&, const std::string&, unsigned int) override { return {}; }
    padmin::ObjectPage listObjectVersions(const std::string&, const std::string&, unsigned int) override { return {}; }
    std::vector<std::pair<std::string, std::string>> deleteObjects(const std::string&,
                                                                   const std::vector<padmin::ObjectSummary>&) override {
        return {};
    }
    padmin::Metrics metrics() const override { return {}; }

private:
    std::shared_ptr<FakeProviderState> s_;
};

class FakeEvents final : public padmin::EventsClient {
public:
    explicit FakeEvents(std::shared_ptr<FakeProviderState> s) : s_(std::move(s)) {}
    std::string providerId() const override { return "aws-s3"; }

    padmin::ChannelRef ensureChannel(const padmin::ChannelSpec& spec) override {
        std::scoped_lock lock(s_->mutex);
        ++s_->ensureCalls;
        return {.queue_name = spec.queue_name,
                .queue_ref = "https://sqs." + spec.region + ".amazonaws.com/" + s_->account + "/" + spec.queue_name,
                .queue_arn = "arn:aws:sqs:" + spec.region + ":" + s_->account + ":" + spec.queue_name,
                .dlq_ref = "dlq", .dlq_arn = "dlq-arn", .created = true};
    }
    std::vector<std::string> subscribe(const padmin::ChannelRef&, const padmin::SubscriptionSpec& spec) override {
        std::scoped_lock lock(s_->mutex);
        ++s_->subscribeCalls;
        if (s_->subscribeFailures > 0) {
            --s_->subscribeFailures;
            throw padmin::ProviderError("Configurations overlap with another application's rule", "InvalidArgument", 400);
        }
        return {spec.rule_id};
    }
    void unsubscribe(const padmin::ChannelRef&, const padmin::SubscriptionSpec&, const std::vector<std::string>& ruleIds) override {
        std::scoped_lock lock(s_->mutex);
        s_->unsubscribed.insert(s_->unsubscribed.end(), ruleIds.begin(), ruleIds.end());
    }
    std::vector<padmin::NotificationRule> rules(const std::string&) override {
        std::scoped_lock lock(s_->mutex);
        return s_->foreignRules;
    }
    void removeChannel(const padmin::ChannelRef&) override {
        std::scoped_lock lock(s_->mutex);
        ++s_->removeChannelCalls;
    }
    padmin::PollResult poll(const padmin::ChannelRef&, const unsigned int max, std::chrono::seconds,
                            std::chrono::seconds) override {
        s_->pollEntered = true;
        while (s_->blockPolls.load()) {
            if (storage::s3::curl::http::cancellationRequested()) throw padmin::ProviderError("cancelled");
            std::this_thread::sleep_for(std::chrono::milliseconds(5));
        }
        std::scoped_lock lock(s_->mutex);
        if (s_->pollError) throw padmin::ProviderError(*s_->pollError, "ServiceUnavailable", 503);
        padmin::PollResult r;
        // Messages stay queued until acknowledged (like a visibility timeout that expired at once).
        for (const auto& m : s_->queue) {
            if (r.messages.size() >= max) break;
            r.messages.push_back(m);
        }
        r.backlog = s_->queue.size();
        return r;
    }
    void ack(const padmin::ChannelRef&, const std::vector<std::string>& receipts) override {
        std::scoped_lock lock(s_->mutex);
        for (const auto& receipt : receipts) {
            s_->acked.push_back(receipt);
            std::erase_if(s_->queue, [&](const auto& m) { return m.receipt == receipt; });
        }
    }
    void retry(const padmin::ChannelRef&, const std::vector<std::string>&, std::chrono::seconds) override {}
    std::optional<uint64_t> backlog(const padmin::ChannelRef&) override { return s_->queue.size(); }
    padmin::Metrics metrics() const override { return {}; }

private:
    std::shared_ptr<FakeProviderState> s_;
};

inline void installFakeProvider() {
    providerState() = std::make_shared<FakeProviderState>();
    padmin::setFactoryForTesting(padmin::Factory{
        .admin = [](const std::shared_ptr<vault::model::APIKey>&) -> std::unique_ptr<padmin::AdminClient> {
            return std::make_unique<FakeAdmin>(providerState());
        },
        .events = [](const std::shared_ptr<vault::model::APIKey>&) -> std::unique_ptr<padmin::EventsClient> {
            if (const auto& missing = providerState()->capabilityMissing)
                throw padmin::CapabilityMissing("events.queues", *missing);
            return std::make_unique<FakeEvents>(providerState());
        },
    });
}

inline void removeFakeProvider() { padmin::setFactoryForTesting(std::nullopt); }

// Now, as an S3 event time.
inline std::string nowIso() {
    const auto t = std::time(nullptr);
    std::tm tm{};
    gmtime_r(&t, &tm);
    char buf[32];
    std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%S.000Z", &tm);
    return buf;
}

// An S3 event notification body as SQS delivers it.
inline std::string awsBody(const std::string& bucket, const std::string& eventName, const std::string& key,
                           const std::string& sequencer, const std::optional<uint64_t> size = std::nullopt,
                           const std::optional<std::string>& etag = std::nullopt,
                           const std::string& eventTime = "2026-10-15T12:00:00.000Z") {
    std::string object = R"("key":")" + key + R"(","sequencer":")" + sequencer + R"(")";
    if (size) object += R"(,"size":)" + std::to_string(*size);
    if (etag) object += R"(,"eTag":")" + *etag + R"(")";
    return R"({"Records":[{"eventVersion":"2.6","eventSource":"aws:s3","eventTime":")" + eventTime +
           R"(","eventName":")" + eventName + R"(","s3":{"bucket":{"name":")" + bucket + R"("},"object":{)" + object + "}}}]}";
}

}
