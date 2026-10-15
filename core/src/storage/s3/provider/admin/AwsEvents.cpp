#include "storage/s3/provider/admin/Adapters.hpp"

#include "vault/model/APIKey.hpp"

#include <algorithm>
#include <stdexcept>

namespace vh::storage::s3::provider::admin {

namespace {

constexpr const char* kXmlContentType = "application/xml";

std::string arnField(const std::string& arn, const std::size_t index) {
    std::size_t start = 0;
    for (std::size_t i = 0; i < index; ++i) {
        start = arn.find(':', start);
        if (start == std::string::npos) return {};
        ++start;
    }
    const auto end = arn.find(':', start);
    return arn.substr(start, end == std::string::npos ? std::string::npos : end - start);
}

std::vector<std::string> ownIds(const std::vector<std::string>& ids, const std::string& fallback) {
    std::vector<std::string> out;
    for (const auto& id : ids)
        if (isOwnedId(id)) out.push_back(id);
    if (out.empty() && isOwnedId(fallback)) out.push_back(fallback);
    return out;
}

}

AwsEvents::AwsEvents(std::shared_ptr<vault::model::APIKey> key) : key_(key), s3_(std::move(key)) {}

Metrics AwsEvents::metrics() const {
    std::scoped_lock lock(metricsMutex_);
    auto m = metrics_;
    const auto s3 = s3_.metrics();
    m.requests += s3.requests;
    m.list += s3.list;
    m.head += s3.head;
    m.get += s3.get;
    m.put += s3.put;
    m.del += s3.del;
    return m;
}

std::string AwsEvents::regionOfQueue(const ChannelRef& channel) {
    // https://sqs.<region>.amazonaws.com/<account>/<name>
    const auto host = detail::hostOf(channel.queue_ref);
    if (host.starts_with("sqs.")) {
        const auto rest = host.substr(4);
        return rest.substr(0, rest.find('.'));
    }
    if (const auto region = arnField(channel.queue_arn, 3); !region.empty()) return region;
    throw std::invalid_argument("not an SQS queue URL: " + channel.queue_ref);
}

nlohmann::json AwsEvents::sqs(const std::string& region, const std::string& action, const nlohmann::json& body,
                              const std::chrono::seconds timeout) {
    auto c = detail::call("POST");
    c.headers["content-type"] = "application/x-amz-json-1.0";
    c.headers["x-amz-target"] = "AmazonSQS." + action;
    c.body = body.dump();
    c.timeout = timeout;
    {
        std::scoped_lock lock(metricsMutex_);
        ++metrics_.requests;
        ++metrics_.queue_requests;
    }
    const sigv4::Credentials credentials{.access_key = key_->access_key, .secret_key = key_->secret_access_key, .session_token = {}};
    const auto response = detail::send({"sqs." + region + ".amazonaws.com", region, "sqs"}, c, credentials);
    if (!response.ok()) throw detail::makeError("SQS " + action, response, detail::sqsError(response), s3_.secrets());
    if (response.body.empty()) return nlohmann::json::object();
    try {
        return nlohmann::json::parse(response.body);
    } catch (const nlohmann::json::exception&) {
        throw ProviderError("SQS " + action + ": response is not JSON");
    }
}

std::optional<std::string> AwsEvents::queueUrl(const std::string& region, const std::string& name) {
    try {
        return sqs(region, "GetQueueUrl", {{"QueueName", name}}).value("QueueUrl", "");
    } catch (const ProviderError& e) {
        if (e.code == "NonExistentQueue") return std::nullopt;
        throw;
    }
}

std::map<std::string, std::string> AwsEvents::queueAttributes(const std::string& region, const std::string& url,
                                                               const std::vector<std::string>& names) {
    const auto result = sqs(region, "GetQueueAttributes", {{"QueueUrl", url}, {"AttributeNames", names}});
    std::map<std::string, std::string> out;
    if (result.contains("Attributes") && result["Attributes"].is_object())
        for (const auto& [k, v] : result["Attributes"].items())
            if (v.is_string()) out[k] = v.get<std::string>();
    return out;
}

ChannelRef AwsEvents::ensureChannel(const ChannelSpec& spec) {
    const auto region = spec.region.empty() ? s3_.defaultRegion() : spec.region;
    ChannelRef ref;
    ref.queue_name = spec.queue_name;
    try {
        const auto dlqName = spec.queue_name + "-dlq";
        auto dlq = queueUrl(region, dlqName);
        if (!dlq) {
            dlq = sqs(region, "CreateQueue", {{"QueueName", dlqName}, {"Attributes", {{"MessageRetentionPeriod", "1209600"}}}})
                      .value("QueueUrl", "");
            ref.created = true;
        }
        ref.dlq_ref = *dlq;
        ref.dlq_arn = queueAttributes(region, ref.dlq_ref, {"QueueArn"})["QueueArn"];

        const nlohmann::json redrive = {{"deadLetterTargetArn", ref.dlq_arn}, {"maxReceiveCount", spec.max_receive_count}};
        auto main = queueUrl(region, spec.queue_name);
        if (!main) {
            main = sqs(region, "CreateQueue",
                       {{"QueueName", spec.queue_name},
                        {"Attributes",
                         {{"MessageRetentionPeriod", std::to_string(spec.retention_seconds)},
                          {"VisibilityTimeout", std::to_string(spec.visibility_timeout_seconds)},
                          {"ReceiveMessageWaitTimeSeconds", "20"},
                          {"RedrivePolicy", redrive.dump()}}}})
                       .value("QueueUrl", "");
            ref.created = true;
        }
        ref.queue_ref = *main;
        auto attributes = queueAttributes(region, ref.queue_ref, {"QueueArn", "RedrivePolicy"});
        ref.queue_arn = attributes["QueueArn"];
        if (attributes["RedrivePolicy"].empty())
            (void)sqs(region, "SetQueueAttributes", {{"QueueUrl", ref.queue_ref}, {"Attributes", {{"RedrivePolicy", redrive.dump()}}}});
    } catch (const ProviderError& e) {
        if (e.accessDenied())
            throw CapabilityMissing("events.queues", std::string(e.what()) + "; " + awsEventsPolicyHint(spec.account_ref));
        throw;
    }
    return ref;
}

std::string AwsEvents::getNotificationXml(const std::string& bucket) {
    const auto response = s3_.bucketCall(bucket, detail::call("GET", {{"notification", ""}}), "get");
    if (!response.ok())
        throw detail::makeError("GetBucketNotificationConfiguration " + bucket, response, detail::s3Error(response), s3_.secrets());
    return response.body;
}

void AwsEvents::putNotificationXml(const std::string& bucket, const std::string& xml) {
    auto c = detail::call("PUT", {{"notification", ""}});
    c.body = xml;
    c.headers["content-type"] = kXmlContentType;
    c.headers["content-md5"] = detail::md5Base64(c.body);
    const auto response = s3_.bucketCall(bucket, c, "put");
    if (!response.ok())
        throw detail::makeError("PutBucketNotificationConfiguration " + bucket, response, detail::s3Error(response), s3_.secrets());
}

std::vector<std::string> AwsEvents::subscribe(const ChannelRef& channel, const SubscriptionSpec& spec) {
    if (!isOwnedId(spec.rule_id)) throw std::invalid_argument("subscription rule ids must start with vaulthalla-");
    storage::upstream::guard::require(s3_.bucketIdentity(spec.bucket));
    const auto region = regionOfQueue(channel);
    const auto account = arnField(channel.queue_arn, 4);

    // 1. Let the bucket publish to the queue (our statement only; every other statement stays).
    try {
        const auto policy = queueAttributes(region, channel.queue_ref, {"Policy"})["Policy"];
        const auto merged = detail::mergeQueuePolicy(policy, channel.queue_arn, account, spec.bucket, true);
        if (merged != policy)
            (void)sqs(region, "SetQueueAttributes", {{"QueueUrl", channel.queue_ref}, {"Attributes", {{"Policy", merged}}}});
    } catch (const ProviderError& e) {
        if (e.accessDenied())
            throw CapabilityMissing("events.queues", std::string(e.what()) + "; " + awsEventsPolicyHint(account));
        throw;
    }

    // 2. GET-merge-PUT the bucket's notification document (PUT replaces it whole).
    const auto elements = detail::parseNotification(getNotificationXml(spec.bucket));
    NotificationRule ours{.id = spec.rule_id, .destination = channel.queue_arn, .destination_name = channel.queue_name,
                          .events = detail::awsEventTypes(), .prefix = spec.prefix, .suffix = {}, .foreign = false, .raw = {}};
    for (const auto& e : elements) {
        if (e.rule.id == spec.rule_id && e.rule.destination == ours.destination && e.rule.prefix == ours.prefix)
            return {spec.rule_id};   // already there
        if (e.kind == "EventBridgeConfiguration" || e.rule.id == spec.rule_id) continue;
        if (detail::overlaps(e.rule, ours))
            throw ProviderError("bucket '" + spec.bucket + "' already has notification rule '" + e.rule.id +
                                    "' for overlapping events and keys (" + e.rule.destination +
                                    "); S3 refuses overlapping rules, so Vaulthalla will not replace it. Narrow that rule "
                                    "or subscribe a prefix it does not cover.",
                                "OverlappingNotification", 409);
    }
    putNotificationXml(spec.bucket, detail::buildNotification(elements, {spec.rule_id}, {ours}));

    const auto after = detail::parseNotification(getNotificationXml(spec.bucket));
    if (std::ranges::none_of(after, [&](const auto& e) { return e.rule.id == spec.rule_id; }))
        throw ProviderError("bucket '" + spec.bucket + "' did not keep the notification rule " + spec.rule_id);
    return {spec.rule_id};
}

void AwsEvents::unsubscribe(const ChannelRef& channel, const SubscriptionSpec& spec, const std::vector<std::string>& ruleIds) {
    storage::upstream::guard::require(s3_.bucketIdentity(spec.bucket));
    const auto ids = ownIds(ruleIds, spec.rule_id);

    try {
        const auto elements = detail::parseNotification(getNotificationXml(spec.bucket));
        const bool present = std::ranges::any_of(elements, [&](const auto& e) {
            return std::ranges::find(ids, e.rule.id) != ids.end();
        });
        if (present) putNotificationXml(spec.bucket, detail::buildNotification(elements, ids, {}));
    } catch (const ProviderError& e) {
        if (e.code != "NoSuchBucket") throw;   // a deleted bucket has no rules left to remove
    }

    if (channel.queue_ref.empty()) return;
    const auto region = regionOfQueue(channel);
    try {
        const auto policy = queueAttributes(region, channel.queue_ref, {"Policy"})["Policy"];
        const auto merged = detail::mergeQueuePolicy(policy, channel.queue_arn, arnField(channel.queue_arn, 4),
                                                     spec.bucket, false);
        if (merged != policy)
            (void)sqs(region, "SetQueueAttributes", {{"QueueUrl", channel.queue_ref}, {"Attributes", {{"Policy", merged}}}});
    } catch (const ProviderError& e) {
        if (e.code != "NonExistentQueue") throw;
    }
}

std::vector<NotificationRule> AwsEvents::rules(const std::string& bucket) {
    std::vector<NotificationRule> out;
    for (auto& e : detail::parseNotification(getNotificationXml(bucket))) {
        if (e.kind == "EventBridgeConfiguration") {
            e.rule.id = "EventBridgeConfiguration";
            e.rule.destination = "eventbridge";
        }
        out.push_back(std::move(e.rule));
    }
    return out;
}

void AwsEvents::removeChannel(const ChannelRef& channel) {
    for (const auto* url : {&channel.queue_ref, &channel.dlq_ref}) {
        if (url->empty()) continue;
        try {
            (void)sqs(regionOfQueue({.queue_name = {}, .queue_ref = *url, .queue_arn = channel.queue_arn, .dlq_ref = {},
                                     .dlq_arn = {}, .created = false}),
                      "DeleteQueue", {{"QueueUrl", *url}});
        } catch (const ProviderError& e) {
            if (e.code != "NonExistentQueue") throw;
        }
    }
}

PollResult AwsEvents::poll(const ChannelRef& channel, const unsigned int max, const std::chrono::seconds wait,
                           const std::chrono::seconds visibility) {
    const auto waitSeconds = std::clamp<long long>(wait.count(), 0, 20);
    const auto result = sqs(regionOfQueue(channel), "ReceiveMessage",
                            {{"QueueUrl", channel.queue_ref},
                             {"MaxNumberOfMessages", std::clamp(max, 1u, 10u)},
                             {"WaitTimeSeconds", waitSeconds},
                             {"VisibilityTimeout", visibility.count()},
                             {"AttributeNames", {"ApproximateReceiveCount", "SentTimestamp"}}},
                            std::chrono::seconds{waitSeconds + 20});
    PollResult out;
    if (!result.contains("Messages") || !result["Messages"].is_array()) return out;
    for (const auto& m : result["Messages"]) {
        ReceivedMessage msg;
        msg.receipt = m.value("ReceiptHandle", "");
        msg.message_id = m.value("MessageId", "");
        msg.body = m.value("Body", "");
        if (m.contains("Attributes") && m["Attributes"].is_object()) {
            const auto& a = m["Attributes"];
            if (a.contains("ApproximateReceiveCount") && a["ApproximateReceiveCount"].is_string())
                msg.attempts = static_cast<unsigned int>(std::stoul(a["ApproximateReceiveCount"].get<std::string>()));
            if (a.contains("SentTimestamp") && a["SentTimestamp"].is_string())
                msg.sent_at = static_cast<std::time_t>(std::stoll(a["SentTimestamp"].get<std::string>()) / 1000);
        }
        out.messages.push_back(std::move(msg));
    }
    return out;
}

void AwsEvents::ack(const ChannelRef& channel, const std::vector<std::string>& receipts) {
    std::size_t failed = 0;
    std::string firstError;
    for (std::size_t start = 0; start < receipts.size(); start += 10) {
        nlohmann::json entries = nlohmann::json::array();
        for (std::size_t i = start; i < std::min(receipts.size(), start + 10); ++i)
            entries.push_back({{"Id", "m" + std::to_string(i)}, {"ReceiptHandle", receipts[i]}});
        const auto result = sqs(regionOfQueue(channel), "DeleteMessageBatch", {{"QueueUrl", channel.queue_ref}, {"Entries", entries}});
        if (result.contains("Failed") && result["Failed"].is_array())
            for (const auto& f : result["Failed"]) {
                ++failed;
                if (firstError.empty()) firstError = f.value("Code", "") + " " + f.value("Message", "");
            }
    }
    if (failed) throw ProviderError("SQS DeleteMessageBatch: " + std::to_string(failed) + " message(s) not deleted (" +
                                        firstError + ")", "BatchEntryFailed");
}

void AwsEvents::retry(const ChannelRef& channel, const std::vector<std::string>& receipts, const std::chrono::seconds delay) {
    for (std::size_t start = 0; start < receipts.size(); start += 10) {
        nlohmann::json entries = nlohmann::json::array();
        for (std::size_t i = start; i < std::min(receipts.size(), start + 10); ++i)
            entries.push_back({{"Id", "m" + std::to_string(i)}, {"ReceiptHandle", receipts[i]},
                               {"VisibilityTimeout", std::clamp<long long>(delay.count(), 0, 43200)}});
        (void)sqs(regionOfQueue(channel), "ChangeMessageVisibilityBatch", {{"QueueUrl", channel.queue_ref}, {"Entries", entries}});
    }
}

std::optional<uint64_t> AwsEvents::backlog(const ChannelRef& channel) {
    const auto attributes = queueAttributes(regionOfQueue(channel), channel.queue_ref, {"ApproximateNumberOfMessages"});
    const auto it = attributes.find("ApproximateNumberOfMessages");
    if (it == attributes.end()) return std::nullopt;
    return std::stoull(it->second);
}

}
