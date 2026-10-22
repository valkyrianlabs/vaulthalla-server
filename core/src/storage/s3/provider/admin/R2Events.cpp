#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/upstream/Names.hpp"

#include "crypto/util/encrypt.hpp"
#include "vault/model/APIKey.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <stdexcept>
#include <thread>

namespace vh::storage::s3::provider::admin {

namespace {

// One URL path segment for the bearer-token API, which no signature covers: encoded, never spliced in raw.
std::string seg(const std::string& s) { return storage::upstream::encodePathSegment(s); }

constexpr const char* kApiBase = "https://api.cloudflare.com/client/v4";

std::string contentType(const nlohmann::json& message) {
    if (!message.contains("metadata") || !message["metadata"].is_object()) return {};
    for (const auto& [k, v] : message["metadata"].items()) {
        std::string name = k;
        std::ranges::transform(name, name.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (name == "cf-content-type" && v.is_string()) return v.get<std::string>();
    }
    return {};
}

std::string decodeB64(const std::string& value) {
    const auto bytes = crypto::util::b64_decode(value);
    return {bytes.begin(), bytes.end()};
}

// The message body as text: JSON bodies arrive as JSON text (or an object), bytes/v8 bodies base64-encoded.
std::string messageBody(const nlohmann::json& message) {
    if (!message.contains("body")) return {};
    const auto& body = message["body"];
    if (!body.is_string()) return body.dump();
    const auto text = body.get<std::string>();
    const auto type = contentType(message);
    if (type == "bytes" || type == "v8") return decodeB64(text);
    if (nlohmann::json::accept(text)) return text;
    try {
        auto decoded = decodeB64(text);
        if (nlohmann::json::accept(decoded)) return decoded;
    } catch (const std::exception&) {
    }
    return text;
}

std::vector<std::string> ruleActions(const nlohmann::json& rule) {
    std::vector<std::string> out;
    if (rule.contains("actions") && rule["actions"].is_array())
        for (const auto& a : rule["actions"]) if (a.is_string()) out.push_back(a.get<std::string>());
    return out;
}

}

R2Events::R2Events(std::shared_ptr<vault::model::APIKey> key) : key_(std::move(key)) {
    if (!key_) throw std::invalid_argument("R2 events need an API key");
    const auto account = staticAccountRef(*key_);
    if (!account) throw std::invalid_argument("Cloudflare R2 endpoint must be https://<account id>.r2.cloudflarestorage.com");
    account_ = *account;
    token_ = key_->provider_token;
    if (token_.empty()) throw CapabilityMissing("events.queues", kCloudflareTokenHint);
}

Metrics R2Events::metrics() const {
    std::scoped_lock lock(metricsMutex_);
    return metrics_;
}

std::optional<std::string> R2Events::jurisdiction() const {
    const auto host = detail::hostOf(key_->endpoint);
    if (host.find(".eu.r2.") != std::string::npos) return std::string("eu");
    if (host.find(".fedramp.r2.") != std::string::npos) return std::string("fedramp");
    return std::nullopt;
}

nlohmann::json R2Events::api(const std::string& method, const std::string& path, const nlohmann::json& body,
                             nlohmann::json* info, const bool bucketScoped) {
    curl::http::Request request;
    request.method = method;
    request.url = std::string(kApiBase) + path;
    request.timeout = std::chrono::seconds{30};
    request.headers.emplace_back("Authorization", "Bearer " + token_);
    request.headers.emplace_back("Content-Type", "application/json");
    if (bucketScoped)
        if (const auto j = jurisdiction()) request.headers.emplace_back("cf-r2-jurisdiction", *j);
    if (!body.is_null()) request.body = body.dump();
    {
        std::scoped_lock lock(metricsMutex_);
        ++metrics_.requests;
        ++metrics_.queue_requests;
    }
    const auto response = curl::http::perform(request);
    const std::vector<std::string> secrets{token_, key_->secret_access_key};
    const auto operation = "Cloudflare API " + method + " " + path.substr(0, path.find('?'));
    if (!response.transport_ok) throw detail::makeError(operation, response, {}, secrets);

    nlohmann::json envelope;
    try {
        envelope = nlohmann::json::parse(response.body);
    } catch (const nlohmann::json::exception&) {
        if (response.ok()) throw ProviderError(operation + ": response is not JSON", {}, response.status);
        throw detail::makeError(operation, response, {}, secrets);
    }
    if (!response.ok() || !envelope.value("success", false))
        throw detail::makeError(operation, response, detail::cloudflareError(response), secrets);
    if (info && envelope.contains("result_info")) *info = envelope["result_info"];
    return envelope.contains("result") ? envelope["result"] : nlohmann::json();
}

std::optional<nlohmann::json> R2Events::findQueue(const std::string& name) {
    for (int page = 1; page < 1000; ++page) {
        nlohmann::json info;
        const auto result = api("GET", "/accounts/" + account_ + "/queues?page=" + std::to_string(page) + "&per_page=100",
                                nullptr, &info);
        if (!result.is_array() || result.empty()) return std::nullopt;
        for (const auto& q : result)
            if (q.value("queue_name", "") == name) return std::optional<nlohmann::json>(std::in_place, q);
        const auto totalPages = info.is_object() ? info.value("total_pages", 0) : 0;
        if (totalPages && page >= totalPages) return std::nullopt;
        if (result.size() < 100) return std::nullopt;
    }
    return std::nullopt;
}

nlohmann::json R2Events::ensureQueue(const std::string& name, bool& created) {
    if (auto existing = findQueue(name)) return *existing;
    created = true;
    return api("POST", "/accounts/" + account_ + "/queues", {{"queue_name", name}});
}

ChannelRef R2Events::ensureChannel(const ChannelSpec& spec) {
    ChannelRef ref;
    ref.queue_name = spec.queue_name;
    try {
        const auto dlqName = spec.queue_name + "-dlq";
        const auto dlq = ensureQueue(dlqName, ref.created);
        ref.dlq_ref = dlq.value("queue_id", "");
        const auto queue = ensureQueue(spec.queue_name, ref.created);
        ref.queue_ref = queue.value("queue_id", "");
        if (ref.queue_ref.empty()) throw ProviderError("Cloudflare Queues returned no queue id for " + spec.queue_name);

        // A queue created a moment ago can still answer 404 here (Cloudflare Queues is eventually consistent; seen
        // live): give a queue this call created a few seconds to appear.
        nlohmann::json consumers;
        for (const auto delay : {0, 500, 1000, 2000, 4000}) {
            if (delay) std::this_thread::sleep_for(std::chrono::milliseconds{delay});
            try {
                consumers = api("GET", "/accounts/" + account_ + "/queues/" + seg(ref.queue_ref) + "/consumers");
                break;
            } catch (const ProviderError& e) {
                if (!ref.created || e.http_status != 404 || delay == 4000) throw;
            }
        }
        bool pull = false;
        if (consumers.is_array())
            for (const auto& c : consumers) {
                const auto type = c.value("type", "");
                if (type == "worker")
                    throw ProviderError("queue '" + spec.queue_name + "' already has a Worker consumer (" +
                                            c.value("script_name", c.value("script", std::string("?"))) +
                                            "); Vaulthalla consumes over HTTP pull and will not remove it",
                                        "WorkerConsumer", 409);
                if (type == "http_pull") pull = true;
            }
        if (!pull)
            (void)api("POST", "/accounts/" + account_ + "/queues/" + seg(ref.queue_ref) + "/consumers",
                      {{"type", "http_pull"},
                       {"dead_letter_queue", dlqName},
                       {"settings",
                        {{"batch_size", 100},
                         {"max_retries", spec.max_receive_count},
                         {"retry_delay", 30},
                         {"visibility_timeout_ms", spec.visibility_timeout_seconds * 1000}}}});
    } catch (const ProviderError& e) {
        if (e.accessDenied()) throw CapabilityMissing("events.queues", std::string(e.what()) + "; " + kCloudflareTokenHint);
        throw;
    }
    return ref;
}

nlohmann::json R2Events::bucketConfiguration(const std::string& bucket) {
    storage::upstream::requireValidBucketName(bucket);   // before the guard: it must check the bucket the URL names
    storage::upstream::guard::require({.provider = "cloudflare-r2", .account_ref = account_, .bucket = bucket});
    try {
        return api("GET", "/accounts/" + account_ + "/event_notifications/r2/" + seg(bucket) + "/configuration", nullptr,
                   nullptr, true);
    } catch (const ProviderError& e) {
        // No configuration yet answers 404 on some accounts; an empty configuration is the same thing.
        if (e.http_status == 404 && !e.accessDenied()) return {{"bucketName", bucket}, {"queues", nlohmann::json::array()}};
        throw;
    }
}

std::vector<std::string> R2Events::ourRuleIds(const nlohmann::json& config, const ChannelRef& channel,
                                              const std::string& marker) {
    const auto plain = [](std::string id) {
        std::erase(id, '-');
        std::ranges::transform(id, id.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return id;
    };
    std::vector<std::string> ids;
    if (!config.is_object() || !config.contains("queues") || !config["queues"].is_array()) return ids;
    for (const auto& q : config["queues"]) {
        const auto queueId = q.value("queueId", "");
        const bool ours = (!queueId.empty() && plain(queueId) == plain(channel.queue_ref)) ||
                          (!channel.queue_name.empty() && q.value("queueName", "") == channel.queue_name);
        if (!ours || !q.contains("rules") || !q["rules"].is_array()) continue;
        for (const auto& r : q["rules"])
            if (r.value("description", "") == marker) ids.push_back(r.value("ruleId", ""));
    }
    std::erase(ids, std::string{});
    return ids;
}

std::vector<std::string> R2Events::subscribe(const ChannelRef& channel, const SubscriptionSpec& spec) {
    if (!isOwnedId(spec.rule_id)) throw std::invalid_argument("subscription rule ids must start with vaulthalla-");
    storage::upstream::requireValidBucketName(spec.bucket);
    const auto config = bucketConfiguration(spec.bucket);
    if (auto existing = ourRuleIds(config, channel, spec.rule_id); !existing.empty()) return existing;

    NotificationRule ours{.id = spec.rule_id, .destination = channel.queue_ref, .destination_name = channel.queue_name,
                          .events = detail::r2Actions(), .prefix = spec.prefix, .suffix = {}, .foreign = false, .raw = {}};
    for (const auto& rule : rules(spec.bucket))
        if (detail::overlaps(rule, ours))
            throw ProviderError("bucket '" + spec.bucket + "' already has event rule " + rule.id + " (" +
                                    (rule.foreign ? "another application's" : "another Vaulthalla subscription's") +
                                    ", queue " + (rule.destination_name.empty() ? rule.destination : rule.destination_name) +
                                    ") for overlapping actions and keys; R2 refuses overlapping rules, so Vaulthalla "
                                    "will not replace it",
                                "OverlappingRule", 409);

    nlohmann::json rule = {{"actions", detail::r2Actions()}, {"description", spec.rule_id}};
    if (!spec.prefix.empty()) rule["prefix"] = spec.prefix;
    (void)api("PUT", "/accounts/" + account_ + "/event_notifications/r2/" + seg(spec.bucket) + "/configuration/queues/" +
                         seg(channel.queue_ref),
              {{"rules", nlohmann::json::array({rule})}}, nullptr, true);

    const auto listed = bucketConfiguration(spec.bucket);
    if (auto ids = ourRuleIds(listed, channel, spec.rule_id); !ids.empty()) return ids;
    std::string seen;
    if (listed.is_object() && listed.contains("queues") && listed["queues"].is_array())
        for (const auto& q : listed["queues"])
            for (const auto& r : q.value("rules", nlohmann::json::array()))
                seen += (seen.empty() ? "" : ", ") + q.value("queueName", std::string("?")) + ":" +
                        r.value("description", std::string("<no description>"));
    throw ProviderError("R2 accepted the event rule for '" + spec.bucket + "' but does not list it (listed: " +
                        (seen.empty() ? std::string("nothing") : seen) + "); remove it from the bucket's event "
                        "notifications if it appears later");
}

void R2Events::unsubscribe(const ChannelRef& channel, const SubscriptionSpec& spec, const std::vector<std::string>& ruleIds) {
    storage::upstream::requireValidBucketName(spec.bucket);
    storage::upstream::guard::require({.provider = "cloudflare-r2", .account_ref = account_, .bucket = spec.bucket});
    auto ids = ruleIds;
    std::erase(ids, std::string{});
    if (ids.empty()) ids = ourRuleIds(bucketConfiguration(spec.bucket), channel, spec.rule_id);
    if (ids.empty()) return;
    // Never a body-less DELETE: that removes every rule of the queue on the bucket, other subscriptions' included.
    (void)api("DELETE", "/accounts/" + account_ + "/event_notifications/r2/" + seg(spec.bucket) + "/configuration/queues/" +
                            seg(channel.queue_ref),
              {{"ruleIds", ids}}, nullptr, true);
}

std::vector<NotificationRule> R2Events::rules(const std::string& bucket) {
    std::vector<NotificationRule> out;
    const auto config = bucketConfiguration(bucket);
    if (!config.is_object() || !config.contains("queues") || !config["queues"].is_array()) return out;
    for (const auto& q : config["queues"]) {
        if (!q.contains("rules") || !q["rules"].is_array()) continue;
        for (const auto& r : q["rules"]) {
            NotificationRule rule;
            rule.id = r.value("ruleId", "");
            rule.destination = q.value("queueId", "");
            rule.destination_name = q.value("queueName", "");
            rule.events = ruleActions(r);
            rule.prefix = r.value("prefix", "");
            rule.suffix = r.value("suffix", "");
            rule.raw = r.value("description", "");
            rule.foreign = !isOwnedId(rule.raw);
            out.push_back(std::move(rule));
        }
    }
    return out;
}

void R2Events::removeChannel(const ChannelRef& channel) {
    for (const auto* id : {&channel.queue_ref, &channel.dlq_ref}) {
        if (id->empty()) continue;
        try {
            (void)api("DELETE", "/accounts/" + account_ + "/queues/" + seg(*id));
        } catch (const ProviderError& e) {
            if (e.http_status != 404) throw;
        }
    }
}

PollResult R2Events::poll(const ChannelRef& channel, const unsigned int max, std::chrono::seconds,
                          const std::chrono::seconds visibility) {
    const auto result = api("POST", "/accounts/" + account_ + "/queues/" + seg(channel.queue_ref) + "/messages/pull",
                            {{"batch_size", std::clamp(max, 1u, 100u)},
                             {"visibility_timeout_ms", std::max<long long>(1000, visibility.count() * 1000)}});
    PollResult out;
    if (!result.is_object()) return out;
    if (result.contains("message_backlog_count") && result["message_backlog_count"].is_number())
        out.backlog = result["message_backlog_count"].get<uint64_t>();
    if (!result.contains("messages") || !result["messages"].is_array()) return out;
    for (const auto& m : result["messages"]) {
        ReceivedMessage msg;
        msg.receipt = m.value("lease_id", "");
        msg.message_id = m.value("id", "");
        msg.body = messageBody(m);
        msg.attempts = m.value("attempts", 0u);
        if (m.contains("timestamp_ms") && m["timestamp_ms"].is_number())
            msg.sent_at = static_cast<std::time_t>(m["timestamp_ms"].get<long long>() / 1000);
        out.messages.push_back(std::move(msg));
    }
    return out;
}

void R2Events::ack(const ChannelRef& channel, const std::vector<std::string>& receipts) {
    for (std::size_t start = 0; start < receipts.size(); start += 100) {
        nlohmann::json acks = nlohmann::json::array();
        for (std::size_t i = start; i < std::min(receipts.size(), start + 100); ++i) acks.push_back({{"lease_id", receipts[i]}});
        (void)api("POST", "/accounts/" + account_ + "/queues/" + seg(channel.queue_ref) + "/messages/ack",
                  {{"acks", acks}, {"retries", nlohmann::json::array()}});
    }
}

void R2Events::retry(const ChannelRef& channel, const std::vector<std::string>& receipts, const std::chrono::seconds delay) {
    for (std::size_t start = 0; start < receipts.size(); start += 100) {
        nlohmann::json retries = nlohmann::json::array();
        for (std::size_t i = start; i < std::min(receipts.size(), start + 100); ++i)
            retries.push_back({{"lease_id", receipts[i]}, {"delay_seconds", std::clamp<long long>(delay.count(), 0, 43200)}});
        (void)api("POST", "/accounts/" + account_ + "/queues/" + seg(channel.queue_ref) + "/messages/ack",
                  {{"acks", nlohmann::json::array()}, {"retries", retries}});
    }
}

std::optional<uint64_t> R2Events::backlog(const ChannelRef&) {
    return std::nullopt;   // reported by every pull (message_backlog_count)
}

}
