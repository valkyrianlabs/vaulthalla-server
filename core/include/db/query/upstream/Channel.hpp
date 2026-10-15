#pragma once

#include "storage/upstream/model/Channel.hpp"
#include "storage/upstream/model/Subscription.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// upstream_event_channel: the queues Vaulthalla consumes.
namespace vh::db::query::upstream {

using ChannelModel = storage::upstream::model::Channel;

class Channel {
public:
    // Upsert by (provider, account_ref, region, queue_name). A given apiKeyId becomes the operating key; a removed
    // channel comes back as provisioning.
    static ChannelModel getOrCreate(const std::string& provider, const std::string& accountRef, const std::string& region,
                                    const std::string& queueName, std::optional<uint32_t> apiKeyId);
    [[nodiscard]] static std::optional<ChannelModel> get(int64_t id);
    // A non-removed channel for the account (+ region), active ones first.
    [[nodiscard]] static std::optional<ChannelModel> find(const std::string& provider, const std::string& accountRef,
                                                          const std::string& region);
    static void updateRefs(int64_t id, const std::optional<std::string>& queueRef, const std::optional<std::string>& queueArn,
                           const std::optional<std::string>& dlqRef, const std::optional<std::string>& dlqArn,
                           bool createdByVaulthalla, storage::upstream::model::ChannelState state);
    // lastError: nullopt keeps the stored one, "" clears it.
    static void setState(int64_t id, storage::upstream::model::ChannelState state,
                         const std::optional<std::string>& lastError = std::nullopt);
    static void setApiKey(int64_t id, std::optional<uint32_t> apiKeyId);

    // One poll's bookkeeping. ok: last_success_at, consecutive_failures = 0, degraded → active, last_message_at when
    // received > 0, backlog when known. Failure: consecutive_failures + 1, last_error(+_at), active → degraded after 3.
    // A successful poll after a gap longer than this marks the stream discontinuous (the queues keep messages 4 days;
    // the margin covers clock skew and the time a message already waited).
    static constexpr std::chrono::seconds kContinuityGap{3 * 24 * 3600};
    // The stream may have lost messages (DLQ, retention gap, burnt receives): events alone no longer keep the index.
    static void markContinuityBroken(int64_t id, const std::string& note);
    static void setDlqDepth(int64_t id, std::optional<uint64_t> depth);
    static void recordPoll(int64_t id, bool ok, unsigned int received, std::optional<uint64_t> backlog,
                           const std::optional<std::string>& error, std::optional<std::time_t> nextPollAt);

    // Channels worth polling: active or degraded, operated by a key, referenced by a pending/active subscription.
    [[nodiscard]] static std::vector<ChannelModel> listPollable();
    [[nodiscard]] static uint64_t countSubscriptions(int64_t id,
                                                     const std::vector<storage::upstream::model::SubscriptionState>& states);
};

}
