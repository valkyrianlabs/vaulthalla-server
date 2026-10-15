#pragma once

#include "storage/upstream/model/Subscription.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// upstream_event_subscription: a vault's event rule on its bucket. At most one live (state <> removed) per vault.
namespace vh::db::query::upstream {

using SubscriptionModel = storage::upstream::model::Subscription;

class Subscription {
public:
    // nullopt when the vault already has a live subscription (uq_upstream_event_subscription_live_vault).
    [[nodiscard]] static std::optional<SubscriptionModel> create(std::optional<int64_t> channelId, int64_t upstreamBucketId,
                                                                 uint32_t vaultId, const std::string& prefix,
                                                                 storage::upstream::model::ForeignObjects foreignObjects,
                                                                 storage::upstream::model::BaselineState baseline);
    [[nodiscard]] static std::optional<SubscriptionModel> get(int64_t id);
    [[nodiscard]] static std::optional<SubscriptionModel> getLiveForVault(uint32_t vaultId);
    // Live subscriptions on a bucket identity (routing inbound events).
    [[nodiscard]] static std::vector<SubscriptionModel> listLiveForBucket(const std::string& provider,
                                                                          const std::string& accountRef,
                                                                          const std::string& bucket);

    // Becoming active stamps activated_at. lastError: nullopt keeps the stored one, "" clears it.
    static void setState(int64_t id, storage::upstream::model::SubscriptionState state,
                         const std::optional<std::string>& lastError = std::nullopt);
    static void setRuleIds(int64_t id, const std::vector<std::string>& ruleIds);
    static void setChannel(int64_t id, std::optional<int64_t> channelId);
    static void setSettings(int64_t id, const std::string& prefix, storage::upstream::model::ForeignObjects foreignObjects);
    static void setBaseline(int64_t id, storage::upstream::model::BaselineState state, std::optional<std::time_t> startedAt);
    static void setForeignRules(int64_t id, unsigned int count);

    [[nodiscard]] static std::vector<SubscriptionModel> listForChannel(int64_t channelId);
    [[nodiscard]] static std::vector<SubscriptionModel> listByState(storage::upstream::model::SubscriptionState state);
    [[nodiscard]] static std::vector<uint32_t> listActiveVaultIds();
    // Pending, active or removing subscriptions whose channel is operated by this API key.
    [[nodiscard]] static uint64_t countActiveUsingKey(uint32_t apiKeyId);
};

}
