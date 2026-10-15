#include "db/query/upstream/Subscription.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/result>

namespace vh::db::query::upstream {

namespace {

namespace smodel = storage::upstream::model;

std::optional<SubscriptionModel> firstSubscription(const pqxx::result& res) {
    if (res.empty()) return std::nullopt;
    return SubscriptionModel(res.one_row_ref());
}

}

std::optional<SubscriptionModel> Subscription::create(const std::optional<int64_t> channelId, const int64_t upstreamBucketId,
                                                      const uint32_t vaultId, const std::string& prefix,
                                                      const smodel::ForeignObjects foreignObjects,
                                                      const smodel::BaselineState baseline) {
    return Transactions::exec("upstream::Subscription::create", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_subscription_create"},
                                  pqxx::params{channelId, upstreamBucketId, vaultId, prefix,
                                               smodel::to_string(foreignObjects), smodel::to_string(baseline)});
        return firstSubscription(res);
    });
}

std::optional<SubscriptionModel> Subscription::get(const int64_t id) {
    return Transactions::exec("upstream::Subscription::get", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_subscription_get"}, pqxx::params{id});
        return firstSubscription(res);
    });
}

std::optional<SubscriptionModel> Subscription::getLiveForVault(const uint32_t vaultId) {
    return Transactions::exec("upstream::Subscription::getLiveForVault", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_subscription_get_live_for_vault"}, pqxx::params{vaultId});
        return firstSubscription(res);
    });
}

std::vector<SubscriptionModel> Subscription::listLiveForBucket(const std::string& provider, const std::string& accountRef,
                                                               const std::string& bucket) {
    return Transactions::exec("upstream::Subscription::listLiveForBucket", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_subscription_list_live_for_bucket"},
                                  pqxx::params{provider, accountRef, bucket});
        return rowsAs<SubscriptionModel>(res);
    });
}

void Subscription::setState(const int64_t id, const smodel::SubscriptionState state,
                            const std::optional<std::string>& lastError) {
    Transactions::exec("upstream::Subscription::setState", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_subscription_set_state"}, pqxx::params{id, smodel::to_string(state), lastError});
    });
}

void Subscription::setRuleIds(const int64_t id, const std::vector<std::string>& ruleIds) {
    Transactions::exec("upstream::Subscription::setRuleIds", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_subscription_set_rule_ids"}, pqxx::params{id, nlohmann::json(ruleIds).dump()});
    });
}

void Subscription::setChannel(const int64_t id, const std::optional<int64_t> channelId) {
    Transactions::exec("upstream::Subscription::setChannel", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_subscription_set_channel"}, pqxx::params{id, channelId});
    });
}

void Subscription::setSettings(const int64_t id, const std::string& prefix, const smodel::ForeignObjects foreignObjects) {
    Transactions::exec("upstream::Subscription::setSettings", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_subscription_set_settings"},
                 pqxx::params{id, prefix, smodel::to_string(foreignObjects)});
    });
}

void Subscription::setBaseline(const int64_t id, const smodel::BaselineState state, const std::optional<std::time_t> startedAt) {
    const std::optional<double> started = startedAt ? std::make_optional(static_cast<double>(*startedAt)) : std::nullopt;
    Transactions::exec("upstream::Subscription::setBaseline", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_subscription_set_baseline"}, pqxx::params{id, smodel::to_string(state), started});
    });
}

void Subscription::setForeignRules(const int64_t id, const unsigned int count) {
    Transactions::exec("upstream::Subscription::setForeignRules", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_subscription_set_foreign_rules"}, pqxx::params{id, static_cast<int>(count)});
    });
}

std::vector<SubscriptionModel> Subscription::listForChannel(const int64_t channelId) {
    return Transactions::exec("upstream::Subscription::listForChannel", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_subscription_list_for_channel"}, pqxx::params{channelId});
        return rowsAs<SubscriptionModel>(res);
    });
}

std::vector<SubscriptionModel> Subscription::listByState(const smodel::SubscriptionState state) {
    return Transactions::exec("upstream::Subscription::listByState", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_subscription_list_by_state"},
                                  pqxx::params{smodel::to_string(state)});
        return rowsAs<SubscriptionModel>(res);
    });
}

std::vector<uint32_t> Subscription::listActiveVaultIds() {
    return Transactions::exec("upstream::Subscription::listActiveVaultIds", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_subscription_list_active_vault_ids"});
        return mapRows(res, [](const pqxx::row_ref row) { return row["vault_id"].as<uint32_t>(); });
    });
}

uint64_t Subscription::countActiveUsingKey(const uint32_t apiKeyId) {
    return Transactions::exec("upstream::Subscription::countActiveUsingKey", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"upstream_subscription_count_active_using_key"}, pqxx::params{apiKeyId})
            .one_field_ref()
            .as<uint64_t>();
    });
}

}
