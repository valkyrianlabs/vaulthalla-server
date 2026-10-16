#include "db/query/upstream/Channel.hpp"

#include "db/Rows.hpp"
#include "db/Transactions.hpp"

#include <pqxx/result>

namespace vh::db::query::upstream {

namespace {

namespace cmodel = storage::upstream::model;

std::optional<ChannelModel> firstChannel(const pqxx::result& res) {
    if (res.empty()) return std::nullopt;
    return ChannelModel(res.one_row_ref());
}

// Enum names are fixed identifiers: safe as a literal text array.
std::string subscriptionStateArray(const std::vector<cmodel::SubscriptionState>& states) {
    std::string out = "{";
    for (const auto s : states) out += (out.size() > 1 ? "," : "") + cmodel::to_string(s);
    return out + "}";
}

std::optional<double> epochParam(const std::optional<std::time_t> t) {
    return t ? std::make_optional(static_cast<double>(*t)) : std::nullopt;
}

}

ChannelModel Channel::getOrCreate(const std::string& provider, const std::string& accountRef, const std::string& region,
                                  const std::string& queueName, const std::optional<uint32_t> apiKeyId) {
    return Transactions::exec("upstream::Channel::getOrCreate", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_channel_get_or_create"},
                                  pqxx::params{provider, accountRef, region, queueName, apiKeyId});
        return ChannelModel(res.one_row_ref());
    });
}

std::optional<ChannelModel> Channel::get(const int64_t id) {
    return Transactions::exec("upstream::Channel::get", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_channel_get"}, pqxx::params{id});
        return firstChannel(res);
    });
}

std::optional<ChannelModel> Channel::find(const std::string& provider, const std::string& accountRef,
                                          const std::string& region) {
    return Transactions::exec("upstream::Channel::find", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_channel_find"}, pqxx::params{provider, accountRef, region});
        return firstChannel(res);
    });
}

void Channel::updateRefs(const int64_t id, const std::optional<std::string>& queueRef,
                         const std::optional<std::string>& queueArn, const std::optional<std::string>& dlqRef,
                         const std::optional<std::string>& dlqArn, const bool createdByVaulthalla,
                         const cmodel::ChannelState state) {
    Transactions::exec("upstream::Channel::updateRefs", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_channel_update_refs"},
                 pqxx::params{id, queueRef, queueArn, dlqRef, dlqArn, createdByVaulthalla, cmodel::to_string(state)});
    });
}

void Channel::setState(const int64_t id, const cmodel::ChannelState state, const std::optional<std::string>& lastError) {
    Transactions::exec("upstream::Channel::setState", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_channel_set_state"}, pqxx::params{id, cmodel::to_string(state), lastError});
    });
}

void Channel::setApiKey(const int64_t id, const std::optional<uint32_t> apiKeyId) {
    Transactions::exec("upstream::Channel::setApiKey", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_channel_set_api_key"}, pqxx::params{id, apiKeyId});
    });
}

void Channel::recordPoll(const int64_t id, const bool ok, const unsigned int received, const std::optional<uint64_t> backlog,
                         const std::optional<std::string>& error, const std::optional<std::time_t> nextPollAt) {
    Transactions::exec("upstream::Channel::recordPoll", [&](pqxx::work& txn) {
        if (ok) {
            const std::optional<int64_t> backlogParam =
                backlog ? std::make_optional(static_cast<int64_t>(*backlog)) : std::nullopt;
            txn.exec(pqxx::prepped{"upstream_channel_record_poll_ok"},
                     pqxx::params{id, static_cast<int>(received), backlogParam, epochParam(nextPollAt),
                                  static_cast<double>(kContinuityGap.count())});
        } else {
            txn.exec(pqxx::prepped{"upstream_channel_record_poll_failed"},
                     pqxx::params{id, error.value_or("poll failed"), epochParam(nextPollAt)});
        }
    });
}

void Channel::markContinuityBroken(const int64_t id, const std::string& note) {
    Transactions::exec("upstream::Channel::markContinuityBroken", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_channel_mark_continuity_broken"}, pqxx::params{id, note});
    });
}

void Channel::setDlqDepth(const int64_t id, const std::optional<uint64_t> depth) {
    const std::optional<int64_t> param = depth ? std::make_optional(static_cast<int64_t>(*depth)) : std::nullopt;
    Transactions::exec("upstream::Channel::setDlqDepth", [&](pqxx::work& txn) {
        txn.exec(pqxx::prepped{"upstream_channel_set_dlq_depth"}, pqxx::params{id, param});
    });
}

std::vector<ChannelModel> Channel::listPollable() {
    return Transactions::exec("upstream::Channel::listPollable", [&](pqxx::work& txn) {
        const auto res = txn.exec(pqxx::prepped{"upstream_channel_list_pollable"});
        return rowsAs<ChannelModel>(res);
    });
}

uint64_t Channel::countSubscriptions(const int64_t id, const std::vector<cmodel::SubscriptionState>& states) {
    if (states.empty()) return 0;
    return Transactions::exec("upstream::Channel::countSubscriptions", [&](pqxx::work& txn) {
        return txn.exec(pqxx::prepped{"upstream_channel_count_subscriptions"},
                        pqxx::params{id, subscriptionStateArray(states)})
            .one_field_ref()
            .as<uint64_t>();
    });
}

}
