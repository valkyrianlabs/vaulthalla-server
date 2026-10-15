#pragma once

#include "db/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// A queue Vaulthalla consumes (upstream_event_channel): one per AWS account + region, one per R2 account.
namespace vh::storage::upstream::model {

enum class ChannelState { Provisioning, Active, Degraded, Failed, Removed };

[[nodiscard]] std::string to_string(ChannelState s);
[[nodiscard]] ChannelState channelStateFromString(const std::string& s);   // throws std::invalid_argument

struct Channel {
    int64_t id{};
    std::string provider;
    std::string account_ref;
    std::string region;                 // "" for account-global queues (R2)
    std::string queue_name;
    std::optional<std::string> queue_ref;   // SQS queue URL / Cloudflare queue id
    std::optional<std::string> queue_arn;
    std::optional<std::string> dlq_ref;
    std::optional<std::string> dlq_arn;
    std::optional<uint32_t> api_key_id;     // the credential that operates it; null = dormant
    ChannelState state{ChannelState::Provisioning};
    bool created_by_vaulthalla{false};
    std::optional<std::time_t> last_poll_at;
    std::optional<std::time_t> last_success_at;
    std::optional<std::time_t> last_message_at;
    std::optional<std::string> last_error;
    std::optional<std::time_t> last_error_at;
    unsigned int consecutive_failures{};
    std::optional<uint64_t> backlog_estimate;
    std::optional<std::time_t> next_poll_at;
    std::time_t created_at{};
    std::time_t updated_at{};

    Channel() = default;
    explicit Channel(pqxx::row_ref row);
};

}
