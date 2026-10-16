#pragma once

#include "db/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// One durable upstream event (upstream_event_inbox). Written before the queue message is acknowledged; the
// (provider, account_ref, bucket, dedupe_key) unique key makes redelivery a no-op.
namespace vh::storage::upstream::model {

enum class InboxKind { Created, Removed };
enum class InboxState { Pending, Applied, Done, Skipped, Failed };
enum class InboxOrigin { External, Self, Unknown };

[[nodiscard]] std::string to_string(InboxKind k);
[[nodiscard]] InboxKind inboxKindFromString(const std::string& s);       // throws std::invalid_argument
[[nodiscard]] std::string to_string(InboxState s);
[[nodiscard]] InboxState inboxStateFromString(const std::string& s);     // throws std::invalid_argument
[[nodiscard]] std::string to_string(InboxOrigin o);
[[nodiscard]] InboxOrigin inboxOriginFromString(const std::string& s);   // throws std::invalid_argument

struct InboxEvent {
    int64_t id{};
    std::optional<int64_t> channel_id;
    std::optional<int64_t> subscription_id;
    std::optional<uint32_t> vault_id;       // null until routed to a subscription
    std::string provider;
    std::string account_ref;
    std::string bucket;
    std::string object_key;
    InboxKind kind{InboxKind::Created};
    std::string event_name;
    std::string dedupe_key;
    std::optional<std::string> message_id;
    std::optional<std::string> sequencer;
    std::optional<std::string> version_id;
    std::optional<std::string> etag;
    std::optional<uint64_t> size_bytes;
    std::time_t event_time{};
    std::optional<int64_t> event_time_ms;   // milliseconds (ordering within a second); null on rows from before FX-3
    std::time_t received_at{};
    InboxState state{InboxState::Pending};
    InboxOrigin origin{InboxOrigin::Unknown};
    std::optional<std::string> note;
    unsigned int attempts{};
    std::optional<std::time_t> next_attempt_at;
    std::optional<std::string> last_error;
    std::optional<std::time_t> finished_at;

    InboxEvent() = default;
    explicit InboxEvent(pqxx::row_ref row);
};

}
