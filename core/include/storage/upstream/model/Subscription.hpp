#pragma once

#include "db/Fwd.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// A vault's event rule on its bucket, routed to a channel (upstream_event_subscription).
namespace vh::storage::upstream::model {

enum class SubscriptionState { Pending, Active, Failed, Removing, Removed };
enum class BaselineState { None, Pending, Running, Done };
enum class ForeignObjects { Import, Ignore };

[[nodiscard]] std::string to_string(SubscriptionState s);
[[nodiscard]] SubscriptionState subscriptionStateFromString(const std::string& s);   // throws std::invalid_argument
[[nodiscard]] std::string to_string(BaselineState s);
[[nodiscard]] BaselineState baselineStateFromString(const std::string& s);           // throws std::invalid_argument
[[nodiscard]] std::string to_string(ForeignObjects f);
[[nodiscard]] ForeignObjects foreignObjectsFromString(const std::string& s);         // throws std::invalid_argument

struct Subscription {
    int64_t id{};
    std::optional<int64_t> channel_id;
    int64_t upstream_bucket_id{};
    std::optional<uint32_t> vault_id;
    std::vector<std::string> rule_ids;      // provider rule ids we own
    std::string prefix;
    ForeignObjects foreign_objects{ForeignObjects::Import};
    SubscriptionState state{SubscriptionState::Pending};
    BaselineState baseline_state{BaselineState::None};
    std::optional<std::time_t> baseline_started_at;
    unsigned int foreign_rules{};
    std::optional<std::string> last_error;
    std::optional<std::time_t> activated_at;
    std::time_t created_at{};
    std::time_t updated_at{};

    Subscription() = default;
    explicit Subscription(pqxx::row_ref row);
};

}
