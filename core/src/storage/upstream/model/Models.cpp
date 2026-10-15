#include "storage/upstream/model/Audit.hpp"
#include "storage/upstream/model/Bucket.hpp"
#include "storage/upstream/model/Channel.hpp"
#include "storage/upstream/model/InboxEvent.hpp"
#include "storage/upstream/model/Subscription.hpp"
#include "storage/upstream/model/WriteIntent.hpp"

#include "db/encoding/has.hpp"
#include "db/encoding/timestamp.hpp"

#include <nlohmann/json.hpp>
#include <pqxx/row>

#include <array>
#include <stdexcept>
#include <utility>

namespace vh::storage::upstream::model {

namespace {

template <typename E, std::size_t N>
std::string nameOf(const E value, const std::array<std::pair<E, const char*>, N>& table) {
    for (const auto& [v, n] : table)
        if (v == value) return n;
    throw std::invalid_argument("unknown enum value");
}

template <typename E, std::size_t N>
E valueOf(const std::string& s, const std::array<std::pair<E, const char*>, N>& table, const char* what) {
    for (const auto& [v, n] : table)
        if (s == n) return v;
    throw std::invalid_argument(std::string("invalid ") + what + ": '" + s + "'");
}

constexpr std::array<std::pair<Ownership, const char*>, 3> kOwnership{{
    {Ownership::Managed, "managed"}, {Ownership::Adopted, "adopted"}, {Ownership::Unmanaged, "unmanaged"}}};

constexpr std::array<std::pair<ProvisioningState, const char*>, 8> kProvisioning{{
    {ProvisioningState::None, "none"}, {ProvisioningState::Creating, "creating"},
    {ProvisioningState::Configuring, "configuring"}, {ProvisioningState::Ready, "ready"},
    {ProvisioningState::Failed, "failed"}, {ProvisioningState::Detached, "detached"},
    {ProvisioningState::Deleting, "deleting"}, {ProvisioningState::Deleted, "deleted"}}};

constexpr std::array<std::pair<AuditOutcome, const char*>, 4> kOutcome{{
    {AuditOutcome::Ok, "ok"}, {AuditOutcome::Refused, "refused"}, {AuditOutcome::Failed, "failed"},
    {AuditOutcome::Partial, "partial"}}};

constexpr std::array<std::pair<ChannelState, const char*>, 5> kChannel{{
    {ChannelState::Provisioning, "provisioning"}, {ChannelState::Active, "active"},
    {ChannelState::Degraded, "degraded"}, {ChannelState::Failed, "failed"}, {ChannelState::Removed, "removed"}}};

constexpr std::array<std::pair<SubscriptionState, const char*>, 5> kSubscription{{
    {SubscriptionState::Pending, "pending"}, {SubscriptionState::Active, "active"},
    {SubscriptionState::Failed, "failed"}, {SubscriptionState::Removing, "removing"},
    {SubscriptionState::Removed, "removed"}}};

constexpr std::array<std::pair<BaselineState, const char*>, 4> kBaseline{{
    {BaselineState::None, "none"}, {BaselineState::Pending, "pending"}, {BaselineState::Running, "running"},
    {BaselineState::Done, "done"}}};

constexpr std::array<std::pair<ForeignObjects, const char*>, 2> kForeign{{
    {ForeignObjects::Import, "import"}, {ForeignObjects::Ignore, "ignore"}}};

constexpr std::array<std::pair<InboxKind, const char*>, 2> kKind{{
    {InboxKind::Created, "created"}, {InboxKind::Removed, "removed"}}};

constexpr std::array<std::pair<InboxState, const char*>, 5> kInbox{{
    {InboxState::Pending, "pending"}, {InboxState::Applied, "applied"}, {InboxState::Done, "done"},
    {InboxState::Skipped, "skipped"}, {InboxState::Failed, "failed"}}};

constexpr std::array<std::pair<InboxOrigin, const char*>, 3> kOrigin{{
    {InboxOrigin::External, "external"}, {InboxOrigin::Self, "self"}, {InboxOrigin::Unknown, "unknown"}}};

constexpr std::array<std::pair<WriteOp, const char*>, 2> kWriteOp{{{WriteOp::Put, "put"}, {WriteOp::Delete, "delete"}}};

std::optional<std::time_t> optTime(const pqxx::row_ref row, const std::string_view name) {
    if (const auto text = db::encoding::try_get<std::string>(row, name))
        return db::encoding::parsePostgresTimestamp(*text);
    return std::nullopt;
}

std::time_t reqTime(const pqxx::row_ref row, const std::string_view name) { return optTime(row, name).value_or(0); }

std::optional<std::string> optText(const pqxx::row_ref row, const std::string_view name) {
    return db::encoding::try_get<std::string>(row, name);
}

std::string text(const pqxx::row_ref row, const std::string_view name) { return optText(row, name).value_or(""); }

}

std::string to_string(const Ownership o) { return nameOf(o, kOwnership); }
Ownership ownershipFromString(const std::string& s) { return valueOf(s, kOwnership, "ownership"); }
std::string to_string(const ProvisioningState s) { return nameOf(s, kProvisioning); }
ProvisioningState provisioningStateFromString(const std::string& s) {
    return valueOf(s, kProvisioning, "provisioning state");
}
std::string to_string(const AuditOutcome o) { return nameOf(o, kOutcome); }
AuditOutcome auditOutcomeFromString(const std::string& s) { return valueOf(s, kOutcome, "audit outcome"); }
std::string to_string(const ChannelState s) { return nameOf(s, kChannel); }
ChannelState channelStateFromString(const std::string& s) { return valueOf(s, kChannel, "channel state"); }
std::string to_string(const SubscriptionState s) { return nameOf(s, kSubscription); }
SubscriptionState subscriptionStateFromString(const std::string& s) {
    return valueOf(s, kSubscription, "subscription state");
}
std::string to_string(const BaselineState s) { return nameOf(s, kBaseline); }
BaselineState baselineStateFromString(const std::string& s) { return valueOf(s, kBaseline, "baseline state"); }
std::string to_string(const ForeignObjects f) { return nameOf(f, kForeign); }
ForeignObjects foreignObjectsFromString(const std::string& s) { return valueOf(s, kForeign, "foreign objects policy"); }
std::string to_string(const InboxKind k) { return nameOf(k, kKind); }
InboxKind inboxKindFromString(const std::string& s) { return valueOf(s, kKind, "event kind"); }
std::string to_string(const InboxState s) { return nameOf(s, kInbox); }
InboxState inboxStateFromString(const std::string& s) { return valueOf(s, kInbox, "inbox state"); }
std::string to_string(const InboxOrigin o) { return nameOf(o, kOrigin); }
InboxOrigin inboxOriginFromString(const std::string& s) { return valueOf(s, kOrigin, "event origin"); }
std::string to_string(const WriteOp op) { return nameOf(op, kWriteOp); }
WriteOp writeOpFromString(const std::string& s) { return valueOf(s, kWriteOp, "write op"); }

Bucket::Bucket(const pqxx::row_ref row)
    : id(row["id"].as<int64_t>()),
      provider(row["provider"].as<std::string>()),
      account_ref(row["account_ref"].as<std::string>()),
      bucket(row["bucket"].as<std::string>()),
      region(optText(row, "region")),
      ownership(ownershipFromString(row["ownership"].as<std::string>())),
      provisioning_state(provisioningStateFromString(row["provisioning_state"].as<std::string>())),
      created_by_vaulthalla(row["created_by_vaulthalla"].as<bool>()),
      operation_token(optText(row, "operation_token")),
      vault_id(db::encoding::try_get<uint32_t>(row, "vault_id")),
      is_protected(row["is_protected"].as<bool>()),
      protected_at(optTime(row, "protected_at")),
      protected_by(db::encoding::try_get<uint32_t>(row, "protected_by")),
      protected_by_name(optText(row, "protected_by_name")),
      protection_reason(optText(row, "protection_reason")),
      last_seen_api_key_id(db::encoding::try_get<uint32_t>(row, "last_seen_api_key_id")),
      discovered_at(optTime(row, "discovered_at")),
      last_seen_at(optTime(row, "last_seen_at")),
      last_error(optText(row, "last_error")),
      created_at(reqTime(row, "created_at")),
      updated_at(reqTime(row, "updated_at")) {}

AuditRecord::AuditRecord(const pqxx::row_ref row)
    : id(row["id"].as<int64_t>()),
      at(reqTime(row, "at")),
      user_id(db::encoding::try_get<uint32_t>(row, "user_id")),
      user_name(optText(row, "user_name")),
      action(row["action"].as<std::string>()),
      provider(text(row, "provider")),
      account_ref(text(row, "account_ref")),
      bucket(text(row, "bucket")),
      api_key_id(db::encoding::try_get<uint32_t>(row, "api_key_id")),
      vault_id(db::encoding::try_get<uint32_t>(row, "vault_id")),
      outcome(auditOutcomeFromString(row["outcome"].as<std::string>())),
      detail_json(optText(row, "detail").value_or("{}")) {}

Channel::Channel(const pqxx::row_ref row)
    : id(row["id"].as<int64_t>()),
      provider(row["provider"].as<std::string>()),
      account_ref(row["account_ref"].as<std::string>()),
      region(text(row, "region")),
      queue_name(row["queue_name"].as<std::string>()),
      queue_ref(optText(row, "queue_ref")),
      queue_arn(optText(row, "queue_arn")),
      dlq_ref(optText(row, "dlq_ref")),
      dlq_arn(optText(row, "dlq_arn")),
      api_key_id(db::encoding::try_get<uint32_t>(row, "api_key_id")),
      state(channelStateFromString(row["state"].as<std::string>())),
      created_by_vaulthalla(row["created_by_vaulthalla"].as<bool>()),
      last_poll_at(optTime(row, "last_poll_at")),
      last_success_at(optTime(row, "last_success_at")),
      last_message_at(optTime(row, "last_message_at")),
      last_error(optText(row, "last_error")),
      last_error_at(optTime(row, "last_error_at")),
      consecutive_failures(db::encoding::try_get<unsigned int>(row, "consecutive_failures").value_or(0)),
      backlog_estimate(db::encoding::try_get<uint64_t>(row, "backlog_estimate")),
      next_poll_at(optTime(row, "next_poll_at")),
      continuity_broken_at(optTime(row, "continuity_broken_at")),
      continuity_note(optText(row, "continuity_note")),
      dlq_depth(db::encoding::try_get<uint64_t>(row, "dlq_depth")),
      created_at(reqTime(row, "created_at")),
      updated_at(reqTime(row, "updated_at")) {}

Subscription::Subscription(const pqxx::row_ref row)
    : id(row["id"].as<int64_t>()),
      channel_id(db::encoding::try_get<int64_t>(row, "channel_id")),
      upstream_bucket_id(row["upstream_bucket_id"].as<int64_t>()),
      vault_id(db::encoding::try_get<uint32_t>(row, "vault_id")),
      prefix(text(row, "prefix")),
      foreign_objects(foreignObjectsFromString(row["foreign_objects"].as<std::string>())),
      state(subscriptionStateFromString(row["state"].as<std::string>())),
      baseline_state(baselineStateFromString(row["baseline_state"].as<std::string>())),
      baseline_started_at(optTime(row, "baseline_started_at")),
      foreign_rules(db::encoding::try_get<unsigned int>(row, "foreign_rules").value_or(0)),
      last_error(optText(row, "last_error")),
      activated_at(optTime(row, "activated_at")),
      created_at(reqTime(row, "created_at")),
      updated_at(reqTime(row, "updated_at")) {
    if (const auto ids = optText(row, "rule_ids")) {
        const auto parsed = nlohmann::json::parse(*ids, nullptr, false);
        if (parsed.is_array())
            for (const auto& id : parsed)
                if (id.is_string()) rule_ids.push_back(id.get<std::string>());
    }
}

InboxEvent::InboxEvent(const pqxx::row_ref row)
    : id(row["id"].as<int64_t>()),
      channel_id(db::encoding::try_get<int64_t>(row, "channel_id")),
      subscription_id(db::encoding::try_get<int64_t>(row, "subscription_id")),
      vault_id(db::encoding::try_get<uint32_t>(row, "vault_id")),
      provider(row["provider"].as<std::string>()),
      account_ref(row["account_ref"].as<std::string>()),
      bucket(row["bucket"].as<std::string>()),
      object_key(row["object_key"].as<std::string>()),
      kind(inboxKindFromString(row["kind"].as<std::string>())),
      event_name(text(row, "event_name")),
      dedupe_key(row["dedupe_key"].as<std::string>()),
      message_id(optText(row, "message_id")),
      sequencer(optText(row, "sequencer")),
      version_id(optText(row, "version_id")),
      etag(optText(row, "etag")),
      size_bytes(db::encoding::try_get<uint64_t>(row, "size_bytes")),
      event_time(reqTime(row, "event_time")),
      event_time_ms(db::encoding::try_get<int64_t>(row, "event_time_ms")),
      received_at(reqTime(row, "received_at")),
      state(inboxStateFromString(row["state"].as<std::string>())),
      origin(inboxOriginFromString(row["origin"].as<std::string>())),
      note(optText(row, "note")),
      attempts(db::encoding::try_get<unsigned int>(row, "attempts").value_or(0)),
      next_attempt_at(optTime(row, "next_attempt_at")),
      last_error(optText(row, "last_error")),
      finished_at(optTime(row, "finished_at")) {}

WriteIntent::WriteIntent(const pqxx::row_ref row)
    : id(row["id"].as<int64_t>()),
      vault_id(row["vault_id"].as<uint32_t>()),
      object_key(row["object_key"].as<std::string>()),
      op(writeOpFromString(row["op"].as<std::string>())),
      expected_size(db::encoding::try_get<uint64_t>(row, "expected_size")),
      recorded_at(reqTime(row, "recorded_at")),
      expires_at(reqTime(row, "expires_at")),
      etag(optText(row, "etag")),
      completed_at(optTime(row, "completed_at")) {}

}
