#include "ops/UpstreamJson.hpp"

#include "db/encoding/timestamp.hpp"
#include "vault/model/APIKey.hpp"

#include <nlohmann/json.hpp>

namespace vh::storage::s3::provider::admin {

namespace {

template <typename T>
nlohmann::json optValue(const std::optional<T>& v) {
    return v ? nlohmann::json(*v) : nlohmann::json(nullptr);
}

}

std::string to_string(const Versioning v) {
    switch (v) {
    case Versioning::Unversioned: return "unversioned";
    case Versioning::Enabled: return "enabled";
    case Versioning::Suspended: return "suspended";
    case Versioning::Unknown: break;
    }
    return "unknown";
}

void to_json(nlohmann::json& j, const AccountIdentity& v) {
    j = {{"provider", v.provider}, {"account_ref", v.account_ref}, {"principal", v.principal}};
}

void to_json(nlohmann::json& j, const Capability& v) {
    j = {{"name", v.name}, {"ok", v.ok}, {"probed", v.probed}, {"detail", v.detail}};
}

void to_json(nlohmann::json& j, const Capabilities& v) {
    j = {{"identity", v.identity}, {"items", v.items},
         {"checked_at", v.checked_at ? nlohmann::json(db::encoding::timestampToString(v.checked_at)) : nlohmann::json(nullptr)}};
}

void from_json(const nlohmann::json& j, Capabilities& v) {
    v = {};
    if (!j.is_object()) return;
    if (const auto it = j.find("identity"); it != j.end() && it->is_object()) {
        v.identity.provider = it->value("provider", "");
        v.identity.account_ref = it->value("account_ref", "");
        v.identity.principal = it->value("principal", "");
    }
    if (const auto it = j.find("items"); it != j.end() && it->is_array())
        for (const auto& item : *it)
            if (item.is_object())
                v.items.push_back({.name = item.value("name", ""), .ok = item.value("ok", false),
                                   .probed = item.value("probed", false), .detail = item.value("detail", "")});
    if (const auto it = j.find("checked_at"); it != j.end() && it->is_string()) {
        try {
            v.checked_at = db::encoding::parsePostgresTimestamp(it->get<std::string>());
        } catch (const std::exception&) {
            v.checked_at = 0;
        }
    }
}

void to_json(nlohmann::json& j, const LifecycleRule& v) {
    j = {{"id", v.id},
         {"enabled", v.enabled},
         {"prefix", v.prefix},
         {"abort_incomplete_multipart_days", optValue(v.abort_incomplete_multipart_days)},
         {"expire_current_days", optValue(v.expire_current_days)},
         {"expire_noncurrent_days", optValue(v.expire_noncurrent_days)},
         {"foreign", v.foreign},
         {"destructive", v.destructive()}};
}

void to_json(nlohmann::json& j, const NotificationRule& v) {
    j = {{"id", v.id}, {"destination", v.destination}, {"destination_name", v.destination_name}, {"events", v.events},
         {"prefix", v.prefix}, {"suffix", v.suffix}, {"foreign", v.foreign}};
}

void to_json(nlohmann::json& j, const BucketConfiguration& v) {
    j = {{"bucket", v.bucket},
         {"region", optValue(v.region)},
         {"versioning", to_string(v.versioning)},
         {"object_lock", optValue(v.object_lock)},
         {"lifecycle", v.lifecycle},
         {"notifications", v.notifications},
         {"lifecycle_readable", v.lifecycle_readable},
         {"notifications_readable", v.notifications_readable},
         {"warnings", v.warnings}};
}

}

namespace vh::ops::upstream {

namespace {

nlohmann::json jsonTime(const std::optional<std::time_t>& t) {
    return t ? nlohmann::json(db::encoding::timestampToString(*t)) : nlohmann::json(nullptr);
}

template <typename T>
nlohmann::json jsonOpt(const std::optional<T>& v) {
    return v ? nlohmann::json(*v) : nlohmann::json(nullptr);
}

}

void to_json(nlohmann::json& j, const AdminStatus& v) {
    j = {{"api_key", v.key ? nlohmann::json(v.key) : nlohmann::json(nullptr)},
         {"supported", v.supported},
         {"enabled", v.enabled},
         {"has_provider_token", v.has_provider_token},
         {"account_ref", jsonOpt(v.account_ref)},
         {"capabilities", v.capabilities ? nlohmann::json(*v.capabilities) : nlohmann::json(nullptr)},
         {"unsupported_reason", v.unsupported_reason}};
}

void to_json(nlohmann::json& j, const BucketRow& v) {
    j = {{"name", v.name},
         {"region", jsonOpt(v.region)},
         {"state", to_string(v.state)},
         {"ownership", v.ownership},
         {"provisioning_state", v.provisioning_state},
         {"is_protected", v.is_protected},
         {"protection_reason", jsonOpt(v.protection_reason)},
         {"protected_by", jsonOpt(v.protected_by)},
         {"protected_at", jsonTime(v.protected_at)},
         {"vault_id", jsonOpt(v.vault_id)},
         {"vault_name", jsonOpt(v.vault_name)},
         {"events_state", jsonOpt(v.events_state)},
         {"listed", v.listed},
         {"last_seen_at", jsonTime(v.last_seen_at)}};
}

void to_json(nlohmann::json& j, const Inventory& v) {
    j = {{"api_key_id", v.key ? nlohmann::json(v.key->id) : nlohmann::json(nullptr)},
         {"provider", v.provider},
         {"account_ref", v.account_ref},
         {"buckets", v.buckets},
         {"next_token", v.next_token}};
}

void to_json(nlohmann::json& j, const Inspection& v) {
    j = {{"bucket", v.bucket}, {"config", v.config}, {"supported_lifecycle_fields", v.supported_lifecycle_fields}};
}

void to_json(nlohmann::json& j, const AdmissionReport& v) {
    j = {{"bucket", v.bucket},
         {"objects_scanned", v.objects_scanned},
         {"bytes_scanned", v.bytes_scanned},
         {"truncated", v.truncated},
         {"has_vaulthalla_manifest", v.has_vaulthalla_manifest},
         {"manifest_vault_id", jsonOpt(v.manifest_vault_id)},
         {"sampled", v.sampled},
         {"sampled_vaulthalla_encrypted", v.sampled_vaulthalla_encrypted},
         {"sampled_plaintext", v.sampled_plaintext},
         {"sample_keys", v.sample_keys},
         {"versioning", storage::s3::provider::admin::to_string(v.versioning)},
         {"object_lock", jsonOpt(v.object_lock)},
         {"blockers", v.blockers},
         {"warnings", v.warnings},
         {"recommended_encrypt_upstream", jsonOpt(v.recommended_encrypt_upstream)}};
}

void to_json(nlohmann::json& j, const ChannelStatus& v) {
    j = {{"provider", v.provider},
         {"account_ref", v.account_ref},
         {"region", v.region},
         {"queue_name", v.queue_name},
         {"state", v.state},
         {"last_poll_at", jsonTime(v.last_poll_at)},
         {"last_message_at", jsonTime(v.last_message_at)},
         {"last_error_at", jsonTime(v.last_error_at)},
         {"last_error", jsonOpt(v.last_error)},
         {"backlog", jsonOpt(v.backlog)},
         {"consecutive_failures", v.consecutive_failures}};
}

void to_json(nlohmann::json& j, const EventStatus& v) {
    j = {{"vault_id", v.vault_id},
         {"vault_name", v.vault_name},
         {"bucket", v.bucket},
         {"supported", v.supported},
         {"unsupported_reason", v.unsupported_reason},
         {"state", v.state},
         {"baseline_state", v.baseline_state},
         {"foreign_objects", v.foreign_objects},
         {"last_error", jsonOpt(v.last_error)},
         {"rule_ids", v.rule_ids},
         {"foreign_rules", v.foreign_rules},
         {"channel", v.channel ? nlohmann::json(*v.channel) : nlohmann::json(nullptr)},
         {"inbox_pending", v.inbox_pending},
         {"inbox_applied", v.inbox_applied},
         {"inbox_failed", v.inbox_failed},
         {"inbox_done_24h", v.inbox_done_24h},
         {"inbox_self_24h", v.inbox_self_24h},
         {"last_event_at", jsonTime(v.last_event_at)}};
}

void to_json(nlohmann::json& j, const CleanupPlan& v) {
    j = {{"bucket", v.bucket},
         {"objects", v.objects},
         {"versions", v.versions},
         {"delete_markers", v.delete_markers},
         {"bytes", v.bytes},
         {"truncated", v.truncated},
         {"versioning", storage::s3::provider::admin::to_string(v.versioning)},
         {"object_lock", jsonOpt(v.object_lock)},
         {"sample_keys", v.sample_keys},
         {"blockers", v.blockers},
         {"warnings", v.warnings},
         {"confirm_token", v.confirm_token},
         {"expires_at", v.expires_at ? nlohmann::json(db::encoding::timestampToString(v.expires_at)) : nlohmann::json(nullptr)}};
}

void to_json(nlohmann::json& j, const CleanupResult& v) {
    j = {{"outcome", v.outcome}, {"deleted", v.deleted}, {"failed", v.failed}, {"bucket_deleted", v.bucket_deleted},
         {"errors", v.errors}};
}

void to_json(nlohmann::json& j, const AuditEntry& v) {
    nlohmann::json detail = nlohmann::json::object();
    try {
        detail = nlohmann::json::parse(v.detail_json);
    } catch (const nlohmann::json::exception&) {
        detail = {{"raw", v.detail_json}};
    }
    j = {{"id", v.id},
         {"at", db::encoding::timestampToString(v.at)},
         {"user_name", jsonOpt(v.user_name)},
         {"action", v.action},
         {"provider", v.provider},
         {"account_ref", v.account_ref},
         {"bucket", v.bucket},
         {"outcome", v.outcome},
         {"api_key_id", jsonOpt(v.api_key_id)},
         {"vault_id", jsonOpt(v.vault_id)},
         {"detail", detail}};
}

namespace {

std::optional<unsigned int> upstreamReqUint(const nlohmann::json& j, const char* name) {
    if (!j.contains(name) || j.at(name).is_null()) return std::nullopt;
    const auto& v = j.at(name);
    if (!v.is_number_integer() || v.get<int64_t>() < 0)
        throw Invalid(std::string(name) + " must be a non-negative integer");
    return static_cast<unsigned int>(v.get<int64_t>());
}

std::optional<std::string> upstreamReqString(const nlohmann::json& j, const char* name) {
    if (!j.contains(name) || j.at(name).is_null()) return std::nullopt;
    if (!j.at(name).is_string()) throw Invalid(std::string(name) + " must be a string");
    return j.at(name).get<std::string>();
}

bool upstreamReqBool(const nlohmann::json& j, const char* name) {
    if (!j.contains(name) || j.at(name).is_null()) return false;
    if (!j.at(name).is_boolean()) throw Invalid(std::string(name) + " must be a boolean");
    return j.at(name).get<bool>();
}

}

LifecyclePatch lifecyclePatchFromJson(const nlohmann::json& j) {
    if (!j.is_object()) throw Invalid("lifecycle must be an object");
    LifecyclePatch patch;
    patch.abort_incomplete_multipart_days = upstreamReqUint(j, "abort_incomplete_multipart_days");
    patch.expire_current_days = upstreamReqUint(j, "expire_current_days");
    patch.expire_noncurrent_days = upstreamReqUint(j, "expire_noncurrent_days");
    patch.prefix = upstreamReqString(j, "prefix");
    patch.clear = upstreamReqBool(j, "clear");
    patch.accept_destructive = upstreamReqBool(j, "accept_destructive");
    return patch;
}

Provision provisionFromJson(const nlohmann::json& j) {
    if (!j.is_object()) throw Invalid("provision must be an object");
    Provision p;
    p.mode = bucketModeFromString(upstreamReqString(j, "mode").value_or("existing"));
    p.region = upstreamReqString(j, "region");
    if (p.region && p.region->empty()) p.region.reset();
    p.generate_name = upstreamReqBool(j, "generate_name");
    if (j.contains("lifecycle") && !j.at("lifecycle").is_null()) p.lifecycle = lifecyclePatchFromJson(j.at("lifecycle"));
    p.events = upstreamReqBool(j, "events");
    p.events_prefix = upstreamReqString(j, "events_prefix").value_or("");
    p.accept_adoption = upstreamReqBool(j, "accept_adoption");
    return p;
}

}
