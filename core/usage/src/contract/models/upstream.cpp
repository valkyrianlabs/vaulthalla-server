// ws models: upstream provider administration (#237) and event-driven sync (#96). Serializers:
// core/src/ops/UpstreamJson.cpp (ops::upstream and storage::s3::provider::admin to_json). Times are ISO-8601 UTC
// strings ("2026-10-20T12:00:00Z", db::encoding::timestampToString) or null.

#include "models.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField upModelTime(std::string name, std::string what) {
    return str(std::move(name)).nullable().desc(std::move(what) + " (ISO-8601 UTC), null when unknown or never.");
}

WsField upModelVersioning() {
    return str("versioning").oneOf({"unversioned", "enabled", "suspended", "unknown"}).desc("Bucket versioning state.");
}

std::vector<std::string> upModelBucketStates() { return {"managed", "adopted", "unmanaged", "protected"}; }

std::vector<std::string> upModelSubscriptionStates() {
    return {"none", "pending", "active", "failed", "removing", "removed"};
}

}

std::vector<WsModel> upstreamModels() {
    std::vector<WsModel> out;

    out.push_back(model("UpstreamAccountIdentity",
        "The provider account behind an API key (storage::s3::provider::admin::to_json(AccountIdentity)).",
        {str("provider").desc("Provider identity: \"aws-s3\" or \"cloudflare-r2\"."),
         str("account_ref").desc("AWS 12-digit account id or Cloudflare account id."),
         str("principal").desc("AWS caller ARN, or \"r2-token\" (never a secret).")}));

    out.push_back(model("UpstreamCapability",
        "One probed provider capability (admin::to_json(Capability)).",
        {str("name").desc("\"buckets.list\", \"buckets.create\", \"lifecycle\", \"events.notifications\", ..."),
         boolean("ok"),
         boolean("probed").desc("false: not checkable without side effects; ok is then a best guess."),
         str("detail")}));

    out.push_back(model("UpstreamCapabilities",
        "The last capability probe of an API key (admin::to_json(Capabilities)).",
        {object("identity", "UpstreamAccountIdentity"),
         objectArray("items", "UpstreamCapability"),
         upModelTime("checked_at", "When the probe ran")}));

    out.push_back(model("UpstreamLifecycleRule",
        "One lifecycle rule on a bucket (admin::to_json(LifecycleRule)). Vaulthalla's own rules are \"vaulthalla-*\".",
        {str("id"),
         boolean("enabled"),
         str("prefix").desc("Empty: the whole bucket."),
         uinteger("abort_incomplete_multipart_days").nullable(),
         uinteger("expire_current_days").nullable().desc("Destructive: deletes live objects."),
         uinteger("expire_noncurrent_days").nullable().desc("AWS only; destructive for old versions."),
         boolean("foreign").desc("Not Vaulthalla's (read-only, preserved on every write)."),
         boolean("destructive").desc("The rule expires current or noncurrent objects.")}));

    out.push_back(model("UpstreamNotificationRule",
        "One event notification rule on a bucket (admin::to_json(NotificationRule)).",
        {str("id"),
         str("destination").desc("AWS queue/topic/lambda ARN, or the R2 queue id."),
         str("destination_name").desc("R2 queue name when known."),
         strArray("events").desc("Provider-native event names / actions."),
         str("prefix"),
         str("suffix"),
         boolean("foreign")}));

    out.push_back(model("UpstreamBucketConfiguration",
        "A bucket's configuration as the provider reports it (admin::to_json(BucketConfiguration)).",
        {str("bucket"),
         str("region").nullable(),
         upModelVersioning(),
         boolean("object_lock").nullable().desc("null: not readable with this credential."),
         boolean("mfa_delete").nullable().desc("null: never configured or not readable."),
         objectArray("lifecycle", "UpstreamLifecycleRule"),
         objectArray("notifications", "UpstreamNotificationRule")
             .desc("Empty with notifications_readable false when unknown."),
         boolean("lifecycle_readable"),
         boolean("notifications_readable"),
         strArray("warnings")}));

    out.push_back(model("UpstreamAdminStatus",
        "Provider administration status of an API key (ops::upstream::to_json(AdminStatus)).",
        {object("api_key", "APIKey").nullable(),
         boolean("supported").desc("The provider has an admin adapter (AWS S3, Cloudflare R2)."),
         boolean("enabled"),
         boolean("has_provider_token").desc("A Cloudflare API token is stored (the token itself is never sent)."),
         str("account_ref").nullable(),
         object("capabilities", "UpstreamCapabilities").nullable().desc("The last probe; null before the first."),
         str("unsupported_reason").desc("Empty when supported.")}));

    out.push_back(model("UpstreamBucketRow",
        "One bucket of the account merged with what Vaulthalla knows (ops::upstream::to_json(BucketRow)).",
        {str("name"),
         str("region").nullable(),
         str("state").oneOf(upModelBucketStates()),
         str("ownership").oneOf({"managed", "adopted", "unmanaged"}),
         str("provisioning_state")
             .oneOf({"none", "creating", "configuring", "ready", "failed", "detached", "deleting", "deleted"}),
         boolean("is_protected"),
         str("protection_reason").nullable(),
         str("protected_by").nullable().desc("User name."),
         upModelTime("protected_at", "When the lock was set"),
         uinteger("vault_id").nullable().desc("The vault bound to the bucket."),
         str("vault_name").nullable(),
         str("events_state").nullable().oneOf(upModelSubscriptionStates())
             .desc("Event subscription state of the bound vault, when it has one."),
         boolean("listed").desc("Seen in the provider listing (false: known locally only)."),
         upModelTime("last_seen_at", "When the bucket was last seen in a listing")}));

    out.push_back(model("UpstreamInventory",
        "One page of an account's buckets (ops::upstream::to_json(Inventory)).",
        {uinteger("api_key_id").nullable(),
         str("provider"),
         str("account_ref"),
         objectArray("buckets", "UpstreamBucketRow"),
         str("next_token").desc("Empty on the last page.")}));

    out.push_back(model("UpstreamInspection",
        "A bucket with its configuration (ops::upstream::to_json(Inspection)).",
        {object("bucket", "UpstreamBucketRow"),
         object("config", "UpstreamBucketConfiguration"),
         strArray("supported_lifecycle_fields",
                  {"abort_incomplete_multipart_days", "expire_current_days", "expire_noncurrent_days", "prefix"})
             .desc("What this provider lets Vaulthalla set (expire_noncurrent_days: AWS only).")}));

    out.push_back(model("UpstreamAdmissionReport",
        "The read-only adoption check of an existing bucket (ops::upstream::to_json(AdmissionReport)).",
        {object("bucket", "UpstreamBucketRow"),
         uinteger("objects_scanned"),
         uinteger("bytes_scanned"),
         boolean("truncated").desc("More objects than were scanned."),
         boolean("has_vaulthalla_manifest").desc(".vaulthalla/index-v1.json is present (another vault's data)."),
         uinteger("manifest_vault_id").nullable(),
         uinteger("sampled").desc("HEADs made on sample objects (metadata only)."),
         uinteger("sampled_vaulthalla_encrypted"),
         uinteger("sampled_plaintext"),
         strArray("sample_keys"),
         upModelVersioning(),
         boolean("object_lock").nullable(),
         strArray("blockers").desc("Non-empty: adoption is refused."),
         strArray("warnings"),
         boolean("recommended_encrypt_upstream").nullable()}));

    out.push_back(model("UpstreamChannelStatus",
        "The queue an event subscription drains (ops::upstream::to_json(ChannelStatus)). account_ref is empty and "
        "last_error null for callers who may not view the API key operating the queue.",
        {str("provider"),
         str("account_ref").desc("Empty when redacted."),
         str("region").desc("Empty for account-global queues (R2)."),
         str("queue_name"),
         str("state").oneOf({"provisioning", "active", "degraded", "failed", "removed"}),
         upModelTime("last_poll_at", "Last poll"),
         upModelTime("last_message_at", "Last message received"),
         upModelTime("last_error_at", "Last error"),
         str("last_error").nullable(),
         uinteger("backlog").nullable().desc("Approximate queue depth, when the provider reports it."),
         uinteger("consecutive_failures")}));

    out.push_back(model("UpstreamEventStatus",
        "A vault's event subscription, queue health and inbox counts (ops::upstream::to_json(EventStatus)). A vault "
        "without a subscription reports state \"none\".",
        {uinteger("vault_id"),
         str("vault_name"),
         str("bucket"),
         boolean("supported"),
         str("unsupported_reason").desc("Empty when supported."),
         str("state").oneOf(upModelSubscriptionStates()),
         str("baseline_state").oneOf({"none", "pending", "running", "done"}),
         str("foreign_objects").oneOf({"import", "ignore"}),
         str("last_error").nullable(),
         strArray("rule_ids"),
         uinteger("foreign_rules").desc("Other applications' notification rules on the bucket (last check)."),
         object("channel", "UpstreamChannelStatus").nullable(),
         uinteger("inbox_pending"),
         uinteger("inbox_applied"),
         uinteger("inbox_failed"),
         uinteger("inbox_done_24h"),
         uinteger("inbox_self_24h"),
         upModelTime("last_event_at", "Last event received")}));

    out.push_back(model("UpstreamCleanupPlan",
        "What a bucket cleanup would delete, with its confirm token (ops::upstream::to_json(CleanupPlan)).",
        {object("bucket", "UpstreamBucketRow"),
         uinteger("objects"),
         uinteger("versions"),
         uinteger("delete_markers"),
         uinteger("bytes"),
         boolean("truncated").desc("Counting stopped at the limit; the token still binds the counts."),
         upModelVersioning(),
         boolean("object_lock").nullable(),
         strArray("sample_keys"),
         strArray("blockers").desc("Non-empty: cleanup is refused."),
         strArray("warnings"),
         str("confirm_token").desc("Pass to upstream.bucket.cleanup; valid 10 minutes, bound to identity and counts."),
         upModelTime("expires_at", "When confirm_token expires")}));

    out.push_back(model("UpstreamCleanupResult",
        "The outcome of a bucket cleanup (ops::upstream::to_json(CleanupResult)).",
        {str("outcome").oneOf({"deleted", "emptied", "partial"}),
         uinteger("deleted"),
         uinteger("failed"),
         boolean("bucket_deleted"),
         strArray("errors")}));

    out.push_back(model("UpstreamAuditEntry",
        "One upstream control-plane audit record (ops::upstream::to_json(AuditEntry)).",
        {integer("id"),
         str("at").desc("ISO-8601 UTC."),
         str("user_name").nullable(),
         str("action").desc("\"protect\", \"unprotect\", \"bucket.create\", \"cleanup\", \"admin.enable\", ..."),
         str("provider"),
         str("account_ref"),
         str("bucket"),
         str("outcome").oneOf({"ok", "refused", "failed", "partial"}),
         uinteger("api_key_id").nullable(),
         uinteger("vault_id").nullable(),
         object("detail").desc("The action's details as recorded (free-form per action); {raw: text} when the stored "
                               "text is not JSON.")}));

    return out;
}

}
