// Contract models: upstream serializers (core/src/ops/UpstreamJson.cpp) against their declared shapes (see
// model_suites.hpp). Every instance is built in memory; each optional member appears both set and unset.

#include "model_suites.hpp"

#include "ops/Upstream.hpp"
#include "ops/UpstreamJson.hpp"
#include "vault/model/APIKey.hpp"

#include <nlohmann/json.hpp>

#include <ctime>
#include <memory>

namespace vh::test_contract_models_upstream {

namespace up = vh::ops::upstream;
namespace padmin = vh::storage::s3::provider::admin;
using nlohmann::json;

constexpr std::time_t kAt = 1'790'000'000;

std::shared_ptr<vault::model::APIKey> seededKey() {
    auto key = std::make_shared<vault::model::APIKey>();
    key->id = 7;
    key->user_id = 1;
    key->name = "aws-admin";
    key->created_at = kAt;
    key->provider = vault::model::S3Provider::AWS;
    key->access_key = "AKIAEXAMPLEEXAMPLE";
    key->region = "us-east-2";
    key->endpoint = "https://s3.us-east-2.amazonaws.com";
    key->admin_enabled = true;
    key->provider_account_id = "123456789012";
    key->admin_validated_at = kAt;
    return key;
}

padmin::Capabilities seededCapabilities() {
    padmin::Capabilities caps;
    caps.identity = {.provider = "aws-s3", .account_ref = "123456789012",
                     .principal = "arn:aws:iam::123456789012:user/vaulthalla-test-admin"};
    caps.items = {{.name = "buckets.list", .ok = true, .probed = true, .detail = "ListBuckets allowed"},
                  {.name = "events.queues", .ok = false, .probed = false, .detail = "not checkable"}};
    caps.checked_at = kAt;
    return caps;
}

up::BucketRow fullRow() {
    return {.name = "vh-test-abc123",
            .region = "us-east-2",
            .state = up::BucketState::Protected,
            .ownership = "managed",
            .provisioning_state = "ready",
            .is_protected = true,
            .protection_reason = "holds the archive",
            .protected_by = "admin",
            .protected_at = kAt,
            .vault_id = 12,
            .vault_name = "archive",
            .events_state = "active",
            .listed = true,
            .last_seen_at = kAt};
}

// A bucket's own lifecycle rule Vaulthalla did not write.
padmin::LifecycleRule theirRule() {
    padmin::LifecycleRule rule;
    rule.id = "their-rule";
    rule.enabled = false;
    rule.prefix = "logs/";
    rule.foreign = true;
    return rule;
}

up::BucketRow bareRow() {
    up::BucketRow row;
    row.name = "foreign-bucket";
    row.ownership = "unmanaged";
    row.provisioning_state = "none";
    row.listed = false;
    return row;
}

padmin::BucketConfiguration fullConfig() {
    padmin::BucketConfiguration c;
    c.bucket = "vh-test-abc123";
    c.region = "us-east-2";
    c.versioning = padmin::Versioning::Enabled;
    c.object_lock = false;
    c.mfa_delete = false;
    c.lifecycle = {{.id = "vaulthalla-abort", .enabled = true, .prefix = "",
                    .abort_incomplete_multipart_days = 7, .expire_current_days = 30, .expire_noncurrent_days = 60,
                    .foreign = false, .unmodeled = false, .raw_xml = {}},
                   theirRule()};
    c.notifications = {{.id = "vaulthalla-events", .destination = "arn:aws:sqs:us-east-2:123456789012:vh-events",
                        .destination_name = "vh-events", .events = {"s3:ObjectCreated:*"}, .prefix = "data/",
                        .suffix = ".bin", .foreign = false, .raw = {}}};
    c.warnings = {"lifecycle rule their-rule is not Vaulthalla's"};
    return c;
}

up::AdmissionReport fullAdmission() {
    up::AdmissionReport r;
    r.bucket = fullRow();
    r.objects_scanned = 120;
    r.bytes_scanned = 4096;
    r.truncated = true;
    r.has_vaulthalla_manifest = true;
    r.manifest_vault_id = 3;
    r.sampled = 4;
    r.sampled_vaulthalla_encrypted = 3;
    r.sampled_plaintext = 1;
    r.sample_keys = {"a.txt"};
    r.versioning = padmin::Versioning::Suspended;
    r.object_lock = true;
    r.blockers = {"object lock is enabled"};
    r.warnings = {"plaintext objects found"};
    r.recommended_encrypt_upstream = false;
    return r;
}

up::EventStatus fullEvents() {
    up::EventStatus e;
    e.vault_id = 12;
    e.vault_name = "archive";
    e.bucket = "vh-test-abc123";
    e.supported = true;
    e.state = "active";
    e.baseline_state = "done";
    e.foreign_objects = "import";
    e.last_error = "queue was throttled";
    e.rule_ids = {"vaulthalla-events"};
    e.foreign_rules = 1;
    e.channel = up::ChannelStatus{.provider = "aws-s3", .account_ref = "123456789012", .region = "us-east-2",
                                  .queue_name = "vh-events", .state = "active", .last_poll_at = kAt,
                                  .last_message_at = kAt, .last_error_at = kAt, .last_error = "throttled",
                                  .backlog = 3, .consecutive_failures = 0};
    e.inbox_pending = 1;
    e.inbox_applied = 2;
    e.inbox_failed = 0;
    e.inbox_done_24h = 5;
    e.inbox_self_24h = 4;
    e.last_event_at = kAt;
    return e;
}

up::CleanupPlan fullCleanupPlan() {
    up::CleanupPlan p;
    p.bucket = fullRow();
    p.objects = 10;
    p.versions = 12;
    p.delete_markers = 2;
    p.bytes = 1 << 20;
    p.truncated = false;
    p.versioning = padmin::Versioning::Enabled;
    p.object_lock = false;
    p.sample_keys = {"a.txt", "b.txt"};
    p.blockers = {};
    p.warnings = {"versions will be deleted"};
    p.confirm_token = "tok-abc";
    p.expires_at = kAt;
    return p;
}

}

namespace vh::test::contract_models {

void checkUpstreamModels(Checker& c) {
    using namespace vh::test_contract_models_upstream;

    // Admin status: with a key, account and probe; and before anything is known.
    up::AdminStatus enabled;
    enabled.key = seededKey();
    enabled.supported = true;
    enabled.enabled = true;
    enabled.has_provider_token = true;
    enabled.account_ref = "123456789012";
    enabled.capabilities = seededCapabilities();
    c.check(json(enabled), "UpstreamAdminStatus", "an enabled AWS key with a probe");
    up::AdminStatus unknown;
    unknown.supported = false;
    unknown.unsupported_reason = "provider has no admin adapter";
    c.check(json(unknown), "UpstreamAdminStatus", "an unsupported key, nothing known");
    padmin::Capabilities unprobed;
    c.check(json(unprobed), "UpstreamCapabilities", "capabilities never probed");

    // Inventory: rows in every state.
    up::Inventory inventory;
    inventory.key = seededKey();
    inventory.provider = "aws-s3";
    inventory.account_ref = "123456789012";
    inventory.buckets = {fullRow(), bareRow()};
    inventory.next_token = "page-2";
    c.check(json(inventory), "UpstreamInventory", "a page with a protected and an unlisted bucket");
    up::Inventory empty;
    empty.provider = "cloudflare-r2";
    c.check(json(empty), "UpstreamInventory", "an empty page without a key");
    for (const auto state : {up::BucketState::Managed, up::BucketState::Adopted, up::BucketState::Unmanaged}) {
        auto row = bareRow();
        row.state = state;
        c.check(json(row), "UpstreamBucketRow", "a bucket in state " + up::to_string(state));
    }

    // Inspection: full configuration and an unreadable one.
    c.check(json(up::Inspection{.bucket = fullRow(), .config = fullConfig(),
                                .supported_lifecycle_fields = {"abort_incomplete_multipart_days", "expire_current_days",
                                                               "expire_noncurrent_days", "prefix"}}),
            "UpstreamInspection", "an AWS bucket with our and foreign rules");
    padmin::BucketConfiguration unreadable;
    unreadable.bucket = "r2-bucket";
    unreadable.lifecycle_readable = false;
    unreadable.notifications_readable = false;
    c.check(json(up::Inspection{.bucket = bareRow(), .config = unreadable,
                                .supported_lifecycle_fields = {"abort_incomplete_multipart_days", "prefix"}}),
            "UpstreamInspection", "an R2 bucket with nothing readable");

    // Adoption preflight.
    c.check(json(fullAdmission()), "UpstreamAdmissionReport", "a blocked bucket with another vault's manifest");
    up::AdmissionReport emptyAdmission;
    emptyAdmission.bucket = bareRow();
    c.check(json(emptyAdmission), "UpstreamAdmissionReport", "an empty bucket");

    // Events: subscribed with a channel; never subscribed.
    c.check(json(fullEvents()), "UpstreamEventStatus", "an active subscription with its queue");
    up::EventStatus none;
    none.vault_id = 13;
    none.vault_name = "scratch";
    none.bucket = "vh-scratch";
    none.unsupported_reason = "the vault's API key is not enabled for provider administration";
    none.state = "none";  // sync::events::subscriptions::Status defaults for a vault never subscribed
    none.baseline_state = "none";
    none.foreign_objects = "import";
    c.check(json(none), "UpstreamEventStatus", "a vault without a subscription");
    auto redacted = fullEvents();
    redacted.channel->account_ref.clear();
    redacted.channel->last_error.reset();
    redacted.channel->backlog.reset();
    redacted.channel->state = "degraded";
    c.check(json(redacted), "UpstreamEventStatus", "a subscription whose queue the caller may not see");

    // Cleanup.
    c.check(json(fullCleanupPlan()), "UpstreamCleanupPlan", "a cleanup plan with its token");
    up::CleanupPlan bareCleanup;
    bareCleanup.bucket = bareRow();
    c.check(json(bareCleanup), "UpstreamCleanupPlan", "a plan without an expiry");
    c.check(json(up::CleanupResult{.outcome = "partial", .deleted = 9, .failed = 1, .bucket_deleted = false,
                                   .errors = {"AccessDenied on a.txt"}}),
            "UpstreamCleanupResult", "a partial cleanup");
    c.check(json(up::CleanupResult{.outcome = "deleted", .deleted = 10, .failed = 0, .bucket_deleted = true,
                                   .errors = {}}),
            "UpstreamCleanupResult", "a deleted bucket");

    // Audit: recorded details, and stored text that isn't JSON.
    c.check(json(up::AuditEntry{.id = 41, .at = kAt, .user_name = "admin", .action = "protect", .provider = "aws-s3",
                                .account_ref = "123456789012", .bucket = "vh-test-abc123", .outcome = "ok",
                                .api_key_id = 7, .vault_id = 12, .detail_json = R"({"reason":"holds the archive"})"}),
            "UpstreamAuditEntry", "a protect record");
    up::AuditEntry rawDetail;
    rawDetail.id = 42;
    rawDetail.at = kAt;
    rawDetail.action = "cleanup";
    rawDetail.outcome = "partial";
    rawDetail.detail_json = "not json";
    c.check(json(rawDetail),
            "UpstreamAuditEntry", "a record whose detail is not JSON");
}

}
