#pragma once

#include "ops/Actor.hpp"
#include "ops/APIKeys.hpp"
#include "storage/s3/provider/admin/Admin.hpp"

#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Upstream bucket administration (#237) and event-driven sync control (#96), shared by `vh upstream …` and the ws
// upstream.* commands. The only authorizing boundary for the upstream control plane.
//
// Authority (admin.upstream.*, module bits in admin_role.upstream_permissions) is split per operation class, and every
// operation that uses an API key also needs that key's keys.api permission, through the same resolver as everywhere:
//   view       inventory, inspect, event status, audit                     + key View
//   configure  admin enable/disable/check, lifecycle, events enable/repair  + key Edit (admin enable) / Consume
//   provision  create a managed bucket, adopt an existing one              + key Consume (+ vault Create)
//   protect    lock a bucket                                               + key View
//   unprotect  unlock a bucket (explicit confirmation, audited)            + key View
//   destroy    detach + cleanup (empty and delete a managed bucket)        + key Consume
// Refusals are ops::Error; a protected bucket is Denied with the lock's reason. NeedsConfirmation codes are below.
namespace vh::ops::upstream {

using KeyRef = api_keys::Ref;
namespace padmin = storage::s3::provider::admin;

inline constexpr const char* UNPROTECT_CONFIRM = "upstream_unprotect";
inline constexpr const char* DESTRUCTIVE_LIFECYCLE = "upstream_destructive_lifecycle";
inline constexpr const char* ADOPTION_CONFIRM = "upstream_adoption";
inline constexpr const char* CLEANUP_CONFIRM = "upstream_cleanup";

enum class BucketState { Managed, Adopted, Unmanaged, Protected };
[[nodiscard]] std::string to_string(BucketState s);
[[nodiscard]] BucketState bucketStateFromString(const std::string& s);   // throws Invalid

// ---- administrative credentials ------------------------------------------------------------------------------------

struct AdminEnable {
    // Cloudflare R2: the account API token for Queues + event notifications (bearer). Never echoed or stored in
    // plaintext; sealed like the S3 secret. Absent = keep the stored one; clear_provider_token removes it.
    std::optional<std::string> provider_token{};
    bool clear_provider_token = false;
};

struct AdminStatus {
    api_keys::APIKeyPtr key;
    bool supported = false;              // provider has an admin adapter (AWS, Cloudflare R2)
    bool enabled = false;
    bool has_provider_token = false;
    std::optional<std::string> account_ref;
    std::optional<padmin::Capabilities> capabilities;  // last probe
    std::string unsupported_reason;
};

// Enables provider administration on an existing upstream key after probing it (identity + capabilities). Needs
// configure + key Edit. A probe failure that isn't an auth failure still enables, with the capability marked missing.
AdminStatus enableAdmin(const Actor& actor, const KeyRef& key, const AdminEnable& req);
// Refused (Conflict) while an active event subscription is operated with this key.
AdminStatus disableAdmin(const Actor& actor, const KeyRef& key);
// Re-probes (configure) or returns the last probe (view only: probe=false).
AdminStatus adminStatus(const Actor& actor, const KeyRef& key, bool probe);

// ---- inventory and locks -------------------------------------------------------------------------------------------

struct BucketRow {
    std::string name;
    std::optional<std::string> region;
    BucketState state = BucketState::Unmanaged;
    std::string ownership;                       // managed | adopted | unmanaged
    std::string provisioning_state;              // none | creating | configuring | ready | failed | detached | …
    bool is_protected = false;
    std::optional<std::string> protection_reason;
    std::optional<std::string> protected_by;     // user name
    std::optional<std::time_t> protected_at;
    std::optional<uint32_t> vault_id;
    std::optional<std::string> vault_name;
    std::optional<std::string> events_state;     // subscription state of the bound vault, when any
    bool listed = true;                          // seen in the provider listing (false: known locally only)
    std::optional<std::time_t> last_seen_at;
};

struct InventoryQuery {
    std::string token{};
    unsigned int max = 1000;
    std::optional<BucketState> state{};
    std::optional<std::string> filter{};         // substring of the name
};

struct Inventory {
    api_keys::APIKeyPtr key;
    std::string provider;
    std::string account_ref;
    std::vector<BucketRow> buckets;
    std::string next_token;
};

// Account-level ListBuckets (one page) merged with what Vaulthalla knows. No bucket-specific or object calls.
[[nodiscard]] Inventory inventory(const Actor& actor, const KeyRef& key, const InventoryQuery& query = {});
// Works for any bucket name in the key's account, listed or not, and for providers without an admin adapter (the
// lock still applies to plain vault storage). Idempotent; audited.
BucketRow protect(const Actor& actor, const KeyRef& key, const std::string& bucket, const std::string& reason);
// NeedsConfirmation{UNPROTECT_CONFIRM} unless confirm.
BucketRow unprotect(const Actor& actor, const KeyRef& key, const std::string& bucket, bool confirm);

// ---- configuration -------------------------------------------------------------------------------------------------

struct Inspection {
    BucketRow bucket;
    padmin::BucketConfiguration config;
    std::vector<std::string> supported_lifecycle_fields;   // what this provider lets Vaulthalla set
};

// Bucket-level configuration reads only (location, versioning, object lock, lifecycle, notifications).
[[nodiscard]] Inspection inspect(const Actor& actor, const KeyRef& key, const std::string& bucket);

// The Vaulthalla-owned lifecycle rule ("vaulthalla-managed"); foreign rules are always preserved.
struct LifecyclePatch {
    std::optional<unsigned int> abort_incomplete_multipart_days{};   // 0 = remove
    std::optional<unsigned int> expire_current_days{};               // 0 = remove; destructive
    std::optional<unsigned int> expire_noncurrent_days{};            // 0 = remove; destructive; AWS only
    std::optional<std::string> prefix{};
    bool clear = false;                                              // drop our rule entirely
    bool accept_destructive = false;                                 // else NeedsConfirmation{DESTRUCTIVE_LIFECYCLE}
};

// Managed or adopted buckets only.
Inspection setLifecycle(const Actor& actor, const KeyRef& key, const std::string& bucket, const LifecyclePatch& patch);

// ---- adoption and provisioning (vault creation) ---------------------------------------------------------------------

struct AdmissionReport {
    BucketRow bucket;
    uint64_t objects_scanned = 0;
    uint64_t bytes_scanned = 0;
    bool truncated = false;                       // more objects than scanned
    bool has_vaulthalla_manifest = false;         // .vaulthalla/index-v1.json present (another vault's data)
    std::optional<uint32_t> manifest_vault_id;
    uint64_t sampled = 0;                         // HEADs made on sample objects (metadata only)
    uint64_t sampled_vaulthalla_encrypted = 0;
    uint64_t sampled_plaintext = 0;
    std::vector<std::string> sample_keys;
    padmin::Versioning versioning = padmin::Versioning::Unknown;
    std::optional<bool> object_lock;
    std::vector<std::string> blockers;            // non-empty: adoption refused
    std::vector<std::string> warnings;
    std::optional<bool> recommended_encrypt_upstream;
};

// Read-only admission: LIST up to maxObjects keys, HEAD up to sampleHeads of them. Needs provision + key Consume.
[[nodiscard]] AdmissionReport adoptPreflight(const Actor& actor, const KeyRef& key, const std::string& bucket,
                                             unsigned int maxObjects = 10000, unsigned int sampleHeads = 16);

enum class BucketMode { Existing, Create, Adopt };
[[nodiscard]] BucketMode bucketModeFromString(const std::string& s);   // existing | create | adopt; throws Invalid

// Carried by ops::vaults::Create (S3Spec::provision). Existing = today's behaviour (no admin calls at all).
struct Provision {
    BucketMode mode = BucketMode::Existing;
    std::optional<std::string> region{};           // AWS region / R2 location hint; default: the key's region
    bool generate_name = false;                    // Create: pick an available "vh-<vault>-<random>" name
    std::optional<LifecyclePatch> lifecycle{};     // Create/Adopt: our lifecycle rule
    bool events = false;                           // subscribe for event-driven sync
    std::string events_prefix{};
    bool accept_adoption = false;                  // Adopt: else NeedsConfirmation{ADOPTION_CONFIRM}
};

// Called by ops::vaults::create before the vault is added (authorization of the vault itself stays there). Returns
// the bucket name to bind. On any failure after a bucket was created, compensates (an empty bucket this attempt
// created is deleted; anything else is left and marked failed) and rethrows.
struct ProvisionTicket {
    std::string bucket;
    int64_t upstream_bucket_id = 0;
    std::string operation_token;
    bool created = false;
};
[[nodiscard]] ProvisionTicket beginProvision(const Actor& actor, unsigned int apiKeyId, const std::string& vaultName,
                                             const std::string& requestedBucket, const Provision& req);
// After the vault exists: bind, lifecycle, events (event failures leave the vault working with a failed
// subscription to repair). Never throws for event failures; returns warnings.
std::vector<std::string> finishProvision(const Actor& actor, const ProvisionTicket& ticket, unsigned int vaultId,
                                         const Provision& req);
void abortProvision(const ProvisionTicket& ticket, const std::string& reason) noexcept;

// ---- events --------------------------------------------------------------------------------------------------------

struct ChannelStatus {
    std::string provider, account_ref, region, queue_name, state;
    std::optional<std::time_t> last_poll_at, last_message_at, last_error_at;
    std::optional<std::string> last_error;
    std::optional<uint64_t> backlog;
    unsigned int consecutive_failures = 0;
};

struct EventStatus {
    uint32_t vault_id = 0;
    std::string vault_name;
    std::string bucket;
    bool supported = false;
    std::string unsupported_reason;
    std::string state;                             // none | pending | active | failed | removing | removed
    std::string baseline_state;
    std::string foreign_objects;                   // import | ignore
    std::optional<std::string> last_error;
    std::vector<std::string> rule_ids;
    unsigned int foreign_rules = 0;                // other applications' rules on the bucket (last check)
    std::optional<ChannelStatus> channel;
    uint64_t inbox_pending = 0, inbox_applied = 0, inbox_failed = 0, inbox_done_24h = 0, inbox_self_24h = 0;
    std::optional<std::time_t> last_event_at;
};

struct EventsEnable {
    std::string prefix{};
    std::optional<std::string> foreign_objects{};  // import (default) | ignore
};

EventStatus enableEvents(const Actor& actor, unsigned int vaultId, const EventsEnable& req);
EventStatus disableEvents(const Actor& actor, unsigned int vaultId);
// Re-creates whatever is missing (queue, policy grant, rule) and re-arms a failed subscription.
EventStatus repairEvents(const Actor& actor, unsigned int vaultId);
// One vault, or every S3 vault the actor may view (view).
[[nodiscard]] std::vector<EventStatus> eventStatus(const Actor& actor, std::optional<unsigned int> vaultId = std::nullopt);

// ---- detach and cleanup --------------------------------------------------------------------------------------------

// Relinquish management of a managed/adopted bucket no live vault uses: remove our event rules and lifecycle rule,
// ownership becomes unmanaged. Upstream data is untouched. Needs destroy.
BucketRow detach(const Actor& actor, const KeyRef& key, const std::string& bucket);

struct CleanupPlan {
    BucketRow bucket;
    uint64_t objects = 0, versions = 0, delete_markers = 0, bytes = 0;
    bool truncated = false;                        // counting stopped at the limit; the token still binds the counts
    padmin::Versioning versioning = padmin::Versioning::Unknown;
    std::optional<bool> object_lock;
    std::vector<std::string> sample_keys;
    std::vector<std::string> blockers;             // non-empty: cleanup refused
    std::string confirm_token;                     // pass to cleanup(); valid 10 minutes, bound to identity + counts
    std::time_t expires_at = 0;
};

struct CleanupResult {
    std::string outcome;                           // deleted | emptied | partial | refused
    uint64_t deleted = 0, failed = 0;
    bool bucket_deleted = false;
    std::vector<std::string> errors;
};

// Read-only count of what cleanup would delete. Needs destroy + key Consume.
[[nodiscard]] CleanupPlan cleanupPreflight(const Actor& actor, const KeyRef& key, const std::string& bucket);
// Re-checks everything, then deletes every object version and (delete_bucket) the bucket. NeedsConfirmation
// {CLEANUP_CONFIRM} without a valid token.
CleanupResult cleanup(const Actor& actor, const KeyRef& key, const std::string& bucket,
                      const std::string& confirmToken, bool deleteBucket = true);

// ---- audit ---------------------------------------------------------------------------------------------------------

struct AuditEntry {
    int64_t id = 0;
    std::time_t at = 0;
    std::optional<std::string> user_name;
    std::string action, provider, account_ref, bucket, outcome;
    std::optional<uint32_t> api_key_id, vault_id;
    std::string detail_json;
};

struct AuditQuery {
    std::optional<std::string> bucket{};
    unsigned int limit = 100;
};

[[nodiscard]] std::vector<AuditEntry> audit(const Actor& actor, const AuditQuery& query = {});

}
