#pragma once

#include "vault/Fwd.hpp"
#include "vault/model/APIKey.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <functional>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// Provider administration for upstream S3 accounts (#237): buckets, lifecycle, event notifications and the queues
// they feed (#96). One administrative API key per provider account does everything; Vaulthalla splits authority with
// admin.upstream.* RBAC, not with extra cloud identities. AWS S3, Cloudflare R2 and Backblaze B2 have adapters (B2 for
// buckets only: its S3-compatible API has no lifecycle or event-notification calls); every other provider answers
// supportsAdmin() == false and keeps working as plain vault storage.
//
// These are trusted primitives: they never authorize (ops::upstream does) and they never consult protection locks
// themselves — storage::upstream::guard is called by the adapters for every bucket-scoped request before it is sent.
namespace vh::storage::s3::provider::admin {

// A provider refused or failed a request. `code` is the provider's error code ("AccessDenied", "NoSuchBucket",
// "BucketAlreadyExists", Cloudflare's numeric code as text, …) when there was one. what() never contains secrets or
// raw authorization material and is capped in size.
struct ProviderError : std::runtime_error {
    std::string code;
    long http_status{};
    ProviderError(const std::string& message, std::string code_ = {}, long http = 0)
        : std::runtime_error(message), code(std::move(code_)), http_status(http) {}

    [[nodiscard]] bool accessDenied() const { return code == "AccessDenied" || http_status == 403 || code == "10000"; }
    [[nodiscard]] bool notFound() const { return http_status == 404; }
};

// The credential can't do this at all (missing cloud permission, or a provider token is needed and absent).
struct CapabilityMissing : std::runtime_error {
    std::string capability;     // e.g. "events.queues", "sqs:CreateQueue"
    CapabilityMissing(std::string capability_, const std::string& message)
        : std::runtime_error(message), capability(std::move(capability_)) {}
};

struct AccountIdentity {
    std::string provider;        // providerIdentity(): "aws-s3" | "cloudflare-r2" | "backblaze-b2"
    std::string account_ref;     // AWS 12-digit account, R2 32-hex account id, B2 the region's S3 endpoint host
    std::string principal;       // AWS caller ARN, R2 "r2-token", B2 "b2-application-key" (never a secret)
};

// One capability probe result. `ok` false + `detail` says what the operator must grant.
struct Capability {
    std::string name;            // "buckets.list" "buckets.create" "lifecycle" "events.notifications" "events.queues"
    bool ok{false};
    bool probed{false};          // false: not checkable without side effects; `ok` is then a best guess
    std::string detail;
};

struct Capabilities {
    AccountIdentity identity;
    std::vector<Capability> items;
    std::time_t checked_at{};
    [[nodiscard]] bool has(const std::string& name) const {
        for (const auto& c : items) if (c.name == name) return c.ok;
        return false;
    }
};

// Account-level bucket listing (names, never object data).
struct BucketSummary {
    std::string name;
    std::optional<std::string> region;           // AWS: from ListBuckets BucketRegion when present
    std::optional<std::time_t> created_at;
};

struct BucketPage {
    std::vector<BucketSummary> buckets;
    std::string next_token;                       // empty on the last page
};

enum class Versioning { Unversioned, Enabled, Suspended, Unknown };

// GetBucketVersioning. AWS: a bucket that was never configured has no status (Unversioned); once Enabled it can only
// go to Suspended, never back to Unversioned. Object Lock implies Enabled and can't be suspended. MFA delete can only
// be changed by the root account with an MFA token, so Vaulthalla reads it and never sets it.
struct VersioningState {
    Versioning status{Versioning::Unknown};
    std::optional<bool> mfa_delete;              // nullopt: the bucket was never configured with MFA delete
};

// Why Cloudflare R2 refuses provider versioning (CapabilityMissing("versioning", …), probe detail).
inline constexpr const char* kR2VersioningUnsupported =
    "Cloudflare R2 has no object versioning (no version ids, noncurrent versions or delete markers); "
    "use local snapshots or local versioning for file recovery on R2";

// What Backblaze B2's S3-compatible API leaves to its console and native API (probe details, CapabilityMissing).
inline constexpr const char* kB2LifecycleUnsupported =
    "Backblaze B2 lifecycle rules are set in the Backblaze console or its native API; its S3-compatible API has no "
    "lifecycle calls, so Vaulthalla neither reads nor changes them";
inline constexpr const char* kB2EventsUnsupported =
    "Backblaze B2 event notifications are not available through its S3-compatible API; event-driven sync supports "
    "AWS S3 and Cloudflare R2 vaults only";
inline constexpr const char* kB2VersioningFixed =
    "Backblaze B2 buckets always keep object versions and how long is set by B2 lifecycle rules (Backblaze console or "
    "native API), so Vaulthalla can't turn versioning on or off, or set its retention, on B2";

// Provider-neutral lifecycle rule. Only the fields both a provider and Vaulthalla support are exposed; adapters refuse
// (Invalid via std::invalid_argument) a field their provider lacks (R2 has no noncurrent versions; neither exposes
// storage-class transitions through Vaulthalla).
struct LifecycleRule {
    std::string id;                                       // Vaulthalla-owned rules are "vaulthalla-*"
    bool enabled{true};
    std::string prefix;                                   // empty = whole bucket
    std::optional<unsigned int> abort_incomplete_multipart_days;
    std::optional<unsigned int> expire_current_days;      // destructive: deletes live objects
    std::optional<unsigned int> expire_noncurrent_days;   // AWS only; destructive for old versions
    bool foreign{false};                                  // not ours (read-only, preserved on every write)
    // The rule has elements this model doesn't carry (tag/size filters, transitions, dates, delete-marker expiry,
    // newer-noncurrent counts): rebuilding it from the fields above would change what it does.
    bool unmodeled{false};
    std::string raw_xml;                                  // foreign rules round-trip verbatim
    [[nodiscard]] bool destructive() const { return expire_current_days || expire_noncurrent_days; }
};

// One event subscription rule on a bucket, ours or another application's.
struct NotificationRule {
    std::string id;                    // AWS configuration Id; R2 ruleId
    std::string destination;           // AWS queue ARN / topic ARN / lambda ARN; R2 queue id
    std::string destination_name;      // R2 queue name when known
    std::vector<std::string> events;   // provider-native event names / actions
    std::string prefix, suffix;
    bool foreign{true};
    std::string raw;                   // AWS: verbatim XML of the configuration element (round-trips on merge)
};

struct BucketConfiguration {
    std::string bucket;
    std::optional<std::string> region;
    Versioning versioning{Versioning::Unknown};
    std::optional<bool> object_lock;                 // nullopt: not readable with this credential
    std::optional<bool> mfa_delete;                  // MfaDelete Enabled/Disabled; nullopt: never configured or unreadable
    std::vector<LifecycleRule> lifecycle;
    std::vector<NotificationRule> notifications;     // empty + notifications_readable=false when unknown
    bool lifecycle_readable{true};
    bool notifications_readable{true};
    std::vector<std::string> warnings;
};

// Read-only object inventory page (admission/preflight). Never reads object bodies.
struct ObjectSummary {
    std::string key;
    uint64_t size{};
    std::string etag;
    std::optional<std::time_t> last_modified;
    std::optional<std::string> version_id;      // version listings only
    bool delete_marker{false};
    bool latest{true};
};

struct ObjectPage {
    std::vector<ObjectSummary> objects;
    std::string next_token;                     // continuation (ListObjectsV2) or "key\nversion" (ListObjectVersions)
};

struct CreateBucketRequest {
    std::string name;
    std::optional<std::string> region;          // AWS region; R2 location hint (wnam, enam, weur, eeur, apac, oc);
                                                // B2: the key's own region or nothing (an account lives in one region)
};

// A read-only provider key limited to one bucket, for a vault read grant (ops/ReadGrants.hpp). Backblaze B2 only so
// far: the native b2_create_key with bucketIds = [the bucket] and kReadKeyCapabilities.
struct ReadKeyRequest {
    std::string bucket{};
    std::string key_name{};          // [A-Za-z0-9-], at most 100 characters
};

struct ReadKey {
    std::string key_id;              // the provider's id for the key (the S3 access key id)
    std::string secret;              // shown once by the provider; the caller encrypts it and never stores it
    std::string key_name;
    std::string bucket;
    std::string bucket_id;           // B2's id of the bucket the key is restricted to
    std::vector<std::string> capabilities;
    std::string endpoint;            // the S3-compatible endpoint the key works with (https://s3.<region>.backblazeb2.com)
    std::string region;
};

// What a read key may do on Backblaze B2: list the bucket it is restricted to, list and read its files. Never
// listAllBucketNames, write, delete, share, retention or key capabilities.
inline const std::vector<std::string>& kReadKeyCapabilities() {
    static const std::vector<std::string> caps{"listBuckets", "listFiles", "readFiles"};
    return caps;
}

inline constexpr const char* kReadKeysUnsupported =
    "read grants with an upstream key are supported for Backblaze B2 so far; not supported for this provider yet";

// How many requests/bytes admin + queue calls cost, for diagnostics and budgets.
struct Metrics {
    uint64_t requests{};
    uint64_t list{}, head{}, get{}, put{}, del{};
    uint64_t queue_requests{};
};

class AdminClient {
public:
    virtual ~AdminClient() = default;

    [[nodiscard]] virtual std::string providerId() const = 0;
    [[nodiscard]] virtual AccountIdentity identity() = 0;
    // Probes what this credential can do without changing anything (read calls + documented dry probes only).
    [[nodiscard]] virtual Capabilities probe() = 0;

    [[nodiscard]] virtual BucketPage listBuckets(const std::string& token = {}, unsigned int max = 1000) = 0;
    // nullopt = does not exist (404). Throws ProviderError on 403 (exists but not ours) and other failures.
    [[nodiscard]] virtual std::optional<std::string> headBucket(const std::string& bucket) = 0;
    // The bucket's region as the caller last recorded it (upstream_bucket.region). A routing hint only: providers
    // with regional endpoints (AWS) send their first HEAD there instead of the global endpoint; a stale hint costs a
    // redirect, never a wrong answer. Invalid values are ignored.
    virtual void setKnownRegion(const std::string& /*bucket*/, const std::string& /*region*/) {}
    // Throws ProviderError with code BucketAlreadyExists / BucketAlreadyOwnedByYou on collision. Never succeeds on a
    // bucket that already exists unless the provider hides it (AWS us-east-1); callers verify emptiness afterwards.
    virtual void createBucket(const CreateBucketRequest& request) = 0;
    // Bucket must be empty (all versions); throws otherwise.
    virtual void deleteBucket(const std::string& bucket) = 0;

    [[nodiscard]] virtual BucketConfiguration inspect(const std::string& bucket) = 0;
    // Whether lifecycle rules can be read and written at all (B2: false — its S3-compatible API has none). When false,
    // inspect() answers lifecycle_readable = false and putLifecycle throws CapabilityMissing("lifecycle", …) with
    // nothing sent (name and guard still checked first).
    [[nodiscard]] virtual bool supportsLifecycle() const { return true; }
    // Writes the full rule set: callers pass foreign rules back unchanged (merge happens in storage::upstream).
    virtual void putLifecycle(const std::string& bucket, const std::vector<LifecycleRule>& rules) = 0;

    // Provider (native) object versioning. AWS: true. R2: false — it has none (kR2VersioningUnsupported). B2: true,
    // always on: versioning() reads it, putVersioning(Enabled) only confirms it and Suspended is CapabilityMissing.
    [[nodiscard]] virtual bool supportsVersioning() const = 0;
    // GetBucketVersioning (guarded). Throws ProviderError when the provider refuses (e.g. AccessDenied: the credential
    // lacks s3:GetBucketVersioning). Providers without versioning answer Unversioned without sending a request; this
    // never claims Enabled for a bucket the provider can't version.
    [[nodiscard]] virtual VersioningState versioning(const std::string& bucket) = 0;
    // PutBucketVersioning (guarded): `target` is Enabled or Suspended (std::invalid_argument otherwise: a bucket can
    // never be put back to unversioned). Never sends MfaDelete. Enabling takes effect eventually: callers re-read
    // until versioning() says Enabled, and AWS asks for 15 minutes before relying on it for writes. Providers without
    // versioning throw CapabilityMissing("versioning", …) without sending anything.
    virtual void putVersioning(const std::string& bucket, Versioning target) = 0;

    [[nodiscard]] virtual ObjectPage listObjects(const std::string& bucket, const std::string& token = {},
                                                 unsigned int max = 1000) = 0;
    // All versions + delete markers (AWS); providers without versioning return listObjects.
    [[nodiscard]] virtual ObjectPage listObjectVersions(const std::string& bucket, const std::string& token = {},
                                                        unsigned int max = 1000) = 0;
    // Batch delete (≤1000). Returns the keys that failed with their error codes.
    [[nodiscard]] virtual std::vector<std::pair<std::string, std::string>> deleteObjects(
        const std::string& bucket, const std::vector<ObjectSummary>& objects) = 0;

    [[nodiscard]] virtual Metrics metrics() const = 0;

    // Read-only keys limited to one bucket (vault read grants). Providers without them answer false, and
    // createReadKey/deleteReadKey throw CapabilityMissing("read_keys", kReadKeysUnsupported) with nothing sent.
    [[nodiscard]] virtual bool supportsReadKeys() const { return false; }
    // Name and guard checked first. Throws CapabilityMissing("writeKeys", …) when the account key may not create keys,
    // ProviderError when the provider refuses.
    [[nodiscard]] virtual ReadKey createReadKey(const ReadKeyRequest& /*request*/) {
        throw CapabilityMissing("read_keys", kReadKeysUnsupported);
    }
    // Deletes a key createReadKey made. Throws ProviderError when the provider refuses or fails (the caller keeps the
    // grant "revocation incomplete" and retries).
    virtual void deleteReadKey(const std::string& /*keyId*/) { throw CapabilityMissing("read_keys", kReadKeysUnsupported); }
};

// ---- events -------------------------------------------------------------------------------------------------------

// A queue Vaulthalla owns for one account (+ region for AWS).
struct ChannelSpec {
    std::string account_ref;
    std::string region;                 // AWS region; R2 "" (account-global)
    std::string queue_name;             // "vaulthalla-events-<region|r2>"; tests: "vaulthalla-test-<run>-…"
    unsigned int retention_seconds{4 * 24 * 3600};
    unsigned int visibility_timeout_seconds{120};
    unsigned int max_receive_count{8};  // then the DLQ
};

struct ChannelRef {
    std::string queue_name;
    std::string queue_ref;              // SQS queue URL / Cloudflare queue id
    std::string queue_arn;              // AWS only
    std::string dlq_ref, dlq_arn;
    bool created{false};                // created by this call (vs reused)
};

struct SubscriptionSpec {
    std::string bucket;
    std::string rule_id;                // "vaulthalla-<subscription id>" (AWS Id; R2 description marker)
    std::string prefix;
};

struct ReceivedMessage {
    std::string receipt;                // SQS receipt handle / CF lease id
    std::string message_id;
    std::string body;                   // decoded body text
    unsigned int attempts{};
    std::optional<std::time_t> sent_at;
};

struct PollResult {
    std::vector<ReceivedMessage> messages;
    std::optional<uint64_t> backlog;    // CF message_backlog_count / SQS ApproximateNumberOfMessages when fetched
};

class EventsClient {
public:
    virtual ~EventsClient() = default;

    [[nodiscard]] virtual std::string providerId() const = 0;
    // Creates or reuses the queue (+ DLQ, consumer), idempotent. Throws CapabilityMissing when the credential can't.
    [[nodiscard]] virtual ChannelRef ensureChannel(const ChannelSpec& spec) = 0;
    // Grants the bucket publish rights on the channel (AWS queue policy; R2: nothing) and adds our rule, keeping every
    // foreign rule. Idempotent: an existing rule with our id is reused. Returns the provider rule ids we own.
    [[nodiscard]] virtual std::vector<std::string> subscribe(const ChannelRef& channel, const SubscriptionSpec& spec) = 0;
    // Removes only our rule ids (and the bucket's queue-policy grant). Never touches foreign rules.
    virtual void unsubscribe(const ChannelRef& channel, const SubscriptionSpec& spec,
                             const std::vector<std::string>& ruleIds) = 0;
    // Every rule on the bucket (ours flagged foreign=false) for coexistence checks and status.
    [[nodiscard]] virtual std::vector<NotificationRule> rules(const std::string& bucket) = 0;
    // Deletes the queue (+DLQ) — only called when no subscription references it and created_by_vaulthalla.
    virtual void removeChannel(const ChannelRef& channel) = 0;

    [[nodiscard]] virtual PollResult poll(const ChannelRef& channel, unsigned int max, std::chrono::seconds wait,
                                          std::chrono::seconds visibility) = 0;
    virtual void ack(const ChannelRef& channel, const std::vector<std::string>& receipts) = 0;
    // Makes messages visible again after `delay` (SQS ChangeMessageVisibility, CF retries).
    virtual void retry(const ChannelRef& channel, const std::vector<std::string>& receipts,
                       std::chrono::seconds delay) = 0;
    [[nodiscard]] virtual std::optional<uint64_t> backlog(const ChannelRef& channel) = 0;

    [[nodiscard]] virtual Metrics metrics() const = 0;
};

// Factory. nullptr when the key's provider has no admin adapter (eventsFor: no events adapter, which includes
// Backblaze B2). eventsFor throws CapabilityMissing for R2 without a
// provider token (the message says which Cloudflare token to add). The key must carry its decrypted secret (and, for
// R2 events, provider_token). Tests install fakes with setFactoryForTesting (honoured in test mode only). Clients are
// not thread-safe: one per worker.
struct Factory {
    std::function<std::unique_ptr<AdminClient>(const std::shared_ptr<vault::model::APIKey>&)> admin;
    std::function<std::unique_ptr<EventsClient>(const std::shared_ptr<vault::model::APIKey>&)> events;
};

// AWS S3, Cloudflare R2, and Backblaze B2 keys whose endpoint is https://s3.<region>.backblazeb2.com. Never a key
// managed storage issued (origin "cloud"): that bucket's account belongs to the service.
[[nodiscard]] bool supportsAdmin(const vault::model::APIKey& key);
// Event-driven sync (EventsClient): AWS S3 and Cloudflare R2 only.
[[nodiscard]] bool supportsEvents(const vault::model::APIKey& key);
// Why supportsAdmin(key) is false, for people ("" when it is true).
[[nodiscard]] std::string adminUnsupportedReason(const vault::model::APIKey& key);
[[nodiscard]] std::unique_ptr<AdminClient> adminFor(const std::shared_ptr<vault::model::APIKey>& key);
[[nodiscard]] std::unique_ptr<EventsClient> eventsFor(const std::shared_ptr<vault::model::APIKey>& key);
void setFactoryForTesting(std::optional<Factory> factory);

// The provider part of a bucket identity: the profile id for providers with an admin adapter ("aws-s3",
// "cloudflare-r2", "backblaze-b2"), "s3:<lower-case provider name>" for the others ("s3:minio").
[[nodiscard]] std::string providerIdentity(vault::model::S3Provider provider);
// The provider part of the identity of the buckets a key reaches, following its endpoint host: an R2, AWS or B2
// endpoint is "cloudflare-r2" / "aws-s3" / "backblaze-b2" whatever provider the key was saved with (so a lock can't be
// dodged by the label).
[[nodiscard]] std::string providerIdentity(const vault::model::APIKey& key);
// Why the key's declared provider contradicts its endpoint (an R2 endpoint saved as "Other"), or nullopt.
[[nodiscard]] std::optional<std::string> providerEndpointMismatch(const vault::model::APIKey& key);

// The account a key belongs to without a network call when the provider encodes it (R2 endpoint host), else the
// cached api_keys.provider_account_id, else nullopt. Backblaze B2: the region's S3 endpoint host
// ("s3.us-west-004.backblazeb2.com"). B2 bucket names are unique across every B2 account, so the host and the name
// identify a bucket; it is also what Vaulthalla recorded for B2 buckets before B2 had an adapter.
[[nodiscard]] std::optional<std::string> staticAccountRef(const vault::model::APIKey& key);

// The region of a Backblaze B2 S3 endpoint (https://s3.<region>.backblazeb2.com → "us-west-004"), nullopt for every
// other endpoint. It is the SigV4 signing region and the only region a bucket of that key can be created in.
[[nodiscard]] std::optional<std::string> b2EndpointRegion(const vault::model::APIKey& key);

// Vaulthalla-owned rule/queue naming.
inline constexpr const char* kOwnedPrefix = "vaulthalla-";
[[nodiscard]] bool isOwnedId(const std::string& id);
[[nodiscard]] std::string defaultQueueName(const std::string& providerId, const std::string& region);

}
