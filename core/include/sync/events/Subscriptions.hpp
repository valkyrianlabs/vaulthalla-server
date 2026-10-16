#pragma once

#include "storage/upstream/Guard.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Event subscriptions of S3 vaults (#96): the vault's bucket notifies a Vaulthalla-owned queue (AWS SQS Standard per
// account+region, Cloudflare Queue per account), which sync::events::Service polls.
//
// Trusted primitives (ops::upstream authorizes). They throw the adapters' exceptions
// (storage::s3::provider::admin::CapabilityMissing / ProviderError), storage::upstream::BucketProtected, or
// std::invalid_argument / std::runtime_error with an operator-readable message; ops maps them to ops::Error.
//
// State machine (upstream_event_subscription.state): pending → active | failed; active → removing → removed;
// failed → (repair) pending. Every transition is persisted before the provider call it guards, so a crash leaves a
// state repair() can finish. Teardown removes only our rule ids and our queue-policy grant; the channel is removed
// when no subscription references it and Vaulthalla created it.
namespace vh::sync::events::subscriptions {

struct ChannelInfo {
    int64_t id = 0;
    std::string provider, account_ref, region, queue_name, state;
    std::optional<std::time_t> last_poll_at, last_success_at, last_message_at, last_error_at;
    std::optional<std::string> last_error;
    std::optional<uint64_t> backlog;
    unsigned int consecutive_failures = 0;
};

struct Status {
    int64_t subscription_id = 0;
    uint32_t vault_id = 0;
    std::string bucket;
    std::string state = "none";          // none (never subscribed) | pending | active | failed | removing | removed
    std::string baseline_state = "none";
    std::string foreign_objects = "import";
    std::string prefix;
    std::optional<std::string> last_error;
    std::vector<std::string> rule_ids;
    unsigned int foreign_rules = 0;
    std::optional<ChannelInfo> channel;
    uint64_t inbox_pending = 0, inbox_applied = 0, inbox_failed = 0, inbox_done_24h = 0, inbox_self_24h = 0;
    std::optional<std::time_t> last_event_at;
};

struct EnableRequest {
    uint32_t vault_id = 0;
    std::string prefix{};
    std::string foreign_objects = "import";   // import | ignore
    // Adoption: events that arrive before the vault's first full listing are held and replayed after it.
    bool baseline_required = false;
};

// Idempotent: an active subscription with the same settings is returned unchanged.
Status enable(const EnableRequest& request);
Status disable(uint32_t vaultId);
Status repair(uint32_t vaultId);
[[nodiscard]] Status status(uint32_t vaultId);

// Vault lifecycle hooks (never throw; failures are recorded on the subscription for repair).
void onVaultRetired(uint32_t vaultId) noexcept;     // deletion scheduled: stop consuming, tear rules down
void onVaultReinstated(uint32_t vaultId) noexcept;  // restored: re-arm

// Bucket lock changes (#237; never throw). A lock stops event processing for the bucket at once (its rules stay in
// place: changing a protected bucket is what the lock forbids); removing it re-arms the subscriptions the lock
// stopped and makes their held events due again.
void onBucketProtected(const storage::upstream::BucketIdentity& bucket) noexcept;
void onBucketUnprotected(const storage::upstream::BucketIdentity& bucket) noexcept;

// Cheap, cached (refreshed by the service): does the vault have an active subscription? CloudEngine records write
// intents for its own PUT/DELETEs only then.
[[nodiscard]] bool activeFor(uint32_t vaultId);
// The vault has an active subscription that imports objects without Vaulthalla metadata (foreign_objects=import).
// An encrypt_upstream vault only accepts a metadata-free object as plaintext content then; otherwise such an object
// over a known encrypted file is treated as tampering (it fails authentication), as before #96. Uncached (rare path).
[[nodiscard]] bool importsForeignObjects(uint32_t vaultId);
// Forces the next activeFor() to reload (after enable/disable done elsewhere, and in tests).
void invalidateCache() noexcept;

// The event service's sweep: finishes teardowns left in `removing` (provider outage, deleted vault).
void retryTeardowns() noexcept;

}
