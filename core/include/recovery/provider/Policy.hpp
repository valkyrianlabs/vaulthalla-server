#pragma once

#include "db/query/upstream/Bucket.hpp"
#include "recovery/Model.hpp"
#include "recovery/provider/Capabilities.hpp"
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/Lifecycle.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Provider versioning policy primitives (trusted: they never authorize; ops::recovery does). AWS S3 and Backblaze B2;
// what each provider can do is recovery::provider::capabilitiesOf (Capabilities.hpp; R2: nothing).
namespace vh::recovery::provider::policy {

namespace padmin = storage::s3::provider::admin;

// AWS: versioning may take up to 15 minutes to apply to every write after it is enabled.
inline constexpr std::chrono::minutes kPropagation{15};
inline constexpr std::chrono::minutes kDisclosureLifetime{10};

[[nodiscard]] std::string to_string(padmin::Versioning v);   // unversioned | enabled | suspended | unknown

// The vault's bucket as Vaulthalla knows it, without a provider request.
struct VaultBucket {
    uint32_t vault_id{};
    std::string bucket;
    uint32_t api_key_id{};
    std::shared_ptr<vault::model::APIKey> key;                         // metadata (no secrets)
    storage::upstream::BucketIdentity identity;
    std::optional<db::query::upstream::BucketModel> row;               // upstream_bucket, when known
    std::optional<db::query::upstream::BucketVersioning> versioning;  // its versioning columns
    [[nodiscard]] bool isProtected() const;
    // managed | adopted | unmanaged | protected
    [[nodiscard]] std::string state() const;
};

// nullopt for a vault that isn't an S3 vault (or doesn't exist).
[[nodiscard]] std::optional<VaultBucket> bucketForVault(uint32_t vaultId);

// ---- versioning ----------------------------------------------------------------------------------------------------

struct ReadBack {
    padmin::VersioningState state;
    unsigned int reads{};
    bool confirmed{false};      // a read said `target`
};

// PutBucketVersioning(target), then re-reads until the provider says `target` (bounded: setReadBackForTesting).
// Throws whatever the adapter throws for the PUT (a read that fails is retried, then reported unconfirmed).
[[nodiscard]] ReadBack putAndConfirm(padmin::AdminClient& admin, const std::string& bucket, padmin::Versioning target);
// Default: 6 reads, 250 ms apart (doubling).
void setReadBackForTesting(unsigned int reads, std::chrono::milliseconds delay);

// ---- retention -----------------------------------------------------------------------------------------------------

struct RetentionResult {
    bool written{false};
    // After the write: the shortest NoncurrentDays over the whole vault (ours or another application's).
    std::optional<unsigned int> effective_days;
    // Other applications' rules that expire noncurrent versions ("id: N days", "(partial)" when they cover some keys).
    std::vector<std::string> foreign_rules;
    std::optional<unsigned int> foreign_whole_days;    // the shortest foreign rule over the whole vault
    // Vaulthalla's own rules that expire old versions ("vaulthalla-managed: 'o/', 30 days").
    std::vector<std::string> vaulthalla_rules;
    std::vector<std::string> warnings;
};

// How the bucket is read for a vault: where its data lives (coverage) and whether .vaulthalla/ must keep its old
// versions (an opaque_v1 vault on a bucket without conditional writes: Backblaze B2).
struct VaultView {
    std::string data_prefix{};            // "" = the whole bucket; opaque_v1 on B2: "o/"
    bool protect_metadata{false};         // warn about any rule that deletes old versions under .vaulthalla/
    bool warn_current_expiry{false};      // warn about foreign rules that expire (hide) current objects (B2)
};

// Vaulthalla's noncurrent retention: the owned rule's NoncurrentDays (indefinite: none of ours) plus the
// manifest-versions rule; every other rule is preserved and re-verified after the write (GET-merge-PUT-GET).
// `scope` (ruleScopeFor) places the owned rule (AWS: where it is; B2 opaque_v1: "o/") and says whether the
// manifest-versions rule is written (B2 opaque_v1: never, and an earlier one is removed).
// Throws std::invalid_argument (lifecycle unreadable, a provider without versions), UnmodeledOwnedRule, ProviderError
// (B2: 409 when the bucket changed between the read and the write), std::runtime_error (foreign rules changed under
// the write).
[[nodiscard]] RetentionResult applyRetention(padmin::AdminClient& admin, const std::string& bucket,
                                             const ProviderRetention& retention, bool allowNoncurrent,
                                             const RuleScope& scope = {}, const VaultView& view = {});
// History off on a provider that always keeps versions (Backblaze B2): the owned rule deletes every old version one
// day after it stops being current (B2's "keep only the last version": daysFromHidingToDeleting 1), scoped and
// verified like applyRetention. Hidden (deleted) files go too: B2 removes a hide marker once it is the oldest version.
[[nodiscard]] RetentionResult applyLatestOnly(padmin::AdminClient& admin, const std::string& bucket,
                                              const RuleScope& scope, const VaultView& view = {});
inline constexpr unsigned int kLatestOnlyDays = 1;   // B2's minimum

// What a bucket's lifecycle already does to noncurrent versions (no write).
[[nodiscard]] RetentionResult describeRetention(const std::vector<padmin::LifecycleRule>& rules, const VaultView& view = {});

// ---- disclosure token ----------------------------------------------------------------------------------------------

struct TokenBinding {
    uint32_t vault_id{};
    storage::upstream::BucketIdentity bucket;
    std::string retention;          // ProviderRetention::str() or "unset"
    uint32_t actor_id{};
    std::string estimate_digest;    // cost::pricingDigest of the disclosed report
};

// HMAC-SHA256 under a per-process random key over the binding and the expiry: "v1.<expires>.<hex mac>". Stateless; a
// restart invalidates outstanding tokens (the person asks for a new disclosure).
[[nodiscard]] std::string issueToken(const TokenBinding& binding, std::time_t expiresAt);
// True when the token was issued for exactly this binding and hasn't expired.
[[nodiscard]] bool verifyToken(const std::string& token, const TokenBinding& binding, std::time_t now);

}
