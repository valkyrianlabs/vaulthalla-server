#pragma once

#include "storage/s3/provider/admin/Admin.hpp"

#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// The Vaulthalla-owned lifecycle rule of a bucket (#237). Every other rule (other applications', the provider's
// defaults such as R2's "Default Multipart Abort Rule") is passed back to the provider unchanged.
namespace vh::storage::upstream::lifecycle {

inline constexpr const char* kOwnedRuleId = "vaulthalla-managed";
// File recovery: once a bucket keeps versions, the remote index manifest (.vaulthalla/index-v1.json, republished on
// every sync pass) piles up noncurrent versions. This second Vaulthalla rule expires them after a day. It is written
// whole from its fields (never patched) and only ever while provider versioning is managed by Vaulthalla.
inline constexpr const char* kManifestRuleId = "vaulthalla-manifest-versions";
inline constexpr const char* kManifestRulePrefix = ".vaulthalla/";
inline constexpr unsigned int kManifestNoncurrentDays = 1;

// One of the rules Vaulthalla writes (kOwnedRuleId, kManifestRuleId).
[[nodiscard]] bool isVaulthallaRule(const std::string& ruleId);

// Patch semantics: absent = unchanged, 0 = remove that field, clear = drop our rule.
struct OwnedRuleChange {
    std::optional<unsigned int> abort_incomplete_multipart_days{};
    std::optional<unsigned int> expire_current_days{};
    std::optional<unsigned int> expire_noncurrent_days{};
    std::optional<std::string> prefix{};
    bool clear = false;
};

struct MergeResult {
    std::vector<s3::provider::admin::LifecycleRule> rules;    // the full document to write
    std::optional<s3::provider::admin::LifecycleRule> owned;  // our rule after the change (nullopt: none)
    bool changed = false;
    // The change adds or tightens an expiration (live objects or old versions get deleted): needs a person's ok.
    bool destructive = false;
};

// Our rule was changed outside Vaulthalla into something this model can't represent (a tag filter, transitions, …):
// rewriting it would silently change what it does, so it is refused (removing it — `clear` — is still allowed).
struct UnmodeledOwnedRule : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Throws std::invalid_argument for fields the provider lacks (noncurrent versions without allowNoncurrent) or a
// change that leaves a rule with no action, and UnmodeledOwnedRule (above).
[[nodiscard]] MergeResult mergeOwnedRule(const std::vector<s3::provider::admin::LifecycleRule>& current,
                                         const OwnedRuleChange& change, bool allowNoncurrent);

// Adds (or refreshes) the manifest-versions rule, or removes it (present = false). Every other rule, ours included, is
// passed through unchanged. changed = false when the document already says exactly that. Throws std::invalid_argument
// without allowNoncurrent (the provider has no versions).
[[nodiscard]] MergeResult mergeManifestRule(const std::vector<s3::provider::admin::LifecycleRule>& current, bool present,
                                            bool allowNoncurrent);

// ---- noncurrent-version retention already on a bucket (ours and foreign) ---------------------------------------------

// One rule's NoncurrentVersionExpiration, read from the rule's raw XML when it has one (foreign and unmodeled rules
// carry elements the LifecycleRule fields don't), else from its fields (our rule as rebuilt by mergeOwnedRule).
struct NoncurrentExpiration {
    std::string rule_id;
    bool foreign{true};
    bool enabled{true};
    std::string prefix;                                     // the rule's key prefix ("" = whole bucket)
    // The rule also filters on tags or object size: it applies to some objects under `prefix`, not all of them.
    bool conditional{false};
    std::optional<unsigned int> days;                       // NoncurrentDays
    std::optional<unsigned int> newer_noncurrent_versions;  // NewerNoncurrentVersions: that many newest stay
};

// Every rule with a NoncurrentVersionExpiration, in document order (disabled ones included, flagged).
[[nodiscard]] std::vector<NoncurrentExpiration> noncurrentExpirations(
    const std::vector<s3::provider::admin::LifecycleRule>& rules);

enum class Coverage { None, Partial, Whole };
// How much of a vault's key prefix an expiration reaches. Whole: enabled, unconditional and its prefix is a prefix of
// `vaultPrefix` (every object of the vault). Partial: enabled and overlapping (a narrower prefix, or a tag/size
// filter). None: disabled, without NoncurrentDays, or a disjoint prefix.
[[nodiscard]] Coverage coverage(const NoncurrentExpiration& expiration, const std::string& vaultPrefix);

// The shortest NoncurrentDays among the expirations that cover the whole vault prefix (nullopt: none does, versions
// are kept until something else deletes them). A rule with NewerNoncurrentVersions still counts: past the newest N,
// noncurrent versions go after its days. Partial rules are not counted; list them with noncurrentExpirations().
[[nodiscard]] std::optional<unsigned int> effectiveNoncurrentDays(
    const std::vector<s3::provider::admin::LifecycleRule>& rules, const std::string& vaultPrefix);

}
