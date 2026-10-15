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

}
