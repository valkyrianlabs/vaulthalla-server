#include "storage/upstream/Lifecycle.hpp"

#include <stdexcept>

namespace vh::storage::upstream::lifecycle {

namespace {

using s3::provider::admin::LifecycleRule;

// A field value after the patch: absent keeps it, 0 removes it.
std::optional<unsigned int> patched(const std::optional<unsigned int>& current, const std::optional<unsigned int>& change) {
    if (!change) return current;
    if (*change == 0) return std::nullopt;
    return change;
}

// Tighter = deletes sooner, or where nothing was deleted before.
bool tightened(const std::optional<unsigned int>& before, const std::optional<unsigned int>& after) {
    if (!after) return false;
    return !before || *after < *before;
}

}

MergeResult mergeOwnedRule(const std::vector<LifecycleRule>& current, const OwnedRuleChange& change,
                           const bool allowNoncurrent) {
    if (change.expire_noncurrent_days && *change.expire_noncurrent_days > 0 && !allowNoncurrent)
        throw std::invalid_argument("this provider has no object versions: noncurrent-version expiration is not supported");

    MergeResult out;
    std::optional<LifecycleRule> before;
    for (const auto& rule : current) {
        if (rule.id == kOwnedRuleId && !rule.foreign) before = rule;
        else out.rules.push_back(rule);
    }

    if (change.clear) {
        out.changed = before.has_value();
        return out;
    }

    LifecycleRule rule = before.value_or(LifecycleRule{});
    rule.id = kOwnedRuleId;
    rule.foreign = false;
    rule.enabled = true;
    rule.raw_xml.clear();
    rule.abort_incomplete_multipart_days = patched(rule.abort_incomplete_multipart_days, change.abort_incomplete_multipart_days);
    rule.expire_current_days = patched(rule.expire_current_days, change.expire_current_days);
    rule.expire_noncurrent_days = patched(rule.expire_noncurrent_days, change.expire_noncurrent_days);
    if (change.prefix) rule.prefix = *change.prefix;

    const bool hasAction = rule.abort_incomplete_multipart_days || rule.expire_current_days || rule.expire_noncurrent_days;
    if (!hasAction) {
        // Every field removed: the same as clearing our rule.
        out.changed = before.has_value();
        return out;
    }

    const std::optional<unsigned int> noneDays;
    out.destructive = tightened(before ? before->expire_current_days : noneDays, rule.expire_current_days) ||
                      tightened(before ? before->expire_noncurrent_days : noneDays, rule.expire_noncurrent_days) ||
                      (before && rule.destructive() && before->prefix != rule.prefix);
    out.changed = !before || before->abort_incomplete_multipart_days != rule.abort_incomplete_multipart_days ||
                  before->expire_current_days != rule.expire_current_days ||
                  before->expire_noncurrent_days != rule.expire_noncurrent_days || before->prefix != rule.prefix ||
                  !before->enabled;
    out.owned = rule;
    out.rules.push_back(rule);
    return out;
}

}
