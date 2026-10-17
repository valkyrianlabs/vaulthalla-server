#include "storage/upstream/Lifecycle.hpp"

#include <pugixml.hpp>

#include <algorithm>
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

std::optional<unsigned int> uintValue(const pugi::xml_node& node) {
    if (!node) return std::nullopt;
    const std::string text = node.text().get();
    if (text.empty() || text.size() > 9 || !std::ranges::all_of(text, [](const char c) { return c >= '0' && c <= '9'; }))
        return std::nullopt;
    return static_cast<unsigned int>(std::stoul(text));
}

// The rule's prefix (Filter/Prefix, Filter/And/Prefix or the legacy Prefix) and whether it also filters on tags or
// object size.
void readFilter(const pugi::xml_node& rule, std::string& prefix, bool& conditional) {
    prefix.clear();
    conditional = false;
    const auto filter = rule.child("Filter");
    if (!filter) {
        prefix = rule.child_value("Prefix");
        return;
    }
    for (const auto child : filter.children()) {
        if (child.type() != pugi::node_element) continue;
        const std::string name = child.name();
        if (name == "Prefix") {
            prefix = child.text().get();
        } else if (name == "And") {
            for (const auto part : child.children()) {
                if (part.type() != pugi::node_element) continue;
                if (std::string(part.name()) == "Prefix") prefix = part.text().get();
                else conditional = true;
            }
        } else {
            conditional = true;   // Tag, ObjectSizeGreaterThan, ObjectSizeLessThan
        }
    }
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
    if (before && before->unmodeled)
        throw UnmodeledOwnedRule(std::string("the bucket's '") + kOwnedRuleId + "' lifecycle rule was changed outside "
                                 "Vaulthalla (it has filters or actions Vaulthalla doesn't manage); rewriting it would "
                                 "change what it does. Remove it (clear) or edit it with the provider.");

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
                      (before && rule.destructive() && before->prefix != rule.prefix) ||
                      // Turning a disabled expiration back on deletes data just as a new rule would.
                      (before && !before->enabled && rule.destructive());
    out.changed = !before || before->abort_incomplete_multipart_days != rule.abort_incomplete_multipart_days ||
                  before->expire_current_days != rule.expire_current_days ||
                  before->expire_noncurrent_days != rule.expire_noncurrent_days || before->prefix != rule.prefix ||
                  !before->enabled;
    out.owned = rule;
    out.rules.push_back(rule);
    return out;
}

bool isVaulthallaRule(const std::string& ruleId) { return ruleId == kOwnedRuleId || ruleId == kManifestRuleId; }

MergeResult mergeManifestRule(const std::vector<LifecycleRule>& current, const bool present, const bool allowNoncurrent) {
    if (present && !allowNoncurrent)
        throw std::invalid_argument("this provider has no object versions: noncurrent-version expiration is not supported");

    LifecycleRule wanted;
    wanted.id = kManifestRuleId;
    wanted.enabled = true;
    wanted.prefix = kManifestRulePrefix;
    wanted.expire_noncurrent_days = kManifestNoncurrentDays;
    wanted.foreign = false;

    // As read back, the rule carries its provider XML; compare what it does, not how it was spelled.
    const auto sameAsWanted = [&](const LifecycleRule& r) {
        for (const auto& e : noncurrentExpirations({r}))
            return e.enabled && !e.conditional && e.prefix == wanted.prefix && e.days == wanted.expire_noncurrent_days &&
                   !e.newer_noncurrent_versions && !r.abort_incomplete_multipart_days && !r.expire_current_days &&
                   !r.unmodeled;
        return false;
    };

    MergeResult out;
    bool had = false, same = false;
    for (const auto& rule : current) {
        if (rule.id == kManifestRuleId) {
            had = true;
            same = sameAsWanted(rule);
            continue;
        }
        out.rules.push_back(rule);
    }
    if (!present) {
        out.changed = had;
        return out;
    }
    out.rules.push_back(wanted);
    out.owned = wanted;
    out.changed = !had || !same;
    // It only ever deletes old copies of Vaulthalla's own index: never a person's data.
    out.destructive = false;
    return out;
}

std::vector<NoncurrentExpiration> noncurrentExpirations(const std::vector<LifecycleRule>& rules) {
    std::vector<NoncurrentExpiration> out;
    for (const auto& rule : rules) {
        NoncurrentExpiration e;
        e.rule_id = rule.id;
        e.foreign = rule.foreign;
        e.enabled = rule.enabled;
        pugi::xml_document doc;
        if (!rule.raw_xml.empty() && doc.load_string(rule.raw_xml.c_str()) && doc.child("Rule")) {
            // The provider's document: it may carry NewerNoncurrentVersions or filters the fields don't model.
            const auto node = doc.child("Rule");
            const auto expiration = node.child("NoncurrentVersionExpiration");
            if (!expiration) continue;
            e.enabled = std::string(node.child_value("Status")) == "Enabled";
            readFilter(node, e.prefix, e.conditional);
            e.days = uintValue(expiration.child("NoncurrentDays"));
            e.newer_noncurrent_versions = uintValue(expiration.child("NewerNoncurrentVersions"));
        } else {
            if (!rule.expire_noncurrent_days) continue;
            e.prefix = rule.prefix;
            // Stored XML that doesn't parse can't be trusted to cover every object.
            e.conditional = !rule.raw_xml.empty() || rule.unmodeled;
            e.days = rule.expire_noncurrent_days;
        }
        out.push_back(std::move(e));
    }
    return out;
}

Coverage coverage(const NoncurrentExpiration& expiration, const std::string& vaultPrefix) {
    if (!expiration.enabled || !expiration.days) return Coverage::None;
    if (vaultPrefix.starts_with(expiration.prefix)) return expiration.conditional ? Coverage::Partial : Coverage::Whole;
    if (expiration.prefix.starts_with(vaultPrefix)) return Coverage::Partial;   // some of the vault's keys
    return Coverage::None;
}

std::optional<unsigned int> effectiveNoncurrentDays(const std::vector<LifecycleRule>& rules, const std::string& vaultPrefix) {
    std::optional<unsigned int> shortest;
    for (const auto& e : noncurrentExpirations(rules))
        if (coverage(e, vaultPrefix) == Coverage::Whole && (!shortest || *e.days < *shortest)) shortest = e.days;
    return shortest;
}

}
