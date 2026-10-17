#include "storage/s3/provider/admin/Internal.hpp"
#include "storage/upstream/Names.hpp"

#include <nlohmann/json.hpp>
#include <pugixml.hpp>

#include <algorithm>
#include <cctype>
#include <sstream>
#include <stdexcept>

namespace vh::storage::s3::provider::admin::detail {

namespace {

constexpr const char* kS3Namespace = "http://s3.amazonaws.com/doc/2006-03-01/";

std::string unquote(std::string etag) {
    if (etag.size() >= 2 && etag.front() == '"' && etag.back() == '"') etag = etag.substr(1, etag.size() - 2);
    if (etag.starts_with("&quot;")) etag = etag.substr(6);
    if (etag.ends_with("&quot;")) etag.resize(etag.size() - 6);
    return etag;
}

std::string printNode(const pugi::xml_node& node) {
    std::ostringstream out;
    node.print(out, "", pugi::format_raw);
    return out.str();
}

pugi::xml_document loadOrThrow(const std::string& xml, const char* what) {
    pugi::xml_document doc;
    if (!xml.empty() && !doc.load_string(xml.c_str())) throw std::runtime_error(std::string(what) + ": response is not XML");
    return doc;
}

std::optional<unsigned int> uintChild(const pugi::xml_node& node, const char* name) {
    const auto child = node.child(name);
    if (!child) return std::nullopt;
    try {
        return static_cast<unsigned int>(std::stoul(child.text().get()));
    } catch (const std::exception&) {
        return std::nullopt;
    }
}

void appendRaw(pugi::xml_node parent, const std::string& raw) {
    pugi::xml_document tmp;
    if (!tmp.load_string(raw.c_str())) throw std::invalid_argument("stored rule XML does not parse");
    for (const auto child : tmp.children()) parent.append_copy(child);
}

std::string ruleFilterPrefix(const pugi::xml_node& rule) {
    if (const auto filter = rule.child("Filter")) {
        if (const auto prefix = filter.child("Prefix")) return prefix.text().get();
        if (const auto andNode = filter.child("And"))
            if (const auto prefix = andNode.child("Prefix")) return prefix.text().get();
        return {};
    }
    return rule.child_value("Prefix");
}

// Whether a lifecycle rule uses anything beyond ID, Status, a plain prefix (legacy Prefix or Filter/Prefix),
// Expiration/Days, NoncurrentVersionExpiration/NoncurrentDays and AbortIncompleteMultipartUpload/DaysAfterInitiation.
bool lifecycleRuleUnmodeled(const pugi::xml_node& rule) {
    const auto onlyChildren = [](const pugi::xml_node& node, std::initializer_list<const char*> allowed) {
        for (const auto child : node.children()) {
            if (child.type() != pugi::node_element) continue;
            bool known = false;
            for (const auto* name : allowed) known = known || std::string(child.name()) == name;
            if (!known) return false;
        }
        return true;
    };
    for (const auto child : rule.children()) {
        if (child.type() != pugi::node_element) continue;
        const std::string name = child.name();
        if (name == "ID" || name == "Status" || name == "Prefix") continue;
        if (name == "Filter" && onlyChildren(child, {"Prefix"})) continue;
        if (name == "Expiration" && onlyChildren(child, {"Days"})) continue;
        if (name == "NoncurrentVersionExpiration" && onlyChildren(child, {"NoncurrentDays"})) continue;
        if (name == "AbortIncompleteMultipartUpload" && onlyChildren(child, {"DaysAfterInitiation"})) continue;
        return true;
    }
    return false;
}

std::string toString(const pugi::xml_document& doc) {
    std::ostringstream out;
    doc.save(out, "", pugi::format_raw);
    return out.str();
}

bool eventsOverlap(const std::string& a, const std::string& b) {
    if (a == b) return true;
    const auto stem = [](const std::string& e) { return e.ends_with("*") ? e.substr(0, e.size() - 1) : e; };
    if (a.ends_with("*") && b.starts_with(stem(a))) return true;
    if (b.ends_with("*") && a.starts_with(stem(b))) return true;
    return false;
}

}

BucketPage parseListBuckets(const std::string& xml) {
    const auto doc = loadOrThrow(xml, "ListBuckets");
    const auto root = doc.child("ListAllMyBucketsResult");
    BucketPage page;
    for (const auto bucket : root.child("Buckets").children("Bucket")) {
        BucketSummary s;
        s.name = bucket.child_value("Name");
        if (const auto region = std::string(bucket.child_value("BucketRegion")); !region.empty()) s.region = region;
        s.created_at = parseIsoTime(bucket.child_value("CreationDate"));
        if (!s.name.empty()) page.buckets.push_back(std::move(s));
    }
    page.next_token = root.child_value("ContinuationToken");
    return page;
}

ObjectPage parseListObjectsV2(const std::string& xml) {
    const auto doc = loadOrThrow(xml, "ListObjectsV2");
    const auto root = doc.child("ListBucketResult");
    ObjectPage page;
    for (const auto contents : root.children("Contents")) {
        ObjectSummary o;
        o.key = contents.child_value("Key");
        o.size = std::strtoull(contents.child_value("Size"), nullptr, 10);
        o.etag = unquote(contents.child_value("ETag"));
        o.last_modified = parseIsoTime(contents.child_value("LastModified"));
        page.objects.push_back(std::move(o));
    }
    if (std::string(root.child_value("IsTruncated")) == "true") page.next_token = root.child_value("NextContinuationToken");
    return page;
}

ObjectPage parseListObjectVersions(const std::string& xml) {
    const auto doc = loadOrThrow(xml, "ListObjectVersions");
    const auto root = doc.child("ListVersionsResult");
    ObjectPage page;
    for (const auto node : root.children()) {
        const std::string name = node.name();
        if (name != "Version" && name != "DeleteMarker") continue;
        ObjectSummary o;
        o.key = node.child_value("Key");
        o.version_id = std::string(node.child_value("VersionId"));
        o.latest = std::string(node.child_value("IsLatest")) == "true";
        o.last_modified = parseIsoTime(node.child_value("LastModified"));
        o.delete_marker = name == "DeleteMarker";
        if (!o.delete_marker) {
            o.size = std::strtoull(node.child_value("Size"), nullptr, 10);
            o.etag = unquote(node.child_value("ETag"));
        }
        page.objects.push_back(std::move(o));
    }
    if (std::string(root.child_value("IsTruncated")) == "true")
        page.next_token = std::string(root.child_value("NextKeyMarker")) + "\n" + root.child_value("NextVersionIdMarker");
    return page;
}

Versioning parseVersioning(const std::string& xml) { return parseVersioningState(xml).status; }

VersioningState parseVersioningState(const std::string& xml) {
    const auto doc = loadOrThrow(xml, "GetBucketVersioning");
    const auto root = doc.child("VersioningConfiguration");
    VersioningState state;
    const std::string status = root.child_value("Status");
    if (status == "Enabled") state.status = Versioning::Enabled;
    else if (status == "Suspended") state.status = Versioning::Suspended;
    else state.status = Versioning::Unversioned;
    // The API reference spells the response element MfaDelete (request syntax) and MFADelete (field list).
    auto mfa = root.child("MfaDelete");
    if (!mfa) mfa = root.child("MFADelete");
    if (mfa) {
        const std::string value = mfa.text().get();
        if (value == "Enabled") state.mfa_delete = true;
        else if (value == "Disabled") state.mfa_delete = false;
    }
    return state;
}

std::string buildVersioning(const Versioning target) {
    if (target != Versioning::Enabled && target != Versioning::Suspended)
        throw std::invalid_argument("bucket versioning can only be set to enabled or suspended");
    pugi::xml_document doc;
    auto root = doc.append_child("VersioningConfiguration");
    root.append_attribute("xmlns") = kS3Namespace;
    root.append_child("Status").text().set(target == Versioning::Enabled ? "Enabled" : "Suspended");
    return toString(doc);
}

std::optional<std::string> parseLocation(const std::string& xml) {
    const auto doc = loadOrThrow(xml, "GetBucketLocation");
    const auto node = doc.child("LocationConstraint");
    if (!node) return std::nullopt;
    std::string region = node.text().get();
    if (region.empty()) return std::string("us-east-1");
    if (region == "EU") return std::string("eu-west-1");
    return region;
}

std::vector<LifecycleRule> parseLifecycle(const std::string& xml) {
    std::vector<LifecycleRule> rules;
    if (xml.empty()) return rules;
    const auto doc = loadOrThrow(xml, "GetBucketLifecycleConfiguration");
    for (const auto node : doc.child("LifecycleConfiguration").children("Rule")) {
        LifecycleRule rule;
        rule.id = node.child_value("ID");
        rule.enabled = std::string(node.child_value("Status")) == "Enabled";
        rule.prefix = ruleFilterPrefix(node);
        rule.abort_incomplete_multipart_days = uintChild(node.child("AbortIncompleteMultipartUpload"), "DaysAfterInitiation");
        rule.expire_current_days = uintChild(node.child("Expiration"), "Days");
        rule.expire_noncurrent_days = uintChild(node.child("NoncurrentVersionExpiration"), "NoncurrentDays");
        // Only Vaulthalla's one managed rule is ever rebuilt from fields; every other rule — another application's,
        // the provider's default, or any other "vaulthalla-*" id — goes back to the provider byte for byte.
        rule.foreign = rule.id != "vaulthalla-managed";
        rule.unmodeled = lifecycleRuleUnmodeled(node);
        rule.raw_xml = printNode(node);
        rules.push_back(std::move(rule));
    }
    return rules;
}

std::string buildLifecycle(const std::vector<LifecycleRule>& rules, const bool allowNoncurrent) {
    pugi::xml_document doc;
    auto root = doc.append_child("LifecycleConfiguration");
    root.append_attribute("xmlns") = kS3Namespace;
    for (const auto& rule : rules) {
        if (rule.foreign) {
            appendRaw(root, rule.raw_xml);
            continue;
        }
        if (!rule.abort_incomplete_multipart_days && !rule.expire_current_days && !rule.expire_noncurrent_days)
            throw std::invalid_argument("lifecycle rule '" + rule.id + "' has no action");
        if (rule.expire_noncurrent_days && !allowNoncurrent)
            throw std::invalid_argument("this provider has no object versions: noncurrent-version expiration is not supported");
        auto node = root.append_child("Rule");
        node.append_child("ID").text().set(rule.id.c_str());
        node.append_child("Filter").append_child("Prefix").text().set(rule.prefix.c_str());
        node.append_child("Status").text().set(rule.enabled ? "Enabled" : "Disabled");
        if (rule.expire_current_days)
            node.append_child("Expiration").append_child("Days").text().set(*rule.expire_current_days);
        if (rule.expire_noncurrent_days)
            node.append_child("NoncurrentVersionExpiration").append_child("NoncurrentDays").text().set(*rule.expire_noncurrent_days);
        if (rule.abort_incomplete_multipart_days)
            node.append_child("AbortIncompleteMultipartUpload").append_child("DaysAfterInitiation")
                .text().set(*rule.abort_incomplete_multipart_days);
    }
    return toString(doc);
}

std::string buildDeleteObjects(const std::vector<ObjectSummary>& objects) {
    pugi::xml_document doc;
    auto root = doc.append_child("Delete");
    root.append_attribute("xmlns") = kS3Namespace;
    root.append_child("Quiet").text().set("true");
    for (const auto& o : objects) {
        auto node = root.append_child("Object");
        node.append_child("Key").text().set(o.key.c_str());
        if (o.version_id && !o.version_id->empty() && *o.version_id != "null")
            node.append_child("VersionId").text().set(o.version_id->c_str());
    }
    return toString(doc);
}

std::vector<std::pair<std::string, std::string>> parseDeleteObjectsErrors(const std::string& xml) {
    std::vector<std::pair<std::string, std::string>> errors;
    if (xml.empty()) return errors;
    const auto doc = loadOrThrow(xml, "DeleteObjects");
    for (const auto error : doc.child("DeleteResult").children("Error")) {
        std::string key = error.child_value("Key");
        if (const std::string version = error.child_value("VersionId"); !version.empty()) key += "?versionId=" + version;
        errors.emplace_back(key, std::string(error.child_value("Code")));
    }
    return errors;
}

std::vector<NotificationElement> parseNotification(const std::string& xml) {
    std::vector<NotificationElement> out;
    if (xml.empty()) return out;
    const auto doc = loadOrThrow(xml, "GetBucketNotificationConfiguration");
    for (const auto node : doc.child("NotificationConfiguration").children()) {
        if (node.type() != pugi::node_element) continue;
        NotificationElement e;
        e.kind = node.name();
        e.rule.id = node.child_value("Id");
        for (const auto* field : {"Queue", "Topic", "CloudFunction"})
            if (const auto value = std::string(node.child_value(field)); !value.empty()) e.rule.destination = value;
        for (const auto event : node.children("Event")) e.rule.events.emplace_back(event.text().get());
        for (const auto filterRule : node.child("Filter").child("S3Key").children("FilterRule")) {
            std::string name = filterRule.child_value("Name");
            std::ranges::transform(name, name.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (name == "prefix") e.rule.prefix = filterRule.child_value("Value");
            if (name == "suffix") e.rule.suffix = filterRule.child_value("Value");
        }
        e.rule.foreign = e.kind == "EventBridgeConfiguration" || !isOwnedId(e.rule.id);
        e.rule.raw = printNode(node);
        out.push_back(std::move(e));
    }
    return out;
}

std::string buildNotification(const std::vector<NotificationElement>& existing, const std::vector<std::string>& dropIds,
                              const std::vector<NotificationRule>& add) {
    pugi::xml_document doc;
    auto root = doc.append_child("NotificationConfiguration");
    root.append_attribute("xmlns") = kS3Namespace;
    for (const auto& e : existing) {
        const bool drop = !e.rule.id.empty() && std::ranges::find(dropIds, e.rule.id) != dropIds.end();
        if (!drop) appendRaw(root, e.rule.raw);
    }
    for (const auto& rule : add) {
        auto node = root.append_child("QueueConfiguration");
        node.append_child("Id").text().set(rule.id.c_str());
        node.append_child("Queue").text().set(rule.destination.c_str());
        for (const auto& event : rule.events) node.append_child("Event").text().set(event.c_str());
        if (!rule.prefix.empty() || !rule.suffix.empty()) {
            auto key = node.append_child("Filter").append_child("S3Key");
            if (!rule.prefix.empty()) {
                auto fr = key.append_child("FilterRule");
                fr.append_child("Name").text().set("prefix");
                fr.append_child("Value").text().set(rule.prefix.c_str());
            }
            if (!rule.suffix.empty()) {
                auto fr = key.append_child("FilterRule");
                fr.append_child("Name").text().set("suffix");
                fr.append_child("Value").text().set(rule.suffix.c_str());
            }
        }
    }
    return toString(doc);
}

bool overlaps(const NotificationRule& a, const NotificationRule& b) {
    bool events = false;
    for (const auto& x : a.events)
        for (const auto& y : b.events)
            if (eventsOverlap(x, y)) events = true;
    if (!events) return false;
    const bool prefixes = a.prefix.starts_with(b.prefix) || b.prefix.starts_with(a.prefix);
    const bool suffixes = a.suffix.ends_with(b.suffix) || b.suffix.ends_with(a.suffix);
    return prefixes && suffixes;
}

const std::vector<std::string>& awsEventTypes() {
    static const std::vector<std::string> types{"s3:ObjectCreated:*", "s3:ObjectRemoved:*", "s3:LifecycleExpiration:*"};
    return types;
}

const std::vector<std::string>& r2Actions() {
    static const std::vector<std::string> actions{"PutObject", "CopyObject", "CompleteMultipartUpload", "DeleteObject",
                                                  "LifecycleDeletion"};
    return actions;
}

namespace {

std::vector<std::string> sourceArns(const nlohmann::json& statement) {
    std::vector<std::string> arns;
    if (!statement.contains("Condition")) return arns;
    const auto& condition = statement["Condition"];
    for (const auto* op : {"ArnLike", "ArnEquals"}) {
        if (!condition.contains(op) || !condition[op].contains("aws:SourceArn")) continue;
        const auto& value = condition[op]["aws:SourceArn"];
        if (value.is_string()) arns.push_back(value.get<std::string>());
        if (value.is_array())
            for (const auto& v : value) if (v.is_string()) arns.push_back(v.get<std::string>());
    }
    return arns;
}

nlohmann::json parsePolicy(const std::string& policyJson) {
    if (policyJson.empty()) return {{"Version", "2012-10-17"}, {"Statement", nlohmann::json::array()}};
    auto policy = nlohmann::json::parse(policyJson);
    if (!policy.contains("Statement")) policy["Statement"] = nlohmann::json::array();
    if (policy["Statement"].is_object()) policy["Statement"] = nlohmann::json::array({policy["Statement"]});
    return policy;
}

}

std::string mergeQueuePolicy(const std::string& policyJson, const std::string& queueArn, const std::string& accountId,
                             const std::string& bucket, const bool add) {
    auto policy = parsePolicy(policyJson);
    auto& statements = policy["Statement"];
    std::vector<std::string> arns;
    nlohmann::json kept = nlohmann::json::array();
    for (const auto& s : statements) {
        if (s.is_object() && s.value("Sid", "") == kPolicySid) arns = sourceArns(s);
        else kept.push_back(s);
    }
    // ArnLike treats '*' and '?' as wildcards: only a valid bucket name (which can't contain them) may become an ARN.
    storage::upstream::requireValidBucketName(bucket);
    const auto arn = "arn:aws:s3:::" + bucket;
    std::erase(arns, arn);
    if (add) arns.push_back(arn);
    std::ranges::sort(arns);

    if (accountId.size() != 12 || !std::ranges::all_of(accountId, [](const unsigned char c) { return std::isdigit(c) != 0; }))
        throw std::invalid_argument("queue policy: '" + accountId + "' is not an AWS account id");
    if (!arns.empty()) {
        kept.push_back({
            {"Sid", kPolicySid},
            {"Effect", "Allow"},
            {"Principal", {{"Service", "s3.amazonaws.com"}}},
            {"Action", "sqs:SendMessage"},
            {"Resource", queueArn},
            {"Condition", {{"ArnLike", {{"aws:SourceArn", arns}}}, {"StringEquals", {{"aws:SourceAccount", accountId}}}}},
        });
    }
    if (kept.empty()) return {};
    policy["Statement"] = kept;
    if (!policy.contains("Version")) policy["Version"] = "2012-10-17";
    return policy.dump();
}

std::vector<std::string> policyBuckets(const std::string& policyJson) {
    std::vector<std::string> buckets;
    if (policyJson.empty()) return buckets;
    const auto policy = parsePolicy(policyJson);
    for (const auto& s : policy["Statement"])
        if (s.is_object() && s.value("Sid", "") == kPolicySid)
            for (const auto& arn : sourceArns(s))
                if (arn.starts_with("arn:aws:s3:::")) buckets.push_back(arn.substr(13));
    return buckets;
}

}
