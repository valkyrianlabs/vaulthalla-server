#include "storage/s3/provider/admin/Adapters.hpp"

#include "vault/model/APIKey.hpp"

#include <vl/keykit/kit.hpp>

#include <algorithm>
#include <cctype>
#include <span>
#include <stdexcept>

namespace vh::storage::s3::provider::admin {

B2Admin::B2Admin(std::shared_ptr<vault::model::APIKey> key) : S3ApiAdmin(std::move(key)) {
    const auto region = b2EndpointRegion(*key_);
    if (!region) throw std::invalid_argument("Backblaze B2 endpoint must be https://s3.<region>.backblazeb2.com");
    region_ = *region;
}

// Built from the region the endpoint named (nothing else of the stored endpoint reaches the host); SigV4 is signed for
// that region.
detail::Endpoint B2Admin::serviceEndpoint() { return {"s3." + region_ + ".backblazeb2.com", region_, "s3"}; }

detail::Endpoint B2Admin::bucketEndpoint(const std::string&) { return serviceEndpoint(); }

std::optional<std::string> B2Admin::accountForGuard() { return staticAccountRef(*key_); }

AccountIdentity B2Admin::identity() {
    return {.provider = "backblaze-b2", .account_ref = *staticAccountRef(*key_), .principal = "b2-application-key"};
}

std::optional<std::string> B2Admin::locationConstraint(const CreateBucketRequest& request) const {
    if (request.region && !request.region->empty() && *request.region != region_)
        throw std::invalid_argument("a Backblaze B2 account keeps its buckets in one region: this key creates them in " +
                                    region_ + ", not '" + *request.region + "'");
    return region_;
}

std::map<std::string, std::string> B2Admin::createBucketHeaders() const { return {{"x-amz-acl", "private"}}; }

std::optional<std::string> B2Admin::headBucket(const std::string& bucket) {
    if (!S3ApiAdmin::headBucket(bucket)) return std::nullopt;
    return region_;
}

void B2Admin::putVersioning(const std::string& bucket, const Versioning target) {
    (void)detail::buildVersioning(target);   // Enabled or Suspended only, as everywhere
    requireBucket(bucket);
    if (target != Versioning::Enabled) throw CapabilityMissing("versioning", kB2VersioningFixed);
    if (versioning(bucket).status != Versioning::Enabled)
        throw ProviderError("Backblaze B2 does not report bucket '" + bucket + "' as versioned");
}

BucketConfiguration B2Admin::inspect(const std::string& bucket) {
    BucketConfiguration config;
    config.bucket = bucket;
    config.region = headBucket(bucket);
    if (!config.region) throw ProviderError("bucket '" + bucket + "' does not exist", "NoSuchBucket", 404);

    const auto versioning = getVersioning(bucket, config.warnings);
    config.versioning = versioning.status;
    config.mfa_delete = versioning.mfa_delete;

    config.object_lock = getObjectLock(bucket);
    if (!config.object_lock)
        config.warnings.emplace_back("object lock configuration is not readable with this application key "
                                     "(readBucketRetentions); cleanup treats it as unknown");

    // Lifecycle rules: B2's native API (b2_list_buckets). A failure here leaves the rest of the inspect standing.
    try {
        const auto& native = listNativeBucket(bucket);
        config.lifecycle = b2lifecycle::fromNative(native.lifecycle_rules, native.bucket_info);
        config.lifecycle_readable = true;
    } catch (const ProviderError& e) {
        config.lifecycle_readable = false;
        config.warnings.push_back(std::string("the bucket's lifecycle rules could not be read through Backblaze's native "
                                              "API: ") + e.what());
    }
    config.notifications_readable = false;
    config.warnings.emplace_back("Backblaze B2 event notifications are managed in the Backblaze console; Vaulthalla "
                                 "does not read or change them");
    return config;
}

Capabilities B2Admin::probe() {
    Capabilities caps;
    caps.identity = identity();
    caps.checked_at = std::time(nullptr);

    try {
        (void)listBuckets({}, 1);
        caps.items.push_back({"buckets.list", true, true, {}});
    } catch (const ProviderError& e) {
        caps.items.push_back({"buckets.list", false, true,
                              std::string(e.what()) + "; the application key must be allowed to list all bucket names "
                              "(a key restricted to one bucket can't administer the account)"});
    }
    caps.items.push_back({"buckets.create", true, false,
                          "checked when a bucket is created (the application key needs writeBuckets and access to all "
                          "buckets)"});
    // Lifecycle rules go through the native API with the same key: b2_authorize_account says what the key may do
    // (b2_list_buckets needs listBuckets, b2_update_bucket writeBuckets). Nothing is changed.
    try {
        const auto& session = nativeSession();
        const auto lacks = [&](const char* c) {
            return session.capabilities &&
                   std::ranges::find(*session.capabilities, std::string(c)) == session.capabilities->end();
        };
        if (lacks("listBuckets") || lacks("writeBuckets"))
            caps.items.push_back({"lifecycle", false, true,
                                  "the application key needs listBuckets and writeBuckets for Vaulthalla to read and set "
                                  "the lifecycle rule that keeps or drops a vault's old versions"});
        else
            caps.items.push_back({"lifecycle", true, session.capabilities.has_value(),
                                  "through Backblaze's native API (b2_list_buckets, b2_update_bucket); Vaulthalla sets "
                                  "only the rule for a vault's file history"});
    } catch (const ProviderError& e) {
        caps.items.push_back({"lifecycle", false, true,
                              std::string("Backblaze's native API refused this application key: ") + e.what()});
    }
    caps.items.push_back({"versioning", true, true, kB2VersioningFixed});
    caps.items.push_back({"events.queues", false, true, kB2EventsUnsupported});
    caps.items.push_back({"events.notifications", false, true, kB2EventsUnsupported});
    return caps;
}

// ---- read keys (vault read grants), through B2's native API ------------------------------------------------------

namespace {

// B2's native errors: {"status": 401, "code": "unauthorized", "message": "…"}.
detail::ErrorInfo b2NativeError(const curl::http::Response& response) {
    try {
        const auto j = nlohmann::json::parse(response.body);
        if (j.is_object()) return {.code = j.value("code", ""), .message = j.value("message", "")};
    } catch (const nlohmann::json::exception&) {
    }
    return {};
}

bool b2ValidKeyName(const std::string& name) {
    return !name.empty() && name.size() <= 100 &&
           std::ranges::all_of(name, [](const unsigned char c) { return std::isalnum(c) != 0 || c == '-'; });
}

std::vector<std::string> b2StringArray(const nlohmann::json& j) {
    std::vector<std::string> out;
    if (!j.is_array()) return out;
    for (const auto& v : j)
        if (v.is_string()) out.push_back(v.get<std::string>());
    return out;
}

}  // namespace

B2Admin::NativeSession B2Admin::authorizeNative() {
    const std::string pair = key_->access_key + ":" + key_->secret_access_key;
    curl::http::Request request;
    request.method = "GET";
    request.url = kAuthorizeUrl;
    request.timeout = std::chrono::seconds{30};
    request.max_response_bytes = 1024 * 1024;
    request.headers.emplace_back(
        "Authorization",
        "Basic " + vl::keykit::base64Encode(std::span(reinterpret_cast<const uint8_t*>(pair.data()), pair.size())));
    count("get");
    const auto response = curl::http::perform(request);
    if (!response.ok()) {
        const auto info = b2NativeError(response);
        auto error = detail::makeError("b2_authorize_account", response, info, secrets());
        if (response.status == 401)
            throw ProviderError(std::string(error.what()) + " (the vault's Backblaze B2 application key was refused)",
                                error.code, error.http_status);
        throw error;
    }
    NativeSession session;
    nlohmann::json j;
    try {
        j = nlohmann::json::parse(response.body);
    } catch (const nlohmann::json::exception&) {
        throw ProviderError("b2_authorize_account: the answer is not JSON", {}, response.status);
    }
    session.token = j.value("authorizationToken", "");
    session.account_id = j.value("accountId", "");
    // v4: apiInfo.storageApi.{apiUrl, allowed.capabilities}; v3 kept capabilities on storageApi itself; v2 had
    // apiUrl and allowed at the top level.
    const nlohmann::json* allowed = nullptr;
    if (j.contains("apiInfo") && j["apiInfo"].is_object() && j["apiInfo"].contains("storageApi") &&
        j["apiInfo"]["storageApi"].is_object()) {
        const auto& storage = j["apiInfo"]["storageApi"];
        session.api_url = storage.value("apiUrl", "");
        if (storage.contains("allowed") && storage["allowed"].is_object()) allowed = &storage["allowed"];
        else if (storage.contains("capabilities")) session.capabilities = b2StringArray(storage["capabilities"]);
    } else {
        session.api_url = j.value("apiUrl", "");
        if (j.contains("allowed") && j["allowed"].is_object()) allowed = &j["allowed"];
    }
    if (allowed && allowed->contains("capabilities")) session.capabilities = b2StringArray((*allowed)["capabilities"]);
    if (session.token.empty() || session.account_id.empty() || !session.api_url.starts_with("https://"))
        throw ProviderError("b2_authorize_account: the answer has no authorization token, account id or https API URL",
                            {}, response.status);
    return session;
}

nlohmann::json B2Admin::nativeCall(const NativeSession& session, const std::string& api, const nlohmann::json& body) {
    curl::http::Request request;
    request.method = "POST";
    request.url = session.api_url + "/b2api/v4/" + api;
    request.timeout = std::chrono::seconds{30};
    request.max_response_bytes = 1024 * 1024;
    request.headers.emplace_back("Authorization", session.token);
    request.headers.emplace_back("Content-Type", "application/json");
    request.body = body.dump();
    count(api == "b2_list_buckets" ? "list" : "put");
    const auto response = curl::http::perform(request);
    auto secrets = this->secrets();
    secrets.push_back(session.token);
    if (!response.ok()) throw detail::makeError(api, response, b2NativeError(response), secrets);
    try {
        auto j = nlohmann::json::parse(response.body);
        if (!j.is_object()) throw ProviderError(api + ": the answer is not a JSON object", {}, response.status);
        return j;
    } catch (const nlohmann::json::exception&) {
        throw ProviderError(api + ": the answer is not JSON", {}, response.status);
    }
}

ReadKey B2Admin::createReadKey(const ReadKeyRequest& request) {
    requireBucket(request.bucket);
    if (!b2ValidKeyName(request.key_name))
        throw std::invalid_argument("a Backblaze B2 key name is 1-100 letters, digits and '-'");

    const auto session = authorizeNative();
    if (session.capabilities && std::ranges::find(*session.capabilities, std::string("writeKeys")) == session.capabilities->end())
        throw CapabilityMissing("writeKeys",
                                "the vault's Backblaze B2 application key may not create keys: it needs the writeKeys "
                                "capability (an account master key, or an application key created with writeKeys) to "
                                "issue a read-only key for bucket '" + request.bucket + "'");

    const auto listed = nativeCall(session, "b2_list_buckets",
                                   {{"accountId", session.account_id}, {"bucketName", request.bucket}});
    std::string bucketId;
    if (listed.contains("buckets") && listed["buckets"].is_array())
        for (const auto& b : listed["buckets"])
            if (b.is_object() && b.value("bucketName", "") == request.bucket) bucketId = b.value("bucketId", "");
    if (bucketId.empty())
        throw ProviderError("b2_list_buckets does not list bucket '" + request.bucket + "' for this application key",
                            "NoSuchBucket", 404);

    const auto& caps = kReadKeyCapabilities();
    nlohmann::json created;
    try {
        created = nativeCall(session, "b2_create_key",
                             {{"accountId", session.account_id},
                              {"keyName", request.key_name},
                              {"capabilities", caps},
                              {"bucketIds", nlohmann::json::array({bucketId})}});
    } catch (const ProviderError& e) {
        if (e.http_status == 401 && !session.capabilities)
            throw CapabilityMissing("writeKeys", std::string(e.what()) +
                                                     " (creating a key needs the writeKeys capability on the vault's "
                                                     "Backblaze B2 application key)");
        throw;
    }
    ReadKey key;
    key.key_id = created.value("applicationKeyId", "");
    key.secret = created.value("applicationKey", "");
    key.key_name = request.key_name;
    key.bucket = request.bucket;
    key.bucket_id = bucketId;
    key.capabilities = caps;
    key.region = region_;
    key.endpoint = "https://s3." + region_ + ".backblazeb2.com";
    if (key.key_id.empty() || key.secret.empty()) {
        // Created but not handed back whole: take it away again rather than leave a key nobody holds.
        if (!key.key_id.empty()) {
            try {
                (void)nativeCall(session, "b2_delete_key", {{"applicationKeyId", key.key_id}});
            } catch (const std::exception&) {
            }
        }
        throw ProviderError("b2_create_key: the answer has no application key id or key");
    }
    return key;
}

void B2Admin::deleteReadKey(const std::string& keyId) {
    if (keyId.empty()) throw std::invalid_argument("a Backblaze B2 key id is required");
    const auto session = authorizeNative();
    (void)nativeCall(session, "b2_delete_key", {{"applicationKeyId", keyId}});
}

// ---- lifecycle rules, through B2's native API -----------------------------------------------------------------------

namespace {

constexpr const char* kB2lHide = "daysFromHidingToDeleting";
constexpr const char* kB2lUpload = "daysFromUploadingToHiding";
constexpr const char* kB2lCancel = "daysFromStartingToCancelingUnfinishedLargeFiles";
constexpr const char* kB2lPrefix = "fileNamePrefix";

// A day value as B2 holds it: null (or absent) = not applied, else a whole number of at least one. Anything else is
// a value this model can't carry (ok = false).
std::optional<unsigned int> b2lDays(const nlohmann::json& rule, const char* name, bool& ok) {
    if (!rule.contains(name) || rule[name].is_null()) return std::nullopt;
    const auto& v = rule[name];
    if (v.is_number_unsigned() && v.get<uint64_t>() >= 1 && v.get<uint64_t>() <= 100000)
        return static_cast<unsigned int>(v.get<uint64_t>());
    if (v.is_number_integer() && v.get<int64_t>() >= 1 && v.get<int64_t>() <= 100000)
        return static_cast<unsigned int>(v.get<int64_t>());
    ok = false;
    return std::nullopt;
}

nlohmann::json b2lValue(const std::optional<unsigned int>& v) { return v ? nlohmann::json(*v) : nlohmann::json(nullptr); }

nlohmann::json b2lRuleJson(const LifecycleRule& r) {
    return {{kB2lPrefix, r.prefix},
            {kB2lHide, b2lValue(r.expire_noncurrent_days)},
            {kB2lUpload, b2lValue(r.expire_current_days)},
            {kB2lCancel, b2lValue(r.abort_incomplete_multipart_days)}};
}

// The rules Vaulthalla recorded in bucketInfo: [{id, fileNamePrefix, the three day values}]. Unreadable = none.
std::vector<LifecycleRule> b2lRecorded(const nlohmann::json& info) {
    std::vector<LifecycleRule> out;
    if (!info.is_object() || !info.contains(kB2RuleRecordKey) || !info[kB2RuleRecordKey].is_string()) return out;
    nlohmann::json record;
    try {
        record = nlohmann::json::parse(info[kB2RuleRecordKey].get<std::string>());
    } catch (const nlohmann::json::exception&) {
        return out;
    }
    if (!record.is_object() || !record.contains("rules") || !record["rules"].is_array()) return out;
    for (const auto& r : record["rules"]) {
        if (!r.is_object() || !r.contains("id") || !r["id"].is_string() || !isOwnedId(r["id"].get<std::string>())) continue;
        bool ok = true;
        LifecycleRule rule;
        rule.id = r["id"].get<std::string>();
        rule.prefix = r.value(kB2lPrefix, "");
        rule.expire_noncurrent_days = b2lDays(r, kB2lHide, ok);
        rule.expire_current_days = b2lDays(r, kB2lUpload, ok);
        rule.abort_incomplete_multipart_days = b2lDays(r, kB2lCancel, ok);
        if (ok) out.push_back(std::move(rule));
    }
    return out;
}

bool b2lSame(const LifecycleRule& a, const LifecycleRule& b) {
    return a.prefix == b.prefix && a.expire_noncurrent_days == b.expire_noncurrent_days &&
           a.expire_current_days == b.expire_current_days &&
           a.abort_incomplete_multipart_days == b.abort_incomplete_multipart_days;
}

// ifRevisionIs takes the revision b2_list_buckets returned (documented as a number, shown as a string in places).
std::optional<int64_t> b2lRevision(const nlohmann::json& v) {
    if (v.is_number_integer()) return v.get<int64_t>();
    if (v.is_string()) {
        const auto s = v.get<std::string>();
        if (!s.empty() && s.size() <= 18 && std::ranges::all_of(s, [](const unsigned char c) { return std::isdigit(c) != 0; }))
            return std::stoll(s);
    }
    return std::nullopt;
}

}  // namespace

namespace b2lifecycle {

std::vector<LifecycleRule> fromNative(const nlohmann::json& rules, const nlohmann::json& bucketInfo) {
    auto recorded = b2lRecorded(bucketInfo);
    std::vector<bool> claimed(recorded.size(), false);
    std::vector<LifecycleRule> out;
    if (!rules.is_array()) return out;
    for (const auto& r : rules) {
        if (!r.is_object()) continue;
        LifecycleRule rule;
        bool ok = true;
        rule.prefix = r.contains(kB2lPrefix) && r[kB2lPrefix].is_string() ? r[kB2lPrefix].get<std::string>() : std::string{};
        if (!r.contains(kB2lPrefix) || !r[kB2lPrefix].is_string()) ok = false;
        rule.expire_noncurrent_days = b2lDays(r, kB2lHide, ok);
        rule.expire_current_days = b2lDays(r, kB2lUpload, ok);
        rule.abort_incomplete_multipart_days = b2lDays(r, kB2lCancel, ok);
        for (const auto& [k, v] : r.items())
            if (k != kB2lPrefix && k != kB2lHide && k != kB2lUpload && k != kB2lCancel && !v.is_null()) ok = false;
        rule.enabled = true;
        rule.unmodeled = !ok;
        rule.raw_json = r.dump();
        rule.foreign = true;
        if (ok)
            for (size_t i = 0; i < recorded.size(); ++i) {
                if (claimed[i] || !b2lSame(recorded[i], rule)) continue;
                claimed[i] = true;
                rule.id = recorded[i].id;
                rule.foreign = false;
                break;
            }
        if (rule.foreign) rule.id = "b2:" + (rule.prefix.empty() ? std::string("(all files)") : rule.prefix);
        out.push_back(std::move(rule));
    }
    return out;
}

std::pair<nlohmann::json, nlohmann::json> toNative(const std::vector<LifecycleRule>& rules, const nlohmann::json& info) {
    auto native = nlohmann::json::array();
    auto record = nlohmann::json::array();
    for (const auto& rule : rules) {
        if (rule.foreign && !rule.raw_json.empty()) {
            // Another application's rule (or one someone edited in the console): exactly as B2 listed it.
            try {
                native.push_back(nlohmann::json::parse(rule.raw_json));
            } catch (const nlohmann::json::exception&) {
                throw std::invalid_argument("lifecycle rule '" + rule.id + "' is not a Backblaze B2 rule");
            }
            continue;
        }
        if (!rule.enabled) throw std::invalid_argument("Backblaze B2 lifecycle rules have no disabled state");
        if (rule.unmodeled) throw std::invalid_argument("lifecycle rule '" + rule.id + "' can't be written to Backblaze B2");
        if (!rule.raw_xml.empty()) throw std::invalid_argument("lifecycle rule '" + rule.id + "' is not a Backblaze B2 rule");
        for (const auto& v : {rule.expire_noncurrent_days, rule.expire_current_days, rule.abort_incomplete_multipart_days})
            if (v && *v == 0) throw std::invalid_argument("Backblaze B2 lifecycle day values are 1 or more");
        if (!rule.expire_noncurrent_days && !rule.expire_current_days && !rule.abort_incomplete_multipart_days)
            throw std::invalid_argument("a Backblaze B2 lifecycle rule needs at least one day value");
        auto j = b2lRuleJson(rule);
        native.push_back(j);
        if (!rule.foreign && isOwnedId(rule.id)) {
            j["id"] = rule.id;
            record.push_back(std::move(j));
        }
    }
    auto outInfo = info.is_object() ? info : nlohmann::json::object();
    if (record.empty()) outInfo.erase(kB2RuleRecordKey);
    else outInfo[kB2RuleRecordKey] = nlohmann::json{{"v", 1}, {"rules", record}}.dump();
    return {native, outInfo};
}

}  // namespace b2lifecycle

const B2Admin::NativeSession& B2Admin::nativeSession() {
    if (!session_) session_ = authorizeNative();
    return *session_;
}

void B2Admin::rememberNativeBucket(const std::string& bucket, const nlohmann::json& b) {
    NativeBucket nb;
    nb.bucket_id = b.value("bucketId", "");
    nb.revision = b.contains("revision") ? b["revision"] : nlohmann::json(nullptr);
    if (b.contains("lifecycleRules") && b["lifecycleRules"].is_array()) nb.lifecycle_rules = b["lifecycleRules"];
    if (b.contains("bucketInfo") && b["bucketInfo"].is_object()) nb.bucket_info = b["bucketInfo"];
    buckets_[bucket] = std::move(nb);
}

const B2Admin::NativeBucket& B2Admin::listNativeBucket(const std::string& bucket) {
    requireBucket(bucket);
    const auto& session = nativeSession();
    // Every bucket type: without bucketTypes B2 lists only allPublic, allPrivate and snapshot buckets.
    const auto listed = nativeCall(session, "b2_list_buckets",
                                   {{"accountId", session.account_id},
                                    {"bucketName", bucket},
                                    {"bucketTypes", nlohmann::json::array({"all"})}});
    if (listed.contains("buckets") && listed["buckets"].is_array())
        for (const auto& b : listed["buckets"])
            if (b.is_object() && b.value("bucketName", "") == bucket && !b.value("bucketId", "").empty()) {
                rememberNativeBucket(bucket, b);
                return buckets_.at(bucket);
            }
    buckets_.erase(bucket);
    throw ProviderError("b2_list_buckets does not list bucket '" + bucket + "' for this application key", "NoSuchBucket",
                        404);
}

void B2Admin::putLifecycle(const std::string& bucket, const std::vector<LifecycleRule>& rules) {
    requireBucket(bucket);
    (void)b2lifecycle::toNative(rules, nlohmann::json::object());   // what B2 can't hold is refused before any request

    const auto& session = nativeSession();
    if (session.capabilities &&
        std::ranges::find(*session.capabilities, std::string("writeBuckets")) == session.capabilities->end())
        throw CapabilityMissing("writeBuckets",
                                "the vault's Backblaze B2 application key may not change bucket '" + bucket +
                                    "': setting its lifecycle rule needs the writeBuckets capability");
    if (!buckets_.contains(bucket)) (void)listNativeBucket(bucket);
    const auto current = buckets_.at(bucket);
    const auto revision = b2lRevision(current.revision);
    if (!revision)
        throw ProviderError("b2_list_buckets gave no revision for bucket '" + bucket +
                            "': Vaulthalla writes its lifecycle rules only conditionally (ifRevisionIs)");
    const auto [native, info] = b2lifecycle::toNative(rules, current.bucket_info);

    nlohmann::json answer;
    try {
        answer = nativeCall(session, "b2_update_bucket",
                            {{"accountId", session.account_id},
                             {"bucketId", current.bucket_id},
                             {"lifecycleRules", native},
                             {"bucketInfo", info},
                             {"ifRevisionIs", *revision}});
    } catch (const ProviderError& e) {
        buckets_.erase(bucket);   // whatever happened, the next write reads the bucket again
        if (e.http_status == 409)
            throw ProviderError("bucket '" + bucket + "' changed since Vaulthalla read its lifecycle rules (" +
                                    std::string(e.what()) + "); nothing was written: read it again and retry",
                                e.code.empty() ? std::string("conflict") : e.code, 409);
        throw;
    }
    if (answer.value("bucketName", bucket) == bucket && answer.contains("bucketId")) rememberNativeBucket(bucket, answer);
    else buckets_.erase(bucket);
}

}
