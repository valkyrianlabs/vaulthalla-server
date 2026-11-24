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

void B2Admin::putLifecycle(const std::string& bucket, const std::vector<LifecycleRule>&) {
    requireBucket(bucket);
    throw CapabilityMissing("lifecycle", kB2LifecycleUnsupported);
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

    config.lifecycle_readable = false;
    config.notifications_readable = false;
    config.warnings.emplace_back("Backblaze B2 lifecycle rules and event notifications are managed in the Backblaze "
                                 "console or its native API; Vaulthalla does not read or change them");
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
    caps.items.push_back({"lifecycle", false, true, kB2LifecycleUnsupported});
    caps.items.push_back({"versioning", false, true, kB2VersioningFixed});
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

}
