#include "storage/s3/provider/admin/Adapters.hpp"
#include "storage/upstream/Names.hpp"

#include <pugixml.hpp>
#include <sstream>

#include "vault/model/APIKey.hpp"

#include <algorithm>
#include <cstring>
#include <stdexcept>

namespace vh::storage::s3::provider::admin {

namespace {

constexpr const char* kXmlContentType = "application/xml";

}

S3ApiAdmin::S3ApiAdmin(std::shared_ptr<vault::model::APIKey> key) : key_(std::move(key)) {
    if (!key_) throw std::invalid_argument("provider admin needs an API key");
    credentials_ = {.access_key = key_->access_key, .secret_key = key_->secret_access_key, .session_token = {}};
}

std::vector<std::string> S3ApiAdmin::secrets() const {
    return {key_->secret_access_key, key_->provider_token, key_->access_key};
}

void S3ApiAdmin::count(const char* kind) {
    std::scoped_lock lock(metricsMutex_);
    ++metrics_.requests;
    if (std::strcmp(kind, "list") == 0) ++metrics_.list;
    else if (std::strcmp(kind, "head") == 0) ++metrics_.head;
    else if (std::strcmp(kind, "get") == 0) ++metrics_.get;
    else if (std::strcmp(kind, "put") == 0) ++metrics_.put;
    else if (std::strcmp(kind, "del") == 0) ++metrics_.del;
    else if (std::strcmp(kind, "queue") == 0) ++metrics_.queue_requests;
}

Metrics S3ApiAdmin::metrics() const {
    std::scoped_lock lock(metricsMutex_);
    return metrics_;
}

curl::http::Response S3ApiAdmin::call(const detail::Endpoint& endpoint, const detail::SignedCall& signedCall,
                                      const char* kind) {
    count(kind);
    return detail::send(endpoint, signedCall, credentials_);
}

storage::upstream::BucketIdentity S3ApiAdmin::bucketIdentity(const std::string& bucket) {
    return {.provider = providerIdentity(*key_), .account_ref = accountForGuard(), .bucket = bucket};
}

void S3ApiAdmin::requireBucket(const std::string& bucket) {
    if (bucket.empty()) throw std::invalid_argument("bucket name is required");
    storage::upstream::requireValidBucketName(bucket);   // before the guard: the guard must see the real name
    storage::upstream::guard::require(bucketIdentity(bucket));
}

curl::http::Response S3ApiAdmin::bucketCall(const std::string& bucket, detail::SignedCall signedCall, const char* kind) {
    requireBucket(bucket);
    signedCall.path = "/" + bucket + (signedCall.path == "/" ? std::string{} : signedCall.path);
    return call(bucketEndpoint(bucket), signedCall, kind);
}

BucketPage S3ApiAdmin::listBuckets(const std::string& token, const unsigned int max) {
    detail::SignedCall c;
    if (pagedListBuckets()) {
        c.query.emplace_back("max-buckets", std::to_string(std::clamp(max, 1u, 10000u)));
        if (!token.empty()) c.query.emplace_back("continuation-token", token);
    }
    const auto response = call(serviceEndpoint(), c, "list");
    if (!response.ok()) throw detail::makeError("ListBuckets", response, detail::s3Error(response), secrets());
    return detail::parseListBuckets(response.body);
}

std::optional<std::string> S3ApiAdmin::headBucket(const std::string& bucket) {
    const auto response = bucketCall(bucket, detail::call("HEAD"), "head");
    if (response.ok()) return key_->region.empty() ? std::string("auto") : key_->region;
    if (response.transport_ok && response.status == 404) return std::nullopt;
    throw detail::makeError("HeadBucket " + bucket, response, detail::s3Error(response), secrets());
}

void S3ApiAdmin::createBucket(const CreateBucketRequest& request) {
    auto c = detail::call("PUT");
    if (const auto location = locationConstraint(request)) {
        pugi::xml_document doc;
        auto root = doc.append_child("CreateBucketConfiguration");
        root.append_attribute("xmlns") = "http://s3.amazonaws.com/doc/2006-03-01/";
        root.append_child("LocationConstraint").text().set(location->c_str());
        std::ostringstream xml;
        doc.save(xml, "", pugi::format_raw | pugi::format_no_declaration);
        c.body = xml.str();
        c.headers["content-type"] = kXmlContentType;
    }
    const auto response = bucketCall(request.name, c, "put");
    if (!response.ok()) throw detail::makeError("CreateBucket " + request.name, response, detail::s3Error(response), secrets());
}

void S3ApiAdmin::deleteBucket(const std::string& bucket) {
    const auto response = bucketCall(bucket, detail::call("DELETE"), "del");
    if (!response.ok()) throw detail::makeError("DeleteBucket " + bucket, response, detail::s3Error(response), secrets());
}

std::optional<std::vector<LifecycleRule>> S3ApiAdmin::getLifecycle(const std::string& bucket) {
    const auto response = bucketCall(bucket, detail::call("GET", {{"lifecycle", ""}}), "get");
    if (response.ok()) return detail::parseLifecycle(response.body);
    const auto info = detail::s3Error(response);
    if (info.code == "NoSuchLifecycleConfiguration") return std::vector<LifecycleRule>{};
    if (response.status == 403 || info.code == "AccessDenied") return std::nullopt;
    throw detail::makeError("GetBucketLifecycleConfiguration " + bucket, response, info, secrets());
}

VersioningState S3ApiAdmin::getVersioning(const std::string& bucket, std::vector<std::string>& warnings) {
    const auto response = bucketCall(bucket, detail::call("GET", {{"versioning", ""}}), "get");
    if (response.ok()) return detail::parseVersioningState(response.body);
    const auto info = detail::s3Error(response);
    if (info.code == "NotImplemented") return {.status = Versioning::Unversioned, .mfa_delete = std::nullopt};
    warnings.push_back(detail::makeError("GetBucketVersioning", response, info, secrets()).what());
    return {};
}

VersioningState S3ApiAdmin::versioning(const std::string& bucket) {
    if (!supportsVersioning()) {
        requireBucket(bucket);
        return {.status = Versioning::Unversioned, .mfa_delete = std::nullopt};
    }
    const auto response = bucketCall(bucket, detail::call("GET", {{"versioning", ""}}), "get");
    if (!response.ok())
        throw detail::makeError("GetBucketVersioning " + bucket, response, detail::s3Error(response), secrets());
    return detail::parseVersioningState(response.body);
}

void S3ApiAdmin::putVersioning(const std::string& bucket, const Versioning target) {
    auto c = detail::call("PUT", {{"versioning", ""}});
    c.body = detail::buildVersioning(target);   // throws for Unversioned/Unknown before anything else
    requireBucket(bucket);
    if (!supportsVersioning()) throw CapabilityMissing("versioning", kR2VersioningUnsupported);
    c.headers["content-type"] = kXmlContentType;
    // AWS rejects PutBucketVersioning without an integrity header (Content-MD5 or an x-amz-checksum-*).
    c.headers["content-md5"] = detail::md5Base64(c.body);
    if (const auto owner = expectedBucketOwner()) c.headers["x-amz-expected-bucket-owner"] = *owner;
    const auto response = bucketCall(bucket, c, "put");
    if (!response.ok())
        throw detail::makeError("PutBucketVersioning " + bucket, response, detail::s3Error(response), secrets());
}

void S3ApiAdmin::putLifecycle(const std::string& bucket, const std::vector<LifecycleRule>& rules) {
    if (rules.empty()) {
        const auto response = bucketCall(bucket, detail::call("DELETE", {{"lifecycle", ""}}), "del");
        if (!response.ok())
            throw detail::makeError("DeleteBucketLifecycle " + bucket, response, detail::s3Error(response), secrets());
        return;
    }
    auto c = detail::call("PUT", {{"lifecycle", ""}});
    c.body = detail::buildLifecycle(rules, allowNoncurrent());
    c.headers["content-type"] = kXmlContentType;
    c.headers["content-md5"] = detail::md5Base64(c.body);
    const auto response = bucketCall(bucket, c, "put");
    if (!response.ok())
        throw detail::makeError("PutBucketLifecycleConfiguration " + bucket, response, detail::s3Error(response), secrets());
}

ObjectPage S3ApiAdmin::listObjects(const std::string& bucket, const std::string& token, const unsigned int max) {
    auto c = detail::call("GET", {{"list-type", "2"}, {"max-keys", std::to_string(std::clamp(max, 1u, 1000u))}});
    if (!token.empty()) c.query.emplace_back("continuation-token", token);
    const auto response = bucketCall(bucket, c, "list");
    if (!response.ok()) throw detail::makeError("ListObjectsV2 " + bucket, response, detail::s3Error(response), secrets());
    return detail::parseListObjectsV2(response.body);
}

ObjectPage S3ApiAdmin::listObjectVersions(const std::string& bucket, const std::string& token, const unsigned int max) {
    if (!allowNoncurrent()) return listObjects(bucket, token, max);
    auto c = detail::call("GET", {{"versions", ""}, {"max-keys", std::to_string(std::clamp(max, 1u, 1000u))}});
    if (!token.empty()) {
        const auto nl = token.find('\n');
        c.query.emplace_back("key-marker", token.substr(0, nl));
        if (nl != std::string::npos && nl + 1 < token.size()) c.query.emplace_back("version-id-marker", token.substr(nl + 1));
    }
    const auto response = bucketCall(bucket, c, "list");
    if (!response.ok())
        throw detail::makeError("ListObjectVersions " + bucket, response, detail::s3Error(response), secrets());
    return detail::parseListObjectVersions(response.body);
}

std::vector<std::pair<std::string, std::string>> S3ApiAdmin::deleteObjects(const std::string& bucket,
                                                                            const std::vector<ObjectSummary>& objects) {
    std::vector<std::pair<std::string, std::string>> failed;
    for (std::size_t start = 0; start < objects.size(); start += 1000) {
        const std::vector chunk(objects.begin() + static_cast<std::ptrdiff_t>(start),
                                objects.begin() + static_cast<std::ptrdiff_t>(std::min(objects.size(), start + 1000)));
        auto c = detail::call("POST", {{"delete", ""}});
        c.body = detail::buildDeleteObjects(chunk);
        c.headers["content-type"] = kXmlContentType;
        c.headers["content-md5"] = detail::md5Base64(c.body);
        const auto response = bucketCall(bucket, c, "del");
        if (!response.ok())
            throw detail::makeError("DeleteObjects " + bucket, response, detail::s3Error(response), secrets());
        for (auto& error : detail::parseDeleteObjectsErrors(response.body)) failed.push_back(std::move(error));
    }
    return failed;
}

}
