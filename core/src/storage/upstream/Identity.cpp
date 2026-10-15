#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "vault/model/APIKey.hpp"

#include <algorithm>
#include <cctype>
#include <regex>

namespace vh::storage::s3::provider::admin {

namespace {

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// "https://host[:port]/..." → "host" (lower-case), or the input when it has no scheme.
std::string endpointHost(const std::string& endpoint) {
    auto rest = endpoint;
    if (const auto scheme = rest.find("://"); scheme != std::string::npos) rest = rest.substr(scheme + 3);
    if (const auto slash = rest.find('/'); slash != std::string::npos) rest = rest.substr(0, slash);
    if (const auto colon = rest.find(':'); colon != std::string::npos) rest = rest.substr(0, colon);
    return lower(rest);
}

}

std::string providerIdentity(const vault::model::S3Provider provider) {
    using vault::model::S3Provider;
    switch (provider) {
    case S3Provider::AWS: return "aws-s3";
    case S3Provider::CloudflareR2: return "cloudflare-r2";
    default: break;
    }
    auto name = lower(vault::model::to_string(provider));
    std::ranges::replace(name, ' ', '-');
    return "s3:" + name;
}

bool supportsAdmin(const vault::model::APIKey& key) {
    return key.provider == vault::model::S3Provider::AWS || key.provider == vault::model::S3Provider::CloudflareR2;
}

std::optional<std::string> staticAccountRef(const vault::model::APIKey& key) {
    using vault::model::S3Provider;
    if (key.provider == S3Provider::CloudflareR2) {
        // https://<32-hex account id>.r2.cloudflarestorage.com (or .eu./.fedramp. jurisdiction hosts)
        static const std::regex r2Host(R"(^([0-9a-f]{32})\.(?:[a-z]+\.)?r2\.cloudflarestorage\.com$)");
        std::smatch match;
        const auto host = endpointHost(key.endpoint);
        if (std::regex_match(host, match, r2Host)) return match[1].str();
        if (key.provider_account_id && !key.provider_account_id->empty()) return key.provider_account_id;
        return std::nullopt;
    }
    if (key.provider == S3Provider::AWS) {
        if (key.provider_account_id && !key.provider_account_id->empty()) return key.provider_account_id;
        return std::nullopt;
    }
    // No admin adapter: the endpoint host is the account (a MinIO cluster, a Wasabi region endpoint, …).
    const auto host = endpointHost(key.endpoint);
    if (host.empty()) return std::nullopt;
    return host;
}

bool isOwnedId(const std::string& id) { return id.starts_with(kOwnedPrefix); }

std::string defaultQueueName(const std::string& providerId, const std::string& region) {
    if (providerId == "cloudflare-r2") return std::string(kOwnedPrefix) + "events-r2";
    return std::string(kOwnedPrefix) + "events-" + (region.empty() ? std::string("us-east-1") : lower(region));
}

}

namespace vh::storage::upstream {

std::string BucketIdentity::toString() const {
    return provider + ":" + account_ref.value_or("?") + ":" + bucket;
}

BucketProtected::BucketProtected(BucketIdentity id)
    : std::runtime_error("upstream bucket '" + id.bucket + "' is protected: Vaulthalla will not touch it until an "
                         "administrator unprotects it"),
      identity(std::move(id)) {}

BucketIdentity identityFor(const vault::model::APIKey& key, const std::string& bucket) {
    return {.provider = s3::provider::admin::providerIdentity(key.provider),
            .account_ref = s3::provider::admin::staticAccountRef(key),
            .bucket = bucket};
}

}
