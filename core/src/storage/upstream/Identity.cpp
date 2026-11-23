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

// What an endpoint host is, whatever provider the key was given: the identity of the buckets behind it (and so their
// protection locks) follows the host. An R2 or AWS endpoint saved under "Other" or "MinIO" used to get an identity of
// its own (s3:other:<host>) that no lock on the real bucket matched.
enum class EndpointKind { R2, Aws, B2, Other };

const std::regex& r2HostPattern() {
    // https://<32-hex account id>.r2.cloudflarestorage.com (or .eu./.fedramp. jurisdiction hosts)
    static const std::regex re(R"(^([0-9a-f]{32})\.(?:[a-z-]+\.)?r2\.cloudflarestorage\.com$)");
    return re;
}

const std::regex& b2HostPattern() {
    // https://s3.<region>.backblazeb2.com: us-west-004, us-east-005, eu-central-003, ca-east-006, …
    // (deploy/psql/153_backblaze_b2_identity.sql matches the same hosts)
    static const std::regex re(R"(^s3\.([a-z]{2}-[a-z]+-[0-9]{3})\.backblazeb2\.com$)");
    return re;
}

EndpointKind endpointKind(const std::string& host) {
    if (std::regex_match(host, r2HostPattern())) return EndpointKind::R2;
    if (std::regex_match(host, b2HostPattern())) return EndpointKind::B2;
    if (host == "amazonaws.com" || host.ends_with(".amazonaws.com") || host.ends_with(".amazonaws.com.cn"))
        return EndpointKind::Aws;
    return EndpointKind::Other;
}

std::optional<std::string> cachedAccount(const vault::model::APIKey& key) {
    if (key.provider_account_id && !key.provider_account_id->empty()) return key.provider_account_id;
    return std::nullopt;
}

}

std::string providerIdentity(const vault::model::S3Provider provider) {
    using vault::model::S3Provider;
    switch (provider) {
    case S3Provider::AWS: return "aws-s3";
    case S3Provider::CloudflareR2: return "cloudflare-r2";
    case S3Provider::BackblazeB2: return "backblaze-b2";
    default: break;
    }
    auto name = lower(vault::model::to_string(provider));
    std::ranges::replace(name, ' ', '-');
    return "s3:" + name;
}

std::string providerIdentity(const vault::model::APIKey& key) {
    switch (endpointKind(endpointHost(key.endpoint))) {
    case EndpointKind::R2: return "cloudflare-r2";
    case EndpointKind::Aws: return "aws-s3";
    case EndpointKind::B2: return "backblaze-b2";
    case EndpointKind::Other: break;
    }
    return providerIdentity(key.provider);
}

std::optional<std::string> providerEndpointMismatch(const vault::model::APIKey& key) {
    using vault::model::S3Provider;
    switch (endpointKind(endpointHost(key.endpoint))) {
    case EndpointKind::R2:
        if (key.provider != S3Provider::CloudflareR2)
            return "this endpoint is Cloudflare R2; choose the cloudflare-r2 provider";
        break;
    case EndpointKind::Aws:
        if (key.provider != S3Provider::AWS) return "this endpoint is AWS S3; choose the aws provider";
        break;
    case EndpointKind::B2:
        if (key.provider != S3Provider::BackblazeB2)
            return "this endpoint is Backblaze B2; choose the backblaze-b2 provider";
        break;
    case EndpointKind::Other:
        break;
    }
    return std::nullopt;
}

bool supportsAdmin(const vault::model::APIKey& key) { return adminUnsupportedReason(key).empty(); }

bool supportsEvents(const vault::model::APIKey& key) {
    using vault::model::S3Provider;
    return supportsAdmin(key) && (key.provider == S3Provider::AWS || key.provider == S3Provider::CloudflareR2);
}

std::string adminUnsupportedReason(const vault::model::APIKey& key) {
    using vault::model::S3Provider;
    if (key.cloudIssued())
        return "this key was issued by managed storage for one vault's bucket; the managed-storage service administers "
               "that account";
    switch (key.provider) {
    case S3Provider::AWS:
    case S3Provider::CloudflareR2:
        return {};
    case S3Provider::BackblazeB2:
        if (endpointKind(endpointHost(key.endpoint)) == EndpointKind::B2) return {};
        return "Backblaze B2 administration needs the key's endpoint to be https://s3.<region>.backblazeb2.com";
    default:
        break;
    }
    if (const auto mismatch = providerEndpointMismatch(key)) return *mismatch;
    return "provider administration supports AWS S3, Cloudflare R2 and Backblaze B2 keys only";
}

std::optional<std::string> b2EndpointRegion(const vault::model::APIKey& key) {
    std::smatch match;
    const auto host = endpointHost(key.endpoint);
    if (!std::regex_match(host, match, b2HostPattern())) return std::nullopt;
    return match[1].str();
}

std::optional<std::string> staticAccountRef(const vault::model::APIKey& key) {
    using vault::model::S3Provider;
    const auto host = endpointHost(key.endpoint);
    switch (endpointKind(host)) {
    case EndpointKind::R2: {
        std::smatch match;
        std::regex_match(host, match, r2HostPattern());
        return match[1].str();
    }
    case EndpointKind::Aws:
        return cachedAccount(key);   // unknown until STS resolves it: locks on the name then apply (fail closed)
    case EndpointKind::B2:
        return host;                 // bucket names are unique across all of B2: the region endpoint is enough
    case EndpointKind::Other:
        break;
    }
    if (key.provider == S3Provider::CloudflareR2 || key.provider == S3Provider::AWS) return cachedAccount(key);
    // No admin adapter: the endpoint host is the account (a MinIO cluster, a Wasabi region endpoint, …).
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
    return {.provider = s3::provider::admin::providerIdentity(key),
            .account_ref = s3::provider::admin::staticAccountRef(key),
            .bucket = bucket};
}

}
