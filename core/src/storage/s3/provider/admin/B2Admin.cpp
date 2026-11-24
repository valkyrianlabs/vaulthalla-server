#include "storage/s3/provider/admin/Adapters.hpp"

#include "vault/model/APIKey.hpp"

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

}
