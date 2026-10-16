#pragma once

#include "storage/upstream/Names.hpp"   // validBucketName (shared with ops and the adapters)
#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"
#include "storage/upstream/model/Bucket.hpp"

#include <functional>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>

// Upstream bucket provisioning (#237): create a managed bucket or take an existing one for adoption, with a durable
// lease (upstream_bucket.operation_token) so concurrent attempts and crashes can't produce two owners. Trusted
// primitives: ops::upstream authorizes and maps the exceptions.
//
// Invariant: the create path never takes over a bucket that exists. HeadBucket must say "absent", CreateBucket must
// succeed, and the new bucket must list empty; any other answer is a ProvisionConflict and nothing is deleted.
namespace vh::storage::upstream::provision {

// Bucket naming lives in storage/upstream/Names.hpp (shared with ops and the adapters); kept reachable here.
using storage::upstream::validBucketName;

// The bucket exists, is known to Vaulthalla already, is bound, or another attempt holds it. Nothing was changed
// upstream.
struct ProvisionConflict : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// Adoption of a bucket that doesn't exist (or isn't reachable with this credential).
struct BucketMissing : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// "vh-<slug of the vault name>-<8 random a-z0-9>", checked free with HeadBucket (≤5 tries).
[[nodiscard]] std::string generateBucketName(const std::string& vaultName, s3::provider::admin::AdminClient& admin);

[[nodiscard]] std::string newOperationToken();

struct Lease {
    model::Bucket row;
    std::string token;
    bool created = false;       // this attempt (or an earlier attempt of ours it resumed) created the bucket
};

// Create path, up to "configuring". Throws BucketProtected, ProvisionConflict, ProviderError/CapabilityMissing (the row
// is then marked failed, never deleted).
[[nodiscard]] Lease createManaged(s3::provider::admin::AdminClient& admin, const BucketIdentity& id,
                                  const std::optional<std::string>& region, std::optional<uint32_t> apiKeyId);

// Adopt path, up to "configuring". Throws BucketProtected, BucketMissing, ProvisionConflict.
[[nodiscard]] Lease beginAdopt(s3::provider::admin::AdminClient& admin, const BucketIdentity& id,
                               std::optional<uint32_t> apiKeyId);

// The vault exists: bind it and mark the lease ready. False when another attempt took the lease meanwhile.
[[nodiscard]] bool complete(const Lease& lease, uint32_t vaultId);

// A later step failed. A bucket this attempt created is deleted only when it is still empty and still ours; anything
// else is marked failed (created) or released back to what it was (adopted). Never throws.
void compensate(s3::provider::admin::AdminClient* admin, const Lease& lease, const std::string& reason) noexcept;

// What a HEAD of one object says (admission sampling). The default goes through an s3::Controller (metered, guarded);
// tests replace it.
using ObjectHead = std::function<std::optional<std::unordered_map<std::string, std::string>>(
    const std::shared_ptr<vault::model::APIKey>& key, const std::string& bucket, const std::string& objectKey)>;
[[nodiscard]] std::optional<std::unordered_map<std::string, std::string>> headObject(
    const std::shared_ptr<vault::model::APIKey>& key, const std::string& bucket, const std::string& objectKey);
void setObjectHeadForTesting(ObjectHead head);

}
