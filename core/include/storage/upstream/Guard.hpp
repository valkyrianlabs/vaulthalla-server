#pragma once

#include "vault/Fwd.hpp"

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

// Hard protection locks for upstream buckets (#237). A protected bucket is excluded from everything Vaulthalla does
// with it: probes, inventory, adoption, vault binding, lifecycle, event rules, sync reads/writes, cleanup, scheduled
// jobs and retries. Account-level ListBuckets may still show its name.
//
// The lock belongs to the bucket's identity (provider, account, bucket), never to an API key, so recreating a key
// cannot bypass it. Enforcement points: s3::Controller::recordRequest (every metered request of a vault/bucket
// controller, including the sync pass, hydrates, conflict resolution, the S3 gateway's upstream and retention
// purges), every admin adapter call that names a bucket, and ops::upstream / ops::vaults before they bind anything.
//
// The protected set is held in memory (reloaded from upstream_bucket on every change made through ops, at sync-pass
// start, and at least every 30 s by the event service), so the hot-path check is a shared-lock hash lookup.
namespace vh::storage::upstream {

struct BucketIdentity {
    std::string provider;                    // admin::providerIdentity(): "aws-s3", "cloudflare-r2", "s3:<name>"
    std::optional<std::string> account_ref;  // nullopt: not resolved yet (protection on any account then applies)
    std::string bucket;

    [[nodiscard]] std::string toString() const;
};

// Thrown wherever a protected bucket would be touched. Not an ops::Error: ops translate it to Denied.
struct BucketProtected : std::runtime_error {
    BucketIdentity identity;
    explicit BucketProtected(BucketIdentity id);
};

// The identity a key + bucket name refer to. Uses the cached/static account (no network).
[[nodiscard]] BucketIdentity identityFor(const vault::model::APIKey& key, const std::string& bucket);

namespace guard {

// True when the identity is locked. With an unknown account, any lock on (provider, bucket) counts (fail closed).
[[nodiscard]] bool isProtected(const BucketIdentity& id);
// Throws BucketProtected.
void require(const BucketIdentity& id);
void require(const vault::model::APIKey& key, const std::string& bucket);

// Reload the protected set from the database (cheap; called after every protect/unprotect and periodically).
void reload();
// Monotonic counter bumped by reload(); lets long-running loops notice a change.
[[nodiscard]] uint64_t epoch();

// Tests: replace the set without a database.
void setForTesting(const std::vector<BucketIdentity>& protectedIds);
void clearForTesting();

}

}
