#pragma once

#include "storage/s3/provider/admin/Admin.hpp"
#include "storage/upstream/Guard.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Explicit upstream cleanup (#237): count what a bucket holds, then delete every object version and the bucket.
// Trusted primitives; ops::upstream decides whether a bucket may be cleaned up at all and re-checks right before.
namespace vh::storage::upstream::cleanup {

struct Count {
    uint64_t objects = 0;          // current versions
    uint64_t versions = 0;         // noncurrent versions
    uint64_t delete_markers = 0;
    uint64_t bytes = 0;
    bool truncated = false;        // stopped at the limit
    std::vector<std::string> sample_keys;
};

// Read-only (ListObjectVersions / ListObjectsV2 pages), at most `limit` entries.
[[nodiscard]] Count count(s3::provider::admin::AdminClient& admin, const std::string& bucket, uint64_t limit = 100'000);

struct Run {
    uint64_t deleted = 0;
    uint64_t failed = 0;
    bool emptied = false;          // the bucket listed empty at the end
    bool bucket_deleted = false;   // deleted and confirmed absent by HeadBucket
    std::vector<std::string> errors;
};

struct Limits {
    std::chrono::seconds deadline{60};
    uint64_t max_objects = 50'000;
};

// Deletes versions page by page (≤1000 per batch) from the start of the listing, so a later run resumes where this one
// stopped. Stops at the limits, or when a whole page fails. A provider refusal for an object (object lock, legal hold)
// is a failure for that object, never bypassed.
[[nodiscard]] Run execute(s3::provider::admin::AdminClient& admin, const std::string& bucket, bool deleteBucket,
                          const Limits& limits = {});

// Confirmation tokens: single use, ten minutes, bound to the identity, the counts the person saw and the actor.
inline constexpr std::chrono::minutes kTokenLifetime{10};
struct Issued {
    std::string token;
    std::time_t expires_at = 0;
};
[[nodiscard]] Issued issueToken(const BucketIdentity& id, const Count& seen, uint32_t actorId);
// The counts the token was issued for (and the token is spent) when it matches; nullopt otherwise.
[[nodiscard]] std::optional<Count> consumeToken(const std::string& token, const BucketIdentity& id, uint32_t actorId);
// Whether what is there now is what the person confirmed (same entries and bytes, both complete or both truncated).
[[nodiscard]] bool sameAs(const Count& seen, const Count& now);

}
