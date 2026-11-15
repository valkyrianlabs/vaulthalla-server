#pragma once

#include <vl/vaultfmt/manifest/WriteCapability.hpp>

#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json_fwd.hpp>

// The bucket capability probe (design/encryption/06-publish-without-preconditions.md §7): one probe per bucket learns
// its vl::vaultfmt::manifest::WriteCapability (sync/manifest/WriteCapability.hpp: what each value means and what the manifest
// does with it), stored per vault (s3.manifest_publish, s3.bucket_probe; storage/BucketCapability.hpp).
namespace vh::storage::s3 {

class Controller;

// What the probe found. `conditional_put`: "supported" (every step answered as S3 specifies), "rejected" (the
// provider refused to evaluate a condition: PreconditionsUnsupported), "ignored" (a write that had to fail with 412
// succeeded) or "inconsistent" (412 where it had to succeed).
struct ProbeStep {
    std::string step;      // put_if_none_match_absent | put_if_none_match_present | put_if_match_wrong | ...
    std::string expected;  // ok | precondition_failed
    std::string got;       // ok | precondition_failed | not_implemented | error
};

struct ProbeResult {
    vl::vaultfmt::manifest::WriteCapability capability{vl::vaultfmt::manifest::WriteCapability::Unknown};
    std::string conditional_put;  // supported | rejected | ignored | inconsistent
    bool versioning{false};       // distinct version ids, listed newest first, each readable by id
    bool get_if_match{false};     // GET If-Match: 412 on a wrong ETag, 200 on the right one
    bool md5_etags{false};        // a single PUT's ETag is the MD5 of its body
    std::string reason;           // one sentence for status and errors
    std::vector<ProbeStep> steps;
    unsigned leftover_versions{};  // probe versions the cleanup could not delete (a protected bucket, a refusal)
    std::time_t probed_at{};
};

// Thrown when the probe could not reach a verdict (transport failure, a permission the key lacks, a protected
// bucket): nothing is recorded, the bucket stays Unknown.
struct ProbeFailed : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// The probe of §7 on one fresh key, `.vaulthalla/probe/<random uid>` (an allowlisted .vaulthalla/ key, so the
// opaque_v1 request rules hold): PUT If-None-Match: * (absent: ok), again (412), PUT If-Match wrong (412) and right
// (ok); the versions listed newest first and read back by id; GET If-Match wrong (412) and right (ok); then every
// version it wrote is deleted by id (on an unversioned bucket, the key). About 10 metered requests, each through the
// controller (budgets, protection locks and the usage ledger apply). Throws ProbeFailed.
[[nodiscard]] ProbeResult probeBucket(const Controller& controller);

// Stored form (s3.bucket_probe): {"v":1, "capability", "conditional_put", "versioning", "get_if_match", "md5_etags",
// "reason", "steps":[{step, expected, got}], "leftover_versions", "probed_at"}.
[[nodiscard]] nlohmann::json toJson(const ProbeResult& result);
[[nodiscard]] ProbeResult probeResultFromJson(const nlohmann::json& j);

// The probe key prefix (spec 06 §7).
inline constexpr std::string_view kProbePrefix = ".vaulthalla/probe/";

}
