#pragma once

#include <ctime>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

#include <nlohmann/json_fwd.hpp>

// What a bucket can do for the writes that must never overwrite another writer's object
// (design/encryption/06-publish-without-preconditions.md §7), learned by one probe and stored per vault
// (s3.manifest_publish, s3.bucket_probe; storage/BucketCapability.hpp).
//
//   Conditional   PUT honours If-None-Match: * and If-Match (AWS S3, Cloudflare R2): the manifest publishes as spec 03
//                 §3.4 says, every write-once object is PUT with If-None-Match: *.
//   VersionLog    conditional PUT is rejected (501 / 400 NotImplemented, Backblaze B2) or silently ignored, and the
//                 bucket keeps versions: write-once objects are PUT plainly (their names are random or
//                 content-addressed); the root publish of spec 06 §5 is not implemented yet and refuses.
//   Insufficient  neither conditional PUT nor versions, or GET If-Match is not honoured: plain PUTs for write-once
//                 objects and the path_v0 index; no opaque_v1 manifest.
//   Unknown       never probed (or the probe could not run): today's behaviour, conditional writes. A bucket is never
//                 downgraded without a probe saying so.
namespace vh::storage::s3 {

class Controller;

enum class WriteCapability { Unknown, Conditional, VersionLog, Insufficient };

// "unknown", "conditional", "version_log", "insufficient".
[[nodiscard]] std::string_view to_string(WriteCapability capability);
// The stored s3.manifest_publish values: "conditional" | "version_log"; anything else is nullopt.
[[nodiscard]] std::optional<WriteCapability> publishModeFromString(std::string_view text);

// May a write carry If-None-Match / If-Match? Conditional, and Unknown (never a silent downgrade).
[[nodiscard]] bool sendsPreconditions(WriteCapability capability) noexcept;

// What the probe found. `conditional_put`: "supported" (every step answered as S3 specifies), "rejected" (the
// provider refused to evaluate a condition: PreconditionsUnsupported), "ignored" (a write that had to fail with 412
// succeeded) or "inconsistent" (412 where it had to succeed).
struct ProbeStep {
    std::string step;      // put_if_none_match_absent | put_if_none_match_present | put_if_match_wrong | ...
    std::string expected;  // ok | precondition_failed
    std::string got;       // ok | precondition_failed | not_implemented | error
};

struct ProbeResult {
    WriteCapability capability{WriteCapability::Unknown};
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
