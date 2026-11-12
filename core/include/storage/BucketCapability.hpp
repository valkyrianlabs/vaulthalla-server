#pragma once

#include "storage/s3/Capability.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>

// A vault's bucket write capability as the daemon uses it (design/encryption/06-publish-without-preconditions.md §7):
// the stored verdict (db::query::vault::BucketCapability, migration 136), probed when a bucket is bound (vault
// creation, a bucket or key change, `vh vault recover`, before a layout migration, `vh vault storage probe`) and, for
// rows from before migration 136, lazily on first use. Never downgraded without a probe: a bucket stored as
// conditional that refuses a condition is marked changed and its vault stalls (noteChanged) until it is probed again.
namespace vh::storage::bucket_capability {

// The stored capability; for a vault never probed, probes it now through `controller` and stores the verdict (at
// most one attempt per vault an hour when the probe can't run; Unknown meanwhile). Test mode never probes lazily
// unless setLazyProbingForTesting(true). `changed`: a conditional bucket refused a condition since its probe
// (noteChanged); callers stall without sending anything until it is probed again.
struct Resolved {
    s3::WriteCapability capability{s3::WriteCapability::Unknown};
    bool changed{false};
};
[[nodiscard]] Resolved resolve(uint32_t vaultId, const s3::Controller& controller);

// Before an operation that depends on the capability (a layout migration's start): probes now and stores the
// verdict, except in test mode without setLazyProbingForTesting(true), where it returns the stored one. Throws
// s3::ProbeFailed.
[[nodiscard]] Resolved reprobe(uint32_t vaultId, const s3::Controller& controller);

// Probes now and stores the verdict. Throws s3::ProbeFailed (nothing stored).
s3::ProbeResult probeAndRecord(uint32_t vaultId, const s3::Controller& controller);

// A probe of `bucket` through `apiKeyId`'s credential, before a vault holds it (creation): nothing is stored. nullopt
// when no probe runs (test mode without a controller factory); throws s3::ProbeFailed.
[[nodiscard]] std::optional<s3::ProbeResult> probeBinding(uint32_t apiKeyId, const std::string& bucket,
                                                          bool opaqueLayout);

// The same for a vault's current binding (its key and bucket), stored. nullopt as above.
[[nodiscard]] std::optional<s3::ProbeResult> probeVault(uint32_t vaultId);

// The bucket refused to evaluate a condition (PreconditionsUnsupported). Stored as conditional: recorded once with
// `detail` (changed_at), logged and, the first time, sent to the operators (operator_notification
// bucket_capability_changed). Never probed: logged, and the next resolve() probes it. Returns the text the stalled
// operation carries ("bucket_capability_changed: …" or "conditional_writes_refused: …"). Nothing is retried without
// the condition.
[[nodiscard]] std::string noteChanged(uint32_t vaultId, const std::string& detail);

// The text a stalled pass carries for an opaque_v1 vault whose bucket can't take the manifest publish.
[[nodiscard]] std::string unpublishableReason(s3::WriteCapability capability);

// ---- test seams (test mode only) -------------------------------------------------------------------------------------
void setLazyProbingForTesting(std::optional<bool> enabled);
// The controller probeBinding / probeVault use instead of a network one.
using ControllerFactory = std::function<std::shared_ptr<s3::Controller>(uint32_t apiKeyId, const std::string& bucket)>;
void setControllerFactoryForTesting(ControllerFactory factory);

}
