#pragma once

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>

// What Vaulthalla knows about a vault's bucket versioning (upstream_bucket.versioning_*, written by the provider policy
// slice). Read-only. Local versioning's backlog replay asks it whether replays are kept as provider history.
namespace vh::recovery::provider {

struct BucketVersioning {
    std::string status{"unknown"};             // unversioned | enabled | suspended | unknown (no bucket row / never read)
    bool enabled_by_vaulthalla{false};
    std::optional<std::time_t> settles_at;     // end of the provider's propagation window after enabling
    // enabled and past settles_at (no settles_at: enabled before Vaulthalla looked, nothing left to wait for)
    bool settled{false};

    // Version-aware writes can be relied on: every PUT becomes a version.
    [[nodiscard]] bool keepsHistory() const { return status == "enabled" && settled; }
};

// The newest upstream_bucket row bound to the vault. One indexed read; a vault without a row reads as status unknown.
[[nodiscard]] BucketVersioning bucketVersioningForVault(uint32_t vaultId, std::time_t now = std::time(nullptr));

}
