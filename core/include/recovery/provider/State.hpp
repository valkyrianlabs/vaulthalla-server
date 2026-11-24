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
    // upstream_bucket.noncurrent_retention_mode: latest = the provider keeps only the latest version (Backblaze B2 with
    // the vault's mode off: old versions are deleted a day after they are replaced).
    std::string retention_mode{"unset"};

    // Version-aware writes can be relied on: every PUT becomes a version that the provider keeps as history. A bucket
    // that keeps only the latest version (latest) versions writes but throws the history away within a day, so
    // replaying old generations there would only cost requests.
    [[nodiscard]] bool keepsHistory() const { return status == "enabled" && settled && retention_mode != "latest"; }
};

// The newest upstream_bucket row bound to the vault. One indexed read; a vault without a row reads as status unknown.
[[nodiscard]] BucketVersioning bucketVersioningForVault(uint32_t vaultId, std::time_t now = std::time(nullptr));

}
