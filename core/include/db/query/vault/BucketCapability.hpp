#pragma once

#include "storage/s3/Capability.hpp"

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// s3.manifest_publish and s3.bucket_probe (migration 136): what a vault's bucket can do for writes that must never
// overwrite (storage/s3/Capability.hpp; design/encryption/06-publish-without-preconditions.md §7). Trusted primitive:
// no authorization here (ops::vault_storage and storage::bucket_capability decide when to read or write it).
namespace vh::db::query::vault {

class BucketCapability {
public:
    struct Stored {
        storage::s3::WriteCapability capability{storage::s3::WriteCapability::Unknown};
        std::optional<storage::s3::ProbeResult> probe;   // absent: never probed
        std::optional<std::time_t> changed_at;           // a conditional bucket refused a condition since its probe
        std::optional<std::string> changed_detail;
    };

    // Unknown for a vault without an s3 row or never probed.
    [[nodiscard]] static Stored get(uint32_t vaultId);

    // Stores a probe's verdict (replacing the previous one, and with it any changed_at).
    static void record(uint32_t vaultId, const storage::s3::ProbeResult& probe);

    // A bucket stored as conditional refused to evaluate a condition: marks its stored probe with changed_at and the
    // detail, once. True when this call set it (alert once); false when already marked or not stored as conditional.
    static bool markChanged(uint32_t vaultId, const std::string& detail);

    // Forgets the verdict of every vault bound to the key (its provider or endpoint changed: another service answers
    // now). Their next use probes again.
    static void clearForKey(uint32_t apiKeyId);

    // Vaults on the opaque_v1 layout whose manifest can't be published on their bucket: probed insufficient, or a
    // conditional bucket marked changed. For health (stats::model::SystemHealth).
    struct Unpublishable {
        uint32_t vault_id{};
        std::string vault_name;
        std::string reason;   // bucket_capability_insufficient | bucket_capability_changed
        std::string detail;
    };
    [[nodiscard]] static std::vector<Unpublishable> unpublishable();
};

}
