#pragma once

#include "ops/Actor.hpp"
#include "storage/s3/Capability.hpp"

#include <optional>
#include <string>

#include <nlohmann/json_fwd.hpp>

// What a vault's bucket can do for the writes that must never overwrite another writer's object
// (design/encryption/06-publish-without-preconditions.md §7), for operators: `vh vault storage probe`, ws
// vault.storage.probe.
//
// Who: super admins and whoever may edit the vault (the admin Edit permission on it, the same that moves it to
// another bucket). The probe writes a few bytes under .vaulthalla/probe/ and deletes exactly the versions it wrote
// (storage/s3/Capability.hpp); it touches no file and carries no key material, so agents may run it (MCP, effect
// write). Recorded in the audit trail (vault.storage.probe). Refused on a protected bucket (denied).
namespace vh::ops::vault_storage {

struct ProbeAnswer {
    unsigned int vault_id{};
    std::string vault_name;
    std::string layout;                          // transparent | path_v0 | opaque_v1
    storage::s3::WriteCapability previous{};     // what was stored before this probe
    bool previously_changed{false};              // the stored verdict was marked changed (bucket_capability_changed)
    storage::s3::ProbeResult probe;
    // Whether the vault's manifest (opaque_v1: the encrypted manifest; path_v0 and transparent: the index) can be
    // published on the bucket by this server version.
    bool manifest_publishable{false};
};

// Probes the vault's bucket now and stores the verdict (replacing a changed one). Refusals: Denied, NotFound,
// Invalid (not an S3 vault), Refused{"bucket_probe_failed"} when the probe could not reach a verdict.
[[nodiscard]] ProbeAnswer probe(const Actor& actor, unsigned int vaultId);

[[nodiscard]] nlohmann::json toJson(const ProbeAnswer& answer);

}
