#pragma once

#include "ops/Actor.hpp"
#include "ops/VaultKeys.hpp"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <ctime>
#include <optional>
#include <string>
#include <vector>

// Vaulthalla Cloud recovery enrollment (Tier B, customer-key-controlled; design/encryption/05-claims-and-custody.md
// §3 as amended 2026-11-10; the cloud's docs/design/recovery-enrollment.md). Explicit per vault, on a linked server:
// enrolling sends the vault's existing KEV1 envelopes, byte for byte from its bucket and wrapped only to recovery
// recipients the customer enrolled, with the public provenance a restore checks against (key checks, attestations,
// attestation public keys, the manifest checkpoint). Never a key, seed, kit or export: the cloud can't decrypt what
// it holds. Unenrolling deletes the cloud's records. Tier A (self-managed recovery) is unchanged either way.
namespace vh::ops::cloud_recovery {

using Channel = vault_keys::Channel;

struct Enrolled {
    unsigned int vault_id{};
    std::string vault_uid;
    bool created{};                 // the cloud's first enrollment of this vault
    uint64_t envelopes_sent{};      // what this upload carried
    uint64_t envelopes_added{};     // what the cloud didn't have yet
    uint64_t versions_added{};
    nlohmann::json coverage;        // the cloud's coverage report
};
// Super admins or users with the export encryption keys permission; the local CLI or a paired device (never the
// browser or an agent), with the keys step-up on a device. Conflict unless the server is linked and every needed key
// version has an envelope for a usable recovery recipient.
Enrolled enroll(const Actor& actor, unsigned int vaultId, Channel channel);

struct VaultCoverage {
    unsigned int vault_id{};
    std::string vault_name;
    std::string vault_uid;
    std::time_t enrolled_at = 0, last_upload_at = 0;
    // ready: the cloud covers every version this vault needs | behind: run enroll again (e.g. after a rotation) |
    // missing: the cloud has no record | unreachable
    std::string state;
    std::vector<unsigned int> not_in_cloud;  // needed versions the cloud has no envelope for
    nlohmann::json cloud;                    // the cloud's coverage report, or null
    std::optional<std::string> detail;
};
// The enrolled vaults (or one), compared with what the cloud holds. Super admins or the view encryption keys
// permission.
std::vector<VaultCoverage> status(const Actor& actor, std::optional<unsigned int> vaultId = std::nullopt);

// Deletes the cloud's records of the vault and forgets the enrollment here. Same permission and channels as enroll.
// NotFound when the vault isn't enrolled from this server.
void unenroll(const Actor& actor, unsigned int vaultId, Channel channel);

}
