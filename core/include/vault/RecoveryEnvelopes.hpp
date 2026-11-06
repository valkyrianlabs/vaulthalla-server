#pragma once

#include "crypto/SecretKey.hpp"
#include "db/query/vault/RecoveryGrants.hpp"
#include "sync/Fwd.hpp"

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// KEV1 envelopes for a vault's recovery recipients (design/encryption/03-metadata-recovery.md §5.1): every key
// version the vault holds, current and future, wrapped to every usable (customer, not revoked) grant and written to
// the vault's own bucket as `.vaulthalla/key/<kid>` (If-None-Match: *). The bucket is the only place key material
// goes: no other host, account or service ever receives an envelope or a key (RecoveryNoSilentCustody).
//
// When:
//   - a rotation (EncryptionManager::prepare_key_rotation, the salvage key, a vault's first key): the new version's
//     envelopes are PUT before the version is committed, so it never seals a file without them; a failed PUT fails the
//     rotation, which changes nothing;
//   - an enrollment (ops::recovery_recipients::add): every version the vault holds;
//   - each sync pass (CloudEngine::ensureRecoveryEnvelopes): whatever is still missing (a bucket that was unreachable).
// A vault without a usable grant makes no request at all.
namespace vh::vault::envelopes {

// The bucket a vault's envelopes go to (an S3 vault's, through its API key). Throws std::runtime_error for a vault
// without one. Tests replace it.
using StoreFactory = std::function<std::shared_ptr<sync::manifest::ObjectStore>(uint32_t vaultId)>;
void setStoreFactoryForTesting(StoreFactory factory);
[[nodiscard]] std::shared_ptr<sync::manifest::ObjectStore> storeFor(uint32_t vaultId);

// Envelopes PUT for one version and not yet recorded.
struct Pending {
    uint32_t vault_id{};
    uint32_t version{};
    std::vector<db::query::vault::KeyEnvelope> envelopes;
    std::shared_ptr<sync::manifest::ObjectStore> store;
    [[nodiscard]] bool empty() const { return envelopes.empty(); }
};

// Wraps `key` (vault version `version`) to every usable grant that has no envelope for that version and PUTs each one.
// Empty (and no request) when no grant needs one. Throws when an envelope can't be written (the ones already PUT are
// removed, best effort).
[[nodiscard]] Pending put(uint32_t vaultId, uint32_t version, const crypto::SecretKey& key);
// Records what put() wrote (vault_key_envelope).
void record(const Pending& pending);
// The version never came to be: removes the objects put() wrote, best effort (never throws).
void discard(const Pending& pending) noexcept;
// put() then record(); returns the number written.
unsigned writeFor(uint32_t vaultId, uint32_t version, const crypto::SecretKey& key);

// Every missing envelope for `versions` (keyOf returns nullptr for a version it can't produce: skipped). Returns the
// number written; throws on a failed PUT (what was written before is recorded).
unsigned ensure(uint32_t vaultId, const std::vector<uint32_t>& versions,
                const std::function<crypto::SecretKeyPtr(uint32_t)>& keyOf);

// ---- D2 (spec 03 §5.5): does the vault have recovery material independent of this host?
//
// A self-hosted vault that encrypts upstream (BYOS; storage layout path_v0 or opaque_v1) is covered by a recovery
// recipient whose envelopes exist for every needed key version, or by a verified export of the current version (the
// CLI's export, or a paired device's confirmation with a matching key check: vault_keys.exported_version). Otherwise it
// is `recovery_material_missing`: status and health report it (degraded, never hidden). A rotation makes an export
// stale. Local and transparent vaults keep the export guidance and are `not_required`. Managed storage (#375) will
// require a recipient outright; it doesn't exist yet.
inline constexpr const char* kMaterialNotRequired = "not_required";
inline constexpr const char* kMaterialRecipient = "recipient";
inline constexpr const char* kMaterialExport = "export";
inline constexpr const char* kMaterialMissing = "recovery_material_missing";

struct Material {
    bool required{false};
    std::string state{kMaterialNotRequired};
    unsigned recipients{};                  // usable grants
    std::vector<uint32_t> uncovered;        // needed versions no usable grant has an envelope for (with recipients)
    bool export_current{false};             // the recorded export is of the current version
    bool rotation_needed{false};            // a revoked grant still holds an envelope of a needed version
    std::string detail;                     // what to do, when missing (or a revocation needs a rotation)
};

// `needed` = the versions the vault still needs (current first), `current` its current version.
[[nodiscard]] Material material(uint32_t vaultId, const std::vector<uint32_t>& needed, uint32_t current);
// The same with the needed versions read from the database (health): the current version, a pending rotation's
// outgoing key, older versions live files are sealed under (except salvaged ones) and versions recovery data references.
[[nodiscard]] Material material(uint32_t vaultId);

}
