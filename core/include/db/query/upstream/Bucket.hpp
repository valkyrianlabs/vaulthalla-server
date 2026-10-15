#pragma once

#include "storage/upstream/Guard.hpp"
#include "storage/upstream/model/Bucket.hpp"

#include <chrono>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// upstream_bucket (migration 110). Trusted primitives: ops::upstream authorizes. Every write that names a bucket takes
// a BucketIdentity whose account_ref is resolved (std::invalid_argument otherwise): rows are keyed by real identity.
namespace vh::db::query::upstream {

using BucketModel = storage::upstream::model::Bucket;

struct SeenBucket {
    std::string bucket;
    std::optional<std::string> region{};
};

struct ClaimOutcome {
    BucketModel bucket;
    bool reclaimed = false;      // an earlier attempt of ours left this row (the bucket may already exist, empty)
};

enum class AdoptResult {
    Adopted,          // row created or taken over for adoption (state configuring, our token)
    Protected,        // locked: nothing changed
    BoundElsewhere,   // already bound to a vault
    Busy,             // another provisioning attempt holds it (creating/configuring, fresh, different token)
};

struct AdoptOutcome {
    AdoptResult result = AdoptResult::Adopted;
    std::optional<BucketModel> bucket;   // the row as it is now (absent only when there was none and nothing was written)
};

class Bucket {
public:
    // An attempt holding creating/configuring longer than this is considered abandoned (crash) and may be re-claimed.
    static constexpr std::chrono::minutes kStaleProvisioning{15};

    [[nodiscard]] static std::optional<BucketModel> get(int64_t id);
    [[nodiscard]] static std::optional<BucketModel> getByIdentity(const std::string& provider, const std::string& accountRef,
                                                                  const std::string& bucket);
    [[nodiscard]] static std::optional<BucketModel> getForVault(uint32_t vaultId);
    [[nodiscard]] static std::vector<BucketModel> listForAccount(const std::string& provider, const std::string& accountRef);
    // Every protected row with this name, any account (what an unresolved identity must honour).
    [[nodiscard]] static std::vector<BucketModel> findProtectedByName(const std::string& provider, const std::string& bucket);

    // A provider listing saw these buckets: upserts discovered_at/last_seen_at/region/last_seen_api_key_id. Never
    // changes ownership, provisioning state or protection.
    static void recordSeen(const std::string& provider, const std::string& accountRef, std::optional<uint32_t> apiKeyId,
                           const std::vector<SeenBucket>& buckets);

    // The create-new path's lease: inserts (unmanaged, creating, provision_attempted, token) — the row claims nothing
    // about the bucket until confirmCreated. nullopt when a row for the identity already exists and is not ours to
    // retry — i.e. the bucket is known (discovered, adopted, bound, protected, or another live attempt). Our own attempt
    // row is re-claimed atomically when it is unbound, unprotected and failed, deleted, or stuck in creating past
    // kStaleProvisioning; a row whose bucket we created and later deleted restarts with created_by_vaulthalla off.
    [[nodiscard]] static std::optional<ClaimOutcome> claimForCreate(const storage::upstream::BucketIdentity& id,
                                                                    const std::optional<std::string>& region,
                                                                    std::optional<uint32_t> apiKeyId,
                                                                    const std::string& operationToken);

    // The adopt path's lease (one transaction, row locked): refuses protected, bound and busy rows; otherwise sets
    // provisioning_state configuring + our token, and ownership adopted (a managed row keeps managed).
    [[nodiscard]] static AdoptOutcome upsertAdopted(const storage::upstream::BucketIdentity& id,
                                                    const std::optional<std::string>& region,
                                                    std::optional<uint32_t> apiKeyId,
                                                    const std::string& operationToken);

    // Gives up a fresh claim that turned out to name a bucket that already exists (it isn't ours to call managed):
    // deletes the row while it still carries our token, is unbound, unprotected and still creating. False otherwise.
    [[nodiscard]] static bool releaseClaim(int64_t id, const std::string& operationToken);

    // Compare-and-set on the operation token (no expected token = unconditional). False when the token didn't match
    // (another attempt took over) or the row is gone. last_error is replaced (nullopt clears it).
    [[nodiscard]] static bool setProvisioningState(int64_t id, storage::upstream::model::ProvisioningState state,
                                                   const std::optional<std::string>& expectedToken,
                                                   const std::optional<std::string>& lastError = std::nullopt);

    // CreateBucket succeeded for the attempt holding `operationToken` and the bucket listed empty: managed and
    // created_by_vaulthalla from now on. False when the token no longer matches.
    [[nodiscard]] static bool confirmCreated(int64_t id, const std::string& operationToken);
    // The attempt holding `operationToken` met a bucket that isn't ours: unmanaged, not created by Vaulthalla.
    static bool disown(int64_t id, const std::string& operationToken, storage::upstream::model::ProvisioningState state,
                       const std::optional<std::string>& lastError);
    // Cleanup's lease (see upstream_bucket_begin_cleanup): nullopt when the row is not a settled, unbound, unlocked bucket
    // Vaulthalla created, or another operation holds it.
    [[nodiscard]] static std::optional<BucketModel> beginCleanup(int64_t id, const std::string& operationToken);
    // True while the row still carries `operationToken` and is neither protected nor bound; refreshes updated_at.
    [[nodiscard]] static bool heartbeat(int64_t id, const std::string& operationToken);

    static void bindVault(int64_t id, uint32_t vaultId, storage::upstream::model::Ownership ownership);
    static void unbindVault(int64_t id);
    // With an expected token, only while the row still carries it (false otherwise).
    static bool setOwnership(int64_t id, storage::upstream::model::Ownership ownership,
                             storage::upstream::model::ProvisioningState state,
                             const std::optional<std::string>& expectedToken = std::nullopt);
    static void setRegion(int64_t id, const std::string& region);

    // Locks the identity (row created as unmanaged when unknown). Idempotent: an existing lock keeps its first
    // protected_at; by/reason are refreshed. Callers then run storage::upstream::guard::reload().
    static BucketModel protect(const storage::upstream::BucketIdentity& id, const std::optional<std::string>& region,
                               std::optional<uint32_t> userId, const std::optional<std::string>& userName,
                               const std::string& reason);
    // nullopt when Vaulthalla knows nothing about the identity.
    static std::optional<BucketModel> unprotect(const storage::upstream::BucketIdentity& id);

    // creating/configuring rows untouched for longer than `olderThan` (crash recovery).
    [[nodiscard]] static std::vector<BucketModel> listStaleProvisioning(std::chrono::seconds olderThan);
};

}
