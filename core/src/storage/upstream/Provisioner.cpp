#include "storage/upstream/Provisioner.hpp"

#include "db/query/upstream/Bucket.hpp"
#include "log/Registry.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/upstream/Inventory.hpp"
#include "vault/model/APIKey.hpp"

#include <paths.h>
#include <sodium.h>

#include <algorithm>
#include <cctype>
#include <mutex>
#include <regex>

namespace vh::storage::upstream::provision {

namespace {

namespace padmin = s3::provider::admin;
using BucketQuery = db::query::upstream::Bucket;
using model::Ownership;
using model::ProvisioningState;

std::string randomLower(const size_t n) {
    static constexpr char kAlphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
    std::string out;
    out.reserve(n);
    for (size_t i = 0; i < n; ++i) out.push_back(kAlphabet[randombytes_uniform(sizeof(kAlphabet) - 1)]);
    return out;
}

std::mutex& headMutex() {
    static std::mutex m;
    return m;
}

ObjectHead& headOverride() {
    static ObjectHead h;
    return h;
}

bool isCollision(const padmin::ProviderError& e) {
    return e.code == "BucketAlreadyExists" || e.code == "BucketAlreadyOwnedByYou" || e.http_status == 409;
}

// HeadBucket: absent → nullopt; present (any region answer) → the region; 403 means it exists in another account.
std::optional<std::string> probeExisting(padmin::AdminClient& admin, const std::string& bucket, bool& exists) {
    try {
        auto region = admin.headBucket(bucket);
        exists = region.has_value();
        return region;
    } catch (const padmin::ProviderError& e) {
        if (e.accessDenied()) {
            exists = true;
            return std::nullopt;
        }
        throw;
    }
}

bool listsEmpty(padmin::AdminClient& admin, const std::string& bucket) {
    return admin.listObjects(bucket, {}, 1).objects.empty();
}

}

std::string newOperationToken() { return randomLower(32); }

std::string generateBucketName(const std::string& vaultName, padmin::AdminClient& admin) {
    std::string slug;
    for (const auto c : vaultName) {
        const auto u = static_cast<unsigned char>(c);
        if (std::isalnum(u)) slug.push_back(static_cast<char>(std::tolower(u)));
        else if (!slug.empty() && slug.back() != '-') slug.push_back('-');
        if (slug.size() >= 40) break;
    }
    while (!slug.empty() && slug.back() == '-') slug.pop_back();
    if (slug.empty()) slug = "vault";

    for (int attempt = 0; attempt < 5; ++attempt) {
        const auto name = "vh-" + slug + "-" + randomLower(8);
        std::string why;
        if (!validBucketName(name, why)) throw std::invalid_argument("generated an invalid bucket name: " + why);
        bool exists = false;
        (void)probeExisting(admin, name, exists);
        if (!exists) return name;
    }
    throw ProvisionConflict("could not find an available bucket name; name the bucket explicitly");
}

Lease createManaged(padmin::AdminClient& admin, const BucketIdentity& id, const std::optional<std::string>& region,
                    const std::optional<uint32_t> apiKeyId) {
    guard::require(id);
    std::string why;
    if (!validBucketName(id.bucket, why)) throw std::invalid_argument("invalid bucket name '" + id.bucket + "': " + why);

    const auto token = newOperationToken();
    const auto claim = BucketQuery::claimForCreate(id, region, apiKeyId, token);
    if (!claim) {
        const auto known = BucketQuery::getByIdentity(id.provider, *id.account_ref, id.bucket);
        if (known && known->is_protected) throw BucketProtected(id);
        throw ProvisionConflict("bucket '" + id.bucket + "' already exists" +
                                (known ? " (Vaulthalla knows it as " + model::to_string(known->ownership) + ")" : "") +
                                "; a new vault can only adopt an existing bucket, never take it over");
    }

    Lease lease{.row = claim->bucket, .token = token, .created = false};
    // Resumable only if this row recorded that an earlier attempt really created the bucket (created_by_vaulthalla is
    // set by confirmCreated alone, after CreateBucket succeeded and the bucket listed empty). Any other existing bucket
    // existed before us, or was re-created by someone else after we deleted ours: never ours.
    const bool ourEarlierBucket = claim->reclaimed && claim->bucket.created_by_vaulthalla;
    // Gives the identity back when this attempt didn't (or can't prove it did) create anything: the claim row goes, or
    // at least claims nothing; a bucket an earlier attempt of ours created stays recorded as ours, failed.
    const auto giveUp = [&](const std::string& message) {
        if (ourEarlierBucket) {
            (void)BucketQuery::setProvisioningState(lease.row.id, ProvisioningState::Failed, token, message);
            return;
        }
        if (!BucketQuery::releaseClaim(lease.row.id, token))
            (void)BucketQuery::disown(lease.row.id, token, ProvisioningState::Failed, message);
    };

    try {
        bool exists = false;
        (void)probeExisting(admin, id.bucket, exists);
        if (exists) {
            if (ourEarlierBucket && listsEmpty(admin, id.bucket)) {
                lease.created = true;   // our own bucket from a failed attempt, still empty: resume it
            } else if (ourEarlierBucket) {
                giveUp("bucket holds objects; it is not resumed by a new vault");
                throw ProvisionConflict("bucket '" + id.bucket + "' (created by an earlier attempt) holds objects; adopt it "
                                        "or clean it up instead");
            } else {
                giveUp("bucket already exists");
                throw ProvisionConflict("bucket '" + id.bucket + "' already exists; adopt it instead of creating it");
            }
        } else {
            try {
                admin.createBucket({.name = id.bucket, .region = region});
            } catch (const padmin::ProviderError& e) {
                if (!isCollision(e)) throw;
                giveUp("bucket name taken: " + std::string(e.what()));
                throw ProvisionConflict("bucket '" + id.bucket + "' already exists (" + e.code + "); adopt it instead");
            }
            // AWS us-east-1 answers 200 to CreateBucket on a bucket the account already owns: a bucket that lists
            // anything existed before this call. (Residual race: an *empty* bucket the same account created between
            // our HeadBucket and CreateBucket is indistinguishable from a new one there; it can only come from another
            // writer racing on the exact name within milliseconds, and it holds nothing.)
            if (!listsEmpty(admin, id.bucket)) {
                (void)BucketQuery::disown(lease.row.id, token, ProvisioningState::Failed,
                                          "bucket held objects right after creation: it existed before");
                throw ProvisionConflict("bucket '" + id.bucket + "' already existed and holds objects; nothing was "
                                        "changed. Adopt it instead");
            }
            if (!BucketQuery::confirmCreated(lease.row.id, token))
                throw ProvisionConflict("another provisioning attempt took over bucket '" + id.bucket + "'");
            lease.created = true;
        }
    } catch (const ProvisionConflict&) {
        throw;
    } catch (const std::exception& e) {
        // Before a confirmed create nothing is ours (a transient HeadBucket/CreateBucket failure must never leave a
        // row that says "Vaulthalla created this"); after it, the bucket is ours and failed.
        if (lease.created) (void)BucketQuery::setProvisioningState(lease.row.id, ProvisioningState::Failed, token, e.what());
        else giveUp(e.what());
        throw;
    }

    if (!BucketQuery::setProvisioningState(lease.row.id, ProvisioningState::Configuring, token))
        throw ProvisionConflict("another provisioning attempt took over bucket '" + id.bucket + "'");
    if (const auto fresh = BucketQuery::get(lease.row.id)) lease.row = *fresh;
    return lease;
}

Lease beginAdopt(padmin::AdminClient& admin, const BucketIdentity& id, const std::optional<uint32_t> apiKeyId) {
    guard::require(id);
    bool exists = false;
    std::optional<std::string> region;
    try {
        region = probeExisting(admin, id.bucket, exists);
    } catch (const padmin::ProviderError& e) {
        throw BucketMissing("bucket '" + id.bucket + "' can't be reached with this credential: " + e.what());
    }
    if (!exists) throw BucketMissing("bucket '" + id.bucket + "' does not exist");
    if (!region) throw ProvisionConflict("bucket '" + id.bucket + "' belongs to another account");

    if (const auto bound = bindingsFor(id); !bound.empty())
        throw ProvisionConflict("bucket '" + id.bucket + "' is already used by vault '" + bound.front().vault_name + "' (ID " +
                                std::to_string(bound.front().vault_id) + (bound.front().deleted ? ", pending deletion)" : ")"));

    const auto token = newOperationToken();
    const auto outcome = BucketQuery::upsertAdopted(id, region, apiKeyId, token);
    switch (outcome.result) {
    case db::query::upstream::AdoptResult::Adopted: break;
    case db::query::upstream::AdoptResult::Protected: throw BucketProtected(id);
    case db::query::upstream::AdoptResult::BoundElsewhere:
        throw ProvisionConflict("bucket '" + id.bucket + "' is already bound to a vault");
    case db::query::upstream::AdoptResult::Busy:
        throw ProvisionConflict("another provisioning attempt is working on bucket '" + id.bucket + "'");
    }
    if (!outcome.bucket) throw std::runtime_error("adoption lease returned no bucket row");
    return {.row = *outcome.bucket, .token = token, .created = false};
}

bool complete(const Lease& lease, const uint32_t vaultId) {
    if (!BucketQuery::setProvisioningState(lease.row.id, ProvisioningState::Ready, lease.token)) return false;
    BucketQuery::bindVault(lease.row.id, vaultId, lease.row.ownership == Ownership::Managed ? Ownership::Managed
                                                                                            : Ownership::Adopted);
    return true;
}

void compensate(padmin::AdminClient* admin, const Lease& lease, const std::string& reason) noexcept {
    try {
        if (lease.created && admin) {
            bool empty = false;
            try {
                empty = admin->listObjectVersions(lease.row.bucket, {}, 1).objects.empty();
            } catch (const std::exception& e) {
                log::Registry::storage()->warn("[upstream::provision] can't tell whether '{}' is empty: {}", lease.row.bucket, e.what());
            }
            const auto current = BucketQuery::get(lease.row.id);
            const bool stillOurs = current && current->operation_token == lease.token && !current->vault_id &&
                                   !current->is_protected && current->created_by_vaulthalla;
            if (empty && stillOurs) {
                admin->deleteBucket(lease.row.bucket);
                (void)BucketQuery::setProvisioningState(lease.row.id, ProvisioningState::Deleted, lease.token,
                                                        "rolled back: " + reason);
                log::Registry::audit()->info("[upstream::provision] rolled back: deleted empty bucket '{}' this attempt created ({})",
                                             lease.row.bucket, reason);
                return;
            }
            (void)BucketQuery::setProvisioningState(lease.row.id, ProvisioningState::Failed, lease.token, reason);
            log::Registry::audit()->warn("[upstream::provision] '{}' kept after a failed provisioning ({}): {}", lease.row.bucket,
                                         empty ? "no longer ours" : "not empty", reason);
            return;
        }
        if (lease.row.ownership == Ownership::Managed) {
            // A managed bucket being re-adopted, or a create that never created anything: back to failed.
            (void)BucketQuery::setProvisioningState(lease.row.id, ProvisioningState::Failed, lease.token, reason);
            return;
        }
        // An adoption that didn't finish: the bucket is unmanaged again, exactly as it was.
        if (const auto current = BucketQuery::get(lease.row.id); current && !current->vault_id)
            (void)BucketQuery::setOwnership(lease.row.id, Ownership::Unmanaged, ProvisioningState::None, lease.token);
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[upstream::provision] compensation for '{}' failed: {}", lease.row.bucket, e.what());
    }
}

std::optional<std::unordered_map<std::string, std::string>> headObject(const std::shared_ptr<vault::model::APIKey>& key,
                                                                        const std::string& bucket,
                                                                        const std::string& objectKey) {
    {
        std::scoped_lock lock(headMutex());
        if (paths::testMode && headOverride()) return headOverride()(key, bucket, objectKey);
    }
    const s3::Controller controller(key, bucket);
    return controller.getHeadObject(objectKey);
}

void setObjectHeadForTesting(ObjectHead head) {
    std::scoped_lock lock(headMutex());
    headOverride() = std::move(head);
}

}
