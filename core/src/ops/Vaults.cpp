#include "ops/Vaults.hpp"

#include "ops/Users.hpp"

#include "config/Registry.hpp"
#include "config/util.hpp"
#include "db/query/identities/User.hpp"
#include "db/encoding/timestamp.hpp"
#include "db/query/sync/Policy.hpp"
#include "db/query/vault/APIKey.hpp"
#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "db/query/vault/Waiver.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/Controller.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "sync/model/Policy.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/Waiver.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/Retention.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/terms/waiver.hpp"

#include <paths.h>

#include <algorithm>
#include <cctype>
#include <mutex>
#include <utility>

namespace vh::ops::vaults {

namespace {

using vault::model::S3Vault;
using vault::model::VaultType;
using VaultPerm = rbac::permission::admin::VaultPermissions;
using KeyPerm = rbac::permission::admin::keys::APIPermissions;
using SyncConfigPerm = rbac::permission::vault::sync::SyncConfigPermissions;
using SyncActionPerm = rbac::permission::vault::sync::SyncActionPermissions;

bool canOnVault(const Actor& actor, const VaultPerm permission, const unsigned int vaultId) {
    return rbac::resolver::Admin::has<VaultPerm>({.user = actor, .permission = permission, .vault_id = vaultId});
}

bool canCreateFor(const Actor& actor, const unsigned int ownerId) {
    return rbac::resolver::Admin::has<VaultPerm>({.user = actor, .permission = VaultPerm::Create, .target_user_id = ownerId});
}

void requireConsume(const Actor& actor, const unsigned int keyId) {
    if (!db::query::vault::APIKey::getAPIKey(keyId)) throw NotFound("API key not found: " + std::to_string(keyId));
    if (!rbac::resolver::Admin::has<KeyPerm>({.user = actor, .permission = KeyPerm::Consume, .api_key_id = keyId}))
        throw Denied("you do not have permission to use api-key " + std::to_string(keyId) + " for this vault");
}

// A protected upstream bucket (#237) can never become a vault's storage. The lock is keyed to the bucket's identity
// (an AWS key whose account isn't resolved yet matches any lock on the name: fail closed).
void requireBucketUnprotected(const unsigned int keyId, const std::string& bucket) {
    const auto key = db::query::vault::APIKey::getAPIKey(keyId);
    if (!key) throw NotFound("API key not found: " + std::to_string(keyId));
    if (storage::upstream::guard::isProtected(storage::upstream::identityFor(*key, bucket)))
        throw Denied("bucket '" + bucket + "' is protected: it can't be used as vault storage until it is unprotected");
}

VaultPtr requireVault(const unsigned int vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    auto vault = runtime::Deps::get().storageManager->getVault(vaultId);
    if (!vault) throw NotFound("vault not found: " + std::to_string(vaultId));
    return vault;
}

// Copies the vault so a patch never mutates the engine's live object before it is persisted.
VaultPtr copyOf(const VaultPtr& vault) {
    if (vault->type == VaultType::S3) return std::make_shared<S3Vault>(*std::static_pointer_cast<S3Vault>(vault));
    return std::make_shared<vault::model::Vault>(*vault);
}

std::optional<std::string> normalizedTier(const unsigned int keyId, const std::optional<std::string>& requested) {
    const auto key = db::query::vault::APIKey::getAPIKey(keyId);
    if (!key) throw NotFound("API key not found: " + std::to_string(keyId));
    const auto tier = storage::s3::provider::resolve(key->provider)->normalizeStorageTier(requested);
    if (!tier.ok) throw Invalid(tier.error);
    return tier.normalized_id;
}

void applySync(sync::model::Policy& policy, const VaultType type, const SyncPatch& patch) {
    try {
        if (patch.interval) policy.interval = *patch.interval;
        if (patch.enabled) policy.enabled = *patch.enabled;
        if (type == VaultType::Local) {
            if (patch.strategy || patch.max_remote_index_age || patch.s3_budget_preset || !patch.s3_budget.empty())
                throw Invalid("sync strategy, remote index age and S3 request budgets only apply to S3 vaults");
            if (patch.conflict_policy)
                dynamic_cast<sync::model::LocalPolicy&>(policy).conflict_policy =
                    sync::model::fsConflictPolicyFromString(*patch.conflict_policy);
        } else {
            auto& remote = dynamic_cast<sync::model::RemotePolicy&>(policy);
            if (patch.strategy) remote.strategy = sync::model::strategyFromString(*patch.strategy);
            if (patch.conflict_policy)
                remote.conflict_policy = sync::model::rsConflictPolicyFromString(*patch.conflict_policy);
            if (patch.max_remote_index_age) remote.max_remote_index_age = *patch.max_remote_index_age;
            if (patch.s3_budget_preset)
                remote.s3_request_budget = sync::model::s3RequestBudgetForPreset(
                    sync::model::s3BudgetPresetFromString(*patch.s3_budget_preset));
            auto& b = remote.s3_request_budget;
            const auto& p = patch.s3_budget;
            if (p.list) b.max_list_requests = *p.list;
            if (p.head) b.max_head_requests = *p.head;
            if (p.get) b.max_get_requests = *p.get;
            if (p.put) b.max_put_requests = *p.put;
            if (p.copy) b.max_copy_requests = *p.copy;
            if (p.del) b.max_delete_requests = *p.del;
            if (p.downloaded_bytes) b.max_downloaded_bytes = *p.downloaded_bytes;
        }
    } catch (const Error&) {
        throw;
    } catch (const std::exception& e) {
        throw Invalid(e.what());
    }
    policy.interval = sync::model::Policy::clampInterval(policy.interval);
    policy.rehash_config();
}

// A new vault's policy before the caller's settings: S3 vaults start from the operator's vaults.s3.* defaults, so
// whatever the request leaves out (CLI without --sync-strategy/--on-sync-conflict, ws without sync fields) gets them.
PolicyPtr freshPolicy(const VaultType type) {
    if (type == VaultType::S3) {
        auto remote = std::make_shared<sync::model::RemotePolicy>();
        const auto& defaults = vh::config::Registry::get().vaults.s3;
        remote->strategy = sync::model::strategyFromString(defaults.default_remote_sync_strategy);
        remote->conflict_policy = sync::model::rsConflictPolicyFromString(defaults.default_remote_conflict_policy);
        return remote;
    }
    return std::make_shared<sync::model::LocalPolicy>();
}

PolicyPtr copyPolicy(const PolicyPtr& policy, const VaultType type) {
    if (type == VaultType::S3)
        return std::make_shared<sync::model::RemotePolicy>(dynamic_cast<const sync::model::RemotePolicy&>(*policy));
    return std::make_shared<sync::model::LocalPolicy>(dynamic_cast<const sync::model::LocalPolicy&>(*policy));
}

// True when the bucket already holds objects, so encrypting (or not) over it changes what existing readers see.
bool bucketHoldsData(const S3Vault& s3) {
    if (paths::testMode) return false;
    const auto key = runtime::Deps::get().apiKeyManager->getAPIKey(s3.api_key_id);
    const storage::s3::Controller controller(key, s3.bucket);
    if (const auto [valid, message] = controller.validateAPICredentials(); !valid)
        throw Invalid("cannot reach the S3 bucket with this API key: " + message);
    return !controller.isBucketEmpty();
}

std::string waiverTextFor(const S3Vault& s3) {
    return std::string(s3.encrypt_upstream ? vault::terms::ENABLE_UPSTREAM_ENCRYPTION_WAIVER
                                           : vault::terms::DISABLE_UPSTREAM_ENCRYPTION_WAIVER);
}

void recordWaiver(const Actor& actor, const std::shared_ptr<S3Vault>& s3) {
    auto waiver = std::make_shared<sync::model::Waiver>();
    waiver->vault = s3;
    waiver->user = actor;
    waiver->apiKey = db::query::vault::APIKey::getAPIKey(s3->api_key_id);
    waiver->encrypt_upstream = s3->encrypt_upstream;
    waiver->waiver_text = waiverTextFor(*s3);
    db::query::vault::Waiver::addWaiver(waiver);
}

void pushSyncToEngine(const unsigned int vaultId, const PolicyPtr& policy) {
    if (const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId)) {
        std::unique_lock lock(engine->mutex);
        engine->sync = policy;
    }
    if (runtime::Deps::get().syncController) runtime::Deps::get().syncController->refreshEngines();
}

// A deleted vault has no engine: RBAC takes the owner the deletion recorded (#162).
bool canRemoveDeleted(const Actor& actor, const vault::model::Deletion& d) {
    auto v = std::make_shared<vault::model::Vault>();
    v->id = d.vault_id;
    v->name = d.vault_name;
    v->owner_id = d.owner_id.value_or(0);
    v->type = d.vault_type;
    return rbac::resolver::Admin::has<VaultPerm>({.user = actor, .permission = VaultPerm::Remove, .vault = v});
}

std::string when(const std::time_t t) { return db::encoding::timestampToString(t); }

std::string duration(const std::chrono::seconds d) { return vh::config::durationToString(d); }

// The S3 data-loss gate: encrypted objects stay upstream, and no export of the key that decrypts them was recorded.
void requireKeyLossAccepted(const bool atRisk, const bool accepted, const std::string& vaultName, const std::string& bucket,
                            const std::string& exportCommand, const std::chrono::seconds keyWindow) {
    if (!atRisk || accepted) return;
    throw NeedsConfirmation(VAULT_UPSTREAM_KEY_LOSS,
        "The objects vault '" + vaultName + "' keeps in bucket '" + bucket + "' are encrypted with its key, and that key "
        "has never been exported. Without the key the upstream data can never be decrypted again. Export it first:\n  " +
        exportCommand + "\nThe key stays exportable with the same command for " + duration(keyWindow) +
        " after the deletion; after that it is destroyed.");
}

void requireNowConfirmed(const bool confirmed, const std::string& vaultName) {
    if (confirmed) return;
    throw NeedsConfirmation(VAULT_DELETE_NOW,
        "Delete '" + vaultName + "' now? Its data is removed within moments and it cannot be restored. Its sealed "
        "encryption key is still kept for the full key retention window.");
}

PolicyPtr currentPolicy(const unsigned int vaultId) {
    if (const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId)) {
        std::shared_lock lock(engine->mutex);
        if (engine->sync) return engine->sync;
    }
    auto policy = db::query::sync::Policy::getSync(vaultId);
    if (!policy) throw NotFound("sync policy not found for vault " + std::to_string(vaultId));
    return policy;
}

}

VaultPtr create(const Actor& actor, const Create& req) {
    requireActor(actor);
    const auto ownerId = req.owner_id.value_or(actor->id);
    if (!vh::identities::manager().user(ownerId)) throw NotFound("owner not found: " + std::to_string(ownerId));
    if (!canCreateFor(actor, ownerId)) throw Denied("you do not have permission to create vaults for this owner");
    if (req.name.empty()) throw Invalid("vault name is required");
    if (db::query::vault::Vault::vaultExists(req.name, ownerId)) {
        // The name of a deleted vault stays reserved until its purge (#162).
        if (const auto deleted = db::query::vault::Deletion::findByName(req.name, ownerId);
            deleted && deleted->state != vault::model::DeletionState::Purged)
            throw Conflict("the name '" + req.name + "' belongs to deleted vault " + std::to_string(deleted->vault_id) +
                           ", reserved until it is purged (" + when(deleted->purge_after) + "): restore it with `vh vault "
                           "restore " + std::to_string(deleted->vault_id) + "`, or purge it now with `vh vault delete " +
                           std::to_string(deleted->vault_id) + " --now`");
        throw Conflict("a vault named '" + req.name + "' already exists for this owner");
    }

    VaultPtr vault;
    const bool provisioning = req.type == VaultType::S3 && req.s3 && req.s3->provision &&
                              req.s3->provision->mode != upstream::BucketMode::Existing;
    if (req.type == VaultType::S3) {
        if (!req.s3) throw Invalid("S3 vaults need an API key and a bucket");
        const bool generated = provisioning && req.s3->provision->mode == upstream::BucketMode::Create &&
                               (req.s3->provision->generate_name || req.s3->bucket.empty());
        if (req.s3->bucket.empty() && !generated) throw Invalid("bucket is required for S3 vaults");
        requireConsume(actor, req.s3->api_key_id);
        if (!req.s3->bucket.empty()) requireBucketUnprotected(req.s3->api_key_id, req.s3->bucket);
        // A deleted vault keeps its bucket until it is purged (its upstream purge may still need it).
        if (const auto owner = db::query::vault::Vault::bucketOwner(req.s3->api_key_id, req.s3->bucket); owner && owner->deleted)
            throw Conflict("bucket '" + req.s3->bucket + "' still belongs to deleted vault '" + owner->vault_name + "' (ID " +
                           std::to_string(owner->vault_id) + "), pending purge: restore it with `vh vault restore " +
                           std::to_string(owner->vault_id) + "`, or purge it now with `vh vault delete " +
                           std::to_string(owner->vault_id) + " --now`");
        else if (owner)
            // One vault per (key, bucket). The upsert used to hand the other vault's binding to the new one.
            throw Conflict("bucket '" + req.s3->bucket + "' is already the storage of vault '" + owner->vault_name +
                           "' (ID " + std::to_string(owner->vault_id) + ") with this API key");
        auto s3 = std::make_shared<S3Vault>(req.name, req.s3->api_key_id, req.s3->bucket);
        s3->storage_tier_id = normalizedTier(req.s3->api_key_id, req.s3->storage_tier);
        s3->encrypt_upstream = req.s3->encrypt_upstream.value_or(true);
        vault = s3;
    } else {
        if (req.s3) throw Invalid("API key and bucket only apply to S3 vaults");
        vault = std::make_shared<vault::model::Vault>();
    }
    vault->type = req.type;
    vault->name = req.name;
    vault->owner_id = ownerId;
    vault->description = req.description;
    vault->quota = req.quota;
    vault->slug = req.slug;
    vault->fuse_name = req.fuse_name;

    auto policy = freshPolicy(req.type);
    applySync(*policy, req.type, req.sync);

    // Provisioning (#237) runs after every check that can refuse without touching the provider, and is compensated if
    // anything after it fails: a bucket this attempt created is deleted only while empty, an adoption is released.
    upstream::ProvisionTicket ticket;
    if (provisioning) {
        const auto s3 = std::static_pointer_cast<S3Vault>(vault);
        ticket = upstream::beginProvision(actor, s3->api_key_id, req.name, s3->bucket, *req.s3->provision);
        s3->bucket = ticket.bucket;
    }

    std::shared_ptr<S3Vault> needsWaiver;
    try {
        if (req.type == VaultType::S3) {
            const auto s3 = std::static_pointer_cast<S3Vault>(vault);
            if (ticket.mode != upstream::BucketMode::Create && bucketHoldsData(*s3)) {
                // An accepted adoption is the informed acceptance: its confirmation text carried the waiver.
                const bool accepted = req.accept_waiver || (ticket.active() && ticket.mode == upstream::BucketMode::Adopt);
                if (!accepted) throw NeedsConfirmation("encryption_waiver", waiverTextFor(*s3));
                needsWaiver = s3;
            }
        }

        vault = runtime::Deps::get().storageManager->addVault(vault, policy);
    } catch (const std::exception& e) {
        upstream::abortProvision(ticket, e.what());
        throw;
    }
    if (needsWaiver) {
        try {
            recordWaiver(actor, std::static_pointer_cast<S3Vault>(vault));
        } catch (const std::exception& e) {
            runtime::Deps::get().storageManager->removeVault(vault->id);
            upstream::abortProvision(ticket, e.what());
            throw;
        }
    }
    if (ticket.active()) (void)upstream::finishProvision(actor, ticket, vault->id, *req.s3->provision);
    return vault;
}

VaultPtr update(const Actor& actor, const Update& req) {
    requireActor(actor);
    const auto existing = requireVault(req.id);
    if (!canOnVault(actor, VaultPerm::Edit, existing->id)) throw Denied("you do not have permission to edit this vault");

    auto staged = copyOf(existing);
    if (req.name) {
        if (req.name->empty()) throw Invalid("vault name cannot be empty");
        if (*req.name != existing->name && db::query::vault::Vault::vaultExists(*req.name, req.owner_id.value_or(existing->owner_id)))
            throw Conflict("a vault named '" + *req.name + "' already exists for this owner");
        staged->name = *req.name;
    }
    if (req.description) staged->description = *req.description;
    if (req.quota) staged->quota = *req.quota;
    if (req.slug) staged->slug = *req.slug;
    if (req.fuse_name) staged->fuse_name = *req.fuse_name;
    if (req.is_active) staged->is_active = *req.is_active;
    if (req.owner_id && *req.owner_id != existing->owner_id) {
        requireTransferable(actor, existing->id, *req.owner_id);
        if (req.name && *req.name != existing->name && db::query::vault::Vault::vaultExists(*req.name, *req.owner_id))
            throw Conflict("the new owner already has a vault named '" + *req.name + "'");
        staged->owner_id = *req.owner_id;
    }

    bool encryptionChanged = false;
    if (existing->type == VaultType::S3) {
        const auto s3 = std::static_pointer_cast<S3Vault>(staged);
        const auto before = std::static_pointer_cast<S3Vault>(existing);
        if (req.api_key_id && *req.api_key_id != before->api_key_id) {
            requireConsume(actor, *req.api_key_id);
            s3->api_key_id = *req.api_key_id;
        }
        if (req.bucket) {
            if (req.bucket->empty()) throw Invalid("bucket cannot be empty");
            s3->bucket = *req.bucket;
        }
        if (s3->api_key_id != before->api_key_id || s3->bucket != before->bucket) {
            requireBucketUnprotected(s3->api_key_id, s3->bucket);
            if (const auto owner = db::query::vault::Vault::bucketOwner(s3->api_key_id, s3->bucket);
                owner && owner->vault_id != existing->id)
                throw Conflict("bucket '" + s3->bucket + "' is already the storage of " +
                               std::string(owner->deleted ? "deleted vault '" : "vault '") + owner->vault_name + "' (ID " +
                               std::to_string(owner->vault_id) + ") with this API key");
        }
        // The tier is provider-specific: re-normalize whenever it or the key (provider) changes.
        if (req.storage_tier || s3->api_key_id != before->api_key_id)
            s3->storage_tier_id = normalizedTier(s3->api_key_id, req.storage_tier ? *req.storage_tier : s3->storage_tier_id);
        if (req.encrypt_upstream && *req.encrypt_upstream != before->encrypt_upstream) {
            s3->encrypt_upstream = *req.encrypt_upstream;
            encryptionChanged = true;
        }
    } else if (req.api_key_id || req.bucket || req.storage_tier || req.encrypt_upstream) {
        throw Invalid("API key, bucket, storage tier and encryption only apply to S3 vaults");
    }

    if (encryptionChanged) {
        if (!rbac::resolver::Vault::has<SyncActionPerm>({.user = actor, .permission = SyncActionPerm::SignWaiver,
                                                        .vault_id = existing->id}))
            throw Denied("changing upstream encryption requires the vault's sign-waiver permission");
        const auto s3 = std::static_pointer_cast<S3Vault>(staged);
        if (bucketHoldsData(*s3) && !req.accept_waiver) throw NeedsConfirmation("encryption_waiver", waiverTextFor(*s3));
    }

    PolicyPtr newPolicy;
    if (!req.sync.empty()) {
        if (!rbac::resolver::Vault::has<SyncConfigPerm>({.user = actor, .permission = SyncConfigPerm::Edit,
                                                        .vault_id = existing->id}))
            throw Denied("you do not have permission to change this vault's sync settings");
        newPolicy = copyPolicy(currentPolicy(existing->id), existing->type);
        applySync(*newPolicy, existing->type, req.sync);
    }

    if (newPolicy) db::query::vault::Vault::updateVaultSync(newPolicy, existing->type);
    runtime::Deps::get().storageManager->updateVault(staged);
    if (encryptionChanged) recordWaiver(actor, std::static_pointer_cast<S3Vault>(staged));
    if (newPolicy) pushSyncToEngine(existing->id, currentPolicy(existing->id));
    return requireVault(existing->id);
}

void requireTransferable(const Actor& actor, const unsigned int vaultId, const unsigned int newOwnerId) {
    requireActor(actor);
    const auto vault = requireVault(vaultId);
    const auto actorState = actor->state();
    if (!actor->isSuperAdmin() &&
        !(actorState->authorizing() && actorState->roles.admin && ops::users::isAdminIdentity(*actorState->roles.admin)))
        throw Denied("only administrators can transfer vault ownership");
    if (!canOnVault(actor, VaultPerm::Edit, vaultId)) throw Denied("you do not have permission to edit vault " + vault->name);
    if (!vh::identities::manager().user(newOwnerId)) throw NotFound("owner not found: " + std::to_string(newOwnerId));
    // Handing a vault to someone is creating one for them.
    if (!canCreateFor(actor, newOwnerId)) throw Denied("you do not have permission to give vaults to that owner");
    if (newOwnerId != vault->owner_id && db::query::vault::Vault::vaultExists(vault->name, newOwnerId))
        throw Conflict("the new owner already has a vault named '" + vault->name + "'");
}

void requireRemovable(const Actor& actor, const unsigned int vaultId) {
    requireActor(actor);
    const auto vault = requireVault(vaultId);
    if (!canOnVault(actor, VaultPerm::Remove, vaultId)) throw Denied("you do not have permission to remove vault " + vault->name);
}

DeletionPtr remove(const Actor& actor, const Remove& req) {
    requireActor(actor);
    if (req.id == 0) throw Invalid("vault ID must be a positive integer");
    const auto live = runtime::Deps::get().storageManager->getVault(req.id);

    if (!live) {
        // Already deleted: only "now" (purge it on the next pass) means anything.
        const auto pending = db::query::vault::Deletion::get(req.id);
        if (!pending || pending->state == vault::model::DeletionState::Purged)
            throw NotFound("vault not found: " + std::to_string(req.id));
        if (!canRemoveDeleted(actor, *pending)) throw Denied("you do not have permission to remove this vault");
        if (!req.now)
            throw Conflict("vault '" + pending->vault_name + "' is already deleted (purge after " + when(pending->purge_after) +
                           "): restore it with `vh vault restore " + std::to_string(req.id) + "`, or purge it now with --now");
        const bool deleteUpstream = pending->isS3() && req.delete_upstream.value_or(pending->delete_upstream);
        if (req.delete_upstream && *req.delete_upstream && !pending->isS3())
            throw Invalid("only S3 vaults have upstream data to delete");
        if (pending->isS3() && pending->upstream_purged_at && !deleteUpstream)
            throw Conflict("the upstream data of vault '" + pending->vault_name + "' is already deleted");
        // The delete already answered the key question; only switching to "keep upstream" asks it again.
        requireKeyLossAccepted(pending->isS3() && pending->encrypt_upstream.value_or(true) && pending->delete_upstream &&
                                   !deleteUpstream && !pending->keyExported(),
                               req.accept_key_loss, pending->vault_name, pending->bucket.value_or(""),
                               vault::model::keyExportCommand(req.id),
                               std::chrono::seconds(pending->key_retain_until - pending->deleted_at));
        requireNowConfirmed(req.confirm_now, pending->vault_name);
        if (!vault::retention::expedite(req.id, pending->isS3() ? std::optional<bool>(deleteUpstream) : std::nullopt))
            throw Conflict("vault '" + pending->vault_name + "' was purged meanwhile");
        log::Registry::audit()->info("[ops::vaults] {} expedited the purge of deleted vault {} ('{}')", actor->name(), req.id,
                                     pending->vault_name);
        return db::query::vault::Deletion::get(req.id);
    }

    if (!canOnVault(actor, VaultPerm::Remove, req.id)) throw Denied("you do not have permission to remove this vault");
    const bool isS3 = live->type == VaultType::S3;
    if (req.delete_upstream && *req.delete_upstream && !isS3) throw Invalid("only S3 vaults have upstream data to delete");
    const bool deleteUpstream = isS3 && req.delete_upstream.value_or(false);

    if (isS3) {
        const auto s3 = std::static_pointer_cast<S3Vault>(live);
        requireKeyLossAccepted(s3->encrypt_upstream && !deleteUpstream &&
                                   !db::query::vault::Key::currentKeyExportedAt(req.id).has_value(),
                               req.accept_key_loss, live->name, s3->bucket, vault::model::keyExportCommand(req.id),
                               vault::retention::windowsFor(live->type).key_retention_window);
    }
    if (req.now) requireNowConfirmed(req.confirm_now, live->name);

    try {
        auto record = vault::retention::schedule(req.id, actor->id, req.now, deleteUpstream);
        log::Registry::audit()->info("[ops::vaults] {} deleted vault {} ('{}'){}{}", actor->name(), req.id, live->name,
                                     req.now ? ", purge now" : "", deleteUpstream ? ", with its upstream data" : "");
        return record;
    } catch (const std::runtime_error& e) {
        // A concurrent delete of the same vault won the row lock.
        if (!runtime::Deps::get().storageManager->getVault(req.id)) throw NotFound("vault not found: " + std::to_string(req.id));
        throw;
    }
}

RemovalPlan removalPlan(const Actor& actor, const unsigned int vaultId) {
    requireActor(actor);
    const auto vault = requireVault(vaultId);
    if (!canOnVault(actor, VaultPerm::Remove, vaultId)) throw Denied("you do not have permission to remove vault " + vault->name);

    const auto windows = vault::retention::windowsFor(vault->type);
    RemovalPlan plan{.vault = vault,
                     .provider = {},
                     .bucket = {},
                     .encrypted_upstream = false,
                     .key_version = 0,
                     .key_exported_at = db::query::vault::Key::currentKeyExportedAt(vaultId),
                     .retention_window = windows.retention_window,
                     .key_retention_window = windows.key_retention_window,
                     .export_command = vault::model::keyExportCommand(vaultId)};
    if (const auto key = db::query::vault::Key::getVaultKey(vaultId)) plan.key_version = key->version;
    if (vault->type == VaultType::S3) {
        const auto s3 = std::static_pointer_cast<S3Vault>(vault);
        plan.bucket = s3->bucket;
        plan.encrypted_upstream = s3->encrypt_upstream;
        if (const auto key = db::query::vault::APIKey::getAPIKey(s3->api_key_id))
            plan.provider = vault::model::to_string(key->provider);
    }
    return plan;
}

std::vector<DeletionPtr> listDeleted(const Actor& actor) {
    requireActor(actor);
    auto all = db::query::vault::Deletion::list();
    std::erase_if(all, [&](const DeletionPtr& d) { return !d || !canRemoveDeleted(actor, *d); });
    return all;
}

VaultPtr restore(const Actor& actor, const unsigned int vaultId) {
    requireActor(actor);
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    const auto d = db::query::vault::Deletion::get(vaultId);
    if (!d) throw NotFound("no deleted vault with ID " + std::to_string(vaultId));
    if (!canRemoveDeleted(actor, *d)) throw Denied("you do not have permission to restore vault " + d->vault_name);
    if (!d->restorable())
        throw Conflict("vault '" + d->vault_name + "' can no longer be restored: its purge " +
                       (d->state == vault::model::DeletionState::Purged ? std::string("has finished") : std::string("has started")));
    auto restored = vault::retention::restore(vaultId);
    if (!restored) throw Conflict("vault '" + d->vault_name + "' can no longer be restored: its purge has started");
    log::Registry::audit()->info("[ops::vaults] {} restored vault {} ('{}')", actor->name(), vaultId, d->vault_name);
    return restored;
}

DeletionPtr findDeleted(const Actor& actor, const std::string& idOrName, const std::optional<unsigned int> ownerId) {
    requireActor(actor);
    DeletionPtr d;
    bool numeric = !idOrName.empty() && std::ranges::all_of(idOrName, [](const unsigned char c) { return std::isdigit(c) != 0; });
    if (numeric && idOrName.size() < 10) d = db::query::vault::Deletion::get(static_cast<unsigned int>(std::stoul(idOrName)));
    if (!d) d = db::query::vault::Deletion::findByName(idOrName, ownerId.value_or(actor->id));
    if (!d && !ownerId) d = db::query::vault::Deletion::findByName(idOrName, std::nullopt);
    if (!d || !canRemoveDeleted(actor, *d)) throw NotFound("no deleted vault '" + idOrName + "'");
    return d;
}

Details get(const Actor& actor, const unsigned int vaultId) {
    requireActor(actor);
    if (!canOnVault(actor, VaultPerm::View, vaultId)) throw Denied("you do not have permission to view this vault");
    Details out{.vault = requireVault(vaultId), .sync = nullptr, .owner_name = {}};
    out.sync = currentPolicy(vaultId);
    if (const auto owner = vh::identities::manager().user(out.vault->owner_id)) out.owner_name = owner->name();
    return out;
}

std::vector<VaultPtr> list(const Actor& actor, db::model::ListQueryParams params,
                           const std::optional<vault::model::VaultType> type) {
    requireActor(actor);
    const auto& perms = actor->vaultsPerms();
    if (perms.self.canView() && !(perms.admin.canView() || perms.user.canView()))
        return db::query::vault::Vault::listUserVaults(actor->id, type, std::move(params));

    auto vaults = db::query::vault::Vault::listVaults(type, std::move(params));
    std::erase_if(vaults, [&](const VaultPtr& v) { return !v || !canOnVault(actor, VaultPerm::View, v->id); });
    return vaults;
}

PolicyPtr updateSync(const Actor& actor, const unsigned int vaultId, const SyncPatch& patch) {
    requireActor(actor);
    const auto vault = requireVault(vaultId);
    if (!rbac::resolver::Vault::has<SyncConfigPerm>({.user = actor, .permission = SyncConfigPerm::Edit, .vault_id = vaultId}))
        throw Denied("you do not have permission to change this vault's sync settings");
    if (patch.empty()) throw Invalid("no sync settings to change");

    auto policy = copyPolicy(currentPolicy(vaultId), vault->type);
    applySync(*policy, vault->type, patch);
    db::query::vault::Vault::updateVaultSync(policy, vault->type);
    pushSyncToEngine(vaultId, policy);
    return policy;
}

SyncStart triggerSync(const Actor& actor, const unsigned int vaultId) {
    requireActor(actor);
    if (!rbac::resolver::Vault::has<SyncActionPerm>({.user = actor, .permission = SyncActionPerm::Trigger, .vault_id = vaultId}))
        throw Denied("you do not have permission to trigger a sync for this vault");
    (void)requireVault(vaultId);
    using RunNowResult = sync::Controller::RunNowResult;
    switch (runtime::Deps::get().syncController->runNow(vaultId)) {
        case RunNowResult::Started: return SyncStart::Started;
        case RunNowResult::Rerun: return SyncStart::RerunQueued;
        case RunNowResult::NoTask:
        default:
            throw NotFound("no sync task is loaded for vault " + std::to_string(vaultId) +
                           "; nothing was started (is its storage engine initialized?)");
    }
}

}
