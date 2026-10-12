#include "vault/Retention.hpp"

#include "config/Registry.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/query/vault/Deletion.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <paths.h>
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <cctype>
#include <mutex>
#include <system_error>

namespace vh::vault::retention {

namespace {

using DeletionQuery = db::query::vault::Deletion;

std::atomic<bool> passRequested{false};
std::mutex passMutex;
std::mutex factoryMutex;
ControllerFactory controllerFactory;

constexpr unsigned int kClaimPerPass = 16;
constexpr auto kDeferredRetry = std::chrono::seconds(0);

bool isAliasName(const std::string& alias) {
    if (alias.empty() || alias.size() > 128 || alias == "." || alias == "..") return false;
    return std::ranges::all_of(alias, [](const unsigned char c) { return std::isalnum(c) != 0 || c == '_' || c == '-'; });
}

std::string trimmed(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back()))) value.pop_back();
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front()))) value.erase(value.begin());
    return value;
}

// 30 s, 60 s, 2 min ... capped at an hour.
std::chrono::seconds backoff(const unsigned int attempts) {
    const auto shift = std::min(attempts, 7u);
    return std::min<std::chrono::seconds>(std::chrono::seconds(30) * (1u << shift), std::chrono::hours(1));
}

std::shared_ptr<storage::s3::Controller> controllerFor(const model::S3Vault& vault) {
    {
        std::scoped_lock lock(factoryMutex);
        if (controllerFactory) return controllerFactory(vault);
    }
    const auto& keys = runtime::Deps::get().apiKeyManager;
    if (!keys) throw std::runtime_error("API key manager is not available");
    const auto key = keys->getAPIKey(vault.api_key_id);
    if (!key) throw std::runtime_error("API key " + std::to_string(vault.api_key_id) + " no longer exists");
    return std::make_shared<storage::s3::Controller>(key, vault.bucket);
}

// Deletes the bucket's objects, one listed page at a time, within the per-pass caps. Every page is listed from the
// start: what was deleted is gone, so a pass after a restart picks up where the last one stopped. True when the
// bucket listed empty.
// Why the bucket's objects must not be deleted, if anything forbids it: the binding is gone (another vault took the
// bucket over) or another vault uses the same bucket on the same endpoint. Defense in depth: never delete objects
// another vault may own.
std::optional<std::string> upstreamBlocker(const model::Deletion& d, std::shared_ptr<model::S3Vault>& s3) {
    s3 = std::dynamic_pointer_cast<model::S3Vault>(DeletionQuery::getDeletedVault(d.vault_id));
    if (!s3 || s3->api_key_id == 0 || s3->bucket.empty()) return "the vault's bucket binding is gone";
    if (const auto others = DeletionQuery::otherVaultsOnBucket(d.vault_id); !others.empty()) {
        std::string names;
        for (const auto& name : others) names += (names.empty() ? "" : ", ") + name;
        return "bucket '" + s3->bucket + "' is also used by " + names;
    }
    return std::nullopt;
}

bool purgeUpstreamPass(const model::Deletion& d, const model::S3Vault& s3Vault,
                       const std::function<bool()>& stopRequested) {
    const auto* s3 = &s3Vault;
    const auto controller = controllerFor(*s3);
    controller->setRequestBudget({
        .max_list_requests = kUpstreamListsPerPass,
        .max_head_requests = 0,
        .max_get_requests = 0,
        .max_put_requests = 0,
        .max_copy_requests = 0,
        .max_delete_requests = kUpstreamDeletesPerPass,
        .max_downloaded_bytes = 0
    });

    uint64_t deleted = 0;
    try {
        while (!(stopRequested && stopRequested())) {
            const auto page = controller->listObjectKeysPage({}, 1000);
            if (page.keys.empty()) {
                log::Registry::audit()->info("[VaultRetention] Upstream data of vault {} ('{}') deleted from bucket '{}' ({} objects this pass)",
                                             d.vault_id, d.vault_name, s3->bucket, deleted);
                return true;
            }
            for (const auto& key : page.keys) {
                if (stopRequested && stopRequested()) return false;
                try {
                    controller->deleteObject(key);
                } catch (const storage::s3::ObjectNotFound&) {
                    // Already gone: the goal.
                }
                ++deleted;
            }
        }
    } catch (const storage::s3::RequestBudgetExceeded&) {
        // This pass's share is used up; the next pass continues.
    }
    log::Registry::vaulthalla()->info("[VaultRetention] Vault {}: deleted {} upstream objects this pass, continuing later",
                                      d.vault_id, deleted);
    return false;
}

enum class PurgeOutcome { Purged, Deferred };

PurgeOutcome purgeOne(const model::Deletion& d, const std::function<bool()>& stopRequested) {
    std::optional<std::string> note;
    if (d.delete_upstream && d.isS3() && !d.upstream_purged_at) {
        std::shared_ptr<model::S3Vault> s3;
        if (const auto blocker = upstreamBlocker(d, s3)) {
            note = "upstream data kept: " + *blocker;
            log::Registry::audit()->warn("[VaultRetention] Vault {} ('{}'): {}", d.vault_id, d.vault_name, *note);
        } else {
            if (!purgeUpstreamPass(d, *s3, stopRequested)) return PurgeOutcome::Deferred;
            DeletionQuery::markUpstreamPurged(d.vault_id);
        }
    }

    const auto alias = trimmed(d.backing_alias);
    if (DeletionQuery::backingAliasShared(d.vault_id, alias))
        throw PathGuardError("another vault uses backing directory '" + alias + "'; nothing was removed");
    removeBackingData(alias);
    DeletionQuery::finishPurge(d.vault_id, note);
    log::Registry::audit()->info("[VaultRetention] Vault {} ('{}') purged{}; its key is kept until the key retention window ends",
                                 d.vault_id, d.vault_name, d.delete_upstream && d.isS3() ? " with its upstream data" : "");
    return PurgeOutcome::Purged;
}

}

Windows windowsFor(const model::VaultType type) {
    const auto& cfg = config::Registry::get().vaults;
    return {
        .retention_window = cfg.retention_window,
        .key_retention_window = type == model::VaultType::S3 ? cfg.s3.tpm_retention_window : cfg.tpm_retention_window
    };
}

bool removeVaultDirectory(const std::filesystem::path& root, const std::string& rawAlias) {
    namespace fs = std::filesystem;
    const auto alias = trimmed(rawAlias);
    if (!isAliasName(alias)) throw PathGuardError("refusing to remove '" + rawAlias + "': not a vault directory name");

    std::error_code ec;
    if (!fs::is_directory(root, ec)) return false;
    const auto canonicalRoot = fs::canonical(root, ec);
    if (ec || canonicalRoot == canonicalRoot.root_path())
        throw PathGuardError("refusing to remove under '" + root.string() + "': not a usable root");

    const auto target = root / alias;
    const auto status = fs::symlink_status(target, ec);
    if (ec || status.type() == fs::file_type::not_found) return false;
    if (status.type() == fs::file_type::symlink)
        throw PathGuardError("refusing to remove '" + target.string() + "': it is a symlink");
    if (status.type() != fs::file_type::directory)
        throw PathGuardError("refusing to remove '" + target.string() + "': not a directory");

    const auto resolved = fs::canonical(target, ec);
    if (ec || resolved.parent_path() != canonicalRoot || resolved == canonicalRoot)
        throw PathGuardError("refusing to remove '" + target.string() + "': it resolves outside '" + canonicalRoot.string() + "'");

    // remove_all never follows symlinks inside the tree: a link to elsewhere is removed, not its target.
    fs::remove_all(resolved);
    return true;
}

void removeBackingData(const std::string& alias) {
    const auto backing = paths::getBackingPath();
    auto cache = paths::getCachePath();
    if (cache.is_absolute()) cache = cache.relative_path();
    removeVaultDirectory(backing, alias);
    removeVaultDirectory(backing / cache, alias);
}

DeletionPtr schedule(const unsigned int vaultId, const std::optional<unsigned int> deletedBy, const bool now,
                     const bool deleteUpstream) {
    const auto& storage = runtime::Deps::get().storageManager;
    const auto vault = storage ? storage->getVault(vaultId) : nullptr;
    if (!vault) throw std::runtime_error("vault " + std::to_string(vaultId) + " not found");
    const auto windows = windowsFor(vault->type);

    auto record = DeletionQuery::schedule({
        .vault_id = vaultId,
        .deleted_by = deletedBy,
        .delete_upstream = deleteUpstream && vault->type == model::VaultType::S3,
        .retention_window = now ? std::chrono::seconds(0) : windows.retention_window,
        .key_retention_window = windows.key_retention_window
    });
    storage->retireVault(vaultId);
    log::Registry::audit()->info("[VaultRetention] Vault {} ('{}') deleted by user {}: {}; key kept until the retention window ends",
                                 vaultId, vault->name, deletedBy ? std::to_string(*deletedBy) : std::string("system"),
                                 now ? "purge now" : "restorable until the retention window ends");
    if (now) requestPass();
    return record;
}

std::shared_ptr<model::Vault> restore(const unsigned int vaultId) {
    if (!DeletionQuery::restore(vaultId)) return nullptr;
    auto vault = runtime::Deps::get().storageManager->reinstateVault(vaultId);
    log::Registry::audit()->info("[VaultRetention] Vault {} ('{}') restored", vaultId, vault ? vault->name : "?");
    return vault;
}

bool expedite(const unsigned int vaultId, const std::optional<bool> deleteUpstream) {
    if (!DeletionQuery::expedite(vaultId, deleteUpstream)) return false;
    requestPass();
    return true;
}

PassResult runPass(const Clock::time_point now, const std::function<bool()>& stopRequested) {
    std::scoped_lock lock(passMutex);
    PassResult result;

    for (const auto& d : DeletionQuery::claimDue(now, kClaimPerPass)) {
        if (stopRequested && stopRequested()) {
            // Claimed but not started: the next pass (or the next start) resumes it.
            DeletionQuery::deferPurge(d->vault_id, now);
            continue;
        }
        try {
            if (purgeOne(*d, stopRequested) == PurgeOutcome::Purged) ++result.purged;
            else {
                DeletionQuery::deferPurge(d->vault_id, now + kDeferredRetry);
                ++result.deferred;
            }
        } catch (const std::exception& e) {
            ++result.failed;
            const auto retry = backoff(d->attempts);
            log::Registry::vaulthalla()->warn("[VaultRetention] Purge of vault {} ('{}') failed (attempt {}), retrying in {}s: {}",
                                              d->vault_id, d->vault_name, d->attempts, retry.count(), e.what());
            try {
                DeletionQuery::recordFailure(d->vault_id, e.what(), now + retry);
            } catch (const std::exception& recordError) {
                log::Registry::vaulthalla()->error("[VaultRetention] Could not record the failed purge of vault {}: {}",
                                                   d->vault_id, recordError.what());
            }
        }
    }

    const auto expired = DeletionQuery::expireKeys(now);
    result.keys_expired = static_cast<unsigned int>(expired.size());
    for (const auto id : expired)
        log::Registry::audit()->info("[VaultRetention] Key retention ended for deleted vault {}: its sealed key copies were "
                                     "removed (the tombstone record stays)", id);
    return result;
}

void requestPass() { passRequested.store(true, std::memory_order_release); }

bool takePassRequest() { return passRequested.exchange(false, std::memory_order_acq_rel); }

void setControllerFactoryForTesting(ControllerFactory factory) {
    std::scoped_lock lock(factoryMutex);
    controllerFactory = std::move(factory);
}

RetainedKey retainedKey(const unsigned int vaultId) {
    const auto keys = DeletionQuery::retainedKeys(vaultId);
    if (keys.empty()) throw std::runtime_error("no key is retained for deleted vault " + std::to_string(vaultId));
    crypto::secrets::KeyProvider tpm(paths::testMode ? "test_vault_master" : "vault_master");
    tpm.init();
    RetainedKey out{.key = crypto::util::decrypt_aes256_gcm(keys.front()->encrypted_key, tpm.getMasterKey(), keys.front()->iv),
                    .record = keys.front()};
    if (out.key.size() != 32) {
        sodium_memzero(out.key.data(), out.key.size());
        throw std::runtime_error("retained key of deleted vault " + std::to_string(vaultId) + " is not a 32-byte AES key");
    }
    return out;
}

}
