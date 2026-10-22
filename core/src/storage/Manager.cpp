#include "storage/Manager.hpp"
#include "storage/Engine.hpp"
#include "storage/CloudEngine.hpp"
#include "sync/events/Subscriptions.hpp"
#include "config/Registry.hpp"
#include "vault/model/Vault.hpp"
#include "vault/model/S3Vault.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/Path.hpp"
#include "db/query/vault/Vault.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/identities/User.hpp"
#include "fs/cache/Registry.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/seed_db.hpp"
#include "crypto/id/Generator.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "preview/cache/Store.hpp"
#include "sync/Controller.hpp"
#include "vault/Retention.hpp"
#include "vault/EncryptionManager.hpp"

#include <paths.h>
#include <ranges>
#include <string>

using namespace vh::storage;
using namespace vh::vault::model;
using vh::identities::User;
using vh::identities::Group;
using namespace vh::config;
using namespace vh::fs::model;
using namespace vh::crypto;

namespace {

std::string enginePathKey(const std::shared_ptr<Engine>& engine) {
    return engine->paths->absRelToRoot(engine->paths->vaultRoot, PathType::FUSE_ROOT).string();
}

void eraseEnginePathEntry(
    std::pmr::unordered_map<std::string, std::shared_ptr<Engine>>& engines,
    const std::shared_ptr<Engine>& engine) {
    if (!engine || !engine->paths) return;
    engines.erase(enginePathKey(engine));
}

std::filesystem::path fuseRootOf(const std::shared_ptr<Engine>& engine) {
    if (!engine || !engine->paths) return {};
    return engine->paths->absRelToRoot(engine->paths->vaultRoot, PathType::FUSE_ROOT);
}

// The FSCache is keyed by FUSE path; a vault's entries must not outlive it or survive into a vault that reuses its
// FUSE name (#180). They re-hydrate from the DB on the next lookup.
void evictCachedVault(const unsigned int vaultId, const std::filesystem::path& fuseRoot) {
    if (const auto& cache = vh::runtime::Deps::get().fsCache) cache->evictVault(vaultId, fuseRoot);
}

}

namespace {
// What the health surfaces say about a vault whose engine failed to start.
Manager::UnavailableVault unavailableFrom(const vh::vault::model::Vault& vault, const std::exception& e) {
    Manager::UnavailableVault out{.vault_id = vault.id, .vault_name = vault.name, .reason = "engine_failed",
                                  .detail = e.what()};
    if (const auto* keys = dynamic_cast<const vh::vault::KeyUnavailable*>(&e)) out.reason = keys->code();
    return out;
}
}

Manager::Manager() = default;

void Manager::noteEngineFailure(const vh::vault::model::Vault& vault, const std::exception& e) {
    std::scoped_lock lock(mutex_);
    unavailable_[vault.id] = unavailableFrom(vault, e);
}

std::vector<Manager::UnavailableVault> Manager::unavailableVaults() const {
    std::scoped_lock lock(mutex_);
    std::vector<UnavailableVault> out;
    for (const auto& v : unavailable_ | std::views::values) out.push_back(v);
    return out;
}

void Manager::initStorageEngines() {
    log::Registry::storage()->debug("[StorageManager] Initializing storage engines...");
    std::scoped_lock lock(mutex_);

    if (const auto& config = Registry::get().dev; config.enabled && config.init_r2_test_vault) {
        if (const auto admin = vh::identities::manager().userByName("admin")) {
            constexpr uintmax_t r2TestVaultQuotaBytes = 10ull * 1024ull * 1024ull * 1024ull;
            const auto existing = db::query::vault::Vault::getVault("R2 Test Vault", admin->id);
            if (!existing) {
                seed::initDevCloudVault();
            } else if (existing->quota == 0) {
                existing->quota = r2TestVaultQuotaBytes;
                db::query::vault::Vault::upsertVault(existing);
                log::Registry::storage()->info("[StorageManager] Updated R2 Test Vault quota to {} bytes", r2TestVaultQuotaBytes);
            }
        }
    }

    // Both indexes start over: a vault id left in vaultToEngine_ would keep answering getEngine() for a vault that is
    // no longer live (or for a different vault that later takes its id).
    engines_.clear();
    vaultToEngine_.clear();
    unavailable_.clear();

    try {
        for (auto& vault : db::query::vault::Vault::listLiveVaults()) {
            try {
                log::Registry::storage()->debug("[StorageManager] Initializing StorageEngine for Vault {} (ID: {}, Type: {})",
                                              vault->name, vault->id, to_string(vault->type));
                std::shared_ptr<Engine> engine;
                if (vault->type == VaultType::Local) engine = std::make_shared<Engine>(vault);
                else if (vault->type == VaultType::S3) {
                    const auto s3Vault = std::static_pointer_cast<S3Vault>(vault);
                    if (s3Vault->api_key_id == 0 || s3Vault->bucket.empty()) {
                        log::Registry::storage()->warn(
                            "[StorageManager] Skipping S3 vault {} (ID: {}) because upstream API key or bucket metadata is missing",
                            s3Vault->name, s3Vault->id);
                        continue;
                    }
                    engine = std::make_shared<CloudEngine>(s3Vault);
                }
                if (!engine) continue;
                engines_[enginePathKey(engine)] = engine;
                vaultToEngine_[vault->id] = engine;
                unavailable_.erase(vault->id);
            } catch (const std::exception& e) {
                log::Registry::storage()->error("[StorageManager] Skipping vault {} (ID: {}) after engine initialization failed: {}",
                                                vault ? vault->name : "<null>",
                                                vault ? vault->id : 0,
                                                e.what());
                if (vault) {
                    vaultToEngine_.erase(vault->id);
                    unavailable_[vault->id] = unavailableFrom(*vault, e);
                }
            }
        }
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[StorageManager] Error initializing storage engines: {}", e.what());
        throw;
    }
}

std::shared_ptr<Engine> Manager::resolveStorageEngine(const fs::path& fusePath) const {
    std::scoped_lock lock(mutex_);

    fs::path current;
    for (const auto& part : fusePath.lexically_normal()) {
        current /= part;

        // Remove trailing slash by converting to generic form and trimming
        std::string currentStr = current.generic_string();
        if (!currentStr.empty() && currentStr.back() == '/') currentStr.pop_back();

        if (engines_.contains(currentStr)) return engines_.at(currentStr);
    }

    log::Registry::storage()->warn("[StorageManager] No storage engine found for path: {}", fusePath.string());
    log::Registry::storage()->info("[StorageManager] Available storage engines:");
    for (const auto& [path, engine] : engines_)
        log::Registry::storage()->info(" - {} (Vault ID: {}, Type: {})", path, engine->vault->id, to_string(engine->vault->type));

    return nullptr;
}

std::vector<std::shared_ptr<Engine>> Manager::getEngines() const {
    std::scoped_lock lock(mutex_);
    std::vector<std::shared_ptr<Engine>> engines;
    engines.reserve(engines_.size());
    for (const auto& [_, engine] : engines_) engines.push_back(engine);
    return engines;
}

void Manager::initUserStorage(const std::shared_ptr<User>& user) {
    try {
        log::Registry::storage()->debug("[StorageManager] Initializing storage user storage...");

        if (!user || !user->id) throw std::runtime_error("User ID is not set. Cannot initialize storage.");

        // Go through addVault like every other surface: it sets the owner, persists the sync policy and
        // registers the engine under the manager lock. The old direct upsert had no owner or sync policy,
        // so every web-console registration failed after the user row was already written.
        auto vault = std::make_shared<Vault>();
        vault->name = user->name() + "'s Local Disk Vault";
        vault->description = "Default local disk vault for " + user->name();
        vault->owner_id = user->id;
        vault->type = VaultType::Local;
        const auto created = addVault(vault, std::make_shared<sync::model::LocalPolicy>());

        log::Registry::storage()->info("[StorageManager] User storage initialized for user: {} (ID: {}, vault ID: {})",
                                              user->name(), user->id, created->id);
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[StorageManager] Error initializing user storage: {}", e.what());
        throw;
    }
}

std::shared_ptr<Vault> Manager::addVault(std::shared_ptr<Vault> vault,
                                                const std::shared_ptr<sync::model::Policy>& sync) {
    if (!vault) throw std::invalid_argument("Vault cannot be null");
    std::scoped_lock lock(mutex_);

    // One owner can't have two vaults with the same name. Enforced here, where every surface (CLI, ws, S3
    // gateway) converges: the CLI checked this itself but the web console silently created a second vault
    // with a suffixed FUSE name (lab parity smoke).
    if (vault->id == 0 && db::query::vault::Vault::vaultExists(vault->name, vault->owner_id))
        throw std::runtime_error("A vault named '" + vault->name + "' already exists for this owner");

    vault->mount_point = id::Generator({ .namespace_token = vault->name }).generate();
    vault->id = db::query::vault::Vault::upsertVault(vault, sync);
    vault = db::query::vault::Vault::getVault(vault->id);
    // Before the engine creates and caches the new root: a deleted vault's entries at this FUSE name must not leak
    // into it (the root itself can only be cached by mkVault, so this can't run afterwards).
    evictCachedVault(vault->id, makeAbsolute(vault->effectiveFuseName()));
    std::shared_ptr<Engine> engine;
    if (vault->type == VaultType::S3) {
        engine = std::make_shared<CloudEngine>(std::static_pointer_cast<S3Vault>(vault));
    } else {
        engine = std::make_shared<Engine>(vault);
    }
    // One engine per vault id, in both indexes (updateVault and reloadEngine keep the same rule): an engine already
    // registered under this id at another FUSE root would stay in engines_ and answer getEngines() scans and path
    // lookups for this vault with another vault's paths and key. A test process that resets the schema reuses ids.
    if (const auto it = vaultToEngine_.find(vault->id); it != vaultToEngine_.end())
        eraseEnginePathEntry(engines_, it->second);
    engines_[enginePathKey(engine)] = engine;
    vaultToEngine_[vault->id] = engine;

    log::Registry::storage()->info("[StorageManager] Added new vault with ID: {}, Name: {}, Type: {}",
                                              vault->id, vault->name, to_string(vault->type));

    return vault;
}

void Manager::updateVault(const std::shared_ptr<Vault>& vault) {
    if (!vault) throw std::invalid_argument("Vault cannot be null");
    if (vault->id == 0) throw std::invalid_argument("Vault ID cannot be zero");
    std::scoped_lock lock(mutex_);
    const auto oldEngineIt = vaultToEngine_.find(vault->id);
    const auto oldEngine = oldEngineIt != vaultToEngine_.end() ? oldEngineIt->second : nullptr;
    const auto oldFuseRoot = oldEngine && oldEngine->paths
        ? oldEngine->paths->absRelToRoot(oldEngine->paths->vaultRoot, PathType::FUSE_ROOT)
        : std::filesystem::path{};

    db::query::vault::Vault::upsertVault(vault);
    const auto refreshed = db::query::vault::Vault::getVault(vault->id);
    if (!refreshed) throw std::runtime_error("Failed to reload updated vault with ID " + std::to_string(vault->id));

    std::shared_ptr<Engine> engine;
    if (refreshed->type == VaultType::S3) {
        engine = std::make_shared<CloudEngine>(std::static_pointer_cast<S3Vault>(refreshed));
    } else {
        engine = std::make_shared<Engine>(refreshed);
    }

    eraseEnginePathEntry(engines_, oldEngine);
    vaultToEngine_[refreshed->id] = engine;
    engines_[enginePathKey(engine)] = engine;

    const auto newFuseRoot = engine->paths->absRelToRoot(engine->paths->vaultRoot, PathType::FUSE_ROOT);
    if (oldFuseRoot != newFuseRoot) {
        // Cached descendants still carry the old FUSE paths; drop them along with anything stale at the new name.
        evictCachedVault(refreshed->id, oldFuseRoot);
        evictCachedVault(refreshed->id, newFuseRoot);
        if (auto root = db::query::fs::Entry::getFSEntryByPath(refreshed->id, "/")) {
            root->name = refreshed->effectiveFuseName();
            root->base32_alias = refreshed->mount_point.string();
            root->path = "/";
            root->fuse_path = newFuseRoot;
            root->backing_path = vh::paths::getBackingPath() / root->base32_alias;
            db::query::fs::Entry::updateFSEntry(root);
            if (runtime::Deps::get().fsCache) runtime::Deps::get().fsCache->cacheEntry(root);
        }
    }

    log::Registry::storage()->info("[StorageManager] Updated vault with ID: {}", vault->id);
}

void Manager::reloadEngine(const unsigned int vaultId) {
    const auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) return;

    std::shared_ptr<Engine> engine;
    try {
        if (vault->type == VaultType::S3) engine = std::make_shared<CloudEngine>(std::static_pointer_cast<S3Vault>(vault));
        else engine = std::make_shared<Engine>(vault);
    } catch (const std::exception& e) {
        noteEngineFailure(*vault, e);
        throw;
    }

    std::scoped_lock lock(mutex_);
    if (const auto it = vaultToEngine_.find(vaultId); it != vaultToEngine_.end())
        eraseEnginePathEntry(engines_, it->second);
    unavailable_.erase(vaultId);
    vaultToEngine_[vaultId] = engine;
    engines_[enginePathKey(engine)] = engine;
    log::Registry::storage()->info("[StorageManager] Reloaded engine for vault with ID: {}", vaultId);
}

void Manager::removeVault(const unsigned int vaultId) {
    std::shared_ptr<Engine> removed;
    {
        std::scoped_lock lock(mutex_);
        if (const auto it = vaultToEngine_.find(vaultId); it != vaultToEngine_.end()) removed = it->second;
    }
    // The vault's sealed derived artifacts (thumbnails, renders, GLB, transcodes) go with it; the rows cascade.
    if (removed) {
        try {
            preview::cache::Store::purgeVault(removed);
        } catch (const std::exception& e) {
            log::Registry::storage()->warn("[StorageManager] Failed to purge derived artifacts of vault {}: {}", vaultId,
                                           e.what());
        }
    }

    std::string backingAlias;
    {
        std::scoped_lock lock(mutex_);
        const auto oldEngineIt = vaultToEngine_.find(vaultId);
        if (oldEngineIt != vaultToEngine_.end()) eraseEnginePathEntry(engines_, oldEngineIt->second);
        if (removed && removed->vault) backingAlias = removed->vault->mount_point.string();

        db::query::vault::Vault::removeVault(vaultId);

        vaultToEngine_.erase(vaultId);
        unavailable_.erase(vaultId);
        evictCachedVault(vaultId, fuseRootOf(removed));
    }

    // Its backing and cache directories and its recovery store too (#162), through the same path guard as the
    // retention purge.
    if (!backingAlias.empty()) {
        try {
            vault::retention::removeBackingData(backingAlias);
        } catch (const std::exception& e) {
            log::Registry::storage()->warn("[StorageManager] Left the backing data of removed vault {} in place: {}", vaultId,
                                           e.what());
        }
    }
    log::Registry::storage()->info("[StorageManager] Removed vault with ID: {}", vaultId);
}

void Manager::retireVault(const unsigned int vaultId) {
    std::shared_ptr<Engine> retired;
    {
        std::scoped_lock lock(mutex_);
        if (const auto it = vaultToEngine_.find(vaultId); it != vaultToEngine_.end()) {
            retired = it->second;
            eraseEnginePathEntry(engines_, retired);
            vaultToEngine_.erase(it);
        }
        unavailable_.erase(vaultId);
    }
    evictCachedVault(vaultId, fuseRootOf(retired));
    // Derived artifacts are a disposable cache; a restored vault regenerates them on demand.
    if (retired) {
        try {
            preview::cache::Store::purgeVault(retired);
        } catch (const std::exception& e) {
            log::Registry::storage()->warn("[StorageManager] Failed to purge derived artifacts of deleted vault {}: {}", vaultId,
                                           e.what());
        }
    }
    // The sync controller drops the vault's task once its engine is gone.
    if (const auto& sync = runtime::Deps::get().syncController) sync->refreshEngines();
    // Event-driven sync (#96): the vault's bucket rules come down (in the background); upstream data stays.
    sync::events::subscriptions::onVaultRetired(vaultId);
    log::Registry::storage()->info("[StorageManager] Vault {} deleted: engine retired, pending purge", vaultId);
}

std::shared_ptr<Vault> Manager::reinstateVault(const unsigned int vaultId) {
    const auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw std::runtime_error("vault " + std::to_string(vaultId) + " is not live; cannot reinstate it");

    std::shared_ptr<Engine> engine;
    try {
        if (vault->type == VaultType::S3) engine = std::make_shared<CloudEngine>(std::static_pointer_cast<S3Vault>(vault));
        else engine = std::make_shared<Engine>(vault);
    } catch (const std::exception& e) {
        noteEngineFailure(*vault, e);
        throw;
    }

    const auto fuseRoot = fuseRootOf(engine);
    // Nothing of an earlier vault at this FUSE name may linger, then the root comes back (its inode was dropped at
    // delete time; descendants get theirs lazily on lookup, as after a restart).
    evictCachedVault(vaultId, fuseRoot);
    if (auto root = db::query::fs::Entry::getFSEntryByPath(vaultId, "/"); root && runtime::Deps::get().fsCache) {
        const auto& cache = runtime::Deps::get().fsCache;
        root->fuse_path = fuseRoot;
        root->backing_path = vh::paths::getBackingPath() / root->base32_alias;
        if (!root->inode) {
            root->inode = cache->assignInode(fuseRoot);
            db::query::fs::Entry::updateFSEntry(root);
        }
        cache->cacheEntry(root);
    }

    {
        std::scoped_lock lock(mutex_);
        if (const auto it = vaultToEngine_.find(vaultId); it != vaultToEngine_.end()) eraseEnginePathEntry(engines_, it->second);
        vaultToEngine_[vaultId] = engine;
        engines_[enginePathKey(engine)] = engine;
        unavailable_.erase(vaultId);
    }
    if (const auto& sync = runtime::Deps::get().syncController) sync->refreshEngines();
    sync::events::subscriptions::onVaultReinstated(vaultId);
    log::Registry::storage()->info("[StorageManager] Vault {} restored", vaultId);
    return vault;
}

std::shared_ptr<Vault> Manager::getVault(const unsigned int vaultId) const {
    std::scoped_lock lock(mutex_);
    if (vaultToEngine_.contains(vaultId)) return vaultToEngine_.at(vaultId)->vault;
    return db::query::vault::Vault::getVault(vaultId);
}

std::shared_ptr<Engine> Manager::getEngine(const unsigned int id) const {
    std::scoped_lock lock(mutex_);
    if (!vaultToEngine_.contains(id)) {
        log::Registry::storage()->warn("[StorageManager] No engine found for vault ID: {}", id);
        return nullptr;
    }
    return vaultToEngine_.at(id);
}

void Manager::registerOpenHandle(const vh::fs::Inode ino) {
    std::scoped_lock lock(openHandleMutex_);
    ++openHandleCounts_[ino];
}

void Manager::closeOpenHandle(const vh::fs::Inode ino) {
    std::scoped_lock lock(openHandleMutex_);
    if (--openHandleCounts_[ino] == 0) openHandleCounts_.erase(ino);
}

unsigned int Manager::getOpenHandleCount(const vh::fs::Inode ino) const {
    std::scoped_lock lock(openHandleMutex_);
    if (openHandleCounts_.contains(ino)) return openHandleCounts_.at(ino);
    return 0;
}
