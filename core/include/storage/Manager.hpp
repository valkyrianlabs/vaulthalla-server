#pragma once

#include <mutex>
#include <vector>
#include <memory>
#include <map>
#include <string>
#include <filesystem>
#include <unordered_map>
#include "fs/Inode.hpp"
#include "identities/Fwd.hpp"
#include "storage/Fwd.hpp"
#include "sync/Fwd.hpp"
#include "vault/Fwd.hpp"

namespace vh::storage {

class Manager {
public:
    Manager();

    void initStorageEngines();

    std::vector<std::shared_ptr<Engine>> getEngines() const;

    std::shared_ptr<Engine> resolveStorageEngine(const std::filesystem::path& fusePath) const;

    void initUserStorage(const std::shared_ptr<identities::User>& user);

    std::shared_ptr<vault::model::Vault> addVault(std::shared_ptr<vault::model::Vault> vault,
                                           const std::shared_ptr<sync::model::Policy>& sync = nullptr);

    void updateVault(const std::shared_ptr<vault::model::Vault>& vault);

    // Rebuilds a vault's engine from its stored row, e.g. after the credentials of the API key it uses changed.
    // No-op for an unknown vault.
    void reloadEngine(unsigned int vaultId);

    // Immediate hard delete (rollbacks, empty S3-gateway buckets): rows, engine, cache and the backing directories.
    // User-initiated deletes go through vault::retention instead.
    void removeVault(unsigned int vaultId);

    // Soft delete (#162), after the vault row was marked deleted: the engine goes, the FS cache forgets the vault and
    // its derived artifacts are purged, so FUSE, sync, shares and the S3 gateway lose it at once. No DB change.
    void retireVault(unsigned int vaultId);

    // Restore, after the vault row was marked live again: rebuilds its engine and re-caches its root.
    std::shared_ptr<vault::model::Vault> reinstateVault(unsigned int vaultId);

    std::shared_ptr<vault::model::Vault> getVault(unsigned int vaultId) const;

    std::shared_ptr<Engine> getEngine(unsigned int id) const;

    // Live vaults whose engine could not start (their keys can't be loaded here, or anything else), by vault id, as
    // last seen by initStorageEngines / reinstateVault / reloadEngine. Health and `vh status` report them.
    struct UnavailableVault {
        unsigned int vault_id{};
        std::string vault_name{};
        std::string reason{};  // vault::KeyUnavailable code (key_missing | key_unsealable | version_missing) or engine_failed
        std::string detail{};
    };
    [[nodiscard]] std::vector<UnavailableVault> unavailableVaults() const;

    void registerOpenHandle(vh::fs::Inode);

    void closeOpenHandle(vh::fs::Inode);

    [[nodiscard]] unsigned int getOpenHandleCount(vh::fs::Inode ino) const;

private:
    mutable std::mutex mutex_, openHandleMutex_;
    std::pmr::unordered_map<std::string, std::shared_ptr<Engine>> engines_;
    std::unordered_map<unsigned int, std::shared_ptr<Engine>> vaultToEngine_;
    std::unordered_map<vh::fs::Inode, int> openHandleCounts_;
    std::map<unsigned int, UnavailableVault> unavailable_;  // guarded by mutex_

    void noteEngineFailure(const vault::model::Vault& vault, const std::exception& e);  // takes mutex_
};

}
