#pragma once

#include <filesystem>
#include <functional>
#include <vector>
#include <memory>
#include <shared_mutex>
#include "fs/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "sync/Fwd.hpp"
#include "vault/Fwd.hpp"
#include "storage/PlaintextReader.hpp"

namespace vh::fs::model {
    struct Path;

}

namespace vh::vault {
    class EncryptionManager;

}

namespace vh::storage {
    namespace fs = std::filesystem;

    enum class StorageType { Local, Cloud };

    struct Engine : std::enable_shared_from_this<Engine> {
        std::shared_ptr<vault::model::Vault> vault;
        std::shared_ptr<sync::model::Policy> sync;
        std::shared_ptr<sync::model::Event> latestSyncEvent;
        std::shared_ptr<vh::fs::model::Path> paths;
        std::shared_ptr<vault::EncryptionManager> encryptionManager;
        std::shared_mutex mutex;

        static constexpr uintmax_t MIN_FREE_SPACE = 10 * 1024 * 1024; // 10 MB

        Engine() = default;

        explicit Engine(const std::shared_ptr<vault::model::Vault> &vault);

        virtual ~Engine() = default;

        void newSyncEvent(uint8_t trigger = 0); // trigger 0: Scheduled
        void saveSyncEvent() const;

        [[nodiscard]] bool isDirectory(const fs::path &rel_path) const;

        [[nodiscard]] bool isFile(const fs::path &rel_path) const;

        // Positioned plaintext access to f's current generation (see storage/PlaintextReader.hpp). Local backing
        // bytes are read in place; a cloud file without a local copy follows ReaderOptions::remote.
        [[nodiscard]] std::unique_ptr<PlaintextReader> openPlaintextReader(
            const std::shared_ptr<vh::fs::model::File> &f, ReaderOptions options = {}) const;

        [[nodiscard]] std::vector<uint8_t> decrypt(const std::shared_ptr<vh::fs::model::File> &f) const;

        [[nodiscard]] std::vector<uint8_t> decrypt(const std::shared_ptr<vh::fs::model::File> &f,
                                                   const std::vector<uint8_t> &payload) const;

        [[nodiscard]] std::vector<uint8_t> decrypt(unsigned int vaultId, const std::filesystem::path &relPath,
                                                   const std::vector<uint8_t> &payload) const;

        void mkdir(const fs::path &relPath, const std::shared_ptr<identities::User>& user);

        void move(const fs::path &from, const fs::path &to, const std::shared_ptr<identities::User>& user);

        void rename(const fs::path &from, const fs::path &to, const std::shared_ptr<identities::User>& user);

        // Copies an entry (a directory with everything under it) within this vault; vault paths. `authorize` sees every
        // source entry and its destination FUSE path before anything is written, and throws to refuse
        // (fs::Filesystem::copy). Throws std::runtime_error naming the reason on any other failure.
        void copy(const fs::path &from, const fs::path &to, unsigned int userId,
                  const std::function<void(const vh::fs::model::Entry &source, const fs::path &destination)> &authorize = {});

        void remove(const fs::path &rel_path, unsigned int userId) const;

        void removeLocally(const std::filesystem::path &rel_path) const;

        void removeLocally(const std::shared_ptr<vh::fs::model::file::Trashed> &f) const;

        [[nodiscard]] static uintmax_t getDirectorySize(const fs::path &path);

        [[nodiscard]] uintmax_t getVaultSize() const;

        [[nodiscard]] uintmax_t getCacheSize() const;

        [[nodiscard]] uintmax_t getVaultAndCacheTotalSize() const;

        // Physical bytes of the vault's recovery blobs (recovery::store), charged to the quota by freeSpace().
        [[nodiscard]] uintmax_t getRecoverySize() const;

        [[nodiscard]] uintmax_t freeSpace() const;

        [[nodiscard]] virtual StorageType type() const { return StorageType::Local; }

        // Drops every derived preview artifact of a file (preview::cache::Store::purgeFile). Best effort: the cache
        // is non-authoritative, so a failure is logged, never thrown. Artifacts are keyed by file id, so rename and
        // move need nothing; call this wherever a file id stops existing (delete, trash, purge).
        void purgeDerivedArtifacts(unsigned int fileId) const;

        [[nodiscard]] std::filesystem::path vaultPathToFusePath(const std::filesystem::path &vPath) const;

        [[nodiscard]] std::filesystem::path fusePathToVaultPath(const std::filesystem::path &fPath) const;

    protected:
        // The backing file is absent. Local vaults: not found. CloudEngine: hydrate / ranged / off.
        [[nodiscard]] virtual std::unique_ptr<PlaintextReader> openMissingReader(
            const std::shared_ptr<vh::fs::model::File> &f, const ReaderOptions &options) const;

        [[nodiscard]] std::unique_ptr<PlaintextReader> openLocalReader(
            const std::shared_ptr<vh::fs::model::File> &f, const ReaderOptions &options) const;
    };
} // namespace vh::storage
