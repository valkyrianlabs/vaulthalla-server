#pragma once

#define FUSE_USE_VERSION 35

#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <shared_mutex>
#include <filesystem>
#include <vector>
#include <fuse3/fuse_lowlevel.h>
#include "fs/Fwd.hpp"

namespace vh::stats::model { struct CacheStatsSnapshot; struct CacheStats; }

namespace vh::fs::cache {

class Registry {
public:
    Registry();

    [[nodiscard]] std::shared_ptr<fs::model::Entry> getEntry(const std::filesystem::path& absPath);
    [[nodiscard]] std::shared_ptr<fs::model::Entry> getEntry(fuse_ino_t ino);
    [[nodiscard]] std::shared_ptr<fs::model::Entry> getEntryById(unsigned int id);

    fuse_ino_t assignInode(const std::filesystem::path& path);
    fuse_ino_t getOrAssignInode(const std::filesystem::path& path);
    fuse_ino_t resolveInode(const std::filesystem::path& absPath);
    std::filesystem::path resolvePath(fuse_ino_t ino);
    void linkPath(const std::filesystem::path& absPath, fuse_ino_t ino);
    void decrementInodeRef(fuse_ino_t ino, uint64_t nlookup);

    void cacheEntry(const std::shared_ptr<fs::model::Entry>& entry, bool isFirstSeeding = false);
    void updateEntry(const std::shared_ptr<fs::model::Entry>& entry);
    [[nodiscard]] bool entryExists(const std::filesystem::path& absPath) const;
    std::shared_ptr<fs::model::Entry> getEntryFromInode(fuse_ino_t ino) const;

    void evictIno(fuse_ino_t ino);
    void evictId(unsigned int id);
    void evictPath(const std::filesystem::path& path);

    // Drops every cached entry, inode and path of vault `vaultId`, and anything cached under `fuseRoot` (the vault's
    // FUSE root; empty or "/" matches no paths). Used when a vault is removed, renamed or created, so a reused FUSE
    // name never resolves to a deleted vault's entries (#180). Entries re-hydrate from the DB on the next lookup.
    void evictVault(unsigned int vaultId, const std::filesystem::path& fuseRoot);

    // Re-reads the subtree totals of directory `dirId` and its ancestors into the cached entries (fs.dir.list serves
    // them from here) after the database changed them. False when the directory no longer exists.
    bool refreshDirStats(unsigned int dirId);

    std::vector<std::shared_ptr<fs::model::Entry>> listDir(unsigned int parentId, bool recursive = false) const;

    std::shared_ptr<stats::model::CacheStatsSnapshot> stats() const;

    std::string dump() const;

private:
    mutable std::shared_mutex mutex_;
    std::shared_ptr<stats::model::CacheStats> stats_;
    fuse_ino_t nextInode_ = 2;
    std::unordered_map<fuse_ino_t, std::filesystem::path> inodeToPath_;
    std::unordered_map<std::filesystem::path, fuse_ino_t> pathToInode_;
    std::unordered_map<fuse_ino_t, std::shared_ptr<fs::model::Entry>> inodeToEntry_;
    std::pmr::unordered_map<std::filesystem::path, std::shared_ptr<fs::model::Entry>> pathToEntry_;
    std::unordered_map<fuse_ino_t, unsigned int> inodeToId_;
    std::unordered_map<unsigned int, std::shared_ptr<fs::model::Entry>> idToEntry_;
    std::unordered_map<unsigned int, unsigned int> childToParent_;
    std::unordered_map<unsigned int, std::unordered_set<unsigned int>> parentToChildren_;  // inverse of childToParent_

    // Keep childToParent_ and parentToChildren_ in step (callers hold mutex_ exclusively).
    void linkChild(unsigned int id, const std::optional<unsigned int>& parentId);
    void unlinkChild(unsigned int id);

    void initRoot();
    void restoreCache();
};

}
