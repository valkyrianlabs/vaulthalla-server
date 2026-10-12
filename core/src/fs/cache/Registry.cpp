#include "fs/cache/Registry.hpp"

#include "fs/model/Entry.hpp"
#include "fs/model/Directory.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/encoding/timestamp.hpp"
#include "log/Registry.hpp"
#include "crypto/id/Generator.hpp"
#include "stats/model/CacheStats.hpp"
#include "fs/model/Path.hpp"
#include "config/Registry.hpp"

#include <paths.h>
#include <unordered_set>
#include <mutex>
#include <limits>
#include <chrono>
#include <sstream>
#include <optional>

using namespace vh::fs::model;
using namespace vh::stats::model;
using namespace std::chrono;

namespace {

// “Represented bytes” for cache working-set tracking.
// This is NOT RAM usage — it’s how much content the cached entries represent.
uint64_t safeSizeBytes(const std::shared_ptr<Entry>& e) noexcept {
    if (!e) return 0;
    const auto s = static_cast<unsigned long long>(e->size_bytes);
    return (s > std::numeric_limits<uint64_t>::max())
        ? std::numeric_limits<uint64_t>::max()
        : static_cast<uint64_t>(s);
}

uint64_t addClamp(uint64_t a, uint64_t b) noexcept {
    constexpr uint64_t max = std::numeric_limits<uint64_t>::max();
    return (max - a < b) ? max : (a + b);
}

uint64_t subClamp(uint64_t a, uint64_t b) noexcept {
    return (a >= b) ? (a - b) : 0;
}

bool pathContains(const std::filesystem::path& root, const std::filesystem::path& candidate) {
    const auto rootStr = makeAbsolute(root).lexically_normal().string();
    const auto candidateStr = makeAbsolute(candidate).lexically_normal().string();

    if (rootStr == "/") return candidateStr == "/";
    if (candidateStr == rootStr) return true;
    return candidateStr.size() > rootStr.size() &&
           candidateStr.compare(0, rootStr.size(), rootStr) == 0 &&
           candidateStr[rootStr.size()] == '/';
}

} // namespace

namespace vh::fs::cache {

Registry::Registry() {
    stats_ = std::make_shared<CacheStats>();

    // Seed hard root mapping for FUSE
    inodeToPath_[vh::fs::kRootInode] = "/";
    pathToInode_["/"] = vh::fs::kRootInode;

    nextInode_ = db::query::fs::Entry::getNextInode();

    initRoot();
    restoreCache();

    log::Registry::storage()->info("[FSCache] Initialized with next inode: {}", nextInode_);
}

void Registry::initRoot() {
    const auto rootEntry = db::query::fs::Entry::getRootEntry();
    if (!rootEntry) {
        log::Registry::storage()->error("[FSCache] Root entry not found in the database");
        throw std::runtime_error("Root entry not found in the database");
    }

    if (!rootEntry->inode) {
        rootEntry->inode = std::make_optional(getOrAssignInode("/"));
        db::query::fs::Entry::updateFSEntry(rootEntry);
    } else if (rootEntry->inode != vh::fs::kRootInode) {
        log::Registry::storage()->warn("[FSCache] Root entry inode is not FUSE_ROOT_ID, resetting to 1");
        rootEntry->inode = vh::fs::kRootInode;
        db::query::fs::Entry::updateFSEntry(rootEntry);
    }

    cacheEntry(rootEntry);
}

void Registry::restoreCache() {
    const auto rootEntry = getEntry(vh::fs::kRootInode);
    if (!rootEntry) throw std::runtime_error("[FSCache] Root entry not found, cannot restore cache");

    for (const auto& entry : db::query::fs::Entry::listDir(rootEntry->id, true)) {
        if (!entry) {
            log::Registry::storage()->warn("[FSCache] Null entry found in directory listing for root");
            continue;
        }

        if (entry->inode) cacheEntry(entry, true /*isFirstSeeding*/);
        else {
            entry->inode = std::make_optional(getOrAssignInode(entry->fuse_path));
            db::query::fs::Entry::updateFSEntry(entry);
            cacheEntry(entry, true /*isFirstSeeding*/);
        }
    }
}

std::shared_ptr<Entry> Registry::getEntry(const std::filesystem::path& absPath) {
    const auto path = makeAbsolute(absPath);
    log::Registry::storage()->debug("[FSCache] Retrieving entry for path: {}", path.string());
    
    {
        std::shared_lock lock(mutex_);
        if (const auto it = pathToEntry_.find(path); it != pathToEntry_.end()) {
            stats_->record_hit();
            return it->second;
        }
    }

    stats_->record_miss();
    ScopedOpTimer timer(stats_.get());

    try {
        std::optional<std::pair<unsigned int, std::filesystem::path>> vaultPath;
        {
            std::shared_lock lock(mutex_);
            std::shared_ptr<Entry> bestVaultRoot;
            for (const auto& [_, candidate] : idToEntry_) {
                if (!candidate || !candidate->vault_id || candidate->path != "/") continue;
                if (candidate->fuse_path.empty() || !pathContains(candidate->fuse_path, path)) continue;
                if (!bestVaultRoot || candidate->fuse_path.string().size() > bestVaultRoot->fuse_path.string().size())
                    bestVaultRoot = candidate;
            }

            if (bestVaultRoot) {
                const auto rel = path == bestVaultRoot->fuse_path
                    ? std::filesystem::path{"/"}
                    : makeAbsolute(path.lexically_relative(bestVaultRoot->fuse_path));
                vaultPath.emplace(static_cast<unsigned int>(*bestVaultRoot->vault_id), rel);
            }
        }

        if (!vaultPath) {
            log::Registry::storage()->debug("[FSCache] No vault root found for path: {}", path.string());
            return nullptr;
        }

        auto entry = db::query::fs::Entry::getFSEntryByPath(vaultPath->first, vaultPath->second);

        if (entry) {
            if (entry->inode) cacheEntry(entry);
            else {
                entry->inode = assignInode(entry->fuse_path.empty() ? path : entry->fuse_path);
                db::query::fs::Entry::updateFSEntry(entry);
                cacheEntry(entry);
            }
        } else {
            log::Registry::storage()->debug(
                "[FSCache] No entry found for path: {} (vault_id: {}, rel_path: {})",
                path.string(),
                vaultPath->first,
                vaultPath->second.string());
        }

        return entry;
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[FSCache] Error retrieving entry for path {}: {}", path.string(), e.what());
        return nullptr;
    }
}

std::shared_ptr<Entry> Registry::getEntry(const Inode ino) {
    log::Registry::storage()->trace("[FSCache] Retrieving entry for inode: {}", ino);

    {
        std::shared_lock lock(mutex_);
        if (const auto it = inodeToEntry_.find(ino); it != inodeToEntry_.end()) {
            stats_->record_hit();
            return it->second;
        }
    }

    stats_->record_miss();
    ScopedOpTimer timer(stats_.get());

    auto entry = db::query::fs::Entry::getFSEntryByInode(ino);
    if (entry) cacheEntry(entry);
    else log::Registry::storage()->warn("[FSCache] No entry found for inode: {}", ino);
    return entry;
}

std::shared_ptr<Entry> Registry::getEntryById(unsigned int id) {
    std::shared_lock lock(mutex_);
    if (const auto it = idToEntry_.find(id); it != idToEntry_.end()) {
        stats_->record_hit();
        return it->second;
    }

    stats_->record_miss();
    ScopedOpTimer timer(stats_.get());

    std::shared_ptr<Entry> entry = nullptr;
    log::Registry::storage()->warn("[FSCache] No entry found for ID: {}", id);
    entry = db::query::fs::Entry::getFSEntryById(id);
    return entry;
}

vh::fs::Inode Registry::resolveInode(const std::filesystem::path& absPath) {
    // Try hot map first
    {
        std::shared_lock lock(mutex_);
        if (const auto it = pathToInode_.find(absPath); it != pathToInode_.end()) return it->second;
    }

    const auto entry = getEntry(absPath);
    if (!entry) {
        log::Registry::storage()->warn("[FSCache] No entry found for path: {}", absPath.string());
        return vh::fs::kRootInode;
    }

    const Inode ino = (entry->inode ? *entry->inode : getOrAssignInode(absPath));
    if (ino == vh::fs::kRootInode) {
        log::Registry::storage()->error("[FSCache] Failed to resolve inode for path: {}", absPath.string());
        return vh::fs::kRootInode;
    }

    linkPath(absPath, ino);
    return ino;
}

vh::fs::Inode Registry::assignInode(const std::filesystem::path& path) {
    std::unique_lock lock(mutex_);
    if (const auto it = pathToInode_.find(path); it != pathToInode_.end()) return it->second;

    const Inode ino = nextInode_++;
    inodeToPath_[ino] = path;
    pathToInode_[path] = ino;
    return ino;
}

vh::fs::Inode Registry::getOrAssignInode(const std::filesystem::path& path) {
    std::scoped_lock lock(mutex_);
    if (path.empty()) throw std::runtime_error("Cannot assign inode to empty path");

    if (const auto it = pathToInode_.find(path); it != pathToInode_.end()) return it->second;

    const Inode ino = nextInode_++;
    pathToInode_[path] = ino;
    inodeToPath_[ino] = path;
    return ino;
}

std::filesystem::path Registry::resolvePath(Inode ino) {
    std::shared_lock lock(mutex_);
    if (!inodeToPath_.contains(ino)) throw std::runtime_error("[FSCache] Inode not found: " + std::to_string(ino));
    return inodeToPath_.at(ino);
}

void Registry::linkPath(const std::filesystem::path& absPath, const Inode ino) {
    std::unique_lock lock(mutex_);
    if (pathToInode_.contains(absPath)) {
        log::Registry::storage()->debug("[FSCache] Path {} already linked to inode {}", absPath.string(), ino);
        return;
    }
    pathToInode_[absPath] = ino;
    inodeToPath_[ino] = absPath;
}

void Registry::decrementInodeRef(const Inode ino, const uint64_t nlookup) {
    if (nlookup > 1) return;
    evictIno(ino);
}

bool Registry::entryExists(const std::filesystem::path& absPath) const {
    const auto path = makeAbsolute(absPath);
    std::shared_lock lock(mutex_);
    return pathToEntry_.contains(path);
}

std::shared_ptr<Entry> Registry::getEntryFromInode(const Inode ino) const {
    std::shared_lock lock(mutex_);
    if (const auto it = inodeToEntry_.find(ino); it != inodeToEntry_.end()) return it->second;
    log::Registry::storage()->warn("[FSCache] No entry found for inode: {}", ino);
    return nullptr;
}

void Registry::cacheEntry(const std::shared_ptr<Entry>& entry, const bool isFirstSeeding) {
    if (!entry || !entry->inode) throw std::invalid_argument("Entry or inode is null");

    log::Registry::storage()->debug("[FSCache] Caching entry: {} with inode {}", entry->fuse_path.string(), *entry->inode);

    // Preflight: reconstruct fuse/backing paths when needed
    if (*entry->inode != vh::fs::kRootInode) {
        if (!entry->vault_id) {
            log::Registry::storage()->error("[FSCache] Entry {} has no vault_id, cannot cache", entry->id);
            throw std::runtime_error("Entry has no vault_id");
        }

        if (entry->fuse_path.empty() || entry->backing_path.empty()) {
            if (!entry->parent_id) {
                log::Registry::storage()->error("[FSCache] Entry {} has no parent_id, cannot cache", entry->id);
                throw std::runtime_error("Entry has no parent_id");
            }

            if (const auto parent = getEntryById(*entry->parent_id)) {
                entry->fuse_path = parent->fuse_path / entry->name;
                entry->backing_path = parent->backing_path / entry->base32_alias;
            } else {
                log::Registry::storage()->error("[FSCache] No parent entry found for entry {}", entry->id);
                throw std::runtime_error("No parent entry found");
            }
        }
    }

    const pqxx::result parentStats =
        (!isFirstSeeding && entry->parent_id)
            ? db::query::fs::Directory::collectParentStats(*entry->parent_id)
            : pqxx::result{};

    std::unique_lock lock(mutex_);

    // --- Used-bytes accounting (incremental, no rescans) ---
    const Inode ino = *entry->inode;

    bool existedAlready = false;
    uint64_t oldSize = 0;

    // Prefer inode match for “old” instance
    if (const auto it = inodeToEntry_.find(ino); it != inodeToEntry_.end() && it->second) {
        existedAlready = true;
        oldSize = safeSizeBytes(it->second);
    } else if (const auto pit = pathToEntry_.find(entry->fuse_path); pit != pathToEntry_.end() && pit->second) {
        existedAlready = true;
        oldSize = safeSizeBytes(pit->second);
    } else if (const auto iit = idToEntry_.find(entry->id); iit != idToEntry_.end() && iit->second) {
        existedAlready = true;
        oldSize = safeSizeBytes(iit->second);
    }

    const uint64_t newSize = safeSizeBytes(entry);

    auto eraseInode = [&](const Inode staleIno) {
        for (auto it = pathToInode_.begin(); it != pathToInode_.end();) {
            if (it->second == staleIno) {
                pathToEntry_.erase(it->first);
                it = pathToInode_.erase(it);
            } else ++it;
        }

        inodeToPath_.erase(staleIno);
        inodeToEntry_.erase(staleIno);
        inodeToId_.erase(staleIno);
    };

    auto erasePath = [&](const std::filesystem::path& stalePath) {
        pathToInode_.erase(stalePath);
        pathToEntry_.erase(stalePath);
    };

    if (const auto it = idToEntry_.find(entry->id); it != idToEntry_.end() && it->second) {
        const auto& old = it->second;
        if (old->fuse_path != entry->fuse_path) erasePath(old->fuse_path);
        if (old->inode && *old->inode != ino) eraseInode(*old->inode);
    }

    for (auto it = pathToInode_.begin(); it != pathToInode_.end();) {
        if (it->second == ino && it->first != entry->fuse_path) {
            pathToEntry_.erase(it->first);
            it = pathToInode_.erase(it);
        } else ++it;
    }

    for (auto it = pathToEntry_.begin(); it != pathToEntry_.end();) {
        const auto& cached = it->second;
        if (cached && cached->id == entry->id && it->first != entry->fuse_path) {
            pathToInode_.erase(it->first);
            it = pathToEntry_.erase(it);
        } else ++it;
    }

    if (const auto it = pathToInode_.find(entry->fuse_path); it != pathToInode_.end() && it->second != ino)
        eraseInode(it->second);

    auto insert = [&](const std::shared_ptr<Entry>& e) {
        if (!e) {
            log::Registry::fs()->error("[FSCache] Attempted to cache a null entry");
            return;
        }

        if (!e->inode) {
            log::Registry::fs()->error("[FSCache] Entry {} has no inode, cannot cache", e->id);
            throw std::runtime_error("Entry has no inode");
        }

        inodeToPath_[*e->inode] = e->fuse_path;
        inodeToEntry_[*e->inode] = e;
        pathToInode_[e->fuse_path] = *e->inode;
        pathToEntry_[e->fuse_path] = e;
        inodeToId_[*e->inode] = e->id;
        idToEntry_[e->id] = e;
        linkChild(e->id, e->parent_id);
    };

    insert(entry);

    // Update upstream directory stats (your existing behavior)
    if (!parentStats.empty()) {
        for (const auto& s : parentStats) {
            const auto id = s["id"].as<unsigned int>();
            if (idToEntry_.contains(id)) {
                const auto dir = std::static_pointer_cast<Directory>(idToEntry_[id]);
                dir->size_bytes = s["size_bytes"].as<uintmax_t>();
                dir->file_count = s["file_count"].as<unsigned int>();
                dir->subdirectory_count = s["subdirectory_count"].as<unsigned int>();
                if (!s["updated_at"].is_null())
                    dir->updated_at = db::encoding::parsePostgresTimestamp(s["updated_at"].as<std::string>());
            } else {
                insert(db::query::fs::Entry::getFSEntryById(id));
            }
        }
    }

    // Apply bytes delta after insert + upstream updates
    const uint64_t curUsed = stats_->snapshot().used_bytes;
    uint64_t updatedUsed = curUsed;

    if (!existedAlready) {
        updatedUsed = addClamp(curUsed, newSize);
        stats_->record_insert();
    } else {
        if (newSize >= oldSize) updatedUsed = addClamp(curUsed, (newSize - oldSize));
        else updatedUsed = subClamp(curUsed, (oldSize - newSize));
    }

    stats_->set_used(updatedUsed);

    log::Registry::fs()->info("[FSCache] Cached entry: {} with inode {}", entry->fuse_path.string(), *entry->inode);
}

void Registry::updateEntry(const std::shared_ptr<Entry>& entry) {
    log::Registry::fs()->debug("[FSCache] Updating entry: {} with inode {}",
                             entry->fuse_path.string(), entry->inode ? *entry->inode : 0);

    db::query::fs::Entry::updateFSEntry(entry);
    cacheEntry(entry);

    log::Registry::fs()->debug("[FSCache] Updated entry: {} with inode {}",
                             entry->fuse_path.string(), entry->inode ? *entry->inode : 0);
}

void Registry::evictIno(Inode ino) {
    std::unique_lock lock(mutex_);

    if (!inodeToPath_.contains(ino) && !inodeToId_.contains(ino)) {
        log::Registry::fs()->debug("[FSCache] Attempted to destroy references for non-existent inode: {}", ino);
        return;
    }

    // Capture removed size before erasing
    uint64_t removedSize = 0;
    if (const auto it = inodeToEntry_.find(ino); it != inodeToEntry_.end()) removedSize = safeSizeBytes(it->second);
    else if (const auto pathIt = inodeToPath_.find(ino); pathIt != inodeToPath_.end()) {
        if (const auto it2 = pathToEntry_.find(pathIt->second); it2 != pathToEntry_.end()) removedSize = safeSizeBytes(it2->second);
    } else if (const auto idIt = inodeToId_.find(ino); idIt != inodeToId_.end()) {
        if (const auto it3 = idToEntry_.find(idIt->second); it3 != idToEntry_.end()) removedSize = safeSizeBytes(it3->second);
    }

    for (auto it = pathToInode_.begin(); it != pathToInode_.end();) {
        if (it->second == ino) {
            pathToEntry_.erase(it->first);
            it = pathToInode_.erase(it);
        } else ++it;
    }

    inodeToPath_.erase(ino);
    inodeToEntry_.erase(ino);
    if (const auto idIt = inodeToId_.find(ino); idIt != inodeToId_.end()) {
        const auto id = idIt->second;
        inodeToId_.erase(idIt);
        idToEntry_.erase(id);
        unlinkChild(id);
    }

    // Update used bytes (bounded)
    const uint64_t curUsed = stats_->snapshot().used_bytes;
    stats_->set_used(subClamp(curUsed, removedSize));

    stats_->record_eviction();
}

void Registry::evictId(const unsigned int id) {
    std::unique_lock lock(mutex_);

    auto entryIt = idToEntry_.find(id);
    std::shared_ptr<Entry> entry = entryIt == idToEntry_.end() ? nullptr : entryIt->second;
    std::optional<Inode> ino;

    if (entry && entry->inode)
        ino = *entry->inode;

    if (!ino) {
        for (const auto& [candidateIno, candidateId] : inodeToId_) {
            if (candidateId == id) {
                ino = candidateIno;
                break;
            }
        }
    }

    if (!entry && !ino) {
        log::Registry::fs()->debug("[FSCache] Attempted to evict non-existent entry ID: {}", id);
        return;
    }

    uint64_t removedSize = safeSizeBytes(entry);
    if (removedSize == 0 && ino) {
        if (const auto inodeEntry = inodeToEntry_.find(*ino); inodeEntry != inodeToEntry_.end())
            removedSize = safeSizeBytes(inodeEntry->second);
    }

    if (ino) {
        for (auto it = pathToInode_.begin(); it != pathToInode_.end();) {
            if (it->second == *ino) {
                pathToEntry_.erase(it->first);
                it = pathToInode_.erase(it);
            } else ++it;
        }

        inodeToPath_.erase(*ino);
        inodeToEntry_.erase(*ino);
        inodeToId_.erase(*ino);
    }

    if (entry) {
        pathToInode_.erase(entry->fuse_path);
        pathToEntry_.erase(entry->fuse_path);
    }

    for (auto it = pathToEntry_.begin(); it != pathToEntry_.end();) {
        const auto& cached = it->second;
        if (cached && cached->id == id) {
            pathToInode_.erase(it->first);
            it = pathToEntry_.erase(it);
        } else ++it;
    }

    for (auto it = inodeToId_.begin(); it != inodeToId_.end();) {
        if (it->second == id) {
            inodeToPath_.erase(it->first);
            inodeToEntry_.erase(it->first);
            it = inodeToId_.erase(it);
        } else ++it;
    }

    idToEntry_.erase(id);
    unlinkChild(id);

    const uint64_t curUsed = stats_->snapshot().used_bytes;
    stats_->set_used(subClamp(curUsed, removedSize));
    stats_->record_eviction();
}

void Registry::evictPath(const std::filesystem::path& path) {
    Inode ino;

    {
        std::unique_lock lock(mutex_);
        if (!pathToInode_.contains(path)) {
            log::Registry::fs()->debug("[FSCache] Attempted to evict non-existent path: {}", path.string());
            return;
        }
        ino = pathToInode_[path];
    }

    stats_->record_invalidation();
    evictIno(ino);
}

void Registry::evictVault(const unsigned int vaultId, const std::filesystem::path& fuseRoot) {
    const bool matchPaths = !fuseRoot.empty() && makeAbsolute(fuseRoot) != "/";
    const auto inVault = [&](const std::shared_ptr<Entry>& e) {
        if (!e) return false;
        if (e->vault_id && static_cast<unsigned int>(*e->vault_id) == vaultId) return true;
        return matchPaths && !e->fuse_path.empty() && pathContains(fuseRoot, e->fuse_path);
    };
    const auto underRoot = [&](const std::filesystem::path& path) {
        return matchPaths && pathContains(fuseRoot, path);
    };

    std::unique_lock lock(mutex_);

    std::unordered_set<unsigned int> ids;
    std::unordered_set<Inode> inodes;
    uint64_t removedSize = 0;

    for (const auto& [id, e] : idToEntry_) {
        if (!inVault(e)) continue;
        ids.insert(id);
        if (e->inode) inodes.insert(*e->inode);
        removedSize = addClamp(removedSize, safeSizeBytes(e));
    }
    for (const auto& [ino, e] : inodeToEntry_)
        if (inVault(e)) inodes.insert(ino);
    for (const auto& [ino, id] : inodeToId_)
        if (ids.contains(id)) inodes.insert(ino);
    for (const auto& [path, ino] : pathToInode_)
        if (underRoot(path)) inodes.insert(ino);
    inodes.erase(vh::fs::kRootInode);

    if (ids.empty() && inodes.empty()) return;

    std::erase_if(pathToInode_, [&](const auto& kv) { return inodes.contains(kv.second) || underRoot(kv.first); });
    std::erase_if(pathToEntry_, [&](const auto& kv) {
        return underRoot(kv.first) || inVault(kv.second) || (kv.second && ids.contains(kv.second->id));
    });
    std::erase_if(inodeToPath_, [&](const auto& kv) { return inodes.contains(kv.first); });
    std::erase_if(inodeToEntry_, [&](const auto& kv) { return inodes.contains(kv.first); });
    std::erase_if(inodeToId_, [&](const auto& kv) { return inodes.contains(kv.first) || ids.contains(kv.second); });
    std::erase_if(idToEntry_, [&](const auto& kv) { return ids.contains(kv.first); });
    for (const auto id : ids) unlinkChild(id);

    stats_->set_used(subClamp(stats_->snapshot().used_bytes, removedSize));
    stats_->record_invalidation();

    log::Registry::fs()->debug("[FSCache] Evicted {} entries and {} inodes of vault {} ({})",
                               ids.size(), inodes.size(), vaultId, fuseRoot.string());
}

void Registry::linkChild(const unsigned int id, const std::optional<unsigned int>& parentId) {
    if (!parentId) {
        unlinkChild(id);
        return;
    }
    const auto [it, inserted] = childToParent_.try_emplace(id, *parentId);
    if (!inserted && it->second != *parentId) {
        if (const auto old = parentToChildren_.find(it->second); old != parentToChildren_.end()) {
            old->second.erase(id);
            if (old->second.empty()) parentToChildren_.erase(old);
        }
        it->second = *parentId;
    }
    parentToChildren_[*parentId].insert(id);
}

void Registry::unlinkChild(const unsigned int id) {
    const auto it = childToParent_.find(id);
    if (it == childToParent_.end()) return;
    if (const auto siblings = parentToChildren_.find(it->second); siblings != parentToChildren_.end()) {
        siblings->second.erase(id);
        if (siblings->second.empty()) parentToChildren_.erase(siblings);
    }
    childToParent_.erase(it);
}

bool Registry::refreshDirStats(const unsigned int dirId) {
    const auto rows = db::query::fs::Directory::collectParentStats(dirId);
    if (rows.empty()) return false;
    std::unique_lock lock(mutex_);
    for (const auto& s : rows) {
        const auto it = idToEntry_.find(s["id"].as<unsigned int>());
        if (it == idToEntry_.end() || !it->second || !it->second->isDirectory()) continue;
        const auto dir = std::static_pointer_cast<Directory>(it->second);
        dir->size_bytes = s["size_bytes"].as<uintmax_t>();
        dir->file_count = s["file_count"].as<unsigned int>();
        dir->subdirectory_count = s["subdirectory_count"].as<unsigned int>();
        if (!s["updated_at"].is_null())
            dir->updated_at = db::encoding::parsePostgresTimestamp(s["updated_at"].as<std::string>());
    }
    return true;
}

std::vector<std::shared_ptr<Entry>> Registry::listDir(const unsigned int parentId, const bool recursive) const {
    // How many entries the database holds there (one statement): the cached children are served only when they
    // account for all of them, otherwise the listing comes from the database.
    const auto shape = db::query::fs::Directory::listingShape(parentId);
    if (!shape) throw std::runtime_error("Parent ID does not exist or is not a directory");
    const auto numEntries = recursive ? shape->subtree : shape->direct;

    std::vector<std::shared_ptr<Entry>> entries;
    // The maps are mutated by concurrent FUSE/ws callers; read them under the lock (released before the DB fallback).
    std::shared_lock lock(mutex_);
    entries.reserve(numEntries);

    auto append_children = [&](const unsigned int pid) {
        const auto children = parentToChildren_.find(pid);
        if (children == parentToChildren_.end()) return;
        for (const auto childId : children->second)
            if (const auto it = idToEntry_.find(childId); it != idToEntry_.end()) entries.push_back(it->second);
    };

    append_children(parentId);

    if (recursive) {
        std::unordered_set<unsigned int> visited;
        visited.reserve(childToParent_.size());

        // By index: append_children grows `entries`, and a range-for would stop at the size it started with (so
        // nothing deeper than grandchildren was collected and every deeper subtree fell back to the DB listing).
        for (std::size_t i = 0; i < entries.size(); ++i) {
            const auto& e = entries[i];
            if (!e) continue;
            const unsigned int eid = e->id;
            if (!visited.insert(eid).second) continue;
            append_children(eid);
        }
    }

    lock.unlock();

    if (entries.size() != numEntries) {
        log::Registry::fs()->warn("[FSCache] Expected {} entries, but found {}", numEntries, entries.size());
        // listDir(id, true) returns only direct child files and symlinks (see Entry::listSubtree): a recursive
        // fallback through it dropped everything deeper, e.g. from a directory rename.
        const auto expected = recursive ? db::query::fs::Entry::listSubtree(parentId)
                                        : db::query::fs::Entry::listDir(parentId, false);
        if (expected.size() != numEntries) {
            if (expected.size() == entries.size())
                log::Registry::fs()->warn("Computed number of entries mismatch with actual");

            log::Registry::fs()->warn(
                "[FSCache] Inconsistent entry count for parent ID {}: expected: {}, found {}, actual: {}; using DB listing",
                parentId,
                numEntries,
                entries.size(),
                expected.size());
        }
        return expected;
    }

    return entries;
}

std::shared_ptr<CacheStatsSnapshot> Registry::stats() const {
    // Snapshot should be atomics-only; safe without locking FSCache maps.
    return std::make_shared<CacheStatsSnapshot>(stats_->snapshot());
}

std::string Registry::dump() const {
    if (!paths::isTestMode() || !config::Registry::get().dev.enabled)
        return "[FSCache] Dump is only available in test mode with dev features enabled";

    std::shared_lock lock(mutex_);
    std::stringstream ss;
    ss << "FSCache dump:\n";
    ss << "  Inode map:\n";
    for (const auto& [ino, path] : inodeToPath_) ss << "    " << ino << ": " << path.string() << "\n";
    ss << "  Path map:\n";
    for (const auto& [path, ino] : pathToInode_) ss << "    " << path.string() << ": " << ino << "\n";
    ss << "  Entry map:\n";
    for (const auto& [id, entry] : idToEntry_) ss << "    " << id << ": " << entry->fuse_path.string() << "\n";
    ss << "  Child-parent map:\n";
    for (const auto& [childId, parentId] : childToParent_) ss << "    " << childId << ": " << parentId << "\n";
    return ss.str();
}

}
