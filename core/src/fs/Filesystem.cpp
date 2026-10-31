#include "fs/Filesystem.hpp"
#include "storage/Manager.hpp"
#include "storage/Engine.hpp"
#include "storage/CloudEngine.hpp"
#include "vault/model/Vault.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Directory.hpp"
#include "fs/model/Symlink.hpp"
#include "fs/model/Path.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Symlink.hpp"
#include "config/Registry.hpp"
#include "db/query/fs/Entry.hpp"
#include "vault/EncryptionManager.hpp"
#include "fs/ops/file.hpp"
#include "crypto/util/hash.hpp"
#include "crypto/util/encrypt.hpp"
#include "preview/render/Service.hpp"
#include <array>
#include "storage/PlaintextReader.hpp"
#include "fs/metadata/Magic.hpp"
#include "runtime/Deps.hpp"
#include "db/Transactions.hpp"
#include "log/Registry.hpp"
#include "db/query/vault/Vault.hpp"
#include "crypto/id/Generator.hpp"
#include "fs/cache/Registry.hpp"
#include "db/encoding/u8.hpp"
#include "identities/User.hpp"
#include "identities/Group.hpp"
#include "fuse/WorkingCopies.hpp"
#include "recovery/local/Versions.hpp"

#include <ranges>
#include <set>
#include <string_view>
#include <unordered_map>
#include <fstream>
#include <vector>
#include <algorithm>
#include <cerrno>
#include <exception>
#include <system_error>
#include <ctime>
#include <paths.h>

using namespace vh::storage;
using namespace vh::vault::model;
using namespace vh::db::encoding;
using namespace vh::config;
using namespace vh::crypto;
using namespace vh::fs;
using namespace vh::fs::ops;
using namespace vh::fs::model;
using namespace vh::fs::metadata;

namespace {

bool symlinkStatusExists(const std::filesystem::path& path) {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(path, ec);
    return !ec && status.type() != std::filesystem::file_type::not_found;
}

bool targetEscapesVaultRoot(const std::filesystem::path& linkVaultPath, const std::filesystem::path& target) {
    std::size_t depth = 0;
    for (const auto& part : linkVaultPath.parent_path()) {
        const auto s = part.string();
        if (s.empty() || s == "/" || s == ".") continue;
        if (s == "..") {
            if (depth == 0) return true;
            --depth;
        } else ++depth;
    }

    for (const auto& part : target) {
        const auto s = part.string();
        if (s.empty() || s == ".") continue;
        if (s == "..") {
            if (depth == 0) return true;
            --depth;
        } else ++depth;
    }

    return false;
}

std::optional<int32_t> linuxUidFor(const std::shared_ptr<vh::identities::User>& user) {
    const auto uid = user ? user->linuxUid() : std::nullopt;
    if (!uid) return std::nullopt;
    return static_cast<int32_t>(*uid);
}

std::optional<int32_t> linuxGidFor(const std::shared_ptr<vh::identities::Group>& group) {
    const auto gid = group ? group->linuxGid() : std::nullopt;
    if (!gid) return std::nullopt;
    return static_cast<int32_t>(*gid);
}

std::optional<int32_t> userIdFor(const std::shared_ptr<vh::identities::User>& user) {
    if (!user) return std::nullopt;
    return static_cast<int32_t>(user->id);
}

std::string mimeTypeFromSourceFile(
    const std::filesystem::path& sourcePath,
    const std::filesystem::path& fallbackPath) {
    try {
        return Magic::get_mime_type(sourcePath.string());
    } catch (const std::exception& e) {
        vh::log::Registry::fs()->warn(
            "[Filesystem] Failed to detect MIME type from source file {}: {}",
            sourcePath.string(),
            e.what());
        return inferMimeTypeFromPath(fallbackPath);
    }
}

} // namespace

static void updateFile(pqxx::work& txn, const std::shared_ptr<File>& file) {
    const auto exists = txn.exec(pqxx::prepped{"fs_entry_exists_by_inode"}, file->inode).one_field_ref().as<bool>();
    const auto sizeRes = txn.exec(pqxx::prepped{"get_file_size_by_inode"}, file->inode);
    const auto existingSize = sizeRes.empty() ? 0 : sizeRes.one_field_ref().as<int64_t>();

    pqxx::params p;
    p.append(file->id);
    p.append(file->size_bytes);
    p.append(file->mime_type);
    p.append(file->content_hash);
    p.append(file->encryption_iv);
    p.append(file->encrypted_with_key_version);
    p.append(file->last_modified_by);

    file->updated_at = std::time(nullptr);
    txn.exec(pqxx::prepped{"update_file_only"}, p);

    // Signed: a shrinking file used to wrap the unsigned difference into a huge positive delta.
    vh::db::query::fs::Directory::addToAncestorStats(txn, file->parent_id,
                                                     static_cast<int64_t>(file->size_bytes) - existingSize,
                                                     exists ? 0 : 1, 0);
}

static void updateFSEntry(pqxx::work& txn, const std::shared_ptr<Entry>& entry) {
    pqxx::params p;
    p.append(entry->inode);
    p.append(entry->vault_id);
    p.append(entry->parent_id);
    p.append(entry->name);
    p.append(entry->base32_alias);
    p.append(entry->last_modified_by);
    p.append(to_utf8_string(entry->path.u8string()));
    p.append(entry->mode);
    p.append(entry->owner_uid);
    p.append(entry->group_gid);
    p.append(entry->is_hidden);
    p.append(entry->is_system);

    txn.exec(pqxx::prepped{"update_fs_entry_by_inode"}, p);
}

void Filesystem::init(const std::shared_ptr<Manager>& manager) {
    std::lock_guard lock(mutex_);
    storageManager_ = std::move(manager);
}

bool Filesystem::isReady() {
    std::lock_guard lock(mutex_);
    return static_cast<bool>(storageManager_);
}

int Filesystem::mkdir(const MkdirContext& ctx) {
    const auto& absPath = ctx.path;
    auto engine = ctx.engine;

    log::Registry::fs()->debug("Creating directory at: {}", absPath.string());

    std::scoped_lock lock(mutex_);

    try {
        if (!storageManager_) {
            log::Registry::fs()->error("[Filesystem::mkdir] StorageManager is not initialized");
            return -EIO;
        }

        const auto& cache = runtime::Deps::get().fsCache;

        if (absPath.empty()) {
            log::Registry::fs()->error("[Filesystem::mkdir] Cannot create directory at empty path");
            return -EINVAL;
        }

        if (ctx.failIfExists && cache->entryExists(absPath)) return -EEXIST;

        std::vector<std::filesystem::path> toCreate;
        std::filesystem::path cur = absPath;

        while (!cur.empty() && !cache->entryExists(cur)) {
            toCreate.push_back(cur);
            cur = cur.parent_path();
        }

        std::ranges::reverse(toCreate);

        if (!engine)
            engine = storageManager_->resolveStorageEngine(absPath);

        if (!engine) {
            log::Registry::fs()->error("[Filesystem::mkdir] No storage engine found for path: {}", absPath.string());
            return -EIO;
        }

        for (const auto& p : toCreate) {
            const auto path = makeAbsolute(p);
            log::Registry::fs()->debug("[Filesystem::mkdir] Creating directory at: {}", path.string());

            auto dir = std::make_shared<Directory>();

            dir->vault_id = engine->vault->id;
            dir->path = engine->fusePathToVaultPath(path);

            const auto parentPath = resolveParent(path);
            const auto parent = (ctx.parent && ctx.parent->fuse_path == parentPath)
                ? ctx.parent
                : cache->getEntry(parentPath);
            if (!parent) {
                log::Registry::fs()->error(
                    "[Filesystem::mkdir] Parent directory does not exist: {}",
                    path.parent_path().string());
                return -ENOENT;
            }

            dir->parent_id = parent->id;
            dir->fuse_path = path;
            dir->name = path.filename();
            dir->base32_alias = id::Generator({ .namespace_token = dir->name }).generate();
            dir->backing_path = parent->backing_path / dir->base32_alias;
            dir->mode = ctx.mode;
            dir->owner_uid = linuxUidFor(ctx.user);
            dir->group_gid = linuxGidFor(ctx.group);
            dir->inode = cache->assignInode(path);
            dir->is_hidden = !dir->name.empty() && dir->name.front() == '.' && !dir->name.starts_with("..");
            dir->is_system = false;
            dir->created_by = dir->last_modified_by = userIdFor(ctx.user);
            dir->created_at = dir->updated_at = std::time(nullptr);

            dir->id = db::query::fs::Directory::upsertDirectory(dir);
            cache->cacheEntry(dir);

            try {
                std::filesystem::create_directories(dir->backing_path);
            } catch (const std::filesystem::filesystem_error& e) {
                log::Registry::fs()->error(
                    "[Filesystem::mkdir] Failed to create backing directory {}: {}",
                    dir->backing_path.string(),
                    e.what());

                if (e.code())
                    return -e.code().value();

                return -EIO;
            }
        }

        log::Registry::fs()->debug("Successfully created directory at: {}", absPath.string());
        return 0;
    } catch (const std::bad_alloc& ex) {
        log::Registry::fs()->error("[Filesystem::mkdir] Out of memory for {}: {}", absPath.string(), ex.what());
        return -ENOMEM;
    } catch (const std::filesystem::filesystem_error& ex) {
        log::Registry::fs()->error("[Filesystem::mkdir] Filesystem error for {}: {}", absPath.string(), ex.what());
        return ex.code() ? -ex.code().value() : -EIO;
    } catch (const std::exception& ex) {
        log::Registry::fs()->error("[Filesystem::mkdir] Failed to create directory {}: {}", absPath.string(), ex.what());
        return -EIO;
    } catch (...) {
        log::Registry::fs()->error("[Filesystem::mkdir] Unknown failure creating directory: {}", absPath.string());
        return -EIO;
    }
}

std::pair<int, std::shared_ptr<model::Entry>> Filesystem::mkdir(const FuseMkdirContext& ctx) {
    const auto& resolved = ctx.resolved;
    if (!resolved.ok()) return {-resolved.errnum, nullptr};
    if (!resolved.user) return {-EACCES, nullptr};
    if (!resolved.path || !resolved.engine || !resolved.parentEntry) return {-EINVAL, nullptr};

    const auto err = mkdir({
        .path = *resolved.path,
        .mode = ctx.mode == 0 ? static_cast<mode_t>(0755) : ctx.mode,
        .engine = resolved.engine,
        .user = resolved.user,
        .group = resolved.group,
        .parent = resolved.parentEntry,
        .failIfExists = true
    });
    if (err) return {err, nullptr};

    const auto entry = runtime::Deps::get().fsCache->getEntry(*resolved.path);
    if (!entry) return {-EIO, nullptr};
    return {0, entry};
}

void Filesystem::mkVault(const std::filesystem::path& absPath, unsigned int vaultId, mode_t mode) {
    if (absPath.empty()) throw std::runtime_error("Cannot create directory at empty path");
    log::Registry::fs()->debug("Creating vault directory at: {}", absPath.string());

    std::scoped_lock lock(mutex_);
    if (!storageManager_) throw std::runtime_error("StorageManager is not initialized");

    const auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw std::runtime_error("Vault with ID " + std::to_string(vaultId) + " does not exist");

    try {
        const auto dir = std::make_shared<Directory>();
        dir->vault_id = vaultId;
        dir->path = "/";
        dir->name = vault->effectiveFuseName();
        dir->parent_id = db::query::fs::Entry::getRootEntry()->id;
        dir->base32_alias = vault->mount_point;
        dir->backing_path = paths::getBackingPath() / dir->base32_alias;
        dir->fuse_path = absPath;
        dir->created_at = dir->updated_at = std::time(nullptr);
        dir->mode = mode;
        dir->inode = runtime::Deps::get().fsCache->assignInode(absPath);
        dir->is_hidden = false;
        dir->is_system = false;

        const auto root = db::query::fs::Entry::getRootEntry();

        dir->id = db::query::fs::Directory::upsertDirectory(dir);

        runtime::Deps::get().fsCache->cacheEntry(dir);

        if (!std::filesystem::exists(dir->backing_path)) std::filesystem::create_directories(dir->backing_path);

        log::Registry::fs()->debug("Successfully created vault directory at: {}", absPath.string());
    } catch (const std::exception& ex) {
        log::Registry::fs()->error("Failed to create vault directory: {} - {}", absPath.string(), ex.what());
        throw std::runtime_error("Failed to create vault directory: " + absPath.string() + " - " + ex.what());
    }
}

bool Filesystem::exists(const std::filesystem::path& absPath) {
    try {
        return runtime::Deps::get().fsCache->entryExists(absPath);
    } catch (const std::exception& ex) {
        log::Registry::fs()->error("Error checking existence of path {}: {}", absPath.string(), ex.what());
        return false;
    }
}

std::pair<int, std::shared_ptr<model::Symlink>>
Filesystem::createSymlink(const FuseCreateSymlinkContext& ctx) {
    const auto& resolved = ctx.resolved;
    const auto linkPath = resolved.path.value_or(std::filesystem::path{});
    const auto& target = ctx.target;

    std::scoped_lock lock(mutex_);

    try {
        if (!resolved.ok()) return {-resolved.errnum, nullptr};
        if (!resolved.user) return {-EACCES, nullptr};
        if (!resolved.path || !resolved.engine || !resolved.parentEntry) return {-EINVAL, nullptr};

        if (!storageManager_) {
            log::Registry::fs()->error("[Filesystem::createSymlink] StorageManager is not initialized");
            return {-EIO, nullptr};
        }

        if (target.empty()) return {-EINVAL, nullptr};

        const auto targetPath = std::filesystem::path(target);
        if (targetPath.is_absolute()) return {-EINVAL, nullptr};

        const auto& engine = resolved.engine;

        const auto& cache = runtime::Deps::get().fsCache;
        if (cache->entryExists(linkPath)) return {-EEXIST, nullptr};

        const auto parent = resolved.parentEntry;
        if (!parent) {
            log::Registry::fs()->error(
                "[Filesystem::createSymlink] Parent directory does not exist: {}",
                linkPath.parent_path().string());
            return {-ENOENT, nullptr};
        }

        const auto vaultPath = engine->fusePathToVaultPath(linkPath);
        if (targetEscapesVaultRoot(vaultPath, targetPath)) return {-EINVAL, nullptr};

        auto symlink = std::make_shared<Symlink>();
        symlink->parent_id = parent->id;
        symlink->vault_id = engine->vault->id;
        symlink->name = linkPath.filename();
        symlink->target = target;
        symlink->path = vaultPath;
        symlink->fuse_path = linkPath;
        symlink->base32_alias = id::Generator({ .namespace_token = symlink->name }).generate();
        symlink->backing_path = parent->backing_path / symlink->base32_alias;
        symlink->mode = 0777;
        symlink->owner_uid = linuxUidFor(resolved.user);
        symlink->group_gid = linuxGidFor(resolved.group);
        symlink->is_hidden = !symlink->name.empty() && symlink->name.starts_with('.');
        symlink->is_system = false;
        symlink->created_by = symlink->last_modified_by = userIdFor(resolved.user);
        symlink->created_at = std::time(nullptr);
        symlink->updated_at = symlink->created_at;
        symlink->inode = std::make_optional(cache->getOrAssignInode(linkPath));
        symlink->size_bytes = symlink->target.size();

        try {
            std::filesystem::create_directories(symlink->backing_path.parent_path());
            std::filesystem::create_symlink(symlink->target, symlink->backing_path);
        } catch (const std::filesystem::filesystem_error& ex) {
            log::Registry::fs()->error(
                "[Filesystem::createSymlink] Failed to create backing symlink for {}: {}",
                linkPath.string(),
                ex.what());
            return {ex.code() ? -ex.code().value() : -EIO, nullptr};
        } catch (const std::exception& ex) {
            log::Registry::fs()->error(
                "[Filesystem::createSymlink] Failed to create backing symlink for {}: {}",
                linkPath.string(),
                ex.what());
            return {-EIO, nullptr};
        }

        if (!symlinkStatusExists(symlink->backing_path)) {
            log::Registry::fs()->error(
                "[Filesystem::createSymlink] Failed to create backing symlink at: {}",
                symlink->backing_path.string());
            return {-EIO, nullptr};
        }

        symlink->id = db::query::fs::Symlink::upsertSymlink(symlink);
        cache->cacheEntry(symlink);

        log::Registry::fs()->debug("[Filesystem::createSymlink] Successfully created symlink at path: {}", linkPath.string());
        return {0, symlink};
    } catch (const std::bad_alloc& ex) {
        log::Registry::fs()->error(
            "[Filesystem::createSymlink] Out of memory creating {}: {}",
            linkPath.string(),
            ex.what());
        return {-ENOMEM, nullptr};
    } catch (const std::filesystem::filesystem_error& ex) {
        log::Registry::fs()->error(
            "[Filesystem::createSymlink] Filesystem error creating {}: {}",
            linkPath.string(),
            ex.what());
        return {ex.code() ? -ex.code().value() : -EIO, nullptr};
    } catch (const std::exception& ex) {
        log::Registry::fs()->error(
            "[Filesystem::createSymlink] Failed to create symlink at path {}: {}",
            linkPath.string(),
            ex.what());
        return {-EIO, nullptr};
    } catch (...) {
        log::Registry::fs()->error(
            "[Filesystem::createSymlink] Unknown failure creating symlink at path: {}",
            linkPath.string());
        return {-EIO, nullptr};
    }
}

namespace {

// One entry of a copy: the source and where it goes. Planned before anything is written.
struct CopyItem {
    std::shared_ptr<Entry> source;
    std::filesystem::path to;       // destination FUSE path
    std::filesystem::path toVault;  // destination vault path
    std::string alias;
    std::filesystem::path backing;  // destination backing path (alias layout, under its destination parent)
    std::shared_ptr<File> content;  // files: the source row the copied bytes belong to (taken with them)
};

constexpr std::string_view kHttpUploadTempPrefix = ".upload-http-";

// In-flight HTTP upload staging files (fuse/Bridge.cpp) are not content: they are never copied.
bool isUploadStaging(const std::string& name) {
    return name.starts_with(kHttpUploadTempPrefix) && name.ends_with(".part");
}

std::size_t depthOf(const std::filesystem::path& p) {
    return static_cast<std::size_t>(std::ranges::distance(p.begin(), p.end()));
}

bool isWithin(const std::filesystem::path& path, const std::filesystem::path& root) {
    const auto rel = path.lexically_normal().lexically_relative(root.lexically_normal());
    return !rel.empty() && rel.native() != ".." && !rel.native().starts_with("../");
}

// Copies a sealed backing file byte for byte (copy_file_range/sendfile under the hood), durably, to a fresh path.
void copyBackingBytes(const std::filesystem::path& from, const std::filesystem::path& to) {
    replaceFileAtomic(to, [&](const std::filesystem::path& temp) {
        std::filesystem::copy_file(from, temp, std::filesystem::copy_options::overwrite_existing);
    });
}

} // namespace

int Filesystem::copy(const CopyContext& ctx) {
    const auto& from = ctx.from;
    const auto& to = ctx.to;
    const auto& cache = runtime::Deps::get().fsCache;

    std::shared_ptr<Engine> engine = ctx.engine;
    std::shared_ptr<Entry> destParent;
    std::vector<CopyItem> items;

    // 1. Plan: what is copied where. Nothing is written yet.
    try {
        {
            std::scoped_lock lock(mutex_);
            if (!storageManager_) {
                log::Registry::fs()->error("[Filesystem::copy] StorageManager is not initialized");
                return -EIO;
            }
            if (!engine) engine = storageManager_->resolveStorageEngine(from);
            if (!engine) {
                log::Registry::fs()->error("[Filesystem::copy] No storage engine found for source path: {}", from.string());
                return -EIO;
            }
            const auto toEngine = storageManager_->resolveStorageEngine(to);
            if (!toEngine) {
                log::Registry::fs()->error("[Filesystem::copy] No storage engine found for destination path: {}", to.string());
                return -EIO;
            }
            if (toEngine->vault->id != engine->vault->id) {
                log::Registry::fs()->error("[Filesystem::copy] Cross-vault copy not supported: {} -> {}", from.string(), to.string());
                return -EXDEV;
            }
        }

        if (from == to) return 0;

        const auto entry = cache->getEntry(from);
        if (!entry) {
            log::Registry::fs()->error("[Filesystem::copy] Source path does not exist: {}", from.string());
            return -ENOENT;
        }
        if (entry->isDirectory() && (!entry->parent_id || isWithin(to, from))) {
            log::Registry::fs()->error("[Filesystem::copy] Cannot copy {} into itself ({})", from.string(), to.string());
            return -EINVAL;
        }

        destParent = cache->getEntry(resolveParent(to));
        if (!destParent || !destParent->isDirectory()) {
            log::Registry::fs()->error("[Filesystem::copy] Destination parent does not exist: {}", to.parent_path().string());
            return -ENOENT;
        }
        if (cache->entryExists(to)) {
            log::Registry::fs()->error("[Filesystem::copy] Destination already exists: {}", to.string());
            return -EEXIST;
        }

        std::vector<std::shared_ptr<Entry>> sources{entry};
        if (entry->isDirectory()) {
            // From the database, the authority on what is under it (the cache can lag or hold stale entries).
            auto descendants = db::query::fs::Entry::listSubtree(entry->id);
            std::erase_if(descendants, [](const std::shared_ptr<Entry>& e) { return !e || isUploadStaging(e->name); });
            // Shallowest first, so every copied entry's destination parent is created before it.
            std::ranges::stable_sort(descendants, {}, [](const std::shared_ptr<Entry>& e) { return depthOf(e->path); });
            sources.insert(sources.end(), descendants.begin(), descendants.end());
        }

        const auto toVault = engine->fusePathToVaultPath(to);
        std::unordered_map<std::string, std::filesystem::path> backingOf;  // destination vault path -> backing path
        for (const auto& source : sources) {
            CopyItem item;
            item.source = source;
            if (source == entry) {
                item.toVault = toVault;
            } else {
                const auto rel = source->path.lexically_relative(entry->path);
                if (rel.empty() || rel.native().starts_with("..")) continue;  // not under the source (moved meanwhile)
                item.toVault = toVault / rel;
            }
            item.to = engine->vaultPathToFusePath(item.toVault);

            const auto parentVault = resolveParent(item.toVault);
            const auto parentBacking = source == entry ? destParent->backing_path : backingOf.at(parentVault.string());
            item.alias = id::Generator({ .namespace_token = item.to.filename().string() }).generate();
            item.backing = parentBacking / item.alias;
            if (source->isDirectory()) backingOf.emplace(item.toVault.string(), item.backing);

            if (source->isSymlink() &&
                targetEscapesVaultRoot(item.toVault, std::static_pointer_cast<Symlink>(source)->target)) {
                log::Registry::fs()->error("[Filesystem::copy] Symlink {} would point outside the vault at {}",
                                           source->path.string(), item.toVault.string());
                return -EINVAL;
            }
            items.push_back(std::move(item));
        }
    } catch (const std::out_of_range&) {
        log::Registry::fs()->error("[Filesystem::copy] The source tree of {} changed while copying it", from.string());
        return -EAGAIN;
    } catch (const std::exception& ex) {
        log::Registry::fs()->error("[Filesystem::copy] Failed to plan copying {} -> {}: {}", from.string(), to.string(), ex.what());
        return -EIO;
    }

    // 2. Authorize every entry before anything is written. A refusal propagates as thrown.
    if (ctx.authorize)
        for (const auto& item : items) ctx.authorize(*item.source, item.to);

    const auto cleanup = [&items] {
        if (items.empty()) return;
        std::error_code ec;
        std::filesystem::remove_all(items.front().backing, ec);
    };

    try {
        // 3. Cloud files with no local copy are fetched first (metered and price-preflighted like any remote read):
        //    a copy needs its bytes now, and the next sync uploads it as a new object.
        const auto cloud = engine->type() == StorageType::Cloud ? std::static_pointer_cast<CloudEngine>(engine) : nullptr;
        uintmax_t required = 0;
        for (auto& item : items) {
            if (item.source->isDirectory() || item.source->isSymlink()) continue;
            auto file = db::query::fs::File::getFileById(item.source->id);
            if (!file) {
                log::Registry::fs()->error("[Filesystem::copy] Source file vanished: {}", item.source->path.string());
                return -ENOENT;
            }
            std::error_code ec;
            const bool local = std::filesystem::is_regular_file(file->backing_path, ec);
            if (local) required += std::filesystem::file_size(file->backing_path, ec);
            else if (file->size_bytes > 0) {
                if (!cloud) {
                    log::Registry::fs()->error("[Filesystem::copy] {} has no bytes on disk: refusing to create an unreadable copy",
                                               file->path.string());
                    return -EIO;
                }
                // The hydrated source copy and the new one both count against the quota.
                required += 2 * (file->size_bytes + vh::crypto::util::AES_TAG_SIZE);
            }
        }

        // 4. Quota: everything the copy adds on disk, before any of it is written.
        if (required > 0 && required > engine->freeSpace()) {
            log::Registry::fs()->warn("[Filesystem::copy] {} -> {} needs {} bytes, more than the vault has left",
                                      from.string(), to.string(), required);
            return -ENOSPC;
        }

        // 5. Bytes: directories, then each file's sealed bytes under its content lock with the row that describes
        //    them, so an overwrite, FUSE seal or key rotation of the source can't hand us bytes of one generation and
        //    the IV of another. Not under mutex_: copying can take a while and the destinations are fresh names.
        for (auto& item : items) {
            if (item.source->isDirectory()) {
                std::filesystem::create_directories(item.backing);
                continue;
            }
            if (item.source->isSymlink()) {
                std::filesystem::create_directories(item.backing.parent_path());
                std::filesystem::create_symlink(std::static_pointer_cast<Symlink>(item.source)->target, item.backing);
                continue;
            }

            if (cloud) {
                const auto file = db::query::fs::File::getFileById(item.source->id);
                std::error_code ec;
                if (file && file->size_bytes > 0 && !std::filesystem::is_regular_file(file->backing_path, ec))
                    (void)cloud->hydrate(file);
            }

            std::scoped_lock contentLock(contentWriteMutex(item.source->id));
            const auto current = db::query::fs::File::getFileById(item.source->id);
            if (!current) {
                cleanup();
                return -ENOENT;
            }
            std::filesystem::create_directories(item.backing.parent_path());
            std::error_code ec;
            if (std::filesystem::is_regular_file(current->backing_path, ec)) copyBackingBytes(current->backing_path, item.backing);
            else if (current->size_bytes == 0) writeFileAtomic(item.backing, {});
            else {
                log::Registry::fs()->error("[Filesystem::copy] {} has no bytes on disk", current->path.string());
                cleanup();
                return -EIO;
            }
            item.content = current;
        }
    } catch (const ContentUnavailable& ex) {
        log::Registry::fs()->warn("[Filesystem::copy] {} -> {}: remote content unavailable: {}", from.string(), to.string(), ex.what());
        cleanup();
        return -ENODATA;
    } catch (const IntegrityError& ex) {
        log::Registry::fs()->error("[Filesystem::copy] {} -> {}: remote content failed authentication: {}", from.string(), to.string(), ex.what());
        cleanup();
        return -EIO;
    } catch (const std::filesystem::filesystem_error& ex) {
        log::Registry::fs()->error("[Filesystem::copy] Filesystem error copying {} -> {}: {}", from.string(), to.string(), ex.what());
        cleanup();
        return ex.code() ? -ex.code().value() : -EIO;
    } catch (const std::exception& ex) {
        log::Registry::fs()->error("[Filesystem::copy] Failed to copy {} -> {}: {}", from.string(), to.string(), ex.what());
        cleanup();
        return -EIO;
    }

    // 6. Rows, shallowest first: each one adds itself to its ancestors' totals, so a copied directory ends up with
    //    the totals of what it holds (#158).
    std::scoped_lock lock(mutex_);
    std::optional<unsigned int> topId;
    try {
        if (cache->entryExists(to)) {
            cleanup();
            return -EEXIST;
        }
        const auto parentNow = cache->getEntry(resolveParent(to));
        if (!parentNow || parentNow->id != destParent->id) {
            cleanup();
            return -ENOENT;
        }

        std::unordered_map<std::string, unsigned int> idOf;  // destination vault path -> new row id
        const auto now = std::time(nullptr);
        for (auto& item : items) {
            const auto parentId = item.source == items.front().source
                                      ? destParent->id
                                      : idOf.at(resolveParent(item.toVault).string());
            const auto name = item.to.filename().string();
            const auto stamp = [&](Entry& e) {
                e.id = 0;
                e.vault_id = engine->vault->id;
                e.parent_id = static_cast<int32_t>(parentId);
                e.name = name;
                e.path = item.toVault;
                e.fuse_path = item.to;
                e.base32_alias = item.alias;
                e.backing_path = item.backing;
                e.created_by = e.last_modified_by = static_cast<int32_t>(ctx.userId);
                e.created_at = e.updated_at = now;
                e.is_hidden = !name.empty() && name.front() == '.' && !name.starts_with("..");
                e.is_system = false;
            };

            std::shared_ptr<Entry> created;
            if (item.source->isDirectory()) {
                auto dir = std::make_shared<Directory>(*std::static_pointer_cast<Directory>(item.source));
                stamp(*dir);
                dir->inode = cache->assignInode(item.to);
                dir->size_bytes = 0;          // totals arrive with each copied child
                dir->file_count = 0;
                dir->subdirectory_count = 0;
                dir->id = db::query::fs::Directory::upsertDirectory(dir);
                idOf.emplace(item.toVault.string(), dir->id);
                created = dir;
            } else if (item.source->isSymlink()) {
                auto link = std::make_shared<Symlink>(*std::static_pointer_cast<Symlink>(item.source));
                stamp(*link);
                link->inode = cache->getOrAssignInode(item.to);
                link->size_bytes = link->target.size();
                link->id = db::query::fs::Symlink::upsertSymlink(link);
                created = link;
            } else {
                // The row the bytes were copied with: same IV, key version, plaintext size and content hash.
                auto file = std::make_shared<File>(*item.content);
                stamp(*file);
                file->inode = cache->getOrAssignInode(item.to);
                file->id = db::query::fs::File::upsertFile(file);
                created = file;
            }
            if (!topId) topId = created->id;
            cache->cacheEntry(created);
        }
    } catch (const std::exception& ex) {
        log::Registry::fs()->error("[Filesystem::copy] Failed to record the copy {} -> {}: {}", from.string(), to.string(), ex.what());
        // Take back what was recorded: the top row with everything under it, off its ancestors' totals.
        try {
            if (topId) {
                db::query::fs::Directory::deleteDirectoryTree(*topId);
                for (const auto& item : items) cache->evictPath(item.to);
                cache->refreshDirStats(destParent->id);
            }
        } catch (const std::exception& undo) {
            log::Registry::fs()->error("[Filesystem::copy] Could not take back the partial copy at {}: {}", to.string(), undo.what());
        }
        cleanup();
        return -EIO;
    }

    // Derived artifacts (thumbnails, renders) are keyed by file id: the copies derive their own on demand.
    log::Registry::fs()->debug("[Filesystem::copy] Copied {} -> {} ({} entries)", from.string(), to.string(), items.size());
    return 0;
}

void Filesystem::remove(const std::filesystem::path& path, const unsigned int userId) {
    const auto& cache = runtime::Deps::get().fsCache;
    const auto entry = cache->getEntry(path);
    if (!entry) throw std::runtime_error("[Filesystem] Path does not exist in cache: " + path.string());
    if (!entry->vault_id) throw std::runtime_error("[Filesystem] Entry has no associated vault ID: " + path.string());
    const auto ancestors = db::query::fs::Directory::ancestorsOf(entry->id);

    // !!! DO NOT CALL THIS FUNCTION DIRECTLY FROM FUSE CALLBACKS - WEBSOCKET OR INTERNAL ONLY !!!
    // This function recursively marks files as trashed in the database and deletes their backing paths
    // which is incompatible with how FUSE expects unlink/rmdir to behave.

    // Trashing ends a file id (its cache_index rows cascade): its sealed derived artifacts go with it.
    const auto engine = storageManager_ ? storageManager_->getEngine(*entry->vault_id) : nullptr;
    const auto purgeDerived = [&engine](const unsigned int fileId) {
        if (engine) engine->purgeDerivedArtifacts(fileId);
    };

    // Local versioning keeps each removed file's last generation (linked before its row goes; the backing file is
    // removed below, after the trash committed). Under the file's content lock with the row re-read: a seal, overwrite
    // or rotation that renamed new bytes over the backing file since `file` was read would otherwise be linked under
    // the old IV. The cache entry goes under the lock too, so a seal that waited for it finds nothing to write back.
    const auto trash = [&](const File& file, const std::function<void(pqxx::work&)>& markTrashed) {
        std::scoped_lock contentLock(contentWriteMutex(file.id));
        const auto current = engine ? db::query::fs::File::getFileById(file.id) : nullptr;
        auto kept = current ? recovery::local::versions::retain(*engine, *current, recovery::local::Reason::Delete,
                                                                {.actor = userId})
                            : recovery::local::versions::Pending{};
        db::Transactions::exec("Filesystem::remove", [&](pqxx::work& txn) {
            kept.attach(txn);
            markTrashed(txn);
        });
        kept.committed();
        if (!file.fuse_path.empty()) cache->evictPath(file.fuse_path);
    };

    if (entry->isDirectory()) {
        for (const auto& file : db::query::fs::File::listFilesInDir(*entry->vault_id, entry->path, true)) {
            trash(*file, [&](pqxx::work& txn) {
                db::query::fs::File::markFileAsTrashed(txn, userId, file->id, file->backing_path);
            });
            cache->evictPath(file->fuse_path);
            purgeDerived(file->id);
        }
        // Trashing files never removes folders (#168): the directory, its subfolders and any symlinks are still
        // there. Delete what is left, off its ancestors' totals. Its subfolders and symlinks leave the cache too: a
        // stale cached subfolder answered lookups after the delete and became the (deleted) parent of anything
        // created again at its path.
        const auto remaining = engine ? db::query::fs::Entry::listSubtree(entry->id)
                                      : std::vector<std::shared_ptr<Entry>>{};
        db::query::fs::Directory::deleteDirectoryTree(entry->id);
        for (const auto& e : remaining)
            if (e) cache->evictPath(engine->vaultPathToFusePath(e->path));
        cache->evictPath(path);
    }
    else if (entry->isSymlink()) {
        db::query::fs::Symlink::deleteSymlink(std::static_pointer_cast<Symlink>(entry));
        cache->evictPath(path);
    }
    else {
        trash(static_cast<const File&>(*entry), [&](pqxx::work& txn) {
            db::query::fs::File::markFileAsTrashed(txn, userId, static_cast<unsigned int>(*entry->vault_id), entry->path,
                                                   entry->backing_path);
        });
        cache->evictPath(path);
        purgeDerived(entry->id);
    }

    if (entry->isSymlink()) {
        if (symlinkStatusExists(entry->backing_path)) std::filesystem::remove(entry->backing_path);
    } else if (std::filesystem::exists(entry->backing_path)) std::filesystem::remove_all(entry->backing_path);

    // fs.dir.list reads directory totals from the cache: refresh what the delete changed (#158). Deleting never
    // removes the parent folder (#168); the loop only guards against a concurrent delete of it.
    for (const auto id : ancestors)
        if (cache->refreshDirStats(id)) break;
}

std::mutex& Filesystem::contentWriteMutex(const uint32_t fileId) {
    static std::array<std::mutex, 128> stripes;
    return stripes[fileId % stripes.size()];
}

std::shared_ptr<File> Filesystem::createFile(const NewFileContext& ctx) {
    if (!ctx.user) throw std::runtime_error("[Filesystem] File creation requires a user");

    const auto engine = ctx.engine ? ctx.engine : storageManager_->resolveStorageEngine(ctx.path);
    if (!engine) throw std::runtime_error("[Filesystem] No storage engine found for file creation");

    log::Registry::fs()->debug("Creating file at path: {}, fuse_path: {}", ctx.path.string(), ctx.fuse_path.string());

    const auto& cache = runtime::Deps::get().fsCache;

    if (ctx.path.empty()) throw std::runtime_error("Cannot create file at empty path");
    if (cache->entryExists(ctx.fuse_path)) {
        if (!ctx.overwrite) {
            log::Registry::fs()->warn("File already exists at path: {}", ctx.fuse_path.string());
            const auto entry = cache->getEntry(ctx.fuse_path);
            if (entry->isDirectory()) throw std::filesystem::filesystem_error(
                "[Filesystem] Cannot create file at path, a directory already exists",
                ctx.fuse_path,
                std::make_error_code(std::errc::file_exists));
            return std::static_pointer_cast<File>(entry);
        }

        log::Registry::fs()->debug("File already exists at path: {}, overwriting", ctx.fuse_path.string());
        auto entry = cache->getEntry(ctx.fuse_path);
        if (entry->isDirectory()) {
            log::Registry::fs()->error("Cannot overwrite directory with file at path: {}", ctx.fuse_path.string());
            throw std::filesystem::filesystem_error(
                "[Filesystem] Cannot overwrite directory with file",
                ctx.fuse_path,
                std::make_error_code(std::errc::file_exists));
        }

        const auto f = std::static_pointer_cast<File>(entry);

        // Overwrites, FUSE seals and key rotation of one file are serialized (one lock per file id), so a conditional
        // write (expected_source_id) is a true compare-and-swap and rotation can't rename stale bytes over new ones.
        // Blobs the version capture frees (keep_last) are unlinked after the content lock is released.
        const recovery::local::versions::DeferBlobFrees deferFrees;
        std::scoped_lock contentLock(contentWriteMutex(f->id));
        if (cache->getEntry(ctx.fuse_path) != entry)
            throw ContentConflict("The file was replaced while it was being saved");
        if (ctx.expected_source_id) {
            if (storage::generationOf(*f).sourceId() != *ctx.expected_source_id)
                throw ContentConflict("The file changed since it was read");
            if (f->inode && fuse::WorkingCopies::instance().isOpen(*f->inode))
                throw ContentConflict("The file is open through the mounted filesystem");
        }
        std::filesystem::create_directories(entry->backing_path.parent_path());

        // Crash-safe order: new ciphertext -> sidecar (fsynced), row updated, sidecar renamed over the backing file.
        // A crash before the row update leaves the old bytes and row; after it, recovery promotes the sidecar (it
        // authenticates under the row). A failed row update removes the sidecar: old bytes, old row, cache untouched.
        const auto staged = std::make_shared<File>(*f);
        const auto sidecar = contentSidecarPath(entry->backing_path);
        std::error_code ec;
        const auto existing = std::filesystem::status(entry->backing_path, ec);
        const auto mode = static_cast<mode_t>(
            ec || !std::filesystem::exists(existing) ? 0600 : static_cast<unsigned>(existing.permissions()) & 0777u);
        ec.clear();
        std::filesystem::remove(sidecar, ec);  // a leftover is settled by startup recovery; we hold the file's lock
        try {
            std::optional<std::string> sealedHash;
            if (ctx.sealed) {
                const auto sealed = ctx.sealed(sidecar);
                sealedHash = sealed.content_hash;
                std::filesystem::permissions(sidecar, static_cast<std::filesystem::perms>(mode),
                                             std::filesystem::perm_options::replace);
                fsyncFile(sidecar);
                staged->encryption_iv = sealed.encryption_iv;
                staged->encrypted_with_key_version = sealed.key_version;
                staged->size_bytes = sealed.plaintext_size;
                staged->mime_type = sealed.mime_type ? *sealed.mime_type : inferMimeTypeFromPath(ctx.path);
            } else if (ctx.source_path) {
                const auto plaintextSize = std::filesystem::file_size(*ctx.source_path);
                if (plaintextSize == 0) {
                    writeFileExclusive(sidecar, {}, mode);
                    staged->encryption_iv.clear();
                    staged->encrypted_with_key_version = 0;
                } else {
                    engine->encryptionManager->encryptFileToFile(*ctx.source_path, sidecar, staged);
                    std::filesystem::permissions(sidecar, static_cast<std::filesystem::perms>(mode),
                                                 std::filesystem::perm_options::replace);
                    fsyncFile(sidecar);
                }
                staged->size_bytes = plaintextSize;
                staged->mime_type = mimeTypeFromSourceFile(*ctx.source_path, ctx.path);
            } else if (!ctx.buffer.empty()) {
                const auto ciphertext = engine->encryptionManager->encrypt(ctx.buffer, staged);
                writeFileExclusive(sidecar, ciphertext, mode);
                staged->size_bytes = ctx.buffer.size();
                staged->mime_type = Magic::get_mime_type_from_buffer(ctx.buffer);
            } else {
                writeFileExclusive(sidecar, {}, mode);
                staged->encryption_iv.clear();
                staged->encrypted_with_key_version = 0;
                staged->size_bytes = 0;
                staged->mime_type = inferMimeTypeFromPath(ctx.path);
            }
            fsyncDirectory(entry->backing_path.parent_path());

            staged->content_hash = sealedHash ? *sealedHash : hash::blake2b(sidecar);
            staged->last_modified_by = userIdFor(ctx.user);
            staged->updated_at = std::time(nullptr);

            // Local versioning keeps the generation being replaced (a link to its inode, staged before the row
            // changes; the rename below never writes that inode again), recorded in the row's transaction.
            auto kept = recovery::local::versions::retain(
                *engine, *f, ctx.version_reason.value_or(recovery::local::Reason::Overwrite),
                {.actor = ctx.user ? std::make_optional(ctx.user->id) : std::nullopt});
            db::Transactions::exec("Filesystem::createFile overwrite", [&](pqxx::work& txn) {
                kept.attach(txn);
                db::query::fs::File::updateFile(txn, staged);
            });
            kept.committed();
        } catch (...) {
            std::filesystem::remove(sidecar, ec);
            throw;
        }

        // The row describes the sidecar now; a failed rename leaves it for recovery to promote.
        std::filesystem::rename(sidecar, entry->backing_path);
        fsyncDirectory(entry->backing_path.parent_path());

        f->encryption_iv = staged->encryption_iv;
        f->encrypted_with_key_version = staged->encrypted_with_key_version;
        f->size_bytes = staged->size_bytes;
        f->mime_type = staged->mime_type;
        f->content_hash = staged->content_hash;
        f->last_modified_by = staged->last_modified_by;
        f->updated_at = staged->updated_at;
        // The size difference reached every ancestor's row; the cached directories (fs.dir.list) follow.
        if (f->parent_id) runtime::Deps::get().fsCache->refreshDirStats(*f->parent_id);

        // The new IV is a new source generation: earlier thumbnails no longer match it and are regenerated.
        if (f->size_bytes > 0 && f->mime_type && isPreviewable(*f->mime_type))
            preview::render::enqueueThumbnails(engine, f, ctx.buffer);

        return f;
    }

    const auto parent = runtime::Deps::get().fsCache->getEntry(resolveParent(ctx.fuse_path));
    if (!parent) {
        log::Registry::fs()->error("Parent directory does not exist for path: {}", ctx.fuse_path.string());
        throw std::filesystem::filesystem_error(
            "[Filesystem] Parent directory does not exist",
            ctx.fuse_path,
            std::make_error_code(std::errc::no_such_file_or_directory));
    }

    const auto f = std::make_shared<File>();
    f->parent_id = parent->id;
    f->vault_id = engine->vault->id;
    f->name = ctx.path.filename();
    f->path = ctx.path;
    f->fuse_path = ctx.fuse_path;
    f->base32_alias = id::Generator({ .namespace_token = f->name }).generate();
    f->backing_path = parent->backing_path / f->base32_alias;
    f->mode = ctx.mode;
    f->owner_uid = linuxUidFor(ctx.user);
    f->group_gid = linuxGidFor(ctx.group);
    f->is_hidden = ctx.path.filename().string().starts_with('.');
    f->created_by = f->last_modified_by = userIdFor(ctx.user);
    f->created_at = f->updated_at = std::time(nullptr);
    f->inode = std::make_optional(cache->getOrAssignInode(ctx.fuse_path));
    f->mime_type = ctx.source_path
        ? mimeTypeFromSourceFile(*ctx.source_path, ctx.path)
        : (ctx.buffer.empty() ? inferMimeTypeFromPath(ctx.path) : Magic::get_mime_type_from_buffer(ctx.buffer));
    f->size_bytes = ctx.source_path ? std::filesystem::file_size(*ctx.source_path) : ctx.buffer.size();

    // A new file at a fresh alias. Created exclusively or replaced by rename, never written in place: a retained
    // generation may share an existing backing inode (recovery.md, "Local storage").
    std::filesystem::create_directories(f->backing_path.parent_path());
    std::optional<std::string> sealedHash;
    if (ctx.sealed) {
        replaceFileAtomic(f->backing_path, [&](const std::filesystem::path& temp) {
            std::filesystem::remove(temp);   // a SealedWriter creates its destination itself (private random name)
            const auto sealed = ctx.sealed(temp);
            sealedHash = sealed.content_hash;
            f->encryption_iv = sealed.encryption_iv;
            f->encrypted_with_key_version = sealed.key_version;
            f->size_bytes = sealed.plaintext_size;
            if (sealed.mime_type) f->mime_type = sealed.mime_type;
        });
    } else if (ctx.source_path && f->size_bytes > 0) {
        replaceFileAtomic(f->backing_path, [&](const std::filesystem::path& temp) {
            engine->encryptionManager->encryptFileToFile(*ctx.source_path, temp, f);
        });
    } else if (ctx.source_path || ctx.buffer.empty()) writeFileExclusive(f->backing_path, {}, 0600);
    else {
        const auto ciphertext = engine->encryptionManager->encrypt(ctx.buffer, f);
        writeFileAtomic(f->backing_path, ciphertext);
    }

    f->content_hash = sealedHash ? *sealedHash : hash::blake2b(f->backing_path);

    if (!std::filesystem::exists(f->backing_path))
        throw std::runtime_error("[Filesystem] Failed to create real file at: " + f->backing_path.string());

    f->id = db::query::fs::File::upsertFile(f);
    cache->cacheEntry(f);

    if (f->size_bytes > 0 && f->mime_type && isPreviewable(*f->mime_type))
        preview::render::enqueueThumbnails(engine, f, ctx.buffer);

    log::Registry::fs()->debug("Successfully created file at path: {}", ctx.path.string());
    return f;
}

std::pair<int, std::shared_ptr<model::Entry>>
Filesystem::createFile(const FuseCreateFileContext& ctx) {
    const auto& resolved = ctx.resolved;
    const auto path = resolved.path.value_or(std::filesystem::path{});

    std::scoped_lock lock(mutex_);

    try {
        if (!resolved.ok()) return {-resolved.errnum, nullptr};
        if (!resolved.user) return {-EACCES, nullptr};
        if (!resolved.path || !resolved.engine || !resolved.parentEntry) return {-EINVAL, nullptr};

        if (!storageManager_) {
            log::Registry::fs()->error("[Filesystem::createFile] StorageManager is not initialized");
            return {-EIO, nullptr};
        }

        const auto& engine = resolved.engine;

        const auto& cache = runtime::Deps::get().fsCache;

        log::Registry::fs()->debug("[Filesystem::createFile] Creating file at path: {}", path.string());

        const auto parent = resolved.parentEntry;
        if (!parent) {
            log::Registry::fs()->error(
                "[Filesystem::createFile] Parent directory does not exist: {}",
                path.parent_path().string());
            return {-ENOENT, nullptr};
        }

        if (cache->entryExists(path)) {
            log::Registry::fs()->error(
                "[Filesystem::createFile] File already exists: {}",
                path.string());
            return {-EEXIST, nullptr};
        }

        auto f = std::make_shared<File>();
        f->parent_id = parent->id;
        f->vault_id = engine->vault->id;
        f->name = path.filename();
        f->path = engine->fusePathToVaultPath(path);
        f->fuse_path = path;
        f->base32_alias = id::Generator({ .namespace_token = f->name }).generate();
        f->backing_path = parent->backing_path / f->base32_alias;
        f->mode = ctx.mode;
        f->owner_uid = linuxUidFor(resolved.user);
        f->group_gid = linuxGidFor(resolved.group);
        f->is_hidden = !f->name.empty() && f->name.starts_with('.');
        f->created_by = f->last_modified_by = userIdFor(resolved.user);
        f->created_at = std::time(nullptr);
        f->updated_at = f->created_at;
        f->inode = std::make_optional(cache->getOrAssignInode(path));
        f->mime_type = inferMimeTypeFromPath(path.filename());
        f->size_bytes = 0;

        try {
            std::filesystem::create_directories(f->backing_path.parent_path());
            writeFileExclusive(f->backing_path, {}, 0600);
        } catch (const std::filesystem::filesystem_error& ex) {
            log::Registry::fs()->error(
                "[Filesystem::createFile] Failed to create backing file for {}: {}",
                path.string(),
                ex.what());
            return {ex.code() ? -ex.code().value() : -EIO, nullptr};
        } catch (const std::exception& ex) {
            log::Registry::fs()->error(
                "[Filesystem::createFile] Failed to create backing file for {}: {}",
                path.string(),
                ex.what());
            return {-EIO, nullptr};
        }

        if (!std::filesystem::exists(f->backing_path)) {
            log::Registry::fs()->error(
                "[Filesystem::createFile] Failed to create real file at: {}",
                f->backing_path.string());
            return {-EIO, nullptr};
        }

        f->content_hash = hash::blake2b(f->backing_path);
        f->id = db::query::fs::File::upsertFile(f);
        cache->cacheEntry(f);

        log::Registry::fs()->debug("[Filesystem::createFile] Successfully created file at path: {}", path.string());
        return {0, f};
    } catch (const std::bad_alloc& ex) {
        log::Registry::fs()->error(
            "[Filesystem::createFile] Out of memory creating {}: {}",
            path.string(),
            ex.what());
        return {-ENOMEM, nullptr};
    } catch (const std::filesystem::filesystem_error& ex) {
        log::Registry::fs()->error(
            "[Filesystem::createFile] Filesystem error creating {}: {}",
            path.string(),
            ex.what());
        return {ex.code() ? -ex.code().value() : -EIO, nullptr};
    } catch (const std::exception& ex) {
        log::Registry::fs()->error(
            "[Filesystem::createFile] Failed to create file at path {}: {}",
            path.string(),
            ex.what());
        return {-EIO, nullptr};
    } catch (...) {
        log::Registry::fs()->error(
            "[Filesystem::createFile] Unknown failure creating file at path: {}",
            path.string());
        return {-EIO, nullptr};
    }
}

void RenameJournal::rollback() noexcept {
    for (auto it = moved.rbegin(); it != moved.rend(); ++it) {
        std::error_code ec;
        std::filesystem::rename(it->second, it->first, ec);
        if (ec) {
            try {
                log::Registry::fs()->error("[Filesystem::rename] Rollback could not move {} back to {}: {}",
                                           it->second.string(), it->first.string(), ec.message());
            } catch (...) {}
        }
    }
    // Only what the rename created; a folder only once it is empty again.
    for (auto it = created.rbegin(); it != created.rend(); ++it) {
        std::error_code ec;
        std::filesystem::remove(*it, ec);
    }
    moved.clear();
    created.clear();
}

namespace {

// The rename works on copies: the cached entries (shared with every in-flight FUSE op) change only once it commits.
std::shared_ptr<Entry> cloneEntry(const std::shared_ptr<Entry>& e) {
    if (const auto d = std::dynamic_pointer_cast<Directory>(e)) return std::make_shared<Directory>(*d);
    if (const auto s = std::dynamic_pointer_cast<Symlink>(e)) return std::make_shared<Symlink>(*s);
    if (const auto f = std::dynamic_pointer_cast<File>(e)) return std::make_shared<File>(*f);
    throw std::runtime_error("unknown entry type: " + e->fuse_path.string());
}

// A failure inside the rename transaction that already has its errno: rolls the transaction back.
struct RenameAborted : std::runtime_error {
    int rc;
    RenameAborted(const int code, const std::string& what) : std::runtime_error(what), rc(code) {}
};

// rename(2)'s rules for replacing `target` with `source`; 0 when it may.
int replaceRefusal(const std::shared_ptr<Entry>& source, const std::shared_ptr<Entry>& target) {
    if (!target->parent_id) return -EBUSY;  // a vault root
    if (source->isDirectory()) {
        if (!target->isDirectory()) return -ENOTDIR;
        if (!vh::db::query::fs::Directory::isDirectoryEmpty(target->id)) return -ENOTEMPTY;
        return 0;
    }
    return target->isDirectory() ? -EISDIR : 0;
}

}

int Filesystem::rename(const std::filesystem::path& oldPath,
                       const std::filesystem::path& newPath,
                       const std::shared_ptr<identities::User>& user,
                       std::shared_ptr<Engine> engine,
                       const RenameMode mode) {
    std::scoped_lock lock(mutex_);
    RenameJournal journal;

    try {
        log::Registry::fs()->debug("[Filesystem::rename] Renaming {} to {}", oldPath.string(), newPath.string());

        if (!storageManager_) {
            log::Registry::fs()->error("[Filesystem::rename] StorageManager is not initialized");
            return -EIO;
        }

        if (oldPath == newPath)
            return 0;

        const auto& cache = runtime::Deps::get().fsCache;
        const auto entry = cache->getEntry(oldPath);
        if (!entry) {
            log::Registry::fs()->error(
                "[Filesystem::rename] Source entry not found: {}",
                oldPath.string());
            return -ENOENT;
        }

        if (!engine)
            engine = storageManager_->resolveStorageEngine(oldPath);

        if (!engine) {
            log::Registry::fs()->error(
                "[Filesystem::rename] No storage engine found for source path: {}",
                oldPath.string());
            return -ENOENT;
        }

        const auto toEngine = storageManager_->resolveStorageEngine(newPath);
        if (!toEngine) {
            log::Registry::fs()->error(
                "[Filesystem::rename] No storage engine found for destination path: {}",
                newPath.string());
            return -ENOENT;
        }

        if (toEngine->vault->id != engine->vault->id) {
            log::Registry::fs()->error(
                "[Filesystem::rename] Cross-vault rename not supported: {} -> {}",
                oldPath.string(),
                newPath.string());
            return -EXDEV;
        }

        if (entry->isDirectory() && !entry->parent_id) {
            log::Registry::fs()->error("[Filesystem::rename] Cannot rename root directory: {}", oldPath.string());
            return -EBUSY;
        }

        if (isWithin(newPath, oldPath)) return -EINVAL;  // a folder into itself

        const auto destParent = cache->getEntry(resolveParent(newPath));
        if (!destParent || !destParent->isDirectory()) {
            log::Registry::fs()->error(
                "[Filesystem::rename] Parent directory does not exist: {}",
                resolveParent(newPath).string());
            return destParent ? -ENOTDIR : -ENOENT;
        }

        // An existing destination: refused, or replaced the way rename(2) replaces it.
        const auto replaced = cache->getEntry(newPath);
        if (replaced && replaced->id == entry->id) return 0;
        if (replaced) {
            if (mode != RenameMode::Replace) return -EEXIST;
            if (const auto refusal = replaceRefusal(entry, replaced)) return refusal;
        }

        // Everything under a directory moves with it, shallowest first so each child's new parent is known.
        std::vector<std::shared_ptr<Entry>> descendants;
        if (entry->isDirectory()) {
            descendants = cache->listDir(entry->id, true);
            std::ranges::stable_sort(descendants, {}, [](const std::shared_ptr<Entry>& e) {
                return std::ranges::distance(e->fuse_path.begin(), e->fuse_path.end());
            });
        }

        const auto moved = cloneEntry(entry);
        std::vector<std::pair<std::filesystem::path, std::shared_ptr<Entry>>> renamed;  // old FUSE path -> new entry
        std::optional<unsigned int> previousParentId;

        // A replaced file's content is a generation local versioning keeps (an editor's save is an overwrite): staged
        // under its content lock, from its row as it is now, like every other capture, and recorded in the rename's
        // transaction.
        std::unique_lock<std::mutex> replacedLock;
        std::optional<recovery::local::versions::Pending> keptReplaced;
        if (replaced && !replaced->isDirectory() && !replaced->isSymlink() && engine) {
            replacedLock = std::unique_lock(contentWriteMutex(replaced->id));
            if (const auto current = db::query::fs::File::getFileById(replaced->id))
                keptReplaced.emplace(recovery::local::versions::retain(
                    *engine, *current, recovery::local::Reason::Overwrite,
                    {.actor = user ? std::make_optional(user->id) : std::nullopt}));
        }

        db::Transactions::exec("Filesystem::rename", [&](pqxx::work& txn) {
            renamed.clear();
            std::vector<uint8_t> buffer;

            if (replaced) {
                if (replaced->isDirectory()) {
                    if (!db::query::fs::Directory::deleteEmptyDirectory(txn, replaced->id))
                        throw RenameAborted(-ENOTEMPTY, "destination folder is not empty: " + newPath.string());
                } else if (replaced->isSymlink()) {
                    db::query::fs::Symlink::deleteSymlink(txn, replaced->id);
                } else {
                    const auto uid = user ? std::optional<unsigned int>(user->id) : std::nullopt;
                    if (keptReplaced) keptReplaced->attach(txn);
                    db::query::fs::File::markFileAsTrashed(txn, uid, replaced->id, replaced->backing_path);
                }
            }

            // The subtree totals the entry carries to its ancestors, taken before anything changes (#158).
            const auto totals = db::query::fs::Directory::subtreeTotalsOf(txn, entry->id);
            const auto oldParentId = db::query::fs::Directory::parentIdOf(txn, entry->id);

            if (const auto rc = handleRename({
                    .from = oldPath,
                    .to = newPath,
                    .buffer = buffer,
                    .user = user,
                    .engine = engine,
                    .entry = moved,
                    .parent = destParent,
                    .journal = journal,
                    .txn = txn
                }); rc != 0)
                throw RenameAborted(rc, "could not rename " + oldPath.string());
            renamed.emplace_back(oldPath, moved);

            std::unordered_map<std::string, std::shared_ptr<Entry>> byNewPath{{newPath.string(), moved}};
            for (const auto& item : descendants) {
                buffer.clear();
                const auto child = cloneEntry(item);
                const auto to = updateSubdirPath(oldPath, newPath, item->fuse_path);
                const auto parentIt = byNewPath.find(resolveParent(to).string());
                if (parentIt == byNewPath.end())
                    throw RenameAborted(-EIO, "no renamed parent for " + item->fuse_path.string());

                if (const auto rc = handleRename({
                        .from = item->fuse_path,
                        .to = to,
                        .buffer = buffer,
                        .user = user,
                        .engine = engine,
                        .entry = child,
                        .parent = parentIt->second,
                        .journal = journal,
                        .txn = txn
                    }); rc != 0)
                    throw RenameAborted(rc, "could not rename " + item->fuse_path.string());
                renamed.emplace_back(item->fuse_path, child);
                if (child->isDirectory()) byNewPath.emplace(to.string(), child);
            }

            if (totals)
                db::query::fs::Directory::shiftSubtreeTotals(
                    txn, oldParentId, db::query::fs::Directory::parentIdOf(txn, entry->id), *totals);
            previousParentId = oldParentId;
        });

        // Committed: nothing below may undo it.
        journal.moved.clear();
        journal.created.clear();
        if (keptReplaced) keptReplaced->committed();

        const auto removeBacking = [](const std::filesystem::path& p, const bool recursive) {
            std::error_code ec;
            if (recursive) std::filesystem::remove_all(p, ec);
            else std::filesystem::remove(p, ec);
            if (ec)
                log::Registry::fs()->warn("[Filesystem::rename] Renamed, but could not remove {}: {}", p.string(),
                                          ec.message());
        };

        // Whatever is left at the old place: a folder's emptied tree (a moved file or symlink is no longer there).
        if (moved->backing_path != entry->backing_path) removeBacking(entry->backing_path, true);

        if (replaced) {
            removeBacking(replaced->backing_path, false);
            // The file id ended with the trash: drop its sealed derived artifacts, as unlink does.
            if (!replaced->isDirectory() && !replaced->isSymlink()) engine->purgeDerivedArtifacts(replaced->id);
            cache->evictPath(newPath);
        }

        for (const auto& [from, item] : renamed) cache->evictPath(from);
        for (const auto& [from, item] : renamed) cache->cacheEntry(item);  // also refreshes new parent chains
        if (previousParentId) cache->refreshDirStats(*previousParentId);
        if (replaced && replaced->parent_id) cache->refreshDirStats(static_cast<unsigned int>(*replaced->parent_id));

        log::Registry::fs()->debug("[Filesystem::rename] Successfully renamed {} to {}{}", oldPath.string(),
                                   newPath.string(), replaced ? " (replaced)" : "");
        return 0;
    } catch (const RenameAborted& ex) {
        journal.rollback();
        log::Registry::fs()->error("[Filesystem::rename] {} -> {}: {}", oldPath.string(), newPath.string(), ex.what());
        return ex.rc;
    } catch (const std::bad_alloc& ex) {
        journal.rollback();
        log::Registry::fs()->error(
            "[Filesystem::rename] Out of memory renaming {} -> {}: {}",
            oldPath.string(),
            newPath.string(),
            ex.what());
        return -ENOMEM;
    } catch (const std::filesystem::filesystem_error& ex) {
        journal.rollback();
        log::Registry::fs()->error(
            "[Filesystem::rename] Filesystem error renaming {} -> {}: {}",
            oldPath.string(),
            newPath.string(),
            ex.what());
        return ex.code() ? -ex.code().value() : -EIO;
    } catch (const std::exception& ex) {
        journal.rollback();
        log::Registry::fs()->error(
            "[Filesystem::rename] Failed to rename {} -> {}: {}",
            oldPath.string(),
            newPath.string(),
            ex.what());
        return -EIO;
    } catch (...) {
        journal.rollback();
        log::Registry::fs()->error(
            "[Filesystem::rename] Unknown failure renaming {} -> {}",
            oldPath.string(),
            newPath.string());
        return -EIO;
    }
}

// Moves one entry (a private copy, see RenameContext) inside the rename's transaction. Exceptions propagate: the
// caller rolls the transaction and ctx.journal back.
int Filesystem::handleRename(const RenameContext& ctx) {
    const auto& entry = ctx.entry;
    if (!entry || !ctx.parent) {
        log::Registry::fs()->error("[Filesystem::handleRename] Null entry or parent for {} -> {}", ctx.from.string(),
                                   ctx.to.string());
        return -EINVAL;
    }

    const auto oldBackingPath = entry->backing_path;
    if (!symlinkStatusExists(oldBackingPath)) {
        log::Registry::fs()->error(
            "[Filesystem::handleRename] Source backing path does not exist: {}",
            oldBackingPath.string());
        return -ENOENT;
    }

    if (entry->id == 0) {
        const auto e = runtime::Deps::get().fsCache->getEntry(entry->fuse_path);
        entry->id = e ? e->id : 0;
    }

    const auto oldVaultPath = entry->path;

    entry->name = ctx.to.filename();
    entry->path = ctx.engine->fusePathToVaultPath(ctx.to);
    entry->fuse_path = ctx.to;
    entry->parent_id = ctx.parent->id;
    entry->last_modified_by = userIdFor(ctx.user);
    entry->updated_at = std::time(nullptr);
    entry->backing_path = ctx.parent->backing_path / entry->base32_alias;

    if (entry->isDirectory()) {
        if (std::filesystem::create_directories(entry->backing_path))
            ctx.journal.created.push_back(entry->backing_path);
    } else if (entry->isSymlink() || canFastPath(entry, ctx.engine)) {
        // Within a vault the bytes only move (see canFastPath).
        if (entry->backing_path != oldBackingPath) {
            std::filesystem::rename(oldBackingPath, entry->backing_path);
            ctx.journal.moved.emplace_back(oldBackingPath, entry->backing_path);
        }
    } else {
        const auto f = std::static_pointer_cast<File>(entry);
        auto buffer = ctx.buffer;

        if (!f->encryption_iv.empty()) buffer = decrypt_file_to_memory(ctx.engine->vault->id, oldVaultPath, ctx.engine);
        else buffer = readFileToVector(oldBackingPath);

        // Replaced by rename, never written in place (the old backing path may be this one, and a retained
        // generation may share its inode).
        ctx.journal.created.push_back(entry->backing_path);
        if (buffer.empty()) {
            writeFileAtomic(entry->backing_path, {});

            if (!std::filesystem::exists(entry->backing_path)) {
                log::Registry::fs()->error(
                    "[Filesystem::handleRename] Failed to create real file at: {}",
                    entry->backing_path.string());
                return -EIO;
            }
        } else {
            const auto ciphertext = ctx.engine->encryptionManager->encrypt(buffer, f);
            if (ciphertext.empty()) {
                log::Registry::fs()->error(
                    "[Filesystem::handleRename] Encryption failed for file: {}",
                    oldBackingPath.string());
                return -EIO;
            }

            writeFileAtomic(entry->backing_path, ciphertext);

            f->size_bytes = buffer.size();  // the plaintext size, as everywhere else
            f->mime_type = Magic::get_mime_type_from_buffer(buffer);
            f->content_hash = hash::blake2b(entry->backing_path);

            if (f->size_bytes > 0 && f->mime_type && isPreviewable(*f->mime_type))
                preview::render::enqueueThumbnails(ctx.engine, f, buffer);

            updateFile(ctx.txn, f);
        }
    }

    updateFSEntry(ctx.txn, entry);

    log::Registry::fs()->debug("[Filesystem::handleRename] Renamed {} to {}", ctx.from.string(), ctx.to.string());
    return 0;
}

Filesystem::AtRestRepair Filesystem::repairAtRest(const std::shared_ptr<Engine>& engine) {
    AtRestRepair result;
    if (!engine || !engine->vault || !engine->encryptionManager) return result;

    const auto& cache = runtime::Deps::get().fsCache;
    std::set<unsigned int> touchedParents;

    for (const auto& listed : db::query::fs::File::listFilesInDir(engine->vault->id, "/", true)) {
        try {
            // By inode: a miss loads and caches the entry (with its backing path) without the by-id miss warning.
            if (!listed->inode) continue;
            const auto entry = std::dynamic_pointer_cast<File>(cache->getEntry(static_cast<vh::fs::Inode>(*listed->inode)));
            if (!entry || !entry->inode) continue;
            if (fuse::WorkingCopies::instance().openSize(*entry->inode)) continue;

            std::error_code ec;
            if (!std::filesystem::is_regular_file(entry->backing_path, ec)) continue;
            const auto onDisk = std::filesystem::file_size(entry->backing_path);

            if (entry->encryption_iv.empty()) {
                if (onDisk == 0) continue;

                const auto staged = std::make_shared<File>(*entry);
                const auto sealed = entry->backing_path.parent_path() /
                                    (entry->backing_path.filename().string() + ".vh-seal-" + generate_random_suffix(8));
                try {
                    engine->encryptionManager->encryptFileToFile(entry->backing_path, sealed, staged);
                    std::filesystem::rename(sealed, entry->backing_path);
                } catch (...) {
                    std::filesystem::remove(sealed, ec);
                    throw;
                }
                entry->encryption_iv = staged->encryption_iv;
                entry->encrypted_with_key_version = staged->encrypted_with_key_version;
                entry->size_bytes = onDisk;
                entry->content_hash = hash::blake2b(entry->backing_path);
                ++result.encrypted;
            } else {
                const auto plaintextSize = onDisk >= vh::crypto::util::AES_TAG_SIZE ? onDisk - vh::crypto::util::AES_TAG_SIZE : 0;
                if (entry->size_bytes == plaintextSize) continue;
                entry->size_bytes = plaintextSize;
                ++result.resized;
            }

            db::query::fs::File::updateFile(entry);
            cache->updateEntry(entry);
            if (entry->parent_id) touchedParents.insert(static_cast<unsigned int>(*entry->parent_id));
        } catch (const std::exception& e) {
            ++result.failed;
            log::Registry::fs()->warn("[Filesystem::repairAtRest] Vault {} file {}: {}",
                                      engine->vault->id, listed->path.string(), e.what());
        }
    }

    for (const auto id : touchedParents) cache->refreshDirStats(id);

    if (result.encrypted || result.resized || result.failed)
        log::Registry::fs()->info(
            "[Filesystem::repairAtRest] Vault {}: encrypted {} plaintext file(s), corrected {} size(s), {} failed",
            engine->vault->id, result.encrypted, result.resized, result.failed);
    return result;
}

// Within a vault a rename only moves the bytes: they stay sealed with the same key and IV, so the files row needs no
// new encryption metadata. Re-encrypting here once turned FUSE-written plaintext into ciphertext the mount then
// served as-is (#173).
bool Filesystem::canFastPath(const std::shared_ptr<Entry>& entry, const std::shared_ptr<Engine>& engine) {
    if (entry->isDirectory()) return false;
    const auto file = std::static_pointer_cast<File>(entry);
    return file->vault_id == engine->vault->id;
}

bool Filesystem::isPreviewable(const std::string& mimeType) {
    if (mimeType == "image/svg+xml" || mimeType == "image/webp") return false;
    return mimeType.starts_with("image") || mimeType.starts_with("application") || mimeType.contains("pdf");
}
