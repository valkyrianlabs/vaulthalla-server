#include "fuse/WorkingCopies.hpp"
#include "fs/Filesystem.hpp"
#include "storage/CloudEngine.hpp"

#include "crypto/util/hash.hpp"
#include "db/query/fs/File.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/metadata/Magic.hpp"
#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "log/Registry.hpp"
#include "platform/Durable.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "db/Transactions.hpp"
#include "recovery/local/Versions.hpp"

#include <paths.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <ctime>
#include <system_error>

namespace vh::fuse {

namespace {

[[noreturn]] void throwErrno(const char* what) {
    throw std::system_error(errno, std::generic_category(), what);
}

// Creates an empty file only the daemon can read; fails if the name is taken.
void createPrivateFile(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) throwErrno("create working copy");
    ::close(fd);
}

void fsyncPath(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) throwErrno("open sealed file");
    const int rc = platform::durable::sync(fd);
    const int err = errno;
    ::close(fd);
    if (rc < 0) {
        errno = err;
        throwErrno("fsync sealed file");
    }
}

std::shared_ptr<storage::Engine> engineFor(const fs::model::File& file) {
    if (!file.vault_id) throw std::runtime_error("File has no vault: " + file.path.string());
    auto engine = runtime::Deps::get().storageManager->getEngine(static_cast<unsigned int>(*file.vault_id));
    if (!engine || !engine->encryptionManager)
        throw std::runtime_error("No encryption manager for vault " + std::to_string(*file.vault_id));
    return engine;
}

WorkingCopyHooks runtimeHooks() {
    return {
        .materialize = [](const fs::model::File& file, const std::filesystem::path& to) {
            const fs::model::File* source = &file;
            std::shared_ptr<fs::model::File> hydrated;
            if (!std::filesystem::exists(file.backing_path)) {
                if (file.size_bytes == 0) return;
                // An index-only cloud file (Cache strategy): its bytes live in the bucket. Fetch them (price-gated,
                // verified, kept as local ciphertext) instead of presenting an empty file, whose first write would be
                // sealed over the real content.
                const auto cloud = std::dynamic_pointer_cast<storage::CloudEngine>(engineFor(file));
                if (!cloud) throw std::runtime_error("Backing bytes are missing for " + file.path.string());
                hydrated = cloud->hydrate(std::make_shared<fs::model::File>(file));
                if (!hydrated || !std::filesystem::exists(hydrated->backing_path))
                    throw std::runtime_error("Remote content is unavailable for " + file.path.string());
                source = hydrated.get();
            }
            if (std::filesystem::file_size(source->backing_path) == 0) return;
            if (source->encryption_iv.empty()) {
                std::filesystem::copy_file(source->backing_path, to, std::filesystem::copy_options::overwrite_existing);
                return;
            }
            engineFor(*source)->encryptionManager->decryptFileToFile(
                source->backing_path, to, source->encryption_iv, source->encrypted_with_key_version);
        },
        .seal = [](const std::filesystem::path& from, const std::filesystem::path& to,
                   const std::shared_ptr<fs::model::File>& staged) {
            engineFor(*staged)->encryptionManager->encryptFileToFile(from, to, staged);
        },
        .current = [](const uint64_t ino) -> std::shared_ptr<fs::model::File> {
            const auto entry = runtime::Deps::get().fsCache->getEntry(static_cast<vh::fs::Inode>(ino));
            if (!entry || entry->isDirectory() || entry->isSymlink()) return nullptr;
            return std::static_pointer_cast<fs::model::File>(entry);
        },
        .commit = [](const WorkingCopyHooks::Commit& c) {
            // Local versioning keeps the generation the seal replaces, in the row's transaction (truncate: the copy
            // was emptied, e.g. O_TRUNC, or is empty now).
            const auto reason = c.truncated || c.staged->size_bytes == 0 ? recovery::local::Reason::Truncate
                                                                          : recovery::local::Reason::Overwrite;
            const auto actor = c.staged->last_modified_by
                ? std::make_optional(static_cast<uint32_t>(*c.staged->last_modified_by)) : std::nullopt;
            auto kept = recovery::local::versions::retain(*engineFor(c.prior), c.prior, reason, {.actor = actor});
            db::Transactions::exec("WorkingCopies::seal", [&](pqxx::work& txn) {
                kept.attach(txn);
                db::query::fs::File::updateFile(txn, c.staged);
            });
            kept.committed();
        },
        .saved = [](const std::shared_ptr<fs::model::File>& file) {
            const auto& cache = runtime::Deps::get().fsCache;
            cache->updateEntry(file);
            if (file->parent_id) cache->refreshDirStats(static_cast<unsigned int>(*file->parent_id));
        },
        .lock = [](const uint32_t fileId) { return std::unique_lock(fs::Filesystem::contentWriteMutex(fileId)); },
    };
}

}

WorkingCopies::WorkingCopies(std::filesystem::path root, WorkingCopyHooks hooks)
    : root_(std::move(root)), hooks_(std::move(hooks)) {
    std::filesystem::create_directories(root_);
    std::filesystem::permissions(root_, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
}

WorkingCopies& WorkingCopies::instance() {
    static WorkingCopies copies(paths::getBackingPath() / ".fuse-plaintext", runtimeHooks());
    return copies;
}

WorkingCopyHooks WorkingCopies::daemonHooks() { return runtimeHooks(); }

void WorkingCopies::clearStale() const {
    std::error_code ec;
    for (const auto& item : std::filesystem::directory_iterator(root_, ec)) {
        if (!item.is_regular_file()) continue;
        std::filesystem::remove(item.path(), ec);
        if (ec)
            log::Registry::fuse()->warn("[WorkingCopies] Could not remove stale working copy {}: {}",
                                        item.path().string(), ec.message());
    }
}

void WorkingCopies::materialize(WorkingCopy& copy) const {
    hooks_.materialize(*copy.opened, copy.path);
    // A file stored in plaintext by an older build gets encrypted the next time this copy is sealed.
    if (copy.opened->encryption_iv.empty() && std::filesystem::file_size(copy.path) > 0) copy.dirty = true;
    copy.ready = true;
}

WorkingCopies::Handle WorkingCopies::open(const uint64_t ino, const std::shared_ptr<fs::model::File>& file,
                                          const int flags) {
    if (!file) throw std::system_error(ENOENT, std::generic_category(), "open working copy");

    std::shared_ptr<WorkingCopy> copy;
    {
        std::scoped_lock lock(mutex_);
        auto& slot = copies_[ino];
        if (!slot) {
            slot = std::make_shared<WorkingCopy>();
            slot->ino = ino;
            slot->opened = file;
            slot->path = root_ / (std::to_string(ino) + "-" + fs::ops::generate_random_suffix(12) + ".plain");
        }
        copy = slot;
        ++copy->refs;
    }

    try {
        std::scoped_lock lock(copy->mutex);
        const int access = flags & O_ACCMODE;
        const bool truncating = (flags & O_TRUNC) && access != O_RDONLY;
        if (!copy->ready) {
            createPrivateFile(copy->path);
            if (truncating) {
                // The content is about to be discarded: don't decrypt (or, for a remote-only file, download) it.
                copy->ready = true;
                copy->dirty = true;
                copy->truncated = true;
            } else {
                materialize(*copy);
            }
        }

        if (truncating && std::filesystem::file_size(copy->path) > 0) {
            std::filesystem::resize_file(copy->path, 0);
            copy->dirty = true;
            copy->truncated = true;
        }

        const int fd = ::open(copy->path.c_str(), access | (flags & O_APPEND) | O_CLOEXEC);
        if (fd < 0) throwErrno("open working copy");
        return {copy, fd};
    } catch (...) {
        Handle failed{copy, -1};
        std::scoped_lock lock(mutex_);
        if (--copy->refs == 0) {
            if (const auto it = copies_.find(ino); it != copies_.end() && it->second == copy) copies_.erase(it);
            std::error_code ec;
            std::filesystem::remove(copy->path, ec);
        }
        throw;
    }
}

ssize_t WorkingCopies::read(const Handle& handle, char* buf, const size_t size, const off_t off) const {
    const auto res = ::pread(handle.fd, buf, size, off);
    if (res < 0) throwErrno("read working copy");
    return res;
}

ssize_t WorkingCopies::write(const Handle& handle, const char* buf, const size_t size, const off_t off,
                             const std::optional<int32_t> userId) const {
    std::scoped_lock lock(handle.copy->mutex);
    const auto res = ::pwrite(handle.fd, buf, size, off);
    if (res < 0) throwErrno("write working copy");
    handle.copy->dirty = true;
    if (userId) handle.copy->lastWriter = userId;
    return res;
}

void WorkingCopies::truncate(const Handle& handle, const off_t size, const std::optional<int32_t> userId) const {
    std::scoped_lock lock(handle.copy->mutex);
    if (::ftruncate(handle.fd, size) < 0) throwErrno("truncate working copy");
    handle.copy->dirty = true;
    if (size == 0) handle.copy->truncated = true;
    if (userId) handle.copy->lastWriter = userId;
}

void WorkingCopies::seal(WorkingCopy& copy) const {
    if (!copy.dirty) return;

    const auto entry = hooks_.current(copy.ino);
    if (!entry) {
        // Deleted while open: there is nothing left to write back to.
        copy.dirty = false;
        return;
    }

    // Blobs the version capture frees (keep_last) are unlinked after the content lock is released.
    const recovery::local::versions::DeferBlobFrees deferFrees;
    std::unique_lock<std::mutex> contentLock;
    if (hooks_.lock) contentLock = hooks_.lock(entry->id);

    const auto plainSize = std::filesystem::file_size(copy.path);
    const auto staged = std::make_shared<fs::model::File>(*entry);
    // The shared content sidecar: overwrites and key rotation use the same name and the same order (sealed bytes,
    // then the row, then the rename), so startup recovery settles any of them the same way.
    const auto sealed = fs::ops::contentSidecarPath(entry->backing_path);

    std::filesystem::create_directories(entry->backing_path.parent_path());
    std::error_code ec;
    std::filesystem::remove(sealed, ec);
    try {
        if (plainSize == 0) {
            createPrivateFile(sealed);
            staged->encryption_iv.clear();
            staged->encrypted_with_key_version = 0;
        } else {
            hooks_.seal(copy.path, sealed, staged);
        }
        fsyncPath(sealed);

        staged->size_bytes = plainSize;
        staged->content_hash = crypto::hash::blake2b(sealed);
        if (plainSize > 0) staged->mime_type = fs::metadata::Magic::get_mime_type(copy.path.string());
        if (copy.lastWriter) staged->last_modified_by = copy.lastWriter;
        staged->updated_at = std::time(nullptr);
        // Row first: a crash after this leaves a promotable sidecar.
        if (hooks_.commit) hooks_.commit({.prior = *entry, .staged = staged, .truncated = copy.truncated});
    } catch (...) {
        std::filesystem::remove(sealed, ec);
        throw;
    }
    std::filesystem::rename(sealed, entry->backing_path);
    fs::ops::fsyncDirectory(entry->backing_path.parent_path());

    entry->encryption_iv = staged->encryption_iv;
    entry->encrypted_with_key_version = staged->encrypted_with_key_version;
    entry->size_bytes = staged->size_bytes;
    entry->content_hash = staged->content_hash;
    entry->mime_type = staged->mime_type;
    entry->last_modified_by = staged->last_modified_by;
    entry->updated_at = staged->updated_at;
    hooks_.saved(entry);
    copy.dirty = false;
    copy.truncated = false;
}

void WorkingCopies::persist(const Handle& handle) const {
    std::scoped_lock lock(handle.copy->mutex);
    seal(*handle.copy);
}

void WorkingCopies::release(Handle& handle) {
    if (!handle.copy) return;
    if (handle.fd >= 0) ::close(handle.fd);
    handle.fd = -1;

    const auto copy = std::move(handle.copy);
    bool last = false;
    {
        std::scoped_lock lock(mutex_);
        last = --copy->refs == 0;
    }
    if (!last) return;

    std::exception_ptr failure;
    {
        std::scoped_lock lock(copy->mutex);
        try {
            seal(*copy);
        } catch (...) {
            failure = std::current_exception();
        }
    }

    std::scoped_lock lock(mutex_);
    if (copy->refs != 0) {
        if (failure) std::rethrow_exception(failure);
        return;  // reopened while sealing: the new handle keeps the copy
    }
    if (const auto it = copies_.find(copy->ino); it != copies_.end() && it->second == copy) copies_.erase(it);

    std::error_code ec;
    if (failure) {
        const auto unsaved = root_ / "unsaved";
        std::filesystem::create_directories(unsaved, ec);
        const auto kept = unsaved / copy->path.filename();
        std::filesystem::rename(copy->path, kept, ec);
        log::Registry::fuse()->error(
            "[WorkingCopies] Could not encrypt changes to inode {} back to disk; plaintext kept at {}",
            copy->ino, ec ? copy->path.string() : kept.string());
        std::rethrow_exception(failure);
    }
    std::filesystem::remove(copy->path, ec);
}

bool WorkingCopies::isOpen(const uint64_t ino) const {
    std::scoped_lock lock(mutex_);
    return copies_.contains(ino);
}

std::optional<uintmax_t> WorkingCopies::openSize(const uint64_t ino) const {
    std::shared_ptr<WorkingCopy> copy;
    {
        std::scoped_lock lock(mutex_);
        const auto it = copies_.find(ino);
        if (it == copies_.end()) return std::nullopt;
        copy = it->second;
    }
    std::scoped_lock lock(copy->mutex);
    if (!copy->ready) return std::nullopt;
    std::error_code ec;
    const auto size = std::filesystem::file_size(copy->path, ec);
    if (ec) return std::nullopt;
    return size;
}

}
