#include "fuse/WorkingCopies.hpp"
#include "fs/Filesystem.hpp"
#include "storage/CloudEngine.hpp"

#include "crypto/util/hash.hpp"
#include "db/query/fs/File.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "identities/User.hpp"
#include "fs/ops/file.hpp"
#include "log/Registry.hpp"
#include "platform/Durable.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"
#include "db/Transactions.hpp"
#include "recovery/local/Versions.hpp"

#include <paths.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <ctime>
#include <algorithm>
#include <array>
#include <vector>
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

std::filesystem::path scratchPathFor(const std::filesystem::path& root, const uint64_t ino) {
    return root / (std::to_string(ino) + "-" + fs::ops::generate_random_suffix(12) + ".scratch");
}

std::size_t removeRegularFiles(const std::filesystem::path& dir, const char* what) {
    std::size_t removed = 0;
    std::error_code ec;
    for (const auto& item : std::filesystem::directory_iterator(dir, ec)) {
        std::error_code type;
        if (!item.is_regular_file(type)) continue;
        std::error_code rm;
        if (std::filesystem::remove(item.path(), rm)) ++removed;
        else if (rm) log::Registry::fuse()->warn("[WorkingCopies] Could not remove a {}: {}", what, rm.message());
    }
    return removed;
}

std::size_t countRegularFiles(const std::filesystem::path& dir) {
    std::size_t n = 0;
    std::error_code ec;
    for (const auto& item : std::filesystem::directory_iterator(dir, ec)) {
        std::error_code type;
        if (item.is_regular_file(type)) ++n;
    }
    return n;
}

// "<stem> (unsaved changes YYYY-MM-DD HHMMSS)<ext>": where a restored copy goes when its old name is taken.
std::string unsavedName(const std::filesystem::path& name) {
    std::array<char, 32> stamp{};
    const auto now = std::time(nullptr);
    std::tm tm{};
    ::localtime_r(&now, &tm);
    std::strftime(stamp.data(), stamp.size(), "%Y-%m-%d %H%M%S", &tm);
    return name.stem().string() + " (unsaved changes " + stamp.data() + ")" + name.extension().string();
}

WorkingCopyHooks runtimeHooks() {
    return {
        .materialize = [](const fs::model::File& file, crypto::ScratchFile& to) {
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
            const auto sink = [&to](const std::span<const uint8_t> chunk) { to.append(chunk); };
            if (source->encryption_iv.empty()) {
                fs::forEachChunk(fs::sourceOf(source->backing_path), sink);
                return;
            }
            engineFor(*source)->encryptionManager->decryptFileTo(
                source->backing_path, sink, source->encryption_iv, source->encrypted_with_key_version);
        },
        .seal = [](const fs::PlaintextSource& from, const std::filesystem::path& to,
                   const std::shared_ptr<fs::model::File>& staged) {
            engineFor(*staged)->encryptionManager->encryptToFile(from, to, staged);
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
        .recover = [](const fs::model::File& last, const fs::PlaintextSource& content,
                      const std::optional<int32_t> writer) {
            const auto engine = engineFor(last);
            const auto user = writer ? identities::User::detached(static_cast<uint32_t>(*writer), {}) : nullptr;
            const auto parent = last.fuse_path.parent_path();
            if (fs::Filesystem::mkdir({.path = parent, .engine = engine, .user = user}) != 0)
                throw std::runtime_error("cannot create the folder it was in");
            const auto& cache = runtime::Deps::get().fsCache;
            for (const auto& name : {last.name, unsavedName(last.name)}) {
                const auto fusePath = parent / name;
                if (cache->entryExists(fusePath)) continue;
                const auto created = fs::Filesystem::createFile({.path = last.path.parent_path() / name,
                                                                 .fuse_path = fusePath, .source = content,
                                                                 .engine = engine, .user = user});
                if (!created) throw std::runtime_error("the file could not be created");
                log::Registry::fuse()->warn("[WorkingCopies] Inode {} was deleted while it had unsaved changes; they "
                                            "were saved as a new file in vault {}", last.inode.value_or(0),
                                            engine->vault->id);
                return;
            }
            throw std::runtime_error("its name and the fallback name are both taken");
        },
    };
}

}

WorkingCopies::WorkingCopies(std::filesystem::path root, WorkingCopyHooks hooks)
    : root_(std::move(root)), hooks_(std::move(hooks)) {
    std::filesystem::create_directories(root_);
    std::filesystem::permissions(root_, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
}

WorkingCopies::~WorkingCopies() { stopRetrying(); }

WorkingCopies& WorkingCopies::instance() {
    static WorkingCopies copies(paths::getBackingPath() / ".fuse-working", runtimeHooks());
    return copies;
}

WorkingCopyHooks WorkingCopies::daemonHooks() { return runtimeHooks(); }

WorkingCopies::StaleSweep WorkingCopies::clearStale() const {
    StaleSweep sweep;
    sweep.removed = removeRegularFiles(root_, "stale working copy");
    sweep.unsavedLost = removeRegularFiles(root_ / "unsaved", "stale unsaved working copy");
    sweep.removed += sweep.unsavedLost;
    if (sweep.unsavedLost > 0)
        log::Registry::fuse()->error(
            "[WorkingCopies] {} file(s) had changes the previous run could not write back to their vaults. They were "
            "encrypted under that run's in-memory key, which ended with it, so they can't be recovered and were "
            "deleted.", sweep.unsavedLost);
    else if (sweep.removed > 0)
        log::Registry::fuse()->info("[WorkingCopies] Deleted {} working copies left by the previous run", sweep.removed);

    // Versions before #328 kept plaintext copies in <backing>/.fuse-plaintext. Its stale copies go; what it kept in
    // unsaved/ is the operator's to recover, so it stays until they delete it.
    const auto legacy = root_.parent_path() / kLegacyDirName;
    std::error_code ec;
    if (std::filesystem::is_directory(legacy, ec)) {
        (void)removeRegularFiles(legacy, "stale plaintext working copy");
        sweep.legacyPlaintextKept = countRegularFiles(legacy / "unsaved");
        if (sweep.legacyPlaintextKept > 0) {
            log::Registry::fuse()->warn(
                "[WorkingCopies] {} plaintext file(s) that an older version could not save are still in {}/unsaved. "
                "Recover what you need from them, then delete them.", sweep.legacyPlaintextKept, legacy.string());
        } else {
            std::filesystem::remove(legacy / "unsaved", ec);
            std::filesystem::remove(legacy, ec);
        }
    }
    return sweep;
}

void WorkingCopies::materialize(WorkingCopy& copy) const {
    hooks_.materialize(*copy.opened, *copy.file);
    copy.file->flush();  // the cached tail block's memory is better spent elsewhere for a copy that may only be read
    // A file stored in plaintext by an older build gets encrypted the next time this copy is sealed.
    if (copy.opened->encryption_iv.empty() && copy.file->size() > 0) copy.dirty = true;
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
        }
        copy = slot;
        ++copy->refs;
    }

    try {
        std::scoped_lock lock(copy->mutex);
        const int access = flags & O_ACCMODE;
        const bool truncating = (flags & O_TRUNC) && access != O_RDONLY;
        if (!copy->ready) {
            copy->file = std::make_unique<crypto::ScratchFile>(scratchPathFor(root_, ino));
            if (truncating) {
                // The content is about to be discarded: don't decrypt (or, for a remote-only file, download) it.
                copy->ready = true;
                copy->dirty = true;
                copy->truncated = true;
            } else {
                materialize(*copy);
            }
        }

        if (truncating && copy->file->size() > 0) {
            copy->file->truncate(0);
            copy->dirty = true;
            copy->truncated = true;
        }

        return {copy, access | (flags & O_APPEND)};
    } catch (...) {
        std::scoped_lock lock(mutex_);
        if (--copy->refs == 0 && !copy->unsaved) {
            if (const auto it = copies_.find(ino); it != copies_.end() && it->second == copy) copies_.erase(it);
        }
        throw;
    }
}

ssize_t WorkingCopies::read(const Handle& handle, char* buf, const size_t size, const off_t off) const {
    if (handle.flags < 0 || (handle.flags & O_ACCMODE) == O_WRONLY)
        throw std::system_error(EBADF, std::generic_category(), "read working copy");
    if (off < 0) throw std::system_error(EINVAL, std::generic_category(), "read working copy");
    const auto n = handle.copy->file->read(static_cast<uint64_t>(off), {reinterpret_cast<uint8_t*>(buf), size});
    return static_cast<ssize_t>(n);
}

ssize_t WorkingCopies::write(const Handle& handle, const char* buf, const size_t size, const off_t off,
                             const std::optional<int32_t> userId) const {
    if (handle.flags < 0 || (handle.flags & O_ACCMODE) == O_RDONLY)
        throw std::system_error(EBADF, std::generic_category(), "write working copy");
    if (off < 0) throw std::system_error(EINVAL, std::generic_category(), "write working copy");
    std::scoped_lock lock(handle.copy->mutex);
    auto& file = *handle.copy->file;
    // O_APPEND writes at the end whatever the offset, as pwrite(2) on an O_APPEND descriptor does on Linux.
    const auto at = (handle.flags & O_APPEND) ? file.size() : static_cast<uint64_t>(off);
    file.write(at, {reinterpret_cast<const uint8_t*>(buf), size});
    handle.copy->dirty = true;
    if (userId) handle.copy->lastWriter = userId;
    return static_cast<ssize_t>(size);
}

void WorkingCopies::truncate(const Handle& handle, const off_t size, const std::optional<int32_t> userId) const {
    if (size < 0) throw std::system_error(EINVAL, std::generic_category(), "truncate working copy");
    std::scoped_lock lock(handle.copy->mutex);
    handle.copy->file->truncate(static_cast<uint64_t>(size));
    handle.copy->dirty = true;
    if (size == 0) handle.copy->truncated = true;
    if (userId) handle.copy->lastWriter = userId;
}

void WorkingCopies::seal(WorkingCopy& copy) const {
    if (!copy.dirty) return;

    const auto entry = hooks_.current(copy.ino);
    if (!entry) {
        if (copy.unsaved) {
            // Deleted after its save failed: the changes become a new file where it was (or stay unsaved).
            const auto& last = copy.lastSeen ? copy.lastSeen : copy.opened;
            if (!hooks_.recover) throw std::runtime_error("The file was deleted; there is nowhere to write it back");
            hooks_.recover(*last, fs::sourceOf(*copy.file), copy.lastWriter);
            markSaved(copy);
            return;
        }
        // Deleted while open: there is nothing left to write back to.
        copy.dirty = false;
        return;
    }
    copy.lastSeen = entry;

    // Blobs the version capture frees (keep_last) are unlinked after the content lock is released.
    const recovery::local::versions::DeferBlobFrees deferFrees;
    std::unique_lock<std::mutex> contentLock;
    if (hooks_.lock) contentLock = hooks_.lock(entry->id);

    const auto plainSize = copy.file->size();
    const auto plaintext = fs::sourceOf(*copy.file);
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
            hooks_.seal(plaintext, sealed, staged);
        }
        fsyncPath(sealed);

        staged->size_bytes = plainSize;
        staged->content_hash = crypto::hash::blake2b(sealed);
        if (plainSize > 0) staged->mime_type = fs::mimeTypeOf(plaintext, entry->path);
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
    markSaved(copy);
}

void WorkingCopies::markSaved(WorkingCopy& copy) const {
    copy.dirty = false;
    copy.truncated = false;
    if (!copy.unsaved) return;
    copy.unsaved = false;
    log::Registry::fuse()->info("[WorkingCopies] Changes to inode {} that could not be saved earlier are now written back",
                                copy.ino);
    // Out of unsaved/ again: a crash from here on loses nothing that wasn't saved.
    try {
        copy.file->rename(scratchPathFor(root_, copy.ino));
    } catch (const std::exception& e) {
        log::Registry::fuse()->warn("[WorkingCopies] Could not move a saved working copy out of unsaved/: {}", e.what());
    }
}

void WorkingCopies::keepUnsaved(WorkingCopy& copy) const {
    if (copy.unsaved) return;
    copy.unsaved = true;
    copy.failedRetries = 0;
    copy.retryAt = std::chrono::steady_clock::now() + kRetryInterval;
    try {
        copy.file->flush();  // no plaintext cache held for as long as it waits
        const auto unsaved = root_ / "unsaved";
        std::filesystem::create_directories(unsaved);
        std::filesystem::permissions(unsaved, std::filesystem::perms::owner_all, std::filesystem::perm_options::replace);
        copy.file->rename(unsaved / copy.file->path().filename());
    } catch (const std::exception& e) {
        log::Registry::fuse()->warn("[WorkingCopies] Could not move an unsaved working copy to unsaved/: {}", e.what());
    }
    log::Registry::fuse()->error(
        "[WorkingCopies] Could not write changes to inode {} back to its vault. They are kept (encrypted, under a key "
        "held only in memory) and retried in {} s, then less often, and opening the file shows them. If the daemon "
        "stops before a retry succeeds, they are lost.", copy.ino, kRetryInterval.count());
}

void WorkingCopies::persist(const Handle& handle) const {
    std::scoped_lock lock(handle.copy->mutex);
    seal(*handle.copy);
}

void WorkingCopies::release(Handle& handle) {
    if (!handle.copy) return;
    handle.flags = -1;

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
            keepUnsaved(*copy);
        }
    }

    std::scoped_lock lock(mutex_);
    if (copy->refs != 0) {
        if (failure) std::rethrow_exception(failure);
        return;  // reopened while sealing: the new handle keeps the copy
    }
    // An unsaved copy stays registered (retried, and reopening the file finds it); a saved one is deleted with the
    // last reference to it.
    if (failure) std::rethrow_exception(failure);
    if (const auto it = copies_.find(copy->ino); it != copies_.end() && it->second == copy) copies_.erase(it);
}

std::size_t WorkingCopies::retryUnsaved(const bool due) {
    std::vector<std::shared_ptr<WorkingCopy>> pending;
    {
        std::scoped_lock lock(mutex_);
        for (const auto& [_, copy] : copies_)
            if (copy->refs == 0) pending.push_back(copy);  // nobody holds it: only unsaved copies stay registered
    }

    std::size_t left = 0;
    for (const auto& copy : pending) {
        bool saved = false;
        {
            std::scoped_lock lock(copy->mutex);
            if (!copy->unsaved) continue;
            const auto now = std::chrono::steady_clock::now();
            if (due && now < copy->retryAt) {
                ++left;
                continue;
            }
            try {
                seal(*copy);
                saved = true;
            } catch (const std::exception& e) {
                ++left;
                copy->failedRetries = std::min(copy->failedRetries + 1, 8u);
                copy->retryAt = now + std::min<std::chrono::steady_clock::duration>(
                                          kRetryInterval * (1u << copy->failedRetries), kMaxRetryInterval);
                log::Registry::fuse()->warn("[WorkingCopies] Still can't write back the unsaved changes to inode {}: {}",
                                            copy->ino, e.what());
            }
        }
        if (!saved) continue;
        std::scoped_lock lock(mutex_);
        if (copy->refs == 0)
            if (const auto it = copies_.find(copy->ino); it != copies_.end() && it->second == copy) copies_.erase(it);
    }
    return left;
}

std::size_t WorkingCopies::unsavedCount() const {
    std::vector<std::shared_ptr<WorkingCopy>> copies;
    {
        std::scoped_lock lock(mutex_);
        for (const auto& [_, copy] : copies_) copies.push_back(copy);
    }
    std::size_t n = 0;
    for (const auto& copy : copies) {
        std::scoped_lock lock(copy->mutex);
        n += copy->unsaved ? 1 : 0;
    }
    return n;
}

void WorkingCopies::startRetrying() {
    std::scoped_lock lock(retryMutex_);
    if (retrier_.joinable()) return;
    retryStop_ = false;
    retrier_ = std::thread([this] {
        std::unique_lock wait(retryMutex_);
        while (!retryCv_.wait_for(wait, kRetryInterval, [this] { return retryStop_; })) {
            wait.unlock();
            try {
                (void)retryUnsaved(true);
            } catch (const std::exception& e) {
                log::Registry::fuse()->warn("[WorkingCopies] Retrying unsaved changes failed: {}", e.what());
            }
            wait.lock();
        }
    });
}

void WorkingCopies::stopRetrying() {
    std::thread retrier;
    {
        std::scoped_lock lock(retryMutex_);
        retryStop_ = true;
        retrier = std::move(retrier_);
    }
    retryCv_.notify_all();
    if (retrier.joinable()) retrier.join();
}

std::size_t WorkingCopies::shutdown() {
    stopRetrying();
    const auto lost = retryUnsaved();
    if (lost > 0)
        log::Registry::fuse()->error(
            "[WorkingCopies] {} file(s) still have changes that could not be written back to their vaults. They are "
            "lost: their encrypted copies can't be read once the daemon exits.", lost);
    std::scoped_lock lock(mutex_);
    std::erase_if(copies_, [](const auto& item) { return item.second->refs == 0; });
    return lost;
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
    return copy->file->size();
}

}
