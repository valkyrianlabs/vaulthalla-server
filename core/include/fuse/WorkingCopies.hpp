#pragma once

#include <sys/types.h>

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <unordered_map>
#include "fs/Fwd.hpp"

namespace vh::fuse {

// Vault bytes are always AES-256-GCM ciphertext on disk; the FUSE mount is the decrypting view (#173). The first open
// of an inode decrypts it into a private working copy (0600, under the daemon's state directory, never inside the
// mount) that every handle on that inode shares. Reads and writes go to the copy. A modified copy is sealed back
// over the backing file (new IV, atomic rename) on flush, fsync and the last release, and the files row records the
// IV, key version and the plaintext size. Permission checks stay in the FUSE handlers: only a handle that passed the
// resolver ever reaches a copy.
struct WorkingCopy {
    uint64_t ino{};
    std::filesystem::path path;
    std::shared_ptr<fs::model::File> opened;  // the entry as first opened; hooks.current() wins once it moves

    std::mutex mutex;                          // serializes materializing, writes, truncation and sealing
    bool ready = false;
    bool dirty = false;
    bool truncated = false;                    // emptied (O_TRUNC, truncate to 0) since the last seal

    std::optional<int32_t> lastWriter;
    unsigned int refs = 0;                     // guarded by the registry mutex
};

struct WorkingCopyHooks {
    // Writes the file's plaintext to `to` (which exists, empty, 0600). Files stored without an IV (left in plaintext
    // by older builds) are copied as they are; the copy is then marked modified so the next seal encrypts it.
    std::function<void(const fs::model::File& file, const std::filesystem::path& to)> materialize;
    // Encrypts plaintext `from` into `to` and records the IV and key version on `staged`.
    std::function<void(const std::filesystem::path& from, const std::filesystem::path& to,
                       const std::shared_ptr<fs::model::File>& staged)> seal;
    // The live entry for an inode (renames move it), or null once it has been deleted.
    std::function<std::shared_ptr<fs::model::File>(uint64_t ino)> current;
    // Records the staged row (the files table only) BEFORE the sealed bytes are renamed into place. `prior` is the
    // entry as it still is (its sealed bytes at prior.backing_path, which local versioning keeps); `truncated` says
    // the copy was emptied since the last seal. Optional.
    struct Commit {
        const fs::model::File& prior;
        const std::shared_ptr<fs::model::File>& staged;
        bool truncated{};
    };
    std::function<void(const Commit& commit)> commit;
    // Records a sealed entry after the rename: cache, directory totals (and the row, if `commit` is not set).
    std::function<void(const std::shared_ptr<fs::model::File>& file)> saved;
    // Serializes content replacement of one file with every other writer (fs::Filesystem::contentWriteMutex).
    std::function<std::unique_lock<std::mutex>(uint32_t fileId)> lock;
};

class WorkingCopies {
public:
    struct Handle {
        std::shared_ptr<WorkingCopy> copy;
        int fd = -1;
    };

    WorkingCopies(std::filesystem::path root, WorkingCopyHooks hooks);

    // The daemon's registry: copies under <backing>/.fuse-plaintext, sealed with each vault's key.
    static WorkingCopies& instance();
    // The hooks instance() uses (vault keys, the files table with local versioning, the FS cache), for a registry
    // over another root (tests).
    static WorkingCopyHooks daemonHooks();

    // Removes working copies a previous run left behind (they are plaintext). Copies that failed to seal are kept
    // in unsaved/ for the operator.
    void clearStale() const;

    // `flags` are the open(2) flags the kernel passed. O_TRUNC on a writable open empties the copy. Throws
    // std::system_error (errno) on failure.
    Handle open(uint64_t ino, const std::shared_ptr<fs::model::File>& file, int flags);

    ssize_t read(const Handle& handle, char* buf, size_t size, off_t off) const;
    ssize_t write(const Handle& handle, const char* buf, size_t size, off_t off, std::optional<int32_t> userId) const;
    void truncate(const Handle& handle, off_t size, std::optional<int32_t> userId) const;

    // Seals a modified copy now (flush, fsync). No-op when nothing changed.
    void persist(const Handle& handle) const;

    // Closes the handle; the last one seals what changed and deletes the copy. A copy that fails to seal moves to
    // unsaved/ (logged) rather than being lost, and the error is rethrown.
    void release(Handle& handle);

    // Plaintext size of an open copy, for getattr while writes are in flight.
    [[nodiscard]] std::optional<uintmax_t> openSize(uint64_t ino) const;
    // Whether a working copy exists for the inode. Registry lock only (never a copy's mutex), so it is safe to call
    // while holding fs::Filesystem::contentWriteMutex (seal takes copy mutex -> content lock).
    [[nodiscard]] bool isOpen(uint64_t ino) const;

    [[nodiscard]] const std::filesystem::path& root() const { return root_; }

private:
    void materialize(WorkingCopy& copy) const;
    void seal(WorkingCopy& copy) const;

    std::filesystem::path root_;
    WorkingCopyHooks hooks_;
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<WorkingCopy>> copies_;
};

}
