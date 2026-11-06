#pragma once

#include <sys/types.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string_view>
#include <thread>
#include <unordered_map>
#include "crypto/ScratchFile.hpp"
#include "fs/Fwd.hpp"
#include "fs/PlaintextSource.hpp"

namespace vh::fuse {

// Vault bytes are always AES-256-GCM ciphertext on disk; the FUSE mount is the decrypting view (#173). The first open
// of an inode decrypts it into a private working copy (under the daemon's state directory, never inside the mount)
// that every handle on that inode shares. Reads and writes go to the copy. A modified copy is sealed back over the
// backing file (new IV, atomic rename) on flush, fsync and the last release, and the files row records the IV, key
// version and the plaintext size. Permission checks stay in the FUSE handlers: only a handle that passed the resolver
// ever reaches a copy.
//
// The copy itself is never plaintext on disk (#328): it is a crypto::ScratchFile, block-wise XChaCha20-Poly1305 under
// a key that exists only in this process's memory. A crash leaves only ciphertext nobody can read; the next start
// deletes it (clearStale).
//
// A copy whose last seal fails is not dropped: it moves to unsaved/ and stays the inode's working copy ("unsaved"),
// as if the daemon still held it open. Reopening the file shows those changes, writers that refuse open files
// (If-Match uploads, `vh fs put --overwrite`, restores) keep refusing, and the seal is retried in the background
// (after kRetryInterval, then backing off to kMaxRetryInterval: each attempt re-encrypts the whole file), on the next
// flush/fsync/release of the file and at shutdown. A file deleted meanwhile is restored
// as a new file where it was (WorkingCopyHooks::recover). Changes still unsaved when the process ends are lost: their
// key goes with it. clearStale() reports how many a crash left behind.
struct WorkingCopy {
    uint64_t ino{};
    std::unique_ptr<crypto::ScratchFile> file;  // the plaintext, encrypted under the process key; set when opened
    std::shared_ptr<fs::model::File> opened;    // the entry as first opened; hooks.current() wins once it moves
    std::shared_ptr<fs::model::File> lastSeen;  // the entry the last seal found (where an unsaved copy belongs)

    std::mutex mutex;                          // serializes materializing, writes, truncation and sealing
    bool ready = false;
    bool dirty = false;
    bool truncated = false;                    // emptied (O_TRUNC, truncate to 0) since the last seal
    std::atomic<bool> unsaved{false};          // the last seal at the last release failed; retried until it works
    unsigned int failedRetries = 0;            // unsaved: background retries that failed (backoff)
    std::chrono::steady_clock::time_point retryAt{};  // unsaved: the background retry waits until then

    std::optional<int32_t> lastWriter;
    unsigned int refs = 0;                     // guarded by the registry mutex
};

struct WorkingCopyHooks {
    // Writes the file's plaintext into `to` (empty). Files stored without an IV (left in plaintext by older builds)
    // are copied as they are; the copy is then marked modified so the next seal encrypts it. On a throw the copy is
    // discarded, so a sink fed unauthenticated plaintext before the tag check failed leaves nothing behind.
    std::function<void(const fs::model::File& file, crypto::ScratchFile& to)> materialize;
    // Encrypts `from` into `to` and records the IV and key version on `staged`.
    std::function<void(const fs::PlaintextSource& from, const std::filesystem::path& to,
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
    // An unsaved copy whose file was deleted after its seal failed: stores the content as a new file where `last`
    // was (or beside it when that name is taken), attributed to `writer`. Throws to retry later. Without this hook
    // such a copy stays unsaved.
    std::function<void(const fs::model::File& last, const fs::PlaintextSource& content,
                       std::optional<int32_t> writer)> recover;
};

class WorkingCopies {
public:
    struct Handle {
        std::shared_ptr<WorkingCopy> copy;
        int flags = -1;  // the open(2) flags (access mode, O_APPEND); -1 once released
    };

    // What clearStale() found.
    struct StaleSweep {
        std::size_t removed{};             // working copies a previous run left (unreadable now), deleted
        std::size_t unsavedLost{};         // of those, copies with changes that run never wrote back
        std::size_t legacyPlaintextKept{}; // plaintext older versions left in <legacy>/unsaved, kept for the operator
    };

    static constexpr auto kRetryInterval = std::chrono::seconds(60);
    static constexpr auto kMaxRetryInterval = std::chrono::minutes(15);
    // Where versions before #328 kept plaintext copies (next to root()); clearStale() cleans it up.
    static constexpr std::string_view kLegacyDirName = ".fuse-plaintext";

    WorkingCopies(std::filesystem::path root, WorkingCopyHooks hooks);
    ~WorkingCopies();

    WorkingCopies(const WorkingCopies&) = delete;
    WorkingCopies& operator=(const WorkingCopies&) = delete;

    // The daemon's registry: copies under <backing>/.fuse-working, sealed with each vault's key.
    static WorkingCopies& instance();
    // The hooks instance() uses (vault keys, the files table with local versioning, the FS cache), for a registry
    // over another root (tests).
    static WorkingCopyHooks daemonHooks();

    // At startup, before anything is open: deletes what a previous run left under root() (ciphertext under a key
    // that died with it), logging how many unsaved changes that loses, and the stale plaintext copies of versions
    // before #328 (their unsaved/ files are the operator's: kept, with a warning).
    StaleSweep clearStale() const;

    // `flags` are the open(2) flags the kernel passed. O_TRUNC on a writable open empties the copy. Throws
    // std::system_error (errno) on failure.
    Handle open(uint64_t ino, const std::shared_ptr<fs::model::File>& file, int flags);

    ssize_t read(const Handle& handle, char* buf, size_t size, off_t off) const;
    ssize_t write(const Handle& handle, const char* buf, size_t size, off_t off, std::optional<int32_t> userId) const;
    void truncate(const Handle& handle, off_t size, std::optional<int32_t> userId) const;

    // Seals a modified copy now (flush, fsync). No-op when nothing changed.
    void persist(const Handle& handle) const;

    // Closes the handle; the last one seals what changed and deletes the copy. A copy that fails to seal is kept as
    // unsaved (see above, logged) and the error is rethrown.
    void release(Handle& handle);

    // Tries to write back every unsaved copy no handle holds; returns how many are still unsaved. `due`: only those
    // whose backoff has run out (the background retry).
    std::size_t retryUnsaved(bool due = false);
    [[nodiscard]] std::size_t unsavedCount() const;
    // Runs retryUnsaved(due) every kRetryInterval on a thread of its own until stopRetrying() (the FUSE service,
    // while mounted).
    void startRetrying();
    void stopRetrying();
    // At shutdown: a last retry, then the copies still unsaved are logged as lost and deleted. Returns that count.
    std::size_t shutdown();

    // Plaintext size of an open copy, for getattr while writes are in flight.
    [[nodiscard]] std::optional<uintmax_t> openSize(uint64_t ino) const;
    // Whether a working copy exists for the inode (open, or unsaved). Registry lock only (never a copy's mutex), so it
    // is safe to call while holding fs::Filesystem::contentWriteMutex (seal takes copy mutex -> content lock).
    [[nodiscard]] bool isOpen(uint64_t ino) const;

    [[nodiscard]] const std::filesystem::path& root() const { return root_; }

private:
    void materialize(WorkingCopy& copy) const;
    void seal(WorkingCopy& copy) const;
    void keepUnsaved(WorkingCopy& copy) const;
    void markSaved(WorkingCopy& copy) const;

    std::filesystem::path root_;
    WorkingCopyHooks hooks_;
    mutable std::mutex mutex_;
    std::unordered_map<uint64_t, std::shared_ptr<WorkingCopy>> copies_;

    std::mutex retryMutex_;
    std::condition_variable retryCv_;
    bool retryStop_{false};
    std::thread retrier_;
};

}
