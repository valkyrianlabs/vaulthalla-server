#pragma once

#include "crypto/SecretKey.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <memory>
#include <mutex>
#include <optional>
#include <shared_mutex>
#include <span>
#include <stdexcept>
#include <vector>

namespace vh::crypto {

// Plaintext that has to sit on disk while it is in use (FUSE working copies, HTTP upload and `vh fs put` staging,
// #328) is kept there only as ciphertext under a key that exists only in this process's memory: processKey() is
// random at first use, mlocked and never written anywhere. Whatever a crash leaves behind can't be read by anyone,
// including the next run of the daemon, which deletes it at startup.
//
// Layout: the plaintext is cut into kBlockSize blocks; block i is stored at offset i * kRecordSize as
//   nonce (kNonceSize random bytes, fresh on every write of the block) ‖ XChaCha20-Poly1305 ciphertext ‖ tag
// with AAD = file id (kIdSize random bytes) ‖ BE64(i). Only the last block may be short. The file id, the logical
// size and the nonce of each block's latest write live in this object only: a block is accepted only if it
// authenticates under this file's id and its own index AND carries the nonce of its latest write. A flipped byte, a
// block moved within the file or copied from another one, an older version of a block, or a cut-off record all fail
// closed (Tampered). A write past the end or an extending truncate stores the gap as encrypted zeros.
//
// One block at a time is cached in memory for writes and one for partial reads (plaintext in locked memory, wiped
// when dropped), so sequential reads and writes smaller than a block decrypt or encrypt each block once. Thread-safe: reads share a lock, writes take it alone.
// The file exists exactly as long as this object: the destructor unlinks it, since nothing else could read it.
class ScratchFile {
public:
    static constexpr std::size_t kBlockSize = 64 * 1024;
    static constexpr std::size_t kNonceSize = 24;
    static constexpr std::size_t kTagSize = 16;
    static constexpr std::size_t kIdSize = 16;
    static constexpr std::size_t kRecordOverhead = kNonceSize + kTagSize;
    static constexpr std::size_t kRecordSize = kBlockSize + kRecordOverhead;

    using Nonce = std::array<uint8_t, kNonceSize>;

    // A block failed authentication, or is missing from disk: the bytes were changed behind the daemon's back.
    class Tampered final : public std::runtime_error {
    public:
        using std::runtime_error::runtime_error;
    };

    // This process's scratch key (random, created on first use, never persisted).
    [[nodiscard]] static const SecretKeyPtr& processKey();

    // Creates `path` (0600; fails with std::system_error if anything exists there). `key` is for tests.
    explicit ScratchFile(std::filesystem::path path, SecretKeyPtr key = processKey());
    ~ScratchFile();

    ScratchFile(const ScratchFile&) = delete;
    ScratchFile& operator=(const ScratchFile&) = delete;

    // Plaintext at `offset` into `out`; returns how much (short only at the end, 0 at or past it).
    std::size_t read(uint64_t offset, std::span<uint8_t> out) const;
    void write(uint64_t offset, std::span<const uint8_t> data);
    void append(std::span<const uint8_t> data);
    // Shrinks or extends (with zeros) to `size`.
    void truncate(uint64_t size);
    [[nodiscard]] uint64_t size() const;

    // Writes the cached block to disk and frees the cache (nothing else needs it on disk: reads see the cache).
    void flush();
    // Moves the file; the object keeps working on it.
    void rename(const std::filesystem::path& to);
    [[nodiscard]] std::filesystem::path path() const;

    // Not secret (the key is): what binds the blocks to this file. For tests and diagnostics.
    [[nodiscard]] std::array<uint8_t, kIdSize> fileId() const { return id_; }
    // The nonce block `index` was last written with (tests: a rewrite never reuses one).
    [[nodiscard]] std::optional<Nonce> nonceOf(uint64_t index) const;

private:
    struct Cache;
    struct ReadCache;

    [[nodiscard]] uint64_t blockCount(uint64_t size) const noexcept;
    [[nodiscard]] std::size_t blockLength(uint64_t index, uint64_t size) const noexcept;
    void writeRecord(uint64_t index, std::span<const uint8_t> plain);
    void readRecord(uint64_t index, std::span<uint8_t> out) const;
    void loadCache(uint64_t index, bool keepContent);
    void flushCache();
    void dropCache() noexcept;
    void growTo(uint64_t size);
    void writeLocked(uint64_t offset, std::span<const uint8_t> data);

    std::filesystem::path path_;
    int fd_{-1};
    SecretKeyPtr key_;
    std::array<uint8_t, kIdSize> id_{};

    mutable std::shared_mutex mutex_;
    uint64_t size_{};
    std::vector<Nonce> nonces_;     // one per block on disk (the cached block's may be stale until it is flushed)
    std::unique_ptr<Cache> cache_;
    uint64_t generation_{};             // moves on every change; invalidates read_

    mutable std::mutex readMutex_;
    mutable std::unique_ptr<ReadCache> read_;
};

}
