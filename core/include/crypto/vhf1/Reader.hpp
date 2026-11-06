#pragma once

#include "crypto/vhf1/Format.hpp"

#include <cstdint>
#include <functional>
#include <optional>
#include <span>
#include <vector>

namespace vh::crypto::vhf1 {

// Whole-object read (spec 02 §3.6): header, expectations, header tag, size, then every chunk in index order. Returns
// the plaintext only when every chunk authenticated; on any failure the partial plaintext is wiped and Error thrown.
// authenticatedSize, when the caller has it (DB row, manifest entry), must equal object.size() (SizeMismatch).
[[nodiscard]] SecureBytes open(std::span<const uint8_t> object, const Expectation& expect, const KeyLookup& keys,
                               std::optional<uint64_t> authenticatedSize = std::nullopt);

// Streaming chunk walker over the object bytes after the header, for a known object size (fstat, Content-Length or
// authenticated metadata). Feed bytes in order in any split; the sink receives each chunk's plaintext, in index
// order, only after that chunk's tag verified with its own index and final flag (the last chunk by the layout is
// final). A chunk that fails is never passed on: its scratch plaintext is wiped and Error(ChunkAuthFailed, i) thrown.
// Chunks already passed on are authentic bytes at their offsets; whether the whole object is intact (no truncation
// beyond the declared size) is known only when finish() returns. Failures are sticky: every later call rethrows.
// One walker per stream; not thread-safe.
class ChunkWalker {
public:
    using Sink = std::function<void(uint64_t index, std::span<const uint8_t> plaintext)>;

    // Throws Error(BadSize) when objectSize has no valid layout for the header's chunk size.
    ChunkWalker(OpenedHeader header, uint64_t objectSize);

    // More bytes than the object size are Error(SizeMismatch).
    void update(std::span<const uint8_t> sealed, const Sink& sink);
    // Error(SizeMismatch) when the stream ended before the object size.
    void finish();

    [[nodiscard]] const Layout& layout() const { return layout_; }
    [[nodiscard]] uint64_t nextChunk() const { return next_; }

private:
    [[noreturn]] void fail(const Error& error);
    void openOne(std::span<const uint8_t> sealed, const Sink& sink);

    OpenedHeader header_;
    Layout layout_;
    std::vector<uint8_t> pending_;  // sealed bytes of a chunk split across update() calls (ciphertext)
    SecureBytes scratch_;           // one chunk of plaintext, wiped after every chunk
    uint64_t next_{};
    std::optional<Error> failed_;
    bool broken_{false};
    bool finished_{false};
};

// Which chunks and object bytes a plaintext range [start, end) needs (§3.7 step 2). An empty range needs none.
struct RangePlan {
    uint64_t start{};
    uint64_t end{};
    std::optional<uint64_t> chunkFirst;
    std::optional<uint64_t> chunkLast;
    std::optional<ByteSpan> objectRange;
};

// Authenticated range reads (§3.7). The object size must come from authenticated metadata and equal the size the
// provider reports (the Content-Range total of the ranged GET, or fstat): SizeUnknown / SizeMismatch otherwise, so a
// truncated object can't pass for a short file. Each covering chunk is authenticated whole with its own index and
// final flag before any byte of it is returned. A chunk that fails authentication is sticky for this reader (this
// generation): every later read rethrows it. Not thread-safe (one scratch chunk); use one reader per thread.
class RangeReader {
public:
    using Fetch = std::function<std::vector<uint8_t>(uint64_t offset, uint64_t length)>;

    RangeReader(OpenedHeader header, std::optional<uint64_t> authenticatedSize, uint64_t providerSize);

    // Error(RangeOutOfBounds) unless start <= end <= plaintext size.
    [[nodiscard]] RangePlan plan(uint64_t start, uint64_t end) const;
    // window holds exactly the object bytes plan(start, end).objectRange names (empty for an empty range); any other
    // length is Error(SizeMismatch).
    [[nodiscard]] SecureBytes read(uint64_t start, uint64_t end, std::span<const uint8_t> window);
    // Fetches the window with one call (one ranged GET) and reads it.
    [[nodiscard]] SecureBytes read(uint64_t start, uint64_t end, const Fetch& fetch);

    [[nodiscard]] const Layout& layout() const { return layout_; }
    [[nodiscard]] const OpenedHeader& header() const { return header_; }
    [[nodiscard]] bool failed() const { return failed_.has_value(); }

private:
    OpenedHeader header_;
    Layout layout_;
    SecureBytes scratch_;
    std::optional<Error> failed_;
};

// Tests: called whenever a chunk fails authentication, with the chunk index and the reader's scratch plaintext right
// after it was wiped (still allocated). An empty function removes the observer.
void setChunkWipeObserverForTesting(std::function<void(uint64_t index, std::span<const uint8_t> scratch)> observer);

}
