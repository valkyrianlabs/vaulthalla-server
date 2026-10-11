#pragma once

#include "fs/Fwd.hpp"
#include "storage/Fwd.hpp"
#include "storage/PlaintextReader.hpp"

#include <chrono>
#include <cstdint>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <vector>

// Cached lossy renders (JPEG) of RenderedImage files: grid thumbnails (caching.thumbnails.sizes, kind
// "thumbnail") and sheet/page renders (kind "render", variant "p<page>-s<size>"), all stored encrypted in
// preview::cache::Store and keyed to the source generation. One decode per source generation and page at a time
// (single flight); a decode emits every missing thumbnail size at or below what it renders. CPU work is bounded by
// two gates: interactive renders and background thumbnailing never wait on each other's slots.
namespace vh::preview::render {

struct Request {
    uint32_t size{1024};
    uint32_t page{0};
};

struct Result {
    std::vector<uint8_t> jpeg;
    bool cacheHit{false};
    std::optional<uint32_t> pageCount;  // PDFs
};

// All render slots stayed busy past the wait budget (HTTP 503 + Retry-After).
class Busy final : public std::runtime_error {
public:
    using std::runtime_error::runtime_error;
};

[[nodiscard]] uint32_t normalizeSize(uint32_t requested);

// Cached render, rendering on a miss. `remote` controls whether a cloud file without local bytes may be fetched
// (a user opening one file: FromConfig/hydrate; grid thumbnails: Off).
[[nodiscard]] Result render(const std::shared_ptr<storage::Engine>& engine,
                            const std::shared_ptr<fs::model::File>& file,
                            Request request,
                            storage::RemoteFetchPolicy remote = storage::RemoteFetchPolicy::FromConfig);

// Cache-only lookup (never renders). Reads and authenticates the artifact.
[[nodiscard]] std::optional<Result> cached(const std::shared_ptr<storage::Engine>& engine,
                                           const std::shared_ptr<fs::model::File>& file,
                                           Request request);

enum class ThumbnailState { Ready, Missing, Failed };

// Index-only readiness of the `size` thumbnail of many files of one engine, in one query: no artifact is opened or
// decrypted (serving it still authenticates the bytes). Failed: the source is known not to render (invalid or over a
// limit) for this generation, so asking again is pointless.
[[nodiscard]] std::vector<ThumbnailState> thumbnailStates(const std::shared_ptr<storage::Engine>& engine,
                                                          const std::vector<std::shared_ptr<fs::model::File>>& files,
                                                          uint32_t size);

// Source decodes performed so far (tests: single flight, shared decodes).
[[nodiscard]] uint64_t decodesForTesting();
// Waits (bounded) until no decode or deferred output is in flight; false on timeout.
[[nodiscard]] bool waitForFlightsForTesting(std::chrono::milliseconds timeout = std::chrono::seconds(10));

// Renders every missing configured thumbnail size from ONE decode, downscaling along a chain (largest first).
// `plaintext`, when the caller already holds the bytes (an upload), avoids re-reading the file. Runs on the
// background render budget; a concurrent decode of the same source (an on-demand render) is joined, not repeated.
void generateThumbnails(const std::shared_ptr<storage::Engine>& engine,
                        const std::shared_ptr<fs::model::File>& file,
                        std::span<const uint8_t> plaintext = {});

// Schedules generateThumbnails on the thumbnail pool (deduplicated per file generation). Copies `plaintext`
// only when it is small enough to be worth keeping instead of re-reading.
void enqueueThumbnails(const std::shared_ptr<storage::Engine>& engine,
                       const std::shared_ptr<fs::model::File>& file,
                       std::span<const uint8_t> plaintext = {});

}
