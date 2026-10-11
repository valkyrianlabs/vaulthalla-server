#include "preview/render/Service.hpp"

#include "concurrency/Task.hpp"
#include "concurrency/ThreadPool.hpp"
#include "concurrency/ThreadPoolManager.hpp"
#include "config/Registry.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"
#include "preview/Plan.hpp"
#include "preview/cache/Store.hpp"
#include "preview/render/Raster.hpp"
#include "runtime/Deps.hpp"
#include "stats/model/CacheStats.hpp"
#include "storage/Engine.hpp"
#include "vault/model/Vault.hpp"

#include <algorithm>
#include <chrono>
#include <future>
#include <mutex>
#include <semaphore>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>

namespace vh::preview::render {

namespace {

// 1 = the legacy plaintext pipeline; 2 = encrypted cache; 3 = fast-DCT/4:2:0 thumbnails, alpha over white.
constexpr uint32_t kGeneratorVersion = 3;
constexpr uint64_t kKeepUploadBufferBytes = 64ull * 1024 * 1024;
constexpr uint64_t kMaxArtifactBytes = 64ull * 1024 * 1024;
constexpr auto kGateWait = std::chrono::seconds(20);

// Two budgets of clamp(cores/4, 1, 4) slots each, so background thumbnailing (imports, sync pulls, grid fills) keeps
// its old throughput but can never hold the slots a person waiting on a preview needs.
[[nodiscard]] std::ptrdiff_t gateSlots() {
    return static_cast<std::ptrdiff_t>(std::clamp(std::thread::hardware_concurrency() / 4, 1u, 4u));
}

[[nodiscard]] std::counting_semaphore<>& interactiveGate() {
    static std::counting_semaphore<> gate(gateSlots());
    return gate;
}

[[nodiscard]] std::counting_semaphore<>& backgroundGate() {
    static std::counting_semaphore<> gate(gateSlots());
    return gate;
}

enum class Lane { Interactive, Background };

struct GateSlot {
    explicit GateSlot(const Lane lane)
        : gate(lane == Lane::Interactive ? interactiveGate() : backgroundGate()) {
        if (!gate.try_acquire_for(kGateWait)) throw Busy("All preview render slots are busy");
    }
    ~GateSlot() { gate.release(); }
    GateSlot(const GateSlot&) = delete;
    GateSlot& operator=(const GateSlot&) = delete;
    std::counting_semaphore<>& gate;
};

[[nodiscard]] bool isPdf(const fs::model::File& file) {
    return classify(file).renderer == "pdf";
}

[[nodiscard]] std::vector<uint32_t> thumbnailSizes() {
    auto sizes = config::Registry::get().caching.thumbnails.sizes;
    std::erase_if(sizes, [](const unsigned int s) { return s < 16 || s > 2048; });
    std::ranges::sort(sizes);
    sizes.erase(std::unique(sizes.begin(), sizes.end()), sizes.end());
    return {sizes.begin(), sizes.end()};
}

[[nodiscard]] bool isThumbnailSize(const uint32_t size) {
    const auto& sizes = config::Registry::get().caching.thumbnails.sizes;
    return std::ranges::find(sizes, size) != sizes.end();
}

[[nodiscard]] cache::ArtifactKey keyFor(const std::shared_ptr<storage::Engine>& engine, const fs::model::File& file,
                                        const Request& request) {
    auto generation = storage::generationOf(file);
    cache::ArtifactKey key{
        .vault_id = engine && engine->vault ? engine->vault->id : generation.vault_id,
        .file_id = file.id,
        .kind = "render",
        .variant = "p" + std::to_string(request.page) + "-s" + std::to_string(request.size),
        .source_id = generation.sourceId(),
        .generator_version = kGeneratorVersion
    };
    if (request.page == 0 && isThumbnailSize(request.size)) {
        key.kind = "thumbnail";
        key.variant = std::to_string(request.size);
    }
    return key;
}

// Generator-independent keys (they describe the source, not a rendering of it).
[[nodiscard]] cache::ArtifactKey sourceKey(const std::shared_ptr<storage::Engine>& engine, const fs::model::File& file,
                                           const std::string& kind, const uint32_t generatorVersion) {
    auto key = keyFor(engine, file, {.size = 0, .page = 0});
    key.kind = kind;
    key.variant = "v1";
    key.generator_version = generatorVersion;
    return key;
}

// Rows written before migration 109 carry no page count; their page count lives in a 'pdf-info' artifact.
[[nodiscard]] cache::ArtifactKey legacyPdfInfoKey(const std::shared_ptr<storage::Engine>& engine,
                                                  const fs::model::File& file) {
    return sourceKey(engine, file, "pdf-info", 2);
}

[[nodiscard]] cache::ArtifactKey failureKey(const std::shared_ptr<storage::Engine>& engine, const fs::model::File& file) {
    return sourceKey(engine, file, "render-failure", kGeneratorVersion);
}

// The derived cache is an optimization: when it can't be reached (database unavailable, no vault key loaded)
// renders still work, they are just not cached.
[[nodiscard]] cache::ReadResult safeRead(const std::shared_ptr<storage::Engine>& engine, const cache::ArtifactKey& key) {
    try {
        return cache::Store::read(engine, key, kMaxArtifactBytes);
    } catch (const std::exception& e) {
        log::Registry::thumb()->debug("[Render] Derived cache unavailable for {}: {}", key.canonical(), e.what());
        return {};
    }
}

[[nodiscard]] std::optional<uint32_t> legacyPageCount(const std::shared_ptr<storage::Engine>& engine,
                                                      const fs::model::File& file) {
    const auto read = safeRead(engine, legacyPdfInfoKey(engine, file));
    if (read.status != cache::LookupStatus::Ready) return std::nullopt;
    try {
        return static_cast<uint32_t>(std::stoul(std::string(read.bytes.begin(), read.bytes.end())));
    } catch (...) {
        return std::nullopt;
    }
}

void storeQuietly(const std::shared_ptr<storage::Engine>& engine, const cache::ArtifactKey& key,
                  const std::vector<uint8_t>& bytes, const std::optional<uint32_t> pageCount) {
    try {
        (void)cache::Store::put(engine, key, bytes, cache::Durability::Disposable, pageCount);
    } catch (const std::exception& e) {
        log::Registry::thumb()->warn("[Render] Could not cache {}: {}", key.canonical(), e.what());
    }
}

[[nodiscard]] std::vector<uint8_t> sourceBytes(const std::shared_ptr<storage::Engine>& engine,
                                               const std::shared_ptr<fs::model::File>& file,
                                               const storage::RemoteFetchPolicy remote, const Limits& limits) {
    if (file->size_bytes > limits.maxSourceBytes) throw LimitExceeded("File exceeds the preview size limit");
    const auto reader = engine->openPlaintextReader(file, {.integrity = storage::IntegrityPolicy::FromConfig,
                                                           .remote = remote});
    return storage::readAll(*reader, limits.maxSourceBytes);
}

[[nodiscard]] Raster rasterize(const fs::model::File& file, const std::span<const uint8_t> bytes, const uint32_t size,
                               const uint32_t page, const Limits& limits, std::optional<uint32_t>& pageCount) {
    if (isPdf(file)) {
        uint32_t pages = 0;
        auto raster = renderPdfPage(bytes, page, size, limits, pages);
        pageCount = pages;
        return raster;
    }
    if (page != 0) throw InvalidInput("Images have a single page");
    return decodeImage(bytes, size, limits);
}

// A source that failed to decode (invalid, or over a limit) is not decoded again for this generation, whatever
// size or page is asked next: hostile files can't turn every request into a fresh decode.
void throwIfKnownBad(const std::shared_ptr<storage::Engine>& engine, const fs::model::File& file) {
    const auto read = safeRead(engine, failureKey(engine, file));
    if (read.status != cache::LookupStatus::Failed) return;
    if (read.failure.starts_with("limit:")) throw LimitExceeded(read.failure.substr(6));
    throw InvalidInput(read.failure.starts_with("invalid:") ? read.failure.substr(8) : read.failure);
}

void rememberFailure(const std::shared_ptr<storage::Engine>& engine, const fs::model::File& file,
                     const std::exception& e) {
    const bool limit = dynamic_cast<const LimitExceeded*>(&e) != nullptr;
    try {
        cache::Store::putFailure(engine, failureKey(engine, file), std::string(limit ? "limit:" : "invalid:") + e.what());
    } catch (const std::exception& err) {
        log::Registry::thumb()->debug("[Render] Could not record render failure: {}", err.what());
    }
}

// ------------------------------------------------------------------------------------------------ single flight

// One decode per source generation and page at a time. A second request for the same source waits for the first
// (an on-demand render waits for a queued thumbnail task, or the other way round) and then reads what it produced.
std::mutex& flightMutex() {
    static std::mutex m;
    return m;
}

std::unordered_map<std::string, std::shared_future<void>>& flights() {
    static std::unordered_map<std::string, std::shared_future<void>> f;
    return f;
}

[[nodiscard]] std::string flightKey(const fs::model::File& file, const uint32_t page) {
    return std::to_string(file.id) + ":" + storage::generationOf(file).sourceId() + ":p" + std::to_string(page);
}

class Flight {
public:
    // Leader when no flight for `key` is running; otherwise holds the running one's future.
    explicit Flight(std::string key) : key_(std::move(key)) {
        std::scoped_lock lock(flightMutex());
        if (const auto it = flights().find(key_); it != flights().end()) {
            other_ = it->second;
            return;
        }
        flights().emplace(key_, done_.get_future().share());
        leader_ = true;
    }
    ~Flight() {
        if (!leader_) return;
        {
            std::scoped_lock lock(flightMutex());
            flights().erase(key_);
        }
        done_.set_value();
    }
    Flight(const Flight&) = delete;
    Flight& operator=(const Flight&) = delete;

    [[nodiscard]] bool leader() const { return leader_; }
    void wait() const {
        if (other_.valid()) (void)other_.wait_for(kGateWait);
    }

private:
    std::string key_;
    std::promise<void> done_;
    std::shared_future<void> other_;
    bool leader_ = false;
};

std::atomic<uint64_t> decodeCount{0};

// One decode of `file` page `page` at `decodeSize`, then every output size (descending) resized down a chain from it,
// encoded and cached. Returns the encoded output of `wanted` (if it is one of `outputs`).
std::optional<std::vector<uint8_t>> produce(const std::shared_ptr<storage::Engine>& engine,
                                            const std::shared_ptr<fs::model::File>& file, const uint32_t page,
                                            std::vector<uint32_t> outputs, const std::optional<uint32_t> wanted,
                                            const Lane lane, const storage::RemoteFetchPolicy remote,
                                            const std::span<const uint8_t> plaintext,
                                            std::optional<uint32_t>& pageCount) {
    std::ranges::sort(outputs, std::greater<>());
    outputs.erase(std::unique(outputs.begin(), outputs.end()), outputs.end());
    const auto limits = limitsFromConfig();
    throwIfKnownBad(engine, *file);

    GateSlot slot(lane);
    std::vector<uint8_t> owned;
    std::span<const uint8_t> bytes = plaintext;
    if (bytes.empty() || bytes.size() != file->size_bytes) {
        owned = sourceBytes(engine, file, remote, limits);
        bytes = owned;
    }

    Raster current;
    try {
        decodeCount.fetch_add(1, std::memory_order_relaxed);
        current = fit(rasterize(*file, bytes, outputs.front(), page, limits, pageCount), outputs.front());
    } catch (const InvalidInput& e) {
        // A page past the end is the caller's mistake, not a property of the file.
        if (std::string_view(e.what()).find("page out of range") == std::string_view::npos &&
            std::string_view(e.what()).find("single page") == std::string_view::npos)
            rememberFailure(engine, *file, e);
        std::fill(owned.begin(), owned.end(), uint8_t{0});
        throw;
    } catch (const LimitExceeded& e) {
        rememberFailure(engine, *file, e);
        std::fill(owned.begin(), owned.end(), uint8_t{0});
        throw;
    }
    std::fill(owned.begin(), owned.end(), uint8_t{0});

    std::optional<std::vector<uint8_t>> result;
    for (const auto size : outputs) {
        current = fit(std::move(current), size);
        auto jpeg = encodeJpeg(current, 85, size <= kThumbnailEncodeMax ? Subsampling::S420 : Subsampling::S444);
        storeQuietly(engine, keyFor(engine, *file, {.size = size, .page = page}), jpeg, pageCount);
        if (wanted && *wanted == size) result = std::move(jpeg);
    }
    return result;
}

struct ThumbnailTask final : concurrency::Task {
    std::shared_ptr<storage::Engine> engine;
    std::shared_ptr<fs::model::File> file;
    std::vector<uint8_t> plaintext;
    std::string dedupeKey;

    void operator()() override {
        try {
            generateThumbnails(engine, file, plaintext);
        } catch (const std::exception& e) {
            log::Registry::thumb()->debug("[Render] Thumbnail generation skipped for file {}: {}", file->id, e.what());
        }
        std::fill(plaintext.begin(), plaintext.end(), uint8_t{0});
    }
};

// Thumbnail sizes this generation still lacks (one index query for all of them).
[[nodiscard]] std::vector<uint32_t> missingThumbnails(const std::shared_ptr<storage::Engine>& engine,
                                                      const fs::model::File& file) {
    const auto sizes = thumbnailSizes();
    std::vector<cache::ArtifactKey> keys;
    keys.reserve(sizes.size());
    for (const auto s : sizes) keys.push_back(keyFor(engine, file, {.size = s, .page = 0}));
    std::vector<cache::IndexStatus> status;
    try {
        status = cache::Store::status(keys);
    } catch (const std::exception&) {
        return sizes;
    }
    std::vector<uint32_t> missing;
    for (std::size_t i = 0; i < sizes.size(); ++i)
        if (status[i].status != cache::LookupStatus::Ready) missing.push_back(sizes[i]);
    return missing;
}

}

uint32_t normalizeSize(const uint32_t requested) {
    if (requested == 0) return 1024;
    return std::clamp<uint32_t>(requested, 16, 2048);
}

uint64_t decodesForTesting() { return decodeCount.load(); }

std::optional<Result> cached(const std::shared_ptr<storage::Engine>& engine,
                             const std::shared_ptr<fs::model::File>& file, Request request) {
    if (!engine || !file) return std::nullopt;
    request.size = normalizeSize(request.size);
    auto read = safeRead(engine, keyFor(engine, *file, request));
    if (read.status != cache::LookupStatus::Ready) {
        if (const auto& stats = runtime::Deps::get().httpCacheStats) stats->record_miss();
        return std::nullopt;
    }
    if (const auto& stats = runtime::Deps::get().httpCacheStats) stats->record_hit(read.bytes.size());
    Result result{.jpeg = std::move(read.bytes), .cacheHit = true, .pageCount = std::nullopt};
    if (isPdf(*file)) result.pageCount = read.pageCount ? read.pageCount : legacyPageCount(engine, *file);
    return result;
}

std::vector<ThumbnailState> thumbnailStates(const std::shared_ptr<storage::Engine>& engine,
                                            const std::vector<std::shared_ptr<fs::model::File>>& files,
                                            const uint32_t size) {
    std::vector<ThumbnailState> out(files.size(), ThumbnailState::Missing);
    std::vector<cache::ArtifactKey> keys;
    keys.reserve(files.size() * 2);
    for (const auto& file : files) {
        keys.push_back(keyFor(engine, *file, {.size = size, .page = 0}));
        keys.push_back(failureKey(engine, *file));
    }
    const auto status = cache::Store::status(keys);
    for (std::size_t i = 0; i < files.size(); ++i) {
        if (status[2 * i].status == cache::LookupStatus::Ready) out[i] = ThumbnailState::Ready;
        else if (status[2 * i + 1].status == cache::LookupStatus::Failed) out[i] = ThumbnailState::Failed;
    }
    return out;
}

Result render(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<fs::model::File>& liveFile,
              Request request, const storage::RemoteFetchPolicy remote) {
    if (!engine || !liveFile) throw std::invalid_argument("Nothing to render");
    // One immutable snapshot for the whole render: the cache key and the reader must describe the same generation.
    // (Overwrites mutate the cached File in place; a key taken from it after reading could label old pixels as new.)
    const auto file = std::make_shared<fs::model::File>(*liveFile);
    if (classify(*file).kind != PreviewKind::RenderedImage) throw InvalidInput("This file type has no server render");
    request.size = normalizeSize(request.size);

    const auto started = std::chrono::steady_clock::now();
    for (int attempt = 0;; ++attempt) {
        if (auto hit = cached(engine, file, request); hit && (!isPdf(*file) || hit->pageCount)) return std::move(*hit);

        Flight flight(flightKey(*file, request.page));
        if (!flight.leader() && attempt == 0) {
            flight.wait();   // someone is decoding this source right now: use what it produces
            continue;
        }

        // Leader: this decode also fills every missing thumbnail size at or below the requested one (page 0), so
        // opening an image after its grid thumbnail, or a grid after an open, never decodes the source twice.
        std::vector<uint32_t> outputs{request.size};
        if (request.page == 0)
            for (const auto s : missingThumbnails(engine, *file))
                if (s <= request.size) outputs.push_back(s);

        std::optional<uint32_t> pageCount;
        auto jpeg = produce(engine, file, request.page, outputs, request.size, Lane::Interactive, remote, {}, pageCount);
        Result result{.jpeg = jpeg ? std::move(*jpeg) : std::vector<uint8_t>{}, .cacheHit = false, .pageCount = pageCount};
        if (const auto& stats = runtime::Deps::get().httpCacheStats)
            stats->record_op_us(static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                std::chrono::steady_clock::now() - started).count()));
        return result;
    }
}

void generateThumbnails(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<fs::model::File>& liveFile,
                        const std::span<const uint8_t> plaintext) {
    if (!engine || !liveFile || liveFile->size_bytes == 0) return;
    const auto file = std::make_shared<fs::model::File>(*liveFile);  // see render(): key and bytes from one generation
    if (!classify(*file).thumbnail) return;

    for (int attempt = 0; attempt < 2; ++attempt) {
        const auto missing = missingThumbnails(engine, *file);
        if (missing.empty()) return;
        Flight flight(flightKey(*file, 0));
        if (!flight.leader()) {
            flight.wait();
            continue;
        }
        std::optional<uint32_t> pageCount;
        (void)produce(engine, file, 0, missing, std::nullopt, Lane::Background, storage::RemoteFetchPolicy::Off,
                      plaintext, pageCount);
        return;
    }
}

void enqueueThumbnails(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<fs::model::File>& file,
                       const std::span<const uint8_t> plaintext) {
    try {
        if (!engine || !file || !classify(*file).thumbnail || file->size_bytes == 0) return;
        static std::mutex queuedMutex;
        static std::unordered_set<std::string> queued;
        const auto key = flightKey(*file, 0);
        {
            std::scoped_lock lock(queuedMutex);
            if (!queued.insert(key).second) return;   // already queued (a running decode is joined via its flight)
        }
        auto task = std::make_shared<ThumbnailTask>();
        task->engine = engine;
        // Snapshot now: the plaintext handed in belongs to this generation, and the file may be overwritten before
        // the task runs (thumbnails of old bytes must never be stored under a newer source id).
        task->file = std::make_shared<fs::model::File>(*file);
        task->dedupeKey = key;
        if (!plaintext.empty() && plaintext.size() == file->size_bytes && plaintext.size() <= kKeepUploadBufferBytes)
            task->plaintext.assign(plaintext.begin(), plaintext.end());

        struct Unqueue final : concurrency::Task {
            std::shared_ptr<ThumbnailTask> inner;
            void operator()() override {
                (*inner)();
                std::scoped_lock lock(queuedMutex);
                queued.erase(inner->dedupeKey);
            }
        };
        auto wrapped = std::make_shared<Unqueue>();
        wrapped->inner = std::move(task);

        const auto pool = concurrency::ThreadPoolManager::instance().thumbPool();
        if (!pool) {
            std::scoped_lock lock(queuedMutex);
            queued.erase(key);
            return;
        }
        pool->submit(wrapped);
    } catch (const std::exception& e) {
        log::Registry::thumb()->error("[Render] Failed to enqueue thumbnails: {}", e.what());
    }
}

}
