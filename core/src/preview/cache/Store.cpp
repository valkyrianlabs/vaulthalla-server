#include "preview/cache/Store.hpp"

#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/query/fs/Cache.hpp"
#include "fs/cache/Record.hpp"
#include "fs/model/Path.hpp"
#include "log/Registry.hpp"
#include "platform/Durable.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/GcmFileReader.hpp"
#include "storage/Manager.hpp"
#include "stats/model/CacheStats.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <fmt/format.h>
#include <mutex>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>
#include <unordered_map>
#include <unordered_set>

namespace vh::preview::cache {

namespace {

constexpr std::array<char, 8> kMagic{'V', 'H', 'D', 'E', 'R', 'I', 'V', '1'};
constexpr uint16_t kHeaderVersion = 1;

std::atomic<int64_t> failureTtlSeconds{24 * 3600};

using Record = fs::cache::Record;

[[nodiscard]] std::string sanitize(const std::string& value) {
    std::string out;
    out.reserve(value.size());
    for (const unsigned char c : value)
        out.push_back(std::isalnum(c) || c == '-' || c == '_' || c == '.' ? static_cast<char>(c) : '_');
    if (out.empty() || out == "." || out == "..") out = "_";
    return out;
}

[[nodiscard]] std::filesystem::path relativePathFor(const ArtifactKey& key) {
    return std::filesystem::path("derived") / std::to_string(key.file_id) /
           (sanitize(key.kind) + "." + sanitize(key.variant) + ".vhd");
}

[[nodiscard]] const std::filesystem::path& cacheRootOf(const std::shared_ptr<storage::Engine>& engine) {
    if (!engine || !engine->paths) throw std::runtime_error("Derived artifacts need a storage engine with paths");
    return engine->paths->cacheRoot;
}

[[nodiscard]] std::array<uint8_t, Store::kHeaderSize> buildHeader(const uint32_t keyVersion,
                                                                   const std::array<uint8_t, 12>& iv) {
    std::array<uint8_t, Store::kHeaderSize> h{};
    std::memcpy(h.data(), kMagic.data(), kMagic.size());
    h[8] = static_cast<uint8_t>(kHeaderVersion & 0xff);
    h[9] = static_cast<uint8_t>(kHeaderVersion >> 8);
    for (int i = 0; i < 4; ++i) h[12 + i] = static_cast<uint8_t>(keyVersion >> (8 * i));
    std::memcpy(h.data() + 16, iv.data(), iv.size());
    return h;
}

struct ParsedHeader {
    uint32_t keyVersion{};
    std::array<uint8_t, 12> iv{};
    std::array<uint8_t, Store::kHeaderSize> raw{};
};

[[nodiscard]] std::optional<ParsedHeader> parseHeader(const std::span<const uint8_t> bytes) {
    if (bytes.size() < Store::kHeaderSize) return std::nullopt;
    ParsedHeader h;
    std::memcpy(h.raw.data(), bytes.data(), h.raw.size());
    if (std::memcmp(h.raw.data(), kMagic.data(), kMagic.size()) != 0) return std::nullopt;
    if ((h.raw[8] | (h.raw[9] << 8)) != kHeaderVersion) return std::nullopt;
    for (int i = 0; i < 4; ++i) h.keyVersion |= static_cast<uint32_t>(h.raw[12 + i]) << (8 * i);
    std::memcpy(h.iv.data(), h.raw.data() + 16, h.iv.size());
    return h;
}

[[nodiscard]] std::optional<ParsedHeader> readHeader(const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return std::nullopt;
    std::array<uint8_t, Store::kHeaderSize> raw{};
    const auto n = ::pread(fd, raw.data(), raw.size(), 0);
    ::close(fd);
    if (n != static_cast<ssize_t>(raw.size())) return std::nullopt;
    return parseHeader(raw);
}

// Hits since the last flush: artifact id -> nothing (the flush stamps NOW()).
std::mutex& touchMutex() {
    static std::mutex m;
    return m;
}

std::unordered_set<unsigned int>& pendingTouches() {
    static std::unordered_set<unsigned int> s;
    return s;
}

void noteTouch(const unsigned int id) {
    std::scoped_lock lock(touchMutex());
    pendingTouches().insert(id);
}

// A row that may still be served: current source and generator, and not an expired failure.
enum class RowState { Usable, Stale, ExpiredFailure };

[[nodiscard]] RowState rowState(const Record& record, const ArtifactKey& key) {
    if (record.source_id != key.source_id || record.generator_version != key.generator_version) return RowState::Stale;
    if (record.status == Record::Status::Failed && std::time(nullptr) - record.created_at > failureTtlSeconds.load())
        return RowState::ExpiredFailure;
    return RowState::Usable;
}

[[nodiscard]] std::vector<uint8_t> aadFor(const std::array<uint8_t, Store::kHeaderSize>& header, const ArtifactKey& key) {
    const auto canonical = key.canonical();
    std::vector<uint8_t> aad(header.begin(), header.end());
    aad.insert(aad.end(), canonical.begin(), canonical.end());
    return aad;
}

void fsyncDir(const std::filesystem::path& dir) {
    const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return;
    (void)platform::durable::sync(fd);
    ::close(fd);
}

void removeQuietly(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

void deleteRecord(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<Record>& record) {
    if (!record) return;
    if (db::query::fs::Cache::deleteDerivedArtifactIfUnchanged(record->id, record->source_id) && engine &&
        engine->paths && !record->path.empty())
        removeQuietly(engine->paths->cacheRoot / record->path);
}

[[nodiscard]] std::shared_ptr<storage::Engine> engineForVault(const uint32_t vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    return manager ? manager->getEngine(vaultId) : nullptr;
}

}

std::string ArtifactKey::canonical() const {
    return fmt::format("{}/{}/{}/{}/{}/{}", vault_id, file_id, kind, variant, source_id, generator_version);
}

void Store::setFailureTtl(const std::chrono::seconds ttl) { failureTtlSeconds.store(ttl.count()); }

Lookup Store::lookup(const std::shared_ptr<storage::Engine>& engine, const ArtifactKey& key) {
    const auto record = db::query::fs::Cache::getDerivedArtifact(key.file_id, key.kind, key.variant);
    if (!record) return {};

    if (rowState(*record, key) != RowState::Usable) {
        deleteRecord(engine, record);  // stale (source changed, generator upgraded) or an expired failure
        return {};
    }

    if (record->status == Record::Status::Failed)
        return {.status = LookupStatus::Failed, .artifact = std::nullopt, .failure = record->failure_reason};

    const auto path = cacheRootOf(engine) / record->path;
    const auto header = readHeader(path);
    std::error_code ec;
    const auto onDisk = std::filesystem::file_size(path, ec);
    if (!header || ec || onDisk != kHeaderSize + record->size + crypto::util::AES_TAG_SIZE) {
        deleteRecord(engine, record);
        return {};
    }
    if (!engine->encryptionManager) return {};
    try {
        (void)engine->encryptionManager->keySnapshot(header->keyVersion);
    } catch (const std::exception&) {
        deleteRecord(engine, record);  // sealed under a key that rotation has retired
        return {};
    }

    noteTouch(record->id);
    return {.status = LookupStatus::Ready, .artifact = Artifact{key, path, record->size, record->page_count}, .failure = {}};
}

ReadResult Store::read(const std::shared_ptr<storage::Engine>& engine, const ArtifactKey& key, const uint64_t maxBytes) {
    const auto record = db::query::fs::Cache::getDerivedArtifact(key.file_id, key.kind, key.variant);
    if (!record) return {};
    switch (rowState(*record, key)) {
        case RowState::Stale:
        case RowState::ExpiredFailure:
            deleteRecord(engine, record);
            return {};
        case RowState::Usable: break;
    }
    if (record->status == Record::Status::Failed)
        return {.status = LookupStatus::Failed, .bytes = {}, .pageCount = std::nullopt, .failure = record->failure_reason};
    if (record->size > maxBytes) return {};
    if (!engine || !engine->encryptionManager) return {};

    const auto path = cacheRootOf(engine) / record->path;
    const auto drop = [&](const std::string& why) -> ReadResult {
        log::Registry::storage()->warn("[DerivedStore] Dropping unreadable artifact {}: {}", key.canonical(), why);
        deleteRecord(engine, record);
        return {};
    };

    // One open, one fstat, one read of header || body || tag.
    const int fd = ::open(path.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) return drop("missing file");
    struct FdGuard { int fd; ~FdGuard() { ::close(fd); } } guard{fd};
    struct stat st{};
    const auto expected = kHeaderSize + record->size + crypto::util::AES_TAG_SIZE;
    if (::fstat(fd, &st) != 0 || static_cast<uint64_t>(st.st_size) != expected) return drop("size mismatch");
    std::vector<uint8_t> sealed(static_cast<std::size_t>(expected));
    std::size_t done = 0;
    while (done < sealed.size()) {
        const auto n = ::pread(fd, sealed.data() + done, sealed.size() - done, static_cast<off_t>(done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return drop("short read");
        done += static_cast<std::size_t>(n);
    }

    const auto header = parseHeader(sealed);
    if (!header) return drop("bad header");
    crypto::SecretKeyPtr secret;
    try {
        secret = engine->encryptionManager->keySnapshot(header->keyVersion);
    } catch (const std::exception&) {
        deleteRecord(engine, record);  // sealed under a key that rotation has retired
        return {};
    }

    ReadResult out;
    out.bytes.resize(static_cast<std::size_t>(record->size));
    const auto body = std::span<const uint8_t>(sealed).subspan(kHeaderSize, out.bytes.size());
    const auto tag = std::span<const uint8_t, crypto::util::AES_TAG_SIZE>(
        sealed.data() + kHeaderSize + out.bytes.size(), crypto::util::AES_TAG_SIZE);
    const auto aad = aadFor(header->raw, key);
    if (!crypto::util::gcmDecrypt(secret->bytes(), header->iv, body, tag, out.bytes, aad)) {
        sodium_memzero(out.bytes.data(), out.bytes.size());
        return drop("authentication failed");
    }
    noteTouch(record->id);
    out.status = LookupStatus::Ready;
    out.pageCount = record->page_count;
    return out;
}

std::vector<IndexStatus> Store::status(const std::vector<ArtifactKey>& keys) {
    std::vector<IndexStatus> out(keys.size());
    if (keys.empty()) return out;
    std::vector<unsigned int> fileIds;
    std::vector<std::string> kinds;
    for (const auto& k : keys) {
        fileIds.push_back(k.file_id);
        if (std::ranges::find(kinds, k.kind) == kinds.end()) kinds.push_back(k.kind);
    }
    const auto rows = db::query::fs::Cache::listDerivedArtifactsFor(fileIds, kinds);
    std::unordered_map<std::string, std::shared_ptr<Record>> byIdentity;
    for (const auto& r : rows) byIdentity[std::to_string(r->file_id) + "/" + r->kind + "/" + r->variant] = r;
    for (std::size_t i = 0; i < keys.size(); ++i) {
        const auto& k = keys[i];
        const auto it = byIdentity.find(std::to_string(k.file_id) + "/" + k.kind + "/" + k.variant);
        if (it == byIdentity.end() || rowState(*it->second, k) != RowState::Usable) continue;
        if (it->second->status == Record::Status::Failed)
            out[i] = {.status = LookupStatus::Failed, .failure = it->second->failure_reason};
        else out[i] = {.status = LookupStatus::Ready, .failure = {}};
    }
    return out;
}

void Store::flushTouches() {
    std::vector<unsigned int> ids;
    {
        std::scoped_lock lock(touchMutex());
        ids.assign(pendingTouches().begin(), pendingTouches().end());
        pendingTouches().clear();
    }
    if (ids.empty()) return;
    try {
        db::query::fs::Cache::touchDerivedArtifacts(ids);
    } catch (const std::exception& e) {
        log::Registry::storage()->debug("[DerivedStore] last_accessed flush failed: {}", e.what());
    }
}

std::unique_ptr<storage::PlaintextReader> Store::open(const std::shared_ptr<storage::Engine>& engine,
                                                      const Artifact& artifact) {
    if (!engine || !engine->encryptionManager) throw std::runtime_error("Derived artifacts need the vault key");
    const auto header = readHeader(artifact.path);
    if (!header) throw storage::IntegrityError("Derived artifact header is invalid");

    storage::GcmFileReader::Params params;
    params.path = artifact.path;
    params.dataOffset = kHeaderSize;
    params.plaintextSize = artifact.size;
    params.key = engine->encryptionManager->keySnapshot(header->keyVersion);
    params.iv = header->iv;
    params.aad = aadFor(header->raw, artifact.key);
    params.expectedHeader.assign(header->raw.begin(), header->raw.end());
    params.generation = storage::Generation{
        .vault_id = artifact.key.vault_id,
        .file_id = artifact.key.file_id,
        .iv_b64 = crypto::util::b64_encode(std::vector<uint8_t>(header->iv.begin(), header->iv.end())),
        .key_version = header->keyVersion,
        .size = artifact.size,
        .updated_at = 0
    };
    params.integrityDomain = "artifact:" + artifact.key.canonical();
    params.strict = false;
    return std::make_unique<storage::GcmFileReader>(std::move(params));
}

struct Store::Writer::Impl {
    std::shared_ptr<storage::Engine> engine;
    ArtifactKey key;
    std::filesystem::path finalPath, tempPath;
    int fd{-1};
    uint64_t maxBytes{};
    uint64_t written{};
    uint32_t keyVersion{};
    std::array<uint8_t, 12> iv{};
    std::unique_ptr<crypto::util::GcmStreamEncryptor> encryptor;
    std::vector<uint8_t> scratch;
    Durability durability{Durability::Durable};
    std::optional<uint32_t> pageCount;
    bool done{false};

    ~Impl() { abort(); }

    void abort() noexcept {
        if (fd >= 0) {
            ::close(fd);
            fd = -1;
        }
        if (!done && !tempPath.empty()) removeQuietly(tempPath);
        done = true;
    }

    void writeAll(const uint8_t* data, std::size_t size) {
        while (size > 0) {
            const auto n = ::write(fd, data, size);
            if (n < 0) {
                if (errno == EINTR) continue;
                throw std::system_error(errno, std::generic_category(), "write derived artifact");
            }
            data += n;
            size -= static_cast<std::size_t>(n);
        }
    }
};

Store::Writer::Writer(std::unique_ptr<Impl> impl) : impl_(std::move(impl)) {}
Store::Writer::Writer(Writer&&) noexcept = default;
Store::Writer& Store::Writer::operator=(Writer&&) noexcept = default;
Store::Writer::~Writer() = default;

uint64_t Store::Writer::bytesWritten() const { return impl_ ? impl_->written : 0; }

void Store::Writer::write(const std::span<const uint8_t> plaintext) {
    if (!impl_ || impl_->done) throw std::logic_error("Derived artifact writer is closed");
    if (plaintext.size() > impl_->maxBytes - std::min(impl_->maxBytes, impl_->written))
        throw std::length_error("Derived artifact exceeds its size limit");
    impl_->scratch.resize(std::max<std::size_t>(impl_->scratch.size(), std::min<std::size_t>(plaintext.size(), 1u << 20)));
    std::size_t offset = 0;
    while (offset < plaintext.size()) {
        const auto step = std::min(plaintext.size() - offset, impl_->scratch.size());
        impl_->encryptor->update(plaintext.subspan(offset, step), std::span<uint8_t>(impl_->scratch.data(), step));
        impl_->writeAll(impl_->scratch.data(), step);
        offset += step;
    }
    impl_->written += plaintext.size();
}

Artifact Store::Writer::commit() {
    if (!impl_ || impl_->done) throw std::logic_error("Derived artifact writer is closed");
    auto& s = *impl_;
    const auto tag = s.encryptor->finish();
    s.writeAll(tag.data(), tag.size());
    // Disposable artifacts skip both fsyncs: a crash can only lose or tear the file, which every read detects (exact
    // size, header, GCM tag) and turns into a regeneration; the temp-file rename still keeps readers from ever seeing
    // a partial file.
    const bool durable = s.durability == Durability::Durable;
    if (durable && platform::durable::sync(s.fd) != 0) throw std::system_error(errno, std::generic_category(), "fsync derived artifact");
    ::close(s.fd);
    s.fd = -1;
    std::fill(s.scratch.begin(), s.scratch.end(), uint8_t{0});

    std::filesystem::rename(s.tempPath, s.finalPath);
    if (durable) fsyncDir(s.finalPath.parent_path());
    s.done = true;

    auto record = std::make_shared<Record>();
    record->vault_id = s.key.vault_id;
    record->file_id = s.key.file_id;
    record->path = relativePathFor(s.key);
    record->type = Record::Type::Derived;
    record->size = s.written;
    record->kind = s.key.kind;
    record->variant = s.key.variant;
    record->source_id = s.key.source_id;
    record->generator_version = s.key.generator_version;
    record->artifact_iv = crypto::util::b64_encode(std::vector<uint8_t>(s.iv.begin(), s.iv.end()));
    record->artifact_key_version = s.keyVersion;
    record->status = Record::Status::Ready;
    record->page_count = s.pageCount;
    try {
        db::query::fs::Cache::upsertDerivedArtifact(record);
    } catch (...) {
        removeQuietly(s.finalPath);
        throw;
    }

    if (const auto& stats = runtime::Deps::get().httpCacheStats) stats->record_insert(s.written);
    return Artifact{s.key, s.finalPath, s.written, s.pageCount};
}

void Store::Writer::abort() noexcept {
    if (impl_) impl_->abort();
}

Store::Writer Store::begin(const std::shared_ptr<storage::Engine>& engine, const ArtifactKey& key,
                           const uint64_t maxBytes, const Durability durability,
                           const std::optional<uint32_t> pageCount) {
    if (!engine || !engine->encryptionManager) throw std::runtime_error("Derived artifacts need the vault key");
    if (key.kind.empty() || key.variant.empty() || key.source_id.empty())
        throw std::invalid_argument("Derived artifact key is incomplete");

    auto impl = std::make_unique<Writer::Impl>();
    impl->engine = engine;
    impl->key = key;
    impl->maxBytes = maxBytes;
    impl->durability = durability;
    impl->pageCount = pageCount;
    impl->finalPath = cacheRootOf(engine) / relativePathFor(key);
    std::filesystem::create_directories(impl->finalPath.parent_path());
    ::chmod(impl->finalPath.parent_path().c_str(), 0700);

    std::array<char, 17> suffix{};
    std::array<uint8_t, 8> rnd{};
    randombytes_buf(rnd.data(), rnd.size());
    for (std::size_t i = 0; i < rnd.size(); ++i) std::snprintf(suffix.data() + 2 * i, 3, "%02x", rnd[i]);
    impl->tempPath = impl->finalPath.parent_path() / ("." + impl->finalPath.filename().string() + ".tmp-" + suffix.data());
    impl->fd = ::open(impl->tempPath.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (impl->fd < 0) throw std::system_error(errno, std::generic_category(), "create derived artifact");

    const auto [secret, version] = engine->encryptionManager->currentKey();
    impl->keyVersion = version;
    randombytes_buf(impl->iv.data(), impl->iv.size());
    const auto header = buildHeader(version, impl->iv);
    const auto aad = aadFor(header, key);
    impl->encryptor = std::make_unique<crypto::util::GcmStreamEncryptor>(secret->bytes(), impl->iv, aad);
    impl->writeAll(header.data(), header.size());
    return Writer(std::move(impl));
}

Artifact Store::put(const std::shared_ptr<storage::Engine>& engine, const ArtifactKey& key,
                    const std::span<const uint8_t> plaintext, const Durability durability,
                    const std::optional<uint32_t> pageCount) {
    auto writer = begin(engine, key, plaintext.size(), durability, pageCount);
    writer.write(plaintext);
    return writer.commit();
}

void Store::putFailure(const std::shared_ptr<storage::Engine>& engine, const ArtifactKey& key,
                       const std::string& reason) {
    (void)engine;
    auto record = std::make_shared<Record>();
    record->vault_id = key.vault_id;
    record->file_id = key.file_id;
    record->path = relativePathFor(key);
    record->type = Record::Type::Derived;
    record->size = 0;
    record->kind = key.kind;
    record->variant = key.variant;
    record->source_id = key.source_id;
    record->generator_version = key.generator_version;
    record->status = Record::Status::Failed;
    record->failure_reason = reason.substr(0, 500);
    db::query::fs::Cache::upsertDerivedArtifact(record);
}

void Store::purgeFile(const std::shared_ptr<storage::Engine>& engine, const uint32_t fileId) {
    for (const auto& record : db::query::fs::Cache::listDerivedArtifactsByFile(fileId)) deleteRecord(engine, record);
    if (engine && engine->paths) {
        std::error_code ec;
        std::filesystem::remove_all(engine->paths->cacheRoot / "derived" / std::to_string(fileId), ec);
    }
}

void Store::purgeVault(const std::shared_ptr<storage::Engine>& engine) {
    if (!engine || !engine->vault) return;
    for (const auto& record : db::query::fs::Cache::listDerivedArtifactsByVault(engine->vault->id))
        deleteRecord(engine, record);
    if (engine->paths) {
        std::error_code ec;
        std::filesystem::remove_all(engine->paths->cacheRoot / "derived", ec);
    }
}

std::size_t Store::purgeRetiredKeys(const std::shared_ptr<storage::Engine>& engine) {
    if (!engine || !engine->vault || !engine->encryptionManager) return 0;
    const auto current = engine->encryptionManager->get_key_version();
    std::size_t removed = 0;
    for (const auto& record : db::query::fs::Cache::listDerivedArtifactsWithStaleKey(engine->vault->id, current)) {
        deleteRecord(engine, record);
        ++removed;
    }
    return removed;
}

std::size_t Store::sweep(const std::shared_ptr<storage::Engine>& engine) {
    if (!engine || !engine->paths || !engine->vault) return 0;
    std::size_t removed = 0;
    std::error_code ec;

    // Legacy plaintext thumbnails (<cacheRoot>/thumbnails/<alias>/<size>.jpg) and the never-used file cache:
    // derived data is now sealed under <cacheRoot>/derived.
    for (const auto& legacy : {engine->paths->thumbnailRoot, engine->paths->fileCacheRoot}) {
        if (std::filesystem::exists(legacy, ec)) {
            removed += static_cast<std::size_t>(std::filesystem::remove_all(legacy, ec));
            log::Registry::storage()->info("[DerivedStore] Removed legacy plaintext cache {}", legacy.string());
        }
    }

    // Artifact directories whose file no longer has any index row (deleted files cascade their rows).
    const auto derivedRoot = engine->paths->cacheRoot / "derived";
    if (!std::filesystem::exists(derivedRoot, ec)) return removed;
    const auto indexed = db::query::fs::Cache::listDerivedFileIdsByVault(engine->vault->id);
    std::unordered_set<std::string> indexedPaths;
    for (const auto& record : db::query::fs::Cache::listDerivedArtifactsByVault(engine->vault->id))
        indexedPaths.insert((engine->paths->cacheRoot / record->path).lexically_normal().string());
    for (const auto& entry : std::filesystem::directory_iterator(derivedRoot, ec)) {
        const auto name = entry.path().filename().string();
        unsigned long id = 0;
        try {
            id = std::stoul(name);
        } catch (...) {
            removed += static_cast<std::size_t>(std::filesystem::remove_all(entry.path(), ec));
            continue;
        }
        if (std::ranges::find(indexed, static_cast<unsigned int>(id)) == indexed.end()) {
            removed += static_cast<std::size_t>(std::filesystem::remove_all(entry.path(), ec));
            continue;
        }
        // Interrupted writes leave .tmp- files behind; a crash between rename and index write leaves an artifact no
        // row points at (it would only be overwritten by the next write of the same key).
        for (const auto& file : std::filesystem::directory_iterator(entry.path(), ec))
            if (file.path().filename().string().find(".tmp-") != std::string::npos ||
                !indexedPaths.contains(file.path().lexically_normal().string())) {
                removeQuietly(file.path());
                ++removed;
            }
    }
    return removed;
}

uint64_t Store::evict(const uint64_t maxBytes, const std::optional<std::chrono::seconds> maxIdle) {
    uint64_t freed = 0;
    const auto drop = [&freed](const std::shared_ptr<Record>& record) {
        const auto engine = engineForVault(record->vault_id);
        deleteRecord(engine, record);
        freed += record->size;
        if (const auto& stats = runtime::Deps::get().httpCacheStats) stats->record_eviction();
    };

    if (maxIdle)
        for (const auto& record : db::query::fs::Cache::listDerivedArtifactsIdle(
                 static_cast<uint64_t>(maxIdle->count()), 1000))
            drop(record);

    auto total = db::query::fs::Cache::derivedArtifactsTotalSize();
    while (total > maxBytes) {
        const auto batch = db::query::fs::Cache::listDerivedArtifactsLru(200);
        if (batch.empty()) break;
        auto remaining = total;
        for (const auto& record : batch) {
            if (remaining <= maxBytes) break;
            drop(record);
            remaining = remaining > record->size ? remaining - record->size : 0;
        }
        // Re-read the real total: rows that could not be deleted (a concurrent regeneration) must not make this loop
        // spin over the same batch.
        const auto after = db::query::fs::Cache::derivedArtifactsTotalSize();
        if (after >= total) break;
        total = after;
    }
    if (const auto& stats = runtime::Deps::get().httpCacheStats) {
        stats->set_used(total);
        stats->set_capacity(maxBytes);
    }
    return freed;
}

}
