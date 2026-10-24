// Remote-only reads for cloud vaults: CloudEngine::openMissingReader (hydrate | ranged | off) and the hydrate
// protocol. See CloudEngine::hydrate and storage/RemoteRangedReader.hpp for the contracts.

#include "storage/CloudEngine.hpp"
#include "sync/events/Subscriptions.hpp"
#include "platform/Durable.hpp"
#include "platform/StagedFile.hpp"

#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/query/fs/File.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "fs/ops/file.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/GcmFileReader.hpp"
#include "storage/RemoteRangedReader.hpp"
#include "storage/ScopedS3RequestUsageCapture.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/model/S3Vault.hpp"

#include <fmt/format.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <fcntl.h>
#include <system_error>
#include <sys/stat.h>
#include <unistd.h>

namespace vh::storage {

namespace cloud_remote_read_detail {

using FileModel = ::vh::fs::model::File;

constexpr const char* kHydrateOperation = "preview_hydrate";
constexpr const char* kRangedOperation = "preview_ranged";
// Room for an error response body on top of the object's own bytes in a hydrate's byte cap.
constexpr uint64_t kErrorBodySlack = 64 * 1024;

[[noreturn]] void throwErrnoAt(const int err, const std::string& what, const std::filesystem::path& path) {
    throw std::system_error(err, std::generic_category(), what + " " + path.string());
}

void writeAllTo(const int fd, std::span<const uint8_t> bytes, const std::filesystem::path& path) {
    while (!bytes.empty()) {
        const auto n = ::write(fd, bytes.data(), bytes.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            throwErrnoAt(errno, "write", path);
        }
        bytes = bytes.subspan(static_cast<std::size_t>(n));
    }
}

// A ciphertext file that is not visible at its target until publish(). Preferably an O_TMPFILE in the target's
// directory (no name at all until linked, so a crash leaves nothing behind); where the filesystem lacks O_TMPFILE,
// a private 0600 O_EXCL sibling that is removed on failure. publish() never replaces an existing file.
class StagedFile {
public:
    explicit StagedFile(std::filesystem::path target) : target_(std::move(target)) {
        const auto dir = target_.parent_path();
        std::error_code ec;
        std::filesystem::create_directories(dir, ec);

        fd_ = platform::staged::openUnnamed(dir.c_str());
        if (fd_ >= 0) return;

        named_ = target_;
        named_ += ".vh-hydrate-" + ::vh::fs::ops::generate_random_suffix(12);
        fd_ = ::open(named_.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd_ < 0) throwErrnoAt(errno, "create", named_);
    }

    ~StagedFile() {
        if (fd_ >= 0) ::close(fd_);
        if (!named_.empty() && !published_) {
            std::error_code ec;
            std::filesystem::remove(named_, ec);
        }
    }

    StagedFile(const StagedFile&) = delete;
    StagedFile& operator=(const StagedFile&) = delete;

    [[nodiscard]] int fd() const { return fd_; }

    // fsyncs the bytes, links them at the target and fsyncs the directory. False when the target exists already
    // (someone else stored the file meanwhile); the staged bytes are then discarded.
    bool publish() {
        if (::fchmod(fd_, 0600) < 0) throwErrnoAt(errno, "chmod", target_);
        if (platform::durable::sync(fd_) < 0) throwErrnoAt(errno, "fsync", target_);

        int rc = 0;
        if (named_.empty()) {
            rc = platform::staged::linkUnnamed(fd_, target_.c_str());
        } else {
            rc = ::link(named_.c_str(), target_.c_str());
        }
        if (rc < 0) {
            if (errno == EEXIST) return false;
            throwErrnoAt(errno, "link", target_);
        }

        published_ = true;
        if (!named_.empty()) {
            std::error_code ec;
            std::filesystem::remove(named_, ec);
        }
        try {
            ::vh::fs::ops::fsyncDirectory(target_.parent_path());
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[CloudStorageEngine] Stored {} but could not fsync its directory: {}",
                                         target_.string(), e.what());
        }
        return true;
    }

private:
    std::filesystem::path target_;
    std::filesystem::path named_;
    int fd_{-1};
    bool published_{false};
};

// The row as the rest of the daemon now sees it (the fs cache entry when there is one).
std::shared_ptr<FileModel> currentRowOf(const std::shared_ptr<FileModel>& f) {
    const auto& cache = runtime::Deps::get().fsCache;
    if (!cache || f->fuse_path.empty()) return f;
    try {
        if (auto entry = std::dynamic_pointer_cast<FileModel>(cache->getEntry(f->fuse_path)); entry && entry->path == f->path)
            return entry;
    } catch (const std::exception&) {}
    return f;
}

bool commitHydratedEncryption(const FileModel& updated, const std::string& expectedIv, const unsigned int expectedVersion) {
    if (!db::query::fs::File::compareAndSetEncryptionIVAndVersion(updated, expectedIv, expectedVersion)) return false;

    // Readers decrypt with the cached row: give it the stored copy's IV before the copy becomes visible.
    if (const auto& cache = runtime::Deps::get().fsCache; cache && !updated.fuse_path.empty()) {
        try {
            if (const auto cached = std::dynamic_pointer_cast<FileModel>(cache->getEntry(updated.fuse_path));
                cached && cached->path == updated.path) {
                cached->encryption_iv = updated.encryption_iv;
                cached->encrypted_with_key_version = updated.encrypted_with_key_version;
            }
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[CloudStorageEngine] Could not refresh the cached row of {}: {}",
                                         updated.path.string(), e.what());
        }
    }
    return true;
}

std::array<uint8_t, crypto::util::AES_IV_SIZE> decodeIv(const std::string& ivB64, const std::filesystem::path& path) {
    const auto raw = crypto::util::b64_decode(ivB64);
    if (raw.size() != crypto::util::AES_IV_SIZE) throw std::runtime_error("Invalid remote IV for " + path.string());
    std::array<uint8_t, crypto::util::AES_IV_SIZE> iv{};
    std::ranges::copy(raw, iv.begin());
    return iv;
}

}

std::unique_ptr<PlaintextReader> CloudEngine::openMissingReader(const std::shared_ptr<vh::fs::model::File>& f,
                                                                const ReaderOptions& options) const {
    switch (resolveRemotePolicy(options.remote)) {
    case RemoteFetchPolicy::Off:
        throw ContentUnavailable("File content is not stored locally and remote reads are off "
                                 "(preview.media.remote): " + f->path.string());
    case RemoteFetchPolicy::Ranged:
        return openRangedReader(f);
    case RemoteFetchPolicy::Hydrate:
    case RemoteFetchPolicy::FromConfig:
        break;
    }
    return openLocalReader(hydrate(f), options);
}

std::unique_ptr<RemoteFetchReservation> CloudEngine::reserveRemoteFetch(const RemoteFetchRequest& request) const {
    try {
        if (fetchGate_) return fetchGate_(*this, request);
        return priceBudgetRemoteFetchGate(*this, request);
    } catch (const ContentUnavailable&) {
        throw;
    } catch (const std::exception& e) {
        // Fail closed: no price decision, no fetch.
        throw ContentUnavailable(fmt::format("S3 price preflight for {} of {} failed: {}", request.operation,
                                             request.path.string(), e.what()));
    }
}

std::shared_ptr<vh::fs::model::File> CloudEngine::hydrate(const std::shared_ptr<vh::fs::model::File>& f) const {
    if (!f) throw std::invalid_argument("Cannot hydrate a null file");
    if (f->backing_path.empty()) throw std::runtime_error("File has no backing path: " + f->path.string());

    constexpr auto kHydrateFailureBackoff = std::chrono::minutes(2);
    const auto key = f->backing_path.lexically_normal().string();
    const auto failureKey = key + "|" + f->encryption_iv + "|" + std::to_string(f->encrypted_with_key_version);
    std::promise<std::shared_ptr<vh::fs::model::File>> promise;
    std::shared_future<std::shared_ptr<vh::fs::model::File>> outcome;
    bool leader = false;
    {
        std::scoped_lock lock(hydrateMutex_);
        const auto now = std::chrono::steady_clock::now();
        std::erase_if(hydrateFailures_, [now](const auto& item) { return now - item.second.at > std::chrono::minutes(2); });
        if (const auto it = hydrateFailures_.find(failureKey); it != hydrateFailures_.end() &&
                                                              now - it->second.at < kHydrateFailureBackoff)
            std::rethrow_exception(it->second.error);
        if (const auto it = hydrating_.find(key); it != hydrating_.end()) {
            outcome = it->second;
        } else {
            outcome = promise.get_future().share();
            hydrating_.emplace(key, outcome);
            leader = true;
        }
    }
    if (!leader) return outcome.get();  // one fetch per file: share the leader's result or failure

    try {
        promise.set_value(hydrateNow(f));
    } catch (...) {
        promise.set_exception(std::current_exception());
        std::scoped_lock lock(hydrateMutex_);
        hydrateFailures_[failureKey] = HydrateFailure{std::chrono::steady_clock::now(), std::current_exception()};
    }
    {
        std::scoped_lock lock(hydrateMutex_);
        hydrating_.erase(key);
    }
    return outcome.get();
}

std::shared_ptr<vh::fs::model::File> CloudEngine::hydrateNow(const std::shared_ptr<vh::fs::model::File>& live) const {
    namespace detail = cloud_remote_read_detail;
    using FileModel = detail::FileModel;
    // One immutable snapshot of the row: every decision below (expected size, IV, the final compare-and-set) is
    // made against the same values, even if rotation or a writer updates the shared cached row meanwhile.
    const auto f = std::make_shared<FileModel>(*live);

    std::error_code ec;
    if (std::filesystem::exists(f->backing_path, ec)) return detail::currentRowOf(f);  // stored meanwhile
    if (f->requiresArchiveRestoreForBodyGet())
        throw ContentUnavailable("Remote object is in an archive tier and must be restored first: " + f->path.string());
    if (!s3Provider_) throw std::runtime_error("Cloud engine has no S3 controller");
    if (!encryptionManager) throw std::runtime_error("Vault has no encryption key loaded");

    const auto objectKey = ::vh::fs::model::stripLeadingSlash(f->path);
    const auto maxStored = f->size_bytes + crypto::util::AES_TAG_SIZE;

    // 1. Price preflight before anything upstream (HEAD + one GET of the whole object).
    auto reservation = reserveRemoteFetch({
        .path = f->path, .operation = detail::kHydrateOperation,
        .head_requests = 1, .get_requests = 1, .download_bytes = maxStored});

    // 2. Request cap for this hydrate alone, on top of the engine-wide budget and any outer capture.
    s3::S3RequestBudget cap;
    cap.max_head_requests = 1;
    cap.max_get_requests = 1;
    cap.max_downloaded_bytes = maxStored + detail::kErrorBodySlack;
    std::optional<ScopedS3RequestUsageCapture> capture(std::in_place, *this, cap);

    const auto settle = [&] {
        if (!capture) return;
        auto used = capture->usage();
        used.source = detail::kHydrateOperation;
        capture.reset();
        if (reservation) reservation->commit(used);
    };

    try {
        // 3. HEAD: version (ETag), stored length and encryption context of the object as it is now.
        const auto head = headRemoteObject(f->path);
        if (!head) throw ContentUnavailable("Remote object not found: " + f->path.string());
        if (head->requires_restore)
            throw ContentUnavailable("Remote object is in an archive tier and must be restored first: " + f->path.string());

        const uint64_t expected = f->size_bytes + (head->encrypted ? crypto::util::AES_TAG_SIZE : 0);
        if (head->content_length && *head->content_length != expected)
            throw ContentUnavailable(fmt::format("Remote object {} is {} bytes but the index expects {}; sync the vault",
                                                 f->path.string(), *head->content_length, expected));

        std::string ivB64;
        unsigned int keyVersion = 0;
        crypto::SecretKeyPtr key;
        std::array<uint8_t, crypto::util::AES_IV_SIZE> iv{};
        std::optional<crypto::util::GcmStreamEncryptor> sealer;
        const bool rowEncrypted = !f->encryption_iv.empty();
        if (!head->encrypted && rowEncrypted && !vh::sync::events::subscriptions::importsForeignObjects(vault->id))
            // A bucket that now claims plaintext for a file whose row records its encryption (an IV) is a downgrade,
            // not a format we accept, unless the vault's event subscription explicitly imports foreign objects (the
            // same rule as CloudEngine's download path). A row without an IV was indexed from an object that was
            // plaintext to begin with (an adopted bucket's or a waivered bucket's existing data, another tool's
            // upload): it is sealed below on the way in, whatever the vault's upstream encryption setting says.
            throw IntegrityError("Remote object is unencrypted but the file is stored encrypted: " + f->path.string());
        if (head->encrypted && rowEncrypted && !head->iv_b64.empty() &&
            (head->iv_b64 != f->encryption_iv || head->key_version != f->encrypted_with_key_version))
            // Index-only rows carry the remote object's IV. A different one is another object version (a rollback, a
            // copied object, or a change sync hasn't indexed yet): never serve it under this row.
            throw ContentUnavailable("Remote object no longer matches the index; sync the vault: " + f->path.string());
        if (head->encrypted) {
            // Index-only rows carry the remote IV (indexAndDeleteFile); the object's own metadata wins when present.
            ivB64 = head->iv_b64.empty() ? f->encryption_iv : head->iv_b64;
            keyVersion = head->iv_b64.empty() ? f->encrypted_with_key_version : head->key_version;
            if (ivB64.empty() || keyVersion == 0)
                throw ContentUnavailable("Remote object has no encryption context: " + f->path.string());
            iv = detail::decodeIv(ivB64, f->path);
            key = encryptionManager->keySnapshot(keyVersion);
        } else {
            // Plaintext upstream: seal it on the way in, under a fresh IV and the current key.
            const auto current = encryptionManager->currentKey();
            key = current.key;
            keyVersion = current.version;
            if (sodium_init() < 0) throw std::runtime_error("libsodium init failed");
            randombytes_buf(iv.data(), iv.size());
            ivB64 = crypto::util::b64_encode(std::vector<uint8_t>(iv.begin(), iv.end()));
            sealer.emplace(key->bytes(), crypto::util::GcmIv(iv.data(), iv.size()));
        }
        if (!key) throw std::runtime_error("No vault key for key version " + std::to_string(keyVersion));

        // 4. One GET bound to the HEAD's version, streamed into an unnamed file next to the backing path.
        detail::StagedFile staged(f->backing_path);
        std::vector<uint8_t> sealed;
        s3::GetObjectOptions options;
        if (!head->etag.empty()) options.if_match = head->etag;
        options.max_body_bytes = expected;
        const auto result = s3Provider_->streamObject(objectKey, options, [&](const std::span<const uint8_t> bytes) {
            if (sealer) {
                sealed.resize(bytes.size());
                sealer->update(bytes, sealed);
                detail::writeAllTo(staged.fd(), sealed, f->backing_path);
            } else {
                detail::writeAllTo(staged.fd(), bytes, f->backing_path);
            }
        });
        if (result.body_bytes != expected)
            throw std::runtime_error(fmt::format("Remote object {} returned {} of {} bytes", f->path.string(),
                                                 result.body_bytes, expected));

        // 5. Seal or authenticate the whole message before anything becomes visible.
        if (sealer) {
            const auto tag = sealer->finish();
            detail::writeAllTo(staged.fd(), tag, f->backing_path);
        } else if (!crypto::util::gcmVerifyFd(staged.fd(), 0, f->size_bytes, key->bytes(),
                                              crypto::util::GcmIv(iv.data(), iv.size()))) {
            throw IntegrityError("Remote object failed authentication; nothing was stored: " + f->path.string());
        }

        // 6. Record a changed IV first, then link the copy in. A crash between the two leaves the row on the new IV
        //    and no local copy, which the next read hydrates again; the reverse order could leave a copy the row
        //    cannot decrypt.
        auto hydrated = std::make_shared<FileModel>(*f);
        hydrated->encryption_iv = ivB64;
        hydrated->encrypted_with_key_version = keyVersion;
        {
            // Always conditional, even when the IV is unchanged: the row must still be the generation this hydrate
            // fetched (rotation may have re-keyed the object and moved the row on meanwhile).
            const auto& commit = catalogCommit_ ? catalogCommit_ : HydrateCatalogCommit(detail::commitHydratedEncryption);
            if (!commit(*hydrated, f->encryption_iv, f->encrypted_with_key_version))
                throw ContentUnavailable("File changed while it was being fetched; retry: " + f->path.string());
        }

        // 7. Never replace a file a writer stored meanwhile: its bytes and its row win.
        const bool stored = staged.publish();
        settle();
        if (!stored) return detail::currentRowOf(f);

        log::Registry::cloud()->info("[CloudStorageEngine] Hydrated {} ({} bytes) for vault {}", f->path.string(),
                                     f->size_bytes, vault ? vault->id : 0);
        return hydrated;
    } catch (const s3::RequestBudgetExceeded& e) {
        settle();
        throw ContentUnavailable(fmt::format("S3 request budget refused hydrating {}: {}", f->path.string(), e.what()));
    } catch (const s3::ConditionalRequestFailed&) {
        settle();
        throw ContentUnavailable("Remote object changed while it was being fetched; sync the vault: " + f->path.string());
    } catch (const s3::ObjectNotFound&) {
        settle();
        throw ContentUnavailable("Remote object not found: " + f->path.string());
    } catch (...) {
        settle();
        throw;
    }
}

std::vector<uint8_t> CloudEngine::fetchSealedObject(const std::string& objectKey, const uint64_t storedBytes,
                                                    const std::string& ivB64, const unsigned int keyVersion,
                                                    const std::string& operation) const {
    namespace detail = cloud_remote_read_detail;
    const std::string& kOperation = operation;
    if (!s3Provider_) throw std::runtime_error("Cloud engine has no S3 controller");
    const std::filesystem::path path = "/" + objectKey;
    (void)detail::decodeIv(ivB64, path);  // a malformed IV is refused before anything is fetched

    auto reservation = reserveRemoteFetch({.path = path, .operation = kOperation, .head_requests = 1,
                                           .get_requests = 1, .download_bytes = storedBytes});
    s3::S3RequestBudget cap;
    cap.max_head_requests = 1;
    cap.max_get_requests = 1;
    cap.max_downloaded_bytes = storedBytes + detail::kErrorBodySlack;
    std::optional<ScopedS3RequestUsageCapture> capture(std::in_place, *this, cap);
    const auto settle = [&] {
        if (!capture) return;
        auto used = capture->usage();
        used.source = kOperation;
        capture.reset();
        if (reservation) reservation->commit(used);
    };

    try {
        const auto head = headRemoteObject(path);
        if (!head) throw ContentUnavailable("Remote object not found: " + objectKey);
        if (head->requires_restore)
            throw ContentUnavailable("Remote object is in an archive tier and must be restored first: " + objectKey);
        if (!head->encrypted || head->key_version != keyVersion || (!head->iv_b64.empty() && head->iv_b64 != ivB64))
            throw ContentUnavailable("Remote object " + objectKey + " is no longer sealed under key version " +
                                     std::to_string(keyVersion) + " as indexed; sync the vault");
        const uint64_t length = head->content_length.value_or(storedBytes);
        if (length < crypto::util::AES_TAG_SIZE || length > storedBytes)
            throw ContentUnavailable(fmt::format("Remote object {} is {} bytes but the index expects {}", objectKey,
                                                 length, storedBytes));

        std::vector<uint8_t> sealed;
        sealed.reserve(static_cast<std::size_t>(length));
        s3::GetObjectOptions options;
        if (!head->etag.empty()) options.if_match = head->etag;
        options.max_body_bytes = length;
        const auto result = s3Provider_->streamObject(objectKey, options, [&](std::span<const uint8_t> bytes) {
            if (sealed.size() + bytes.size() > length)
                throw ContentUnavailable("Remote object " + objectKey + " is larger than its HEAD said");
            sealed.insert(sealed.end(), bytes.begin(), bytes.end());
        });
        settle();
        if (result.body_bytes != length || sealed.size() != length)
            throw ContentUnavailable(fmt::format("Remote object {} returned {} of {} bytes", objectKey,
                                                 result.body_bytes, length));
        return sealed;
    } catch (const s3::RequestBudgetExceeded& e) {
        settle();
        throw ContentUnavailable(fmt::format("S3 request budget refused fetching {}: {}", objectKey, e.what()));
    } catch (const s3::ConditionalRequestFailed&) {
        settle();
        throw ContentUnavailable("Remote object changed while it was being fetched: " + objectKey);
    } catch (const s3::ObjectNotFound&) {
        settle();
        throw ContentUnavailable("Remote object not found: " + objectKey);
    } catch (...) {
        settle();
        throw;
    }
}

std::unique_ptr<PlaintextReader> CloudEngine::openRangedReader(const std::shared_ptr<vh::fs::model::File>& f) const {
    namespace detail = cloud_remote_read_detail;

    if (f->requiresArchiveRestoreForBodyGet())
        throw ContentUnavailable("Remote object is in an archive tier and must be restored first: " + f->path.string());
    if (!s3Provider_) throw std::runtime_error("Cloud engine has no S3 controller");

    const auto self = std::static_pointer_cast<const CloudEngine>(shared_from_this());
    const auto maxGets = RemoteRangedReader::defaultMaxGetRequests(f->size_bytes, rangedLimits_);
    const auto maxBytes = RemoteRangedReader::defaultMaxDownloadedBytes(f->size_bytes, rangedLimits_);

    // Reserve the reader's worst case up front; the actual usage is committed when the reader is destroyed.
    auto reservation = reserveRemoteFetch({
        .path = f->path, .operation = detail::kRangedOperation,
        .head_requests = 1, .get_requests = maxGets, .download_bytes = maxBytes});

    s3::S3RequestBudget headCap;
    headCap.max_head_requests = 1;
    headCap.max_get_requests = 0;
    std::optional<ScopedS3RequestUsageCapture> capture(std::in_place, *this, headCap);
    const auto settleHead = [&] {
        if (!capture) return;
        auto used = capture->usage();
        used.source = detail::kRangedOperation;
        capture.reset();
        if (reservation) reservation->commit(used);
    };

    std::optional<RemoteObjectHead> head;
    try {
        head = headRemoteObject(f->path);
    } catch (const s3::RequestBudgetExceeded& e) {
        settleHead();
        throw ContentUnavailable(fmt::format("S3 request budget refused opening {}: {}", f->path.string(), e.what()));
    } catch (...) {
        settleHead();
        throw;
    }

    try {
        if (!head) throw ContentUnavailable("Remote object not found: " + f->path.string());
        if (head->requires_restore)
            throw ContentUnavailable("Remote object is in an archive tier and must be restored first: " + f->path.string());
        if (head->etag.empty())
            throw ContentUnavailable("Remote object has no ETag to bind ranged reads to: " + f->path.string());
        const uint64_t expected = f->size_bytes + (head->encrypted ? crypto::util::AES_TAG_SIZE : 0);
        if (head->content_length && *head->content_length != expected)
            throw ContentUnavailable(fmt::format("Remote object {} is {} bytes but the index expects {}; sync the vault",
                                                 f->path.string(), *head->content_length, expected));

        RemoteRangedReader::Params params;
        params.engine = self;
        params.controller = s3Provider_;
        params.objectKey = ::vh::fs::model::stripLeadingSlash(f->path);
        params.etag = head->etag;
        params.plaintextSize = f->size_bytes;
        params.limits = rangedLimits_;
        params.generation = generationOf(*f);
        if (vault) params.generation.vault_id = vault->id;
        if (head->encrypted) {
            const auto ivB64 = head->iv_b64.empty() ? f->encryption_iv : head->iv_b64;
            const auto keyVersion = head->iv_b64.empty() ? f->encrypted_with_key_version : head->key_version;
            if (ivB64.empty() || keyVersion == 0)
                throw ContentUnavailable("Remote object has no encryption context: " + f->path.string());
            if (!encryptionManager) throw std::runtime_error("Vault has no encryption key loaded");
            params.iv = detail::decodeIv(ivB64, f->path);
            params.key = encryptionManager->keySnapshot(keyVersion);
            // The remote generation: the object's own IV (local and remote IVs differ after a normal download).
            params.generation.iv_b64 = ivB64;
            params.generation.key_version = keyVersion;
        } else {
            params.generation.iv_b64.clear();
            params.generation.key_version = 0;
        }

        auto headUsage = capture->usage();
        headUsage.source = detail::kRangedOperation;
        capture.reset();
        params.reservation = std::move(reservation);
        params.initialUsage = headUsage;
        return std::make_unique<RemoteRangedReader>(std::move(params));
    } catch (...) {
        if (capture) settleHead();
        else if (reservation) reservation->release();
        throw;
    }
}

}
