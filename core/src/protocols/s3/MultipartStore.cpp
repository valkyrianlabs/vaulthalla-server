#include "protocols/s3/MultipartStore.hpp"

#include "config/Registry.hpp"
#include "db/query/s3/Gateway.hpp"
#include "fs/PlaintextSource.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "protocols/s3/Error.hpp"
#include "protocols/s3/PartCipher.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"

#include <sodium.h>

#include <algorithm>
#include <array>
#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iomanip>
#include <paths.h>
#include <set>
#include <sstream>
#include <system_error>

namespace vh::protocols::s3 {

namespace {
constexpr auto privateDirPerms = std::filesystem::perms::owner_all;

std::string multipartHex(const unsigned char* bytes, const std::size_t n) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < n; ++i)
        out << std::setw(2) << static_cast<unsigned>(bytes[i]);
    return out.str();
}

std::string objectKeyFor(const std::string& key) {
    return ObjectStore::vaultPathToKey(ObjectStore::keyToVaultPath(key));
}

db::query::s3::MultipartUpload requireUploadFor(
    const ResolvedBucket& bucket,
    const std::string& key,
    const std::string& uploadId) {
    const auto upload = db::query::s3::Gateway::getMultipartUpload(uploadId);
    if (!upload || upload->vault_id != bucket.vault_id || upload->object_key != objectKeyFor(key))
        throw noSuchUpload(uploadId);
    return *upload;
}

void ensurePrivateDir(const std::filesystem::path& path) {
    std::error_code ec;
    std::filesystem::create_directories(path, ec);
    if (ec) throw invalidArgument("Unable to create multipart part directory", path.string());
    std::filesystem::permissions(path, privateDirPerms, std::filesystem::perm_options::replace, ec);
    if (ec) throw invalidArgument("Unable to secure multipart part directory", path.string());
}

std::filesystem::path uploadDirFor(const db::query::s3::MultipartUpload& upload) {
    if (upload.parts_dir_id.empty()) throw noSuchUpload(upload.upload_id);
    return MultipartStore::partRoot() / upload.parts_dir_id;
}

std::filesystem::path ensureUploadDirFor(const db::query::s3::MultipartUpload& upload) {
    const auto root = MultipartStore::partRoot();
    ensurePrivateDir(root);
    const auto dir = uploadDirFor(upload);
    ensurePrivateDir(dir);
    return dir;
}

// Every write of a part gets a new file, so a part's file and the IV in its row always change together.
std::filesystem::path newPartPath(const std::filesystem::path& dir, const uint32_t partNumber) {
    std::array<unsigned char, 8> nonce{};
    randombytes_buf(nonce.data(), nonce.size());
    return dir / (std::to_string(partNumber) + "." + multipartHex(nonce.data(), nonce.size()));
}

void removeQuietly(const std::filesystem::path& path) noexcept {
    std::error_code ec;
    std::filesystem::remove(path, ec);
}

const vault::EncryptionManager& keysFor(const std::shared_ptr<storage::Engine>& engine, const uint32_t vaultId) {
    if (!engine || !engine->encryptionManager)
        throw S3Error{"InternalError", "The vault's key is not available for multipart parts",
                      http::status::internal_server_error, std::to_string(vaultId)};
    return *engine->encryptionManager;
}

fs::PlaintextSource memorySource(const std::vector<uint8_t>& bytes) {
    return {.size = bytes.size(), .read = [&bytes](const uint64_t offset, const std::span<uint8_t> out) -> std::size_t {
        if (offset >= bytes.size()) return 0;
        const auto n = static_cast<std::size_t>(std::min<uint64_t>(out.size(), bytes.size() - offset));
        std::memcpy(out.data(), bytes.data() + offset, n);
        return n;
    }};
}

part_cipher::Binding bindingOf(const db::query::s3::MultipartUpload& upload, const uint32_t partNumber) {
    return {.vault_id = upload.vault_id, .upload_id = upload.upload_id, .part_number = partNumber};
}

S3Error invalidPart(const uint32_t partNumber, const std::string& why, const std::string& key) {
    return S3Error{"InvalidPart", "Multipart part " + std::to_string(partNumber) + " " + why + "; upload it again",
                   http::status::bad_request, key};
}

// A part stored as plaintext before #345: sealed (read once, checked against its recorded size and MD5), the row
// switched to the sealed copy, and the plaintext deleted. Returns the row as it is now, or nullopt when the plaintext
// can't be sealed (missing, or it no longer matches its ETag): then it is left exactly as it was.
std::optional<db::query::s3::MultipartPart> sealLegacyPart(const db::query::s3::MultipartUpload& upload,
                                                           const db::query::s3::MultipartPart& part,
                                                           const vault::EncryptionManager& keys) {
    if (part.encryption_iv) return part;
    const auto log = log::Registry::runtime();
    std::error_code ec;
    if (!std::filesystem::is_regular_file(part.path, ec) || std::filesystem::file_size(part.path, ec) != part.size_bytes) {
        log->error("[S3Gateway] Multipart upload {}: plaintext part {} is missing or not its recorded size; left as is",
                   upload.upload_id, part.part_number);
        return std::nullopt;
    }

    const auto sealedPath = newPartPath(part.path.parent_path(), part.part_number);
    const auto sealed = part_cipher::seal(keys, bindingOf(upload, part.part_number), fs::sourceOf(part.path), sealedPath);
    if (sealed.md5 != part.md5 || sealed.size_bytes != part.size_bytes) {
        removeQuietly(sealedPath);
        log->error("[S3Gateway] Multipart upload {}: plaintext part {} no longer matches its ETag; left as is",
                   upload.upload_id, part.part_number);
        return std::nullopt;
    }
    if (!db::query::s3::Gateway::sealLegacyMultipartPart(upload.upload_id, part.part_number, part.path, sealedPath,
                                                          sealed.encryption_iv, sealed.key_version)) {
        removeQuietly(sealedPath);  // re-uploaded or gone meanwhile: the row says what is current
        return db::query::s3::Gateway::getMultipartPart(upload.upload_id, part.part_number);
    }
    removeQuietly(part.path);
    return db::query::s3::Gateway::getMultipartPart(upload.upload_id, part.part_number);
}

void removeUploadFiles(const db::query::s3::MultipartUpload& upload) {
    for (const auto& part : db::query::s3::Gateway::listMultipartParts(upload.upload_id)) removeQuietly(part.path);
    db::query::s3::Gateway::deleteMultipartParts(upload.upload_id);
    std::error_code ec;
    std::filesystem::remove_all(uploadDirFor(upload), ec);
}
}

std::filesystem::path MultipartStore::partRoot() {
    return paths::getS3GatewayMultipartPartsPath();
}

std::string MultipartStore::createUpload(
    const ResolvedBucket& bucket,
    const std::string& key,
    const PutObjectOptions& options) const {
    (void)abortExpiredUploads();

    const auto uploadId = boost::uuids::to_string(boost::uuids::random_generator()());
    const auto partsDirId = boost::uuids::to_string(boost::uuids::random_generator()());
    db::query::s3::Gateway::createMultipartUpload({
        .upload_id = uploadId,
        .parts_dir_id = partsDirId,
        .vault_id = bucket.vault_id,
        .object_key = ObjectStore::vaultPathToKey(ObjectStore::keyToVaultPath(key)),
        .initiated_by = bucket.actor ? bucket.actor->id : 0,
        .content_type = options.content_type,
        .metadata = options.metadata,
        .storage_class = options.storage_class
    });
    return uploadId;
}

db::query::s3::MultipartPart MultipartStore::uploadPart(
    const ResolvedBucket& bucket,
    const std::string& key,
    const std::string& uploadId,
    const uint32_t partNumber,
    const std::vector<uint8_t>& body) const {
    return uploadPartFromSource(bucket, key, uploadId, partNumber, memorySource(body));
}

db::query::s3::MultipartPart MultipartStore::uploadPartFromSource(
    const ResolvedBucket& bucket,
    const std::string& key,
    const std::string& uploadId,
    const uint32_t partNumber,
    const fs::PlaintextSource& body) const {
    if (partNumber == 0 || partNumber > 10000)
        throw invalidArgument("Part number must be between 1 and 10000");
    const auto upload = requireUploadFor(bucket, key, uploadId);
    const auto& keys = keysFor(bucket.engine, bucket.vault_id);

    const auto path = newPartPath(ensureUploadDirFor(upload), partNumber);
    const auto sealed = part_cipher::seal(keys, bindingOf(upload, partNumber), body, path);

    const db::query::s3::MultipartPart part{
        .upload_id = uploadId,
        .part_number = partNumber,
        .etag = "\"" + multipartHex(sealed.md5.data(), sealed.md5.size()) + "\"",
        .size_bytes = sealed.size_bytes,
        .md5 = sealed.md5,
        .path = path,
        .created_at = std::time(nullptr),
        .encryption_iv = sealed.encryption_iv,
        .key_version = sealed.key_version
    };
    std::optional<std::filesystem::path> previous;
    try {
        previous = db::query::s3::Gateway::upsertMultipartPart(part);
    } catch (...) {
        removeQuietly(path);
        throw;
    }
    if (previous && *previous != path) removeQuietly(*previous);
    return *db::query::s3::Gateway::getMultipartPart(uploadId, partNumber);
}

db::query::s3::ObjectState MultipartStore::completeUpload(
    const ResolvedBucket& bucket,
    const std::string& key,
    const std::string& uploadId,
    const std::vector<std::pair<uint32_t, std::string>>& requestedParts) const {
    const auto upload = requireUploadFor(bucket, key, uploadId);
    auto parts = db::query::s3::Gateway::listMultipartParts(uploadId);
    if (parts.empty()) throw invalidArgument("Multipart upload has no parts", key);

    const auto useRequested = !requestedParts.empty();
    if (useRequested) {
        parts.clear();
        uint32_t previousPartNumber = 0;
        for (const auto& [partNumber, etag] : requestedParts) {
            if (partNumber <= previousPartNumber)
                throw S3Error{"InvalidPartOrder", "Multipart parts must be listed in ascending order",
                              http::status::bad_request, key};
            previousPartNumber = partNumber;

            auto part = db::query::s3::Gateway::getMultipartPart(uploadId, partNumber);
            if (!part) throw invalidArgument("Missing multipart part " + std::to_string(partNumber), key);
            if (!etag.empty() && part->etag != etag && part->etag != "\"" + etag + "\"")
                throw invalidArgument("Multipart part ETag mismatch", key);
            parts.push_back(*part);
        }
    }

    const auto minPartSize = static_cast<uint64_t>(config::Registry::get().s3_gateway.multipart.min_part_size_mb) *
                             1024ull * 1024ull;
    for (std::size_t i = 0; i + 1 < parts.size(); ++i) {
        if (parts[i].size_bytes < minPartSize)
            throw S3Error{"EntityTooSmall", "Multipart parts must be at least the configured minimum size",
                          http::status::bad_request, key};
    }

    const auto& keys = keysFor(bucket.engine, bucket.vault_id);
    std::vector<part_cipher::Stored> stored;
    std::vector<std::vector<uint8_t>> partMd5s;
    stored.reserve(parts.size());
    partMd5s.reserve(parts.size());
    for (auto& part : parts) {
        if (!part.encryption_iv) {
            const auto now = sealLegacyPart(upload, part, keys);
            if (!now || !now->encryption_iv) throw invalidPart(part.part_number, "is unreadable", key);
            part = *now;
        }
        stored.push_back({.binding = bindingOf(upload, part.part_number), .path = part.path,
                          .encryption_iv = *part.encryption_iv, .key_version = part.key_version.value_or(0),
                          .size_bytes = part.size_bytes});
        partMd5s.push_back(part.md5);
    }

    const auto failed = [&](const std::exception& e, const uint32_t partNumber) {
        log::Registry::runtime()->error("[S3Gateway] Multipart upload {} of vault {}: {}", uploadId, bucket.vault_id,
                                        e.what());
        return invalidPart(partNumber, "failed its integrity check", key);
    };

    PutObjectOptions options{
        .content_type = upload.content_type.value_or("application/octet-stream"),
        .storage_class = upload.storage_class,
        .metadata = upload.metadata,
        .multipart = true,
        .part_count = static_cast<uint32_t>(parts.size()),
        .etag_override = ObjectStore::multipartEtag(partMd5s)
    };

    // The parts are authenticated before anything is written (open), and again as the vault seals them: a part that
    // fails either way leaves the object untouched and the upload open, so the client can upload that part again.
    db::query::s3::ObjectState state;
    try {
        const auto source = part_cipher::open(keys, stored);
        state = objects_.putObjectFromSource(bucket, key, source, options);
    } catch (const part_cipher::Tampered& e) {
        throw failed(e, e.partNumber());
    } catch (const vault::KeyVersionUnavailable& e) {
        throw failed(e, 0);
    }

    db::query::s3::Gateway::markMultipartUploadCompleted(uploadId);
    removeUploadFiles(upload);
    return state;
}

void MultipartStore::abortUpload(const ResolvedBucket& bucket, const std::string& key, const std::string& uploadId) const {
    const auto upload = requireUploadFor(bucket, key, uploadId);
    removeUploadFiles(upload);
    db::query::s3::Gateway::abortMultipartUpload(uploadId);
}

std::size_t MultipartStore::abortExpiredUploads() const {
    const auto days = config::Registry::get().s3_gateway.multipart.abort_after_days;
    const auto cutoff = std::time(nullptr) - static_cast<std::time_t>(days) * 24 * 60 * 60;
    const auto uploads = db::query::s3::Gateway::listMultipartUploadsInitiatedBefore(cutoff);

    std::size_t aborted = 0;
    for (const auto& upload : uploads) {
        removeUploadFiles(upload);
        db::query::s3::Gateway::abortMultipartUpload(upload.upload_id);
        ++aborted;
    }
    return aborted;
}

std::vector<db::query::s3::MultipartUpload> MultipartStore::listUploads(
    const ResolvedBucket& bucket,
    const std::string& prefix) const {
    (void)abortExpiredUploads();
    return db::query::s3::Gateway::listMultipartUploads(bucket.vault_id, prefix);
}

std::vector<db::query::s3::MultipartPart> MultipartStore::listParts(
    const ResolvedBucket& bucket,
    const std::string& key,
    const std::string& uploadId) const {
    (void)requireUploadFor(bucket, key, uploadId);
    return db::query::s3::Gateway::listMultipartParts(uploadId);
}

MultipartStore::Sweep MultipartStore::sweepAtStartup() const {
    Sweep out;
    const auto root = partRoot();
    std::error_code ec;
    if (!std::filesystem::is_directory(root, ec)) return out;

    const auto log = log::Registry::runtime();
    const auto uploads = db::query::s3::Gateway::listOpenMultipartUploads();  // throws: then nothing is removed
    const auto storage = runtime::Deps::get().storageManager;

    std::set<std::string> openDirs;
    for (const auto& upload : uploads) {
        if (upload.parts_dir_id.empty()) continue;
        openDirs.insert(upload.parts_dir_id);
        auto parts = db::query::s3::Gateway::listMultipartParts(upload.upload_id);

        const auto legacy = std::ranges::count_if(parts, [](const auto& p) { return !p.encryption_iv; });
        if (legacy > 0) {
            std::shared_ptr<storage::Engine> engine;
            try {
                if (storage) engine = storage->getEngine(upload.vault_id);
            } catch (const std::exception&) {
            }
            if (!engine || !engine->encryptionManager) {
                log->warn("[S3Gateway] Multipart upload {}: {} plaintext part(s) not sealed yet (vault {} is not "
                          "loaded); retried at the next start and on CompleteMultipartUpload",
                          upload.upload_id, legacy, upload.vault_id);
                out.unconvertible += static_cast<std::size_t>(legacy);
            } else {
                for (auto& part : parts) {
                    if (part.encryption_iv) continue;
                    try {
                        if (const auto now = sealLegacyPart(upload, part, *engine->encryptionManager);
                            now && now->encryption_iv) {
                            part = *now;
                            ++out.sealed;
                            continue;
                        }
                    } catch (const std::exception& e) {
                        log->error("[S3Gateway] Multipart upload {}: sealing plaintext part {} failed: {}",
                                   upload.upload_id, part.part_number, e.what());
                    }
                    ++out.unconvertible;
                }
            }
        }

        // What no row points at: a crashed Complete's plaintext concatenation (.complete-object, before #345), a write
        // that never reached its row, a superseded copy.
        std::set<std::filesystem::path> referenced;
        for (const auto& part : db::query::s3::Gateway::listMultipartParts(upload.upload_id))
            referenced.insert(part.path.lexically_normal());
        const auto dir = uploadDirFor(upload);
        if (!std::filesystem::is_directory(dir, ec)) continue;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            if (referenced.contains(entry.path().lexically_normal())) continue;
            std::error_code rm;
            std::filesystem::remove_all(entry.path(), rm);
            if (!rm) ++out.strays;
        }
    }

    for (const auto& entry : std::filesystem::directory_iterator(root, ec)) {
        if (openDirs.contains(entry.path().filename().string())) continue;
        std::error_code rm;
        std::filesystem::remove_all(entry.path(), rm);
        if (!rm) ++out.orphanDirs;
    }

    if (out.sealed || out.unconvertible || out.strays || out.orphanDirs)
        log->info("[S3Gateway] Multipart part store: {} plaintext part(s) sealed, {} left as they are, {} stray "
                  "file(s) and {} finished upload director(ies) removed",
                  out.sealed, out.unconvertible, out.strays, out.orphanDirs);
    return out;
}

} // namespace vh::protocols::s3
