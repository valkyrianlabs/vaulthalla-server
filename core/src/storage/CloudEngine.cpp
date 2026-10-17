#include "storage/CloudEngine.hpp"
#include "vault/EncryptionManager.hpp"
#include "storage/s3/Controller.hpp"
#include "fs/model/Entry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/file/Trashed.hpp"
#include "fs/model/Directory.hpp"
#include "vault/model/S3Vault.hpp"
#include "fs/model/Path.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Directory.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/ops/file.hpp"
#include "preview/render/Service.hpp"
#include "log/Registry.hpp"
#include "concurrency/ThreadPoolManager.hpp"
#include "concurrency/ThreadPool.hpp"
#include "fs/Filesystem.hpp"
#include "runtime/Deps.hpp"
#include "vault/APIKeyManager.hpp"
#include "config/Registry.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/RemoteManifest.hpp"
#include "sync/model/Event.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "identities/Manager.hpp"
#include "db/query/upstream/WriteIntent.hpp"
#include "sync/events/Subscriptions.hpp"
#include "recovery/local/Versions.hpp"
#include "db/Transactions.hpp"

#include <algorithm>
#include <cctype>
#include <ctime>

using namespace vh::fs;
using namespace vh::fs::model;
using namespace vh::storage;
using namespace vh::vault;
using namespace vh::concurrency;
using namespace vh::config;
using namespace vh::sync::model;
using namespace vh::fs::ops;

static constexpr std::string_view META_VH_ENCRYPTED_FLAG = "vh-encrypted";
static constexpr std::string_view META_VH_IV_FLAG = "vh-iv";
static constexpr std::string_view META_VH_KEY_VERSION_FLAG = "vh-key-version";
static constexpr std::string_view META_CONTENT_HASH_FLAG = "content-hash";
static constexpr std::string_view META_VH_ENCRYPTED = "x-amz-meta-vh-encrypted";
static constexpr std::string_view META_VH_IV = "x-amz-meta-vh-iv";
static constexpr std::string_view META_VH_KEY_VERSION = "x-amz-meta-vh-key-version";
static constexpr std::string_view META_CONTENT_HASH = "x-amz-meta-content-hash";

namespace {
    constexpr int REMOTE_MANIFEST_PUBLISH_MAX_ATTEMPTS = 3;

    std::optional<std::string> header_value(
        const std::unordered_map<std::string, std::string>& headers,
        const std::string_view name) {
        auto target = std::string(name);
        std::ranges::transform(target, target.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });

        for (const auto& [key, value] : headers) {
            auto normalized = key;
            std::ranges::transform(normalized, normalized.begin(), [](unsigned char c) {
                return static_cast<char>(std::tolower(c));
            });
            if (normalized == target) return value;
        }

        return std::nullopt;
    }

    bool contains_case_insensitive(std::string haystack, std::string needle) {
        std::ranges::transform(haystack, haystack.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        std::ranges::transform(needle, needle.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        return haystack.find(needle) != std::string::npos;
    }

    std::optional<bool> parse_encrypted_flag(std::string value) {
        std::ranges::transform(value, value.begin(), [](unsigned char c) {
            return static_cast<char>(std::tolower(c));
        });
        if (value == "true" || value == "1") return true;
        if (value == "false" || value == "0") return false;
        return std::nullopt;
    }

    std::optional<std::pair<std::string, unsigned int>> encryption_payload_from_file(
        const std::shared_ptr<File>& file,
        const bool trustFileEncryptionMetadata) {
        if (!trustFileEncryptionMetadata || !file) return std::nullopt;
        if (file->encryption_iv.empty() || file->encrypted_with_key_version == 0) return std::nullopt;
        return std::make_pair(file->encryption_iv, file->encrypted_with_key_version);
    }

    std::optional<std::pair<std::string, unsigned int>> encryption_payload_from_headers(
        const std::unordered_map<std::string, std::string>& headers) {
        std::string iv_b64;
        unsigned int key_version = 0;
        if (const auto iv = header_value(headers, META_VH_IV)) iv_b64 = *iv;
        if (const auto version = header_value(headers, META_VH_KEY_VERSION))
            key_version = std::stoul(*version);
        if (iv_b64.empty() || key_version == 0) return std::nullopt;
        return std::make_pair(iv_b64, key_version);
    }

    fs::path resolvedBackingPath(const CloudEngine& engine, const std::shared_ptr<File>& file) {
        if (!file) throw std::invalid_argument("[CloudStorageEngine] Invalid file");
        if (file->backing_path.is_absolute()) return file->backing_path;
        if (!engine.paths) return file->backing_path;
        return engine.paths->absPath(file->backing_path, PathType::BACKING_ROOT);
    }
}

std::unordered_map<std::string, std::string> CloudEngine::getMetaMapFromFile(const std::shared_ptr<File>& f) const {
    std::unordered_map<std::string, std::string> meta;
    const auto encrypt = s3Vault()->encrypt_upstream;
    meta[std::string(META_VH_ENCRYPTED_FLAG)] = encrypt ? "true" : "false";
    if (f->content_hash) meta[std::string(META_CONTENT_HASH_FLAG)] = *f->content_hash;
    if (encrypt) {
        if (f->encryption_iv.empty() || f->encrypted_with_key_version == 0)
            throw std::runtime_error("[CloudStorageEngine] Missing encryption metadata for upload: " + f->path.string());
        meta[std::string(META_VH_KEY_VERSION_FLAG)] = std::to_string(f->encrypted_with_key_version);
        meta[std::string(META_VH_IV_FLAG)] = f->encryption_iv;
    }

    return meta;
}

CloudEngine::CloudEngine(const std::shared_ptr<vh::vault::model::S3Vault>& vault)
    : Engine(vault),
      key_(runtime::Deps::get().apiKeyManager->getAPIKey(vault->api_key_id)),
      s3Provider_(std::make_shared<s3::Controller>(key_, vault->bucket)) {
    resolveS3ProviderConfiguration();
    s3Provider_->setUsageVault(vault->id);   // feeds the vault's local usage ledger (recovery cost estimates)
}

CloudEngine::CloudEngine(const std::shared_ptr<vh::vault::model::S3Vault>& vault, std::shared_ptr<s3::Controller> s3Provider)
    : Engine(vault),
      key_(runtime::Deps::get().apiKeyManager->getAPIKey(vault->api_key_id)),
      s3Provider_(std::move(s3Provider)) {
    resolveS3ProviderConfiguration();
    if (s3Provider_ && vault) s3Provider_->setUsageVault(vault->id);
}

void CloudEngine::upload(const std::shared_ptr<File>& f) const {
    const auto backingPath = resolvedBackingPath(*this, f);
    if (!fs::exists(backingPath) || !fs::is_regular_file(backingPath))
        throw std::runtime_error("[CloudStorageEngine] Invalid file: " + f->path.string());

    const fs::path s3Key = stripLeadingSlash(f->path);
    const auto backingSize = fs::file_size(backingPath);

    if (!s3Vault()->encrypt_upstream) {
        const auto ciphertext = readFileToVector(backingPath);
        if (ciphertext.empty()) {
            auto options = requestOptionsFor(s3::provider::RequestOperation::PutObject);
            options.metadata = getMetaMapFromFile(f);
            auto own = noteOwnWrite(s3Key, false, 0, f);
            s3Provider_->uploadBufferWithMetadata(s3Key, {}, options);
            own.done();
            return;
        }
        upload(f, ciphertext);
        return;
    }

    if (backingSize == 0) {
        if (!encryptionManager)
            throw std::runtime_error("[CloudStorageEngine] Encryption manager unavailable for empty encrypted upload");
        const auto ciphertext = encryptionManager->encrypt({}, f);
        auto options = requestOptionsFor(s3::provider::RequestOperation::PutObject);
        options.metadata = getMetaMapFromFile(f);
        auto own = noteOwnWrite(s3Key, false, ciphertext.size(), f);
        s3Provider_->uploadBufferWithMetadata(s3Key, ciphertext, options);
        own.done();
        return;
    }

    if (!f->content_hash) f->content_hash = db::query::fs::File::getContentHash(vault->id, f->path);
    const auto meta = getMetaMapFromFile(f);
    auto options = requestOptionsFor(s3::provider::RequestOperation::PutObject);
    options.metadata = meta;
    auto own = noteOwnWrite(s3Key, false, backingSize, f);

    if (backingSize < s3::Controller::MIN_PART_SIZE)
        s3Provider_->uploadObjectWithMetadata(s3Key, backingPath, options);
    else {
        auto multipartOptions = requestOptionsFor(s3::provider::RequestOperation::CreateMultipartUpload);
        multipartOptions.metadata = meta;
        s3Provider_->uploadLargeObject(
            s3Key,
            backingPath,
            s3::Controller::MIN_PART_SIZE,
            multipartOptions);
    }
    own.done();
}

void CloudEngine::upload(const std::shared_ptr<File>& f, const std::vector<uint8_t>& buffer, const bool isCiphertext) const {
    if (buffer.empty()) throw std::invalid_argument("[CloudStorageEngine] Buffer for upload cannot be empty");
    if (!f) throw std::invalid_argument("[CloudStorageEngine] Invalid file or buffer for upload");

    if (!s3Vault()->encrypt_upstream) {
        const auto plaintext = isCiphertext ? decrypt(f, buffer) : buffer;
        auto options = requestOptionsFor(s3::provider::RequestOperation::PutObject);
        options.metadata = getMetaMapFromFile(f);
        auto own = noteOwnWrite(stripLeadingSlash(f->path), false, plaintext.size(), f);
        s3Provider_->uploadBufferWithMetadata(stripLeadingSlash(f->path), plaintext, options);
        own.done();
        return;
    }

    const auto s3Key = stripLeadingSlash(f->path);
    const auto meta = getMetaMapFromFile(f);
    auto options = requestOptionsFor(s3::provider::RequestOperation::PutObject);
    options.metadata = meta;
    auto own = noteOwnWrite(s3Key, false, buffer.size(), f);

    if (buffer.size() < s3::Controller::MIN_PART_SIZE) s3Provider_->uploadBufferWithMetadata(s3Key, buffer, options);
    else {
        auto multipartOptions = requestOptionsFor(s3::provider::RequestOperation::CreateMultipartUpload);
        multipartOptions.metadata = meta;
        s3Provider_->uploadLargeObject(
            s3Key,
            buffer,
            s3::Controller::MIN_PART_SIZE,
            multipartOptions);
    }
    own.done();
}

std::shared_ptr<File> CloudEngine::uploadBufferObject(
    const fs::path& rel_path,
    const std::vector<uint8_t>& plaintext,
    std::optional<std::string> contentHash) const {
    auto file = std::make_shared<File>();
    file->vault_id = vault ? vault->id : 0;
    file->path = makeAbsolute(rel_path);
    file->name = file->path.filename();
    file->size_bytes = plaintext.size();
    file->content_hash = std::move(contentHash);
    file->created_at = file->updated_at = std::time(nullptr);
    file->remote_storage_class = configuredStorageClass();

    std::vector<uint8_t> payload;
    if (s3Vault()->encrypt_upstream) {
        if (!encryptionManager)
            throw std::runtime_error("[CloudStorageEngine] Encryption manager unavailable for buffer upload");
        payload = encryptionManager->encrypt(plaintext, file);
        file->remote_encrypted = true;
    } else {
        payload = plaintext;
        file->remote_encrypted = false;
        file->encryption_iv.clear();
        file->encrypted_with_key_version = 0;
    }

    const auto s3Key = stripLeadingSlash(file->path);
    auto options = requestOptionsFor(s3::provider::RequestOperation::PutObject);
    options.metadata = getMetaMapFromFile(file);
    auto own = noteOwnWrite(s3Key, false, payload.size());

    if (payload.size() < s3::Controller::MIN_PART_SIZE) {
        s3Provider_->uploadBufferWithMetadata(s3Key, payload, options);
    } else {
        auto multipartOptions = requestOptionsFor(s3::provider::RequestOperation::CreateMultipartUpload);
        multipartOptions.metadata = options.metadata;
        s3Provider_->uploadLargeObject(
            s3Key,
            payload,
            s3::Controller::MIN_PART_SIZE,
            multipartOptions);
    }
    own.done();

    return file;
}

std::vector<uint8_t> CloudEngine::downloadToBuffer(const fs::path& rel_path) const {
    std::vector<uint8_t> buffer;
    s3Provider_->downloadToBuffer(stripLeadingSlash(rel_path), buffer);
    return buffer;
}

std::vector<uint8_t> CloudEngine::decryptRemotePayload(
    const fs::path& rel_path,
    const std::vector<uint8_t>& payload,
    const std::shared_ptr<File>& remoteFile) const {
    return decryptRemotePayload(rel_path, payload, remoteFile, RemoteEncryptionResolveOptions{});
}

std::vector<uint8_t> CloudEngine::decryptRemotePayload(
    const fs::path& rel_path,
    const std::vector<uint8_t>& payload,
    const std::shared_ptr<File>& remoteFile,
    const RemoteEncryptionResolveOptions options) const {
    const auto context = resolveRemoteEncryptionContext(rel_path, remoteFile, options);
    if (!context.encrypted) return payload;
    if (!context.payload)
        throw std::runtime_error("[CloudStorageEngine] No IV found for encrypted file: " + rel_path.string());

    const auto& [iv_b64, key_version] = *context.payload;
    return encryptionManager->decrypt(payload, iv_b64, key_version);
}

std::shared_ptr<File> CloudEngine::downloadFile(const fs::path& rel_path) {
    return downloadFileWithRemoteMetadata(rel_path, nullptr);
}

std::shared_ptr<File> CloudEngine::downloadFile(const std::shared_ptr<File>& remoteFile) {
    if (!remoteFile) throw std::invalid_argument("[CloudStorageEngine] Cannot download null remote file");
    return downloadFileWithRemoteMetadata(remoteFile->path, remoteFile);
}

std::shared_ptr<File> CloudEngine::downloadFileWithRemoteMetadata(
    const fs::path& rel_path,
    const std::shared_ptr<File>& remoteFile) {
    auto buffer = downloadToBuffer(rel_path);

    buffer = decryptRemotePayload(
        rel_path,
        buffer,
        remoteFile,
        remoteFile
            ? RemoteEncryptionResolveOptions{true, true}
            : RemoteEncryptionResolveOptions{});

    const auto owner = vh::identities::manager().user(vault->owner_id);
    if (!owner) throw std::runtime_error("[CloudStorageEngine] Vault owner not found for file creation");

    const auto f = Filesystem::createFile({
            .path = makeAbsolute(rel_path),
            .fuse_path = vaultPathToFusePath(makeAbsolute(rel_path)),
            .buffer = buffer,
            .engine = shared_from_this(),
            .user = owner,
            .overwrite = true
        });

    preview::render::enqueueThumbnails(shared_from_this(), f, buffer);

    return f;
}

std::shared_ptr<File> CloudEngine::indexAndDeleteFile(const std::shared_ptr<File>& remoteFile) {
    if (!remoteFile) throw std::invalid_argument("[CloudStorageEngine] Cannot index null remote file");

    const auto owner = vh::identities::manager().user(vault->owner_id);
    if (!owner) throw std::runtime_error("[CloudStorageEngine] Vault owner not found for metadata-only indexing");

    const auto rel_path = makeAbsolute(remoteFile->path);
    auto indexed = db::query::fs::File::getFileByPath(vault->id, rel_path);
    // The local copy this download replaces (cache strategy: index-only), when it holds other content.
    std::optional<File> replaced;
    if (indexed && !(remoteFile->encryption_iv == indexed->encryption_iv &&
                     remoteFile->encrypted_with_key_version == indexed->encrypted_with_key_version))
        replaced = *indexed;

    if (!indexed) {
        indexed = Filesystem::createFile({
            .path = rel_path,
            .fuse_path = vaultPathToFusePath(rel_path),
            .buffer = {},
            .engine = shared_from_this(),
            .user = owner,
            .overwrite = true
        });
    }

    indexed->size_bytes = remoteFile->size_bytes;
    indexed->content_hash = remoteFile->content_hash;
    indexed->remote_encrypted = remoteFile->remote_encrypted;
    if (!remoteFile->encryption_iv.empty())
        indexed->encryption_iv = remoteFile->encryption_iv;
    if (remoteFile->encrypted_with_key_version > 0)
        indexed->encrypted_with_key_version = remoteFile->encrypted_with_key_version;
    indexed->updated_at = remoteFile->updated_at;
    indexed->last_modified_by = vault->owner_id;
    auto kept = replaced ? vh::recovery::local::versions::retain(*this, *replaced, vh::recovery::local::Reason::Download)
                         : vh::recovery::local::versions::Pending{};
    vh::db::Transactions::exec("CloudEngine::indexAndDeleteFile", [&](pqxx::work& txn) {
        kept.attach(txn);
        db::query::fs::File::updateFile(txn, indexed);
    });
    kept.committed();

    if (!indexed->backing_path.empty() && fs::exists(indexed->backing_path))
        fs::remove(indexed->backing_path);
    return indexed;
}

std::unordered_map<std::u8string, std::shared_ptr<File>>
CloudEngine::getGroupedFilesFromS3(const fs::path& prefix) const {
    return groupEntriesByPath(filesFromS3XML(s3Provider_->listObjects(prefix)));
}

bool CloudEngine::refreshRemoteIndexFromManifestIfChanged() const {
    const std::string manifestKey = remote_manifest::INDEX_V1_KEY;
    const auto head = s3Provider_->getHeadObject(manifestKey);
    if (!head) return false;

    const auto remoteEtag = header_value(*head, "ETag");
    const auto localEtag = db::query::sync::RemoteObjectIndex::getManifestETag(vault->id, manifestKey);
    if (remoteEtag && localEtag && *remoteEtag == *localEtag &&
        db::query::sync::RemoteObjectIndex::countForVault(vault->id) > 0) {
        db::query::sync::RemoteObjectIndex::upsertManifestETag(vault->id, manifestKey, remoteEtag);
        return true;
    }

    std::vector<uint8_t> buffer;
    s3Provider_->downloadToBuffer(manifestKey, buffer);
    const std::string manifest(buffer.begin(), buffer.end());
    const auto metadata = remote_manifest::inspectIndexV1Metadata(manifest, vault->id);
    const auto files = remote_manifest::parseIndexV1(manifest, vault->id);
    db::query::sync::RemoteObjectIndex::replaceFromManifest(vault->id, files);
    db::query::sync::RemoteObjectIndex::upsertManifestState(
        vault->id,
        manifestKey,
        remoteEtag,
        metadata.generated_at == 0 ? std::optional<std::time_t>{} : std::make_optional(metadata.generated_at),
        metadata.object_count,
        metadata.object_checksum);
    return true;
}

void CloudEngine::publishRemoteIndexManifest(const std::optional<std::string>& expectedETag) const {
    const auto files = db::query::sync::RemoteObjectIndex::listFilesForVault(vault->id);
    const auto manifest = remote_manifest::buildIndexV1(vault->id, files);
    const auto metadata = remote_manifest::inspectIndexV1Metadata(manifest, vault->id);
    const std::vector<uint8_t> payload(manifest.begin(), manifest.end());

    const auto ifMatch = expectedETag;
    const auto ifNoneMatch = ifMatch
        ? std::optional<std::string>{}
        : std::make_optional<std::string>("*");

    auto options = requestOptionsFor(s3::provider::RequestOperation::PutObject);
    options.metadata = {{"vh-manifest-version", std::to_string(remote_manifest::INDEX_V1_VERSION)}};

    s3Provider_->uploadBufferWithMetadataConditional(
        remote_manifest::INDEX_V1_KEY,
        payload,
        options,
        ifMatch,
        ifNoneMatch);

    const auto head = s3Provider_->getHeadObject(remote_manifest::INDEX_V1_KEY);
    db::query::sync::RemoteObjectIndex::upsertManifestState(
        vault->id,
        remote_manifest::INDEX_V1_KEY,
        head ? header_value(*head, "ETag") : std::nullopt,
        metadata.generated_at == 0 ? std::optional<std::time_t>{} : std::make_optional(metadata.generated_at),
        metadata.object_count,
        metadata.object_checksum);
}

void CloudEngine::publishRemoteIndexManifestWithRetry() const {
    std::string lastConflict;
    auto expectedETag = db::query::sync::RemoteObjectIndex::getManifestETag(
        vault->id,
        remote_manifest::INDEX_V1_KEY);

    for (int attempt = 1; attempt <= REMOTE_MANIFEST_PUBLISH_MAX_ATTEMPTS; ++attempt) {
        try {
            publishRemoteIndexManifest(expectedETag);
            return;
        } catch (const s3::ConditionalRequestFailed& e) {
            lastConflict = e.what();
            log::Registry::cloud()->warn(
                "[CloudStorageEngine] Remote index manifest publish conflict for vault {}; refreshing ETag before retry {}/{}",
                vault->id,
                attempt,
                REMOTE_MANIFEST_PUBLISH_MAX_ATTEMPTS);

            const auto head = s3Provider_->getHeadObject(remote_manifest::INDEX_V1_KEY);
            expectedETag = head ? header_value(*head, "ETag") : std::nullopt;
            db::query::sync::RemoteObjectIndex::upsertManifestETag(
                vault->id,
                remote_manifest::INDEX_V1_KEY,
                expectedETag);
        }
    }

    throw std::runtime_error(
        "remote index manifest publish conflict after " +
        std::to_string(REMOTE_MANIFEST_PUBLISH_MAX_ATTEMPTS) +
        " attempts" +
        (lastConflict.empty() ? std::string{} : ": " + lastConflict));
}

void CloudEngine::applyRemoteIndexMutation(const std::vector<Action>& plan) const {
    const auto replayMutation = [&]() {
        bool mutated = false;

        for (const auto& action : plan) {
            switch (action.type) {
            case ActionType::Upload:
                if (action.local) {
                    auto indexed = std::make_shared<File>(*action.local);
                    if (s3Vault()->encrypt_upstream) {
                        indexed->remote_encrypted = true;
                    } else {
                        indexed->remote_encrypted = false;
                        indexed->encryption_iv.clear();
                        indexed->encrypted_with_key_version = 0;
                    }
                    indexed->remote_storage_class = configuredStorageClass();
                    db::query::sync::RemoteObjectIndex::upsertFile(vault->id, indexed);
                    mutated = true;
                }
                break;
            case ActionType::DeleteRemote:
                if (action.remote) {
                    db::query::sync::RemoteObjectIndex::deleteKey(vault->id, action.remote->path);
                    mutated = true;
                }
                break;
            default:
                break;
            }
        }

        return mutated;
    };

    std::string lastConflict;
    auto expectedETag = db::query::sync::RemoteObjectIndex::getManifestETag(
        vault->id,
        remote_manifest::INDEX_V1_KEY);
    if (!expectedETag) {
        (void)refreshRemoteIndexFromManifestIfChanged();
        expectedETag = db::query::sync::RemoteObjectIndex::getManifestETag(
            vault->id,
            remote_manifest::INDEX_V1_KEY);
    }

    if (!replayMutation()) return;

    for (int attempt = 1; attempt <= REMOTE_MANIFEST_PUBLISH_MAX_ATTEMPTS; ++attempt) {
        if (attempt > 1) {
            log::Registry::cloud()->warn(
                "[CloudStorageEngine] Remote index manifest publish conflict for vault {}; reloading manifest before retry {}/{}",
                vault->id,
                attempt,
                REMOTE_MANIFEST_PUBLISH_MAX_ATTEMPTS);
            (void)refreshRemoteIndexFromManifestIfChanged();
            expectedETag = db::query::sync::RemoteObjectIndex::getManifestETag(
                vault->id,
                remote_manifest::INDEX_V1_KEY);
            replayMutation();
        }

        try {
            publishRemoteIndexManifest(expectedETag);
            return;
        } catch (const s3::ConditionalRequestFailed& e) {
            lastConflict = e.what();
        }
    }

    throw SyncStalled(
        "remote index manifest update conflict after " +
        std::to_string(REMOTE_MANIFEST_PUBLISH_MAX_ATTEMPTS) +
        " attempts" +
        (lastConflict.empty() ? std::string{} : ": " + lastConflict));
}

bool CloudEngine::selectedDownloadRequiresRestore(const std::shared_ptr<File>& remoteFile) const {
    if (!remoteFile) return false;
    if (remoteFile->requiresArchiveRestoreForBodyGet()) return true;

    if (!remoteFile->remote_storage_class) return false;
    auto storageClass = *remoteFile->remote_storage_class;
    std::ranges::transform(storageClass, storageClass.begin(), [](unsigned char c) {
        return static_cast<char>(std::toupper(c));
    });
    if (storageClass != "INTELLIGENT_TIERING")
        return false;

    const auto head = s3Provider_->getHeadObject(stripLeadingSlash(remoteFile->path));
    if (!head) return true;

    if (const auto archiveStatus = header_value(*head, "x-amz-archive-status");
        archiveStatus && !archiveStatus->empty())
        return true;

    if (const auto restore = header_value(*head, "x-amz-restore");
        restore && contains_case_insensitive(*restore, "ongoing-request=\"true\""))
        return true;

    return false;
}

std::string CloudEngine::getRemoteContentHash(const fs::path& rel_path) const {
    if (const auto head = s3Provider_->getHeadObject(stripLeadingSlash(rel_path)))
        if (const auto hash = header_value(*head, META_CONTENT_HASH)) return *hash;
    return "";
}

bool CloudEngine::remoteFileIsEncrypted(const fs::path& rel_path) const {
    return resolveRemoteEncryptionContext(rel_path, nullptr, RemoteEncryptionResolveOptions{}).encrypted;
}

std::vector<std::shared_ptr<Directory>> CloudEngine::extractDirectories(
    const std::vector<std::shared_ptr<File>>& files) const {

    std::unordered_map<std::u8string, std::shared_ptr<Directory>> directories;

    for (const auto& file : files) {
        fs::path current = "/";

        for (const auto& part : file->path.parent_path()) {
            current /= part;

            if (!directories.contains(current.u8string())) {
                const auto dir = std::make_shared<Directory>();
                dir->path = current;
                dir->name = current.filename().string();
                dir->created_by = dir->last_modified_by = vault->owner_id;
                dir->vault_id = vault->id;
                const auto parent_path = current.has_parent_path() ? current.parent_path() : "/";
                dir->parent_id = db::query::fs::Directory::getDirectoryIdByPath(vault->id, parent_path);

                directories[current.u8string()] = dir;
            }
        }
    }

    std::vector<std::shared_ptr<Directory>> result;
    for (const auto& [_, dir] : directories)
        result.push_back(dir);

    std::ranges::sort(result, [](const auto& a, const auto& b) {
        return std::distance(a->path.begin(), a->path.end()) < std::distance(b->path.begin(), b->path.end());
    });

    return result;
}

std::optional<std::pair<std::string, unsigned int>> CloudEngine::getRemoteIVBase64AndVersion(const fs::path& rel_path) const {
    const auto context = resolveRemoteEncryptionContext(rel_path, nullptr, RemoteEncryptionResolveOptions{});
    if (!context.payload) {
        log::Registry::cloud()->error("[CloudStorageEngine] No IV or key version found for encrypted file: {}", rel_path.string());
        return std::nullopt;
    }

    return context.payload;
}

CloudEngine::RemoteEncryptionContext CloudEngine::resolveRemoteEncryptionContext(
    const fs::path& rel_path,
    const std::shared_ptr<File>& remoteFile,
    const RemoteEncryptionResolveOptions options) const {
    const auto filePayload = encryption_payload_from_file(remoteFile, options.trust_file_encryption_metadata);

    bool headLoaded = false;
    std::optional<std::unordered_map<std::string, std::string>> head;
    const auto loadHead = [&]() -> const std::optional<std::unordered_map<std::string, std::string>>& {
        if (!headLoaded) {
            head = s3Provider_->getHeadObject(stripLeadingSlash(rel_path));
            headLoaded = true;
        }
        return head;
    };

    const auto localPayload = [&]() -> std::optional<std::pair<std::string, unsigned int>> {
        if (!options.allow_local_db_recovery) return std::nullopt;
        return db::query::fs::File::getEncryptionIVAndVersion(vault->id, rel_path);
    };

    // Whether this vault may take an object that says (or shows) it is plaintext as this file's content. A vault that
    // doesn't encrypt upstream always may. An encrypting one may for a key it has never sealed locally (a new object,
    // an adopted bucket's data) or when its event subscription imports foreign objects; for a file it holds sealed,
    // "plaintext" upstream is a downgrade (a sealed object stripped of its metadata, or relabelled vh-encrypted=false)
    // and stays an authentication failure.
    const auto plaintextAllowed = [&]() {
        const auto s3 = s3Vault();
        if (!s3 || !s3->encrypt_upstream) return true;
        try {
            if (!db::query::fs::File::getEncryptionIVAndVersion(vault->id, rel_path)) return true;
        } catch (const std::exception&) {
            return false;   // unknown: keep the authenticated behaviour
        }
        if (vh::sync::events::subscriptions::importsForeignObjects(vault->id)) {
            log::Registry::cloud()->warn(
                "[CloudStorageEngine] Vault {}: importing '{}' as plaintext over a sealed file: the upstream object "
                "carries no usable Vaulthalla encryption metadata (the event subscription imports foreign objects)",
                vault->id, rel_path.string());
            return true;
        }
        log::Registry::cloud()->warn(
            "[CloudStorageEngine] Vault {}: refusing '{}' as plaintext: the vault holds it sealed and encrypts upstream",
            vault->id, rel_path.string());
        return false;
    };

    const auto encryptedWith = [](std::optional<std::pair<std::string, unsigned int>> payload = std::nullopt) {
        RemoteEncryptionContext context;
        context.encrypted = true;
        context.payload = std::move(payload);
        return context;
    };

    if (remoteFile && remoteFile->remote_encrypted.has_value()) {
        if (!*remoteFile->remote_encrypted) return {};
        if (filePayload) return encryptedWith(filePayload);

        if (const auto& loadedHead = loadHead()) {
            if (const auto flag = header_value(*loadedHead, META_VH_ENCRYPTED)) {
                const auto encrypted = parse_encrypted_flag(*flag);
                if (encrypted && !*encrypted && plaintextAllowed()) return {};
            }
            if (const auto headPayload = encryption_payload_from_headers(*loadedHead))
                return encryptedWith(headPayload);
        }

        if (const auto recoveryPayload = localPayload()) return encryptedWith(recoveryPayload);
        return encryptedWith();
    }

    if (const auto& loadedHead = loadHead()) {
        if (const auto flag = header_value(*loadedHead, META_VH_ENCRYPTED)) {
            if (const auto encrypted = parse_encrypted_flag(*flag)) {
                if (!*encrypted) {
                    if (plaintextAllowed()) return {};
                    if (filePayload) return encryptedWith(filePayload);
                    if (const auto recoveryPayload = localPayload()) return encryptedWith(recoveryPayload);
                    return encryptedWith();
                }
                if (const auto headPayload = encryption_payload_from_headers(*loadedHead))
                    return encryptedWith(headPayload);
                if (filePayload) return encryptedWith(filePayload);
                if (const auto recoveryPayload = localPayload()) return encryptedWith(recoveryPayload);
                return encryptedWith();
            }
        }

        if (const auto headPayload = encryption_payload_from_headers(*loadedHead))
            return encryptedWith(headPayload);

        // The object is there and carries no Vaulthalla metadata at all: plaintext written by another tool (#96 —
        // e.g. an external overwrite of a file Vaulthalla knows). The local row's IV describes the copy it replaced,
        // so recovering from it would fail authentication on bytes that were never sealed. A vault that doesn't
        // encrypt upstream takes it as plaintext; an encrypting one only when its event subscription explicitly
        // imports foreign objects. Otherwise it stays an authentication failure: a sealed object stripped of its
        // metadata and replaced must not become vault content silently.
        if (plaintextAllowed()) return {};
    }

    // No HEAD answer: fall back to what the index row or the local row recorded.
    if (filePayload) return encryptedWith(filePayload);
    if (const auto recoveryPayload = localPayload()) return encryptedWith(recoveryPayload);

    return {};
}

std::optional<CloudEngine::RemoteObjectHead> CloudEngine::headRemoteObject(const fs::path& rel_path) const {
    const auto head = s3Provider_->getHeadObject(stripLeadingSlash(rel_path));
    if (!head) return std::nullopt;

    RemoteObjectHead out;
    if (const auto etag = header_value(*head, "ETag")) out.etag = *etag;
    if (const auto length = header_value(*head, "Content-Length")) {
        try {
            out.content_length = std::stoull(*length);
        } catch (const std::exception&) {
            out.content_length.reset();
        }
    }

    std::optional<std::pair<std::string, unsigned int>> payload;
    try {
        payload = encryption_payload_from_headers(*head);
    } catch (const std::exception&) {
        payload.reset();  // an unparsable key version is no usable encryption context
    }
    std::optional<bool> flag;
    if (const auto value = header_value(*head, META_VH_ENCRYPTED)) flag = parse_encrypted_flag(*value);
    // Objects Vaulthalla writes always carry vh-encrypted; an object without any vh metadata is plaintext.
    out.encrypted = flag ? *flag : payload.has_value();
    if (out.encrypted && payload) {
        out.iv_b64 = payload->first;
        out.key_version = payload->second;
    }
    if (const auto hash = header_value(*head, META_CONTENT_HASH); hash && !hash->empty()) out.content_hash = *hash;

    if (auto storageClass = header_value(*head, "x-amz-storage-class")) {
        std::ranges::transform(*storageClass, storageClass->begin(), [](unsigned char c) {
            return static_cast<char>(std::toupper(c));
        });
        if (*storageClass == "GLACIER" || *storageClass == "DEEP_ARCHIVE") {
            const auto restore = header_value(*head, "x-amz-restore");
            out.requires_restore = !restore || !contains_case_insensitive(*restore, "ongoing-request=\"false\"");
        }
    }
    if (const auto archiveStatus = header_value(*head, "x-amz-archive-status"); archiveStatus && !archiveStatus->empty())
        out.requires_restore = true;

    return out;
}

std::optional<CloudEngine::RemoteObjectHead> CloudEngine::headRemoteObjectStrict(const fs::path& rel_path) const {
    s3::Controller::resetLastHeadOutcome();
    auto head = headRemoteObject(rel_path);
    if (head) return head;
    const auto outcome = s3::Controller::lastHeadOutcome();
    if (outcome.performed && !(outcome.transport_ok && outcome.http_status == 404))
        throw std::runtime_error(fmt::format("HEAD of '{}' failed (HTTP {}{}): whether the object exists is unknown",
                                             rel_path.string(), outcome.http_status,
                                             outcome.transport_ok ? "" : ", transport error"));
    return std::nullopt;
}

std::vector<uint8_t> CloudEngine::fetchRemotePlaintext(const std::shared_ptr<File>& remoteFile,
                                                       const std::optional<std::string>& ifMatch,
                                                       const std::optional<uint64_t> maxBytes) const {
    if (!remoteFile) throw std::invalid_argument("[CloudStorageEngine] Cannot fetch a null remote file");
    const auto relPath = makeAbsolute(remoteFile->path);
    std::vector<uint8_t> payload;
    if (remoteFile->size_bytes) payload.reserve(maxBytes ? std::min<uint64_t>(remoteFile->size_bytes, *maxBytes)
                                                         : remoteFile->size_bytes);
    s3Provider_->streamObject(
        stripLeadingSlash(relPath),
        s3::GetObjectOptions{.range = std::nullopt, .if_match = ifMatch, .max_body_bytes = maxBytes},
        [&](const std::span<const uint8_t> chunk) { payload.insert(payload.end(), chunk.begin(), chunk.end()); });
    return decryptRemotePayload(relPath, payload, remoteFile, RemoteEncryptionResolveOptions{true, true});
}

std::shared_ptr<File> CloudEngine::replaceLocalContent(const fs::path& rel_path, const std::vector<uint8_t>& plaintext,
                                                       const std::string& expectedSourceId) {
    const auto owner = vh::identities::manager().user(vault->owner_id);
    if (!owner) throw std::runtime_error("[CloudStorageEngine] Vault owner not found for file replacement");
    const auto path = makeAbsolute(rel_path);
    const auto f = Filesystem::createFile({
        .path = path,
        .fuse_path = vaultPathToFusePath(path),
        .buffer = plaintext,
        .engine = shared_from_this(),
        .user = owner,
        .overwrite = true,
        .expected_source_id = expectedSourceId
    });
    preview::render::enqueueThumbnails(shared_from_this(), f, plaintext);
    return f;
}

void CloudEngine::setRemoteFetchGate(RemoteFetchGate gate) { fetchGate_ = std::move(gate); }

void CloudEngine::setRangedReadLimits(const RangedReadLimits& limits) { rangedLimits_ = limits; }

void CloudEngine::setHydrateCatalogCommitForTesting(HydrateCatalogCommit commit) { catalogCommit_ = std::move(commit); }

void CloudEngine::purge(const fs::path& rel_path) const {
    removeLocally(rel_path);
    removeRemotely(rel_path);
}

void CloudEngine::purge(const std::shared_ptr<file::Trashed>& f) const {
    removeLocally(f);
    removeRemotely(f);
}

void CloudEngine::removeRemotely(const fs::path& rel_path) const {
    auto own = noteOwnWrite(stripLeadingSlash(rel_path), true, std::nullopt);
    s3Provider_->deleteObject(stripLeadingSlash(rel_path));
    own.done();
    // The file may still be indexed (remote-only removal); its derived artifacts go with the remote copy, as the
    // path-keyed thumbnails did. After removeLocally the row (and its artifacts) are already gone.
    if (const auto file = db::query::fs::File::getFileByPath(vault->id, makeAbsolute(rel_path)))
        purgeDerivedArtifacts(file->id);
}

void CloudEngine::removeRemotely(const std::shared_ptr<file::Trashed>& f) const {
    // Trashing ended the file id and dropped its derived artifacts.
    auto own = noteOwnWrite(stripLeadingSlash(makeAbsolute(f->path)), true, std::nullopt);
    s3Provider_->deleteObject(stripLeadingSlash(makeAbsolute(f->path)));
    own.done();
}

CloudEngine::OwnWrite CloudEngine::noteOwnWrite(const fs::path& key, const bool isDelete,
                                               const std::optional<uint64_t> objectSize,
                                               const std::shared_ptr<File>& file) const {
    if (!vault) return OwnWrite{};
    auto write = recovery::hooks::UpstreamWrite{.vault_id = vault->id, .key = key.string(), .is_delete = isDelete,
                                                .object_size = isDelete ? std::nullopt : objectSize,
                                                .etag = std::nullopt, .version_id = std::nullopt,
                                                .file = isDelete ? nullptr : file};
    s3::Controller::resetLastPutOutcome();
    try {
        if (!vh::sync::events::subscriptions::activeFor(vault->id)) return OwnWrite{std::nullopt, std::move(write)};
        return OwnWrite{db::query::upstream::WriteIntent::record(
                            vault->id, key.string(),
                            isDelete ? vh::storage::upstream::model::WriteOp::Delete
                                     : vh::storage::upstream::model::WriteOp::Put,
                            isDelete ? std::nullopt : objectSize),
                        std::move(write)};
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn("[CloudStorageEngine] Vault {}: could not record a write intent for '{}': {}",
                                     vault->id, key.string(), e.what());
        return OwnWrite{std::nullopt, std::move(write)};
    }
}

void CloudEngine::OwnWrite::done() {
    if (id_) {
        const auto id = *std::exchange(id_, std::nullopt);
        // The stored object's ETag (unquoted, as notifications carry it), so the intent only matches the event of
        // exactly this object (a restore's CopyObject included), never another writer's same-size object.
        std::optional<std::string> etag;
        if (write_ && !write_->is_delete) {
            auto tag = s3::Controller::lastPutOutcome().etag;
            if (tag.size() >= 2 && tag.front() == '"' && tag.back() == '"') tag = tag.substr(1, tag.size() - 2);
            if (!tag.empty()) etag = std::move(tag);
        }
        try {
            db::query::upstream::WriteIntent::complete(id, etag);   // lives from completion, not from the start of the upload
        } catch (const std::exception& e) {
            log::Registry::cloud()->warn("[CloudStorageEngine] write intent {}: completion not recorded: {}", id, e.what());
        }
    }
    if (auto write = std::exchange(write_, std::nullopt)) {
        if (!write->is_delete) {
            const auto outcome = s3::Controller::lastPutOutcome();
            if (!outcome.etag.empty()) write->etag = outcome.etag;
            write->version_id = outcome.version_id;
        }
        recovery::hooks::afterUpstreamWrite(*write);
    }
}

CloudEngine::OwnWrite::~OwnWrite() {
    if (!id_) return;
    try {
        db::query::upstream::WriteIntent::remove(*id_);    // the request failed: nothing of ours will be notified
    } catch (...) {
        // Expires on its own.
    }
}

std::shared_ptr<vh::vault::model::S3Vault> CloudEngine::s3Vault() const { return std::static_pointer_cast<vh::vault::model::S3Vault>(vault); }

void CloudEngine::resolveS3ProviderConfiguration() {
    s3Profile_.reset();
    storageTier_.reset();

    const auto s3 = std::dynamic_pointer_cast<vh::vault::model::S3Vault>(vault);
    if (!s3) return;

    if (key_) s3Profile_ = s3::provider::resolve(key_->provider);
    else s3Profile_ = s3::provider::resolve(vh::vault::model::S3Provider::Other);

    const auto resolution = s3Profile_->normalizeStorageTier(s3->storage_tier_id);
    if (!resolution.ok) throw std::runtime_error(resolution.error);

    storageTier_ = resolution.resolved;
    if (resolution.normalized_id) s3->storage_tier_id = resolution.normalized_id;
    else if (s3->storage_tier_id && s3::provider::isProviderDefaultTierValue(*s3->storage_tier_id)) s3->storage_tier_id.reset();
}

s3::RequestOptions CloudEngine::requestOptionsFor(const s3::provider::RequestOperation operation) const {
    if (!s3Profile_) return {};

    const auto mutation = s3Profile_->requestMutation(operation, storageTier_);
    s3::RequestOptions options;
    options.system_headers = mutation.system_headers;
    return options;
}

std::optional<std::string> CloudEngine::configuredStorageClass() const {
    if (!storageTier_ || !storageTier_->wire_class) return std::nullopt;
    return storageTier_->wire_class;
}

std::shared_ptr<RemotePolicy> CloudEngine::remote_policy() const {
    return std::static_pointer_cast<RemotePolicy>(sync);
}

void CloudEngine::configureS3RequestBudget(const s3::S3RequestBudget& budget) const {
    if (s3Provider_) s3Provider_->setRequestBudget(budget);
}

void CloudEngine::clearS3RequestBudget() const {
    if (s3Provider_) s3Provider_->clearRequestBudget();
}

void CloudEngine::resetS3RequestMetrics() const {
    if (s3Provider_) s3Provider_->resetRequestMetrics();
}

s3::S3RequestMetrics CloudEngine::s3RequestMetrics() const {
    if (!s3Provider_) return {};
    return s3Provider_->requestMetrics();
}

void CloudEngine::setS3ControllerForTesting(std::shared_ptr<s3::Controller> s3Provider) {
    s3Provider_ = std::move(s3Provider);
    if (s3Provider_ && vault) s3Provider_->setUsageVault(vault->id);
}

void CloudEngine::setS3ProviderProfileForTesting(s3::provider::ProfilePtr profile) {
    s3Profile_ = std::move(profile);
    storageTier_.reset();

    const auto s3 = std::dynamic_pointer_cast<vh::vault::model::S3Vault>(vault);
    if (!s3 || !s3Profile_) return;

    const auto resolution = s3Profile_->normalizeStorageTier(s3->storage_tier_id);
    if (!resolution.ok) throw std::runtime_error(resolution.error);
    storageTier_ = resolution.resolved;
    if (resolution.normalized_id) s3->storage_tier_id = resolution.normalized_id;
    else if (s3->storage_tier_id && s3::provider::isProviderDefaultTierValue(*s3->storage_tier_id)) s3->storage_tier_id.reset();
}
