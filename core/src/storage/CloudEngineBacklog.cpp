// Local versioning's upstream backlog: replaying one retained generation (recovery/local/Backlog.cpp drives it).

#include "storage/CloudEngine.hpp"
#include "vault/Content.hpp"

#include "crypto/util/encrypt.hpp"
#include "db/query/recovery/Generation.hpp"
#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/ObjectKeys.hpp"
#include "storage/s3/Controller.hpp"
#include "crypto/vhf1/Format.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/S3Vault.hpp"

#include <sodium.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

namespace vh::storage {

namespace {

// Wipes a buffer holding key material or plaintext on every path out of the scope.
struct BacklogWipeOnExit {
    std::vector<uint8_t>& bytes;
    ~BacklogWipeOnExit() { sodium_memzero(bytes.data(), bytes.size()); }
};

}

std::optional<std::string> CloudEngine::uploadGeneration(const std::filesystem::path& key,
                                                         const std::filesystem::path& blob,
                                                         const db::query::recovery::GenerationRow& generation) const {
    std::error_code ec;
    if (!std::filesystem::is_regular_file(blob, ec))
        throw ContentUnavailable("the retained generation's blob is missing: " + blob.string());
    if (!generation.encryption_iv || generation.encryption_iv->empty() || !generation.key_version)
        throw ContentUnavailable("the retained generation has no encryption metadata: " + generation.path);

    // The generation as the files row described it then: its own IV, key version and hash go on the object.
    auto file = std::make_shared<vh::fs::model::File>();
    file->vault_id = vault ? std::make_optional(static_cast<int32_t>(vault->id)) : std::nullopt;
    if (generation.file_id) file->id = *generation.file_id;
    file->path = generation.path;
    file->name = std::filesystem::path(generation.path).filename().string();
    file->size_bytes = generation.size_bytes;
    file->content_hash = generation.content_hash;
    file->encryption_iv = *generation.encryption_iv;
    file->encrypted_with_key_version = *generation.key_version;
    file->updated_at = generation.source_updated_at.value_or(generation.created_at);
    // opaque_v1: the generation goes up as its file's object, o/<uid>, and carries no metadata (its header names the
    // generation and key version).
    const bool opaque = opaqueLayout();
    if (opaque) {
        file->object_uid = object_keys::uidOfContentKey(key.string());
        if (!file->object_uid) throw ContentUnavailable("the retained generation has no object key: " + generation.path);
    }

    auto options = requestOptionsFor(s3::provider::RequestOperation::PutObject);
    if (!opaque) options.metadata = getMetaMapFromFile(file);

    if (!s3Vault()->encrypt_upstream) {
        if (!encryptionManager) throw ContentUnavailable("no encryption manager for vault " + std::to_string(vault->id));
        crypto::SecretKeyPtr secret;
        try {
            secret = encryptionManager->historicalKeySnapshot(*generation.key_version);
        } catch (const vh::vault::KeyVersionUnavailable& e) {
            throw ContentUnavailable(e.what());
        }
        std::vector<uint8_t> plaintext;
        const BacklogWipeOnExit wipePlaintext{plaintext};
        try {
            // Whatever format the generation was sealed in (legacy GCM or VHF1), authenticated as a whole.
            plaintext = vh::vault::content::openBuffer(
                vh::fs::ops::readFileToVector(blob),
                {.vaultUid = encryptionManager->vaultUid(), .generation = *generation.encryption_iv,
                 .keyVersion = *generation.key_version},
                *secret);
        } catch (const std::exception& e) {
            throw IntegrityError(std::string("the retained generation failed authentication: ") + e.what());
        }

        auto own = noteOwnWrite(key, false, plaintext.size(), file);
        if (plaintext.size() < s3::Controller::MIN_PART_SIZE)
            s3Provider_->uploadBufferWithMetadata(key, plaintext, options);
        else {
            auto multipartOptions = requestOptionsFor(s3::provider::RequestOperation::CreateMultipartUpload);
            multipartOptions.metadata = options.metadata;
            s3Provider_->uploadLargeObject(key, plaintext, object_keys::partSizeFor(plaintext.size()), multipartOptions);
        }
        own.done();
        return s3::Controller::lastPutOutcome().version_id;
    }

    const auto size = std::filesystem::file_size(blob);
    if (opaque) {
        // What goes up as o/<uid> must open as o/<uid>.
        std::vector<uint8_t> header(std::min<uint64_t>(size, crypto::vhf1::kHeaderSize));
        if (std::ifstream in(blob, std::ios::binary);
            !in.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size())))
            throw ContentUnavailable("the retained generation's blob is unreadable: " + blob.string());
        try {
            requireOpaqueHeader(header, *file);
        } catch (const IntegrityError& e) {
            throw IntegrityError(std::string("the retained generation does not name its file's object: ") + e.what());
        }
    }
    auto own = noteOwnWrite(key, false, size, file);
    if (size < s3::Controller::MIN_PART_SIZE)
        s3Provider_->uploadObjectWithMetadata(key, blob, options);
    else {
        auto multipartOptions = requestOptionsFor(s3::provider::RequestOperation::CreateMultipartUpload);
        multipartOptions.metadata = options.metadata;
        s3Provider_->uploadLargeObject(key, blob, object_keys::partSizeFor(size), multipartOptions);
    }
    own.done();
    return s3::Controller::lastPutOutcome().version_id;
}

}
