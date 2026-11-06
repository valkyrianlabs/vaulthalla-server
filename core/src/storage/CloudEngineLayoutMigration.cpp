// What the bucket layout migration path_v0 -> opaque_v1 (vault/LayoutMigration.hpp, #373) needs from CloudEngine: its
// writes of re-sealed objects as Vaulthalla's own writes, the switch of the in-memory layout after the cutover
// transaction, and the bucket-only load of the manifest v2.

#include "storage/CloudEngine.hpp"

#include "fs/model/File.hpp"
#include "storage/ObjectKeys.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/manifest/Reader.hpp"
#include "sync/manifest/Store.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/S3Vault.hpp"

#include <fmt/format.h>

#include <stdexcept>

namespace vh::storage {

s3::PutOutcome CloudEngine::putMigratedObject(const std::string& key, const std::filesystem::path& source,
                                              const uint64_t size,
                                              const std::shared_ptr<vh::fs::model::File>& generation) const {
    if (object_keys::classify(key) != object_keys::KeyClass::Content)
        throw std::invalid_argument("a migrated object is written to o/<uid> only");
    const bool single = size < s3::Controller::MIN_PART_SIZE;
    // The provider's mutation (storage class) and nothing else: no x-amz-meta-*, whatever the vault's layout is now.
    const auto options = requestOptionsFor(single ? s3::provider::RequestOperation::PutObject
                                                  : s3::provider::RequestOperation::CreateMultipartUpload);
    auto own = noteOwnWrite(key, false, size, generation);
    if (single) s3Provider_->uploadObjectWithMetadata(key, source, options);
    else s3Provider_->uploadLargeObject(key, source, object_keys::partSizeFor(size), options);
    own.done();
    return s3::Controller::lastPutOutcome();
}

void CloudEngine::deleteMigratedObject(const std::string& key) const {
    if (object_keys::classify(key) != object_keys::KeyClass::Content)
        throw std::invalid_argument("a migrated delete marker goes on o/<uid> only");
    auto own = noteOwnWrite(key, true, std::nullopt);
    s3Provider_->deleteObject(key);
    own.done();
}

void CloudEngine::adoptStorageLayout(const vault::model::StorageLayout layout) {
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    if (!s3) throw std::logic_error("only an S3 vault has a storage layout");
    s3->storage_layout = layout;
    applyLayoutPolicy();
    std::scoped_lock lock(manifestV2Mutex_);
    manifestV2_.reset();   // created again on first use, for the layout the vault has now
}

sync::manifest::Content CloudEngine::loadManifestFromBucket() const {
    if (!opaqueLayout()) throw std::logic_error("only an opaque_v1 vault has a manifest v2");
    if (!encryptionManager) throw std::runtime_error("Vault has no encryption key loaded");
    sync::manifest::S3Store store(s3Provider_);
    const auto em = encryptionManager;
    const crypto::vhf1::KeyLookup keys = [em](const uint32_t version) -> crypto::SecretKeyPtr {
        try {
            return em->historicalKeySnapshot(version);
        } catch (const std::exception&) {
            return nullptr;
        }
    };
    return sync::manifest::load(store, em->vaultUid(), keys, {.known = std::nullopt, .use_provider_versions = false, .root_object = std::nullopt})
        .content;
}

}
