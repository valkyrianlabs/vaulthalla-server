// The opaque_v1 data plane of CloudEngine (design/encryption/01-provider-blind-storage.md §4): object keys o/<file
// uid> and .vaulthalla/…, no provider-visible names or metadata, reads bound to the vault and the file's uid, the
// classified listing (content, metadata, foreign) and the import of foreign objects. Key construction and parsing live
// in storage/ObjectKeys.hpp; the request rules are enforced by s3::Controller::enforceRequestPolicy.

#include "storage/CloudEngine.hpp"

#include "crypto/vhf1/Format.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/ObjectIdentity.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "fs/model/file/Trashed.hpp"
#include "identities/Manager.hpp"
#include "log/Registry.hpp"
#include "runtime/Deps.hpp"
#include "storage/ObjectKeys.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/S3Vault.hpp"

#include <fmt/format.h>
#include <sodium.h>

#include <cerrno>
#include <system_error>

namespace vh::storage {

namespace cloud_opaque_detail {

crypto::vhf1::KeyLookup keyLookupOf(const std::shared_ptr<vault::EncryptionManager>& em) {
    return [em](const uint32_t version) -> crypto::SecretKeyPtr {
        try {
            return em->keySnapshot(version);
        } catch (const std::exception&) {
            return nullptr;  // not held: KeyUnavailable
        }
    };
}

struct WipeOnExit {
    std::vector<uint8_t>& bytes;
    ~WipeOnExit() { sodium_memzero(bytes.data(), bytes.size()); }
};

}

bool CloudEngine::opaqueLayout() const {
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    return s3 && s3->storage_layout == vault::model::StorageLayout::OpaqueV1;
}

void CloudEngine::applyLayoutPolicy() const {
    if (s3Provider_) s3Provider_->setOpaqueLayout(opaqueLayout());
}

std::string CloudEngine::objectKeyOf(const vh::fs::model::File& f) const {
    if (!opaqueLayout()) return vh::fs::model::stripLeadingSlash(f.path).string();
    if (!f.object_uid)
        throw std::runtime_error(fmt::format("[CloudStorageEngine] file {} has no object uid: it has no object in an "
                                             "opaque_v1 bucket", f.id));
    return object_keys::contentKey(*f.object_uid);
}

std::string CloudEngine::objectKeyOf(const vh::fs::model::file::Trashed& f) const {
    if (!opaqueLayout()) return vh::fs::model::stripLeadingSlash(vh::fs::model::makeAbsolute(f.path)).string();
    if (!f.object_uid)
        throw std::runtime_error(fmt::format("[CloudStorageEngine] trashed file {} has no object uid", f.id));
    return object_keys::contentKey(*f.object_uid);
}

std::string CloudEngine::objectKeyForPath(const std::filesystem::path& rel_path) const {
    if (!opaqueLayout()) return vh::fs::model::stripLeadingSlash(rel_path).string();
    const auto uid = db::query::sync::ObjectIdentity::uidAtPath(vault->id, vh::fs::model::makeAbsolute(rel_path));
    if (!uid)
        throw std::runtime_error(fmt::format("[CloudStorageEngine] vault {}: no file (entry) has an object at this path",
                                             vault->id));
    return object_keys::contentKey(*uid);
}

CloudEngine::OpaqueListing CloudEngine::listOpaqueBucket() const {
    if (!opaqueLayout()) throw std::logic_error("listOpaqueBucket is for opaque_v1 vaults");
    OpaqueListing out;
    // The whole bucket in one listing: the query carries no prefix, so no name (spec 01 §4.3 rule 5); content and
    // foreign objects are told apart here. .vaulthalla/ objects are the manifest's (filesFromS3XML drops them).
    for (auto& f : vh::fs::model::filesFromS3XML(s3Provider_->listObjects({}))) {
        const auto key = vh::fs::model::stripLeadingSlash(f->path).string();
        switch (object_keys::classify(key)) {
        case object_keys::KeyClass::Content:
            f->object_uid = object_keys::uidOfContentKey(key);
            f->remote_encrypted = true;
            out.objects.push_back(std::move(f));
            break;
        case object_keys::KeyClass::Metadata:
            break;
        case object_keys::KeyClass::Foreign:
            out.foreign.push_back(key);
            break;
        }
    }
    return out;
}

std::vector<uint8_t> CloudEngine::openOpaqueObject(const std::vector<uint8_t>& sealed,
                                                   const std::shared_ptr<vh::fs::model::File>& f) const {
    if (!encryptionManager) throw std::runtime_error("Vault has no encryption key loaded");
    if (!f || !f->object_uid) throw IntegrityError("an opaque_v1 object is read only against its file's uid");
    vault::content::Binding binding{.vaultUid = encryptionManager->vaultUid(), .generation = f->encryption_iv,
                                    .keyVersion = f->encrypted_with_key_version, .objectUid = f->object_uid};
    try {
        if (binding.generation.empty() || binding.keyVersion == 0) {
            // No generation recorded for this object (a row indexed from a listing or an event): the header names it,
            // and must name this vault and this file to be read at all.
            const auto opened = crypto::vhf1::openHeader(
                sealed, {.kind = crypto::vhf1::Kind::FileContent, .vaultUid = binding.vaultUid,
                         .objectUid = f->object_uid, .generation = std::nullopt},
                cloud_opaque_detail::keyLookupOf(encryptionManager));
            binding.generation = vault::content::generationOf(opened.params().salt);
            binding.keyVersion = opened.params().keyVersion;
        }
    } catch (const crypto::vhf1::Error& e) {
        vault::content::throwIntegrity(e, "the object's header");
    }
    const auto key = encryptionManager->keySnapshot(binding.keyVersion);
    if (!key) throw std::runtime_error("No vault key for key version " + std::to_string(binding.keyVersion));
    return vault::content::openBuffer(sealed, binding, *key);
}

std::pair<std::string, unsigned int> CloudEngine::opaqueObjectGeneration(const crypto::id::ObjectUid& uid) const {
    if (!encryptionManager) throw std::runtime_error("Vault has no encryption key loaded");
    std::vector<uint8_t> header;
    s3::GetObjectOptions options;
    options.range = std::make_pair(uint64_t{0}, uint64_t{crypto::vhf1::kHeaderSize - 1});
    options.max_body_bytes = crypto::vhf1::kHeaderSize;
    (void)s3Provider_->streamObject(object_keys::contentKey(uid), options, [&](const std::span<const uint8_t> bytes) {
        header.insert(header.end(), bytes.begin(), bytes.end());
    });
    try {
        const auto opened = crypto::vhf1::openHeader(
            header, {.kind = crypto::vhf1::Kind::FileContent, .vaultUid = encryptionManager->vaultUid(),
                     .objectUid = uid, .generation = std::nullopt},
            cloud_opaque_detail::keyLookupOf(encryptionManager));
        return {vault::content::generationOf(opened.params().salt), opened.params().keyVersion};
    } catch (const crypto::vhf1::Error& e) {
        vault::content::throwIntegrity(e, "the object's header");
    }
}

void CloudEngine::requireOpaqueHeader(const std::span<const uint8_t> sealed, const vh::fs::model::File& f) const {
    if (!encryptionManager) throw std::runtime_error("Vault has no encryption key loaded");
    if (!f.object_uid) throw IntegrityError("an opaque_v1 object needs its file's uid");
    if (sealed.size() < crypto::vhf1::kHeaderSize)
        throw IntegrityError("the sealed content is shorter than a VHF1 header; it is not uploaded");
    (void)vault::content::openHeader(sealed.first(crypto::vhf1::kHeaderSize),
                                     {.vaultUid = encryptionManager->vaultUid(), .generation = f.encryption_iv,
                                      .keyVersion = f.encrypted_with_key_version, .objectUid = f.object_uid},
                                     encryptionManager->keySnapshot(f.encrypted_with_key_version));
}

std::shared_ptr<vh::fs::model::File> CloudEngine::importForeignObject(const std::string& key) {
    if (!opaqueLayout()) throw std::logic_error("importForeignObject is for opaque_v1 vaults");
    if (object_keys::classify(key) != object_keys::KeyClass::Foreign)
        throw std::invalid_argument("only a foreign object is imported");
    const auto path = std::filesystem::path(object_keys::importedPathOf(key)).lexically_normal();
    if (db::query::sync::ObjectIdentity::uidAtPath(vault->id, path)) return nullptr;   // imported before

    const auto owner = identities::manager().user(vault->owner_id);
    if (!owner) throw std::runtime_error("[CloudStorageEngine] Vault owner not found for an import");

    std::vector<uint8_t> plaintext;
    const cloud_opaque_detail::WipeOnExit wipe{plaintext};
    {
        // The one request of an opaque_v1 vault that names a foreign key: it reads what someone else put there.
        const s3::ScopedForeignObjectRead foreign;
        s3Provider_->downloadToBuffer(key, plaintext);
    }

    // /Imported and the key's own folders, created as the vault owner.
    std::filesystem::path dir = "/";
    for (const auto& part : path.parent_path().relative_path()) {
        dir /= part;
        const auto fuseDir = vaultPathToFusePath(dir);
        if (runtime::Deps::get().fsCache->entryExists(fuseDir)) continue;
        const auto rc = vh::fs::Filesystem::mkdir({.path = fuseDir, .engine = shared_from_this(), .user = owner});
        if (rc < 0 && rc != -EEXIST)
            throw std::system_error(-rc, std::generic_category(), "could not create " + dir.string());
    }
    auto created = vh::fs::Filesystem::createFile({.path = path, .fuse_path = vaultPathToFusePath(path), .buffer = plaintext,
                                           .engine = shared_from_this(), .user = owner, .overwrite = false});
    log::Registry::cloud()->info("[CloudStorageEngine] Vault {}: imported a foreign object ({} bytes) as file {}",
                                 vault->id, plaintext.size(), created ? created->id : 0);
    return created;
}

}
