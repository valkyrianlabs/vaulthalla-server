#include "sync/rotation/Runtime.hpp"
#include "fs/Filesystem.hpp"

#include "crypto/util/encrypt.hpp"
#include "crypto/util/verify.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "fs/ops/file.hpp"
#include "fuse/WorkingCopies.hpp"
#include "log/Registry.hpp"
#include "recovery/local/Backlog.hpp"
#include "runtime/Deps.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "sync/model/Action.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"
#include "vault/Content.hpp"

#include <sodium.h>

#include <algorithm>
#include <span>

#include <stdexcept>
#include <string>
#include <unordered_map>

namespace vh::sync::rotation {

namespace {

// In-memory authentication through EncryptionManager, which alone holds the previous key during a rotation. The
// plaintext never leaves this frame and is wiped.
bool authenticatesInMemory(const vault::EncryptionManager& em, const std::vector<uint8_t>& bytes,
                           const EncryptionState& state) {
    if (!state.encrypted() || bytes.size() < crypto::util::AES_TAG_SIZE) return false;
    try {
        auto plaintext = em.decrypt(bytes, state.iv_b64, state.key_version);
        sodium_memzero(plaintext.data(), plaintext.size());
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

bool fileAuthenticatesWith(const vault::EncryptionManager& em, const std::filesystem::path& path,
                           const EncryptionState& state) {
    if (!state.encrypted()) return false;
    if (state.key_version != em.get_key_version())
        return authenticatesInMemory(em, fs::ops::readFileToVector(path), state);

    // Current key: stream it (either format), nothing but a wiped scratch buffer ever holds plaintext.
    try {
        return vh::vault::content::verifyWholeFile(
            path, {.vaultUid = em.vaultUid(), .generation = state.iv_b64, .keyVersion = state.key_version},
            *em.keySnapshot(state.key_version));
    } catch (const std::invalid_argument&) {
        return false;  // a generation id that is neither an IV nor a salt
    }
}

// FUSE opens decrypt with the cached row: give it the committed IV and version.
void refreshCachedEncryption(const FileSP& file) {
    if (!file || !file->inode) return;
    const auto& cache = runtime::Deps::get().fsCache;
    if (!cache) return;
    const auto cached = std::dynamic_pointer_cast<fs::model::File>(cache->getEntry(static_cast<vh::fs::Inode>(*file->inode)));
    if (!cached || cached == file || cached->path != file->path) return;
    cached->encryption_iv = file->encryption_iv;
    cached->encrypted_with_key_version = file->encrypted_with_key_version;
}

std::optional<Remote> remoteFor(const std::shared_ptr<storage::Engine>& engine) {
    if (engine->type() != storage::StorageType::Cloud) return std::nullopt;
    const auto cloud = std::static_pointer_cast<storage::CloudEngine>(engine);
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(engine->vault);

    Remote remote;
    remote.encryptUpstream = !s3 || s3->encrypt_upstream;
    remote.download = [cloud](const FileSP& file) {
        auto bytes = cloud->downloadToBuffer(file->path);
        // opaque_v1 (#369/#371): what the bucket holds at o/<uid> must be this file's object. Its header binds the
        // vault, the object uid and the key version; the generation check against the row comes later (the object may
        // already be on the current key). A swapped or foreign object fails here, before anything trusts it.
        if (cloud->opaqueLayout() && file->object_uid && !bytes.empty()) {
            const auto& em = *cloud->encryptionManager;
            try {
                (void)crypto::vhf1::openHeader(
                    std::span<const uint8_t>(bytes).first(std::min<std::size_t>(bytes.size(), crypto::vhf1::kHeaderSize)),
                    {crypto::vhf1::Kind::FileContent, em.vaultUid(), *file->object_uid, std::nullopt},
                    [&em](const uint32_t v) -> crypto::SecretKeyPtr {
                        try {
                            return em.historicalKeySnapshot(v);
                        } catch (const std::exception&) {
                            return nullptr;
                        }
                    });
            } catch (const crypto::vhf1::Error& e) {
                vault::content::throwIntegrity(e, "the object of " + std::to_string(file->id));
            }
        }
        return bytes;
    };
    remote.objectState = [cloud](const FileSP& file) -> std::optional<EncryptionState> {
        if (!cloud->remoteFileIsEncrypted(file->path)) return std::nullopt;
        if (const auto payload = cloud->getRemoteIVBase64AndVersion(file->path))
            return EncryptionState{.iv_b64 = payload->first, .key_version = payload->second};
        return std::nullopt;  // flagged encrypted without IV metadata: the caller tries the row's IV
    };
    remote.upload = [cloud](const FileSP& file, const std::vector<uint8_t>& bytes, const bool isCiphertext) {
        // Publishing the file's content writes its key: local versioning's backlog goes first, as for a sync upload
        // (recovery/local/Backlog). A replay that can't be sent fails this file's rotation; the next pass retries.
        if (const auto replay = recovery::local::backlog::replayBeforeUpload(*cloud, *file); replay.blocked)
            throw std::runtime_error("earlier versions could not be replayed upstream first: " +
                                     replay.error.value_or("unknown"));
        cloud->upload(file, bytes, isCiphertext);
        // opaque_v1: the index row (and so the next manifest) names the object the bucket now holds. Path-keyed
        // layouts are reconciled after the pass (reconcileRemoteIndex), which can't match o/<uid> rows by path.
        if (cloud->opaqueLayout() && isCiphertext) cloud->recordOwnUpload(file);
    };
    return remote;
}

}

Deps runtimeDeps(const std::shared_ptr<storage::Engine>& engine) {
    if (!engine || !engine->vault || !engine->encryptionManager)
        throw std::invalid_argument("key rotation needs an engine with a vault and an encryption manager");

    const auto em = engine->encryptionManager;
    Deps deps;

    deps.crypto.currentKeyVersion = [em] { return em->get_key_version(); };
    deps.crypto.reseal = [em](const std::vector<uint8_t>& ciphertext, const FileSP& file) {
        return em->rotateDecryptEncrypt(ciphertext, file);
    };
    deps.crypto.seal = [em](const std::vector<uint8_t>& plaintext, const FileSP& file) {
        return em->encrypt(plaintext, file);
    };
    deps.crypto.open = [em](const std::vector<uint8_t>& ciphertext, const EncryptionState& state) {
        return em->decrypt(ciphertext, state.iv_b64, state.key_version);
    };
    deps.crypto.bufferAuthenticates = [em](const std::vector<uint8_t>& bytes, const EncryptionState& state) {
        return authenticatesInMemory(*em, bytes, state);
    };
    deps.crypto.fileAuthenticates = [em](const std::filesystem::path& path, const EncryptionState& state) {
        return fileAuthenticatesWith(*em, path, state);
    };

    deps.catalog.commit = [](const fs::model::File& file, const EncryptionState& expected) {
        return db::query::fs::File::compareAndSetEncryptionIVAndVersion(file, expected.iv_b64, expected.key_version);
    };
    deps.catalog.committed = [](const FileSP& file) { refreshCachedEncryption(file); };
    deps.catalog.lock = [](const FileSP& file) { return std::unique_lock(fs::Filesystem::contentWriteMutex(file->id)); };
    deps.catalog.current = [](const FileSP& file) -> std::optional<EncryptionState> {
        const auto stored = db::query::fs::File::getEncryptionIVAndVersion(
            static_cast<unsigned int>(file->vault_id.value_or(0)), file->path);
        if (!stored) return std::nullopt;
        return EncryptionState{.iv_b64 = stored->first, .key_version = stored->second};
    };
    deps.catalog.busy = [](const FileSP& file) {
        return file->inode && fuse::WorkingCopies::instance().isOpen(*file->inode);
    };

    deps.remote = remoteFor(engine);
    return deps;
}

RecoveryReport recoverVault(const std::shared_ptr<storage::Engine>& engine, const Deps& deps) {
    if (!engine || !engine->vault || !engine->paths) return {};

    const auto vaultId = engine->vault->id;
    std::unordered_map<std::string, FileSP> byBacking;
    bool loaded = false;
    const BackingLookup lookup = [&](const std::filesystem::path& backing) -> FileSP {
        if (!loaded) {
            for (const auto& file : db::query::fs::File::getAllFiles(vaultId))
                if (file) byBacking[file->backing_path.lexically_normal().string()] = file;
            loaded = true;
        }
        const auto it = byBacking.find(backing.lexically_normal().string());
        return it == byBacking.end() ? nullptr : it->second;
    };

    const auto report = recoverSidecars(engine->paths->backingVaultRoot, lookup, deps);
    if (report.promoted || report.discarded || report.unresolved)
        log::Registry::sync()->info(
            "[KeyRotation] Vault {}: recovered rotation sidecars: {} promoted, {} discarded, {} unresolved",
            vaultId, report.promoted, report.discarded, report.unresolved);
    return report;
}

void reconcileRemoteIndex(const std::shared_ptr<storage::Engine>& engine, const unsigned int keyVersion) {
    if (!engine || !engine->vault || engine->type() != storage::StorageType::Cloud) return;
    if (const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(engine->vault); s3 && !s3->encrypt_upstream)
        return;

    const auto vaultId = engine->vault->id;
    std::unordered_map<std::string, FileSP> rows;
    bool rowsLoaded = false;
    std::vector<model::Action> plan;
    std::size_t unmatched = 0;

    for (const auto& object : db::query::sync::RemoteObjectIndex::listFilesForVault(vaultId)) {
        if (!object || !object->remote_encrypted.value_or(false)) continue;
        if (object->encryption_iv.empty() || object->encrypted_with_key_version >= keyVersion) continue;

        if (!rowsLoaded) {
            for (const auto& row : db::query::fs::File::listFilesInDir(vaultId, "/", true))
                if (row) rows[row->path.string()] = row;
            rowsLoaded = true;
        }

        const auto it = rows.find(object->path.string());
        if (it == rows.end()) {
            ++unmatched;
            continue;
        }
        const auto& row = it->second;
        // Not rotated yet: the pass is incomplete anyway and comes back here.
        if (row->encryption_iv.empty() || row->encrypted_with_key_version != keyVersion) continue;
        // Rotation keeps the content hash; a different one means the content changed, which a regular sync upload
        // (and its own index update) owns.
        if (!row->content_hash || !object->content_hash || *row->content_hash != *object->content_hash) {
            ++unmatched;
            continue;
        }

        model::Action action;
        action.type = model::ActionType::Upload;
        action.local = row;
        plan.push_back(std::move(action));
    }

    if (unmatched)
        log::Registry::sync()->warn(
            "[KeyRotation] Vault {}: {} remote index entr{} still record an older key version for content this "
            "rotation did not re-encrypt; a regular sync refreshes them",
            vaultId, unmatched, unmatched == 1 ? "y" : "ies");

    if (plan.empty()) return;
    std::static_pointer_cast<storage::CloudEngine>(engine)->applyRemoteIndexMutation(plan);
    log::Registry::sync()->info("[KeyRotation] Vault {}: updated {} remote index entr{} to key version {}", vaultId,
                                plan.size(), plan.size() == 1 ? "y" : "ies", keyVersion);
}

}
