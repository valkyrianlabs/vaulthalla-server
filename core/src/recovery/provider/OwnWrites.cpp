#include "recovery/provider/OwnWrites.hpp"

#include "db/query/recovery/ObjectVersion.hpp"
#include "fs/model/File.hpp"
#include "log/Registry.hpp"
#include "recovery/provider/Versions.hpp"

#include <ctime>

namespace vh::recovery::provider {

namespace {

constexpr uint64_t kOwnWriteGcmTagBytes = 16;

// Whether the object this write stored is sealed: the generation says so when it knows (a restore's copy), else the
// size relation tells (a sealed object is the plaintext plus the 16-byte tag; a plaintext-upstream PUT stores the
// plaintext size).
bool ownWriteEncrypted(const hooks::UpstreamWrite& write) {
    const auto& f = write.file;
    if (!f) return false;
    if (f->remote_encrypted) return *f->remote_encrypted && !f->encryption_iv.empty();
    if (f->encryption_iv.empty() || !write.object_size) return false;
    return *write.object_size == f->size_bytes + kOwnWriteGcmTagBytes;
}

}

void noteOwnWrite(const hooks::UpstreamWrite& write) noexcept {
    try {
        if (write.key.empty() || versions::isInternalKey(write.key)) return;
        // DeleteObject on a versioned bucket creates a delete marker, but the data plane doesn't surface the marker's
        // version id (deleteObject returns nothing) and rows need one: the next ListObjectVersions learns the marker.
        // What we do know: the key's latest version stopped being current now. (Unversioned buckets never get rows;
        // a suspended bucket's "null" version is replaced by the marker, which the next listing marks gone.)
        if (write.is_delete) {
            (void)db::query::recovery::ObjectVersion::markSuperseded(write.vault_id, write.key, std::string{},
                                                                     std::time(nullptr));
            return;
        }
        // An unversioned bucket answers without x-amz-version-id: nothing is retained, nothing to index.
        if (!write.version_id || write.version_id->empty()) return;

        const auto now = std::time(nullptr);
        db::query::recovery::ObjectVersionRow row;
        row.vault_id = write.vault_id;
        row.object_key = write.key;
        row.version_id = *write.version_id;
        row.is_latest = true;
        row.etag = write.etag;
        row.size_bytes = write.object_size;
        row.storage_class = write.file ? write.file->remote_storage_class : std::nullopt;
        row.last_modified = now;
        row.origin = "vaulthalla";
        if (const auto& f = write.file) {
            const bool encrypted = ownWriteEncrypted(write);
            row.encrypted = encrypted;
            if (encrypted) {
                row.encryption_iv = f->encryption_iv;
                row.key_version = f->encrypted_with_key_version;
            }
            row.content_hash = f->content_hash;
            row.plaintext_bytes = f->size_bytes;
        }
        db::query::recovery::ObjectVersion::upsert(row);
        // "null" (a suspended bucket) replaces the previous null version in place: still the key's latest.
        db::query::recovery::ObjectVersion::markSuperseded(write.vault_id, write.key, *write.version_id, now);
    } catch (const std::exception& e) {
        log::Registry::cloud()->warn("[Recovery] Vault {}: provider version of '{}' not indexed: {}", write.vault_id,
                                     write.key, e.what());
    } catch (...) {
        log::Registry::cloud()->warn("[Recovery] Vault {}: provider version of '{}' not indexed", write.vault_id,
                                     write.key);
    }
}

}
