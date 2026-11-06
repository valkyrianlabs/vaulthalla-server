#pragma once

#include "crypto/id/ObjectUid.hpp"
#include "fs/Fwd.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <set>
#include <string>

// The path ↔ object mapping of an opaque_v1 vault (design/encryption/01-provider-blind-storage.md §4.5): the bucket
// names files by uid only (o/<uid>), the database keeps which file a uid is (files.object_uid, and
// files_trashed.object_uid while the file is in the trash).
namespace vh::db::query::sync {

class ObjectIdentity {
public:
    // The live file with this object uid in this vault.
    [[nodiscard]] static std::shared_ptr<vh::fs::model::File> fileByUid(uint32_t vaultId,
                                                                        const crypto::id::ObjectUid& uid);
    // The uid of the content at a vault path: the live file there, else the most recently trashed file that was
    // there and is still in the trash.
    [[nodiscard]] static std::optional<crypto::id::ObjectUid> uidAtPath(uint32_t vaultId,
                                                                        const std::filesystem::path& path);
    // Where a uid's file is: its live path, else the path it was trashed from (still in the trash), else the legacy
    // path the bucket layout migration (#373) re-sealed its history from.
    [[nodiscard]] static std::optional<std::filesystem::path> pathOfUid(uint32_t vaultId,
                                                                       const crypto::id::ObjectUid& uid);
    // The uids of files still in the vault trash (their objects stay until the trash is purged).
    [[nodiscard]] static std::set<crypto::id::ObjectUid> trashedUids(uint32_t vaultId);
    // A live or trashed file of this vault has this uid.
    [[nodiscard]] static bool known(uint32_t vaultId, const crypto::id::ObjectUid& uid);
};

}
