#pragma once

#include "crypto/id/ObjectUid.hpp"

#include <cstdint>
#include <filesystem>
#include <optional>

// The permanent id an entry created at one path gets, chosen before the creation instead of drawn at insert: a change
// made on a mirror creates its entry under a uid it records first (mirror::submit), and the core executes that change
// with the same uid, so both servers hold the entry under one id (design/peers/mirror.md "As built: a change made on the
// mirror"). Thread-local and scoped: the folder, file and symlink inserts (db::query::fs::Directory, File, Symlink) ask
// for a new entry at (vault, vault-relative path); anything else draws a new uid as always.
namespace vh::db::query::fs {

class AssignedUid {
public:
    AssignedUid(uint32_t vaultId, std::filesystem::path path, const vh::crypto::id::ObjectUid& uid);
    ~AssignedUid();
    AssignedUid(const AssignedUid&) = delete;
    AssignedUid& operator=(const AssignedUid&) = delete;

    // The uid assigned to a new entry of `vaultId` at `path` on this thread, else nullopt.
    [[nodiscard]] static std::optional<vh::crypto::id::ObjectUid> forPath(uint32_t vaultId,
                                                                          const std::filesystem::path& path);
    // forPath, else a new uid.
    [[nodiscard]] static vh::crypto::id::ObjectUid forPathOrNew(uint32_t vaultId, const std::filesystem::path& path);

private:
    AssignedUid* outer_;
    uint32_t vaultId_;
    std::filesystem::path path_;
    vh::crypto::id::ObjectUid uid_;
};

}
