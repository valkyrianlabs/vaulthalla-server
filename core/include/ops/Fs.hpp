#pragma once

#include "ops/Actor.hpp"
#include "fs/Filesystem.hpp"
#include "fs/Fwd.hpp"
#include "storage/Fwd.hpp"

#include <cstdint>
#include <filesystem>
#include <memory>
#include <optional>
#include <string>

// File operations as one account performs them on one vault: the operation layer every write surface is to share, so
// that a change submitted by a linked server and one made in the console run the same code (design/peers/mirror.md,
// "A change made on the mirror"). Each op does, inside it: the filesystem permission check, the space check where
// that operation has one, name-clash handling, the mutation through vh::fs::Filesystem, the `operations` record
// (move, rename, copy) and the audit event; then it asks the sync controller for an early pass.
//
// Paths are vault-relative ("/docs/a.txt"), as the ws fs.* commands name them. Refusals are ops::Error types: Denied
// (no permission, no actor), NotFound (no engine for the vault, a missing source or destination folder), Conflict
// (the name is taken), Invalid (into itself), ContentConflict below. Anything else is a fault.
//
// Callers today: the ws fs.* handlers (protocols/ws/handler/fs/Storage.cpp, Upload.cpp). The HTTP lanes, text save,
// `vh fs put`, shares, the S3 gateway and FUSE still have their own paths to vh::fs::Filesystem.
namespace vh::ops::fs {

// A sealed commit was based on a generation the file no longer has (or the file is gone, or open through the mount).
// Nothing was written. ws code "conflict", like the name clash it is told apart from by type.
struct ContentConflict final : Conflict {
    using Conflict::Conflict;
};

// fs.dir.create: Touch at `path`; Conflict when something is there, NotFound when its folder is missing. Audited
// fs.mkdir.
void mkdir(const Actor& actor, uint32_t vaultId, const std::filesystem::path& path);

// fs.entry.move / fs.entry.rename: Move (or Rename) on the source and, into another folder, what creating the entry
// (and everything a folder carries) there needs (#256). NotFound for a missing source or destination folder,
// Conflict for a taken destination (never replaced), Invalid for a folder into itself. Recorded in `operations`,
// audited fs.move / fs.rename.
void move(const Actor& actor, uint32_t vaultId, const std::filesystem::path& from, const std::filesystem::path& to);
void rename(const Actor& actor, uint32_t vaultId, const std::filesystem::path& from, const std::filesystem::path& to);

// fs.entry.copy: every copied entry passes Copy (and Read for a file) on its source and Touch or Write at its new
// path before anything is written (#167); the vault's quota is checked by vh::fs::Filesystem::copy. Recorded in
// `operations`, audited fs.copy.
void copy(const Actor& actor, uint32_t vaultId, const std::filesystem::path& from, const std::filesystem::path& to);

// fs.entry.delete: Delete at `path`. Files go to the trash (local versioning keeps their last generation), folders
// and symlinks are deleted (vh::fs::Filesystem::remove). Audited fs.delete.
void remove(const Actor& actor, uint32_t vaultId, const std::filesystem::path& path);

// The ws upload lane (fs.upload.*), whose bytes the session writes through the mount to a staged entry beside the
// target (`.upload-<id>.part`, sealed by FUSE). authorizeUpload is the check fs.upload.start and .finish make (Write at
// `path`; NotFound "Unknown storage engine") and returns the engine. commitStaged checks it again and renames the
// staged entry onto `path` (vh::fs::RenameMode::NoReplace); a failed rename is a fault naming errno, as before.
struct StagedCommit {
    uint32_t vault_id{};
    std::filesystem::path path{};    // where the file goes
    std::filesystem::path staged{};  // the staged entry holding its bytes
};
std::shared_ptr<vh::storage::Engine> authorizeUpload(const Actor& actor, uint32_t vaultId,
                                                     const std::filesystem::path& path);
void commitStaged(const Actor& actor, const StagedCommit& commit);

// Commits a file from bytes that are already sealed (vh::fs::NewFileContext::sealed): nothing is encrypted and no
// plaintext exists. Without `base`, a new file: Write at `path`, and a name already taken (a file, a folder, or a
// create of the same path in progress) is a Conflict, never an overwrite. With `base`, a replacement of the file
// whose current generation is that one (storage::Generation::sourceId): Overwrite at `path`, a compare-and-swap under
// the file's content lock; a file that has another generation by then, is gone, or is open through the mount is a
// ContentConflict. The folder must exist (NotFound). No space check: no caller of this path checks one at commit (the
// HTTP lanes check when an upload begins). Audited fs.commit.
struct SealedCommit {
    uint32_t vault_id{};
    std::filesystem::path path{};
    std::optional<std::string> base{};
    vh::fs::SealedWriter sealed{};
};
std::shared_ptr<vh::fs::model::File> commitSealed(const Actor& actor, const SealedCommit& commit);

}
