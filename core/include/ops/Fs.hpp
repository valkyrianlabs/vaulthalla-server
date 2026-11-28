#pragma once

#include "ops/Actor.hpp"
#include "fs/Filesystem.hpp"
#include "fs/Fwd.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
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
// Every operation that changes the vault refuses first, after its permission check, for a vault held here as another
// server's copy that is not Live (vh::mirror::access::requireWritable: MirrorReadOnly, ws code "read_only" with its
// reason). On a Live mirror, mkdir, move, rename and remove are applied here at once as pending changes and submitted
// to the core (mirror::submit::Local, right after the gate's line); copy is submitted only (its new entries come back
// from the core). The person sees the change at once; the core executes it as that person, and the change is
// confirmed through the log, or reverted and kept (a conflict copy or a held change) when the core refuses.
//
// Callers today: the ws fs.* handlers (protocols/ws/handler/fs/Storage.cpp, Upload.cpp), `vh fs mkdir|mv|rm`
// (protocols/shell/commands/fs.cpp) and FUSE setattr. The HTTP
// lanes, text save, `vh fs put`, shares, the S3 gateway and the rest of FUSE still have their own paths to
// vh::fs::Filesystem (which refuses for such a vault too).
namespace vh::ops::fs {

// A change a linked server submitted for a vault this server is the core of (mirror::submit; design/peers/mirror.md
// "A change made on the mirror" step 4). While one is alive on this thread, the ops run as the person the mirror named
// (a remote account, which never authorizes on its own) and are authorized for vault `vault_id` by that linked server's
// vault role, the ceiling (rbac::resolver::PeerVault::may: the role's base permissions, no path overrides), not by the
// person's own RBAC; per-account rules for the mirror's people are a later piece, so for now the ceiling alone decides.
// The audit event names the peer and the request. Other vaults resolve as always.
class PeerSubmission {
public:
    struct View {
        uint32_t peer_id{};
        uint32_t vault_id{};
        std::string request_id{};
        std::string peer_node{};
    };
    explicit PeerSubmission(View view);
    ~PeerSubmission();
    PeerSubmission(const PeerSubmission&) = delete;
    PeerSubmission& operator=(const PeerSubmission&) = delete;

    // This thread's submission, nullptr without one.
    [[nodiscard]] static const View* current() noexcept;

private:
    View view_;
    const View* outer_;
};

// A sealed commit was based on a generation the file no longer has (or the file is gone, or open through the mount).
// Nothing was written. ws code "conflict", like the name clash it is told apart from by type.
struct ContentConflict final : Conflict {
    using Conflict::Conflict;
};

// Whether `actor` may do `action` at `path`, telling a missing entry from a refusal without an existence oracle
// (design decision, wave 4; piece B's "changed meanwhile" needs it): Missing only for an action on an existing entry
// (not Write, Touch or Link, which create one) when nothing is at `path` and the actor may list the nearest folder that
// exists (they could see it is missing there anyway); Denied for a refusal, and for a missing entry under a folder the
// actor may not list. Every op below refuses the same way: NotFound for Missing (commitSealed's replacement:
// ContentConflict, the base is gone), Denied for Denied. NotFound (thrown) without an engine for the vault.
enum class Access { Allowed, Denied, Missing };
[[nodiscard]] Access check(const Actor& actor, uint32_t vaultId, const std::filesystem::path& path,
                           vh::rbac::permission::vault::FilesystemAction action);

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

// A setattr through the mount (chmod, chown, utimens; design/peers/mirror.md, the known limit of migration 160): the
// entry's mode, owner uid, group gid and modification time, each only when given, in one transaction
// (db::query::fs::Entry::setAttributes) so the change journal and the replication log record it. Write at `path` for
// any of them; an owner or group that differs from the entry's needs a super admin (as chown needs root), else Denied.
// Audited fs.chown when the owner or group changes (mode and times are not audited: a copy with `cp -p` sets them on
// every file). NotFound for a missing entry.
struct Attributes {
    std::optional<uint32_t> mode{};
    std::optional<int32_t> owner_uid{}, group_gid{};
    std::optional<int64_t> mtime_us{};
};
void setAttributes(const Actor& actor, uint32_t vaultId, const std::filesystem::path& path, const Attributes& attrs);

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
