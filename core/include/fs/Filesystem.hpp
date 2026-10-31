#pragma once

#include <cstdint>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>
#include <utility>
#include <pqxx/pqxx>

#include "fuse/resolver/Resolved.hpp"
#include "fs/Fwd.hpp"
#include "identities/Fwd.hpp"
#include "recovery/Fwd.hpp"
#include "storage/Fwd.hpp"

namespace vh::fs {

// What a rename does to an existing entry at its destination.
enum class RenameMode {
    NoReplace,  // -EEXIST (the default: ws rename/move, uploads, RENAME_NOREPLACE)
    Replace     // POSIX rename(2): the destination goes the way an unlink/rmdir would take it, in the same transaction
};

// Backing-path changes a rename made before its transaction committed, undone (newest first) if it does not commit.
struct RenameJournal {
    std::vector<std::pair<std::filesystem::path, std::filesystem::path>> moved;  // from -> to
    std::vector<std::filesystem::path> created;
    void rollback() noexcept;
};

struct RenameContext {
    std::filesystem::path from, to;
    std::vector<uint8_t> buffer;
    std::shared_ptr<identities::User> user;
    std::shared_ptr<storage::Engine> engine;
    std::shared_ptr<model::Entry> entry;   // a private copy: published to the cache only once the rename commits
    std::shared_ptr<model::Entry> parent;  // its destination parent (as it will be after the rename)
    RenameJournal& journal;
    pqxx::work& txn;
};

// Content that is already sealed (recovery restores a retained generation): how the bytes a SealedWriter produced are
// sealed. An empty IV (with key version 0) only for an empty file, as every empty file is stored.
struct SealedContent {
    std::string encryption_iv{};
    unsigned int key_version{};
    uint64_t plaintext_size{};
    std::optional<std::string> mime_type{};   // nullopt: inferred from the path (sealed bytes can't be sniffed)
    // BLAKE2b of the sealed bytes as files.content_hash holds it, when the writer already computed it while sealing
    // (resumable uploads): createFile then skips reading the whole file back. nullopt: createFile hashes dst.
    std::optional<std::string> content_hash{};
};

// Creates `dst` (the content sidecar on an overwrite, the new backing path otherwise) holding the sealed bytes
// (AES-256-GCM body‖tag, or nothing) and says how they are sealed; createFile fsyncs and publishes them. Throws to
// refuse; whatever it left at dst is removed.
using SealedWriter = std::function<SealedContent(const std::filesystem::path& dst)>;

struct NewFileContext {
    std::filesystem::path path{}, fuse_path{};
    std::vector<uint8_t> buffer{};
    std::optional<std::filesystem::path> source_path{};
    std::shared_ptr<storage::Engine> engine = nullptr;
    std::shared_ptr<identities::User> user = nullptr;
    std::shared_ptr<identities::Group> group = nullptr;
    mode_t mode = 0644;
    bool overwrite = false;
    // Conditional overwrite: only replace the content if it is still this generation (storage::Generation::sourceId)
    // and not open through FUSE; otherwise ContentConflict. No generation has the id "": with overwrite, that means
    // "create it only if it does not exist" (an existing file is a ContentConflict).
    std::optional<std::string> expected_source_id{};
    // Why an overwrite replaces the content, as local versioning records the replaced generation (default overwrite):
    // a sync download, a restore, a conflict resolution.
    std::optional<recovery::local::Reason> version_reason{};
    // Commits content that is already sealed instead of buffer/source_path (nothing is encrypted, no plaintext is
    // produced) through the same overwrite and new-file branches: content lock, CAS, refusals, rows, cache. The
    // writer runs under the content lock on an overwrite.
    SealedWriter sealed{};
};

struct ContentConflict final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

struct MkdirContext {
    std::filesystem::path path{};
    mode_t mode = 0755;
    std::shared_ptr<storage::Engine> engine = nullptr;
    std::shared_ptr<identities::User> user = nullptr;
    std::shared_ptr<identities::Group> group = nullptr;
    std::shared_ptr<model::Entry> parent = nullptr;
    bool failIfExists = false;
};

// Authorizes one entry of a copy before anything is written: the source entry and the FUSE path it would be copied
// to. Throws to refuse the whole copy (the exception reaches the caller of Filesystem::copy unchanged).
using CopyAuthorizer = std::function<void(const model::Entry& source, const std::filesystem::path& destination)>;

struct CopyContext {
    std::filesystem::path from{}, to{};  // FUSE paths, in one vault
    unsigned int userId = 0;
    std::shared_ptr<storage::Engine> engine = nullptr;
    // Called for the copied entry and, for a directory, every entry under it (shallowest first).
    CopyAuthorizer authorize{};
};

struct FuseMkdirContext {
    fuse::resolver::Resolved resolved{};
    mode_t mode = 0755;
};

struct FuseCreateFileContext {
    fuse::resolver::Resolved resolved{};
    mode_t mode = 0644;
};

struct FuseCreateSymlinkContext {
    fuse::resolver::Resolved resolved{};
    std::string target{};
};

class Filesystem {
public:
    static void init(const std::shared_ptr<storage::Manager>& manager);
    static bool isReady();
    static void mkVault(const std::filesystem::path& absPath, unsigned int vaultId, mode_t mode = 0755);
    static bool exists(const std::filesystem::path& absPath);

    static int mkdir(const MkdirContext& ctx);
    static std::pair<int, std::shared_ptr<model::Entry>> mkdir(const FuseMkdirContext& ctx);

    // Copies a file, symlink or directory (with everything under it) within one vault (#167). Every copied file gets
    // its bytes at once, at its own alias backing path: the source's sealed bytes are copied as they are (no AAD, the
    // IV and key version travel with them in the row; any later write of either file draws a fresh IV), so no
    // plaintext is produced and a corrupted source stays detectable instead of being re-sealed as valid. A cloud
    // file with no local copy is hydrated first (metered, price-preflighted); the next sync uploads the copy.
    // Refuses before writing anything: -ENOENT/-EEXIST, -EXDEV (other vault), -EINVAL (into itself, or a symlink
    // whose target would leave the vault), -ENOSPC (the vault's quota), -ENODATA (remote content unavailable).
    // On a failure after that, nothing of the copy is left. Exceptions from ctx.authorize propagate.
    static int copy(const CopyContext& ctx);
    static void remove(const std::filesystem::path& path, unsigned int userId);
    // Moves an entry (with everything under it) within one vault. Nothing changes on a refusal or a failure: -ENOENT,
    // -EXDEV (other vault), -EINVAL (into itself), -EBUSY (a vault root), -EEXIST (destination taken, NoReplace).
    // With RenameMode::Replace an existing destination is replaced as rename(2) replaces it (the FUSE handler, after
    // checking Delete on it): a file is trashed like an unlink (row, backing bytes, derived artifacts), a symlink or
    // an empty folder deleted; -EISDIR / -ENOTDIR / -ENOTEMPTY when the types don't allow it.
    static int rename(const std::filesystem::path& oldPath, const std::filesystem::path& newPath,
                      const std::shared_ptr<identities::User>& user = nullptr,
                      std::shared_ptr<storage::Engine> engine = nullptr, RenameMode mode = RenameMode::NoReplace);

    static std::pair<int, std::shared_ptr<model::Entry>> createFile(const FuseCreateFileContext& ctx);
    static std::shared_ptr<model::File> createFile(const NewFileContext& ctx);
    static std::pair<int, std::shared_ptr<model::Symlink>> createSymlink(const FuseCreateSymlinkContext& ctx);

    static bool isPreviewable(const std::string& mimeType);

    // Serializes content replacement of one file across every writer (web/API overwrite, FUSE seal, key rotation).
    // Striped by file id; never held while taking mutex_.
    static std::mutex& contentWriteMutex(uint32_t fileId);

    struct AtRestRepair {
        unsigned int encrypted = 0;  // stored in plaintext, now sealed
        unsigned int resized = 0;    // sealed, but the recorded size was not the plaintext size
        unsigned int failed = 0;
    };

    // Brings a vault's files to the at-rest format the FUSE mount relies on (#173): ciphertext on disk, IV recorded,
    // size_bytes the plaintext size. Older builds left files written through FUSE in plaintext and recorded the
    // ciphertext length for files the rename path encrypted. Files open in FUSE are left to their own seal; files
    // with no local bytes (cloud index-only) are skipped.
    static AtRestRepair repairAtRest(const std::shared_ptr<storage::Engine>& engine);

private:
    inline static std::mutex mutex_;
    inline static std::shared_ptr<storage::Manager> storageManager_ = nullptr;

    static int handleRename(const RenameContext& ctx);

    static bool canFastPath(const std::shared_ptr<model::Entry>& entry, const std::shared_ptr<storage::Engine>& engine);
};

}
