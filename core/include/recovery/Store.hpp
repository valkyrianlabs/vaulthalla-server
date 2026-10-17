#pragma once

#include "db/query/recovery/Blob.hpp"
#include "vault/Fwd.hpp"

#include <pqxx/transaction>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

// The local recovery store: immutable sealed generations ("blobs") under
//
//     <paths::getBackingPath()>/.vh-recovery/<vault mount_point>/<aa>/<storage_name>
//
// storage_name = 32 [a-z0-9] from the CSPRNG, <aa> its first two characters. Outside backingVaultRoot, so rotation,
// repairAtRest and vault size walks never see it. A blob is a file's sealed bytes exactly as they were (AES-256-GCM
// body‖tag, no header); IV and key version live in recovery_blob. Directories are 0700, blobs 0600. Never plaintext.
//
// Capture protocol (crash-safe, zero-copy where possible):
//   1. capture*() stages the file under its final name, durably (file + directory fsync), before any DB row exists:
//      link(2) the sealed backing file (falling back to a reflink, then a copy with fsync), or write it from a stream.
//      When a blob of the same generation (vault, IV, key version) already exists, nothing is staged.
//   2. attach(txn) inserts the recovery_blob row in the caller's transaction (with its files / file_versions rows) and
//      returns the blob id to reference. A concurrent capture of the same generation that committed first wins: the
//      existing id is returned and this capture's file becomes redundant.
//   3. After the caller's transaction commits: committed() drops a redundant file and, for captureMove, unlinks the
//      origin (the delete path). If the transaction fails, abort() (or the destructor) removes the staged file and
//      leaves the origin untouched.
//   A crash between 1 and 3 leaves an orphan file without a row; sweep() removes it once it is older than an hour. A row
//   whose file is missing is reported (restorable=false, "blob missing"), never deleted.
namespace vh::recovery::store {

inline constexpr const char* kStoreDirName = ".vh-recovery";

// The vault a blob belongs to: its id and its backing alias (vault.mount_point, trimmed).
struct VaultRef {
    uint32_t id{};
    std::string alias{};
};
[[nodiscard]] VaultRef vaultRef(const vault::model::Vault& v);

// What the captured bytes are.
struct GenerationMeta {
    std::string encryption_iv{};                 // "" for an empty or legacy plaintext generation (never deduplicated)
    unsigned int key_version{};
    uint64_t plaintext_bytes{};
    std::optional<std::string> content_hash{};
};

[[nodiscard]] std::filesystem::path root();                     // <backing>/.vh-recovery
// Throws std::invalid_argument unless alias is one [A-Za-z0-9_-] name (1..128).
[[nodiscard]] std::filesystem::path vaultDir(const VaultRef& vault);
[[nodiscard]] std::filesystem::path blobPath(const VaultRef& vault, const std::string& storageName);
[[nodiscard]] bool validStorageName(const std::string& name);
[[nodiscard]] std::string newStorageName();

enum class CaptureMethod { Existing, Link, Reflink, Copy, Stream };
[[nodiscard]] std::string to_string(CaptureMethod m);   // existing | link | reflink | copy | stream

namespace detail {
struct Stager;
}

class Capture {
public:
    Capture(Capture&& other) noexcept;
    Capture& operator=(Capture&&) = delete;
    Capture(const Capture&) = delete;
    Capture& operator=(const Capture&) = delete;
    ~Capture();                                // abort() unless committed()

    // Step 2, in the caller's transaction. Returns the blob id to reference from file_versions. Idempotent per
    // capture. Throws std::runtime_error when a reused blob vanished meanwhile (the caller's transaction fails; retry).
    [[nodiscard]] int64_t attach(pqxx::work& txn);
    // Step 3 after commit. Never throws (failures are logged: a leftover file is an orphan the sweep removes).
    void committed() noexcept;
    // The caller's transaction failed or was never run: removes the staged file; the origin is untouched.
    void abort() noexcept;

    [[nodiscard]] CaptureMethod method() const { return method_; }
    [[nodiscard]] const std::string& storageName() const { return storageName_; }
    [[nodiscard]] std::filesystem::path path() const;
    [[nodiscard]] uint64_t cipherBytes() const { return cipherBytes_; }
    // After attach(): the id, and whether it is an existing blob (no new bytes were kept).
    [[nodiscard]] std::optional<int64_t> blobId() const { return blobId_; }
    [[nodiscard]] bool reused() const { return method_ == CaptureMethod::Existing || redundant_; }

private:
    friend struct detail::Stager;
    Capture() = default;

    VaultRef vault_{};
    GenerationMeta meta_{};
    CaptureMethod method_{CaptureMethod::Existing};
    std::string storageName_;
    uint64_t cipherBytes_{};
    std::optional<std::filesystem::path> unlinkOriginOnCommit_;
    std::optional<int64_t> blobId_;
    bool ownsFile_{false};                     // this capture created the file at path()
    bool redundant_{false};                    // attach() found another blob of the generation
    bool done_{false};
};

// Captures the sealed backing file before it is replaced (rename over it) or kept as a snapshot member: link, else
// reflink, else copy (+ fsync). The backing file is not changed.
[[nodiscard]] Capture captureLink(const VaultRef& vault, const std::filesystem::path& backing, const GenerationMeta& meta);
// The delete path: like captureLink, and committed() then unlinks `backing` (+ directory fsync). Callers must not
// unlink it themselves; on abort it stays.
[[nodiscard]] Capture captureMove(const VaultRef& vault, const std::filesystem::path& backing, const GenerationMeta& meta);
// Always copies (+ fsync): for a source that may change after the capture (a sidecar that is reused, a file outside
// the backing tree).
[[nodiscard]] Capture captureCopy(const VaultRef& vault, const std::filesystem::path& source, const GenerationMeta& meta);
// Writes the sealed bytes with `write(fd)` (a stream, a remote body) into a staged 0600 file, then fsync + rename.
[[nodiscard]] Capture captureStream(const VaultRef& vault, const GenerationMeta& meta,
                                    const std::function<void(int fd)>& write);

// ---- reading and removal -------------------------------------------------------------------------------------------

struct BlobHandle {
    db::query::recovery::BlobRow row{};          // IV, key version, sizes for GcmFileReader / decrypt
    std::filesystem::path path{};
    bool present{false};                        // false: the row exists but its file is missing ("blob missing")
};

// nullopt when no blob of that id belongs to the vault.
[[nodiscard]] std::optional<BlobHandle> open(const VaultRef& vault, int64_t blobId);

// Deletes the row when nothing references it (row first, in its own transaction, then the file: a crash in between
// leaves an orphan file for the sweep, never a row without its file). False when referenced or absent.
bool removeBlob(const VaultRef& vault, int64_t blobId);
// removeBlob for each id (ids returned by Snapshot::remove, Generation::remove/removeVersions/releaseBlob). Returns how
// many were removed. Never throws for a single failure (logged).
uint64_t removeBlobs(const VaultRef& vault, const std::vector<int64_t>& blobIds) noexcept;

// ---- accounting ----------------------------------------------------------------------------------------------------

// Physical (deduplicated) bytes of the vault's blobs, from the DB (no walk). Cached for `maxAge` per vault; captures
// and removals through this store invalidate it.
[[nodiscard]] uint64_t physicalBytes(uint32_t vaultId, std::chrono::milliseconds maxAge = std::chrono::seconds(5));
// What the store adds beyond the vault's live backing files (BlobQuery::chargedBytes): what the vault quota charges.
// Cached like physicalBytes; a replaced live generation is charged at the latest after maxAge.
[[nodiscard]] uint64_t chargedBytes(uint32_t vaultId, std::chrono::milliseconds maxAge = std::chrono::seconds(5));
void invalidateUsage(uint32_t vaultId) noexcept;

// ---- maintenance ---------------------------------------------------------------------------------------------------

struct SweepReport {
    uint64_t temp_removed{};                   // staging leftovers (.tmp-*)
    uint64_t orphans_removed{}, orphan_bytes{}; // blob files without a row
    uint64_t unreferenced_removed{};           // rows (and files) nothing references
    std::vector<int64_t> missing{};              // rows whose file is missing (reported, kept)
    std::vector<std::string> errors{};
};

// Startup / periodic maintenance of one vault's store. Files and rows younger than minAge (by inode change time) are
// never touched, so an in-flight capture is safe.
SweepReport sweep(const VaultRef& vault, std::chrono::seconds minAge = std::chrono::hours(1));

// Removes <root>/<alias> (vault purge / removal) through vault::retention::removeVaultDirectory's path guard. False when
// there was nothing to remove; throws vault::retention::PathGuardError on an unsafe alias or layout.
bool removeVaultStore(const std::string& alias);

}
