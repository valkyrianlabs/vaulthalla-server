#pragma once

// Vault key rotation: the per-file re-encryption protocol, crash recovery and the pass that decides when a rotation
// is finished. Everything here works through injected seams (Deps), so the protocol is tested without a TPM, a
// database or S3; sync/rotation/Runtime.hpp wires the daemon's EncryptionManager, files table, fs cache and cloud
// engine into them.
//
// Invariants
//  - A files row only moves to a new (IV, key version) after every copy of the new ciphertext it will describe is
//    durable: the local sidecar is fsynced (file and directory) and, for cloud vaults that encrypt upstream, the
//    remote object has been replaced (PUT is atomic and the object carries its own IV/version as metadata).
//  - Both the old and the new local ciphertext exist until the row commits: the new bytes go to
//    `<backing>.vh-rotate`, the row is updated (compare-and-set on the old IV/version), then the sidecar is renamed
//    over the backing file and the directory fsynced.
//  - Recovery is decided by authentication, not by guessing which step ran: a sidecar is promoted iff it
//    authenticates under the row's current (IV, version); it is discarded iff the backing file does (or the row
//    says the bytes are not encrypted); otherwise both are kept and the rotation stays in progress.
//  - A rotation finishes only when nothing is unresolved, no file failed, and re-querying the files still on an
//    older key version comes back empty. Until then the old key stays loaded, so every file remains decryptable.

#include "fs/Fwd.hpp"

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace vh::sync::rotation {

using FileSP = std::shared_ptr<fs::model::File>;

inline constexpr std::string_view kSidecarSuffix = ".vh-rotate";

[[nodiscard]] std::filesystem::path sidecarPathFor(const std::filesystem::path& backing);
[[nodiscard]] bool isSidecar(const std::filesystem::path& path);
[[nodiscard]] std::filesystem::path backingPathForSidecar(const std::filesystem::path& sidecar);

// What a files row (or a remote object's metadata) says about the bytes it describes.
struct EncryptionState {
    std::string iv_b64;
    unsigned int key_version{};

    [[nodiscard]] bool encrypted() const { return !iv_b64.empty(); }
    bool operator==(const EncryptionState&) const = default;
};

[[nodiscard]] EncryptionState stateOf(const fs::model::File& file);

struct Crypto {
    std::function<unsigned int()> currentKeyVersion;
    // Re-seals ciphertext written under the file's (IV, version) with the current key and records the new IV and
    // version on `file`. Throws when the input does not authenticate.
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>& ciphertext, const FileSP& file)> reseal;
    // Seals plaintext with the current key and records the new IV and version on `file`.
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>& plaintext, const FileSP& file)> seal;
    // Decrypts in memory (legacy remote objects in a vault that stores plaintext upstream).
    std::function<std::vector<uint8_t>(const std::vector<uint8_t>& ciphertext, const EncryptionState& state)> open;
    // Whether the bytes authenticate under `state`. Never writes plaintext anywhere. The file variant throws on I/O
    // errors (a file that cannot be read is never treated as "does not authenticate" by a caller that deletes).
    std::function<bool(const std::filesystem::path& path, const EncryptionState& state)> fileAuthenticates;
    std::function<bool(const std::vector<uint8_t>& bytes, const EncryptionState& state)> bufferAuthenticates;
};

struct Catalog {
    // Moves the file's row from `expected` to the file's (IV, version), only if the row (same vault and path) still
    // says `expected`. False when it changed meanwhile (rewritten, moved, deleted): the caller backs out. `published`:
    // the remote now holds the new generation (uploaded by this rotation).
    std::function<bool(const fs::model::File& file, const EncryptionState& expected, bool published)> commit;
    // After a commit took effect on disk: refresh in-memory copies of the row (fs cache). Optional.
    std::function<void(const FileSP& file)> committed;
    // A writer holds the file open (FUSE working copy); its seal would race the rename. Optional.
    std::function<bool(const FileSP& file)> busy;
    // The file's content lock (fs::Filesystem::contentWriteMutex), held for the whole per-file rotation so an
    // overwrite or FUSE seal can't land between reading the old bytes and renaming the re-keyed ones. Optional.
    std::function<std::unique_lock<std::mutex>(const FileSP& file)> lock;
    // The row's encryption state as stored right now; checked under the lock. Optional.
    std::function<std::optional<EncryptionState>(const FileSP& file)> current;
};

// Cloud vaults only.
struct Remote {
    bool encryptUpstream{true};
    std::function<std::vector<uint8_t>(const FileSP& file)> download;
    // The object's own encryption metadata (x-amz-meta-vh-iv / vh-key-version); nullopt when the object says it is
    // plaintext or carries no metadata.
    std::function<std::optional<EncryptionState>(const FileSP& file)> objectState;
    // Replaces the object (PUT is atomic). Ciphertext uploads carry the file's IV and version as object metadata.
    std::function<void(const FileSP& file, const std::vector<uint8_t>& bytes, bool isCiphertext)> upload;
};

enum class Step { SidecarWritten, Published, Committed, Renamed };

// Test seam: thrown from a step hook to simulate a crash right after that step. It is not a std::exception, and the
// protocol rethrows it without running any cleanup, so the files are left exactly as a crash would leave them.
struct SimulatedCrash {
    Step at;
};

struct Deps {
    Crypto crypto;
    Catalog catalog;
    std::optional<Remote> remote;
    std::function<void(Step, const FileSP&)> afterStep;  // test seam, optional
};

enum class Outcome {
    Rotated,   // the row and every copy of the bytes are on the current key
    Skipped,   // nothing to do: not encrypted (empty or legacy plaintext), or already current
    Deferred,  // open for writing; retried next pass
    Conflict,  // the row changed under us; the new bytes were discarded and the next pass re-reads it
};

[[nodiscard]] std::string_view to_string(Outcome outcome);

// Rotates one file. Throws on failure, leaving the row, the backing file and the remote object consistent (the
// old ciphertext still authenticates under the row, which the old key can still decrypt).
Outcome rotateFile(const FileSP& file, const Deps& deps);

enum class Resolution { None, Promoted, Discarded, Unresolved };

// Settles `<backing>.vh-rotate` against `state` (the row's current encryption state; nullopt when no row maps to
// this backing path). Promoted: the sidecar authenticated and replaced the backing file. Discarded: the backing file
// is what the row describes (or nothing references either), the sidecar was removed. Unresolved: neither could be
// shown to match, both were kept.
Resolution resolveSidecar(const std::filesystem::path& backing,
                          const std::optional<EncryptionState>& state,
                          const Crypto& crypto);

struct RecoveryReport {
    unsigned int promoted{};
    unsigned int discarded{};
    unsigned int unresolved{};
};

// The row for a backing path: nullptr when none maps to it. Called only when a sidecar was found.
using BackingLookup = std::function<FileSP(const std::filesystem::path& backing)>;

// Finds every `*.vh-rotate` under root and resolves it. A promoted file is passed to deps.catalog.committed.
RecoveryReport recoverSidecars(const std::filesystem::path& root, const BackingLookup& lookup, const Deps& deps);

struct Failure {
    std::filesystem::path path;
    std::string reason;
};

struct BatchResult {
    std::size_t rotated{};
    std::size_t skipped{};
    std::size_t deferred{};
    std::size_t conflicts{};
    std::vector<Failure> failures;
    bool aborted{};  // stopped early (S3 request budget exhausted); the rest of the range was not attempted

    void merge(const BatchResult& other);
};

// Rotates files[begin, end). One file failing does not stop the others; S3 budget exhaustion stops the range.
BatchResult rotateRange(const std::vector<FileSP>& files, std::size_t begin, std::size_t end, const Deps& deps);

// Splits n items into at most maxParts contiguous, non-empty [begin, end) ranges (none when n is 0).
std::vector<std::pair<std::size_t, std::size_t>> splitRanges(std::size_t n, std::size_t maxParts);

struct PassDeps {
    std::function<bool()> inProgress;
    std::function<unsigned int()> keyVersion;
    std::function<RecoveryReport()> recover;                            // optional
    std::function<std::vector<FileSP>(unsigned int keyVersion)> pending;  // encrypted rows on an older key version
    std::function<BatchResult(const std::vector<FileSP>& files)> rotateAll;
    std::function<void()> reconcile;                                    // optional; throws when it could not
    std::function<void()> finish;
};

enum class PassStatus { Idle, Finished, Incomplete };

struct PassResult {
    PassStatus status{PassStatus::Idle};
    unsigned int keyVersion{};
    RecoveryReport recovery;
    std::size_t attempted{};
    BatchResult batch;
    std::size_t remaining{};
    std::string reconcileError;
};

// One rotation pass: recover sidecars, rotate what is still on an older key, reconcile, re-query, and finish only
// when nothing failed and nothing remains.
PassResult runPass(const PassDeps& deps);

}
