#pragma once

// Local format conversion of legacy (gcm0) content to VHF1 (#372, WS2-c; design/encryption/02-authenticated-file-format.md
// §6.1, §6.2): every legacy local backing file and every legacy `.vh-recovery` blob (snapshot members, local versions,
// the upstream backlog) is re-sealed as VHF1 under the same key version. Nothing is rotated: the key version stays, only
// the generation id changes (a fresh salt), so caches keyed on it refresh on their own.
//
// Per item, before anything is replaced (§6.2):
//   1. the legacy tag authenticates over the whole input, while BLAKE2b of the plaintext is computed as it streams;
//   2. the VHF1 output is written once (O_EXCL, fsynced with its directory), then authenticated with a full chunk walk
//      bound to the vault, the salt, the key version and the object, and BLAKE2b of its plaintext is computed again;
//   3. both digests and both plaintext sizes match, and the plaintext size is the one the catalog records.
// Only then is the catalog moved to the new generation and the legacy form removed. No plaintext touches disk: it
// exists only in the codecs' wiped 64 KiB buffers, and the only files written are VHF1 bytes.
//
// Live files use the rotation sidecar protocol (sync/rotation/Rotation.hpp) under the file's content lock:
//   VHF1 -> <backing>.vh-rotate (fsync) [-> link into the recovery store when a blob holds the same generation] ->
//   one transaction: files row compare-and-set (old generation -> new) [+ that blob row moved to the link] ->
//   rename the sidecar over the backing file -> unlink the old blob file.
// A crash before the transaction leaves the old row: startup recovery discards the sidecar (the backing file
// authenticates), and the store sweep removes the unreferenced link. A crash after it leaves the new row: recovery
// promotes the sidecar, and the sweep removes the old blob file. A blob that is a hard link of a live file's generation
// is therefore converted once, together with the file, and stays a hard link of it.
//
// Other blobs are immutable and need no lock: VHF1 -> a new store name (O_EXCL, fsync) -> compare-and-set of the
// blob row (generation, storage name, size) -> unlink the old file. A crash leaves an unreferenced file either way,
// which the store sweep removes (recovery/Store.hpp).
//
// files.content_hash and recovery_blob.content_hash are kept, as key rotation keeps them: they are change detectors
// sync compares with its baselines, and the plaintext didn't change.
//
// Never during a key rotation or a key salvage of the vault (checked before every item; an item already running
// finishes, which is safe: it re-seals under the key version it read and the compare-and-set settles the rest).

#include "crypto/SecretKey.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "sync/rotation/Rotation.hpp"
#include "vault/Content.hpp"

#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <vector>

namespace vh::vault::conversion {

using FileSP = sync::rotation::FileSP;
using Digest = std::array<uint8_t, 32>;  // BLAKE2b-256 of the plaintext (memory only, never stored)

struct Converted {
    std::string generation{};  // the VHF1 salt, base64
    uint64_t plaintextBytes{};
    uint64_t sealedBytes{};
    Digest digest{};
};

// Re-seals the legacy generation at src (bound by `from`, a gcm0 generation, opened with key) as a new VHF1 file at dst
// under the same key version, bound to from.vaultUid and objectUid, and verifies it (steps 1-3 above; the caller checks
// the recorded size). dst is created with O_EXCL and `mode`, and fsynced; its directory is not. Throws
// storage::IntegrityError when the input doesn't authenticate or the output doesn't verify, std::invalid_argument for a
// generation that isn't legacy; on any throw nothing is left at dst.
[[nodiscard]] Converted convertFile(const std::filesystem::path& src, const content::Binding& from,
                                    const crypto::SecretKey& key, const std::filesystem::path& dst, mode_t mode,
                                    const crypto::id::ObjectUid& objectUid);

// A recovery_blob row (recovery/Store.hpp) the conversion works on.
struct Blob {
    int64_t id{};
    std::string storageName{};
    std::string generation{};
    unsigned int keyVersion{};
    uint64_t cipherBytes{};
    uint64_t plaintextBytes{};
    // The object uid of a live file the blob was captured from (file_versions.file_id), bound into the VHF1 header;
    // a fresh one when no such file is left.
    std::optional<crypto::id::ObjectUid> objectUid{};
};

// The recovery_blob row change of one conversion: compare-and-set from (generation, storage name) to the new ones.
struct BlobSwap {
    int64_t id{};
    unsigned int keyVersion{};
    std::string fromGeneration{}, fromStorageName{};
    std::string toGeneration{}, toStorageName{};
    uint64_t cipherBytes{};
};

struct FileCommit {
    bool file{false};  // the files row moved to the new generation
    bool blob{false};  // and the shared blob row with it
};

enum class Step { Staged, Linked, Committed, Replaced };
[[nodiscard]] std::string_view to_string(Step step);

// Test seam: thrown from Deps::afterStep to simulate a crash right after `at`. Not a std::exception; the protocol
// rethrows it without any cleanup, leaving the files as a crash would.
struct SimulatedCrash {
    Step at;
};

// Thrown (not a std::exception) when a key rotation or salvage started: the pass stops at once.
struct Blocked {
    std::string reason{};
};

struct Deps {
    // The rotation protocol's seams, reused as they are: the content lock, the row as stored now, busy (FUSE working
    // copies), the cache refresh after a commit (catalog.*) and sidecar authentication (crypto.fileAuthenticates, for a
    // sidecar an interrupted write left). Nothing else of it is used.
    sync::rotation::Deps rotation{};

    crypto::id::ObjectUid vaultUid{};
    // Live files: the strict live key (nullptr when the version isn't current). Blobs: any version the vault holds
    // (throws vault::KeyVersionUnavailable otherwise).
    std::function<crypto::SecretKeyPtr(unsigned int version)> liveKey;
    std::function<crypto::SecretKeyPtr(unsigned int version)> historicalKey;
    // Why the conversion must not run right now (a rotation or salvage of the vault); nullopt when it may.
    std::function<std::optional<std::string>()> blocked;

    // The blob holding a live file's exact generation, if any (dedupe on generation).
    std::function<std::optional<Blob>(const std::string& generation, unsigned int keyVersion)> sharedBlob;
    // One transaction: the files row from `expected` to file's generation (compare-and-set, like rotation's), and, when
    // given and the row moved, the blob swap.
    std::function<FileCommit(const fs::model::File& file, const sync::rotation::EncryptionState& expected,
                             const std::optional<BlobSwap>& blob)> commitFile;
    // The blob row swap alone (compare-and-set); false when the row changed or is gone.
    std::function<bool(const BlobSwap& swap)> commitBlob;

    std::function<std::filesystem::path(const std::string& storageName)> blobPath;
    std::function<std::string()> newStorageName;
    // Creates the store directory a new blob goes into (0700, like the store's own).
    std::function<void(const std::filesystem::path& dir)> prepareBlobDir;

    // A cloud vault that stores plaintext upstream: a live row without local bytes has nothing sealed anywhere, so its
    // legacy generation id is stale metadata and is cleared (as rotation does); the next download seals VHF1.
    bool plaintextUpstream{false};

    std::function<void()> usageChanged;                             // optional: blob bytes changed (quota cache)
    std::function<void(Step, std::string_view what)> afterStep;     // test seam, optional
};

enum class Outcome {
    Converted,  // VHF1 now, verified and committed (or a stale id cleared)
    Skipped,    // not legacy
    Deferred,   // open for writing; next pass
    Conflict,   // the row changed meanwhile; the new bytes were discarded, next pass re-reads it
};
[[nodiscard]] std::string_view to_string(Outcome outcome);

struct ItemStats {
    uint64_t bytesRead{};   // sealed bytes read (what the throughput limit counts)
    bool blobConverted{};   // a shared blob converted with the live file
};

// One live file (a files row on the current key version). Throws (std::exception) on failure, leaving the row and
// the backing file as they were, or Blocked.
Outcome convertLiveFile(const FileSP& file, const Deps& deps, ItemStats& stats);
// One recovery blob. Throws on failure, leaving the row and its file as they were, or Blocked.
Outcome convertBlob(const Blob& blob, const Deps& deps, ItemStats& stats);

// ---- pacing --------------------------------------------------------------------------------------------------------

struct Limits {
    uint64_t maxBytesPerSecond{0};  // 0: unlimited
    unsigned int maxCpuPercent{100};  // of one core, 1..100 (100: no pause)
};

// How long to pause after an item that read `bytes` and kept the worker busy for `busy`: long enough that the
// average stays under both limits.
[[nodiscard]] std::chrono::nanoseconds pauseAfter(const Limits& limits, uint64_t bytes, std::chrono::nanoseconds busy);

// ---- one pass over a vault -----------------------------------------------------------------------------------------

struct PassDeps {
    Deps item{};
    // Live files of the vault still legacy on keyVersion (ascending id, after `afterId`).
    std::function<std::vector<FileSP>(uint32_t afterId, std::size_t limit)> liveFiles;
    // Legacy blobs (ascending id). Blobs holding the generation of a live file this pass converts are left out: they
    // convert with it.
    std::function<std::vector<Blob>(int64_t afterId, std::size_t limit)> blobs;
    // False when the vault's live files are converted elsewhere (encrypt_upstream cloud vaults: the bucket layout
    // migration converts local and remote bytes together, spec 01 §6); blobs convert either way.
    bool convertLiveFiles{true};
    Limits limits{};
    std::size_t batch{64};
    std::function<void(std::chrono::nanoseconds)> pause;   // optional (default: no pause)
    std::function<bool()> stop;                            // optional: the service is stopping
    std::function<std::chrono::steady_clock::time_point()> now;  // optional (tests)
};

struct PassResult {
    std::size_t files{}, blobs{}, cleared{};
    uint64_t bytes{};
    std::size_t skipped{}, deferred{}, conflicts{};
    std::vector<sync::rotation::Failure> failures{};  // the first 50
    std::size_t failed{};
    std::optional<std::string> blocked{};
    bool stopped{};
};

PassResult runPass(const PassDeps& deps);

}
