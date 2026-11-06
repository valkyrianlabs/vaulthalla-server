#include "sync/rotation/Rotation.hpp"

#include "crypto/util/encrypt.hpp"
#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "log/Registry.hpp"
#include "log/Redact.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/Content.hpp"

#include <fmt/format.h>
#include <sodium.h>
#include <sys/stat.h>

#include <algorithm>
#include <stdexcept>
#include <system_error>

namespace vh::sync::rotation {

namespace {

void reachedStep(const Deps& deps, const Step step, const FileSP& file) {
    if (deps.afterStep) deps.afterStep(step, file);
}

[[noreturn]] void failRotation(const FileSP& file, const std::string_view what) {
    throw std::runtime_error(fmt::format("{}: {}", file->path.string(), what));
}

void removeSidecarQuietly(const std::filesystem::path& sidecar) {
    std::error_code ec;
    std::filesystem::remove(sidecar, ec);
    if (ec)
        log::Registry::sync()->warn("[KeyRotation] Could not remove sidecar {}: {}", sidecar.string(), ec.message());
}

void fsyncDirectoryQuietly(const std::filesystem::path& dir) {
    try {
        fs::ops::fsyncDirectory(dir);
    } catch (const std::exception& e) {
        log::Registry::sync()->warn("[KeyRotation] Could not fsync directory {}: {}", dir.string(), e.what());
    }
}

// The sidecar replaces the backing file, so it takes the backing file's permission bits.
mode_t sidecarMode(const std::filesystem::path& backing) {
    struct stat st{};
    if (::stat(backing.c_str(), &st) == 0 && S_ISREG(st.st_mode)) return st.st_mode & 07777;
    return 0600;
}

bool commitRow(const Deps& deps, const FileSP& file, const EncryptionState& expected) {
    if (!deps.catalog.commit) throw std::logic_error("key rotation: no catalog commit");
    return deps.catalog.commit(*file, expected);
}

void notifyCommitted(const Deps& deps, const FileSP& file) {
    if (!deps.catalog.committed) return;
    try {
        deps.catalog.committed(file);
    } catch (const std::exception& e) {
        log::Registry::sync()->warn("[KeyRotation] {} rotated, but refreshing cached metadata failed: {}",
                                    log::file(file->id, file->path), e.what());
    }
}

// Local copy (local vaults, and cloud vaults' local copies in every strategy, Cache included):
//   1. new ciphertext -> <backing>.vh-rotate (O_EXCL, fsync file + directory)
//   2. (cloud, encrypt upstream) PUT the same ciphertext with its IV/version as object metadata
//   3. compare-and-set the row from the old to the new (IV, version)
//   4. rename the sidecar over the backing file, fsync the directory
// A crash before 3 leaves the row on the old ciphertext (still in place, old key still loaded): recovery discards
// the sidecar. A crash after 3 leaves the row on the sidecar: recovery promotes it. An uploaded object that the row
// never adopted is self-describing and is simply re-uploaded by the next attempt.
Outcome rotateLocalCopy(const FileSP& file, const EncryptionState& expected, const Deps& deps, const bool publish) {
    const auto& backing = file->backing_path;
    const auto dir = backing.parent_path();
    const auto sidecar = sidecarPathFor(backing);

    const auto ciphertext = fs::ops::readFileToVector(backing);
    if (ciphertext.size() < crypto::util::AES_TAG_SIZE)
        failRotation(file, fmt::format("backing file is {} bytes, shorter than an AES-GCM tag", ciphertext.size()));

    const auto next = deps.crypto.reseal(ciphertext, file);
    // A re-seal is a new generation (VHF1 for the daemon's crypto) of the same plaintext: whatever the formats, both
    // sizes must hold the same plaintext length.
    const auto before = vh::vault::content::plaintextSizeOfGeneration(ciphertext.size(), expected.iv_b64);
    if (!before || *before != vh::vault::content::plaintextSizeOfGeneration(next.size(), file->encryption_iv))
        failRotation(file, "re-encrypted size differs from the original's plaintext size");
    if (stateOf(*file) == expected) failRotation(file, "re-encryption did not produce a new IV");

    bool created = false;
    try {
        fs::ops::writeFileExclusive(sidecar, next, sidecarMode(backing));
        created = true;
        fs::ops::fsyncDirectory(dir);
        reachedStep(deps, Step::SidecarWritten, file);

        if (publish) {
            deps.remote->upload(file, next, true);
            reachedStep(deps, Step::Published, file);
        }

        if (deps.catalog.busy && deps.catalog.busy(file)) {
            removeSidecarQuietly(sidecar);
            return Outcome::Deferred;
        }
    } catch (const SimulatedCrash&) {
        throw;
    } catch (...) {
        if (created) removeSidecarQuietly(sidecar);
        throw;
    }

    // If the commit throws, whether it took effect is unknown: the sidecar is kept, and recovery keeps whichever
    // copy authenticates under what the row says.
    if (!commitRow(deps, file, expected)) {
        removeSidecarQuietly(sidecar);
        return Outcome::Conflict;
    }
    reachedStep(deps, Step::Committed, file);

    // From here the sidecar is the copy the row describes. A failed rename leaves it for recovery to promote.
    std::filesystem::rename(sidecar, backing);
    fsyncDirectoryQuietly(dir);
    reachedStep(deps, Step::Renamed, file);

    notifyCommitted(deps, file);
    return Outcome::Rotated;
}

// Remote object only (cloud vault, no local copy, e.g. Cache strategy after eviction). Nothing is written locally.
//   1. GET the object; its metadata says which (IV, version) it is sealed with
//   2. PUT the re-encrypted object (atomic replace, new IV/version as metadata)
//   3. compare-and-set the row
// A crash between 2 and 3 leaves an object on the current key whose metadata describes it while the row still has
// the old IV: the row stays on an older version, so the next pass picks it up again, sees the object is already
// current, checks it authenticates under its own metadata and adopts that metadata without another upload.
Outcome rotateRemoteObject(const FileSP& file, const EncryptionState& expected, const unsigned int current,
                           const Deps& deps) {
    const auto& remote = *deps.remote;
    const auto payload = remote.download(file);

    std::optional<EncryptionState> object;
    if (!payload.empty()) {
        object = remote.objectState(file);
        // An object without usable metadata is still the row's ciphertext if it authenticates under the row.
        if (!object && deps.crypto.bufferAuthenticates(payload, expected)) object = expected;
    }

    if (!object) {
        if (remote.encryptUpstream)
            failRotation(file, "the remote object is empty or carries no encryption metadata, and does not "
                               "authenticate under the row's IV; refusing to guess");
        // The vault stores plaintext upstream and keeps no local copy: no ciphertext exists for this row, its IV is
        // stale metadata.
        file->encryption_iv.clear();
        file->encrypted_with_key_version = 0;
    } else if (object->key_version == current) {
        if (!deps.crypto.bufferAuthenticates(payload, *object))
            failRotation(file, "the remote object does not authenticate under its own metadata");
        file->encryption_iv = object->iv_b64;
        file->encrypted_with_key_version = object->key_version;
    } else if (!remote.encryptUpstream) {
        // An encrypted object left from when the vault encrypted upstream: store it the way the vault says now.
        auto plaintext = deps.crypto.open(payload, *object);
        file->encryption_iv.clear();
        file->encrypted_with_key_version = 0;
        try {
            remote.upload(file, plaintext, false);
        } catch (...) {
            sodium_memzero(plaintext.data(), plaintext.size());
            throw;
        }
        sodium_memzero(plaintext.data(), plaintext.size());
        reachedStep(deps, Step::Published, file);
    } else {
        file->encryption_iv = object->iv_b64;
        file->encrypted_with_key_version = object->key_version;
        const auto next = deps.crypto.reseal(payload, file);
        remote.upload(file, next, true);
        reachedStep(deps, Step::Published, file);
    }

    if (!commitRow(deps, file, expected)) return Outcome::Conflict;
    reachedStep(deps, Step::Committed, file);
    notifyCommitted(deps, file);
    return Outcome::Rotated;
}

}

std::filesystem::path sidecarPathFor(const std::filesystem::path& backing) {
    static_assert(kSidecarSuffix == fs::ops::kContentSidecarSuffix);
    return fs::ops::contentSidecarPath(backing);
}

bool isSidecar(const std::filesystem::path& path) {
    const auto name = path.filename().string();
    return name.size() > kSidecarSuffix.size() && name.ends_with(kSidecarSuffix);
}

std::filesystem::path backingPathForSidecar(const std::filesystem::path& sidecar) {
    const auto name = sidecar.filename().string();
    if (!isSidecar(sidecar)) throw std::invalid_argument("not a key rotation sidecar: " + sidecar.string());
    return sidecar.parent_path() / name.substr(0, name.size() - kSidecarSuffix.size());
}

EncryptionState stateOf(const fs::model::File& file) {
    return {.iv_b64 = file.encryption_iv, .key_version = file.encrypted_with_key_version};
}

std::string_view to_string(const Outcome outcome) {
    switch (outcome) {
        case Outcome::Rotated: return "rotated";
        case Outcome::Skipped: return "skipped";
        case Outcome::Deferred: return "deferred";
        case Outcome::Conflict: return "conflict";
    }
    return "unknown";
}

Outcome rotateFile(const FileSP& file, const Deps& deps) {
    if (!file) return Outcome::Skipped;

    const auto expected = stateOf(*file);
    const auto current = deps.crypto.currentKeyVersion();

    // Empty files and legacy plaintext have no IV: nothing is sealed, so there is nothing to re-key (and decrypting
    // them fails on the IV size). Filesystem::repairAtRest seals legacy plaintext with the current key.
    if (!expected.encrypted() || expected.key_version >= current) return Outcome::Skipped;

    std::unique_lock<std::mutex> contentLock;
    if (deps.catalog.lock) contentLock = deps.catalog.lock(file);
    if (deps.catalog.current) {
        // Rewritten since it was listed: the next pass re-lists it with its new state.
        if (const auto stored = deps.catalog.current(file); !stored || !(*stored == expected)) return Outcome::Conflict;
    }
    if (deps.catalog.busy && deps.catalog.busy(file)) return Outcome::Deferred;

    const auto& backing = file->backing_path;
    std::error_code ec;
    if (std::filesystem::exists(std::filesystem::symlink_status(sidecarPathFor(backing), ec)) &&
        resolveSidecar(backing, expected, deps.crypto) == Resolution::Unresolved)
        failRotation(file, "a sidecar from an interrupted rotation could not be resolved");

    const bool hasLocalCopy = std::filesystem::is_regular_file(backing, ec);
    if (!deps.remote) {
        if (!hasLocalCopy) failRotation(file, "backing file is missing: " + backing.string());
        return rotateLocalCopy(file, expected, deps, false);
    }

    // A vault that stores plaintext upstream has nothing under the vault key remotely: only the local copy changes.
    if (hasLocalCopy) return rotateLocalCopy(file, expected, deps, deps.remote->encryptUpstream);
    return rotateRemoteObject(file, expected, current, deps);
}

Resolution resolveSidecar(const std::filesystem::path& backing,
                          const std::optional<EncryptionState>& state,
                          const Crypto& crypto) {
    const auto sidecar = sidecarPathFor(backing);
    std::error_code ec;
    if (!std::filesystem::exists(std::filesystem::symlink_status(sidecar, ec))) return Resolution::None;

    const auto dir = backing.parent_path();
    const auto discard = [&](const std::string_view why) {
        std::filesystem::remove(sidecar);
        fsyncDirectoryQuietly(dir);
        log::Registry::sync()->info("[KeyRotation] Discarded {}: {}", sidecar.string(), why);
        return Resolution::Discarded;
    };

    const bool backingExists = std::filesystem::exists(std::filesystem::symlink_status(backing, ec));

    if (!state) {
        if (!backingExists) return discard("no file row and no backing file reference it");
        log::Registry::sync()->error(
            "[KeyRotation] {} has no file row but its backing file exists; keeping both for an operator",
            sidecar.string());
        return Resolution::Unresolved;
    }

    // Sidecars only ever hold ciphertext; a row that says its bytes are not encrypted does not describe one.
    if (!state->encrypted()) return discard("the row says its bytes are not encrypted");

    const auto authenticates = [&](const std::filesystem::path& path) {
        try {
            return crypto.fileAuthenticates(path, *state);
        } catch (const std::exception& e) {
            log::Registry::sync()->warn("[KeyRotation] Could not verify {}: {}", log::path(path), e.what());
            return false;
        }
    };

    if (authenticates(sidecar)) {
        std::filesystem::rename(sidecar, backing);
        fsyncDirectoryQuietly(dir);
        log::Registry::sync()->info("[KeyRotation] Promoted {}: the row already describes it", sidecar.string());
        return Resolution::Promoted;
    }

    if (backingExists && authenticates(backing)) return discard("the backing file is what the row describes");

    log::Registry::sync()->error(
        "[KeyRotation] Neither {} nor its backing file authenticates under the row's IV (key version {}); keeping "
        "both, the rotation stays in progress",
        sidecar.string(), state->key_version);
    return Resolution::Unresolved;
}

RecoveryReport recoverSidecars(const std::filesystem::path& root, const BackingLookup& lookup, const Deps& deps) {
    RecoveryReport report;
    std::error_code ec;
    if (root.empty() || !std::filesystem::is_directory(root, ec)) return report;

    std::vector<std::filesystem::path> sidecars;
    std::filesystem::recursive_directory_iterator it(root, std::filesystem::directory_options::skip_permission_denied, ec);
    for (; !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec)) {
        std::error_code typeEc;
        if (isSidecar(it->path()) && it->is_regular_file(typeEc)) sidecars.push_back(it->path());
    }
    if (ec) {
        // A sidecar the walk missed could be the only copy its row describes: never finish on a partial walk.
        ++report.unresolved;
        log::Registry::sync()->error("[KeyRotation] Could not scan {} for rotation sidecars: {}", root.string(),
                                     ec.message());
    }

    for (const auto& sidecar : sidecars) {
        const auto backing = backingPathForSidecar(sidecar);
        Resolution resolution = Resolution::Unresolved;
        FileSP file;
        try {
            file = lookup ? lookup(backing) : nullptr;
            const auto state = file ? std::make_optional(stateOf(*file)) : std::nullopt;
            resolution = resolveSidecar(backing, state, deps.crypto);
        } catch (const std::exception& e) {
            log::Registry::sync()->error("[KeyRotation] Could not resolve {}: {}", sidecar.string(), e.what());
        }

        switch (resolution) {
            case Resolution::Promoted:
                ++report.promoted;
                if (file) notifyCommitted(deps, file);
                break;
            case Resolution::Discarded: ++report.discarded; break;
            case Resolution::None: break;
            case Resolution::Unresolved: ++report.unresolved; break;
        }
    }
    return report;
}

void BatchResult::merge(const BatchResult& other) {
    rotated += other.rotated;
    skipped += other.skipped;
    deferred += other.deferred;
    conflicts += other.conflicts;
    failures.insert(failures.end(), other.failures.begin(), other.failures.end());
    aborted = aborted || other.aborted;
}

BatchResult rotateRange(const std::vector<FileSP>& files, const std::size_t begin, const std::size_t end,
                        const Deps& deps) {
    BatchResult result;
    const auto last = std::min(end, files.size());
    for (std::size_t i = begin; i < last; ++i) {
        const auto& file = files[i];
        if (!file) {
            ++result.skipped;
            continue;
        }

        try {
            switch (rotateFile(file, deps)) {
                case Outcome::Rotated: ++result.rotated; break;
                case Outcome::Skipped: ++result.skipped; break;
                case Outcome::Deferred:
                    ++result.deferred;
                    log::Registry::sync()->info("[KeyRotation] {} is open for writing; rotating it next pass",
                                                log::file(file->id, file->path));
                    break;
                case Outcome::Conflict:
                    ++result.conflicts;
                    log::Registry::sync()->info("[KeyRotation] {} changed while it was being rotated; re-reading it "
                                                "next pass", log::file(file->id, file->path));
                    break;
            }
        } catch (const SimulatedCrash&) {
            throw;
        } catch (const storage::s3::RequestBudgetExceeded& e) {
            result.failures.push_back({file->path, e.what()});
            result.aborted = true;
            log::Registry::sync()->warn("[KeyRotation] S3 request budget exhausted at {}: {}", log::file(file->id, file->path),
                                        e.what());
            break;
        } catch (const std::exception& e) {
            result.failures.push_back({file->path, e.what()});
            log::Registry::sync()->error("[KeyRotation] Failed to rotate {}: {}", log::file(file->id, file->path), e.what());
        } catch (...) {
            result.failures.push_back({file->path, "unknown error"});
            log::Registry::sync()->error("[KeyRotation] Failed to rotate {}: unknown error", log::file(file->id, file->path));
        }
    }
    return result;
}

std::vector<std::pair<std::size_t, std::size_t>> splitRanges(const std::size_t n, const std::size_t maxParts) {
    std::vector<std::pair<std::size_t, std::size_t>> ranges;
    if (n == 0) return ranges;
    const auto parts = std::clamp<std::size_t>(maxParts, 1, n);
    const auto base = n / parts;
    const auto extra = n % parts;
    std::size_t begin = 0;
    for (std::size_t i = 0; i < parts; ++i) {
        const auto size = base + (i < extra ? 1 : 0);
        ranges.emplace_back(begin, begin + size);
        begin += size;
    }
    return ranges;
}

PassResult runPass(const PassDeps& deps) {
    PassResult result;
    if (!deps.inProgress()) return result;

    result.status = PassStatus::Incomplete;
    result.keyVersion = deps.keyVersion();

    if (deps.recover) {
        try {
            result.recovery = deps.recover();
        } catch (const std::exception& e) {
            ++result.recovery.unresolved;
            log::Registry::sync()->error("[KeyRotation] Sidecar recovery failed: {}", e.what());
        }
    }

    if (const auto files = deps.pending(result.keyVersion); !files.empty()) {
        result.attempted = files.size();
        result.batch = deps.rotateAll(files);
    }

    if (deps.reconcile) {
        try {
            deps.reconcile();
        } catch (const std::exception& e) {
            result.reconcileError = e.what();
        }
    }

    // What decides completion is the database, re-read after the work: not the work's own bookkeeping.
    result.remaining = deps.pending(result.keyVersion).size();

    if (result.recovery.unresolved == 0 && result.batch.failures.empty() && !result.batch.aborted &&
        result.reconcileError.empty() && result.remaining == 0) {
        deps.finish();
        result.status = PassStatus::Finished;
    }
    return result;
}

}
