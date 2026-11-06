#include "vault/FormatConversion.hpp"

#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "log/Redact.hpp"
#include "log/Registry.hpp"
#include "platform/Durable.hpp"
#include "storage/PlaintextReader.hpp"

#include <fmt/format.h>
#include <sodium.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <stdexcept>
#include <sys/stat.h>
#include <system_error>
#include <unistd.h>

namespace vh::vault::conversion {

namespace {

namespace sfs = std::filesystem;
namespace rotation = sync::rotation;

constexpr std::size_t kFailuresKept = 50;

// The pass reports a failure under the item's label; the reason says only what went wrong.
[[noreturn]] void fail(const std::string_view why) { throw std::runtime_error(std::string(why)); }

struct OutFd {
    explicit OutFd(const int f) : fd(f) {}
    OutFd(const OutFd&) = delete;
    OutFd& operator=(const OutFd&) = delete;
    ~OutFd() { closeQuietly(); }
    void closeQuietly() noexcept {
        if (fd >= 0) ::close(fd);
        fd = -1;
    }
    int fd;
};

// BLAKE2b-256 of a plaintext stream; the state is wiped whatever happens.
class PlaintextDigest {
public:
    PlaintextDigest() { crypto_generichash_init(&state_, nullptr, 0, Digest{}.size()); }
    ~PlaintextDigest() { sodium_memzero(&state_, sizeof state_); }
    PlaintextDigest(const PlaintextDigest&) = delete;
    PlaintextDigest& operator=(const PlaintextDigest&) = delete;

    void update(const std::span<const uint8_t> bytes) {
        crypto_generichash_update(&state_, bytes.data(), bytes.size());
        size_ += bytes.size();
    }
    [[nodiscard]] Digest finish() {
        Digest out{};
        crypto_generichash_final(&state_, out.data(), out.size());
        return out;
    }
    [[nodiscard]] uint64_t size() const { return size_; }

private:
    crypto_generichash_state state_{};
    uint64_t size_{};
};

void writeAll(const int fd, std::span<const uint8_t> bytes, const sfs::path& path) {
    while (!bytes.empty()) {
        const auto n = ::write(fd, bytes.data(), bytes.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            throw std::system_error(errno, std::generic_category(), "write " + path.string());
        }
        bytes = bytes.subspan(static_cast<std::size_t>(n));
    }
}

void unlinkQuietly(const sfs::path& p) noexcept {
    if (p.empty()) return;
    if (::unlink(p.c_str()) != 0 && errno != ENOENT)
        log::Registry::crypto()->warn("[FormatConversion] Could not remove {}: {}", log::path(p), std::strerror(errno));
}

void fsyncDirectoryQuietly(const sfs::path& dir) noexcept {
    try {
        fs::ops::fsyncDirectory(dir);
    } catch (const std::exception& e) {
        log::Registry::crypto()->warn("[FormatConversion] Could not fsync directory {}: {}", log::path(dir), e.what());
    }
}

void reached(const Deps& deps, const Step step, const std::string_view what) {
    if (deps.afterStep) deps.afterStep(step, what);
}

void checkBlocked(const Deps& deps) {
    if (!deps.blocked) return;
    if (auto why = deps.blocked()) throw Blocked{std::move(*why)};
}

// A gcm0 generation, or nothing to do. A malformed id is damage: never guessed, never converted.
bool isLegacy(const std::string& generation) {
    try {
        return content::formatOf(generation) == content::Format::Gcm0;
    } catch (const std::invalid_argument&) {
        fail("malformed generation id");
    }
}

// The sidecar replaces the backing file, so it takes its permission bits (as rotation's does).
mode_t modeOf(const sfs::path& backing) {
    struct stat st{};
    if (::stat(backing.c_str(), &st) == 0 && S_ISREG(st.st_mode)) return st.st_mode & 07777;
    return 0600;
}

uint64_t sizeOf(const sfs::path& p) {
    std::error_code ec;
    const auto size = sfs::file_size(p, ec);
    if (ec) throw std::system_error(ec, "size of " + p.string());
    return size;
}

// The legacy bytes on disk must hold exactly the plaintext size the catalog records: a VHF1 reader takes its size
// from there, so converting a row whose size drifted would turn a readable file into an unreadable one.
void requireRecordedSize(const sfs::path& src, const uint64_t recorded) {
    const auto held = content::plaintextSizeOf(sizeOf(src), content::Format::Gcm0);
    if (!held || *held != recorded)
        fail(fmt::format("the stored bytes don't hold the recorded size ({} bytes); not converted", recorded));
}

}

std::string_view to_string(const Step step) {
    switch (step) {
    case Step::Staged: return "staged";
    case Step::Linked: return "linked";
    case Step::Committed: return "committed";
    case Step::Replaced: return "replaced";
    }
    return "unknown";
}

std::string_view to_string(const Outcome outcome) {
    switch (outcome) {
    case Outcome::Converted: return "converted";
    case Outcome::Skipped: return "skipped";
    case Outcome::Deferred: return "deferred";
    case Outcome::Conflict: return "conflict";
    }
    return "unknown";
}

Converted convertFile(const sfs::path& src, const content::Binding& from, const crypto::SecretKey& key,
                      const sfs::path& dst, const mode_t mode, const crypto::id::ObjectUid& objectUid) {
    if (content::formatOf(from.generation) != content::Format::Gcm0)
        throw std::invalid_argument("Only a legacy (gcm0) generation is converted: " + src.string());

    OutFd out(::open(dst.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, mode));
    if (out.fd < 0) throw std::system_error(errno, std::generic_category(), "create " + dst.string());
    try {
        if (::fchmod(out.fd, mode) != 0) throw std::system_error(errno, std::generic_category(), "chmod " + dst.string());

        // 1. Legacy tag over the whole input (openFileTo throws at the end otherwise), plaintext digest as it streams.
        //    What reaches the sealer before the tag is checked is only ever written sealed, and discarded on a throw.
        Converted result;
        PlaintextDigest input;
        {
            content::Sealer sealer(key, from.keyVersion, from.vaultUid, objectUid,
                                   [&](const std::span<const uint8_t> bytes) { writeAll(out.fd, bytes, dst); });
            content::openFileTo(src, from, key, [&](const std::span<const uint8_t> plain) {
                input.update(plain);
                sealer.write(plain);
            });
            sealer.finish();
            result.generation = sealer.generation();
            result.sealedBytes = sealer.objectSize();
        }
        result.plaintextBytes = input.size();
        result.digest = input.finish();
        if (platform::durable::sync(out.fd) != 0)
            throw std::system_error(errno, std::generic_category(), "fsync " + dst.string());
        out.closeQuietly();

        // 2. The output as a reader will see it: its size, then a full chunk walk bound to vault, salt, key version and
        //    object, with its own plaintext digest.
        if (sizeOf(dst) != content::sealedSize(result.plaintextBytes, content::Format::Vhf1) ||
            sizeOf(dst) != result.sealedBytes)
            throw storage::IntegrityError("The converted generation has the wrong size");
        PlaintextDigest output;
        content::openFileTo(dst,
                            {.vaultUid = from.vaultUid, .generation = result.generation, .keyVersion = from.keyVersion,
                             .objectUid = objectUid},
                            key, [&](const std::span<const uint8_t> plain) { output.update(plain); });
        const auto outputSize = output.size();
        const auto outputDigest = output.finish();

        // 3. Same plaintext.
        if (outputSize != result.plaintextBytes ||
            sodium_memcmp(outputDigest.data(), result.digest.data(), result.digest.size()) != 0)
            throw storage::IntegrityError("The converted generation's plaintext differs from the original's");
        return result;
    } catch (...) {
        out.closeQuietly();
        unlinkQuietly(dst);
        throw;
    }
}

Outcome convertLiveFile(const FileSP& file, const Deps& deps, ItemStats& stats) {
    if (!file) return Outcome::Skipped;
    const auto what = log::file(file->id, file->path);
    const auto expected = rotation::stateOf(*file);
    if (!isLegacy(expected.iv_b64)) return Outcome::Skipped;

    std::unique_lock<std::mutex> contentLock;
    if (deps.rotation.catalog.lock) contentLock = deps.rotation.catalog.lock(file);
    checkBlocked(deps);
    if (deps.rotation.catalog.current) {
        if (const auto stored = deps.rotation.catalog.current(file); !stored || !(*stored == expected))
            return Outcome::Conflict;
    }
    if (deps.rotation.catalog.busy && deps.rotation.catalog.busy(file)) return Outcome::Deferred;

    const auto& backing = file->backing_path;
    const auto dir = backing.parent_path();
    const auto sidecar = rotation::sidecarPathFor(backing);
    std::error_code ec;
    // A sidecar an interrupted write or rotation left: settled by authentication, as startup recovery would.
    if (sfs::exists(sfs::symlink_status(sidecar, ec)) &&
        rotation::resolveSidecar(backing, expected, deps.rotation.crypto) == rotation::Resolution::Unresolved)
        fail("a sidecar from an interrupted write could not be resolved");

    if (!sfs::is_regular_file(backing, ec)) {
        if (!deps.plaintextUpstream) fail("the backing file is missing");
        // Nothing sealed exists for this row anywhere (the bucket holds plaintext, there is no local copy): its legacy
        // generation id is stale metadata, cleared as key rotation clears it. The next download seals VHF1.
        auto next = std::make_shared<fs::model::File>(*file);
        next->encryption_iv.clear();
        next->encrypted_with_key_version = 0;
        if (!deps.commitFile(*next, expected, std::nullopt).file) return Outcome::Conflict;
        file->encryption_iv.clear();
        file->encrypted_with_key_version = 0;
        if (deps.rotation.catalog.committed) deps.rotation.catalog.committed(file);
        return Outcome::Converted;
    }

    if (!file->object_uid) fail("the file has no object uid");
    const auto key = deps.liveKey(expected.key_version);
    if (!key) fail(fmt::format("key version {} is not the vault's current key", expected.key_version));
    requireRecordedSize(backing, file->size_bytes);
    stats.bytesRead = sizeOf(backing);

    const auto shared = deps.sharedBlob ? deps.sharedBlob(expected.iv_b64, expected.key_version) : std::nullopt;

    const content::Binding from{.vaultUid = deps.vaultUid, .generation = expected.iv_b64,
                                .keyVersion = expected.key_version, .objectUid = file->object_uid};
    const auto converted = convertFile(backing, from, *key, sidecar, modeOf(backing), *file->object_uid);

    std::optional<BlobSwap> swap;
    sfs::path linked, oldBlob;
    const auto cleanup = [&] {
        unlinkQuietly(sidecar);
        unlinkQuietly(linked);
    };
    try {
        fs::ops::fsyncDirectory(dir);
        reached(deps, Step::Staged, what);

        // The blob of the same generation becomes a hard link of the converted bytes: one conversion for both, and the
        // store keeps sharing the live file's inode.
        if (shared && shared->plaintextBytes == converted.plaintextBytes) {
            const auto name = deps.newStorageName();
            linked = deps.blobPath(name);
            oldBlob = deps.blobPath(shared->storageName);
            if (deps.prepareBlobDir) deps.prepareBlobDir(linked.parent_path());
            if (::link(sidecar.c_str(), linked.c_str()) != 0)
                throw std::system_error(errno, std::generic_category(), "link " + linked.string());
            fs::ops::fsyncDirectory(linked.parent_path());
            swap = BlobSwap{.id = shared->id, .keyVersion = shared->keyVersion,
                            .fromGeneration = shared->generation, .fromStorageName = shared->storageName,
                            .toGeneration = converted.generation, .toStorageName = name,
                            .cipherBytes = converted.sealedBytes};
            reached(deps, Step::Linked, what);
        }

        if (deps.rotation.catalog.busy && deps.rotation.catalog.busy(file)) {
            cleanup();
            return Outcome::Deferred;
        }
    } catch (const SimulatedCrash&) {
        throw;
    } catch (...) {
        cleanup();
        throw;
    }

    auto next = std::make_shared<fs::model::File>(*file);
    next->encryption_iv = converted.generation;
    // If the transaction throws, whether it took effect is unknown: both files stay, and recovery keeps whichever copy
    // authenticates under what the row says (the sweep removes whichever store file ends up unreferenced).
    const auto commit = deps.commitFile(*next, expected, swap);
    if (!commit.file) {
        cleanup();
        return Outcome::Conflict;
    }
    if (swap && !commit.blob) {
        unlinkQuietly(linked);  // the blob was removed or changed meanwhile: the link is nobody's
        swap.reset();
    }
    file->encryption_iv = converted.generation;
    reached(deps, Step::Committed, what);

    // From here the sidecar is what the row describes; a failed rename leaves it for recovery to promote.
    sfs::rename(sidecar, backing);
    fsyncDirectoryQuietly(dir);
    if (swap) {
        unlinkQuietly(oldBlob);
        fsyncDirectoryQuietly(oldBlob.parent_path());
        stats.blobConverted = true;
    }
    reached(deps, Step::Replaced, what);

    if (deps.rotation.catalog.committed) {
        try {
            deps.rotation.catalog.committed(file);
        } catch (const std::exception& e) {
            log::Registry::crypto()->warn("[FormatConversion] {} converted, but refreshing cached metadata failed: {}",
                                          what, e.what());
        }
    }
    if (swap && deps.usageChanged) deps.usageChanged();
    return Outcome::Converted;
}

Outcome convertBlob(const Blob& blob, const Deps& deps, ItemStats& stats) {
    const auto what = fmt::format("recovery blob {}", blob.id);
    if (!isLegacy(blob.generation)) return Outcome::Skipped;
    checkBlocked(deps);

    const auto key = deps.historicalKey(blob.keyVersion);
    if (!key) fail(fmt::format("key version {} is not held", blob.keyVersion));
    const auto src = deps.blobPath(blob.storageName);
    std::error_code ec;
    if (!sfs::is_regular_file(src, ec)) fail("its file is missing");
    requireRecordedSize(src, blob.plaintextBytes);
    stats.bytesRead = sizeOf(src);

    // A fresh store name: nothing references it until the row does, so an interrupted conversion leaves only an
    // unreferenced file for the sweep.
    const auto name = deps.newStorageName();
    const auto dst = deps.blobPath(name);
    if (deps.prepareBlobDir) deps.prepareBlobDir(dst.parent_path());
    const auto objectUid = blob.objectUid.value_or(crypto::id::newObjectUid());
    const content::Binding from{.vaultUid = deps.vaultUid, .generation = blob.generation, .keyVersion = blob.keyVersion};
    const auto converted = convertFile(src, from, *key, dst, 0600, objectUid);
    if (converted.plaintextBytes != blob.plaintextBytes) {
        unlinkQuietly(dst);
        fail("the converted size differs from the recorded one");
    }

    const BlobSwap swap{.id = blob.id, .keyVersion = blob.keyVersion, .fromGeneration = blob.generation,
                        .fromStorageName = blob.storageName, .toGeneration = converted.generation,
                        .toStorageName = name, .cipherBytes = converted.sealedBytes};
    try {
        fs::ops::fsyncDirectory(dst.parent_path());
        reached(deps, Step::Staged, what);
    } catch (const SimulatedCrash&) {
        throw;
    } catch (...) {
        unlinkQuietly(dst);
        throw;
    }

    // A throw here leaves dst: referenced if the transaction took effect, otherwise swept.
    if (!deps.commitBlob(swap)) {
        unlinkQuietly(dst);
        return Outcome::Conflict;
    }
    reached(deps, Step::Committed, what);

    unlinkQuietly(src);
    fsyncDirectoryQuietly(src.parent_path());
    reached(deps, Step::Replaced, what);
    if (deps.usageChanged) deps.usageChanged();
    return Outcome::Converted;
}

std::chrono::nanoseconds pauseAfter(const Limits& limits, const uint64_t bytes, const std::chrono::nanoseconds busy) {
    using std::chrono::nanoseconds;
    nanoseconds pause{0};
    if (limits.maxBytesPerSecond > 0 && bytes > 0) {
        // The time `bytes` may take at the limit (long double: no overflow for any file size), minus the time it took.
        const auto allowed = static_cast<long double>(bytes) * 1e9L / static_cast<long double>(limits.maxBytesPerSecond);
        const auto wait = allowed - static_cast<long double>(busy.count());
        if (wait > 0) pause = nanoseconds(static_cast<nanoseconds::rep>(wait));
    }
    const auto cpu = std::clamp(limits.maxCpuPercent, 1u, 100u);
    if (cpu < 100 && busy.count() > 0) {
        // busy / (busy + idle) = cpu%  =>  idle = busy * (100 - cpu) / cpu
        const auto idle = nanoseconds(busy.count() / cpu * (100 - cpu) + busy.count() % cpu * (100 - cpu) / cpu);
        pause = std::max(pause, idle);
    }
    return pause;
}

PassResult runPass(const PassDeps& deps) {
    PassResult result;
    const auto now = [&] { return deps.now ? deps.now() : std::chrono::steady_clock::now(); };
    const auto stopping = [&] { return deps.stop && deps.stop(); };
    const auto addFailure = [&](std::string path, std::string reason) {
        ++result.failed;
        if (result.failures.size() < kFailuresKept) result.failures.push_back({std::move(path), std::move(reason)});
    };

    // Runs one item, counts it, paces the worker. False: stop the pass (blocked, stopping).
    const auto run = [&](const std::string& label, const auto& convert) -> bool {
        if (stopping()) {
            result.stopped = true;
            return false;
        }
        ItemStats stats;
        const auto started = now();
        try {
            const auto [outcome, isBlob] = convert(stats);
            switch (outcome) {
            case Outcome::Converted:
                if (isBlob) ++result.blobs;
                else if (stats.bytesRead == 0) ++result.cleared;
                else ++result.files;
                if (stats.blobConverted) ++result.blobs;
                result.bytes += stats.bytesRead;
                break;
            case Outcome::Skipped: ++result.skipped; break;
            case Outcome::Deferred: ++result.deferred; break;
            case Outcome::Conflict: ++result.conflicts; break;
            }
        } catch (const Blocked& b) {
            result.blocked = b.reason;
            return false;
        } catch (const SimulatedCrash&) {
            throw;
        } catch (const std::exception& e) {
            addFailure(label, e.what());
            log::Registry::crypto()->error("[FormatConversion] {} was not converted: {}", label, e.what());
        }
        const auto busy = std::chrono::duration_cast<std::chrono::nanoseconds>(now() - started);
        if (const auto pause = pauseAfter(deps.limits, stats.bytesRead, busy); pause.count() > 0 && deps.pause)
            deps.pause(pause);
        return true;
    };

    if (deps.item.blocked) {
        if (auto why = deps.item.blocked()) {
            result.blocked = std::move(why);
            return result;
        }
    }
    const auto batch = std::max<std::size_t>(deps.batch, 1);

    if (deps.convertLiveFiles && deps.liveFiles) {
        uint32_t after = 0;
        for (;;) {
            const auto page = deps.liveFiles(after, batch);
            for (const auto& file : page) {
                if (!file) continue;
                after = std::max(after, file->id);
                if (!run(log::file(file->id, file->path), [&](ItemStats& s) {
                        return std::pair{convertLiveFile(file, deps.item, s), false};
                    }))
                    return result;
            }
            if (page.size() < batch) break;
        }
    }

    if (deps.blobs) {
        int64_t after = 0;
        for (;;) {
            const auto page = deps.blobs(after, batch);
            for (const auto& blob : page) {
                after = std::max(after, blob.id);
                if (!run(fmt::format("recovery blob {}", blob.id), [&](ItemStats& s) {
                        return std::pair{convertBlob(blob, deps.item, s), true};
                    }))
                    return result;
            }
            if (page.size() < batch) break;
        }
    }
    return result;
}

}
