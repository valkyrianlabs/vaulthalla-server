#include "mirror/Contents.hpp"

#include "concurrency/ThreadPoolManager.hpp"
#include "config/Registry.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/peer/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/ops/file.hpp"
#include "log/Registry.hpp"
#include "peer/Links.hpp"
#include "platform/Durable.hpp"
#include "platform/StagedFile.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"

#include <fmt/format.h>

#include <paths.h>

#include <cerrno>
#include <cstdlib>
#include <filesystem>
#include <fcntl.h>
#include <future>
#include <algorithm>
#include <atomic>
#include <map>
#include <mutex>
#include <sys/stat.h>
#include <thread>
#include <tuple>
#include <unistd.h>

namespace vh::mirror::contents {

namespace {

using db::query::mirror::Expected;
using db::query::mirror::MirrorVault;
using db::query::mirror::MirrorVaults;
using db::query::mirror::PendingContents;
using db::query::mirror::SealedObjects;
using peer::object::FetchStatus;
using Clock = std::chrono::steady_clock;

[[noreturn]] void throwErrno(const int err, const std::string& what) {
    throw std::system_error(err, std::generic_category(), what);
}

void writeAll(const int fd, std::span<const uint8_t> bytes) {
    while (!bytes.empty()) {
        const auto n = ::write(fd, bytes.data(), bytes.size());
        if (n < 0) {
            if (errno == EINTR) continue;
            throwErrno(errno, "write received bytes");
        }
        bytes = bytes.subspan(static_cast<std::size_t>(n));
    }
}

uint64_t fdSize(const int fd) {
    struct stat st{};
    if (::fstat(fd, &st) != 0) throwErrno(errno, "stat received bytes");
    return static_cast<uint64_t>(st.st_size);
}

// The received bytes until they are verified: an unnamed file in the backing file's directory (Linux O_TMPFILE: a
// crash leaves nothing, and nothing can open it), or where there is none (macOS) a private O_EXCL sibling removed on
// every path but success. Nothing reads it as the file until linkInto() renames it over the backing path.
class Staged {
public:
    explicit Staged(const std::filesystem::path& backing) : backing_(backing) {
        std::error_code ec;
        std::filesystem::create_directories(backing.parent_path(), ec);
        fd_ = platform::staged::openUnnamed(backing.parent_path().c_str());
        if (fd_ >= 0) return;
        named_ = backing;
        named_ += ".vh-receive-" + vh::fs::ops::generate_random_suffix(12);
        fd_ = ::open(named_.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
        if (fd_ < 0) throwErrno(errno, "create " + named_.string());
    }
    ~Staged() {
        if (fd_ >= 0) ::close(fd_);
        if (!named_.empty() && !linked_) {
            std::error_code ec;
            std::filesystem::remove(named_, ec);
        }
    }
    Staged(const Staged&) = delete;
    Staged& operator=(const Staged&) = delete;

    [[nodiscard]] int fd() const noexcept { return fd_; }

    // The verified bytes become the backing file: the modification time set, flushed, linked at the content sidecar
    // (which startup recovery promotes if a crash comes next: it authenticates under the row) and renamed over the
    // backing path (replacing an older generation's bytes, never writing them in place), the directory flushed. The
    // caller holds the file's content lock and the row's compare-and-set.
    void linkInto(const int64_t mtimeUs) {
        const timespec times[2] = {{.tv_sec = 0, .tv_nsec = UTIME_OMIT},
                                   {.tv_sec = static_cast<time_t>(mtimeUs / 1'000'000),
                                    .tv_nsec = static_cast<long>((mtimeUs % 1'000'000) * 1000)}};
        if (::fchmod(fd_, 0600) != 0) throwErrno(errno, "chmod received bytes");
        if (::futimens(fd_, times) != 0) throwErrno(errno, "set the modification time");
        if (platform::durable::sync(fd_) != 0) throwErrno(errno, "flush received bytes");
        const auto sidecar = vh::fs::ops::contentSidecarPath(backing_);
        std::error_code ec;
        std::filesystem::remove(sidecar, ec);  // a leftover; the content lock is held
        if (named_.empty()) {
            if (platform::staged::linkUnnamed(fd_, sidecar.c_str()) != 0) throwErrno(errno, "link " + sidecar.string());
        } else if (::link(named_.c_str(), sidecar.c_str()) != 0) {
            throwErrno(errno, "link " + sidecar.string());
        }
        linked_ = true;
        if (!named_.empty()) std::filesystem::remove(named_, ec);
        std::filesystem::rename(sidecar, backing_);
        vh::fs::ops::fsyncDirectory(backing_.parent_path());
    }

private:
    std::filesystem::path backing_;
    std::filesystem::path named_;
    int fd_{-1};
    bool linked_{false};
};

// The vault's linked server, over the sealed lane: fails fast (Unreachable) while the link is not up, so an open never
// waits on a dial that cannot succeed.
class PeerSource final : public Source {
public:
    PeerSource(const uint32_t peerId, const vh::crypto::id::ObjectUid& vaultUid, Expected expected)
        : peerId_(peerId), vaultUid_(vaultUid), expected_(std::move(expected)),
          deadline_(Clock::now() + kTransferDeadline) {}

    SourceResult read(const uint64_t offset, const uint64_t sealedSize, const std::function<bool()>& cancelled,
                      const peer::object::Sink& sink) override {
        if (!vh::config::Registry::get().peers.experimental) return {FetchStatus::Unreachable, "peers.experimental is off"};
        const auto links = peer::linkService();
        if (!links) return {FetchStatus::Unreachable, "the link service is not running"};
        const auto row = db::query::peer::Peers::byId(peerId_);
        if (!row || row->revoked()) return {FetchStatus::Unreachable, "the vault's linked server is no longer linked"};
        if (!links->health(peerId_).connected)
            return {FetchStatus::Unreachable, "the link to " + row->name + " is down"};
        peer::object::FetchOptions options;
        options.tls = links->clientTls();
        options.offset = offset;
        options.expectedSize = sealedSize;
        options.deadline = deadline_;
        options.cancelled = cancelled;
        const auto r = peer::object::fetch(
            *row, {.vault = vaultUid_, .object = expected_.object_uid, .generation = expected_.generation}, options, sink);
        std::string error = r.error;
        if (r.status == FetchStatus::Refused && !r.code.empty()) error = r.code + ": " + r.error;
        return {r.status, std::move(error)};
    }

private:
    uint32_t peerId_;
    vh::crypto::id::ObjectUid vaultUid_;
    Expected expected_;
    Clock::time_point deadline_;
};

std::mutex& factoryMutex() {
    static std::mutex m;
    return m;
}

SourceFactory& testFactory() {
    static SourceFactory f;
    return f;
}

std::shared_ptr<vh::storage::Engine> engineOf(const uint32_t vaultId) {
    const auto& manager = runtime::Deps::get().storageManager;
    return manager ? manager->getEngine(vaultId) : nullptr;
}

std::unique_ptr<Source> sourceFor(const MirrorVault& mirror, const Expected& e) {
    {
        std::scoped_lock lock(factoryMutex());
        if (testFactory()) return testFactory()(mirror, e);
    }
    const auto engine = engineOf(mirror.vault_id);
    if (!engine || !engine->encryptionManager) return nullptr;
    return std::make_unique<PeerSource>(mirror.peer_id, engine->encryptionManager->vaultUid(), e);
}

// Why the vault's linked server cannot be reached now, when it cannot: the switch, the row, the link's health. Nothing
// when a test supplies the bytes.
std::optional<std::string> linkDownReason(const MirrorVault& mirror, peer::LinkService& links) {
    {
        std::scoped_lock lock(factoryMutex());
        if (testFactory()) return std::nullopt;
    }
    if (!vh::config::Registry::get().peers.experimental) return "peers.experimental is off";
    const auto row = db::query::peer::Peers::byId(mirror.peer_id);
    if (!row || row->revoked()) return "the vault's linked server is no longer linked";
    if (!links.health(mirror.peer_id).connected) return "the link to " + row->name + " is down";
    return std::nullopt;
}

// Mount opens waiting now, and a cap fixed by a test.
std::atomic<unsigned>& mountWaiters() {
    static std::atomic<unsigned> n{0};
    return n;
}

std::atomic<unsigned>& testMountCap() {
    static std::atomic<unsigned> n{0};
    return n;
}

// One waiting mount open, released on every way out of the wait.
class MountWait {
public:
    // Takes a place when one is free under the cap.
    MountWait() {
        const auto cap = mountWaitCap();
        auto n = mountWaiters().load(std::memory_order_relaxed);
        while (n < cap)
            if (mountWaiters().compare_exchange_weak(n, n + 1, std::memory_order_acq_rel)) {
                held_ = true;
                return;
            }
    }
    ~MountWait() {
        if (held_) mountWaiters().fetch_sub(1, std::memory_order_acq_rel);
    }
    MountWait(const MountWait&) = delete;
    MountWait& operator=(const MountWait&) = delete;
    [[nodiscard]] bool held() const noexcept { return held_; }

private:
    bool held_{false};
};

// One fetch per file however many opens wait for it.
using Key = std::tuple<uint32_t, std::string, std::string>;  // vault, object uid, generation

std::mutex& inflightMutex() {
    static std::mutex m;
    return m;
}

std::map<Key, std::shared_future<Result>>& inflight() {
    static std::map<Key, std::shared_future<Result>> m;
    return m;
}

Result failure(const Expected& e, const std::string& reason) {
    const auto row = PendingContents::recordFailure(e.vault_id, e.object_uid, e.generation, reason);
    if (!row) return {.outcome = Outcome::Superseded, .reason = "the file changed while it was being fetched"};
    log::Registry::storage()->warn("[MirrorContents] Vault {}: {} of {} failed: {}{}", e.vault_id,
                                   vl::keykit::toBase32(e.object_uid), e.generation.substr(0, 12), reason,
                                   row->failed() ? " (no more attempts until it is retried)" : "");
    return {.outcome = Outcome::Failed, .reason = reason, .failedForGood = row->failed()};
}

// The compare-and-set and the link, under the file's content lock: Received, or Superseded when the row or the file
// moved on (nothing is linked then).
Result commit(const Expected& e, const uint32_t fileId, Staged* staged) {
    std::scoped_lock contentLock(vh::fs::Filesystem::contentWriteMutex(fileId));
    const auto file = vh::db::query::fs::File::getFileById(fileId);
    if (!file) return {.outcome = Outcome::Superseded, .reason = "the file is gone"};
    const bool linked = db::Transactions::exec("mirror::contents::commit", [&](pqxx::work& txn) {
        const auto locked = PendingContents::lockForLink(txn, e);
        if (!locked || *locked != fileId) return false;
        if (staged) staged->linkInto(e.mtime_us);
        PendingContents::clear(txn, e);
        return true;
    });
    if (!linked) {
        (void)PendingContents::dropSuperseded(e.vault_id, e.object_uid, e.generation);
        return {.outcome = Outcome::Superseded, .reason = "the file changed while it was being fetched"};
    }
    return {.outcome = Outcome::Received};
}

// The bytes at the backing path are already exactly the expected generation's (a crash after the link, before the row
// went): checked as received bytes are.
bool alreadyHeld(const Expected& e, const std::filesystem::path& backing, const vh::vault::content::Binding& binding,
                 const vh::crypto::SecretKey& key) {
    const int fd = ::open(backing.c_str(), O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return false;
    bool held = false;
    try {
        held = fdSize(fd) == vh::vault::content::sealedSizeOf(e.size_bytes, e.generation) &&
               vh::crypto::hash::blake2bFd(fd) == e.content_hash &&
               vh::vault::content::verifyFd(fd, e.size_bytes, binding, key);
    } catch (const std::exception&) {
        held = false;
    }
    ::close(fd);
    return held;
}

}

std::string_view codeOf(const Reason r) {
    switch (r) {
        case Reason::LinkDown: return "mirror_link_down";
        case Reason::TimedOut: return "mirror_fetch_timeout";
        case Reason::Failed: return "mirror_fetch_failed";
        case Reason::Missing: return "mirror_contents_missing";
    }
    return "mirror_fetch_failed";
}

int errnoOf(const Reason r) {
    switch (r) {
        case Reason::LinkDown: return ENOLINK;
        case Reason::TimedOut: return ETIMEDOUT;
        case Reason::Failed:
        case Reason::Missing: return ENODATA;
    }
    return ENODATA;
}

NotReceived::NotReceived(const Reason reason, const std::string& detail)
    : std::system_error(errnoOf(reason), std::generic_category(), std::string(codeOf(reason)) + ": " + detail),
      reason_(reason) {}

std::optional<std::string_view> reasonCodeIn(const std::string_view message) {
    for (const auto r : {Reason::LinkDown, Reason::TimedOut, Reason::Failed, Reason::Missing}) {
        const auto code = codeOf(r);
        if (message.starts_with(code) && message.size() > code.size() && message[code.size()] == ':') return code;
    }
    return std::nullopt;
}

void setSourceFactoryForTesting(SourceFactory factory) {
    std::scoped_lock lock(factoryMutex());
    testFactory() = std::move(factory);
}

std::string_view toString(const Outcome o) {
    switch (o) {
        case Outcome::Received: return "received";
        case Outcome::LinkDown: return "link_down";
        case Outcome::Failed: return "failed";
        case Outcome::Superseded: return "superseded";
        case Outcome::NotPending: return "not_pending";
        case Outcome::Cancelled: return "cancelled";
    }
    return "unknown";
}

Result receive(const Expected& expected, Source& source, const std::function<bool()>& cancelled) {
    // The row as it is now: a caller's copy may be older.
    const auto current = PendingContents::get(expected.vault_id, expected.object_uid);
    if (!current || current->generation != expected.generation) return {.outcome = Outcome::NotPending};
    const auto& e = *current;
    if (e.failed())
        return {.outcome = Outcome::Failed, .reason = e.last_error.value_or("failed"), .failedForGood = true};

    const auto fileId = SealedObjects::fileIdOf(e.vault_id, e.object_uid);
    const auto file = fileId ? vh::db::query::fs::File::getFileById(*fileId) : nullptr;
    if (!file || file->encryption_iv != e.generation) {
        (void)PendingContents::dropSuperseded(e.vault_id, e.object_uid, e.generation);
        return {.outcome = Outcome::Superseded, .reason = "the file no longer names that generation"};
    }

    vh::vault::content::Format format{};
    try {
        format = vh::vault::content::formatOf(e.generation);
    } catch (const std::invalid_argument&) {
        return failure(e, "not a generation id");
    }
    if (format == vh::vault::content::Format::Plain) {
        // An empty file has no bytes to send (and a plain one with bytes is never sent).
        if (e.size_bytes > 0) return failure(e, "format_not_portable: a plain file with bytes is never sent");
        return commit(e, *fileId, nullptr);
    }
    if (format == vh::vault::content::Format::Gcm0) return failure(e, "format_not_portable: gcm0 binds nothing");

    const auto engine = engineOf(e.vault_id);
    if (!engine || !engine->encryptionManager) return failure(e, "the vault's engine is not loaded");
    vh::crypto::SecretKeyPtr key;
    try {
        key = engine->encryptionManager->keySnapshot(e.key_version);
    } catch (const std::exception& ex) {
        return failure(e, fmt::format("key version {} is not held here: {}", e.key_version, ex.what()));
    }
    if (!key) return failure(e, fmt::format("key version {} is not held here", e.key_version));
    // The header must name this vault, this salt and this key version. Not the object: a local vault's copy keeps its
    // source's sealed bytes (Filesystem::copy), whose header names the source's uid under the same generation.
    const vh::vault::content::Binding binding{.vaultUid = engine->encryptionManager->vaultUid(),
                                               .generation = e.generation, .keyVersion = e.key_version,
                                               .objectUid = std::nullopt};
    const auto sealedSize = vh::vault::content::sealedSizeOf(e.size_bytes, e.generation);

    if (alreadyHeld(e, file->backing_path, binding, *key)) return commit(e, *fileId, nullptr);

    Staged staged(file->backing_path);
    uint64_t written = 0;
    const peer::object::Sink sink = [&](const std::span<const uint8_t> bytes) {
        if (written + bytes.size() > sealedSize) throwErrno(EFBIG, "more bytes than the generation seals to");
        writeAll(staged.fd(), bytes);
        written += bytes.size();
    };
    const auto stop = [&] { return cancelled && cancelled(); };
    std::string lastError;
    for (unsigned attempt = 0;; ++attempt) {
        if (stop()) return {.outcome = Outcome::Cancelled};
        SourceResult r;
        try {
            r = source.read(written, sealedSize, stop, sink);
        } catch (const std::system_error& ex) {
            if (ex.code().value() == EFBIG) return failure(e, ex.what());
            throw;  // the disk: not the file's fault, nothing counted
        }
        if (r.status == FetchStatus::Complete) break;
        if (r.status == FetchStatus::Cancelled) return {.outcome = Outcome::Cancelled, .reason = r.error};
        if (r.status == FetchStatus::Unreachable) return {.outcome = Outcome::LinkDown, .reason = r.error};
        if (r.status == FetchStatus::Refused) return failure(e, r.error);
        lastError = r.error;  // Interrupted: resume from what arrived
        if (attempt >= kMaxResumes)
            return failure(e, fmt::format("the transfer broke off {} times; last: {}", attempt + 1, lastError));
    }

    // Invariant 8, in order: the size, the content hash over the sealed bytes, then authentication of the header and
    // every chunk with the key against the expected binding.
    if (fdSize(staged.fd()) != sealedSize)
        return failure(e, fmt::format("size: {} bytes arrived, the generation seals to {}", fdSize(staged.fd()),
                                      sealedSize));
    if (vh::crypto::hash::blake2bFd(staged.fd()) != e.content_hash)
        return failure(e, "content hash: the bytes are not the ones the log names");
    if (!vh::vault::content::verifyFd(staged.fd(), e.size_bytes, binding, *key))
        return failure(e, "authentication: the bytes do not open under the vault key as that generation");

    auto result = commit(e, *fileId, &staged);
    if (result.outcome == Outcome::Received)
        log::Registry::storage()->info("[MirrorContents] Vault {}: received {} ({} sealed bytes)", e.vault_id,
                                       vl::keykit::toBase32(e.object_uid), sealedSize);
    return result;
}

unsigned mountWaitCap() {
    if (const auto fixed = testMountCap().load(std::memory_order_relaxed)) return fixed;
    unsigned workers = 0;
    if (const auto& pool = vh::concurrency::ThreadPoolManager::instance().fusePool()) workers = pool->workerCount();
    // Before the pools exist (tests, early startup): the size the manager would give the FUSE pool.
    if (workers == 0) workers = std::max(std::thread::hardware_concurrency() * 3u, 8u) / 6u + 1u;
    return std::clamp(workers / 4u, 1u, 4u);
}

void setMountWaitCapForTesting(const unsigned cap) { testMountCap().store(cap, std::memory_order_relaxed); }

unsigned mountWaitersForTesting() { return mountWaiters().load(std::memory_order_acquire); }

bool awaitIfPending(const vh::fs::model::File& file, const std::chrono::milliseconds wait, const Opener opener) {
    if (!file.vault_id || !file.object_uid) return false;
    const auto vaultId = *file.vault_id;
    if (!PendingContents::mayHavePending(vaultId)) return false;
    const auto expected = PendingContents::get(vaultId, *file.object_uid);
    // Nothing pending, or pending for another generation than the row the caller holds (its bytes are whatever is on
    // disk for that row; the newer row arrives with the log).
    if (!expected || expected->generation != file.encryption_iv) return false;
    // A detached vault's file whose contents never arrived (wave 5): it never will; the entry says so, nothing is read.
    if (expected->missing())
        throw NotReceived(Reason::Missing, "this file's contents never arrived from the core before the vault was "
                                           "detached; only the core's copy holds them");
    if (expected->failed())
        throw NotReceived(Reason::Failed, expected->last_error.value_or("fetching this file failed"));

    const auto links = peer::linkService();
    if (!links) throw NotReceived(Reason::LinkDown, "the link service is not running");
    const auto mirror = MirrorVaults::get(vaultId);
    if (!mirror || mirror->role != "mirror") return false;
    // The link down: said at once, without a transfer that could only find it down.
    if (const auto why = linkDownReason(*mirror, *links)) throw NotReceived(Reason::LinkDown, *why);
    const Key key{vaultId, vh::crypto::id::toUuid(*file.object_uid), expected->generation};
    std::shared_future<Result> outcome;
    {
        std::scoped_lock lock(inflightMutex());
        if (const auto it = inflight().find(key); it != inflight().end()) {
            outcome = it->second;
        } else {
            auto promise = std::make_shared<std::promise<Result>>();
            outcome = promise->get_future().share();
            inflight().emplace(key, outcome);
            const auto job = [promise, key, e = *expected, m = *mirror, links] {
                Result result{.outcome = Outcome::LinkDown, .reason = "the transfer did not run"};
                try {
                    auto slot = links->transfers().acquire(m.peer_id, peer::TransferPriority::Interactive,
                                                           Clock::now() + kInteractiveSlotWait);
                    if (!slot) {
                        result = {.outcome = links->transfers().stopping() ? Outcome::Cancelled : Outcome::LinkDown,
                                  .reason = "no transfer slot to the linked server came free"};
                    } else if (const auto source = sourceFor(m, e); !source) {
                        result = {.outcome = Outcome::LinkDown, .reason = "the vault's engine is not loaded"};
                    } else {
                        result = receive(e, *source, [links] { return links->transfers().stopping(); });
                    }
                } catch (const std::exception& ex) {
                    result = {.outcome = Outcome::LinkDown, .reason = ex.what()};
                }
                {
                    std::scoped_lock done(inflightMutex());
                    inflight().erase(key);
                }
                promise->set_value(std::move(result));
            };
            if (!links->transfers().spawn(job)) {
                inflight().erase(key);
                throw NotReceived(Reason::LinkDown, "the server is stopping");
            }
        }
    }
    // The mount's opens share one worker pool with every other vault: past the cap, the fetch goes on (started above)
    // and the open answers at once.
    std::optional<MountWait> place;
    if (opener == Opener::Mount) place.emplace();
    if (place && !place->held() && outcome.wait_for(std::chrono::milliseconds(0)) != std::future_status::ready)
        throw NotReceived(Reason::TimedOut, "the file is on its way from the vault's linked server, and the mount's "
                                            "opens that may wait for one are all waiting; open it again shortly");
    if (outcome.wait_for(wait) != std::future_status::ready)
        throw NotReceived(Reason::TimedOut, fmt::format("the file has not arrived from the vault's linked server within "
                                                        "{} s; it is still coming",
                                                        std::chrono::duration_cast<std::chrono::seconds>(wait).count()));
    const auto& result = outcome.get();
    switch (result.outcome) {
        case Outcome::Received:
        case Outcome::NotPending: return true;
        case Outcome::LinkDown:
        case Outcome::Cancelled: throw NotReceived(Reason::LinkDown, result.reason);
        case Outcome::Failed: throw NotReceived(Reason::Failed, result.reason);
        case Outcome::Superseded: throw NotReceived(Reason::Failed, result.reason + "; open it again");
    }
    return true;
}

// Test instances only (paths::testMode): while VH_TEST_FAULT_DIR/mirror-contents-hold exists, background fetching
// fetches nothing, so the Tier B drill can show a file opened on the mirror arriving ahead of the queue. Never in a
// packaged daemon. A person's open (awaitIfPending) is not held.
static bool contentsHeldForTesting() {
    if (!vh::paths::testMode) return false;
    const char* dir = std::getenv("VH_TEST_FAULT_DIR");
    std::error_code ec;
    return dir && std::filesystem::exists(std::filesystem::path(dir) / "mirror-contents-hold", ec);
}

std::size_t fetchOutstanding(const uint32_t vaultId, const std::size_t max) {
    if (contentsHeldForTesting()) return 0;
    const auto mirror = MirrorVaults::get(vaultId);
    if (!mirror || mirror->role != "mirror") return 0;
    const auto links = peer::linkService();
    if (!links) return 0;
    std::size_t received = 0;
    for (const auto& e : PendingContents::outstanding(vaultId, max)) {
        auto slot = links->transfers().acquire(mirror->peer_id, peer::TransferPriority::Background, Clock::now());
        if (!slot) break;
        const auto source = sourceFor(*mirror, e);
        if (!source) break;
        const auto result = receive(e, *source, [&links] { return links->transfers().stopping(); });
        if (result.outcome == Outcome::Received) ++received;
        if (result.outcome == Outcome::LinkDown || result.outcome == Outcome::Cancelled) break;
    }
    return received;
}

}
