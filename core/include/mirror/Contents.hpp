#pragma once

#include "db/query/mirror/Contents.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "fs/Fwd.hpp"
#include "peer/ObjectClient.hpp"

#include <chrono>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>

// A mirror's file contents (design/peers/mirror.md "Contents", "As built: sealed contents"): receiving one expected
// generation's sealed bytes, verifying them and linking them into place, and fetching a file a person opens before
// anything else. What a mirror expects is db::query::mirror::PendingContents (migration 161); the bytes come from the
// vault's linked server over the sealed lane (peer::object) through the link service's transfer slots.
//
// Invariant 8: nothing is linked into place before its size, content hash and authentication checks pass. The bytes go
// to an unnamed file in the vault's backing area; then the size, the BLAKE2b content hash and vault::content::verifyFd
// with the vault key against the expected binding; then, under the file's content lock, a compare-and-set that the row
// still expects exactly that generation (and the file's row still names it); only then is the file linked into place
// (the content sidecar renamed over the backing path, with the modification time it was told) and the row removed.
// Any failure discards the unnamed file. Three failed attempts mark the file failed with the reason; it is not tried
// again until PendingContents::retry.
namespace vh::mirror::contents {

// How long an open waits for a file to arrive (the mount, downloads, previews, the ws download). The transfer goes on
// after the wait ends; the open fails with Reason::TimedOut.
inline constexpr std::chrono::seconds kOpenWait{15};
// One file's whole transfer, resumes included.
inline constexpr std::chrono::minutes kTransferDeadline{30};
// Interrupted transfers resumed (by range) within one attempt before it counts as failed.
inline constexpr unsigned kMaxResumes = 5;
// How long a fetch a person waits for may wait for a transfer slot before it gives up (not counted as a failure).
inline constexpr std::chrono::seconds kInteractiveSlotWait{60};

// Why an open of a file whose contents have not arrived fails, as each surface reports it.
enum class Reason {
    LinkDown,  // the vault's linked server cannot be reached now: ENOLINK
    TimedOut,  // not received within kOpenWait (it keeps coming): ETIMEDOUT
    Failed,    // fetching failed (three attempts, or the file is marked failed): ENODATA
    Missing,   // the vault was detached before these contents arrived (migration 167): ENODATA, for good
};

// mirror_link_down | mirror_fetch_timeout | mirror_fetch_failed | mirror_contents_missing: the leading code of the
// message, and the HTTP lanes' error code (503 with Retry-After; 410 for mirror_contents_missing, which never arrives).
[[nodiscard]] std::string_view codeOf(Reason r);
// The mount's errno for each reason (FUSE open answers it; fuse::errnoFrom reads it off the system_error).
[[nodiscard]] int errnoOf(Reason r);

class NotReceived final : public std::system_error {
public:
    NotReceived(Reason reason, const std::string& detail);
    [[nodiscard]] Reason reason() const noexcept { return reason_; }

private:
    Reason reason_;
};

// The reason code a message starts with ("mirror_link_down: …"), for a vh::storage::ContentUnavailable carrying one.
[[nodiscard]] std::optional<std::string_view> reasonCodeIn(std::string_view message);

// Where one expected generation's sealed bytes come from: the vault's linked server (the default), or a test.
struct SourceResult {
    peer::object::FetchStatus status{peer::object::FetchStatus::Unreachable};
    std::string error{};
};

class Source {
public:
    virtual ~Source() = default;
    // The bytes from `offset` to `sealedSize`, in order, into `sink`.
    virtual SourceResult read(uint64_t offset, uint64_t sealedSize, const std::function<bool()>& cancelled,
                              const peer::object::Sink& sink) = 0;
};

using SourceFactory = std::function<std::unique_ptr<Source>(const db::query::mirror::MirrorVault& mirror,
                                                            const db::query::mirror::Expected& expected)>;
// Tests: where bytes come from instead of the linked server. Empty restores the linked server.
void setSourceFactoryForTesting(SourceFactory factory);

enum class Outcome {
    Received,    // verified and in place (or found in place already), the row cleared
    LinkDown,    // the source could not be reached: nothing counted
    Failed,      // this attempt failed (counted); the row is failed after kMaxAttempts
    Superseded,  // the row or the file moved on meanwhile: nothing linked, nothing counted
    NotPending,  // nothing is expected for the file
    Cancelled,   // stopped (the service is stopping): nothing counted
};

struct Result {
    Outcome outcome{Outcome::NotPending};
    std::string reason{};
    bool failedForGood{false};  // Failed, and the row is now failed (no more retries until told)
};

[[nodiscard]] std::string_view toString(Outcome o);

// One attempt at one expected file through `source`: receive, verify, then link (above). A row already failed is not
// tried (Failed, failedForGood). Blocks the caller: runs on a transfer thread, never on a FUSE or request thread.
[[nodiscard]] Result receive(const db::query::mirror::Expected& expected, Source& source,
                             const std::function<bool()>& cancelled = {});

// Who is opening: the mount's opens run on the FUSE worker pool, which serves every vault, so only a few may wait at a
// time (mountWaitCap); every other surface runs on threads of its own and waits the full kOpenWait.
enum class Opener { Mount, Other };

// How many mount opens may wait for a pending file at once: a quarter of the FUSE worker pool (concurrency::
// ThreadPoolManager::fusePool, fixed at max(3 x cores, 8) / 6 workers: 2 on a 1-4 core host, 9 on 18 cores), at
// least 1 and at most 4, so a recursive reader on a freshly mirrored vault never parks more than a quarter of the
// mount's workers (half on the smallest hosts) and the rest keeps serving every vault.
[[nodiscard]] unsigned mountWaitCap();
// Tests: a fixed cap (0 restores the pool's share); mount opens waiting now.
void setMountWaitCapForTesting(unsigned cap);
[[nodiscard]] unsigned mountWaitersForTesting();

// An open on the mirror: false when nothing is pending for `file` (the caller reads as usual; costs no query for a
// vault with no pending contents once known). Otherwise fetches it ahead of everything else (an interactive transfer
// slot; one transfer per file however many wait) and waits at most `wait`: true once its bytes are in place. Throws
// NotReceived (LinkDown, TimedOut or Failed). Holds no database connection while it waits. A mount open over
// mountWaitCap does not wait at all: its fetch is still started (or joined) ahead of the queue, so a retry soon finds the
// file, and it fails with TimedOut at once.
[[nodiscard]] bool awaitIfPending(const vh::fs::model::File& file, std::chrono::milliseconds wait = kOpenWait,
                                  Opener opener = Opener::Other);

// Background work (the log applier's, a later piece; tests): up to `max` outstanding files of a mirror vault, in
// priority order, each in a background slot taken without waiting (stops when none is free). Returns how many were
// received. Runs on the caller's thread.
std::size_t fetchOutstanding(uint32_t vaultId, std::size_t max);

}
