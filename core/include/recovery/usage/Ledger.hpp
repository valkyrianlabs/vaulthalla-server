#pragma once

#include "recovery/Fwd.hpp"
#include "recovery/Hooks.hpp"

#include <chrono>
#include <cstdint>
#include <ctime>
#include <functional>
#include <string>
#include <vector>

// Local per-vault upstream usage accounting (vault_upstream_usage_daily). Owned by the provider policy + cost slice.
//
// Nothing here ever leaves the host. Counters live in memory per (vault, UTC day) and are added to the table by
// flush(): every kFlushInterval from the vault retention service's loop (tick) and once more at shutdown. A crash loses
// at most the last interval's counts (≤ 60 s); a failed flush keeps its deltas for the next one.
//
// Feeds:
//   s3::Controller::recordRequest / recordUploadBytes   every metered request of a controller that knows its vault
//                                                       (CloudEngine sets it): List/Head/Get/Put/Copy/Delete + bytes
//   noteUpstreamWrite (recovery::hooks)                 every successful CloudEngine PUT/DELETE: first put vs
//                                                       overwrite (+ the replaced object's bytes), deletes (+ bytes)
// Requests are classified further by the calling thread's RequestTag (ScopedRequestTag): multipart initiations and
// parts, version listings, and version restores (CopyObject / GET ?versionId and their bytes). The data plane tags
// multipart and ListObjectVersions itself; restore code tags its requests with RequestTag::VersionRestore.
namespace vh::recovery::usage {

inline constexpr std::chrono::seconds kFlushInterval{60};
inline constexpr std::chrono::hours kAlertInterval{1};

enum class RequestTag : uint8_t {
    None,
    MultipartInitiate,   // CreateMultipartUpload (a Put request; counts multipart_uploads)
    MultipartPart,       // UploadPart (a Put request; counts multipart_parts)
    VersionList,         // ListObjectVersions (a List request; counts version_list_requests)
    VersionRestore,      // a provider-version restore: its Copy/Get requests count version_restore_requests and its
                         // downloaded bytes version_restore_bytes
};

// Tags the calling thread's requests until destroyed (nests: the previous tag comes back).
class ScopedRequestTag {
public:
    explicit ScopedRequestTag(RequestTag tag) noexcept;
    ~ScopedRequestTag();
    ScopedRequestTag(const ScopedRequestTag&) = delete;
    ScopedRequestTag& operator=(const ScopedRequestTag&) = delete;

private:
    RequestTag previous_;
};

[[nodiscard]] RequestTag currentRequestTag() noexcept;

enum class Request : uint8_t { List, Head, Get, Put, Copy, Delete };

// The controller feed (never throws, never blocks on I/O). vaultId 0 is ignored.
void noteRequest(uint32_t vaultId, Request kind, uint64_t count = 1) noexcept;
void noteDownloadedBytes(uint32_t vaultId, uint64_t bytes) noexcept;
void noteUploadedBytes(uint32_t vaultId, uint64_t bytes) noexcept;

// Counts one successful upstream write (first put vs overwrite, replaced bytes, deletes). One single-row read of the
// key's remote_object_index entry (what the object was before this write). Never throws.
void noteUpstreamWrite(const hooks::UpstreamWrite& write) noexcept;

// ---- flushing ------------------------------------------------------------------------------------------------------

struct FlushResult {
    size_t rows = 0;         // (vault, day) deltas written
    size_t dropped = 0;      // deltas of vaults that no longer exist
    bool ok = true;
    std::string error;       // when !ok: the deltas are kept for the next flush
};

// Adds every pending delta to vault_upstream_usage_daily (additive; one transaction). Never throws.
FlushResult flush() noexcept;
// Periodic driver: flushes when kFlushInterval has passed since the last flush, and at most every kAlertInterval
// evaluates the recovery cost alerts (recovery::cost::evaluateAlerts). Never throws.
void tick(std::chrono::system_clock::time_point now) noexcept;

// The UTC day ("YYYY-MM-DD") of t.
[[nodiscard]] std::string utcDay(std::time_t t);

// ---- tests ---------------------------------------------------------------------------------------------------------

[[nodiscard]] std::vector<db::query::recovery::UsageDay> pendingForTesting();
void resetForTesting();
// The clock counters are dated with (default: std::time). Empty restores it.
void setClockForTesting(std::function<std::time_t()> clock);
// Replaces what tick() runs hourly (default: the cost alert evaluation). Empty restores it.
void setAlertJobForTesting(std::function<void()> job);

}
