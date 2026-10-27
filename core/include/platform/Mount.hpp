#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// The FUSE mount's lifecycle around libfuse (fuse/Service.cpp). Nothing here may stat or open the mount itself:
// a wedged daemon would block the caller forever (CLAUDE.md), so mounts are found in the mount table.
namespace vh::platform::mount {

// Mount modes (#199/#200):
//   disabled         no mount; vaults are served over HTTP/WS/CLI/S3 only.
//   service_private  mounted for the daemon's own uid only (no allow_other). No platform provides it.
//   multiuser        any local uid, each request authorized for its caller (allow_other).
// Linux: multiuser only, as it has always been. macOS: disabled only (#262): the server never mounts there, and
// Finder access belongs to Vaulthalla Desktop's File Provider (valkyrianlabs/vaulthalla-desktop#1).
[[nodiscard]] std::string_view defaultMode() noexcept;
[[nodiscard]] bool supportsMode(std::string_view mode) noexcept;

// Whether this platform has a FUSE runtime at all. Linux: always (the kernel bridge links libfuse3). macOS: never;
// config load then runs any configured mount.mode as disabled, with a warning (config/Config.cpp).
[[nodiscard]] bool fuseRuntimeAvailable() noexcept;

// Everything below is the mount's lifecycle, called only by the kernel bridge (fuse/Service.cpp), so only platforms
// that build the bridge implement it (Linux).

// The FUSE implementation behind the mount, for health output.
[[nodiscard]] std::string_view backend() noexcept;

// What the mount guarantees about who reaches it, for health output: "enforced" (per-uid RBAC proven by this
// platform's integration suites), "unproven" (the mode's isolation has not passed its hardware gate yet).
[[nodiscard]] std::string_view isolation(std::string_view mode) noexcept;

// Mount options for the daemon's FUSE session in `mode` (one supportsMode() accepts).
// Linux: allow_other + auto_unmount (per-uid RBAC; the kernel unmounts if the daemon dies).
[[nodiscard]] std::vector<std::string> fuseOptions(std::string_view mode);

// Whether something is mounted at `path`, or a dead FUSE endpoint is left there.
// Linux: lstat (ENOTCONN, or a st_dev boundary with the parent) — the proven check.
[[nodiscard]] bool isMountedOrStale(const std::filesystem::path& path);

// Before (re)creating the mountpoint: detaches a mount a previous run left there. Linux: nothing (the existing
// ENOTCONN handling covers it).
void detachStale(const std::filesystem::path& path) noexcept;

// Detaches the mount at `path` without waiting for its users (Linux: lazy umount2(MNT_DETACH), then fusermount3/
// fusermount/umount -l). Best effort.
void detach(const std::filesystem::path& path) noexcept;

// The FUSE connection mounted at `path`, from the mount table (Linux: the fusectl minor in /proc/self/mountinfo),
// or nullopt when nothing is mounted there.
[[nodiscard]] std::optional<std::string> fuseConnection(const std::filesystem::path& path);

// Ends a connection still referenced after detach, so the receive loop wakes (Linux: fusectl abort). False where the
// OS has no such control; the caller then relies on fuse_session_exit and the forced unmount.
bool abortConnection(const std::string& connection) noexcept;

}
