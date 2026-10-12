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
//   service_private  mounted for the daemon's own uid only (no allow_other).
//   multiuser        any local uid, each request authorized for its caller (allow_other).
// Linux: multiuser only, as it has always been. macOS: disabled (default) and service_private; multiuser waits on
// the K2 proof (#221).
[[nodiscard]] std::string_view defaultMode() noexcept;
[[nodiscard]] bool supportsMode(std::string_view mode) noexcept;

// Whether the FUSE library is present at run time. Linux links it outright; macOS weak-links macFUSE's libfuse3 so
// the daemon starts (and serves storage) on a Mac without macFUSE.
[[nodiscard]] bool fuseRuntimeAvailable() noexcept;

// The FUSE implementation behind the mount, for health output.
[[nodiscard]] std::string_view backend() noexcept;

// What the mount guarantees about who reaches it, for health output: "enforced" (per-uid RBAC proven by this
// platform's integration suites), "unproven" (the mode's isolation has not passed its hardware gate yet).
[[nodiscard]] std::string_view isolation(std::string_view mode) noexcept;

// Mount options for the daemon's FUSE session in `mode` (one supportsMode() accepts).
// Linux: allow_other + auto_unmount (per-uid RBAC; the kernel unmounts if the daemon dies).
// macOS service_private (macFUSE kernel backend): no allow_other, so only the daemon's uid reaches it; the kernel's
// name/attribute caches off; Finder metadata kept out of vaults.
[[nodiscard]] std::vector<std::string> fuseOptions(std::string_view mode);

// Detaches the mount at `path` without waiting for its users (Linux: lazy umount2(MNT_DETACH), then fusermount3/
// fusermount/umount -l; macOS: unmount(MNT_FORCE), then diskutil unmount force). Best effort.
void detach(const std::filesystem::path& path) noexcept;

// The FUSE connection mounted at `path`, from the mount table (Linux: the fusectl minor in /proc/self/mountinfo;
// macOS: the fsid from getfsstat(MNT_NOWAIT)), or nullopt when nothing is mounted there.
[[nodiscard]] std::optional<std::string> fuseConnection(const std::filesystem::path& path);

// Ends a connection still referenced after detach, so the receive loop wakes (Linux: fusectl abort). False where the
// OS has no such control (macOS); the caller then relies on fuse_session_exit and the forced unmount.
bool abortConnection(const std::string& connection) noexcept;

}
