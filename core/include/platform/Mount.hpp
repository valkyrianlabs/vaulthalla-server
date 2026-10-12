#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

// The FUSE mount's lifecycle around libfuse (fuse/Service.cpp). Nothing here may stat or open the mount itself:
// a wedged daemon would block the caller forever (CLAUDE.md), so mounts are found in the mount table.
namespace vh::platform::mount {

// Mount options for the daemon's FUSE session.
// Linux: allow_other + auto_unmount (per-uid RBAC; the kernel unmounts if the daemon dies).
// macOS (macFUSE kernel backend): a service-private mount — no allow_other, so only the daemon's uid reaches it —
// with the kernel's name/attribute caches off and Finder metadata kept out of vaults. Wider modes are decision #200.
[[nodiscard]] std::vector<std::string> fuseOptions();

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
