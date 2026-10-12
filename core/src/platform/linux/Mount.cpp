#include "platform/Mount.hpp"

#include <cerrno>
#include <cstdlib>
#include <sys/stat.h>
#include <fstream>
#include <sstream>
#include <sys/mount.h>  // umount2, MNT_DETACH

namespace vh::platform::mount {

std::string_view defaultMode() noexcept { return "multiuser"; }

bool supportsMode(const std::string_view mode) noexcept { return mode == "multiuser"; }

bool fuseRuntimeAvailable() noexcept { return true; }

std::string_view backend() noexcept { return "linux-fuse"; }

std::string_view isolation(std::string_view) noexcept { return "enforced"; }  // Tier A (make itest) proves it

std::vector<std::string> fuseOptions(std::string_view) {
    return {"-o", "allow_other", "-o", "auto_unmount"};
}

bool isMountedOrStale(const std::filesystem::path& p) {
    // If lstat returns ENOTCONN, it's a stale FUSE endpoint => treat as mounted.
    struct stat st{}, pst{};
    if (::lstat(p.c_str(), &st) != 0) return (errno == ENOTCONN);
    const auto parent = p.parent_path().empty() ? std::filesystem::path("/") : p.parent_path();

    // If parent can't be stat'ed, be conservative.
    if (::lstat(parent.c_str(), &pst) != 0) return true;

    // Different st_dev than parent => mountpoint boundary
    return st.st_dev != pst.st_dev;
}

void detachStale(const std::filesystem::path&) noexcept {}

void detach(const std::filesystem::path& path) noexcept {
    // 1) Try kernel lazy detach
    if (::umount2(path.c_str(), MNT_DETACH) == 0) return;

    // 2) Fallbacks (some distros prefer fusermount3), stopping at the first that works
    for (const auto* command : {"fusermount3 -uz ", "fusermount -uz ", "umount -l "})
        if (std::system((command + path.string() + " >/dev/null 2>&1").c_str()) == 0) return;
}

std::optional<std::string> fuseConnection(const std::filesystem::path& path) {
    std::ifstream mountinfo("/proc/self/mountinfo");
    std::string line;
    while (std::getline(mountinfo, line)) {
        // <id> <parent> <major>:<minor> <root> <mount point> ... - <fstype> ...
        std::istringstream fields(line);
        std::string id, parent, dev, root, mountPoint;
        if (!(fields >> id >> parent >> dev >> root >> mountPoint)) continue;
        if (mountPoint != path.string() || line.find(" - fuse.") == std::string::npos) continue;
        if (const auto colon = dev.find(':'); colon != std::string::npos) return dev.substr(colon + 1);
    }
    return std::nullopt;
}

bool abortConnection(const std::string& connection) noexcept {
    std::ofstream abort("/sys/fs/fuse/connections/" + connection + "/abort");
    abort << "1" << std::flush;
    return static_cast<bool>(abort);
}

}
