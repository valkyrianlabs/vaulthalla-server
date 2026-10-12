#include "platform/Mount.hpp"

#include <cstdlib>
#include <cstring>
#include <string_view>
#include <vector>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/ucred.h>

namespace vh::platform::mount {

std::vector<std::string> fuseOptions() {
    // macFUSE kernel backend. No allow_other: the mount answers only the daemon's own uid (service-private).
    // novncache/noattrcache: every lookup and getattr reaches the daemon (entry_timeout is not honored on macOS).
    return {"-o", "volname=Vaulthalla", "-o", "noappledouble", "-o", "noapplexattr",
            "-o", "novncache", "-o", "noattrcache"};
}

void detach(const std::filesystem::path& path) noexcept {
    if (::unmount(path.c_str(), MNT_FORCE) == 0) return;
    const std::string command = "/usr/sbin/diskutil unmount force '" + path.string() + "' >/dev/null 2>&1";
    (void)std::system(command.c_str());
}

std::optional<std::string> fuseConnection(const std::filesystem::path& path) {
    // MNT_NOWAIT: the kernel's cached table, never a round trip to a (possibly wedged) file system.
    const int count = ::getfsstat(nullptr, 0, MNT_NOWAIT);
    if (count <= 0) return std::nullopt;
    std::vector<struct statfs> mounts(static_cast<std::size_t>(count) + 8);
    const int got = ::getfsstat(mounts.data(), static_cast<int>(mounts.size() * sizeof(struct statfs)), MNT_NOWAIT);
    for (int i = 0; i < got; ++i) {
        const auto& m = mounts[static_cast<std::size_t>(i)];
        const std::string_view type = m.f_fstypename;
        if (path.string() != m.f_mntonname || (!type.starts_with("macfuse") && !type.starts_with("fuse"))) continue;
        return std::to_string(m.f_fsid.val[0]) + ":" + std::to_string(m.f_fsid.val[1]);
    }
    return std::nullopt;
}

bool abortConnection(const std::string&) noexcept {
    return false;  // no fusectl on macOS
}

}
