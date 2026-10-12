#include "platform/StagedFile.hpp"

#include <cerrno>
#include <filesystem>
#include <string>
#include <fcntl.h>
#include <unistd.h>

namespace vh::platform::staged {

int openUnnamed(const char* dir) noexcept {
    return ::open(dir, O_TMPFILE | O_RDWR | O_CLOEXEC, 0600);
}

int linkUnnamed(const int fd, const char* target) noexcept {
    const auto procPath = "/proc/self/fd/" + std::to_string(fd);
    int rc = ::linkat(AT_FDCWD, procPath.c_str(), AT_FDCWD, target, AT_SYMLINK_FOLLOW);
    if (rc < 0 && errno == ENOENT) {
        std::error_code ec;
        if (std::filesystem::exists(std::filesystem::path(target).parent_path(), ec))
            rc = ::linkat(fd, "", AT_FDCWD, target, AT_EMPTY_PATH);  // no /proc
        else
            errno = ENOENT;
    }
    return rc;
}

}
