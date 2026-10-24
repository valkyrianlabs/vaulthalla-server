#include "platform/Durable.hpp"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace vh::platform::durable {

int sync(const int fd) noexcept {
    if (::fcntl(fd, F_FULLFSYNC) == 0) return 0;
    // File systems without a full flush (some network and FAT volumes) refuse the request itself; anything else
    // (EIO, EBADF) is a real failure and must not be masked by a weaker fsync that happens to succeed.
    if (errno != ENOTSUP && errno != EOPNOTSUPP && errno != EINVAL && errno != ENOTTY) return -1;
    return ::fsync(fd);
}

}
