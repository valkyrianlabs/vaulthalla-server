#include "platform/Clone.hpp"

#include <cerrno>
#include <fcntl.h>
#include <linux/fs.h>
#include <sys/ioctl.h>
#include <unistd.h>

namespace vh::platform::clone {

int cloneFile(const char* source, const char* target) noexcept {
    const int in = ::open(source, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (in < 0) return -1;
    const int out = ::open(target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out < 0) {
        const int saved = errno;
        ::close(in);
        errno = saved;
        return -1;
    }
    if (::ioctl(out, FICLONE, in) != 0) {
        const int saved = errno;
        ::close(out);
        ::close(in);
        ::unlink(target);
        errno = saved;
        return -1;
    }
    ::close(in);
    if (::close(out) != 0) {
        const int saved = errno;
        ::unlink(target);
        errno = saved;
        return -1;
    }
    return 0;
}

}
