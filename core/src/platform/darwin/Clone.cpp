#include "platform/Clone.hpp"

#include <cerrno>
#include <sys/clonefile.h>
#include <sys/stat.h>
#include <unistd.h>

namespace vh::platform::clone {

int cloneFile(const char* source, const char* target) noexcept {
    // clonefile(2) never replaces an existing target (EEXIST) and keeps the source's mode; tighten it to 0600.
    if (::clonefile(source, target, CLONE_NOFOLLOW) != 0) return -1;
    if (::chmod(target, 0600) != 0) {
        const int saved = errno;
        ::unlink(target);
        errno = saved;
        return -1;
    }
    return 0;
}

}
