#include "platform/StagedFile.hpp"

#include <cerrno>

namespace vh::platform::staged {

int openUnnamed(const char*) noexcept {
    errno = EOPNOTSUPP;
    return -1;
}

int linkUnnamed(int, const char*) noexcept {
    errno = EOPNOTSUPP;
    return -1;
}

}
