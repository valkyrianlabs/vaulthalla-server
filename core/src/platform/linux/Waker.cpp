#include "platform/Waker.hpp"

#include <cerrno>
#include <cstdint>
#include <system_error>
#include <sys/eventfd.h>
#include <unistd.h>

namespace vh::platform {

Waker::Waker() {
    readFd_ = writeFd_ = ::eventfd(0, EFD_CLOEXEC);
    if (readFd_ < 0) throw std::system_error(errno, std::generic_category(), "eventfd");
}

Waker::~Waker() {
    if (readFd_ >= 0) ::close(readFd_);
}

void Waker::notify() const noexcept {
    const std::uint64_t one = 1;
    (void)!::write(writeFd_, &one, sizeof one);
}

bool Waker::wait() const noexcept {
    std::uint64_t count = 0;
    while (::read(readFd_, &count, sizeof count) < 0)
        if (errno != EINTR) return false;
    return true;
}

}
