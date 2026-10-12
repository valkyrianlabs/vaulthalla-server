#include "platform/Waker.hpp"

#include <cerrno>
#include <system_error>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>

namespace vh::platform {

Waker::Waker() {
    int fds[2];
    if (::pipe(fds) != 0) throw std::system_error(errno, std::generic_category(), "pipe");
    for (const int fd : fds) {
        ::fcntl(fd, F_SETFD, FD_CLOEXEC);
        // Non-blocking both ends: notify() from a signal handler must never block on a full pipe (a pending byte
        // already means "woken"), and wait() polls before it reads.
        ::fcntl(fd, F_SETFL, ::fcntl(fd, F_GETFL) | O_NONBLOCK);
    }
    readFd_ = fds[0];
    writeFd_ = fds[1];
}

Waker::~Waker() {
    if (readFd_ >= 0) ::close(readFd_);
    if (writeFd_ >= 0) ::close(writeFd_);
}

void Waker::notify() const noexcept {
    const char one = 1;
    (void)!::write(writeFd_, &one, 1);
}

bool Waker::wait() const noexcept {
    pollfd p{readFd_, POLLIN, 0};
    for (;;) {
        if (::poll(&p, 1, -1) < 0) {
            if (errno == EINTR) continue;
            return false;
        }
        char buf[64];
        if (::read(readFd_, buf, sizeof buf) > 0) return true;
        if (errno != EINTR && errno != EAGAIN) return false;
    }
}

}
