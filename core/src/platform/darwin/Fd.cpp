#include "platform/Fd.hpp"

#include <cerrno>
#include <fcntl.h>
#include <unistd.h>

namespace vh::platform::fd {

namespace {

int cloexec(const int fd) noexcept {
    if (fd >= 0 && ::fcntl(fd, F_SETFD, FD_CLOEXEC) != 0) {
        const int saved = errno;
        ::close(fd);
        errno = saved;
        return -1;
    }
    return fd;
}

}

int socket(const int domain, const int type, const int protocol) noexcept {
    return cloexec(::socket(domain, type, protocol));
}

int accept(const int listenFd, sockaddr* addr, socklen_t* len) noexcept {
    return cloexec(::accept(listenFd, addr, len));
}

int socketpair(const int domain, const int type, const int protocol, int fds[2]) noexcept {
    if (::socketpair(domain, type, protocol, fds) != 0) return -1;
    if (cloexec(fds[0]) < 0) {
        ::close(fds[1]);
        return -1;
    }
    if (cloexec(fds[1]) < 0) {
        ::close(fds[0]);
        return -1;
    }
    return 0;
}

bool pipe(int fds[2]) noexcept {
    if (::pipe(fds) != 0) return false;
    if (cloexec(fds[0]) < 0) {
        ::close(fds[1]);
        return false;
    }
    if (cloexec(fds[1]) < 0) {
        ::close(fds[0]);
        return false;
    }
    return true;
}

void suppressSigpipe(const int fd) noexcept {
    constexpr int on = 1;
    (void)::setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, sizeof on);
}

}
