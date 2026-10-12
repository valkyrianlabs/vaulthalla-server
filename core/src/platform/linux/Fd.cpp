#include "platform/Fd.hpp"

#include <fcntl.h>
#include <unistd.h>

namespace vh::platform::fd {

int socket(const int domain, const int type, const int protocol) noexcept {
    return ::socket(domain, type | SOCK_CLOEXEC, protocol);
}

int accept(const int listenFd, sockaddr* addr, socklen_t* len) noexcept {
    return ::accept4(listenFd, addr, len, SOCK_CLOEXEC);
}

int socketpair(const int domain, const int type, const int protocol, int fds[2]) noexcept {
    return ::socketpair(domain, type | SOCK_CLOEXEC, protocol, fds);
}

bool pipe(int fds[2]) noexcept {
    return ::pipe2(fds, O_CLOEXEC) == 0;
}

void suppressSigpipe(int) noexcept {}

}
