#pragma once

#include <sys/socket.h>

namespace vh::platform::fd {

// Descriptors created close-on-exec. Linux sets the flag atomically (SOCK_CLOEXEC, accept4, pipe2); macOS has no
// such flags in its SDK and sets FD_CLOEXEC right after, so a fork+exec in another thread can race in between.
// Child processes on macOS are therefore spawned with POSIX_SPAWN_CLOEXEC_DEFAULT, never fork+exec.
// All return -1 (or false) with errno set on failure, like the calls they wrap.
[[nodiscard]] int socket(int domain, int type, int protocol) noexcept;
[[nodiscard]] int accept(int listenFd, sockaddr* addr, socklen_t* len) noexcept;
[[nodiscard]] int socketpair(int domain, int type, int protocol, int fds[2]) noexcept;
[[nodiscard]] bool pipe(int fds[2]) noexcept;

// A write to a peer that went away must fail with EPIPE, not raise SIGPIPE. Every send() also passes MSG_NOSIGNAL;
// macOS additionally needs SO_NOSIGPIPE on the socket (Linux: no-op).
void suppressSigpipe(int fd) noexcept;

}
