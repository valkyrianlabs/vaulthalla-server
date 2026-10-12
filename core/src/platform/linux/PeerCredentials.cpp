#include "platform/PeerCredentials.hpp"

#include <cerrno>
#include <system_error>
#include <sys/socket.h>

namespace vh::platform {

PeerCredentials peerCredentials(const int fd) {
    ucred c{};
    socklen_t len = sizeof(c);
    if (::getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &c, &len) != 0)
        throw std::system_error(errno, std::generic_category(), "SO_PEERCRED");
    return {c.uid, c.gid, c.pid};
}

}
