#include "platform/PeerCredentials.hpp"

#include <cerrno>
#include <system_error>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

namespace vh::platform {

PeerCredentials peerCredentials(const int fd) {
    PeerCredentials out{};
    if (::getpeereid(fd, &out.uid, &out.gid) != 0)
        throw std::system_error(errno, std::generic_category(), "getpeereid");
    socklen_t len = sizeof(out.pid);
    if (::getsockopt(fd, SOL_LOCAL, LOCAL_PEERPID, &out.pid, &len) != 0) out.pid = -1;  // logging only
    return out;
}

}
