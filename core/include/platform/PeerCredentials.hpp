#pragma once

#include <sys/types.h>

namespace vh::platform {

// Kernel credentials of a connected AF_UNIX stream peer, as they were when it connected (the effective uid/gid:
// `sudo vh` is uid 0). Linux: SO_PEERCRED. macOS: getpeereid() + LOCAL_PEERPID. The pid is for logs only; never
// authorize on it (it can be reused).
struct PeerCredentials {
    uid_t uid;
    gid_t gid;
    pid_t pid;
};

// Throws std::system_error.
[[nodiscard]] PeerCredentials peerCredentials(int fd);

}
