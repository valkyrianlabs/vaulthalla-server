#pragma once

#include <filesystem>
#include <string>

namespace vh::platform::state {

// Makes the backing/state root private to the daemon's uid: encrypted vault bytes, sealed secrets and in-flight
// upload staging live under it, and no other local account may traverse it.
// Linux: nothing — the Debian package owns /var/lib/vaulthalla's ownership and modes (postinst), unchanged.
// macOS: the root must not be a symlink, must be owned by this process's uid (the installer creates it for
// _vaulthalla), and no ancestor may be replaceable by another account; it is then made 0700 and checked.
// Returns an empty string, or why the boundary can't be established: startup must then stop (main.cpp).
[[nodiscard]] std::string restrictToService(const std::filesystem::path& root);

}
