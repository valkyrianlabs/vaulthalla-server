#pragma once

#include <filesystem>
#include <string>

namespace vh::platform::state {

// Makes the backing/state root private to the daemon's uid: encrypted vault bytes, sealed secrets and in-flight
// upload staging live under it, and no other local account may traverse it.
// Linux: nothing — the Debian package owns /var/lib/vaulthalla's ownership and modes (postinst), unchanged.
// macOS: chmod 0700 on the root (the installer creates it for _vaulthalla; this keeps it so on every start).
// Returns an empty string, or what went wrong (logged by the caller; never fatal).
[[nodiscard]] std::string restrictToService(const std::filesystem::path& root);

}
