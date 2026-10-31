#pragma once

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>

// What the device listener's diagnostics may say about the host's network without privileges
// (docs/reference/transfer-protocol.md §1.1, §1.3). Read-only and cheap: config and state files the daemon can read,
// nothing that needs root, never a rule change. Unknown is reported as unknown, never guessed.
namespace vh::platform::network {

struct FirewallState {
    // "ufw" | "firewalld" | "nftables" | "alf" (macOS application firewall) | "unknown". Linux never claims "none":
    // plain iptables rules can't be seen without root.
    std::string detected = "unknown";
    std::optional<bool> active{};      // null when it can't be told
    std::optional<std::string> hint{}; // what to run so `port`/tcp gets through, when that is known
};

// `root` prefixes every path read (tests point it at a fixture tree); "/" on a real host.
[[nodiscard]] FirewallState detectFirewall(uint16_t port, const std::filesystem::path& root = "/");

// Whether `<hostname>.local` resolves for other hosts: macOS always (mDNSResponder); Linux when avahi-daemon runs
// (`/run/avahi-daemon/pid` exists).
[[nodiscard]] bool mdnsResponderAvailable(const std::filesystem::path& root = "/");

}
