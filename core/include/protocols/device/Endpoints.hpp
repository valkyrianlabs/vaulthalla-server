#pragma once

#include "config/Config.hpp"

#include <cstdint>
#include <ctime>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

// Where a paired device can reach this node's device listener (docs/reference/transfer-protocol.md §1.1, §1.3):
// interface addresses classified by range, `<hostname>.local` where an mDNS responder runs, and the operator's
// configured names (device_server.advertise). Computed on every call; the server never asks a third party for its
// public address.
namespace vh::protocols::device::endpoints {

enum class Kind { Loopback, Lan, Vpn, Wan, Passthrough };

[[nodiscard]] std::string_view to_string(Kind kind) noexcept;
[[nodiscard]] std::optional<Kind> kindFromString(std::string_view text) noexcept;

// One address of one interface, numeric (no scope id).
struct InterfaceAddress {
    std::string interface{};
    std::string address{};
};

// The host's interface addresses (getifaddrs: interfaces that are up, IPv4 and IPv6).
[[nodiscard]] std::vector<InterfaceAddress> enumerateInterfaces();
// Tests: answer enumerateInterfaces() with this instead (an empty function restores the real one).
void setInterfaceEnumeratorForTesting(std::function<std::vector<InterfaceAddress>()> enumerator);

// fnmatch(3)-style glob (`*`, `?`, `[...]`) against an interface name.
[[nodiscard]] bool globMatch(std::string_view pattern, std::string_view name) noexcept;

// The kind of an address by its range alone; nullopt for addresses never advertised (unspecified, link-local,
// multicast, reserved, unparsable). IPv4-mapped IPv6 is classified as its IPv4 address.
[[nodiscard]] std::optional<Kind> classifyAddress(std::string_view address) noexcept;

// An interface address as advertised: nullopt when the interface matches an `exclude` glob or the address is never
// advertised; interfaces named tailscale*, wg*, zt* or utun* make every non-loopback address on them `vpn`.
[[nodiscard]] std::optional<Kind> classify(std::string_view address, std::string_view interfaceName,
                                           const std::vector<std::string>& exclude) noexcept;

struct Candidate {
    std::string host{};
    uint16_t port = 0;
    Kind kind = Kind::Lan;
    std::string source{};                    // "interface" | "mdns" | "config"
    std::optional<std::string> interface{};  // source "interface" only
};

// Everything the list depends on, so building it is a pure function.
struct Inputs {
    uint16_t port = 0;           // the listener's port (bound, else configured)
    bool remote = false;         // device_server.remote
    bool ipv6 = true;            // IPv6 addresses are reachable (an IPv6 socket is bound, or nothing is bound yet)
    std::vector<InterfaceAddress> interfaces{};
    std::optional<std::string> mdnsHost{};  // "<hostname>.local" when a responder runs
};

inline constexpr std::size_t kMaxCandidates = 32;

// The §1.1 list: interface addresses (only loopback ones while `remote` is off), the mDNS name (remote only), then
// the configured names (whatever `remote` says), de-duplicated by (host lowercased, port), stably ordered loopback,
// lan, vpn, wan, passthrough, capped at kMaxCandidates.
[[nodiscard]] std::vector<Candidate> buildCandidates(const config::DeviceServerConfig& cfg, const Inputs& in);

// `<hostname>.local` (first label of the host name) when platform::network says a responder runs, else nullopt.
[[nodiscard]] std::optional<std::string> mdnsHostname();

// The live answer: the running DeviceServer's status (bound port, IPv6), the current config, the host's interfaces.
struct Advertisement {
    uint16_t port = 0;
    bool remote = false;
    bool listening = false;
    std::time_t generated_at = 0;
    std::vector<Candidate> candidates{};
};
[[nodiscard]] Advertisement current();

// The node id (device_node, as device.pair.status reports it), read once per process: it never changes.
[[nodiscard]] std::string nodeId();
void clearNodeIdForTesting();

// The latest Device-session handshake from a source that is neither loopback nor private (classifyAddress is
// `wan`): proof that a remote client reached the listener directly. In memory only; a restart forgets it.
struct RemoteContact {
    std::time_t at = 0;
    std::string ip{};
};
void noteDeviceHandshake(std::string_view address);
[[nodiscard]] std::optional<RemoteContact> lastRemoteDevice();
void clearLastRemoteDeviceForTesting();

}
