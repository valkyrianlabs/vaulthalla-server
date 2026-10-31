#pragma once

#include "device/Device.hpp"
#include "device/Fwd.hpp"
#include "device/Pairing.hpp"
#include "ops/Actor.hpp"
#include "platform/Network.hpp"
#include "protocols/device/Endpoints.hpp"
#include "protocols/device/Fwd.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

// Paired devices (Vaulthalla Desktop), shared by `vh device ...` and the ws device.* commands. D3: a device acts as
// the user who approved it, with that user's RBAC, and there are no device permissions: any signed-in user may open
// a pairing window and approve devices for their own account; super admins may list and revoke every device. The
// listener's network exposure (remote connections) is a daemon setting: super admins only, like settings.update.
//
// The device's own side of pairing and rotation (device.pair.*, device.identity.rotate) takes the connection's Peer
// (its key, decided at the TLS handshake) instead of an actor.
namespace vh::ops::devices {

using vh::device::Device;

// ---- pairing, owner side

[[nodiscard]] vh::device::PairingWindow openWindow(const Actor& actor);
// Closes the caller's own window. With `any`, whoever's window is open (super admins only; `vh device pair --close
// --any`). False when no such window was open.
bool closeWindow(const Actor& actor, bool any = false);

struct PendingList {
    std::optional<vh::device::PairingWindow> window{};  // the caller's open window, if any
    std::vector<vh::device::PendingRequest> requests{};
};
[[nodiscard]] PendingList pending(const Actor& actor);

// Number matching: `code` must be the one the device shows (any other code denies the request: ops::Invalid).
[[nodiscard]] Device approve(const Actor& actor, const std::string& requestId, const std::string& code);
void deny(const Actor& actor, const std::string& requestId);

// ---- pairing, device side

struct PairRequest {
    std::string name{};
    std::string platform{};
    std::string app_version{};
    std::string commitment{};  // 64 hex
};
[[nodiscard]] vh::device::PairRequestReceipt pairRequest(const vh::device::Peer& peer, const PairRequest& req);
[[nodiscard]] std::time_t pairConfirm(const vh::device::Peer& peer, const std::string& requestId,
                                      const std::string& nonceDevice);

struct PairStatus {
    vh::device::RequestState state{};
    std::optional<std::string> node_id{};
    std::optional<std::string> node_name{};
    std::optional<std::string> device_id{};
};
[[nodiscard]] PairStatus pairStatus(const vh::device::Peer& peer, const std::string& requestId);

// ---- devices

// A device as the caller names it: its device id (the current key's SPKI hash, 64 hex), the row id, or (CLI) an
// unambiguous prefix of at least 8 hex digits of the device id.
using Ref = std::string;

// The caller's devices; with `all`, every device (super admins only). Revoked devices are listed with revoked_at.
[[nodiscard]] std::vector<Device> list(const Actor& actor, bool all = false);
[[nodiscard]] Device get(const Actor& actor, const Ref& device);
[[nodiscard]] Device rename(const Actor& actor, const Ref& device, const std::string& name);
// The device's user, a super admin, or the device itself (`self`: the calling connection, which acts as its user).
// Closes the device's live sessions. Revocation is final.
Device revoke(const Actor& actor, const Ref& device, const vh::device::Peer* self = nullptr);

// device.identity.rotate (spec §4): on the device's own session, `certificate` (DER) endorsed by the old key's
// `signature` over the rotation message. Returns the new device id.
[[nodiscard]] std::string rotateIdentity(const Actor& actor, const vh::device::Peer& peer,
                                         const std::vector<uint8_t>& certificate, int64_t timestamp,
                                         const std::vector<uint8_t>& signature);

struct ServerIdentityInfo {
    std::string spki_sha256{};
    // Spec §5's announcement (next key, switch time) is not implemented: the daemon has one key until it is
    // regenerated, which makes every Desktop pair again.
};
[[nodiscard]] ServerIdentityInfo serverIdentity(const vh::device::Peer& peer);

// ---- endpoint advertisement (docs/reference/transfer-protocol.md §1)

struct Endpoints {
    std::string node_id{};
    protocols::device::endpoints::Advertisement advertisement{};
};
// device.endpoints: a paired device's own session only (no address disclosure before a device is trusted).
[[nodiscard]] Endpoints endpoints(const vh::device::Peer& peer);

struct PairingBootstrap {
    std::string node_id{};
    std::string server_spki_sha256{};  // empty until the listener has loaded its identity
    protocols::device::endpoints::Advertisement endpoints{};
};
// What device.pairing.open adds for the "Pair a device" dialog (any signed-in user, as openWindow).
[[nodiscard]] PairingBootstrap pairingBootstrap(const Actor& actor);

// ---- the listener's exposure (super admins only)

[[nodiscard]] protocols::device::ListenerStatus remoteStatus(const Actor& actor);

struct RemoteDiagnostics {
    std::vector<std::string> bind{};
    bool ipv6 = false;
    std::vector<protocols::device::endpoints::Candidate> candidates{};
    platform::network::FirewallState firewall{};
    std::optional<protocols::device::endpoints::RemoteContact> last_remote_device{};
};
// device.remote.status's `diagnostics` (§1.3).
[[nodiscard]] RemoteDiagnostics remoteDiagnostics(const Actor& actor);
// Persists device_server.remote (config.yaml, kept across restarts and upgrades) and rebinds the listener now.
[[nodiscard]] protocols::device::ListenerStatus setRemote(const Actor& actor, bool enabled);

}
