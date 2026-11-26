#pragma once

#include "device/Fwd.hpp"
#include "device/Pairing.hpp"
#include "ops/Actor.hpp"
#include "peer/Links.hpp"
#include "peer/Pairing.hpp"
#include "peer/Peer.hpp"
#include "protocols/device/Endpoints.hpp"
#include "protocols/ws/Fwd.hpp"

#include <nlohmann/json_fwd.hpp>

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

// Linked servers (design/peers/link.md), shared by `vh peer ...` and the ws peer.* commands.
//
// Who may: a super admin, on the host's control socket (`vh`), in the web console with the device-trust step-up for
// the two commands that make a link (peer.pairing.approve and peer.link.start), or on a full-access, directly
// connected device's session (Vaulthalla Desktop) on RBAC alone (Cooper, 2026-11-25). Never a scoped device, a
// device reached through the Vaulthalla Cloud relay, an agent (MCP, `vh mcp`), a share session or a linked server:
// ops::Refused("peer_forbidden") here, on top of the router's and the MCP catalog's own refusals.
//
// Gate: while peers.experimental is off every operation but enabled() refuses with ops::Refused("peers_experimental").
//
// The wire side (peer.pair.*, peer.identity.rotate, peer.unlinked) takes the connection instead of an actor.
namespace vh::ops::peers {

// ops::Refused("peers_experimental") unless peers.experimental is on.
void requireExperimental();

// Whether peers.experimental is on: the one operation that answers with the switch off, so that a console or Desktop
// can leave linked servers out without provoking a refusal (ws peer.status). The same callers as the rest.
[[nodiscard]] bool enabled(const Actor& actor);

// ---- pairing, the side that opens a window (B)

struct OpenWindow {
    vh::device::PairingWindow window{};
    std::string node_id{};
    std::string spki_sha256{};  // this server's key: the fingerprint the other side may pass as expect_spki
    protocols::device::endpoints::Advertisement endpoints{};
    std::string name{};
};
// Opens (or extends) a 10-minute window for linking a server, node-wide with device pairing ("one window at a time").
// Creates the peer wrap key on first use (the card carries it). Audited peer.pairing.open.
[[nodiscard]] OpenWindow openWindow(const Actor& actor);
bool closeWindow(const Actor& actor);

struct PendingLinks {
    std::optional<vh::device::PairingWindow> window{};
    std::vector<vh::peer::PendingLink> requests{};
};
[[nodiscard]] PendingLinks pending(const Actor& actor);

// Number matching: `code` must be the one the dialling server shows. With `expectSpki` (the brokered path: Desktop's
// pin for the dialling server) the requesting key must be that one. Either mismatch denies the request. Writes the
// `peer` row (sharing identities). compared_by follows the caller's channel: desktop over a (full-access) device
// session, person in the console or on the host socket. Audited peer.link with compared_by and pinned (expectSpki).
[[nodiscard]] vh::peer::Record approve(const Actor& actor, const std::string& requestId, const std::string& code,
                                       const std::optional<std::string>& expectSpki);
void deny(const Actor& actor, const std::string& requestId);

// ---- pairing, the dialling side (A)

// Starts dialling `endpoints` (the address an admin typed, or what peer.pairing.open answered on the other server);
// with `expectSpki` only that key completes the handshake, else trust on first use guarded by the code. The caller's
// channel decides the row's compared_by, as for approve(). Returns the attempt (connecting); peer.link.status shows
// its code once it has one.
[[nodiscard]] vh::peer::LinkAttempt linkStart(const Actor& actor, const std::vector<vh::peer::Endpoint>& endpoints,
                                              const std::optional<std::string>& expectSpki);
[[nodiscard]] vh::peer::LinkAttempt linkStatus(const Actor& actor, const std::string& linkId);
[[nodiscard]] vh::peer::LinkAttempt linkCancel(const Actor& actor, const std::string& linkId);

// ---- linked servers

struct Linked {
    vh::peer::Record record{};
    vh::peer::Health health{};
};
// Every linked server, revoked ones included (all = true) or only the live ones.
[[nodiscard]] std::vector<Linked> list(const Actor& actor, bool all = false);
// A peer by its row id, node id, key (64 hex) or an unambiguous prefix of 8+ hex digits of its key, or its name.
[[nodiscard]] Linked get(const Actor& actor, const std::string& ref);
// The same lookup with no caller and no switch (trusted: ops::peer_policy and `vh vault role --peer` authorize).
// ops::NotFound, or ops::Invalid when the reference is ambiguous.
[[nodiscard]] vh::peer::Record resolveRef(const std::string& ref);
[[nodiscard]] vh::peer::Record rename(const Actor& actor, const std::string& ref, const std::string& name);
// Revokes the row, closes its connections at once, and tells the peer (peer.unlinked) when it is connected.
// Audited peer.unlink.
[[nodiscard]] vh::peer::Record unlink(const Actor& actor, const std::string& ref);

// ---- the wire

// peer.pair.*: the dialling server on a pairing-only connection of this server's listener.
[[nodiscard]] vh::peer::LinkRequestReceipt pairRequest(const vh::device::Peer& connection, const nlohmann::json& payload);
[[nodiscard]] std::time_t pairConfirm(const vh::device::Peer& connection, const std::string& requestId,
                                      const std::string& nonceA);
[[nodiscard]] vh::peer::LinkRequestStatus pairStatus(const vh::device::Peer& connection, const std::string& requestId);

// peer.identity.rotate on a Peer session: the other server announces its next identity key, signed by its current
// one over "vh/peer/rotate/v1" ‖ next ‖ this server's key ‖ its node id ‖ counter. Stored as next_spki_sha256 (either
// key is accepted until the new one is seen). Audited peer.identity.rotate.
void identityRotateReceived(const std::shared_ptr<protocols::ws::Session>& session, const nlohmann::json& payload);
// peer.unlinked on a Peer session: the other server unlinked; this side's row is revoked too and the connection ends
// after the answer. Audited peer.unlink (by the peer).
void unlinkedReceived(const std::shared_ptr<protocols::ws::Session>& session);

}
