#pragma once

#include "device/Crypto.hpp"
#include "identities/Fwd.hpp"

#include <atomic>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vh::device {

// Who is on the other end of one device-listener connection, decided once at the TLS handshake (spec §2): the
// client certificate's key, and the device row it matched. Without a row the connection is pairing-only.
struct Peer {
    crypto::Hash spki{};
    std::string spkiHex{};
    std::vector<uint8_t> spkiDer{};  // verifies rotation proofs (spec §4)
    std::string address{};           // the TCP peer's IP (the listener has no proxy in front of it)
    std::optional<uint32_t> deviceRowId{};
    // Authenticated by the row's previous key (the grace between a rotation and the first handshake with the new
    // key).
    bool viaPreviousKey = false;
    // design/cloud/relay.md: the connection came through the Vaulthalla Cloud relay (the key was proven inside the
    // relayed TLS stream, never by a client certificate), or the device was paired that way. Either one holds the
    // session to the read-only capability set (Router::isRelayedReadCommand) on every connection. `address` is then
    // the browser's address as the relay reports it: display and per-address limits only, never loopback.
    bool relayed = false;
    bool pairedViaRelay = false;
    // Scoped devices (migration 152): the row's scope, read at the handshake ("read" | "write" | "destructive"). A
    // change closes the device's sessions, so a connection never runs under a scope wider than the row's.
    std::string scope{"destructive"};
    // Last time last_seen_at was written for this connection (steady clock, seconds), for throttling.
    mutable std::atomic<int64_t> lastTouchSeconds{0};

    [[nodiscard]] bool paired() const noexcept { return deviceRowId.has_value(); }
    [[nodiscard]] bool readOnly() const noexcept { return relayed || pairedViaRelay; }
    // Limited to less than its user's rights: never pairs, approves, steps up or handles keys (Router, ops, StepUp).
    [[nodiscard]] bool scoped() const noexcept { return scope != "destructive"; }
    // The first 16 hex digits of the key: how log lines name a device.
    [[nodiscard]] std::string shortId() const { return spkiHex.substr(0, 16); }
};

struct Authorization {
    std::shared_ptr<Peer> peer{};
    // The device's user (the canonical object) for a Device session; null for a pairing-only connection.
    std::shared_ptr<identities::User> user{};
};

// Authorizes a connection by its client key at handshake time: a live device (current or previous key) gives a
// Device session as that row's user; anything else (unknown, revoked, an account that no longer exists) a
// pairing-only one. A handshake with a rotated device's new key ends the old key's grace. Records last_seen_at/last_ip.
// Throws only on a database failure (the listener then refuses the connection).
// `relayed`: the key was proven inside a relayed stream (design/cloud/relay.md); the peer is marked so.
[[nodiscard]] Authorization authorize(const crypto::PublicKey& key, const std::string& address, bool relayed = false);

// Writes last_seen_at/last_ip for a Device session at most every 5 minutes (called per command). Never throws.
void touch(const Peer& peer);

}
