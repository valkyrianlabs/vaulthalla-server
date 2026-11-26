#pragma once

#include "peer/Peer.hpp"

#include <vl/keykit/kev1.hpp>

#include <cstdint>
#include <span>
#include <string>

// This server's keys as a linked server sees them (design/peers/link.md, "Keys"): the identity (device_tls, the
// device listener's, for TLS both ways), the attestation key (key_attest) and the peer wrap key, an X25519 key sealed
// in its own slot (KeyProvider "peer_wrap", "test_peer_wrap" in test mode) that linked servers wrap vault keys and
// shared secrets to. The wrap key is created when the first link is made (the first card), never before.
namespace vh::peer::keys {

[[nodiscard]] std::string wrapSlotName();

// The wrap key's public half, generating and sealing the key on first need. A key that is gone while live links pin
// its public half is never silently replaced: that throws crypto::secrets::MasterSecretLost (unlink those servers
// and link them again, or restore the sealed state).
[[nodiscard]] Key32 wrapPublicKey();

// This server's card now: its node id, its name (the host name), every attestation public key it has had (the current
// one created if there is none yet), the wrap key, kPeerProtocol and this build's version.
[[nodiscard]] Card localCard();

// The name this server goes by on a card (the host name; "vaulthalla" when it has none).
[[nodiscard]] std::string serverName();

// A vault key version a linked server wrapped to this server's wrap key (design/peers/mirror.md "Starting a mirror"
// step 4): the KEV1 envelope (suite X25519) for `vaultUid`, opened with the sealed wrap key. Throws
// vl::keykit::kev1::Error with the first check that fails (another vault, another recipient, a damaged envelope). The
// key is held only in the returned locked buffer; the wrap key never leaves this function.
[[nodiscard]] vl::keykit::kev1::Unwrapped unwrapVaultKey(std::span<const uint8_t> envelope,
                                                         const vl::keykit::Uid& vaultUid);

}
