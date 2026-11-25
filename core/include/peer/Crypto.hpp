#pragma once

#include "device/Crypto.hpp"
#include "peer/Fwd.hpp"

#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/types.h>

// The byte-level protocol of linking two servers (design/peers/link.md, "Pairing" and "Rotation"). Pure and
// deterministic; the fixed vector is core/test-assets/peer/pairing-vectors.json, asserted by PeerCryptoVectors
// (test_peer_crypto.cpp), and is what Vaulthalla Desktop implements its brokered check against.
//
// Every domain tag differs from device pairing's ("vh-pair-commit-v1", "vh-pair-v1"), so a code computed for one can
// never be accepted for the other.
//
//   card     = "vh/peer/card/v1" ‖ LP(node_id) ‖ LP(name) ‖ UInt32BE(n) ‖ attest_public_key[32] × n
//              ‖ wrap_public_key[32] ‖ UInt32BE(peer_protocol) ‖ LP(product_version)
//              (LP(s) = UInt32BE(byte length) ‖ the UTF-8 bytes; the attestation keys in the card's order)
//   commit   = SHA-256("vh/peer/commit/v1" ‖ spki_A ‖ nonce_A)
//   digest   = SHA-256("vh/peer/sas/v1" ‖ spki_B ‖ spki_A ‖ nonce_A ‖ nonce_B ‖ SHA-256(card_A) ‖ SHA-256(card_B))
//   code     = UInt64BE(digest[0..8]) mod 1 000 000, six digits (device::crypto::sasCode)
//   rotate   = "vh/peer/rotate/v1" ‖ next_spki[32] ‖ peer_spki[32] ‖ LP(node_id) ‖ UInt64BE(counter), signed
//              ECDSA P-256 / SHA-256 (DER) by the announcing server's current identity key
//
// A is the server that dials (peer.link.start), B the one that opened the window (peer.pairing.open). spki_X is the
// SHA-256 of X's identity certificate's SubjectPublicKeyInfo; each side takes the other's from the TLS handshake.
namespace vh::peer::crypto {

using Hash = vh::device::crypto::Hash;

inline constexpr std::string_view kCardDomain = "vh/peer/card/v1";
inline constexpr std::string_view kCommitDomain = "vh/peer/commit/v1";
inline constexpr std::string_view kSasDomain = "vh/peer/sas/v1";
inline constexpr std::string_view kRotateDomain = "vh/peer/rotate/v1";

[[nodiscard]] std::vector<uint8_t> cardBytes(const Card& card);
[[nodiscard]] Hash cardHash(const Card& card);
[[nodiscard]] Hash commitment(const Hash& spkiA, const Hash& nonceA);
[[nodiscard]] Hash sasDigest(const Hash& spkiB, const Hash& spkiA, const Hash& nonceA, const Hash& nonceB,
                             const Hash& cardHashA, const Hash& cardHashB);
// The six-digit code both sides show.
[[nodiscard]] std::string sasCode(const Hash& digest);

[[nodiscard]] std::vector<uint8_t> rotationMessage(const Hash& nextSpki, const Hash& peerSpki, std::string_view nodeId,
                                                   uint64_t counter);
// ECDSA P-256 / SHA-256 over `message` with `key` (this server's identity key), DER Ecdsa-Sig-Value. Throws on failure.
[[nodiscard]] std::vector<uint8_t> signP256(EVP_PKEY* key, std::span<const uint8_t> message);

}
