#pragma once

#include "db/query/vault/Key.hpp"
#include "vault/Fwd.hpp"

#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

// Key attestations: this node's signature over one vault key version's key check, so a backup can prove the key it
// carries is one this node created or held (`vh vault keys import` restores only attested versions as canonical;
// .claude/context/key-backup.md, revision 3).
//
//   attestation = Ed25519(sk, "vh-key-attest-v1" ‖ node_id ‖ UInt64BE(vault_id) ‖ UInt32BE(version) ‖ key_check)
//
// node_id is this install's id (device_node.node_id, migration 112: a UUID string) as its UTF-8 bytes; key_check is the
// 16 raw bytes of the key check (vault/KeyCheck.hpp). The tail after node_id has a fixed size (28 bytes), so the
// message is unambiguous. libsodium crypto_sign_detached; the keypair comes from a 32-byte seed sealed on this host
// (KeyProvider "key_attest"). Public keys live in key_attestation_keys (migration 113); a key id names one.
//
// Test vector (seed = bytes 0x00..0x1f, node_id "00000000-0000-4000-8000-000000000001", vault 42, version 3, key check
// 72e4c8b7f8ab43b8ed8869a57cef1703; the message is 80 bytes):
//   public key 03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8
//   signature  fbda258fa125ef4237a54b7cde732c073ba598fa4a1a782226aa82514ee5c36a
//              3ad452e6d36593337dc1619e61391c6ae20685155b11cc2b6deaf637e893840c
// Pinned by VaultKeyAttestation.MatchesTheDocumentedVector (test_vault_keys.cpp); also in
// docs/vaults/secrets-and-key-export.md and .claude/context/key-backup.md.
namespace vh::vault::attestation {

inline constexpr std::string_view kDomain = "vh-key-attest-v1";
inline constexpr std::size_t kSignatureSize = 64;
inline constexpr std::size_t kPublicKeySize = 32;
inline constexpr std::size_t kSeedSize = 32;
// Key ids are key_attestation_keys.id, a SERIAL (PostgreSQL integer): 1 to 2^31 - 1. An attestation naming another
// value is malformed (the ws contract's VaultKeyAttestation.key_id declares the same bounds).
inline constexpr unsigned int kMinKeyId = 1;
inline constexpr unsigned int kMaxKeyId = 2147483647;

struct Attestation {
    unsigned int key_id{};
    std::vector<uint8_t> signature{};  // 64 bytes
};

// ---- pure functions (no database, no sealed key)

// Throws std::invalid_argument when keyCheckHex is not 32 lowercase hex digits.
[[nodiscard]] std::vector<uint8_t> message(std::string_view nodeId, uint64_t vaultId, uint32_t version,
                                           const std::string& keyCheckHex);
// The public key of the keypair `seed` (32 bytes) derives.
[[nodiscard]] std::vector<uint8_t> publicKeyFromSeed(std::span<const uint8_t> seed);
[[nodiscard]] std::vector<uint8_t> signWithSeed(std::span<const uint8_t> seed, std::span<const uint8_t> message);
[[nodiscard]] bool verifySignature(std::span<const uint8_t> publicKey, std::span<const uint8_t> message,
                                   std::span<const uint8_t> signature);

// ---- this node

// Signs (vaultId, version, keyCheck) with this node's attestation key, creating the key (and its key_attestation_keys
// row) on first need, or a new one when the sealed seed no longer unseals. nullopt when signing failed (logged): the
// lazy backfill tries again the next time the version unseals.
[[nodiscard]] std::optional<Attestation> attest(unsigned int vaultId, unsigned int version,
                                                const std::string& keyCheckHex);

enum class Verdict {
    Valid,
    Missing,       // no signature
    UnknownKey,    // key_id names no public key this node has
    BadSignature,  // does not verify over this node, vault, version and key check
};
[[nodiscard]] std::string to_string(Verdict verdict);

// Checks an attestation against this node's public keys (current and retired), this node's id, and the given vault,
// version and key check.
[[nodiscard]] Verdict check(const Attestation& attestation, unsigned int vaultId, unsigned int version,
                            const std::string& keyCheckHex);

// ---- recorded provenance (migration 113)

// What the daemon records for a key version it holds: the key check of `key` and this node's attestation over it
// (no attestation when signing failed; the backfill retries).
[[nodiscard]] db::query::vault::Key::Provenance provenanceOf(unsigned int vaultId, unsigned int version,
                                                             std::span<const uint8_t> key);
// Lazy backfill: the daemon just unsealed `rec` to `key`. When the row's recorded key check differs (or is missing) or
// it has no attestation, records both (Key::recordProvenance; one conditional UPDATE). Never throws: a failure is
// logged and retried the next time the version unseals.
void backfill(const vh::vault::model::Key& rec, std::span<const uint8_t> key);

// Test seam: forget the cached signing key so the next attest() unseals (or regenerates) it again.
void resetForTesting();

}
