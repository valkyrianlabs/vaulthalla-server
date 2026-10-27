#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include <openssl/types.h>

// The byte-level protocol of device pairing (docs/pairing.md in valkyrianlabs/vaulthalla-desktop, "the spec"): SPKI hashes,
// the commit-then-reveal SAS, the key rotation proof and the encodings they travel in. Every function here is pure
// and deterministic except the CSPRNG helpers; the spec's test vectors are asserted in test_device_crypto.cpp.
namespace vh::device::crypto {

using Hash = std::array<uint8_t, 32>;

// ---- encodings (spec §1: 32-byte values are lowercase hex, DER blobs standard base64 with padding)

[[nodiscard]] std::string toHex(std::span<const uint8_t> bytes);
// Exactly 64 hex digits (either case); nullopt otherwise.
[[nodiscard]] std::optional<Hash> hashFromHex(std::string_view hex);
[[nodiscard]] std::string toBase64(std::span<const uint8_t> bytes);
// Standard alphabet, padding required, no whitespace; nullopt otherwise.
[[nodiscard]] std::optional<std::vector<uint8_t>> fromBase64(std::string_view text);

[[nodiscard]] Hash sha256(std::span<const uint8_t> bytes);
[[nodiscard]] bool constantTimeEqual(std::span<const uint8_t> a, std::span<const uint8_t> b) noexcept;
[[nodiscard]] bool constantTimeEqual(std::string_view a, std::string_view b) noexcept;

// ---- pairing (spec §3)

// SHA-256("vh-pair-commit-v1" ‖ device_spki_sha256 ‖ nonce_device)
[[nodiscard]] Hash commitment(const Hash& deviceSpki, const Hash& nonceDevice);
// SHA-256("vh-pair-v1" ‖ server_spki_sha256 ‖ device_spki_sha256 ‖ nonce_device ‖ nonce_server)
[[nodiscard]] Hash sasDigest(const Hash& serverSpki, const Hash& deviceSpki, const Hash& nonceDevice,
                             const Hash& nonceServer);
// UInt64(big-endian digest[0..8]) mod 1 000 000, six digits with leading zeros ("022592").
[[nodiscard]] std::string sasCode(const Hash& digest);
// "680179" -> "680 179" (how both sides show it).
[[nodiscard]] std::string displayCode(std::string_view code);
// Accepts "680179", "680 179", "680-179"; nullopt unless that leaves exactly six digits.
[[nodiscard]] std::optional<std::string> normalizeCode(std::string_view text);

[[nodiscard]] Hash randomNonce();
// Six uniformly random digits (number-matching decoys).
[[nodiscard]] std::string randomCode();
// `n` random bytes as lowercase hex.
[[nodiscard]] std::string randomHex(std::size_t n);

// ---- key rotation (spec §4)

// "vh-device-rotate-v1" ‖ new_spki_sha256 ‖ server_spki_sha256 ‖ UInt64BE(timestamp): 91 bytes.
[[nodiscard]] std::vector<uint8_t> rotationMessage(const Hash& newSpki, const Hash& serverSpki, uint64_t timestamp);
// ECDSA-P256-SHA256 over `message` with the DER Ecdsa-Sig-Value `signature`, under the key in `spkiDer`.
[[nodiscard]] bool verifyEcdsaP256Sha256(std::span<const uint8_t> spkiDer, std::span<const uint8_t> message,
                                         std::span<const uint8_t> signature);

// ---- keys and certificates (spec §1-2)

// A P-256 public key as the protocol sees it: its DER SubjectPublicKeyInfo and that DER's SHA-256.
struct PublicKey {
    std::vector<uint8_t> spkiDer{};
    Hash spkiSha256{};
};

// The key of a certificate, if it is EC on prime256v1 (nothing else is accepted: chain, dates, EKU and the
// self-signature are not checked; the pin carries trust). Never throws.
[[nodiscard]] std::optional<PublicKey> p256KeyOf(const X509* certificate) noexcept;
// The same from a DER certificate (device.identity.rotate's `certificate`).
[[nodiscard]] std::optional<PublicKey> p256KeyOfCertificate(std::span<const uint8_t> der) noexcept;
// The SPKI of an uncompressed P-256 point (04 ‖ X ‖ Y, 65 bytes): spec §1's 26-byte prefix followed by the point.
[[nodiscard]] std::optional<PublicKey> p256KeyFromPoint(std::span<const uint8_t> point);

}
