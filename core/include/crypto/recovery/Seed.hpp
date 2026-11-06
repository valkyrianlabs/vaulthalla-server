#pragma once

#include "crypto/SecretBytes.hpp"

#include <array>
#include <cstdint>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

// The recovery seed (design/encryption/03-metadata-recovery.md §5.3): 16 random bytes generated on a customer device
// (Vaulthalla Desktop, or the offline `vh-recovery kit create`), never on the server. Written as its 26-symbol
// lower-case Crockford base32 form plus one check symbol alphabet[SHA-256(seed)[0] >> 3] (27 symbols; grouping with
// spaces or dashes is cosmetic). Vectors: vectors.json `recovery_seed`.
//
//   PRK          = HKDF-Extract(salt = "vh.recovery.v1", IKM = seed)
//   x25519 sk    = HKDF-Expand(PRK, "x25519", 32)    the recovery recipient's key (KEV1 suite 1)
//   ed25519 seed = HKDF-Expand(PRK, "ed25519", 32)   sealed vaults' recovery signing key (spec 04 §4)
namespace vh::crypto::recovery {

inline constexpr std::size_t kSeedSize = 16;
inline constexpr std::size_t kSeedTextSize = 27;

// code(): "bad_length", "bad_symbol" (not the alphabet, or non-canonical padding), "bad_check".
class SeedError : public std::runtime_error {
public:
    explicit SeedError(std::string code);
    [[nodiscard]] const std::string& code() const noexcept { return code_; }

private:
    std::string code_;
};

class RecoverySeed {
public:
    // 16 bytes from the CSPRNG.
    [[nodiscard]] static RecoverySeed generate();
    // Parses the text form; whitespace and '-' are ignored, letters may be upper case. Throws SeedError.
    [[nodiscard]] static RecoverySeed parse(std::string_view text);
    // From the raw 16 bytes (tests, vectors).
    [[nodiscard]] static RecoverySeed fromBytes(std::span<const uint8_t> bytes);

    [[nodiscard]] std::string text() const;
    [[nodiscard]] std::span<const uint8_t> bytes() const noexcept { return seed_.bytes(); }

    // The recovery recipient: its X25519 secret key (locked memory) and public key.
    [[nodiscard]] SecretBytes x25519SecretKey() const;
    [[nodiscard]] std::vector<uint8_t> x25519PublicKey() const;
    // The Ed25519 signing seed and its public key.
    [[nodiscard]] SecretBytes ed25519Seed() const;
    [[nodiscard]] std::vector<uint8_t> ed25519PublicKey() const;

private:
    explicit RecoverySeed(SecretBytes seed) : seed_(std::move(seed)) {}
    [[nodiscard]] SecretBytes expand(std::string_view label) const;

    SecretBytes seed_;
};

}
