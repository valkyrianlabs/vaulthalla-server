#pragma once

#include <cstdint>
#include <span>
#include <string>

// The key check: a public fingerprint of one vault key version that identifies it without revealing it, so a backup
// (Vaulthalla Desktop's 1Password item, an export file) can prove it holds the same key the daemon uses.
//
//   key_check = lowercase hex of BLAKE2b-128 (libsodium crypto_generichash, 16-byte output), keyed by the 32 key bytes,
//               over "vh-key-check-v1" ‖ vault_id ‖ UInt32BE(version)
//
// vault_id is the vault's numeric id as ASCII decimal without sign or leading zeros ("42"); the version is the last 4
// bytes, so the message is unambiguous. Test vector (key = bytes 0x00..0x1f): vault 42, version 3 →
// 72e4c8b7f8ab43b8ed8869a57cef1703; vault 1, version 1 → c7a67cdafd3140b29e19b0b5e543cb13. Documented in
// docs/vaults/secrets-and-key-export.md and .claude/context/key-backup.md; Desktop computes the same value.
namespace vh::vault {

inline constexpr std::string_view kKeyCheckDomain = "vh-key-check-v1";

[[nodiscard]] std::string keyCheck(std::span<const uint8_t> key, unsigned int vaultId, unsigned int version);

// Constant-time comparison of two key checks (lowercase hex); false when either is malformed.
[[nodiscard]] bool keyCheckEquals(const std::string& a, const std::string& b);

}
