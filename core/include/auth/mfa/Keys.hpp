#pragma once

#include "crypto/SecretBytes.hpp"

#include <cstdint>
#include <memory>
#include <span>
#include <stdexcept>
#include <string_view>
#include <vector>

// The two MFA keys (#356; MFA design note sections 4.2, 4.3 and 9), both internal secrets sealed under the host master
// through crypto::secrets::Manager::sealedKey (seal-and-read-back, fail closed, never regenerated while anything
// depends on them; crypto/secrets/Dependents.hpp):
//   mfa_seal    the AES-256-GCM key that seals each TOTP seed
//   mfa_pepper  the BLAKE2b key that hashes each recovery code
// Each is created the first time it is needed and then served from locked memory. A key that can't be unsealed
// makes only its own factor unavailable: TOTP (or recovery codes) refuse with Unavailable, while passkeys and the CLI
// reset keep working. Both are part of `vh secrets export`.
namespace vh::auth::mfa::keys {

inline constexpr const char* kSealName = "mfa_seal";
inline constexpr const char* kPepperName = "mfa_pepper";
inline constexpr std::size_t kKeyBytes = 32;

// The key could not be unsealed (or created). The reason is in the crypto log; nothing was regenerated.
struct Unavailable final : std::runtime_error {
    using std::runtime_error::runtime_error;
};

using Key = std::shared_ptr<const crypto::SecretBytes>;

// Throw Unavailable when the key can't be had. A failure is not cached: the next call tries again.
[[nodiscard]] Key seal();
[[nodiscard]] Key pepper();

// Forgets the cached keys (tests, and after `vh secrets` changes the stored rows).
void resetForTesting();

// A sealed TOTP seed as totp_factors stores it: secret_sealed (ciphertext || 16-byte tag) and secret_iv (12 bytes).
struct SealedSecret {
    std::vector<uint8_t> ciphertext{};
    std::vector<uint8_t> iv{};
};

// AES-256-GCM with AAD "vh/mfa/totp/v1" || BE32(userId) || factorUuid (lower-case canonical form), so a sealed seed
// opens only for the row it was written for.
[[nodiscard]] SealedSecret sealTotpSecret(std::span<const uint8_t> key, uint32_t userId, std::string_view factorUuid,
                                          std::span<const uint8_t> secret);
// Throws std::runtime_error when the tag doesn't verify (another key, user or factor, or a tampered row).
[[nodiscard]] crypto::SecretBytes openTotpSecret(std::span<const uint8_t> key, uint32_t userId,
                                                 std::string_view factorUuid, const SealedSecret& sealed);

}
