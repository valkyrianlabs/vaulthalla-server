#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>

// MFA recovery codes (#356; MFA design note section 4.3): ten per batch, each 10 Crockford base32 characters (50
// bits) shown as XXXXX-XXXXX. Stored only as a keyed BLAKE2b-256 under the sealed mfa_pepper, domain-separated per
// account. The codes are random and high-entropy and the key is sealed, so a slow hash adds nothing (the #171
// reasoning) and the hash can be looked up directly, which keeps single use one conditional UPDATE.
//
// A code is a secret: never log it, put it in audit details or telemetry, or keep it past the response that shows it.
namespace vh::auth::mfa::recovery {

inline constexpr std::size_t kCodesPerBatch = 10;
inline constexpr std::size_t kCodeChars = 10;
inline constexpr std::size_t kHashBytes = 32;
inline constexpr std::string_view kDomain = "vh/mfa/recovery/v1";

using Hash = std::array<uint8_t, kHashBytes>;

// A fresh code, formatted XXXXX-XXXXX (libsodium's CSPRNG, uniform over the 32 Crockford symbols).
[[nodiscard]] std::string generateCode();

// The user's input as the 10 canonical characters: case-insensitive, hyphens and spaces dropped, and Crockford's
// look-alikes read as what they look like (I, L -> 1; O -> 0). nullopt for anything else.
[[nodiscard]] std::optional<std::string> normalize(std::string_view input);

// BLAKE2b-256 keyed by `pepper` over kDomain || BE32(userId) || the normalized code.
[[nodiscard]] Hash hash(std::span<const uint8_t> pepper, uint32_t userId, std::string_view normalized);

}
