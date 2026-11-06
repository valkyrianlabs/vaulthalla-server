#pragma once

// Validation of the relying-party configuration (auth.webauthn.*), shared by config.yaml loading and settings.update.
//
// - rp_id: empty (passkeys unavailable) or a lowercase ASCII host name: labels of [a-z0-9-] (1..63, no hyphen at
//   either end), at most 253 characters, no trailing dot, and never an IP address (WebAuthn refuses them; a numeric
//   last label is refused). Internationalized names are written in their xn-- form.
// - origins: required (1..16) when rp_id is set and empty when it isn't. Each one is exactly a serialized origin,
//   `https://host[:port]`, or `http://localhost[:port]` for development: lowercase, no path, query, fragment,
//   user info or trailing slash, no default port written out, and its host is rp_id or a subdomain of it.
// - rp_name: 1..64 characters of valid UTF-8 without control characters.

#include <span>
#include <string>
#include <string_view>

namespace vh::auth::webauthn {

inline constexpr std::size_t kMaxOrigins = 16;
inline constexpr std::size_t kMaxRpNameBytes = 64;

[[nodiscard]] bool isValidRpId(std::string_view rpId);

// Throws std::invalid_argument naming the first rule the configuration breaks.
void validateRelyingParty(std::string_view rpId, std::span<const std::string> origins, std::string_view rpName);

}
