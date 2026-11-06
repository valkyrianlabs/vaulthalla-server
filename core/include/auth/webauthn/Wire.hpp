#pragma once

// The WebAuthn L3 JSON forms a browser sends (RegistrationResponseJSON, AuthenticationResponseJSON: what
// PublicKeyCredential.toJSON() returns), decoded strictly: one JSON object of at most 64 KiB, no duplicate keys,
// nesting at most 8 deep, `type` "public-key", `id` equal to `rawId`, and every binary field strict base64url
// (Base64Url.hpp). Derived convenience fields (response.publicKey, publicKeyAlgorithm, authenticatorData of a
// registration) are ignored: the verifier reads only the signed structures.

#include "auth/webauthn/Types.hpp"

namespace vh::auth::webauthn::wire {

inline constexpr std::size_t kMaxBytes = 65536;

[[nodiscard]] std::optional<RegistrationResponse> parseRegistration(std::string_view text);
[[nodiscard]] std::optional<AssertionResponse> parseAssertion(std::string_view text);

}
