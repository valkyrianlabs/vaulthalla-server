#pragma once

// base64url without padding (RFC 4648 section 5), the encoding of every binary field in WebAuthn's JSON forms and of
// clientDataJSON.challenge. Decoding is strict (libsodium): no padding, no whitespace, no non-zero trailing bits.

#include "auth/webauthn/Types.hpp"

namespace vh::auth::webauthn {

[[nodiscard]] std::string base64urlEncode(ByteView bytes);
[[nodiscard]] std::optional<Bytes> base64urlDecode(std::string_view text);

}
