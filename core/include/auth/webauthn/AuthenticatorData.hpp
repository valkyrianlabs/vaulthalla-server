#pragma once

// authenticatorData (WebAuthn L3 section 6.1), parsed strictly: rpIdHash (32) | flags (1) | signCount (4, big-endian)
// | attested credential data iff AT | extensions (one strict CBOR map) iff ED, and nothing after. Attested credential
// data is aaguid (16) | credentialIdLength (2) | credentialId (<= 1023) | credentialPublicKey (one strict CBOR item,
// at most cose::kMaxKeyBytes). The COSE key's meaning is checked by cose::parse, not here.

#include "auth/webauthn/Types.hpp"

namespace vh::auth::webauthn::authdata {

inline constexpr std::size_t kMinBytes = 37;
inline constexpr std::size_t kMaxBytes = 4096;
inline constexpr std::size_t kMaxCredentialIdBytes = 1023;

namespace flag {
inline constexpr std::uint8_t UP = 0x01, UV = 0x04, BE = 0x08, BS = 0x10, AT = 0x40, ED = 0x80;
}

struct Parsed {
    std::optional<AuthenticatorData> data;
    Failure failure = Failure::None;
};

[[nodiscard]] Parsed parse(ByteView raw);

}
