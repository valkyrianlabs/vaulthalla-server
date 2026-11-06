#pragma once

// COSE_Key credential public keys (RFC 9052/9053, WebAuthn L3 section 5.8.5) for the three algorithms in scope, and
// signature verification with them. No cryptography is implemented here: ES256 and RS256 go through OpenSSL 3 EVP,
// EdDSA through libsodium's crypto_sign_verify_detached.
//
// Accepted keys (check 9), anything else refuses:
//   EdDSA  kty 1 (OKP), alg -8,   crv 6 (Ed25519), x: 32 bytes, a valid point in the prime-order subgroup
//   ES256  kty 2 (EC2), alg -7,   crv 1 (P-256),   x, y: 32 bytes each, a point on the curve (EVP public check)
//   RS256  kty 3 (RSA), alg -257, n: 2048..4096 bits without leading zero bytes, e: odd, 3..2^32-1
// Only the labels above (plus kid, 2) may appear; private-key parameters refuse. The encoding must be exactly one
// strict CBOR map (Cbor.hpp).

#include "auth/webauthn/Types.hpp"

#include <optional>

namespace vh::auth::webauthn::cose {

inline constexpr std::size_t kMaxKeyBytes = 1024;
inline constexpr int kMinRsaBits = 2048;
inline constexpr int kMaxRsaBits = 4096;

struct PublicKey {
    Algorithm algorithm = Algorithm::ES256;
    Bytes x;  // OKP / EC2 x
    Bytes y;  // EC2 y
    Bytes n;  // RSA modulus
    Bytes e;  // RSA public exponent
};

struct Parsed {
    std::optional<PublicKey> key;
    Failure failure = Failure::None;
};

// Parses and validates `encoded` (exactly one COSE_Key).
[[nodiscard]] Parsed parse(ByteView encoded);

// True when `signature` is `key`'s valid signature over `message`: ES256 an ASN.1 DER ECDSA signature over SHA-256,
// EdDSA a 64-byte Ed25519 signature, RS256 RSASSA-PKCS1-v1_5 with SHA-256.
[[nodiscard]] bool verify(const PublicKey& key, ByteView message, ByteView signature);

}
