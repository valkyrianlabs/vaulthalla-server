#pragma once

// OpenSSL 3 public keys for the verifier (internal to auth/webauthn). Only key import, public-key checks and EVP
// signature verification: nothing here computes cryptography itself.

#include "auth/webauthn/Types.hpp"

#include <memory>

struct evp_pkey_st;

namespace vh::auth::webauthn::openssl {

struct PkeyDeleter {
    void operator()(evp_pkey_st* key) const;
};
using Pkey = std::unique_ptr<evp_pkey_st, PkeyDeleter>;

// An uncompressed P-256 point (x, y: 32 bytes each), after EVP_PKEY_public_check. nullptr when it isn't one.
[[nodiscard]] Pkey p256(ByteView x, ByteView y);
// An RSA public key from big-endian n and e, after EVP_PKEY_public_check. nullptr otherwise.
[[nodiscard]] Pkey rsa(ByteView n, ByteView e);
// The modulus size of an RSA key in bits (0 if it isn't RSA).
[[nodiscard]] int rsaBits(const Pkey& key);

enum class Kind { P256, Rsa, Ed25519, Other };
[[nodiscard]] Kind kind(const evp_pkey_st* key);

// EVP_DigestVerify: SHA-256 for P-256 (DER ECDSA) and RSA (PKCS#1 v1.5); one-shot for Ed25519.
[[nodiscard]] bool verify(evp_pkey_st* key, ByteView message, ByteView signature);

}
