#pragma once

// The attestation object (WebAuthn L3 section 6.5) and check 10 of design section 4.1.
//
// The object is one strict CBOR map with exactly `fmt` (text, [a-z0-9-]{1,32}), `attStmt` (map) and `authData`
// (bytes). Statements:
//   none    attStmt must be empty.
//   packed  attStmt is {alg, sig} (self attestation: alg must be the credential's, sig verified with the credential
//           key) or {alg, sig, x5c} (sig verified with the leaf certificate's key, and the leaf must meet section
//           8.2.1: X.509 v3, subject C/O/CN present and OU "Authenticator Attestation", not a CA, and an
//           id-fido-gen-ce-aaguid extension, if any, non-critical and equal to the AAGUID). The chain is not
//           evaluated: there is no trust store and no metadata service, so the result carries no more trust than
//           self attestation.
//   other   recorded and treated as none (its attStmt must still be a strict CBOR map).

#include "auth/webauthn/Cbor.hpp"
#include "auth/webauthn/Cose.hpp"
#include "auth/webauthn/Types.hpp"

namespace vh::auth::webauthn::attestation {

inline constexpr std::size_t kMaxBytes = 32768;
inline constexpr std::size_t kMaxCertificates = 8;

struct Object {
    std::string fmt;
    Bytes authData;
    cbor::Item root;               // owns statement
    const cbor_item_t* statement = nullptr;
};

struct Parsed {
    std::optional<Object> object;
    Failure failure = Failure::None;
};

[[nodiscard]] Parsed parse(ByteView encoded);

struct Verified {
    AttestationType type = AttestationType::None;
    Failure failure = Failure::None;
};

// Check 10 over authData || clientDataHash.
[[nodiscard]] Verified verify(const Object& object, const cose::PublicKey& credentialKey, const Aaguid& aaguid,
                              ByteView clientDataHash);

}
