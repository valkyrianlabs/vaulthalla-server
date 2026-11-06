#pragma once

// WebAuthn relying-party verifier (#355, docs/dev/mfa-design.md section 4.1, decision D5).
//
// Extractable on purpose (the vl-sigv4 model): everything under auth/webauthn/ includes only its own headers, the
// standard library, libcbor, OpenSSL 3, libsodium and the vendored nlohmann/json, and knows nothing about the daemon
// (no database, sessions, config registry or logging). The daemon adapts it: the credential lookup is an interface,
// the challenge store is a plain in-memory object, and failures are values the caller logs and audits.
// tools/contracts/test_webauthn_contract.py pins the boundary.

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace vh::auth::webauthn {

using Bytes = std::vector<std::uint8_t>;
using ByteView = std::span<const std::uint8_t>;

inline ByteView view(const std::string_view s) {
    return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()};
}

// Why a ceremony was refused: for the auth log only. The client always gets the same uniform refusal.
enum class Failure : std::uint8_t {
    None = 0,
    NotConfigured,              // no rp_id / origins: passkeys are unavailable
    MalformedResponse,          // the response JSON or its base64url fields
    InputTooLarge,
    // check 1: the challenge record
    ChallengeUnknown,           // never issued, already used, or purged
    ChallengeExpired,
    ChallengeSessionMismatch,
    ChallengePurposeMismatch,
    ChallengeUserMismatch,
    ChallengeScopeMismatch,
    // checks 2-5: clientDataJSON
    ClientDataMalformed,
    ClientDataTypeMismatch,
    ClientDataChallengeMismatch,
    OriginMismatch,
    CrossOrigin,
    TopOrigin,
    // checks 6-7: authenticatorData
    AuthenticatorDataMalformed,
    RpIdHashMismatch,
    UserNotPresent,
    UserNotVerified,
    BackupStateWithoutEligibility,
    // check 8: attested credential data
    AttestedCredentialMissing,
    AttestedCredentialUnexpected,
    CredentialIdLength,
    CredentialIdMismatch,
    CredentialAlreadyRegistered,
    // check 9: the COSE credential public key
    CoseKeyMalformed,
    UnsupportedAlgorithm,
    KeyParametersMismatch,
    InvalidPublicKey,
    RsaKeySize,
    // check 10: attestation
    AttestationMalformed,
    AttestationAlgorithmMismatch,
    AttestationSignatureInvalid,
    AttestationCertificateInvalid,
    // check 11: the stored credential
    CredentialUnknown,
    CredentialDisabled,
    CredentialSuspended,
    CredentialRpIdMismatch,
    CredentialOwnerMismatch,
    UserHandleMissing,
    UserHandleMismatch,
    // check 12
    SignatureInvalid,
    // check 13
    BackupEligibilityChanged,
    // check 14
    SignCountRegression,
};

std::string_view toString(Failure f);

// What a challenge was issued for (design section 4.1, check 1). A `login` challenge is discoverable sign-in (no user
// known yet); `mfa` follows a verified password; `stepup` and `approval` carry a family/target scope.
enum class Purpose : std::uint8_t { Register, Login, Mfa, StepUp, Approval };

std::string_view toString(Purpose p);

// The three algorithms in scope, as COSE identifiers (RFC 9053 / IANA "COSE Algorithms").
enum class Algorithm : std::int32_t { EdDSA = -8, ES256 = -7, RS256 = -257 };

std::string_view toString(Algorithm a);

// Spec policy for the UV flag. The daemon always requires it (design 4.1 check 7); `Preferred` exists so the published
// W3C vectors, several of which carry UV = 0, run through the same code. Nothing outside tests may select it
// (tools/contracts/test_webauthn_contract.py).
enum class UserVerification : std::uint8_t { Required, Preferred };

// The relying party as configured (auth.webauthn.*). Never derived from request headers.
struct RelyingParty {
    std::string id;                       // rp_id: a host name, never an IP address
    std::vector<std::string> origins;     // exact serialized origins, e.g. "https://vault.example.com"
    UserVerification userVerification = UserVerification::Required;

    [[nodiscard]] bool configured() const { return !id.empty() && !origins.empty(); }
};

// authenticatorData flags (WebAuthn L3 section 6.1).
struct Flags {
    bool userPresent = false;        // UP, bit 0
    bool userVerified = false;       // UV, bit 2
    bool backupEligible = false;     // BE, bit 3
    bool backupState = false;        // BS, bit 4
    bool attestedCredential = false; // AT, bit 6
    bool extensions = false;         // ED, bit 7
};

using Aaguid = std::array<std::uint8_t, 16>;

struct AttestedCredential {
    Aaguid aaguid{};
    Bytes credentialId;
    Bytes publicKeyCose;  // exactly the COSE_Key bytes inside authenticatorData
};

struct AuthenticatorData {
    std::array<std::uint8_t, 32> rpIdHash{};
    std::uint8_t flagsByte = 0;
    Flags flags;
    std::uint32_t signCount = 0;
    std::optional<AttestedCredential> attested;
};

// A credential as the relying party stores it (the design's webauthn_credentials row joined with the owner's
// user_mfa.webauthn_user_handle).
struct StoredCredential {
    Bytes id;
    std::int64_t userId = 0;
    Bytes userHandle;          // the owner's 32-byte WebAuthn user handle
    Bytes publicKeyCose;
    std::string rpId;
    std::uint32_t signCount = 0;
    bool backupEligible = false;
    bool backupState = false;
    bool disabled = false;
    bool suspended = false;
};

// The relying party's credential storage, as far as verification needs it.
class CredentialLookup {
public:
    virtual ~CredentialLookup() = default;
    // The credential with exactly this id, whoever owns it, disabled and suspended ones included.
    [[nodiscard]] virtual std::optional<StoredCredential> find(ByteView credentialId) const = 0;
};

// What a ceremony is expected to answer (check 1). Compared against the challenge record the response's challenge
// names; any difference refuses.
struct Expectation {
    std::string session;               // the ws session uuid that asked for the challenge
    Purpose purpose = Purpose::Mfa;
    std::optional<std::int64_t> user;  // nullopt only for discoverable `login`
    std::string scope;                 // step-up family/target or approval target; empty otherwise
};

// The PublicKeyCredential a browser returns, decoded from its WebAuthn L3 JSON form (Json.hpp).
struct RegistrationResponse {
    Bytes rawId;
    Bytes clientDataJSON;
    Bytes attestationObject;
    // Client hints the browser reports beside the signed data (getTransports(), the credProps extension). Nothing
    // signs them: they are stored as hints, never used for a security decision.
    std::vector<std::string> transports;
    std::optional<bool> residentKey;
};

struct AssertionResponse {
    Bytes rawId;
    Bytes clientDataJSON;
    Bytes authenticatorData;
    Bytes signature;
    std::optional<Bytes> userHandle;
};

// How the attestation statement was handled (check 10). Nothing is trusted beyond the credential key itself: no
// trust chain, no metadata service.
enum class AttestationType : std::uint8_t {
    None,        // fmt "none"
    Self,        // fmt "packed" without x5c: signed by the credential key, verified
    Basic,       // fmt "packed" with x5c: signature and leaf certificate verified, chain not evaluated
    Unverified,  // any other fmt: recorded, treated as "none"
};

std::string_view toString(AttestationType t);

// A verified registration: what the relying party stores.
struct NewCredential {
    Bytes id;
    Bytes publicKeyCose;
    Algorithm algorithm = Algorithm::ES256;
    Aaguid aaguid{};
    std::uint32_t signCount = 0;
    bool userVerified = false;
    bool backupEligible = false;
    bool backupState = false;
    std::string attestationFormat;
    AttestationType attestationType = AttestationType::None;
    std::string rpId;
};

// A verified assertion: who signed in and what to write back to the credential row.
struct VerifiedAssertion {
    std::int64_t userId = 0;
    Bytes credentialId;
    std::uint32_t signCount = 0;       // store when storeSignCount
    bool storeSignCount = false;
    bool userVerified = false;
    bool backupState = false;          // store as reported (check 13)
    bool counterRegression = false;    // BE = 1 and signCount did not grow: accepted, audit it
};

// The result of a ceremony. On SignCountRegression with suspendCredential, the caller suspends the credential
// (possible clone of a device-bound key), audits and notifies (design 4.1, signCount table).
template <class T>
struct Outcome {
    std::optional<T> value;
    Failure failure = Failure::None;
    bool suspendCredential = false;

    static Outcome ok(T v) { return {std::move(v), Failure::None, false}; }
    static Outcome refuse(const Failure f, const bool suspend = false) { return {std::nullopt, f, suspend}; }
    explicit operator bool() const { return value.has_value(); }
};

}
