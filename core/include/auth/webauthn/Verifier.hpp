#pragma once

// The WebAuthn relying-party ceremonies of design section 4.1: registration (`none` and `packed` attestation) and
// assertions, ES256 / EdDSA (Ed25519) / RS256 only, every check of the table in its order. Any failure refuses; the
// Failure says why, for the auth log only.
//
// Two layers:
//   verifyRegistration / verifyAssertion run checks 2-14 against a challenge the caller already holds. Pure: no
//   state, no clock. The W3C vectors run here.
//   Verifier adds check 1: it reads the challenge out of clientDataJSON, burns its record in the ChallengeStore and
//   checks the record's binding, then runs the pure layer with the record's value.
//
// The caller persists what an outcome says: the NewCredential row, the new signCount and backup state, a suspension
// on a device-bound counter regression, and the audit events (counterRegression, suspension).

#include "auth/webauthn/Challenge.hpp"
#include "auth/webauthn/Types.hpp"

namespace vh::auth::webauthn {

inline constexpr std::size_t kMinCredentialIdBytes = 16;
inline constexpr std::size_t kMaxCredentialIdBytes = 1023;
inline constexpr std::size_t kMaxSignatureBytes = 1024;

[[nodiscard]] Outcome<NewCredential> verifyRegistration(const RelyingParty& rp, ByteView expectedChallenge,
                                                        const RegistrationResponse& response,
                                                        const CredentialLookup& credentials);

// `expected` names the purpose and user: `login` (discoverable sign-in) requires a userHandle and takes the user from
// the credential; every other purpose requires the credential to belong to expected.user.
[[nodiscard]] Outcome<VerifiedAssertion> verifyAssertion(const RelyingParty& rp, ByteView expectedChallenge,
                                                         const AssertionResponse& response,
                                                         const CredentialLookup& credentials,
                                                         const Expectation& expected);

class Verifier {
public:
    Verifier(RelyingParty rp, ChallengeStore& challenges, const CredentialLookup& credentials);

    // expected.purpose must be Purpose::Register.
    [[nodiscard]] Outcome<NewCredential> registration(const RegistrationResponse& response, const Expectation& expected,
                                                      ChallengeStore::Clock::time_point now
                                                      = ChallengeStore::Clock::now()) const;

    // expected.purpose is anything but Purpose::Register.
    [[nodiscard]] Outcome<VerifiedAssertion> assertion(const AssertionResponse& response, const Expectation& expected,
                                                       ChallengeStore::Clock::time_point now
                                                       = ChallengeStore::Clock::now()) const;

    [[nodiscard]] const RelyingParty& relyingParty() const { return rp_; }

private:
    // Check 1: the challenge in clientDataJSON names a live record bound to `expected`; it is burnt either way.
    [[nodiscard]] Failure claimChallenge(ByteView clientDataJSON, const Expectation& expected,
                                         ChallengeStore::Clock::time_point now, Bytes& challenge) const;

    RelyingParty rp_;
    ChallengeStore& challenges_;
    const CredentialLookup& credentials_;
};

}
