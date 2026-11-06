#include "auth/webauthn/Verifier.hpp"

#include "auth/webauthn/Attestation.hpp"
#include "auth/webauthn/AuthenticatorData.hpp"
#include "auth/webauthn/Base64Url.hpp"
#include "auth/webauthn/ClientData.hpp"
#include "auth/webauthn/Cose.hpp"

#include <sodium.h>

#include <algorithm>

namespace vh::auth::webauthn {

namespace {

std::array<std::uint8_t, crypto_hash_sha256_BYTES> sha256(const ByteView data) {
    std::array<std::uint8_t, crypto_hash_sha256_BYTES> out{};
    crypto_hash_sha256(out.data(), data.data(), data.size());
    return out;
}

bool sameBytes(const ByteView a, const ByteView b) {
    return a.size() == b.size() && (a.empty() || sodium_memcmp(a.data(), b.data(), a.size()) == 0);
}

// Checks 2-5.
Failure checkClientData(const RelyingParty& rp, const ByteView json, const std::string_view type,
                        const ByteView expectedChallenge) {
    if (json.size() > clientdata::kMaxBytes) return Failure::InputTooLarge;
    const auto c = clientdata::parse(json);
    if (!c) return Failure::ClientDataMalformed;                                     // 2
    if (c->type != type) return Failure::ClientDataTypeMismatch;                     // 2
    const auto challenge = base64urlDecode(c->challenge);                            // 3
    if (!challenge || expectedChallenge.empty() || !sameBytes(*challenge, expectedChallenge))
        return Failure::ClientDataChallengeMismatch;
    if (std::ranges::find(rp.origins, c->origin) == rp.origins.end()) return Failure::OriginMismatch;  // 4
    if (c->crossOrigin.value_or(false)) return Failure::CrossOrigin;                // 5
    if (c->topOrigin) return Failure::TopOrigin;                                     // 5
    return Failure::None;
}

// Checks 6-7 (and the BE/BS consistency rule of WebAuthn L3 section 6.1).
Failure checkAuthenticatorData(const RelyingParty& rp, const AuthenticatorData& d) {
    if (!sameBytes(d.rpIdHash, sha256(view(rp.id)))) return Failure::RpIdHashMismatch;
    if (!d.flags.userPresent) return Failure::UserNotPresent;
    if (!d.flags.userVerified && rp.userVerification == UserVerification::Required) return Failure::UserNotVerified;
    if (d.flags.backupState && !d.flags.backupEligible) return Failure::BackupStateWithoutEligibility;
    return Failure::None;
}

}

Outcome<NewCredential> verifyRegistration(const RelyingParty& rp, const ByteView expectedChallenge,
                                          const RegistrationResponse& response, const CredentialLookup& credentials) {
    using Result = Outcome<NewCredential>;
    if (!rp.configured()) return Result::refuse(Failure::NotConfigured);
    if (response.rawId.size() > kMaxCredentialIdBytes) return Result::refuse(Failure::CredentialIdLength);

    if (const auto f = checkClientData(rp, response.clientDataJSON, "webauthn.create", expectedChallenge);
        f != Failure::None)
        return Result::refuse(f);
    const auto clientDataHash = sha256(response.clientDataJSON);

    auto att = attestation::parse(response.attestationObject);
    if (!att.object) return Result::refuse(att.failure);
    const auto ad = authdata::parse(att.object->authData);
    if (!ad.data) return Result::refuse(ad.failure);
    if (const auto f = checkAuthenticatorData(rp, *ad.data); f != Failure::None) return Result::refuse(f);  // 6-7

    // 8: attested credential data, a credential id of 16..1023 bytes, the one the response names, new to us.
    if (!ad.data->flags.attestedCredential || !ad.data->attested) return Result::refuse(Failure::AttestedCredentialMissing);
    const auto& cred = *ad.data->attested;
    if (cred.credentialId.size() < kMinCredentialIdBytes || cred.credentialId.size() > kMaxCredentialIdBytes)
        return Result::refuse(Failure::CredentialIdLength);
    if (!sameBytes(cred.credentialId, response.rawId)) return Result::refuse(Failure::CredentialIdMismatch);
    if (credentials.find(cred.credentialId)) return Result::refuse(Failure::CredentialAlreadyRegistered);

    // 9: the COSE key.
    const auto key = cose::parse(cred.publicKeyCose);
    if (!key.key) return Result::refuse(key.failure);

    // 10: the attestation statement.
    const auto verified = attestation::verify(*att.object, *key.key, cred.aaguid, clientDataHash);
    if (verified.failure != Failure::None) return Result::refuse(verified.failure);

    NewCredential out;
    out.id = cred.credentialId;
    out.publicKeyCose = cred.publicKeyCose;
    out.algorithm = key.key->algorithm;
    out.aaguid = cred.aaguid;
    out.signCount = ad.data->signCount;           // 14: stored
    out.userVerified = ad.data->flags.userVerified;
    out.backupEligible = ad.data->flags.backupEligible;  // 13: stored
    out.backupState = ad.data->flags.backupState;
    out.attestationFormat = att.object->fmt;
    out.attestationType = verified.type;
    out.rpId = rp.id;
    return Result::ok(std::move(out));
}

Outcome<VerifiedAssertion> verifyAssertion(const RelyingParty& rp, const ByteView expectedChallenge,
                                           const AssertionResponse& response, const CredentialLookup& credentials,
                                           const Expectation& expected) {
    using Result = Outcome<VerifiedAssertion>;
    if (!rp.configured()) return Result::refuse(Failure::NotConfigured);
    if (expected.purpose == Purpose::Register) return Result::refuse(Failure::ChallengePurposeMismatch);
    if (response.rawId.empty() || response.rawId.size() > kMaxCredentialIdBytes)
        return Result::refuse(Failure::CredentialIdLength);
    if (response.signature.size() > kMaxSignatureBytes) return Result::refuse(Failure::InputTooLarge);

    if (const auto f = checkClientData(rp, response.clientDataJSON, "webauthn.get", expectedChallenge);
        f != Failure::None)
        return Result::refuse(f);                                                   // 2-5
    const auto ad = authdata::parse(response.authenticatorData);
    if (!ad.data) return Result::refuse(ad.failure);
    if (const auto f = checkAuthenticatorData(rp, *ad.data); f != Failure::None) return Result::refuse(f);  // 6-7
    if (ad.data->flags.attestedCredential) return Result::refuse(Failure::AttestedCredentialUnexpected);

    // 11: the credential, its owner and the user handle.
    const auto cred = credentials.find(response.rawId);
    if (!cred) return Result::refuse(Failure::CredentialUnknown);
    if (cred->disabled) return Result::refuse(Failure::CredentialDisabled);
    if (cred->suspended) return Result::refuse(Failure::CredentialSuspended);
    if (cred->rpId != rp.id) return Result::refuse(Failure::CredentialRpIdMismatch);
    // An empty userHandle is the same as none (authenticators without a discoverable credential).
    const bool hasHandle = response.userHandle && !response.userHandle->empty();
    if (expected.purpose == Purpose::Login) {
        if (!hasHandle) return Result::refuse(Failure::UserHandleMissing);
        if (!sameBytes(*response.userHandle, cred->userHandle)) return Result::refuse(Failure::UserHandleMismatch);
    } else {
        if (!expected.user || cred->userId != *expected.user) return Result::refuse(Failure::CredentialOwnerMismatch);
        if (hasHandle && !sameBytes(*response.userHandle, cred->userHandle))
            return Result::refuse(Failure::UserHandleMismatch);
    }

    // 12: the signature over authenticatorData || SHA-256(clientDataJSON) with the stored key.
    const auto key = cose::parse(cred->publicKeyCose);
    if (!key.key) return Result::refuse(key.failure);
    Bytes message(response.authenticatorData);
    const auto clientDataHash = sha256(response.clientDataJSON);
    message.insert(message.end(), clientDataHash.begin(), clientDataHash.end());
    if (!cose::verify(*key.key, message, response.signature)) return Result::refuse(Failure::SignatureInvalid);

    // 13: BE never changes for a credential; BS is stored as reported.
    if (ad.data->flags.backupEligible != cred->backupEligible) return Result::refuse(Failure::BackupEligibilityChanged);

    VerifiedAssertion out;
    out.userId = cred->userId;
    out.credentialId = cred->id;
    out.userVerified = ad.data->flags.userVerified;
    out.backupState = ad.data->flags.backupState;

    // 14: the backup-aware signCount table. Synced passkeys report 0 forever.
    const auto stored = cred->signCount;
    const auto received = ad.data->signCount;
    if (received > stored) {
        out.signCount = received;
        out.storeSignCount = true;
    } else if (stored != 0) {
        if (!cred->backupEligible) return Result::refuse(Failure::SignCountRegression, /*suspend=*/true);
        out.signCount = stored;
        out.counterRegression = true;
    }
    return Result::ok(std::move(out));
}

Verifier::Verifier(RelyingParty rp, ChallengeStore& challenges, const CredentialLookup& credentials)
    : rp_(std::move(rp)), challenges_(challenges), credentials_(credentials) {}

Failure Verifier::claimChallenge(const ByteView clientDataJSON, const Expectation& expected,
                                 const ChallengeStore::Clock::time_point now, Bytes& challenge) const {
    if (clientDataJSON.size() > clientdata::kMaxBytes) return Failure::InputTooLarge;
    const auto c = clientdata::parse(clientDataJSON);
    if (!c) return Failure::ClientDataMalformed;
    auto value = base64urlDecode(c->challenge);
    if (!value || value->size() != ChallengeStore::kBytes) return Failure::ChallengeUnknown;
    if (const auto f = challenges_.consume(*value, expected, now); f != Failure::None) return f;
    challenge = std::move(*value);
    return Failure::None;
}

Outcome<NewCredential> Verifier::registration(const RegistrationResponse& response, const Expectation& expected,
                                              const ChallengeStore::Clock::time_point now) const {
    using Result = Outcome<NewCredential>;
    if (!rp_.configured()) return Result::refuse(Failure::NotConfigured);
    if (expected.purpose != Purpose::Register || !expected.user) return Result::refuse(Failure::ChallengePurposeMismatch);
    Bytes challenge;
    if (const auto f = claimChallenge(response.clientDataJSON, expected, now, challenge); f != Failure::None)
        return Result::refuse(f);
    return verifyRegistration(rp_, challenge, response, credentials_);
}

Outcome<VerifiedAssertion> Verifier::assertion(const AssertionResponse& response, const Expectation& expected,
                                               const ChallengeStore::Clock::time_point now) const {
    using Result = Outcome<VerifiedAssertion>;
    if (!rp_.configured()) return Result::refuse(Failure::NotConfigured);
    if (expected.purpose == Purpose::Register) return Result::refuse(Failure::ChallengePurposeMismatch);
    Bytes challenge;
    if (const auto f = claimChallenge(response.clientDataJSON, expected, now, challenge); f != Failure::None)
        return Result::refuse(f);
    return verifyAssertion(rp_, challenge, response, credentials_, expected);
}

}
