// The WebAuthn verifier's ceremonies (#355, docs/dev/mfa-design.md section 4.1): registration and assertion through
// the challenge store for every algorithm in scope, and at least one negative test per check of the table, each made
// with an otherwise valid, correctly signed ceremony so that only the property under test is wrong.

#include "auth/webauthn/Challenge.hpp"
#include "auth/webauthn/Verifier.hpp"
#include "webauthn/Fixtures.hpp"

#include <gtest/gtest.h>

#include <chrono>

namespace vh::test_webauthn {

namespace {

using wa::Failure;
using wa::Purpose;
using Clock = wa::ChallengeStore::Clock;

constexpr std::int64_t kUser = 41;
constexpr std::int64_t kOtherUser = 42;

wa::Expectation expect(const Purpose p, const std::optional<std::int64_t> user = kUser, std::string scope = {},
                       std::string session = "ws-session-1") {
    return {std::move(session), p, user, std::move(scope)};
}

}

class WebAuthnCeremony : public ::testing::TestWithParam<wa::Algorithm> {
protected:
    wa::RelyingParty rp = relyingParty();
    wa::ChallengeStore store;
    MemoryCredentials credentials;
    wa::Verifier verifier{rp, store, credentials};
    Bytes handle = randomBytes(32);
    Clock::time_point now = Clock::now();

    struct Registration {
        std::string type = "webauthn.create";
        std::string origin = std::string(kOrigin);
        std::string extra;
        std::uint8_t flags = flags::UP | flags::UV | flags::AT;
        std::uint32_t signCount = 0;
        std::string rpId = std::string(kRpId);
        std::size_t credentialIdBytes = 32;
        bool packed = false;
    };

    Bytes challengeFor(const wa::Expectation& e) {
        const auto c = store.issue(e, now);
        EXPECT_TRUE(c);
        return {c->begin(), c->end()};
    }

    static void same(auto&) {}

    template <class Tweak = void (*)(Registration&)>
    wa::RegistrationResponse registration(const TestKey& key, const Bytes& challenge, Tweak tweak = &same<Registration>) {
        Registration o;
        tweak(o);
        wa::RegistrationResponse r;
        const auto cd = clientDataJSON(o.type, challenge, o.origin, o.extra);
        r.clientDataJSON = bytesOf(cd);
        Attested a;
        a.aaguid[0] = 0xAA;
        a.credentialId = randomBytes(o.credentialIdBytes);
        a.cose = key.cose();
        r.rawId = a.credentialId;
        const auto ad = authenticatorData(o.flags, o.signCount, a, o.rpId);
        r.attestationObject = o.packed ? attestationPackedSelf(ad, key, sha256(r.clientDataJSON)) : attestationNone(ad);
        return r;
    }

    // Registers a fresh credential of this key for kUser and stores it.
    wa::StoredCredential& enrolled(const TestKey& key, const std::uint8_t extraFlags = 0, const std::uint32_t count = 0) {
        const auto e = expect(Purpose::Register);
        const auto out = verifier.registration(registration(key, challengeFor(e), [&](Registration& o) {
            o.flags |= extraFlags;
            o.signCount = count;
        }), e, now);
        EXPECT_TRUE(out) << wa::toString(out.failure);
        return credentials.store(*out.value, kUser, handle);
    }

    struct Assertion {
        std::string type = "webauthn.get";
        std::string origin = std::string(kOrigin);
        std::string extra;
        std::uint8_t flags = flags::UP | flags::UV;
        std::uint32_t signCount = 0;
        std::string rpId = std::string(kRpId);
        std::optional<Bytes> userHandle;
        const TestKey* signer = nullptr;  // another key: a wrong signature
        bool corruptSignature = false;
        std::optional<Attested> attested;
    };

    template <class Tweak = void (*)(Assertion&)>
    wa::AssertionResponse assertion(const TestKey& key, const wa::StoredCredential& cred, const Bytes& challenge,
                                    Tweak tweak = &same<Assertion>) {
        Assertion o;
        tweak(o);
        wa::AssertionResponse r;
        r.rawId = cred.id;
        r.clientDataJSON = bytesOf(clientDataJSON(o.type, challenge, o.origin, o.extra));
        r.authenticatorData = authenticatorData(o.flags, o.signCount, o.attested, o.rpId);
        r.signature = (o.signer ? *o.signer : key).sign(concat({r.authenticatorData, sha256(r.clientDataJSON)}));
        if (o.corruptSignature) r.signature.back() ^= 0x01;
        r.userHandle = o.userHandle;
        return r;
    }

    template <class Tweak = void (*)(Assertion&)>
    wa::Outcome<wa::VerifiedAssertion> assertMfa(const TestKey& key, const wa::StoredCredential& cred,
                                                 Tweak tweak = &same<Assertion>) {
        const auto e = expect(Purpose::Mfa);
        return verifier.assertion(assertion(key, cred, challengeFor(e), tweak), e, now);
    }

    template <class Tweak>
    Failure registerWith(const TestKey& key, Tweak tweak) {
        const auto e = expect(Purpose::Register);
        return verifier.registration(registration(key, challengeFor(e), tweak), e, now).failure;
    }
};

inline std::string algorithmName(const ::testing::TestParamInfo<wa::Algorithm>& info) {
    return std::string(wa::toString(info.param));
}

INSTANTIATE_TEST_SUITE_P(Algorithms, WebAuthnCeremony,
                         ::testing::Values(wa::Algorithm::ES256, wa::Algorithm::EdDSA, wa::Algorithm::RS256),
                         algorithmName);

TEST_P(WebAuthnCeremony, RegistersAndSignsIn) {
    const TestKey key(GetParam());
    const auto e = expect(Purpose::Register);
    const auto reg = verifier.registration(registration(key, challengeFor(e)), e, now);
    ASSERT_TRUE(reg) << wa::toString(reg.failure);
    EXPECT_EQ(reg.value->algorithm, GetParam());
    EXPECT_EQ(reg.value->attestationType, wa::AttestationType::None);
    EXPECT_EQ(reg.value->attestationFormat, "none");
    EXPECT_EQ(reg.value->rpId, kRpId);
    EXPECT_EQ(reg.value->aaguid[0], 0xAA);
    auto& cred = credentials.store(*reg.value, kUser, handle);

    const auto signedIn = assertMfa(key, cred, [&](auto& o) { o.signCount = 0; });
    ASSERT_TRUE(signedIn) << wa::toString(signedIn.failure);
    EXPECT_EQ(signedIn.value->userId, kUser);
    EXPECT_TRUE(signedIn.value->userVerified);
    EXPECT_FALSE(signedIn.value->storeSignCount);
    EXPECT_FALSE(signedIn.value->counterRegression);
}

TEST_P(WebAuthnCeremony, PackedSelfAttestationIsVerified) {
    const TestKey key(GetParam());
    const auto e = expect(Purpose::Register);
    const auto reg = verifier.registration(registration(key, challengeFor(e), [](Registration& o) { o.packed = true; }), e, now);
    ASSERT_TRUE(reg) << wa::toString(reg.failure);
    EXPECT_EQ(reg.value->attestationType, wa::AttestationType::Self);
}

TEST_P(WebAuthnCeremony, PackedSelfAttestationWithAWrongSignatureOrAlgorithmIsRefused) {
    const TestKey key(GetParam());
    const TestKey other(GetParam());
    const auto e = expect(Purpose::Register);
    auto r = registration(key, challengeFor(e));
    // Re-wrap the same authData in a packed statement signed by another key.
    const auto cd = sha256(r.clientDataJSON);
    Attested a;
    a.aaguid[0] = 0xAA;
    a.credentialId = r.rawId;
    a.cose = key.cose();
    const auto ad = authenticatorData(flags::UP | flags::UV | flags::AT, 0, a);
    r.attestationObject = attestationPackedSelf(ad, other, cd);
    EXPECT_EQ(verifier.registration(r, e, now).failure, Failure::AttestationSignatureInvalid);

    const auto e2 = expect(Purpose::Register);
    auto r2 = registration(key, challengeFor(e2));
    a.credentialId = r2.rawId;
    const auto ad2 = authenticatorData(flags::UP | flags::UV | flags::AT, 0, a);
    const auto wrongAlg = GetParam() == wa::Algorithm::ES256 ? -8 : -7;
    r2.attestationObject = attestationPackedSelf(ad2, key, sha256(r2.clientDataJSON), wrongAlg);
    EXPECT_EQ(verifier.registration(r2, e2, now).failure, Failure::AttestationAlgorithmMismatch);
}

TEST_P(WebAuthnCeremony, DiscoverableLoginTakesTheUserFromTheUserHandle) {
    const TestKey key(GetParam());
    const auto& cred = enrolled(key);
    const auto e = expect(Purpose::Login, std::nullopt);
    const auto ok = verifier.assertion(assertion(key, cred, challengeFor(e), [&](auto& o) { o.userHandle = handle; }), e, now);
    ASSERT_TRUE(ok) << wa::toString(ok.failure);
    EXPECT_EQ(ok.value->userId, kUser);

    const auto e2 = expect(Purpose::Login, std::nullopt);
    EXPECT_EQ(verifier.assertion(assertion(key, cred, challengeFor(e2)), e2, now).failure, Failure::UserHandleMissing);
    const auto e3 = expect(Purpose::Login, std::nullopt);
    EXPECT_EQ(verifier.assertion(assertion(key, cred, challengeFor(e3), [&](auto& o) { o.userHandle = randomBytes(32); }), e3, now).failure,
              Failure::UserHandleMismatch);
}

// Check 12.
TEST_P(WebAuthnCeremony, AWrongSignatureIsRefused) {
    const TestKey key(GetParam());
    const TestKey other(GetParam());
    const auto& cred = enrolled(key);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.signer = &other; }).failure, Failure::SignatureInvalid);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.corruptSignature = true; }).failure, Failure::SignatureInvalid);
}

// Check 7, both ceremonies.
TEST_P(WebAuthnCeremony, UserPresenceAndVerificationAreRequired) {
    const TestKey key(GetParam());
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.flags = flags::UV | flags::AT; }), Failure::UserNotPresent);
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.flags = flags::UP | flags::AT; }), Failure::UserNotVerified);
    const auto& cred = enrolled(key);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.flags = flags::UV; }).failure, Failure::UserNotPresent);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.flags = flags::UP; }).failure, Failure::UserNotVerified);
}

// Check 6, both ceremonies.
TEST_P(WebAuthnCeremony, AnotherRpIdHashIsRefused) {
    const TestKey key(GetParam());
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.rpId = "example.test"; }), Failure::RpIdHashMismatch);
    const auto& cred = enrolled(key);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.rpId = "evil.example.test"; }).failure, Failure::RpIdHashMismatch);
}

class WebAuthnChecks : public WebAuthnCeremony {};

INSTANTIATE_TEST_SUITE_P(Es256, WebAuthnChecks, ::testing::Values(wa::Algorithm::ES256), algorithmName);

// Check 2.
TEST_P(WebAuthnChecks, TheWrongCeremonyTypeIsRefused) {
    const TestKey key(GetParam());
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.type = "webauthn.get"; }), Failure::ClientDataTypeMismatch);
    const auto& cred = enrolled(key);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.type = "webauthn.create"; }).failure, Failure::ClientDataTypeMismatch);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.type = "payment.get"; }).failure, Failure::ClientDataTypeMismatch);
}

// Check 4: configured origins only, exactly.
TEST_P(WebAuthnChecks, AForeignOriginIsRefused) {
    const TestKey key(GetParam());
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.origin = "https://evil.example"; }), Failure::OriginMismatch);
    const auto& cred = enrolled(key);
    for (const auto* origin : {"https://evil.example", "https://vault.example.test:8443", "http://vault.example.test",
                               "https://VAULT.example.test", "https://vault.example.test/", "https://sub.vault.example.test"})
        EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.origin = origin; }).failure, Failure::OriginMismatch) << origin;
}

// Check 5.
TEST_P(WebAuthnChecks, CrossOriginAndTopOriginAreRefused) {
    const TestKey key(GetParam());
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.extra = R"(,"crossOrigin":true)"; }), Failure::CrossOrigin);
    const auto& cred = enrolled(key);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.extra = R"(,"crossOrigin":true)"; }).failure, Failure::CrossOrigin);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.extra = R"(,"crossOrigin":false,"topOrigin":"https://vault.example.test")"; }).failure,
              Failure::TopOrigin);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.extra = R"(,"crossOrigin":"false")"; }).failure, Failure::ClientDataMalformed);
    // An absent crossOrigin is fine (older clients).
    EXPECT_TRUE(assertMfa(key, cred, [&](auto& o) { o.extra = R"(,"other_keys_can_be_added_here":"do not compare clientDataJSON")"; }));
}

// Check 1: the challenge record.
TEST_P(WebAuthnChecks, ChallengesAreSingleUseShortLivedAndBound) {
    const TestKey key(GetParam());
    const auto& cred = enrolled(key);
    const auto e = expect(Purpose::Mfa);
    const auto challenge = challengeFor(e);
    const auto response = assertion(key, cred, challenge);
    EXPECT_TRUE(verifier.assertion(response, e, now));
    EXPECT_EQ(verifier.assertion(response, e, now).failure, Failure::ChallengeUnknown) << "reused";

    const auto expired = assertion(key, cred, challengeFor(e));
    EXPECT_EQ(verifier.assertion(expired, e, now + std::chrono::seconds(121)).failure, Failure::ChallengeExpired);

    const auto foreign = assertion(key, cred, challengeFor(expect(Purpose::Mfa, kUser, {}, "ws-session-2")));
    EXPECT_EQ(verifier.assertion(foreign, e, now).failure, Failure::ChallengeSessionMismatch);

    const auto otherPurpose = assertion(key, cred, challengeFor(expect(Purpose::StepUp, kUser, "keys")));
    EXPECT_EQ(verifier.assertion(otherPurpose, e, now).failure, Failure::ChallengePurposeMismatch);

    const auto otherUser = assertion(key, cred, challengeFor(expect(Purpose::Mfa, kOtherUser)));
    EXPECT_EQ(verifier.assertion(otherUser, e, now).failure, Failure::ChallengeUserMismatch);

    const auto stepUp = expect(Purpose::StepUp, kUser, "keys:vault:7");
    const auto otherTarget = assertion(key, cred, challengeFor(expect(Purpose::StepUp, kUser, "keys:vault:8")));
    EXPECT_EQ(verifier.assertion(otherTarget, stepUp, now).failure, Failure::ChallengeScopeMismatch);
    EXPECT_TRUE(verifier.assertion(assertion(key, cred, challengeFor(stepUp)), stepUp, now));

    const auto unknown = assertion(key, cred, randomBytes(32));
    EXPECT_EQ(verifier.assertion(unknown, e, now).failure, Failure::ChallengeUnknown);
    const auto shortChallenge = assertion(key, cred, randomBytes(16));
    EXPECT_EQ(verifier.assertion(shortChallenge, e, now).failure, Failure::ChallengeUnknown);
}

TEST_P(WebAuthnChecks, AFailedAttemptBurnsTheChallenge) {
    const TestKey key(GetParam());
    const TestKey other(GetParam());
    const auto& cred = enrolled(key);
    const auto e = expect(Purpose::Mfa);
    const auto challenge = challengeFor(e);
    EXPECT_EQ(verifier.assertion(assertion(key, cred, challenge, [&](auto& o) { o.signer = &other; }), e, now).failure,
              Failure::SignatureInvalid);
    EXPECT_EQ(verifier.assertion(assertion(key, cred, challenge), e, now).failure, Failure::ChallengeUnknown);
}

// Check 3 (the pure layer: a challenge other than the record's).
TEST_P(WebAuthnChecks, AChallengeOtherThanTheExpectedOneIsRefused) {
    const TestKey key(GetParam());
    const auto& cred = enrolled(key);
    const auto r = assertion(key, cred, randomBytes(32));
    EXPECT_EQ(wa::verifyAssertion(rp, randomBytes(32), r, credentials, expect(Purpose::Mfa)).failure,
              Failure::ClientDataChallengeMismatch);
    EXPECT_EQ(wa::verifyAssertion(rp, {}, r, credentials, expect(Purpose::Mfa)).failure,
              Failure::ClientDataChallengeMismatch);
}

// Check 8.
TEST_P(WebAuthnChecks, AttestedCredentialDataIsChecked) {
    const TestKey key(GetParam());
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.flags = flags::UP | flags::UV; }), Failure::AuthenticatorDataMalformed)
        << "AT clear but credential data present: trailing bytes";
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.credentialIdBytes = 15; }), Failure::CredentialIdLength);
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.credentialIdBytes = 16; }), Failure::None);
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.credentialIdBytes = 1023; }), Failure::None);
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.credentialIdBytes = 1024; }), Failure::CredentialIdLength);

    // AT clear and no credential data at all.
    const auto e = expect(Purpose::Register);
    auto r = registration(key, challengeFor(e));
    r.attestationObject = attestationNone(authenticatorData(flags::UP | flags::UV, 0));
    EXPECT_EQ(verifier.registration(r, e, now).failure, Failure::AttestedCredentialMissing);

    // rawId must name the attested credential.
    const auto e2 = expect(Purpose::Register);
    auto r2 = registration(key, challengeFor(e2));
    r2.rawId = randomBytes(32);
    EXPECT_EQ(verifier.registration(r2, e2, now).failure, Failure::CredentialIdMismatch);

    // A credential id already registered, to anyone.
    const auto e3 = expect(Purpose::Register);
    auto r3 = registration(key, challengeFor(e3));
    const auto first = wa::verifyRegistration(rp, {}, r3, credentials);  // no challenge: refused, nothing stored
    EXPECT_FALSE(first);
    auto ok = verifier.registration(r3, e3, now);
    ASSERT_TRUE(ok);
    credentials.store(*ok.value, kOtherUser, randomBytes(32));
    const auto e4 = expect(Purpose::Register);
    auto r4 = registration(key, challengeFor(e4));
    Attested a;
    a.credentialId = r3.rawId;
    a.cose = key.cose();
    r4.rawId = r3.rawId;
    r4.attestationObject = attestationNone(authenticatorData(flags::UP | flags::UV | flags::AT, 0, a));
    EXPECT_EQ(verifier.registration(r4, e4, now).failure, Failure::CredentialAlreadyRegistered);

    // An assertion never carries attested credential data.
    const auto& cred = enrolled(key);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.flags = flags::UP | flags::UV | flags::AT; }).failure,
              Failure::AuthenticatorDataMalformed);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) {
                  o.flags = flags::UP | flags::UV | flags::AT;
                  o.attested = Attested{{}, cred.id, key.cose()};
              }).failure,
              Failure::AttestedCredentialUnexpected);
}

// Check 11.
TEST_P(WebAuthnChecks, TheCredentialMustBeLiveOurOwnAndOwnedByTheUser) {
    const TestKey key(GetParam());
    auto& cred = enrolled(key);
    // Wrong owner: the challenge is for kOtherUser, the credential is kUser's.
    const auto e = expect(Purpose::Mfa, kOtherUser);
    EXPECT_EQ(verifier.assertion(assertion(key, cred, challengeFor(e)), e, now).failure,
              Failure::CredentialOwnerMismatch);
    EXPECT_EQ(assertMfa(key, cred, [&](auto& o) { o.userHandle = randomBytes(32); }).failure, Failure::UserHandleMismatch);
    EXPECT_TRUE(assertMfa(key, cred, [&](auto& o) { o.userHandle = handle; }));
    EXPECT_TRUE(assertMfa(key, cred, [](auto& o) { o.userHandle = Bytes{}; })) << "an empty userHandle is no userHandle";

    auto unknown = cred;
    unknown.id = randomBytes(32);
    EXPECT_EQ(assertMfa(key, unknown).failure, Failure::CredentialUnknown);

    credentials.rows.back().disabled = true;
    EXPECT_EQ(assertMfa(key, cred).failure, Failure::CredentialDisabled);
    credentials.rows.back().disabled = false;
    credentials.rows.back().suspended = true;
    EXPECT_EQ(assertMfa(key, cred).failure, Failure::CredentialSuspended);
    credentials.rows.back().suspended = false;
    credentials.rows.back().rpId = "old.example.test";
    EXPECT_EQ(assertMfa(key, cred).failure, Failure::CredentialRpIdMismatch);
}

// Check 13.
TEST_P(WebAuthnChecks, BackupEligibilityNeverChangesAndBackupStateNeedsIt) {
    const TestKey key(GetParam());
    const auto& deviceBound = enrolled(key);
    EXPECT_EQ(assertMfa(key, deviceBound, [&](auto& o) { o.flags = flags::UP | flags::UV | flags::BE; }).failure,
              Failure::BackupEligibilityChanged);
    const TestKey synced(GetParam());
    const auto& syncedCred = enrolled(synced, flags::BE | flags::BS);
    EXPECT_EQ(assertMfa(synced, syncedCred).failure, Failure::BackupEligibilityChanged) << "BE 1 -> 0";
    const auto ok = assertMfa(synced, syncedCred, [&](auto& o) { o.flags = flags::UP | flags::UV | flags::BE; });
    ASSERT_TRUE(ok);
    EXPECT_FALSE(ok.value->backupState) << "BS is reported as it is, to be stored";
    EXPECT_EQ(assertMfa(key, deviceBound, [&](auto& o) { o.flags = flags::UP | flags::UV | flags::BS; }).failure,
              Failure::BackupStateWithoutEligibility);
    EXPECT_EQ(registerWith(key, [&](auto& o) { o.flags = flags::UP | flags::UV | flags::AT | flags::BS; }),
              Failure::BackupStateWithoutEligibility);
}

// Check 14: the backup-aware signCount table.
TEST_P(WebAuthnChecks, SignCountFollowsTheBackupAwareTable) {
    const TestKey key(GetParam());
    auto& deviceBound = enrolled(key, 0, 5);
    const auto grew = assertMfa(key, deviceBound, [&](auto& o) { o.signCount = 6; });
    ASSERT_TRUE(grew);
    EXPECT_TRUE(grew.value->storeSignCount);
    EXPECT_EQ(grew.value->signCount, 6u);
    credentials.rows.back().signCount = 6;
    for (const std::uint32_t regressed : {6u, 2u, 0u}) {
        const auto refused = assertMfa(key, deviceBound, [&](auto& o) { o.signCount = regressed; });
        EXPECT_EQ(refused.failure, Failure::SignCountRegression) << regressed;
        EXPECT_TRUE(refused.suspendCredential) << "a device-bound key that went backwards may be a clone";
    }

    const TestKey synced(GetParam());
    auto& syncedCred = enrolled(synced, flags::BE | flags::BS, 9);
    const auto regressed = assertMfa(synced, syncedCred, [&](auto& o) { o.flags = flags::UP | flags::UV | flags::BE | flags::BS; o.signCount = 3; });
    ASSERT_TRUE(regressed) << "a synced passkey's counter regression is audited, not refused";
    EXPECT_TRUE(regressed.value->counterRegression);
    EXPECT_FALSE(regressed.value->storeSignCount);

    const TestKey zero(GetParam());
    const auto& zeroCred = enrolled(zero, flags::BE | flags::BS, 0);
    const auto still = assertMfa(zero, zeroCred, [&](auto& o) { o.flags = flags::UP | flags::UV | flags::BE | flags::BS; });
    ASSERT_TRUE(still) << "synced passkeys report 0 forever";
    EXPECT_FALSE(still.value->counterRegression);
    EXPECT_FALSE(still.value->storeSignCount);
    const TestKey zeroBound(GetParam());
    const auto& zeroBoundCred = enrolled(zeroBound, 0, 0);
    EXPECT_TRUE(assertMfa(zeroBound, zeroBoundCred)) << "0 -> 0 is accepted whatever BE says";
}

TEST_P(WebAuthnChecks, NothingVerifiesWithoutAConfiguredRelyingParty) {
    const TestKey key(GetParam());
    wa::Verifier unconfigured({"", {}, {}}, store, credentials);
    const auto e = expect(Purpose::Register);
    EXPECT_EQ(unconfigured.registration(registration(key, challengeFor(e)), e, now).failure, Failure::NotConfigured);
    EXPECT_EQ(verifier.registration(registration(key, challengeFor(e)), expect(Purpose::Mfa), now).failure,
              Failure::ChallengePurposeMismatch);
}

// Check 9 on registration: keys outside the three algorithms, or not what they claim to be.
TEST_P(WebAuthnChecks, CredentialKeysAreValidated) {
    const TestKey es(wa::Algorithm::ES256);
    const auto withKey = [&](const Bytes& cose) {
        const auto e = expect(Purpose::Register);
        auto r = registration(es, challengeFor(e));
        Attested a;
        a.credentialId = r.rawId;
        a.cose = cose;
        r.attestationObject = attestationNone(authenticatorData(flags::UP | flags::UV | flags::AT, 0, a));
        return verifier.registration(r, e, now).failure;
    };
    CborWriter es384;
    es384.map(5).integer(1).integer(2).integer(3).integer(-35).integer(-1).integer(2).integer(-2).bytes(randomBytes(48))
        .integer(-3).bytes(randomBytes(48));
    EXPECT_EQ(withKey(es384.out), Failure::UnsupportedAlgorithm);

    auto badY = es.y;
    badY[31] ^= 0x01;
    CborWriter offCurve;
    offCurve.map(5).integer(1).integer(2).integer(3).integer(-7).integer(-1).integer(1).integer(-2).bytes(es.x)
        .integer(-3).bytes(badY);
    EXPECT_EQ(withKey(offCurve.out), Failure::InvalidPublicKey);

    const TestKey rsa1024(wa::Algorithm::RS256, 1024);
    EXPECT_EQ(withKey(rsa1024.cose()), Failure::RsaKeySize);
}

}
