// The published W3C WebAuthn Level 3 test vectors (section 16, https://www.w3.org/TR/webauthn-3/#sctn-test-vectors),
// extracted verbatim into core/test-assets/webauthn/w3c-webauthn-l3-vectors.json by
// tools/dev/extract_w3c_webauthn_vectors.py (#355). RP ID example.org, origin https://example.org.
//
// Every vector runs through the real verifier. Those in scope (ES256, EdDSA, RS256; none, packed self and packed
// x5c, plus formats recorded as "none") register and then sign in with the credential they registered. The rest are
// published negative vectors: crossOrigin true (one with a topOrigin too), and algorithms out of scope (ES384, ES512, Ed448).
//
// Several vectors carry UV = 0. They run with UserVerification::Preferred (the spec's policy knob) so their parsing and
// signatures are checked, and again with Required (the daemon's only setting), where every UV = 0 vector refuses.

#include "auth/webauthn/AuthenticatorData.hpp"
#include "auth/webauthn/Attestation.hpp"
#include "auth/webauthn/Verifier.hpp"
#include "webauthn/Fixtures.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <filesystem>
#include <fstream>
#include <map>

namespace vh::test_webauthn {

namespace {

using wa::AttestationType;
using wa::Failure;

struct Expected {
    Failure registration = Failure::None;
    AttestationType type = AttestationType::None;
    wa::Algorithm algorithm = wa::Algorithm::ES256;
    Failure assertion = Failure::None;  // with the credential the registration would have stored
};

const std::map<std::string, Expected>& expectations() {
    static const std::map<std::string, Expected> m{
        {"16.2", {Failure::None, AttestationType::None}},
        {"16.3", {Failure::None, AttestationType::Self}},
        {"16.4", {Failure::CrossOrigin, AttestationType::None, wa::Algorithm::ES256, Failure::CrossOrigin}},
        // crossOrigin true and a topOrigin: crossOrigin is checked first (topOrigin alone: WebAuthnChecks).
        {"16.5", {Failure::CrossOrigin, AttestationType::None, wa::Algorithm::ES256, Failure::CrossOrigin}},
        {"16.6", {Failure::None, AttestationType::None}},  // a 1023-byte credential id
        {"16.7", {Failure::None, AttestationType::Basic}},
        {"16.8", {Failure::UnsupportedAlgorithm}},
        {"16.9", {Failure::UnsupportedAlgorithm}},
        {"16.10", {Failure::None, AttestationType::Basic, wa::Algorithm::RS256}},
        {"16.11", {Failure::None, AttestationType::Basic, wa::Algorithm::EdDSA}},
        {"16.12", {Failure::UnsupportedAlgorithm}},  // Ed448
        {"16.13", {Failure::None, AttestationType::Unverified}},  // tpm
        {"16.14", {Failure::None, AttestationType::Unverified}},  // android-key
        {"16.15", {Failure::None, AttestationType::Unverified}},  // apple
        {"16.16", {Failure::None, AttestationType::Unverified}},  // fido-u2f
    };
    return m;
}

nlohmann::json vectors() {
    std::ifstream in(std::filesystem::path(VH_TEST_ASSETS_DIR) / "webauthn" / "w3c-webauthn-l3-vectors.json");
    return nlohmann::json::parse(in);
}

Bytes field(const nlohmann::json& ceremony, const char* key) { return hex(ceremony.at(key).get<std::string>()); }

wa::RelyingParty w3c(const wa::UserVerification uv) { return {"example.org", {"https://example.org"}, uv}; }

wa::RegistrationResponse registrationOf(const nlohmann::json& v) {
    const auto& r = v.at("registration");
    return {field(r, "credential_id"), field(r, "clientDataJSON"), field(r, "attestationObject"), {}, {}};
}

wa::AssertionResponse assertionOf(const nlohmann::json& v) {
    const auto& a = v.at("authentication");
    return {field(v.at("registration"), "credential_id"), field(a, "clientDataJSON"), field(a, "authenticatorData"),
            field(a, "signature"), std::nullopt};
}

// The credential straight out of the attestation object, for vectors whose registration is refused on purpose.
wa::StoredCredential parsedCredential(const nlohmann::json& v) {
    const auto att = wa::attestation::parse(registrationOf(v).attestationObject);
    const auto ad = wa::authdata::parse(att.object->authData);
    wa::StoredCredential s;
    s.id = ad.data->attested->credentialId;
    s.publicKeyCose = ad.data->attested->publicKeyCose;
    s.userId = 1;
    s.rpId = "example.org";
    s.signCount = ad.data->signCount;
    s.backupEligible = ad.data->flags.backupEligible;
    s.backupState = ad.data->flags.backupState;
    return s;
}

bool registrationUserVerified(const nlohmann::json& v) {
    const auto att = wa::attestation::parse(registrationOf(v).attestationObject);
    return wa::authdata::parse(att.object->authData).data->flags.userVerified;
}

bool assertionUserVerified(const nlohmann::json& v) {
    return wa::authdata::parse(assertionOf(v).authenticatorData).data->flags.userVerified;
}

}

TEST(WebAuthnW3cVectors, TheAssetIsTheSpecificationsSection16) {
    const auto doc = vectors();
    EXPECT_NE(doc.at("source").get<std::string>().find("https://www.w3.org/TR/webauthn-3/#sctn-test-vectors"),
              std::string::npos);
    ASSERT_EQ(doc.at("vectors").size(), expectations().size());
    for (const auto& v : doc.at("vectors")) EXPECT_TRUE(expectations().contains(v.at("section").get<std::string>()));
}

TEST(WebAuthnW3cVectors, RegisterAndSignInAsPublished) {
    const auto rp = w3c(wa::UserVerification::Preferred);
    const auto doc = vectors();
    std::size_t signedIn_ = 0;
    for (const auto& v : doc.at("vectors")) {
        const auto section = v.at("section").get<std::string>();
        SCOPED_TRACE(section + " " + v.at("title").get<std::string>());
        const auto& want = expectations().at(section);
        MemoryCredentials credentials;
        const auto reg = wa::verifyRegistration(rp, field(v.at("registration"), "challenge"), registrationOf(v),
                                                credentials);
        EXPECT_EQ(reg.failure, want.registration) << wa::toString(reg.failure);
        if (want.registration == Failure::None) {
            ASSERT_TRUE(reg);
            EXPECT_EQ(reg.value->algorithm, want.algorithm);
            EXPECT_EQ(reg.value->attestationType, want.type) << wa::toString(reg.value->attestationType);
            EXPECT_EQ(reg.value->id, field(v.at("registration"), "credential_id"));
            credentials.store(*reg.value, 1, {});
        } else if (want.assertion != Failure::None) {
            credentials.rows.push_back(parsedCredential(v));
        } else {
            continue;  // an algorithm out of scope never becomes a credential
        }
        const auto signedIn = wa::verifyAssertion(rp, field(v.at("authentication"), "challenge"), assertionOf(v),
                                                  credentials, {"s", wa::Purpose::Mfa, 1, {}});
        EXPECT_EQ(signedIn.failure, want.assertion) << wa::toString(signedIn.failure);
        if (want.assertion == Failure::None) {
            ASSERT_TRUE(signedIn);
            EXPECT_EQ(signedIn.value->userId, 1);
            ++signedIn_;
        }
    }
    EXPECT_EQ(signedIn_, 10u) << "ten vectors register and sign in";
}

TEST(WebAuthnW3cVectors, TheDaemonsPolicyRefusesEveryVectorWithoutUserVerification) {
    const auto rp = w3c(wa::UserVerification::Required);
    std::size_t refusedRegistrations = 0, refusedAssertions = 0;
    const auto doc = vectors();
    for (const auto& v : doc.at("vectors")) {
        const auto section = v.at("section").get<std::string>();
        SCOPED_TRACE(section);
        const auto& want = expectations().at(section);
        if (want.registration != Failure::None) continue;
        MemoryCredentials credentials;
        const auto reg = wa::verifyRegistration(rp, field(v.at("registration"), "challenge"), registrationOf(v),
                                                credentials);
        if (!registrationUserVerified(v)) {
            EXPECT_EQ(reg.failure, Failure::UserNotVerified);
            ++refusedRegistrations;
        } else {
            EXPECT_EQ(reg.failure, Failure::None) << wa::toString(reg.failure);
        }
        credentials.rows.push_back(parsedCredential(v));
        const auto signedIn = wa::verifyAssertion(rp, field(v.at("authentication"), "challenge"), assertionOf(v),
                                                  credentials, {"s", wa::Purpose::Mfa, 1, {}});
        EXPECT_EQ(signedIn.failure, assertionUserVerified(v) ? Failure::None : Failure::UserNotVerified);
        if (!assertionUserVerified(v)) ++refusedAssertions;
    }
    EXPECT_GT(refusedRegistrations, 0u);
    EXPECT_GT(refusedAssertions, 0u);
}

// The same published ceremonies, each with one property changed: proof that the checks bite on real authenticator
// output and not only on this suite's own fixtures.
TEST(WebAuthnW3cVectors, PublishedCeremoniesRefuseWhenAnythingChanges) {
    const auto rp = w3c(wa::UserVerification::Preferred);
    const auto doc = vectors();
    const auto& v = doc.at("vectors").at(1);  // 16.3, packed self attestation
    ASSERT_EQ(v.at("section").get<std::string>(), "16.3");
    const auto challenge = field(v.at("registration"), "challenge");
    MemoryCredentials none;

    auto wrongChallenge = challenge;
    wrongChallenge[0] ^= 1;
    EXPECT_EQ(wa::verifyRegistration(rp, wrongChallenge, registrationOf(v), none).failure,
              Failure::ClientDataChallengeMismatch);
    EXPECT_EQ(wa::verifyRegistration({"example.com", {"https://example.org"}, wa::UserVerification::Preferred},
                                     challenge, registrationOf(v), none).failure,
              Failure::RpIdHashMismatch);
    EXPECT_EQ(wa::verifyRegistration({"example.org", {"https://example.com"}, wa::UserVerification::Preferred},
                                     challenge, registrationOf(v), none).failure,
              Failure::OriginMismatch);
    auto tampered = registrationOf(v);
    tampered.clientDataJSON.back() = ' ';  // the attestation signature covers the clientDataJSON hash
    tampered.clientDataJSON.push_back('}');
    EXPECT_EQ(wa::verifyRegistration(rp, challenge, tampered, none).failure, Failure::AttestationSignatureInvalid);
    auto trailing = registrationOf(v);
    trailing.attestationObject.push_back(0x00);
    EXPECT_EQ(wa::verifyRegistration(rp, challenge, trailing, none).failure, Failure::AttestationMalformed);

    auto reg = wa::verifyRegistration(rp, challenge, registrationOf(v), none);
    ASSERT_TRUE(reg);
    MemoryCredentials credentials;
    credentials.store(*reg.value, 1, {});
    EXPECT_EQ(wa::verifyRegistration(rp, challenge, registrationOf(v), credentials).failure,
              Failure::CredentialAlreadyRegistered);
    const auto authChallenge = field(v.at("authentication"), "challenge");
    const wa::Expectation mfa{"s", wa::Purpose::Mfa, 1, {}};
    auto badSig = assertionOf(v);
    badSig.signature[badSig.signature.size() - 1] ^= 1;
    EXPECT_EQ(wa::verifyAssertion(rp, authChallenge, badSig, credentials, mfa).failure, Failure::SignatureInvalid);
    auto badData = assertionOf(v);
    badData.authenticatorData[36] ^= 1;  // signCount: covered by the signature
    EXPECT_EQ(wa::verifyAssertion(rp, authChallenge, badData, credentials, mfa).failure, Failure::SignatureInvalid);
    EXPECT_EQ(wa::verifyAssertion(rp, authChallenge, assertionOf(v), credentials, {"s", wa::Purpose::Mfa, 2, {}}).failure,
              Failure::CredentialOwnerMismatch);
    EXPECT_EQ(wa::verifyAssertion(rp, authChallenge, assertionOf(v), credentials, mfa).failure, Failure::None);
}

}
