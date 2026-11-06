// The WebAuthn verifier's strict parsers (#355): CBOR (definite lengths, no trailing bytes, no duplicate map keys,
// bounded nesting and sizes), COSE keys, authenticatorData, clientDataJSON, the browser's response JSON, base64url and
// the auth.webauthn configuration rules. WebAuthnFuzzCorpus replays every committed fuzz input (and every crash that
// became a regression input) on every build.

#include "auth/webauthn/Attestation.hpp"
#include "auth/webauthn/AuthenticatorData.hpp"
#include "auth/webauthn/Base64Url.hpp"
#include "auth/webauthn/Cbor.hpp"
#include "auth/webauthn/Challenge.hpp"
#include "auth/webauthn/ClientData.hpp"
#include "auth/webauthn/Cose.hpp"
#include "auth/webauthn/RelyingParty.hpp"
#include "auth/webauthn/Wire.hpp"
#include "webauthn/Fixtures.hpp"

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <iterator>

namespace vh::test_webauthn {

namespace cbor = wa::cbor;
using wa::Failure;

namespace {

bool strict(const Bytes& b) { return cbor::decode(b) != nullptr; }

Bytes nested(const std::size_t depth) {
    CborWriter w;
    for (std::size_t i = 0; i < depth; ++i) w.array(1);
    w.integer(0);
    return w.out;
}

}

TEST(WebAuthnCbor, AcceptsTheStrictProfile) {
    CborWriter w;
    w.map(4).integer(1).integer(2).integer(-1).bytes(randomBytes(32)).text("k").text("v").text("b").byte(0xF5);
    EXPECT_TRUE(strict(w.out));
    EXPECT_TRUE(strict(nested(7)));
    EXPECT_EQ(cbor::scan(concat({w.out, Bytes{0x00}})), w.out.size()) << "scan reports the item's own length";
}

TEST(WebAuthnCbor, RefusesIndefiniteLengthsTagsFloatsAndOtherSimpleValues) {
    EXPECT_FALSE(strict({0x5F, 0x41, 0x00, 0xFF}));        // indefinite byte string
    EXPECT_FALSE(strict({0x7F, 0x61, 0x61, 0xFF}));        // indefinite text string
    EXPECT_FALSE(strict({0x9F, 0x01, 0xFF}));              // indefinite array
    EXPECT_FALSE(strict({0xBF, 0x01, 0x02, 0xFF}));        // indefinite map
    EXPECT_FALSE(strict({0xFF}));                          // a lone break
    EXPECT_FALSE(strict({0xC2, 0x41, 0x01}));              // tag 2 (bignum)
    EXPECT_FALSE(strict({0xF9, 0x3C, 0x00}));              // half float
    EXPECT_FALSE(strict({0xFB, 0, 0, 0, 0, 0, 0, 0, 0}));  // double
    EXPECT_FALSE(strict({0xF7}));                          // undefined
    EXPECT_FALSE(strict({0xF8, 0x20}));                    // simple(32)
    EXPECT_FALSE(strict({0x1C}));                          // reserved additional information
    EXPECT_TRUE(strict({0xF6}));                           // null
}

TEST(WebAuthnCbor, RefusesTrailingBytesAndTruncation) {
    EXPECT_FALSE(strict({0x01, 0x00}));
    EXPECT_FALSE(strict({0xA1, 0x01}));      // a map missing its value
    EXPECT_FALSE(strict({0x42, 0x00}));      // a byte string shorter than its length
    EXPECT_FALSE(strict({}));
    EXPECT_FALSE(strict({0x5B, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}));  // a 2^64-1 byte length
}

TEST(WebAuthnCbor, RefusesDuplicateAndNonScalarMapKeys) {
    CborWriter dup;
    dup.map(2).integer(3).integer(-7).integer(3).integer(-8);
    EXPECT_FALSE(strict(dup.out));
    CborWriter dupText;
    dupText.map(2).text("fmt").text("none").text("fmt").text("packed");
    EXPECT_FALSE(strict(dupText.out));
    // The same value under a longer encoding is still the same key.
    CborWriter longForm;
    longForm.map(2).integer(1).integer(0).byte(0x18).byte(0x01).integer(0);
    EXPECT_FALSE(strict(longForm.out));
    CborWriter nestedDup;
    nestedDup.map(1).text("a").map(2).integer(-1).integer(0).integer(-1).integer(1);
    EXPECT_FALSE(strict(nestedDup.out)) << "duplicates are refused at every level";
    CborWriter bytesKey;
    bytesKey.map(1).bytes(Bytes{1}).integer(0);
    EXPECT_FALSE(strict(bytesKey.out));
    CborWriter arrayKey;
    arrayKey.map(1).array(0).integer(0);
    EXPECT_FALSE(strict(arrayKey.out));
    CborWriter distinct;
    distinct.map(3).integer(1).integer(0).integer(-2).integer(0).text("1").integer(0);
    EXPECT_TRUE(strict(distinct.out)) << "1, -2 and \"1\" are different keys";
}

TEST(WebAuthnCbor, BoundsNestingSizesAndItemCount) {
    EXPECT_TRUE(strict(nested(8)));
    EXPECT_FALSE(strict(nested(9)));
    EXPECT_FALSE(strict(nested(10000)));
    CborWriter wide;
    wide.array(65);
    for (int i = 0; i < 65; ++i) wide.integer(i);
    EXPECT_FALSE(strict(wide.out));
    CborWriter huge;
    huge.map(0xFFFFFFFF);
    EXPECT_FALSE(strict(huge.out)) << "a claimed size is refused before anything is allocated";
    CborWriter many;  // 8 arrays of 64: 521 items
    many.array(8);
    for (int a = 0; a < 8; ++a) {
        many.array(64);
        for (int i = 0; i < 64; ++i) many.integer(0);
    }
    EXPECT_FALSE(strict(many.out));
}

TEST(WebAuthnCbor, TextStringsAreUtf8) {
    CborWriter ok;
    ok.text("p\xC3\xA5skey");
    EXPECT_TRUE(strict(ok.out));
    for (const auto* bad : {"\xC3", "\xC0\xAF", "\xED\xA0\x80", "\xF4\x90\x80\x80", "\xFF"}) {
        CborWriter w;
        w.text(bad);
        EXPECT_FALSE(strict(w.out)) << bad;
    }
}

TEST(WebAuthnCose, RefusesKeysOutsideTheProfile) {
    const TestKey es(wa::Algorithm::ES256), ed(wa::Algorithm::EdDSA), rsa(wa::Algorithm::RS256);
    for (const auto* key : {&es, &ed, &rsa}) {
        const auto parsed = wa::cose::parse(key->cose());
        ASSERT_TRUE(parsed.key) << wa::toString(parsed.failure);
        EXPECT_EQ(parsed.key->algorithm, key->algorithm());
    }
    const auto failure = [](const CborWriter& w) { return wa::cose::parse(w.out).failure; };
    CborWriter noAlg;
    noAlg.map(4).integer(1).integer(2).integer(-1).integer(1).integer(-2).bytes(es.x).integer(-3).bytes(es.y);
    EXPECT_EQ(failure(noAlg), Failure::CoseKeyMalformed);
    CborWriter wrongKty;
    wrongKty.map(5).integer(1).integer(1).integer(3).integer(-7).integer(-1).integer(1).integer(-2).bytes(es.x)
        .integer(-3).bytes(es.y);
    EXPECT_EQ(failure(wrongKty), Failure::KeyParametersMismatch);
    CborWriter wrongCrv;
    wrongCrv.map(5).integer(1).integer(2).integer(3).integer(-7).integer(-1).integer(2).integer(-2).bytes(es.x)
        .integer(-3).bytes(es.y);
    EXPECT_EQ(failure(wrongCrv), Failure::KeyParametersMismatch);
    CborWriter priv;  // a private scalar (label -4) never belongs in a credential public key
    priv.map(6).integer(1).integer(2).integer(3).integer(-7).integer(-1).integer(1).integer(-2).bytes(es.x)
        .integer(-3).bytes(es.y).integer(-4).bytes(randomBytes(32));
    EXPECT_EQ(failure(priv), Failure::CoseKeyMalformed);
    CborWriter shortX;
    shortX.map(5).integer(1).integer(2).integer(3).integer(-7).integer(-1).integer(1).integer(-2).bytes(Bytes(31, 1))
        .integer(-3).bytes(es.y);
    EXPECT_EQ(failure(shortX), Failure::InvalidPublicKey);
    CborWriter compressed;  // y as a sign bit (RFC 9053 allows it; WebAuthn credential keys don't use it)
    compressed.map(5).integer(1).integer(2).integer(3).integer(-7).integer(-1).integer(1).integer(-2).bytes(es.x)
        .integer(-3).byte(0xF5);
    EXPECT_EQ(failure(compressed), Failure::InvalidPublicKey);

    // Ed25519: small-order and non-canonical points.
    Bytes identity(32, 0);
    identity[0] = 0x01;
    CborWriter smallOrder;
    smallOrder.map(4).integer(1).integer(1).integer(3).integer(-8).integer(-1).integer(6).integer(-2).bytes(identity);
    EXPECT_EQ(failure(smallOrder), Failure::InvalidPublicKey);
    CborWriter ed448;
    ed448.map(4).integer(1).integer(1).integer(3).integer(-8).integer(-1).integer(7).integer(-2).bytes(randomBytes(57));
    EXPECT_EQ(failure(ed448), Failure::KeyParametersMismatch);

    // RSA: modulus size, leading zeros and the exponent.
    const auto rsaKey = [&](const Bytes& n, const Bytes& e) {
        CborWriter w;
        w.map(4).integer(1).integer(3).integer(3).integer(-257).integer(-1).bytes(n).integer(-2).bytes(e);
        return wa::cose::parse(w.out).failure;
    };
    EXPECT_EQ(rsaKey(rsa.n, rsa.e), Failure::None);
    EXPECT_EQ(rsaKey(concat({Bytes{0x00}, rsa.n}), rsa.e), Failure::InvalidPublicKey);
    EXPECT_EQ(rsaKey(rsa.n, Bytes{0x01, 0x00, 0x00}), Failure::InvalidPublicKey) << "even exponent";
    EXPECT_EQ(rsaKey(rsa.n, Bytes{0x01}), Failure::InvalidPublicKey);
    auto big = randomBytes(513);
    big[0] = 0x01;
    big.back() |= 1;
    EXPECT_EQ(rsaKey(big, rsa.e), Failure::RsaKeySize) << "4097 bits";
    Bytes shortModulus(rsa.n.begin() + 1, rsa.n.end());
    shortModulus[0] |= 0x80;  // a random key's second byte is 0x00 about once in 256 runs: that is a leading zero, not a short key
    EXPECT_EQ(rsaKey(shortModulus, rsa.e), Failure::RsaKeySize) << "2040 bits";

    CborWriter trailing;
    trailing.raw(es.cose()).byte(0x00);
    EXPECT_EQ(failure(trailing), Failure::CoseKeyMalformed);
    EXPECT_EQ(wa::cose::parse(Bytes(wa::cose::kMaxKeyBytes + 1, 0)).failure, Failure::CoseKeyMalformed);
}

TEST(WebAuthnCose, VerifiesOnlyGenuineSignatures) {
    for (const auto alg : {wa::Algorithm::ES256, wa::Algorithm::EdDSA, wa::Algorithm::RS256}) {
        SCOPED_TRACE(std::string(wa::toString(alg)));
        const TestKey key(alg);
        const auto parsed = wa::cose::parse(key.cose());
        ASSERT_TRUE(parsed.key);
        const auto message = bytesOf("authenticatorData || clientDataHash");
        auto sig = key.sign(message);
        EXPECT_TRUE(wa::cose::verify(*parsed.key, message, sig));
        EXPECT_FALSE(wa::cose::verify(*parsed.key, bytesOf("another message"), sig));
        EXPECT_FALSE(wa::cose::verify(*parsed.key, message, {}));
        auto longer = sig;
        longer.push_back(0);
        EXPECT_FALSE(wa::cose::verify(*parsed.key, message, longer)) << "trailing bytes after the signature";
        sig[sig.size() / 2] ^= 0x40;
        EXPECT_FALSE(wa::cose::verify(*parsed.key, message, sig));
    }
}

TEST(WebAuthnAuthenticatorData, ParsesStrictly) {
    const TestKey key(wa::Algorithm::ES256);
    Attested a;
    a.credentialId = randomBytes(20);
    a.cose = key.cose();
    const auto withCred = authenticatorData(flags::UP | flags::AT, 7, a);
    const auto parsed = wa::authdata::parse(withCred);
    ASSERT_TRUE(parsed.data);
    EXPECT_EQ(parsed.data->signCount, 7u);
    EXPECT_EQ(parsed.data->attested->credentialId, a.credentialId);
    EXPECT_EQ(parsed.data->attested->publicKeyCose, a.cose);

    EXPECT_EQ(wa::authdata::parse(Bytes(36, 0)).failure, Failure::AuthenticatorDataMalformed);
    EXPECT_EQ(wa::authdata::parse(concat({withCred, Bytes{0x00}})).failure, Failure::AuthenticatorDataMalformed);
    EXPECT_EQ(wa::authdata::parse(Bytes(withCred.begin(), withCred.end() - 1)).failure,
              Failure::AuthenticatorDataMalformed);
    EXPECT_EQ(wa::authdata::parse(Bytes(wa::authdata::kMaxBytes + 1, 0)).failure, Failure::InputTooLarge);

    CborWriter ext;
    ext.map(1).text("credProtect").integer(2);
    EXPECT_TRUE(wa::authdata::parse(authenticatorData(flags::UP | flags::ED, 0, std::nullopt, kRpId, ext.out)).data);
    EXPECT_FALSE(wa::authdata::parse(authenticatorData(flags::UP, 0, std::nullopt, kRpId, ext.out)).data)
        << "extensions without ED are trailing bytes";
    CborWriter notMap;
    notMap.array(0);
    EXPECT_FALSE(wa::authdata::parse(authenticatorData(flags::UP | flags::ED, 0, std::nullopt, kRpId, notMap.out)).data);
    const auto deep = nested(9);
    CborWriter deepExt;
    deepExt.map(1).text("x").raw(deep);
    EXPECT_FALSE(wa::authdata::parse(authenticatorData(flags::UP | flags::ED, 0, std::nullopt, kRpId, deepExt.out)).data);
    CborWriter indefinite;
    indefinite.byte(0xBF).text("x").integer(1).byte(0xFF);
    EXPECT_FALSE(wa::authdata::parse(authenticatorData(flags::UP | flags::ED, 0, std::nullopt, kRpId, indefinite.out)).data);
}

TEST(WebAuthnAttestationObject, IsExactlyFmtAttStmtAndAuthData) {
    const auto ad = authenticatorData(flags::UP, 0);
    EXPECT_TRUE(wa::attestation::parse(attestationNone(ad)).object);
    CborWriter extra;
    extra.map(4).text("fmt").text("none").text("attStmt").map(0).text("authData").bytes(ad).text("epAtt").byte(0xF5);
    EXPECT_EQ(wa::attestation::parse(extra.out).failure, Failure::AttestationMalformed);
    CborWriter dup;
    dup.map(3).text("fmt").text("none").text("fmt").text("none").text("authData").bytes(ad);
    EXPECT_EQ(wa::attestation::parse(dup.out).failure, Failure::AttestationMalformed);
    CborWriter badFmt;
    badFmt.map(3).text("fmt").text("None!").text("attStmt").map(0).text("authData").bytes(ad);
    EXPECT_EQ(wa::attestation::parse(badFmt.out).failure, Failure::AttestationMalformed);
    EXPECT_EQ(wa::attestation::parse(Bytes(wa::attestation::kMaxBytes + 1, 0)).failure, Failure::InputTooLarge);

    // fmt "none" with a statement.
    const TestKey key(wa::Algorithm::ES256);
    CborWriter noneWithStmt;
    noneWithStmt.map(3).text("fmt").text("none").text("attStmt").map(1).text("sig").bytes(Bytes{1})
        .text("authData").bytes(ad);
    const auto parsed = wa::attestation::parse(noneWithStmt.out);
    ASSERT_TRUE(parsed.object);
    const auto pk = wa::cose::parse(key.cose());
    EXPECT_EQ(wa::attestation::verify(*parsed.object, *pk.key, {}, Bytes(32, 0)).failure, Failure::AttestationMalformed);
    // An unknown format is recorded and treated as none.
    CborWriter other;
    other.map(3).text("fmt").text("android-safetynet").text("attStmt").map(1).text("ver").text("1")
        .text("authData").bytes(ad);
    const auto unknown = wa::attestation::parse(other.out);
    ASSERT_TRUE(unknown.object);
    EXPECT_EQ(wa::attestation::verify(*unknown.object, *pk.key, {}, Bytes(32, 0)).type, wa::AttestationType::Unverified);
    // packed with the retired ecdaaKeyId.
    CborWriter ecdaa;
    ecdaa.map(3).text("fmt").text("packed").text("attStmt").map(3).text("alg").integer(-7).text("sig").bytes(Bytes{1})
        .text("ecdaaKeyId").bytes(Bytes{1}).text("authData").bytes(ad);
    const auto e = wa::attestation::parse(ecdaa.out);
    ASSERT_TRUE(e.object);
    EXPECT_EQ(wa::attestation::verify(*e.object, *pk.key, {}, Bytes(32, 0)).failure, Failure::AttestationMalformed);
}

TEST(WebAuthnClientData, ParsesStrictly) {
    const auto parse = [](const std::string& s) { return wa::clientdata::parse(wa::view(s)); };
    const auto ok = parse(R"({"type":"webauthn.get","challenge":"AAAA","origin":"https://a.test","crossOrigin":false,)"
                          R"("other":{"nested":[1,2,{"x":null}]}})");
    ASSERT_TRUE(ok);
    EXPECT_EQ(ok->type, "webauthn.get");
    EXPECT_EQ(ok->challenge, "AAAA");
    EXPECT_EQ(ok->origin, "https://a.test");
    EXPECT_EQ(ok->crossOrigin, false);
    EXPECT_FALSE(ok->topOrigin);

    const std::string base = R"("challenge":"AAAA","origin":"https://a.test")";
    EXPECT_FALSE(parse(R"({"type":"webauthn.get","type":"webauthn.create",)" + base + "}")) << "duplicate key";
    EXPECT_FALSE(parse(R"({"type":"webauthn.get",)" + base + R"(,"x":{"a":1,"a":2}})")) << "nested duplicate";
    EXPECT_FALSE(parse(R"({"type":1,)" + base + "}"));
    EXPECT_FALSE(parse(R"({"type":["webauthn.get"],)" + base + "}"));
    EXPECT_FALSE(parse(R"({"type":"webauthn.get",)" + base + R"(,"crossOrigin":1})"));
    EXPECT_FALSE(parse(R"({"type":"webauthn.get",)" + base + R"(,"topOrigin":true})"));
    EXPECT_FALSE(parse(R"({"challenge":"AAAA","origin":"https://a.test"})")) << "type missing";
    EXPECT_FALSE(parse(R"({"type":"webauthn.get",)" + base + "} x"));
    EXPECT_FALSE(parse(R"({"type":"webauthn.get",)" + base + "}{}"));
    EXPECT_FALSE(parse(R"({"type":"webauthn.get",/*c*/)" + base + "}"));
    EXPECT_FALSE(parse("\xEF\xBB\xBF" R"({"type":"webauthn.get",)" + base + "}")) << "byte-order mark";
    EXPECT_FALSE(parse(std::string("{\"type\":\"webauthn.get\xff\",") + base + "}")) << "invalid UTF-8";
    EXPECT_FALSE(parse(R"(["webauthn.get"])"));
    EXPECT_FALSE(parse(R"({"type":"webauthn.get",)" + base + R"(,"x":[[[[[[[[1]]]]]]]]})")) << "nesting past 8";
    EXPECT_TRUE(parse(R"({"type":"webauthn.get",)" + base + R"(,"x":[[[[[[1]]]]]]})"));
    EXPECT_FALSE(parse(R"({"type":"webauthn.get",)" + base + R"(,"pad":")" + std::string(4096, 'a') + R"("})"))
        << "over 4 KiB";
}

TEST(WebAuthnBase64Url, IsStrict) {
    EXPECT_EQ(wa::base64urlDecode("AQID"), (Bytes{1, 2, 3}));
    EXPECT_EQ(wa::base64urlDecode("_-8"), (Bytes{0xFF, 0xEF}));
    EXPECT_FALSE(wa::base64urlDecode("AQ=="));  // padding
    EXPECT_FALSE(wa::base64urlDecode("AQ I"));  // whitespace
    EXPECT_FALSE(wa::base64urlDecode("/+8"));   // standard alphabet
    EXPECT_FALSE(wa::base64urlDecode("AR"));    // non-zero trailing bits
    EXPECT_FALSE(wa::base64urlDecode("A"));
    EXPECT_EQ(wa::base64urlEncode(Bytes{0xFF, 0xEF}), "_-8");
    const auto r = randomBytes(33);
    EXPECT_EQ(wa::base64urlDecode(wa::base64urlEncode(r)), r);
}

TEST(WebAuthnWire, DecodesTheL3JsonForms) {
    const auto id = randomBytes(16);
    const auto b = [](const Bytes& x) { return wa::base64urlEncode(x); };
    const std::string reg = R"({"id":")" + b(id) + R"(","rawId":")" + b(id) + R"(","type":"public-key",)"
        R"("authenticatorAttachment":"platform","clientExtensionResults":{"credProps":{"rk":true}},)"
        R"("response":{"clientDataJSON":"e30","attestationObject":"oA","transports":["internal","hybrid"],)"
        R"("publicKeyAlgorithm":-7}})";
    const auto r = wa::wire::parseRegistration(reg);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->rawId, id);
    EXPECT_EQ(r->clientDataJSON, bytesOf("{}"));
    EXPECT_EQ(r->transports, (std::vector<std::string>{"internal", "hybrid"}));
    EXPECT_EQ(r->residentKey, true);

    const std::string assertion = R"({"id":")" + b(id) + R"(","rawId":")" + b(id) + R"(","type":"public-key",)"
        R"("clientExtensionResults":{},"response":{"clientDataJSON":"e30","authenticatorData":"AA","signature":"AQ",)"
        R"("userHandle":null}})";
    const auto a = wa::wire::parseAssertion(assertion);
    ASSERT_TRUE(a);
    EXPECT_FALSE(a->userHandle);
    EXPECT_EQ(a->signature, (Bytes{1}));

    auto replace = [](std::string s, const std::string& from, const std::string& to) {
        s.replace(s.find(from), from.size(), to);
        return s;
    };
    EXPECT_FALSE(wa::wire::parseAssertion(replace(assertion, R"("type":"public-key")", R"("type":"password")")));
    EXPECT_FALSE(wa::wire::parseAssertion(replace(assertion, R"("rawId":")" + b(id), R"("rawId":")" + b(randomBytes(16)))))
        << "id and rawId differ";
    EXPECT_FALSE(wa::wire::parseAssertion(replace(assertion, R"("signature":"AQ")", R"("signature":"AQ==")")));
    EXPECT_FALSE(wa::wire::parseAssertion(replace(assertion, R"("signature":"AQ")", R"("signature":"AQ","signature":"AA")")));
    EXPECT_FALSE(wa::wire::parseAssertion(replace(assertion, R"("signature":"AQ",)", "")));
    EXPECT_FALSE(wa::wire::parseAssertion(replace(assertion, R"("userHandle":null)", R"("userHandle":5)")));
    EXPECT_FALSE(wa::wire::parseRegistration(replace(reg, R"("rk":true)", R"("rk":"yes")")));
    EXPECT_FALSE(wa::wire::parseRegistration(replace(reg, R"(["internal","hybrid"])", R"("internal")")));
    EXPECT_FALSE(wa::wire::parseRegistration(std::string(wa::wire::kMaxBytes + 1, ' ')));
}

TEST(WebAuthnChallengeStore, IsBoundedPerSessionAndOverall) {
    wa::ChallengeStore store(std::chrono::seconds(120), 4, 2);
    const auto now = wa::ChallengeStore::Clock::now();
    const wa::Expectation a{"a", wa::Purpose::Mfa, 1, {}}, b{"b", wa::Purpose::Mfa, 1, {}}, c{"c", wa::Purpose::Mfa, 1, {}};
    const auto first = store.issue(a, now);
    ASSERT_TRUE(first);
    ASSERT_TRUE(store.issue(a, now + std::chrono::seconds(1)));
    ASSERT_TRUE(store.issue(a, now + std::chrono::seconds(2)));
    EXPECT_EQ(store.size(), 2u) << "a session keeps its two newest challenges";
    EXPECT_EQ(store.consume(*first, a, now), Failure::ChallengeUnknown) << "the oldest was dropped";
    ASSERT_TRUE(store.issue(b, now));
    ASSERT_TRUE(store.issue(b, now));
    EXPECT_FALSE(store.issue(c, now)) << "full of live challenges";
    EXPECT_TRUE(store.issue(c, now + std::chrono::seconds(200))) << "expired ones make room";
    store.forgetSession("b");
    EXPECT_EQ(store.size(), 1u);
    const auto mine = store.issue(a, now);
    ASSERT_TRUE(mine);
    EXPECT_EQ(store.consume(*mine, {"a", wa::Purpose::Login, std::nullopt, {}}, now), Failure::ChallengePurposeMismatch);
    const auto login = store.issue({"a", wa::Purpose::Login, std::nullopt, {}}, now);
    EXPECT_EQ(store.consume(*login, {"a", wa::Purpose::Login, 1, {}}, now), Failure::ChallengeUserMismatch)
        << "a login challenge names no user";
}

TEST(WebAuthnRelyingParty, ConfigurationRules) {
    const auto ok = [](const std::string& id, const std::vector<std::string>& origins, const std::string& name = "Vaulthalla") {
        try {
            wa::validateRelyingParty(id, origins, name);
            return true;
        } catch (const std::invalid_argument&) {
            return false;
        }
    };
    EXPECT_TRUE(ok("", {}));
    EXPECT_TRUE(ok("vault.example.com", {"https://vault.example.com"}));
    EXPECT_TRUE(ok("example.com", {"https://vault.example.com", "https://example.com:8443"}));
    EXPECT_TRUE(ok("localhost", {"http://localhost:3000", "https://localhost"}));
    EXPECT_TRUE(ok("xn--bcher-kva.example", {"https://xn--bcher-kva.example"}));
    EXPECT_TRUE(ok("vault.example.com", {"https://vault.example.com"}, "Vaulthalla på kontoret"));

    EXPECT_FALSE(ok("", {"https://vault.example.com"})) << "origins without rp_id";
    EXPECT_FALSE(ok("vault.example.com", {})) << "rp_id without origins";
    for (const auto* id : {"192.168.1.10", "10.0.0.1", "[::1]", "::1", "Vault.example.com", "vault.example.com.",
                           "https://vault.example.com", "vault.example.com:443", "-vault.example.com", "vault_x.example",
                           "a..b", "bücher.example"})
        EXPECT_FALSE(ok(id, {"https://vault.example.com"})) << id;
    for (const auto* origin : {"https://vault.example.com/", "https://vault.example.com/path", "http://vault.example.com",
                               "https://vault.example.com:443", "https://vault.example.com:0", "https://vault.example.com:65536",
                               "https://vault.example.com:080", "https://user@vault.example.com", "https://evil.com",
                               "https://notvault.example.com", "HTTPS://vault.example.com", "vault.example.com",
                               "https://vault.example.com?x", "https://192.168.1.10"})
        EXPECT_FALSE(ok("vault.example.com", {origin})) << origin;
    EXPECT_FALSE(ok("vault.example.com", {"https://vault.example.com", "https://vault.example.com"})) << "listed twice";
    EXPECT_FALSE(ok("vault.example.com", {"https://vault.example.com"}, ""));
    EXPECT_FALSE(ok("vault.example.com", {"https://vault.example.com"}, std::string(65, 'a')));
    EXPECT_FALSE(ok("vault.example.com", {"https://vault.example.com"}, "Vault\nhalla"));
    EXPECT_FALSE(ok("vault.example.com", {"https://vault.example.com"}, "\xC3"));
    std::vector<std::string> many;
    for (int i = 0; i < 17; ++i) many.push_back("https://h" + std::to_string(i) + ".example.com");
    EXPECT_FALSE(ok("example.com", many));
}

TEST(WebAuthnFuzzCorpus, ReplaysEveryCommittedInput) {
    namespace fs = std::filesystem;
    const auto root = fs::path(VH_TEST_ASSETS_DIR).parent_path() / "src" / "auth" / "webauthn" / "fuzz" / "corpus";
    ASSERT_TRUE(fs::is_directory(root)) << root;
    std::size_t inputs = 0;
    for (const auto* target : {"cbor_cose", "authenticator_data", "client_data"}) {
        std::size_t perTarget = 0;
        for (const auto& entry : fs::directory_iterator(root / target)) {
            std::ifstream in(entry.path(), std::ios::binary);
            const Bytes data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
            const std::string_view text(reinterpret_cast<const char*>(data.data()), data.size());
            // The fuzz targets' bodies: none of these may crash, hang or leak (make test runs them under ASan/UBSan).
            (void)cbor::decode(data);
            if (const auto key = wa::cose::parse(data); key.key) (void)wa::cose::verify(*key.key, data, data);
            if (const auto att = wa::attestation::parse(data); att.object)
                if (const auto ad = wa::authdata::parse(att.object->authData); ad.data && ad.data->attested)
                    if (const auto key = wa::cose::parse(ad.data->attested->publicKeyCose); key.key)
                        (void)wa::attestation::verify(*att.object, *key.key, ad.data->attested->aaguid, Bytes(32, 0));
            if (const auto ad = wa::authdata::parse(data); ad.data && ad.data->attested)
                (void)wa::cose::parse(ad.data->attested->publicKeyCose);
            (void)wa::clientdata::parse(data);
            (void)wa::wire::parseRegistration(text);
            (void)wa::wire::parseAssertion(text);
            ++perTarget;
        }
        EXPECT_GT(perTarget, 0u) << target << " has a seed corpus";
        inputs += perTarget;
    }
    EXPECT_GT(inputs, 20u);
}

}
