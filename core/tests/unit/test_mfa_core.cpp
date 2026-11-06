// MFA factor primitives (#356; MFA design note sections 4.2, 4.3): RFC 6238 TOTP with its window and replay guard,
// RFC 4648 base32 and otpauth URIs, recovery code format and keyed hashing, TOTP seed sealing bound to account and
// factor, the guarded seal-and-read-back of the MFA keys, and log redaction of every form of MFA material.
// DB-free; the storage layer is test_mfa_factors.cpp.
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/RecoveryCodes.hpp"
#include "auth/mfa/Totp.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/secrets/Manager.hpp"
#include "protocols/ws/LogRedaction.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <set>
#include <string>
#include <vector>

namespace vh::auth::mfa::test_core {

using json = nlohmann::json;

const std::vector<uint8_t> kRfcSeed = [] {
    const std::string ascii = "12345678901234567890";  // RFC 6238 Appendix B, SHA-1
    return std::vector<uint8_t>(ascii.begin(), ascii.end());
}();

std::chrono::system_clock::time_point at(const int64_t unixSeconds) {
    return std::chrono::system_clock::time_point(std::chrono::seconds(unixSeconds));
}

// ── TOTP ────────────────────────────────────────────────────────────────────────────────────────────────────────────

TEST(MfaTotp, Rfc6238AppendixBSha1Vectors) {
    const std::vector<std::pair<int64_t, std::string>> vectors{
        {59, "94287082"},         {1111111109, "07081804"}, {1111111111, "14050471"},
        {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"},
    };
    for (const auto& [t, expected] : vectors) {
        const auto step = totp::stepAt(at(t));
        EXPECT_EQ(totp::code(kRfcSeed, step, 8), expected) << "T = " << t;
        // The 6-digit code (what Vaulthalla uses) is the same truncation modulo 10^6.
        EXPECT_EQ(totp::code(kRfcSeed, step), expected.substr(2)) << "T = " << t;
    }
    EXPECT_EQ(totp::stepAt(at(59)), 1);
    EXPECT_EQ(totp::stepAt(at(1111111109)), 0x23523EC);
}

TEST(MfaTotp, ParametersAreTheOnesEveryAuthenticatorAccepts) {
    EXPECT_EQ(totp::kSecretBytes, 20u);
    EXPECT_EQ(totp::kDigits, 6);
    EXPECT_EQ(totp::kPeriodSeconds, 30);
    const auto a = totp::generateSecret();
    const auto b = totp::generateSecret();
    EXPECT_EQ(a.size(), 20u);
    EXPECT_FALSE(std::ranges::equal(a.bytes(), b.bytes()));
    EXPECT_THROW((void)totp::code(kRfcSeed, 1, 5), std::invalid_argument);
    EXPECT_THROW((void)totp::code({}, 1), std::invalid_argument);
}

TEST(MfaTotp, AcceptsOneStepEitherSideAndRefusesTwo) {
    const int64_t now = 50'000'000;
    for (const int64_t offset : {-1, 0, 1}) {
        const auto c = totp::code(kRfcSeed, now + offset);
        EXPECT_EQ(totp::match(kRfcSeed, c, now, 0), now + offset) << offset;
    }
    for (const int64_t offset : {-2, 2, -3, 3}) {
        const auto c = totp::code(kRfcSeed, now + offset);
        EXPECT_FALSE(totp::match(kRfcSeed, c, now, 0)) << "drift of " << offset << " steps is refused";
    }
}

TEST(MfaTotp, AStepAtOrBeforeTheLastUsedOneIsAReplay) {
    const int64_t now = 50'000'000;
    const auto c = totp::code(kRfcSeed, now);
    EXPECT_FALSE(totp::match(kRfcSeed, c, now, now)) << "the same step again";
    EXPECT_FALSE(totp::match(kRfcSeed, c, now, now + 1)) << "an older step than the last used";
    EXPECT_EQ(totp::match(kRfcSeed, c, now, now - 1), now);
    EXPECT_FALSE(totp::match(kRfcSeed, totp::code(kRfcSeed, now - 1), now, now - 1));
}

TEST(MfaTotp, CodeInputIsSixDigitsWithOptionalSpaces) {
    EXPECT_EQ(totp::normalizeCode("123456"), "123456");
    EXPECT_EQ(totp::normalizeCode("123 456"), "123456");
    EXPECT_EQ(totp::normalizeCode(" 12 34 56 "), "123456");
    for (const auto* bad : {"", "12345", "1234567", "12345a", "123-456", "１２３４５６"})
        EXPECT_FALSE(totp::normalizeCode(bad)) << bad;
    EXPECT_FALSE(totp::match(kRfcSeed, "abcdef", 1, 0));
}

TEST(MfaTotp, Base32IsRfc4648WithoutPadding) {
    const auto b32 = [](const std::string& s) {
        return totp::base32(std::vector<uint8_t>(s.begin(), s.end()));
    };
    EXPECT_EQ(b32(""), "");
    EXPECT_EQ(b32("f"), "MY");
    EXPECT_EQ(b32("fo"), "MZXQ");
    EXPECT_EQ(b32("foo"), "MZXW6");
    EXPECT_EQ(b32("foob"), "MZXW6YQ");
    EXPECT_EQ(b32("fooba"), "MZXW6YTB");
    EXPECT_EQ(b32("foobar"), "MZXW6YTBOI");
    EXPECT_EQ(totp::base32(kRfcSeed), "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ");
    EXPECT_EQ(totp::base32(totp::generateSecret().bytes()).size(), 32u) << "160 bits, no padding";
}

TEST(MfaTotp, OtpauthUriCarriesTheStandardParametersAndEncodesTheLabel) {
    const auto uri = totp::otpauthUri("Vaulthalla", "alice smith@example", "GEZDGNBV");
    EXPECT_EQ(uri, "otpauth://totp/Vaulthalla:alice%20smith%40example?secret=GEZDGNBV&issuer=Vaulthalla"
                   "&algorithm=SHA1&digits=6&period=30");
    EXPECT_NE(totp::otpauthUri("A:B", "x?y&z", "S").find("A%3AB:x%3Fy%26z"), std::string::npos);
}

// ── recovery codes ──────────────────────────────────────────────────────────────────────────────────────────────────

TEST(MfaRecoveryCodes, TenCrockfordCharactersInTwoGroups) {
    std::set<std::string> seen;
    for (int i = 0; i < 200; ++i) {
        const auto code = recovery::generateCode();
        ASSERT_EQ(code.size(), 11u) << code;
        EXPECT_EQ(code[5], '-');
        for (std::size_t j = 0; j < code.size(); ++j) {
            if (j == 5) continue;
            EXPECT_NE(std::string_view("0123456789ABCDEFGHJKMNPQRSTVWXYZ").find(code[j]), std::string_view::npos)
                << code;
        }
        seen.insert(code);
    }
    EXPECT_EQ(seen.size(), 200u) << "50 bits each: no repeats in a few hundred";
}

TEST(MfaRecoveryCodes, InputIsReadTheWayAPersonTypesIt) {
    EXPECT_EQ(recovery::normalize("ABCDE-FGHJK"), "ABCDEFGHJK");
    EXPECT_EQ(recovery::normalize("abcde fghjk"), "ABCDEFGHJK");
    EXPECT_EQ(recovery::normalize("abcdefghjk"), "ABCDEFGHJK");
    EXPECT_EQ(recovery::normalize("O0IL1-oilAB"), "00111011AB");
    EXPECT_EQ(recovery::normalize("OIL00-11111"), "0110011111") << "Crockford look-alikes: O -> 0, I and L -> 1";
    for (const auto* bad : {"", "ABCDE", "ABCDE-FGHJKM", "ABCDE-FGHJU", "ABCDE_FGHJK", "ABCDE-FGHJ!"})
        EXPECT_FALSE(recovery::normalize(bad)) << bad;
}

TEST(MfaRecoveryCodes, TheHashIsKeyedAndBoundToTheAccount) {
    const std::vector<uint8_t> pepper(32, 0x42), other(32, 0x43);
    const auto h = recovery::hash(pepper, 7, "ABCDEFGHJK");
    EXPECT_EQ(h.size(), 32u);
    EXPECT_EQ(h, recovery::hash(pepper, 7, "ABCDEFGHJK"));
    EXPECT_NE(h, recovery::hash(pepper, 8, "ABCDEFGHJK")) << "another account";
    EXPECT_NE(h, recovery::hash(other, 7, "ABCDEFGHJK")) << "another pepper";
    EXPECT_NE(h, recovery::hash(pepper, 7, "ABCDEFGHJM")) << "another code";
    EXPECT_THROW((void)recovery::hash(std::vector<uint8_t>(8, 1), 7, "ABCDEFGHJK"), std::invalid_argument);
}

// ── sealing ─────────────────────────────────────────────────────────────────────────────────────────────────────────

TEST(MfaSeal, ATotpSeedOpensOnlyForItsAccountAndFactor) {
    const std::vector<uint8_t> key(32, 0x11), wrongKey(32, 0x12);
    const std::string factor = "3f2504e0-4f89-41d3-9a0c-0305e82c3301";
    const std::string otherFactor = "3f2504e0-4f89-41d3-9a0c-0305e82c3302";
    const auto seed = totp::generateSecret();

    const auto sealed = keys::sealTotpSecret(key, 5, factor, seed.bytes());
    EXPECT_EQ(sealed.iv.size(), 12u);
    EXPECT_EQ(sealed.ciphertext.size(), seed.size() + 16u);
    EXPECT_FALSE(std::ranges::search(sealed.ciphertext, seed.bytes())) << "the seed never appears in the row";

    const auto opened = keys::openTotpSecret(key, 5, factor, sealed);
    EXPECT_TRUE(std::ranges::equal(opened.bytes(), seed.bytes()));

    EXPECT_THROW((void)keys::openTotpSecret(key, 6, factor, sealed), std::runtime_error) << "moved to another account";
    EXPECT_THROW((void)keys::openTotpSecret(key, 5, otherFactor, sealed), std::runtime_error) << "another factor";
    EXPECT_THROW((void)keys::openTotpSecret(wrongKey, 5, factor, sealed), std::runtime_error) << "another key";
    auto tampered = sealed;
    tampered.ciphertext[0] ^= 1;
    EXPECT_THROW((void)keys::openTotpSecret(key, 5, factor, tampered), std::runtime_error);
    EXPECT_THROW((void)keys::sealTotpSecret(std::vector<uint8_t>(16, 1), 5, factor, seed.bytes()),
                 std::invalid_argument);

    const auto again = keys::sealTotpSecret(key, 5, factor, seed.bytes());
    EXPECT_NE(again.iv, sealed.iv) << "a fresh IV per seal";
}

// The guard every MFA key goes through (crypto::secrets::Manager::sealedKey), on a Manager without a TPM.
TEST(MfaSeal, AKeyIsCreatedOnceReadBackAndThenServedAsStored) {
    const auto secrets = crypto::secrets::Manager::createForTesting({});
    const auto none = [] { return std::optional<std::string>(); };
    const auto first = secrets->sealedKey("mfa_seal", 32, none);
    EXPECT_EQ(first.size(), 32u);
    ASSERT_TRUE(secrets->hasSecret("mfa_seal"));
    const auto second = secrets->sealedKey("mfa_seal", 32, none);
    EXPECT_TRUE(std::ranges::equal(first.bytes(), second.bytes())) << "a round trip returns the stored key";
    EXPECT_THROW((void)secrets->sealedKey("mfa_seal", 0, none), std::invalid_argument);
}

TEST(MfaSeal, AMissingKeyWithDependentsIsNeverRegenerated) {
    const auto secrets = crypto::secrets::Manager::createForTesting({});
    bool asked = false;
    const auto dependents = [&] {
        asked = true;
        return std::optional<std::string>("3 sealed TOTP factor(s)");
    };
    try {
        (void)secrets->sealedKey("mfa_seal", 32, dependents);
        FAIL() << "a key that sealed factors depend on must not be replaced";
    } catch (const crypto::secrets::MasterSecretLost& e) {
        EXPECT_NE(std::string(e.what()).find("3 sealed TOTP factor(s)"), std::string::npos);
    }
    EXPECT_TRUE(asked);
    EXPECT_FALSE(secrets->hasSecret("mfa_seal")) << "nothing is stored in its place";
}

TEST(MfaSeal, AnUnreadableKeyFailsClosedAndIsKept) {
    const auto secrets = crypto::secrets::Manager::createForTesting({{"mfa_pepper", "short"}});
    bool asked = false;
    const auto dependents = [&] {
        asked = true;
        return std::optional<std::string>();
    };
    EXPECT_THROW((void)secrets->sealedKey("mfa_pepper", 32, dependents), std::runtime_error);
    EXPECT_THROW((void)secrets->sealedKey("mfa_pepper", 32, dependents), std::runtime_error) << "every time";
    EXPECT_FALSE(asked) << "an existing row is never a candidate for regeneration";
    EXPECT_EQ(secrets->getSecret("mfa_pepper"), "short") << "never replaced";
}

// ── redaction ───────────────────────────────────────────────────────────────────────────────────────────────────────

TEST(MfaLogRedaction, CodesSeedsUrisAndCredentialsNeverReachALog) {
    const json msg{
        {"command", "auth.mfa.verify"},
        {"payload",
         {{"method", "totp"},
          {"code", "123456"},
          {"recovery_code", "ABCDE-FGHJK"},
          {"codes", json::array({"ABCDE-FGHJK", "MNPQR-STVWX"})},
          {"secret_base32", "GEZDGNBVGY3TQOJQ"},
          {"otpauth_uri", "otpauth://totp/V:a?secret=GEZDGNBVGY3TQOJQ"},
          {"uri", "OTPAUTH://totp/V:a?secret=JBSWY3DPEHPK3PXP"},
          {"list", json::array({"otpauth://totp/x?secret=MFRGGZDFMZTWQ2LK"})},
          {"credential", {{"id", "AAAA"}, {"response", {{"clientDataJSON", "eyJ"}}}}},
          {"client_data_json", "eyJ0eXBlIjoid2ViYXV0aG4uZ2V0In0"},
          {"authenticator_data", "SZYN5YgO"},
          {"signature", "MEUCIQ"},
          {"assertion", "x"},
          {"attestation_object", "o2Nm"},
          {"user_handle", "dXNlcg"},
          {"batch_id", "3f2504e0-4f89-41d3-9a0c-0305e82c3301"},
          {"label", "Phone"}}}};
    const auto out = protocols::ws::redactForLog(msg);
    const auto dumped = out.dump();
    for (const auto* leaked : {"123456", "ABCDE", "MNPQR", "GEZDGNBV", "JBSWY3DP", "MFRGGZDF", "eyJ", "SZYN5YgO",
                               "MEUCIQ", "o2Nm", "dXNlcg", "AAAA"})
        EXPECT_EQ(dumped.find(leaked), std::string::npos) << leaked;
    EXPECT_EQ(out["payload"]["method"], "totp");
    EXPECT_EQ(out["payload"]["label"], "Phone");
    EXPECT_EQ(out["payload"]["batch_id"], "3f2504e0-4f89-41d3-9a0c-0305e82c3301") << "ids stay readable";
}

}
