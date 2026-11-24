// OpenPGP through the system gpg (crypto/openpgp/Gpg.hpp), DB-free: keys are generated per run in a private keyring
// (tests/helpers/openpgp_keys.hpp). A modern ECC key of the shape the Sentinel handoff key has (ed25519 primary,
// cv25519 encryption subkey) is pinned and encrypted to; revoked, expired and sign-only keys are refused, say which,
// and a message opens with the recipients' secret keys and with nothing else. Skips where gpg isn't installed.

#include "../helpers/openpgp_keys.hpp"

#include "crypto/openpgp/Gpg.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>

namespace vh::test_openpgp_gpg {

namespace pgp = crypto::openpgp;
using test::openpgp::Keyring;

class OpenPgpGpg : public ::testing::Test {
protected:
    // One keyring for the suite: generating keys is the slow part.
    inline static std::unique_ptr<Keyring> keys;
    inline static std::string sentinel, client, expired, signOnly, revoked;

    static void SetUpTestSuite() {
        keys = std::make_unique<Keyring>();
        if (!keys->available()) return;
        sentinel = keys->generate("Sentinel test (credential handoff) <sentinel@example.test>");
        client = keys->generate("Client test <client@example.test>");
        expired = keys->generate("Expired test <expired@example.test>", "1d", std::string("20200101T000000"));
        signOnly = keys->generateSignOnly("Sign only <signonly@example.test>");
        revoked = keys->generate("Revoked test <revoked@example.test>");
        keys->revoke(revoked);
    }

    static void TearDownTestSuite() { keys.reset(); }

    void SetUp() override {
        if (!keys || !keys->available()) GTEST_SKIP() << "gpg is not installed";
    }
};

TEST_F(OpenPgpGpg, FingerprintsAreFullAndNormalized) {
    EXPECT_EQ(pgp::normalizeFingerprint("a6a1 7529 84df b0db 38dd  235d 2096 c49d 7a8f 000a"),
              "A6A1752984DFB0DB38DD235D2096C49D7A8F000A");
    for (const auto* bad : {"", "2096C49D7A8F000A", "A6A1752984DFB0DB38DD235D2096C49D7A8F000", "Z6A1752984DFB0DB38DD235D2096C49D7A8F000A",
                            "A6A1752984DFB0DB38DD235D2096C49D7A8F000AFF"})
        EXPECT_THROW((void)pgp::normalizeFingerprint(bad), std::invalid_argument) << bad;
}

TEST_F(OpenPgpGpg, AnEccHandoffKeyIsReadAndUsable) {
    const auto info = pgp::inspect(keys->publicKey(sentinel));
    EXPECT_EQ(info.fingerprint, sentinel);
    EXPECT_EQ(info.algorithm, "ed25519");
    ASSERT_EQ(info.user_ids.size(), 1u);
    EXPECT_EQ(info.user_ids[0], "Sentinel test (credential handoff) <sentinel@example.test>");
    ASSERT_EQ(info.encryption_keys.size(), 1u) << "the cv25519 subkey";
    EXPECT_NE(info.encryption_keys[0], sentinel) << "a subkey, not the signing primary";
    EXPECT_EQ(info.encryption_algorithms[0], "cv25519");
    EXPECT_FALSE(info.unusableReason().has_value());
    EXPECT_NO_THROW(pgp::requireEncryptable(info));
}

TEST_F(OpenPgpGpg, RevokedExpiredAndSignOnlyKeysAreRefusedSayingWhich) {
    const auto why = [](const std::string& armored) {
        try {
            pgp::requireEncryptable(pgp::inspect(armored));
        } catch (const pgp::BadKey& e) {
            return std::string(e.what());
        }
        return std::string("usable");
    };
    EXPECT_NE(why(keys->publicKey(revoked)).find("revoked"), std::string::npos) << why(keys->publicKey(revoked));
    EXPECT_NE(why(keys->publicKey(expired)).find("expired on 2020-01-02"), std::string::npos) << why(keys->publicKey(expired));
    EXPECT_NE(why(keys->publicKey(signOnly)).find("no valid encryption-capable subkey"), std::string::npos)
        << why(keys->publicKey(signOnly));
    for (const auto& fpr : {revoked, expired, signOnly})
        EXPECT_THROW((void)pgp::encrypt("x", {keys->publicKey(fpr)}), pgp::BadKey) << fpr;
}

TEST_F(OpenPgpGpg, OnlyOnePublicKeyIsAccepted) {
    EXPECT_THROW((void)pgp::inspect(""), pgp::BadKey);
    EXPECT_THROW((void)pgp::inspect("not a key"), pgp::BadKey);
    EXPECT_THROW((void)pgp::inspect(keys->publicKey(sentinel) + keys->publicKey(client)), pgp::BadKey) << "two keys";
    try {
        (void)pgp::inspect(keys->secretKey(sentinel));
        ADD_FAILURE() << "a secret key was accepted";
    } catch (const pgp::BadKey& e) {
        EXPECT_NE(std::string(e.what()).find("secret key"), std::string::npos) << e.what();
    }
}

TEST_F(OpenPgpGpg, TheMessageOpensWithTheRecipientsKeysAndNothingElse) {
    const std::string secret = R"({"secret_access_key":"gw-secret-0123456789"})";
    const auto message = pgp::encrypt(secret, {keys->publicKey(sentinel)});
    EXPECT_TRUE(message.starts_with("-----BEGIN PGP MESSAGE-----"));
    EXPECT_EQ(message.find("gw-secret"), std::string::npos);

    // The recipient's secret key opens it.
    EXPECT_EQ(keys->decrypt(message), secret);

    // A keyring without that key does not (the client's own key, alone).
    Keyring other;
    const auto stranger = other.generate("Stranger <stranger@example.test>");
    (void)stranger;
    EXPECT_FALSE(other.decrypt(message).has_value());

    // Two recipients in one message: each opens it alone.
    Keyring second;
    const auto clientKey = second.generate("Second client <second@example.test>");
    const auto both = pgp::encrypt(secret, {keys->publicKey(sentinel), second.publicKey(clientKey)});
    EXPECT_EQ(keys->decrypt(both), secret);
    EXPECT_EQ(second.decrypt(both), secret);
    EXPECT_FALSE(other.decrypt(both).has_value());
}

TEST_F(OpenPgpGpg, NothingIsLeftRunningOrOnDisk) {
    std::filesystem::path home;
    {
        const pgp::TempHome h;
        home = h.path();
        EXPECT_TRUE(std::filesystem::is_directory(home));
        EXPECT_EQ(std::filesystem::status(home).permissions() & std::filesystem::perms::all,
                  std::filesystem::perms::owner_all);
    }
    EXPECT_FALSE(std::filesystem::exists(home));

    // The process plumbing: input over stdin, output and errors captured, the exit status kept.
    const auto echo = pgp::run("/bin/sh", {"-c", "cat; echo oops >&2; exit 3"}, "piped");
    EXPECT_EQ(echo.out, "piped");
    EXPECT_EQ(echo.err, "oops\n");
    EXPECT_EQ(echo.exit_code, 3);
    const auto slow = pgp::run("/bin/sh", {"-c", "sleep 30"}, {}, std::chrono::seconds(1));
    EXPECT_TRUE(slow.timed_out);
}

}
