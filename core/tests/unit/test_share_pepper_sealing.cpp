// vh-test-tier: db-only
// #322: the share-token pepper (the BLAKE2b key that hashes every share token) was stored in plaintext in
// internal_secrets. It is now sealed under the host master key through crypto::secrets::Manager. The one-time
// conversion keeps the value (so existing links keep working), deletes the plaintext only after the sealed copy reads
// back identical, can resume after a crash between those steps, and fails closed instead of ever replacing a pepper.

#include "../helpers/db_suite.hpp"
#include "crypto/model/Secret.hpp"
#include "crypto/secrets/Manager.hpp"
#include "db/query/crypto/Secret.hpp"
#include "runtime/Deps.hpp"
#include "share/Token.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <memory>
#include <string>
#include <vector>

namespace vh::test_share_pepper_sealing {

using share::Token;
using share::TokenKind;
using SecretRow = crypto::model::Secret;
namespace q = db::query::crypto;

class SharePepperSealing : public vh::test::db::Suite {
protected:
    static void SetUpTestSuite() {
        if (setUpDbSuite("test_share_pepper_sealing", {.runtime = false})) runtime::Deps::init();
    }

    static void TearDownTestSuite() { tearDownDbSuite(); }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        Token::clearPepperForTesting();
        wipe();
    }

    void TearDown() override {
        if (skipTests) return;
        wipe();
        Token::clearPepperForTesting();
    }

    static void wipe() {
        q::Secret::deleteSecret(Token::kSealedPepperKey);
        q::Secret::deleteSecret(Token::kLegacyPepperKey);
        Token::resetPepperCacheForTesting();
    }

    static const crypto::secrets::Manager& secrets() { return *runtime::Deps::get().secretsManager; }

    static void putPlaintext(const std::vector<uint8_t>& pepper) {
        auto row = std::make_shared<SecretRow>();
        row->key = Token::kLegacyPepperKey;
        row->value = pepper;
        row->iv = std::vector<uint8_t>(12, 0x01);  // the old code stored an unused IV
        q::Secret::upsertSecret(row);
    }

    static void putSealed(const std::vector<uint8_t>& pepper) {
        secrets().setSecret(Token::kSealedPepperKey, std::string(pepper.begin(), pepper.end()));
    }

    static std::vector<uint8_t> unsealed() {
        const auto v = secrets().getSecret(Token::kSealedPepperKey);
        return v ? std::vector<uint8_t>(v->begin(), v->end()) : std::vector<uint8_t>{};
    }

    // What a token hashes to under `pepper` (the pre-#322 computation).
    static std::vector<uint8_t> hashUnder(const std::vector<uint8_t>& pepper, const std::string& secret) {
        Token::setPepperForTesting(pepper);
        auto h = Token::hashSecret(TokenKind::PublicShare, secret);
        Token::clearPepperForTesting();
        return h;
    }

    static std::vector<uint8_t> hashNow(const std::string& secret) {
        Token::resetPepperCacheForTesting();
        return Token::hashSecret(TokenKind::PublicShare, secret);
    }
};

TEST_F(SharePepperSealing, FreshInstallStoresOnlyASealedPepper) {
    (void)hashNow("anything");
    EXPECT_FALSE(q::Secret::secretExists(Token::kLegacyPepperKey));
    const auto row = q::Secret::getSecret(Token::kSealedPepperKey);
    ASSERT_TRUE(row);
    const auto pepper = unsealed();
    ASSERT_EQ(pepper.size(), static_cast<size_t>(crypto_generichash_KEYBYTES));
    EXPECT_NE(row->value, pepper) << "the stored value must be ciphertext, not the pepper";
    EXPECT_EQ(row->value.size(), pepper.size() + 16u) << "AES-256-GCM: pepper + tag";
}

TEST_F(SharePepperSealing, ConvertsAPlaintextPepperAndExistingLinksKeepWorking) {
    const std::vector<uint8_t> legacy(32, 0x5a);
    const auto linkHash = hashUnder(legacy, "existing-link-secret");  // what an existing link row stores
    putPlaintext(legacy);

    EXPECT_EQ(hashNow("existing-link-secret"), linkHash);
    EXPECT_FALSE(q::Secret::secretExists(Token::kLegacyPepperKey)) << "plaintext removed after conversion";
    EXPECT_EQ(unsealed(), legacy) << "the value is preserved, now sealed";
    EXPECT_NE(q::Secret::getSecret(Token::kSealedPepperKey)->value, legacy);

    // Idempotent: a second load changes nothing.
    const auto rowBefore = q::Secret::getSecret(Token::kSealedPepperKey)->value;
    EXPECT_EQ(hashNow("existing-link-secret"), linkHash);
    EXPECT_EQ(q::Secret::getSecret(Token::kSealedPepperKey)->value, rowBefore);
}

TEST_F(SharePepperSealing, ResumesAConversionInterruptedBeforeThePlaintextWasDeleted) {
    const std::vector<uint8_t> pepper(32, 0x33);
    putSealed(pepper);
    putPlaintext(pepper);  // crash after sealing, before the delete
    EXPECT_EQ(hashNow("link"), hashUnder(pepper, "link"));
    EXPECT_FALSE(q::Secret::secretExists(Token::kLegacyPepperKey));
    EXPECT_EQ(unsealed(), pepper);
}

TEST_F(SharePepperSealing, RefusesToChooseWhenPlaintextAndSealedDisagree) {
    putSealed(std::vector<uint8_t>(32, 0x11));
    putPlaintext(std::vector<uint8_t>(32, 0x22));
    EXPECT_THROW((void)hashNow("link"), std::runtime_error);
    EXPECT_TRUE(q::Secret::secretExists(Token::kLegacyPepperKey)) << "nothing deleted while they disagree";
    EXPECT_EQ(unsealed(), std::vector<uint8_t>(32, 0x11));
}

TEST_F(SharePepperSealing, FailsClosedWhenTheSealedPepperCannotBeUnsealed) {
    // A row sealed under another host's master key (DB restored without its .sealed_master.blob) looks like this.
    auto row = std::make_shared<SecretRow>();
    row->key = Token::kSealedPepperKey;
    row->value = std::vector<uint8_t>(48, 0x7e);
    row->iv = std::vector<uint8_t>(12, 0x09);
    q::Secret::upsertSecret(row);

    EXPECT_THROW((void)hashNow("link"), std::runtime_error);
    EXPECT_THROW((void)hashNow("link"), std::runtime_error) << "every attempt fails; nothing is cached";
    EXPECT_EQ(q::Secret::getSecret(Token::kSealedPepperKey)->value, row->value) << "never replaced";
    EXPECT_FALSE(q::Secret::secretExists(Token::kLegacyPepperKey));
}

}
