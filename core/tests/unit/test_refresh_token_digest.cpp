#include "../helpers/identities.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Manager.hpp"
#include "auth/session/Validator.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "seed/include/SqlDeployer.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

// #171: refresh tokens were stored as Argon2 password hashes (~0.57 s per verify, paid on every page load and every
// HTTP preview/download). They are now a `sha256:` digest; legacy rows still verify and are rewritten on first use.
namespace vh::auth::session::test_refresh_digest {

namespace hash = vh::crypto::hash;
using hash::TokenMatch;

constexpr auto kIp = "127.0.0.1";
constexpr auto kUserAgent = "refresh-token-digest-test";

bool isDigestForm(const std::string& stored) {
    if (!stored.starts_with("sha256:") || stored.size() != 7 + 64) return false;
    for (const char c : stored.substr(7))
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

std::shared_ptr<protocols::ws::Session> baseSession() {
    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    session->ipAddress = kIp;
    session->userAgent = kUserAgent;
    return session;
}

// ── Pure helper ─────────────────────────────────────────────────────────────────────────────────────────────────────

TEST(RefreshTokenDigest, DigestIsSha256HexWithPrefix) {
    // SHA-256("abc"), FIPS 180-2 test vector.
    EXPECT_EQ("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", hash::tokenDigest("abc"));
    EXPECT_TRUE(isDigestForm(hash::tokenDigest("some.jwt.token")));
    EXPECT_EQ(hash::tokenDigest("x"), hash::tokenDigest("x"));
    EXPECT_NE(hash::tokenDigest("x"), hash::tokenDigest("y"));
}

TEST(RefreshTokenDigest, VerifiesBothFormatsAndRejectsWrongTokens) {
    const std::string token = "header.payload.signature";

    EXPECT_EQ(TokenMatch::Digest, hash::verifyToken(token, hash::tokenDigest(token)));
    EXPECT_EQ(TokenMatch::Mismatch, hash::verifyToken("header.payload.other", hash::tokenDigest(token)));

    const auto legacy = hash::password(token);
    EXPECT_EQ(TokenMatch::Legacy, hash::verifyToken(token, legacy));
    EXPECT_EQ(TokenMatch::Mismatch, hash::verifyToken("header.payload.other", legacy));
}

TEST(RefreshTokenDigest, MalformedStoredValuesNeverMatch) {
    const std::string token = "header.payload.signature";
    const auto digest = hash::tokenDigest(token);
    std::string upper = digest;
    for (auto& c : upper) if (c >= 'a' && c <= 'f') c = static_cast<char>(c - 'a' + 'A');

    for (const std::string& stored : {
             std::string{},
             std::string{"sha256:"},
             digest.substr(0, digest.size() - 1),
             digest + "0",
             upper,
             std::string{"SHA256:"} + digest.substr(7),
             digest.substr(7),            // bare hex, no prefix
             token,                       // the raw token itself
             std::string{"$argon2id$v=19$m=65536,t=2,p=1$garbage"},
             std::string{"not-a-hash"},
         }) {
        EXPECT_EQ(TokenMatch::Mismatch, hash::verifyToken(token, stored)) << "stored: " << stored;
    }
}

TEST(RefreshTokenDigest, HundredVerifiesTakeWellUnderASecond) {
    const std::string token(400, 't');
    const auto stored = hash::tokenDigest(token);

    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 100; ++i) ASSERT_EQ(TokenMatch::Digest, hash::verifyToken(token, stored));
    const auto elapsed = std::chrono::steady_clock::now() - start;

    EXPECT_LT(elapsed, std::chrono::milliseconds(100));
}

// ── Issuer (no DB) ──────────────────────────────────────────────────────────────────────────────────────────────────

class RefreshTokenDigestIssuer : public ::testing::Test {
protected:
    void SetUp() override { Issuer::setJwtSecretForTesting("refresh-token-digest-test-secret"); }
    void TearDown() override { Issuer::clearJwtSecretForTesting(); }
};

TEST_F(RefreshTokenDigestIssuer, NewHumanAndShareRefreshTokensAreStoredAsDigest) {
    auto session = baseSession();

    Issuer::refreshToken(session);
    ASSERT_TRUE(session->tokens->refreshToken);
    EXPECT_EQ(hash::tokenDigest(session->tokens->refreshToken->rawToken), session->tokens->refreshToken->hashedToken);

    Issuer::shareRefreshToken(session);
    ASSERT_TRUE(session->tokens->shareRefreshToken);
    EXPECT_EQ(hash::tokenDigest(session->tokens->shareRefreshToken->rawToken),
              session->tokens->shareRefreshToken->hashedToken);
}

// ── DB-backed: stored rows, legacy rewrite ──────────────────────────────────────────────────────────────────────────

struct ScopedRuntimeSessionManager {
    std::shared_ptr<Manager> previous;

    explicit ScopedRuntimeSessionManager(std::shared_ptr<Manager> manager)
        : previous(vh::runtime::Deps::get().sessionManager) {
        vh::runtime::Deps::get().sessionManager = std::move(manager);
    }

    ~ScopedRuntimeSessionManager() { vh::runtime::Deps::get().sessionManager = std::move(previous); }
};

class RefreshTokenDigestDb : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> user;

    static bool hasDbEnv() {
        return std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
               std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME");
    }

    static void SetUpTestSuite() {
        if (!hasDbEnv()) {
            skipTests = true;
            std::cout << "[test_refresh_token_digest] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }

        vh::paths::enableTestMode();
        vh::db::Transactions::init();
        vh::db::seed::nuke_and_recreate_schema_public();
        vh::db::seed::init_tables_if_not_exists();
        vh::db::Transactions::dbPool_->initPreparedStatements();
        vh::seed::initPermissions();
        vh::seed::initRoles();

        const auto uRole = vh::db::query::rbac::role::Admin::get("unprivileged");
        if (!uRole) throw std::runtime_error("Missing unprivileged role");
        auto u = vh::test::identities::createUser("refresh_digest_user", uRole, "refresh_digest_user@vaulthalla.test", hash::password("refresh-digest-user-pass"), std::nullopt);
        user = vh::identities::manager().user(u->id);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        Issuer::setJwtSecretForTesting("refresh-token-digest-db-test-secret");
    }

    void TearDown() override { Issuer::clearJwtSecretForTesting(); }

    // Mints a human refresh token for `user` and stores its row with `storedHash` (the digest when empty).
    static std::shared_ptr<model::RefreshToken> storeToken(const std::function<std::string(const std::string&)>& storedHash = {}) {
        auto session = baseSession();
        session->user = user;
        Issuer::refreshToken(session);
        auto token = session->tokens->refreshToken;
        if (storedHash) token->hashedToken = storedHash(token->rawToken);
        vh::db::query::auth::RefreshToken::set(token);
        return token;
    }

    static std::string storedHash(const std::string& jti) {
        const auto row = vh::db::query::auth::RefreshToken::get(jti);
        if (!row) throw std::runtime_error("refresh token row missing");
        return row->hashedToken;
    }

    // The HTTP / page-load path: no runtime session, rehydrate from the stored row.
    static std::shared_ptr<protocols::ws::Session> validateRaw(const std::string& raw) {
        Manager manager;
        return manager.validateRawRefreshToken(raw);
    }

    // The ws handshake path: a fresh socket carrying the refresh cookie.
    static std::shared_ptr<protocols::ws::Session> validateViaSocket(const std::string& raw) {
        ScopedRuntimeSessionManager scoped(std::make_shared<Manager>());
        auto session = baseSession();
        model::RefreshToken::addToSession(session, raw);
        Validator::validateRefreshToken(session);
        return session;
    }
};

TEST_F(RefreshTokenDigestDb, NewTokensAreStoredAsDigestAndVerify) {
    const auto token = storeToken();

    EXPECT_TRUE(isDigestForm(storedHash(token->jti)));
    EXPECT_EQ(hash::tokenDigest(token->rawToken), storedHash(token->jti));

    const auto session = validateRaw(token->rawToken);
    ASSERT_TRUE(session && session->user);
    EXPECT_EQ(user->id, session->user->id);

    const auto socket = validateViaSocket(token->rawToken);
    ASSERT_TRUE(socket->user);
    EXPECT_EQ(user->id, socket->user->id);
}

TEST_F(RefreshTokenDigestDb, LegacyArgon2RowVerifiesAndIsRewrittenToDigest) {
    const auto token = storeToken([](const std::string& raw) { return hash::password(raw); });
    ASSERT_TRUE(storedHash(token->jti).starts_with("$argon2"));

    const auto session = validateRaw(token->rawToken);
    ASSERT_TRUE(session && session->user);
    EXPECT_EQ(user->id, session->user->id);

    EXPECT_EQ(hash::tokenDigest(token->rawToken), storedHash(token->jti));
    EXPECT_EQ(hash::tokenDigest(token->rawToken), session->tokens->refreshToken->hashedToken);

    // Later checks take the digest path and still succeed.
    EXPECT_NO_THROW((void)validateRaw(token->rawToken));
    EXPECT_NO_THROW((void)validateViaSocket(token->rawToken));
}

TEST_F(RefreshTokenDigestDb, LegacyArgon2RowIsRewrittenOnTheSocketPathToo) {
    const auto token = storeToken([](const std::string& raw) { return hash::password(raw); });

    const auto socket = validateViaSocket(token->rawToken);
    ASSERT_TRUE(socket->user);
    EXPECT_EQ(hash::tokenDigest(token->rawToken), storedHash(token->jti));
}

TEST_F(RefreshTokenDigestDb, WrongTokenFailsForBothFormatsAndLeavesTheRowAlone) {
    const auto digestRow = storeToken([](const std::string&) { return hash::tokenDigest("some-other-token"); });
    EXPECT_ANY_THROW((void)validateRaw(digestRow->rawToken));
    EXPECT_ANY_THROW((void)validateViaSocket(digestRow->rawToken));

    const auto legacyHash = hash::password("some-other-token");
    const auto legacyRow = storeToken([&](const std::string&) { return legacyHash; });
    EXPECT_ANY_THROW((void)validateRaw(legacyRow->rawToken));
    EXPECT_EQ(legacyHash, storedHash(legacyRow->jti));
}

TEST_F(RefreshTokenDigestDb, MalformedStoredHashFails) {
    for (const std::string bad : {"not-a-hash", "sha256:XYZ", "sha256:", "$argon2id$garbage"}) {
        const auto token = storeToken([&](const std::string&) { return bad; });
        EXPECT_ANY_THROW((void)validateRaw(token->rawToken)) << "stored: " << bad;
        EXPECT_EQ(bad, storedHash(token->jti));
    }
}

TEST_F(RefreshTokenDigestDb, RewriteIsConditionalOnTheLegacyValue) {
    const auto token = storeToken([](const std::string& raw) { return hash::password(raw); });
    const auto legacy = storedHash(token->jti);
    const auto digest = hash::tokenDigest(token->rawToken);

    EXPECT_FALSE(vh::db::query::auth::RefreshToken::rewriteHash(token->jti, "something-else", digest));
    EXPECT_EQ(legacy, storedHash(token->jti));

    EXPECT_TRUE(vh::db::query::auth::RefreshToken::rewriteHash(token->jti, legacy, digest));
    EXPECT_EQ(digest, storedHash(token->jti));
}

TEST_F(RefreshTokenDigestDb, StoredTokenVerifiesAreFast) {
    const auto token = storeToken();

    const auto start = std::chrono::steady_clock::now();
    for (int i = 0; i < 50; ++i) ASSERT_NO_THROW((void)validateRaw(token->rawToken));
    const auto elapsed = std::chrono::steady_clock::now() - start;

    std::cout << "[test_refresh_token_digest] 50 stored-token rehydrations: "
              << std::chrono::duration_cast<std::chrono::milliseconds>(elapsed).count() << " ms" << std::endl;
    // One Argon2 verify alone was ~0.57 s; 50 would be ~28 s.
    EXPECT_LT(elapsed, std::chrono::seconds(5));
}

}
