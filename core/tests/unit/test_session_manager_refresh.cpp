#include "auth/session/Manager.hpp"
#include "auth/model/Token.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Validator.hpp"
#include "identities/User.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "share/Principal.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <string>

namespace vh::auth::session::test_refresh {

std::shared_ptr<protocols::ws::Session> baseSession() {
    auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    session->ipAddress = "127.0.0.1";
    session->userAgent = "session-manager-refresh-test";
    return session;
}

std::shared_ptr<share::Principal> sharePrincipal() {
    auto principal = std::make_shared<share::Principal>();
    principal->share_id = "share-id";
    principal->share_session_id = "share-session-id";
    principal->vault_id = 42;
    principal->root_entry_id = 7;
    principal->root_path = "/share";
    return principal;
}

std::shared_ptr<protocols::ws::Session> readyShareSession() {
    auto session = baseSession();
    session->setSharePrincipal(sharePrincipal(), "vhss_ready");
    return session;
}

std::shared_ptr<protocols::ws::Session> pendingShareSession() {
    auto session = baseSession();
    session->setPendingShareSession("share-session-id", "vhss_pending");
    return session;
}

std::shared_ptr<identities::User> testUser() {
    vh::identities::UserState userState;
    userState.name = "session-refresh-human";
    auto user = vh::identities::User::detached(17, std::move(userState));
    return user;
}

struct ScopedRuntimeSessionManager {
    std::shared_ptr<Manager> previous;

    explicit ScopedRuntimeSessionManager(std::shared_ptr<Manager> manager)
        : previous(vh::runtime::Deps::get().sessionManager) {
        vh::runtime::Deps::get().sessionManager = std::move(manager);
    }

    ~ScopedRuntimeSessionManager() {
        vh::runtime::Deps::get().sessionManager = std::move(previous);
    }
};

class SessionManagerRefreshTest : public ::testing::Test {
protected:
    void SetUp() override {
        Issuer::setJwtSecretForTesting("session-manager-refresh-test-secret");
    }

    void TearDown() override {
        Issuer::clearJwtSecretForTesting();
    }
};

TEST_F(SessionManagerRefreshTest, ShareRegistrationIndexesCurrentRefreshJtiAndValidatesRawToken) {
    Manager manager;
    auto session = readyShareSession();

    manager.rotateShareRefreshToken(session);

    const auto jti = session->tokens->shareRefreshToken->jti;
    const auto raw = session->tokens->shareRefreshToken->rawToken;

    EXPECT_EQ(nullptr, manager.get(jti));
    EXPECT_EQ(session, manager.getShareByRefreshJti(jti));
    EXPECT_EQ(session, manager.validateRawShareRefreshToken(raw));
    EXPECT_THROW((void)manager.validateRawRefreshToken(raw), std::invalid_argument);
}

TEST_F(SessionManagerRefreshTest, ShareRefreshCookieBootstrapIndexesPendingCredential) {
    Manager manager;
    auto session = baseSession();

    manager.rotateShareRefreshToken(session);

    const auto jti = session->tokens->shareRefreshToken->jti;
    const auto raw = session->tokens->shareRefreshToken->rawToken;

    EXPECT_EQ(session, manager.getShareByRefreshJti(jti));
    EXPECT_THROW((void)manager.validateRawShareRefreshToken(raw), std::invalid_argument);
    EXPECT_THROW((void)manager.validateRawRefreshToken(raw), std::invalid_argument);
}

TEST_F(SessionManagerRefreshTest, ShareRefreshRotationRemovesOldJtiAndIndexesNewJti) {
    Manager manager;
    auto session = readyShareSession();

    manager.rotateShareRefreshToken(session);
    const auto oldJti = session->tokens->shareRefreshToken->jti;
    const auto oldRaw = session->tokens->shareRefreshToken->rawToken;

    manager.rotateShareRefreshToken(session);
    const auto newJti = session->tokens->shareRefreshToken->jti;
    const auto newRaw = session->tokens->shareRefreshToken->rawToken;

    EXPECT_NE(oldJti, newJti);
    EXPECT_EQ(nullptr, manager.getShareByRefreshJti(oldJti));
    EXPECT_EQ(session, manager.getShareByRefreshJti(newJti));
    EXPECT_THROW((void)manager.validateRawShareRefreshToken(oldRaw), std::invalid_argument);
    EXPECT_EQ(session, manager.validateRawShareRefreshToken(newRaw));
}

TEST_F(SessionManagerRefreshTest, PendingShareDoesNotValidateUntilPromotionPreservesCurrentJti) {
    Manager manager;
    auto session = pendingShareSession();

    manager.rotateShareRefreshToken(session);
    const auto jti = session->tokens->shareRefreshToken->jti;
    const auto raw = session->tokens->shareRefreshToken->rawToken;

    EXPECT_EQ(session, manager.getShareByRefreshJti(jti));
    EXPECT_THROW((void)manager.validateRawShareRefreshToken(raw), std::invalid_argument);

    session->setSharePrincipal(sharePrincipal(), session->shareSessionToken());
    manager.cache(session);

    EXPECT_EQ(session, manager.getShareByRefreshJti(jti));
    EXPECT_EQ(session, manager.validateRawShareRefreshToken(raw));
}

TEST_F(SessionManagerRefreshTest, HumanAndShareRefreshIndexesStaySeparate) {
    Manager manager;

    auto shareSession = readyShareSession();
    manager.rotateShareRefreshToken(shareSession);
    const auto shareRaw = shareSession->tokens->shareRefreshToken->rawToken;

    auto humanSession = baseSession();
    manager.rotateRefreshToken(humanSession);
    humanSession->setAuthenticatedUser(testUser());
    manager.cache(humanSession);
    const auto oldHumanJti = humanSession->tokens->refreshToken->jti;

    manager.rotateRefreshToken(humanSession);
    const auto newHumanJti = humanSession->tokens->refreshToken->jti;
    const auto humanRaw = humanSession->tokens->refreshToken->rawToken;

    EXPECT_EQ(nullptr, manager.get(oldHumanJti));
    EXPECT_EQ(humanSession, manager.get(newHumanJti));
    EXPECT_EQ(nullptr, manager.getShareByRefreshJti(newHumanJti));

    EXPECT_THROW((void)manager.validateRawRefreshToken(shareRaw), std::invalid_argument);
    EXPECT_THROW((void)manager.validateRawShareRefreshToken(humanRaw), std::invalid_argument);
}

TEST_F(SessionManagerRefreshTest, RemoveEvictsUnauthenticatedSessionFromRuntimeCache) {
    Manager manager;
    auto session = baseSession();

    manager.cache(session);

    EXPECT_EQ(session, manager.get(session->uuid));
    EXPECT_EQ(1u, manager.getActive().size());

    manager.remove(session);

    EXPECT_EQ(nullptr, manager.get(session->uuid));
    EXPECT_TRUE(manager.getActive().empty());
}

TEST_F(SessionManagerRefreshTest, RemoveEvictsHumanIndexesWithoutRevokingRefreshToken) {
    Manager manager;
    auto session = baseSession();

    manager.rotateRefreshToken(session);
    session->setAuthenticatedUser(testUser());
    manager.cache(session);

    const auto jti = session->tokens->refreshToken->jti;
    const auto raw = session->tokens->refreshToken->rawToken;
    const auto hash = session->tokens->refreshToken->hashedToken;

    EXPECT_EQ(session, manager.get(session->uuid));
    EXPECT_EQ(session, manager.get(jti));
    EXPECT_EQ(1u, manager.getSessionsByUserId(session->user->id).size());

    manager.remove(session);

    EXPECT_EQ(nullptr, manager.get(session->uuid));
    EXPECT_EQ(nullptr, manager.get(jti));
    EXPECT_TRUE(manager.getSessionsByUserId(session->user->id).empty());
    ASSERT_TRUE(session->tokens->refreshToken);
    EXPECT_FALSE(session->tokens->refreshToken->revoked);
    EXPECT_EQ(raw, session->tokens->refreshToken->rawToken);
    EXPECT_EQ(hash, session->tokens->refreshToken->hashedToken);
}

TEST_F(SessionManagerRefreshTest, RemoveEvictsShareIndexesWithoutRevokingRefreshToken) {
    Manager manager;
    auto session = readyShareSession();

    manager.rotateShareRefreshToken(session);

    const auto jti = session->tokens->shareRefreshToken->jti;
    const auto raw = session->tokens->shareRefreshToken->rawToken;
    const auto hash = session->tokens->shareRefreshToken->hashedToken;

    EXPECT_EQ(session, manager.get(session->uuid));
    EXPECT_EQ(session, manager.getShareByRefreshJti(jti));

    manager.remove(session);

    EXPECT_EQ(nullptr, manager.get(session->uuid));
    EXPECT_EQ(nullptr, manager.getShareByRefreshJti(jti));
    ASSERT_TRUE(session->tokens->shareRefreshToken);
    EXPECT_FALSE(session->tokens->shareRefreshToken->revoked);
    EXPECT_EQ(raw, session->tokens->shareRefreshToken->rawToken);
    EXPECT_EQ(hash, session->tokens->shareRefreshToken->hashedToken);
}

TEST_F(SessionManagerRefreshTest, InvalidateStillRevokesRuntimeOnlyAccessTokenAndRemovesIndexes) {
    Manager manager;
    auto session = baseSession();
    session->tokens->accessToken = std::make_shared<vh::auth::model::Token>();

    manager.cache(session);

    EXPECT_EQ(session, manager.get(session->uuid));

    manager.invalidate(session);

    EXPECT_EQ(nullptr, manager.get(session->uuid));
    EXPECT_TRUE(manager.getActive().empty());
    EXPECT_TRUE(session->tokens->accessToken->revoked);
}

TEST_F(SessionManagerRefreshTest, PriorSessionRehydrationRestoresHumanMode) {
    auto manager = std::make_shared<Manager>();
    ScopedRuntimeSessionManager scoped(manager);

    auto prior = baseSession();
    manager->rotateRefreshToken(prior);
    prior->setAuthenticatedUser(testUser());
    manager->cache(prior);

    const auto raw = prior->tokens->refreshToken->rawToken;
    const auto claims = Issuer::decode(raw);
    ASSERT_TRUE(claims);

    auto reconnected = baseSession();

    ASSERT_TRUE(Validator::tryRehydrateFromPriorSession(reconnected, raw, claims));
    ASSERT_TRUE(reconnected->user);
    EXPECT_EQ(prior->user->id, reconnected->user->id);
    EXPECT_EQ(protocols::ws::SessionMode::Human, reconnected->mode());
}

}
