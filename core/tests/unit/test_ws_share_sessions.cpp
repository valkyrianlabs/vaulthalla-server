#include "../helpers/share_fakes.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Manager.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/handler/share/Sessions.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/seed_db.hpp"
#include "share/Principal.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <atomic>
#include <chrono>
#include <memory>
#include <stdexcept>
#include <thread>

namespace vh::protocols::ws::handler::share::test_sessions {
using namespace vh::test::shares;
constexpr std::string_view kChallengeCode = "123456";

vh::rbac::role::Vault uploadDropboxRoleForTest() {
    // The role new installs seed (#151: upload-only, no directory List).
    auto vaultRole = vh::seed::shareUploadDropboxRole();
    vaultRole.id = 99;
    vaultRole.assign(99, "public", 42);
    return vaultRole;
}

bool opSet(const uint32_t ops, const vh::share::Operation op) {
    return (ops & vh::share::bit(op)) != 0;
}

void attachShareRefreshToken(const std::shared_ptr<Session>& session, const std::string& jti) {
    auto token = std::make_shared<vh::auth::model::RefreshToken>();
    token->jti = jti;
    token->rawToken = "raw-" + jti;
    token->hashedToken = "hashed-" + jti;
    token->subject = session->ipAddress + ":" + session->userAgent;
    token->issuedAt = std::chrono::system_clock::now() - std::chrono::minutes(1);
    token->expiresAt = std::chrono::system_clock::now() + std::chrono::hours(1);
    token->userAgent = session->userAgent;
    token->ipAddress = session->ipAddress;
    session->tokens->shareRefreshToken = std::move(token);
}

std::shared_ptr<vh::share::Principal> principalForRouterTest() {
    auto principal = std::make_shared<vh::share::Principal>();
    principal->share_id = uuidFor(1);
    principal->share_session_id = uuidFor(2);
    principal->vault_id = 42;
    principal->root_entry_id = 77;
    principal->root_path = "/reports";
    principal->expires_at = kNow + 3600;
    return principal;
}

void expectNoSecretFields(const nlohmann::json& value) {
    EXPECT_FALSE(value.dump().contains("token_lookup_id"));
    EXPECT_FALSE(value.dump().contains("token_hash"));
    EXPECT_FALSE(value.dump().contains("verification_code"));
    EXPECT_FALSE(value.dump().contains("email@example.com"));
}

class WsShareSessionsTest : public Harness {
protected:
    std::shared_ptr<RecordingCodeSender> codeSender = std::make_shared<RecordingCodeSender>();
    std::shared_ptr<vh::auth::session::Manager> oldSessionManager;

    void SetUp() override {
        oldSessionManager = vh::runtime::Deps::get().sessionManager;
        vh::runtime::Deps::get().sessionManager = std::make_shared<vh::auth::session::Manager>();
        startManager({
            .challenge_ttl_seconds = 300,
            .challenge_max_attempts = 3,
            .challenge_code_generator = [] { return std::string(kChallengeCode); },
            .challenge_code_sender = codeSender
        });
        Sessions::setManagerFactoryForTesting([this] { return manager; });
    }

    void TearDown() override {
        Sessions::resetManagerFactoryForTesting();
        vh::runtime::Deps::get().sessionManager = oldSessionManager;
        Harness::TearDown();
    }

    vh::share::CreateLinkResult create(const vh::share::AccessMode mode = vh::share::AccessMode::Public) {
        const auto ops = vh::share::bit(vh::share::Operation::Metadata) | vh::share::bit(vh::share::Operation::List) |
                         vh::share::bit(vh::share::Operation::Download);
        return manager->createLink(rbac::Actor::human(user), linkRequest(makeLink(ops, mode), publicRole));
    }
};

TEST_F(WsShareSessionsTest, RouterClassifiesPublicHumanAndShareCommands) {
    auto unauth = publicSession();
    auto human = humanSession();
    auto pending = publicSession();
    pending->setPendingShareSession(uuidFor(10), "vhss_pending");
    auto share = publicSession();
    share->setSharePrincipal(principalForRouterTest(), "vhss_ready");

    using Decision = Router::CommandAuthDecision;
    EXPECT_EQ(Decision::Allow, Router::classifyCommand("share.session.open", *unauth));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.dir.list", *unauth));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.link.create", *unauth));

    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.session.open", *human));
    EXPECT_EQ(Decision::RequireHumanAuth, Router::classifyCommand("share.link.create", *human));
    EXPECT_EQ(Decision::RequireHumanAuth, Router::classifyCommand("fs.dir.list", *human));

    EXPECT_EQ(Decision::Allow, Router::classifyCommand("share.email.challenge.confirm", *pending));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("share.link.create", *pending));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("auth.logout", *share));
    EXPECT_EQ(Decision::Deny, Router::classifyCommand("fs.dir.list", *share));
}

TEST_F(WsShareSessionsTest, ValidPublicTokenOpensReadyShareSession) {
    const auto created = create();
    auto session = publicSession();

    const auto response = Sessions::open({{"public_token", created.public_token}}, session);

    EXPECT_EQ("ready", response.at("status").get<std::string>());
    EXPECT_TRUE(response.at("session_token").get<std::string>().starts_with("vhss_"));
    EXPECT_TRUE(session->isShareMode());
    ASSERT_NE(session->sharePrincipal(), nullptr);
    EXPECT_EQ(created.link->id, session->sharePrincipal()->share_id);
    EXPECT_EQ(nullptr, session->user);
    expectNoSecretFields(response);
}

TEST_F(WsShareSessionsTest, OpenResponseIncludesEffectivePreviewWhenScopedRoleAllowsIt) {
    auto created = create();
    created.link->allowed_ops |= vh::share::bit(vh::share::Operation::Preview);
    store->links[created.link->id] = created.link;
    auto session = publicSession();

    const auto response = Sessions::open({{"public_token", created.public_token}}, session);
    const auto share = response.at("share");
    const auto effective = share.at("effective_allowed_ops").get<uint32_t>();

    EXPECT_TRUE(opSet(share.at("allowed_ops").get<uint32_t>(), vh::share::Operation::Preview));
    EXPECT_TRUE(opSet(effective, vh::share::Operation::Preview));
    EXPECT_TRUE(opSet(effective, vh::share::Operation::Download));
    expectNoSecretFields(response);
}

TEST_F(WsShareSessionsTest, OpenResponseRemovesPreviewFromEffectiveOpsWhenScopedRoleDeniesIt) {
    auto created = create();
    created.link->link_type = vh::share::LinkType::Upload;
    created.link->allowed_ops = vh::share::bit(vh::share::Operation::Metadata) |
                                vh::share::bit(vh::share::Operation::List) |
                                vh::share::bit(vh::share::Operation::Preview) |
                                vh::share::bit(vh::share::Operation::Upload);
    store->links[created.link->id] = created.link;
    store->vault_roles[created.link->id] = std::make_shared<vh::rbac::role::Vault>(uploadDropboxRoleForTest());
    auto session = publicSession();

    const auto response = Sessions::open({{"public_token", created.public_token}}, session);
    const auto share = response.at("share");
    const auto effective = share.at("effective_allowed_ops").get<uint32_t>();

    EXPECT_TRUE(opSet(share.at("allowed_ops").get<uint32_t>(), vh::share::Operation::Preview));
    EXPECT_FALSE(opSet(effective, vh::share::Operation::Preview));
    // #151: the seeded dropbox role is upload-only, so even a link that asks for list can't list through it.
    EXPECT_TRUE(opSet(share.at("allowed_ops").get<uint32_t>(), vh::share::Operation::List));
    EXPECT_FALSE(opSet(effective, vh::share::Operation::List));
    EXPECT_TRUE(opSet(effective, vh::share::Operation::Upload));
    expectNoSecretFields(response);
}

TEST_F(WsShareSessionsTest, OpeningSameReadyPublicTokenIsIdempotent) {
    const auto created = create();
    auto session = publicSession();

    const auto first = Sessions::open({{"public_token", created.public_token}}, session);
    const auto firstSessionId = first.at("session_id").get<std::string>();
    const auto firstSessionToken = first.at("session_token").get<std::string>();

    const auto second = Sessions::open({{"public_token", created.public_token}}, session);

    EXPECT_EQ("ready", second.at("status").get<std::string>());
    EXPECT_EQ(firstSessionId, second.at("session_id").get<std::string>());
    EXPECT_EQ(firstSessionToken, second.at("session_token").get<std::string>());
    EXPECT_TRUE(session->isShareMode());
    ASSERT_NE(session->sharePrincipal(), nullptr);
    EXPECT_EQ(created.link->id, session->sharePrincipal()->share_id);
    EXPECT_EQ(1u, store->sessions.size());
    expectNoSecretFields(second);
}

TEST_F(WsShareSessionsTest, OpeningDifferentPublicTokenReplacesReadyShareSession) {
    const auto firstLink = create();
    auto secondLink = create();
    secondLink.link->root_entry_id = 88;
    secondLink.link->root_path = "/reports/child.txt";
    secondLink.link->target_type = vh::share::TargetType::File;
    secondLink.link->allowed_ops = vh::share::bit(vh::share::Operation::Download);

    auto session = publicSession();
    attachShareRefreshToken(session, "share-refresh-switch");
    vh::runtime::Deps::get().sessionManager->cache(session);

    const auto first = Sessions::open({{"public_token", firstLink.public_token}}, session);
    ASSERT_EQ("ready", first.at("status").get<std::string>());
    ASSERT_NE(session->sharePrincipal(), nullptr);
    EXPECT_EQ(firstLink.link->id, session->sharePrincipal()->share_id);

    const auto second = Sessions::open({{"public_token", secondLink.public_token}}, session);

    EXPECT_EQ("ready", second.at("status").get<std::string>());
    ASSERT_NE(session->sharePrincipal(), nullptr);
    EXPECT_EQ(secondLink.link->id, session->sharePrincipal()->share_id);
    EXPECT_EQ(secondLink.link->root_entry_id, session->sharePrincipal()->root_entry_id);
    EXPECT_EQ(secondLink.link->root_path, session->sharePrincipal()->root_path);
    EXPECT_NE(first.at("session_id").get<std::string>(), second.at("session_id").get<std::string>());
    EXPECT_EQ(session, vh::runtime::Deps::get().sessionManager->getShareByRefreshJti("share-refresh-switch"));
    expectNoSecretFields(second);
}

TEST_F(WsShareSessionsTest, OpeningEmailRequiredTokenReplacesReadyShareSessionWithPending) {
    const auto readyLink = create();
    const auto emailLink = create(vh::share::AccessMode::EmailValidated);
    auto session = publicSession();
    attachShareRefreshToken(session, "share-refresh-email-switch");
    vh::runtime::Deps::get().sessionManager->cache(session);

    const auto ready = Sessions::open({{"public_token", readyLink.public_token}}, session);
    ASSERT_EQ("ready", ready.at("status").get<std::string>());
    ASSERT_TRUE(session->isShareMode());
    ASSERT_NE(session->sharePrincipal(), nullptr);
    EXPECT_EQ(readyLink.link->id, session->sharePrincipal()->share_id);

    const auto pending = Sessions::open({{"public_token", emailLink.public_token}}, session);

    EXPECT_EQ("email_required", pending.at("status").get<std::string>());
    EXPECT_TRUE(session->isSharePending());
    EXPECT_EQ(nullptr, session->sharePrincipal());
    EXPECT_EQ(pending.at("session_id").get<std::string>(), session->shareSessionId());
    EXPECT_EQ(session, vh::runtime::Deps::get().sessionManager->getShareByRefreshJti("share-refresh-email-switch"));
    expectNoSecretFields(pending);
}

TEST_F(WsShareSessionsTest, PublicOpenPromotesExistingShareRefreshJtiToReadyShareStorage) {
    const auto created = create();
    auto session = publicSession();
    attachShareRefreshToken(session, "share-refresh-jti-ready");
    vh::runtime::Deps::get().sessionManager->cache(session);

    ASSERT_EQ(nullptr, vh::runtime::Deps::get().sessionManager->get("share-refresh-jti-ready"));
    ASSERT_EQ(session, vh::runtime::Deps::get().sessionManager->getShareByRefreshJti("share-refresh-jti-ready"));

    const auto response = Sessions::open({{"public_token", created.public_token}}, session);

    EXPECT_EQ("ready", response.at("status").get<std::string>());
    EXPECT_EQ(nullptr, vh::runtime::Deps::get().sessionManager->get("share-refresh-jti-ready"));
    EXPECT_EQ(session, vh::runtime::Deps::get().sessionManager->getShareByRefreshJti("share-refresh-jti-ready"));
    EXPECT_TRUE(session->isShareMode());
    EXPECT_FALSE(session->user);
}

// sharing.* (#164): the public /ws/share entry point refuses links whose kind (or sharing as a whole) is off,
// including a token the same socket had already opened.
TEST_F(WsShareSessionsTest, OpenIsRefusedWhileSharingOrTheLinksKindIsOff) {
    const auto publicLink = create();
    const auto emailLink = create(vh::share::AccessMode::EmailValidated);
    auto session = publicSession();
    ASSERT_EQ("ready", Sessions::open({{"public_token", publicLink.public_token}}, session).at("status"));

    const auto previous = vh::config::Registry::get();
    struct Restore {
        const vh::config::Config& cfg;
        ~Restore() { vh::config::Registry::set(cfg); }
    } restore{previous};

    auto cfg = previous;
    cfg.sharing.enable_anonymous = false;
    vh::config::Registry::set(cfg);
    EXPECT_THROW(Sessions::open({{"public_token", publicLink.public_token}}, session), vh::ops::Denied);
    EXPECT_THROW(Sessions::open({{"public_token", publicLink.public_token}}, publicSession()), vh::ops::Denied);
    EXPECT_EQ("email_required",
              Sessions::open({{"public_token", emailLink.public_token}}, publicSession()).at("status"));

    cfg.sharing.enable_anonymous = true;
    cfg.sharing.enabled = false;
    vh::config::Registry::set(cfg);
    EXPECT_THROW(Sessions::open({{"public_token", emailLink.public_token}}, publicSession()), vh::ops::Denied);

    vh::config::Registry::set(previous);
    EXPECT_EQ("ready", Sessions::open({{"public_token", publicLink.public_token}}, publicSession()).at("status"));
}

TEST_F(WsShareSessionsTest, EmailValidatedShareOpensPendingAndDoesNotGrantPrincipal) {
    const auto created = create(vh::share::AccessMode::EmailValidated);
    auto session = publicSession();

    const auto response = Sessions::open({{"public_token", created.public_token}}, session);

    EXPECT_EQ("email_required", response.at("status").get<std::string>());
    EXPECT_TRUE(response.at("session_token").get<std::string>().starts_with("vhss_"));
    EXPECT_TRUE(session->isSharePending());
    EXPECT_EQ(nullptr, session->sharePrincipal());
    EXPECT_THROW({ (void)manager->resolvePrincipal(session->shareSessionToken()); }, std::runtime_error);
    expectNoSecretFields(response);
}

TEST_F(WsShareSessionsTest, EmailConfirmPromotesExistingShareRefreshJtiToReadyShareStorage) {
    const auto created = create(vh::share::AccessMode::EmailValidated);
    auto session = publicSession();
    attachShareRefreshToken(session, "share-refresh-jti-email");
    vh::runtime::Deps::get().sessionManager->cache(session);

    const auto opened = Sessions::open({{"public_token", created.public_token}}, session);

    EXPECT_EQ("email_required", opened.at("status").get<std::string>());
    ASSERT_EQ(nullptr, vh::runtime::Deps::get().sessionManager->get("share-refresh-jti-email"));
    ASSERT_EQ(session, vh::runtime::Deps::get().sessionManager->getShareByRefreshJti("share-refresh-jti-email"));
    EXPECT_TRUE(session->isSharePending());

    const auto challenge = Sessions::startEmailChallenge({{"email", " Email@Example.COM "}}, session);
    const auto confirmed = Sessions::confirmEmailChallenge({
        {"challenge_id", challenge.at("challenge_id").get<std::string>()},
        {"code", std::string(kChallengeCode)}
    }, session);

    EXPECT_EQ("ready", confirmed.at("status").get<std::string>());
    EXPECT_EQ(nullptr, vh::runtime::Deps::get().sessionManager->get("share-refresh-jti-email"));
    EXPECT_EQ(session, vh::runtime::Deps::get().sessionManager->getShareByRefreshJti("share-refresh-jti-email"));
    EXPECT_TRUE(session->isShareMode());
    EXPECT_FALSE(session->user);
}

TEST_F(WsShareSessionsTest, ChallengeStartAndConfirmEstablishShareModeWithoutReturningCode) {
    const auto created = create(vh::share::AccessMode::EmailValidated);
    auto session = publicSession();
    Sessions::open({{"public_token", created.public_token}}, session);

    const auto challenge = Sessions::startEmailChallenge({{"email", " Email@Example.COM "}}, session);

    EXPECT_EQ("challenge_created", challenge.at("status").get<std::string>());
    EXPECT_TRUE(session->isSharePending());
    EXPECT_FALSE(challenge.contains("verification_code"));
    expectNoSecretFields(challenge);
    // #317: the code goes to the recipient by email, never in the reply.
    ASSERT_EQ(codeSender->sent.size(), 1u);
    EXPECT_EQ(codeSender->sent.front().code, std::string(kChallengeCode));
    EXPECT_EQ(codeSender->sent.front().to, "email@example.com");

    EXPECT_THROW(Sessions::confirmEmailChallenge({
        {"challenge_id", challenge.at("challenge_id").get<std::string>()},
        {"code", "000000"}
    }, session), std::runtime_error);

    const auto confirmed = Sessions::confirmEmailChallenge({
        {"challenge_id", challenge.at("challenge_id").get<std::string>()},
        {"code", std::string(kChallengeCode)}
    }, session);

    EXPECT_EQ("ready", confirmed.at("status").get<std::string>());
    EXPECT_TRUE(confirmed.at("verified").get<bool>());
    EXPECT_TRUE(session->isShareMode());
    ASSERT_NE(session->sharePrincipal(), nullptr);
    EXPECT_TRUE(session->sharePrincipal()->email_verified);
    expectNoSecretFields(confirmed);
}

TEST_F(WsShareSessionsTest, ChallengeFlowRejectsInvalidStates) {
    const auto publicShare = create();
    auto ready = publicSession();
    Sessions::open({{"public_token", publicShare.public_token}}, ready);

    EXPECT_THROW(Sessions::startEmailChallenge({{"email", "email@example.com"}}, ready), vh::ops::Conflict);
    EXPECT_THROW(Sessions::open({{"public_token", publicShare.public_token}}, humanSession()), vh::ops::Denied);
    EXPECT_THROW(Sessions::confirmEmailChallenge({
        {"challenge_id", uuidFor(999)},
        {"code", std::string(kChallengeCode)}
    }, publicSession()), vh::ops::Invalid);
}

}

namespace vh::protocols::ws::test_share_identity {

// #389 ("Malformed share token prefix", once): a share session's identity is re-set by whichever thread re-resolves it
// (HTTP connection threads, resumable-upload commit workers) while others read it. Readers used to get a reference
// into a string being replaced, so a token could come back torn. Every read is now a whole token of one of the writes.
TEST(WsShareIdentity, ConcurrentReadersSeeWholeTokensWhileTheyAreReplaced) {
    // Well-formed session tokens of different lengths, both past any small-string buffer.
    const std::string a = "vhss_0b2d6f1e-6a0c-4c55-9e3f-2f7d1a9c4b10_7k3m9q2r5t8v1w4x6y0z";
    const std::string b = "vhss_9f8e7d6c-5b4a-4321-8fed-cba987654321_a1b2c3d4e5f6g7h8j9k0m1n2p3q4r5s6";
    const auto principal = [](const std::string& id) {
        auto p = std::make_shared<vh::share::Principal>();
        p->share_session_id = id;
        return p;
    };
    const auto pa = principal("session-a"), pb = principal("session-b");
    auto session = std::make_shared<Session>(std::make_shared<Router>());
    session->setSharePrincipal(pa, a);

    std::atomic<bool> stop{false};
    std::thread writer([&] {
        for (int i = 0; i < 20000; ++i) session->setSharePrincipal(i % 2 ? pa : pb, i % 2 ? a : b);
        stop = true;
    });
    unsigned torn = 0, reads = 0;
    while (!stop.load()) {
        const auto token = session->shareSessionToken();
        const auto id = session->shareSessionId();
        if (token != a && token != b) ++torn;
        if (id != "session-a" && id != "session-b") ++torn;
        if (const auto p = session->sharePrincipal(); !p || (p != pa && p != pb)) ++torn;
        EXPECT_NO_THROW((void)vh::share::Token::parse(token));
        ++reads;
    }
    writer.join();
    EXPECT_EQ(torn, 0u) << "of " << reads << " reads";
    EXPECT_TRUE(session->isShareMode());
}

}
