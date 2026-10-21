#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Manager.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "db/encoding/bytea.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/share/Sessions.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/seed_db.hpp"
#include "share/AuditEvent.hpp"
#include "share/EmailChallenge.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "share/Token.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <chrono>
#include <format>
#include <memory>
#include <stdexcept>
#include <unordered_map>

namespace vh::protocols::ws::handler::share::test_sessions {
constexpr std::time_t kNow = 1'800'000'000;
constexpr std::string_view kChallengeCode = "123456";

std::string uuidFor(const uint32_t value) {
    return std::format("00000000-0000-4000-8000-{:012d}", value);
}

class FakeAuthorizer final : public vh::share::ShareAuthorizer {
public:
    vh::share::AuthorizationDecision canCreateLink(
        const rbac::Actor& actor,
        const vh::share::Link&
    ) const override {
        return {actor.isHuman(), actor.isHuman() ? "allowed" : "not_human"};
    }

    vh::share::AuthorizationDecision canUpdateLink(
        const rbac::Actor& actor,
        const vh::share::Link&,
        const vh::share::Link&
    ) const override {
        return {actor.isHuman(), actor.isHuman() ? "allowed" : "not_human"};
    }

    vh::share::AuthorizationDecision canManageLink(
        const rbac::Actor& actor,
        const vh::share::Link&
    ) const override {
        return {actor.isHuman(), actor.isHuman() ? "allowed" : "not_human"};
    }

    vh::share::AuthorizationDecision canListVaultLinks(const rbac::Actor& actor, uint32_t) const override {
        return {actor.isHuman(), actor.isHuman() ? "allowed" : "not_human"};
    }
};

class FakeStore final : public vh::share::ShareStore {
public:
    std::unordered_map<std::string, std::shared_ptr<vh::share::Link>> links;
    std::unordered_map<std::string, std::string> link_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<vh::share::Session>> sessions;
    std::unordered_map<std::string, std::string> session_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<vh::share::EmailChallenge>> challenges;
    std::unordered_map<std::string, std::shared_ptr<vh::rbac::role::Vault>> vault_roles;
    std::unordered_map<std::string, uint32_t> recipients_by_hash;
    std::unordered_map<std::string, std::shared_ptr<vh::rbac::role::Vault>> recipient_roles;
    std::vector<std::shared_ptr<vh::share::AuditEvent>> audits;
    uint32_t next_link{100};
    uint32_t next_session{200};
    uint32_t next_challenge{300};
    uint32_t next_recipient{400};

    std::shared_ptr<vh::share::Link> createLink(const std::shared_ptr<vh::share::Link>& link) override {
        auto stored = std::make_shared<vh::share::Link>(*link);
        if (stored->id.empty()) stored->id = uuidFor(next_link++);
        stored->created_at = kNow;
        stored->updated_at = kNow;
        links[stored->id] = stored;
        link_by_lookup[stored->token_lookup_id] = stored->id;
        return stored;
    }

    std::shared_ptr<vh::share::Link> getLink(const std::string& id) override {
        if (!links.contains(id)) return nullptr;
        return links.at(id);
    }

    std::shared_ptr<vh::share::Link> getLinkByLookupId(const std::string& lookupId) override {
        if (!link_by_lookup.contains(lookupId)) return nullptr;
        return getLink(link_by_lookup.at(lookupId));
    }

    std::vector<std::shared_ptr<vh::share::Link>> listLinksForUser(
        uint32_t userId,
        const db::model::ListQueryParams&
    ) override {
        std::vector<std::shared_ptr<vh::share::Link>> out;
        for (auto& [_, link] : links)
            if (link->created_by == userId) out.push_back(link);
        return out;
    }

    std::vector<std::shared_ptr<vh::share::Link>> listLinksForVault(
        uint32_t vaultId,
        const db::model::ListQueryParams&
    ) override {
        std::vector<std::shared_ptr<vh::share::Link>> out;
        for (auto& [_, link] : links)
            if (link->vault_id == vaultId) out.push_back(link);
        return out;
    }

    std::shared_ptr<vh::share::Link> updateLink(const std::shared_ptr<vh::share::Link>& link) override {
        links[link->id] = link;
        link_by_lookup[link->token_lookup_id] = link->id;
        return link;
    }

    void revokeLink(const std::string& id, uint32_t revokedBy) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        link->revoked_at = kNow;
        link->revoked_by = revokedBy;
    }

    void rotateLinkToken(
        const std::string& id,
        const std::string& lookupId,
        const std::vector<uint8_t>& tokenHash,
        uint32_t updatedBy
    ) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        link_by_lookup.erase(link->token_lookup_id);
        link->token_lookup_id = lookupId;
        link->token_hash = tokenHash;
        link->updated_by = updatedBy;
        link_by_lookup[lookupId] = id;
    }

    void touchLinkAccess(const std::string& id) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        ++link->access_count;
        link->last_accessed_at = kNow;
    }

    void incrementDownload(const std::string& id) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        ++link->download_count;
    }

    void upsertVaultRoleForShare(
        const std::string& shareId,
        uint32_t,
        const std::shared_ptr<vh::rbac::role::Vault>& role
    ) override {
        vault_roles[shareId] = std::make_shared<vh::rbac::role::Vault>(*role);
    }

    std::shared_ptr<vh::rbac::role::Vault> getVaultRoleForShare(const std::string& shareId) override {
        if (!vault_roles.contains(shareId)) return nullptr;
        return vault_roles.at(shareId);
    }

    std::shared_ptr<vh::rbac::role::Vault> getRecipientVaultRoleForShare(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        const auto key = shareId + ":" + db::encoding::to_hex_bytea(emailHash);
        if (!recipient_roles.contains(key)) return nullptr;
        return recipient_roles.at(key);
    }

    uint32_t upsertValidatedRecipient(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        const auto key = shareId + ":" + db::encoding::to_hex_bytea(emailHash);
        if (recipients_by_hash.contains(key)) return recipients_by_hash.at(key);
        const auto id = next_recipient++;
        recipients_by_hash[key] = id;
        return id;
    }

    void upsertRecipientVaultRoleAssignment(
        const std::string& shareId,
        const uint32_t vaultId,
        const uint32_t recipientId,
        const uint32_t roleId,
        const std::vector<rbac::permission::Override>& overrides
    ) override {
        auto role = getVaultRoleTemplate(roleId);
        auto assigned = std::make_shared<vh::rbac::role::Vault>(*role);
        assigned->assign(recipientId, "actor", vaultId);
        assigned->fs.overrides = overrides;
        for (const auto& [key, id] : recipients_by_hash)
            if (id == recipientId && key.starts_with(shareId + ":"))
                recipient_roles[key] = assigned;
    }

    std::shared_ptr<vh::share::Session> createSession(
        const std::shared_ptr<vh::share::Session>& session
    ) override {
        auto stored = std::make_shared<vh::share::Session>(*session);
        if (stored->id.empty()) stored->id = uuidFor(next_session++);
        stored->created_at = kNow;
        stored->last_seen_at = kNow;
        sessions[stored->id] = stored;
        session_by_lookup[stored->session_token_lookup_id] = stored->id;
        return stored;
    }

    std::shared_ptr<vh::share::Session> getSession(const std::string& id) override {
        if (!sessions.contains(id)) return nullptr;
        return sessions.at(id);
    }

    std::shared_ptr<vh::share::Session> getSessionByLookupId(const std::string& lookupId) override {
        if (!session_by_lookup.contains(lookupId)) return nullptr;
        return getSession(session_by_lookup.at(lookupId));
    }

    void verifySession(const std::string& sessionId, const std::vector<uint8_t>& emailHash) override {
        auto session = getSession(sessionId);
        if (!session) throw std::runtime_error("missing session");
        session->email_hash = emailHash;
        session->verified_at = kNow;
    }

    void touchSession(const std::string& sessionId) override {
        auto session = getSession(sessionId);
        if (!session) throw std::runtime_error("missing session");
        session->last_seen_at = kNow + 1;
    }

    void revokeSession(const std::string& sessionId) override {
        auto session = getSession(sessionId);
        if (!session) throw std::runtime_error("missing session");
        session->revoked_at = kNow;
    }

    void revokeSessionsForShare(const std::string& shareId) override {
        for (auto& [_, session] : sessions)
            if (session->share_id == shareId && !session->revoked_at) session->revoked_at = kNow;
    }

    std::shared_ptr<vh::share::EmailChallenge> createEmailChallenge(
        const std::shared_ptr<vh::share::EmailChallenge>& challenge
    ) override {
        auto stored = std::make_shared<vh::share::EmailChallenge>(*challenge);
        if (stored->id.empty()) stored->id = uuidFor(next_challenge++);
        stored->created_at = kNow;
        challenges[stored->id] = stored;
        return stored;
    }

    std::shared_ptr<vh::share::EmailChallenge> getEmailChallenge(const std::string& id) override {
        if (!challenges.contains(id)) return nullptr;
        return challenges.at(id);
    }

    std::shared_ptr<vh::share::EmailChallenge> getActiveEmailChallenge(
        const std::string& shareId,
        const std::vector<uint8_t>& emailHash
    ) override {
        std::shared_ptr<vh::share::EmailChallenge> best;
        for (auto& [_, challenge] : challenges) {
            if (challenge->share_id != shareId) continue;
            if (challenge->email_hash != emailHash) continue;
            if (!challenge->canAttempt(kNow)) continue;
            if (!best || challenge->created_at > best->created_at) best = challenge;
        }
        return best;
    }

    void recordEmailChallengeAttempt(const std::string& challengeId) override {
        auto challenge = getEmailChallenge(challengeId);
        if (!challenge) throw std::runtime_error("missing challenge");
        ++challenge->attempts;
    }

    void consumeEmailChallenge(const std::string& challengeId) override {
        auto challenge = getEmailChallenge(challengeId);
        if (!challenge) throw std::runtime_error("missing challenge");
        if (challenge->consumed_at) throw std::runtime_error("challenge consumed");
        challenge->consumed_at = kNow;
    }

    void appendAuditEvent(const std::shared_ptr<vh::share::AuditEvent>& event) override {
        audits.push_back(std::make_shared<vh::share::AuditEvent>(*event));
    }
};

vh::share::Link makeLink(const vh::share::AccessMode mode = vh::share::AccessMode::Public) {
    vh::share::Link link;
    link.vault_id = 42;
    link.root_entry_id = 77;
    link.root_path = "/reports";
    link.target_type = vh::share::TargetType::Directory;
    link.link_type = vh::share::LinkType::Access;
    link.access_mode = mode;
    link.allowed_ops = vh::share::bit(vh::share::Operation::Metadata) |
                       vh::share::bit(vh::share::Operation::List) |
                       vh::share::bit(vh::share::Operation::Download);
    link.expires_at = kNow + 3600;
    return link;
}

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

std::shared_ptr<Session> publicSession() {
    auto session = std::make_shared<Session>(std::make_shared<Router>());
    session->ipAddress = "127.0.0.1";
    session->userAgent = "ws-share-test";
    return session;
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

std::shared_ptr<Session> humanSession() {
    auto session = publicSession();
    vh::identities::UserState userState;
    userState.name = "human";
    auto user = vh::identities::User::detached(9, std::move(userState));
    session->user = user;
    return session;
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

class WsShareSessionsTest : public ::testing::Test {
protected:
    std::shared_ptr<FakeStore> store;
    std::shared_ptr<FakeAuthorizer> authorizer;
    std::shared_ptr<vh::share::Manager> manager;
    std::shared_ptr<identities::User> user;
    std::shared_ptr<vh::auth::session::Manager> oldSessionManager;

    void SetUp() override {
        vh::share::Token::setPepperForTesting(std::vector<uint8_t>(32, 0x61));
        oldSessionManager = vh::runtime::Deps::get().sessionManager;
        vh::runtime::Deps::get().sessionManager = std::make_shared<vh::auth::session::Manager>();
        store = std::make_shared<FakeStore>();
        authorizer = std::make_shared<FakeAuthorizer>();
        vh::share::ManagerOptions options;
        options.clock = [] { return kNow; };
        options.session_ttl_seconds = 600;
        options.challenge_ttl_seconds = 300;
        options.challenge_max_attempts = 3;
        options.challenge_code_generator = [] { return std::string(kChallengeCode); };
        manager = std::make_shared<vh::share::Manager>(store, authorizer, options);
        Sessions::setManagerFactoryForTesting([this] { return manager; });

        vh::identities::UserState userState;
        userState.name = "share-owner";
        user = vh::identities::User::detached(7, std::move(userState));
    }

    void TearDown() override {
        Sessions::resetManagerFactoryForTesting();
        vh::runtime::Deps::get().sessionManager = oldSessionManager;
        vh::share::Token::clearPepperForTesting();
    }

    vh::share::CreateLinkResult create(const vh::share::AccessMode mode = vh::share::AccessMode::Public) {
        std::vector<vh::share::RecipientRoleAssignmentRequest> recipients;
        if (mode == vh::share::AccessMode::EmailValidated) {
            recipients.push_back({
                .email = "email@example.com",
                .role = vh::share::RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::Reader().name}
            });
            recipients.push_back({
                .email = "recipient@example.com",
                .role = vh::share::RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::Reader().name}
            });
        }
        return manager->createLink(rbac::Actor::human(user), {
            .link = makeLink(mode),
            .public_role = mode == vh::share::AccessMode::EmailValidated
                               ? vh::share::RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::ImplicitDeny().name}
                               : vh::share::RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::Reader().name},
            .recipients = std::move(recipients)
        });
    }

    std::string wrongSecret(const std::string& token) const {
        auto parsed = vh::share::Token::parse(token);
        parsed.secret.back() = parsed.secret.back() == 'a' ? 'b' : 'a';
        return (parsed.kind == vh::share::TokenKind::PublicShare ? "vhs_" : "vhss_") +
               parsed.lookup_id + "_" + parsed.secret;
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

TEST_F(WsShareSessionsTest, PublicSessionRejectsMalformedWrongOrInactiveTokens) {
    const auto created = create();

    EXPECT_THROW(Sessions::open({{"public_token", "not-a-share-token"}}, publicSession()), std::exception);
    EXPECT_THROW(Sessions::open({{"public_token", wrongSecret(created.public_token)}}, publicSession()), std::runtime_error);

    created.link->expires_at = kNow - 1;
    EXPECT_THROW(Sessions::open({{"public_token", created.public_token}}, publicSession()), std::runtime_error);

    created.link->expires_at = kNow + 3600;
    created.link->revoked_at = kNow;
    EXPECT_THROW(Sessions::open({{"public_token", created.public_token}}, publicSession()), std::runtime_error);

    created.link->revoked_at.reset();
    created.link->disabled_at = kNow;
    EXPECT_THROW(Sessions::open({{"public_token", created.public_token}}, publicSession()), std::runtime_error);
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
