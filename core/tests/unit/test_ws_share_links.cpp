#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "protocols/ws/handler/Settings.hpp"
#include "protocols/ws/handler/share/Links.hpp"
#include "share/AuditEvent.hpp"
#include "share/EmailChallenge.hpp"
#include "share/Manager.hpp"
#include "share/Token.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <format>
#include <memory>
#include <stdexcept>
#include <unordered_map>

namespace vh::protocols::ws::handler::share::test_links {
constexpr std::time_t kNow = 1'800'000'000;

std::string uuidFor(const uint32_t value) {
    return std::format("00000000-0000-4000-8000-{:012d}", value);
}

class FakeAuthorizer final : public vh::share::ShareAuthorizer {
public:
    bool allow_create{true};
    bool allow_update{true};
    bool allow_manage{true};
    bool allow_list_vault{true};

    vh::share::AuthorizationDecision canCreateLink(
        const rbac::Actor& actor,
        const vh::share::Link&
    ) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_create, allow_create ? "allowed" : "create_denied"};
    }

    vh::share::AuthorizationDecision canUpdateLink(
        const rbac::Actor& actor,
        const vh::share::Link&,
        const vh::share::Link&
    ) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_update, allow_update ? "allowed" : "update_denied"};
    }

    vh::share::AuthorizationDecision canManageLink(
        const rbac::Actor& actor,
        const vh::share::Link&
    ) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_manage, allow_manage ? "allowed" : "manage_denied"};
    }

    vh::share::AuthorizationDecision canListVaultLinks(const rbac::Actor& actor, uint32_t) const override {
        if (!actor.isHuman()) return {false, "not_human"};
        return {allow_list_vault, allow_list_vault ? "allowed" : "list_denied"};
    }
};

class FakeStore final : public vh::share::ShareStore {
public:
    std::unordered_map<std::string, std::shared_ptr<vh::share::Link>> links;
    std::unordered_map<std::string, std::string> link_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<vh::share::Session>> sessions;
    std::unordered_map<std::string, std::string> session_by_lookup;
    std::unordered_map<std::string, std::shared_ptr<vh::share::EmailChallenge>> challenges;
    std::vector<std::shared_ptr<vh::share::AuditEvent>> audits;
    uint32_t next_link{100};

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
        auto stored = std::make_shared<vh::share::Link>(*link);
        stored->updated_at = kNow + 1;
        links[stored->id] = stored;
        link_by_lookup[stored->token_lookup_id] = stored->id;
        return stored;
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

    void touchLinkAccess(const std::string&) override {}

    void incrementDownload(const std::string& id) override {
        auto link = getLink(id);
        if (!link) throw std::runtime_error("missing link");
        ++link->download_count;
    }

    std::shared_ptr<vh::share::Session> createSession(
        const std::shared_ptr<vh::share::Session>& session
    ) override {
        auto stored = std::make_shared<vh::share::Session>(*session);
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

    void verifySession(const std::string&, const std::vector<uint8_t>&) override {}
    void touchSession(const std::string&) override {}
    void revokeSession(const std::string&) override {}
    void revokeSessionsForShare(const std::string& shareId) override {
        for (auto& [_, session] : sessions)
            if (session->share_id == shareId && !session->revoked_at) session->revoked_at = kNow;
    }

    std::shared_ptr<vh::share::EmailChallenge> createEmailChallenge(
        const std::shared_ptr<vh::share::EmailChallenge>& challenge
    ) override {
        challenges[challenge->id] = challenge;
        return challenge;
    }

    std::shared_ptr<vh::share::EmailChallenge> getEmailChallenge(const std::string& id) override {
        if (!challenges.contains(id)) return nullptr;
        return challenges.at(id);
    }

    std::shared_ptr<vh::share::EmailChallenge> getActiveEmailChallenge(
        const std::string&,
        const std::vector<uint8_t>&
    ) override {
        return nullptr;
    }

    void recordEmailChallengeAttempt(const std::string&) override {}
    void consumeEmailChallenge(const std::string&) override {}
    void appendAuditEvent(const std::shared_ptr<vh::share::AuditEvent>& event) override {
        audits.push_back(std::make_shared<vh::share::AuditEvent>(*event));
    }
};

nlohmann::json createPayload() {
    return {
        {"vault_id", 42},
        {"root_entry_id", 77},
        {"root_path", "/reports"},
        {"target_type", "directory"},
        {"link_type", "access"},
        {"access_mode", "public"},
        {"allowed_ops", nlohmann::json::array({"metadata", "list", "download"})},
        {"name", "Reports"},
        {"public_label", "Shared reports"},
        {"expires_at", "2027-01-15T00:00:00Z"},
        {"duplicate_policy", "reject"},
        {"metadata", {{"case", "ws"}}}
    };
}

std::shared_ptr<Session> authenticatedSession() {
    auto session = std::make_shared<Session>(std::make_shared<Router>());
    vh::identities::UserState userState;
    userState.name = "owner";
    auto user = vh::identities::User::detached(9, std::move(userState));
    session->user = user;
    return session;
}

class WsShareLinksTest : public ::testing::Test {
protected:
    std::shared_ptr<FakeStore> store;
    std::shared_ptr<FakeAuthorizer> authorizer;
    std::shared_ptr<vh::share::Manager> manager;
    std::shared_ptr<Session> session;

    void SetUp() override {
        vh::share::Token::setPepperForTesting(std::vector<uint8_t>(32, 0x61));
        store = std::make_shared<FakeStore>();
        authorizer = std::make_shared<FakeAuthorizer>();
        vh::share::ManagerOptions options;
        options.clock = [] { return kNow; };
        manager = std::make_shared<vh::share::Manager>(store, authorizer, options);
        Links::setManagerFactoryForTesting([this] { return manager; });
        session = authenticatedSession();
    }

    void TearDown() override {
        Links::resetManagerFactoryForTesting();
        vh::share::Token::clearPepperForTesting();
    }

    nlohmann::json createShare() {
        return Links::create(createPayload(), session);
    }
};

void expectNoSecretFields(const nlohmann::json& value) {
    EXPECT_FALSE(value.contains("token_lookup_id"));
    EXPECT_FALSE(value.contains("token_hash"));
    EXPECT_FALSE(value.contains("public_token"));
    EXPECT_FALSE(value.contains("session_token"));
    EXPECT_FALSE(value.contains("verification_code"));
    EXPECT_FALSE(value.contains("email"));
}

TEST_F(WsShareLinksTest, AuthenticatedCreateSucceedsWhenAuthorizerAllows) {
    const auto response = createShare();

    ASSERT_TRUE(response.contains("share"));
    EXPECT_TRUE(response.at("public_token").get<std::string>().starts_with("vhs_"));
    EXPECT_EQ(
        "/share/" + response.at("public_token").get<std::string>(),
        response.at("public_url_path").get<std::string>()
    );
    EXPECT_EQ(9u, response.at("share").at("created_by").get<uint32_t>());
    expectNoSecretFields(response.at("share"));
}

TEST_F(WsShareLinksTest, UnauthenticatedManagementCommandsDenied) {
    auto unauthenticated = std::make_shared<Session>(std::make_shared<Router>());
    const auto created = createShare();
    const auto id = created.at("share").at("id").get<std::string>();

    EXPECT_THROW(Links::create(createPayload(), unauthenticated), std::runtime_error);
    EXPECT_THROW(Links::get({{"id", id}}, unauthenticated), std::runtime_error);
    EXPECT_THROW(Links::list(nlohmann::json::object(), unauthenticated), std::runtime_error);
    EXPECT_THROW(Links::update({{"id", id}, {"name", "x"}}, unauthenticated), std::runtime_error);
    EXPECT_THROW(Links::revoke({{"id", id}}, unauthenticated), std::runtime_error);
    EXPECT_THROW(Links::rotateToken({{"id", id}}, unauthenticated), std::runtime_error);
}

TEST_F(WsShareLinksTest, GetAndListDoNotLeakSecrets) {
    const auto created = createShare();
    const auto id = created.at("share").at("id").get<std::string>();

    const auto got = Links::get({{"id", id}}, session);
    expectNoSecretFields(got.at("share"));
    EXPECT_FALSE(got.contains("public_token"));

    const auto listed = Links::list(nlohmann::json::object(), session);
    ASSERT_EQ(1u, listed.at("shares").size());
    expectNoSecretFields(listed.at("shares").at(0));
    EXPECT_FALSE(listed.contains("public_token"));
}

TEST_F(WsShareLinksTest, CreateAndRotateReturnOneTimePublicTokenOnly) {
    const auto created = createShare();
    const auto id = created.at("share").at("id").get<std::string>();
    const auto originalToken = created.at("public_token").get<std::string>();
    const auto originalLookup = store->getLink(id)->token_lookup_id;

    const auto rotated = Links::rotateToken({{"id", id}}, session);

    EXPECT_TRUE(rotated.at("public_token").get<std::string>().starts_with("vhs_"));
    EXPECT_NE(originalToken, rotated.at("public_token").get<std::string>());
    EXPECT_NE(originalLookup, store->getLink(id)->token_lookup_id);
    expectNoSecretFields(rotated.at("share"));
}

TEST_F(WsShareLinksTest, UpdateAndRevokeCallManagerAndReturnSafeResponses) {
    const auto created = createShare();
    const auto id = created.at("share").at("id").get<std::string>();

    const auto updated = Links::update(
        {
            {"id", id},
            {"name", "Updated reports"},
            {"allowed_ops", nlohmann::json::array({"metadata", "download"})}
        },
        session
    );
    EXPECT_EQ("Updated reports", updated.at("share").at("name").get<std::string>());
    EXPECT_EQ(vh::share::bit(vh::share::Operation::Metadata) | vh::share::bit(vh::share::Operation::Download),
              store->getLink(id)->allowed_ops);
    expectNoSecretFields(updated.at("share"));

    const auto revoked = Links::revoke({{"id", id}}, session);
    EXPECT_TRUE(revoked.at("revoked").get<bool>());
    EXPECT_TRUE(store->getLink(id)->revoked_at.has_value());
}

TEST_F(WsShareLinksTest, MalformedRequestsRejected) {
    EXPECT_THROW(Links::create({{"vault_id", 42}}, session), vh::ops::Invalid);

    const auto created = createShare();
    const auto id = created.at("share").at("id").get<std::string>();
    EXPECT_THROW(Links::update({{"id", id}, {"vault_id", 99}}, session), vh::ops::Invalid);
    EXPECT_THROW(Links::list({{"direction", "sideways"}}, session), vh::ops::Invalid);
}

TEST_F(WsShareLinksTest, ManagerErrorsSurfaceAsHandlerErrors) {
    authorizer->allow_create = false;
    EXPECT_THROW(Links::create(createPayload(), session), vh::ops::Denied);

    authorizer->allow_create = true;
    const auto created = createShare();
    const auto id = created.at("share").at("id").get<std::string>();
    authorizer->allow_manage = false;
    EXPECT_THROW(Links::get({{"id", id}}, session), std::runtime_error);
    EXPECT_THROW(Links::rotateToken({{"id", id}}, session), std::runtime_error);
}

// sharing.* (#164) through the ws surface: refused with the stable "denied" code the console maps, and the policy
// the console reads to hide what it can't create.
TEST_F(WsShareLinksTest, CreateIsRefusedWithDeniedWhileSharingOrItsKindIsOff) {
    const auto previous = vh::config::Registry::get();
    struct Restore {
        const vh::config::Config& cfg;
        ~Restore() { vh::config::Registry::set(cfg); }
    } restore{previous};

    auto cfg = previous;
    cfg.sharing.enabled = false;
    vh::config::Registry::set(cfg);
    try {
        (void)createShare();
        ADD_FAILURE() << "share.link.create succeeded with sharing.enabled = false";
    } catch (...) {
        const auto reply = vh::protocols::ws::core::describeCurrentError();
        EXPECT_EQ(reply.data, (nlohmann::json{{"code", "denied"}}));
        EXPECT_EQ(reply.message, "Sharing is disabled on this server");
    }
    auto policy = vh::protocols::ws::handler::Settings::policy(session).at("policy");
    EXPECT_FALSE(policy.at("sharing").at("enabled").get<bool>());

    cfg.sharing.enabled = true;
    cfg.sharing.enable_anonymous = false;
    vh::config::Registry::set(cfg);
    EXPECT_THROW((void)createShare(), vh::ops::Denied);
    EXPECT_TRUE(store->links.empty());
    policy = vh::protocols::ws::handler::Settings::policy(session).at("policy");
    EXPECT_FALSE(policy.at("sharing").at("enable_anonymous").get<bool>());
    EXPECT_TRUE(policy.at("sharing").at("enable_email_validated").get<bool>());
    EXPECT_EQ(policy.at("vaults").at("s3").at("default_remote_sync_strategy"), cfg.vaults.s3.default_remote_sync_strategy);

    vh::config::Registry::set(previous);
    EXPECT_NO_THROW((void)createShare());
}

}
