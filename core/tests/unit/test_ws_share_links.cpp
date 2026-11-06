#include "../helpers/share_fakes.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "protocols/ws/handler/Settings.hpp"
#include "protocols/ws/handler/share/Links.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <memory>
#include <stdexcept>

namespace vh::protocols::ws::handler::share::test_links {

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

class WsShareLinksTest : public vh::test::shares::Harness {
protected:
    std::shared_ptr<Session> session = vh::test::shares::humanSession();

    void SetUp() override {
        startManager();
        Links::setManagerFactoryForTesting([this] { return manager; });
    }

    void TearDown() override {
        Links::resetManagerFactoryForTesting();
        Harness::TearDown();
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
        "/share#" + response.at("public_token").get<std::string>(),
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
