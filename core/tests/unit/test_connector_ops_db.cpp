// vh-test-tier: db-only
// Remote connectors' operations (design/core/mcp-remote-signin.md, build step 3), DB-backed, through the real ws
// handlers under the router's step-up scope and through the CLI router as the host:
//   - only super admins see or change anything; an agent is refused even below the MCP exclusion;
//   - switching on takes a connector.trust step-up bound to the exact origin (the host is exempt); bad origins are
//     refused; switching off ends every grant;
//   - the policy: narrowing never asks, widening asks with a target naming the new policy, and lowering the widest
//     scope ends the grants above it;
//   - registered clients: the step-up binds the name and URIs, bad redirect URIs are refused, removing one ends its
//     grants;
//   - grants: each user lists and revokes their own, never another's; super admins every one;
//   - the audit events of each change.
#include "../helpers/db_suite.hpp"
#include "../helpers/web_session.hpp"
#include "audit/Trail.hpp"
#include "connector/Grants.hpp"
#include "connector/Urls.hpp"
#include "db/Transactions.hpp"
#include "db/query/connector/Connector.hpp"
#include "ops/Connector.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/types.hpp"
#include "protocols/ws/handler/Connector.hpp"
#include "runtime/Deps.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <string>
#include <vector>

namespace vh::test_connector_ops_db {

using namespace vh::test::web;
namespace q = db::query::connector;
namespace h = protocols::ws::handler;
using auth::stepup::Family;

class ConnectorOpsDb : public vh::test::db::Suite {
protected:
    AuthRuntime auth_{{.level = auth::mfa::policy::Level::Optional, .webauthn = false}};

    static void SetUpTestSuite() {
        if (!setUpDbSuite("connector_ops")) return;
        audit::Trail::instance()->resetForTesting();
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        q::Settings::put({}, std::nullopt);
        (void)connector::revokeAll(connector::Revocation::Manual);
    }

    // A signed-in console socket of `user` (the canonical object, so its role counts).
    static SessionPtr console(const UserPtr& user) {
        auto s = detachedWebSession(user->id, 2, {"pwd", "hwk"});
        s->user = user;
        return s;
    }

    static void approve(const SessionPtr& s, const Answer& refused) {
        ASSERT_EQ(refused.code, "step_up_required") << refused.message;
        ASSERT_EQ(refused.data.at("family"), "connector.trust");
        s->stepUp().addGrant(grantFor(s, Family::ConnectorTrust, refused.data.at("target").get<std::string>()));
    }

    static connector::Grant grantOf(const UserPtr& user, const connector::Scope scope) {
        const auto c = q::Clients::insert({.client_id = "vhc_ops_" + tag(), .kind = "registered", .name = "App",
                                           .redirect_uris = {"https://app.example/cb"}});
        return connector::create(*user, {.client_row = c.id, .client_id = c.client_id, .client_name = c.name,
                                         .redirect_uri = "https://app.example/cb", .scope = scope,
                                         .resource = "https://vh.example.com/mcp", .approved_via = "webauthn"});
    }

    static std::string reasonOf(const connector::Grant& g) {
        const auto now = connector::get(g.row.id);
        return now && now->row.revoked_reason ? *now->row.revoked_reason : std::string("live");
    }

    static std::vector<std::string> auditActions(const int64_t afterSeq) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("connector ops audit", [&](pqxx::work& txn) {
            std::vector<std::string> out;
            for (const auto& r : txn.exec("SELECT action FROM audit_event WHERE action LIKE 'connector.%' AND seq > $1 "
                                          "AND action <> 'connector.grant.create' ORDER BY seq",
                                          pqxx::params{afterSeq}))
                out.push_back(r[0].as<std::string>());
            return out;
        });
    }

    static int64_t auditHead() {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("connector ops audit head", [](pqxx::work& txn) {
            return txn.exec("SELECT COALESCE(MAX(seq), 0) FROM audit_event").one_field_ref().as<int64_t>();
        });
    }

    static std::shared_ptr<protocols::shell::Router> cli() {
        static const auto r = [] {
            auto rt = std::make_shared<protocols::shell::Router>();
            protocols::shell::commands::registerAllCommands(rt);
            return rt;
        }();
        return r;
    }
};

TEST(ConnectorUrls, OriginsAndRedirectUris) {
    using connector::urls::canonicalOrigin;
    EXPECT_EQ(canonicalOrigin("https://Vault.Example.com"), "https://vault.example.com");
    EXPECT_EQ(canonicalOrigin("https://vault.example.com:443/"), "https://vault.example.com");
    for (const auto* bad : {"http://vault.example.com", "https://vault.example.com:8443", "https://10.0.0.5",
                            "https://[2001:db8::1]", "https://localhost", "https://vault.example.com/mcp",
                            "https://vault.example.com?x=1", "https://user@vault.example.com", "vault.example.com",
                            "https://vault..example.com", "https://-vault.example.com", "https://vault.example.123",
                            "https://väult.example.com", ""})
        EXPECT_FALSE(canonicalOrigin(bad)) << bad;

    using connector::urls::validRedirectUri;
    for (const auto* good : {"https://claude.ai/api/mcp/auth_callback", "http://127.0.0.1/callback",
                             "http://127.0.0.1:53682/callback", "http://[::1]:8080/cb", "http://localhost/cb",
                             "https://app.example.com:8443/cb?x=1"})
        EXPECT_TRUE(validRedirectUri(good)) << good;
    for (const auto* bad : {"http://app.example.com/cb", "https://app.example.com/cb#frag", "https://10.0.0.5/cb",
                            "https://user@app.example.com/cb", "custom://cb", "https://app.example.com/c b", ""})
        EXPECT_FALSE(validRedirectUri(bad)) << bad;
    EXPECT_TRUE(connector::urls::isLoopbackRedirect("http://127.0.0.1:5000/cb"));
    EXPECT_FALSE(connector::urls::isLoopbackRedirect("https://127.0.0.1/cb"));
    EXPECT_EQ(connector::urls::hostOf("https://Claude.AI/api/mcp/auth_callback"), "claude.ai");
    EXPECT_EQ(connector::urls::hostOf("vhc_abc"), "");
}

TEST_F(ConnectorOpsDb, OnlySuperAdminsAndNeverAnAgent) {
    const auto plain = newUser("unprivileged");
    const auto s = console(plain);
    for (const auto& fn : std::vector<std::function<json()>>{
             [&] { return h::Connector::status(json::object(), s); },
             [&] { return h::Connector::enable({{"url", "https://vh.example.com"}}, s); },
             [&] { return h::Connector::disable(json::object(), s); },
             [&] { return h::Connector::policyUpdate({{"max_scope", "read"}}, s); },
             [&] { return h::Connector::clientsList(json::object(), s); },
             [&] { return h::Connector::grantsList({{"all", true}}, s); },
             [&] { return h::Connector::grantsRevoke({{"all", true}}, s); }})
        EXPECT_EQ(run(s, fn).code, "denied");
    EXPECT_TRUE(run(s, [&] { return h::Connector::grantsList(json::object(), s); }).ok) << "anyone lists their own";

    EXPECT_THROW((void)ops::connector::enable(superUser, ops::connector::Channel::Agent, "https://vh.example.com"),
                 ops::Denied);
    EXPECT_THROW((void)ops::connector::addClient(superUser, ops::connector::Channel::Agent, "x", {"https://a.example/cb"}),
                 ops::Denied);
    EXPECT_FALSE(q::Settings::get().enabled);
}

TEST_F(ConnectorOpsDb, SwitchingOnTakesAStepUpBoundToTheOriginAndOffEndsEveryGrant) {
    const auto s = console(superUser);
    const auto head = auditHead();
    for (const auto* bad : {"http://vh.example.com", "https://10.0.0.5", "https://vh.example.com:8443", "https://vh.example.com/x"})
        EXPECT_EQ(run(s, [&] { return h::Connector::enable({{"url", bad}}, s); }).code, "invalid") << bad;

    const auto refused = run(s, [&] { return h::Connector::enable({{"url", "https://VH.example.com/"}}, s); });
    EXPECT_EQ(refused.data.at("target"), "connector.enable:https://vh.example.com");
    approve(s, refused);
    // A grant for one origin never switches it on at another.
    EXPECT_EQ(run(s, [&] { return h::Connector::enable({{"url", "https://other.example.com"}}, s); }).code,
              "step_up_required");
    const auto on = run(s, [&] { return h::Connector::enable({{"url", "https://vh.example.com"}}, s); });
    ASSERT_TRUE(on.ok) << on.message;
    EXPECT_TRUE(on.data.at("enabled").get<bool>());
    EXPECT_EQ(on.data.at("resource"), "https://vh.example.com/mcp");
    EXPECT_EQ(on.data.at("max_scope"), "write") << "decided 2026-11-22";
    EXPECT_FALSE(on.data.at("dcr_enabled").get<bool>());
    EXPECT_TRUE(run(s, [&] { return h::Connector::enable({{"url", "https://vh.example.com"}}, s); }).ok)
        << "already on there: no new step-up";

    const auto a = grantOf(superUser, connector::Scope::Read);
    const auto b = grantOf(superUser, connector::Scope::Write);
    const auto off = run(s, [&] { return h::Connector::disable(json::object(), s); });
    ASSERT_TRUE(off.ok) << off.message;
    EXPECT_FALSE(off.data.at("enabled").get<bool>());
    EXPECT_EQ(off.data.at("live_grants"), 0);
    EXPECT_EQ(reasonOf(a), "switch_off");
    EXPECT_EQ(reasonOf(b), "switch_off");
    EXPECT_EQ(auditActions(head), (std::vector<std::string>{"connector.enable", "connector.grant.revoke",
                                                            "connector.grant.revoke", "connector.disable"}));
}

TEST_F(ConnectorOpsDb, ThePolicyWidensOnlyWithAStepUpAndNarrowingEndsWhatItNoLongerAllows) {
    const auto s = console(superUser);
    const auto readGrant = grantOf(superUser, connector::Scope::Read);
    const auto writeGrant = grantOf(superUser, connector::Scope::Write);

    // Narrowing: no step-up; the write grant ends.
    const auto narrowed = run(s, [&] { return h::Connector::policyUpdate({{"max_scope", "read"}, {"client_hosts", {"claude.ai"}}}, s); });
    ASSERT_TRUE(narrowed.ok) << narrowed.message;
    EXPECT_EQ(narrowed.data.at("max_scope"), "read");
    EXPECT_EQ(narrowed.data.at("client_hosts"), json::array({"claude.ai"}));
    EXPECT_EQ(reasonOf(readGrant), "live");
    EXPECT_EQ(reasonOf(writeGrant), "grantor_policy");

    // Widening, each way, asks; the target names the policy it would set.
    for (const auto& change : {json{{"max_scope", "destructive"}}, json{{"dcr_enabled", true}},
                               json{{"client_hosts", json::array()}}, json{{"client_hosts", {"claude.ai", "evil.example"}}}}) {
        const auto refused = run(s, [&] { return h::Connector::policyUpdate(change, s); });
        EXPECT_EQ(refused.code, "step_up_required") << change.dump();
        if (refused.code == "step_up_required") {
            EXPECT_TRUE(refused.data.at("target").get<std::string>().starts_with("connector.policy:")) << change.dump();
        }
    }
    const auto refused = run(s, [&] { return h::Connector::policyUpdate({{"dcr_enabled", true}}, s); });
    approve(s, refused);
    const auto widened = run(s, [&] { return h::Connector::policyUpdate({{"dcr_enabled", true}}, s); });
    ASSERT_TRUE(widened.ok) << widened.message;
    EXPECT_TRUE(widened.data.at("dcr_enabled").get<bool>());
    EXPECT_EQ(run(s, [&] { return h::Connector::policyUpdate({{"max_scope", "admin"}}, s); }).code, "invalid");
    EXPECT_EQ(run(s, [&] { return h::Connector::policyUpdate({{"client_hosts", {"not a host"}}}, s); }).code, "invalid");
}

TEST_F(ConnectorOpsDb, RegisteredClientsBindTheirStepUpAndRemovingOneEndsItsGrants) {
    const auto s = console(superUser);
    const json add{{"name", "Codex on laptop"}, {"redirect_uris", {"http://127.0.0.1/callback"}}};
    for (const auto& bad : {json{{"name", "x"}, {"redirect_uris", {"http://app.example.com/cb"}}},
                            json{{"name", ""}, {"redirect_uris", {"https://a.example/cb"}}},
                            json{{"name", "x"}, {"redirect_uris", json::array()}}})
        EXPECT_EQ(run(s, [&] { return h::Connector::clientsAdd(bad, s); }).code, "invalid") << bad.dump();
    const auto refused = run(s, [&] { return h::Connector::clientsAdd(add, s); });
    approve(s, refused);
    const json other{{"name", "Codex on laptop"}, {"redirect_uris", {"http://127.0.0.1/other"}}};
    EXPECT_EQ(run(s, [&] { return h::Connector::clientsAdd(other, s); }).code, "step_up_required")
        << "the approval names the exact URIs";
    const auto added = run(s, [&] { return h::Connector::clientsAdd(add, s); });
    ASSERT_TRUE(added.ok) << added.message;
    EXPECT_EQ(added.data.at("kind"), "registered");
    EXPECT_TRUE(added.data.at("client_id").get<std::string>().starts_with("vhc_"));
    EXPECT_EQ(added.data.at("client_id").get<std::string>().size(), 26u);

    const auto clientRow = added.data.at("id").get<std::string>();
    const auto g = connector::create(*superUser, {.client_row = clientRow, .client_id = added.data.at("client_id").get<std::string>(),
                                                  .client_name = "Codex on laptop", .redirect_uri = "http://127.0.0.1/callback",
                                                  .scope = connector::Scope::Read, .resource = "https://vh.example.com/mcp",
                                                  .approved_via = "webauthn"});
    const auto removed = run(s, [&] { return h::Connector::clientsRemove({{"id", clientRow.substr(0, 8)}}, s); });
    ASSERT_TRUE(removed.ok) << removed.message;
    EXPECT_EQ(removed.data.at("grants_revoked"), 1);
    EXPECT_EQ(reasonOf(g), "client_removed");
    EXPECT_EQ(run(s, [&] { return h::Connector::clientsRemove({{"id", clientRow}}, s); }).code, "conflict");
    EXPECT_EQ(run(s, [&] { return h::Connector::clientsRemove({{"id", "ffffffff"}}, s); }).code, "not_found");
}

TEST_F(ConnectorOpsDb, EachUserSeesAndEndsOnlyTheirOwnGrants) {
    const auto plain = newUser("unprivileged");
    const auto mine = grantOf(plain, connector::Scope::Read);  // made below the policy, as an older grant might be
    const auto admins = grantOf(superUser, connector::Scope::Read);
    const auto p = console(plain);
    const auto list = run(p, [&] { return h::Connector::grantsList(json::object(), p); });
    ASSERT_TRUE(list.ok);
    ASSERT_EQ(list.data.at("grants").size(), 1u);
    EXPECT_EQ(list.data.at("grants")[0].at("id"), mine.row.id);
    EXPECT_EQ(run(p, [&] { return h::Connector::grantsRevoke({{"id", admins.row.id}}, p); }).code, "not_found");
    EXPECT_EQ(run(p, [&] { return h::Connector::grantsRevoke({{"all", true}, {"user_id", superUser->id}}, p); }).code,
              "denied");
    EXPECT_TRUE(run(p, [&] { return h::Connector::grantsRevoke({{"id", mine.row.id.substr(0, 8)}}, p); }).ok);
    EXPECT_EQ(reasonOf(mine), "manual");
    EXPECT_EQ(run(p, [&] { return h::Connector::grantsRevoke({{"id", mine.row.id}}, p); }).code, "conflict");

    const auto s = console(superUser);
    const auto all = run(s, [&] { return h::Connector::grantsList({{"all", true}}, s); });
    ASSERT_TRUE(all.ok);
    EXPECT_GE(all.data.at("grants").size(), 2u);
    const auto ended = run(s, [&] { return h::Connector::grantsRevoke({{"all", true}}, s); });
    ASSERT_TRUE(ended.ok) << ended.message;
    EXPECT_EQ(ended.data.at("revoked"), 1);
    EXPECT_EQ(reasonOf(admins), "manual");
}

TEST_F(ConnectorOpsDb, TheCliIsTheHostAndNeedsNoStepUp) {
    const auto r = cli();
    auto res = r->executeLine("connector enable --url https://cli.example.com", superUser, nullptr);
    EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
    EXPECT_EQ(q::Settings::get().public_origin, "https://cli.example.com");
    res = r->executeLine("connector status --json", superUser, nullptr);
    ASSERT_EQ(res.exit_code, 0) << res.stderr_text;
    EXPECT_TRUE(json::parse(res.stdout_text).at("enabled").get<bool>());
    res = r->executeLine("connector set --max-scope read --client-hosts claude.ai,chatgpt.com", superUser, nullptr);
    EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
    EXPECT_EQ(q::Settings::get().client_hosts, (std::vector<std::string>{"chatgpt.com", "claude.ai"}));
    res = r->executeLine("connector client add --name Laptop --redirect http://127.0.0.1/callback", superUser, nullptr);
    EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
    EXPECT_NE(res.stdout_text.find("vhc_"), std::string::npos);
    const auto g = grantOf(superUser, connector::Scope::Read);
    res = r->executeLine("connector list --json", superUser, nullptr);
    ASSERT_EQ(res.exit_code, 0) << res.stderr_text;
    EXPECT_FALSE(json::parse(res.stdout_text).at("grants").empty());
    res = r->executeLine("connector revoke " + g.row.id.substr(0, 8), superUser, nullptr);
    EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
    EXPECT_EQ(reasonOf(g), "manual");
    res = r->executeLine("connector disable", superUser, nullptr);
    EXPECT_EQ(res.exit_code, 0) << res.stderr_text;
    EXPECT_FALSE(q::Settings::get().enabled);

    // An agent's call reaching the CLI (vh mcp marks it) is refused by the operation itself.
    const protocols::shell::AgentCallScope agent;
    res = r->executeLine("connector enable --url https://cli.example.com", superUser, nullptr);
    EXPECT_NE(res.exit_code, 0);
    EXPECT_FALSE(q::Settings::get().enabled);
}

}
