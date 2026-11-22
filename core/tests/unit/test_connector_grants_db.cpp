// vh-test-tier: db-only
// Remote-connector grants (design/core/mcp-remote-signin.md, build step 2), DB-backed:
//   - a grant's first refresh token is issued once (a second redemption of its code gets none), and only its digest
//     is stored;
//   - rotation: each refresh answers a new token and retires the old; a retired token presented again ends the grant
//     (refresh_reuse, audited, the user notified), except once, within the lost-response allowance, while its
//     successor was never used; concurrent refreshes of one token leave exactly one live token;
//   - another client's refresh changes nothing; expiry (absolute and idle) ends the grant;
//   - every end condition: the user not a grantor, deactivated, a code never redeemed, sign out everywhere (sessions
//     revoked), a recovery-code sign-in's revocation, the switch off; and the audit events of each.
#include "../helpers/db_suite.hpp"
#include "../helpers/web_session.hpp"
#include "audit/Trail.hpp"
#include "auth/Manager.hpp"
#include "connector/Grants.hpp"
#include "db/Transactions.hpp"
#include "db/query/connector/Connector.hpp"
#include "identities/Manager.hpp"
#include "notifications/AccountSecurity.hpp"
#include "ops/Users.hpp"
#include "runtime/Deps.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <atomic>
#include <map>
#include <string>
#include <thread>
#include <variant>
#include <vector>

namespace vh::test_connector_grants_db {

namespace q = db::query::connector;
using connector::RefreshRefusal;
using connector::Refreshed;
using connector::Revocation;
using vh::test::web::tag;

class ConnectorGrantsDb : public vh::test::db::Suite {
protected:
    std::vector<notifications::account::Notice> notices;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("connector_grants")) return;
        audit::Trail::instance()->resetForTesting();
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        notifications::account::setSinkForTesting([this](const notifications::account::Notice& n) { notices.push_back(n); });
    }

    void TearDown() override {
        if (skipTests) return;
        notifications::account::setSinkForTesting({});
    }

    static q::ClientRow client() {
        return q::Clients::insert({.client_id = "vhc_test_" + tag(), .kind = "registered", .name = "Test client",
                                   .redirect_uris = {"https://client.example/cb"}, .created_by = superUser->id});
    }

    static connector::Grant grantFor(const identities::User& user, const connector::Scope scope = connector::Scope::Read) {
        const auto c = client();
        return connector::create(user, {.client_row = c.id, .client_id = c.client_id, .client_name = c.name,
                                        .redirect_uri = c.redirect_uris.front(), .scope = scope,
                                        .resource = "https://vh.example/mcp", .approved_via = "webauthn",
                                        .client_host = "client.example", .redirect_host = "client.example"});
    }

    static std::string refreshOk(const std::string& token, const std::string& clientId, bool* allowance = nullptr) {
        auto r = connector::refresh(token, clientId);
        if (!std::holds_alternative<Refreshed>(r)) {
            ADD_FAILURE() << "refresh refused: " << static_cast<int>(std::get<RefreshRefusal>(r));
            return {};
        }
        if (allowance) *allowance = std::get<Refreshed>(r).allowance;
        return std::get<Refreshed>(r).refresh_token;
    }

    static RefreshRefusal refused(const std::string& token, const std::string& clientId) {
        auto r = connector::refresh(token, clientId);
        if (std::holds_alternative<Refreshed>(r)) {
            ADD_FAILURE() << "refresh was accepted";
            return RefreshRefusal::Unknown;
        }
        return std::get<RefreshRefusal>(r);
    }

    static std::string reasonOf(const std::string& grantId) {
        const auto g = connector::get(grantId);
        return g && g->row.revoked_reason ? *g->row.revoked_reason : std::string("live");
    }

    static void sql(const std::string& statement, const std::string& grantId) {
        db::Transactions::exec("connector test sql", [&](pqxx::work& txn) { txn.exec(statement, pqxx::params{grantId}); });
    }

    static std::vector<std::string> auditFor(const std::string& grantId) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("connector audit", [&](pqxx::work& txn) {
            std::vector<std::string> out;
            for (const auto& r : txn.exec("SELECT action, COALESCE(details::jsonb->>'reason', details::jsonb->>'from', '') "
                                          "FROM audit_event WHERE action LIKE 'connector.%' "
                                          "AND details::jsonb->>'grant_id' = $1 ORDER BY seq",
                                          pqxx::params{grantId})) {
                auto a = r[0].as<std::string>();
                if (const auto extra = r[1].as<std::string>(); !extra.empty()) a += "/" + extra;
                out.push_back(a);
            }
            return out;
        });
    }

    static int liveTokens(const std::string& grantId) {
        return db::Transactions::exec("connector live tokens", [&](pqxx::work& txn) {
            return txn.exec("SELECT count(*) FROM connector_refresh_tokens WHERE grant_id = $1::uuid AND used_at IS NULL "
                            "AND revoked_at IS NULL",
                            pqxx::params{grantId})
                .one_field_ref()
                .as<int>();
        });
    }

    static std::shared_ptr<identities::User> ordinaryUser(const bool active = true) {
        return ops::users::create(superUser, {.name = "conn_" + tag(), .role = "unprivileged", .is_active = active}).user;
    }
};

TEST_F(ConnectorGrantsDb, TheFirstRefreshTokenIsIssuedOnceAndOnlyItsDigestIsStored) {
    const auto g = grantFor(*superUser);
    EXPECT_EQ(g.scope, connector::Scope::Read);
    EXPECT_FALSE(g.row.redeemed);
    const auto lifetime = std::chrono::duration_cast<std::chrono::seconds>(connector::kGrantLifetime).count();
    EXPECT_NEAR(static_cast<double>(g.row.expires_at - g.row.created_at), static_cast<double>(lifetime), 5.0);

    const auto token = connector::issueFirstRefreshToken(g.row.id);
    ASSERT_TRUE(token);
    EXPECT_TRUE(token->starts_with(connector::kRefreshTokenPrefix));
    EXPECT_GE(token->size(), 6u + 43u);
    EXPECT_FALSE(connector::issueFirstRefreshToken(g.row.id)) << "a second redemption mints nothing";

    const auto stored = db::Transactions::exec("connector stored", [&](pqxx::work& txn) {
        return txn.exec("SELECT token_digest FROM connector_refresh_tokens WHERE grant_id = $1::uuid", pqxx::params{g.row.id})
            .one_field_ref()
            .as<std::string>();
    });
    EXPECT_EQ(stored, connector::digestOf(*token));
    EXPECT_EQ(stored.find(token->substr(6)), std::string::npos);
    EXPECT_TRUE(connector::get(g.row.id)->row.redeemed);
    EXPECT_EQ(auditFor(g.row.id), (std::vector<std::string>{"connector.grant.create", "connector.token.issue/code"}));
}

TEST_F(ConnectorGrantsDb, RotationRetiresEachTokenAndReuseEndsTheGrant) {
    const auto g = grantFor(*superUser, connector::Scope::Write);
    const auto t0 = *connector::issueFirstRefreshToken(g.row.id);
    const auto t1 = refreshOk(t0, g.row.client_id);
    const auto t2 = refreshOk(t1, g.row.client_id);
    EXPECT_NE(t1, t0);
    EXPECT_NE(t2, t1);
    EXPECT_EQ(liveTokens(g.row.id), 1);

    // t1 was used a minute ago: outside the allowance, presenting it again is reuse.
    sql("UPDATE connector_refresh_tokens SET used_at = used_at - interval '1 minute' WHERE grant_id = $1::uuid "
        "AND used_at IS NOT NULL", g.row.id);
    EXPECT_EQ(refused(t1, g.row.client_id), RefreshRefusal::Reused);
    EXPECT_EQ(reasonOf(g.row.id), "refresh_reuse");
    EXPECT_EQ(refused(t2, g.row.client_id), RefreshRefusal::Ended) << "the whole family ends";
    EXPECT_EQ(liveTokens(g.row.id), 0);
    ASSERT_EQ(notices.size(), 1u);
    EXPECT_EQ(notices.front().event, "connector.grant.reuse");
    EXPECT_EQ(notices.front().user_id, superUser->id);
    EXPECT_EQ(auditFor(g.row.id),
              (std::vector<std::string>{"connector.grant.create", "connector.token.issue/code", "connector.token.issue/refresh",
                                        "connector.token.issue/refresh", "connector.grant.revoke/refresh_reuse"}));
}

TEST_F(ConnectorGrantsDb, TheLostResponseAllowanceReplacesAnUnusedSuccessorOnce) {
    const auto g = grantFor(*superUser);
    const auto t0 = *connector::issueFirstRefreshToken(g.row.id);
    const auto t1 = refreshOk(t0, g.row.client_id);  // its answer "lost"
    bool allowance = false;
    const auto t2 = refreshOk(t0, g.row.client_id, &allowance);
    EXPECT_TRUE(allowance);
    EXPECT_EQ(liveTokens(g.row.id), 1);
    const auto t3 = refreshOk(t2, g.row.client_id);
    EXPECT_FALSE(t3.empty());
    // The replaced successor was never delivered; whoever presents it now holds a copy: reuse.
    EXPECT_EQ(refused(t1, g.row.client_id), RefreshRefusal::Reused);
    EXPECT_EQ(reasonOf(g.row.id), "refresh_reuse");

    // No allowance once the successor was used.
    const auto h = grantFor(*superUser);
    const auto u0 = *connector::issueFirstRefreshToken(h.row.id);
    const auto u1 = refreshOk(u0, h.row.client_id);
    (void)refreshOk(u1, h.row.client_id);
    EXPECT_EQ(refused(u0, h.row.client_id), RefreshRefusal::Reused);
}

TEST_F(ConnectorGrantsDb, ConcurrentRefreshesOfOneTokenLeaveExactlyOneLiveToken) {
    const auto g = grantFor(*superUser);
    const auto t0 = *connector::issueFirstRefreshToken(g.row.id);
    constexpr int kThreads = 8;
    std::atomic<int> rotated{0}, allowed{0}, other{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kThreads; ++i)
        threads.emplace_back([&] {
            const auto r = connector::refresh(t0, g.row.client_id);
            if (const auto* ok = std::get_if<Refreshed>(&r)) (ok->allowance ? allowed : rotated)++;
            else other++;
        });
    for (auto& t : threads) t.join();
    EXPECT_EQ(rotated.load(), 1);
    EXPECT_EQ(allowed.load(), kThreads - 1) << "each later one within the allowance replaces the unused successor";
    EXPECT_EQ(other.load(), 0);
    EXPECT_EQ(liveTokens(g.row.id), 1);
    EXPECT_EQ(reasonOf(g.row.id), "live");
}

TEST_F(ConnectorGrantsDb, AnotherClientsRefreshChangesNothingAndExpiryEndsTheGrant) {
    const auto g = grantFor(*superUser);
    const auto t0 = *connector::issueFirstRefreshToken(g.row.id);
    EXPECT_EQ(refused(t0, "vhc_someone_else"), RefreshRefusal::WrongClient);
    EXPECT_EQ(refused("vh_rt_not-a-token", g.row.client_id), RefreshRefusal::Unknown);
    EXPECT_EQ(refused("not even the prefix", g.row.client_id), RefreshRefusal::Unknown);
    const auto t1 = refreshOk(t0, g.row.client_id);

    // Idle: the current token expired.
    sql("UPDATE connector_refresh_tokens SET expires_at = NOW() - interval '1 second', issued_at = NOW() - interval '31 days' "
        "WHERE grant_id = $1::uuid AND used_at IS NULL", g.row.id);
    EXPECT_EQ(refused(t1, g.row.client_id), RefreshRefusal::Expired);
    EXPECT_EQ(reasonOf(g.row.id), "expired");

    // Absolute: the grant's lifetime is over.
    const auto h = grantFor(*superUser);
    const auto u0 = *connector::issueFirstRefreshToken(h.row.id);
    sql("UPDATE connector_grants SET created_at = NOW() - interval '91 days', expires_at = NOW() - interval '1 day' "
        "WHERE id = $1::uuid", h.row.id);
    EXPECT_EQ(refused(u0, h.row.client_id), RefreshRefusal::Expired);
    EXPECT_EQ(reasonOf(h.row.id), "expired");
    EXPECT_FALSE(connector::issueFirstRefreshToken(h.row.id));
}

TEST_F(ConnectorGrantsDb, EveryEndCondition) {
    // The grantor policy: super admins only (decided 2026-11-22).
    EXPECT_TRUE(connector::mayGrant(*superUser));
    const auto plain = ordinaryUser();
    EXPECT_FALSE(connector::mayGrant(*plain));

    const auto keeps = grantFor(*superUser);
    (void)connector::issueFirstRefreshToken(keeps.row.id);
    const auto notGrantor = grantFor(*plain);  // made below the ops layer: the policy check is ops::connector's
    (void)connector::issueFirstRefreshToken(notGrantor.row.id);
    // Deactivated out of band (no session revocation ran): the reconciliation finds it.
    const auto inactive = ordinaryUser();
    const auto leaving = grantFor(*inactive);
    (void)connector::issueFirstRefreshToken(leaving.row.id);
    db::Transactions::exec("connector deactivate", [&](pqxx::work& txn) {
        txn.exec("UPDATE users SET is_active = FALSE WHERE id = $1", pqxx::params{inactive->id});
    });
    (void)identities::manager().reconcile();
    // Deactivated through ops: its sessions end, and its connected apps with them.
    const auto deactivated = ordinaryUser();
    const auto ended = grantFor(*deactivated);
    (void)ops::users::update(superUser, {.id = deactivated->id, .is_active = false});
    EXPECT_EQ(reasonOf(ended.row.id), "sessions_revoked");
    const auto unredeemed = grantFor(*superUser);
    sql("UPDATE connector_grants SET created_at = NOW() - interval '11 minutes' WHERE id = $1::uuid", unredeemed.row.id);
    const auto fresh = grantFor(*superUser);  // not redeemed yet, but within its ten minutes

    EXPECT_GE(connector::reconcile(), 3u);
    EXPECT_EQ(reasonOf(keeps.row.id), "live");
    EXPECT_EQ(reasonOf(fresh.row.id), "live");
    EXPECT_EQ(reasonOf(notGrantor.row.id), "grantor_policy");
    EXPECT_EQ(reasonOf(leaving.row.id), "user_inactive");
    EXPECT_EQ(reasonOf(unredeemed.row.id), "expired");
    EXPECT_EQ(connector::reconcile(), 0u) << "nothing left to end";

    // Sign out everywhere ends the user's connected apps too.
    runtime::Deps::get().authManager->revokeSessions(superUser->id);
    EXPECT_EQ(reasonOf(keeps.row.id), "sessions_revoked");
    EXPECT_EQ(reasonOf(fresh.row.id), "sessions_revoked");

    // A recovery-code sign-in's revocation, and the switch going off, by name.
    const auto a = grantFor(*superUser);
    EXPECT_EQ(connector::revokeForUser(superUser->id, Revocation::MfaRecovery, {.id = superUser->id, .name = "admin"}), 1u);
    EXPECT_EQ(reasonOf(a.row.id), "mfa_recovery");
    const auto b = grantFor(*superUser);
    const auto c = grantFor(*superUser);
    EXPECT_EQ(connector::revokeAll(Revocation::SwitchOff, {.id = superUser->id, .name = "admin"}), 2u);
    EXPECT_EQ(reasonOf(b.row.id), "switch_off");
    EXPECT_EQ(reasonOf(c.row.id), "switch_off");
    EXPECT_FALSE(connector::revoke(c.row.id, Revocation::Manual)) << "revocation is final";
    EXPECT_EQ(auditFor(c.row.id), (std::vector<std::string>{"connector.grant.create", "connector.grant.revoke/switch_off"}));
    EXPECT_EQ(auditFor(notGrantor.row.id).back(), "connector.grant.revoke/grantor_policy");

    for (const auto r : {Revocation::Manual, Revocation::UserInactive, Revocation::GrantorPolicy, Revocation::RefreshReuse,
                         Revocation::CodeReuse, Revocation::SwitchOff, Revocation::Expired, Revocation::ClientRemoved,
                         Revocation::SessionsRevoked, Revocation::MfaRecovery})
        EXPECT_EQ(connector::parseRevocation(connector::to_string(r)), r);
}

TEST_F(ConnectorGrantsDb, ClientsAndSettingsRoundTrip) {
    const auto before = q::Settings::get();
    EXPECT_FALSE(before.enabled);
    EXPECT_EQ(before.max_scope, "write");
    EXPECT_FALSE(before.dcr_enabled);
    EXPECT_TRUE(before.client_hosts.empty());
    q::Settings::put({.enabled = true, .public_origin = "https://vh.example", .max_scope = "read", .dcr_enabled = false,
                      .client_hosts = {"claude.ai", "chatgpt.com"}},
                     superUser->id);
    const auto after = q::Settings::get();
    EXPECT_TRUE(after.enabled);
    EXPECT_EQ(after.public_origin, "https://vh.example");
    EXPECT_EQ(after.max_scope, "read");
    EXPECT_EQ(after.client_hosts, (std::vector<std::string>{"claude.ai", "chatgpt.com"}));
    EXPECT_EQ(after.changed_by, superUser->id);
    q::Settings::put({}, superUser->id);
    EXPECT_FALSE(q::Settings::get().enabled);

    const auto c = q::Clients::insert({.client_id = "vhc_rt_" + tag(), .kind = "registered", .name = "Laptop",
                                       .redirect_uris = {"http://127.0.0.1/callback", "https://a.example/cb?x=\"1\""}});
    const auto back = q::Clients::byClientId(c.client_id);
    ASSERT_TRUE(back);
    EXPECT_EQ(back->redirect_uris, c.redirect_uris) << "quotes and commas survive the array";
    EXPECT_TRUE(back->live());
    EXPECT_TRUE(q::Clients::disable(c.id));
    EXPECT_FALSE(q::Clients::disable(c.id));
    EXPECT_FALSE(q::Clients::byId("not-a-uuid"));
    EXPECT_FALSE(q::Grants::byId("not-a-uuid"));
}

}
