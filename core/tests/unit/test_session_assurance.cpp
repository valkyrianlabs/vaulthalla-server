// Session assurance on refresh tokens (#354, MFA design note section 5.3): a refresh row is written once, at sign-in,
// with aal / amr / auth_time; a socket signs in once; a planted cookie never becomes the victim's session; the MFA
// policy hook is checked against the row on every use; and a user can list and revoke their own sessions, with
// revocation immediate on the socket and the HTTP lanes.
#include "../helpers/identities.hpp"
#include "auth/Manager.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Assurance.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Manager.hpp"
#include "auth/session/Validator.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Sessions.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "rbac/PolicyEpoch.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <chrono>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>

namespace vh::auth::session::test_assurance {

using json = nlohmann::json;
using SessionPtr = std::shared_ptr<protocols::ws::Session>;

constexpr auto kPassword = "Session-Assurance-Pass-1";

// ── DB-free ─────────────────────────────────────────────────────────────────────────────────────────────────────────

TEST(SessionAssurance, WithoutAPolicyEveryRealLevelSatisfiesItAndInstallingOneBumpsTheEpoch) {
    const auto user = test::identities::detachedUser(31, "assurance-user");
    model::RefreshToken row;
    EXPECT_EQ(row.aal, 1);
    EXPECT_EQ(row.amr, std::vector<std::string>{"pwd"});
    EXPECT_TRUE(assurance::satisfied(*user, row));
    row.aal = 2;
    EXPECT_TRUE(assurance::satisfied(*user, row));
    row.aal = 3;
    EXPECT_FALSE(assurance::satisfied(*user, row)) << "not a level";

    const auto before = rbac::policyEpoch();
    assurance::setPolicy([](const identities::User&, const model::RefreshToken& r) { return r.aal >= 2; });
    EXPECT_GT(rbac::policyEpoch(), before) << "the 30 s validation cache must not hide a policy change";
    row.aal = 1;
    EXPECT_FALSE(assurance::satisfied(*user, row));
    row.aal = 2;
    EXPECT_TRUE(assurance::satisfied(*user, row));

    const auto installed = rbac::policyEpoch();
    assurance::setPolicy(nullptr);
    EXPECT_GT(rbac::policyEpoch(), installed);
    row.aal = 1;
    EXPECT_TRUE(assurance::satisfied(*user, row));

    const auto factors = rbac::policyEpoch();
    assurance::policyChanged();
    EXPECT_GT(rbac::policyEpoch(), factors);

    EXPECT_EQ(assurance::password().aal, 1);
    EXPECT_EQ(assurance::password().amr, std::vector<std::string>{"pwd"});
}

TEST(SessionAssurance, SessionIdsAreOpaqueStableAndDistinct) {
    const std::string jti = "6f1c2b0e-7d7a-4f53-9d43-1a2b3c4d5e6f";
    const auto id = ops::sessions::handle(jti);
    EXPECT_EQ(id.size(), 32u);
    EXPECT_EQ(id.find_first_not_of("0123456789abcdef"), std::string::npos);
    EXPECT_EQ(id, ops::sessions::handle(jti));
    EXPECT_NE(id, ops::sessions::handle("6f1c2b0e-7d7a-4f53-9d43-1a2b3c4d5e70"));
    EXPECT_EQ(id.find("6f1c2b0e"), std::string::npos) << "the id must not carry the jti";
}

// ── DB-backed ───────────────────────────────────────────────────────────────────────────────────────────────────────

class SessionAssuranceDb : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> alice, mallory;
    std::shared_ptr<Manager> previousSessions;
    std::shared_ptr<auth::Manager> previousAuth;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_session_assurance] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::seed::init_tables_if_not_exists();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::initPermissions();
        seed::initRoles();

        const auto role = db::query::rbac::role::Admin::get("unprivileged");
        if (!role) throw std::runtime_error("Missing unprivileged role");
        alice = identities::manager().user(
            test::identities::createUser("assurance_alice", role, std::nullopt, crypto::hash::password(kPassword))->id);
        mallory = identities::manager().user(
            test::identities::createUser("assurance_mallory", role, std::nullopt, crypto::hash::password(kPassword))->id);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        Issuer::setJwtSecretForTesting("session-assurance-test-secret");
        previousSessions = runtime::Deps::get().sessionManager;
        previousAuth = runtime::Deps::get().authManager;
        runtime::Deps::get().sessionManager = std::make_shared<Manager>();
        runtime::Deps::get().authManager = std::make_shared<auth::Manager>();
        // Every test starts with no signed-in sessions.
        db::query::auth::RefreshToken::revokeAll(alice->id);
        db::query::auth::RefreshToken::revokeAll(mallory->id);
    }

    void TearDown() override {
        if (skipTests) return;
        assurance::setPolicy(nullptr);
        runtime::Deps::get().sessionManager = previousSessions;
        runtime::Deps::get().authManager = previousAuth;
        Issuer::clearJwtSecretForTesting();
    }

    static Manager& sessions() { return *runtime::Deps::get().sessionManager; }

    // A websocket as the server accepts it: the handshake hands the session its refresh cookie (none: empty), and
    // tryRehydrate either signs it in from the cookie's row or gives it a fresh refresh token (Session::hydrateFromRequest).
    static SessionPtr connect(const std::string& cookie = {}, const std::string& agent = "assurance-browser",
                              const std::string& ip = "127.0.0.1") {
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->ipAddress = ip;
        session->userAgent = agent;
        model::RefreshToken::addToSession(session, cookie);
        sessions().tryRehydrate(session);
        return session;
    }

    static std::string cookieOf(const SessionPtr& s) { return s->tokens->refreshToken->rawToken; }
    static std::string jtiOf(const SessionPtr& s) { return s->tokens->refreshToken->jti; }

    static void login(const std::shared_ptr<identities::User>& user, const SessionPtr& s) {
        runtime::Deps::get().authManager->loginUser(user->name(), kPassword, s);
    }

    // An HTTP lane (preview/download/upload): the cookie alone.
    static bool httpLaneAccepts(const std::string& cookie) {
        try {
            const auto session = sessions().validateRawRefreshToken(cookie);
            return session && session->user;
        } catch (const std::exception&) {
            return false;
        }
    }

    static int rowsFor(const std::shared_ptr<identities::User>& user) {
        return static_cast<int>(db::query::auth::RefreshToken::list(user->id).size());
    }
};

TEST_F(SessionAssuranceDb, APasswordSignInWritesItsRowOnceWithAal1) {
    const auto socket = connect();
    ASSERT_FALSE(socket->user);
    ASSERT_FALSE(db::query::auth::RefreshToken::get(jtiOf(socket))) << "an anonymous socket's token has no row";

    const auto before = std::chrono::system_clock::now() - std::chrono::seconds(2);
    login(alice, socket);
    const auto row = db::query::auth::RefreshToken::get(jtiOf(socket));
    ASSERT_TRUE(row);
    EXPECT_EQ(row->userId, alice->id);
    EXPECT_EQ(row->aal, 1);
    EXPECT_EQ(row->amr, std::vector<std::string>{"pwd"});
    EXPECT_GE(row->authTime, before);
    EXPECT_LE(row->authTime, std::chrono::system_clock::now() + std::chrono::seconds(2));
    EXPECT_TRUE(httpLaneAccepts(cookieOf(socket)));
}

// A jti is never promoted twice: not on the same socket, and not by another socket holding the same token.
TEST_F(SessionAssuranceDb, AJtiIsNeverPromotedTwice) {
    const auto socket = connect();
    login(alice, socket);
    const auto jti = jtiOf(socket);
    EXPECT_THROW(sessions().promote(socket), std::runtime_error);

    const auto copy = connect();
    copy->tokens->refreshToken = std::make_shared<model::RefreshToken>(*socket->tokens->refreshToken);
    copy->setAuthenticatedUser(mallory);
    EXPECT_THROW(sessions().promote(copy, {.aal = 2, .amr = {"pwd", "otp"}}), std::runtime_error);

    const auto row = db::query::auth::RefreshToken::get(jti);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->userId, alice->id) << "the row was rewritten";
    EXPECT_EQ(row->aal, 1);
}

// Session fixation, case 1: a valid refresh JWT with no row. The attacker's own handshake minted it; it is planted in
// the victim's browser. The victim's socket never adopts it (a fresh token is minted for the victim's handshake), so
// after the victim signs in the attacker's copy is still nobody's session.
TEST_F(SessionAssuranceDb, APlantedCookieWithNoRowNeverBecomesTheVictimsSession) {
    const auto attacker = connect();
    const auto planted = cookieOf(attacker);
    ASSERT_FALSE(attacker->user);

    const auto victim = connect(planted);  // same address and browser string: the planted JWT's subject matches
    ASSERT_FALSE(victim->user);
    EXPECT_NE(cookieOf(victim), planted) << "the victim's socket adopted a cookie minted at another handshake";
    EXPECT_NE(jtiOf(victim), jtiOf(attacker));

    login(alice, victim);
    ASSERT_TRUE(victim->user);
    EXPECT_FALSE(db::query::auth::RefreshToken::get(jtiOf(attacker))) << "the planted jti got a row";

    EXPECT_FALSE(httpLaneAccepts(planted)) << "the planted cookie opens the victim's files";
    EXPECT_FALSE(sessions().validate(attacker, "")) << "the attacker's socket became signed in";
    EXPECT_FALSE(attacker->user);
    const auto reconnect = connect(planted);
    EXPECT_FALSE(reconnect->user) << "a new socket with the planted cookie is signed in";
    EXPECT_TRUE(httpLaneAccepts(cookieOf(victim)));
}

// Session fixation, case 2: a valid cookie whose row belongs to another account (the attacker signed in and planted
// the cookie). The victim's socket comes up as the attacker's session, and signing in on it is refused: the victim's
// credentials are never attached to the attacker's row.
TEST_F(SessionAssuranceDb, APlantedCookieOfAnotherAccountIsNeverPromotedToTheVictim) {
    const auto attacker = connect();
    login(mallory, attacker);
    const auto planted = cookieOf(attacker);

    const auto victim = connect(planted);
    ASSERT_TRUE(victim->user);
    EXPECT_EQ(victim->user->id, mallory->id);

    const auto aliceRows = rowsFor(alice);
    try {
        login(alice, victim);
        ADD_FAILURE() << "a second sign-in on a signed-in socket";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, auth::Manager::kAlreadySignedIn);
    }
    EXPECT_EQ(victim->user->id, mallory->id);
    EXPECT_EQ(rowsFor(alice), aliceRows) << "the victim got a row from the planted cookie";
    const auto row = db::query::auth::RefreshToken::get(jtiOf(attacker));
    ASSERT_TRUE(row);
    EXPECT_EQ(row->userId, mallory->id);

    // The attacker's cookie stays the attacker's account, never alice's.
    const auto lane = sessions().validateRawRefreshToken(planted);
    ASSERT_TRUE(lane && lane->user);
    EXPECT_EQ(lane->user->id, mallory->id);
}

// The ws login handler answers already_signed_in on a signed-in socket (the router lets auth.login through).
TEST_F(SessionAssuranceDb, TheLoginCommandOnASignedInSocketAnswersAlreadySignedIn) {
    const auto socket = connect();
    login(alice, socket);
    try {
        (void)protocols::ws::handler::Auth::login(json{{"name", mallory->name()}, {"password", kPassword}}, socket);
        ADD_FAILURE() << "signed in twice";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "already_signed_in");
    }
    EXPECT_EQ(socket->user->id, alice->id);
}

TEST_F(SessionAssuranceDb, SessionsAreListedWithOpaqueIdsAndRevokedAtOnce) {
    const auto laptop = connect({}, "laptop-browser", "10.0.0.20");
    login(alice, laptop);
    const auto phone = connect({}, "phone-browser", "10.0.0.21");
    login(alice, phone);
    const auto other = connect({}, "mallory-browser", "10.0.0.30");
    login(mallory, other);

    const auto listed = protocols::ws::handler::Auth::listSessions(laptop).at("sessions");
    ASSERT_EQ(listed.size(), 2u) << listed.dump();
    std::string phoneId;
    int current = 0;
    for (const auto& s : listed) {
        EXPECT_EQ(s.at("aal"), 1);
        EXPECT_EQ(s.at("amr"), json::array({"pwd"}));
        EXPECT_GT(s.at("auth_time").get<int64_t>(), 0);
        const auto id = s.at("id").get<std::string>();
        EXPECT_NE(id, jtiOf(laptop));
        EXPECT_NE(id, jtiOf(phone));
        EXPECT_EQ(listed.dump().find(jtiOf(phone)), std::string::npos) << "a jti reached the client";
        if (s.at("current").get<bool>()) {
            ++current;
            EXPECT_EQ(s.at("user_agent"), "laptop-browser");
        } else {
            phoneId = id;
            EXPECT_EQ(s.at("ip_address"), "10.0.0.21");
        }
    }
    EXPECT_EQ(current, 1);
    ASSERT_FALSE(phoneId.empty());

    // Warm the HTTP lane's 30 s validation cache, then revoke: the very next request is refused.
    ASSERT_TRUE(httpLaneAccepts(cookieOf(phone)));
    const auto phoneCookie = cookieOf(phone);
    const auto phoneToken = phone->tokens->accessToken->rawToken;

    // Another account can't see or revoke it.
    EXPECT_THROW((void)ops::sessions::revoke(mallory, jtiOf(other), {.id = phoneId}, other), ops::NotFound);
    EXPECT_TRUE(httpLaneAccepts(phoneCookie));

    const auto revoked = protocols::ws::handler::Auth::revokeSessions(json{{"id", phoneId}}, laptop);
    EXPECT_EQ(revoked.at("revoked"), 1);
    EXPECT_FALSE(httpLaneAccepts(phoneCookie)) << "the HTTP lanes still accept a revoked session";
    EXPECT_TRUE(phone->closing()) << "the revoked session's socket is still open";
    EXPECT_FALSE(sessions().validate(phone, phoneToken));
    EXPECT_FALSE(connect(phoneCookie, "phone-browser", "10.0.0.21")->user) << "the cookie signs in again";
    const auto row = db::query::auth::RefreshToken::get(jtiOf(phone));
    ASSERT_TRUE(row);
    EXPECT_TRUE(row->revoked);

    EXPECT_TRUE(httpLaneAccepts(cookieOf(laptop))) << "revoking another session ended this one";
    EXPECT_FALSE(laptop->closing());
    EXPECT_TRUE(httpLaneAccepts(cookieOf(other))) << "another account's session ended";

    // A revoked or unknown id is not_found; exactly one of id and all_others.
    EXPECT_THROW((void)ops::sessions::revoke(alice, jtiOf(laptop), {.id = phoneId}, laptop), ops::NotFound);
    EXPECT_THROW((void)ops::sessions::revoke(alice, jtiOf(laptop), {.id = std::string(32, '0')}, laptop), ops::NotFound);
    EXPECT_THROW((void)ops::sessions::revoke(alice, jtiOf(laptop), {}, laptop), ops::Invalid);
    EXPECT_THROW((void)ops::sessions::revoke(alice, jtiOf(laptop), {.id = phoneId, .all_others = true}, laptop),
                 ops::Invalid);
}

TEST_F(SessionAssuranceDb, SigningOutEveryOtherSessionKeepsTheCurrentOne) {
    const auto here = connect({}, "here-browser");
    login(alice, here);
    const auto there = connect({}, "there-browser");
    login(alice, there);
    const auto elsewhere = connect({}, "elsewhere-browser");
    login(alice, elsewhere);
    ASSERT_TRUE(httpLaneAccepts(cookieOf(there)));

    const auto revoked = protocols::ws::handler::Auth::revokeSessions(json{{"all_others", true}}, here);
    EXPECT_EQ(revoked.at("revoked"), 2);
    EXPECT_FALSE(httpLaneAccepts(cookieOf(there)));
    EXPECT_FALSE(httpLaneAccepts(cookieOf(elsewhere)));
    EXPECT_TRUE(there->closing() && elsewhere->closing());
    EXPECT_TRUE(httpLaneAccepts(cookieOf(here)));
    EXPECT_FALSE(here->closing());

    const auto listed = protocols::ws::handler::Auth::listSessions(here).at("sessions");
    ASSERT_EQ(listed.size(), 1u);
    EXPECT_TRUE(listed[0].at("current").get<bool>());

    // Revoking the current session signs it out too (its socket closes after the reply).
    const auto id = listed[0].at("id").get<std::string>();
    EXPECT_EQ(protocols::ws::handler::Auth::revokeSessions(json{{"id", id}}, here).at("revoked"), 1);
    EXPECT_FALSE(httpLaneAccepts(cookieOf(here)));
    EXPECT_TRUE(here->closing());
}

// The MFA policy hook, against the stored row, on every use: a live socket, the HTTP lanes (cached and not), a
// reconnect with the cookie, auth.refresh. A refused row is revoked for good.
TEST_F(SessionAssuranceDb, TheMfaPolicyIsCheckedAgainstTheRowOnEveryUse) {
    const auto socket = connect();
    login(alice, socket);
    const auto cookie = cookieOf(socket);
    const auto token = socket->tokens->accessToken->rawToken;
    ASSERT_TRUE(httpLaneAccepts(cookie));  // warms the 30 s cache
    ASSERT_TRUE(sessions().validate(socket, token));

    const auto bystander = connect();
    login(mallory, bystander);

    const auto aliceId = alice->id;
    assurance::setPolicy([aliceId](const identities::User& user, const model::RefreshToken& row) {
        return user.id != aliceId || row.aal >= 2;
    });

    EXPECT_FALSE(httpLaneAccepts(cookie)) << "the validation cache hid the policy change";
    const auto row = db::query::auth::RefreshToken::get(jtiOf(socket));
    ASSERT_TRUE(row);
    EXPECT_TRUE(row->revoked) << "a row below the policy must be revoked, not just refused";
    EXPECT_FALSE(sessions().validate(socket, token));
    EXPECT_FALSE(connect(cookie)->user);
    EXPECT_TRUE(httpLaneAccepts(cookieOf(bystander))) << "the policy refused a session it allows";

    // Lifting the policy doesn't bring a revoked session back.
    assurance::setPolicy(nullptr);
    EXPECT_FALSE(httpLaneAccepts(cookie));
}

TEST_F(SessionAssuranceDb, TheMfaPolicyRefusesARowOnRehydrationAndAuthRefresh) {
    const auto socket = connect();
    login(alice, socket);
    const auto cookie = cookieOf(socket);

    const auto aliceId = alice->id;
    assurance::setPolicy([aliceId](const identities::User& user, const model::RefreshToken& row) {
        return user.id != aliceId || row.aal >= 2;
    });

    // A fresh daemon (no live session): the lanes rehydrate from the stored row alone.
    Manager restarted;
    EXPECT_THROW((void)restarted.validateRawRefreshToken(cookie), std::exception);
    EXPECT_TRUE(db::query::auth::RefreshToken::get(jtiOf(socket))->revoked);
    EXPECT_THROW(sessions().renewAccessToken(socket, socket->tokens->accessToken->rawToken), std::exception);
}

}
