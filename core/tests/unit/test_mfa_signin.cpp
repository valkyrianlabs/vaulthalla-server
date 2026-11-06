// vh-test-tier: db-only
// Pending-MFA sign-in and guided enrollment (#357; MFA design note sections 5.2, 5.3, 7.1, 7.2, 8.1 and 8.2).
//
// DB-free: the router's pending mode runs exactly its allowlist, and nothing else reaches a handler.
// DB-backed: the maintainer's regression list. A password alone never signs in an account that must have MFA or has
// a factor; during pending no session row exists, so auth.refresh, a reconnect, another socket and the HTTP lanes all
// refuse the cookie; completion writes exactly one row at aal 2 with the right amr; recovery codes are single use and
// land in RecoveryRestricted (other web sessions signed out); TOTP drift beyond one step and replays are refused; a
// pending sign-in ends when it expires, after 5 failures, on cancel and on sign-out; an aal 1 admin session from
// before the policy is refused at next use (D2); and a passkey (a software authenticator speaking real WebAuthn)
// enrolls and signs in, while one without user verification is refused.
#include "../helpers/identities.hpp"
#include "auth/Manager.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/Pending.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/mfa/SignIn.hpp"
#include "auth/mfa/Totp.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Assurance.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Manager.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Registry.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Peer.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/Refusal.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "protocols/ws/handler/Mfa.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "webauthn/Fixtures.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <chrono>
#include <cstdlib>
#include <format>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <unistd.h>

namespace vh::auth::mfa::test_signin {

using json = nlohmann::json;
using SessionPtr = std::shared_ptr<protocols::ws::Session>;
using Decision = protocols::ws::Router::CommandAuthDecision;
using protocols::ws::handler::Mfa;
namespace wa = vh::auth::webauthn;
namespace tw = vh::test_webauthn;

constexpr auto kPassword = "Mfa-SignIn-Pass-1";

// An answer as the ws client sees it: the data of a success, or {code, ...} of a refusal.
struct Answer {
    bool ok{false};
    json data{};
    std::string code{};
    std::string message{};
};

Answer call(const std::function<json()>& fn) {
    try {
        return {.ok = true, .data = fn()};
    } catch (...) {
        auto reply = protocols::ws::core::describeCurrentError();
        const auto code = reply.data.is_object() ? reply.data.value("code", std::string{}) : std::string{};
        return {.ok = false, .data = reply.data, .code = code,
                .message = reply.message};
    }
}

// ── DB-free: the router's pending mode ─────────────────────────────────────────────────────────────────────────────

SessionPtr pendingSocket(const PendingKind kind) {
    auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    s->mfa().setPending({.user_id = 7, .kind = kind, .methods = {"totp"},
                         .expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5)});
    return s;
}

constexpr std::array<std::string_view, 14> kOutsideTheAllowlist{
    "auth.login", "auth.refresh", "auth.isAuthenticated", "meta.hello", "meta.contract.get", "auth.users.list",
    "auth.mfa.status", "auth.mfa.recovery.generate", "auth.mfa.factor.rename", "auth.sessions.list",
    "storage.vault.list", "fs.list", "share.session.open", "device.pair.request"};

TEST(WsAuthRouting, APendingSessionRunsOnlyItsAllowlist) {
    const auto mfa = pendingSocket(PendingKind::Mfa);
    for (const auto cmd : kPendingCommands) EXPECT_EQ(Decision::Allow, protocols::ws::Router::classifyCommand(cmd, *mfa)) << cmd;
    for (const auto cmd : kPendingEnrollmentCommands)
        EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand(cmd, *mfa)) << cmd << " outside enrollment";
    for (const auto cmd : kOutsideTheAllowlist)
        EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand(cmd, *mfa)) << cmd;

    const auto enrolling = pendingSocket(PendingKind::Enrollment);
    for (const auto cmd : kPendingCommands)
        EXPECT_EQ(Decision::Allow, protocols::ws::Router::classifyCommand(cmd, *enrolling)) << cmd;
    for (const auto cmd : kPendingEnrollmentCommands)
        EXPECT_EQ(Decision::Allow, protocols::ws::Router::classifyCommand(cmd, *enrolling)) << cmd;
    for (const auto cmd : kOutsideTheAllowlist)
        EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand(cmd, *enrolling)) << cmd;

    // Once it ends the socket is anonymous again: the session lifecycle, and none of the pending commands.
    enrolling->mfa().clearPending();
    EXPECT_EQ(Decision::Allow, protocols::ws::Router::classifyCommand("auth.login", *enrolling));
    for (const auto cmd : kPendingEnrollmentCommands)
        EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand(cmd, *enrolling)) << cmd;
    EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand("auth.mfa.verify", *enrolling));
}

TEST(WsAuthRouting, ThePendingCommandsAreNeitherSessionLifecycleNorPublic) {
    const auto anonymous = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    const auto human = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    vh::identities::UserState state;
    state.name = "routing-human";
    human->user = vh::identities::User::detached(9, std::move(state));
    for (const auto& list : {std::vector<std::string_view>(kPendingCommands.begin(), kPendingCommands.end()),
                             std::vector<std::string_view>(kPendingEnrollmentCommands.begin(),
                                                           kPendingEnrollmentCommands.end())})
        for (const auto cmd : list) {
            if (cmd == "auth.logout") continue;  // the session lifecycle's own
            EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand(cmd, *anonymous)) << cmd;
            EXPECT_EQ(Decision::RequireHumanAuth, protocols::ws::Router::classifyCommand(cmd, *human)) << cmd;
        }
}

TEST(WsAuthRouting, APendingSessionReachesNoOtherHandler) {
    auto router = std::make_shared<protocols::ws::Router>();
    int reached = 0, allowed = 0;
    for (const auto cmd : kOutsideTheAllowlist)
        router->registerHandler(std::string(cmd), [&](json&&, const auto&) { ++reached; });
    router->registerHandler("auth.mfa.cancel", [&](json&&, const auto&) { ++allowed; });
    auto session = std::make_shared<protocols::ws::Session>(router);
    session->ipAddress = "203.0.113.9";
    session->close();
    session->mfa().setPending({.user_id = 7, .kind = PendingKind::Enrollment,
                               .expires_at = std::chrono::system_clock::now() + std::chrono::minutes(10)});
    for (const auto cmd : kOutsideTheAllowlist)
        router->routeMessage(json{{"command", std::string(cmd)}, {"payload", json::object()}}, session);
    router->routeMessage(json{{"command", "auth.mfa.cancel"}}, session);
    EXPECT_EQ(reached, 0) << "a command outside the pending allowlist ran";
    EXPECT_EQ(allowed, 1);
}

// ── DB-backed ──────────────────────────────────────────────────────────────────────────────────────────────────────

std::vector<uint8_t> fromBase32(const std::string& text) {
    static constexpr std::string_view kAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::vector<uint8_t> out;
    uint32_t buffer = 0;
    int bits = 0;
    for (const char c : text) {
        buffer = (buffer << 5) | static_cast<uint32_t>(kAlphabet.find(c));
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<uint8_t>((buffer >> bits) & 0xff));
        }
    }
    return out;
}

class MfaSignInDb : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::optional<std::string> sealing{};  // why TOTP / recovery codes can't run here
    inline static int counter = 0;
    std::shared_ptr<session::Manager> previousSessions;
    std::shared_ptr<auth::Manager> previousAuth;
    std::optional<config::Config> previousConfig;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_mfa_signin] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_mfa_signin_" + std::to_string(::getpid()));
        paths::backingPath = root / "backing";
        std::filesystem::create_directories(paths::backingPath);
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        try {
            (void)keys::seal();
            (void)keys::pepper();
        } catch (const std::exception& e) {
            sealing = e.what();
        }
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        session::Issuer::setJwtSecretForTesting("mfa-signin-test-secret");
        previousSessions = runtime::Deps::get().sessionManager;
        previousAuth = runtime::Deps::get().authManager;
        runtime::Deps::get().sessionManager = std::make_shared<session::Manager>();
        runtime::Deps::get().authManager = std::make_shared<auth::Manager>();
        previousConfig = config::Registry::get();
        auto cfg = *previousConfig;
        cfg.auth.webauthn.rp_id = std::string(tw::kRpId);
        cfg.auth.webauthn.origins = {std::string(tw::kOrigin)};
        config::Registry::set(cfg);
        policy::setLevel(policy::Level::Admins);
        policy::install();
        signin::resetAccountFailuresForTesting();
    }

    void TearDown() override {
        if (skipTests) return;
        session::assurance::setPolicy(nullptr);
        policy::setLevel(policy::Level::Admins);
        signin::resetAccountFailuresForTesting();
        if (previousConfig) config::Registry::set(*previousConfig);
        runtime::Deps::get().sessionManager = previousSessions;
        runtime::Deps::get().authManager = previousAuth;
        session::Issuer::clearJwtSecretForTesting();
    }

    void needSealing() const {
        if (sealing) GTEST_SKIP() << "mfa_seal / mfa_pepper can't be had on this host: " << *sealing;
    }

    static std::shared_ptr<identities::User> newUser(const std::string& role) {
        const auto r = db::query::rbac::role::Admin::get(role);
        if (!r) throw std::runtime_error("Missing role " + role);
        const auto name = "mfa_" + role + "_" + std::to_string(::getpid()) + "_" + std::to_string(++counter);
        return vh::identities::manager().user(
            test::identities::createUser(name, r, std::nullopt, crypto::hash::password(kPassword))->id);
    }

    static session::Manager& sessions() { return *runtime::Deps::get().sessionManager; }

    // A websocket as the server accepts it (see test_session_assurance.cpp).
    static SessionPtr connect(const std::string& cookie = {}, const std::string& ip = "127.0.0.1") {
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->ipAddress = ip;
        session->userAgent = "mfa-browser";
        model::RefreshToken::addToSession(session, cookie);
        sessions().tryRehydrate(session);
        return session;
    }

    static std::string cookieOf(const SessionPtr& s) { return s->tokens->refreshToken->rawToken; }
    static std::string jtiOf(const SessionPtr& s) { return s->tokens->refreshToken->jti; }

    static Answer login(const std::shared_ptr<identities::User>& user, const SessionPtr& s,
                        const std::string& password = kPassword) {
        return call([&] { return protocols::ws::handler::Auth::login(json{{"name", user->name()}, {"password", password}}, s); });
    }

    static bool httpLaneAccepts(const std::string& cookie) {
        try {
            const auto session = sessions().validateRawRefreshToken(cookie);
            return session && session->user;
        } catch (const std::exception&) {
            return false;
        }
    }

    static std::vector<std::shared_ptr<model::RefreshToken>> liveRows(const std::shared_ptr<identities::User>& user) {
        std::vector<std::shared_ptr<model::RefreshToken>> out;
        for (const auto& row : db::query::auth::RefreshToken::list(user->id))
            if (row && !row->revoked) out.push_back(row);
        return out;
    }

    // Everything that could turn the pending cookie into a session refuses it, because no row exists.
    void expectNoSessionFor(const SessionPtr& pending) {
        EXPECT_FALSE(pending->user) << "a pending socket has a user";
        EXPECT_FALSE(pending->tokens->accessToken && !pending->tokens->accessToken->rawToken.empty())
            << "a pending socket got an access token";
        EXPECT_FALSE(db::query::auth::RefreshToken::get(jtiOf(pending))) << "a pending socket's token has a row";
        EXPECT_FALSE(httpLaneAccepts(cookieOf(pending))) << "an HTTP lane accepted the pending cookie";
        EXPECT_THROW(sessions().renewAccessToken(pending, ""), std::exception) << "auth.refresh";
        EXPECT_FALSE(pending->user);
        EXPECT_FALSE(connect(cookieOf(pending))->user) << "a reconnect (or another tab) with the cookie";
        if (pending->mfa().pendingKind()) {
            EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand("auth.refresh", *pending));
            EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand("auth.isAuthenticated", *pending));
        }
    }

    struct Totp {
        uint32_t factor{};
        std::vector<uint8_t> seed{};
        std::vector<std::string> codes{};  // the recovery codes it came with
    };

    static std::string codeAt(const std::vector<uint8_t>& seed, const int64_t stepOffset = 0) {
        return totp::code(seed, totp::stepAt(std::chrono::system_clock::now()) + stepOffset);
    }

    // The guided first run with an authenticator app, to completion: pending enrollment, start, confirm, acknowledge.
    Totp enrollTotpAtSignIn(const std::shared_ptr<identities::User>& user, SessionPtr& socket) {
        socket = connect();
        const auto answer = login(user, socket);
        EXPECT_EQ(answer.code, "mfa_enrollment_required") << answer.message;
        const auto started = Mfa::totpStart(json{{"label", "Phone"}}, socket);
        Totp t{.factor = started.at("enrollment_id").get<uint32_t>(),
               .seed = fromBase32(started.at("secret_base32").get<std::string>())};
        const auto confirmed = Mfa::totpConfirm(json{{"enrollment_id", t.factor}, {"code", codeAt(t.seed)}}, socket);
        t.codes = confirmed.at("recovery_codes").at("codes").get<std::vector<std::string>>();
        const auto done = Mfa::acknowledgeRecovery(
            json{{"batch_id", confirmed.at("recovery_codes").at("batch_id")}}, socket);
        EXPECT_EQ(done.at("aal"), 2);
        return t;
    }

    // The TOTP step the last sign-in spent is used: wait for the next one before signing in with a code again.
    static void nextStep() {
        const auto now = std::chrono::system_clock::now();
        const auto step = totp::stepAt(now);
        while (totp::stepAt(std::chrono::system_clock::now()) == step)
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
    }

    // ---- a software authenticator (real WebAuthn: ES256, none attestation)

    struct Authenticator {
        tw::TestKey key{wa::Algorithm::ES256};
        wa::Bytes credentialId = tw::randomBytes(32);
        uint32_t signCount = 0;
    };

    static wa::Bytes challengeOf(const json& publicKey) {
        return *wa::base64urlDecode(publicKey.at("challenge").get<std::string>());
    }

    static json registration(Authenticator& a, const json& publicKey, const uint8_t flags) {
        const auto cd = tw::clientDataJSON("webauthn.create", challengeOf(publicKey));
        tw::Attested at;
        at.credentialId = a.credentialId;
        at.cose = a.key.cose();
        const auto ad = tw::authenticatorData(flags, a.signCount, at);
        const auto id = wa::base64urlEncode(a.credentialId);
        return {{"id", id}, {"rawId", id}, {"type", "public-key"},
                {"response", {{"clientDataJSON", wa::base64urlEncode(tw::bytesOf(cd))},
                              {"attestationObject", wa::base64urlEncode(tw::attestationNone(ad))},
                              {"transports", {"internal"}}}},
                {"clientExtensionResults", {{"credProps", {{"rk", true}}}}}};
    }

    static json assertion(Authenticator& a, const json& publicKey, const uint8_t flags) {
        const auto cd = tw::bytesOf(tw::clientDataJSON("webauthn.get", challengeOf(publicKey)));
        const auto ad = tw::authenticatorData(flags, ++a.signCount);
        const auto sig = a.key.sign(tw::concat({ad, tw::sha256(cd)}));
        const auto id = wa::base64urlEncode(a.credentialId);
        return {{"id", id}, {"rawId", id}, {"type", "public-key"},
                {"response", {{"clientDataJSON", wa::base64urlEncode(cd)},
                              {"authenticatorData", wa::base64urlEncode(ad)},
                              {"signature", wa::base64urlEncode(sig)}}}};
    }
};

constexpr uint8_t kUv = tw::flags::UP | tw::flags::UV;

TEST_F(MfaSignInDb, AnAccountThatNeedsNoMfaAndHasNoFactorSignsInWithItsPassword) {
    const auto user = newUser("unprivileged");
    ASSERT_FALSE(policy::requirement(*user).required);
    const auto socket = connect();
    const auto answer = login(user, socket);
    ASSERT_TRUE(answer.ok) << answer.message;
    ASSERT_TRUE(socket->user);
    const auto rows = liveRows(user);
    ASSERT_EQ(rows.size(), 1u);
    EXPECT_EQ(rows[0]->aal, 1);
    EXPECT_EQ(rows[0]->amr, std::vector<std::string>{"pwd"});
}

TEST_F(MfaSignInDb, ThePolicyRequiresMfaOfPrivilegedAccountsOnly) {
    EXPECT_EQ(policy::level(), policy::Level::Admins) << "D2: the default";
    for (const auto* role : {"super_admin", "admin", "identity_admin", "security_admin", "key_custodian"}) {
        const auto r = db::query::rbac::role::Admin::get(role);
        if (!r) continue;
        const auto user = newUser(role);
        EXPECT_TRUE(policy::privileged(*user)) << role;
        EXPECT_EQ(policy::requirement(*user).reason, policy::Reason::PolicyAdmins) << role;
    }
    for (const auto* role : {"unprivileged", "auditor"}) {
        const auto user = newUser(role);
        EXPECT_FALSE(policy::privileged(*user)) << role;
        EXPECT_FALSE(policy::requirement(*user).required) << role;
    }
    const auto plain = newUser("unprivileged");
    policy::setLevel(policy::Level::All);
    EXPECT_EQ(policy::requirement(*plain).reason, policy::Reason::PolicyAll);
    policy::setLevel(policy::Level::Optional);
    const auto admin = newUser("super_admin");
    EXPECT_FALSE(policy::requirement(*admin).required);
    db::Transactions::exec("mfa test", [&](pqxx::work& txn) {
        (void)ensureUser(plain->id);
        txn.exec("UPDATE user_mfa SET required = TRUE WHERE user_id = $1", pqxx::params{plain->id});
    });
    EXPECT_EQ(policy::requirement(*plain).reason, policy::Reason::UserRequired);
}

// The maintainer's regression list: missing MFA. An admin without a factor reaches only the guided enrollment.
TEST_F(MfaSignInDb, AnAdminWithoutAFactorMayOnlyEnroll) {
    const auto admin = newUser("super_admin");
    const auto socket = connect();
    const auto answer = login(admin, socket);
    ASSERT_FALSE(answer.ok);
    EXPECT_EQ(answer.code, "mfa_enrollment_required") << answer.message;
    const auto& pending = answer.data.at("pending");
    EXPECT_EQ(pending.at("kind"), "enrollment");
    EXPECT_EQ(pending.at("methods"), json::array({"webauthn", "totp"}));
    EXPECT_FALSE(pending.contains("webauthn")) << "enrollment registers; it has nothing to assert";
    EXPECT_GT(pending.at("expires_at").get<int64_t>(), std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count() + 9 * 60);
    expectNoSessionFor(socket);
    EXPECT_TRUE(liveRows(admin).empty());

    // A second password attempt on the pending socket is not routed, and the handlers refuse what they don't serve.
    EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand("auth.login", *socket));
    EXPECT_EQ(call([&] { return Mfa::verify(json{{"method", "totp"}, {"code", "000000"}}, socket); }).code, "invalid");
    EXPECT_FALSE(call([&] { return Mfa::status(socket); }).ok);
    EXPECT_FALSE(call([&] { return Mfa::generateRecovery(socket); }).ok);
}

TEST_F(MfaSignInDb, EnrollmentCompletesOnlyOnAcknowledgementWithOneAal2Row) {
    needSealing();
    const auto admin = newUser("super_admin");
    const auto socket = connect();
    ASSERT_EQ(login(admin, socket).code, "mfa_enrollment_required");

    const auto started = Mfa::totpStart(json{{"label", "Phone"}}, socket);
    const auto seed = fromBase32(started.at("secret_base32").get<std::string>());
    EXPECT_TRUE(started.at("otpauth_uri").get<std::string>().starts_with("otpauth://totp/"));
    const auto wrong = call([&] {
        return Mfa::totpConfirm(json{{"enrollment_id", started.at("enrollment_id")},
                                     {"code", std::format("{:06}", (std::stoi(codeAt(seed)) + 1) % 1000000)}}, socket);
    });
    EXPECT_EQ(wrong.code, "invalid");
    const auto confirmed = Mfa::totpConfirm(json{{"enrollment_id", started.at("enrollment_id")},
                                                 {"code", codeAt(seed)}}, socket);
    ASSERT_TRUE(confirmed.contains("recovery_codes"));
    EXPECT_EQ(confirmed.at("recovery_codes").at("codes").size(), 10u);
    EXPECT_EQ(confirmed.at("factor").at("kind"), "totp");

    // The factor is enrolled, but the sign-in is not complete until the codes are acknowledged.
    expectNoSessionFor(socket);
    EXPECT_EQ(call([&] { return Mfa::totpStart(json::object(), socket); }).code, "conflict")
        << "a pending enrollment sets up one factor";
    EXPECT_EQ(call([&] { return Mfa::acknowledgeRecovery(json{{"batch_id", "00000000-0000-4000-8000-000000000000"}},
                                                         socket); }).code, "not_found");

    const auto done = Mfa::acknowledgeRecovery(json{{"batch_id", confirmed.at("recovery_codes").at("batch_id")}}, socket);
    EXPECT_EQ(done.at("aal"), 2);
    EXPECT_EQ(done.at("remaining"), 10);
    EXPECT_EQ(done.at("user").at("id"), admin->id);
    ASSERT_TRUE(socket->user);
    EXPECT_FALSE(socket->mfa().pendingKind());
    const auto rows = liveRows(admin);
    ASSERT_EQ(rows.size(), 1u) << "completion writes exactly one row";
    EXPECT_EQ(rows[0]->jti, jtiOf(socket));
    EXPECT_EQ(rows[0]->aal, 2);
    EXPECT_EQ(rows[0]->amr, (std::vector<std::string>{"pwd", "otp"}));
    EXPECT_TRUE(httpLaneAccepts(cookieOf(socket)));
    EXPECT_TRUE(sessions().validate(socket, socket->tokens->accessToken->rawToken));

    // Next sign-in: the factor is asked for, with recovery codes as the fallback.
    nextStep();
    const auto again = connect();
    const auto answer = login(admin, again);
    EXPECT_EQ(answer.code, "mfa_required");
    EXPECT_EQ(answer.data.at("pending").at("methods"), json::array({"totp", "recovery_code"}));
    EXPECT_EQ(answer.data.at("pending").at("attempts_remaining"), kPendingMaxFailures);
}

// The maintainer's regression list: bypass through refresh or reconnect, and time drift.
TEST_F(MfaSignInDb, PasswordAndAuthenticatorCodeWithDriftAndReplayRefused) {
    needSealing();
    const auto admin = newUser("super_admin");
    SessionPtr first;
    const auto t = enrollTotpAtSignIn(admin, first);
    nextStep();

    const auto socket = connect();
    ASSERT_EQ(login(admin, socket).code, "mfa_required");
    expectNoSessionFor(socket);

    const auto drift = call([&] { return Mfa::verify(json{{"method", "totp"}, {"code", codeAt(t.seed, 2)}}, socket); });
    EXPECT_EQ(drift.code, "mfa_invalid") << "two steps of drift";
    EXPECT_EQ(drift.data.at("attempts_remaining"), kPendingMaxFailures - 1);
    const auto past = call([&] { return Mfa::verify(json{{"method", "totp"}, {"code", codeAt(t.seed, -2)}}, socket); });
    EXPECT_EQ(past.code, "mfa_invalid");
    expectNoSessionFor(socket);

    const auto code = codeAt(t.seed, 1);  // one step ahead: inside the window
    const auto ok = call([&] { return Mfa::verify(json{{"method", "totp"}, {"code", code}}, socket); });
    ASSERT_TRUE(ok.ok) << ok.message;
    EXPECT_EQ(ok.data.at("aal"), 2);
    EXPECT_FALSE(ok.data.contains("recovery"));
    const auto row = db::query::auth::RefreshToken::get(jtiOf(socket));
    ASSERT_TRUE(row);
    EXPECT_EQ(row->aal, 2);
    EXPECT_EQ(row->amr, (std::vector<std::string>{"pwd", "otp"}));

    // The same code (its step is spent) on another sign-in is refused.
    const auto replay = connect();
    ASSERT_EQ(login(admin, replay).code, "mfa_required");
    EXPECT_EQ(call([&] { return Mfa::verify(json{{"method", "totp"}, {"code", code}}, replay); }).code, "mfa_invalid");
    EXPECT_FALSE(replay->user);
}

// The maintainer's regression list: recovery code replay. A recovery sign-in lands in RecoveryRestricted.
TEST_F(MfaSignInDb, ARecoveryCodeSignsInOnceAndSignsOtherWebSessionsOut) {
    needSealing();
    const auto admin = newUser("super_admin");
    SessionPtr other;
    const auto t = enrollTotpAtSignIn(admin, other);
    ASSERT_TRUE(httpLaneAccepts(cookieOf(other)));

    const auto socket = connect();
    ASSERT_EQ(login(admin, socket).code, "mfa_required");
    const auto ok = call([&] { return Mfa::verify(json{{"method", "recovery_code"}, {"code", t.codes[3]}}, socket); });
    ASSERT_TRUE(ok.ok) << ok.message;
    ASSERT_TRUE(ok.data.contains("recovery"));
    EXPECT_EQ(ok.data.at("recovery").at("codes_remaining"), 9);
    EXPECT_GT(ok.data.at("recovery").at("cooldown_until").get<int64_t>(),
              std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch())
                      .count() + 23 * 3600);
    EXPECT_EQ(ok.data.at("recovery").at("sessions_revoked"), 1);
    const auto row = db::query::auth::RefreshToken::get(jtiOf(socket));
    ASSERT_TRUE(row);
    EXPECT_EQ(row->aal, 2);
    EXPECT_EQ(row->amr, (std::vector<std::string>{"pwd", "rec"}));
    EXPECT_FALSE(httpLaneAccepts(cookieOf(other))) << "the other web session survived a recovery sign-in";
    EXPECT_TRUE(httpLaneAccepts(cookieOf(socket)));
    const auto status = Mfa::status(socket);
    EXPECT_TRUE(status.at("recovery_restricted").get<bool>());
    EXPECT_FALSE(status.at("cooldown_until").is_null());
    EXPECT_EQ(status.at("recovery").at("remaining"), 9);

    // Recovery codes are spent: the same one never works again, and new codes can be made from the recovery session.
    const auto replay = connect();
    ASSERT_EQ(login(admin, replay).code, "mfa_required");
    EXPECT_EQ(call([&] { return Mfa::verify(json{{"method", "recovery_code"}, {"code", t.codes[3]}}, replay); }).code,
              "mfa_invalid");
    EXPECT_FALSE(replay->user);
    EXPECT_TRUE(call([&] { return Mfa::generateRecovery(socket); }).ok);
}

TEST_F(MfaSignInDb, FiveFailuresEndThePendingSignInAndTheAccountIsThrottled) {
    needSealing();
    const auto admin = newUser("super_admin");
    SessionPtr first;
    const auto t = enrollTotpAtSignIn(admin, first);
    nextStep();
    const auto socket = connect();
    ASSERT_EQ(login(admin, socket).code, "mfa_required");
    Answer last;
    for (int i = 0; i < kPendingMaxFailures; ++i)
        last = call([&] { return Mfa::verify(json{{"method", "totp"}, {"code", codeAt(t.seed, 3)}}, socket); });
    EXPECT_EQ(last.code, "mfa_invalid");
    EXPECT_EQ(last.data.at("attempts_remaining"), 0);
    EXPECT_FALSE(socket->mfa().pendingKind()) << "the 5th failure ends the pending sign-in";
    EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand("auth.mfa.verify", *socket));
    expectNoSessionFor(socket);

    // Five failures on the account: a new pending sign-in is refused even the right code for a while.
    const auto again = connect();
    ASSERT_EQ(login(admin, again).code, "mfa_required");
    const auto limited = call([&] { return Mfa::verify(json{{"method", "totp"}, {"code", codeAt(t.seed)}}, again); });
    EXPECT_EQ(limited.code, "rate_limited");
    EXPECT_GT(limited.data.at("retry_after").get<int64_t>(), 0);
    signin::resetAccountFailuresForTesting();
    EXPECT_TRUE(call([&] { return Mfa::verify(json{{"method", "totp"}, {"code", codeAt(t.seed)}}, again); }).ok);
}

// The maintainer's regression list: idle during pending. It expires (5 minutes; enrollment 10), and so do cancel and
// sign-out.
TEST_F(MfaSignInDb, APendingSignInEndsWhenItExpiresIsCancelledOrSignedOut) {
    const auto admin = newUser("super_admin");
    const auto socket = connect();
    ASSERT_EQ(login(admin, socket).code, "mfa_enrollment_required");
    (void)socket->mfa().updatePending([](Pending& p) { p.expires_at = std::chrono::system_clock::now() - std::chrono::seconds(1); });
    EXPECT_EQ(call([&] { return Mfa::totpStart(json::object(), socket); }).code, "mfa_expired");
    EXPECT_FALSE(socket->mfa().pendingKind());
    expectNoSessionFor(socket);

    const auto cancelled = connect();
    ASSERT_EQ(login(admin, cancelled).code, "mfa_enrollment_required");
    EXPECT_TRUE(call([&] { return Mfa::cancel(cancelled); }).ok);
    EXPECT_FALSE(cancelled->mfa().pendingKind());
    EXPECT_EQ(Decision::Allow, protocols::ws::Router::classifyCommand("auth.login", *cancelled));

    const auto signedOut = connect();
    ASSERT_EQ(login(admin, signedOut).code, "mfa_enrollment_required");
    (void)protocols::ws::handler::Auth::logout(signedOut);
    EXPECT_FALSE(signedOut->mfa().pendingKind());
    expectNoSessionFor(signedOut);
    EXPECT_TRUE(liveRows(admin).empty());
}

// D2: a session signed in with a password before the policy applied to the account is never grandfathered.
TEST_F(MfaSignInDb, AnAal1AdminSessionIsRefusedAtNextUse) {
    const auto admin = newUser("super_admin");
    policy::setLevel(policy::Level::Optional);
    const auto socket = connect();
    ASSERT_TRUE(login(admin, socket).ok) << "optional: a password signs in an account without a factor";
    const auto cookie = cookieOf(socket);
    ASSERT_TRUE(httpLaneAccepts(cookie));
    ASSERT_EQ(db::query::auth::RefreshToken::get(jtiOf(socket))->aal, 1);

    policy::setLevel(policy::Level::Admins);  // an upgrade to the default, or a raise
    EXPECT_FALSE(httpLaneAccepts(cookie));
    EXPECT_TRUE(db::query::auth::RefreshToken::get(jtiOf(socket))->revoked) << "revoked, not just refused";
    EXPECT_FALSE(sessions().validate(socket, socket->tokens->accessToken->rawToken));
    EXPECT_FALSE(connect(cookie)->user);
}

TEST_F(MfaSignInDb, AnOptionalAccountWithAFactorIsAlwaysAskedForIt) {
    needSealing();
    const auto user = newUser("unprivileged");
    const auto socket = connect();
    ASSERT_TRUE(login(user, socket).ok);
    // Account → Security: its first factor, no step-up needed (there is nothing to step up with).
    const auto started = Mfa::totpStart(json{{"label", "Phone"}}, socket);
    const auto seed = fromBase32(started.at("secret_base32").get<std::string>());
    const auto confirmed = Mfa::totpConfirm(json{{"enrollment_id", started.at("enrollment_id")}, {"code", codeAt(seed)}},
                                            socket);
    ASSERT_TRUE(confirmed.contains("recovery_codes")) << "the first factor comes with recovery codes";
    EXPECT_EQ(Mfa::acknowledgeRecovery(json{{"batch_id", confirmed.at("recovery_codes").at("batch_id")}}, socket)
                  .at("remaining"), 10);
    EXPECT_FALSE(Mfa::status(socket).at("policy").at("required").get<bool>());

    nextStep();
    const auto again = connect();
    EXPECT_EQ(login(user, again).code, "mfa_required");
    expectNoSessionFor(again);
}

TEST_F(MfaSignInDb, ReplacingRecoveryCodesNeedsAStepUp) {
    needSealing();
    const auto admin = newUser("super_admin");
    SessionPtr socket;
    (void)enrollTotpAtSignIn(admin, socket);
    // As the router runs it: under the request's step-up scope (#359). A fresh aal 2 sign-in stands in for the
    // account.credentials step-up.
    const auto asRouted = [&](const std::function<json()>& fn) {
        const stepup::Scope scope(socket);
        return call(fn);
    };
    const auto fresh = asRouted([&] { return Mfa::generateRecovery(socket); });
    ASSERT_TRUE(fresh.ok) << fresh.message;
    EXPECT_EQ(fresh.data.at("codes").size(), 10u);

    socket->tokens->refreshToken->authTime -= std::chrono::minutes(10);
    const auto stale = asRouted([&] { return Mfa::generateRecovery(socket); });
    EXPECT_EQ(stale.code, "step_up_required");
    EXPECT_EQ(stale.data.at("family"), "account.credentials");
    EXPECT_EQ(stale.data.at("methods"), json::array({"password_totp"})) << "an account with a factor: never a password";
}

// The pinned mTLS Desktop tunnel never prompts: a paired device of an admin without any factor keeps working under the
// policy, and the MFA commands refuse it rather than ask it for anything.
TEST_F(MfaSignInDb, ADeviceSessionOfAnAdminIsNeverAskedForMfa) {
    const auto admin = newUser("super_admin");
    ASSERT_TRUE(policy::requirement(*admin).required);
    auto peer = std::make_shared<vh::device::Peer>();
    peer->spkiHex = std::string(64, 'b');
    peer->address = "127.0.0.1";
    peer->deviceRowId = 1;
    const auto device = protocols::ws::Session::devicePrincipal(std::move(peer), admin, [] {});
    EXPECT_TRUE(sessions().validate(device, ""));
    EXPECT_FALSE(sessions().endIfBelowPolicy(device));
    EXPECT_EQ(Decision::Allow, protocols::ws::Router::classifyCommand("fs.list", *device));
    EXPECT_EQ(call([&] { return Mfa::status(device); }).code, "denied");
    EXPECT_EQ(call([&] { return Mfa::totpStart(json::object(), device); }).code, "denied");
    EXPECT_EQ(Decision::Deny, protocols::ws::Router::classifyCommand("auth.login", *device));
}

// First run with a passkey (design 8.1), then password + passkey, then a passkey without user verification.
TEST_F(MfaSignInDb, APasskeyEnrollsAtFirstRunAndSignsInAndUvIsRequired) {
    needSealing();  // the first factor's recovery codes
    const auto admin = newUser("super_admin");
    Authenticator key;
    const auto socket = connect();
    ASSERT_EQ(login(admin, socket).code, "mfa_enrollment_required");

    const auto options = Mfa::registerOptions(json{{"label", "Laptop"}}, socket);
    const auto& pk = options.at("publicKey");
    EXPECT_EQ(pk.at("rp").at("id"), tw::kRpId);
    EXPECT_EQ(pk.at("authenticatorSelection").at("userVerification"), "required");
    EXPECT_EQ(pk.at("attestation"), "none");
    EXPECT_EQ(wa::base64urlDecode(pk.at("user").at("id").get<std::string>())->size(), 32u);
    EXPECT_EQ(pk.at("pubKeyCredParams").at(0).at("alg"), -8);

    // Without UV the registration is refused (and the registration is spent).
    const auto noUv = call([&] {
        return Mfa::registerFinish(json{{"registration_id", options.at("registration_id")},
                                        {"credential", registration(key, pk, tw::flags::UP | tw::flags::AT)}}, socket);
    });
    EXPECT_EQ(noUv.code, "invalid");
    const auto options2 = Mfa::registerOptions(json{{"label", "Laptop"}}, socket);
    const auto finished = Mfa::registerFinish(
        json{{"registration_id", options2.at("registration_id")},
             {"credential", registration(key, options2.at("publicKey"), kUv | tw::flags::AT)}}, socket);
    EXPECT_EQ(finished.at("factor").at("kind"), "webauthn");
    EXPECT_EQ(finished.at("factor").at("label"), "Laptop");
    EXPECT_FALSE(finished.at("factor").at("backup_eligible").get<bool>());
    expectNoSessionFor(socket);
    const auto done = Mfa::acknowledgeRecovery(json{{"batch_id", finished.at("recovery_codes").at("batch_id")}}, socket);
    EXPECT_EQ(done.at("aal"), 2);
    EXPECT_EQ(db::query::auth::RefreshToken::get(jtiOf(socket))->amr, (std::vector<std::string>{"pwd", "hwk"}));

    // Password + passkey.
    const auto again = connect();
    const auto answer = login(admin, again);
    ASSERT_EQ(answer.code, "mfa_required");
    const auto& request = answer.data.at("pending").at("webauthn").at("publicKey");
    EXPECT_EQ(request.at("userVerification"), "required");
    ASSERT_EQ(request.at("allowCredentials").size(), 1u);
    EXPECT_EQ(request.at("allowCredentials").at(0).at("id"), wa::base64urlEncode(key.credentialId));

    // isUserVerified: false is refused, and its challenge is burnt; the refusal carries a fresh one.
    const auto refused = call([&] {
        return Mfa::verify(json{{"method", "webauthn"}, {"credential", assertion(key, request, tw::flags::UP)}}, again);
    });
    EXPECT_EQ(refused.code, "mfa_invalid");
    expectNoSessionFor(again);
    const auto& fresh = refused.data.at("pending").at("webauthn").at("publicKey");
    EXPECT_NE(fresh.at("challenge"), request.at("challenge"));

    // A fresh challenge on request (an expired ceremony): not an attempt.
    const auto renewed = call([&] { return Mfa::verify(json{{"method", "webauthn"}}, again); });
    EXPECT_EQ(renewed.code, "mfa_required");
    EXPECT_EQ(renewed.data.at("pending").at("attempts_remaining"), kPendingMaxFailures - 1);

    const auto& current = renewed.data.at("pending").at("webauthn").at("publicKey");
    const auto ok = call([&] {
        return Mfa::verify(json{{"method", "webauthn"}, {"credential", assertion(key, current, kUv)}}, again);
    });
    ASSERT_TRUE(ok.ok) << ok.message;
    EXPECT_EQ(ok.data.at("aal"), 2);
    EXPECT_EQ(db::query::auth::RefreshToken::get(jtiOf(again))->amr, (std::vector<std::string>{"pwd", "hwk"}));

    // A challenge issued for one socket is refused on another.
    const auto third = connect();
    const auto thirdAnswer = login(admin, third);
    const auto fourth = connect();
    ASSERT_EQ(login(admin, fourth).code, "mfa_required");
    const auto crossed = call([&] {
        return Mfa::verify(json{{"method", "webauthn"},
                                {"credential", assertion(key, thirdAnswer.data.at("pending").at("webauthn")
                                                                  .at("publicKey"), kUv)}}, fourth);
    });
    EXPECT_EQ(crossed.code, "mfa_invalid");
    EXPECT_FALSE(fourth->user);
}

}
