// vh-test-tier: db-only
// MFA policy, lockout, admin and CLI reset, auditable recovery (#360; MFA design note sections 7.1, 7.3, 7.4, 7.5,
// decisions D2 and D4).
//
//   - the policy level is auth.mfa.policy: raising it refuses a password-only session at its next use, and the
//     upgrade default (admins) refuses an old admin row (D2), which then signs in through guided enrollment;
//   - weakening it is audited (auth.mfa.policy.change) and mailed to the security recipients; strengthening only
//     audited;
//   - auth.mfa.admin_webauthn_only holds an admin to passkeys: an authenticator-app session is refused, the sign-in
//     offers only a passkey enrollment, and no authenticator app can be set up;
//   - a recovery-code sign-in (D4) signs every other web session out and revokes the paired devices' key-backup grants,
//     lists the devices without revoking them, starts the cooldown (keys, device.trust, identity.admin, secrets and
//     settings answer recovery_cooldown), and flags the factor enrolled next, which can't answer those families;
//   - auth.mfa.admin.reset and `vh user mfa reset` disable every factor, void the codes, sign every session out,
//     revoke the grants and require enrollment, with their permission rules (super admin only by a super admin, never
//     yourself on the web, root refused on the CLI, the bound user or a users-manager on the CLI), and the two
//     channels leave the same state;
//   - every recovery path is reconstructed from the audit trail alone, and ops::audit::verify (vh audit verify)
//     passes afterwards;
//   - a password reset never touches factors; the last factor of a required account can't be removed;
//   - the 10th failed factor of a streak notifies the user and the security recipients.
#include "../helpers/db_suite.hpp"
#include "../helpers/web_session.hpp"
#include "audit/Trail.hpp"
#include "auth/approval/Approvals.hpp"
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/Recovery.hpp"
#include "crypto/SecretBytes.hpp"
#include "db/query/device/BackupGrant.hpp"
#include "ops/Audit.hpp"
#include "ops/BackupGrants.hpp"
#include "ops/Config.hpp"
#include "ops/Error.hpp"
#include "ops/Mfa.hpp"
#include "notifications/AccountSecurity.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "UsageManager.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <pqxx/pqxx>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

namespace vh::auth::mfa::test_policy_db {

using namespace vh::test::web;
using protocols::ws::handler::Mfa;
namespace stepup = vh::auth::stepup;

// Notices sent while a test runs (notifications::account's test sink).
struct Notices {
    std::mutex mutex;
    std::vector<notifications::account::Notice> sent;
    std::vector<std::string> events() {
        std::lock_guard lock(mutex);
        std::vector<std::string> out;
        for (const auto& n : sent) out.push_back(n.event);
        return out;
    }
    bool has(const std::string& event, const std::optional<uint32_t> user = std::nullopt) {
        std::lock_guard lock(mutex);
        return std::ranges::any_of(sent, [&](const auto& n) { return n.event == event && (!user || n.user_id == user); });
    }
};

class MfaPolicyDb : public vh::test::db::Suite {
protected:
    inline static std::filesystem::path previousConfigPath;
    inline static std::shared_ptr<protocols::shell::Router> shell;
    inline static Notices notices;
    AuthRuntime auth_;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("mfa_policy")) return;
        // Settings writes go to a private copy, never the tree's config.yaml.
        previousConfigPath = paths::configPath;
        if (std::filesystem::exists(previousConfigPath))
            std::filesystem::copy_file(previousConfigPath, root / "config.yaml",
                                       std::filesystem::copy_options::overwrite_existing);
        paths::configPath = root / "config.yaml";
        // TOTP and recovery codes need mfa_seal / mfa_pepper: where sealing can't round-trip (the CI container's
        // TPM), serve fixed test keys instead, so the recovery paths always run.
        try {
            (void)keys::seal();
            (void)keys::pepper();
        } catch (const std::exception&) {
            keys::setForTesting(std::make_shared<const crypto::SecretBytes>(crypto::SecretBytes::random(32)),
                                std::make_shared<const crypto::SecretBytes>(crypto::SecretBytes::random(32)));
        }
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        shell = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerUserCommands(shell);
        vh::audit::Trail::instance()->resetForTesting();
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        paths::configPath = previousConfigPath;
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        auto cfg = config::Registry::get();
        cfg.auth.mfa = config::MfaConfig{};  // admins, 24 h cooldown
        config::Registry::set(cfg);
        policy::install();
        {
            std::lock_guard lock(notices.mutex);
            notices.sent.clear();
        }
        notifications::account::setSinkForTesting([](const notifications::account::Notice& n) {
            std::lock_guard lock(notices.mutex);
            notices.sent.push_back(n);
        });
        ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());
    }

    void TearDown() override {
        totp::resetClockForTesting();
        notifications::account::setSinkForTesting(nullptr);
    }

    static uint32_t freshUid() {
        static uint32_t next = 0;
        return 3'000'000 + static_cast<uint32_t>(::getpid() % 100'000) * 20 + next++;
    }

    static UserPtr superAdmin() { return vh::identities::manager().userByName("admin"); }

    // A paired Desktop with a key-backup grant (#362) over vault 1.
    static vh::device::Device pairDevice(const UserPtr& user) {
        auto d = db::query::device::Devices::insert({.user_id = user->id,
                                                     .approved_by = user->id,
                                                     .name = "Mac " + tag(),
                                                     .platform = "macOS",
                                                     .spki_sha256 = vh::device::crypto::toHex(vh::device::crypto::randomNonce())});
        (void)db::query::device::BackupGrants::create({.device_id = d.id, .user_id = user->id, .vault_ids = {1}});
        return d;
    }

    static std::optional<std::string> grantRevokedFor(const uint32_t deviceId) {
        if (db::query::device::BackupGrants::liveForDevice(deviceId)) return std::nullopt;
        const auto g = db::query::device::BackupGrants::lastRevokedForDevice(deviceId);
        return g ? g->revoked_reason : std::nullopt;
    }

    // A step-up grant on a signed-in web session, as auth.stepup.finish leaves it.
    static void grant(const SessionPtr& s, const stepup::Family family) {
        s->stepUp().addGrant({.user_id = s->user->id, .refresh_jti = jtiOf(s), .family = family,
                              .method = "password_totp",
                              .expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5)});
    }

    static json settingsWith(const std::function<void(json&)>& edit) {
        auto doc = json(config::Registry::get());
        edit(doc);
        return doc;
    }

    static uint64_t nowUs() {
        return static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::microseconds>(
                                         std::chrono::system_clock::now().time_since_epoch())
                                         .count());
    }

    // The trail since `sinceUs`, oldest first, for the given action prefixes, as `vh audit list` shows it.
    static std::vector<vh::audit::Record> trail(const uint64_t sinceUs, const std::vector<std::string>& prefixes) {
        EXPECT_TRUE(vh::audit::Trail::instance()->flushNow());
        std::vector<vh::audit::Record> out;
        for (const auto& prefix : prefixes)
            for (auto& e : ops::audit::list(superAdmin(), {.since_us = sinceUs, .action_prefix = prefix}, 1000).events)
                out.push_back(std::move(e));
        std::ranges::sort(out, {}, &vh::audit::Record::seq);
        return out;
    }

    static json detailsOf(const vh::audit::Record& r) { return json::parse(r.details); }

    // The actions of `events` concerning `userId` (as actor, or as target_id / user_id of an admin's event), in order.
    static std::vector<std::string> actionsFor(const std::vector<vh::audit::Record>& events, const uint32_t userId) {
        std::vector<std::string> out;
        for (const auto& e : events) {
            const auto d = detailsOf(e);
            const bool about = (e.actor_id && *e.actor_id == userId) ||
                               (d.contains("target_id") && d.at("target_id") == userId) ||
                               (d.contains("user_id") && d.at("user_id") == userId);
            if (about) out.push_back(e.action + ":" + e.outcome);
        }
        return out;
    }

    // `expected` appears in `actual` in this order (other events may come between).
    static void expectSubsequence(const std::vector<std::string>& actual, const std::vector<std::string>& expected) {
        std::size_t i = 0;
        for (const auto& a : actual)
            if (i < expected.size() && a == expected[i]) ++i;
        std::string got;
        for (const auto& a : actual) got += "\n  " + a;
        EXPECT_EQ(i, expected.size()) << "missing from the trail from " << (i < expected.size() ? expected[i] : "")
                                      << "; the trail was:" << got;
    }

    static void expectTrailVerifies() {
        ASSERT_TRUE(vh::audit::Trail::instance()->flushNow());
        const auto v = ops::audit::verify(superAdmin());
        EXPECT_TRUE(v.ok) << v.problem;
    }

    static std::size_t liveFactors(const uint32_t userId) { return factors(userId).size(); }
};

// ── policy level (7.1, D2) ─────────────────────────────────────────────────────────────────────────────────────────

// A policy raise takes effect at next use: a password-only session of an account the new level holds to MFA is
// revoked and refused, and its next sign-in is the guided enrollment.
TEST_F(MfaPolicyDb, RaisingThePolicyRefusesPasswordOnlySessionsAtNextUse) {
    policy::setLevel(policy::Level::Optional);
    const auto user = newUser("unprivileged");
    const auto s = connect();
    ASSERT_TRUE(login(user, s).ok);
    const auto jti = jtiOf(s);
    ASSERT_TRUE(connect(cookieOf(s))->user) << "aal 1 is enough under optional";

    const auto since = nowUs();
    (void)ops::config::saveSettings(superAdmin(), settingsWith([](json& d) { d["auth"]["mfa"]["policy"] = "all"; }));
    EXPECT_EQ(policy::level(), policy::Level::All);
    EXPECT_FALSE(connect(cookieOf(s))->user) << "policy all: the aal 1 row is refused at next use";
    EXPECT_FALSE(rowLive(jti)) << "and revoked, not grandfathered";
    EXPECT_EQ(login(user, connect()).code, "mfa_enrollment_required");

    const auto events = trail(since, {"auth.mfa.policy."});
    ASSERT_FALSE(events.empty());
    EXPECT_EQ(detailsOf(events.back()).at("from"), "optional");
    EXPECT_EQ(detailsOf(events.back()).at("to"), "all");
    EXPECT_EQ(detailsOf(events.back()).at("weakened"), "") << "a raise is not a weakening";
    EXPECT_FALSE(notices.has("mfa.policy_weakened")) << "raising mails nobody";
}

// D2: an upgraded install runs `admins`. An admin's session from before (aal 1, amr pwd) is refused at its next use,
// never grandfathered, and the admin signs in once more through guided enrollment (passkey or authenticator app).
TEST_F(MfaPolicyDb, TheUpgradeRefusesOldAdminRowsAndLeadsToGuidedEnrollment) {
    policy::setLevel(policy::Level::Optional);  // the session as it was signed in before the upgrade
    const auto admin = newUser("admin");
    const auto s = connect();
    ASSERT_TRUE(login(admin, s).ok);
    const auto row = db::query::auth::RefreshToken::get(jtiOf(s));
    ASSERT_TRUE(row);
    EXPECT_EQ(row->aal, 1);

    // The upgraded daemon: config.yaml has no auth.mfa.policy, so it reads the default.
    auto cfg = config::Registry::get();
    cfg.auth.mfa = nlohmann::json::object().get<config::MfaConfig>();
    config::Registry::set(cfg);
    session::assurance::policyChanged();
    ASSERT_EQ(policy::level(), policy::Level::Admins);

    EXPECT_FALSE(connect(cookieOf(s))->user);
    EXPECT_FALSE(rowLive(jtiOf(s)));
    const auto next = connect();
    const auto answer = login(admin, next);
    EXPECT_EQ(answer.code, "mfa_enrollment_required");
    const auto methods = answer.data.at("pending").at("methods").get<std::vector<std::string>>();
    EXPECT_NE(std::ranges::find(methods, "webauthn"), methods.end());
    EXPECT_NE(std::ranges::find(methods, "totp"), methods.end());
    EXPECT_FALSE(next->user) << "pending enrollment is not a session";
}

TEST_F(MfaPolicyDb, WeakeningThePolicyIsAuditedAndMailedToSecurity) {
    policy::setLevel(policy::Level::All);
    const auto since = nowUs();
    (void)ops::config::saveSettings(superAdmin(),
                                    settingsWith([](json& d) { d["auth"]["mfa"]["policy"] = "optional"; }));
    EXPECT_TRUE(notices.has("mfa.policy_weakened"));
    {
        std::lock_guard lock(notices.mutex);
        const auto it = std::ranges::find(notices.sent, std::string("mfa.policy_weakened"),
                                          &notifications::account::Notice::event);
        ASSERT_NE(it, notices.sent.end());
        EXPECT_TRUE(it->to_security);
        EXPECT_FALSE(it->to_user);
    }
    const auto events = trail(since, {"auth.mfa.policy.change"});
    ASSERT_EQ(events.size(), 1u);
    EXPECT_EQ(events.front().outcome, "success");
    EXPECT_EQ(detailsOf(events.front()).at("weakened"), "policy");
    EXPECT_EQ(events.front().actor_id, superAdmin()->id);

    // Turning an admin flag off weakens too.
    (void)ops::config::saveSettings(superAdmin(),
                                    settingsWith([](json& d) { d["auth"]["mfa"]["admin_webauthn_only"] = true; }));
    notices.sent.clear();
    (void)ops::config::saveSettings(superAdmin(),
                                    settingsWith([](json& d) { d["auth"]["mfa"]["admin_webauthn_only"] = false; }));
    EXPECT_TRUE(notices.has("mfa.policy_weakened"));

    // A settings save that doesn't touch the policy records nothing about it.
    const auto quiet = nowUs();
    (void)ops::config::saveSettings(superAdmin(), settingsWith([](json&) {}));
    EXPECT_TRUE(trail(quiet, {"auth.mfa.policy."}).empty());
}

TEST_F(MfaPolicyDb, AdminWebAuthnOnlyRefusesAuthenticatorApps) {
    const auto admin = newUser("admin");
    SessionPtr s;
    (void)enrollTotpAtSignIn(admin, s);
    ASSERT_TRUE(connect(cookieOf(s))->user);

    auto cfg = config::Registry::get();
    cfg.auth.mfa.admin_webauthn_only = true;
    config::Registry::set(cfg);
    session::assurance::policyChanged();

    EXPECT_FALSE(connect(cookieOf(s))->user) << "a session signed in with an authenticator app is refused";
    EXPECT_FALSE(policy::factorAllowed(*admin, FactorKind::Totp));
    EXPECT_FALSE(policy::hasAllowedFactor(*admin));
    const auto next = connect();
    const auto answer = login(admin, next);
    EXPECT_EQ(answer.code, "mfa_enrollment_required") << "its only factor doesn't count: enroll a passkey";
    EXPECT_EQ(answer.data.at("pending").at("methods"), json::array({"webauthn"}));
    EXPECT_EQ(call([&] { return Mfa::totpStart(json::object(), next); }).code, "invalid");

    // Unprivileged accounts are not affected.
    const auto plain = newUser("unprivileged");
    EXPECT_TRUE(policy::factorAllowed(*plain, FactorKind::Totp));
}

// ── recovery-code sign-in (7.4, D4) ────────────────────────────────────────────────────────────────────────────────

TEST_F(MfaPolicyDb, ARecoveryCodeSignInRevokesSessionsAndGrantsStartsTheCooldownAndIsAuditable) {
    const auto admin = newUser("super_admin");  // settings.update is a super admin's
    SessionPtr first;
    const auto t = enrollTotpAtSignIn(admin, first);
    const auto other = signInTotp(admin, t);
    const auto mac = pairDevice(admin);
    ASSERT_TRUE(rowLive(jtiOf(first)));
    ASSERT_TRUE(rowLive(jtiOf(other)));

    const auto since = nowUs();
    Answer answer;
    const auto rec = signInRecovery(admin, t.codes[0], &answer);
    ASSERT_TRUE(rec->user);
    const auto& recovery = answer.data.at("recovery");
    EXPECT_EQ(recovery.at("codes_remaining"), 9);
    EXPECT_EQ(recovery.at("sessions_revoked"), 2);
    EXPECT_EQ(recovery.at("grants_revoked"), 1);
    ASSERT_EQ(recovery.at("devices").size(), 1u) << "the paired device is listed for the person to decide";
    EXPECT_EQ(recovery.at("devices")[0].at("id"), mac.id);
    EXPECT_TRUE(recovery.at("devices")[0].at("key_backup_revoked").get<bool>());

    // Automatic: other web sessions and the device's key-backup grant. Not automatic: the device itself.
    EXPECT_FALSE(rowLive(jtiOf(first)));
    EXPECT_FALSE(rowLive(jtiOf(other)));
    EXPECT_TRUE(rowLive(jtiOf(rec)));
    const auto device = db::query::device::Devices::byId(mac.id);
    ASSERT_TRUE(device);
    EXPECT_FALSE(device->revoked()) << "a lost browser factor never breaks a legitimate Desktop's sync";
    EXPECT_EQ(grantRevokedFor(mac.id), std::optional<std::string>("recovery_code"));
    EXPECT_TRUE(notices.has("mfa.recovery_signin", admin->id));

    // The cooldown: a cooldown family is refused before any grant counts, even one this session holds.
    const auto until = recovery::cooldownUntil(admin->id);
    ASSERT_TRUE(until);
    EXPECT_EQ(*until, recovery.at("cooldown_until").get<int64_t>());
    grant(rec, stepup::Family::Settings);
    {
        const stepup::Scope scope(rec);
        for (const auto family : {stepup::Family::Settings, stepup::Family::IdentityAdmin, stepup::Family::Secrets})
            EXPECT_THROW(stepup::require(family), ops::RecoveryCooldown) << stepup::to_string(family);
        EXPECT_THROW(stepup::require(stepup::Family::Keys, std::string("vault.keys.export:1")), ops::RecoveryCooldown);
        EXPECT_THROW(stepup::require(stepup::Family::DeviceTrust, std::string("x")), ops::RecoveryCooldown);
        const auto refused = call([&] {
            (void)ops::config::saveSettings(rec->user, settingsWith([](json&) {}));
            return json::object();
        });
        EXPECT_EQ(refused.code, "recovery_cooldown");
        EXPECT_EQ(refused.data.at("family"), "settings");
        EXPECT_EQ(refused.data.at("cooldown_until"), *until);
    }
    EXPECT_EQ(call([&] { return stepup::begin(rec, stepup::Family::IdentityAdmin, std::nullopt); }).code,
              "recovery_cooldown");

    // The paired device (still paired, D4) can't get around it: neither its approval key nor a console approval makes
    // a grant for a cooldown family, and one it already holds doesn't count (#361's methods).
    {
        auto peer = std::make_shared<vh::device::Peer>();
        peer->spkiHex = mac.spki_sha256;
        peer->deviceRowId = mac.id;
        const auto device = protocols::ws::Session::devicePrincipal(peer, admin, [] {});
        device->stepUp().addGrant({.user_id = admin->id, .family = stepup::Family::Secrets,
                                   .method = std::string(stepup::kConsoleApprovalMethod),
                                   .expires_at = std::chrono::system_clock::now() + std::chrono::minutes(5)});
        {
            const stepup::Scope scope(device);
            EXPECT_THROW(stepup::require(stepup::Family::Secrets), ops::RecoveryCooldown);
            EXPECT_FALSE(ops::backup_grants::covering({1})) << "its key-backup grant was revoked";
        }
        EXPECT_EQ(call([&] {
                      (void)auth::approval::request(device, stepup::Family::Settings, std::nullopt, "change settings");
                      return json::object();
                  }).code,
                  "recovery_cooldown");
        EXPECT_EQ(call([&] {
                      (void)auth::approval::challenge(device, stepup::Family::Keys, "vault.keys.export:1");
                      return json::object();
                  }).code,
                  "recovery_cooldown");
        device->close();
    }

    // Required next: a replacement factor, without a step-up, flagged as enrolled during recovery; then new codes.
    const auto started = Mfa::totpStart(json{{"label", "New phone"}}, rec);
    const auto seed = fromBase32(started.at("secret_base32").get<std::string>());
    nextStep();
    const auto enrolled = Mfa::totpConfirm(json{{"enrollment_id", started.at("enrollment_id")}, {"code", codeAt(seed)}}, rec);
    EXPECT_TRUE(enrolled.at("factor").at("created_during_recovery").get<bool>());
    const auto batch = Mfa::generateRecovery(rec);
    (void)Mfa::acknowledgeRecovery(json{{"batch_id", batch.at("batch_id")}}, rec);

    // A factor enrolled during recovery can't answer a cooldown family while the cooldown runs; it can answer
    // account.credentials (removing the lost factor).
    const auto newFactor = enrolled.at("factor").at("id").get<uint32_t>();
    const auto credentials = stepup::methods(*admin, stepup::Family::AccountCredentials);
    EXPECT_NE(std::ranges::find(credentials, "password_totp"), credentials.end());

    // Out of the cooldown, the same session may step up again.
    db::Transactions::exec("test end cooldown", [&](pqxx::work& txn) {
        txn.exec("UPDATE user_mfa SET recovery_cooldown_until = NOW() - interval '1 second' WHERE user_id = $1",
                 pqxx::params{admin->id});
    });
    EXPECT_FALSE(recovery::cooldownUntil(admin->id));
    {
        const stepup::Scope scope(rec);
        EXPECT_NO_THROW(stepup::require(stepup::Family::Settings)) << "the grant it holds counts again";
    }

    // Reconstructed from the trail alone: the code's use, the sign-in, the revoked sessions and grant, the cooldown
    // refusals, the flagged factor and the new codes.
    const auto events = trail(since, {"auth.", "keys.backup."});
    expectSubsequence(actionsFor(events, admin->id),
                      {"auth.mfa.challenge:info", "auth.mfa.recovery.use:success", "auth.login.success:success",
                       "auth.mfa.verify:success", "keys.backup.grant.revoke:success",
                       "auth.mfa.recovery.signin:info", "auth.stepup.required:denied",
                       "auth.mfa.factor.enroll:success", "auth.mfa.recovery.generate:success",
                       "auth.mfa.recovery.acknowledge:success"});
    for (const auto& e : events) {
        const auto d = detailsOf(e);
        if (e.action == "auth.mfa.recovery.signin") {
            EXPECT_EQ(d.at("sessions_revoked"), 2);
            EXPECT_EQ(d.at("grants_revoked"), 1);
            EXPECT_EQ(d.at("cooldown_until"), *until);
        }
        if (e.action == "auth.mfa.factor.enroll" && e.actor_id == admin->id && d.at("factor_id") == newFactor) {
            EXPECT_TRUE(d.at("during_recovery").get<bool>());
        }
        if (e.action == "auth.stepup.required" && e.outcome == "denied" && e.actor_id == admin->id) {
            EXPECT_EQ(d.at("reason"), "recovery_cooldown");
        }
        EXPECT_EQ(e.details.find(t.codes[0]), std::string::npos) << "no code in the trail";
    }
    expectTrailVerifies();
}

// A factor enrolled during the cooldown, used for a fresh sign-in, still can't answer a cooldown family's step-up: the
// ceremony offers nothing, and the cooldown refuses before any grant.
TEST_F(MfaPolicyDb, AFactorEnrolledDuringRecoveryCantSatisfyStepUpDuringTheCooldown) {
    const auto admin = newUser("admin");
    SessionPtr first;
    const auto t = enrollTotpAtSignIn(admin, first);
    const auto rec = signInRecovery(admin, t.codes[1]);
    // The person removes the lost authenticator (account.credentials: the recovery-code session can, after a step-up
    // a fresh factor would give; here the old one is simply removed directly) and enrolls a new one.
    ASSERT_TRUE(removeFactor(admin->id, FactorKind::Totp, t.factor));
    const auto started = Mfa::totpStart(json{{"label", "New"}}, rec);
    const auto seed = fromBase32(started.at("secret_base32").get<std::string>());
    nextStep();
    const auto enrolled = Mfa::totpConfirm(json{{"enrollment_id", started.at("enrollment_id")}, {"code", codeAt(seed)}}, rec);
    ASSERT_TRUE(enrolled.at("factor").at("created_during_recovery").get<bool>());

    const auto fresh = signInTotp(admin, {.factor = enrolled.at("factor").at("id").get<uint32_t>(), .seed = seed});
    ASSERT_TRUE(fresh->user);
    EXPECT_TRUE(stepup::methods(*admin, stepup::Family::IdentityAdmin).empty());
    EXPECT_FALSE(stepup::methods(*admin, stepup::Family::AccountCredentials).empty());
    {
        const stepup::Scope scope(fresh);
        EXPECT_THROW(stepup::require(stepup::Family::IdentityAdmin), ops::RecoveryCooldown)
            << "a fresh aal 2 sign-in with the new factor doesn't stand in for a grant";
        EXPECT_NO_THROW(stepup::require(stepup::Family::AccountCredentials))
            << "account.credentials is not held back: the fresh sign-in counts";
    }
    EXPECT_EQ(call([&] { return stepup::begin(fresh, stepup::Family::Secrets, std::nullopt); }).code,
              "recovery_cooldown");
}

// ── admin reset (7.4) ──────────────────────────────────────────────────────────────────────────────────────────────

TEST_F(MfaPolicyDb, AnAdminResetDisablesFactorsRevokesEverythingAndRequiresEnrollment) {
    const auto target = newUser("unprivileged");
    policy::setLevel(policy::Level::All);
    SessionPtr targetSession;
    const auto t = enrollTotpAtSignIn(target, targetSession);
    policy::setLevel(policy::Level::Optional);
    const auto mac = pairDevice(target);
    ASSERT_EQ(liveFactors(target->id), 1u);

    const auto boss = newUser("admin");
    const auto bossSession = connect();
    ASSERT_TRUE(login(boss, bossSession).ok) << "optional: the admin signs in with a password here";

    // Under a web scope the reset needs an account.credentials step-up.
    {
        const stepup::Scope scope(bossSession);
        const auto refused = call([&] {
            return Mfa::adminReset(json{{"user_id", target->id}, {"reason", "lost phone"}}, bossSession);
        });
        EXPECT_EQ(refused.code, "step_up_required");
        EXPECT_EQ(refused.data.at("family"), "account.credentials");
    }
    EXPECT_EQ(liveFactors(target->id), 1u) << "nothing changed";

    const auto since = nowUs();
    grant(bossSession, stepup::Family::AccountCredentials);
    Answer reset;
    {
        const stepup::Scope scope(bossSession);
        reset = call([&] {
            return Mfa::adminReset(json{{"user_id", target->id}, {"reason", "lost phone, ticket 42"}}, bossSession);
        });
    }
    ASSERT_TRUE(reset.ok) << reset.code << " " << reset.message;
    EXPECT_EQ(reset.data.at("factors_disabled"), 1);
    EXPECT_EQ(reset.data.at("sessions_revoked"), 1);
    EXPECT_EQ(reset.data.at("grants_revoked"), 1);
    EXPECT_GE(reset.data.at("recovery_batches_voided").get<int>(), 1);

    EXPECT_EQ(liveFactors(target->id), 0u) << "disabled";
    db::Transactions::exec("test kept for audit", [&](pqxx::work& txn) {
        EXPECT_EQ(txn.exec("SELECT COUNT(*) FROM totp_factors WHERE user_id = $1 AND disabled_at IS NOT NULL",
                           pqxx::params{target->id}).one_field().as<int>(), 1)
            << "kept, never deleted";
    });
    EXPECT_FALSE(recoveryStatus(target->id).active_batch) << "codes voided";
    EXPECT_FALSE(rowLive(jtiOf(targetSession)));
    const auto device = db::query::device::Devices::byId(mac.id);
    EXPECT_TRUE(device && !device->revoked());
    EXPECT_EQ(grantRevokedFor(mac.id), std::optional<std::string>("admin_reset"));
    const auto state = userState(target->id);
    ASSERT_TRUE(state);
    EXPECT_TRUE(state->required) << "enrollment at the next sign-in, whatever the policy";
    EXPECT_TRUE(state->reset_at);
    EXPECT_TRUE(recovery::cooldownUntil(target->id));
    EXPECT_TRUE(notices.has("mfa.reset", target->id));

    // The used codes are gone with the batch: a recovery code no longer works, and the next sign-in is enrollment.
    const auto next = connect();
    const auto answer = login(target, next);
    EXPECT_EQ(answer.code, "mfa_enrollment_required");
    const auto started = Mfa::totpStart(json{{"label", "Replacement"}}, next);
    const auto seed = fromBase32(started.at("secret_base32").get<std::string>());
    nextStep();
    const auto confirmed = Mfa::totpConfirm(json{{"enrollment_id", started.at("enrollment_id")}, {"code", codeAt(seed)}}, next);
    EXPECT_TRUE(confirmed.at("factor").at("created_during_recovery").get<bool>()) << "inside the reset's cooldown";
    (void)Mfa::acknowledgeRecovery(json{{"batch_id", confirmed.at("recovery_codes").at("batch_id")}}, next);
    EXPECT_TRUE(next->user);

    const auto events = trail(since, {"auth.", "keys.backup."});
    expectSubsequence(actionsFor(events, target->id),
                      {"auth.mfa.factor.remove:success", "keys.backup.grant.revoke:success",
                       "auth.mfa.admin.reset:success", "auth.mfa.challenge:info", "auth.mfa.factor.enroll:success",
                       "auth.mfa.recovery.acknowledge:success", "auth.login.success:success"});
    const auto it = std::ranges::find(events, std::string("auth.mfa.admin.reset"), &vh::audit::Record::action);
    ASSERT_NE(it, events.end());
    EXPECT_EQ(it->actor_id, boss->id);
    const auto d = detailsOf(*it);
    EXPECT_EQ(d.at("target_id"), target->id);
    EXPECT_EQ(d.at("channel"), "admin_reset");
    EXPECT_EQ(d.at("reason"), "lost phone, ticket 42");
    EXPECT_EQ(d.at("factors_disabled"), 1);
    (void)t;
    expectTrailVerifies();
}

TEST_F(MfaPolicyDb, WhoMayResetWhomOnTheWeb) {
    policy::setLevel(policy::Level::Optional);
    const auto plain = newUser("unprivileged");
    const auto boss = newUser("admin");
    const auto super2 = newUser("super_admin");
    const auto since = nowUs();

    // Nobody without reset-password over the account.
    EXPECT_THROW(ops::mfa::reset(plain, boss->id, "x", ops::mfa::Channel::Web), ops::Denied);
    // A super admin's MFA only by another super admin.
    EXPECT_THROW(ops::mfa::reset(boss, super2->id, "x", ops::mfa::Channel::Web), ops::Denied);
    EXPECT_NO_THROW(ops::mfa::reset(superAdmin(), super2->id, "second super admin lost a key", ops::mfa::Channel::Web));
    // Never yourself on the web.
    EXPECT_THROW(ops::mfa::reset(boss, boss->id, "x", ops::mfa::Channel::Web), ops::Denied);
    // A reason is required and bounded.
    EXPECT_THROW(ops::mfa::reset(superAdmin(), plain->id, "", ops::mfa::Channel::Web), ops::Invalid);
    EXPECT_THROW(ops::mfa::reset(superAdmin(), plain->id, std::string(201, 'x'), ops::mfa::Channel::Web), ops::Invalid);
    // Requiring MFA follows the same rule, and never on yourself.
    EXPECT_THROW(ops::mfa::require(plain, boss->id, true, ops::mfa::Channel::Web), ops::Denied);
    EXPECT_THROW(ops::mfa::require(boss, boss->id, false, ops::mfa::Channel::Web), ops::Denied);
    EXPECT_NO_THROW(ops::mfa::require(boss, plain->id, true, ops::mfa::Channel::Web));
    EXPECT_TRUE(policy::requirement(*plain).required);
    EXPECT_EQ(policy::requirement(*plain).reason, policy::Reason::UserRequired);

    const auto events = trail(since, {"auth.mfa.admin."});
    const auto denied = std::ranges::count_if(events, [](const auto& e) { return e.outcome == "denied"; });
    EXPECT_GE(denied, 5) << "every refusal is audited";
}

// ── `vh user mfa reset` (7.4: the sole super admin's documented recovery) ────────────────────────────────────────────

TEST_F(MfaPolicyDb, CliResetPermissionsAndParityWithTheWeb) {
    policy::setLevel(policy::Level::All);
    const auto self = newUser("unprivileged", freshUid());
    const auto viaWeb = newUser("unprivileged");
    SessionPtr a, b;
    (void)enrollTotpAtSignIn(self, a);
    (void)enrollTotpAtSignIn(viaWeb, b);
    const auto stranger = newUser("unprivileged", freshUid());
    const auto manager = newUser("admin", freshUid());
    const auto unbound = newUser("admin");  // no Linux UID: not a CLI user at all
    const auto root = vh::identities::manager().userByName("root");

    const stepup::Scope host(stepup::Channel::Host);
    const auto run = [&](const std::string& line, const UserPtr& who) { return shell->executeLine(line, who, nullptr); };

    // root (sudo) is refused, even though it may otherwise do anything.
    if (root) {
        EXPECT_NE(run("user mfa reset " + self->name() + " --yes", root).exit_code, 0);
    }
    // Another account without users-manage, and an account with no bound UID, are refused.
    EXPECT_NE(run("user mfa reset " + self->name() + " --yes", stranger).exit_code, 0);
    EXPECT_NE(run("user mfa reset " + self->name() + " --yes", unbound).exit_code, 0);
    // Without --yes and no terminal: nothing happens.
    EXPECT_NE(run("user mfa reset " + self->name(), self).exit_code, 0);
    EXPECT_EQ(liveFactors(self->id), 1u);

    const auto since = nowUs();
    // The bound Linux user resets its own account.
    const auto own = run("user mfa reset " + self->name() + " --reason lost-every-factor --yes", self);
    EXPECT_EQ(own.exit_code, 0) << own.stderr_text << own.stdout_text;
    // A users-manager resets another's.
    const auto managed = run("user mfa reset " + stranger->name() + " --yes", manager);
    EXPECT_EQ(managed.exit_code, 0) << managed.stderr_text;
    // The same through the web.
    const auto webAdmin = newUser("admin");
    const auto webSession = connect();
    policy::setLevel(policy::Level::Optional);
    ASSERT_TRUE(login(webAdmin, webSession).ok);
    grant(webSession, stepup::Family::AccountCredentials);
    {
        const stepup::Scope web(webSession);
        ASSERT_NO_THROW(ops::mfa::reset(webAdmin, viaWeb->id, "lost every factor", ops::mfa::Channel::Web));
    }

    // Parity: the CLI and the web leave the same state.
    const auto facts = [](const UserPtr& u) {
        const auto st = userState(u->id);
        return json{{"factors", factors(u->id).size()},
                    {"active_codes", recoveryStatus(u->id).active_batch.has_value()},
                    {"required", st && st->required},
                    {"reset", st && st->reset_at.has_value()},
                    {"cooldown", recovery::cooldownUntil(u->id).has_value()},
                    {"live_sessions", std::ranges::count_if(db::query::auth::RefreshToken::list(u->id),
                                                            [](const auto& r) { return r && !r->revoked; })}};
    };
    EXPECT_EQ(facts(self), facts(viaWeb));
    EXPECT_EQ(facts(self).at("factors"), 0);

    // `vh user mfa status` agrees.
    const auto status = run("user mfa status " + self->name() + " --json", self);
    EXPECT_EQ(status.exit_code, 0) << status.stderr_text;
    const auto parsed = json::parse(status.stdout_text);
    EXPECT_EQ(parsed.at("factors").size(), 0u);
    EXPECT_TRUE(parsed.at("required_flag").get<bool>());

    // Requiring is never for yourself, on the CLI either.
    EXPECT_NE(run("user mfa require " + self->name() + " --off", self).exit_code, 0);

    // An agent call (vh mcp) can't reset: it can't step up.
    {
        const stepup::Scope agent(stepup::Channel::Agent);
        EXPECT_THROW(ops::mfa::reset(manager, self->id, "agent", ops::mfa::Channel::Cli), ops::StepUpRequired);
    }

    const auto events = trail(since, {"auth.mfa.admin.reset"});
    std::vector<std::string> channels;
    for (const auto& e : events)
        if (e.outcome == "success") channels.push_back(detailsOf(e).at("channel"));
    EXPECT_EQ(std::ranges::count(channels, "cli_reset"), 2);
    EXPECT_EQ(std::ranges::count(channels, "admin_reset"), 1);
    expectSubsequence(actionsFor(trail(since, {"auth."}), self->id),
                      {"auth.mfa.factor.remove:success", "auth.mfa.admin.reset:success"});
    expectTrailVerifies();
}

// ── invariants ─────────────────────────────────────────────────────────────────────────────────────────────────────

TEST_F(MfaPolicyDb, APasswordResetNeverTouchesFactors) {
    const auto admin = newUser("admin");
    SessionPtr s;
    const auto t = enrollTotpAtSignIn(admin, s);
    const auto before = factors(admin->id).size();
    const auto codes = recoveryStatus(admin->id).remaining;
    (void)runtime::Deps::get().authManager->resetPassword(admin->id, kPassword);
    EXPECT_EQ(factors(admin->id).size(), before);
    EXPECT_EQ(recoveryStatus(admin->id).remaining, codes);
    EXPECT_EQ(login(admin, connect()).code, "mfa_required") << "MFA still applies at the next sign-in";
    (void)t;
}

TEST_F(MfaPolicyDb, TheLastFactorOfARequiredAccountCantBeRemoved) {
    const auto admin = newUser("admin");
    SessionPtr s;
    const auto t = enrollTotpAtSignIn(admin, s);
    grant(s, stepup::Family::AccountCredentials);
    const stepup::Scope scope(s);
    const auto refused = call([&] { return Mfa::removeFactor(json{{"kind", "totp"}, {"id", t.factor}}, s); });
    EXPECT_EQ(refused.code, "mfa_last_factor");
    EXPECT_EQ(factors(admin->id).size(), 1u);
}

// 7.3: the 10th failure of a streak notifies the user and the security recipients, once; delays never exceed 15
// minutes.
TEST_F(MfaPolicyDb, TheTenthFailureNotifiesOnce) {
    const auto user = newUser("unprivileged");
    const auto t0 = signin::AccountBackoff::Clock::now();
    auto now = t0;
    for (int i = 1; i <= 12; ++i) {
        now += signin::accountRetryAfter(user->id, now) + std::chrono::seconds(1);
        const auto f = signin::recordAccountFailure(user->id, now);
        EXPECT_EQ(f.failures, i);
        EXPECT_EQ(f.notify, i == signin::kAccountNotifyAt) << i;
        EXPECT_LE(f.delay, std::chrono::minutes(15));
    }
    const auto sent = notices.events();
    EXPECT_EQ(std::ranges::count(sent, "mfa.failures"), 1);
    EXPECT_TRUE(notices.has("mfa.failures", user->id));
}

}
