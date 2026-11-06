// vh-test-tier: db-only
// Step-up (#359; MFA design note section 5.4, decisions D3 and D6), DB-backed: table-driven over the contract
// annotations, every command refuses without a grant and passes the gate with one; D3 (the password alone only for an
// account without MFA, never keys, device.trust or data.destroy); a passkey step-up bound to its session, family and
// target; recovery codes, a reconnect with the cookie and a paired device never satisfying it; five failures revoking
// the session; logout and invalidation dropping grants; and the regression list (privilege elevation, a stolen browser
// session approving a device or making a grant). DB-free half: test_mfa_stepup.cpp.
#include "../helpers/identities.hpp"
#include "Contract.hpp"
#include "auth/Manager.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Policy.hpp"
#include "auth/mfa/SignIn.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Assurance.hpp"
#include "auth/session/Issuer.hpp"
#include "auth/session/Manager.hpp"
#include "auth/stepup/StepUp.hpp"
#include "auth/webauthn/Base64Url.hpp"
#include "config/Registry.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/auth/RefreshToken.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/rbac/role/Vault.hpp"
#include "db/query/vault/Vault.hpp"
#include "device/Crypto.hpp"
#include "device/Pairing.hpp"
#include "device/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Group.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/BackupGrants.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/Refusal.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "protocols/ws/handler/Devices.hpp"
#include "protocols/ws/handler/Groups.hpp"
#include "protocols/ws/handler/Mfa.hpp"
#include "protocols/ws/handler/Settings.hpp"
#include "protocols/ws/handler/StepUp.hpp"
#include "protocols/ws/handler/rbac/roles/Admin.hpp"
#include "protocols/ws/handler/rbac/roles/Vault.hpp"
#include "protocols/ws/handler/vault/Vaults.hpp"
#include "rbac/role/Admin.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Manager.hpp"
#include "webauthn/Fixtures.hpp"
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <chrono>
#include <cstdlib>
#include <functional>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <unistd.h>

namespace vh::auth::stepup::test_stepup_db {

using json = nlohmann::json;
using SessionPtr = std::shared_ptr<protocols::ws::Session>;
using SysClock = std::chrono::system_clock;
namespace wa = vh::auth::webauthn;
namespace tw = vh::test_webauthn;

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
        return {.ok = false, .data = reply.data, .code = code, .message = reply.message};
    }
}

// A signed-in web socket without a database: a detached user and a refresh row in memory.
SessionPtr detachedWebSession(const uint32_t userId, const uint8_t aal = 1,
                              std::vector<std::string> amr = {"pwd"},
                              const SysClock::time_point authTime = SysClock::now() - std::chrono::hours(1)) {
    auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    identities::UserState state;
    state.name = "stepup-" + std::to_string(userId);
    s->user = identities::User::detached(userId, std::move(state));
    s->tokens->refreshToken = std::make_shared<model::RefreshToken>();
    s->tokens->refreshToken->jti = "jti-" + std::to_string(userId);
    s->tokens->refreshToken->aal = aal;
    s->tokens->refreshToken->amr = std::move(amr);
    s->tokens->refreshToken->authTime = authTime;
    return s;
}

Grant grantFor(const SessionPtr& s, const Family family, std::optional<std::string> target = std::nullopt,
               const std::chrono::seconds ttl = std::chrono::seconds(300)) {
    return {.user_id = s->user->id, .refresh_jti = s->tokens->refreshToken->jti, .family = family,
            .target = targetBound(family) ? std::move(target) : std::nullopt, .method = "test",
            .expires_at = SysClock::now() + ttl};
}

// ── DB-backed ─────────────────────────────────────────────────────────────────────────────────────────────────────────

constexpr auto kPassword = "StepUp-Pass-1-xyz";

class StepUpDb : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static int counter = 0;
    std::shared_ptr<session::Manager> previousSessions;
    std::shared_ptr<auth::Manager> previousAuth;
    std::optional<config::Config> previousConfig;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_mfa_stepup] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_mfa_stepup_" + std::to_string(::getpid()));
        paths::backingPath = root / "backing";
        std::filesystem::create_directories(paths::backingPath);
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        session::Issuer::setJwtSecretForTesting("mfa-stepup-test-secret");
        previousSessions = runtime::Deps::get().sessionManager;
        previousAuth = runtime::Deps::get().authManager;
        runtime::Deps::get().sessionManager = std::make_shared<session::Manager>();
        runtime::Deps::get().authManager = std::make_shared<auth::Manager>();
        previousConfig = config::Registry::get();
        auto cfg = *previousConfig;
        cfg.auth.webauthn.rp_id = std::string(tw::kRpId);
        cfg.auth.webauthn.origins = {std::string(tw::kOrigin)};
        config::Registry::set(cfg);
        // An account that need not have MFA signs in with its password (aal 1): the table runs as a super admin.
        mfa::policy::setLevel(mfa::policy::Level::Optional);
        session::assurance::setPolicy(nullptr);
        mfa::signin::resetAccountFailuresForTesting();
    }

    void TearDown() override {
        if (skipTests) return;
        mfa::policy::setLevel(mfa::policy::Level::Admins);
        if (previousConfig) config::Registry::set(*previousConfig);
        runtime::Deps::get().sessionManager = previousSessions;
        runtime::Deps::get().authManager = previousAuth;
        session::Issuer::clearJwtSecretForTesting();
    }

    static std::string tag() { return std::to_string(::getpid()) + "_" + std::to_string(++counter); }

    static std::shared_ptr<identities::User> newUser(const std::string& role) {
        const auto r = db::query::rbac::role::Admin::get(role);
        if (!r) throw std::runtime_error("Missing role " + role);
        return vh::identities::manager().user(
            test::identities::createUser("su_" + role + "_" + tag(), r, std::nullopt,
                                         crypto::hash::password(kPassword))->id);
    }

    static session::Manager& sessions() { return *runtime::Deps::get().sessionManager; }

    static SessionPtr connect(const std::string& cookie = {}) {
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->ipAddress = "127.0.0.1";
        session->userAgent = "stepup-browser";
        model::RefreshToken::addToSession(session, cookie);
        sessions().tryRehydrate(session);
        return session;
    }

    static SessionPtr signedIn(const std::shared_ptr<identities::User>& user) {
        const auto s = connect();
        const auto answer = call([&] {
            return protocols::ws::handler::Auth::login(json{{"name", user->name()}, {"password", kPassword}}, s);
        });
        EXPECT_TRUE(answer.ok) << answer.code << " " << answer.message;
        EXPECT_TRUE(s->user);
        return s;
    }

    // A command as the router runs it: under the request's step-up scope.
    static Answer run(const SessionPtr& s, const std::function<json()>& fn) {
        const Scope scope(s);
        return call(fn);
    }

    // ---- a software authenticator (real WebAuthn: ES256)

    struct Authenticator {
        tw::TestKey key{wa::Algorithm::ES256};
        wa::Bytes credentialId = tw::randomBytes(32);
        uint32_t signCount = 0;
    };

    static void enrollPasskey(const std::shared_ptr<identities::User>& user, Authenticator& a) {
        (void)mfa::ensureUser(user->id);
        (void)mfa::addWebAuthnCredential(user->id, {.credential_id = a.credentialId, .public_key_cose = a.key.cose(),
                                                    .cose_alg = -7, .rp_id = std::string(tw::kRpId),
                                                    .attestation_fmt = "none", .label = "Laptop"});
    }

    static json assertion(Authenticator& a, const json& publicKey, const uint8_t flags = tw::flags::UP | tw::flags::UV) {
        const auto challenge = *wa::base64urlDecode(publicKey.at("challenge").get<std::string>());
        const auto cd = tw::bytesOf(tw::clientDataJSON("webauthn.get", challenge));
        const auto ad = tw::authenticatorData(flags, ++a.signCount);
        const auto sig = a.key.sign(tw::concat({ad, tw::sha256(cd)}));
        const auto id = wa::base64urlEncode(a.credentialId);
        return {{"id", id}, {"rawId", id}, {"type", "public-key"},
                {"response", {{"clientDataJSON", wa::base64urlEncode(cd)},
                              {"authenticatorData", wa::base64urlEncode(ad)},
                              {"signature", wa::base64urlEncode(sig)}}}};
    }

    // A confirmed pairing request owned by `owner`: the code the person would choose.
    struct PairingRequest {
        std::string request_id;
        std::string code;
    };
    static PairingRequest pairingRequest(const uint32_t owner, const uint8_t tag) {
        auto& pairing = vh::device::Pairing::instance();
        pairing.resetForTesting();
        const auto now = vh::device::PairingClock::now();
        (void)pairing.open(owner, now);
        vh::device::crypto::Hash spki{};
        spki.fill(tag);
        const vh::device::Peer peer{.spki = spki, .spkiHex = vh::device::crypto::toHex(spki), .address = "192.0.2.77"};
        const auto nonce = vh::device::crypto::randomNonce();
        const auto receipt = pairing.request(peer, {.name = "Studio Mac", .platform = "macOS", .app_version = "1.0",
                                                    .commitment = vh::device::crypto::commitment(peer.spki, nonce)},
                                             now);
        vh::device::crypto::Hash server{};
        server.fill(0xee);
        (void)pairing.confirm(peer, receipt.request_id, nonce, server, now);
        return {.request_id = receipt.request_id, .code = *pairing.codeForTesting(receipt.request_id)};
    }
};

// Table-driven over the contract annotations: every annotated command refuses without a grant (step_up_required with
// its family) and passes the gate with one. Each row is the command's real ws handler, under the router's scope.
TEST_F(StepUpDb, EveryAnnotatedCommandRefusesWithoutAGrantAndRunsWithOne) {
    namespace h = protocols::ws::handler;
    const auto admin = newUser("super_admin");
    const auto s = signedIn(admin);
    ASSERT_TRUE(s->user);
    ASSERT_EQ(s->tokens->refreshToken->aal, 1);

    const auto subject = newUser("unprivileged");
    const auto other = newUser("unprivileged");
    const auto group = test::identities::createGroup("su_group_" + tag());
    vh::identities::manager().addMembers(group->id, {other->id});
    const auto vaultRole = db::query::rbac::role::Vault::get("implicit_deny");
    ASSERT_TRUE(vaultRole);
    const auto pairing = pairingRequest(admin->id, 0x5a);

    struct Row {
        std::function<json()> fn;
        bool expectOk{true};  // false: the gate passes, and what follows needs more than this environment has
    };
    // Names created by earlier rows, found again by later ones.
    std::string adminRoleName = "su_role_" + tag(), vaultRoleName = "su_vrole_" + tag();
    std::map<std::string, Row> rows{
        {"auth.register", {[&] {
             return h::Auth::registerUser(json{{"name", "su_reg_" + tag()}, {"role", "unprivileged"},
                                               {"password", "Registered-Pass-9-xyz"}}, s);
         }}},
        {"auth.user.update", {[&] { return h::Auth::updateUser(json{{"id", subject->id}, {"role", "auditor"}}, s); }}},
        {"auth.user.change_password", {[&] {
             return h::Auth::changePassword(json{{"id", other->id}, {"new_password", "Reset-Pass-7-xyz-" + tag()}}, s);
         }}},
        {"role.admin.add", {[&] { return h::rbac::roles::Admin::add(json{{"name", adminRoleName}}, s); }}},
        {"role.admin.update", {[&] {
             const auto r = db::query::rbac::role::Admin::get(adminRoleName);
             return h::rbac::roles::Admin::update(json{{"id", r->id}, {"description", "edited"}}, s);
         }}},
        {"role.admin.delete", {[&] {
             const auto r = db::query::rbac::role::Admin::get(adminRoleName);
             return h::rbac::roles::Admin::remove(json{{"id", r->id}}, s);
         }}},
        {"role.vault.add", {[&] { return h::rbac::roles::Vault::add(json{{"name", vaultRoleName}}, s); }}},
        {"role.vault.update", {[&] {
             const auto r = db::query::rbac::role::Vault::get(vaultRoleName);
             return h::rbac::roles::Vault::update(json{{"id", r->id}, {"description", "edited"}}, s);
         }}},
        {"role.vault.delete", {[&] {
             const auto r = db::query::rbac::role::Vault::get(vaultRoleName);
             return h::rbac::roles::Vault::remove(json{{"id", r->id}}, s);
         }}},
        {"group.member.add", {[&] {
             return h::Groups::addMember(json{{"groupId", group->id}, {"memberName", subject->name()}}, s);
         }}},
        {"group.member.remove", {[&] {
             return h::Groups::removeMember(json{{"groupId", group->id}, {"userId", other->id}}, s);
         }}},
        {"group.remove", {[&] { return h::Groups::remove(json{{"id", group->id}}, s); }}},
        {"device.pairing.approve", {[&] {
             return h::Devices::pairingApprove(json{{"request_id", pairing.request_id}, {"code", pairing.code}}, s);
         }}},
        // #360: another account's MFA.
        {"auth.mfa.admin.require", {[&] {
             return h::Mfa::adminRequire(json{{"user_id", subject->id}, {"required", true}}, s);
         }}},
        {"auth.mfa.admin.reset", {[&] {
             return h::Mfa::adminReset(json{{"user_id", subject->id}, {"reason", "step-up table"}}, s);
         }}},
        {"auth.user.delete", {[&] { return h::Auth::deleteUser(json{{"id", other->id}, {"confirm", true}}, s); }}},
    };

    // The rest of the table is exercised elsewhere or needs what this environment lacks (a provider, a sealed key,
    // a vault engine, a factor); each says where and why, so a new annotation can't go unexamined.
    const std::map<std::string, std::string> elsewhere{
        {"vault.keys.export", "console: export_requires_device first; device: test_key_backup_grants_db.cpp"},
        {"vault.keys.import", "console: import_requires_device first; needs a sealed vault key (test_vault_keys)"},
        {"vault.keys.recipients.add", "console: recipient_requires_device first; device refusal and host exemption in "
                                      "RecoveryRecipient.EnrollmentIsForTheCliAndPairedDevicesWithTheExportPermission"},
        {"vault.keys.recipients.revoke", "console: recipient_requires_device first; same gate as .add (an S3 vault and "
                                         "its bucket: test_recovery_recipients)"},
        {"device.remote.enable", "writes the daemon's config file: refusal in AStolenBrowserSessionCantApprove..."},
        {"device.approval.key.register", "a paired device's own session: test_device_approvals_db.cpp"},
        {"device.backup.grant.create", "needs a paired device and an exportable vault: test_key_backup_grants_db.cpp"},
        {"device.backup.grant.extend", "needs a live grant: test_key_backup_grants_db.cpp"},
        {"device.backup.grant.confirm", "needs a live grant: test_key_backup_grants_db.cpp"},
        {"settings.update", "writes the daemon's config file: refusal in AStolenBrowserSessionCantApprove..."},
        {"email.config.update", "settings.update's email sections (ops::config::saveSettings): writes the config file"},
        {"auth.mfa.factor.remove", "covered by APasskeyStepUpIsBoundToItsSessionFamilyAndTarget"},
        {"auth.mfa.webauthn.register.options", "covered by APasskeyStepUpIsBoundToItsSessionFamilyAndTarget"},
        {"auth.mfa.webauthn.register.finish", "same handler gate as .options"},
        {"auth.mfa.totp.enroll.start", "same gate as webauthn.register (mfaWsRequireForAnotherFactor); needs mfa_seal"},
        {"auth.mfa.totp.enroll.confirm", "same gate as webauthn.register; needs mfa_seal"},
        {"auth.mfa.recovery.generate", "needs mfa_pepper; same family gate"},
        {"role.vault.assign", "needs a vault"},
        {"role.vault.unassign", "needs a vault"},
        {"role.vault.overrides.add", "needs a vault assignment"},
        {"role.vault.overrides.update", "needs a vault assignment"},
        {"role.vault.overrides.remove", "needs a vault assignment"},
        {"storage.apiKey.add", "needs ak_master (sealed): ops gate before addAPIKey"},
        {"storage.apiKey.update", "needs an API key"},
        {"storage.apiKey.remove", "needs an API key"},
        {"email.provider.secret.set", "needs the secrets manager's sealed master"},
        {"s3.gateway.credentials.create", "needs s3gw_master (sealed)"},
        {"s3.gateway.credentials.scope.update", "needs a credential"},
        {"s3.gateway.credentials.roles.assign", "needs a credential"},
        {"s3.gateway.credentials.roles.revoke", "needs a credential"},
        {"s3.gateway.credentials.roles.overrides.add", "needs a credential"},
        {"s3.gateway.credentials.roles.overrides.remove", "needs a credential"},
        {"s3.gateway.credentials.defaultRole.set", "needs a credential"},
        {"s3.gateway.credentials.defaultRole.clear", "needs a credential"},
        {"s3.gateway.credentials.defaultRole.overrides.add", "needs a credential"},
        {"s3.gateway.credentials.defaultRole.overrides.remove", "needs a credential"},
        {"upstream.admin.enable", "needs a provider administration API"},
        {"upstream.bucket.cleanup", "needs a provider bucket"},
        {"upstream.bucket.unprotect", "needs a protected provider bucket"},
        {"upstream.bucket.lifecycle.set", "needs a provider bucket"},
        {"storage.vault.remove", "covered by ATargetBoundGrantBindsTheExactAction"},
        {"recovery.point.delete", "needs a recovery point"},
        {"vault.recovery.suspend", "needs a versioned provider bucket"},
        {"vault.recover", "needs a bucket and the customer's recovery material (VaultRecoverDb; the console is refused "
                          "recover_requires_device first)"},
    };

    std::set<std::string> annotated;
    for (const auto& r : contract::stepUpTable()) {
        annotated.insert(r.command);
        EXPECT_TRUE(rows.contains(r.command) || elsewhere.contains(r.command))
            << r.command << " is annotated but neither exercised here nor accounted for";
    }
    for (const auto& [cmd, _] : rows) EXPECT_TRUE(annotated.contains(cmd)) << cmd << " is not annotated";

    // Run in dependency order (create before update before delete).
    const std::vector<std::string> order{
        "auth.register", "auth.user.update", "auth.user.change_password", "role.admin.add", "role.admin.update",
        "role.admin.delete", "role.vault.add", "role.vault.update", "role.vault.delete", "group.member.add",
        "group.member.remove", "group.remove", "device.pairing.approve", "auth.mfa.admin.require",
        "auth.mfa.admin.reset", "auth.user.delete"};
    ASSERT_EQ(order.size(), rows.size());
    const auto table = contract::stepUpTable();
    for (const auto& cmd : order) {
        const auto& row = rows.at(cmd);
        s->stepUp().clear();  // each row starts without a grant (an earlier row's family grant would serve it)
        const auto family = std::ranges::find(table, cmd, &contract::WsStepUp::command)->family;
        const auto refused = run(s, row.fn);
        ASSERT_EQ(refused.code, "step_up_required") << cmd << ": " << refused.message;
        EXPECT_EQ(refused.data.at("family"), family) << cmd;
        EXPECT_EQ(refused.data.at("target").is_string(), targetBound(*parseFamily(family))) << cmd;

        s->stepUp().addGrant(grantFor(s, *parseFamily(family), refused.data.at("target").is_string()
                                                                  ? std::optional(refused.data.at("target").get<std::string>())
                                                                  : std::nullopt));
        const auto ran = run(s, row.fn);
        EXPECT_NE(ran.code, "step_up_required") << cmd << " refused with a grant";
        if (row.expectOk) {
            EXPECT_TRUE(ran.ok) << cmd << ": " << ran.code << " " << ran.message;
        }
    }
}

// The regression list: privilege elevation. Without a grant, or with one for another family, it is refused.
TEST_F(StepUpDb, PrivilegeElevationNeedsAnIdentityAdminGrant) {
    namespace h = protocols::ws::handler;
    const auto admin = newUser("super_admin");
    const auto s = signedIn(admin);
    const auto target = newUser("unprivileged");
    const auto group = test::identities::createGroup("su_elev_" + tag());

    const auto promote = [&] { return h::Auth::updateUser(json{{"id", target->id}, {"role", "admin"}}, s); };
    const auto join = [&] {
        return h::Groups::addMember(json{{"groupId", group->id}, {"memberName", target->name()}}, s);
    };
    EXPECT_EQ(run(s, promote).code, "step_up_required");
    EXPECT_EQ(run(s, join).code, "step_up_required");
    s->stepUp().addGrant(grantFor(s, Family::Settings));
    s->stepUp().addGrant(grantFor(s, Family::Secrets));
    EXPECT_EQ(run(s, promote).code, "step_up_required") << "a grant for another family";
    EXPECT_EQ(vh::identities::manager().user(target->id)->state()->roles.admin->name, "unprivileged");

    // Your own name or email is not identity.admin.
    EXPECT_TRUE(run(s, [&] { return h::Auth::updateUser(json{{"email", "me@example.test"}}, s); }).ok);
}

// D3: the password alone, only for an account that need not have MFA and has no factor, and never for keys,
// device.trust or data.destroy. The server decides at begin and again at finish.
TEST_F(StepUpDb, PasswordAloneOnlyForLowerRiskFamiliesOfAnAccountWithoutMfa) {
    namespace h = protocols::ws::handler;
    const auto user = newUser("unprivileged");
    const auto s = signedIn(user);
    ASSERT_FALSE(mfa::policy::requirement(*user).required);

    for (const auto* family : {"keys", "device.trust", "data.destroy"}) {
        const auto begun = run(s, [&] { return h::StepUp::begin(json{{"family", family}, {"target", "x:1"}}, s); });
        EXPECT_EQ(begun.code, "step_up_unavailable") << family << ": " << begun.message;
    }
    const auto begun = run(s, [&] { return h::StepUp::begin(json{{"family", "account.credentials"}}, s); });
    ASSERT_TRUE(begun.ok) << begun.message;
    EXPECT_EQ(begun.data.at("methods"), json::array({"password"}));
    EXPECT_FALSE(begun.data.contains("webauthn"));

    const auto wrong = run(s, [&] {
        return h::StepUp::finish(json{{"stepup_id", begun.data.at("stepup_id")}, {"method", "password"},
                                      {"password", "nope"}}, s);
    });
    EXPECT_EQ(wrong.code, "step_up_failed");
    EXPECT_EQ(wrong.data.at("attempts_remaining"), kMaxFailures - 1);
    // A ceremony is answered once: the wrong answer spent it.
    const auto again = run(s, [&] {
        return h::StepUp::finish(json{{"stepup_id", begun.data.at("stepup_id")}, {"method", "password"},
                                      {"password", kPassword}}, s);
    });
    EXPECT_EQ(again.code, "not_found");

    const auto second = run(s, [&] { return h::StepUp::begin(json{{"family", "account.credentials"}}, s); });
    const auto granted = run(s, [&] {
        return h::StepUp::finish(json{{"stepup_id", second.data.at("stepup_id")}, {"method", "password"},
                                      {"password", kPassword}}, s);
    });
    ASSERT_TRUE(granted.ok) << granted.message;
    EXPECT_EQ(granted.data.at("family"), "account.credentials");
    EXPECT_TRUE(granted.data.at("uses").is_null());
    // The password change itself now runs (and asks for no second step-up within the window).
    EXPECT_TRUE(run(s, [&] {
                    return h::Auth::changePassword(json{{"id", user->id}, {"old_password", kPassword},
                                                        {"new_password", "Changed-Pass-3-xyz"}}, s);
                }).ok);

    // Under policy admins a privileged account is required to have MFA: never the password alone.
    mfa::policy::setLevel(mfa::policy::Level::Admins);
    const auto admin = newUser("super_admin");
    const auto adminSession = detachedWebSession(admin->id);
    adminSession->user = admin;
    EXPECT_EQ(methods(*admin, Family::Settings), std::vector<std::string>{});
    EXPECT_EQ(run(adminSession, [&] { return h::StepUp::begin(json{{"family", "settings"}}, adminSession); }).code,
              "step_up_unavailable");
}

// A passkey step-up: bound to its session, family and target; another session, family or target, a replay, and an
// assertion without UV are refused. An account with a factor is never offered the password alone.
TEST_F(StepUpDb, APasskeyStepUpIsBoundToItsSessionFamilyAndTarget) {
    namespace h = protocols::ws::handler;
    const auto user = newUser("unprivileged");
    Authenticator key;
    enrollPasskey(user, key);
    // An account with a factor signs in with it; here the sessions are made at aal 1 with an old auth_time, so the
    // sign-in never stands in for a step-up.
    const auto a = connect();
    const auto b = connect();
    for (const auto& s : {a, b}) {
        s->setAuthenticatedUser(user);
        sessions().promote(s);
        s->tokens->refreshToken->authTime = SysClock::now() - std::chrono::hours(2);
    }

    const auto begun = run(a, [&] {
        return h::StepUp::begin(json{{"family", "data.destroy"}, {"target", "storage.vault.remove:999"}}, a);
    });
    ASSERT_TRUE(begun.ok) << begun.message;
    EXPECT_EQ(begun.data.at("methods"), json::array({"webauthn"})) << "a factor: never the password alone";
    const auto& pk = begun.data.at("webauthn").at("publicKey");
    EXPECT_EQ(pk.at("userVerification"), "required");

    // Without UV: refused (and the challenge burned).
    const auto noUv = run(a, [&] {
        return h::StepUp::finish(json{{"stepup_id", begun.data.at("stepup_id")}, {"method", "webauthn"},
                                      {"credential", assertion(key, pk, tw::flags::UP)}}, a);
    });
    EXPECT_EQ(noUv.code, "step_up_failed");

    const auto second = run(a, [&] {
        return h::StepUp::begin(json{{"family", "data.destroy"}, {"target", "storage.vault.remove:999"}}, a);
    });
    const auto signedAssertion = assertion(key, second.data.at("webauthn").at("publicKey"));
    // The assertion answers its own ceremony only: presented on another session's, it fails, and the attempt burns
    // its challenge, so it can't be used afterwards either.
    const auto onB = run(b, [&] {
        return h::StepUp::begin(json{{"family", "data.destroy"}, {"target", "storage.vault.remove:999"}}, b);
    });
    const auto stolen = run(b, [&] {
        return h::StepUp::finish(json{{"stepup_id", onB.data.at("stepup_id")}, {"method", "webauthn"},
                                      {"credential", signedAssertion}}, b);
    });
    EXPECT_EQ(stolen.code, "step_up_failed") << "an assertion for another session's challenge";
    const auto replayed = run(a, [&] {
        return h::StepUp::finish(json{{"stepup_id", second.data.at("stepup_id")}, {"method", "webauthn"},
                                      {"credential", signedAssertion}}, a);
    });
    EXPECT_EQ(replayed.code, "step_up_failed") << "a burned challenge";
    const auto third = run(a, [&] {
        return h::StepUp::begin(json{{"family", "data.destroy"}, {"target", "storage.vault.remove:999"}}, a);
    });
    const auto granted = run(a, [&] {
        return h::StepUp::finish(json{{"stepup_id", third.data.at("stepup_id")}, {"method", "webauthn"},
                                      {"credential", assertion(key, third.data.at("webauthn").at("publicKey"))}}, a);
    });
    ASSERT_TRUE(granted.ok) << granted.code << " " << granted.message;
    EXPECT_EQ(granted.data.at("uses"), 1);

    {
        const Scope onA(a);
        EXPECT_THROW(require(Family::DataDestroy, std::string("storage.vault.remove:1000")), ops::StepUpRequired)
            << "another target";
        EXPECT_THROW(require(Family::Keys, std::string("storage.vault.remove:999")), ops::StepUpRequired)
            << "another family";
    }
    {
        const Scope onB(b);
        EXPECT_THROW(require(Family::DataDestroy, std::string("storage.vault.remove:999")), ops::StepUpRequired)
            << "another session";
    }
    {
        const Scope onA(a);
        EXPECT_NO_THROW(require(Family::DataDestroy, std::string("storage.vault.remove:999")));
    }
    {
        const Scope onA(a);
        EXPECT_THROW(require(Family::DataDestroy, std::string("storage.vault.remove:999")), ops::StepUpRequired)
            << "consumed";
    }

    // A second factor is account.credentials; so is removing one.
    EXPECT_EQ(run(a, [&] { return h::Mfa::registerOptions(json{{"label", "Second"}}, a); }).code, "step_up_required");
    const auto factors = mfa::factors(user->id);
    ASSERT_EQ(factors.size(), 1u);
    const auto remove = [&] { return h::Mfa::removeFactor(json{{"kind", "webauthn"}, {"id", factors[0].id}}, a); };
    EXPECT_EQ(run(a, remove).code, "step_up_required");
    a->stepUp().addGrant(grantFor(a, Family::AccountCredentials));
    EXPECT_TRUE(run(a, [&] { return h::Mfa::registerOptions(json{{"label", "Second"}}, a); }).ok);
    const auto removed = run(a, remove);
    ASSERT_TRUE(removed.ok) << removed.message;
    EXPECT_EQ(removed.data.at("sessions_revoked"), 1) << "the other web session is signed out";
    EXPECT_TRUE(mfa::factors(user->id).empty());
}

// Recovery codes, a refresh token (a reconnect with the cookie) and a paired device never satisfy a step-up.
TEST_F(StepUpDb, RecoveryCodesRefreshTokensAndDevicesNeverSatisfyIt) {
    namespace h = protocols::ws::handler;
    const auto admin = newUser("super_admin");
    const auto s = signedIn(admin);

    // A fresh aal 2 sign-in stands in for a family grant, unless it was a recovery code.
    s->tokens->refreshToken->aal = 2;
    s->tokens->refreshToken->authTime = SysClock::now();
    s->tokens->refreshToken->amr = {"pwd", "rec"};
    {
        const Scope scope(s);
        EXPECT_THROW(require(Family::Settings), ops::StepUpRequired) << "a recovery-code sign-in";
    }
    s->tokens->refreshToken->amr = {"pwd", "hwk"};
    {
        const Scope scope(s);
        EXPECT_NO_THROW(require(Family::Settings));
        EXPECT_THROW(require(Family::DataDestroy, std::string("storage.vault.remove:5")), ops::StepUpRequired)
            << "never for a target-bound family";
    }
    s->tokens->refreshToken->authTime = SysClock::now() - ttl() - std::chrono::seconds(5);
    {
        const Scope scope(s);
        EXPECT_THROW(require(Family::Settings), ops::StepUpRequired) << "an older sign-in";
    }

    // A grant stays on its socket: the same cookie on a new connection has none.
    s->stepUp().addGrant(grantFor(s, Family::Settings));
    const auto reconnect = connect(s->tokens->refreshToken->rawToken);
    ASSERT_TRUE(reconnect->user);
    EXPECT_TRUE(reconnect->stepUp().grants().empty());
    {
        const Scope scope(reconnect);
        EXPECT_THROW(require(Family::Settings), ops::StepUpRequired);
    }

    // A paired device: refused (its connection is never a person's approval; it can ask for one in the console, #361),
    // can't begin a web step-up, and without a key-backup grant (#362) its key export isn't covered either.
    auto peer = std::make_shared<vh::device::Peer>();
    peer->spki.fill(0x42);
    peer->spkiHex = vh::device::crypto::toHex(peer->spki);
    const auto paired = db::query::device::Devices::byCurrentSpki(peer->spkiHex);
    peer->deviceRowId = paired ? paired->id
                               : db::query::device::Devices::insert({.user_id = admin->id, .approved_by = admin->id,
                                                                    .name = "StepUp Mac", .platform = "macOS",
                                                                    .spki_sha256 = peer->spkiHex})
                                     .id;
    const auto device = protocols::ws::Session::devicePrincipal(peer, admin, [] {});
    {
        const Scope scope(device);
        EXPECT_EQ(scope.channel(), Channel::Device);
        try {
            require(Family::IdentityAdmin);
            ADD_FAILURE() << "a device stepped up";
        } catch (const ops::StepUpRequired& e) {
            EXPECT_EQ(e.methods, std::vector<std::string>{"console_approval"});
        }
        EXPECT_FALSE(ops::backup_grants::covering({7}))
            << "a device without a key-backup grant (#362): its key export needs the keys step-up";
    }
    EXPECT_EQ(run(device, [&] { return h::StepUp::begin(json{{"family", "settings"}}, device); }).code, "denied");
    device->close();
}

// Five failed step-ups in 15 minutes revoke the session; logout and invalidation (idle, revocation, policy) drop grants.
TEST_F(StepUpDb, FiveFailuresRevokeTheSessionAndSignOutDropsGrants) {
    namespace h = protocols::ws::handler;
    const auto user = newUser("unprivileged");
    const auto s = signedIn(user);
    const auto jti = s->tokens->refreshToken->jti;
    for (int i = 1; i <= kMaxFailures; ++i) {
        const auto begun = run(s, [&] { return h::StepUp::begin(json{{"family", "settings"}}, s); });
        ASSERT_TRUE(begun.ok) << i << " " << begun.message;
        const auto failed = run(s, [&] {
            return h::StepUp::finish(json{{"stepup_id", begun.data.at("stepup_id")}, {"method", "password"},
                                          {"password", "wrong"}}, s);
        });
        ASSERT_EQ(failed.code, "step_up_failed");
        EXPECT_EQ(failed.data.at("attempts_remaining"), kMaxFailures - i);
    }
    const auto row = db::query::auth::RefreshToken::get(jti);
    ASSERT_TRUE(row);
    EXPECT_TRUE(row->revoked) << "five failures revoke the session";

    const auto other = signedIn(user);
    other->stepUp().addGrant(grantFor(other, Family::Settings));
    (void)h::Auth::logout(other);
    EXPECT_TRUE(other->stepUp().grants().empty()) << "logout";

    const auto third = signedIn(user);
    third->stepUp().addGrant(grantFor(third, Family::Settings));
    sessions().invalidate(third);  // what idle sign-out, revocation and the MFA policy end in
    EXPECT_TRUE(third->stepUp().grants().empty()) << "invalidation";
}

// The regression list: a stolen browser session (signed in, no grant) can't approve a device, turn remote device
// connections on, or make a device.trust grant with what a cookie thief has.
TEST_F(StepUpDb, AStolenBrowserSessionCantApproveADeviceOrMakeAGrant) {
    namespace h = protocols::ws::handler;
    const auto admin = newUser("super_admin");
    const auto s = signedIn(admin);
    const auto pairing = pairingRequest(admin->id, 0x6b);
    auto cfg = config::Registry::get();
    cfg.device_server.remote = false;  // so device.remote.enable reaches its gate (and never writes config.yaml)
    config::Registry::set(cfg);

    const auto approve = run(s, [&] {
        return h::Devices::pairingApprove(json{{"request_id", pairing.request_id}, {"code", pairing.code}}, s);
    });
    ASSERT_EQ(approve.code, "step_up_required");
    EXPECT_EQ(approve.data.at("family"), "device.trust");
    const auto target = approve.data.at("target").get<std::string>();
    EXPECT_TRUE(target.starts_with("device.pairing.approve:" + pairing.request_id + ":"));
    EXPECT_EQ(target.find(pairing.code), std::string::npos) << "the target never carries the code";
    EXPECT_EQ(run(s, [&] { return h::Devices::remoteEnable(s); }).code, "step_up_required");
    EXPECT_EQ(run(s, [&] { return h::Settings::update(json::object(), s); }).code, "step_up_required");
    // A password (all a session thief might add) never makes a device.trust grant.
    EXPECT_EQ(run(s, [&] { return h::StepUp::begin(json{{"family", "device.trust"}, {"target", target}}, s); }).code,
              "step_up_unavailable");
    // A grant for another target doesn't approve this one.
    s->stepUp().addGrant(grantFor(s, Family::DeviceTrust, target + "x"));
    EXPECT_EQ(run(s, [&] {
                  return h::Devices::pairingApprove(json{{"request_id", pairing.request_id}, {"code", pairing.code}},
                                                    s);
              }).code,
              "step_up_required");
}

// data.destroy is bound to the exact removal: a grant for a soft delete doesn't purge the vault now.
TEST_F(StepUpDb, ATargetBoundGrantBindsTheExactAction) {
    namespace h = protocols::ws::handler;
    const auto admin = newUser("super_admin");
    const auto s = signedIn(admin);
    const auto owner = run(s, [&] {
        return h::Auth::registerUser(json{{"name", "su_owner_" + tag()}, {"role", "unprivileged"},
                                          {"password", "Owner-Pass-5-xyz"}}, s);
    });
    s->stepUp().addGrant(grantFor(s, Family::IdentityAdmin));
    const auto created = run(s, [&] {
        return h::Auth::registerUser(json{{"name", "su_owner_" + tag()}, {"role", "unprivileged"},
                                          {"password", "Owner-Pass-5-xyz"}}, s);
    });
    ASSERT_TRUE(created.ok) << created.message;
    EXPECT_EQ(owner.code, "step_up_required");
    const auto vaults = db::query::vault::Vault::listUserVaults(created.data.at("user").at("id").get<uint32_t>());
    if (vaults.empty()) GTEST_SKIP() << "no default vault in this environment";
    const auto id = vaults.front()->id;

    const auto soft = run(s, [&] { return h::Vaults::remove(json{{"id", id}}, s); });
    ASSERT_EQ(soft.code, "step_up_required") << soft.message;
    EXPECT_EQ(soft.data.at("target"), "storage.vault.remove:" + std::to_string(id));
    s->stepUp().addGrant(grantFor(s, Family::DataDestroy, soft.data.at("target").get<std::string>()));
    const auto now = run(s, [&] { return h::Vaults::remove(json{{"id", id}, {"now", true}, {"confirm_now", true}}, s); });
    EXPECT_EQ(now.code, "step_up_required") << "a grant for a soft delete never purges now";
    EXPECT_EQ(now.data.at("target"), "storage.vault.remove:" + std::to_string(id) + ":now");
    const auto removed = run(s, [&] { return h::Vaults::remove(json{{"id", id}}, s); });
    EXPECT_TRUE(removed.ok) << removed.code << " " << removed.message;
}

}
