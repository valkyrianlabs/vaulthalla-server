// vh-test-tier: db-only
// Importing the MFA keys on a new host (#398; follows #356, #393): `vh secret set mfa-seal|mfa-pepper <file>` takes what
// `vh secret export` wrote. A database restored onto a fresh state directory (no mfa_seal / mfa_pepper rows) plus both
// imports keeps TOTP and recovery codes working with no re-enrollment; a mismatched key is refused and changes nothing;
// only a super admin may import, and every attempt is audited without the key or the code. The host here is simulated
// by a secrets manager with no rows (Manager::createForTesting), so no real sealing is involved.
#include "../helpers/db_suite.hpp"
#include "../helpers/web_session.hpp"
#include "audit/Trail.hpp"
#include "auth/mfa/Factors.hpp"
#include "auth/mfa/Keys.hpp"
#include "auth/mfa/Totp.hpp"
#include "crypto/secrets/Manager.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/MfaKeys.hpp"
#include "ops/Users.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "runtime/Deps.hpp"
#include "UsageManager.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <unistd.h>
#include <vector>

namespace vh::auth::mfa::test_key_import {

using Clock = std::chrono::system_clock;
using UserPtr = std::shared_ptr<identities::User>;
using json = nlohmann::json;

using vh::test::web::fromBase32;

std::vector<uint8_t> randomKey() {
    std::vector<uint8_t> k(32);
    randombytes_buf(k.data(), k.size());
    return k;
}

class MfaKeyImportDb : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static std::atomic<int> counter{0};
    inline static std::shared_ptr<crypto::secrets::Manager> originalSecrets;  // Deps outlive this suite

    static void SetUpTestSuite() {
        if (!setUpDbSuite("mfa_key_import")) return;
        originalSecrets = runtime::Deps::get().secretsManager;
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        audit::Trail::instance()->resetForTesting();
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerSecretsCommands(router);
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        runtime::Deps::get().secretsManager = originalSecrets;
        keys::resetForTesting();
        tearDownDbSuite();
    }

    // A host that has these keys (rows in its secrets manager), or none (a fresh state directory).
    static void hostWith(const std::vector<uint8_t>& seal, const std::vector<uint8_t>& pepper) {
        std::unordered_map<std::string, std::string> rows;
        if (!seal.empty()) rows[keys::kSealName] = std::string(seal.begin(), seal.end());
        if (!pepper.empty()) rows[keys::kPepperName] = std::string(pepper.begin(), pepper.end());
        runtime::Deps::get().secretsManager = crypto::secrets::Manager::createForTesting(std::move(rows));
        keys::resetForTesting();
    }

    static bool hasRow(const char* name) { return runtime::Deps::get().secretsManager->hasSecret(name); }

    static std::string rowBytes(const char* name) {
        return runtime::Deps::get().secretsManager->getSecret(name).value_or("");
    }

    static protocols::shell::CommandResult cli(const std::string& line, const UserPtr& user) {
        return router->executeLine(line, user, nullptr);
    }

    static UserPtr createUser(const std::string& role) {
        const auto created = ops::users::create(
            superUser, {.name = "mfakey_" + std::to_string(::getpid()) + "_" + std::to_string(++counter), .role = role,
                        .password = std::string("Mfa-Key-Import-Pass-123")});
        return identities::manager().user(created.user->id);
    }

    static std::string writeExport(const std::string& name, const std::vector<uint8_t>& key) {
        const auto path = (root / (name + "_" + std::to_string(++counter) + ".json")).string();
        const auto b64 = crypto::util::b64_encode(key);
        std::ofstream(path) << json::array({json{{"name", name}, {"encoding", "base64"}, {"secret", b64}}}).dump(4);
        return path;
    }

    static long long auditCount(const std::string& outcome) {
        (void)audit::Trail::instance()->flushNow();
        return db::Transactions::exec("mfaKeyImport::audit", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = 'secrets.mfa_key.import' AND outcome = $1",
                            pqxx::params{outcome}).one_field().as<long long>();
        });
    }

    static long long auditMentioning(const std::string& needle) {
        (void)audit::Trail::instance()->flushNow();
        return db::Transactions::exec("mfaKeyImport::auditText", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM audit_event WHERE message LIKE $1 OR details::text LIKE $1",
                            pqxx::params{"%" + needle + "%"}).one_field().as<long long>();
        });
    }
};

TEST_F(MfaKeyImportDb, ARestoreOnAFreshHostPlusBothImportsKeepsTotpAndRecoveryCodesWorking) {
    const auto seal = randomKey(), pepper = randomKey();
    hostWith(seal, pepper);

    // The old host: a confirmed TOTP factor and an acknowledged recovery code batch for the admin.
    const auto uid = superUser->id;
    auto started = startTotp(uid, {.label = "Phone", .account = "admin"});
    const auto seed = fromBase32(started.secret_base32);
    const auto enrolledAt = Clock::now();
    ASSERT_TRUE(confirmTotp(uid, started.factor_id, totp::code(seed, totp::stepAt(enrolledAt)), enrolledAt));
    auto batch = generateRecoveryCodes(uid);
    ASSERT_EQ(acknowledgeRecoveryCodes(uid, batch.batch_id), batch.codes.size());
    const std::string code = batch.codes.front();

    // `vh secret export` writes the format the import takes.
    const auto sealFile = (root / "export-seal.json").string(), pepperFile = (root / "export-pepper.json").string();
    ASSERT_EQ(cli("secret export mfa-seal --output " + sealFile, superUser).exit_code, 0);
    ASSERT_EQ(cli("secret export mfa-pepper --output " + pepperFile, superUser).exit_code, 0);

    // The new host: the database came over, the state directory did not (no rows, so the keys are unavailable).
    hostWith({}, {});
    const auto later = enrolledAt + std::chrono::seconds(90);
    EXPECT_THROW((void)verifyTotp(uid, totp::code(seed, totp::stepAt(later)), later), keys::Unavailable);
    EXPECT_THROW((void)useRecoveryCode(uid, code), keys::Unavailable);
    ASSERT_FALSE(hasRow(keys::kSealName));
    ASSERT_FALSE(hasRow(keys::kPepperName));

    // Without a confirmation nothing is adopted.
    const auto asked = cli("secret set mfa-seal " + sealFile, superUser);
    EXPECT_NE(asked.exit_code, 0);
    ASSERT_TRUE(asked.confirmation);
    EXPECT_EQ(asked.confirmation->code, "mfa_seal_import");
    EXPECT_FALSE(hasRow(keys::kSealName));

    const auto successBefore = auditCount("success");
    const auto sealed = cli("secret set mfa-seal " + sealFile + " --yes", superUser);
    ASSERT_EQ(sealed.exit_code, 0) << sealed.stderr_text << sealed.stdout_text;
    EXPECT_EQ(rowBytes(keys::kSealName), std::string(seal.begin(), seal.end()));
    const auto b64Seal = crypto::util::b64_encode(seal);
    EXPECT_EQ(sealed.stdout_text.find(b64Seal), std::string::npos) << "the key is never printed";
    EXPECT_NE(verifyTotp(uid, totp::code(seed, totp::stepAt(later)), later), std::nullopt) << "TOTP works again";

    // The pepper needs a recovery code of the actor's own.
    EXPECT_NE(cli("secret set mfa-pepper " + pepperFile + " --yes", superUser).exit_code, 0) << "--code is required";
    const auto sealedPepper = cli("secret set mfa-pepper " + pepperFile + " --code " + code + " --yes", superUser);
    ASSERT_EQ(sealedPepper.exit_code, 0) << sealedPepper.stderr_text << sealedPepper.stdout_text;
    EXPECT_EQ(rowBytes(keys::kPepperName), std::string(pepper.begin(), pepper.end()));
    EXPECT_EQ(sealedPepper.stdout_text.find(crypto::util::b64_encode(pepper)), std::string::npos);
    EXPECT_TRUE(useRecoveryCode(uid, code)) << "the recovery code works again";

    // Both audited, neither key nor code in the trail.
    EXPECT_EQ(auditCount("success"), successBefore + 2);
    EXPECT_EQ(auditMentioning(b64Seal), 0);
    EXPECT_EQ(auditMentioning(crypto::util::b64_encode(pepper)), 0);
    EXPECT_EQ(auditMentioning(code), 0);

    // A working key is never replaced: importing again (even the right key) is refused and changes nothing.
    const auto failuresBefore = auditCount("failure");
    EXPECT_NE(cli("secret set mfa-seal " + sealFile + " --yes", superUser).exit_code, 0);
    EXPECT_NE(cli("secret set mfa-pepper " + pepperFile + " --code " + code + " --yes", superUser).exit_code, 0);
    EXPECT_EQ(rowBytes(keys::kSealName), std::string(seal.begin(), seal.end()));
    EXPECT_EQ(rowBytes(keys::kPepperName), std::string(pepper.begin(), pepper.end()));
    EXPECT_EQ(auditCount("failure"), failuresBefore + 2);
}

TEST_F(MfaKeyImportDb, AMismatchedKeyIsRefusedAndNothingChanges) {
    const auto seal = randomKey(), pepper = randomKey();
    hostWith(seal, pepper);
    const auto uid = superUser->id;
    auto started = startTotp(uid, {.label = "Phone", .account = "admin"});
    const auto seed = fromBase32(started.secret_base32);
    const auto now = Clock::now();
    ASSERT_TRUE(confirmTotp(uid, started.factor_id, totp::code(seed, totp::stepAt(now)), now));
    auto batch = generateRecoveryCodes(uid);
    ASSERT_EQ(acknowledgeRecoveryCodes(uid, batch.batch_id), batch.codes.size());
    hostWith({}, {});

    const auto before = auditCount("failure");
    // A key that is not this database's: refused for the seal, and for the pepper whether the key or the code is off.
    const auto wrongSeal = writeExport("mfa-seal", randomKey());
    const auto wrongPepper = writeExport("mfa-pepper", randomKey());
    const auto rightPepper = writeExport("mfa-pepper", pepper);
    EXPECT_NE(cli("secret set mfa-seal " + wrongSeal + " --yes", superUser).exit_code, 0);
    EXPECT_NE(cli("secret set mfa-pepper " + wrongPepper + " --code " + batch.codes[0] + " --yes", superUser).exit_code, 0);
    EXPECT_NE(cli("secret set mfa-pepper " + rightPepper + " --code AAAAA-AAAAA --yes", superUser).exit_code, 0)
        << "a code that is not stored";
    EXPECT_NE(cli("secret set mfa-pepper " + rightPepper + " --code nonsense --yes", superUser).exit_code, 0);
    // Not an export file at all, or the wrong entry.
    const auto junk = (root / "junk.json").string();
    std::ofstream(junk) << "not json";
    EXPECT_NE(cli("secret set mfa-seal " + junk + " --yes", superUser).exit_code, 0);
    EXPECT_NE(cli("secret set mfa-seal " + rightPepper + " --yes", superUser).exit_code, 0) << "the entry is mfa-pepper";

    EXPECT_FALSE(hasRow(keys::kSealName));
    EXPECT_FALSE(hasRow(keys::kPepperName));
    EXPECT_THROW((void)verifyTotp(uid, "000000", now), keys::Unavailable);
    EXPECT_GE(auditCount("failure"), before + 4);
}

TEST_F(MfaKeyImportDb, OnlyASuperAdminMayImportAndNothingStoredMeansNothingToImport) {
    const auto seal = randomKey();
    hostWith(seal, {});
    const auto uid = superUser->id;
    auto started = startTotp(uid, {.label = "Phone", .account = "admin"});
    const auto now = Clock::now();
    ASSERT_TRUE(confirmTotp(uid, started.factor_id, totp::code(fromBase32(started.secret_base32), totp::stepAt(now)), now));
    hostWith({}, {});
    const auto file = writeExport("mfa-seal", seal);

    const auto admin = createUser("admin");
    const auto deniedBefore = auditCount("denied");
    EXPECT_NE(cli("secret set mfa-seal " + file + " --yes", admin).exit_code, 0);
    EXPECT_THROW((void)ops::mfa_keys::import(admin, ops::mfa_keys::Key::Seal, seal, "", true), ops::Denied);
    EXPECT_GT(auditCount("denied"), deniedBefore);
    EXPECT_FALSE(hasRow(keys::kSealName));

    // The pepper: no recovery code is stored anywhere, so there is nothing for it to protect.
    const auto pepperFile = writeExport("mfa-pepper", randomKey());
    EXPECT_NE(cli("secret set mfa-pepper " + pepperFile + " --code AAAAA-AAAAA --yes", superUser).exit_code, 0);
    EXPECT_FALSE(hasRow(keys::kPepperName));

    // The super admin succeeds with the same file.
    EXPECT_EQ(cli("secret set mfa-seal " + file + " --yes", superUser).exit_code, 0);
    EXPECT_TRUE(hasRow(keys::kSealName));
}

}
