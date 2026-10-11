// The built-in super-admin ('admin') web credential (auth/Bootstrap.hpp). No universal default password: a fresh
// install gets a random one, written once to a plaintext file for the operator; nothing restarts, upgrades or the
// file's deletion reset it; `vh setup set-super-admin-password` (the configured super-admin UID only) rotates it.
// The web console only warns, for the super admin, while the generated password and its file both remain.

#include "db/query/identities/Loader.hpp"
#include "auth/Bootstrap.hpp"
#include "auth/Manager.hpp"
#include "auth/session/Issuer.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "fs/Filesystem.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Users.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Auth.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "UsageManager.hpp"

#include <gtest/gtest.h>
#include <paths.h>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <set>
#include <string>

namespace {
// Credentials are never part of identity state: read the stored hash directly.
std::string hashOf(const uint32_t userId) {
    const auto c = vh::db::query::identities::Loader::credentialsById(userId);
    return c ? c->passwordHash : std::string{};
}
}

namespace vh::test_auth_bootstrap {

using UserPtr = std::shared_ptr<identities::User>;
namespace bootstrap = auth::bootstrap;

constexpr const char* kRetiredDefault = "vh!adm1n";

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

std::string readFile(const std::filesystem::path& path) {
    std::ifstream in(path);
    std::string line;
    std::getline(in, line);
    return line;
}

bool isLowerHex(const std::string& value) {
    return value.find_first_not_of("0123456789abcdef") == std::string::npos;
}

TEST(AuthBootstrap, GeneratedPasswordsAre128BitHexAndUnique) {
    std::set<std::string> seen;
    for (int i = 0; i < 64; ++i) {
        const auto password = bootstrap::generatePassword();
        EXPECT_EQ(password.size(), 32u) << "16 random bytes as hex";
        EXPECT_TRUE(isLowerHex(password)) << password;
        seen.insert(password);
    }
    EXPECT_EQ(seen.size(), 64u);
}

class AuthBootstrapDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_auth_bootstrap] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_bootstrap_" + tag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        seed::reconcileSystemPrincipals();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        auth::session::Issuer::setJwtSecretForTesting("auth-bootstrap-test-secret");
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
    }

    static void TearDownTestSuite() {
        if (!skipTests) auth::session::Issuer::clearJwtSecretForTesting();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static UserPtr admin() { return vh::identities::manager().userByName(bootstrap::kSuperAdminName); }

    // What the daemon does on every start once 'admin' exists (main.cpp initDB).
    static void restart() {
        if (!db::query::identities::User::adminUserExists()) seed::seed_database();
        seed::reconcileSystemPrincipals();
        (void)bootstrap::retireLegacyDefaultPassword();
    }

    // Puts admin back in the "fresh install" state with a known generated password.
    static std::string freshGenerated() {
        const auto hash = bootstrap::issueInitialCredential();
        vh::identities::manager().setPasswordHash(admin()->id, hash);
        return readFile(bootstrap::initialPasswordFile());
    }

    // Protected accounts' linux_uid only changes under the bootstrap guard (as the seed does).
    static void unbindAdminUid() {
        struct Republish { ~Republish() { (void)vh::identities::manager().reconcile(); } } republish;
        db::Transactions::exec("bootstrap::unbindUid", [](pqxx::work& txn) {
            txn.exec("SELECT set_config('vaulthalla.bootstrap', 'on', true)");
            txn.exec("UPDATE users SET linux_uid = NULL WHERE name = 'admin'");
        });
    }

    // As `vh setup assign-admin` does.
    static void bindAdminUid(const unsigned int uid) {
        unbindAdminUid();
        vh::identities::manager().bindLinuxUid(admin()->id, uid, std::nullopt);
    }

    static std::shared_ptr<protocols::ws::Session> wsFor(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->ipAddress = "127.0.0.1";
        s->userAgent = "auth-bootstrap-test";
        s->user = user;
        return s;
    }

    static UserPtr plainUser() {
        const auto created = ops::users::create(admin(), {.name = "bs_plain_" + tag(), .role = "unprivileged",
                                                          .password = std::string("Bootstrap-Test-Pass-123")});
        return vh::identities::manager().user(created.user->id);
    }
};

TEST_F(AuthBootstrapDbTest, AFreshInstallGetsAUniqueGeneratedPasswordWrittenOnce) {
    const auto file = bootstrap::initialPasswordFile();
    ASSERT_TRUE(std::filesystem::exists(file)) << "the seed writes the initial password for the operator";
    const auto password = readFile(file);
    EXPECT_EQ(password.size(), 32u);
    EXPECT_TRUE(isLowerHex(password));
    EXPECT_EQ(std::filesystem::status(file).permissions() & std::filesystem::perms::all,
              std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

    const auto account = admin();
    EXPECT_NE(hashOf(account->id), password) << "stored through the password hash, not in clear";
    EXPECT_TRUE(crypto::hash::verifyPassword(password, hashOf(account->id)));
    EXPECT_FALSE(crypto::hash::verifyPassword(kRetiredDefault, hashOf(account->id)));
    EXPECT_TRUE(bootstrap::superAdminPasswordIsGenerated());
    EXPECT_TRUE(bootstrap::initialPasswordExposed());
}

TEST_F(AuthBootstrapDbTest, RestartsNeverResetTheCredentialOrRecreateADeletedFile) {
    const auto password = freshGenerated();
    const auto hash = hashOf(admin()->id);

    restart();
    EXPECT_EQ(hashOf(admin()->id), hash) << "a restart (or upgrade/reinstall start) re-seeded admin";
    EXPECT_EQ(readFile(bootstrap::initialPasswordFile()), password);

    std::filesystem::remove(bootstrap::initialPasswordFile());
    restart();
    restart();
    EXPECT_FALSE(std::filesystem::exists(bootstrap::initialPasswordFile())) << "a deleted copy came back";
    EXPECT_EQ(hashOf(admin()->id), hash) << "deleting the copy changed the password";
    EXPECT_TRUE(bootstrap::superAdminPasswordIsGenerated()) << "deleting the copy is not a rotation";
    EXPECT_FALSE(bootstrap::initialPasswordExposed());
}

// Every daemon start runs this. Argon2 is deliberately slow (~0.3 s a hash), and the protected principals already
// exist after the first boot, so a reconcile on an existing database hashes nothing and stays cheap.
TEST_F(AuthBootstrapDbTest, ReconcilingExistingPrincipalsHashesNoPasswords) {
    const auto before = hashOf(admin()->id);
    const auto start = std::chrono::steady_clock::now();
    seed::reconcileSystemPrincipals();
    const auto elapsed = std::chrono::steady_clock::now() - start;
    EXPECT_LT(elapsed, std::chrono::milliseconds(250)) << "a password was hashed on a restart";
    EXPECT_EQ(hashOf(admin()->id), before);
    for (const auto* name : {"root", "system"})
        EXPECT_NE(vh::identities::manager().userByName(name), nullptr) << name;

    // The legacy-default check verifies a given hash once; later starts skip the Argon2 verify until it changes.
    EXPECT_FALSE(bootstrap::retireLegacyDefaultPassword());
    const auto again = std::chrono::steady_clock::now();
    EXPECT_FALSE(bootstrap::retireLegacyDefaultPassword());
    EXPECT_LT(std::chrono::steady_clock::now() - again, std::chrono::milliseconds(100)) << "admin's hash was re-verified";
}

TEST_F(AuthBootstrapDbTest, ALegacyDefaultPasswordIsReplacedOnceAndOthersAreLeftAlone) {
    vh::identities::manager().setPasswordHash(admin()->id, crypto::hash::password(kRetiredDefault));
    std::filesystem::remove(bootstrap::initialPasswordFile());
    db::Transactions::exec("bootstrap::legacyState", [](pqxx::work& txn) {
        txn.exec("UPDATE auth_bootstrap_state SET super_admin_password_generated = FALSE");
    });

    EXPECT_TRUE(bootstrap::retireLegacyDefaultPassword());
    const auto password = readFile(bootstrap::initialPasswordFile());
    EXPECT_EQ(password.size(), 32u);
    EXPECT_TRUE(crypto::hash::verifyPassword(password, hashOf(admin()->id)));
    EXPECT_FALSE(crypto::hash::verifyPassword(kRetiredDefault, hashOf(admin()->id)));
    EXPECT_TRUE(bootstrap::superAdminPasswordIsGenerated());
    EXPECT_FALSE(bootstrap::retireLegacyDefaultPassword()) << "it ran twice";

    // An operator-chosen password is never touched, and gets no file or warning.
    vh::identities::manager().setPasswordHash(admin()->id, crypto::hash::password("Operator-Chosen-Pass-77"));
    (void)bootstrap::onSuperAdminPasswordChanged();
    const auto chosen = hashOf(admin()->id);
    restart();
    EXPECT_EQ(hashOf(admin()->id), chosen);
    EXPECT_FALSE(std::filesystem::exists(bootstrap::initialPasswordFile()));
    EXPECT_FALSE(bootstrap::superAdminPasswordIsGenerated());
}

TEST_F(AuthBootstrapDbTest, OnlyTheConfiguredSuperAdminUidMaySetThePassword) {
    (void)freshGenerated();
    unbindAdminUid();
    EXPECT_THROW((void)ops::users::setSuperAdminPassword(admin(), "Rotated-Pass-1234567"), ops::Denied)
        << "no super-admin UID is configured yet";

    bindAdminUid(64001);
    const auto root = vh::identities::manager().userByName("root");
    const auto system = vh::identities::manager().userByName("system");
    const auto plain = plainUser();
    for (const auto& other : {root, system, plain}) {
        ASSERT_TRUE(other);
        EXPECT_THROW((void)ops::users::setSuperAdminPassword(other, "Rotated-Pass-1234567"), ops::Denied) << other->name();
    }
    EXPECT_TRUE(bootstrap::superAdminPasswordIsGenerated()) << "a refused attempt changed state";

    // Through the CLI router: refused before any prompt for anyone else; the super admin needs a terminal.
    const auto router = std::make_shared<protocols::shell::Router>();
    protocols::shell::commands::registerSetupCommands(router);
    const auto refused = router->executeLine("setup set-super-admin-password", plain, nullptr);
    EXPECT_NE(refused.exit_code, 0);
    EXPECT_NE(refused.stderr_text.find("only the Linux user bound as the Vaulthalla super admin"), std::string::npos)
        << refused.stderr_text;
    const auto noTerminal = router->executeLine("setup set-super-admin-password", admin(), nullptr);
    EXPECT_NE(noTerminal.exit_code, 0);
    EXPECT_NE(noTerminal.stderr_text.find("interactive terminal"), std::string::npos) << noTerminal.stderr_text;
}

TEST_F(AuthBootstrapDbTest, RotationTakesEffectAndRemovesTheFile) {
    const auto generated = freshGenerated();
    bindAdminUid(64002);

    const auto result = ops::users::setSuperAdminPassword(admin(), "Rotated-Pass-1234567");
    EXPECT_FALSE(result.leftover_file);
    EXPECT_TRUE(crypto::hash::verifyPassword("Rotated-Pass-1234567", hashOf(admin()->id)));
    EXPECT_FALSE(crypto::hash::verifyPassword(generated, hashOf(admin()->id)));
    EXPECT_FALSE(std::filesystem::exists(bootstrap::initialPasswordFile()));
    EXPECT_FALSE(bootstrap::superAdminPasswordIsGenerated());

    auto session = wsFor(nullptr);
    runtime::Deps::get().sessionManager->rotateRefreshToken(session);
    EXPECT_NO_THROW(runtime::Deps::get().authManager->loginUser("admin", "Rotated-Pass-1234567", session));
}

TEST_F(AuthBootstrapDbTest, AFileThatCannotBeRemovedIsReportedNotRolledBack) {
    (void)freshGenerated();
    bindAdminUid(64003);
    // Something removal can't delete in its place: a non-empty directory with the file's name.
    std::filesystem::remove(bootstrap::initialPasswordFile());
    std::filesystem::create_directories(bootstrap::initialPasswordFile() / "stuck");

    const auto result = ops::users::setSuperAdminPassword(admin(), "Rotated-Pass-7654321");
    EXPECT_TRUE(result.leftover_file);
    EXPECT_TRUE(crypto::hash::verifyPassword("Rotated-Pass-7654321", hashOf(admin()->id)))
        << "a failed cleanup undid the password change";
    EXPECT_FALSE(bootstrap::superAdminPasswordIsGenerated());

    std::filesystem::remove_all(bootstrap::initialPasswordFile());
}

TEST_F(AuthBootstrapDbTest, AChangeFromTheWebConsoleCountsAsARotation) {
    const auto generated = freshGenerated();
    (void)ops::users::changePassword(admin(), admin()->id, generated, "Web-Changed-Pass-123");
    EXPECT_FALSE(bootstrap::superAdminPasswordIsGenerated());
    EXPECT_FALSE(std::filesystem::exists(bootstrap::initialPasswordFile()));
}

TEST_F(AuthBootstrapDbTest, TheWebWarningIsForTheSuperAdminOnlyAndClearsWhenTheFileGoes) {
    const auto generated = freshGenerated();

    // Signing in with the generated password gives a normal, fully usable session.
    auto session = wsFor(nullptr);
    runtime::Deps::get().sessionManager->rotateRefreshToken(session);
    ASSERT_NO_THROW(runtime::Deps::get().authManager->loginUser("admin", generated, session));
    ASSERT_TRUE(session->user);

    const auto status = protocols::ws::handler::Auth::securityStatus(session);
    ASSERT_TRUE(status.at("initial_password_file").is_string());
    EXPECT_EQ(status.at("initial_password_file").get<std::string>(), bootstrap::initialPasswordFile().string());

    const auto plainStatus = protocols::ws::handler::Auth::securityStatus(wsFor(plainUser()));
    EXPECT_TRUE(plainStatus.at("initial_password_file").is_null()) << "a non-admin account got the warning";

    // Keeping the generated password and deleting its copy clears the warning without a rotation.
    ASSERT_FALSE(bootstrap::removeInitialPasswordFile());
    EXPECT_TRUE(protocols::ws::handler::Auth::securityStatus(session).at("initial_password_file").is_null());
    EXPECT_TRUE(bootstrap::superAdminPasswordIsGenerated());
    EXPECT_TRUE(crypto::hash::verifyPassword(generated, hashOf(admin()->id)));
}

}
