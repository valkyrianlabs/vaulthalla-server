// #393: the host master ('master', test_master in test mode) wraps every internal_secrets row: the MFA keys, the
// share-link pepper, email provider credentials and the JWT secret. A missing sealed blob is never replaced while any
// of those but the JWT secret are on record (MasterSecretLost, with the recovery steps); a fresh install still
// generates it. Each test runs in its own backing directory, which is how a lost or restored state directory looks;
// a restore carries the .sealed_test_* blobs over, as the fixtures that swap backing paths do.

#include "crypto/secrets/Dependents.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/secrets/Manager.hpp"
#include "db/Transactions.hpp"
#include "seed/include/init_db_tables.hpp"

#include <gtest/gtest.h>
#include <paths.h>
#include <pqxx/pqxx>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace vh::test_host_master_guard {

namespace secrets = crypto::secrets;

class HostMasterGuardTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::string skipWhy;
    inline static std::filesystem::path root, savedBacking;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            skipWhy = "Skipping db tests due to missing environment variables.";
            std::cout << "[test_host_master_guard] " << skipWhy << std::endl;
            return;
        }
        paths::enableTestMode();
        savedBacking = paths::backingPath;
        root = std::filesystem::temp_directory_path() /
               ("vh_host_master_guard_" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 1000000));
        std::filesystem::create_directories(root);
        paths::backingPath = root / "probe";
        std::filesystem::create_directories(paths::backingPath);
        // These tests generate and then unseal; a backend that can't (CI's container TPM) skips them.
        try {
            std::vector<uint8_t> first;
            {
                secrets::KeyProvider probe("test_host_guard_probe");
                probe.init();
                first.assign(probe.getMasterKey().begin(), probe.getMasterKey().end());
            }
            secrets::KeyProvider again("test_host_guard_probe");
            again.init();
            if (!std::ranges::equal(again.getMasterKey(), first)) throw std::runtime_error("a different secret");
        } catch (const std::exception& e) {
            skipTests = true;
            skipWhy = std::string("sealing doesn't round-trip on this host: ") + e.what();
            return;
        }
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
    }

    static void TearDownTestSuite() {
        if (!root.empty()) {
            paths::backingPath = savedBacking;
            std::error_code ec;
            std::filesystem::remove_all(root, ec);
        }
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << skipWhy;
        clearInternalSecrets();
    }

    void TearDown() override {
        if (skipTests) return;
        clearInternalSecrets();  // later suites start from an empty table, as after a schema reset
    }

    static void clearInternalSecrets() {
        db::Transactions::exec("hostMasterGuard::clear", [](pqxx::work& txn) { txn.exec("DELETE FROM internal_secrets"); });
    }

    // A state directory of its own (empty: a lost one, or a new host).
    static std::filesystem::path stateDir(const std::string& name) {
        static std::atomic<unsigned> n{0};
        const auto dir = root / (name + "_" + std::to_string(n.fetch_add(1)));
        std::filesystem::create_directories(dir);
        paths::backingPath = dir;
        return dir;
    }

    // Restores a state directory: the test-mode sealed blobs come along (never a real install's).
    static void carrySealedBlobs(const std::filesystem::path& from, const std::filesystem::path& to) {
        for (const auto& item : std::filesystem::directory_iterator(from))
            if (item.path().filename().string().starts_with(".sealed_test_"))
                std::filesystem::copy(item.path(), to / item.path().filename(),
                                      std::filesystem::copy_options::recursive |
                                          std::filesystem::copy_options::overwrite_existing);
    }

    static bool hostMasterSealed() { return secrets::KeyProvider("test_master").sealedExists(); }

    static long long rows() {
        return db::Transactions::exec("hostMasterGuard::rows", [](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM internal_secrets").one_field_ref().as<long long>();
        });
    }
};

TEST_F(HostMasterGuardTest, AFreshInstallGeneratesTheHostMaster) {
    (void)stateDir("fresh");
    ASSERT_FALSE(hostMasterSealed());
    EXPECT_FALSE(secrets::dependents::internalSecrets()());
    const secrets::Manager manager;
    EXPECT_TRUE(hostMasterSealed());
    const auto jwt = manager.jwtSecret();
    EXPECT_EQ(jwt.size(), 64u);
    manager.setSecret("host_guard_fresh", "value");
    EXPECT_EQ(manager.getSecret("host_guard_fresh").value_or(""), "value");
}

TEST_F(HostMasterGuardTest, OnlyRegenerableRowsOnRecordStillGenerate) {
    // A JWT secret sealed under a lost master, and the plaintext pepper row of releases before #322: neither depends
    // on the host master (the JWT secret regenerates; the plaintext pepper is converted on first use).
    db::Transactions::exec("hostMasterGuard::regenerable", [](pqxx::work& txn) {
        txn.exec("INSERT INTO internal_secrets (key, value, iv) VALUES ('jwt_secret', '\\x0102'::bytea, "
                 "'\\x0304'::bytea), ('share.token.pepper.v1', '\\x0506'::bytea, '\\x'::bytea)");
    });
    EXPECT_FALSE(secrets::dependents::internalSecrets()());
    (void)stateDir("regenerable");
    const secrets::Manager manager;
    EXPECT_TRUE(hostMasterSealed());
    EXPECT_EQ(manager.jwtSecret().size(), 64u) << "the unreadable JWT secret is replaced";
}

TEST_F(HostMasterGuardTest, AMissingBlobWithInternalSecretsRefusesAndSealsNothing) {
    (void)stateDir("original");
    {
        const secrets::Manager manager;
        manager.setSecret("mfa_seal", "a-key-only-this-master-opens");
        manager.setSecret("share.token.pepper.sealed.v1", "a-pepper-only-this-master-opens");
    }
    const auto described = secrets::dependents::internalSecrets()();
    ASSERT_TRUE(described);
    EXPECT_NE(described->find("2 internal secret(s)"), std::string::npos) << *described;

    const auto lost = stateDir("lost");
    try {
        const secrets::Manager manager;
        ADD_FAILURE() << "a lost host master must not be regenerated over internal secrets";
    } catch (const secrets::MasterSecretLost& e) {
        const std::string what = e.what();
        EXPECT_NE(what.find("test_master"), std::string::npos) << what;
        EXPECT_NE(what.find("mfa_seal"), std::string::npos) << what;
        EXPECT_NE(what.find("share.token.pepper.sealed.v1"), std::string::npos) << what;
        EXPECT_NE(what.find("Restore the state directory"), std::string::npos) << what;
        EXPECT_NE(what.find("a-lost-host-master"), std::string::npos) << what;
    }
    EXPECT_FALSE(hostMasterSealed()) << "nothing may be sealed in its place";
    for (const auto& item : std::filesystem::directory_iterator(lost))
        ADD_FAILURE() << "left behind: " << item.path().filename();
    EXPECT_EQ(rows(), 2) << "the internal secrets are untouched";
}

TEST_F(HostMasterGuardTest, TheRestoredStateDirectoryOpensThemAgain) {
    const auto original = stateDir("original");
    {
        const secrets::Manager manager;
        manager.setSecret("mfa_pepper", "kept-across-the-restore");
    }
    const auto lost = stateDir("lost");
    EXPECT_THROW({ const secrets::Manager manager; }, secrets::MasterSecretLost);

    carrySealedBlobs(original, lost);
    const secrets::Manager manager;
    EXPECT_EQ(manager.getSecret("mfa_pepper").value_or(""), "kept-across-the-restore");
}

TEST_F(HostMasterGuardTest, GivingTheSecretsUpExplicitlyLetsANewHostStart) {
    (void)stateDir("old_host");
    {
        const secrets::Manager manager;
        manager.setSecret("mfa_seal", "lost-with-the-old-host");
        (void)manager.jwtSecret();
    }
    (void)stateDir("new_host");
    EXPECT_THROW({ const secrets::Manager manager; }, secrets::MasterSecretLost);
    EXPECT_FALSE(hostMasterSealed());

    // docs: vaults/secrets-and-key-export#a-lost-host-master (the factor tables are empty here).
    db::Transactions::exec("hostMasterGuard::giveUp", [](pqxx::work& txn) {
        txn.exec("DELETE FROM internal_secrets WHERE key NOT IN ('jwt_secret', 'share.token.pepper.v1')");
        txn.exec("DELETE FROM totp_factors");
        txn.exec("DELETE FROM recovery_codes");
    });
    const secrets::Manager manager;
    EXPECT_TRUE(hostMasterSealed());
    EXPECT_EQ(manager.jwtSecret().size(), 64u);
}

}
