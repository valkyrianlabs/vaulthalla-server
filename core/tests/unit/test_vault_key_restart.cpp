// A daemon restart in the middle of a vault key rotation (prepared, not finished) must load both keys again. The old
// key used to be read with SELECT * from vault_keys_trashed, which has no updated_at column, so vault::model::Key
// threw and the vault's key could not be loaded at all until the rotation was finished by hand.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_vault_key_restart {

namespace stdfs = std::filesystem;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "r" + std::to_string(n.fetch_add(1));
}

class VaultKeyRestartDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> superUser;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_vault_key_restart] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = stdfs::temp_directory_path() / ("vh_vault_key_restart_" + tag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        stdfs::create_directories(paths::backingPath);
        stdfs::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);

        const auto user = vh::test::identities::createUser("vkr_super_" + tag(),
                                                           db::query::rbac::role::Admin::get("super_admin"),
                                                           "vkr@vaulthalla.test", "x", std::nullopt);
        superUser = vh::identities::manager().user(user->id);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }
};

TEST_F(VaultKeyRestartDbTest, ARestartMidRotationLoadsBothKeys) {
    const auto v = ops::vaults::create(superUser, {.name = "vkr_" + tag(), .type = vault::model::VaultType::Local});
    const auto em = runtime::Deps::get().storageManager->getEngine(v->id)->encryptionManager;
    const auto first = em->get_key_version();

    std::vector<uint8_t> plain(4096);
    randombytes_buf(plain.data(), plain.size());
    auto f = std::make_shared<fs::model::File>();
    const auto sealed = em->encrypt(plain, f);

    em->prepare_key_rotation();
    ASSERT_TRUE(em->rotation_in_progress());

    // What startup does: a manager loaded from the database.
    std::unique_ptr<vault::EncryptionManager> fresh;
    ASSERT_NO_THROW(fresh = std::make_unique<vault::EncryptionManager>(v->id));
    EXPECT_TRUE(fresh->rotation_in_progress());
    EXPECT_EQ(fresh->get_key_version(), first + 1);
    EXPECT_EQ(fresh->decrypt(sealed, f->encryption_iv, first), plain);   // files not yet re-encrypted stay readable

    em->finish_key_rotation();
}

}
