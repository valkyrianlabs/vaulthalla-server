#include "db/Transactions.hpp"
#include "fs/Filesystem.hpp"
#include "fs/PlaintextSource.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fuse/WorkingCopies.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <algorithm>
#include <chrono>
#include <cstring>
#include <filesystem>
#include <string>
#include <unistd.h>

// #328 review: restoring an unsaved file that was deleted meanwhile is a new write by its last writer, authorized as
// one. A writer who may no longer write there gets nothing created (the daemon's real recover hook, real RBAC).

namespace wcrbac {

using UserPtr = std::shared_ptr<vh::identities::User>;

std::string tag() {
    return std::to_string(::getpid()) + "_" +
           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 1'000'000'000);
}

vh::fs::PlaintextSource bytes(const std::string& text) {
    return {.size = text.size(), .read = [text](const uint64_t offset, const std::span<uint8_t> out) -> std::size_t {
        if (offset >= text.size()) return 0;
        const auto n = std::min<std::size_t>(out.size(), text.size() - offset);
        std::memcpy(out.data(), text.data() + offset, n);
        return n;
    }};
}

}

class WorkingCopyRecoverRbacTest : public ::testing::Test {
protected:
    inline static bool skip = false;
    inline static std::filesystem::path root;
    inline static wcrbac::UserPtr admin, reader;
    inline static std::shared_ptr<vh::storage::Engine> vault;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skip = true;
            return;
        }
        vh::paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_wc_recover_" + wcrbac::tag());
        vh::paths::backingPath = root / "backing";
        vh::paths::mountPath = root / "mount";
        std::filesystem::create_directories(vh::paths::backingPath);
        std::filesystem::create_directories(vh::paths::mountPath);
        vh::db::Transactions::init();
        vh::db::seed::nuke_and_recreate_schema_public();
        vh::db::Transactions::dbPool_->initPreparedStatements();
        vh::seed::seed_database();
        vh::runtime::Deps::init();
        vh::fs::Filesystem::init(vh::runtime::Deps::get().storageManager);
        admin = vh::identities::manager().userByName("admin");
        const auto v = vh::ops::vaults::create(admin, {.name = "wcr_" + wcrbac::tag(), .type = vh::vault::model::VaultType::Local});
        vault = vh::runtime::Deps::get().storageManager->getEngine(v->id);
        const auto created = vh::ops::users::create(admin, {.name = "wcr_reader_" + wcrbac::tag(), .role = "unprivileged",
                                                            .password = std::string("Recover-Rbac-Pass-123")});
        (void)vh::ops::roles::assignVaultRole(admin, {.target = {.vault_id = v->id, .subject = {.type = "user", .id = created.user->id}},
                                                      .role = std::string("reader")});
        reader = vh::identities::manager().user(created.user->id);
    }

    static void TearDownTestSuite() {
        std::error_code ec;
        if (!root.empty()) std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skip) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    // The row the working copy remembers for a file that has since been deleted.
    static vh::fs::model::File lastSeen(const std::string& path) {
        vh::fs::model::File f;
        f.name = std::filesystem::path(path).filename().string();
        f.path = path;
        f.fuse_path = vault->vaultPathToFusePath(path);
        f.vault_id = static_cast<int32_t>(vault->vault->id);
        return f;
    }
};

TEST_F(WorkingCopyRecoverRbacTest, AWriterWhoMayNoLongerWriteThereGetsNothingCreated) {
    const auto hooks = vh::fuse::WorkingCopies::daemonHooks();
    ASSERT_TRUE(hooks.recover);
    const auto last = lastSeen("/notes-reader.txt");
    EXPECT_THROW(hooks.recover(last, wcrbac::bytes("unsaved"), static_cast<int32_t>(reader->id)), std::runtime_error);
    EXPECT_FALSE(vh::runtime::Deps::get().fsCache->entryExists(last.fuse_path));
    // An unknown writer is refused too.
    EXPECT_THROW(hooks.recover(last, wcrbac::bytes("unsaved"), std::nullopt), std::runtime_error);
    EXPECT_FALSE(vh::runtime::Deps::get().fsCache->entryExists(last.fuse_path));
}

TEST_F(WorkingCopyRecoverRbacTest, AWriterWhoMayWriteThereGetsTheFileBack) {
    const auto hooks = vh::fuse::WorkingCopies::daemonHooks();
    const auto last = lastSeen("/notes-admin.txt");
    hooks.recover(last, wcrbac::bytes("unsaved"), static_cast<int32_t>(admin->id));
    EXPECT_TRUE(vh::runtime::Deps::get().fsCache->entryExists(last.fuse_path));
}
