// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// #256: fs.entry.move / fs.entry.rename (and FUSE rename) authorized Move/Rename on the source only, so a user who may
// move something could put it into a folder they may not write. Moving or renaming into another folder now needs what
// creating the entry there needs (Touch for a folder, Write for a file, as fs.dir.create / an upload / each entry of
// fs.entry.copy), for the entry and everything a folder carries. A rename within its own folder is unchanged. The
// FUSE side is proven in Tier A ("Move Into Unwritable Folder").

#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/fs/Storage.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "vault/model/Vault.hpp"
#include "db/Transactions.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace vh::test_fs_move_authz {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
using Handler = std::function<json(const json&, const std::shared_ptr<protocols::ws::Session>&)>;

std::string maTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "m" + std::to_string(n.fetch_add(1));
}

const std::vector<std::pair<std::string, Handler>>& handlers() {
    static const std::vector<std::pair<std::string, Handler>> all{
        {"fs.entry.move", &protocols::ws::handler::fs::Storage::move},
        {"fs.entry.rename", &protocols::ws::handler::fs::Storage::rename},
    };
    return all;
}

class FsMoveAuthzDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    EnginePtr engine;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_fs_move_authz] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_fs_move_authz_" + maTag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        // Earlier suites in this binary used their own schema: their cached entries and engines (ids reused after the
        // reset) would answer for ours.
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = vh::identities::manager().userByName("admin");

        // The ws handlers ask the sync controller for an early pass; an unstarted one just queues it.
        previousController = runtime::Deps::get().syncController;
        runtime::Deps::setSyncController(std::make_shared<sync::Controller>());
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        runtime::Deps::setSyncController(previousController);
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        const auto vault = ops::vaults::create(superUser, {.name = "ma_" + maTag(),
                                                           .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);
        for (const auto* dir : {"/src", "/src/dir", "/src/empty", "/locked", "/open", "/drop"})
            engine->mkdir(dir, superUser);
        write("/src/a.txt", "alpha\n");
        write("/src/dir/inner.txt", "inner\n");
    }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    [[nodiscard]] bool exists(const std::string& path) const {
        return runtime::Deps::get().fsCache->entryExists(engine->vaultPathToFusePath(path));
    }

    static std::shared_ptr<protocols::ws::Session> wsAs(const UserPtr& user) {
        auto session = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        session->user = user;
        return session;
    }

    [[nodiscard]] json payload(const std::string& from, const std::string& to) const {
        return {{"vault_id", engine->vault->id}, {"from", from}, {"to", to}};
    }

    // A power user (may move, rename, upload and create folders anywhere) except for `denied` under `pattern`.
    [[nodiscard]] UserPtr powerUserDenied(const std::vector<std::string>& denied, const std::string& pattern) const {
        const auto created = ops::users::create(superUser, {.name = "ma_user_" + maTag(), .role = "unprivileged",
                                                            .password = std::string("Move-Authz-Pass-123")});
        const ops::roles::VaultSubject target{.vault_id = engine->vault->id,
                                              .subject = {.type = "user", .id = created.user->id}};
        (void)ops::roles::assignVaultRole(superUser, {.target = target, .role = std::string("power_user")});
        ops::roles::PermissionEdit edit;
        for (const auto& p : denied) edit.changes.emplace_back(p, false);
        (void)ops::roles::addVaultRoleOverrides(superUser, {.target = target, .permissions = edit, .pattern = pattern});
        return vh::identities::manager().user(created.user->id);
    }

    // May not create anything (file or folder) under /locked.
    [[nodiscard]] UserPtr lockedOut() const {
        return powerUserDenied({"vault.fs.files.upload", "vault.fs.directories.touch"}, "/locked/**");
    }
};

TEST_F(FsMoveAuthzDbTest, IntoAFolderTheCallerCannotWriteIsDeniedAndNothingMoves) {
    const auto user = lockedOut();
    for (const auto& [command, handler] : handlers()) {
        SCOPED_TRACE(command);
        EXPECT_THROW((void)handler(payload("/src/a.txt", "/locked/a.txt"), wsAs(user)), ops::Denied);
        EXPECT_TRUE(exists("/src/a.txt"));
        EXPECT_FALSE(exists("/locked/a.txt"));

        EXPECT_THROW((void)handler(payload("/src/dir", "/locked/dir"), wsAs(user)), ops::Denied);
        EXPECT_TRUE(exists("/src/dir/inner.txt"));
        EXPECT_FALSE(exists("/locked/dir"));
    }
}

TEST_F(FsMoveAuthzDbTest, IntoAWritableFolderIsAllowed) {
    const auto user = lockedOut();
    (void)protocols::ws::handler::fs::Storage::move(payload("/src/a.txt", "/open/a.txt"), wsAs(user));
    EXPECT_TRUE(exists("/open/a.txt"));
    EXPECT_FALSE(exists("/src/a.txt"));

    (void)protocols::ws::handler::fs::Storage::rename(payload("/src/dir", "/open/moved"), wsAs(user));
    EXPECT_TRUE(exists("/open/moved/inner.txt"));
    EXPECT_FALSE(exists("/src/dir"));

    // The admin is never refused.
    (void)protocols::ws::handler::fs::Storage::move(payload("/open/a.txt", "/locked/a.txt"), wsAs(superUser));
    EXPECT_TRUE(exists("/locked/a.txt"));
}

// Renaming within its own folder adds nothing to that folder: the source's Rename/Move is enough, as before, even for
// a caller who may not create anything there.
TEST_F(FsMoveAuthzDbTest, WithinTheSameFolderOnlyTheSourceCheckApplies) {
    const auto user = powerUserDenied({"vault.fs.files.upload", "vault.fs.directories.touch"}, "/src/**");
    (void)protocols::ws::handler::fs::Storage::rename(payload("/src/a.txt", "/src/b.txt"), wsAs(user));
    EXPECT_TRUE(exists("/src/b.txt"));
    (void)protocols::ws::handler::fs::Storage::move(payload("/src/dir", "/src/dir2"), wsAs(user));
    EXPECT_TRUE(exists("/src/dir2/inner.txt"));

    // ... and the source check itself still applies.
    const auto noRename = powerUserDenied({"vault.fs.files.rename", "vault.fs.files.move"}, "/src/**");
    EXPECT_THROW((void)protocols::ws::handler::fs::Storage::rename(payload("/src/b.txt", "/src/c.txt"), wsAs(noRename)),
                 ops::Denied);
    EXPECT_THROW((void)protocols::ws::handler::fs::Storage::move(payload("/src/b.txt", "/src/c.txt"), wsAs(noRename)),
                 ops::Denied);
    EXPECT_TRUE(exists("/src/b.txt"));
}

// A folder needs Touch at its new place, a file Write; a folder carries its contents, each checked at its new path
// (as fs.entry.copy checks every entry it writes).
TEST_F(FsMoveAuthzDbTest, AFolderNeedsTouchAndCarriesItsContents) {
    const auto user = powerUserDenied({"vault.fs.files.upload"}, "/drop/**");

    EXPECT_THROW((void)protocols::ws::handler::fs::Storage::move(payload("/src/a.txt", "/drop/a.txt"), wsAs(user)),
                 ops::Denied);
    EXPECT_TRUE(exists("/src/a.txt"));

    (void)protocols::ws::handler::fs::Storage::move(payload("/src/empty", "/drop/empty"), wsAs(user));
    EXPECT_TRUE(exists("/drop/empty"));

    EXPECT_THROW((void)protocols::ws::handler::fs::Storage::move(payload("/src/dir", "/drop/dir"), wsAs(user)),
                 ops::Denied);
    EXPECT_TRUE(exists("/src/dir/inner.txt"));
    EXPECT_FALSE(exists("/drop/dir"));
}

// The destination is authorized before anything about it is looked up: a refused caller gets denied, not not_found
// for a missing folder or conflict for a taken name.
TEST_F(FsMoveAuthzDbTest, ARefusalSaysNothingAboutTheDestination) {
    const auto user = lockedOut();
    write("/locked/taken.txt", "taken\n");
    for (const auto& [command, handler] : handlers()) {
        SCOPED_TRACE(command);
        EXPECT_THROW((void)handler(payload("/src/a.txt", "/locked/missing/a.txt"), wsAs(user)), ops::Denied);
        EXPECT_THROW((void)handler(payload("/src/a.txt", "/locked/taken.txt"), wsAs(user)), ops::Denied);
    }

    // An allowed caller still gets the typed answers.
    EXPECT_THROW((void)protocols::ws::handler::fs::Storage::move(payload("/src/a.txt", "/missing/a.txt"), wsAs(user)),
                 ops::NotFound);
    write("/open/taken.txt", "taken\n");
    EXPECT_THROW((void)protocols::ws::handler::fs::Storage::move(payload("/src/a.txt", "/open/taken.txt"), wsAs(user)),
                 ops::Conflict);
    EXPECT_TRUE(exists("/src/a.txt"));
}

}
