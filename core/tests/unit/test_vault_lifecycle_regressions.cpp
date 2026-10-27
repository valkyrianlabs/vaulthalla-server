// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Regressions found while provisioning the authorized-pentest fixture on vh-storage (1.10.0), driven through the real
// runtime (storage manager, FS cache, RBAC evaluator, share manager) against the test DB:
//   #178 share links over a subfolder were refused: the share authorizer evaluated the vault path as a FUSE path
//   #179 deleting a user who had shared, uploaded to someone else's vault or kept versions hit a foreign key
//   #180 a deleted vault's FS cache entries survived into a new vault with the same FUSE name
// and one found on macOS: storage::Manager::addVault left an engine already registered under the same vault id (a
// schema reset in one test process reuses ids) in its path index, so getEngines() scans (ops::vault_keys) could
// answer with the old vault's engine and key, depending on unordered_map iteration order.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/rbac.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "rbac/Actor.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "share/Manager.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/model/LocalPolicy.hpp"
#include "UsageManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <memory>
#include <string>

namespace vh::test_vault_lifecycle_regressions {

using UserPtr = std::shared_ptr<identities::User>;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

class VaultLifecycleRegressionTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser;

    static UserPtr createUser(const std::string& name, const std::string& roleName) {
        auto user = vh::test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test", "x", std::nullopt);
        return vh::identities::manager().user(user->id);
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_vault_lifecycle_regressions] Skipping db tests due to missing environment variables."
                      << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_vault_lifecycle_" + tag());
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

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::rbac::registerCommands(router);
        protocols::shell::commands::vault::registerCommands(router);

        superUser = createUser("vl_super_" + tag(), "super_admin");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static void assignVaultRole(const unsigned int vaultId, const std::string& role, const UserPtr& user) {
        std::string out;
        int code = 1;
        try {
            const auto res = router->executeLine(
                "vault role assign " + std::to_string(vaultId) + " " + role + " -u " + user->name(), superUser, nullptr);
            code = res.exit_code;
            out = res.stdout_text + res.stderr_text;
        } catch (const std::exception& e) {
            out = e.what();
        }
        ASSERT_EQ(code, 0) << out;
    }

    static std::shared_ptr<vault::model::Vault> addVault(const std::string& name, const UserPtr& owner) {
        auto v = std::make_shared<vault::model::Vault>();
        v->name = name;
        v->owner_id = owner->id;
        v->type = vault::model::VaultType::Local;
        return runtime::Deps::get().storageManager->addVault(v, std::make_shared<sync::model::LocalPolicy>());
    }

    static std::shared_ptr<storage::Engine> engineFor(const unsigned int vaultId) {
        return runtime::Deps::get().storageManager->getEngine(vaultId);
    }

    static std::filesystem::path fuseRoot(const std::shared_ptr<storage::Engine>& engine) {
        return engine->vaultPathToFusePath("/");
    }

    static int mkdir(const std::shared_ptr<storage::Engine>& engine, const std::string& vaultPath,
                     const bool failIfExists = false) {
        return fs::Filesystem::mkdir({
            .path = engine->vaultPathToFusePath(vaultPath),
            .engine = engine,
            .user = superUser,
            .failIfExists = failIfExists
        });
    }

    static share::Link folderLink(const unsigned int vaultId, const unsigned int rootEntryId, const std::string& rootPath) {
        share::Link link;
        link.vault_id = vaultId;
        link.root_entry_id = rootEntryId;
        link.root_path = rootPath;
        link.target_type = share::TargetType::Directory;
        link.link_type = share::LinkType::Access;
        link.access_mode = share::AccessMode::Public;
        link.allowed_ops = share::bit(share::Operation::Metadata) |
                           share::bit(share::Operation::List) |
                           share::bit(share::Operation::Download);
        link.duplicate_policy = share::DuplicatePolicy::Reject;
        return link;
    }

    static const std::shared_ptr<fs::cache::Registry>& cache() { return runtime::Deps::get().fsCache; }
};

TEST_F(VaultLifecycleRegressionTest, ShareLinkCanTargetASubfolderButNotAMismatchedRootEntry) {
    const auto vault = addVault("vl_share_" + tag(), superUser);
    const auto engine = engineFor(vault->id);
    ASSERT_TRUE(engine);
    ASSERT_EQ(mkdir(engine, "/docs"), 0);
    const auto docs = db::query::fs::Entry::getFSEntryByPath(vault->id, "/docs");
    const auto vaultRoot = db::query::fs::Entry::getFSEntryByPath(vault->id, "/");
    ASSERT_TRUE(docs && vaultRoot);

    auto sharer = createUser("vl_sharer_" + tag(), "unprivileged");
    ASSERT_NO_FATAL_FAILURE(assignVaultRole(vault->id, "power_user", sharer));
    sharer = vh::identities::manager().user(sharer->id);
    const auto outsider = createUser("vl_outsider_" + tag(), "unprivileged");

    share::Manager manager;

    // Before #178 only "/" passed: "/docs" was evaluated as a FUSE path, found nothing and failed as MissingEntry.
    const auto created = manager.createLink(rbac::Actor::human(sharer), {.link = folderLink(vault->id, docs->id, "/docs")});
    ASSERT_TRUE(created.link);
    EXPECT_EQ(created.link->root_path, "/docs");
    EXPECT_NO_THROW((void)manager.createLink(rbac::Actor::human(sharer), {.link = folderLink(vault->id, vaultRoot->id, "/")}));

    // Still refused without the vault permission, and for a root entry that isn't the named path.
    EXPECT_THROW((void)manager.createLink(rbac::Actor::human(outsider), {.link = folderLink(vault->id, docs->id, "/docs")}),
                 std::exception);
    EXPECT_THROW((void)manager.createLink(rbac::Actor::human(sharer), {.link = folderLink(vault->id, vaultRoot->id, "/docs")}),
                 std::exception);
}

TEST_F(VaultLifecycleRegressionTest, AVaultPathNamingAnotherVaultsFuseRootIsNotJudgedAsThatVault) {
    // Vault B's FUSE root is "/<b>"; as a path *inside* vault A that names nothing. The old share authorizer passed the
    // vault path straight through, so it resolved to B's root and was judged under A's role.
    const auto a = addVault("vl_cross_a_" + tag(), superUser);
    const auto b = addVault("vl_cross_b_" + tag(), superUser);
    const auto engineB = engineFor(b->id);
    ASSERT_TRUE(engineFor(a->id) && engineB);
    const auto bRoot = db::query::fs::Entry::getFSEntryByPath(b->id, "/");
    ASSERT_TRUE(bRoot);

    auto sharer = createUser("vl_cross_sharer_" + tag(), "unprivileged");
    ASSERT_NO_FATAL_FAILURE(assignVaultRole(a->id, "power_user", sharer));
    sharer = vh::identities::manager().user(sharer->id);

    share::Manager manager;
    EXPECT_THROW((void)manager.createLink(rbac::Actor::human(sharer),
                                          {.link = folderLink(a->id, bRoot->id, fuseRoot(engineB).string())}),
                 std::exception);
}

TEST_F(VaultLifecycleRegressionTest, DeletingAUserWithShareAndUploadHistorySucceeds) {
    const auto vault = addVault("vl_del_" + tag(), superUser);
    const auto engine = engineFor(vault->id);
    ASSERT_TRUE(engine);
    ASSERT_EQ(mkdir(engine, "/drop"), 0);
    const auto drop = db::query::fs::Entry::getFSEntryByPath(vault->id, "/drop");
    ASSERT_TRUE(drop);

    auto leaver = createUser("vl_leaver_" + tag(), "unprivileged");
    ASSERT_NO_FATAL_FAILURE(assignVaultRole(vault->id, "power_user", leaver));
    leaver = vh::identities::manager().user(leaver->id);

    share::Manager manager;
    const auto link = manager.createLink(rbac::Actor::human(leaver), {.link = folderLink(vault->id, drop->id, "/drop")}).link;
    ASSERT_TRUE(link);

    // Attribution in a vault the user doesn't own, plus the share audit trail (createLink wrote one).
    db::Transactions::exec("VaultLifecycleRegressionTest::attribute", [&](pqxx::work& txn) {
        txn.exec("UPDATE fs_entry SET created_by = $1, last_modified_by = $1 WHERE id = $2",
                 pqxx::params{leaver->id, drop->id});
    });
    const auto auditRows = [&] {
        return db::Transactions::exec("VaultLifecycleRegressionTest::audit", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM share_access_event WHERE share_id = $1::uuid OR actor_user_id = $2",
                            pqxx::params{link->id, leaver->id}).one_field_ref().as<long>();
        });
    };
    ASSERT_GT(auditRows(), 0);

    ASSERT_NO_THROW(vh::identities::manager().deleteUser(leaver->id));
    EXPECT_EQ(vh::identities::manager().user(leaver->id), nullptr);

    const auto after = db::Transactions::exec("VaultLifecycleRegressionTest::after", [&](pqxx::work& txn) {
        const auto links = txn.exec("SELECT COUNT(*) FROM share_link WHERE id = $1::uuid", pqxx::params{link->id})
                               .one_field_ref().as<long>();
        const auto attributed = txn.exec("SELECT created_by IS NULL AND last_modified_by IS NULL FROM fs_entry WHERE id = $1",
                                         pqxx::params{drop->id}).one_field_ref().as<bool>();
        const auto orphanedAudit = txn.exec("SELECT COUNT(*) FROM share_access_event WHERE actor_user_id IS NULL AND "
                                            "event_type = 'share.link.create' AND target_entry_id = $1",
                                            pqxx::params{drop->id}).one_field_ref().as<long>();
        return std::tuple{links, attributed, orphanedAudit};
    });
    EXPECT_EQ(std::get<0>(after), 0) << "a deleted account's public links must not outlive it";
    EXPECT_TRUE(std::get<1>(after)) << "the folder stays, its attribution is cleared";
    EXPECT_GT(std::get<2>(after), 0) << "the audit event stays, without the identity";
}

TEST_F(VaultLifecycleRegressionTest, AReusedFuseNameStartsEmptyAfterTheVaultIsDeleted) {
    const auto name = "vl_reuse_" + tag();
    const auto first = addVault(name, superUser);
    const auto firstEngine = engineFor(first->id);
    ASSERT_TRUE(firstEngine);
    const auto root = fuseRoot(firstEngine);
    ASSERT_EQ(mkdir(firstEngine, "/stale"), 0);
    ASSERT_TRUE(cache()->entryExists(root / "stale"));

    runtime::Deps::get().storageManager->removeVault(first->id);
    EXPECT_FALSE(cache()->entryExists(root / "stale"));
    EXPECT_FALSE(cache()->entryExists(root));

    const auto second = addVault(name, superUser);
    const auto secondEngine = engineFor(second->id);
    ASSERT_TRUE(secondEngine);
    ASSERT_EQ(fuseRoot(secondEngine), root) << "the scenario needs the FUSE name to be reused";

    EXPECT_FALSE(cache()->entryExists(root / "stale")) << "the deleted vault's entry leaked into the new vault";
    const auto newRoot = cache()->getEntry(root);
    ASSERT_TRUE(newRoot);
    ASSERT_TRUE(newRoot->vault_id);
    EXPECT_EQ(static_cast<unsigned int>(*newRoot->vault_id), second->id);
    EXPECT_EQ(mkdir(secondEngine, "/stale", true /*failIfExists*/), 0) << "was -EEXIST from the stale cache entry";
}

TEST_F(VaultLifecycleRegressionTest, RenamingAVaultMovesItsCachedEntriesToTheNewFuseRoot) {
    const auto vault = addVault("vl_rename_" + tag(), superUser);
    const auto engine = engineFor(vault->id);
    ASSERT_TRUE(engine);
    const auto oldRoot = fuseRoot(engine);
    ASSERT_EQ(mkdir(engine, "/kid"), 0);
    ASSERT_TRUE(cache()->entryExists(oldRoot / "kid"));

    auto renamed = db::query::vault::Vault::getVault(vault->id);
    ASSERT_TRUE(renamed);
    renamed->fuse_name = "vl_renamed_" + tag();
    runtime::Deps::get().storageManager->updateVault(renamed);
    const auto newRoot = fuseRoot(engineFor(vault->id));
    ASSERT_NE(newRoot, oldRoot);

    EXPECT_FALSE(cache()->entryExists(oldRoot / "kid"));
    EXPECT_FALSE(cache()->entryExists(oldRoot));
    const auto kid = cache()->getEntry(newRoot / "kid");
    ASSERT_TRUE(kid) << "entries must re-hydrate under the renamed root";
    EXPECT_EQ(kid->fuse_path, newRoot / "kid");
}

// One engine per vault id. The scenario every unit-test binary hits: a suite resets the schema while the process keeps
// its storage::Manager, so the next suite's vaults reuse the ids of the previous suite's vaults (at other FUSE roots).
// ops::vault_keys found its engine by scanning getEngines(); with the old engine still indexed by its FUSE root it
// exported and confirmed against the old vault's key whenever the hash order put that one first
// (DeviceHttpTest.VaultKeyExportOnlyOnAPairedDevice, on macOS's libc++).
class StorageEngineRegistryTest : public VaultLifecycleRegressionTest {
protected:
    // What the next suite's SetUpTestSuite does, in the same process (same storage::Manager).
    static void resetSchema() {
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        superUser = createUser("vl_super_" + tag(), "super_admin");
    }

    // Every engine the manager indexes is the one getEngine() returns for its vault id.
    static void expectOneEnginePerVaultId() {
        const auto& manager = runtime::Deps::get().storageManager;
        for (const auto& engine : manager->getEngines()) {
            ASSERT_TRUE(engine && engine->vault);
            EXPECT_EQ(manager->getEngine(engine->vault->id), engine)
                << "vault " << engine->vault->id << " has a second engine at " << fuseRoot(engine);
        }
    }
};

TEST_F(StorageEngineRegistryTest, AVaultIdReusedAfterASchemaResetHasOneEngine) {
    const auto before = addVault("vl_ids_before_" + tag(), superUser);
    const auto oldEngine = engineFor(before->id);
    ASSERT_TRUE(oldEngine);
    const auto oldRoot = fuseRoot(oldEngine);

    resetSchema();
    // The same seed and the same creations: the vault sequence hands out the old id again, under another name.
    const auto after = addVault("vl_ids_after_" + tag(), superUser);
    ASSERT_EQ(after->id, before->id) << "the scenario needs the vault id to be reused";
    const auto newEngine = engineFor(after->id);
    ASSERT_TRUE(newEngine);
    ASSERT_NE(newEngine, oldEngine);
    ASSERT_NE(fuseRoot(newEngine), oldRoot);

    expectOneEnginePerVaultId();
    const auto engines = runtime::Deps::get().storageManager->getEngines();
    EXPECT_EQ(std::ranges::count(engines, oldEngine), 0) << "the replaced engine is still indexed";
    EXPECT_NE(runtime::Deps::get().storageManager->resolveStorageEngine(oldRoot / "x"), oldEngine);

    // A full re-initialization starts both indexes over: no id survives for a vault that is not live.
    runtime::Deps::get().storageManager->initStorageEngines();
    expectOneEnginePerVaultId();
    for (const auto& vault : db::query::vault::Vault::listLiveVaults())
        EXPECT_TRUE(runtime::Deps::get().storageManager->getEngine(vault->id)) << vault->id;
}

}
