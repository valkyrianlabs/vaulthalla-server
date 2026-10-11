// Safe vault deletion with retention (#162), driven through ops::vaults and vault::retention against the test DB:
// schedule → restore, schedule → purge after the window (the pass takes an injected clock), delete now, the key
// tombstone and its expiry, the S3 key-loss gate, the bounded and resumable upstream purge (fake S3 controller), the
// shared-bucket guard, and the path guard that keeps a purge inside the backing root.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/identities/User.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/Entry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Roles.hpp"
#include "ops/Vaults.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/s3/Controller.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/Retention.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Deletion.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace vh::test_vault_retention {

using UserPtr = std::shared_ptr<identities::User>;
using Clock = std::chrono::system_clock;
using vault::model::DeletionState;
using DeletionQuery = db::query::vault::Deletion;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

std::shared_ptr<vault::model::APIKey> fakeKey() {
    return std::make_shared<vault::model::APIKey>(1, "fake", vault::model::S3Provider::AWS, "AKIATESTACCESSKEY000",
                                                  "secret-value-0000000000000000000000000", "us-east-1",
                                                  "https://s3.example.com");
}

// A bucket in memory: lists in pages, meters through the controller's own budget like the real one.
class FakeBucket final : public storage::s3::Controller {
public:
    mutable std::mutex mutex;
    mutable std::set<std::string> objects;
    mutable unsigned lists = 0, deletes = 0;

    FakeBucket() : Controller(fakeKey(), "fake-bucket") {}

    storage::s3::ObjectKeyPage listObjectKeysPage(const std::string&, const unsigned int maxKeys) const override {
        recordRequest(RequestKind::List);
        std::scoped_lock lock(mutex);
        ++lists;
        storage::s3::ObjectKeyPage page;
        for (const auto& key : objects) {
            if (page.keys.size() == maxKeys) {
                page.next_continuation_token = "more";
                break;
            }
            page.keys.push_back(key);
        }
        return page;
    }

    void deleteObject(const std::filesystem::path& key) const override {
        recordRequest(RequestKind::Delete);
        std::scoped_lock lock(mutex);
        ++deletes;
        objects.erase(key.string());
    }
};

class VaultRetentionTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser, bob;

    static UserPtr createUser(const std::string& name, const std::string& roleName) {
        auto user = vh::test::identities::createUser(name, db::query::rbac::role::Admin::get(roleName), name + "@vaulthalla.test", "x", std::nullopt);
        return vh::identities::manager().user(user->id);
    }

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_vault_retention] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_vault_retention_" + tag());
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

        superUser = createUser("vr_super_" + tag(), "super_admin");
        bob = createUser("vr_bob_" + tag(), "unprivileged");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    void TearDown() override { vault::retention::setControllerFactoryForTesting({}); }

    static ops::vaults::VaultPtr localVault(const std::string& prefix) {
        return ops::vaults::create(superUser, {.name = prefix + tag(), .type = vault::model::VaultType::Local});
    }

    static unsigned int seedKey(const std::string& endpoint = "https://s3.example.com") {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "vr_key_" + tag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                          "us-east-1", endpoint);
        return runtime::Deps::get().apiKeyManager->addAPIKey(key);
    }

    static ops::vaults::VaultPtr s3Vault(const unsigned int keyId, const std::string& bucket) {
        return ops::vaults::create(superUser, {
            .name = "vr_s3_" + tag(), .type = vault::model::VaultType::S3,
            .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = bucket}});
    }

    static std::filesystem::path backingDir(const ops::vaults::VaultPtr& v) {
        return paths::getBackingPath() / v->mount_point;
    }

    static unsigned int vaultRows(const unsigned int id) {
        return db::Transactions::exec("VaultRetentionTest::rows", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM vault WHERE id = $1", pqxx::params{id}).one_field_ref().as<unsigned int>();
        });
    }

    static std::optional<int64_t> rootParent(const unsigned int id) {
        return db::Transactions::exec("VaultRetentionTest::rootParent", [&](pqxx::work& txn) -> std::optional<int64_t> {
            const auto r = txn.exec("SELECT parent_id FROM fs_entry WHERE vault_id = $1 AND path = '/'", pqxx::params{id});
            if (r.empty() || r[0][0].is_null()) return std::nullopt;
            return r[0][0].as<int64_t>();
        });
    }

    static std::vector<uint8_t> liveKey(const unsigned int id) {
        return runtime::Deps::get().storageManager->getEngine(id)->encryptionManager->get_key("test");
    }
};

TEST_F(VaultRetentionTest, ScheduleHidesTheVaultAndRestoreBringsItBackAsItWas) {
    const auto v = localVault("vr_restore_");
    const auto engine = runtime::Deps::get().storageManager->getEngine(v->id);
    ASSERT_TRUE(engine);
    const auto fuseRoot = engine->vaultPathToFusePath("/");
    ASSERT_EQ(fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/docs"), .engine = engine, .user = superUser}), 0);
    const auto parentBefore = rootParent(v->id);
    ASSERT_TRUE(parentBefore);

    const auto d = ops::vaults::remove(superUser, {.id = v->id});
    ASSERT_TRUE(d);
    EXPECT_EQ(d->state, DeletionState::Pending);
    EXPECT_EQ(d->purge_after - d->deleted_at, vault::retention::windowsFor(v->type).retention_window.count());
    EXPECT_GE(d->key_retain_until - d->deleted_at, vault::retention::windowsFor(v->type).key_retention_window.count());

    // Gone from every live surface at once; the data stays on disk.
    EXPECT_FALSE(db::query::vault::Vault::getVault(v->id));
    EXPECT_FALSE(runtime::Deps::get().storageManager->getEngine(v->id));
    for (const auto& listed : db::query::vault::Vault::listVaults()) EXPECT_NE(listed->id, v->id);
    EXPECT_FALSE(runtime::Deps::get().fsCache->entryExists(fuseRoot));
    EXPECT_FALSE(rootParent(v->id)) << "the root is detached from the mount";
    EXPECT_TRUE(std::filesystem::exists(backingDir(v)));
    EXPECT_THROW((void)ops::vaults::get(superUser, v->id), ops::NotFound);

    // The name stays reserved, and the refusal says how to get it back.
    try {
        (void)ops::vaults::create(superUser, {.name = v->name, .type = vault::model::VaultType::Local});
        ADD_FAILURE() << "a deleted vault's name was reused before its purge";
    } catch (const ops::Conflict& e) {
        EXPECT_TRUE(std::string(e.what()).contains("vh vault restore")) << e.what();
    }
    // Deleting it again only means something with --now.
    EXPECT_THROW((void)ops::vaults::remove(superUser, {.id = v->id}), ops::Conflict);

    // Others can neither see, restore nor purge it.
    for (const auto& listed : ops::vaults::listDeleted(bob)) EXPECT_NE(listed->vault_id, v->id);
    EXPECT_THROW((void)ops::vaults::restore(bob, v->id), ops::Denied);
    EXPECT_THROW((void)ops::vaults::remove(bob, {.id = v->id, .now = true, .confirm_now = true}), ops::Denied);

    const auto restored = ops::vaults::restore(superUser, v->id);
    ASSERT_TRUE(restored);
    EXPECT_EQ(restored->name, v->name);
    EXPECT_EQ(rootParent(v->id), parentBefore);
    const auto back = runtime::Deps::get().storageManager->getEngine(v->id);
    ASSERT_TRUE(back);
    EXPECT_TRUE(runtime::Deps::get().fsCache->getEntry(fuseRoot));
    EXPECT_TRUE(runtime::Deps::get().fsCache->getEntry(back->vaultPathToFusePath("/docs"))) << "the vault's contents came back";
    EXPECT_FALSE(DeletionQuery::get(v->id));
    EXPECT_THROW((void)ops::vaults::restore(superUser, v->id), ops::NotFound);
}

// A vault waiting for its purge doesn't keep a vault role in use (before #162 deleting the vault cascaded its
// assignments away at once; the integration harness deletes a vault, then its role). Deleting the role removes the
// assignment there too, so a restore brings the vault back without it.
TEST_F(VaultRetentionTest, ARoleAssignedOnlyOnADeletedVaultCanBeDeleted) {
    const auto v = localVault("vr_role_");
    const auto role = ops::roles::createVaultRole(superUser, {.name = "vr_role_" + tag()});
    ASSERT_TRUE(role);
    const auto assignments = [&] {
        return db::Transactions::exec("VaultRetentionTest::assignments", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM vault_role_assignments WHERE role_id = $1", pqxx::params{role->id})
                .one_field_ref().as<unsigned int>();
        });
    };
    db::Transactions::exec("VaultRetentionTest::assign", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO vault_role_assignments (vault_id, subject_type, subject_id, role_id) VALUES ($1, 'user', $2, $3)",
                 pqxx::params{v->id, bob->id, role->id});
    });

    EXPECT_THROW((void)ops::roles::removeVaultRole(superUser, role->id), ops::Conflict) << "a live vault keeps it in use";

    (void)ops::vaults::remove(superUser, {.id = v->id});
    EXPECT_NO_THROW((void)ops::roles::removeVaultRole(superUser, role->id));
    EXPECT_EQ(assignments(), 0u);

    ASSERT_TRUE(ops::vaults::restore(superUser, v->id));
    EXPECT_EQ(assignments(), 0u);
}

TEST_F(VaultRetentionTest, PurgeAfterTheWindowRemovesDataAndKeepsTheKeyUntilItsWindowEnds) {
    const auto v = localVault("vr_purge_");
    const auto key = liveKey(v->id);
    std::ofstream(backingDir(v) / "blob.bin") << "ciphertext";
    const auto cacheDir = paths::getBackingPath() / paths::getCachePath().relative_path() / v->mount_point;
    ASSERT_TRUE(std::filesystem::exists(backingDir(v) / "blob.bin"));

    const auto d = ops::vaults::remove(superUser, {.id = v->id});
    const auto deletedAt = Clock::from_time_t(d->deleted_at);

    // Inside the window nothing is purged.
    auto pass = vault::retention::runPass(deletedAt + std::chrono::seconds(30));
    EXPECT_EQ(DeletionQuery::get(v->id)->state, DeletionState::Pending);
    EXPECT_TRUE(std::filesystem::exists(backingDir(v)));

    pass = vault::retention::runPass(Clock::from_time_t(d->purge_after) + std::chrono::seconds(1));
    EXPECT_GE(pass.purged, 1u);
    EXPECT_FALSE(std::filesystem::exists(backingDir(v)));
    EXPECT_FALSE(std::filesystem::exists(cacheDir));
    EXPECT_EQ(vaultRows(v->id), 0u) << "the vault row (and its cascade) goes at the purge";

    const auto tomb = DeletionQuery::get(v->id);
    ASSERT_TRUE(tomb);
    EXPECT_EQ(tomb->state, DeletionState::Purged);
    EXPECT_EQ(tomb->vault_name, v->name);
    EXPECT_TRUE(tomb->keyRetained());
    EXPECT_THROW((void)ops::vaults::restore(superUser, v->id), ops::Conflict);

    // The retained key is the vault's key, still exportable.
    const auto retained = vault::retention::retainedKey(v->id);
    EXPECT_EQ(retained.key, key);
    EXPECT_EQ(retained.record->version, tomb->key_version.value_or(0));

    // The name is free again once the vault is purged.
    EXPECT_NO_THROW((void)ops::vaults::create(superUser, {.name = v->name, .type = vault::model::VaultType::Local}));

    // Key retention ends on its own clock; the tombstone stays.
    pass = vault::retention::runPass(Clock::from_time_t(tomb->key_retain_until) - std::chrono::hours(1));
    EXPECT_FALSE(DeletionQuery::retainedKeys(v->id).empty());
    pass = vault::retention::runPass(Clock::from_time_t(tomb->key_retain_until) + std::chrono::seconds(1));
    EXPECT_GE(pass.keys_expired, 1u);
    EXPECT_TRUE(DeletionQuery::retainedKeys(v->id).empty());
    EXPECT_THROW((void)vault::retention::retainedKey(v->id), std::runtime_error);
    const auto expired = DeletionQuery::get(v->id);
    ASSERT_TRUE(expired);
    EXPECT_FALSE(expired->keyRetained());
    EXPECT_EQ(expired->vault_name, v->name);
    EXPECT_TRUE(expired->key_version);
}

TEST_F(VaultRetentionTest, DeleteNowAsksOncePurgesOnTheNextPassAndKeepsTheFullKeyWindow) {
    const auto v = localVault("vr_now_");
    try {
        (void)ops::vaults::remove(superUser, {.id = v->id, .now = true});
        ADD_FAILURE() << "delete now went ahead without confirmation";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, ops::vaults::VAULT_DELETE_NOW);
    }
    EXPECT_TRUE(db::query::vault::Vault::getVault(v->id)) << "an unconfirmed delete now changes nothing";

    const auto d = ops::vaults::remove(superUser, {.id = v->id, .now = true, .confirm_now = true});
    EXPECT_EQ(d->purge_after, d->deleted_at);
    EXPECT_GE(d->key_retain_until - d->deleted_at, vault::retention::windowsFor(v->type).key_retention_window.count())
        << "delete now never shortens the key retention window";

    (void)vault::retention::runPass(Clock::from_time_t(d->deleted_at) + std::chrono::seconds(1));
    EXPECT_EQ(DeletionQuery::get(v->id)->state, DeletionState::Purged);
    EXPECT_FALSE(std::filesystem::exists(backingDir(v)));
    EXPECT_TRUE(DeletionQuery::get(v->id)->keyRetained());

    // A scheduled deletion can be expedited the same way.
    const auto w = localVault("vr_expedite_");
    (void)ops::vaults::remove(superUser, {.id = w->id});
    EXPECT_THROW((void)ops::vaults::remove(superUser, {.id = w->id, .now = true}), ops::NeedsConfirmation);
    (void)ops::vaults::remove(superUser, {.id = w->id, .now = true, .confirm_now = true});
    (void)vault::retention::runPass(Clock::now() + std::chrono::seconds(1));
    EXPECT_EQ(DeletionQuery::get(w->id)->state, DeletionState::Purged);
}

TEST_F(VaultRetentionTest, AnInterruptedPurgeResumesOnTheNextPass) {
    const auto v = localVault("vr_resume_");
    const auto d = ops::vaults::remove(superUser, {.id = v->id, .now = true, .confirm_now = true});
    // A daemon stopping before the work began: the claim is released for the next pass, nothing is lost.
    (void)vault::retention::runPass(Clock::now() + std::chrono::seconds(1), [] { return true; });
    EXPECT_EQ(DeletionQuery::get(v->id)->state, DeletionState::Purging);
    EXPECT_TRUE(std::filesystem::exists(backingDir(v)));
    EXPECT_FALSE(DeletionQuery::get(v->id)->restorable()) << "a purge that started is never undone";
    (void)vault::retention::runPass(Clock::now() + std::chrono::seconds(2));
    EXPECT_EQ(DeletionQuery::get(d->vault_id)->state, DeletionState::Purged);
    EXPECT_FALSE(std::filesystem::exists(backingDir(v)));
}

TEST_F(VaultRetentionTest, S3KeepsUpstreamDataOnlyAfterTheKeyLossIsAcceptedOrTheKeyExported) {
    const auto keyId = seedKey();
    const auto v = s3Vault(keyId, "vr-gate-" + tag());
    try {
        (void)ops::vaults::remove(superUser, {.id = v->id});
        ADD_FAILURE() << "encrypted upstream data was orphaned without a word about the key";
    } catch (const ops::NeedsConfirmation& e) {
        EXPECT_EQ(e.code, ops::vaults::VAULT_UPSTREAM_KEY_LOSS);
        EXPECT_TRUE(std::string(e.what()).contains("vh vault keys export " + std::to_string(v->id))) << e.what();
    }
    const auto plan = ops::vaults::removalPlan(superUser, v->id);
    EXPECT_TRUE(plan.encrypted_upstream);
    EXPECT_FALSE(plan.keyExported());

    // An export recorded for the current key version clears the gate.
    db::query::vault::Key::markExported(v->id, db::query::vault::Key::getVaultKey(v->id)->version);
    EXPECT_TRUE(ops::vaults::removalPlan(superUser, v->id).keyExported());
    const auto d = ops::vaults::remove(superUser, {.id = v->id});
    EXPECT_FALSE(d->delete_upstream);
    EXPECT_FALSE(d->upstreamKeyAtRisk());
    EXPECT_TRUE(d->keyExported());
    EXPECT_GE(d->key_retain_until - d->deleted_at,
              vault::retention::windowsFor(vault::model::VaultType::S3).key_retention_window.count());

    // Accepting the loss explicitly works too, and the listing keeps warning about it.
    const auto w = s3Vault(keyId, "vr-accept-" + tag());
    const auto accepted = ops::vaults::remove(superUser, {.id = w->id, .accept_key_loss = true});
    EXPECT_TRUE(accepted->upstreamKeyAtRisk());

    // A deleted vault's bucket is not handed to a new vault while it is pending.
    const auto pendingBucket = std::static_pointer_cast<vault::model::S3Vault>(w)->bucket;
    ASSERT_FALSE(pendingBucket.empty());
    EXPECT_THROW((void)s3Vault(keyId, pendingBucket), ops::Conflict);
}

TEST_F(VaultRetentionTest, UpstreamPurgeIsBoundedPerPassResumableAndThenRemovesLocalData) {
    auto bucket = std::make_shared<FakeBucket>();
    for (int i = 0; i < 2500; ++i) bucket->objects.insert("obj/" + std::to_string(i));
    vault::retention::setControllerFactoryForTesting([bucket](const vault::model::S3Vault&) { return bucket; });

    const auto keyId = seedKey("https://s3.bounded.example.com");
    const auto v = s3Vault(keyId, "vr-upstream-" + tag());
    const auto d = ops::vaults::remove(superUser, {.id = v->id, .now = true, .delete_upstream = true, .confirm_now = true});
    EXPECT_TRUE(d->delete_upstream);
    EXPECT_FALSE(d->upstreamKeyAtRisk()) << "deleting upstream data needs no key-loss acceptance";

    auto now = Clock::now() + std::chrono::seconds(1);
    for (int i = 0; i < 5 && DeletionQuery::get(v->id)->state != DeletionState::Purged; ++i, now += std::chrono::seconds(1))
        (void)vault::retention::runPass(now);
    EXPECT_TRUE(bucket->objects.empty());
    EXPECT_EQ(bucket->deletes, 2500u);
    EXPECT_LE(bucket->lists, 2u * vault::retention::kUpstreamListsPerPass);
    const auto tomb = DeletionQuery::get(v->id);
    ASSERT_TRUE(tomb);
    EXPECT_EQ(tomb->state, DeletionState::Purged);
    EXPECT_TRUE(tomb->upstream_purged_at);
    EXPECT_FALSE(tomb->last_error);
    EXPECT_FALSE(std::filesystem::exists(backingDir(v)));
}

TEST_F(VaultRetentionTest, NeverDeletesObjectsOfABucketAnotherVaultUses) {
    auto bucket = std::make_shared<FakeBucket>();
    bucket->objects = {"a", "b"};
    vault::retention::setControllerFactoryForTesting([bucket](const vault::model::S3Vault&) { return bucket; });

    // Two credentials for the same endpoint and region, one bucket: two vaults over the same objects.
    const auto shared = "vr-shared-" + tag();
    const auto keyA = seedKey("https://s3.shared.example.com"), keyB = seedKey("https://s3.shared.example.com");
    const auto mine = s3Vault(keyA, shared);
    const auto theirs = s3Vault(keyB, shared);
    (void)ops::vaults::remove(superUser, {.id = mine->id, .now = true, .delete_upstream = true, .confirm_now = true});

    (void)vault::retention::runPass(Clock::now() + std::chrono::seconds(1));
    EXPECT_EQ(DeletionQuery::get(mine->id)->state, DeletionState::Purged) << "the local purge still finishes";
    EXPECT_EQ(bucket->objects.size(), 2u);
    EXPECT_EQ(bucket->deletes, 0u);
    const auto tomb = DeletionQuery::get(mine->id);
    ASSERT_TRUE(tomb && tomb->last_error);
    EXPECT_TRUE(tomb->last_error->contains("upstream data kept")) << *tomb->last_error;
    EXPECT_FALSE(tomb->upstream_purged_at);
    EXPECT_TRUE(db::query::vault::Vault::getVault(theirs->id));
}

TEST_F(VaultRetentionTest, PathGuardKeepsAPurgeInsideTheBackingRoot) {
    namespace fsys = std::filesystem;
    const auto root = fsys::temp_directory_path() / ("vh_path_guard_" + tag());
    const auto outside = fsys::temp_directory_path() / ("vh_path_guard_outside_" + tag());
    fsys::create_directories(root);
    fsys::create_directories(outside);
    std::ofstream(outside / "precious") << "keep me";

    using vault::retention::PathGuardError;
    using vault::retention::removeVaultDirectory;
    EXPECT_THROW(removeVaultDirectory(root, "../" + outside.filename().string()), PathGuardError);
    EXPECT_THROW(removeVaultDirectory(root, ""), PathGuardError);
    EXPECT_THROW(removeVaultDirectory(root, "a/b"), PathGuardError);
    EXPECT_THROW(removeVaultDirectory(root, ".."), PathGuardError);

    fsys::create_directory_symlink(outside, root / "linkalias");
    EXPECT_THROW(removeVaultDirectory(root, "linkalias"), PathGuardError);
    EXPECT_TRUE(fsys::exists(outside / "precious"));

    std::ofstream(root / "filealias") << "not a directory";
    EXPECT_THROW(removeVaultDirectory(root, "filealias"), PathGuardError);

    EXPECT_FALSE(removeVaultDirectory(root, "missingalias"));

    // A real vault directory goes, and a symlink inside it is removed, not followed.
    fsys::create_directories(root / "realalias" / "sub");
    fsys::create_directory_symlink(outside, root / "realalias" / "sub" / "escape");
    EXPECT_TRUE(removeVaultDirectory(root, "realalias"));
    EXPECT_FALSE(fsys::exists(root / "realalias"));
    EXPECT_TRUE(fsys::exists(outside / "precious"));

    fsys::remove_all(root);
    fsys::remove_all(outside);
}

}
