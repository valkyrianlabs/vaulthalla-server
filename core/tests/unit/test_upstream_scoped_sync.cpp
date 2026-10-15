// Event-scoped sync passes (#96), against the test DB and an in-memory bucket (the sync-conflict harness):
//  - a scoped pass plans only the keys its events named (no LIST, no manifest refresh);
//  - an upstream removal deletes a local copy that is unchanged since both sides last agreed, and keeps (re-uploads)
//    one that changed; mirror + keep_local keeps the local side authoritative;
//  - a regular pass that runs while a removal event is pending applies the same rule instead of re-uploading;
//  - without removal events, a missing object is uploaded again exactly as before;
//  - one pass per vault: the controller's pass lease.

#include "../helpers/sync_conflict_harness.hpp"

#include "sync/Controller.hpp"
#include "sync/model/Scope.hpp"

namespace vh::test_upstream_scoped_sync {

using namespace test_support::sync_conflicts;
using ActionType = sync::model::ActionType;

class UpstreamScopedSyncTest : public Harness {
protected:
    void TearDown() override { sync::Cloud::setPendingRemovalsProvider({}); }

    static std::shared_ptr<sync::Cloud> newPass(const Fixture& f, std::shared_ptr<sync::model::PassScope> scope) {
        auto cloud = scope ? std::make_shared<sync::Cloud>(f.engine, std::move(scope)) : std::make_shared<sync::Cloud>(f.engine);
        cloud->event = std::make_shared<sync::model::Event>();
        cloud->event->vault_id = f.vault->id;
        cloud->event->timestamp_begin = std::time(nullptr);
        db::query::sync::Event::create(cloud->event);
        return cloud;
    }

    // Plans and runs one pass inline (uploads, downloads and local deletes), like Harness::pass.
    static std::vector<sync::model::Action> run(const Fixture& f, const std::shared_ptr<sync::Cloud>& cloud) {
        cloud->loadRemovedKeys();
        if (cloud->scope) cloud->initScopedBins();
        else cloud->initBins();
        const auto plan = cloud->planPass();
        for (const auto& a : plan) {
            if (a.type == ActionType::Upload)
                sync::tasks::Upload(f.engine, a.local, cloud->op(sync::model::Throughput::Metric::UPLOAD))();
            else if (a.type == ActionType::Download)
                sync::tasks::Download(f.engine, a.remote, cloud->op(sync::model::Throughput::Metric::DOWNLOAD), false)();
            else if (a.type == ActionType::DeleteLocal)
                f.engine->removeLocally(a.local->path);
        }
        f.engine->applyRemoteIndexMutation(plan);
        cloud->clearBins();
        return plan;
    }

    static std::shared_ptr<sync::model::PassScope> scopeOf(std::initializer_list<const char*> keys,
                                                           std::initializer_list<const char*> removed = {}) {
        auto scope = std::make_shared<sync::model::PassScope>();
        for (const auto* k : keys) scope->keys.insert(reinterpret_cast<const char8_t*>(k));
        for (const auto* k : removed) {
            scope->keys.insert(reinterpret_cast<const char8_t*>(k));
            scope->removed.insert(reinterpret_cast<const char8_t*>(k));
        }
        return scope;
    }

    // Another writer deleted the object; the removal event has been applied to the index.
    static void remoteDelete(const Fixture& f, const std::string& path) {
        db::query::sync::RemoteObjectIndex::deleteKey(f.vault->id, path);
    }

    static bool localExists(const Fixture& f, const std::string& path) {
        return db::query::fs::File::getFileByPath(f.vault->id, path) != nullptr;
    }
};

TEST_F(UpstreamScopedSyncTest, ScopedPassPlansOnlyTheNamedKeys) {
    const auto f = remoteVault(superUser);
    remoteWrite(f, "/named.txt", "from events");
    remoteWrite(f, "/other.txt", "not named");

    const auto plan = run(f, newPass(f, scopeOf({"/named.txt"})));
    EXPECT_EQ(planned(plan, ActionType::Download, "/named.txt"), 1u);
    EXPECT_EQ(planned(plan, ActionType::Download, "/other.txt"), 0u) << "keys outside the scope are not reconciled";
    EXPECT_EQ(readLocal(f, "/named.txt"), "from events");
    EXPECT_FALSE(localExists(f, "/other.txt"));
}

TEST_F(UpstreamScopedSyncTest, RemovalDeletesAnUnchangedLocalCopy) {
    const auto f = remoteVault(superUser);
    write(f, "/gone.txt", "synced once");
    (void)run(f, newPass(f, nullptr));   // upload: both sides agree
    remoteDelete(f, "/gone.txt");

    const auto plan = run(f, newPass(f, scopeOf({}, {"/gone.txt"})));
    EXPECT_EQ(planned(plan, ActionType::DeleteLocal, "/gone.txt"), 1u);
    EXPECT_EQ(planned(plan, ActionType::Upload, "/gone.txt"), 0u) << "a deleted object must not come back";
    EXPECT_FALSE(localExists(f, "/gone.txt"));
}

TEST_F(UpstreamScopedSyncTest, RemovalKeepsALocalCopyThatChanged) {
    const auto f = remoteVault(superUser);
    write(f, "/edited.txt", "synced once");
    (void)run(f, newPass(f, nullptr));
    write(f, "/edited.txt", "edited locally after the sync");
    remoteDelete(f, "/edited.txt");

    const auto plan = run(f, newPass(f, scopeOf({}, {"/edited.txt"})));
    EXPECT_EQ(planned(plan, ActionType::DeleteLocal, "/edited.txt"), 0u) << "local changes are never thrown away";
    EXPECT_EQ(planned(plan, ActionType::Upload, "/edited.txt"), 1u);
    EXPECT_EQ(readLocal(f, "/edited.txt"), "edited locally after the sync");
}

TEST_F(UpstreamScopedSyncTest, RemovalUnderMirrorKeepLocalReuploads) {
    const auto f = remoteVault(superUser, sync::model::RemotePolicy::ConflictPolicy::KeepLocal);
    f.engine->remote_policy()->strategy = sync::model::RemotePolicy::Strategy::Mirror;
    write(f, "/authoritative.txt", "local is the source");
    (void)run(f, newPass(f, nullptr));
    remoteDelete(f, "/authoritative.txt");

    const auto plan = run(f, newPass(f, scopeOf({}, {"/authoritative.txt"})));
    EXPECT_EQ(planned(plan, ActionType::DeleteLocal, "/authoritative.txt"), 0u);
    EXPECT_EQ(planned(plan, ActionType::Upload, "/authoritative.txt"), 1u);
}

TEST_F(UpstreamScopedSyncTest, RegularPassHonoursAPendingRemovalInsteadOfReuploading) {
    const auto f = remoteVault(superUser);
    write(f, "/pending.txt", "synced once");
    write(f, "/untouched.txt", "synced once");
    write(f, "/stays.txt", "synced once");   // the index keeps a row: no manifest reload (see the event applier)
    (void)run(f, newPass(f, nullptr));
    remoteDelete(f, "/pending.txt");
    remoteDelete(f, "/untouched.txt");
    const auto vaultId = f.vault->id;
    sync::Cloud::setPendingRemovalsProvider([vaultId](const uint32_t v) {
        std::unordered_set<std::u8string> keys;
        if (v == vaultId) keys.insert(u8"/pending.txt");
        return keys;
    });

    const auto plan = run(f, newPass(f, nullptr));
    EXPECT_EQ(planned(plan, ActionType::DeleteLocal, "/pending.txt"), 1u);
    EXPECT_EQ(planned(plan, ActionType::Upload, "/pending.txt"), 0u);
    // No removal event for this one: a listing-style absence keeps the old behaviour (upload it again).
    EXPECT_EQ(planned(plan, ActionType::Upload, "/untouched.txt"), 1u);
}

TEST_F(UpstreamScopedSyncTest, ScopedCreateEventForAnUnchangedObjectTransfersNothing) {
    const auto f = remoteVault(superUser);
    write(f, "/same.txt", "content");
    (void)run(f, newPass(f, nullptr));   // uploaded; index row written by the pass

    const auto plan = run(f, newPass(f, scopeOf({"/same.txt"})));
    EXPECT_EQ(planned(plan, ActionType::Download, "/same.txt") + planned(plan, ActionType::Upload, "/same.txt"), 0u)
        << "a notification about Vaulthalla's own write must not trigger a transfer";
}

TEST_F(UpstreamScopedSyncTest, MetadataFreeOverwriteOfAnEncryptedFileIsNotImportedWithoutAnImportPolicy) {
    // An encrypting vault with no event subscription importing foreign objects: a sealed object replaced by bytes
    // without Vaulthalla metadata is tampering as far as the vault knows. It must fail authentication, not become the
    // file's content.
    const auto f = remoteVault(superUser, sync::model::RemotePolicy::ConflictPolicy::KeepRemote);
    write(f, "/sealed.txt", "original sealed content");
    (void)run(f, newPass(f, nullptr));
    f.bucket->put("sealed.txt", bytes("replaced by another tool"), {});
    auto row = db::query::sync::RemoteObjectIndex::getFile(f.vault->id, "/sealed.txt");
    ASSERT_TRUE(row);
    row->remote_etag = f.bucket->get("sealed.txt")->etag;
    row->size_bytes = 24;
    row->content_hash.reset();
    row->remote_encrypted.reset();
    row->encryption_iv.clear();
    row->encrypted_with_key_version = 0;
    db::query::sync::RemoteObjectIndex::upsertEventFile(f.vault->id, row);

    auto scope = scopeOf({"/sealed.txt"});
    scope->changed.insert(u8"/sealed.txt");
    (void)run(f, newPass(f, scope));
    EXPECT_EQ(readLocal(f, "/sealed.txt"), "original sealed content");
}

TEST(UpstreamPassLease, OnePassPerVault) {
    sync::Controller controller;
    EXPECT_TRUE(controller.tryAcquirePass(41));
    EXPECT_FALSE(controller.tryAcquirePass(41));
    EXPECT_TRUE(controller.passRunning(41));
    EXPECT_TRUE(controller.tryAcquirePass(42)) << "other vaults are independent";
    controller.releasePass(41);
    EXPECT_FALSE(controller.passRunning(41));
    EXPECT_TRUE(controller.tryAcquirePass(41));
}

TEST_F(UpstreamScopedSyncTest, RunScopedRefusesUnknownAndDisabledVaults) {
    sync::Controller controller;
    EXPECT_EQ(controller.runScoped(987654, scopeOf({"/x"})), sync::Controller::ScopedResult::NoEngine);

    const auto f = remoteVault(superUser);
    {
        std::unique_lock lock(f.engine->mutex);
        f.engine->sync->enabled = false;
    }
    EXPECT_EQ(controller.runScoped(f.vault->id, scopeOf({"/x"})), sync::Controller::ScopedResult::Disabled);
    EXPECT_FALSE(controller.passRunning(f.vault->id)) << "a refused scoped pass holds no lease";
}

}
