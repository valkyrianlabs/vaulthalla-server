// Local versioning (recovery::local::versions) and its upstream backlog (recovery::local::backlog): every content
// change keeps the prior sealed generation (createFile overwrite, FUSE seal, deletes), nothing else does (rename, copy,
// key rotation), the off path costs no query, retention (keep_last / max age / quota; pending and snapshot-held blobs
// stay), crash leftovers, concurrent writers; and in upstream vaults the ordered replay through the VersionedBucket
// fake (outage, order, per-generation IV/key metadata, unversioned buckets, smart-cache release, price estimate).
// DB-backed; skipped without the VH_TEST_DB_* environment.

#include "../helpers/versioned_bucket.hpp"

#include "crypto/util/encrypt.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/recovery/Blob.hpp"
#include "db/query/recovery/Generation.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/recovery/Snapshot.hpp"
#include "db/query/sync/Conflict.hpp"
#include "db/query/sync/Event.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/file/Trashed.hpp"
#include "fs/ops/file.hpp"
#include "fuse/WorkingCopies.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "recovery/Store.hpp"
#include "recovery/local/Backlog.hpp"
#include "recovery/local/Versions.hpp"
#include "recovery/provider/State.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Cloud.hpp"
#include "sync/ConflictResolver.hpp"
#include "sync/Planner.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/RemoteManifest.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/ScopedOp.hpp"
#include "sync/model/Throughput.hpp"
#include "sync/rotation/Runtime.hpp"
#include "sync/tasks/Download.hpp"
#include "sync/tasks/Upload.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>
#include <pqxx/pqxx>

#include <fcntl.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_recovery_versions {

namespace rq = db::query::recovery;
namespace store = recovery::store;
namespace versions = recovery::local::versions;
namespace backlog = recovery::local::backlog;
namespace sfs = std::filesystem;
using recovery::local::Reason;
using test_support::versioned::VersionedBucket;
using test_support::versioned::Versioning;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "v" + std::to_string(n.fetch_add(1));
}

std::vector<uint8_t> bytes(const std::string& s) { return {s.begin(), s.end()}; }
std::string str(const std::vector<uint8_t>& b) { return {b.begin(), b.end()}; }

class RecoveryVersionsTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> superUser;
    inline static sfs::path scratch;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_recovery_versions] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = sfs::temp_directory_path() / ("vh_recovery_versions_" + tag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        scratch = root / "scratch";
        sfs::create_directories(paths::backingPath);
        sfs::create_directories(paths::mountPath);
        sfs::create_directories(scratch);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        superUser = vh::identities::manager().userByName("admin");
        recovery::local::invalidateAllPolicies();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    // ---- vaults ------------------------------------------------------------------------------------------------------

    static void setPolicy(const uint32_t vaultId, const recovery::LocalVersioningPolicy& lv) {
        rq::PolicyRow row;
        row.vault_id = vaultId;
        row.local_versioning = lv;
        rq::Policy::upsert(row);
        recovery::local::invalidatePolicy(vaultId);
    }

    static recovery::LocalVersioningPolicy on(std::optional<unsigned> keepLast = std::nullopt) {
        return {.enabled = true, .keep_last = keepLast, .max_age_days = std::nullopt, .quota_bytes = std::nullopt};
    }

    static std::shared_ptr<storage::Engine> localVault(const std::optional<recovery::LocalVersioningPolicy>& policy = on()) {
        const auto v = ops::vaults::create(superUser, {.name = "rv_local_" + tag(), .type = vault::model::VaultType::Local});
        if (policy) setPolicy(v->id, *policy);
        return runtime::Deps::get().storageManager->getEngine(v->id);
    }

    struct Cloud {
        std::shared_ptr<storage::CloudEngine> engine;
        std::shared_ptr<VersionedBucket> bucket;
        std::string bucketName;
    };

    static Cloud cloudVault(const sync::model::RemotePolicy::Strategy strategy, const bool encryptUpstream = true,
                            const std::optional<recovery::LocalVersioningPolicy>& policy = on()) {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "rv_key_" + tag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                          "us-east-1", "https://s3.example.com");
        const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        Cloud c;
        c.bucketName = "rv-" + tag();
        const auto v = ops::vaults::create(superUser, {.name = "rv_cloud_" + tag(), .type = vault::model::VaultType::S3,
                                                       .s3 = ops::vaults::S3Spec{.api_key_id = keyId, .bucket = c.bucketName,
                                                                                 .encrypt_upstream = encryptUpstream},
                                                       .accept_waiver = !encryptUpstream});
        c.engine = std::static_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(v->id));
        c.bucket = std::make_shared<VersionedBucket>(Versioning::Enabled, c.bucketName);
        c.engine->setS3ControllerForTesting(c.bucket);
        const auto rp = c.engine->remote_policy();
        rp->strategy = strategy;
        rp->conflict_policy = sync::model::RemotePolicy::ConflictPolicy::KeepLocal;
        if (policy) setPolicy(v->id, *policy);
        setBucketVersioning(c, "enabled", std::time(nullptr) - 60);
        return c;
    }

    // What the provider policy slice records about the bucket (upstream_bucket.versioning_*).
    static void setBucketVersioning(const Cloud& c, const std::string& status, const std::optional<std::time_t> settlesAt) {
        db::Transactions::exec("RecoveryVersionsTest::setBucketVersioning", [&](pqxx::work& txn) {
            txn.exec(R"SQL(
                INSERT INTO upstream_bucket (provider, account_ref, bucket, vault_id, versioning_status, versioning_settles_at)
                VALUES ('aws-s3', 'rv-test', $1, $2, $3, to_timestamp($4::double precision))
                ON CONFLICT (provider, account_ref, bucket) DO UPDATE
                    SET versioning_status = EXCLUDED.versioning_status,
                        versioning_settles_at = EXCLUDED.versioning_settles_at, updated_at = now()
            )SQL", pqxx::params{c.bucketName, c.engine->vault->id, status,
                                settlesAt ? std::make_optional(static_cast<double>(*settlesAt)) : std::nullopt});
        });
    }

    // ---- files -------------------------------------------------------------------------------------------------------

    static std::shared_ptr<fs::model::File> write(const std::shared_ptr<storage::Engine>& engine, const std::string& path,
                                                  const std::string& content,
                                                  const std::optional<Reason> reason = std::nullopt) {
        return fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                           .buffer = bytes(content), .engine = engine, .user = superUser,
                                           .overwrite = true, .version_reason = reason});
    }

    static std::shared_ptr<fs::model::File> row(const std::shared_ptr<storage::Engine>& engine, const std::string& path) {
        return db::query::fs::File::getFileByPath(engine->vault->id, path);
    }

    static std::string readLocal(const std::shared_ptr<storage::Engine>& engine, const std::string& path) {
        const auto reader = engine->openPlaintextReader(row(engine, path));
        return str(storage::readAll(*reader, 1 << 20));
    }

    // Local versions of a path, oldest first (whatever happened to the file since).
    static std::vector<rq::GenerationRow> versionsOf(const std::shared_ptr<storage::Engine>& engine,
                                                     const std::string& path) {
        auto rows = rq::Generation::listByPath(engine->vault->id, path, rq::Origin::Version, 1000);
        std::ranges::sort(rows, {}, &rq::GenerationRow::id);
        return rows;
    }

    // Sealed bytes under any key version the vault ever had (recovery reads).
    static std::string open(const std::shared_ptr<storage::Engine>& engine, const std::vector<uint8_t>& sealed,
                            const std::string& iv, const unsigned int keyVersion) {
        const auto key = engine->encryptionManager->historicalKeySnapshot(keyVersion);
        const std::vector<uint8_t> raw(key->bytes().begin(), key->bytes().end());
        return str(crypto::util::decrypt_aes256_gcm(sealed, raw, crypto::util::b64_decode(iv)));
    }

    static std::string decryptVersion(const std::shared_ptr<storage::Engine>& engine, const rq::GenerationRow& g) {
        if (!g.blob_id) throw std::runtime_error("version has no blob");
        const auto h = store::open(store::vaultRef(*engine->vault), *g.blob_id);
        if (!h || !h->present) throw std::runtime_error("blob missing");
        return open(engine, fs::ops::readFileToVector(h->path), h->row.encryption_iv, h->row.key_version);
    }

    static uint64_t blobsOf(const uint32_t vaultId) { return rq::Blob::usage(vaultId).blobs; }

    // The sync upload of one file, as a pass runs it (the replay goes first). True when it succeeded.
    static bool upload(const Cloud& c, const std::string& path) {
        sync::tasks::Upload task(c.engine, row(c.engine, path), std::make_shared<sync::model::ScopedOp>());
        auto done = task.promise.get_future();
        task();
        return std::get<bool>(done.get());
    }

    // One regular sync pass, inline: the real planner and tasks; the index mutation (and manifest) only when every
    // transfer succeeded, as sync::Cloud does.
    static std::vector<sync::model::Action> runPass(const Cloud& c) {
        auto cloud = std::make_shared<sync::Cloud>(c.engine);
        cloud->event = std::make_shared<sync::model::Event>();
        cloud->event->vault_id = c.engine->vault->id;
        cloud->event->timestamp_begin = std::time(nullptr);
        db::query::sync::Event::create(cloud->event);
        cloud->initBins();
        const auto plan = cloud->planPass();
        bool ok = true;
        for (const auto& a : plan) {
            using AT = sync::model::ActionType;
            if (a.type == AT::Upload) {
                sync::tasks::Upload task(c.engine, a.local, cloud->op(sync::model::Throughput::Metric::UPLOAD));
                auto done = task.promise.get_future();
                task();
                ok = std::get<bool>(done.get()) && ok;
            } else if (a.type == AT::Download) {
                sync::tasks::Download task(c.engine, a.remote, cloud->op(sync::model::Throughput::Metric::DOWNLOAD), false);
                auto done = task.promise.get_future();
                task();
                ok = std::get<bool>(done.get()) && ok;
            }
        }
        if (ok) c.engine->applyRemoteIndexMutation(plan);
        cloud->clearBins();
        return plan;
    }

    static unsigned planned(const std::vector<sync::model::Action>& plan, const sync::model::ActionType type) {
        return static_cast<unsigned>(std::ranges::count_if(plan, [&](const auto& a) { return a.type == type; }));
    }

    // The bucket's history of a key, oldest first, decrypted where Vaulthalla encrypted it.
    static std::vector<std::string> history(const Cloud& c, const std::string& path) {
        std::vector<std::string> out;
        auto versions = c.bucket->history(path.substr(1));
        std::ranges::reverse(versions);
        for (const auto& v : versions) {
            if (v.delete_marker) {
                out.emplace_back("<deleted>");
                continue;
            }
            if (v.meta.contains("vh-iv"))
                out.push_back(open(c.engine, v.body, v.meta.at("vh-iv"),
                                   static_cast<unsigned>(std::stoul(v.meta.at("vh-key-version")))));
            else out.push_back(str(v.body));
        }
        return out;
    }
};

// ---- capture: what keeps a version, what doesn't ---------------------------------------------------------------------

TEST_F(RecoveryVersionsTest, CreateFileOverwriteKeepsTheDecryptablePriorGeneration) {
    const auto engine = localVault();
    const auto first = write(engine, "/doc.txt", "first draft");
    const auto firstIv = first->encryption_iv;
    EXPECT_TRUE(versionsOf(engine, "/doc.txt").empty()) << "a new file replaces nothing";

    write(engine, "/doc.txt", "second draft");
    write(engine, "/doc.txt", "restored", Reason::Restore);
    EXPECT_EQ(readLocal(engine, "/doc.txt"), "restored");

    const auto kept = versionsOf(engine, "/doc.txt");
    ASSERT_EQ(kept.size(), 2u);
    EXPECT_EQ(decryptVersion(engine, kept[0]), "first draft");
    EXPECT_EQ(kept[0].reason, "overwrite");
    EXPECT_EQ(kept[0].encryption_iv, firstIv) << "the blob is the generation's sealed bytes, IV in the row";
    EXPECT_EQ(kept[0].upstream_state, rq::UpstreamState::None) << "a local vault has no backlog";
    EXPECT_EQ(kept[0].file_id, first->id);
    EXPECT_EQ(kept[0].size_bytes, std::string("first draft").size());
    EXPECT_EQ(decryptVersion(engine, kept[1]), "second draft");
    EXPECT_EQ(kept[1].reason, "restore") << "the caller says why the content was replaced";
    EXPECT_LT(kept[0].version_number, kept[1].version_number);
}

TEST_F(RecoveryVersionsTest, AFuseSealKeepsTheReplacedGenerationAndTruncationIsLabelled) {
    const auto engine = localVault();
    const auto f = write(engine, "/fuse.txt", "before the edit");
    ASSERT_TRUE(f->inode);
    fuse::WorkingCopies copies(scratch / ("wc_" + tag()), fuse::WorkingCopies::daemonHooks());

    auto h = copies.open(*f->inode, f, O_RDWR);
    const std::string edit = "BEFORE";
    ASSERT_EQ(copies.write(h, edit.data(), edit.size(), 0, std::nullopt), static_cast<ssize_t>(edit.size()));
    copies.release(h);
    EXPECT_EQ(readLocal(engine, "/fuse.txt"), "BEFORE the edit");

    auto t = copies.open(*f->inode, f, O_WRONLY | O_TRUNC);
    ASSERT_EQ(copies.write(t, "x", 1, 0, std::nullopt), 1);
    copies.release(t);

    const auto kept = versionsOf(engine, "/fuse.txt");
    ASSERT_EQ(kept.size(), 2u);
    EXPECT_EQ(decryptVersion(engine, kept[0]), "before the edit");
    EXPECT_EQ(kept[0].reason, "overwrite");
    EXPECT_EQ(decryptVersion(engine, kept[1]), "BEFORE the edit");
    EXPECT_EQ(kept[1].reason, "truncate") << "opened with O_TRUNC";
}

TEST_F(RecoveryVersionsTest, DeletesKeepTheLastGenerationAfterTheFileIsGone) {
    const auto engine = localVault();
    const auto f = write(engine, "/gone.txt", "last words");
    const auto backing = f->backing_path;
    fs::Filesystem::remove(engine->vaultPathToFusePath("/gone.txt"), superUser->id);
    EXPECT_FALSE(sfs::exists(backing)) << "the delete still removes the live file";
    EXPECT_FALSE(row(engine, "/gone.txt"));

    const auto kept = versionsOf(engine, "/gone.txt");
    ASSERT_EQ(kept.size(), 1u);
    EXPECT_EQ(kept[0].reason, "delete");
    EXPECT_FALSE(kept[0].file_id) << "outlives the file (ON DELETE SET NULL)";
    EXPECT_EQ(decryptVersion(engine, kept[0]), "last words");

    // A folder delete keeps every file in it.
    engine->mkdir("/dir", superUser);
    engine->mkdir("/dir/sub", superUser);
    write(engine, "/dir/a.txt", "alpha");
    write(engine, "/dir/sub/b.txt", "beta");
    fs::Filesystem::remove(engine->vaultPathToFusePath("/dir"), superUser->id);
    ASSERT_EQ(versionsOf(engine, "/dir/a.txt").size(), 1u);
    EXPECT_EQ(decryptVersion(engine, versionsOf(engine, "/dir/sub/b.txt").at(0)), "beta");
}

TEST_F(RecoveryVersionsTest, AnEditorSaveByRenameOverKeepsTheReplacedVersion) {
    // vim / LibreOffice / IDEs: write a temporary file, then rename it over the original.
    const auto engine = localVault();
    write(engine, "/doc.txt", "draft one");
    write(engine, "/.doc.txt.swp", "draft two");
    ASSERT_EQ(fs::Filesystem::rename(engine->vaultPathToFusePath("/.doc.txt.swp"), engine->vaultPathToFusePath("/doc.txt"),
                                     superUser, engine, fs::RenameMode::Replace), 0);
    EXPECT_EQ(readLocal(engine, "/doc.txt"), "draft two");
    EXPECT_FALSE(row(engine, "/.doc.txt.swp"));

    const auto kept = versionsOf(engine, "/doc.txt");
    ASSERT_EQ(kept.size(), 1u) << "the save replaced a generation: it is kept";
    EXPECT_EQ(kept[0].reason, "overwrite");
    EXPECT_EQ(decryptVersion(engine, kept[0]), "draft one");
    EXPECT_TRUE(versionsOf(engine, "/.doc.txt.swp").empty()) << "the temporary file moved, nothing of it was replaced";

    // Without local versioning a rename over keeps nothing.
    const auto off = localVault(std::nullopt);
    write(off, "/a.txt", "a");
    write(off, "/b.txt", "b");
    ASSERT_EQ(fs::Filesystem::rename(off->vaultPathToFusePath("/b.txt"), off->vaultPathToFusePath("/a.txt"), superUser,
                                     off, fs::RenameMode::Replace), 0);
    EXPECT_TRUE(versionsOf(off, "/a.txt").empty());
}

TEST_F(RecoveryVersionsTest, RenameCopyAndKeyRotationKeepNoVersion) {
    const auto engine = localVault();
    write(engine, "/r.txt", "same bytes");
    ASSERT_EQ(fs::Filesystem::rename(engine->vaultPathToFusePath("/r.txt"), engine->vaultPathToFusePath("/moved.txt"),
                                     superUser), 0);
    ASSERT_EQ(fs::Filesystem::copy({.from = engine->vaultPathToFusePath("/moved.txt"),
                                    .to = engine->vaultPathToFusePath("/copy.txt"), .userId = superUser->id,
                                    .engine = engine, .authorize = {}}), 0);

    // Rotation re-seals the same plaintext under the new key: not a content change.
    engine->encryptionManager->prepare_key_rotation();
    const auto deps = sync::rotation::runtimeDeps(engine);
    for (const auto* path : {"/moved.txt", "/copy.txt"})
        static_cast<void>(sync::rotation::rotateFile(row(engine, path), deps));
    engine->encryptionManager->finish_key_rotation();
    EXPECT_EQ(row(engine, "/moved.txt")->encrypted_with_key_version, engine->encryptionManager->get_key_version());

    for (const auto* path : {"/r.txt", "/moved.txt", "/copy.txt"}) EXPECT_TRUE(versionsOf(engine, path).empty()) << path;
    EXPECT_EQ(blobsOf(engine->vault->id), 0u);
    EXPECT_EQ(readLocal(engine, "/copy.txt"), "same bytes");
}

TEST_F(RecoveryVersionsTest, VersioningOffKeepsNothingAndCostsNoQueryPerWrite) {
    const auto engine = localVault(std::nullopt);
    write(engine, "/off.txt", "one");
    write(engine, "/off.txt", "two");   // the first overwrite loads (and caches) the policy
    const auto loads = versions::counters().policy_loads;
    for (int i = 0; i < 5; ++i) write(engine, "/off.txt", "again " + std::to_string(i));
    EXPECT_EQ(versions::counters().policy_loads, loads) << "the off path is decided in memory";
    EXPECT_TRUE(versionsOf(engine, "/off.txt").empty());
    EXPECT_EQ(blobsOf(engine->vault->id), 0u);

    // Turning it on applies to the next write (the policy writer invalidates the cache).
    setPolicy(engine->vault->id, on());
    write(engine, "/off.txt", "kept from now on");
    EXPECT_EQ(versionsOf(engine, "/off.txt").size(), 1u);
}

TEST_F(RecoveryVersionsTest, EmptyGenerationsAreSkippedNotKept) {
    const auto engine = localVault();
    write(engine, "/empty.txt", "");
    const auto skipped = versions::counters().skipped;
    write(engine, "/empty.txt", "");              // empty -> empty
    write(engine, "/empty.txt", "now something"); // the empty generation has nothing to keep
    EXPECT_TRUE(versionsOf(engine, "/empty.txt").empty());
    EXPECT_EQ(versions::counters().skipped, skipped + 2);
}

TEST_F(RecoveryVersionsTest, ConcurrentWritersGetDistinctVersionNumbers) {
    const auto engine = localVault();
    write(engine, "/busy.txt", "seed");
    constexpr int kThreads = 4, kWrites = 5;
    std::vector<std::thread> threads;
    for (int t = 0; t < kThreads; ++t)
        threads.emplace_back([&, t] {
            for (int i = 0; i < kWrites; ++i) write(engine, "/busy.txt", "t" + std::to_string(t) + "-" + std::to_string(i));
        });
    for (auto& t : threads) t.join();

    const auto kept = versionsOf(engine, "/busy.txt");
    ASSERT_EQ(kept.size(), static_cast<size_t>(kThreads * kWrites));
    std::set<int> numbers;
    for (const auto& g : kept) numbers.insert(g.version_number);
    EXPECT_EQ(numbers.size(), kept.size());
}

TEST_F(RecoveryVersionsTest, ACrashBetweenStagingAndCommitLeavesAnOrphanTheSweepRemoves) {
    const auto engine = localVault();
    const auto f = write(engine, "/crash.txt", "staged then lost");
    const auto ref = store::vaultRef(*engine->vault);
    sfs::path leftover;
    {
        auto pending = versions::retain(*engine, *row(engine, "/crash.txt"), Reason::Overwrite);
        ASSERT_TRUE(pending.active());
        // The process dies here: the staged blob (linked under its final name) has no row. Keep a file like it the
        // way a crash would leave it, then let this capture abort (which removes its own).
        std::vector<sfs::path> staged;
        for (const auto& e : sfs::recursive_directory_iterator(store::vaultDir(ref)))
            if (e.is_regular_file()) staged.push_back(e.path());
        ASSERT_EQ(staged.size(), 1u);
        leftover = staged[0].parent_path() / (staged[0].filename().string().substr(0, 2) + std::string(30, 'z'));
        sfs::create_hard_link(staged[0], leftover);
    }
    ASSERT_TRUE(sfs::exists(leftover));
    EXPECT_EQ(blobsOf(engine->vault->id), 0u) << "no row was ever written";
    EXPECT_TRUE(versionsOf(engine, "/crash.txt").empty());

    const auto report = store::sweep(ref, std::chrono::seconds(0));
    EXPECT_EQ(report.orphans_removed, 1u);
    EXPECT_FALSE(sfs::exists(leftover));
    EXPECT_EQ(readLocal(engine, "/crash.txt"), "staged then lost") << "the live file never depended on the capture";
}

// ---- retention -------------------------------------------------------------------------------------------------------

TEST_F(RecoveryVersionsTest, KeepLastPrunesRightAfterCaptureAndFreesTheBlobs) {
    const auto engine = localVault(on(2));
    for (int i = 0; i < 6; ++i) write(engine, "/k.txt", "gen " + std::to_string(i));
    const auto kept = versionsOf(engine, "/k.txt");
    ASSERT_EQ(kept.size(), 2u) << "keep_last 2, pruned in the capture's transaction";
    EXPECT_EQ(decryptVersion(engine, kept[0]), "gen 3");
    EXPECT_EQ(decryptVersion(engine, kept[1]), "gen 4");
    EXPECT_EQ(blobsOf(engine->vault->id), 2u) << "pruned blobs are removed after commit";
}

TEST_F(RecoveryVersionsTest, MaxAgeAndQuotaPruneOldestFirst) {
    const auto engine = localVault();
    for (int i = 0; i < 4; ++i) write(engine, "/q.txt", std::string(1000 + i, 'a' + static_cast<char>(i)));
    auto kept = versionsOf(engine, "/q.txt");
    ASSERT_EQ(kept.size(), 3u);
    const auto ref = store::vaultRef(*engine->vault);

    db::Transactions::exec("RecoveryVersionsTest::age", [&](pqxx::work& txn) {
        txn.exec("UPDATE file_versions SET created_at = now() - interval '10 days' WHERE id = $1", pqxx::params{kept[0].id});
    });
    auto policy = on();
    policy.max_age_days = 5;
    auto r = versions::applyRetention(ref, policy, std::time(nullptr));
    EXPECT_EQ(r.versions_removed, 1u);
    kept = versionsOf(engine, "/q.txt");
    ASSERT_EQ(kept.size(), 2u);
    EXPECT_EQ(kept[0].size_bytes, 1001u) << "the oldest went";

    policy = on();
    policy.quota_bytes = kept[1].cipher_bytes.value();   // room for one blob
    r = versions::applyRetention(ref, policy, std::time(nullptr));
    EXPECT_EQ(r.versions_removed, 1u);
    EXPECT_EQ(r.blobs_removed, 1u);
    kept = versionsOf(engine, "/q.txt");
    ASSERT_EQ(kept.size(), 1u);
    EXPECT_EQ(kept[0].size_bytes, 1002u) << "the newest stays";
}

TEST_F(RecoveryVersionsTest, ASnapshotHeldBlobOutlivesItsPrunedVersion) {
    const auto engine = localVault(on(1));
    write(engine, "/s.txt", "snapshotted");
    write(engine, "/s.txt", "next");
    const auto first = versionsOf(engine, "/s.txt").at(0);

    // A snapshot of the same generation references the same blob (dedupe by IV + key version).
    const auto snapshotId = rq::Snapshot::create({.vault_id = engine->vault->id, .name = "keep-" + tag(),
                                                  .root_path = "/s.txt", .root_type = recovery::PointKind::File});
    db::Transactions::exec("RecoveryVersionsTest::member", [&](pqxx::work& txn) {
        static_cast<void>(rq::Generation::insertSnapshotMember(
            txn, {.vault_id = engine->vault->id, .file_id = first.file_id, .blob_id = first.blob_id,
                  .content_hash = first.content_hash, .size_bytes = first.size_bytes, .mime_type = std::nullopt,
                  .path = "/s.txt", .mode = std::nullopt, .source_updated_at = std::nullopt, .created_by = std::nullopt,
                  .snapshot_id = snapshotId, .rel_path = "s.txt", .reason = std::nullopt,
                  .upstream_state = rq::UpstreamState::None, .upstream_key = std::nullopt}));
    });

    write(engine, "/s.txt", "and again");   // keep_last 1 prunes the first version
    const auto kept = versionsOf(engine, "/s.txt");
    ASSERT_EQ(kept.size(), 1u);
    EXPECT_NE(kept[0].id, first.id);
    const auto blob = store::open(store::vaultRef(*engine->vault), *first.blob_id);
    ASSERT_TRUE(blob);
    EXPECT_TRUE(blob->present) << "the snapshot still references it";
}

// The recovery rows ride in the content write's transaction; failing them must never fail the write (a FUSE seal would
// return EIO, an overwrite would be refused). attach() works under a savepoint: the version is skipped, the write lands.
TEST_F(RecoveryVersionsTest, ABrokenVersionAttachSkipsTheVersionButNeverTheWrite) {
    const auto engine = localVault();
    const auto ref = store::vaultRef(*engine->vault);
    const auto f = write(engine, "/b.txt", "one");

    // The live generation already has a blob (as a snapshot leaves it): retain() reuses it (Existing) ...
    auto held = store::captureLink(ref, f->backing_path, {.encryption_iv = f->encryption_iv,
                                                          .key_version = f->encrypted_with_key_version,
                                                          .plaintext_bytes = f->size_bytes,
                                                          .content_hash = f->content_hash});
    const auto heldId = db::Transactions::exec("RecoveryVersionsTest::held", [&](pqxx::work& txn) {
        return held.attach(txn);
    });
    held.committed();
    // ... and it is removed between retain() and attach().
    versions::setAttachHookForTesting([&](pqxx::work&) {
        EXPECT_TRUE(store::removeBlob(ref, heldId));
    });
    const auto failedBefore = versions::counters().failed;
    EXPECT_NO_THROW(write(engine, "/b.txt", "two"));
    versions::setAttachHookForTesting({});
    EXPECT_EQ(readLocal(engine, "/b.txt"), "two") << "the write committed";
    EXPECT_TRUE(versionsOf(engine, "/b.txt").empty()) << "that version was skipped";
    EXPECT_EQ(versions::counters().failed, failedBefore + 1);

    // A failing statement inside the attach (an FK error, …) aborts only the savepoint, through the FUSE seal too.
    versions::setAttachHookForTesting([](pqxx::work& txn) { txn.exec("SELECT 1 / 0"); });
    const auto cur = row(engine, "/b.txt");
    ASSERT_TRUE(cur->inode);
    fuse::WorkingCopies copies(scratch / ("wc_" + tag()), fuse::WorkingCopies::daemonHooks());
    auto h = copies.open(*cur->inode, cur, O_RDWR);
    ASSERT_EQ(copies.write(h, "T", 1, 0, std::nullopt), 1);
    EXPECT_NO_THROW(copies.release(h)) << "no EIO from the seal";
    versions::setAttachHookForTesting({});
    EXPECT_EQ(readLocal(engine, "/b.txt"), "Two");
    EXPECT_TRUE(versionsOf(engine, "/b.txt").empty());
    EXPECT_EQ(versions::counters().failed, failedBefore + 2);

    // Nothing left behind: the next write keeps its version as usual.
    write(engine, "/b.txt", "three");
    ASSERT_EQ(versionsOf(engine, "/b.txt").size(), 1u);
    EXPECT_EQ(decryptVersion(engine, versionsOf(engine, "/b.txt").at(0)), "Two");
}

// Off-path and critical-section costs: with local versioning off and nothing pending, uploads cost no backlog query
// (one check per vault, remembered until the policy changes); blobs a capture frees are unlinked after the content
// lock is released (FUSE seal, createFile overwrite), never inside it.
TEST_F(RecoveryVersionsTest, BacklogChecksAndBlobFreesStayOffTheHotPaths) {
    const auto off = cloudVault(sync::model::RemotePolicy::Strategy::Sync, true, std::nullopt);
    const auto checksBefore = versions::counters().backlog_checks;
    for (int i = 0; i < 3; ++i) {
        write(off.engine, "/o" + std::to_string(i) + ".txt", "x");
        ASSERT_TRUE(upload(off, "/o" + std::to_string(i) + ".txt"));
    }
    EXPECT_EQ(versions::counters().backlog_checks, checksBefore + 1) << "one check for the vault, not one per upload";
    setPolicy(off.engine->vault->id, on());   // a policy change forgets it
    setPolicy(off.engine->vault->id, {});
    write(off.engine, "/o0.txt", "y");
    ASSERT_TRUE(upload(off, "/o0.txt"));
    EXPECT_EQ(versions::counters().backlog_checks, checksBefore + 2);

    const auto engine = localVault(on(1));
    const auto f = write(engine, "/k.txt", "1");
    write(engine, "/k.txt", "2");
    unsigned frees = 0;
    versions::setDeferredFreeHookForTesting([&] {
        auto& m = fs::Filesystem::contentWriteMutex(f->id);
        EXPECT_TRUE(m.try_lock()) << "the content lock is released before the blobs go";
        m.unlock();
        ++frees;
    });
    write(engine, "/k.txt", "3");   // keep_last 1 prunes version "1" and frees its blob
    EXPECT_EQ(frees, 1u);
    fuse::WorkingCopies copies(scratch / ("wc_" + tag()), fuse::WorkingCopies::daemonHooks());
    const auto cur = row(engine, "/k.txt");
    auto h = copies.open(*cur->inode, cur, O_RDWR);
    ASSERT_EQ(copies.write(h, "4", 1, 0, std::nullopt), 1);
    copies.release(h);              // the seal prunes version "2"
    versions::setDeferredFreeHookForTesting({});
    EXPECT_EQ(frees, 2u);
    EXPECT_EQ(blobsOf(engine->vault->id), 1u) << "the frees did happen";
    EXPECT_EQ(decryptVersion(engine, versionsOf(engine, "/k.txt").at(0)), "3");
}

// A delete links the backing file into the store. A seal (overwrite, rotation) that renames new bytes over it between
// the delete reading the row and linking would leave a blob whose IV doesn't match its bytes. Deletes take the file's
// content lock and re-read the row: here the "seal" holds the lock while the delete waits, and the kept version is the
// sealed content, decryptable under its own IV.
TEST_F(RecoveryVersionsTest, ADeleteRacingASealKeepsTheGenerationTheRowDescribes) {
    const auto engine = localVault();
    const std::vector<std::pair<std::string, std::function<void(const std::string&)>>> deletes{
        {"Filesystem::remove", [&](const std::string& p) { fs::Filesystem::remove(engine->vaultPathToFusePath(p), superUser->id); }},
        {"Engine::removeLocally", [&](const std::string& p) { engine->removeLocally(p); }},
    };
    for (const auto& [name, remove] : deletes) {
        SCOPED_TRACE(name);
        const auto path = "/race-" + tag() + ".txt";
        const auto f = write(engine, path, "before the seal");
        std::atomic<bool> done{false};
        std::thread deleter;
        {
            std::unique_lock lock(fs::Filesystem::contentWriteMutex(f->id));
            deleter = std::thread([&] {
                remove(path);
                done = true;
            });
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
            EXPECT_FALSE(done) << "the delete waits for the content lock";

            // The seal's protocol, under the lock: sealed sidecar, row, rename over the backing file, cache.
            auto staged = std::make_shared<fs::model::File>(*row(engine, path));
            const auto sealed = engine->encryptionManager->encrypt(bytes("after the seal"), staged);
            const auto sidecar = fs::ops::contentSidecarPath(staged->backing_path);
            fs::ops::writeFileExclusive(sidecar, sealed);
            staged->size_bytes = std::string("after the seal").size();
            staged->content_hash = crypto::hash::blake2b(sidecar);
            db::Transactions::exec("RecoveryVersionsTest::seal", [&](pqxx::work& txn) {
                db::query::fs::File::updateFile(txn, staged);
            });
            sfs::rename(sidecar, staged->backing_path);
            runtime::Deps::get().fsCache->updateEntry(staged);
        }
        deleter.join();
        EXPECT_FALSE(row(engine, path));
        const auto kept = versionsOf(engine, path);
        ASSERT_EQ(kept.size(), 1u);
        EXPECT_EQ(decryptVersion(engine, kept[0]), "after the seal") << "the blob's IV matches its bytes";
    }
}

// ---- the upstream backlog ----------------------------------------------------------------------------------------------

TEST_F(RecoveryVersionsTest, AnOutageQueuesVersionsInOrderAndTheReplayKeepsIt) {
    const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
    write(c.engine, "/log.txt", "v1");
    ASSERT_TRUE(upload(c, "/log.txt"));

    write(c.engine, "/log.txt", "v2");
    c.bucket->failNext(VersionedBucket::Op::Put, VersionedBucket::Failure::Transport, 1);
    EXPECT_FALSE(upload(c, "/log.txt")) << "the provider is down";
    write(c.engine, "/log.txt", "v3");      // writes keep working locally
    write(c.engine, "/log.txt", "v4");

    auto kept = versionsOf(c.engine, "/log.txt");
    ASSERT_EQ(kept.size(), 3u);
    // The provider version index learned v1 from its own PUT (recovery::provider::noteOwnWrite): recognized by IV.
    EXPECT_EQ(kept[0].upstream_state, rq::UpstreamState::Sent) << "v1 was already upstream";
    EXPECT_TRUE(kept[0].upstream_version_id) << "pointing at the provider's version of v1";
    EXPECT_EQ(kept[1].upstream_state, rq::UpstreamState::Pending);
    EXPECT_EQ(kept[1].upstream_key, "log.txt");
    EXPECT_EQ(backlog::summary(c.engine->vault->id).pending_versions, 2u);

    // A replay that fails holds the current content back: the provider never sees v4 before v2/v3.
    c.bucket->failNext(VersionedBucket::Op::Put, VersionedBucket::Failure::Transport, 1);
    EXPECT_FALSE(upload(c, "/log.txt"));
    EXPECT_EQ(history(c, "/log.txt"), (std::vector<std::string>{"v1"}));
    kept = versionsOf(c.engine, "/log.txt");
    EXPECT_EQ(kept[1].upstream_state, rq::UpstreamState::Pending);
    EXPECT_EQ(kept[1].upstream_attempts, 1u);
    EXPECT_TRUE(kept[1].upstream_error);
    EXPECT_EQ(backlog::summary(c.engine->vault->id).failing, 1u);

    ASSERT_TRUE(upload(c, "/log.txt")) << "the provider is back";
    EXPECT_EQ(history(c, "/log.txt"), (std::vector<std::string>{"v1", "v2", "v3", "v4"}));

    kept = versionsOf(c.engine, "/log.txt");
    const auto versions = c.bucket->history("log.txt");   // newest first: v4, v3, v2, v1
    for (size_t i = 1; i < kept.size(); ++i) {
        EXPECT_EQ(kept[i].upstream_state, rq::UpstreamState::Sent);
        const auto& v = versions.at(versions.size() - 1 - i);
        EXPECT_EQ(kept[i].upstream_version_id, v.version_id);
        EXPECT_EQ(v.meta.at("vh-iv"), kept[i].encryption_iv.value()) << "each version carries its own IV";
        EXPECT_EQ(v.meta.at("content-hash"), kept[i].content_hash.value());
    }
    EXPECT_EQ(backlog::summary(c.engine->vault->id).pending_versions, 0u);
    EXPECT_TRUE(kept[1].blob_id) << "a sync vault keeps its local history";
}

// A replay interrupted half way leaves the bucket's current object at one of the file's own earlier generations,
// Vaulthalla's own write of its history. The next pass must finish the publication: before the fix it read that object
// as a remote change, so `ask` recorded a spurious conflict and keep_remote / keep_newest (LastModified) downloaded the
// stale generation over the live file. An already-synced file (g0 uploaded; g1 lands, g2 fails) and a new file (its
// first upload replays g0, then g1 fails), with the remote index from the DB and from a full LIST (ETag, no hash).
TEST_F(RecoveryVersionsTest, AnInterruptedReplayIsFinishedByTheNextPassUnderEveryPolicy) {
    using CP = sync::model::RemotePolicy::ConflictPolicy;
    using AT = sync::model::ActionType;
    struct Case {
        CP policy;
        bool fresh;     // never uploaded before the outage
        bool listed;    // the next pass lists the bucket instead of reading the index
    };
    for (const auto& [policy, fresh, listed] :
         {Case{CP::Ask, false, false}, Case{CP::KeepNewest, true, false}, Case{CP::Ask, false, true},
          Case{CP::KeepRemote, true, false}, Case{CP::KeepRemote, true, true}, Case{CP::Ask, true, false}}) {
        SCOPED_TRACE(std::string(sync::model::to_string(policy)) + (fresh ? ", new file" : ", synced file") +
                     (listed ? ", listed" : ", indexed"));
        const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
        c.engine->remote_policy()->conflict_policy = policy;
        std::vector<std::string> expected;
        if (!fresh) {
            write(c.engine, "/i.txt", "g0");
            ASSERT_EQ(planned(runPass(c), AT::Upload), 1u);
            ASSERT_EQ(history(c, "/i.txt"), (std::vector<std::string>{"g0"}));
            write(c.engine, "/i.txt", "g1");
            write(c.engine, "/i.txt", "g2");
            expected = {"g0", "g1"};
        } else {
            write(c.engine, "/i.txt", "g0");
            write(c.engine, "/i.txt", "g1");
            expected = {"g0"};
        }
        write(c.engine, "/i.txt", "current");
        // One replay lands, then a failure (a new vault's first pass publishes its index manifest only after its
        // transfers since #248, so nothing else is PUT first).
        c.bucket->failAfter(VersionedBucket::Op::Put, VersionedBucket::Failure::Transport, 1);
        ASSERT_EQ(planned(runPass(c), AT::Upload), 1u);
        ASSERT_EQ(history(c, "/i.txt"), expected) << "interrupted";
        ASSERT_EQ(readLocal(c.engine, "/i.txt"), "current");

        if (listed) {
            // Lose the index and the manifest: the next pass lists the bucket (ETags, object sizes, no hashes).
            db::query::sync::RemoteObjectIndex::replaceFromListObjects(c.engine->vault->id, {});
            (void)c.bucket->seedDeleteMarker(sync::model::remote_manifest::INDEX_V1_KEY);
        }
        const auto next = runPass(c);
        EXPECT_EQ(planned(next, AT::Upload), 1u) << "the publication is finished";
        EXPECT_EQ(planned(next, AT::Download), 0u) << "never the stale generation over the live file";
        EXPECT_EQ(readLocal(c.engine, "/i.txt"), "current");
        const auto full = fresh ? std::vector<std::string>{"g0", "g1", "current"}
                                : std::vector<std::string>{"g0", "g1", "g2", "current"};
        EXPECT_EQ(history(c, "/i.txt"), full);
        EXPECT_TRUE(db::query::sync::Conflict::openForVault(c.engine->vault->id).empty()) << "no conflict";
        EXPECT_EQ(backlog::summary(c.engine->vault->id).pending_versions, 0u);

        const auto after = runPass(c);
        EXPECT_EQ(planned(after, AT::Upload) + planned(after, AT::Download), 0u) << "settled";
    }
}

// An autosave/append workload during an outage would queue one full blob per write, every one replayed. A key keeps at
// most keep_last (else kDefaultPendingCap) pending versions; older ones are skipped ('coalesced'), and the version
// quota reaches pending versions too, visibly (skipped 'quota', reported).
TEST_F(RecoveryVersionsTest, TheUpstreamBacklogOfAKeyIsBoundedAndTheQuotaReachesIt) {
    const auto pendingOf = [](const std::vector<rq::GenerationRow>& rows) {
        return std::ranges::count_if(rows, [](const auto& g) { return g.upstream_state == rq::UpstreamState::Pending; });
    };

    // keep_last 3: the backlog is the newest three; older ones were coalesced and pruned with their blobs.
    const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync, true, on(3));
    const auto coalescedBefore = versions::counters().coalesced;
    for (int i = 0; i < 10; ++i) write(c.engine, "/auto.txt", "save " + std::to_string(i));
    auto kept = versionsOf(c.engine, "/auto.txt");
    EXPECT_EQ(pendingOf(kept), 3);
    EXPECT_EQ(kept.size(), 3u) << "coalesced versions beyond keep_last are pruned";
    EXPECT_EQ(blobsOf(c.engine->vault->id), 3u);
    EXPECT_GE(versions::counters().coalesced, coalescedBefore + 6);
    ASSERT_TRUE(upload(c, "/auto.txt"));
    EXPECT_EQ(history(c, "/auto.txt"), (std::vector<std::string>{"save 6", "save 7", "save 8", "save 9"}))
        << "three replays, then the current content";

    // No keep_last: the default cap; the coalesced versions stay as local versions, skipped, with the reason.
    const auto d = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
    const auto writes = versions::kDefaultPendingCap + 8;
    for (unsigned i = 0; i < writes; ++i) write(d.engine, "/log.txt", "line " + std::to_string(i));
    kept = versionsOf(d.engine, "/log.txt");
    ASSERT_EQ(kept.size(), writes - 1);
    EXPECT_EQ(pendingOf(kept), static_cast<long>(versions::kDefaultPendingCap));
    EXPECT_EQ(backlog::summary(d.engine->vault->id).pending_versions, versions::kDefaultPendingCap);
    EXPECT_EQ(kept.front().upstream_state, rq::UpstreamState::Skipped);
    EXPECT_EQ(kept.front().upstream_error, "coalesced");
    EXPECT_TRUE(kept.front().blob_id) << "still a local version";
    EXPECT_EQ(kept.back().upstream_state, rq::UpstreamState::Pending);

    // The version quota applies to pending versions too: dropped oldest first, skipped 'quota' first, reported.
    recovery::LocalVersioningPolicy tight = on();
    tight.quota_bytes = 0;
    const auto report = versions::applyRetention(store::vaultRef(*d.engine->vault), tight, std::time(nullptr));
    EXPECT_EQ(report.pending_dropped, versions::kDefaultPendingCap);
    EXPECT_TRUE(versionsOf(d.engine, "/log.txt").empty());
    EXPECT_EQ(backlog::summary(d.engine->vault->id).pending_versions, 0u);
    EXPECT_EQ(blobsOf(d.engine->vault->id), 0u);
}

// Every writer of a key's current content replays the key's backlog first, not only the sync Upload task: a conflict
// resolved keep_local and a key rotation that re-publishes the file. Otherwise the provider got the current content
// before its predecessors (and those were replayed on top of it later).
TEST_F(RecoveryVersionsTest, KeepLocalResolutionAndRotationReplayTheBacklogFirst) {
    {
        const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
        c.engine->remote_policy()->conflict_policy = sync::model::RemotePolicy::ConflictPolicy::Ask;
        write(c.engine, "/k.txt", "k0");
        ASSERT_EQ(planned(runPass(c), sync::model::ActionType::Upload), 1u);
        write(c.engine, "/k.txt", "k1");
        write(c.engine, "/k.txt", "mine");
        (void)c.bucket->seed("k.txt", "theirs");   // someone else's write meanwhile
        db::query::sync::RemoteObjectIndex::replaceFromListObjects(c.engine->vault->id, {});
        (void)c.bucket->seedDeleteMarker(sync::model::remote_manifest::INDEX_V1_KEY);
        (void)runPass(c);   // lists the bucket: both sides changed
        const auto open = db::query::sync::Conflict::openForVault(c.engine->vault->id);
        const auto fileId = row(c.engine, "/k.txt")->id;
        ASSERT_TRUE(open.contains(fileId));
        sync::ConflictResolver::resolve(c.engine, open.at(fileId), sync::ConflictDecision::KeepLocal);
        EXPECT_EQ(history(c, "/k.txt"), (std::vector<std::string>{"k0", "theirs", "k1", "mine"}));
        EXPECT_EQ(backlog::summary(c.engine->vault->id).pending_versions, 0u);
    }
    {
        const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
        write(c.engine, "/r.txt", "r1");
        ASSERT_TRUE(upload(c, "/r.txt"));
        write(c.engine, "/r.txt", "r2");
        write(c.engine, "/r.txt", "r3");
        c.engine->encryptionManager->prepare_key_rotation();
        const auto deps = sync::rotation::runtimeDeps(c.engine);
        static_cast<void>(sync::rotation::rotateFile(row(c.engine, "/r.txt"), deps));
        c.engine->encryptionManager->finish_key_rotation();
        EXPECT_EQ(history(c, "/r.txt"), (std::vector<std::string>{"r1", "r2", "r3"}))
            << "r2 replayed before the rotation published r3";
        EXPECT_EQ(backlog::summary(c.engine->vault->id).pending_versions, 0u);
    }
}

TEST_F(RecoveryVersionsTest, AReplayedGenerationKeepsItsOwnKeyVersionAcrossARotation) {
    for (const bool encryptUpstream : {true, false}) {
        SCOPED_TRACE(encryptUpstream ? "encrypted upstream" : "plaintext upstream");
        const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync, encryptUpstream);
        write(c.engine, "/rot.txt", "v1");
        ASSERT_TRUE(upload(c, "/rot.txt"));
        write(c.engine, "/rot.txt", "v2");                 // keeps v1 (old key, already upstream)
        const auto oldKey = row(c.engine, "/rot.txt")->encrypted_with_key_version;
        c.engine->encryptionManager->prepare_key_rotation();
        c.engine->encryptionManager->finish_key_rotation();
        write(c.engine, "/rot.txt", "v3");                 // keeps v2, sealed under the retired key
        ASSERT_NE(row(c.engine, "/rot.txt")->encrypted_with_key_version, oldKey);

        ASSERT_TRUE(upload(c, "/rot.txt"));
        const auto versions = c.bucket->history("rot.txt");   // newest first
        ASSERT_EQ(versions.size(), 3u);
        if (encryptUpstream) {
            EXPECT_EQ(versions[1].meta.at("vh-key-version"), std::to_string(oldKey)) << "the replay kept v2's key";
            EXPECT_EQ(versions[0].meta.at("vh-key-version"), std::to_string(oldKey + 1));
            EXPECT_EQ(history(c, "/rot.txt"), (std::vector<std::string>{"v1", "v2", "v3"}));
        } else {
            EXPECT_EQ(versions[1].meta.at("vh-encrypted"), "false");
            EXPECT_EQ(str(versions[1].body), "v2") << "decrypted with the retired key, sent as plaintext";
            EXPECT_EQ(str(versions[0].body), "v3");
        }
    }
}

TEST_F(RecoveryVersionsTest, ABucketWithoutHistorySkipsTheBacklog) {
    const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
    c.bucket->setVersioning(Versioning::Unversioned);
    setBucketVersioning(c, "unversioned", std::nullopt);
    write(c.engine, "/u.txt", "a");
    ASSERT_TRUE(upload(c, "/u.txt"));
    write(c.engine, "/u.txt", "b");
    write(c.engine, "/u.txt", "c");
    c.bucket->resetCounters();
    ASSERT_TRUE(upload(c, "/u.txt"));
    EXPECT_EQ(c.bucket->counters().put, 1u) << "only the latest content";
    for (const auto& g : versionsOf(c.engine, "/u.txt")) EXPECT_EQ(g.upstream_state, rq::UpstreamState::Skipped);
    EXPECT_TRUE(versionsOf(c.engine, "/u.txt").at(1).blob_id) << "kept locally all the same";

    // Propagating (enabled, not settled yet) doesn't replay either; maintenance skips backlogs of unversioned buckets.
    const auto p = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
    setBucketVersioning(p, "enabled", std::time(nullptr) + 600);
    EXPECT_FALSE(recovery::provider::bucketVersioningForVault(p.engine->vault->id).keepsHistory());
    write(p.engine, "/p.txt", "1");
    write(p.engine, "/p.txt", "2");
    setBucketVersioning(p, "suspended", std::nullopt);
    const auto report = versions::maintain(std::time(nullptr), false);
    EXPECT_GE(report.backlog_skipped, 1u);
    EXPECT_EQ(versionsOf(p.engine, "/p.txt").at(0).upstream_state, rq::UpstreamState::Skipped);
}

// #249: pending generations of a deleted file whose delete already reached the bucket (the trash purge deletes the
// object without replaying the backlog), or whose key is never written again, used to stay pending forever and keep
// their blobs. Maintenance settles them: replayed into a bucket that keeps history (then deleted again, so the file
// stays deleted), skipped 'orphaned' where there is no history to complete; rows of any other key are not touched.
TEST_F(RecoveryVersionsTest, MaintenanceSettlesTheBacklogOfADeletedFile) {
    const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
    const auto vaultId = c.engine->vault->id;
    // Deletes the file and purges it upstream the way Local::removeTrashedFiles does (no replay first).
    const auto deleteAndPurge = [&](const std::string& path) {
        fs::Filesystem::remove(c.engine->vaultPathToFusePath(path), superUser->id);
        for (const auto& t : db::query::fs::File::listTrashedFiles(vaultId)) {
            if (t->path != path) continue;
            c.engine->purge(t);
            db::query::sync::RemoteObjectIndex::deleteKey(vaultId, t->path);
            c.engine->publishRemoteIndexManifestWithRetry();
            db::query::fs::File::markTrashedFileDeleted(t->id);
        }
    };
    const auto pendingOf = [&](const std::string& path) {
        unsigned n = 0;
        for (const auto& g : versionsOf(c.engine, path)) n += g.upstream_state == rq::UpstreamState::Pending;
        return n;
    };

    // o.txt: synced, then edited while the provider was down, then deleted and purged with the provider up. g1 and g2
    // are pending (each retained when the next write replaced it); g3, retained by the delete, stays local (a sync
    // vault's delete doesn't queue its last generation upstream).
    write(c.engine, "/o.txt", "g0");
    ASSERT_EQ(planned(runPass(c), sync::model::ActionType::Upload), 1u);
    c.bucket->failNext(VersionedBucket::Op::Put, VersionedBucket::Failure::Transport, 1);
    write(c.engine, "/o.txt", "g1");
    EXPECT_FALSE(upload(c, "/o.txt")) << "the provider is down";
    write(c.engine, "/o.txt", "g2");
    write(c.engine, "/o.txt", "g3");
    deleteAndPurge("/o.txt");
    ASSERT_EQ(history(c, "/o.txt"), (std::vector<std::string>{"g0", "<deleted>"}));
    ASSERT_EQ(pendingOf("/o.txt"), 2u) << "g1 and g2 never reached the bucket";

    // never.txt: created, edited and deleted before any upload: the bucket never had its content (the purge's DELETE
    // only left a delete marker).
    write(c.engine, "/never.txt", "n0");
    write(c.engine, "/never.txt", "n1");
    write(c.engine, "/never.txt", "n2");
    deleteAndPurge("/never.txt");
    ASSERT_EQ(pendingOf("/never.txt"), 2u);

    // Keys a pass will still write or delete keep their rows: a live file, and a trashed file whose object is still
    // in the bucket (its upstream delete is pending).
    write(c.engine, "/live.txt", "l0");
    write(c.engine, "/trashed.txt", "t0");
    ASSERT_EQ(planned(runPass(c), sync::model::ActionType::Upload), 2u);
    write(c.engine, "/live.txt", "l1");
    write(c.engine, "/live.txt", "l2");
    write(c.engine, "/trashed.txt", "t1");
    write(c.engine, "/trashed.txt", "t2");
    fs::Filesystem::remove(c.engine->vaultPathToFusePath("/trashed.txt"), superUser->id);
    const auto liveBefore = pendingOf("/live.txt");
    const auto trashedBefore = pendingOf("/trashed.txt");
    ASSERT_GE(liveBefore, 1u);
    ASSERT_GE(trashedBefore, 1u);

    c.bucket->resetCounters();
    const auto report = versions::maintain(std::time(nullptr), false);
    for (const auto& e : report.errors) EXPECT_FALSE(e.starts_with("vault " + std::to_string(vaultId) + " ")) << e;

    // Replayed oldest first, then deleted again: the provider's history is complete and the file stays deleted.
    EXPECT_EQ(pendingOf("/o.txt"), 0u);
    for (const auto& g : versionsOf(c.engine, "/o.txt"))
        if (g.upstream_key) {
            EXPECT_EQ(g.upstream_state, rq::UpstreamState::Sent) << g.id;
        }
    EXPECT_EQ(history(c, "/o.txt"), (std::vector<std::string>{"g0", "<deleted>", "g1", "g2", "<deleted>"}));
    EXPECT_FALSE(c.bucket->current("o.txt")) << "never resurrected";
    EXPECT_FALSE(db::query::sync::RemoteObjectIndex::getFile(vaultId, "/o.txt"));
    EXPECT_GE(report.backlog_replayed, 2u);

    // Never upstream: nothing to complete, nothing sent.
    EXPECT_EQ(pendingOf("/never.txt"), 0u);
    unsigned orphaned = 0;
    for (const auto& g : versionsOf(c.engine, "/never.txt"))
        orphaned += g.upstream_state == rq::UpstreamState::Skipped && g.upstream_error == std::optional<std::string>("orphaned");
    EXPECT_EQ(orphaned, 2u);
    EXPECT_EQ(history(c, "/never.txt"), (std::vector<std::string>{"<deleted>"}));
    EXPECT_GE(report.backlog_orphaned, 2u);

    // Untouched: they are a pass's to replay.
    EXPECT_EQ(pendingOf("/live.txt"), liveBefore);
    EXPECT_EQ(pendingOf("/trashed.txt"), trashedBefore);
    const auto requests = c.bucket->counters();
    EXPECT_EQ(requests.put, 2u) << "g1 and g2 only";
    EXPECT_EQ(requests.del, 1u);
    EXPECT_EQ(requests.head, 1u) << "the absence check of o.txt";

    // The next pass neither downloads the replayed generations nor re-sends anything, and maintenance is idempotent.
    const auto next = runPass(c);
    for (const auto& a : next)
        if (a.type == sync::model::ActionType::Download && a.remote) {
            EXPECT_NE(a.remote->path.string(), "/o.txt") << "a replayed generation downloaded as the deleted file";
        }
    EXPECT_FALSE(row(c.engine, "/o.txt"));
    c.bucket->resetCounters();
    (void)versions::maintain(std::time(nullptr), false);
    EXPECT_EQ(c.bucket->counters().put + c.bucket->counters().del, 0u);
    EXPECT_EQ(backlog::summary(vaultId).pending_versions, pendingOf("/live.txt") + pendingOf("/trashed.txt"));
}

TEST_F(RecoveryVersionsTest, MaintenanceSkipsTheOrphanedBacklogOfABucketWithoutHistoryAndWaitsWhileItPropagates) {
    // Propagating (enabled, not settled): nothing yet, no request.
    const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
    write(c.engine, "/p.txt", "p0");
    ASSERT_TRUE(upload(c, "/p.txt"));
    c.bucket->failNext(VersionedBucket::Op::Put, VersionedBucket::Failure::Transport, 1);
    write(c.engine, "/p.txt", "p1");
    EXPECT_FALSE(upload(c, "/p.txt"));
    write(c.engine, "/p.txt", "p2");
    fs::Filesystem::remove(c.engine->vaultPathToFusePath("/p.txt"), superUser->id);
    for (const auto& t : db::query::fs::File::listTrashedFiles(c.engine->vault->id))
        if (t->path == "/p.txt") {
            c.engine->purge(t);
            db::query::fs::File::markTrashedFileDeleted(t->id);
        }
    setBucketVersioning(c, "enabled", std::time(nullptr) + 600);
    c.bucket->resetCounters();
    (void)versions::maintain(std::time(nullptr), false);
    const auto pending = [&] {
        unsigned n = 0;
        for (const auto& g : versionsOf(c.engine, "/p.txt")) n += g.upstream_state == rq::UpstreamState::Pending;
        return n;
    };
    EXPECT_GE(pending(), 1u) << "waits for the propagation window";
    EXPECT_EQ(c.bucket->counters().put + c.bucket->counters().head + c.bucket->counters().del, 0u);

    // The bucket keeps no history (suspended): skipped 'orphaned', without a request.
    setBucketVersioning(c, "suspended", std::nullopt);
    (void)versions::maintain(std::time(nullptr), false);
    EXPECT_EQ(pending(), 0u);
    bool orphaned = false;
    for (const auto& g : versionsOf(c.engine, "/p.txt"))
        orphaned = orphaned || g.upstream_error == std::optional<std::string>("orphaned");
    EXPECT_TRUE(orphaned);
    EXPECT_EQ(c.bucket->counters().put + c.bucket->counters().head + c.bucket->counters().del, 0u);
}

TEST_F(RecoveryVersionsTest, SmartCacheReleasesBodiesTheProviderHoldsAndKeepsTheRows) {
    const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Cache);
    write(c.engine, "/c.txt", "c1");
    ASSERT_TRUE(upload(c, "/c.txt"));
    write(c.engine, "/c.txt", "c2");
    write(c.engine, "/c.txt", "c3");
    ASSERT_EQ(blobsOf(c.engine->vault->id), 2u);

    ASSERT_TRUE(upload(c, "/c.txt"));
    const auto kept = versionsOf(c.engine, "/c.txt");
    ASSERT_EQ(kept.size(), 2u);
    EXPECT_EQ(kept[1].upstream_state, rq::UpstreamState::Sent);
    EXPECT_FALSE(kept[1].blob_id) << "the provider holds c2: no local duplicate";
    EXPECT_TRUE(kept[1].upstream_version_id) << "the row stays, as a provider-held version";
    EXPECT_EQ(kept[0].upstream_state, rq::UpstreamState::Sent) << "c1 was already upstream (indexed by its own PUT)";
    EXPECT_TRUE(kept[0].upstream_version_id);
    EXPECT_FALSE(kept[0].blob_id) << "the provider holds c1 too: no local duplicate";
    EXPECT_EQ(blobsOf(c.engine->vault->id), 0u);
    EXPECT_EQ(history(c, "/c.txt"), (std::vector<std::string>{"c1", "c2", "c3"}));
}

TEST_F(RecoveryVersionsTest, ThePriceEstimateCountsTheReplays) {
    const auto c = cloudVault(sync::model::RemotePolicy::Strategy::Sync);
    write(c.engine, "/e.txt", "e1");
    ASSERT_TRUE(upload(c, "/e.txt"));
    write(c.engine, "/e.txt", "e2");
    write(c.engine, "/e.txt", "e3");
    const auto file = row(c.engine, "/e.txt");
    const std::vector<sync::model::Action> plan{
        {.type = sync::model::ActionType::Upload, .key = {.rel = u8"e.txt"}, .local = file, .remote = nullptr,
         .freeAfterDownload = false}};

    const auto pendingBytes = [&] {
        uint64_t total = 0;
        for (const auto& g : versionsOf(c.engine, "/e.txt")) total += g.cipher_bytes.value_or(0);
        return total;
    }();
    const auto withHistory = sync::Planner::estimateS3Cost(plan);
    EXPECT_EQ(withHistory.put_requests, 1u + 1u + 2u) << "upload + index manifest + two replays";
    EXPECT_EQ(withHistory.planned_upload_bytes, file->size_bytes + pendingBytes);

    setBucketVersioning(c, "unversioned", std::nullopt);
    const auto without = sync::Planner::estimateS3Cost(plan);
    EXPECT_EQ(without.put_requests, 2u) << "nothing is replayed into a bucket without history";
}

}
