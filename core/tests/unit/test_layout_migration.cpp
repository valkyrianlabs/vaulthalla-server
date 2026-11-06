// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
//
// LayoutMigration* (#373, design/encryption/01-provider-blind-storage.md §6 and §8 as the issue's consolidated scope
// keeps them): real path_v0 vaults on the VersionedBucket fake (S3 versioning, Object Lock, injected faults) migrate
// to opaque_v1. Every retained version, delete marker, backlog generation and current content is re-sealed into
// o/<uid> and verified by decryption; nothing legacy is touched before the cutover or deleted before the waiting period
// and a confirmed cleanup; a failure leaves path_v0; Object Lock and refused deletes block, never force; status is
// never complete while a legacy version is listed; LayoutMigrationCost: the estimate matches what was sent.

#include "../helpers/versioned_bucket.hpp"

#include "crypto/util/encrypt.hpp"
#include "crypto/vhf1/Format.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/recovery/Generation.hpp"
#include "db/query/recovery/ObjectVersion.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/sync/Event.hpp"
#include "db/query/sync/ObjectIdentity.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "db/query/vault/LayoutMigration.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/ops/file.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/VaultLayout.hpp"
#include "ops/Vaults.hpp"
#include "recovery/local/Versions.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "stats/model/SystemHealth.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/ObjectKeys.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "storage/s3/provider/Registry.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/Cloud.hpp"
#include "sync/Controller.hpp"
#include "sync/model/Action.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "sync/model/Throughput.hpp"
#include "sync/tasks/Download.hpp"
#include "sync/tasks/Upload.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/LayoutMigration.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace vh::test_layout_migration {

namespace keys = storage::object_keys;
namespace content = vault::content;
namespace lm = vault::layout;
namespace sfs = std::filesystem;
using test_support::versioned::VersionedBucket;
using test_support::versioned::Versioning;
using Bytes = std::vector<uint8_t>;
using Q = db::query::vault::LayoutMigration;
using Strategy = sync::model::RemotePolicy::Strategy;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "m" + std::to_string(n.fetch_add(1));
}

Bytes bytes(const std::string& s) { return {s.begin(), s.end()}; }
std::string str(const Bytes& b) { return {b.begin(), b.end()}; }

// A crash at a named step: not a std::exception, so run() lets it through like a dying process.
struct Crash {
    std::string at;
};

class LayoutMigrationTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> superUser;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_layout_migration] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = sfs::temp_directory_path() / ("vh_layout_migration_" + tag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        sfs::create_directories(paths::backingPath);
        sfs::create_directories(paths::mountPath);

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

    void TearDown() override { storage::upstream::guard::clearForTesting(); }

    struct Vault {
        std::shared_ptr<storage::CloudEngine> engine;
        std::shared_ptr<VersionedBucket> bucket;
        std::string bucketName;
        [[nodiscard]] uint32_t id() const { return engine->vault->id; }
    };

    // An encrypting cloud vault on path_v0 (this binary's default for new encrypting vaults), its key exported (the
    // recovery material the migration requires), on a versioned bucket unless told otherwise.
    static Vault legacyVault(const Versioning mode = Versioning::Enabled, const Strategy strategy = Strategy::Sync,
                             const bool localVersioning = false) {
        auto apiKey = std::make_shared<vault::model::APIKey>(superUser->id, "lm_key_" + tag(),
                                                             vault::model::S3Provider::AWS, "AKIATESTACCESSKEY000",
                                                             "secret-value-0000000000000000000000000", "us-east-1",
                                                             "https://s3.example.com");
        const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(apiKey);
        Vault v;
        v.bucketName = "lm-" + tag();
        const auto created = ops::vaults::create(superUser, {.name = "lm_vault_" + tag(),
                                                             .type = vault::model::VaultType::S3,
                                                             .s3 = ops::vaults::S3Spec{.api_key_id = keyId,
                                                                                       .bucket = v.bucketName}});
        v.engine = std::static_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(created->id));
        EXPECT_FALSE(v.engine->opaqueLayout()) << "a legacy (path_v0) vault";
        v.bucket = std::make_shared<VersionedBucket>(mode, v.bucketName);
        v.bucket->setNow(std::time(nullptr) - 3600);
        v.engine->setS3ControllerForTesting(v.bucket);
        v.engine->setRemoteFetchGate([](const storage::CloudEngine&, const storage::RemoteFetchRequest&) {
            return std::unique_ptr<storage::RemoteFetchReservation>{};
        });
        const auto rp = v.engine->remote_policy();
        rp->strategy = strategy;
        rp->conflict_policy = sync::model::RemotePolicy::ConflictPolicy::Ask;
        db::Transactions::exec("LayoutMigrationTest::setup", [&](pqxx::work& txn) {
            txn.exec("UPDATE vault_keys SET exported_version = version, exported_at = now() WHERE vault_id = $1",
                     pqxx::params{created->id});
            if (mode == Versioning::Enabled)
                txn.exec(R"SQL(
                    INSERT INTO upstream_bucket (provider, account_ref, bucket, vault_id, versioning_status,
                                                 versioning_settles_at)
                    VALUES ('aws-s3', 'lm-test', $1, $2, 'enabled', now() - interval '1 minute')
                    ON CONFLICT (provider, account_ref, bucket) DO UPDATE SET versioning_status = 'enabled'
                )SQL", pqxx::params{v.bucketName, created->id});
        });
        if (localVersioning) {
            db::query::recovery::PolicyRow row;
            row.vault_id = created->id;
            row.local_versioning = {.enabled = true, .keep_last = std::nullopt, .max_age_days = std::nullopt,
                                    .quota_bytes = std::nullopt};
            db::query::recovery::Policy::upsert(row);
            recovery::local::invalidatePolicy(created->id);
        }
        return v;
    }

    static std::shared_ptr<fs::model::File> write(const Vault& v, const std::string& path, const std::string& text) {
        return fs::Filesystem::createFile({.path = path, .fuse_path = v.engine->vaultPathToFusePath(path),
                                           .buffer = bytes(text), .engine = v.engine, .user = superUser,
                                           .overwrite = true});
    }

    static std::shared_ptr<fs::model::File> row(const Vault& v, const std::string& path) {
        return db::query::fs::File::getFileByPath(v.id(), path);
    }

    // The file's backing bytes rewritten in the legacy format (one AES-256-GCM message under the current key), as
    // builds before #367 stored every file; the row (and the cached entry) point at the legacy IV.
    static void makeLegacy(const Vault& v, const std::string& path) {
        const auto f = row(v, path);
        ASSERT_TRUE(f);
        const auto text = readLocal(v, path);
        const auto [key, version] = v.engine->encryptionManager->currentKey();
        std::vector<uint8_t> iv;
        const auto sealed = crypto::util::encrypt_aes256_gcm(bytes(text), key->bytes(), iv);
        fs::ops::writeFileAtomic(f->backing_path, sealed);
        auto next = *f;
        next.encryption_iv = crypto::util::b64_encode(iv);
        next.encrypted_with_key_version = version;
        ASSERT_TRUE(db::query::fs::File::compareAndSetEncryptionIVAndVersion(next, f->encryption_iv,
                                                                            f->encrypted_with_key_version));
        if (const auto cached = std::dynamic_pointer_cast<fs::model::File>(
                runtime::Deps::get().fsCache->getEntry(v.engine->vaultPathToFusePath(path)))) {
            cached->encryption_iv = next.encryption_iv;
            cached->encrypted_with_key_version = version;
        }
        ASSERT_EQ(content::formatOf(row(v, path)->encryption_iv), content::Format::Gcm0);
    }

    static std::string readLocal(const Vault& v, const std::string& path) {
        const auto reader = v.engine->openPlaintextReader(row(v, path));
        return str(storage::readAll(*reader, 64 << 20));
    }

    // One regular sync pass inline: trash purge, the bins, the plan, the transfers, the index and the manifest.
    static std::vector<sync::model::Action> pass(const Vault& v) {
        auto cloud = std::make_shared<sync::Cloud>(v.engine);
        cloud->event = std::make_shared<sync::model::Event>();
        cloud->event->vault_id = v.id();
        cloud->event->timestamp_begin = std::time(nullptr);
        db::query::sync::Event::create(cloud->event);
        cloud->removeTrashedFiles();
        cloud->processFutures();
        cloud->initBins();
        const auto plan = cloud->planPass();
        bool ok = true;
        for (const auto& a : plan) {
            using AT = sync::model::ActionType;
            if (a.type == AT::EnsureDirectories) {
                cloud->ensureDirectoriesFromRemote();
            } else if (a.type == AT::Upload) {
                sync::tasks::Upload task(v.engine, a.local, cloud->op(sync::model::Throughput::Metric::UPLOAD));
                auto done = task.promise.get_future();
                task();
                ok = std::get<bool>(done.get()) && ok;
            } else if (a.type == AT::Download || a.type == AT::IndexRemoteOnly) {
                const bool index = a.type == AT::IndexRemoteOnly;
                sync::tasks::Download task(v.engine, a.remote,
                                           cloud->op(index ? sync::model::Throughput::Metric::INDEX
                                                           : sync::model::Throughput::Metric::DOWNLOAD),
                                           index);
                auto done = task.promise.get_future();
                task();
                ok = std::get<bool>(done.get()) && ok;
            }
        }
        EXPECT_TRUE(ok) << "every transfer of the pass succeeded";
        if (ok) v.engine->applyRemoteIndexMutation(plan);
        cloud->clearBins();
        return plan;
    }

    static unsigned transfers(const std::vector<sync::model::Action>& plan) {
        unsigned n = 0;
        for (const auto& a : plan)
            if (a.type == sync::model::ActionType::Upload || a.type == sync::model::ActionType::Download ||
                a.type == sync::model::ActionType::DeleteRemote || a.type == sync::model::ActionType::DeleteLocal)
                ++n;
        return n;
    }

    // Drops the local copy: the row becomes index-only (the remote object's metadata), as a cache eviction leaves it.
    static void evict(const Vault& v, const std::string& path) {
        const auto indexed = db::query::sync::RemoteObjectIndex::getFile(v.id(), path);
        ASSERT_TRUE(indexed) << path;
        (void)v.engine->indexAndDeleteFile(indexed);
        ASSERT_FALSE(sfs::exists(row(v, path)->backing_path));
    }

    static void remove(const Vault& v, const std::string& path) {
        fs::Filesystem::remove(v.engine->vaultPathToFusePath(path), superUser->id);
    }

    static sync::Controller& leases() {
        static sync::Controller controller;
        return controller;
    }

    static lm::RunDeps deps() {
        lm::RunDeps d;
        d.tryAcquirePass = [](const uint32_t id) { return leases().tryAcquirePass(id); };
        d.releasePass = [](const uint32_t id) { leases().releasePass(id); };
        d.pricePreflight = [](const storage::CloudEngine&, lm::Estimate& e, bool) { e.priced = false; };
        return d;
    }

    static void start(const Vault& v) {
        (void)ops::vault_layout::start(superUser, {.vault_id = v.id(), .accept_unpriced = true});
    }

    static lm::RunResult migrate(const Vault& v, const lm::RunDeps& d = deps()) {
        start(v);
        return lm::run(v.engine, d);
    }

    static lm::Row rowOf(const Vault& v) {
        const auto r = Q::get(v.id());
        EXPECT_TRUE(r);
        return *r;
    }

    // Plaintext of one o/<uid> object version, opened as opaque_v1 reads it: bound to the vault and this uid.
    static std::string opaquePlain(const Vault& v, const crypto::id::ObjectUid& uid, const Bytes& sealed) {
        const auto em = v.engine->encryptionManager;
        const auto opened = crypto::vhf1::openHeader(
            sealed, {.kind = crypto::vhf1::Kind::FileContent, .vaultUid = em->vaultUid(), .objectUid = uid,
                     .generation = std::nullopt},
            [&](const uint32_t version) { return em->historicalKeySnapshot(version); });
        const content::Binding b{.vaultUid = em->vaultUid(),
                                 .generation = content::generationOf(opened.params().salt),
                                 .keyVersion = opened.params().keyVersion, .objectUid = uid};
        return str(content::openBuffer(sealed, b, *em->historicalKeySnapshot(b.keyVersion)));
    }

    // The o/<uid> history, oldest first: plaintext of each version, "<deleted>" for a delete marker.
    static std::vector<std::string> opaqueHistory(const Vault& v, const crypto::id::ObjectUid& uid) {
        auto h = v.bucket->history(keys::contentKey(uid));
        std::ranges::reverse(h);
        std::vector<std::string> out;
        for (const auto& ver : h) out.push_back(ver.delete_marker ? "<deleted>" : opaquePlain(v, uid, ver.body));
        return out;
    }

    static std::vector<std::string> legacyKeys(const Vault& v) {
        std::vector<std::string> out;
        for (const auto& k : v.bucket->keys())
            if (keys::classify(k) == keys::KeyClass::Foreign) out.push_back(k);
        return out;
    }

    static void allowCleanupNow(const Vault& v) {
        db::Transactions::exec("LayoutMigrationTest::allowCleanupNow", [&](pqxx::work& txn) {
            txn.exec("UPDATE vault_layout_migration SET cleanup_after = now() - interval '1 minute' WHERE vault_id = $1",
                     pqxx::params{v.id()});
        });
    }

    static uint64_t legacyRows(const Vault& v) {
        return db::Transactions::exec("LayoutMigrationTest::legacyRows", [&](pqxx::work& txn) {
            return txn.exec("SELECT count(*) FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                            "WHERE e.vault_id = $1 AND f.content_format = 'gcm0'", pqxx::params{v.id()})
                .one_field_ref()
                .as<uint64_t>();
        });
    }
};

// The acceptance scenario: a versioned path_v0 bucket with legacy (gcm0) and VHF1 versions, a deleted file's history
// and delete marker, a legacy local copy, an index-only file, and a file the vault never uploaded. Every version and
// marker is carried into o/<uid> in order, every file reads back, the next sync pass has nothing to do, and nothing
// legacy was deleted.
TEST_F(LayoutMigrationTest, LayoutMigrationVersionedBucketCarriesEveryVersionAndMarker) {
    auto v = legacyVault();
    v.engine->mkdir("/docs", superUser);
    write(v, "/docs/a.txt", "alpha one");
    makeLegacy(v, "/docs/a.txt");
    write(v, "/b.txt", "bravo");
    makeLegacy(v, "/b.txt");
    write(v, "/gone.txt", "gone soon");
    (void)pass(v);
    write(v, "/docs/a.txt", "alpha two (vhf1)");
    (void)pass(v);
    write(v, "/docs/a.txt", "alpha three");
    makeLegacy(v, "/docs/a.txt");
    (void)pass(v);
    remove(v, "/gone.txt");
    (void)pass(v);   // trash purge: a delete marker on gone.txt
    evict(v, "/b.txt");
    write(v, "/new.txt", "never uploaded");   // the vault's sync waits during the migration anyway

    const auto legacyBefore = v.bucket->keys();
    const auto aUid = *row(v, "/docs/a.txt")->object_uid;
    const auto bUid = *row(v, "/b.txt")->object_uid;
    const auto newUid = *row(v, "/new.txt")->object_uid;
    v.bucket->md5Etags = true;
    v.bucket->clearRequests();

    const auto result = migrate(v);
    ASSERT_EQ(result.state, lm::State::CutOver) << result.error.value_or("");
    ASSERT_FALSE(result.error) << *result.error;
    EXPECT_TRUE(v.engine->opaqueLayout());
    EXPECT_TRUE(v.bucket->opaqueLayout()) << "the controller enforces the opaque_v1 rules from the cutover on";
    EXPECT_EQ(legacyRows(v), 0u) << "no legacy (gcm0) live row after the cutover";

    // History, oldest first, under each file's uid.
    EXPECT_EQ(opaqueHistory(v, aUid), (std::vector<std::string>{"alpha one", "alpha two (vhf1)", "alpha three"}))
        << "every retained version; the latest is the local copy's generation, uploaded from it (converted) once";
    EXPECT_EQ(opaqueHistory(v, bUid), (std::vector<std::string>{"bravo"})) << "the index-only file's object";
    EXPECT_EQ(opaqueHistory(v, newUid), (std::vector<std::string>{"never uploaded"}));
    // The deleted file's history: a fresh uid (no row names it any more) that keeps its path through the items.
    std::optional<crypto::id::ObjectUid> goneUid;
    for (const auto& it : Q::items(v.id()))
        if (it.legacy_key == std::optional<std::string>("gone.txt")) goneUid = it.object_uid;
    ASSERT_TRUE(goneUid);
    EXPECT_EQ(opaqueHistory(v, *goneUid), (std::vector<std::string>{"gone soon", "<deleted>"}));
    EXPECT_EQ(db::query::sync::ObjectIdentity::pathOfUid(v.id(), *goneUid), std::optional<sfs::path>("/gone.txt"));

    // Nothing legacy was written or deleted, and no request to o/ carried a name or metadata.
    for (const auto& k : legacyBefore) EXPECT_FALSE(v.bucket->history(k).empty()) << k;
    for (const auto& r : v.bucket->requests()) {
        if (r.op == VersionedBucket::Op::List) continue;
        if (keys::classify(r.key) == keys::KeyClass::Foreign) {
            EXPECT_TRUE(r.op == VersionedBucket::Op::Get || r.op == VersionedBucket::Op::Head)
                << "only reads of legacy keys: " << r.key;
        } else {
            EXPECT_TRUE(r.metadata.empty()) << r.key;
        }
    }

    // Every file reads, and opaque_v1 sync has nothing to transfer.
    EXPECT_EQ(readLocal(v, "/docs/a.txt"), "alpha three");
    EXPECT_EQ(readLocal(v, "/b.txt"), "bravo");
    EXPECT_EQ(readLocal(v, "/new.txt"), "never uploaded");
    const auto after = pass(v);
    EXPECT_EQ(transfers(after), 0u) << "the cutover recorded every object as both sides agree";

    const auto r = rowOf(v);
    EXPECT_TRUE(r.manifest_verified_at) << r.last_error.value_or("");
    ASSERT_TRUE(r.cleanup_after);
    EXPECT_GE(*r.cleanup_after - *r.cutover_at, 7 * 86400 - 5) << "default waiting period";
    EXPECT_NE(r.state, lm::State::Complete);
    const auto status = ops::vault_layout::status(superUser, v.id()).front();
    EXPECT_EQ(status.layout, "opaque_v1");
    EXPECT_GT(status.legacy_listed, 0u) << "legacy versions still carry names: never complete";
}

// LayoutMigrationCost: with MD5 ETags (no read-back beyond the sample), the requests and bytes the run sent are the
// estimate's, exactly.
TEST_F(LayoutMigrationTest, LayoutMigrationCostMatchesThePreflight) {
    auto v = legacyVault();
    write(v, "/x.bin", std::string(200'000, 'x'));
    makeLegacy(v, "/x.bin");
    write(v, "/y.txt", "why");
    (void)pass(v);
    write(v, "/x.bin", std::string(150'000, 'z'));
    (void)pass(v);
    evict(v, "/y.txt");
    v.bucket->md5Etags = true;

    std::optional<lm::Estimate> seen;
    auto d = deps();
    d.pricePreflight = [&](const storage::CloudEngine&, lm::Estimate& e, bool) { seen = e; };
    v.bucket->resetCounters();
    v.engine->resetS3RequestMetrics();
    const auto result = migrate(v, d);
    ASSERT_EQ(result.state, lm::State::CutOver) << result.error.value_or("");
    ASSERT_TRUE(seen);
    const auto usage = rowOf(v).usage;
    ASSERT_TRUE(usage);
    EXPECT_EQ((*usage)["list_requests"].get<uint64_t>(), seen->list_requests);
    EXPECT_EQ((*usage)["head_requests"].get<uint64_t>(), seen->head_requests);
    EXPECT_EQ((*usage)["get_requests"].get<uint64_t>(), seen->get_requests);
    EXPECT_EQ((*usage)["put_requests"].get<uint64_t>(), seen->put_requests);
    EXPECT_EQ((*usage)["delete_requests"].get<uint64_t>(), seen->delete_requests);
    EXPECT_EQ((*usage)["uploaded_bytes"].get<uint64_t>(), seen->upload_bytes);
    EXPECT_EQ((*usage)["downloaded_bytes"].get<uint64_t>(), seen->download_bytes)
        << "small vault: the sample reads back every object";
    EXPECT_EQ(seen->versions, 2u) << "x.bin's first version (its second is the local copy's) and y.txt's (its only copy)";
    EXPECT_EQ(seen->current_files, 1u);
}

// Non-MD5 ETags (SSE-KMS-like) are no proof: every PUT is read back and authenticated.
TEST_F(LayoutMigrationTest, LayoutMigrationNonMd5EtagsForceReadBack) {
    auto v = legacyVault();
    write(v, "/a.txt", "a");
    write(v, "/b.txt", "b");
    (void)pass(v);
    v.bucket->md5Etags = false;
    auto d = deps();
    d.sampleMinimum = 0;
    const auto result = migrate(v, d);
    ASSERT_EQ(result.state, lm::State::CutOver) << result.error.value_or("");
    unsigned objectGets = 0;
    for (const auto& r : v.bucket->requests())
        if (r.op == VersionedBucket::Op::Get && keys::classify(r.key) == keys::KeyClass::Content) ++objectGets;
    EXPECT_GE(objectGets, 2u) << "each re-sealed object read back";
}

// A legacy version that doesn't authenticate fails the migration: the vault stays path_v0, nothing is deleted, and a
// restart after the cause is gone resumes.
TEST_F(LayoutMigrationTest, LayoutMigrationVerificationFailureStaysPathV0) {
    auto v = legacyVault();
    write(v, "/t.txt", "tamper target");
    makeLegacy(v, "/t.txt");
    (void)pass(v);
    write(v, "/t.txt", "current");
    (void)pass(v);
    // The older (gcm0) version is corrupted in the provider.
    const auto history = v.bucket->history("t.txt");
    ASSERT_EQ(history.size(), 2u);
    v.bucket->tamper("t.txt", history.back().version_id, 3);
    const auto keysBefore = v.bucket->keys();

    const auto result = migrate(v);
    EXPECT_EQ(result.state, lm::State::Failed);
    EXPECT_NE(result.error.value_or("").find("authenticate"), std::string::npos) << result.error.value_or("");
    EXPECT_FALSE(v.engine->opaqueLayout());
    EXPECT_EQ(rowOf(v).state, lm::State::Failed);
    for (const auto& k : keysBefore) EXPECT_FALSE(v.bucket->history(k).empty()) << "nothing deleted: " << k;
    const auto vault = db::query::vault::Vault::getVault(v.id());
    EXPECT_EQ(std::dynamic_pointer_cast<vault::model::S3Vault>(vault)->storage_layout, vault::model::StorageLayout::PathV0);
    EXPECT_EQ(readLocal(v, "/t.txt"), "current") << "the vault keeps working on path_v0";
}

// A crash at any item resumes from the database: the second run finishes, every file reads, and verified items are
// not copied again.
TEST_F(LayoutMigrationTest, LayoutMigrationResumesAfterACrash) {
    auto v = legacyVault();
    for (int i = 0; i < 4; ++i) write(v, "/f" + std::to_string(i) + ".txt", "file " + std::to_string(i));
    (void)pass(v);
    for (int i = 0; i < 4; ++i) write(v, "/f" + std::to_string(i) + ".txt", "file " + std::to_string(i) + " v2");
    (void)pass(v);
    v.bucket->md5Etags = true;

    int items = 0;
    auto d = deps();
    d.afterStep = [&](const std::string_view step) {
        if (step.starts_with("item:") && ++items == 3) throw Crash{std::string(step)};
    };
    start(v);
    EXPECT_THROW((void)lm::run(v.engine, d), Crash);
    leases().releasePass(v.id());   // the crashed process held it
    EXPECT_FALSE(v.engine->opaqueLayout());
    v.bucket->clearRequests();

    const auto result = lm::run(v.engine, deps());
    ASSERT_EQ(result.state, lm::State::CutOver) << result.error.value_or("");
    for (int i = 0; i < 4; ++i) {
        EXPECT_EQ(readLocal(v, "/f" + std::to_string(i) + ".txt"), "file " + std::to_string(i) + " v2");
        const auto uid = *row(v, "/f" + std::to_string(i) + ".txt")->object_uid;
        const auto h = opaqueHistory(v, uid);
        ASSERT_FALSE(h.empty());
        EXPECT_EQ(h.front(), "file " + std::to_string(i));
        EXPECT_EQ(h.back(), "file " + std::to_string(i) + " v2");
    }
    unsigned objectPuts = 0;
    for (const auto& r : v.bucket->requests())
        if (r.op == VersionedBucket::Op::Put && keys::classify(r.key) == keys::KeyClass::Content) ++objectPuts;
    EXPECT_EQ(objectPuts, 8u - 3u) << "the three items verified before the crash are not copied again";
}

// Injected provider faults (a 503 on a PUT, a transport error on a GET) fail the run before the cutover; a restart
// resumes and finishes.
TEST_F(LayoutMigrationTest, LayoutMigrationFaultsFailThenResume) {
    auto v = legacyVault();
    write(v, "/a.txt", "a1");
    (void)pass(v);
    write(v, "/a.txt", "a2");
    (void)pass(v);
    v.bucket->failNext(VersionedBucket::Op::Put, VersionedBucket::Failure::Http503);
    auto result = migrate(v);
    EXPECT_EQ(result.state, lm::State::Failed);
    EXPECT_FALSE(v.engine->opaqueLayout());

    v.bucket->failNext(VersionedBucket::Op::Get, VersionedBucket::Failure::Transport);
    result = migrate(v);
    EXPECT_EQ(result.state, lm::State::Failed) << "attempt 2";

    result = migrate(v);
    ASSERT_EQ(result.state, lm::State::CutOver) << result.error.value_or("");
    EXPECT_EQ(rowOf(v).attempts, 2u);
    EXPECT_EQ(opaqueHistory(v, *row(v, "/a.txt")->object_uid), (std::vector<std::string>{"a1", "a2"}));
}

// An incomplete listing (a page fails) never becomes an inventory: nothing is copied, the vault stays path_v0.
TEST_F(LayoutMigrationTest, LayoutMigrationIncompleteListingRefuses) {
    auto v = legacyVault();
    write(v, "/a.txt", "a");
    (void)pass(v);
    v.bucket->failNext(VersionedBucket::Op::List, VersionedBucket::Failure::Http503);
    const auto puts = v.bucket->counters().put;
    const auto result = migrate(v);
    EXPECT_EQ(result.state, lm::State::Failed);
    EXPECT_EQ(v.bucket->counters().put, puts) << "nothing written on a partial picture";
    EXPECT_FALSE(v.engine->opaqueLayout());
}

// The bucket changed since the vault's last sync (another writer): the migration refuses before any write and says to
// sync first; a sync pass, then a restart, migrates.
TEST_F(LayoutMigrationTest, LayoutMigrationDivergedBucketRefusesUntilSynced) {
    auto v = legacyVault();
    write(v, "/d.txt", "ours");
    (void)pass(v);
    write(v, "/d.txt", "ours, later");
    (void)pass(v);
    // Another writer puts the first generation back as the current object; this vault hasn't synced since.
    const auto first = v.bucket->history("d.txt").back();
    (void)v.bucket->seed("d.txt", first.body, first.meta);

    const auto puts = v.bucket->counters().put;
    auto result = migrate(v);
    EXPECT_EQ(result.state, lm::State::Failed);
    EXPECT_NE(result.error.value_or("").find("sync"), std::string::npos) << result.error.value_or("");
    EXPECT_EQ(v.bucket->counters().put, puts);
}

// Cleanup: refused before the waiting period; the dry run lists exactly the inventoried legacy versions and markers;
// Object Lock retention and a legal hold block their versions (named, dated), a refused delete is reported, never
// done; status is cleanup_blocked until a complete listing shows nothing legacy, then complete. The o/ objects stay.
TEST_F(LayoutMigrationTest, LayoutMigrationCleanupRespectsWaitObjectLockAndRefusals) {
    auto v = legacyVault();
    write(v, "/a.txt", "a1");
    write(v, "/b.txt", "b1");
    write(v, "/c.txt", "c1");
    (void)pass(v);
    write(v, "/a.txt", "a2");
    (void)pass(v);
    v.bucket->md5Etags = true;
    ASSERT_EQ(migrate(v).state, lm::State::CutOver);

    EXPECT_THROW((void)ops::vault_layout::cleanup(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name}),
                 ops::Conflict)
        << "the waiting period has not ended";
    allowCleanupNow(v);

    const auto dry = ops::vault_layout::cleanup(superUser, {.vault_id = v.id(), .confirm = std::nullopt});
    EXPECT_TRUE(dry.dry_run);
    EXPECT_GE(dry.plan.deletable, 4u) << "a.txt x2, b.txt, c.txt and the old index manifest's versions";
    EXPECT_TRUE(dry.plan.kept.empty());
    EXPECT_THROW((void)ops::vault_layout::cleanup(superUser, {.vault_id = v.id(), .confirm = "not the name"}),
                 ops::Invalid);

    // Locks on two versions, and the key may not delete a third.
    const auto bVersion = v.bucket->history("b.txt").front().version_id;
    const auto cVersion = v.bucket->history("c.txt").front().version_id;
    v.bucket->lockVersion("b.txt", bVersion, "COMPLIANCE", std::time(nullptr) + 86400);
    v.bucket->setLegalHold("c.txt", cVersion, true);

    (void)ops::vault_layout::cleanup(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name});
    auto run = lm::runCleanup(*v.engine, {});
    EXPECT_EQ(run.state, lm::State::CleanupBlocked);
    EXPECT_EQ(run.deleted, dry.plan.deletable - 2);
    ASSERT_EQ(run.remaining.size(), 2u);
    std::map<std::string, lm::CleanupEntry> remaining;
    for (const auto& e : run.remaining) remaining[e.key] = e;
    EXPECT_EQ(remaining.at("b.txt").reason, "object_lock_retention");
    EXPECT_TRUE(remaining.at("b.txt").retain_until);
    EXPECT_EQ(remaining.at("c.txt").reason, "legal_hold");
    EXPECT_EQ(rowOf(v).state, lm::State::CleanupBlocked) << "never complete while a legacy version is listed";
    EXPECT_FALSE(v.bucket->history("b.txt").empty());
    EXPECT_TRUE(v.bucket->history("a.txt").empty()) << "deleted by version id, every one";

    // The hold is lifted; a refused delete (no permission) stays blocked and is reported, never done.
    v.bucket->setLegalHold("c.txt", cVersion, false);
    v.bucket->refuseDeletes = true;
    run = lm::runCleanup(*v.engine, {});
    EXPECT_EQ(run.state, lm::State::CleanupBlocked);
    EXPECT_EQ(run.deleted, 0u);
    bool refused = false;
    for (const auto& e : run.remaining) refused = refused || e.reason.starts_with("refused");
    EXPECT_TRUE(refused);
    EXPECT_FALSE(v.bucket->history("c.txt").empty());

    // Retention passes (its date is in the past now), deletes are allowed: complete.
    v.bucket->refuseDeletes = false;
    v.bucket->lockVersion("b.txt", bVersion, "COMPLIANCE", v.bucket->now() - 1);
    db::Transactions::exec("LayoutMigrationTest::retentionPassed", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_layout_migration_item SET retain_until = now() - interval '1 minute' "
                 "WHERE vault_id = $1 AND legacy_key = 'b.txt'", pqxx::params{v.id()});
    });
    run = lm::runCleanup(*v.engine, {});
    EXPECT_EQ(run.state, lm::State::Complete);
    EXPECT_TRUE(run.remaining.empty());
    EXPECT_TRUE(legacyKeys(v).empty());
    EXPECT_EQ(rowOf(v).state, lm::State::Complete);
    EXPECT_EQ(readLocal(v, "/a.txt"), "a2");
    EXPECT_EQ(opaqueHistory(v, *row(v, "/a.txt")->object_uid), (std::vector<std::string>{"a1", "a2"}));
}

// A protected bucket (protection lock) refuses the cleanup outright.
TEST_F(LayoutMigrationTest, LayoutMigrationProtectedBucketRefusesCleanup) {
    auto v = legacyVault();
    write(v, "/a.txt", "a");
    (void)pass(v);
    ASSERT_EQ(migrate(v).state, lm::State::CutOver);
    allowCleanupNow(v);
    storage::upstream::guard::setForTesting({storage::upstream::identityFor(*v.engine->s3ApiKey(), v.bucketName)});
    EXPECT_THROW((void)ops::vault_layout::cleanup(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name}),
                 ops::Error);
    storage::upstream::guard::clearForTesting();
    EXPECT_FALSE(v.bucket->history("a.txt").empty());
}

// Versions that can't be re-sealed now (an archive storage class) and objects that aren't Vaulthalla's (plaintext,
// no metadata) are kept, named in cleanup_blocked, never deleted.
TEST_F(LayoutMigrationTest, LayoutMigrationKeepsArchivedAndUnattributedVersions) {
    auto v = legacyVault();
    write(v, "/a.txt", "a");
    (void)pass(v);
    const auto current = *v.bucket->current("a.txt");
    (void)v.bucket->seed("old/archived.bin", current.body, current.meta, "DEEP_ARCHIVE");
    (void)v.bucket->seed("someone-elses.txt", std::string("plain text"));
    ASSERT_EQ(migrate(v).state, lm::State::CutOver) << rowOf(v).last_error.value_or("");
    allowCleanupNow(v);
    (void)ops::vault_layout::cleanup(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name});
    const auto run = lm::runCleanup(*v.engine, {});
    EXPECT_EQ(run.state, lm::State::CleanupBlocked);
    std::map<std::string, std::string> reasons;
    for (const auto& e : run.remaining) reasons[e.key] = e.reason;
    EXPECT_EQ(reasons["old/archived.bin"], lm::kArchived);
    EXPECT_EQ(reasons["someone-elses.txt"], lm::kUnattributed);
    EXPECT_FALSE(v.bucket->history("someone-elses.txt").empty());
    const auto status = ops::vault_layout::status(superUser, v.id()).front();
    EXPECT_EQ(status.blocked_total, 2u);
}

// An unversioned bucket (R2 has no versioning): current objects only, deleted by key after a HEAD shows the
// inventoried ETag.
TEST_F(LayoutMigrationTest, LayoutMigrationUnversionedBucket) {
    auto v = legacyVault(Versioning::Unversioned);
    v.engine->setS3ProviderProfileForTesting(storage::s3::provider::resolve(vault::model::S3Provider::CloudflareR2));
    write(v, "/u.txt", "u1");
    makeLegacy(v, "/u.txt");
    write(v, "/w.txt", "w1");
    (void)pass(v);
    evict(v, "/w.txt");
    v.bucket->md5Etags = true;
    ASSERT_EQ(migrate(v).state, lm::State::CutOver) << rowOf(v).last_error.value_or("");
    EXPECT_EQ(rowOf(v).versioned, std::optional<bool>(false));
    EXPECT_EQ(readLocal(v, "/u.txt"), "u1");
    EXPECT_EQ(readLocal(v, "/w.txt"), "w1");
    EXPECT_EQ(transfers(pass(v)), 0u);
    allowCleanupNow(v);
    (void)ops::vault_layout::cleanup(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name});
    const auto run = lm::runCleanup(*v.engine, {});
    EXPECT_EQ(run.state, lm::State::Complete);
    EXPECT_TRUE(legacyKeys(v).empty());
}

// The pending upstream backlog (local versioning): a generation never uploaded is replayed into o/<uid> between the
// history and the current content; one the bucket already holds is carried with its version and marked sent.
TEST_F(LayoutMigrationTest, LayoutMigrationReplaysTheBacklog) {
    auto v = legacyVault(Versioning::Enabled, Strategy::Sync, /*localVersioning=*/true);
    write(v, "/k.txt", "k1");
    (void)pass(v);
    write(v, "/k.txt", "k2");   // k1 retained: pending, but already a version of the key
    write(v, "/k.txt", "k3");   // k2 retained: pending, never uploaded
    const auto pending = db::query::recovery::Generation::listPending(v.id(), 100);
    ASSERT_EQ(pending.size(), 2u);
    v.bucket->md5Etags = true;
    ASSERT_EQ(migrate(v).state, lm::State::CutOver) << rowOf(v).last_error.value_or("");
    EXPECT_EQ(opaqueHistory(v, *row(v, "/k.txt")->object_uid), (std::vector<std::string>{"k1", "k2", "k3"}));
    EXPECT_TRUE(db::query::recovery::Generation::listPending(v.id(), 100).empty()) << "both sent";
    for (const auto& g : pending) {
        const auto now = db::query::recovery::Generation::get(g.id);
        ASSERT_TRUE(now);
        EXPECT_TRUE(now->upstream_key && keys::classify(*now->upstream_key) == keys::KeyClass::Content);
    }
}

// #376 readiness: health says whether legacy content remains, and goes false once nothing legacy is left.
TEST_F(LayoutMigrationTest, LayoutMigrationHealthReportsLegacyContent) {
    auto v = legacyVault();
    write(v, "/a.txt", "a");
    (void)pass(v);
    auto legacy = Q::legacySummary();
    EXPECT_TRUE(legacy.remaining());
    EXPECT_TRUE(std::ranges::find(legacy.path_v0_vaults, v.id()) != legacy.path_v0_vaults.end());
    ASSERT_EQ(migrate(v).state, lm::State::CutOver);
    legacy = Q::legacySummary();
    EXPECT_TRUE(std::ranges::find(legacy.path_v0_vaults, v.id()) == legacy.path_v0_vaults.end());
    EXPECT_TRUE(std::ranges::find(legacy.migrations_unfinished, v.id()) != legacy.migrations_unfinished.end())
        << "cut over, legacy objects still listed";
    allowCleanupNow(v);
    (void)ops::vault_layout::cleanup(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name});
    ASSERT_EQ(lm::runCleanup(*v.engine, {}).state, lm::State::Complete);
    legacy = Q::legacySummary();
    EXPECT_TRUE(std::ranges::find(legacy.migrations_unfinished, v.id()) == legacy.migrations_unfinished.end());
}

// Who may: status needs the encryption-key View permission, start and cleanup the Rotate permission; a start is
// refused while one runs, and the encryption setting can't change under a running migration.
TEST_F(LayoutMigrationTest, LayoutMigrationOpsRefuse) {
    auto v = legacyVault();
    write(v, "/a.txt", "a");
    (void)pass(v);
    EXPECT_THROW((void)ops::vault_layout::status(nullptr, v.id()), ops::Denied);
    start(v);
    EXPECT_THROW(start(v), ops::Conflict) << "one migration at a time";
    EXPECT_THROW((void)ops::vault_layout::cleanup(superUser, {.vault_id = v.id(), .confirm = std::nullopt}), ops::Conflict)
        << "nothing to clean up before the cutover";
}

}
