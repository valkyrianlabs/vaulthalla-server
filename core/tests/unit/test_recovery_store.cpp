// The local recovery store (recovery::store): blob layout, zero-copy capture (link / delete path), dedupe per
// generation, the abort/commit protocol, crash leftovers and the orphan sweep, missing-file reporting, quota accounting
// in Engine::freeSpace, and removal with the vault (purge and hard removal) behind the path guard. DB-backed; skipped
// without the VH_TEST_DB_* environment.

#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/recovery/Blob.hpp"
#include "db/query/recovery/Generation.hpp"
#include "fs/Filesystem.hpp"
#include "fs/ops/file.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "recovery/Store.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/Retention.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>
#include <pqxx/pqxx>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <span>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

namespace vh::test_recovery_store {

namespace store = vh::recovery::store;
namespace rq = db::query::recovery;
namespace sfs = std::filesystem;

std::string recoveryStoreTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "s" + std::to_string(n.fetch_add(1));
}

std::string slurp(const sfs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void spit(const sfs::path& p, const std::string& bytes) {
    sfs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out << bytes;
}

uint64_t filesUnder(const sfs::path& dir) {
    uint64_t n = 0;
    std::error_code ec;
    for (sfs::recursive_directory_iterator it(dir, ec), end; !ec && it != end; it.increment(ec))
        if (it->is_regular_file()) ++n;
    return n;
}

class RecoveryStoreTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> superUser;
    inline static sfs::path scratch;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_recovery_store] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = sfs::temp_directory_path() / ("vh_recovery_store_" + recoveryStoreTag());
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

        const auto user = vh::test::identities::createUser("rst_super_" + recoveryStoreTag(),
                                                           db::query::rbac::role::Admin::get("super_admin"),
                                                           "rst_super@vaulthalla.test", "x", std::nullopt);
        superUser = vh::identities::manager().user(user->id);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static std::shared_ptr<vault::model::Vault> addVault() {
        return ops::vaults::create(superUser, {.name = "rst_vault_" + recoveryStoreTag(),
                                               .type = vault::model::VaultType::Local});
    }

    // A sealed "backing file" (its bytes stand in for ciphertext).
    static sfs::path backingFile(const std::string& bytes) {
        const auto p = scratch / ("b_" + recoveryStoreTag());
        spit(p, bytes);
        return p;
    }

    static store::GenerationMeta meta(const std::string& iv, const uint64_t plaintext = 1) {
        return {.encryption_iv = iv, .key_version = 1, .plaintext_bytes = plaintext, .content_hash = "h"};
    }

    // attach() + a local version referencing the blob, in one transaction; then committed().
    static int64_t commitWithVersion(store::Capture& cap, const store::VaultRef& ref, const std::string& path) {
        const auto id = db::Transactions::exec("test::commit", [&](pqxx::work& txn) {
            const auto blobId = cap.attach(txn);
            static_cast<void>(rq::Generation::insertLocalVersion(
                txn, {.vault_id = ref.id, .file_id = std::nullopt, .blob_id = blobId, .content_hash = "h",
                      .size_bytes = 1, .mime_type = std::nullopt, .path = path, .mode = std::nullopt,
                      .source_updated_at = std::nullopt, .created_by = std::nullopt, .snapshot_id = std::nullopt,
                      .rel_path = std::nullopt, .reason = "overwrite", .upstream_state = rq::UpstreamState::None,
                      .upstream_key = std::nullopt}));
            return blobId;
        });
        cap.committed();
        return id;
    }
};

TEST(RecoveryStoreNames, StorageNamesAreRandomLowercaseAlphanumerics) {
    const auto a = store::newStorageName();
    const auto b = store::newStorageName();
    EXPECT_EQ(a.size(), 32u);
    EXPECT_TRUE(store::validStorageName(a));
    EXPECT_NE(a, b);
    for (const auto* bad : {"", "short", "ABCDEFGHIJKLMNOPQRSTUVWXYZ012345", "abcdefghijklmnopqrstuvwxyz01234/",
                            "abcdefghijklmnopqrstuvwxyz0123456", "../cdefghijklmnopqrstuvwxyz012345"})
        EXPECT_FALSE(store::validStorageName(bad)) << bad;
    EXPECT_THROW(static_cast<void>(store::vaultDir({.id = 1, .alias = "../etc"})), std::invalid_argument);
    EXPECT_THROW(static_cast<void>(store::vaultDir({.id = 1, .alias = ""})), std::invalid_argument);
    EXPECT_THROW(static_cast<void>(store::vaultDir({.id = 1, .alias = "a/b"})), std::invalid_argument);
    EXPECT_EQ(store::vaultDir({.id = 1, .alias = "ABC_12-x  "}).filename(), "ABC_12-x") << "CHAR(33) padding trimmed";
}

TEST_F(RecoveryStoreTest, LinkCaptureKeepsTheBytesAfterTheOriginalIsReplaced) {
    const auto v = addVault();
    const auto ref = store::vaultRef(*v);
    const auto src = backingFile("sealed-generation-1");
    auto cap = store::captureLink(ref, src, meta("ivLink1", 3));
    EXPECT_EQ(cap.method(), store::CaptureMethod::Link) << "same filesystem: zero-copy";
    EXPECT_EQ(cap.path(), store::root() / ref.alias / cap.storageName().substr(0, 2) / cap.storageName());
    EXPECT_EQ(cap.cipherBytes(), 19u);
    const auto id = commitWithVersion(cap, ref, "/a.txt");

    // Every content write replaces the backing file by rename: the retained inode is never written again.
    const std::string replacement = "sealed-generation-2!";
    fs::ops::writeFileAtomic(src, std::span(reinterpret_cast<const uint8_t*>(replacement.data()), replacement.size()));
    EXPECT_EQ(slurp(src), replacement);
    const auto h = store::open(ref, id);
    ASSERT_TRUE(h);
    EXPECT_TRUE(h->present);
    EXPECT_EQ(slurp(h->path), "sealed-generation-1");
    EXPECT_EQ(h->row.encryption_iv, "ivLink1");
    EXPECT_EQ(h->row.cipher_bytes, 19u);
    EXPECT_EQ(h->row.plaintext_bytes, 3u);

    struct stat st{};
    ASSERT_EQ(::stat(store::vaultDir(ref).c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0700u);
    ASSERT_EQ(::stat(store::root().c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0700u);
    EXPECT_FALSE(store::open({.id = ref.id + 1000, .alias = ref.alias}, id)) << "another vault's blob is not found";
}

TEST_F(RecoveryStoreTest, CopiesAndStreamsAreDurableAndPrivate) {
    const auto v = addVault();
    const auto ref = store::vaultRef(*v);
    auto copied = store::captureCopy(ref, backingFile("copy-bytes"), meta("ivCopy"));
    EXPECT_TRUE(copied.method() == store::CaptureMethod::Copy || copied.method() == store::CaptureMethod::Reflink);
    struct stat st{};
    ASSERT_EQ(::stat(copied.path().c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
    static_cast<void>(commitWithVersion(copied, ref, "/c.txt"));
    EXPECT_EQ(slurp(copied.path()), "copy-bytes");

    auto streamed = store::captureStream(ref, meta("ivStream"), [](const int fd) {
        const std::string body = "streamed";
        ASSERT_EQ(::write(fd, body.data(), body.size()), static_cast<ssize_t>(body.size()));
    });
    EXPECT_EQ(streamed.method(), store::CaptureMethod::Stream);
    ASSERT_EQ(::stat(streamed.path().c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u);
    static_cast<void>(commitWithVersion(streamed, ref, "/s.txt"));
    EXPECT_EQ(slurp(streamed.path()), "streamed");

    // A producer that throws leaves nothing behind.
    EXPECT_THROW(static_cast<void>(store::captureStream(ref, meta("ivThrow"), [](int) {
                     throw std::runtime_error("source went away");
                 })),
                 std::runtime_error);
    EXPECT_EQ(filesUnder(store::vaultDir(ref)), 2u);
    EXPECT_THROW(static_cast<void>(store::captureLink(ref, scratch / "missing", meta("ivMissing"))), std::system_error);
}

TEST_F(RecoveryStoreTest, DeletePathUnlinksTheOriginOnlyAfterCommit) {
    const auto v = addVault();
    const auto ref = store::vaultRef(*v);
    const auto src = backingFile("deleted-file-bytes");

    {
        auto cap = store::captureMove(ref, src, meta("ivMove"));
        EXPECT_TRUE(sfs::exists(src)) << "nothing is lost before the transaction commits";
        const auto staged = cap.path();
        EXPECT_TRUE(sfs::exists(staged));
        EXPECT_THROW(db::Transactions::exec("test::fails", [&](pqxx::work& txn) {
                         static_cast<void>(cap.attach(txn));
                         throw std::runtime_error("the delete failed");
                     }),
                     std::runtime_error);
        cap.abort();
        EXPECT_FALSE(sfs::exists(staged));
        EXPECT_TRUE(sfs::exists(src)) << "an aborted delete keeps the file";
        EXPECT_FALSE(rq::Blob::findByGeneration(ref.id, "ivMove", 1)) << "the row rolled back with the transaction";
    }
    {
        auto dropped = store::captureMove(ref, src, meta("ivMove"));
        const auto staged = dropped.path();
        // Destroyed without commit: the same as abort().
        static_cast<void>(staged);
    }
    EXPECT_EQ(filesUnder(store::vaultDir(ref)), 0u);
    EXPECT_TRUE(sfs::exists(src));

    auto cap = store::captureMove(ref, src, meta("ivMove"));
    const auto id = commitWithVersion(cap, ref, "/deleted.txt");
    EXPECT_FALSE(sfs::exists(src)) << "committed: the backing file is gone";
    EXPECT_EQ(slurp(store::open(ref, id)->path), "deleted-file-bytes");
}

TEST_F(RecoveryStoreTest, OneGenerationIsStoredOnceEvenWhenCapturedConcurrently) {
    const auto v = addVault();
    const auto ref = store::vaultRef(*v);

    auto first = store::captureLink(ref, backingFile("same-sealed-bytes"), meta("ivDup"));
    const auto id = commitWithVersion(first, ref, "/one.txt");
    // A second snapshot of the unchanged file: no new bytes.
    auto second = store::captureCopy(ref, backingFile("same-sealed-bytes"), meta("ivDup"));
    EXPECT_EQ(second.method(), store::CaptureMethod::Existing);
    EXPECT_TRUE(second.reused());
    EXPECT_EQ(commitWithVersion(second, ref, "/one.txt"), id);
    EXPECT_EQ(filesUnder(store::vaultDir(ref)), 1u);
    EXPECT_EQ(rq::Blob::refCount(id), 2u);

    // Two captures staged before either row exists: the one committed second adopts the first and drops its file.
    const auto writer = [](const int fd) { ASSERT_EQ(::write(fd, "race", 4), 4); };
    auto x = store::captureStream(ref, meta("ivRace"), writer);
    auto y = store::captureStream(ref, meta("ivRace"), writer);
    EXPECT_NE(x.storageName(), y.storageName());
    const auto xid = commitWithVersion(x, ref, "/race.txt");
    const auto yPath = y.path();
    EXPECT_EQ(commitWithVersion(y, ref, "/race.txt"), xid);
    EXPECT_TRUE(y.reused());
    EXPECT_FALSE(sfs::exists(yPath));
    EXPECT_TRUE(sfs::exists(x.path()));
    EXPECT_EQ(filesUnder(store::vaultDir(ref)), 2u);

    // An empty IV is never deduplicated.
    auto e1 = store::captureStream(ref, meta(""), writer);
    auto e2 = store::captureStream(ref, meta(""), writer);
    EXPECT_NE(commitWithVersion(e1, ref, "/e.txt"), commitWithVersion(e2, ref, "/e.txt"));
}

TEST_F(RecoveryStoreTest, SweepRemovesCrashLeftoversAndReportsMissingFiles) {
    const auto v = addVault();
    const auto ref = store::vaultRef(*v);

    auto kept = store::captureLink(ref, backingFile("kept"), meta("ivKept"));
    const auto keptId = commitWithVersion(kept, ref, "/kept.txt");

    // A crash after the file was staged but before its row committed, a staging leftover, and a committed blob whose
    // referencing rows went away without the store's cleanup.
    const auto orphanName = store::newStorageName();
    const auto orphan = store::blobPath(ref, orphanName);
    spit(orphan, "orphaned");
    const auto temp = store::vaultDir(ref) / "ab" / (".tmp-" + store::newStorageName());
    spit(temp, "partial");
    auto unreferenced = store::captureStream(ref, meta("ivUnref"), [](const int fd) { ASSERT_EQ(::write(fd, "u", 1), 1); });
    const auto unrefPath = unreferenced.path();
    const auto unrefId = db::Transactions::exec("t", [&](pqxx::work& txn) { return unreferenced.attach(txn); });
    unreferenced.committed();

    // Young files and rows are never touched (an in-flight capture looks exactly like this).
    auto young = store::sweep(ref, std::chrono::hours(1));
    EXPECT_EQ(young.orphans_removed + young.temp_removed + young.unreferenced_removed, 0u);
    EXPECT_TRUE(sfs::exists(orphan));

    const auto report = store::sweep(ref, std::chrono::seconds(0));
    EXPECT_EQ(report.orphans_removed, 1u);
    EXPECT_EQ(report.orphan_bytes, 8u);
    EXPECT_EQ(report.temp_removed, 1u);
    EXPECT_EQ(report.unreferenced_removed, 1u);
    EXPECT_TRUE(report.missing.empty());
    EXPECT_TRUE(report.errors.empty());
    EXPECT_FALSE(sfs::exists(orphan));
    EXPECT_FALSE(sfs::exists(temp));
    EXPECT_FALSE(sfs::exists(unrefPath));
    EXPECT_FALSE(rq::Blob::get(unrefId));
    EXPECT_TRUE(sfs::exists(kept.path())) << "a referenced blob stays";

    // A row whose file vanished: reported, kept, and read back as not present.
    sfs::remove(kept.path());
    const auto missing = store::sweep(ref, std::chrono::seconds(0));
    EXPECT_EQ(missing.missing, std::vector<int64_t>{keptId});
    EXPECT_TRUE(rq::Blob::get(keptId)) << "never deleted";
    const auto h = store::open(ref, keptId);
    ASSERT_TRUE(h);
    EXPECT_FALSE(h->present);

    // A new capture of that generation repairs it under the existing row.
    auto repair = store::captureLink(ref, backingFile("kept"), meta("ivKept"));
    EXPECT_EQ(repair.storageName(), h->row.storage_name);
    EXPECT_EQ(commitWithVersion(repair, ref, "/kept.txt"), keptId);
    EXPECT_TRUE(store::open(ref, keptId)->present);
}

TEST_F(RecoveryStoreTest, BlobsAreRemovedOnlyWhenNothingReferencesThem) {
    const auto v = addVault();
    const auto ref = store::vaultRef(*v);
    auto cap = store::captureLink(ref, backingFile("refd"), meta("ivRef"));
    const auto id = commitWithVersion(cap, ref, "/r.txt");
    EXPECT_FALSE(store::removeBlob(ref, id));
    EXPECT_TRUE(sfs::exists(cap.path()));
    EXPECT_FALSE(store::removeBlob({.id = ref.id + 1000, .alias = ref.alias}, id)) << "another vault's blob";

    const auto versions = rq::Generation::listByPath(ref.id, "/r.txt", std::nullopt, 10);
    ASSERT_EQ(versions.size(), 1u);
    const auto freed = rq::Generation::remove(versions[0].id);
    ASSERT_EQ(freed, id);
    EXPECT_EQ(store::removeBlobs(ref, {*freed, 999999999}), 1u);
    EXPECT_FALSE(sfs::exists(cap.path()));
    EXPECT_FALSE(rq::Blob::get(id));
}

TEST_F(RecoveryStoreTest, RecoveryBytesCountAgainstTheVaultQuota) {
    const auto v = addVault();
    const auto ref = store::vaultRef(*v);
    const auto engine = runtime::Deps::get().storageManager->getEngine(v->id);
    ASSERT_TRUE(engine);
    const auto savedQuota = engine->vault->quota;
    engine->vault->quota = 1ull << 30;
    store::invalidateUsage(v->id);   // vault ids repeat across suites (each recreates the schema); the cache is per process

    const auto before = engine->freeSpace();
    EXPECT_EQ(engine->getRecoverySize(), 0u);
    auto cap = store::captureStream(ref, meta("ivQuota"), [](const int fd) {
        const std::string body(4096, 'q');
        ASSERT_EQ(::write(fd, body.data(), body.size()), 4096);
    });
    static_cast<void>(commitWithVersion(cap, ref, "/q.bin"));
    EXPECT_EQ(engine->getRecoverySize(), 4096u) << "committed() refreshes the cached usage";
    EXPECT_EQ(before - engine->freeSpace(), 4096u);
    EXPECT_EQ(store::physicalBytes(v->id), rq::Blob::physicalBytes(v->id));

    // A second capture of the same generation costs nothing.
    auto again = store::captureCopy(ref, cap.path(), meta("ivQuota"));
    static_cast<void>(commitWithVersion(again, ref, "/q.bin"));
    EXPECT_EQ(engine->getRecoverySize(), 4096u);
    engine->vault->quota = savedQuota;
}

TEST_F(RecoveryStoreTest, VaultPurgeAndRemovalTakeTheStoreWithThemBehindThePathGuard) {
    // Retention purge path.
    const auto purged = addVault();
    const auto purgedRef = store::vaultRef(*purged);
    auto cap = store::captureLink(purgedRef, backingFile("purge-me"), meta("ivPurge"));
    static_cast<void>(commitWithVersion(cap, purgedRef, "/p.txt"));
    ASSERT_TRUE(sfs::is_directory(store::vaultDir(purgedRef)));
    vault::retention::removeBackingData(purgedRef.alias);
    EXPECT_FALSE(sfs::exists(store::vaultDir(purgedRef)));

    // Hard removal (storage::Manager::removeVault): store dir and rows (cascade) go.
    const auto removed = addVault();
    const auto removedRef = store::vaultRef(*removed);
    auto cap2 = store::captureLink(removedRef, backingFile("remove-me"), meta("ivRemove"));
    const auto blobId = commitWithVersion(cap2, removedRef, "/r.txt");
    runtime::Deps::get().storageManager->removeVault(removed->id);
    EXPECT_FALSE(sfs::exists(store::vaultDir(removedRef)));
    EXPECT_FALSE(rq::Blob::get(blobId));

    // The guard: never outside the store root, never through a symlink.
    EXPECT_FALSE(store::removeVaultStore("absent_alias"));
    EXPECT_THROW(store::removeVaultStore("../backing"), vault::retention::PathGuardError);
    EXPECT_THROW(store::removeVaultStore(""), vault::retention::PathGuardError);
    const auto outside = scratch / ("outside_" + recoveryStoreTag());
    sfs::create_directories(outside);
    spit(outside / "keep.txt", "keep");
    sfs::create_directories(store::root());
    sfs::create_directory_symlink(outside, store::root() / "linked_alias");
    EXPECT_THROW(store::removeVaultStore("linked_alias"), vault::retention::PathGuardError);
    EXPECT_TRUE(sfs::exists(outside / "keep.txt"));
    sfs::remove(store::root() / "linked_alias");
}

}
