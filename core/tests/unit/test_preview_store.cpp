#include "db/Transactions.hpp"
#include "db/query/fs/Cache.hpp"
#include "db/query/identities/User.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Record.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "preview/cache/Store.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <thread>

namespace vh::preview::cache::test_store {

namespace {

std::string tag() {
    return std::to_string(::getpid()) + "_" +
           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 1'000'000'000);
}

std::vector<uint8_t> bytesOf(const std::string& s) { return {s.begin(), s.end()}; }

std::vector<uint8_t> fileBytes(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

bool contains(const std::vector<uint8_t>& haystack, const std::string& needle) {
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

}

class PreviewStoreDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::filesystem::path root;

    static void TearDownTestSuite() {
        std::error_code ec;
        if (!root.empty()) std::filesystem::remove_all(root, ec);  // test vault backing (encrypted files up to 300 MiB)
    }
    inline static std::shared_ptr<identities::User> admin;

    std::shared_ptr<storage::Engine> engine;
    std::shared_ptr<fs::model::File> file;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_preview_store_" + tag());
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
        admin = vh::identities::manager().userByName("admin");
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        const auto vault = ops::vaults::create(admin, {.name = "ps_" + tag(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);
        const std::string path = "/source.txt";
        file = fs::Filesystem::createFile({.path = path,
                                           .fuse_path = engine->vaultPathToFusePath(path),
                                           .buffer = bytesOf("source document"),
                                           .engine = engine,
                                           .user = admin});
        ASSERT_TRUE(file);
    }

    [[nodiscard]] ArtifactKey keyFor(const std::string& kind, const std::string& variant) const {
        return {.vault_id = engine->vault->id, .file_id = file->id, .kind = kind, .variant = variant,
                .source_id = storage::generationOf(*file).sourceId(), .generator_version = 1};
    }
};

TEST_F(PreviewStoreDbTest, PutLookupOpenRoundTripsAndStoresOnlyCiphertext) {
    const std::string secret = "PLAINTEXT-MARKER-0123456789-thumbnail-bytes";
    const auto artifact = Store::put(engine, keyFor("thumbnail", "128"), bytesOf(secret));
    EXPECT_FALSE(contains(fileBytes(artifact.path), "PLAINTEXT-MARKER"));
    EXPECT_EQ(std::filesystem::status(artifact.path).permissions() & std::filesystem::perms::all,
              std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);

    const auto found = Store::lookup(engine, keyFor("thumbnail", "128"));
    ASSERT_EQ(found.status, LookupStatus::Ready);
    const auto reader = Store::open(engine, *found.artifact);
    EXPECT_EQ(storage::readAll(*reader, 1 << 20), bytesOf(secret));
    std::vector<uint8_t> part(9);
    ASSERT_EQ(reader->read(10, part), part.size());
    EXPECT_EQ(std::string(part.begin(), part.end()), secret.substr(10, 9));
}

TEST_F(PreviewStoreDbTest, ContentChangeAndGeneratorUpgradeInvalidateDeterministically) {
    const auto original = Store::put(engine, keyFor("render", "p0-s1024"), bytesOf("v1"));
    ASSERT_TRUE(std::filesystem::exists(original.path));

    auto newer = keyFor("render", "p0-s1024");
    newer.generator_version = 2;
    EXPECT_EQ(Store::lookup(engine, newer).status, LookupStatus::Missing);
    EXPECT_FALSE(std::filesystem::exists(original.path));  // stale artifact removed on sight

    (void)Store::put(engine, keyFor("render", "p0-s1024"), bytesOf("v1"));
    // Overwrite the source: every content write reseals with a fresh IV, so the source id changes.
    const std::string path = "/source.txt";
    file = fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                       .buffer = bytesOf("rewritten document"), .engine = engine,
                                       .user = admin, .overwrite = true});
    EXPECT_EQ(Store::lookup(engine, keyFor("render", "p0-s1024")).status, LookupStatus::Missing);
}

TEST_F(PreviewStoreDbTest, AnArtifactCannotBeSwappedOntoAnotherIdentity) {
    const auto a = Store::put(engine, keyFor("thumbnail", "128"), bytesOf("artifact A bytes"));
    const auto b = Store::put(engine, keyFor("thumbnail", "256"), bytesOf("artifact B bytes"));
    // An attacker with write access to the cache copies A's sealed bytes over B: the AAD binds the identity.
    std::filesystem::copy_file(a.path, b.path, std::filesystem::copy_options::overwrite_existing);
    auto found = Store::lookup(engine, keyFor("thumbnail", "256"));
    ASSERT_EQ(found.status, LookupStatus::Ready);
    const auto reader = Store::open(engine, *found.artifact);
    EXPECT_THROW((void)storage::readAll(*reader, 1 << 20), storage::IntegrityError);
}

TEST_F(PreviewStoreDbTest, FailuresAreNegativelyCachedUntilTheTtlOrASourceChange) {
    Store::putFailure(engine, keyFor("model-glb", "v1"), "invalid_input: not a STEP file");
    auto found = Store::lookup(engine, keyFor("model-glb", "v1"));
    EXPECT_EQ(found.status, LookupStatus::Failed);
    EXPECT_NE(found.failure.find("invalid_input"), std::string::npos);

    Store::setFailureTtl(std::chrono::seconds(0));
    std::this_thread::sleep_for(std::chrono::milliseconds(1100));
    EXPECT_EQ(Store::lookup(engine, keyFor("model-glb", "v1")).status, LookupStatus::Missing);
    Store::setFailureTtl(std::chrono::hours(24));
}

TEST_F(PreviewStoreDbTest, WriterEnforcesItsLimitAndAbortLeavesNothing) {
    auto writer = Store::begin(engine, keyFor("transcode-h264-720", "v1"), 10);
    EXPECT_THROW(writer.write(bytesOf("more than ten bytes")), std::length_error);
    writer.abort();
    const auto dir = engine->paths->cacheRoot / "derived" / std::to_string(file->id);
    for (const auto& entry : std::filesystem::directory_iterator(dir))
        EXPECT_EQ(entry.path().filename().string().find(".tmp-"), std::string::npos) << entry.path();
    EXPECT_EQ(Store::lookup(engine, keyFor("transcode-h264-720", "v1")).status, LookupStatus::Missing);
}

TEST_F(PreviewStoreDbTest, EvictionKeepsTheCacheWithinCapacityLeastRecentlyUsedFirst) {
    const std::vector<uint8_t> blob(1000, 0x5a);
    for (int i = 0; i < 5; ++i) (void)Store::put(engine, keyFor("render", "v" + std::to_string(i)), blob);
    const auto before = db::query::fs::Cache::derivedArtifactsTotalSize();
    ASSERT_GE(before, 5000u);
    const auto freed = Store::evict(before - 2500);
    EXPECT_GE(freed, 2500u);
    EXPECT_LE(db::query::fs::Cache::derivedArtifactsTotalSize(), before - 2500);
}

TEST_F(PreviewStoreDbTest, SweepRemovesLegacyPlaintextThumbnailsAndOrphans) {
    std::filesystem::create_directories(engine->paths->thumbnailRoot / "ALIAS");
    std::ofstream(engine->paths->thumbnailRoot / "ALIAS" / "128.jpg") << "legacy plaintext jpeg";
    const auto orphan = engine->paths->cacheRoot / "derived" / "999999";
    std::filesystem::create_directories(orphan);
    std::ofstream(orphan / "x.v1.vhd") << "x";
    const auto kept = Store::put(engine, keyFor("thumbnail", "128"), bytesOf("kept"));

    EXPECT_GT(Store::sweep(engine), 0u);
    EXPECT_FALSE(std::filesystem::exists(engine->paths->thumbnailRoot));
    EXPECT_FALSE(std::filesystem::exists(orphan));
    EXPECT_TRUE(std::filesystem::exists(kept.path));
}

TEST_F(PreviewStoreDbTest, DerivedArtifactsAreNotChargedToTheVaultQuota) {
    const auto before = engine->getCacheSize();
    (void)Store::put(engine, keyFor("render", "big"), std::vector<uint8_t>(200'000, 1));
    EXPECT_EQ(engine->getCacheSize(), before);
}

TEST_F(PreviewStoreDbTest, PurgeFileRemovesRowsAndFiles) {
    const auto a = Store::put(engine, keyFor("thumbnail", "128"), bytesOf("a"));
    Store::purgeFile(engine, file->id);
    EXPECT_FALSE(std::filesystem::exists(a.path));
    EXPECT_TRUE(db::query::fs::Cache::listDerivedArtifactsByFile(file->id).empty());
}

}
