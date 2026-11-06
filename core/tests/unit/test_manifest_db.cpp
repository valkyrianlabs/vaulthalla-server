// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Encrypted manifest v2 (#368, WS3-a), the database half:
//   ManifestContent  every DB fact the restore needs is in the manifest: DB → collect → publish → bucket → load →
//                    a scratch schema, compared row for row with an independent projection of the live tables.
//   ManifestState    remote_manifest_state records the epoch, root hash and ETag of every publish; the root history
//                    keeps three roots; a rollback or fork is refused, recorded, and raises one operator
//                    notification per refused root.
//   ManifestUids     directories and symlinks get their uid once, from the collector, and keep it; a trashed file
//                    keeps its object uid.

#include "crypto/id/ObjectUid.hpp"
#include "db/Transactions.hpp"
#include "db/query/sync/Manifest.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "notifications/OperatorNotificationBus.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/Controller.hpp"
#include "sync/manifest/Objects.hpp"
#include "sync/manifest/Publisher.hpp"
#include "sync/manifest/Reader.hpp"
#include "sync/manifest/Service.hpp"
#include "sync/manifest/Store.hpp"
#include "db/query/vault/Vault.hpp"
#include "sync/model/Event.hpp"
#include "sync/model/RemotePolicy.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"
#include "../helpers/versioned_bucket.hpp"

#include <gtest/gtest.h>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <set>
#include <string>
#include <tuple>
#include <vector>

namespace vh::test_manifest_db {

namespace mf = vh::sync::manifest;
using test_support::versioned::Versioning;
using test_support::versioned::VersionedBucket;

namespace {

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "m" + std::to_string(n.fetch_add(1));
}

// A recovery_blob storage name: 32 lower-case hex digits, unique.
std::string storageName() {
    auto text = crypto::id::toUuid(crypto::id::newObjectUid());
    std::erase(text, '-');
    return text;
}

std::string uuidOf(const std::string& b32) { return crypto::id::toUuid(*crypto::id::fromBase32(b32)); }

std::vector<uint8_t> keyBytes(const uint8_t seed) {
    std::vector<uint8_t> k(32);
    for (std::size_t i = 0; i < k.size(); ++i) k[i] = static_cast<uint8_t>(seed + i);
    return k;
}

// The scratch schema both sides are loaded into: one normalized row per fact the restore needs.
void createScratch(pqxx::work& txn, const std::string& s) {
    txn.exec("DROP SCHEMA IF EXISTS " + s + " CASCADE");
    txn.exec("CREATE SCHEMA " + s);
    txn.exec("CREATE TABLE " + s + ".vault (name text, created_at text, quota bigint, strategy text, recovery_mode text)");
    txn.exec("CREATE TABLE " + s + ".entries (uid text, kind text, parent text, name text, mode int, owner_uid bigint, "
             "owner_gid bigint, mtime text, ctime text, size bigint, mime text, key_version int, content_hash text, "
             "etag text, object_size bigint, object_version text, target text, trashed_at text, trashed_by text, "
             "trashed_path text)");
    txn.exec("CREATE TABLE " + s + ".versions (uid text, version_id text, key_version int, size bigint, etag text, "
             "last_modified text, noncurrent_at text, delete_marker bool)");
    txn.exec("CREATE TABLE " + s + ".keys (version int, key_check text, attestation_key_id int, signature text, "
             "public_key text, created_at text, retired_at text)");
    txn.exec("CREATE TABLE " + s + ".snapshots (id bigint, name text, created_at text, root_path text)");
    txn.exec("CREATE TABLE " + s + ".members (snapshot_id bigint, uid text, path text, key_version int, "
             "provider_version_id text, restorable bool)");
}

// The manifest's side: what came back out of the bucket.
void loadScratch(pqxx::work& txn, const std::string& s, const mf::Content& c) {
    if (c.vault)
        txn.exec("INSERT INTO " + s + ".vault VALUES ($1, $2, $3::bigint, $4, $5)",
                 pqxx::params{c.vault->name, c.vault->created_at,
                              c.vault->quota_bytes ? std::optional<int64_t>(*c.vault->quota_bytes) : std::nullopt,
                              c.vault->sync_strategy,
                              c.vault->recovery_policy ? std::optional(c.vault->recovery_policy->mode) : std::nullopt});
    for (const auto& e : c.entries) {
        txn.exec("INSERT INTO " + s + ".entries VALUES ($1,$2,$3,$4,$5::int,$6::bigint,$7::bigint,$8,$9,$10::bigint,$11,$12::int,$13,$14,$15::bigint,$16,$17,$18,$19,$20)",
                 pqxx::params{uuidOf(e.uid), std::string(mf::to_string(e.kind)),
                              e.parent ? std::optional(uuidOf(*e.parent)) : std::nullopt, e.name,
                              e.mode ? std::optional<int64_t>(*e.mode) : std::nullopt,
                              e.owner ? std::optional(e.owner->uid) : std::nullopt,
                              e.owner ? std::optional(e.owner->gid) : std::nullopt, e.mtime, e.ctime,
                              e.size ? std::optional<int64_t>(*e.size) : std::nullopt, e.mime,
                              e.key_version ? std::optional<int64_t>(*e.key_version) : std::nullopt, e.content_hash,
                              e.object ? e.object->etag : std::nullopt,
                              e.object ? std::optional<int64_t>(e.object->size) : std::nullopt,
                              e.object ? e.object->version_id : std::nullopt, e.target,
                              e.trashed ? std::optional(e.trashed->at) : std::nullopt,
                              e.trashed ? e.trashed->by : std::nullopt, e.trashed ? e.trashed->path : std::nullopt});
        for (const auto& v : e.versions)
            txn.exec("INSERT INTO " + s + ".versions VALUES ($1,$2,$3::int,$4::bigint,$5,$6,$7,$8::bool)",
                     pqxx::params{uuidOf(e.uid), v.version_id,
                                  v.key_version ? std::optional<int64_t>(*v.key_version) : std::nullopt,
                                  v.size ? std::optional<int64_t>(*v.size) : std::nullopt, v.etag, v.last_modified,
                                  v.noncurrent_at, v.delete_marker});
    }
    for (const auto& k : c.keys)
        txn.exec("INSERT INTO " + s + ".keys VALUES ($1::int,$2,$3::int,$4,$5,$6,$7)",
                 pqxx::params{static_cast<int64_t>(k.version), k.key_check,
                              k.attestation ? std::optional<int64_t>(k.attestation->key_id) : std::nullopt,
                              k.attestation ? std::optional(k.attestation->signature) : std::nullopt,
                              k.attestation ? k.attestation->public_key : std::nullopt, k.created_at, k.retired_at});
    for (const auto& snap : c.snapshots) {
        txn.exec("INSERT INTO " + s + ".snapshots VALUES ($1::bigint,$2,$3,$4)",
                 pqxx::params{static_cast<int64_t>(snap.id), snap.name, snap.created_at, snap.root_path});
        for (const auto& m : snap.members)
            txn.exec("INSERT INTO " + s + ".members VALUES ($1::bigint,$2,$3,$4::int,$5,$6::bool)",
                     pqxx::params{static_cast<int64_t>(snap.id), m.uid ? std::optional(uuidOf(*m.uid)) : std::nullopt,
                                  m.path_at_capture,
                                  m.key_version ? std::optional<int64_t>(*m.key_version) : std::nullopt,
                                  m.provider_version_id, m.restorable_from_bucket});
    }
}

// The database's side, by its own SQL (not the collector's): `keys_` maps every uid to its o/<base32> object key.
void projectLive(pqxx::work& txn, const std::string& s, const uint32_t vaultId) {
    const auto iso = [](const std::string& col) {
        return "to_char(" + col + " AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"')";
    };
    const pqxx::params v{vaultId};
    txn.exec("INSERT INTO " + s + ".vault SELECT v.name, " + iso("v.created_at") +
                 ", NULLIF(v.quota, 0), r.strategy, p.mode FROM vault v LEFT JOIN sync sy ON sy.vault_id = v.id "
                 "LEFT JOIN rsync r ON r.sync_id = sy.id LEFT JOIN vault_recovery_policy p ON p.vault_id = v.id "
                 "WHERE v.id = $1",
             v);
    txn.exec("INSERT INTO " + s + ".entries SELECT COALESCE(d.uid, f.object_uid, sl.uid)::text, "
             "  CASE WHEN d.fs_entry_id IS NOT NULL THEN 'dir' WHEN f.fs_entry_id IS NOT NULL THEN 'file' ELSE 'symlink' END, "
             "  CASE WHEN p.vault_id IS DISTINCT FROM e.vault_id THEN NULL ELSE pd.uid::text END, "
             "  CASE WHEN p.vault_id IS DISTINCT FROM e.vault_id THEN '' ELSE e.name END, "
             "  e.mode, CASE WHEN e.owner_uid IS NULL AND e.group_gid IS NULL THEN NULL ELSE COALESCE(e.owner_uid, 0) END, "
             "  CASE WHEN e.owner_uid IS NULL AND e.group_gid IS NULL THEN NULL ELSE COALESCE(e.group_gid, 0) END, " +
                 iso("e.updated_at") + ", " + iso("e.created_at") + ", f.size_bytes, f.mime_type, "
             "  NULLIF(f.encrypted_with_key_version, 0), f.content_hash, roi.etag, roi.size_bytes, roi.version_id, "
             "  sl.target, NULL, NULL, NULL "
             "FROM fs_entry e LEFT JOIN fs_entry p ON p.id = e.parent_id LEFT JOIN directories pd ON pd.fs_entry_id = p.id "
             "LEFT JOIN directories d ON d.fs_entry_id = e.id LEFT JOIN files f ON f.fs_entry_id = e.id "
             "LEFT JOIN symlinks sl ON sl.fs_entry_id = e.id "
             "LEFT JOIN keys_ k ON k.uid = COALESCE(d.uid, f.object_uid, sl.uid) "
             "LEFT JOIN remote_object_index roi ON roi.vault_id = e.vault_id AND roi.object_key = k.key "
             "WHERE e.vault_id = $1 AND COALESCE(d.uid, f.object_uid, sl.uid) IS NOT NULL",
             v);
    txn.exec("INSERT INTO " + s + ".entries SELECT t.object_uid::text, 'file', pd.uid::text, "
             "  regexp_replace(t.path, '^.*/', ''), NULL, NULL, NULL, NULL, NULL, t.size_bytes, NULL, NULL, NULL, "
             "  roi.etag, roi.size_bytes, roi.version_id, NULL, " + iso("t.trashed_at") + ", u.name, t.path "
             "FROM files_trashed t LEFT JOIN users u ON u.id = t.trashed_by "
             "LEFT JOIN fs_entry pe ON pe.vault_id = t.vault_id AND pe.path = "
             "  (CASE WHEN t.path ~ '^/[^/]*$' THEN '/' ELSE regexp_replace(t.path, '/[^/]*$', '') END) "
             "LEFT JOIN directories pd ON pd.fs_entry_id = pe.id "
             "LEFT JOIN keys_ k ON k.uid = t.object_uid "
             "LEFT JOIN remote_object_index roi ON roi.vault_id = t.vault_id AND roi.object_key = k.key "
             "WHERE t.vault_id = $1 AND t.deleted_at IS NULL AND t.object_uid IS NOT NULL",
             v);
    // Tombstones: provider versions of objects no file or trash row names.
    txn.exec("INSERT INTO " + s + ".entries SELECT g.uid::text, 'tombstone', NULL, '', NULL, NULL, NULL, NULL, "
             "  NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL "
             "FROM (SELECT DISTINCT k.uid FROM upstream_object_version uov JOIN keys_ k ON k.key = uov.object_key "
             "      WHERE uov.vault_id = $1 AND uov.gone_at IS NULL "
             "        AND NOT EXISTS (SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
             "                        WHERE e.vault_id = $1 AND f.object_uid = k.uid) "
             "        AND NOT EXISTS (SELECT 1 FROM files_trashed t WHERE t.vault_id = $1 AND t.deleted_at IS NULL "
             "                        AND t.object_uid = k.uid)) g",
             v);
    txn.exec("INSERT INTO " + s + ".versions SELECT k.uid::text, uov.version_id, uov.key_version, uov.size_bytes, uov.etag, " +
                 iso("uov.last_modified") + ", " + iso("uov.became_noncurrent_at") + ", uov.is_delete_marker "
             "FROM upstream_object_version uov JOIN keys_ k ON k.key = uov.object_key "
             "WHERE uov.vault_id = $1 AND uov.gone_at IS NULL",
             v);
    txn.exec("INSERT INTO " + s + ".keys SELECT version, key_check, attestation_key_id, "
             "  translate(encode(attestation, 'base64'), E'\\n', ''), translate(encode(a.public_key, 'base64'), E'\\n', ''), " +
                 iso("k.created_at") + ", NULL FROM vault_keys k LEFT JOIN key_attestation_keys a ON a.id = k.attestation_key_id "
             "WHERE k.vault_id = $1 "
             "UNION ALL SELECT version, key_check, attestation_key_id, translate(encode(attestation, 'base64'), E'\\n', ''), "
             "  translate(encode(a.public_key, 'base64'), E'\\n', ''), " + iso("t.created_at") + ", " + iso("t.trashed_at") +
                 " FROM vault_keys_trashed t LEFT JOIN key_attestation_keys a ON a.id = t.attestation_key_id "
             "WHERE t.vault_id = $1 AND t.version NOT IN (SELECT version FROM vault_keys WHERE vault_id = $1)",
             v);
    txn.exec("INSERT INTO " + s + ".snapshots SELECT id, name, " + iso("created_at") +
                 ", root_path FROM recovery_snapshot WHERE vault_id = $1 AND state = 'ready'",
             v);
    txn.exec("INSERT INTO " + s + ".members SELECT fv.snapshot_id, f.object_uid::text, fv.path, NULLIF(b.key_version, 0), "
             "  fv.upstream_version_id, fv.upstream_version_id IS NOT NULL "
             "FROM file_versions fv JOIN recovery_snapshot rs ON rs.id = fv.snapshot_id "
             "LEFT JOIN files f ON f.fs_entry_id = fv.file_id LEFT JOIN recovery_blob b ON b.id = fv.blob_id "
             "WHERE rs.vault_id = $1 AND rs.state = 'ready'",
             v);
}

}

class ManifestDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> superUser;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    std::shared_ptr<storage::Engine> engine;
    uint32_t vaultId{};
    mf::Uid vaultUid{};

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_manifest_db] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_manifest_" + tag());
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
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = identities::manager().userByName("admin");
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
        const auto vault = ops::vaults::create(superUser, {.name = "manifest_" + tag(), .type = vault::model::VaultType::Local});
        vaultId = vault->id;
        ASSERT_TRUE(vault->uid);
        vaultUid = *vault->uid;
        engine = runtime::Deps::get().storageManager->getEngine(vaultId);
        ASSERT_TRUE(engine);
    }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    void mkdir(const std::string& path) const {
        ASSERT_EQ(fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath(path), .engine = engine, .user = superUser}), 0);
    }

    [[nodiscard]] std::string objectUidAt(const std::string& path) const {
        return db::Transactions::exec("objectUidAt", [&](pqxx::work& txn) {
            return mf::uidText(crypto::id::fromUuid(
                txn.exec("SELECT f.object_uid::text FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                         "WHERE e.vault_id = $1 AND e.path = $2",
                         pqxx::params{vaultId, path}).one_field_ref().as<std::string>()));
        });
    }

    // A vault with a nested tree, a symlink, a trashed file, provider versions (one of a purged file: a tombstone),
    // a current-object index row, a ready snapshot with members, and its keys.
    void seedRichVault() {
        mkdir("/Reports");
        mkdir("/Reports/2026");
        write("/Reports/2026/q3.pdf", "board pack");
        write("/Reports/notes.txt", "notes");
        write("/top.txt", "top");
        write("/Reports/old.txt", "to the trash");
        const auto q3 = objectUidAt("/Reports/2026/q3.pdf");
        fs::Filesystem::remove(engine->vaultPathToFusePath("/Reports/old.txt"), superUser->id);
        const auto purged = mf::uidText(crypto::id::newObjectUid());
        db::Transactions::exec("seedRichVault", [&](pqxx::work& txn) {
            const auto reports = txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = '/Reports'",
                                          pqxx::params{vaultId}).one_field_ref().as<int64_t>();
            const auto link = txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, path, mode) "
                                       "VALUES ($1, $2, 'latest', '/Reports/latest', 511) RETURNING id",
                                       pqxx::params{vaultId, reports}).one_field_ref().as<int64_t>();
            txn.exec("INSERT INTO symlinks (fs_entry_id, target) VALUES ($1, '2026/q3.pdf')", pqxx::params{link});
            for (const auto& [uid, vid, latest] : {std::tuple{q3, std::string("v-2"), true}, std::tuple{q3, std::string("v-1"), false},
                                                   std::tuple{purged, std::string("v-9"), false}})
                txn.exec("INSERT INTO upstream_object_version (vault_id, object_key, version_id, is_latest, etag, size_bytes, "
                         "  last_modified, origin, key_version, became_noncurrent_at) "
                         "VALUES ($1, $2, $3, $4, '\"e\"', 146, now() - interval '1 day', 'vaulthalla', 1, "
                         "  CASE WHEN $4 THEN NULL ELSE now() END)",
                         pqxx::params{vaultId, "o/" + uid, vid, latest});
            txn.exec("INSERT INTO remote_object_index (vault_id, object_key, size_bytes, etag, version_id, source) "
                     "VALUES ($1, $2, 146, '\"e2\"', 'v-2', 'manifest')",
                     pqxx::params{vaultId, "o/" + q3});
            const auto snap = txn.exec("INSERT INTO recovery_snapshot (vault_id, name, root_path, root_type, state) "
                                       "VALUES ($1, 'before audit', '/Reports', 'directory', 'ready') RETURNING id",
                                       pqxx::params{vaultId}).one_field_ref().as<int64_t>();
            const auto blob = txn.exec("INSERT INTO recovery_blob (vault_id, storage_name, key_version, cipher_bytes, "
                                       "  plaintext_bytes) VALUES ($1, $2, 1, 30, 10) RETURNING id",
                                       pqxx::params{vaultId, storageName()})
                                  .one_field_ref().as<int64_t>();
            const auto fileId = txn.exec("SELECT f.fs_entry_id FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                         "WHERE e.vault_id = $1 AND e.path = '/Reports/2026/q3.pdf'",
                                         pqxx::params{vaultId}).one_field_ref().as<int64_t>();
            txn.exec("INSERT INTO file_versions (vault_id, file_id, snapshot_id, blob_id, version_number, size_bytes, path, "
                     "  rel_path, upstream_version_id) VALUES ($1, $2, $3, $4, 1, 10, '/Reports/2026/q3.pdf', '2026/q3.pdf', 'v-1')",
                     pqxx::params{vaultId, fileId, snap, blob});
            txn.exec("INSERT INTO file_versions (vault_id, file_id, snapshot_id, blob_id, version_number, size_bytes, path, "
                     "  rel_path) VALUES ($1, NULL, $2, $3, 2, 10, '/Reports/gone.txt', 'gone.txt')",
                     pqxx::params{vaultId, snap, blob});
        });
    }

    [[nodiscard]] std::shared_ptr<vault::EncryptionManager> testKeys() const {
        const auto k = keyBytes(7);
        return std::make_shared<vault::EncryptionManager>(vault::EncryptionManager::ForTesting{}, vaultId, k, 1);
    }

    [[nodiscard]] static std::size_t drainManifestAlerts(const std::string& eventKey) {
        std::size_t n = 0;
        for (const auto& a : notifications::OperatorNotificationBus::instance().drain(512))
            if (a.eventKey == eventKey) ++n;
        return n;
    }
};

TEST_F(ManifestDbTest, ContentRoundTripsDatabaseToBucketToScratchSchema) {
    seedRichVault();
    const auto collected = db::query::sync::Manifest::collect(vaultId);

    auto bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
    mf::S3Store store(bucket);
    const auto key = std::make_shared<const crypto::SecretKey>(keyBytes(9));
    const auto lookup = [key](uint32_t) { return key; };
    mf::PublisherCache cache;
    mf::PublishOptions options;
    options.now = mf::isoTime(std::time(nullptr));
    const auto published = mf::publish(store, vaultUid, lookup, {1, key}, collected, std::nullopt, cache, options);
    const auto loaded = mf::load(store, vaultUid, lookup);
    ASSERT_TRUE(loaded.issues.empty());
    EXPECT_EQ(loaded.known(), published.published.known);

    // The manifest names every kind the vault holds.
    std::map<mf::EntryKind, int> kinds;
    int trashed = 0;
    for (const auto& e : loaded.content.entries) {
        ++kinds[e.kind];
        trashed += e.trashed ? 1 : 0;
    }
    EXPECT_EQ(kinds[mf::EntryKind::Dir], 3);      // the vault root, /Reports, /Reports/2026
    EXPECT_GE(kinds[mf::EntryKind::File], 4);     // three live files and the trashed one
    EXPECT_EQ(kinds[mf::EntryKind::Symlink], 1);
    EXPECT_EQ(kinds[mf::EntryKind::Tombstone], 1);
    EXPECT_EQ(trashed, 1);
    for (const auto& e : loaded.content.entries)
        if (e.trashed) {
            EXPECT_TRUE(e.parent) << "the trashed file's folder still exists";
            EXPECT_EQ(e.name, "old.txt");
        }
    ASSERT_EQ(loaded.content.snapshots.size(), 1u);
    EXPECT_EQ(loaded.content.snapshots[0].members.size(), 2u);
    EXPECT_FALSE(loaded.content.keys.empty());

    const auto s = "vh_manifest_scratch_" + std::to_string(vaultId);
    const auto live = "vh_manifest_live_" + std::to_string(vaultId);
    const auto diff = db::Transactions::exec("compare", [&](pqxx::work& txn) {
        createScratch(txn, s);
        createScratch(txn, live);
        txn.exec("CREATE TEMP TABLE keys_ (uid uuid, key text) ON COMMIT DROP");
        for (const auto row : txn.exec("SELECT f.object_uid FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                                       "WHERE e.vault_id = $1 UNION SELECT d.uid FROM directories d JOIN fs_entry e "
                                       "ON e.id = d.fs_entry_id WHERE e.vault_id = $1 UNION SELECT s.uid FROM symlinks s "
                                       "JOIN fs_entry e ON e.id = s.fs_entry_id WHERE e.vault_id = $1 UNION SELECT "
                                       "object_uid FROM files_trashed WHERE vault_id = $1 AND object_uid IS NOT NULL",
                                       pqxx::params{vaultId})) {
            const auto uuid = row[0].as<std::string>();
            txn.exec("INSERT INTO keys_ VALUES ($1::uuid, $2)",
                     pqxx::params{uuid, "o/" + mf::uidText(crypto::id::fromUuid(uuid))});
        }
        // Objects with provider versions but no file (purged): their uid is in the key.
        for (const auto row : txn.exec("SELECT DISTINCT object_key FROM upstream_object_version WHERE vault_id = $1 "
                                       "AND object_key LIKE 'o/%' AND object_key NOT IN (SELECT key FROM keys_)",
                                       pqxx::params{vaultId})) {
            const auto key = row[0].as<std::string>();
            if (const auto uid = crypto::id::fromBase32(key.substr(2)))
                txn.exec("INSERT INTO keys_ VALUES ($1::uuid, $2)", pqxx::params{crypto::id::toUuid(*uid), key});
        }
        loadScratch(txn, s, loaded.content);
        projectLive(txn, live, vaultId);
        std::vector<std::string> out;
        for (const auto* table : {"vault", "entries", "versions", "keys", "snapshots", "members"}) {
            if (txn.exec("SELECT count(*) FROM " + live + "." + table).one_field_ref().as<int>() == 0)
                out.push_back(std::string(table) + ": the live projection is empty (nothing was compared)");
            for (const auto& [a, b] : {std::pair{s, live}, std::pair{live, s}}) {
                for (const auto row : txn.exec("SELECT row_to_json(x)::text FROM (SELECT * FROM " + a + "." + table +
                                               " EXCEPT ALL SELECT * FROM " + b + "." + table + ") x"))
                    out.push_back(std::string(table) + " only in " + a + ": " + row[0].as<std::string>());
            }
        }
        txn.exec("DROP SCHEMA " + s + " CASCADE");
        txn.exec("DROP SCHEMA " + live + " CASCADE");
        return out;
    });
    for (const auto& d : diff) ADD_FAILURE() << d;
}

TEST_F(ManifestDbTest, UidsAreAssignedOnceAndTrashKeepsTheObjectUid) {
    mkdir("/A");
    write("/A/f.txt", "x");
    const auto uid = objectUidAt("/A/f.txt");
    const auto first = db::query::sync::Manifest::collect(vaultId);
    const auto second = db::query::sync::Manifest::collect(vaultId);
    EXPECT_EQ(first.entries, second.entries);
    for (const auto& e : first.entries) { EXPECT_TRUE(crypto::id::fromBase32(e.uid)) << e.name; }

    fs::Filesystem::remove(engine->vaultPathToFusePath("/A/f.txt"), superUser->id);
    const auto after = db::query::sync::Manifest::collect(vaultId);
    const auto it = std::ranges::find(after.entries, uid, &mf::Entry::uid);
    ASSERT_NE(it, after.entries.end()) << "the trashed file keeps its uid";
    ASSERT_TRUE(it->trashed);
    EXPECT_EQ(it->trashed->path, "/A/f.txt");
    EXPECT_EQ(it->trashed->by, superUser->name());

    // A uid never changes once assigned.
    EXPECT_ANY_THROW(db::Transactions::exec("rewrite uid", [&](pqxx::work& txn) {
        txn.exec("UPDATE directories d SET uid = $2::uuid FROM fs_entry e WHERE e.id = d.fs_entry_id AND e.vault_id = $1",
                 pqxx::params{vaultId, crypto::id::toUuid(crypto::id::newObjectUid())});
    }));
}

TEST_F(ManifestDbTest, StateRecordsEveryPublishAndKeepsThreeRoots) {
    write("/a.txt", "a");
    auto bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
    mf::Service service(vaultId, vaultUid, std::make_shared<mf::S3Store>(bucket), testKeys());
    std::vector<mf::PublishReport> reports;
    for (int i = 0; i < 4; ++i) {
        write("/a.txt", "a" + std::to_string(i));
        reports.push_back(service.publish());
    }
    const auto state = db::query::sync::Manifest::state(vaultId);
    ASSERT_TRUE(state.epoch);
    EXPECT_EQ(*state.epoch, 4u);
    EXPECT_EQ(state.root_sha256, mf::sha256Hex(bucket->current(std::string(mf::kRootKey))->body));
    EXPECT_EQ(state.etag, bucket->current(std::string(mf::kRootKey))->etag);
    EXPECT_FALSE(state.refused_reason);

    const auto retained = db::query::sync::Manifest::retainedSids(vaultId);
    for (std::size_t i = 1; i < reports.size(); ++i)
        for (const auto& sid : reports[i].published.sids()) { EXPECT_TRUE(retained.contains(sid)) << "epoch " << i + 1; }
    std::set<std::string> later;
    for (std::size_t i = 1; i < reports.size(); ++i)
        for (const auto& sid : reports[i].published.sids()) later.insert(sid);
    for (const auto& sid : reports[0].published.sids())
        if (!later.contains(sid)) { EXPECT_FALSE(retained.contains(sid)) << "epoch 1 is past the three retained roots"; }
    const auto rows = db::Transactions::exec("count roots", [&](pqxx::work& txn) {
        return txn.exec("SELECT count(*) FROM remote_manifest_root WHERE vault_id = $1", pqxx::params{vaultId})
            .one_field_ref().as<int>();
    });
    EXPECT_EQ(rows, 3);

    // verifyRemote with nothing new: no change.
    const auto ok = service.verifyRemote();
    ASSERT_TRUE(ok);
    EXPECT_EQ(ok->epoch, 4u);

    // GC runs once a day.
    EXPECT_TRUE(service.collectGarbageIfDue());
    EXPECT_FALSE(service.collectGarbageIfDue());
}

TEST_F(ManifestDbTest, RollbackAndForkAreRefusedRecordedAndAlertedOnce) {
    write("/a.txt", "a");
    auto bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
    const auto keys = testKeys();
    mf::Service service(vaultId, vaultUid, std::make_shared<mf::S3Store>(bucket), keys);
    (void)drainManifestAlerts("");
    (void)service.publish();
    const auto epoch1 = *bucket->current(std::string(mf::kRootKey));
    write("/a.txt", "b");
    (void)service.publish();
    write("/a.txt", "c");
    (void)service.publish();
    const auto before = db::query::sync::Manifest::state(vaultId);

    bucket->seed(std::string(mf::kRootKey), epoch1.body);  // a replayed older root
    EXPECT_THROW((void)service.verifyRemote(), mf::ChainRejected);
    EXPECT_THROW((void)service.publish(), mf::ChainRejected) << "nothing is published over a refused root";
    auto state = db::query::sync::Manifest::state(vaultId);
    EXPECT_EQ(state.refused_reason, "rollback");
    EXPECT_EQ(state.refused_epoch, 1u);
    EXPECT_EQ(state.epoch, before.epoch) << "the database keeps its state";
    EXPECT_EQ(state.root_sha256, before.root_sha256);
    EXPECT_EQ(drainManifestAlerts("manifest_rollback"), 1u) << "one alert per refused root";

    // A fork: an authentic root at the known epoch that isn't ours.
    mf::RootDocument other;
    {
        const auto k = keys->currentKey();
        const auto lookup = service.keyLookup();
        auto history = bucket->history(std::string(mf::kRootKey));
        // history[0] is the replayed epoch-1 copy; history[1] is our epoch 3.
        other = mf::openRoot(history[1].body, vaultUid, lookup);
        other.published_at = "2031-01-01T00:00:00Z";
        bucket->seed(std::string(mf::kRootKey), mf::sealRoot(other, vaultUid, {k.version, k.key}));
    }
    EXPECT_THROW((void)service.verifyRemote(), mf::ChainRejected);
    state = db::query::sync::Manifest::state(vaultId);
    EXPECT_EQ(state.refused_reason, "fork");
    EXPECT_EQ(drainManifestAlerts("manifest_fork"), 1u);

    // Our own root back in place: accepted again, the refusal cleared by the next publish.
    bucket->seed(std::string(mf::kRootKey), bucket->history(std::string(mf::kRootKey))[2].body);
    ASSERT_TRUE(service.verifyRemote());
    write("/a.txt", "d");
    const auto r = service.publish();
    EXPECT_EQ(r.published.known.epoch, 4u);
    EXPECT_FALSE(db::query::sync::Manifest::state(vaultId).refused_reason);
}

TEST_F(ManifestDbTest, OpaqueVaultsPublishManifestV2InsteadOfIndexV1) {
    // opaque_v1 is internal (test mode only, until #371): the engine publishes the encrypted manifest, never the
    // plaintext index, and a refused root stalls the pass.
    auto apiKey = std::make_shared<vault::model::APIKey>(superUser->id, "manifest_key_" + tag(), vault::model::S3Provider::AWS,
                                                         "AKIAMANIFESTTEST0000", "manifest-secret-00000000000000000000",
                                                         "us-east-1", "https://s3.example.com");
    const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(apiKey);
    auto s3 = std::make_shared<vault::model::S3Vault>("manifest_s3_" + tag(), keyId, "manifest-bucket-" + tag());
    s3->owner_id = superUser->id;
    s3->mount_point = "manifest_s3_" + tag();
    s3->encrypt_upstream = true;
    s3->storage_layout = vault::model::StorageLayout::OpaqueV1;
    s3->id = db::query::vault::Vault::upsertVault(s3, std::make_shared<sync::model::RemotePolicy>());
    const auto stored = std::dynamic_pointer_cast<vault::model::S3Vault>(db::query::vault::Vault::getVault(s3->id));
    ASSERT_TRUE(stored && stored->uid);
    ASSERT_EQ(stored->storage_layout, vault::model::StorageLayout::OpaqueV1);

    auto bucket = std::make_shared<VersionedBucket>(Versioning::Enabled);
    const auto cloud = std::make_shared<storage::CloudEngine>(stored, bucket);
    cloud->encryptionManager->load_key();

    cloud->publishRemoteIndexManifestWithRetry();
    EXPECT_TRUE(bucket->current(std::string(mf::kRootKey)));
    EXPECT_TRUE(bucket->current(std::string(mf::kLayoutKey)));
    EXPECT_FALSE(bucket->current(".vaulthalla/index-v1.json")) << "no plaintext index for an opaque_v1 vault";
    EXPECT_EQ(db::query::sync::Manifest::state(s3->id).epoch, 1u);

    // Nothing changed: no publish. The pass doesn't load the v2 manifest into the path-keyed index.
    cloud->applyRemoteIndexMutation({});
    EXPECT_EQ(db::query::sync::Manifest::state(s3->id).epoch, 1u);
    EXPECT_FALSE(cloud->refreshRemoteIndexFromManifestIfChanged());
    cloud->publishRemoteIndexManifestWithRetry();
    const auto epoch2 = db::query::sync::Manifest::state(s3->id);
    EXPECT_EQ(epoch2.epoch, 2u);

    // A replayed epoch-1 root: refused, the pass stalls, the database keeps epoch 2.
    bucket->seed(std::string(mf::kRootKey), bucket->history(std::string(mf::kRootKey)).back().body);
    EXPECT_THROW((void)cloud->refreshRemoteIndexFromManifestIfChanged(), sync::model::SyncStalled);
    EXPECT_THROW(cloud->publishRemoteIndexManifestWithRetry(), sync::model::SyncStalled);
    const auto after = db::query::sync::Manifest::state(s3->id);
    EXPECT_EQ(after.epoch, 2u);
    EXPECT_EQ(after.root_sha256, epoch2.root_sha256);
    EXPECT_EQ(after.refused_reason, "rollback");
    EXPECT_EQ(drainManifestAlerts("manifest_rollback"), 1u);
}

}
