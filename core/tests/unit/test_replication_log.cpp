// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The replication log of a mirrored vault (migration 160, db::query::mirror, design/peers/mirror.md "The replication
// log", "Parity"). Triggers on the entry tables write it in each mutation's own transaction, so these tests drive the
// product's write paths (mkdir, uploads, the seal's row update, rename, move, copy, trash, purge, restore, symlinks,
// key rotation's re-seal, vault settings, psql by hand) on a vault this server is the core of, on a local and on an S3
// vault, and read the log back as a consumer will: numbered, in whole groups, self-contained. Proven here: each op and
// its complete state; one transaction is one group; trash, restore and purge are distinct; mtime-only, attribution-only,
// owner and key-version changes are recorded; vh.mirror_apply suppresses rows; a vault that is not mirrored writes
// nothing; (term, seq) has no gaps under concurrent writers; the running digest equals the one recomputed from the
// tables after random operations; replaying the log's states alone reproduces the tree.
// tools/contracts/test_replication_log_contract.py keeps every SQL writer of these tables classified.

#include "mirror/start/Guard.hpp"
#include "../helpers/db_suite.hpp"

#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/fs/Symlink.hpp"
#include "db/query/mirror/Log.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Symlink.hpp"
#include "fs/model/file/Trashed.hpp"
#include "identities/User.hpp"
#include "mirror/Hash.hpp"
#include "mirror/Sequencer.hpp"
#include "ops/Error.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <map>
#include <memory>
#include <random>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_replication_log {

using json = nlohmann::json;
using EnginePtr = std::shared_ptr<storage::Engine>;
using Lines = std::vector<std::string>;
namespace mq = vh::db::query::mirror;

std::string rlTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "r" + std::to_string(n.fetch_add(1));
}

class MirrorReplicationLogDbTest : public vh::test::db::Suite {
protected:
    inline static uint32_t peerId{};

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_replication_log")) return;
        vh::db::query::peer::NewPeer p;
        p.node_id = "peer-node-" + rlTag();
        p.name = "mirror peer";
        p.spki_sha256 = std::string(64, 'a');
        p.wrap_public_key.fill(7);
        peerId = vh::db::query::peer::Peers::insert(p).id;
    }

    // No vault stays mirrored for the suites after this one that share the schema.
    static void TearDownTestSuite() {
        if (!skipTests)
            for (const auto& m : mq::MirrorVaults::list()) (void)mq::MirrorVaults::remove(m.vault_id);
        tearDownDbSuite();
    }

    // ---- vaults

    static EnginePtr localVault() {
        const auto v = ops::vaults::create(superUser, {.name = "rl_" + rlTag(), .type = vault::model::VaultType::Local});
        return runtime::Deps::get().storageManager->getEngine(v->id);
    }

    static EnginePtr s3Vault() {
        auto apiKey = std::make_shared<vault::model::APIKey>(superUser->id, "rl_key_" + rlTag(),
                                                             vault::model::S3Provider::AWS, "AKIATESTACCESSKEY000",
                                                             "secret-value-0000000000000000000000000", "us-east-1",
                                                             "https://s3.example.com");
        const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(apiKey);
        const auto v = ops::vaults::create(superUser, {.name = "rls3_" + rlTag(), .type = vault::model::VaultType::S3,
                                                       .s3 = ops::vaults::S3Spec{.api_key_id = keyId,
                                                                                 .bucket = "rl-" + rlTag()}});
        return runtime::Deps::get().storageManager->getEngine(v->id);
    }

    static mq::MirrorVault mirror(const EnginePtr& engine) {
        return mq::MirrorVaults::startCore(engine->vault->id, peerId);
    }

    static uint32_t vid(const EnginePtr& engine) { return engine->vault->id; }

    // ---- writes through the product

    static void write(const EnginePtr& engine, const std::string& path, const std::string& content) {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path,
                                                .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine,
                                                .user = superUser,
                                                .overwrite = true}));
    }

    static uint32_t symlink(const EnginePtr& engine, const std::string& dir, const std::string& name,
                            const std::string& target) {
        auto link = std::make_shared<fs::model::Symlink>();
        link->vault_id = static_cast<int32_t>(vid(engine));
        link->parent_id = static_cast<int32_t>(entryId(engine, dir));
        link->name = name;
        link->path = (dir == "/" ? "" : dir) + "/" + name;
        link->fuse_path = engine->vaultPathToFusePath(link->path);
        link->base32_alias = "rl" + rlTag();
        link->target = target;
        link->created_by = link->last_modified_by = static_cast<int32_t>(superUser->id);
        return db::query::fs::Symlink::upsertSymlink(link);
    }

    static uint32_t entryId(const EnginePtr& engine, const std::string& path) {
        return db::Transactions::exec("rl entry id", [&](pqxx::work& txn) {
            const auto r = txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = $2",
                                    pqxx::params{vid(engine), path});
            return r.empty() ? 0u : r[0][0].as<uint32_t>();
        });
    }

    static std::string uidOf(const EnginePtr& engine, const std::string& path) {
        return db::Transactions::exec("rl uid", [&](pqxx::work& txn) {
            const auto r = txn.exec("SELECT COALESCE(f.object_uid, d.uid, s.uid)::text FROM fs_entry e "
                                    "LEFT JOIN files f ON f.fs_entry_id = e.id "
                                    "LEFT JOIN directories d ON d.fs_entry_id = e.id "
                                    "LEFT JOIN symlinks s ON s.fs_entry_id = e.id "
                                    "WHERE e.vault_id = $1 AND e.path = $2",
                                    pqxx::params{vid(engine), path});
            return r.empty() || r[0][0].is_null() ? std::string{} : r[0][0].as<std::string>();
        });
    }

    static void sql(const std::string& statement) {
        db::Transactions::exec("rl sql", [&](pqxx::work& txn) { txn.exec(statement); });
    }

    static uint32_t trashId(const EnginePtr& engine, const std::string& path) {
        for (const auto& t : db::query::fs::File::listTrashedFiles(vid(engine)))
            if (t && t->path == path) return t->id;
        return 0;
    }

    // The manifest applier's restore (ManifestApply::create): the file is live again under its trashed uid, and its
    // trash row ends, in one transaction.
    static void restore(const EnginePtr& engine, const std::string& trashedPath, const std::string& to) {
        db::Transactions::exec("rl restore", [&](pqxx::work& txn) {
            const auto t = txn.exec("SELECT id, object_uid::text, size_bytes FROM files_trashed "
                                    "WHERE vault_id = $1 AND path = $2 AND deleted_at IS NULL ORDER BY id DESC LIMIT 1",
                                    pqxx::params{vid(engine), trashedPath}).one_row();
            const auto parent = txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = '/'",
                                         pqxx::params{vid(engine)}).one_field().as<uint32_t>();
            const auto id = txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, created_by, last_modified_by, path, "
                                     "  mode, base32_alias) VALUES ($1, $2, $3, $4, $4, $5, 420, "
                                     "  substr(md5(random()::text) || md5(random()::text), 1, 33)) RETURNING id",
                                     pqxx::params{vid(engine), parent, to.substr(1), superUser->id, to})
                                .one_field().as<uint32_t>();
            txn.exec("INSERT INTO files (fs_entry_id, size_bytes, content_hash, encryption_iv, "
                     "  encrypted_with_key_version, object_uid) VALUES ($1, $2, 'restored', '', 0, $3::uuid)",
                     pqxx::params{id, t["size_bytes"].as<int64_t>(), t["object_uid"].as<std::string>()});
            txn.exec("UPDATE files_trashed SET deleted_at = NOW() WHERE id = $1", pqxx::params{t["id"].as<uint32_t>()});
        });
    }

    // ---- reading the log as a consumer

    struct Cursor {
        mq::Position at{1, 0};
    };

    static std::vector<mq::Group> drain(const EnginePtr& engine, Cursor& cursor, const std::size_t limit = 10'000) {
        (void)mq::Log::sequence(vid(engine));
        std::vector<mq::Group> out;
        for (;;) {
            const auto page = mq::Log::groupsAfter(vid(engine), cursor.at, limit);
            EXPECT_FALSE(page.expired);
            if (page.expired) break;
            for (const auto& g : page.groups) out.push_back(g);
            cursor.at = page.last;
            if (!page.more) break;
        }
        return out;
    }

    static std::string where(const mq::Row& r) {
        if (r.name) return *r.name;
        if (r.state.contains("trashed")) return r.state["trashed"].value("path", std::string("?"));
        return "?";
    }

    // "op type name" per row, every group in order.
    static Lines lines(const std::vector<mq::Group>& groups) {
        Lines out;
        for (const auto& g : groups)
            for (const auto& r : g.rows) out.push_back(r.op + " " + r.entry_type.value_or("-") + " " + where(r));
        return out;
    }

    static Lines drainLines(const EnginePtr& engine, Cursor& cursor) { return lines(drain(engine, cursor)); }

    static std::size_t countRows(const uint32_t vaultId) {
        return db::Transactions::exec("rl count", [&](pqxx::work& txn) {
            return txn.exec("SELECT count(*) FROM vault_replication_log WHERE vault_id = $1", pqxx::params{vaultId})
                .one_field().as<std::size_t>();
        });
    }

    // Every state field a replicated entry of its type must carry (design/peers/mirror.md "Self-contained rows").
    static void expectComplete(const mq::Row& r) {
        SCOPED_TRACE(r.op + " " + r.state.dump());
        ASSERT_TRUE(r.entry_uid);
        EXPECT_EQ(r.state.value("uid", std::string{}), *r.entry_uid);
        EXPECT_EQ(r.state.value("v", 0), 1);
        if (r.state.contains("trashed")) {
            for (const auto* k : {"path", "at", "by"}) EXPECT_TRUE(r.state["trashed"].contains(k)) << k;
            EXPECT_TRUE(r.state["trashed"]["by"].contains("node"));
            EXPECT_TRUE(r.state.contains("size"));
            return;
        }
        for (const auto* k : {"type", "parent", "name", "hidden", "created_at", "created_by", "modified_by"})
            EXPECT_TRUE(r.state.contains(k)) << k;
        EXPECT_TRUE(r.state["created_by"].contains("node"));
        EXPECT_TRUE(r.state["created_by"].contains("id"));
        const auto type = r.state.value("type", std::string{});
        EXPECT_EQ(r.entry_type.value_or(""), type);
        if (type != "directory") {
            EXPECT_TRUE(r.state.contains("modified_at"));
        }
        if (type != "symlink") {
            EXPECT_TRUE(r.state.contains("mode")) << "a symlink has no mode; everything else does";
        }
        if (type == "file") {
            for (const auto* k : {"size", "content_hash", "generation", "key_version", "content_format"})
                EXPECT_TRUE(r.state.contains(k)) << k;
        }
        if (type == "symlink") {
            EXPECT_TRUE(r.state.contains("target"));
        }
        if (r.entry_hash) {
            EXPECT_EQ(*r.entry_hash, vh::mirror::entryHash(r.state)) << "the row's hash is its state's";
        }
    }

    static void expectDigestHolds(const EnginePtr& engine) {
        (void)mq::Log::sequence(vid(engine));
        const auto mv = mq::MirrorVaults::get(vid(engine));
        ASSERT_TRUE(mv);
        const auto recomputed = mq::Digests::recompute(vid(engine));
        EXPECT_EQ(mv->digest.hex(), recomputed.hex()) << "the running digest is the tree's";
        EXPECT_EQ(mv->digest.entries, recomputed.entries);
        EXPECT_EQ(mq::Digests::stored(vid(engine)), recomputed);
    }

    // Each op, its type and a complete state: the same on any vault type.
    static void exerciseEveryOperation(const EnginePtr& engine) {
        Cursor cursor;
        mirror(engine);

        engine->mkdir("/docs", superUser);
        write(engine, "/docs/a.txt", "first");
        auto groups = drain(engine, cursor);
        for (const auto& g : groups)
            for (const auto& r : g.rows) expectComplete(r);
        EXPECT_EQ(lines(groups), (Lines{"upsert directory docs", "upsert file a.txt"}));

        // Overwrite (uploads), then the FUSE seal's row update.
        write(engine, "/docs/a.txt", "second, longer");
        EXPECT_EQ(drainLines(engine, cursor), (Lines{"upsert file a.txt"}));
        auto sealed = db::query::fs::File::getFileByPath(vid(engine), "/docs/a.txt");
        ASSERT_TRUE(sealed);
        sealed->size_bytes += 3;
        sealed->content_hash = "sealed-" + rlTag();
        db::query::fs::File::updateFile(sealed);
        groups = drain(engine, cursor);
        EXPECT_EQ(lines(groups), (Lines{"upsert file a.txt"}));
        ASSERT_EQ(groups.size(), 1u);
        EXPECT_EQ(groups[0].rows[0].state.value("content_hash", std::string{}), sealed->content_hash);
        EXPECT_TRUE(groups[0].rows[0].prev_hash) << "it replaced a state the log had";

        // A key-version change (rotation's re-seal: new generation under the next version), which the journal skips.
        sealed->encryption_iv = "rotated-iv-" + rlTag();
        sealed->encrypted_with_key_version += 1;
        db::query::fs::File::setEncryptionIVAndVersion(sealed);
        groups = drain(engine, cursor);
        ASSERT_EQ(lines(groups), (Lines{"upsert file a.txt"}));
        EXPECT_EQ(groups[0].rows[0].state.value("key_version", 0u), sealed->encrypted_with_key_version);
        EXPECT_EQ(groups[0].rows[0].state.value("generation", std::string{}), sealed->encryption_iv);

        // Rename, move, copy.
        engine->mkdir("/box", superUser);
        engine->rename("/docs/a.txt", "/docs/b.txt", superUser);
        engine->move("/docs/b.txt", "/box/b.txt", superUser);
        engine->copy("/box/b.txt", "/docs/c.txt", superUser->id, {});
        groups = drain(engine, cursor);
        EXPECT_EQ(lines(groups), (Lines{"upsert directory box", "move file b.txt", "move file b.txt", "upsert file c.txt"}));
        for (const auto& g : groups)
            for (const auto& r : g.rows) expectComplete(r);
        ASSERT_EQ(groups.size(), 4u);
        EXPECT_EQ(groups[2].rows[0].parent_uid.value_or(""), uidOf(engine, "/box")) << "a move names its new parent";
        EXPECT_NE(groups[3].rows[0].entry_uid, groups[2].rows[0].entry_uid) << "a copy is a new entry";

        // A symlink, and psql by hand: its target, a mode, a modification time alone, an attribution alone, an owner.
        const auto linkId = symlink(engine, "/docs", "latest", "c.txt");
        const auto other = ops::users::create(superUser, {.name = "rl_user_" + rlTag(), .role = "unprivileged",
                                                          .password = std::string("Replication-Log-Pass-123")});
        const auto docsC = entryId(engine, "/docs/c.txt");
        sql("UPDATE symlinks SET target = 'b.txt' WHERE fs_entry_id = " + std::to_string(linkId));
        sql("UPDATE fs_entry SET mode = 384 WHERE id = " + std::to_string(docsC));
        sql("UPDATE fs_entry SET updated_at = updated_at + INTERVAL '1 minute' WHERE id = " + std::to_string(docsC));
        db::Transactions::exec("rl attribution only", [&](pqxx::work& txn) {
            txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)");
            txn.exec("UPDATE fs_entry SET last_modified_by = $1 WHERE id = $2", pqxx::params{other.user->id, docsC});
        });
        db::Transactions::exec("rl owner", [&](pqxx::work& txn) {
            txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)");
            txn.exec("UPDATE fs_entry SET owner_uid = 4242, group_gid = 4343 WHERE id = $1", pqxx::params{docsC});
        });
        groups = drain(engine, cursor);
        EXPECT_EQ(lines(groups), (Lines{"upsert symlink latest", "upsert symlink latest", "upsert file c.txt",
                                        "upsert file c.txt", "upsert file c.txt", "upsert file c.txt"}));
        ASSERT_EQ(groups.size(), 6u);
        EXPECT_EQ(groups[1].rows[0].state.value("target", std::string{}), "b.txt");
        EXPECT_EQ(groups[2].rows[0].state.value("mode", 0), 384);
        EXPECT_NE(groups[3].rows[0].state["modified_at"], groups[2].rows[0].state["modified_at"]) << "mtime alone";
        EXPECT_EQ(groups[4].rows[0].state["modified_by"]["id"], other.user->id) << "attribution alone";
        EXPECT_EQ(groups[4].rows[0].state["modified_at"], groups[3].rows[0].state["modified_at"]);
        EXPECT_EQ(groups[5].rows[0].state.value("owner_uid", 0), 4242);
        EXPECT_EQ(groups[5].rows[0].state.value("owner_gid", 0), 4343);
        for (const auto& g : groups)
            for (const auto& r : g.rows) expectComplete(r);

        // Trash, restore, trash again, purge: four different ops.
        const auto cUid = uidOf(engine, "/docs/c.txt");
        engine->remove("/docs/c.txt", superUser->id);
        groups = drain(engine, cursor);
        ASSERT_EQ(lines(groups), (Lines{"trash file /docs/c.txt"}));
        EXPECT_EQ(groups[0].rows[0].entry_uid.value_or(""), cUid);
        EXPECT_TRUE(groups[0].rows[0].prev_hash) << "it replaced the live file";
        EXPECT_TRUE(groups[0].rows[0].entry_hash) << "a trashed file is still part of the tree";
        expectComplete(groups[0].rows[0]);

        restore(engine, "/docs/c.txt", "/c.txt");
        groups = drain(engine, cursor);
        ASSERT_EQ(lines(groups), (Lines{"restore file c.txt"}));
        EXPECT_EQ(groups[0].rows[0].entry_uid.value_or(""), cUid);
        expectComplete(groups[0].rows[0]);

        write(engine, "/p.txt", "to purge");
        engine->remove("/p.txt", superUser->id);
        EXPECT_EQ(drainLines(engine, cursor), (Lines{"upsert file p.txt", "trash file /p.txt"}));
        db::query::fs::File::markTrashedFileDeleted(trashId(engine, "/p.txt"));
        groups = drain(engine, cursor);
        ASSERT_EQ(lines(groups), (Lines{"purge file /p.txt"}));
        EXPECT_FALSE(groups[0].rows[0].entry_hash);
        EXPECT_TRUE(groups[0].rows[0].prev_hash);

        // A folder delete takes what is under it, in one group.
        write(engine, "/box/inner.txt", "i");
        engine->mkdir("/box/sub", superUser);
        (void)drain(engine, cursor);
        engine->remove("/box", superUser->id);
        groups = drain(engine, cursor);
        std::set<std::string> removed;
        for (const auto& g : groups)
            for (const auto& r : g.rows) removed.insert(r.op + " " + where(r));
        EXPECT_TRUE(removed.contains("delete box")) << ::testing::PrintToString(lines(groups));
        EXPECT_TRUE(removed.contains("delete sub")) << ::testing::PrintToString(lines(groups));

        // The vault's settings and a key record.
        sql("UPDATE vault SET description = 'mirrored " + rlTag() + "', quota = 123456789 WHERE id = " +
            std::to_string(vid(engine)));
        // Rotation is refused on a mirrored vault until it goes over the link (mirror/start/Guard.hpp); the log's key
        // rows are what that rotation will write, so this test lets one through.
        vh::mirror::start::allowRotationOnMirroredForTesting(true);
        engine->encryptionManager->prepare_key_rotation();
        engine->encryptionManager->finish_key_rotation();
        vh::mirror::start::allowRotationOnMirroredForTesting(false);
        groups = drain(engine, cursor);
        const auto all = lines(groups);
        ASSERT_FALSE(all.empty());
        EXPECT_TRUE(all.front().starts_with("vault - ")) << all.front();
        const auto& vaultRow = groups.front().rows.front();
        EXPECT_EQ(vaultRow.state.value("quota", 0), 123456789);
        EXPECT_EQ(vaultRow.state.value("uid", std::string{}), vaultRow.entry_uid.value_or(""));
        EXPECT_TRUE(vaultRow.state.contains("owner"));
        std::vector<json> keys;
        for (const auto& g : groups)
            for (const auto& r : g.rows)
                if (r.op == "key") {
                    keys.push_back(r.state);
                    EXPECT_TRUE(r.state.contains("version"));
                    for (const auto* secret : {"encrypted_key", "iv", "key", "encrypted_key_next", "master_version"})
                        EXPECT_FALSE(r.state.contains(secret)) << "a key record carries no key material: " << secret;
                }
        ASSERT_FALSE(keys.empty()) << ::testing::PrintToString(all);
        // The new version, then its key check and attestation as rotation records them.
        EXPECT_TRUE(keys.back().contains("key_check")) << ::testing::PrintToString(keys);
        EXPECT_GT(keys.back().value("version", 0), 1) << ::testing::PrintToString(keys);

        expectDigestHolds(engine);
    }
};

// ---------------------------------------------------------------------------------------------------- the hash

TEST_F(MirrorReplicationLogDbTest, TheDatabaseHashesStatesAsTheHeaderSays) {
    const auto vector = json::parse(R"({"v":1,"uid":"0f8fad5b-d9cb-469f-a165-70867728950e","type":"file",
        "parent":"7c9e6679-7425-40de-944b-e07fc1f90ae7","name":"Résumé.txt","mode":420,"hidden":false,
        "owner_uid":1000,"owner_gid":1000,"created_at":1732540000123456,"modified_at":1732540100654321,
        "created_by":{"node":"node-a","id":3},"modified_by":{"node":"node-b","id":7},"size":5,"content_hash":"ab12",
        "mime":"text/plain","generation":"AAAA","key_version":2,"content_format":"vhf1"})");
    EXPECT_EQ(vh::mirror::toHex(mq::Digests::hashInDatabase(vector)),
              "c3cd6e5ea36d18109bdc5878a6ce1bcc6ea5e8325b3b78e5cb186ba636cae95d");

    // Real states of every kind, built by the database, hash the same in C++.
    const auto engine = localVault();
    mirror(engine);
    engine->mkdir("/h", superUser);
    write(engine, "/h/f.txt", "hash me");
    (void)symlink(engine, "/h", "l", "f.txt");
    engine->remove("/h/f.txt", superUser->id);
    Cursor cursor;
    std::size_t seen = 0;
    for (const auto& g : drain(engine, cursor))
        for (const auto& r : g.rows)
            if (r.entry_hash) {
                EXPECT_EQ(mq::Digests::hashInDatabase(r.state), vh::mirror::entryHash(r.state)) << r.state.dump();
                ++seen;
            }
    EXPECT_GE(seen, 4u);
}

// ---------------------------------------------------------------------------------------------------- ops and states

TEST_F(MirrorReplicationLogDbTest, EveryOperationOnALocalVaultLogsItsOpAndACompleteState) {
    exerciseEveryOperation(localVault());
}

TEST_F(MirrorReplicationLogDbTest, EveryOperationOnAnS3VaultLogsItsOpAndACompleteState) {
    exerciseEveryOperation(s3Vault());
}

TEST_F(MirrorReplicationLogDbTest, StartingACoreTakesTheTreeAsItsBaseline) {
    const auto engine = localVault();
    engine->mkdir("/before", superUser);
    write(engine, "/before/x.txt", "x");
    write(engine, "/y.txt", "y");
    engine->remove("/y.txt", superUser->id);
    EXPECT_EQ(countRows(vid(engine)), 0u) << "nothing is logged before the vault is mirrored";

    const auto mv = mirror(engine);
    EXPECT_EQ(mv.role, "core");
    EXPECT_EQ(mv.position(), (mq::Position{1, 0}));
    EXPECT_EQ(mv.digest.entries, 3) << "a folder, a file and a trashed file";
    EXPECT_EQ(mv.digest, mq::Digests::recompute(vid(engine)));
    EXPECT_EQ(countRows(vid(engine)), 0u);
    EXPECT_THROW((void)mirror(engine), ops::Conflict);
    EXPECT_THROW((void)mq::MirrorVaults::startCore(vid(engine) + 100000, peerId), ops::NotFound);

    EXPECT_TRUE(mq::MirrorVaults::remove(vid(engine)));
    write(engine, "/after.txt", "a");
    EXPECT_EQ(countRows(vid(engine)), 0u) << "a vault no longer mirrored writes nothing";
}

// ---------------------------------------------------------------------------------------------------- groups

TEST_F(MirrorReplicationLogDbTest, OneTransactionIsOneGroupIncludingSwapsCascadesAndFolderMoves) {
    const auto engine = localVault();
    engine->mkdir("/tree/deep", superUser);
    write(engine, "/tree/deep/f.txt", "f");
    write(engine, "/a.txt", "a");
    write(engine, "/b.txt", "b");
    engine->mkdir("/dest", superUser);
    mirror(engine);
    Cursor cursor;

    // A rename swap through a temporary name, by hand, in one transaction.
    const auto a = entryId(engine, "/a.txt");
    const auto b = entryId(engine, "/b.txt");
    db::Transactions::exec("rl swap", [&](pqxx::work& txn) {
        txn.exec("UPDATE fs_entry SET name = 'swap.tmp', path = '/swap.tmp' WHERE id = $1", pqxx::params{a});
        txn.exec("UPDATE fs_entry SET name = 'a.txt', path = '/a.txt' WHERE id = $1", pqxx::params{b});
        txn.exec("UPDATE fs_entry SET name = 'b.txt', path = '/b.txt' WHERE id = $1", pqxx::params{a});
    });
    auto groups = drain(engine, cursor);
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(lines(groups), (Lines{"move file swap.tmp", "move file a.txt", "move file b.txt"}));
    EXPECT_EQ(groups[0].last_seq - groups[0].first_seq + 1, groups[0].rows.size());

    // A folder move: the folder and every entry under it (the server re-stamps each descendant) in one group.
    engine->move("/tree", "/dest/tree", superUser);
    groups = drain(engine, cursor);
    ASSERT_EQ(groups.size(), 1u) << ::testing::PrintToString(lines(groups));
    EXPECT_EQ(groups[0].rows.front().op, "move");
    EXPECT_EQ(groups[0].rows.front().name.value_or(""), "tree");
    EXPECT_EQ(groups[0].rows.front().parent_uid.value_or(""), uidOf(engine, "/dest"));

    // A cascade delete: the folder first, then everything under it, in one group.
    db::Transactions::exec("rl cascade", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM fs_entry WHERE id = $1", pqxx::params{entryId(engine, "/dest/tree")});
    });
    groups = drain(engine, cursor);
    ASSERT_EQ(groups.size(), 1u);
    EXPECT_EQ(lines(groups), (Lines{"delete directory tree", "delete directory deep", "delete file f.txt"}));
    for (const auto& r : groups[0].rows) {
        EXPECT_FALSE(r.entry_hash);
        EXPECT_TRUE(r.prev_hash);
    }
    expectDigestHolds(engine);
}

// Groups are numbered in commit order: a transaction that writes first and commits last comes after.
TEST_F(MirrorReplicationLogDbTest, GroupsAreNumberedInCommitOrder) {
    const auto engine = localVault();
    write(engine, "/early.txt", "e");
    write(engine, "/late.txt", "l");
    mirror(engine);
    Cursor cursor;
    const auto early = entryId(engine, "/early.txt");
    const auto late = entryId(engine, "/late.txt");
    db::Transactions::exec("rl written first, committed last", [&](pqxx::work& txn) {
        txn.exec("UPDATE fs_entry SET name = 'early2.txt', path = '/early2.txt' WHERE id = $1", pqxx::params{early});
        db::Transactions::exec("rl written last, committed first", [&](pqxx::work& inner) {
            inner.exec("UPDATE fs_entry SET name = 'late2.txt', path = '/late2.txt' WHERE id = $1", pqxx::params{late});
        });
        EXPECT_EQ(drainLines(engine, cursor), (Lines{"move file late2.txt"})) << "only what committed is readable";
    });
    EXPECT_EQ(drainLines(engine, cursor), (Lines{"move file early2.txt"}));
}

// The reader cuts only between groups: a page never ends inside one, and a group larger than the page comes whole.
TEST_F(MirrorReplicationLogDbTest, PagesEndOnlyBetweenGroups) {
    const auto engine = localVault();
    mirror(engine);
    const auto root = entryId(engine, "/");
    const auto group = [&](const int files) {
        db::Transactions::exec("rl group", [&](pqxx::work& txn) {
            for (int i = 0; i < files; ++i) {
                const auto name = "g" + rlTag() + ".txt";
                const auto id = txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, path, created_by, "
                                         "  last_modified_by) VALUES ($1, $2, $3, $4, $5, $5) RETURNING id",
                                         pqxx::params{vid(engine), root, name, "/" + name, superUser->id})
                                    .one_field().as<uint32_t>();
                txn.exec("INSERT INTO files (fs_entry_id, size_bytes, encryption_iv, encrypted_with_key_version, "
                         "  object_uid) VALUES ($1, 0, '', 0, gen_random_uuid())",
                         pqxx::params{id});
            }
        });
    };
    group(3);
    group(1);
    group(4);
    (void)mq::Log::sequence(vid(engine));

    const auto sizes = [](const mq::Page& p) {
        std::vector<std::size_t> out;
        for (const auto& g : p.groups) out.push_back(g.rows.size());
        return out;
    };
    auto page = mq::Log::groupsAfter(vid(engine), {1, 0}, 2);
    EXPECT_EQ(sizes(page), (std::vector<std::size_t>{3})) << "a first group larger than the page comes whole";
    EXPECT_TRUE(page.more);
    EXPECT_EQ(page.last, (mq::Position{1, 3}));
    page = mq::Log::groupsAfter(vid(engine), {1, 0}, 5);
    EXPECT_EQ(sizes(page), (std::vector<std::size_t>{3, 1}));
    EXPECT_EQ(page.last, (mq::Position{1, 4}));
    page = mq::Log::groupsAfter(vid(engine), page.last, 5);
    EXPECT_EQ(sizes(page), (std::vector<std::size_t>{4}));
    EXPECT_FALSE(page.more);
    page = mq::Log::groupsAfter(vid(engine), page.last, 5);
    EXPECT_TRUE(page.groups.empty());
    EXPECT_FALSE(page.expired);
    EXPECT_TRUE(mq::Log::groupsAfter(vid(engine), {1, 99}, 5).expired) << "a position never handed out";
    EXPECT_TRUE(mq::Log::groupsAfter(localVault()->vault->id, {1, 0}, 5).expired) << "a vault that is not a core";
}

// ---------------------------------------------------------------------------------------------------- switches

TEST_F(MirrorReplicationLogDbTest, MirrorApplySuppressesRowsAndAVaultNotMirroredWritesNothing) {
    const auto engine = localVault();
    const auto bystander = localVault();
    write(engine, "/x.txt", "x");
    mirror(engine);
    const auto before = countRows(vid(engine));
    const auto storedBefore = mq::Digests::stored(vid(engine));

    const auto x = entryId(engine, "/x.txt");
    db::Transactions::exec("rl applied from a core", [&](pqxx::work& txn) {
        mq::Log::markMirrorApply(txn);
        txn.exec("UPDATE fs_entry SET name = 'y.txt', path = '/y.txt' WHERE id = $1", pqxx::params{x});
        txn.exec("UPDATE vault SET description = 'applied' WHERE id = $1", pqxx::params{vid(engine)});
    });
    EXPECT_EQ(countRows(vid(engine)), before) << "vh.mirror_apply: no rows";
    EXPECT_EQ(mq::Digests::stored(vid(engine)), storedBefore) << "and no entry hash moved";
    // The switch is transaction-local.
    sql("UPDATE fs_entry SET name = 'z.txt', path = '/z.txt' WHERE id = " + std::to_string(x));
    EXPECT_EQ(countRows(vid(engine)), before + 1);

    write(bystander, "/b.txt", "b");
    bystander->mkdir("/d", superUser);
    bystander->remove("/b.txt", superUser->id);
    EXPECT_EQ(countRows(vid(bystander)), 0u);
    EXPECT_FALSE(mq::MirrorVaults::get(vid(bystander)));
}

// ---------------------------------------------------------------------------------------------------- concurrency

// Writers on several connections, a shared entry they all touch, and sequencers running meanwhile: every number from 1
// to the last is used once, each group's rows are consecutive and one transaction's, and the digest holds.
TEST_F(MirrorReplicationLogDbTest, SequenceIsGapFreeUnderConcurrentWriters) {
    const auto engine = localVault();
    write(engine, "/shared.txt", "s");
    mirror(engine);
    const auto root = entryId(engine, "/");
    const auto shared = entryId(engine, "/shared.txt");
    constexpr int kWriters = 3;
    constexpr int kTransactions = 40;

    std::atomic<bool> stop{false};
    std::atomic<int> failures{0};
    std::thread sequencer([&] {
        while (!stop) {
            try {
                (void)vh::mirror::Sequencer::instance()->tick();
            } catch (const std::exception&) {
                ++failures;
            }
        }
    });
    std::vector<std::thread> writers;
    for (int w = 0; w < kWriters; ++w)
        writers.emplace_back([&, w] {
            std::mt19937 rng(1234 + w);
            for (int t = 0; t < kTransactions; ++t) {
                try {
                    db::Transactions::exec("rl writer", [&](pqxx::work& txn) {
                        const auto name = "w" + std::to_string(w) + "_" + std::to_string(t) + ".txt";
                        const auto id = txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, path, created_by, "
                                                 "  last_modified_by) VALUES ($1, $2, $3, $4, $5, $5) RETURNING id",
                                                 pqxx::params{vid(engine), root, name, "/" + name, superUser->id})
                                            .one_field().as<uint32_t>();
                        txn.exec("INSERT INTO files (fs_entry_id, size_bytes, encryption_iv, encrypted_with_key_version, "
                                 "  object_uid) VALUES ($1, 1, '', 0, gen_random_uuid())",
                                 pqxx::params{id});
                        if (rng() % 2) txn.exec("UPDATE files SET size_bytes = size_bytes + 1 WHERE fs_entry_id = $1",
                                                pqxx::params{id});
                        // Two tables of one entry, from every writer.
                        if (rng() % 3 == 0)
                            txn.exec("UPDATE files SET size_bytes = size_bytes + 1 WHERE fs_entry_id = $1",
                                     pqxx::params{shared});
                        else if (rng() % 3 == 1)
                            txn.exec("UPDATE fs_entry SET mode = $2 WHERE id = $1",
                                     pqxx::params{shared, static_cast<int>(256 + rng() % 256)});
                    });
                } catch (const std::exception&) {
                    ++failures;
                }
            }
        });
    for (auto& t : writers) t.join();
    stop = true;
    sequencer.join();
    EXPECT_EQ(failures.load(), 0);

    Cursor cursor;
    const auto groups = drain(engine, cursor);
    uint64_t expected = 1;
    std::set<uint64_t> txids;
    std::size_t rows = 0;
    for (const auto& g : groups) {
        EXPECT_TRUE(txids.insert(g.txid).second) << "a transaction is one group";
        for (const auto& r : g.rows) {
            EXPECT_EQ(r.seq, expected++) << "no gaps, no repeats";
            EXPECT_EQ(r.txid, g.txid);
            ++rows;
        }
    }
    EXPECT_EQ(groups.size(), static_cast<std::size_t>(kWriters * kTransactions));
    const auto mv = mq::MirrorVaults::get(vid(engine));
    ASSERT_TRUE(mv);
    EXPECT_EQ(mv->last_seq, rows);
    EXPECT_EQ(rows, countRows(vid(engine)));
    expectDigestHolds(engine);
}

// ---------------------------------------------------------------------------------------------------- parity

// The tree's states, by uid, as the tables hold them (live entries and trashed files).
std::map<std::string, json> treeStates(const uint32_t vaultId) {
    return db::Transactions::exec("rl tree", [&](pqxx::work& txn) {
        std::map<std::string, json> out;
        for (const auto row : txn.exec("SELECT s::text FROM (SELECT vh_mirror_entry_state(id) AS s FROM fs_entry "
                                       "WHERE vault_id = $1) x WHERE s IS NOT NULL",
                                       pqxx::params{vaultId})) {
            const auto s = json::parse(row[0].as<std::string>());
            out[s["uid"].get<std::string>()] = s;
        }
        for (const auto row : txn.exec(
                 "SELECT vh_mirror_trash_state(t.object_uid, t.size_bytes, t.path, t.trashed_at, t.trashed_by)::text "
                 "FROM files_trashed t WHERE t.vault_id = $1 AND t.deleted_at IS NULL AND t.object_uid IS NOT NULL "
                 "  AND NOT EXISTS (SELECT 1 FROM files f JOIN fs_entry e ON e.id = f.fs_entry_id "
                 "                  WHERE f.object_uid = t.object_uid AND e.vault_id = t.vault_id)",
                 pqxx::params{vaultId})) {
            const auto s = json::parse(row[0].as<std::string>());
            out[s["uid"].get<std::string>()] = s;
        }
        return out;
    });
}

// Random operations through the product's write paths; after each step the running digest equals the recomputed one,
// and at the end replaying the log's rows onto an empty model gives the tree, state for state.
TEST_F(MirrorReplicationLogDbTest, TheDigestHoldsAndReplayingTheLogReproducesTheTree) {
    const auto engine = localVault();
    mirror(engine);   // an empty vault: the log alone has to carry everything
    const auto seed = static_cast<unsigned>(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    SCOPED_TRACE("seed " + std::to_string(seed));
    std::mt19937 rng(seed);
    const auto pick = [&](const std::vector<std::string>& v) { return v[rng() % v.size()]; };

    std::vector<std::string> dirs{"/"};
    std::vector<std::string> files;
    std::vector<std::string> trashed;
    const auto join = [](const std::string& dir, const std::string& name) {
        return (dir == "/" ? "" : dir) + "/" + name;
    };
    const auto under = [](const std::string& path, const std::string& dir) {
        return path == dir || path.starts_with(dir + "/");
    };

    for (int step = 0; step < 120; ++step) {
        const auto op = rng() % 9;
        const auto name = "n" + std::to_string(step);
        try {
            if (op == 0 || dirs.size() < 3) {
                const auto path = join(pick(dirs), name);
                engine->mkdir(path, superUser);
                dirs.push_back(path);
            } else if (op <= 2 || files.empty()) {
                const auto path = join(pick(dirs), name + ".txt");
                write(engine, path, std::string(rng() % 64, 'x'));
                files.push_back(path);
            } else if (op == 3) {
                write(engine, pick(files), "overwritten " + std::to_string(step));
            } else if (op == 4) {
                const auto from = pick(files);
                const auto to = join(pick(dirs), name + ".moved");
                engine->rename(from, to, superUser);
                std::ranges::replace(files, from, to);
            } else if (op == 5) {
                const auto from = pick(files);
                engine->remove(from, superUser->id);
                std::erase(files, from);
                trashed.push_back(from);
            } else if (op == 6 && !trashed.empty()) {
                const auto t = pick(trashed);
                std::erase(trashed, t);
                if (rng() % 2) {
                    db::query::fs::File::markTrashedFileDeleted(trashId(engine, t));
                } else {
                    // Restored by the applier's statements: no backing bytes, so the product's own paths leave it be.
                    restore(engine, t, "/" + name + ".restored");
                }
            } else if (op == 7) {
                const auto path = pick(files);
                db::Transactions::exec("rl attributes", [&](pqxx::work& txn) {
                    txn.exec("UPDATE fs_entry SET mode = $3, owner_uid = $4 WHERE vault_id = $1 AND path = $2",
                             pqxx::params{vid(engine), path, static_cast<int>(256 + rng() % 256),
                                          static_cast<int>(rng() % 5000)});
                });
            } else if (dirs.size() > 3) {
                // A folder and what is under it.
                auto dir = pick(dirs);
                if (dir == "/") continue;
                engine->remove(dir, superUser->id);
                std::erase_if(dirs, [&](const std::string& d) { return under(d, dir); });
                std::erase_if(files, [&](const std::string& f) { return under(f, dir); });
            }
        } catch (const std::exception& e) {
            ADD_FAILURE() << "step " << step << " op " << op << ": " << e.what();
        }
        if (step % 20 == 19) expectDigestHolds(engine);
    }
    expectDigestHolds(engine);

    // Replay: upserts, moves, trash and restores set an entry's state; deletes and purges remove it.
    Cursor cursor;
    std::map<std::string, json> model;
    std::map<std::string, vh::mirror::Hash> hashes;
    for (const auto& g : drain(engine, cursor))
        for (const auto& r : g.rows) {
            if (r.op == "vault" || r.op == "key") continue;
            ASSERT_TRUE(r.entry_uid);
            const auto known = hashes.find(*r.entry_uid);
            if (r.prev_hash) {
                ASSERT_NE(known, hashes.end()) << "a change to an entry the log never created: " << r.state.dump();
                EXPECT_EQ(known->second, *r.prev_hash) << "prev_hash is the state the log last gave it";
            } else {
                EXPECT_EQ(known, hashes.end()) << "a creation of an entry the log already has";
            }
            if (r.entry_hash) {
                model[*r.entry_uid] = r.state;
                hashes[*r.entry_uid] = *r.entry_hash;
            } else {
                model.erase(*r.entry_uid);
                hashes.erase(*r.entry_uid);
            }
        }
    const auto tree = treeStates(vid(engine));
    EXPECT_EQ(model.size(), tree.size());
    for (const auto& [uid, state] : tree) {
        const auto it = model.find(uid);
        ASSERT_NE(it, model.end()) << "missing from the replay: " << state.dump();
        EXPECT_EQ(vh::mirror::entryHash(it->second), vh::mirror::entryHash(state)) << it->second.dump() << " vs "
                                                                                     << state.dump();
    }
    // Parents resolve inside the replayed tree (or to the vault root).
    // An entry directly under the root names the vault's uid as its parent (migration 164: each server's root folder
    // has a uid of its own; the vault's uid is the one both share).
    const auto rootUid = *mq::MirrorVaults::vaultUidOf(vid(engine));
    for (const auto& [uid, state] : model) {
        if (state.contains("parent")) {
            EXPECT_TRUE(state["parent"] == rootUid || model.contains(state["parent"].get<std::string>()))
                << state.dump();
        }
    }
}

// ---------------------------------------------------------------------------------------------------- retention

TEST_F(MirrorReplicationLogDbTest, RetentionNeverPassesTheAcknowledgedPositionNorAGroup) {
    const auto engine = localVault();
    mirror(engine);
    const auto root = entryId(engine, "/");
    for (int g = 0; g < 4; ++g)
        db::Transactions::exec("rl retention", [&](pqxx::work& txn) {
            for (int i = 0; i < 2; ++i) {
                const auto name = "p" + rlTag();
                const auto id = txn.exec("INSERT INTO fs_entry (vault_id, parent_id, name, path, created_by, "
                                         "  last_modified_by) VALUES ($1, $2, $3, $4, $5, $5) RETURNING id",
                                         pqxx::params{vid(engine), root, name, "/" + name, superUser->id})
                                    .one_field().as<uint32_t>();
                txn.exec("INSERT INTO directories (fs_entry_id, uid) VALUES ($1, gen_random_uuid())", pqxx::params{id});
            }
        });
    (void)mq::Log::sequence(vid(engine));
    ASSERT_EQ(countRows(vid(engine)), 8u);

    // Nothing acknowledged: nothing goes, however old.
    EXPECT_EQ(mq::Log::prune(std::chrono::seconds(0), 0).rows, 0u);
    EXPECT_FALSE(mq::MirrorVaults::acknowledge(vid(engine), {1, 99})) << "never past what was numbered";
    ASSERT_TRUE(mq::MirrorVaults::acknowledge(vid(engine), {1, 5}));
    EXPECT_FALSE(mq::MirrorVaults::acknowledge(vid(engine), {1, 3})) << "never backwards";

    // Acknowledged through the middle of the third group: retention stops at the end of the second.
    EXPECT_EQ(mq::Log::prune(std::chrono::seconds(0), 0).rows, 4u);
    const auto mv = mq::MirrorVaults::get(vid(engine));
    ASSERT_TRUE(mv);
    EXPECT_EQ(mv->pruned, (mq::Position{1, 4}));
    EXPECT_TRUE(mq::Log::groupsAfter(vid(engine), {1, 2}, 10).expired);
    const auto page = mq::Log::groupsAfter(vid(engine), {1, 4}, 10);
    EXPECT_FALSE(page.expired);
    EXPECT_EQ(page.groups.size(), 2u);

    // Young rows stay when the count allows them.
    ASSERT_TRUE(mq::MirrorVaults::acknowledge(vid(engine), {1, 8}));
    EXPECT_EQ(mq::Log::prune(std::chrono::hours(24), 1'000).rows, 0u);
    EXPECT_EQ(mq::Log::prune(std::chrono::hours(24), 2).rows, 2u) << "more than 2 rows behind the newest";

    // A vault no longer mirrored loses its rows and entry hashes to the sweep.
    db::Transactions::exec("rl end", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM mirror_vault WHERE vault_id = $1", pqxx::params{vid(engine)});
    });
    EXPECT_GT(mq::Log::prune(std::chrono::hours(24), 1'000).orphans, 0u);
    EXPECT_EQ(countRows(vid(engine)), 0u);
    EXPECT_EQ(mq::Digests::stored(vid(engine)).entries, 0);
}

}
