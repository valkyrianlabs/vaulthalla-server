// Versioned vault_master rewrap (#352, design/sealing/master-secrets.md §6, migration 121). The acceptance matrix:
// interrupted staging at every batch boundary and at every other crash point (between verify and switch included),
// writes during staging and during the window, an old/new master mismatch and a tampered staged wrap, TPM loss mid
// staging and mid window, live/retired/deleted vault keys, explicit rollback (staging and window), finalize (by hand
// and on expiry), and a restore on a new host from the database, the vault-key exports and the attestation records.
// Every crash point is followed by the same proof: every key row unwraps under the master it names and is its
// recorded key, every row names the current master, and no file body changed.

#include "audit/Trail.hpp"
#include "crypto/SecretBytes.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/query/fs/File.hpp"
#include "device/Peer.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Users.hpp"
#include "ops/VaultKeys.hpp"
#include "ops/MasterSecrets.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/types.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/vault/Keys.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "UsageManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/Master.hpp"
#include "vault/MasterRewrap.hpp"
#include "vault/Retention.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace vh::test_vault_master_rewrap {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
namespace rw = vault::master::rewrap;
namespace vm = vault::master;
using WsKeys = protocols::ws::handler::VaultKeys;

struct SimulatedCrash : std::runtime_error {
    SimulatedCrash() : std::runtime_error("simulated crash") {}
};

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "m" + std::to_string(n.fetch_add(1));
}

// One vault key row, as stored.
struct StoredRow {
    std::string table;
    unsigned int vault_id{}, version{}, master{};
    std::vector<uint8_t> encrypted_key, iv;
    std::optional<std::string> key_check;
    bool next{false}, prev{false};
};

class VaultMasterRewrapTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static std::filesystem::path root;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_vault_master_rewrap] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_master_rewrap_" + tag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        vm::resetForTesting();
        vault::attestation::resetForTesting();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        superUser = identities::manager().userByName("admin");

        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<protocols::shell::UsageManager>();
        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerSecretsCommands(router);
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        (void)runtime::Deps::releaseSessions();  // the sessions this suite cached (#397)
        rw::setCrashHookForTesting(nullptr);
        vm::resetForTesting();
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        rw::setCrashHookForTesting(nullptr);
        // Every test starts with no rotation in progress (a previous one may have left a window open).
        const auto st = rw::state();
        if (st.previous_version) (void)rw::finalize();
        else if (st.staging_version) (void)rw::rollback();
    }

    void TearDown() override { rw::setCrashHookForTesting(nullptr); }

    // ---- fixtures

    static EnginePtr newVault(const std::string& prefix = "mr") {
        const auto v = ops::vaults::create(superUser, {.name = prefix + "_" + tag(), .type = vault::model::VaultType::Local});
        return runtime::Deps::get().storageManager->getEngine(v->id);
    }

    static void write(const EnginePtr& engine, const std::string& path, const std::string& content) {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine, .user = superUser, .overwrite = true}));
    }

    static std::string readFile(const unsigned int vaultId, const std::string& path) {
        const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
        const auto file = db::query::fs::File::getFileByPath(vaultId, path);
        if (!engine || !file) return "<missing>";
        const auto reader = engine->openPlaintextReader(file, {.integrity = storage::IntegrityPolicy::Strict});
        const auto bytes = storage::readAll(*reader, 1 << 20);
        return {bytes.begin(), bytes.end()};
    }

    static std::vector<uint8_t> backingOf(const unsigned int vaultId, const std::string& path) {
        const auto file = db::query::fs::File::getFileByPath(vaultId, path);
        std::ifstream in(file->backing_path, std::ios::binary);
        return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
    }

    static bool hasEngine(const unsigned int vaultId) {
        for (const auto& e : runtime::Deps::get().storageManager->getEngines())
            if (e && e->vault && e->vault->id == vaultId) return true;
        return false;
    }

    static std::shared_ptr<protocols::ws::Session> device(const UserPtr& user) {
        auto peer = std::make_shared<vh::device::Peer>();
        peer->spkiHex = std::string(64, 'b');
        peer->address = "127.0.0.1";
        peer->deviceRowId = 1;
        return protocols::ws::Session::devicePrincipal(peer, user, {});
    }

    static std::vector<StoredRow> storedRows() {
        return db::Transactions::exec("rewrapTest::rows", [](pqxx::work& txn) {
            std::vector<StoredRow> out;
            for (const auto* t : {"vault_keys", "vault_keys_trashed", "vault_deletion_key"})
                for (const auto& r : txn.exec(std::string("SELECT vault_id, version, master_version, encrypted_key, iv, "
                                                          "key_check, encrypted_key_next IS NOT NULL, "
                                                          "encrypted_key_prev IS NOT NULL FROM ") +
                                              t + " ORDER BY vault_id, version")) {
                    StoredRow row;
                    row.table = t;
                    row.vault_id = r[0].as<unsigned int>();
                    row.version = r[1].as<unsigned int>();
                    row.master = r[2].as<unsigned int>();
                    row.encrypted_key = db::encoding::from_hex_bytea(r[3].as<std::string>());
                    row.iv = db::encoding::from_hex_bytea(r[4].as<std::string>());
                    if (!r[5].is_null()) row.key_check = r[5].as<std::string>();
                    row.next = r[6].as<bool>();
                    row.prev = r[7].as<bool>();
                    out.push_back(std::move(row));
                }
            return out;
        });
    }

    // The key bytes each row holds, by (table, vault, version), unwrapped under the master the row names.
    static std::map<std::tuple<std::string, unsigned, unsigned>, std::vector<uint8_t>> keyBytes() {
        std::map<std::tuple<std::string, unsigned, unsigned>, std::vector<uint8_t>> out;
        for (const auto& row : storedRows()) {
            const crypto::WipedKeyCopy raw(vm::unwrap(row.encrypted_key, row.iv, row.master));
            out[{row.table, row.vault_id, row.version}] = raw.bytes;
        }
        return out;
    }

    // The proof after every step: every row names the current master, unwraps under it, and is its recorded key;
    // and the keys are exactly the ones before (`expected`, when given).
    static void expectEveryKeyReadable(
        const std::optional<std::map<std::tuple<std::string, unsigned, unsigned>, std::vector<uint8_t>>>& expected = {},
        const std::string& where = "") {
        vm::resetForTesting();  // a crashed process unseals from scratch
        const auto current = rw::state().version;
        for (const auto& row : storedRows()) {
            const auto name = where + ": " + row.table + " vault " + std::to_string(row.vault_id) + " v" +
                              std::to_string(row.version);
            EXPECT_EQ(row.master, current) << name;
            try {
                const crypto::WipedKeyCopy raw(vm::unwrap(row.encrypted_key, row.iv, row.master));
                ASSERT_EQ(raw.bytes.size(), 32u) << name;
                if (row.key_check) {
                    EXPECT_EQ(vault::keyCheck(raw.bytes, row.vault_id, row.version), *row.key_check) << name;
                }
                if (expected) {
                    const auto it = expected->find({row.table, row.vault_id, row.version});
                    if (it != expected->end()) {
                        EXPECT_EQ(it->second, raw.bytes) << name << ": the key changed";
                    }
                }
            } catch (const std::exception& e) {
                ADD_FAILURE() << name << " does not unwrap: " << e.what();
            }
        }
    }

    // A fresh EncryptionManager (what a daemon restart builds) loads the vault's keys from the database.
    static std::vector<uint8_t> loadedKey(const unsigned int vaultId) {
        vm::resetForTesting();
        const vault::EncryptionManager em(vaultId);
        const auto [key, version] = em.currentKey();
        return {key->bytes().begin(), key->bytes().end()};
    }

    static std::vector<uint8_t> engineKey(const EnginePtr& engine) {
        const auto [key, version] = engine->encryptionManager->currentKey();
        return {key->bytes().begin(), key->bytes().end()};
    }

    static unsigned int countMaster(const unsigned int version) {
        unsigned int n = 0;
        for (const auto& row : storedRows()) n += row.master == version ? 1 : 0;
        return n;
    }

    static bool slotOnHost(const unsigned int version) {
        return crypto::secrets::KeyProvider(vm::slotName(version)).sealedExists();
    }

    // A crash hook that throws at the n-th time `point` is reached (1-based).
    static rw::CrashHook crashAt(const std::string& point, const int n = 1) {
        auto seen = std::make_shared<int>(0);
        return [point, n, seen](const std::string_view p) {
            if (p == point && ++*seen == n) throw SimulatedCrash();
        };
    }

    // A vault with files, a retired key version (a finished key rotation), and a deleted vault's retained keys.
    struct World {
        EnginePtr live, rotated;
        unsigned int deletedId{};
        std::vector<uint8_t> deletedKey;
        unsigned int retiredVersion{};
        std::vector<uint8_t> retiredKey;
        std::map<std::string, std::vector<uint8_t>> bodies;  // vault:path -> ciphertext on disk
    };

    static World world() {
        World w;
        w.live = newVault("mrlive");
        write(w.live, "/a.txt", "alpha");
        write(w.live, "/b.txt", "bravo bravo");
        w.rotated = newVault("mrrot");
        write(w.rotated, "/old.txt", "written under the first key");
        w.retiredVersion = w.rotated->encryptionManager->get_key_version();
        {
            const auto k = w.rotated->encryptionManager->historicalKeySnapshot(w.retiredVersion);
            w.retiredKey.assign(k->bytes().begin(), k->bytes().end());
        }
        w.rotated->encryptionManager->prepare_key_rotation();
        w.rotated->encryptionManager->finish_key_rotation();
        write(w.rotated, "/new.txt", "written under the second key");
        const auto doomed = newVault("mrdel");
        w.deletedId = doomed->vault->id;
        w.deletedKey = engineKey(doomed);
        (void)ops::vaults::remove(superUser, {.id = w.deletedId});
        for (const auto& [id, path] : std::vector<std::pair<unsigned, std::string>>{
                 {w.live->vault->id, "/a.txt"}, {w.live->vault->id, "/b.txt"}, {w.rotated->vault->id, "/new.txt"}})
            w.bodies[std::to_string(id) + ":" + path] = backingOf(id, path);
        return w;
    }

    static void expectWorldReads(const World& w, const std::string& where) {
        EXPECT_EQ(readFile(w.live->vault->id, "/a.txt"), "alpha") << where;
        EXPECT_EQ(readFile(w.live->vault->id, "/b.txt"), "bravo bravo") << where;
        EXPECT_EQ(readFile(w.rotated->vault->id, "/new.txt"), "written under the second key") << where;
        EXPECT_EQ(loadedKey(w.live->vault->id), engineKey(w.live)) << where;
        EXPECT_EQ(loadedKey(w.rotated->vault->id), engineKey(w.rotated)) << where;
        {
            vm::resetForTesting();
            const vault::EncryptionManager em(w.rotated->vault->id);
            const auto retired = em.historicalKeySnapshot(w.retiredVersion);
            EXPECT_TRUE(std::ranges::equal(retired->bytes(), w.retiredKey)) << where << ": retired key";
        }
        const auto retained = vault::retention::retainedKey(w.deletedId);
        EXPECT_TRUE(std::ranges::equal(retained.key->bytes(), w.deletedKey)) << where << ": deleted vault's key";
        // Never a file body: the ciphertext on disk is byte for byte what it was.
        for (const auto& [where2, body] : w.bodies) {
            const auto colon = where2.find(':');
            EXPECT_EQ(backingOf(static_cast<unsigned>(std::stoul(where2.substr(0, colon))), where2.substr(colon + 1)),
                      body)
                << where << ": " << where2 << " was rewritten";
        }
    }

    static UserPtr createUser(const std::string& prefix, const std::string& role) {
        const auto created = ops::users::create(superUser, {.name = prefix + "_" + tag(), .role = role,
                                                            .password = std::string("Master-Rewrap-Pass-123")});
        return identities::manager().user(created.user->id);
    }

    static protocols::shell::CommandResult cli(const std::string& line, const UserPtr& user) {
        return router->executeLine(line, user, nullptr);
    }

    static long long auditCount(const std::string& action, const std::string& outcome) {
        (void)audit::Trail::instance()->flushNow();
        return db::Transactions::exec("rewrapTest::audit", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = $1 AND outcome = $2",
                            pqxx::params{action, outcome})
                .one_field_ref()
                .as<long long>();
        });
    }
};

// ---- the migration and its guard ----------------------------------------------------------------------------------

TEST_F(VaultMasterRewrapTest, RowsStartOnVersionOneAndTheGuardRefusesAWrapUnderAnotherMaster) {
    const auto engine = newVault("mrguard");
    const auto id = engine->vault->id;
    const auto st = rw::state();
    for (const auto& row : storedRows())
        if (row.vault_id == id) {
            EXPECT_EQ(row.master, st.version);
        }

    // A row declaring a master other than the current one is refused: nothing would unwrap it after a window.
    EXPECT_ANY_THROW(db::Transactions::exec("rewrapTest::stale", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_keys SET master_version = $2 WHERE vault_id = $1", pqxx::params{id, st.version + 7});
    }));
    // A change of the wrapped bytes drops any staged or retained wrap of the old bytes.
    db::Transactions::exec("rewrapTest::stage", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_keys SET encrypted_key_next = encrypted_key, iv_next = iv, master_version_next = 99, "
                 "encrypted_key_prev = encrypted_key, iv_prev = iv, master_version_prev = 98 WHERE vault_id = $1",
                 pqxx::params{id});
        txn.exec("UPDATE vault_keys SET iv = iv WHERE vault_id = $1", pqxx::params{id});  // unchanged bytes: kept
    });
    auto mine = [&] {
        for (const auto& r : storedRows())
            if (r.table == "vault_keys" && r.vault_id == id) return r;
        return StoredRow{};
    };
    EXPECT_TRUE(mine().next);
    EXPECT_TRUE(mine().prev);
    const auto row = mine();
    db::Transactions::exec("rewrapTest::rewrite", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_keys SET encrypted_key = $2 WHERE vault_id = $1",
                 pqxx::params{id, db::encoding::to_hex_bytea(row.encrypted_key)});  // same value: still kept
        auto other = row.iv;
        other[0] ^= 1;
        txn.exec("UPDATE vault_keys SET iv = $2 WHERE vault_id = $1", pqxx::params{id, db::encoding::to_hex_bytea(other)});
        txn.exec("UPDATE vault_keys SET iv = $2 WHERE vault_id = $1", pqxx::params{id, db::encoding::to_hex_bytea(row.iv)});
    });
    EXPECT_FALSE(mine().next);
    EXPECT_FALSE(mine().prev);
    expectEveryKeyReadable({}, "after the guard checks");
}

// ---- rotate, finalize -------------------------------------------------------------------------------------------

TEST_F(VaultMasterRewrapTest, RotateRewrapsLiveRetiredAndDeletedKeysAndNeverTouchesAFile) {
    const auto w = world();
    const auto before = keyBytes();
    const auto from = rw::state().version;

    const auto r = rw::rotate({.window = std::chrono::hours(1), .batch = 2});
    EXPECT_EQ(r.from, from);
    EXPECT_EQ(r.to, rw::state().version);
    EXPECT_GT(r.to, from);
    EXPECT_EQ(r.rows, before.size());
    EXPECT_GE(r.batches, 3u);  // three tables, two rows per batch
    EXPECT_EQ(countMaster(r.to), before.size());
    for (const auto& row : storedRows()) {
        EXPECT_TRUE(row.prev) << row.table << " " << row.vault_id;  // retained for the window
        EXPECT_FALSE(row.next);
    }
    EXPECT_TRUE(slotOnHost(from));
    EXPECT_TRUE(slotOnHost(r.to));
    expectEveryKeyReadable(before, "after the switch");
    expectWorldReads(w, "after the switch");

    const auto st = rw::state();
    ASSERT_TRUE(st.previous_version);
    EXPECT_EQ(*st.previous_version, from);
    ASSERT_TRUE(st.window_until);

    // Rotating again inside the window is refused: one previous master at a time.
    try {
        (void)rw::rotate();
        ADD_FAILURE() << "a rotation inside the window must be refused";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "window_open");
    }

    const auto f = rw::finalize();
    EXPECT_TRUE(f.finalized);
    EXPECT_EQ(f.previous, from);
    EXPECT_EQ(f.deleted, std::vector<unsigned int>{from});
    EXPECT_FALSE(slotOnHost(from));
    for (const auto& row : storedRows()) EXPECT_FALSE(row.prev);
    expectEveryKeyReadable(before, "after finalize");
    expectWorldReads(w, "after finalize");
    // A second finalize has nothing to do.
    EXPECT_FALSE(rw::finalize().finalized);
}

TEST_F(VaultMasterRewrapTest, TheWindowEndsByItselfWhenItExpires) {
    const auto w = world();
    const auto before = keyBytes();
    const auto r = rw::rotate({.window = std::chrono::hours(2)});
    EXPECT_FALSE(rw::expireIfDue(std::chrono::system_clock::now()).finalized) << "not due yet";
    EXPECT_TRUE(rw::state().previous_version);
    const auto f = rw::expireIfDue(std::chrono::system_clock::now() + std::chrono::hours(3));
    EXPECT_TRUE(f.finalized);
    EXPECT_FALSE(rw::state().previous_version);
    EXPECT_FALSE(slotOnHost(r.from));
    expectEveryKeyReadable(before, "after expiry");
    expectWorldReads(w, "after expiry");
}

// ---- interrupted rotations -----------------------------------------------------------------------------------------

TEST_F(VaultMasterRewrapTest, AnInterruptedStagingResumesAtEveryBatchBoundary) {
    const auto w = world();
    for (int i = 0; i < 3; ++i) write(newVault("mrmany"), "/f.txt", "file " + std::to_string(i));
    const auto before = keyBytes();
    const auto from = rw::state().version;

    // Crash right after the record of the staging and right after sealing the new master.
    for (const auto* point : {"staging_recorded", "sealed"}) {
        rw::setCrashHookForTesting(crashAt(point));
        EXPECT_THROW((void)rw::rotate({.batch = 1}), SimulatedCrash) << point;
        rw::setCrashHookForTesting(nullptr);
        EXPECT_EQ(rw::state().version, from) << point;
        ASSERT_TRUE(rw::state().staging_version) << point;
        expectEveryKeyReadable(before, point);
    }

    // Then after every single batch (one row per batch), each run resuming where the last one stopped.
    const auto target = *rw::state().staging_version;
    unsigned int crashes = 0, lastStaged = 0;
    for (;;) {
        rw::setCrashHookForTesting(crashAt("batch"));
        try {
            (void)rw::rotate({.batch = 1});
            ADD_FAILURE() << "every batch is a crash point";
            break;
        } catch (const SimulatedCrash&) {
        }
        rw::setCrashHookForTesting(nullptr);
        ++crashes;
        const auto s = rw::status();
        EXPECT_EQ(s.state.version, from);
        EXPECT_EQ(s.state.staging_version, target) << "a resumed staging keeps its master";
        EXPECT_EQ(s.staged, lastStaged + 1) << "each batch commits exactly its row";
        lastStaged = s.staged;
        expectEveryKeyReadable(before, "after batch " + std::to_string(crashes));
        if (s.staged == s.rows) break;
        ASSERT_LT(crashes, 1000u);
    }
    EXPECT_EQ(crashes, before.size());

    // Between verify and switch.
    rw::setCrashHookForTesting(crashAt("verified"));
    EXPECT_THROW((void)rw::rotate({.batch = 1}), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    EXPECT_EQ(rw::state().version, from);
    expectEveryKeyReadable(before, "between verify and switch");
    expectWorldReads(w, "between verify and switch");

    // Right after the switch committed: consistent on the new side.
    rw::setCrashHookForTesting(crashAt("switched"));
    EXPECT_THROW((void)rw::rotate({.batch = 1}), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto st = rw::state();
    EXPECT_EQ(st.version, target);
    EXPECT_EQ(st.previous_version, from);
    EXPECT_FALSE(st.staging_version);
    expectEveryKeyReadable(before, "after the switch");
    expectWorldReads(w, "after the switch");

    // An interrupted finalize (committed, slot not yet deleted) is finished by the next one.
    rw::setCrashHookForTesting(crashAt("finalize_committed"));
    EXPECT_THROW((void)rw::finalize(), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    EXPECT_FALSE(rw::state().previous_version);
    EXPECT_EQ(rw::state().discard_versions, std::vector<unsigned int>{from});
    EXPECT_TRUE(slotOnHost(from));
    expectEveryKeyReadable(before, "after an interrupted finalize");
    const auto f = rw::finalize();
    EXPECT_EQ(f.deleted, std::vector<unsigned int>{from});
    EXPECT_FALSE(slotOnHost(from));
    EXPECT_TRUE(rw::state().discard_versions.empty());
    expectWorldReads(w, "after finalize");
}

TEST_F(VaultMasterRewrapTest, WritesDuringStagingAreCaughtUpAtTheSwitch) {
    const auto w = world();
    const auto before = keyBytes();
    const auto from = rw::state().version;

    // Between the verification and the switch: a vault key rotation (its current row changes, a retired row
    // appears) and a new vault, all wrapped under the current master.
    EnginePtr fresh;
    auto once = std::make_shared<bool>(false);
    rw::setCrashHookForTesting([&, once](const std::string_view point) {
        if (point != "verified" || *once) return;
        *once = true;
        w.live->encryptionManager->prepare_key_rotation();
        w.live->encryptionManager->finish_key_rotation();
        fresh = newVault("mrfresh");
        for (const auto& row : storedRows())
            EXPECT_EQ(row.master, from) << "rows written during staging use the current master";
    });
    const auto r = rw::rotate();
    rw::setCrashHookForTesting(nullptr);
    ASSERT_TRUE(fresh);
    EXPECT_GE(r.caught_up, 3u);  // live's current row, its new retired row, the new vault's row
    expectEveryKeyReadable(before, "after a switch with catch-up");
    write(fresh, "/x.txt", "created during staging");
    EXPECT_EQ(readFile(fresh->vault->id, "/x.txt"), "created during staging");
    EXPECT_EQ(loadedKey(fresh->vault->id), engineKey(fresh));
    EXPECT_EQ(loadedKey(w.live->vault->id), engineKey(w.live));
    write(w.live, "/after.txt", "under the vault's new key");  // (the rotation's sync pass isn't run here)
    EXPECT_EQ(readFile(w.live->vault->id, "/after.txt"), "under the vault's new key");
    (void)rw::finalize();
    expectEveryKeyReadable(before, "after finalize");
}

// ---- mismatches --------------------------------------------------------------------------------------------------

TEST_F(VaultMasterRewrapTest, AStagedWrapThatIsNotTheRowsKeyAbortsBeforeTheSwitch) {
    const auto w = world();
    const auto before = keyBytes();
    rw::setCrashHookForTesting(crashAt("verified"));
    EXPECT_THROW((void)rw::rotate(), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto from = rw::state().version;
    const auto target = *rw::state().staging_version;

    // One staged wrap authenticates under the new master but holds another key.
    std::vector<uint8_t> other(32);
    randombytes_buf(other.data(), other.size());
    std::vector<uint8_t> iv;
    const auto forged = crypto::util::encrypt_aes256_gcm(other, vm::provider(target)->getMasterKey(), iv);
    db::Transactions::exec("rewrapTest::forge", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault_keys SET encrypted_key_next = $2, iv_next = $3 WHERE vault_id = $1",
                 pqxx::params{w.live->vault->id, db::encoding::to_hex_bytea(forged), db::encoding::to_hex_bytea(iv)});
    });
    try {
        (void)rw::rotate();
        ADD_FAILURE() << "a staged wrap of another key must abort the rotation";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "mismatch") << e.what();
    }
    EXPECT_EQ(rw::state().version, from) << "nothing switched";
    expectEveryKeyReadable(before, "after a mismatch");
    expectWorldReads(w, "after a mismatch");

    // The bad wrap was dropped: the next run stages it again and switches.
    const auto r = rw::rotate();
    EXPECT_EQ(r.to, target);
    expectEveryKeyReadable(before, "after the retry");
    expectWorldReads(w, "after the retry");
}

TEST_F(VaultMasterRewrapTest, AStagedMasterReplacedByAnotherSecretNeverSwitches) {
    const auto w = world();
    const auto before = keyBytes();
    rw::setCrashHookForTesting(crashAt("verified"));
    EXPECT_THROW((void)rw::rotate(), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto from = rw::state().version;
    const auto target = *rw::state().staging_version;

    // The staged slot now holds a different secret than the one the rows were staged under (old/new mismatch).
    {
        crypto::secrets::KeyProvider slot(vm::slotName(target));
        slot.destroySealed();
        slot.init();
    }
    vm::resetForTesting();
    try {
        (void)rw::rotate();
        ADD_FAILURE() << "wraps under another master must abort the rotation";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "mismatch") << e.what();
    }
    EXPECT_EQ(rw::state().version, from);
    expectEveryKeyReadable(before, "after an old/new master mismatch");

    const auto r = rw::rotate();
    EXPECT_EQ(r.to, target);
    expectEveryKeyReadable(before, "after restaging");
    expectWorldReads(w, "after restaging");
}

TEST_F(VaultMasterRewrapTest, ARowThatDoesNotUnwrapRefusesBeforeAnythingIsSealed) {
    const auto engine = newVault("mrbad");
    const auto id = engine->vault->id;
    const auto st = rw::state();
    const auto original = [&] {
        for (const auto& r : storedRows())
            if (r.table == "vault_keys" && r.vault_id == id) return r.encrypted_key;
        return std::vector<uint8_t>{};
    }();
    std::vector<uint8_t> junk(original.size());
    randombytes_buf(junk.data(), junk.size());
    const auto setKey = [&](const std::vector<uint8_t>& bytes) {
        db::Transactions::exec("rewrapTest::setKey", [&](pqxx::work& txn) {
            txn.exec("UPDATE vault_keys SET encrypted_key = $2 WHERE vault_id = $1",
                     pqxx::params{id, db::encoding::to_hex_bytea(bytes)});
        });
    };
    setKey(junk);
    try {
        (void)rw::rotate();
        ADD_FAILURE() << "an unreadable row must refuse the rotation";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "unreadable_rows");
        EXPECT_NE(std::string(e.what()).find("vh vault keys import"), std::string::npos) << e.what();
    }
    const auto after = rw::state();
    EXPECT_EQ(after.version, st.version);
    EXPECT_FALSE(after.staging_version);
    EXPECT_EQ(after.highest_version, st.highest_version);
    EXPECT_FALSE(slotOnHost(st.highest_version + 1)) << "nothing was sealed";
    setKey(original);
    expectEveryKeyReadable({}, "restored");
}

// ---- TPM loss -----------------------------------------------------------------------------------------------------

TEST_F(VaultMasterRewrapTest, TpmLossMidStagingRestagesUnderAFreshMaster) {
    const auto w = world();
    const auto before = keyBytes();
    rw::setCrashHookForTesting(crashAt("batch", 2));
    EXPECT_THROW((void)rw::rotate({.batch = 1}), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto target = *rw::state().staging_version;
    EXPECT_GT(rw::status().staged, 0u);

    // The staged master's sealed state is gone. Nothing was switched to it, so it is simply replaced.
    crypto::secrets::KeyProvider(vm::slotName(target)).destroySealed();
    vm::resetForTesting();
    const auto r = rw::rotate();
    EXPECT_EQ(r.to, target);
    EXPECT_EQ(r.staged_now, before.size()) << "every row is staged again under the new secret";
    expectEveryKeyReadable(before, "after restaging");
    expectWorldReads(w, "after restaging");
}

TEST_F(VaultMasterRewrapTest, TpmLossMidWindowRollsBackFromTheRetainedWraps) {
    const auto w = world();
    const auto before = keyBytes();
    const auto r = rw::rotate();

    // The new master's sealed state is lost inside the window: the daemon refuses to invent one, and says how back.
    crypto::secrets::KeyProvider(vm::slotName(r.to)).destroySealed();
    vm::resetForTesting();
    try {
        const vault::EncryptionManager em(w.live->vault->id);
        ADD_FAILURE() << "a lost current master must not be regenerated";
    } catch (const crypto::secrets::MasterSecretLost& e) {
        EXPECT_NE(std::string(e.what()).find("vh secret master rollback"), std::string::npos) << e.what();
    }
    EXPECT_FALSE(slotOnHost(r.to)) << "nothing was sealed in its place";
    // Finalize refuses: it would delete the only master that still unwraps the rows.
    try {
        (void)rw::finalize();
        ADD_FAILURE() << "finalize without the current master must be refused";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "verification_failed");
    }
    EXPECT_TRUE(slotOnHost(r.from));

    const auto back = rw::rollback();
    EXPECT_EQ(back.kind, rw::RollbackResult::Kind::Reverted);
    EXPECT_EQ(back.to, r.from);
    EXPECT_EQ(back.rows, before.size());
    EXPECT_EQ(back.rewrapped, 0u);
    EXPECT_EQ(rw::state().version, r.from);
    expectEveryKeyReadable(before, "after the rollback");
    expectWorldReads(w, "after the rollback");
}

// ---- rollback -----------------------------------------------------------------------------------------------------

TEST_F(VaultMasterRewrapTest, RollbackInsideTheWindowRewrapsWhatChangedDuringIt) {
    const auto w = world();
    const auto r = rw::rotate();

    // During the window: a vault key rotation and a new vault (both wrapped under the new master, no retained wrap).
    w.rotated->encryptionManager->prepare_key_rotation();
    w.rotated->encryptionManager->finish_key_rotation();
    const auto fresh = newVault("mrwin");
    write(fresh, "/x.txt", "created inside the window");
    const auto before = keyBytes();

    rw::setCrashHookForTesting(crashAt("rollback_committed"));
    EXPECT_THROW((void)rw::rollback(), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto st = rw::state();
    EXPECT_EQ(st.version, r.from);
    EXPECT_FALSE(st.previous_version);
    EXPECT_EQ(st.discard_versions, std::vector<unsigned int>{r.to});
    expectEveryKeyReadable(before, "after an interrupted rollback");
    // The next finalize (or the retention loop) deletes the rolled-back master.
    EXPECT_EQ(rw::finalize().deleted, std::vector<unsigned int>{r.to});
    EXPECT_FALSE(slotOnHost(r.to));
    expectEveryKeyReadable(before, "after the rollback");
    EXPECT_EQ(readFile(fresh->vault->id, "/x.txt"), "created inside the window");
    EXPECT_EQ(loadedKey(fresh->vault->id), engineKey(fresh));
    EXPECT_EQ(readFile(w.live->vault->id, "/a.txt"), "alpha");
    EXPECT_EQ(loadedKey(w.rotated->vault->id), engineKey(w.rotated));

    // A later rotation never reuses the rolled-back version's number.
    const auto again = rw::rotate();
    EXPECT_GT(again.to, r.to);
    expectEveryKeyReadable(before, "after another rotation");
    (void)rw::finalize();
}

TEST_F(VaultMasterRewrapTest, RollbackWhileStagingAbandonsIt) {
    const auto w = world();
    const auto before = keyBytes();
    const auto from = rw::state().version;
    rw::setCrashHookForTesting(crashAt("batch"));
    EXPECT_THROW((void)rw::rotate({.batch = 1}), SimulatedCrash);
    rw::setCrashHookForTesting(nullptr);
    const auto target = *rw::state().staging_version;

    const auto r = rw::rollback();
    EXPECT_EQ(r.kind, rw::RollbackResult::Kind::AbandonedStaging);
    EXPECT_EQ(r.from, target);
    EXPECT_FALSE(rw::state().staging_version);
    EXPECT_EQ(rw::state().version, from);
    EXPECT_FALSE(slotOnHost(target));
    for (const auto& row : storedRows()) EXPECT_FALSE(row.next);
    expectEveryKeyReadable(before, "after abandoning");
    expectWorldReads(w, "after abandoning");
    try {
        (void)rw::rollback();
        ADD_FAILURE() << "nothing left to roll back";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "no_window");
    }
}

// ---- the CLI ------------------------------------------------------------------------------------------------------

TEST_F(VaultMasterRewrapTest, TheCliIsSuperAdminOnlyConfirmsAndAuditsEveryStep) {
    const auto w = world();
    const auto admin = createUser("mradm", "admin");
    const auto deniedBefore = auditCount("secrets.master.rotate", "denied");
    EXPECT_NE(cli("secret master status", admin).exit_code, 0);
    EXPECT_NE(cli("secret master rotate --yes", admin).exit_code, 0);
    EXPECT_GT(auditCount("secrets.master.rotate", "denied"), deniedBefore);

    const auto s = cli("secret master status --json", superUser);
    ASSERT_EQ(s.exit_code, 0) << s.stderr_text << s.stdout_text;
    const auto status = json::parse(s.stdout_text);
    EXPECT_EQ(status.at("phase"), "idle");
    EXPECT_EQ(status.at("rows").get<unsigned>(), storedRows().size());
    EXPECT_EQ(s.stdout_text.find("\"key\""), std::string::npos);

    // Without a terminal, rotate asks for --yes and changes nothing.
    const auto from = rw::state().version;
    const auto refused = cli("secret master rotate", superUser);
    EXPECT_NE(refused.exit_code, 0);
    ASSERT_TRUE(refused.confirmation);
    EXPECT_EQ(refused.confirmation->code, "vault_master_rotate");
    EXPECT_EQ(rw::state().version, from);

    // An agent never rotates it, even with --yes.
    {
        const protocols::shell::AgentCallScope agent;
        EXPECT_NE(cli("secret master rotate --yes", superUser).exit_code, 0);
    }
    EXPECT_EQ(rw::state().version, from);

    const auto okBefore = auditCount("secrets.master.rotate", "success");
    const auto rotated = cli("secret master rotate --yes --window-hours 24 --json", superUser);
    ASSERT_EQ(rotated.exit_code, 0) << rotated.stderr_text << rotated.stdout_text;
    EXPECT_EQ(json::parse(rotated.stdout_text).at("from").get<unsigned>(), from);
    EXPECT_EQ(auditCount("secrets.master.rotate", "success"), okBefore + 1);
    EXPECT_EQ(json::parse(cli("secret master status --json", superUser).stdout_text).at("phase"), "recovery_window");

    const auto rb = cli("secret master rollback --yes", superUser);
    ASSERT_EQ(rb.exit_code, 0) << rb.stderr_text << rb.stdout_text;
    EXPECT_EQ(rw::state().version, from);
    EXPECT_GE(auditCount("secrets.master.rollback", "success"), 1);
    const auto none = cli("secret master rollback --yes", superUser);
    EXPECT_NE(none.exit_code, 0);
    EXPECT_GE(auditCount("secrets.master.rollback", "failure"), 1);

    ASSERT_EQ(cli("secret master rotate --yes", superUser).exit_code, 0);
    const auto fin = cli("secret master finalize --yes", superUser);
    ASSERT_EQ(fin.exit_code, 0) << fin.stderr_text << fin.stdout_text;
    EXPECT_GE(auditCount("secrets.master.finalize", "success"), 1);
    expectEveryKeyReadable({}, "after the CLI round trip");
    expectWorldReads(w, "after the CLI round trip");
}

// ---- new host (last: it discards every sealed secret of this suite) ------------------------------------------------

TEST_F(VaultMasterRewrapTest, ZNewHostRestoreFromTheDatabaseTheKeyExportsAndTheAttestations) {
    const auto w = world();
    // The key exports Vaulthalla Desktop keeps (current and every needed historical version, with attestations).
    // Every vault with key rows in this database, live or deleted (earlier tests left some of each).
    std::map<unsigned, json> exports;
    std::set<unsigned> deleted;
    for (const auto& row : storedRows()) {
        if (row.table == "vault_deletion_key") deleted.insert(row.vault_id);
        if (!exports.contains(row.vault_id))
            exports[row.vault_id] = WsKeys::exportKeys({{"vault_id", row.vault_id}}, device(superUser));
    }
    const auto r = rw::rotate();  // the database now names version r.to, with a window open

    // A new host: the database comes along, every sealed secret (both vault masters, the attestation seed) does not.
    for (const auto& item : std::filesystem::directory_iterator(paths::getBackingPath()))
        if (item.path().filename().string().starts_with(".sealed_test_")) std::filesystem::remove_all(item.path());
    vm::resetForTesting();
    vault::attestation::resetForTesting();
    try {
        const vault::EncryptionManager em(w.live->vault->id);
        ADD_FAILURE() << "a lost master must never be regenerated over existing key rows";
    } catch (const crypto::secrets::MasterSecretLost&) {
    }
    EXPECT_FALSE(slotOnHost(r.to));
    try {
        (void)rw::rollback();
        ADD_FAILURE() << "the previous master is gone too";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "previous_unavailable");
    }

    // The engines of the old process go away; import restores each vault under a new installation master.
    for (const auto& [id, keys] : exports) {
        if (!deleted.contains(id)) runtime::Deps::get().storageManager->retireVault(id);
        const auto name = keys.at("vault_name").get<std::string>();
        const auto result = ops::vault_keys::importKeys(superUser, {.vault_id = id, .keys = &keys, .confirm_name = name},
                                                        ops::vault_keys::Channel::Cli);
        EXPECT_TRUE(result.written) << id << ": " << ops::vault_keys::toJson(result).dump();
        for (const auto& v : result.versions)
            EXPECT_EQ(v.outcome, ops::vault_keys::ImportOutcome::Restored) << id << " v" << v.version;
    }
    EXPECT_TRUE(slotOnHost(r.to)) << "the import sealed a new master for the current version";
    EXPECT_TRUE(hasEngine(w.live->vault->id));
    EXPECT_EQ(readFile(w.live->vault->id, "/a.txt"), "alpha");
    EXPECT_EQ(readFile(w.live->vault->id, "/b.txt"), "bravo bravo");
    EXPECT_EQ(readFile(w.rotated->vault->id, "/new.txt"), "written under the second key");
    EXPECT_TRUE(std::ranges::equal(vault::retention::retainedKey(w.deletedId).key->bytes(), w.deletedKey));
    expectEveryKeyReadable({}, "after the new-host restore");

    // The window from the old host closes: every row verifies under this host's master.
    const auto f = rw::finalize();
    EXPECT_TRUE(f.finalized);
    expectEveryKeyReadable({}, "after finalize on the new host");
}

}
