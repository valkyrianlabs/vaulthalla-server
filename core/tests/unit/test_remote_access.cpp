// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
//
// RemoteAccess* (design/cloud/managed-remotes.md, "Entitlement states and the access gate"): an S3 vault's remote
// access is full, read_only or none. read_only: the sync pass is skipped and says why, nothing is uploaded, deleted or
// published (also not by calling the engine or the controller directly), reads and hydrates work, local writes wait
// and go up once access is full again. none: no request at all, a remote-only file fails as remote_unavailable, a
// local copy still reads. The gate is held in memory (it survives an engine reload from its row), shows in the status
// and in health, makes a key rotation wait, and goes with the S3 binding at a detach.

#include "../helpers/bytes.hpp"
#include "../helpers/db_suite.hpp"
#include "../helpers/parity.hpp"
#include "../helpers/versioned_bucket.hpp"

#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/Event.hpp"
#include "db/query/vault/RemoteAccess.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "ops/Error.hpp"
#include "ops/VaultRemote.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "stats/model/SystemHealth.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include <vl/vaultfmt/ObjectKeys.hpp>
#include "storage/PlaintextReader.hpp"
#include "storage/RemoteAccess.hpp"
#include "sync/Cloud.hpp"
#include "sync/Controller.hpp"
#include "sync/model/Event.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/RemoteDetach.hpp"
#include "vault/model/S3Vault.hpp"

#include <filesystem>

namespace vh::test_remote_access {

namespace rac = storage::remote_access;
namespace rd = vault::remote::detach;
namespace vr = ops::vault_remote;
using test_support::versioned::CloudVault;
using test_support::versioned::Versioning;
using vh::test::bin::bytes;
using vh::test::bin::str;

class RemoteAccessTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<protocols::shell::Router> router;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_remote_access")) return;
        router = test::parity::shellRouter();
        protocols::shell::commands::vault::registerCommands(router);
    }
    static void TearDownTestSuite() {
        if (skipTests) return;
        rac::clear();
        tearDownDbSuite();
    }

    static CloudVault vault() {
        return test_support::versioned::makeCloudVault(superUser, "rac", Versioning::Enabled, true,
                                                       sync::model::RemotePolicy::Strategy::Cache);
    }

    static std::shared_ptr<storage::CloudEngine> engineOf(const CloudVault& v) {
        return std::dynamic_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(v.id()));
    }

    static std::shared_ptr<fs::model::File> write(const CloudVault& v, const std::string& path, const std::string& text) {
        const auto engine = engineOf(v);
        return fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                           .buffer = bytes(text), .engine = engine, .user = superUser,
                                           .overwrite = true});
    }

    static std::shared_ptr<fs::model::File> row(const CloudVault& v, const std::string& path) {
        return db::query::fs::File::getFileByPath(v.id(), path);
    }

    static std::string readLocal(const CloudVault& v, const std::string& path) {
        const auto reader = engineOf(v)->openPlaintextReader(row(v, path));
        return str(storage::readAll(*reader, 1 << 20));
    }

    static unsigned pass(const CloudVault& v) {
        return static_cast<unsigned>(test_support::versioned::runSyncPass(engineOf(v), {.purgeTrash = true}).plan.size());
    }

    struct PassRecord {
        std::string status, stall_reason;
    };
    // The daemon's own pass (sync::Cloud::operator()): the lease, the gate, the stages, the event it recorded (the
    // newest by id: runSyncPass's inline passes record events in the same second).
    static std::optional<PassRecord> daemonPass(const CloudVault& v) {
        auto task = std::make_shared<sync::Cloud>(engineOf(v));
        (*task)();
        return db::Transactions::exec("RemoteAccessTest::event", [&](pqxx::work& txn) -> std::optional<PassRecord> {
            const auto res = txn.exec("SELECT status, COALESCE(stall_reason, '') FROM sync_event WHERE vault_id = $1 "
                                      "ORDER BY id DESC LIMIT 1", pqxx::params{v.id()});
            if (res.empty()) return std::nullopt;
            return PassRecord{res[0][0].as<std::string>(), res[0][1].as<std::string>()};
        });
    }

    static void set(const CloudVault& v, const rac::Mode mode, const std::optional<std::string>& reason = std::nullopt) {
        (void)rac::set(v.id(), mode, reason, "system:test");
    }

    static std::string contentKey(const CloudVault& v, const std::string& path) {
        return vl::vaultfmt::keys::contentKey(*row(v, path)->object_uid);
    }

    static void dropLocalCopy(const CloudVault& v, const std::string& path) {
        std::error_code ec;
        ASSERT_TRUE(std::filesystem::remove(row(v, path)->backing_path, ec)) << path;
    }
};

// read_only: the pass is skipped before any request and says so; local writes wait and go up once access is full.
TEST_F(RemoteAccessTest, RemoteAccessReadOnlySkipsThePassAndUploadsWhatWaitedOnceFull) {
    auto v = vault();
    write(v, "/a.txt", "alpha");
    (void)pass(v);
    ASSERT_TRUE(v.bucket->current(contentKey(v, "/a.txt")));

    set(v, rac::Mode::ReadOnly, std::string("payment overdue"));
    EXPECT_EQ(rac::mode(v.id()), rac::Mode::ReadOnly);
    write(v, "/b.txt", "bravo, written while read-only");
    v.bucket->resetCounters();
    const auto skipped = daemonPass(v);
    ASSERT_TRUE(skipped);
    EXPECT_EQ(skipped->status, "stalled");
    EXPECT_EQ(skipped->stall_reason, "skipped: remote read-only (payment overdue)");
    const auto c = v.bucket->counters();
    EXPECT_EQ(c.list + c.head + c.get + c.put + c.copy + c.del, 0u) << "nothing reached the bucket";
    EXPECT_FALSE(v.bucket->current(contentKey(v, "/b.txt")));
    EXPECT_EQ(readLocal(v, "/b.txt"), "bravo, written while read-only") << "the local write is kept";

    set(v, rac::Mode::Full);
    (void)pass(v);
    ASSERT_TRUE(v.bucket->current(contentKey(v, "/b.txt"))) << "uploaded on return to full";
}

// Every write path refuses while read_only, before anything changes: upload, purge (the local copy stays), the
// manifest publish, the envelopes, and the controller itself as the last line. Reads still work.
TEST_F(RemoteAccessTest, RemoteAccessReadOnlyRefusesEveryWriteAndKeepsReads) {
    auto v = vault();
    write(v, "/a.txt", "alpha");
    write(v, "/b.txt", "bravo");
    (void)pass(v);
    set(v, rac::Mode::ReadOnly);
    const auto engine = engineOf(v);
    v.bucket->resetCounters();

    EXPECT_THROW(engine->upload(row(v, "/a.txt")), rac::Restricted);
    EXPECT_THROW(engine->purge(std::filesystem::path("/a.txt")), rac::Restricted);
    EXPECT_TRUE(row(v, "/a.txt")) << "a refused purge leaves the local file";
    EXPECT_THROW(engine->publishRemoteIndexManifest(), rac::Restricted);
    EXPECT_THROW((void)engine->ensureRecoveryEnvelopes(), rac::Restricted);
    try {
        engine->s3Controller()->deleteObject(contentKey(v, "/b.txt"));
        ADD_FAILURE() << "the controller let a DELETE through";
    } catch (const rac::Restricted& e) {
        EXPECT_EQ(e.code(), "remote_read_only");
    }
    EXPECT_EQ(v.bucket->counters().put + v.bucket->counters().del, 0u);
    EXPECT_TRUE(v.bucket->current(contentKey(v, "/b.txt")));

    // Reads: a listing and a hydrate of a file without a local copy.
    EXPECT_NO_THROW((void)engine->s3Controller()->listObjectKeysPage("", 10));
    dropLocalCopy(v, "/b.txt");
    EXPECT_EQ(readLocal(v, "/b.txt"), "bravo");
}

// none: no request at all; a remote-only file fails as remote_unavailable before any request, a local copy reads.
TEST_F(RemoteAccessTest, RemoteAccessNoneMakesNoRequestAndKeepsLocalCopies) {
    auto v = vault();
    write(v, "/a.txt", "alpha");
    write(v, "/b.txt", "bravo");
    (void)pass(v);
    dropLocalCopy(v, "/b.txt");
    set(v, rac::Mode::None, std::string("suspended"));
    v.bucket->resetCounters();

    EXPECT_EQ(readLocal(v, "/a.txt"), "alpha");
    try {
        (void)readLocal(v, "/b.txt");
        ADD_FAILURE() << "a remote-only file was served without remote access";
    } catch (const storage::ContentUnavailable& e) {
        EXPECT_NE(std::string(e.what()).find("remote_unavailable"), std::string::npos) << e.what();
    }
    EXPECT_THROW((void)engineOf(v)->s3Controller()->listObjectKeysPage("", 10), rac::Restricted);
    const auto skipped = daemonPass(v);
    ASSERT_TRUE(skipped);
    EXPECT_EQ(skipped->stall_reason, "skipped: remote unavailable (suspended)");
    const auto c = v.bucket->counters();
    EXPECT_EQ(c.list + c.head + c.get + c.put + c.copy + c.del, 0u);
}

// The gate is the database's: an engine reload (or a restart) reads it back; status and health show it; it never
// claims more than it is.
TEST_F(RemoteAccessTest, RemoteAccessIsKeptAcrossReloadsAndShownInStatusAndHealth) {
    auto v = vault();
    EXPECT_EQ(vr::status(superUser, v.id()).front().access->mode, rac::Mode::Full);
    EXPECT_FALSE(vr::status(superUser, v.id()).front().access->set_by) << "never set";
    set(v, rac::Mode::ReadOnly, std::string("over quota"));

    rac::clear();
    EXPECT_EQ(rac::mode(v.id()), rac::Mode::Full) << "memory only (cleared)";
    runtime::Deps::get().storageManager->reloadEngine(v.id());
    EXPECT_EQ(rac::mode(v.id()), rac::Mode::ReadOnly) << "a new engine reads the row";

    const auto status = vr::toJson(vr::status(superUser, v.id()).front());
    EXPECT_EQ(status.at("access").at("mode"), "read_only");
    EXPECT_EQ(status.at("access").at("reason"), "over quota");
    EXPECT_EQ(status.at("access").at("set_by"), "system:test");

    const auto health = stats::model::SystemHealth::snapshot();
    const auto listed = std::ranges::any_of(health.vaultsRemoteRestricted,
                                            [&](const auto& h) { return h.vaultId == v.id() && h.reason == "over quota"; });
    EXPECT_TRUE(listed);
    EXPECT_FALSE(health.healthy());

    set(v, rac::Mode::Full);
    const auto after = stats::model::SystemHealth::snapshot();
    EXPECT_FALSE(std::ranges::any_of(after.vaultsRemoteRestricted, [&](const auto& h) { return h.vaultId == v.id(); }));
}

// The operator's setter (`vh vault remote access`), its refusals, and a key rotation that waits.
TEST_F(RemoteAccessTest, RemoteAccessOperatorSetterAndRotationWaits) {
    auto v = vault();
    const auto id = std::to_string(v.id());
    const auto [setCode, setOut] = test::parity::cli(*router, "vault remote access " + id + " --set read-only --reason "
                                                     "maintenance", superUser);
    EXPECT_EQ(setCode, 0) << setOut;
    EXPECT_NE(setOut.find("read-only"), std::string::npos) << setOut;
    EXPECT_EQ(rac::state(v.id()).set_by, std::optional<std::string>("user:" + superUser->name()));
    EXPECT_NE(test::parity::cli(*router, "vault remote access " + id + " --set sideways", superUser).first, 0);
    EXPECT_NE(test::parity::cli(*router, "vault remote access " + id, superUser).first, 0);

    const auto before = engineOf(v)->encryptionManager->get_key_version();
    const auto [rotateCode, rotateOut] = test::parity::cli(*router, "vault keys rotate " + id, superUser);
    EXPECT_EQ(rotateCode, 0) << rotateOut;
    EXPECT_NE(rotateOut.find("waits"), std::string::npos) << rotateOut;
    EXPECT_EQ(engineOf(v)->encryptionManager->get_key_version(), before);

    EXPECT_EQ(test::parity::cli(*router, "vault remote access " + id + " --set full", superUser).first, 0);
    EXPECT_EQ(rac::mode(v.id()), rac::Mode::Full);

    const auto local = ops::vaults::create(superUser, {.name = "rac_local_" + vh::test::uniqueTag('r'),
                                                       .type = vault::model::VaultType::Local});
    EXPECT_THROW((void)vr::setAccess(superUser, {.vault_id = local->id, .mode = rac::Mode::ReadOnly, .reason = {}}),
                 ops::Conflict);
    EXPECT_THROW((void)rac::set(local->id, rac::Mode::ReadOnly, std::nullopt, "system:test"), std::invalid_argument);
}

// A read-only vault still detaches (reads are all a detach needs), and the gate goes with the S3 binding.
TEST_F(RemoteAccessTest, RemoteAccessReadOnlyVaultDetachesAndTheGateGoes) {
    auto v = vault();
    write(v, "/a.txt", "alpha");
    (void)pass(v);
    dropLocalCopy(v, "/a.txt");
    set(v, rac::Mode::ReadOnly);
    (void)vr::detach(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name});
    static sync::Controller leases;
    rd::RunDeps d;
    d.tryAcquirePass = [](const uint32_t id) { return leases.tryAcquirePass(id); };
    d.releasePass = [](const uint32_t id) { leases.releasePass(id); };
    d.swapEngine = [](const uint32_t id) { runtime::Deps::get().storageManager->reloadEngine(id); };
    const auto result = rd::run(v.id(), d);
    EXPECT_EQ(result.state, rd::State::Done) << result.error.value_or("");
    EXPECT_FALSE(db::query::vault::RemoteAccess::get(v.id()));
    EXPECT_EQ(rac::mode(v.id()), rac::Mode::Full);
    const auto engine = runtime::Deps::get().storageManager->getEngine(v.id());
    EXPECT_EQ(str(storage::readAll(*engine->openPlaintextReader(row(v, "/a.txt")), 1 << 20)), "alpha");
}

}
