// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The mirror is read-only (server mirror phase 2, wave 4 piece A; design/peers/mirror.md "Strict mode", "As built: the
// gate"; mirror::access, migration 165). A vault this server holds as another server's copy changes through nothing but
// its core's log: the gate's state for every reason, its publication (writers, the link, the watcher's reconcile), every
// write surface refusing in its own terms while the same operation on an ordinary vault and on a core's mirrored vault
// still works, the database backstop (a direct write refused; the follower's and a pending change's flags, creating and
// removing a copy let through), the background jobs leaving a copy untouched, a seal through the mount refused with the
// copy kept unsaved. And the fixes carried into wave 4: FUSE setattr reaching the row (journal and replication log), a
// create that lost its race refused, and "missing" told apart from "no permission" without an existence oracle.

#include "../helpers/db_suite.hpp"
#include "../helpers/identities.hpp"

#include "crypto/ScratchFile.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/Entry.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/identities/helpers.hpp"
#include "db/query/mirror/Log.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Crypto.hpp"
#include "fs/Filesystem.hpp"
#include "fs/PlaintextSource.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fuse/WorkingCopies.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/start/Guard.hpp"
#include "ops/Error.hpp"
#include "ops/Fs.hpp"
#include "ops/Recovery.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/handler/Common.hpp"
#include "protocols/s3/Auth.hpp"
#include "protocols/s3/Error.hpp"
#include "protocols/s3/ObjectStore.hpp"
#include "protocols/ws/core/Refusal.hpp"
#include "rbac/Mirrored.hpp"
#include "rbac/permission/admin/VaultGlobals.hpp"
#include "rbac/permission/vault/Filesystem.hpp"
#include "rbac/role/Vault.hpp"
#include "rbac/role/vault/Global.hpp"
#include "recovery/Model.hpp"
#include "recovery/local/Versions.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/FormatConversionService.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <pqxx/pqxx>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <fcntl.h>
#include "crypto/id/ObjectUid.hpp"
#include "mirror/leave/Leave.hpp"

#include <vl/keykit/uid.hpp>

#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <vector>

namespace vh::test_mirror_gate_db {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
using FsAction = rbac::permission::vault::FilesystemAction;
namespace mq = vh::db::query::mirror;
namespace access = vh::mirror::access;
namespace dc = vh::device::crypto;
namespace stdfs = std::filesystem;

std::string mgTag() {
    static std::atomic<unsigned> n{0};
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000) + "g" +
           std::to_string(n.fetch_add(1));
}

class MirrorGateDbTest : public vh::test::db::Suite {
protected:
    inline static uint32_t peerId{};

    static void SetUpTestSuite() {
        if (!setUpDbSuite("mirror_gate")) return;
        const auto t = mgTag();
        const auto spki = dc::sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(t.data()), t.size()));
        peerId = db::query::peer::Peers::insert(
                     {.node_id = "node-core-" + t, .name = "core-" + t, .spki_sha256 = dc::toHex(spki)})
                     .id;
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        for (const auto& m : mq::MirrorVaults::list()) (void)mq::MirrorVaults::remove(m.vault_id);
        access::resetForTesting();
        tearDownDbSuite();
    }

    static void sql(const std::string& statement) {
        db::Transactions::exec("mg sql", [&](pqxx::work& txn) { txn.exec(statement); });
    }

    // A local vault with /doc.txt and the folder /dir (written before it is anything's mirror).
    static EnginePtr localVault(const std::string& prefix = "mg_") {
        const auto v = ops::vaults::create(superUser, {.name = prefix + mgTag(), .type = vault::model::VaultType::Local});
        const auto engine = runtime::Deps::get().storageManager->getEngine(v->id);
        EXPECT_EQ(fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/dir"), .engine = engine, .user = superUser}),
                  0);
        write(engine, "/doc.txt", "mirror gate");
        return engine;
    }

    static void write(const EnginePtr& engine, const std::string& path, const std::string& text,
                      const bool overwrite = true) {
        (void)fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                          .buffer = std::vector<uint8_t>(text.begin(), text.end()), .engine = engine,
                                          .user = superUser, .overwrite = overwrite});
    }

    static mq::Grant fullGrant() {
        const auto role = rbac::role::Vault::Full();
        return {.role_name = role.name, .files = role.fs.files.toMask(), .directories = role.fs.directories.toMask(),
                .sync = role.sync.toMask(), .roles = role.roles.toMask(), .granted_by_node = "node-core",
                .granted_at = 0};
    }

    // The vault becomes this server's mirror of the linked server's vault: granted Full (so RBAC lets this server's
    // super admin write, and only the gate refuses), the first copy finished, the link up.
    static uint32_t makeMirror(const EnginePtr& engine, const bool finished = true, const bool linkUp = true) {
        const auto id = engine->vault->id;
        (void)mq::MirrorVaults::startMirror(id, peerId);
        EXPECT_TRUE(mq::MirrorVaults::recordGrant(id, fullGrant()));
        if (finished) {
            sql("UPDATE mirror_vault SET copy_finished = TRUE WHERE vault_id = " + std::to_string(id));
            access::reload();
        }
        access::linkChanged(peerId, linkUp);
        return id;
    }

    static uint64_t count(const std::string& statement) {
        return db::Transactions::exec("mg count", [&](pqxx::work& txn) {
            return txn.exec(statement).one_field().as<uint64_t>();
        });
    }

    static uint32_t entryId(const uint32_t vaultId, const std::string& path) {
        return db::Transactions::exec("mg entry", [&](pqxx::work& txn) {
            const auto r = txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = $2", pqxx::params{vaultId, path});
            return r.empty() ? 0u : r[0][0].as<uint32_t>();
        });
    }

    template <class F>
    static void expectReadOnly(F&& f, const std::string_view reason, const std::string& what) {
        try {
            f();
            ADD_FAILURE() << what << ": not refused";
        } catch (const access::MirrorReadOnly& e) {
            EXPECT_EQ(e.code, "read_only") << what;
            EXPECT_EQ(e.reason, reason) << what;
            EXPECT_NE(std::string(e.what()).find(access::sentence(reason)), std::string::npos) << what;
        } catch (const std::exception& e) {
            ADD_FAILURE() << what << ": refused with something else: " << e.what();
        }
    }

    // A person on a custom admin role whose global vault policy for their own vaults is `base` (the rest none).
    static UserPtr selfPolicyAccount(const std::string& prefix, const rbac::role::vault::Base& base) {
        using Scope = rbac::role::vault::Global::Scope;
        const auto role = ops::roles::createAdminRole(superUser, ops::roles::CreateRole{.name = prefix + "_role_" + mgTag()},
                                                      "test");
        const auto created = ops::users::create(superUser, {.name = prefix + "_" + mgTag(), .role = role->name,
                                                            .password = std::string("Mirror-Gate-Pass-12345")});
        const auto id = created.user->id;
        const auto none = rbac::role::vault::Base::None();
        const auto globals = rbac::permission::admin::VaultGlobals::Custom(
            rbac::role::vault::Global::Custom(id, Scope::Self, base), rbac::role::vault::Global::Custom(id, Scope::Admin, none),
            rbac::role::vault::Global::Custom(id, Scope::User, none));
        db::Transactions::exec("mg policy", [&](pqxx::work& txn) { db::query::identities::upsertGlobalVRoles(txn, globals, id); });
        (void)identities::manager().reconcile();
        return identities::manager().user(id);
    }
};

// ---- the gate's state ------------------------------------------------------------------------------------------------

TEST_F(MirrorGateDbTest, EachFactGivesItsStateAndReason) {
    const auto ordinary = localVault();
    EXPECT_EQ(access::state(ordinary->vault->id), access::State::NotMirrored);
    EXPECT_EQ(access::reason(ordinary->vault->id), "");
    EXPECT_NO_THROW(access::requireWritable(ordinary->vault->id, "a test write"));

    const auto engine = localVault();
    const auto v = makeMirror(engine, /*finished=*/false, /*linkUp=*/true);
    EXPECT_EQ(access::state(v), access::State::ReadOnly);
    EXPECT_EQ(access::reason(v), access::kFirstCopy);

    sql("UPDATE mirror_vault SET copy_finished = TRUE WHERE vault_id = " + std::to_string(v));
    access::reload();
    EXPECT_EQ(access::state(v), access::State::Live) << "role mirror, first copy finished, live, link up";
    EXPECT_TRUE(access::acceptsLocalChanges()) << "piece B: a Live mirror takes a person's change as pending";
    EXPECT_EQ(access::reason(v), "");
    EXPECT_NO_THROW(access::requireWritable(v, "a test write")) << "live: let through to the pending path";

    access::linkChanged(peerId, false);
    EXPECT_EQ(access::state(v), access::State::ReadOnly);
    EXPECT_EQ(access::reason(v), access::kLinkDown);
    access::linkChanged(peerId, true);

    // Each writer of the facts republishes before it returns.
    ASSERT_TRUE(mq::MirrorVaults::setState(v, "paused"));
    EXPECT_EQ(access::reason(v), access::kPaused);
    ASSERT_TRUE(mq::MirrorVaults::stop(v, "diverged", "mirror_digest_mismatch"));
    EXPECT_EQ(access::reason(v), access::kDiverged);
    ASSERT_TRUE(mq::MirrorVaults::stop(v, "expired", "mirror_log_expired"));
    EXPECT_EQ(access::reason(v), access::kExpired);
    ASSERT_TRUE(mq::MirrorVaults::stop(v, "stopped", "mirror_key_missing"));
    EXPECT_EQ(access::reason(v), access::kStopped);
    const auto f = access::facts(v);
    ASSERT_TRUE(f);
    EXPECT_EQ(f->stop_reason.value_or(""), "mirror_key_missing");
    ASSERT_TRUE(mq::MirrorVaults::setState(v, "live"));
    EXPECT_EQ(access::state(v), access::State::Live);

    ASSERT_TRUE(mq::MirrorVaults::orphan(v));
    EXPECT_EQ(access::reason(v), access::kOrphaned) << "orphaned: read-only whatever the link says";
    expectReadOnly([&] { access::requireWritable(v, "a test write"); }, access::kOrphaned, "orphaned");

    ASSERT_TRUE(mq::MirrorVaults::remove(v));
    EXPECT_EQ(access::state(v), access::State::NotMirrored) << "the row gone: an ordinary vault again";
    EXPECT_NO_THROW(access::requireWritable(v, "a test write"));

    // A core's mirrored vault is not held here: writes are its own.
    const auto core = localVault("mg_core_");
    (void)mq::MirrorVaults::startCore(core->vault->id, peerId);
    EXPECT_EQ(access::state(core->vault->id), access::State::NotMirrored);
    ASSERT_TRUE(mq::MirrorVaults::remove(core->vault->id));
}

TEST_F(MirrorGateDbTest, AChangeMadeBehindTheDaemonsBackIsReconciled) {
    const auto v = makeMirror(localVault());
    ASSERT_EQ(access::state(v), access::State::Live);
    sql("UPDATE mirror_vault SET state = 'diverged' WHERE vault_id = " + std::to_string(v));   // psql by hand
    EXPECT_EQ(access::state(v), access::State::Live) << "memory, until the watcher's pass";
    EXPECT_TRUE(access::reconcile());
    EXPECT_EQ(access::reason(v), access::kDiverged);
    EXPECT_FALSE(access::reconcile()) << "nothing changed since";

    sql("DELETE FROM mirror_vault WHERE vault_id = " + std::to_string(v));
    EXPECT_TRUE(access::reconcile());
    EXPECT_EQ(access::state(v), access::State::NotMirrored);
    rbac::mirrored::reload();
}

// ---- every write surface ---------------------------------------------------------------------------------------------

TEST_F(MirrorGateDbTest, TheOperationLayerRefusesEveryWriteAndTheWsReplySaysWhy) {
    const auto engine = localVault();
    // Read-only: the link is down (a Live mirror takes these as pending changes: MirrorSubmitDbTest).
    const auto v = makeMirror(engine, /*finished=*/true, /*linkUp=*/false);
    const auto reason = access::kLinkDown;
    expectReadOnly([&] { ops::fs::mkdir(superUser, v, "/new"); }, reason, "fs.dir.create");
    expectReadOnly([&] { ops::fs::rename(superUser, v, "/doc.txt", "/renamed.txt"); }, reason, "fs.entry.rename");
    expectReadOnly([&] { ops::fs::move(superUser, v, "/doc.txt", "/dir/doc.txt"); }, reason, "fs.entry.move");
    expectReadOnly([&] { ops::fs::copy(superUser, v, "/doc.txt", "/copy.txt"); }, reason, "fs.entry.copy");
    expectReadOnly([&] { ops::fs::remove(superUser, v, "/doc.txt"); }, reason, "fs.entry.delete");
    expectReadOnly([&] { (void)ops::fs::authorizeUpload(superUser, v, "/up.txt"); }, reason, "fs.upload.start");
    expectReadOnly([&] { ops::fs::commitStaged(superUser, {.vault_id = v, .path = "/up.txt", .staged = "/doc.txt"}); },
                   reason, "fs.upload.finish");
    expectReadOnly([&] { ops::fs::setAttributes(superUser, v, "/doc.txt", {.mode = 0600}); }, reason, "setattr");
    EXPECT_TRUE(entryId(v, "/doc.txt") && !entryId(v, "/new") && !entryId(v, "/copy.txt")) << "nothing changed";

    // The ws answer: code read_only and the reason (protocols/ws/core/Refusal.hpp).
    try {
        ops::fs::mkdir(superUser, v, "/new");
    } catch (...) {
        const auto reply = protocols::ws::core::describeCurrentError();
        EXPECT_EQ(reply.data.value("code", ""), "read_only");
        EXPECT_EQ(reply.data.value("reason", ""), reason);
    }

    // Paused: the same refusal says so.
    ASSERT_TRUE(mq::MirrorVaults::setState(v, "paused"));
    expectReadOnly([&] { ops::fs::mkdir(superUser, v, "/new"); }, access::kPaused, "paused");
    ASSERT_TRUE(mq::MirrorVaults::setState(v, "live"));
    access::linkChanged(peerId, true);

    // The same operations on an ordinary vault and on a core's mirrored vault work.
    for (const bool asCore : {false, true}) {
        const auto other = localVault(asCore ? "mg_core_" : "mg_plain_");
        const auto o = other->vault->id;
        if (asCore) (void)mq::MirrorVaults::startCore(o, peerId);
        ops::fs::mkdir(superUser, o, "/new");
        ops::fs::copy(superUser, o, "/doc.txt", "/copy.txt");
        ops::fs::rename(superUser, o, "/copy.txt", "/copy2.txt");
        ops::fs::move(superUser, o, "/copy2.txt", "/new/copy2.txt");
        ops::fs::setAttributes(superUser, o, "/doc.txt", {.mode = 0640});
        ops::fs::remove(superUser, o, "/new/copy2.txt");
        EXPECT_TRUE(entryId(o, "/new") && !entryId(o, "/new/copy2.txt")) << (asCore ? "core" : "ordinary");
        if (asCore) {
            EXPECT_GT(count("SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(o)), 0u)
                << "a core's writes are logged";
            ASSERT_TRUE(mq::MirrorVaults::remove(o));
        }
    }
}

TEST_F(MirrorGateDbTest, TheFilesystemLayerUnderEverySurfaceRefusesToo) {
    const auto engine = localVault();
    const auto v = makeMirror(engine, /*finished=*/true, /*linkUp=*/false);   // read-only: the link is down
    EXPECT_THROW(write(engine, "/doc.txt", "replaced"), access::MirrorReadOnly) << "a file write (every upload lane)";
    EXPECT_THROW(write(engine, "/fresh.txt", "new", false), access::MirrorReadOnly);
    EXPECT_EQ(fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/x/y"), .engine = engine, .user = superUser}),
              -EROFS);
    EXPECT_EQ(fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/dir"), .engine = engine, .user = superUser}),
              0)
        << "nothing to create: not a write";
    EXPECT_EQ(fs::Filesystem::rename(engine->vaultPathToFusePath("/doc.txt"), engine->vaultPathToFusePath("/r.txt"),
                                     superUser, engine),
              -EROFS);
    EXPECT_EQ(fs::Filesystem::copy({.from = engine->vaultPathToFusePath("/doc.txt"),
                                    .to = engine->vaultPathToFusePath("/c.txt"), .userId = superUser->id,
                                    .engine = engine}),
              -EROFS);
    EXPECT_THROW(fs::Filesystem::remove(engine->vaultPathToFusePath("/doc.txt"), superUser->id), access::MirrorReadOnly);
    EXPECT_TRUE(entryId(v, "/doc.txt") && !entryId(v, "/r.txt") && !entryId(v, "/c.txt") && !entryId(v, "/x"));
}

TEST_F(MirrorGateDbTest, HttpLanesAnswer503WithRetryAfterAndTheReason) {
    const auto engine = localVault();
    const auto v = makeMirror(engine, /*finished=*/true, /*linkUp=*/false);   // read-only: the link is down
    // Every HTTP lane that writes (upload content, text save, the upload sessions, `vh fs put`) authorizes Write or
    // Overwrite through http::access before it stages a byte.
    EXPECT_THROW(protocols::http::access::requireUser(superUser, engine, "/up.txt", FsAction::Write), vh::ops::ReadOnly);
    EXPECT_THROW(protocols::http::access::requireUser(superUser, engine, "/doc.txt", FsAction::Overwrite),
                 vh::ops::ReadOnly);
    EXPECT_THROW((void)protocols::http::access::resolveUserPath(superUser, v, "/doc.txt",
                                                                protocols::http::access::Need::Overwrite),
                 vh::ops::ReadOnly);
    EXPECT_NO_THROW(protocols::http::access::requireUser(superUser, engine, "/doc.txt", FsAction::Read)) << "reads go on";

    protocols::http::request req{protocols::http::verb::put, "/upload/content", 11};
    const auto res = protocols::http::handler::errorFor(req, access::MirrorReadOnly(v, std::string(access::kLinkDown),
                                                                                    "an upload"));
    const auto& r = std::get<protocols::http::string_response>(res);
    EXPECT_EQ(r.result(), protocols::http::status::service_unavailable);
    EXPECT_EQ(std::string(r[protocols::http::field::retry_after]), "30");
    const auto body = json::parse(r.body());
    EXPECT_EQ(body.value("code", ""), "read_only");
    EXPECT_EQ(body.value("reason", ""), access::kLinkDown);

    const auto plain = localVault();
    EXPECT_NO_THROW(protocols::http::access::requireUser(superUser, plain, "/up.txt", FsAction::Write));
}

TEST_F(MirrorGateDbTest, TheS3GatewayAnswersServiceUnavailableEvenToASuperAdmin) {
    const auto engine = localVault();
    const auto v = makeMirror(engine, /*finished=*/true, /*linkUp=*/false);   // read-only: the link is down
    const protocols::s3::ResolvedBucket bucket{.bucket_name = "mg-bucket", .vault_id = v, .mode = "local",
                                               .api_exclusive = false, .engine = engine, .actor = superUser,
                                               .gateway_access = std::nullopt};
    const protocols::s3::ObjectStore store;
    using A = rbac::s3::policy::S3Action;
    for (const auto action : {A::PutObject, A::DeleteObject, A::CreateMultipartUpload, A::UploadPart,
                              A::CompleteMultipartUpload, A::CopyObjectDestination}) {
        try {
            store.requireS3Permission(bucket, protocols::s3::AuthContext{}, action, "doc.txt");
            ADD_FAILURE() << "a write through the gateway was not refused";
        } catch (const protocols::s3::S3Error& e) {
            EXPECT_EQ(e.code, "ServiceUnavailable");
            EXPECT_EQ(e.status, protocols::s3::http::status::service_unavailable);
        }
    }
    EXPECT_NO_THROW(store.requireS3Permission(bucket, protocols::s3::AuthContext{}, A::GetObject, "doc.txt"));
    EXPECT_NO_THROW(store.requireS3Permission(bucket, protocols::s3::AuthContext{}, A::ListObjects));

    const auto plain = localVault();
    const protocols::s3::ResolvedBucket ordinary{.bucket_name = "mg-plain", .vault_id = plain->vault->id, .mode = "local",
                                                 .api_exclusive = false, .engine = plain, .actor = superUser,
                                                 .gateway_access = std::nullopt};
    EXPECT_NO_THROW(store.requireS3Permission(ordinary, protocols::s3::AuthContext{}, A::PutObject, "doc.txt"));
}

TEST_F(MirrorGateDbTest, ACopysSettingsAndRemoteAreItsCoresWhateverTheState) {
    const auto engine = localVault();
    const auto v = makeMirror(engine);
    expectReadOnly([&] { (void)ops::vaults::update(superUser, {.id = v, .description = std::string("mine now")}); },
                   access::kCoreOwned, "vault.update");
    expectReadOnly([&] { (void)ops::recovery::update(superUser, v, {.mode = vh::recovery::Mode::LocalSnapshots}); },
                   access::kCoreOwned, "vault.recovery.update");

    const auto plain = localVault();
    EXPECT_NO_THROW((void)ops::vaults::update(superUser, {.id = plain->vault->id, .description = std::string("ok")}));
}

// ---- the database backstop (migration 165) ----------------------------------------------------------------------------

TEST_F(MirrorGateDbTest, TheBackstopRefusesADirectWriteAndLetsTheFollowerAndAPendingChangeThrough) {
    const auto engine = localVault();
    const auto v = makeMirror(engine);
    const auto vs = std::to_string(v);
    const auto doc = std::to_string(entryId(v, "/doc.txt"));
    const auto dir = std::to_string(entryId(v, "/dir"));

    const auto refused = [&](const std::string& statement) {
        try {
            sql(statement);
            ADD_FAILURE() << "not refused: " << statement;
        } catch (const std::exception& e) {
            EXPECT_NE(std::string(e.what()).find("mirror_read_only"), std::string::npos) << statement << ": " << e.what();
        }
    };
    refused("UPDATE fs_entry SET mode = 384 WHERE id = " + doc);
    refused("UPDATE fs_entry SET name = 'x.txt' WHERE id = " + doc);
    refused("UPDATE fs_entry SET updated_at = now() - interval '1 day' WHERE id = " + doc);
    refused("UPDATE files SET size_bytes = size_bytes + 1 WHERE fs_entry_id = " + doc);
    refused("DELETE FROM fs_entry WHERE id = " + doc);
    refused("INSERT INTO fs_entry (vault_id, parent_id, name, path, base32_alias) VALUES (" + vs + ", " + dir +
            ", 'n', '/dir/n', substr(md5(random()::text) || md5(random()::text), 1, 33))");
    refused("INSERT INTO files_trashed (vault_id, path, backing_path, base32_alias) VALUES (" + vs +
            ", '/t', '/b', substr(md5(random()::text) || md5(random()::text), 1, 33))");

    // Not replicated, never refused: a folder's modification time alone (the totals), an inode, a path rewrite.
    EXPECT_NO_THROW(sql("UPDATE fs_entry SET updated_at = now() WHERE id = " + dir));
    EXPECT_NO_THROW(sql("UPDATE directories SET size_bytes = size_bytes WHERE fs_entry_id = " + dir));
    EXPECT_NO_THROW(db::Transactions::exec("mg inode", [&](pqxx::work& txn) {
        txn.exec("SELECT set_config('vh.keep_mtime', 'on', true)");   // else migration 149 stamps the file's mtime
        txn.exec("UPDATE fs_entry SET inode = inode, path = path WHERE id = " + doc);
    }));
    refused("UPDATE fs_entry SET inode = inode WHERE id = " + doc + "  -- 149 stamps the mtime: a replicated change");

    // The follower (vh.mirror_apply) and a pending change (vh.mirror_local, piece B) pass.
    for (const bool local : {false, true}) {
        EXPECT_NO_THROW(db::Transactions::exec("mg flagged", [&](pqxx::work& txn) {
            if (local) mq::Log::markMirrorLocal(txn);
            else mq::Log::markMirrorApply(txn);
            txn.exec("UPDATE fs_entry SET mode = " + std::string(local ? "416" : "384") + " WHERE id = " + doc);
        }));
    }
    EXPECT_EQ(count("SELECT mode FROM fs_entry WHERE id = " + doc), 416u);

    // An orphaned copy is read-only too.
    ASSERT_TRUE(mq::MirrorVaults::orphan(v));
    refused("UPDATE fs_entry SET mode = 420 WHERE id = " + doc);

    // An ordinary vault: nothing refused.
    const auto plain = localVault();
    EXPECT_NO_THROW(sql("UPDATE fs_entry SET mode = 384 WHERE id = " + std::to_string(entryId(plain->vault->id, "/doc.txt"))));

    // Removing the copy as a whole (storage::Manager::removeVault, behind every removal of one) sets no flag.
    runtime::Deps::get().storageManager->removeVault(v);
    EXPECT_EQ(count("SELECT count(*) FROM fs_entry WHERE vault_id = " + vs), 0u);
    EXPECT_EQ(count("SELECT count(*) FROM mirror_vault WHERE vault_id = " + vs), 0u);
    rbac::mirrored::reload();
    access::reload();
}

// ---- background work ------------------------------------------------------------------------------------------------

TEST_F(MirrorGateDbTest, BackgroundJobsLeaveACopyUntouched) {
    const auto engine = localVault();
    const auto v = makeMirror(engine);

    // Format conversion: nothing visited.
    const auto pass = vault::conversion::convertVault(engine, {}, [] { return false; }, {});
    EXPECT_TRUE(pass.blocked.has_value());
    EXPECT_EQ(pass.files, 0u);

    // Local versioning: no capture on a copy, a capture on an ordinary vault.
    const auto plain = localVault();
    for (const auto& e : {engine, plain})
        sql("INSERT INTO vault_recovery_policy (vault_id, local_versioning) VALUES (" + std::to_string(e->vault->id) +
            ", TRUE) ON CONFLICT (vault_id) DO UPDATE SET local_versioning = TRUE");
    for (const auto& e : {engine, plain}) {
        recovery::local::invalidatePolicy(e->vault->id);
        const auto file = std::dynamic_pointer_cast<fs::model::File>(
            runtime::Deps::get().fsCache->getEntry(e->vaultPathToFusePath("/doc.txt")));
        ASSERT_TRUE(file);
        auto kept = recovery::local::versions::retain(*e, *file, recovery::local::Reason::Overwrite);
        EXPECT_EQ(kept.active(), e == plain) << (e == plain ? "an ordinary vault keeps a version" : "a copy keeps none");
        kept.abort();
    }
    const auto report = recovery::local::versions::maintain(std::time(nullptr), false);
    EXPECT_TRUE(report.errors.empty());

    // Key rotation and salvage: refused on the mirror's side even where a test lets a core rotate.
    vh::mirror::start::allowRotationOnMirroredForTesting(true);
    EXPECT_THROW(engine->encryptionManager->prepare_key_rotation(), vh::ops::Refused);
    vh::mirror::start::allowRotationOnMirroredForTesting(false);
    EXPECT_THROW(engine->encryptionManager->prepare_key_rotation(), vh::ops::Refused);
    (void)v;
}

// What strict mode cannot refuse, on piece A's branch: a copy written through an already-open handle is never sealed
// over the core's content. The seal is refused, the copy is kept unsaved (the bytes stay in this process; reopening
// shows them; the retry holds them while the vault is read-only), and no byte of the vault changes. Piece B seals it as
// pending instead.
TEST_F(MirrorGateDbTest, AWriteThroughAnOpenHandleIsNeverSealedOverTheCoresContent) {
    const auto engine = localVault();
    const auto v = makeMirror(engine);
    const auto dir = root / ("wc_" + mgTag());
    stdfs::create_directories(dir / "backing");
    auto file = std::make_shared<fs::model::File>();
    file->id = entryId(v, "/doc.txt");
    file->inode = 990000 + file->id;
    file->vault_id = static_cast<int32_t>(v);
    file->path = "/doc.txt";
    file->backing_path = dir / "backing" / "ALIAS";
    { std::ofstream(file->backing_path) << "core's bytes"; }
    unsigned seals = 0;
    fuse::WorkingCopies copies(dir / "working", fuse::WorkingCopyHooks{
        .materialize = [](const fs::model::File&, crypto::ScratchFile&) {},
        .seal = [&](const fs::PlaintextSource&, const stdfs::path&, const std::shared_ptr<fs::model::File>&) { ++seals; },
        .current = [&](uint64_t) { return file; },
        .commit = {}, .saved = {}, .lock = {}, .recover = {},
    });
    auto handle = copies.open(*file->inode, file, O_RDWR);
    const std::string text = "the person's change";
    ASSERT_EQ(copies.write(handle, text.data(), text.size(), 0, std::nullopt), static_cast<ssize_t>(text.size()));
    // Paused (any read-only state but the link down, where the seal is kept as pending: MirrorSubmitDbTest).
    ASSERT_TRUE(mq::MirrorVaults::setState(v, "paused"));
    EXPECT_THROW(copies.persist(handle), access::MirrorReadOnly) << "flush and fsync: EROFS";
    EXPECT_THROW(copies.release(handle), access::MirrorReadOnly);
    EXPECT_EQ(seals, 0u) << "nothing sealed";
    EXPECT_EQ(copies.unsavedCount(), 1u) << "kept unsaved, not dropped";
    EXPECT_EQ(copies.retryUnsaved(), 1u) << "the retry holds it while the vault is read-only";
    std::ifstream in(file->backing_path);
    EXPECT_EQ(std::string(std::istreambuf_iterator<char>(in), {}), "core's bytes") << "no byte of the vault changed";
    EXPECT_EQ(copies.shutdown(), 1u);
}

// ---- the carried fixes ----------------------------------------------------------------------------------------------

TEST_F(MirrorGateDbTest, ACreateThatLostItsRaceIsRefusedNotReportedAsStored) {
    const auto engine = localVault();
    try {
        write(engine, "/doc.txt", "someone else's", /*overwrite=*/false);
        ADD_FAILURE() << "createFile(overwrite=false) returned the existing file";
    } catch (const std::filesystem::filesystem_error& e) {
        EXPECT_EQ(e.code(), std::errc::file_exists);
    }
    const auto file = std::dynamic_pointer_cast<fs::model::File>(
        runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath("/doc.txt")));
    ASSERT_TRUE(file);
    EXPECT_EQ(file->size_bytes, std::string("mirror gate").size()) << "the existing file is untouched";
}

TEST_F(MirrorGateDbTest, ASetattrReachesTheRowTheJournalAndTheReplicationLog) {
    const auto engine = localVault("mg_core_");
    const auto v = engine->vault->id;
    (void)mq::MirrorVaults::startCore(v, peerId);
    const auto doc = entryId(v, "/doc.txt");
    const auto ds = std::to_string(doc);
    const auto mtimeBefore = count("SELECT floor(extract(epoch FROM updated_at) * 1000000)::bigint FROM fs_entry WHERE id = " + ds);
    const auto journalBefore = count("SELECT count(*) FROM fs_change_log WHERE vault_id = " + std::to_string(v));
    const auto logBefore = count("SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(v));

    // chmod: the mode, nothing else (the modification time stays).
    ops::fs::setAttributes(superUser, v, "/doc.txt", {.mode = 0600});
    EXPECT_EQ(count("SELECT mode FROM fs_entry WHERE id = " + ds), 0600u);
    EXPECT_EQ(count("SELECT floor(extract(epoch FROM updated_at) * 1000000)::bigint FROM fs_entry WHERE id = " + ds),
              mtimeBefore) << "a chmod never moves the modification time";
    EXPECT_GT(count("SELECT count(*) FROM fs_change_log WHERE vault_id = " + std::to_string(v)), journalBefore)
        << "the journal records the mode";
    EXPECT_GT(count("SELECT count(*) FROM vault_replication_log WHERE vault_id = " + std::to_string(v)), logBefore);

    // utimens: kept exactly as given, and the log's actor is the person.
    const int64_t when = 1700000000123456;
    ops::fs::setAttributes(superUser, v, "/doc.txt", {.mtime_us = when});
    EXPECT_EQ(count("SELECT floor(extract(epoch FROM updated_at) * 1000000)::bigint FROM fs_entry WHERE id = " + ds),
              static_cast<uint64_t>(when));
    EXPECT_EQ(count("SELECT actor_id FROM vault_replication_log WHERE vault_id = " + std::to_string(v) +
                    " ORDER BY id DESC LIMIT 1"),
              superUser->id);
    const auto cached = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath("/doc.txt"));
    ASSERT_TRUE(cached);
    EXPECT_EQ(cached->updated_at, when / 1000000) << "getattr answers the new time";

    // chown: a super admin only.
    const auto person = selfPolicyAccount("mg_writer", rbac::role::vault::Base::Full());
    const auto own = ops::vaults::create(superUser, {.name = "mg_own_" + mgTag(), .type = vault::model::VaultType::Local,
                                                     .owner_id = person->id});
    const auto ownEngine = runtime::Deps::get().storageManager->getEngine(own->id);
    write(ownEngine, "/a.txt", "a");
    EXPECT_NO_THROW(ops::fs::setAttributes(person, own->id, "/a.txt", {.mode = 0644}));
    EXPECT_THROW(ops::fs::setAttributes(person, own->id, "/a.txt", {.owner_uid = 4242}), vh::ops::Denied);
    EXPECT_NO_THROW(ops::fs::setAttributes(superUser, own->id, "/a.txt", {.owner_uid = 4242}));
    ASSERT_TRUE(mq::MirrorVaults::remove(v));
}

TEST_F(MirrorGateDbTest, MissingIsToldApartFromNoPermissionWithoutAnExistenceOracle) {
    const auto owner = selfPolicyAccount("mg_owner", rbac::role::vault::Base::Full());
    const auto stranger = selfPolicyAccount("mg_stranger", rbac::role::vault::Base::Full());
    const auto own = ops::vaults::create(superUser, {.name = "mg_own_" + mgTag(), .type = vault::model::VaultType::Local,
                                                     .owner_id = owner->id});
    const auto engine = runtime::Deps::get().storageManager->getEngine(own->id);
    write(engine, "/here.txt", "here");

    // The owner may list the folder: a missing entry is missing (before: denied, like a refusal).
    EXPECT_EQ(ops::fs::check(owner, own->id, "/gone.txt", FsAction::Delete), ops::fs::Access::Missing);
    EXPECT_EQ(ops::fs::check(owner, own->id, "/nowhere/gone.txt", FsAction::Overwrite), ops::fs::Access::Missing)
        << "judged at the nearest folder that exists";
    EXPECT_EQ(ops::fs::check(owner, own->id, "/here.txt", FsAction::Delete), ops::fs::Access::Allowed);
    EXPECT_THROW(ops::fs::remove(owner, own->id, "/gone.txt"), vh::ops::NotFound);

    // Someone with no access learns nothing: denied whether or not the entry exists.
    EXPECT_EQ(ops::fs::check(stranger, own->id, "/gone.txt", FsAction::Delete), ops::fs::Access::Denied);
    EXPECT_EQ(ops::fs::check(stranger, own->id, "/here.txt", FsAction::Delete), ops::fs::Access::Denied);
    EXPECT_THROW(ops::fs::remove(stranger, own->id, "/gone.txt"), vh::ops::Denied);
}

// Wave 5 (lead's review): while the vault's core deletes it (its retention window), the copy is read-only on every
// surface with the reason mirror_core_deleting (its sentence names what happens, when, and detach), reads go on, and
// once the core restores the vault the copy is the core's again.
TEST_F(MirrorGateDbTest, WhileTheCoreDeletesTheVaultEverySurfaceRefusesWithThatReason) {
    const auto engine = localVault("mg_deleting_");
    const auto v = makeMirror(engine);   // live, the link up
    ASSERT_EQ(access::state(v), access::State::Live);
    const auto core = *db::query::peer::Peers::byId(peerId);
    const auto uid = vl::keykit::toBase32(*engine->vault->uid);
    (void)vh::mirror::leave::deletingReceived(core, {{"vault_uid", uid}, {"deleting", true},
                                                     {"purge_after", static_cast<int64_t>(std::time(nullptr) + 3600)},
                                                     {"copy", "leave"}});
    const auto reason = access::kCoreDeleting;
    EXPECT_EQ(access::state(v), access::State::ReadOnly);
    EXPECT_EQ(access::reason(v), reason);
    // The operation layer (the ws commands) and its reply.
    expectReadOnly([&] { ops::fs::mkdir(superUser, v, "/new"); }, reason, "fs.dir.create");
    expectReadOnly([&] { ops::fs::remove(superUser, v, "/doc.txt"); }, reason, "fs.entry.delete");
    expectReadOnly([&] { (void)ops::fs::authorizeUpload(superUser, v, "/up.txt"); }, reason, "fs.upload.start");
    // The filesystem layer under every surface (the mount, uploads, vh fs put, shares).
    EXPECT_THROW(write(engine, "/doc.txt", "replaced"), access::MirrorReadOnly);
    EXPECT_EQ(fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/x/y"), .engine = engine, .user = superUser}),
              -EROFS);
    // The HTTP lanes, with the reason.
    try {
        protocols::http::access::requireUser(superUser, engine, "/up.txt", FsAction::Write);
        ADD_FAILURE() << "an HTTP write was let through";
    } catch (const vh::ops::ReadOnly& e) {
        EXPECT_EQ(e.reason, reason);
    }
    EXPECT_NO_THROW(protocols::http::access::requireUser(superUser, engine, "/doc.txt", FsAction::Read)) << "reads go on";
    // The S3 gateway.
    const protocols::s3::ResolvedBucket bucket{.bucket_name = "mg-deleting", .vault_id = v, .mode = "local",
                                               .api_exclusive = false, .engine = engine, .actor = superUser,
                                               .gateway_access = std::nullopt};
    try {
        protocols::s3::ObjectStore{}.requireS3Permission(bucket, protocols::s3::AuthContext{},
                                                         rbac::s3::policy::S3Action::PutObject, "doc.txt");
        ADD_FAILURE() << "an S3 write was let through";
    } catch (const protocols::s3::S3Error& e) {
        EXPECT_EQ(e.code, "ServiceUnavailable");
    }
    EXPECT_TRUE(entryId(v, "/doc.txt") && !entryId(v, "/new") && !entryId(v, "/x")) << "nothing changed";
    EXPECT_NE(access::sentence(reason).find("vh mirror detach"), std::string::npos);

    (void)vh::mirror::leave::deletingReceived(core, {{"vault_uid", uid}, {"deleting", false}});
    EXPECT_EQ(access::state(v), access::State::Live) << "restored on the core: the copy follows again";
}

}
