// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
//
// RemoteDetach* (design/storage/attach-remote.md, "The reverse"): real local vaults are attached to a bucket (the
// VersionedBucket fake) and then detached again: every file is held and authenticated locally before the vault becomes
// local in one transaction, remote-only files are fetched, recovery envelopes come back from the bucket into the
// database and are never left behind, a crash after each named step resumes, a file that changes meanwhile is checked
// again, a local copy that doesn't authenticate keeps the vault an S3 vault, an abort changes nothing, and the bucket
// is never written to or deleted from.

#include "../helpers/bytes.hpp"
#include "../helpers/db_suite.hpp"
#include "../helpers/recovery_local.hpp"
#include "../helpers/versioned_bucket.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/seed.hpp>
#include "audit/Trail.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/RemoteDetach.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "ops/Error.hpp"
#include "ops/RecoveryRecipients.hpp"
#include "ops/VaultRemote.hpp"
#include "ops/Vaults.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Controller.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/RemoteAttach.hpp"
#include "vault/RemoteAttachService.hpp"
#include "vault/RemoteDetach.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <filesystem>
#include <fstream>
#include <map>

namespace vh::test_remote_detach {

namespace ra = vault::remote;
namespace rd = vault::remote::detach;
namespace vr = ops::vault_remote;
using test_support::versioned::VersionedBucket;
using test_support::versioned::Versioning;
using AttachQ = db::query::vault::RemoteAttach;
using DetachQ = db::query::vault::RemoteDetach;
using EnginePtr = std::shared_ptr<storage::Engine>;
using json = nlohmann::json;

using vh::test::bin::bytes;
using vh::test::bin::str;

struct Crash {
    std::string at;
};

class RemoteDetachTest : public vh::test::db::Suite {
protected:
    inline static std::map<std::string, std::shared_ptr<VersionedBucket>> buckets;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_remote_detach")) return;
        ra::setControllerFactoryForTesting(
            [](unsigned int, const std::string& bucket) -> std::shared_ptr<storage::s3::Controller> {
                const auto it = buckets.find(bucket);
                return it == buckets.end() ? nullptr : it->second;
            });
    }
    static void TearDownTestSuite() {
        if (skipTests) return;
        ra::setControllerFactoryForTesting({});
        buckets.clear();
        tearDownDbSuite();
    }

    struct Vault {
        unsigned int id{};
        std::string name;
        unsigned int keyId{};
        std::string bucketName;
        std::shared_ptr<VersionedBucket> bucket;
    };

    static sync::Controller& leases() {
        static sync::Controller controller;
        return controller;
    }

    static EnginePtr engineOf(const Vault& v) { return runtime::Deps::get().storageManager->getEngine(v.id); }

    static std::shared_ptr<fs::model::File> write(const Vault& v, const std::string& path, const std::string& text) {
        const auto engine = engineOf(v);
        return fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                           .buffer = bytes(text), .engine = engine, .user = superUser,
                                           .overwrite = true});
    }

    static std::shared_ptr<fs::model::File> row(const Vault& v, const std::string& path) {
        return db::query::fs::File::getFileByPath(v.id, path);
    }

    static std::filesystem::path backingOf(const Vault& v, const std::string& path) {
        const auto f = row(v, path);
        if (f->backing_path.is_absolute()) return f->backing_path;
        return engineOf(v)->paths->absPath(f->backing_path, fs::model::PathType::BACKING_ROOT);
    }

    static std::string readLocal(const Vault& v, const std::string& path) {
        const auto reader = engineOf(v)->openPlaintextReader(row(v, path));
        return str(storage::readAll(*reader, 64 << 20));
    }

    static std::string typeOf(const Vault& v) {
        return db::Transactions::exec("RemoteDetachTest::typeOf", [&](pqxx::work& txn) {
            return txn.exec("SELECT type FROM vault WHERE id = $1", pqxx::params{v.id}).one_field_ref().as<std::string>();
        });
    }

    static uint64_t count(const std::string& sql, const uint32_t id) {
        return db::Transactions::exec("RemoteDetachTest::count", [&](pqxx::work& txn) {
            return txn.exec(sql, pqxx::params{id}).one_field_ref().as<uint64_t>();
        });
    }

    static uint64_t auditEvents(const std::string& action, const uint32_t vaultId) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return count("SELECT COUNT(*) FROM audit_event WHERE action = '" + action + "' AND vault_id = $1", vaultId);
    }

    template <class Fn>
    static std::string code(Fn&& fn) {
        try {
            (void)fn();
            return "ok";
        } catch (const ops::Refused& e) {
            return e.code;
        } catch (const ops::Denied&) {
            return "denied";
        } catch (const ops::Conflict&) {
            return "conflict";
        } catch (const ops::Invalid&) {
            return "invalid";
        } catch (const ops::NotFound&) {
            return "not_found";
        }
    }

    // A local vault with its key exported (or a recovery recipient), attached to an empty versioned bucket: an
    // encrypting opaque_v1 S3 vault whose engine reads that bucket.
    static Vault attachedVault(const std::function<void(const Vault&)>& beforeAttach = {}, const bool exported = true) {
        const auto created = ops::vaults::create(superUser, {.name = "rd_" + vh::test::uniqueTag('d'),
                                                             .type = vault::model::VaultType::Local});
        Vault v;
        v.id = created->id;
        v.name = created->name;
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "rd_key_" + vh::test::uniqueTag('d'),
                                                          vault::model::S3Provider::AWS, "AKIATESTACCESSKEY000",
                                                          "secret-value-0000000000000000000000000", "us-east-1",
                                                          "https://s3.example.com");
        v.keyId = runtime::Deps::get().apiKeyManager->addAPIKey(key);
        v.bucketName = "rd-" + vh::test::uniqueTag('d');
        v.bucket = std::make_shared<VersionedBucket>(Versioning::Enabled, v.bucketName);
        v.bucket->md5Etags = true;
        buckets[v.bucketName] = v.bucket;
        if (exported)
            db::Transactions::exec("RemoteDetachTest::markExported", [&](pqxx::work& txn) {
                txn.exec("UPDATE vault_keys SET exported_version = version, exported_at = now() WHERE vault_id = $1",
                         pqxx::params{v.id});
            });
        if (beforeAttach) beforeAttach(v);
        (void)vr::attach(superUser, {.vault_id = v.id, .api_key_id = v.keyId, .bucket = v.bucketName,
                                     .storage_tier = std::nullopt, .accept_unpriced = true});
        ra::RunDeps d;
        d.tryAcquirePass = [](const uint32_t id) { return leases().tryAcquirePass(id); };
        d.releasePass = [](const uint32_t id) { leases().releasePass(id); };
        d.pricePreflight = [](const ra::PricePreflight&, ra::Estimate& e) { e.priced = false; };
        const auto bucket = v.bucket;
        d.swapEngine = [bucket](const uint32_t id) {
            auto& manager = *runtime::Deps::get().storageManager;
            manager.reloadEngine(id);
            const auto cloud = std::dynamic_pointer_cast<storage::CloudEngine>(manager.getEngine(id));
            if (!cloud) throw std::runtime_error("the reloaded engine is not a cloud engine");
            cloud->setS3ControllerForTesting(bucket);
            cloud->setRemoteFetchGate([](const storage::CloudEngine&, const storage::RemoteFetchRequest&) {
                return std::unique_ptr<storage::RemoteFetchReservation>{};
            });
        };
        d.firstPass = [](const uint32_t, std::time_t) -> std::optional<json> {
            return json{{"status", "not_run"}, {"started_at", nullptr}, {"finished_at", nullptr}, {"error", nullptr}};
        };
        const auto attached = ra::run(v.id, d);
        EXPECT_EQ(attached.state, ra::State::Done) << attached.error.value_or("");
        EXPECT_EQ(typeOf(v), "s3");
        return v;
    }

    static rd::RunDeps detachDeps() {
        rd::RunDeps d;
        d.tryAcquirePass = [](const uint32_t id) { return leases().tryAcquirePass(id); };
        d.releasePass = [](const uint32_t id) { leases().releasePass(id); };
        d.swapEngine = [](const uint32_t id) { runtime::Deps::get().storageManager->reloadEngine(id); };
        return d;
    }

    static vr::Status startDetach(const Vault& v) { return vr::detach(superUser, {.vault_id = v.id, .confirm = v.name}); }

    static rd::RunResult detach(const Vault& v) {
        (void)startDetach(v);
        return rd::run(v.id, detachDeps());
    }

    static rd::Row rowOf(const Vault& v) {
        const auto r = DetachQ::get(v.id);
        EXPECT_TRUE(r);
        return r.value_or(rd::Row{});
    }

    // Every version of every key: the bucket as it stands (a detach never changes it).
    static std::map<std::string, std::vector<std::string>> snapshot(const Vault& v) {
        std::map<std::string, std::vector<std::string>> out;
        for (const auto& k : v.bucket->keys())
            for (const auto& version : v.bucket->history(k)) out[k].push_back(version.version_id + "/" + version.etag);
        return out;
    }

    static void dropLocalCopy(const Vault& v, const std::string& path) {
        std::error_code ec;
        ASSERT_TRUE(std::filesystem::remove(backingOf(v, path), ec)) << path;
    }
};

// The acceptance scenario: an attached vault with a file that has no local copy becomes a local vault in place. Same id
// and uid, every file reads from this host, the remote-only one was fetched, the S3 side of the catalog is gone, the
// engine is a local one, and the bucket is exactly as it was.
TEST_F(RemoteDetachTest, RemoteDetachTurnsAnS3VaultIntoALocalVaultInPlace) {
    auto v = attachedVault([](const Vault& lv) {
        engineOf(lv)->mkdir("/docs", superUser);
        write(lv, "/docs/a.txt", "alpha");
        write(lv, "/docs/b.txt", std::string(200'000, 'b'));
        write(lv, "/c.txt", "charlie");
        write(lv, "/empty.txt", "");
    });
    const auto uid = *engineOf(v)->vault->uid;
    db::Transactions::exec("RemoteDetachTest::gateway", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO s3_gateway_bucket (vault_id, bucket_name, mode) VALUES ($1, $2, 'remote_cache') "
                 "ON CONFLICT (vault_id) DO UPDATE SET mode = 'remote_cache'",
                 pqxx::params{v.id, "gw-" + vh::test::uniqueTag('d')});
    });
    dropLocalCopy(v, "/docs/b.txt");   // a remote-only file: the bucket holds its only copy
    const auto before = snapshot(v);
    ASSERT_FALSE(before.empty());

    const auto started = startDetach(v);
    EXPECT_EQ(started.remote, "detaching:preparing");
    EXPECT_EQ(ops::vaults::get(superUser, v.id).remote, "detaching:preparing");
    EXPECT_EQ(typeOf(v), "s3");

    const auto result = rd::run(v.id, detachDeps());
    EXPECT_EQ(result.state, rd::State::Done) << result.error.value_or("");
    const auto done = rowOf(v);
    EXPECT_EQ(done.state, rd::State::Done) << done.last_error.value_or("");
    ASSERT_TRUE(done.estimate);
    const auto estimate = rd::estimateFromJson(*done.estimate);
    EXPECT_EQ(estimate.files, 3u) << "the empty file has no backing bytes";
    EXPECT_EQ(estimate.files_remote_only, 1u);

    // The same vault, now local, with every file read from this host.
    const auto vault = db::query::vault::Vault::getVault(v.id);
    ASSERT_TRUE(vault);
    EXPECT_EQ(vault->type, vault::model::VaultType::Local);
    EXPECT_EQ(*vault->uid, uid);
    EXPECT_FALSE(std::dynamic_pointer_cast<storage::CloudEngine>(engineOf(v))) << "the engine was swapped";
    EXPECT_EQ(readLocal(v, "/docs/a.txt"), "alpha");
    EXPECT_EQ(readLocal(v, "/docs/b.txt"), std::string(200'000, 'b'));
    EXPECT_EQ(readLocal(v, "/c.txt"), "charlie");
    EXPECT_EQ(readLocal(v, "/empty.txt"), "");
    EXPECT_TRUE(std::filesystem::exists(backingOf(v, "/docs/b.txt")));

    EXPECT_EQ(count("SELECT count(*) FROM s3 WHERE vault_id = $1", v.id), 0u);
    EXPECT_EQ(count("SELECT count(*) FROM rsync r JOIN sync s ON s.id = r.sync_id WHERE s.vault_id = $1", v.id), 0u);
    EXPECT_EQ(count("SELECT count(*) FROM fsync f JOIN sync s ON s.id = f.sync_id WHERE s.vault_id = $1", v.id), 1u);
    EXPECT_EQ(count("SELECT count(*) FROM remote_object_index WHERE vault_id = $1", v.id), 0u);
    EXPECT_EQ(count("SELECT count(*) FROM remote_manifest_root WHERE vault_id = $1", v.id), 0u);
    EXPECT_EQ(count("SELECT count(*) FROM sync_file_baseline WHERE vault_id = $1", v.id), 0u);
    EXPECT_EQ(count("SELECT count(*) FROM s3_gateway_bucket WHERE vault_id = $1 AND mode = 'local'", v.id), 1u);
    EXPECT_FALSE(AttachQ::get(v.id)) << "the attach that made it an S3 vault is over";
    EXPECT_EQ(ops::vaults::get(superUser, v.id).remote, "none");

    const auto status = vr::status(superUser, v.id).front();
    EXPECT_EQ(status.detach_items.files_fetched, 1u);
    EXPECT_EQ(status.detach_items.files_verified, 3u);
    EXPECT_EQ(snapshot(v), before) << "nothing was written to or deleted from the bucket";
    EXPECT_EQ(auditEvents("vault.remote.detach", v.id), 1u);
    EXPECT_EQ(auditEvents("vault.remote.detach.cutover", v.id), 1u);

    // A local vault again: a remote can be attached afresh (to another empty bucket).
    EXPECT_EQ(code([&] { return startDetach(v); }), "conflict") << "only an S3 vault detaches";
}

TEST_F(RemoteDetachTest, RemoteDetachEveryPreconditionRefusesWithNothingWritten) {
    auto v = attachedVault([](const Vault& lv) { write(lv, "/a.txt", "alpha"); });
    const auto refused = [&](const std::string& expected) {
        EXPECT_EQ(code([&] { return startDetach(v); }), expected);
        EXPECT_FALSE(DetachQ::get(v.id)) << expected << ": no detach was recorded";
        EXPECT_EQ(typeOf(v), "s3") << expected;
    };

    // The confirmation is the vault's name.
    EXPECT_EQ(code([&] { return vr::detach(superUser, {.vault_id = v.id, .confirm = "nope"}); }), "invalid");
    EXPECT_FALSE(DetachQ::get(v.id));

    // An open sync conflict would leave a version in the bucket undecided.
    db::Transactions::exec("RemoteDetachTest::conflict", [&](pqxx::work& txn) {
        const auto event = txn.exec("INSERT INTO sync_event (vault_id) VALUES ($1) RETURNING id", pqxx::params{v.id})
                               .one_field_ref().as<int64_t>();
        txn.exec("INSERT INTO sync_conflicts (event_id, file_id, conflict_type) VALUES ($1, $2, 'mismatch')",
                 pqxx::params{event, row(v, "/a.txt")->id});
    });
    refused("sync_conflicts_open");
    db::Transactions::exec("RemoteDetachTest::resolve", [&](pqxx::work& txn) {
        txn.exec("UPDATE sync_conflicts SET resolved_at = now(), resolution = 'kept_local' WHERE file_id = $1",
                 pqxx::params{row(v, "/a.txt")->id});
    });

    // Legacy content: the format conversion finishes first.
    write(v, "/old.txt", "legacy bytes");
    test_support::recovery_local::makeLegacyGcm(engineOf(v), "/old.txt", "legacy bytes");
    refused("legacy_content");
    fs::Filesystem::remove(engineOf(v)->vaultPathToFusePath("/old.txt"), superUser->id);

    // A local vault has no remote to detach.
    const auto local = ops::vaults::create(superUser, {.name = "rd_local_" + vh::test::uniqueTag('d'),
                                                       .type = vault::model::VaultType::Local});
    EXPECT_EQ(code([&] { return vr::detach(superUser, {.vault_id = local->id, .confirm = local->name}); }), "conflict");

    EXPECT_EQ(code([&] { return startDetach(v); }), "ok") << "and with every precondition met it starts";
}

// A crash after each named step leaves a state the next run continues from; the outcome is the same either way.
TEST_F(RemoteDetachTest, RemoteDetachResumesAfterACrashAtEveryStep) {
    for (const std::string step : {"prepared", "item:", "pass:", "hydrated", "checked", "cutover", "swapped"}) {
        SCOPED_TRACE(step);
        auto v = attachedVault([](const Vault& lv) {
            write(lv, "/one.txt", "one");
            write(lv, "/two.txt", std::string(70'000, '2'));
        });
        dropLocalCopy(v, "/two.txt");
        (void)startDetach(v);
        auto crashing = detachDeps();
        bool crashed = false;
        crashing.afterStep = [&](const std::string_view at) {
            if (!crashed && at.starts_with(step)) {
                crashed = true;
                throw Crash{std::string(at)};
            }
        };
        EXPECT_THROW((void)rd::run(v.id, crashing), Crash);
        ASSERT_TRUE(crashed);
        const bool cutOver = step == "cutover" || step == "swapped";
        EXPECT_EQ(typeOf(v), cutOver ? "local" : "s3");
        if (!cutOver) EXPECT_TRUE(rd::inProgress(v.id));

        const auto resumed = rd::run(v.id, detachDeps());
        EXPECT_EQ(resumed.state, rd::State::Done) << resumed.error.value_or("");
        EXPECT_EQ(typeOf(v), "local");
        EXPECT_FALSE(std::dynamic_pointer_cast<storage::CloudEngine>(engineOf(v)));
        EXPECT_EQ(readLocal(v, "/one.txt"), "one");
        EXPECT_EQ(readLocal(v, "/two.txt"), std::string(70'000, '2'));
    }
}

// Writes and deletes while the files are fetched and verified: what the cutover sees is what is held.
TEST_F(RemoteDetachTest, RemoteDetachWritesAndDeletesDuringTheDetachEndConsistent) {
    auto v = attachedVault([](const Vault& lv) {
        write(lv, "/a.txt", "alpha");
        write(lv, "/b.txt", "bravo");
        write(lv, "/c.txt", "charlie");
    });
    (void)startDetach(v);
    auto d = detachDeps();
    bool changed = false;
    d.afterStep = [&](const std::string_view at) {
        if (changed || !at.starts_with("item:")) return;
        changed = true;
        write(v, "/a.txt", "alpha, rewritten while the detach ran");
        fs::Filesystem::remove(engineOf(v)->vaultPathToFusePath("/b.txt"), superUser->id);
        write(v, "/d.txt", "delta, new meanwhile");
    };
    const auto result = rd::run(v.id, d);
    ASSERT_TRUE(changed);
    EXPECT_EQ(result.state, rd::State::Done) << result.error.value_or("");
    EXPECT_EQ(typeOf(v), "local");
    EXPECT_EQ(readLocal(v, "/a.txt"), "alpha, rewritten while the detach ran");
    EXPECT_FALSE(row(v, "/b.txt"));
    EXPECT_EQ(readLocal(v, "/c.txt"), "charlie");
    EXPECT_EQ(readLocal(v, "/d.txt"), "delta, new meanwhile");
    EXPECT_EQ(count("SELECT count(*) FROM vault_remote_detach_item WHERE vault_id = $1 AND kind = 'content'", v.id), 3u);
}

// A local copy that doesn't authenticate fails the detach before the cutover: the vault stays an S3 vault.
TEST_F(RemoteDetachTest, RemoteDetachRefusesALocalCopyThatDoesNotAuthenticate) {
    auto v = attachedVault([](const Vault& lv) { write(lv, "/a.txt", std::string(10'000, 'a')); });
    {
        std::fstream f(backingOf(v, "/a.txt"), std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(500);
        f.put('\x5a');
    }
    const auto result = detach(v);
    EXPECT_EQ(result.state, rd::State::Failed);
    EXPECT_NE(result.error.value_or("").find("authenticate"), std::string::npos) << result.error.value_or("");
    EXPECT_EQ(typeOf(v), "s3");
    EXPECT_TRUE(std::dynamic_pointer_cast<storage::CloudEngine>(engineOf(v)));
    EXPECT_EQ(count("SELECT count(*) FROM s3 WHERE vault_id = $1", v.id), 1u);
    EXPECT_EQ(vr::status(superUser, v.id).front().detach_items.files_failed, 1u);
    EXPECT_EQ(DetachQ::summary().failed.size(), 1u);
    EXPECT_EQ(auditEvents("vault.remote.detach.failed", v.id), 1u);

    // The local copy repaired (fetched again from the bucket): started again, the detach resumes and finishes.
    dropLocalCopy(v, "/a.txt");
    EXPECT_EQ(detach(v).state, rd::State::Done);
    EXPECT_EQ(readLocal(v, "/a.txt"), std::string(10'000, 'a'));
    EXPECT_TRUE(DetachQ::summary().failed.empty());
}

// Recovery envelopes: after the attach the bucket holds them and the database doesn't. The detach copies each one
// back, checked, before the vault becomes local, so the local vault's recovery material is what it was.
TEST_F(RemoteDetachTest, RemoteDetachBringsTheRecoveryEnvelopesBackIntoTheDatabase) {
    const auto seed = vl::keykit::RecoverySeed::generate();
    auto v = attachedVault(
        [&](const Vault& lv) {
            write(lv, "/a.txt", "alpha");
            (void)ops::recovery_recipients::add(
                superUser, {.vault_id = lv.id, .public_key = crypto::util::b64_encode(seed.x25519PublicKey()),
                            .label = std::string("Recovery kit")},
                ops::vault_keys::Channel::Cli);
        },
        false);
    const auto inBucket = AttachQ::envelopes(v.id);
    ASSERT_EQ(inBucket.size(), 1u);
    ASSERT_TRUE(inBucket[0].bytes.empty()) << "the attach moved it into the bucket";
    const auto object = v.bucket->current(vl::keykit::kev1::objectKey(inBucket[0].kid));
    ASSERT_TRUE(object);

    EXPECT_EQ(detach(v).state, rd::State::Done);
    const auto held = AttachQ::envelopes(v.id);
    ASSERT_EQ(held.size(), 1u);
    EXPECT_EQ(held[0].bytes, object->body) << "byte for byte the bucket's";
    EXPECT_TRUE(v.bucket->current(vl::keykit::kev1::objectKey(inBucket[0].kid))) << "and the bucket keeps its copy";
    EXPECT_EQ(vault::envelopes::material(v.id).state, std::string(vault::envelopes::kMaterialRecipient));
    EXPECT_EQ(vr::status(superUser, v.id).front().detach_items.envelopes_copied, 1u);
}

// An envelope the bucket doesn't hold can't be kept: the detach fails and the vault stays an S3 vault. And an envelope
// row that loses its database copy between the check and the cutover stops the cutover.
TEST_F(RemoteDetachTest, RemoteDetachNeverLeavesAnEnvelopeBehind) {
    const auto seed = vl::keykit::RecoverySeed::generate();
    const auto enroll = [&](const Vault& lv) {
        write(lv, "/a.txt", "alpha");
        (void)ops::recovery_recipients::add(
            superUser, {.vault_id = lv.id, .public_key = crypto::util::b64_encode(seed.x25519PublicKey()),
                        .label = std::string("Recovery kit")},
            ops::vault_keys::Channel::Cli);
    };

    auto missing = attachedVault(enroll, false);
    const auto kid = AttachQ::envelopes(missing.id).at(0).kid;
    const auto key = vl::keykit::kev1::objectKey(kid);
    const auto version = missing.bucket->history(key).at(0).version_id;
    ASSERT_TRUE(missing.bucket->purgeVersion(key, version));
    const auto failed = detach(missing);
    EXPECT_EQ(failed.state, rd::State::Failed);
    EXPECT_NE(failed.error.value_or("").find("not in the bucket"), std::string::npos) << failed.error.value_or("");
    EXPECT_EQ(typeOf(missing), "s3");
    EXPECT_EQ(count("SELECT count(*) FROM vault_key_envelope WHERE vault_id = $1 AND envelope IS NULL", missing.id), 1u);

    auto racing = attachedVault(enroll, false);
    (void)startDetach(racing);
    auto d = detachDeps();
    bool cleared = false;
    d.afterStep = [&](const std::string_view at) {
        if (at != "checked" || cleared) return;
        cleared = true;
        db::Transactions::exec("RemoteDetachTest::clear", [&](pqxx::work& txn) {
            txn.exec("UPDATE vault_key_envelope SET envelope = NULL WHERE vault_id = $1", pqxx::params{racing.id});
        });
    };
    const auto refused = rd::run(racing.id, d);
    ASSERT_TRUE(cleared);
    EXPECT_EQ(refused.state, rd::State::Failed);
    EXPECT_NE(refused.error.value_or("").find("recovery envelope"), std::string::npos) << refused.error.value_or("");
    EXPECT_EQ(typeOf(racing), "s3") << "the cutover refused: nothing changed";
    EXPECT_EQ(count("SELECT count(*) FROM s3 WHERE vault_id = $1", racing.id), 1u);
    EXPECT_EQ(detach(racing).state, rd::State::Done) << "started again, the envelope is copied and the vault cuts over";
    EXPECT_EQ(count("SELECT count(*) FROM vault_key_envelope WHERE vault_id = $1 AND envelope IS NULL", racing.id), 0u);
}

// An abort before the cutover changes nothing: the vault is still an S3 vault, the bucket untouched, and the envelope
// bytes the detach copied are cleared again (the bucket's copy reads back equal).
TEST_F(RemoteDetachTest, RemoteDetachAbortLeavesTheVaultAnS3Vault) {
    const auto seed = vl::keykit::RecoverySeed::generate();
    auto v = attachedVault(
        [&](const Vault& lv) {
            write(lv, "/a.txt", "alpha");
            write(lv, "/b.txt", "bravo");
            (void)ops::recovery_recipients::add(
                superUser, {.vault_id = lv.id, .public_key = crypto::util::b64_encode(seed.x25519PublicKey()),
                            .label = std::string("Recovery kit")},
                ops::vault_keys::Channel::Cli);
        },
        false);
    dropLocalCopy(v, "/b.txt");
    const auto before = snapshot(v);
    (void)startDetach(v);
    auto crashing = detachDeps();
    crashing.afterStep = [&](const std::string_view at) {
        if (at == "hydrated") throw Crash{std::string(at)};
    };
    EXPECT_THROW((void)rd::run(v.id, crashing), Crash);
    EXPECT_EQ(count("SELECT count(*) FROM vault_key_envelope WHERE vault_id = $1 AND envelope IS NOT NULL", v.id), 1u);

    EXPECT_EQ(code([&] { return vr::abort(superUser, {.vault_id = v.id, .confirm = "nope"}); }), "invalid");
    (void)vr::abort(superUser, {.vault_id = v.id, .confirm = v.name});
    EXPECT_TRUE(rowOf(v).abort_requested_at);
    EXPECT_EQ(rd::run(v.id, detachDeps()).state, rowOf(v).state) << "a run does nothing once an abort was asked for";

    // The service carries it out (other tests' unfinished detaches set aside: it runs every row).
    for (const auto& other : DetachQ::list())
        if (other.vault_id != v.id && rd::running(other.state) && rd::beforeCutover(other.state))
            DetachQ::setState(other.vault_id, rd::State::Failed, "left by another test");
    vault::RemoteAttachService service;
    service.runOnce();
    EXPECT_EQ(rowOf(v).state, rd::State::Aborted);
    EXPECT_EQ(typeOf(v), "s3");
    EXPECT_TRUE(std::dynamic_pointer_cast<storage::CloudEngine>(engineOf(v)));
    EXPECT_EQ(readLocal(v, "/b.txt"), "bravo") << "the fetched copy stays";
    EXPECT_EQ(count("SELECT count(*) FROM vault_key_envelope WHERE vault_id = $1 AND envelope IS NOT NULL", v.id), 0u)
        << "an S3 vault's envelopes live in its bucket again";
    EXPECT_EQ(snapshot(v), before);
    EXPECT_EQ(ops::vaults::get(superUser, v.id).remote, "attached");
    EXPECT_EQ(auditEvents("vault.remote.abort", v.id), 1u);
    EXPECT_EQ(code([&] { return vr::abort(superUser, {.vault_id = v.id, .confirm = v.name}); }), "conflict");

    // Started again after the abort, it runs from the start.
    EXPECT_EQ(detach(v).state, rd::State::Done);
    EXPECT_EQ(typeOf(v), "local");
}

// The pass lease: while a sync pass holds it, the detach waits at the cutover (verified, not failed).
TEST_F(RemoteDetachTest, RemoteDetachWaitsForARunningSyncPass) {
    auto v = attachedVault([](const Vault& lv) { write(lv, "/a.txt", "alpha"); });
    (void)startDetach(v);
    ASSERT_TRUE(leases().tryAcquirePass(v.id));
    const auto busy = rd::run(v.id, detachDeps());
    EXPECT_TRUE(busy.busy);
    EXPECT_EQ(busy.state, rd::State::Verifying);
    EXPECT_TRUE(rowOf(v).verified_at);
    EXPECT_EQ(typeOf(v), "s3");
    leases().releasePass(v.id);
    EXPECT_EQ(rd::run(v.id, detachDeps()).state, rd::State::Done);
    EXPECT_EQ(typeOf(v), "local");
}

// Local history whose bodies only the bucket holds is counted, and pending upstream backlog is skipped at the cutover.
TEST_F(RemoteDetachTest, RemoteDetachSettlesTheUpstreamBacklog) {
    auto v = attachedVault([](const Vault& lv) { write(lv, "/a.txt", "alpha"); });
    db::Transactions::exec("RemoteDetachTest::backlog", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO vault_recovery_policy (vault_id, mode) VALUES ($1, 'provider_versioning') "
                 "ON CONFLICT (vault_id) DO UPDATE SET mode = 'provider_versioning'",
                 pqxx::params{v.id});
    });
    EXPECT_EQ(detach(v).state, rd::State::Done);
    EXPECT_EQ(count("SELECT count(*) FROM vault_recovery_policy WHERE vault_id = $1 AND mode = 'local_snapshots'", v.id),
              1u) << "provider versioning has no provider any more; local snapshots keep working";
    EXPECT_EQ(count("SELECT count(*) FROM file_versions WHERE vault_id = $1 AND upstream_state = 'pending'", v.id), 0u);
}

}
