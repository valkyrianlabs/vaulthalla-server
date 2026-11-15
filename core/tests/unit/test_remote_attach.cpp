// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
//
// RemoteAttach* (design/storage/attach-remote.md): real local vaults attach a bucket (the VersionedBucket fake: S3
// versioning, conditional writes on or off, injected faults) and become encrypting opaque_v1 S3 vaults in place.
// Every precondition refuses with nothing written; a crash after each named step resumes; writes, renames and deletes
// during the upload and between the verification and the cutover end consistent after the first pass; a stray version
// is removed; verification failures keep the vault local; an abort deletes exactly the recorded versions; the cutover
// is one transaction; recovery envelopes a local vault holds are copied into the bucket; a rotation waits.

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
#include "db/query/sync/Manifest.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "ops/Error.hpp"
#include "ops/RecoveryRecipients.hpp"
#include "ops/VaultRemote.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/vault.hpp"
#include "../helpers/parity.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Manager.hpp"
#include "storage/ObjectKeys.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/upstream/Guard.hpp"
#include "sync/Controller.hpp"
#include "sync/manifest/Document.hpp"
#include "sync/manifest/Objects.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/RemoteAttach.hpp"
#include "vault/RemoteAttachService.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/S3Vault.hpp"

#include <fstream>
#include <map>
#include <set>

namespace vh::test_remote_attach {

namespace keys = storage::object_keys;
namespace ra = vault::remote;
namespace vr = ops::vault_remote;
using test_support::versioned::VersionedBucket;
using test_support::versioned::Versioning;
using Q = db::query::vault::RemoteAttach;
using EnginePtr = std::shared_ptr<storage::Engine>;
using json = nlohmann::json;

using vh::test::bin::bytes;
using vh::test::bin::str;

// A crash at a named step: not a std::exception, so run() lets it through like a dying process.
struct Crash {
    std::string at;
};

class RemoteAttachTest : public vh::test::db::Suite {
protected:
    inline static std::map<std::string, std::shared_ptr<VersionedBucket>> buckets;
    inline static std::shared_ptr<protocols::shell::Router> router;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_remote_attach")) return;
        router = test::parity::shellRouter();
        protocols::shell::commands::vault::registerCommands(router);
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
    void TearDown() override { storage::upstream::guard::clearForTesting(); }

    struct Vault {
        EnginePtr engine;
        unsigned int keyId{};
        std::string bucketName;
        std::shared_ptr<VersionedBucket> bucket;
        [[nodiscard]] uint32_t id() const { return engine->vault->id; }
    };

    static unsigned int apiKey(const vault::model::S3Provider provider = vault::model::S3Provider::AWS) {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "ra_key_" + vh::test::uniqueTag('a'), provider,
                                                          "AKIATESTACCESSKEY000",
                                                          "secret-value-0000000000000000000000000", "us-east-1",
                                                          "https://s3.example.com");
        return runtime::Deps::get().apiKeyManager->addAPIKey(key);
    }

    static std::shared_ptr<VersionedBucket> newBucket(const std::string& name, const Versioning mode) {
        auto bucket = std::make_shared<VersionedBucket>(mode, name);
        bucket->md5Etags = true;
        buckets[name] = bucket;
        return bucket;
    }

    static void markExported(const uint32_t id) {
        db::Transactions::exec("RemoteAttachTest::markExported", [&](pqxx::work& txn) {
            txn.exec("UPDATE vault_keys SET exported_version = version, exported_at = now() WHERE vault_id = $1",
                     pqxx::params{id});
        });
    }

    // A local vault with its key exported (the recovery material an attach requires), an API key and an empty bucket.
    static Vault localVault(const Versioning mode = Versioning::Enabled, const bool exported = true,
                            const vault::model::S3Provider provider = vault::model::S3Provider::AWS) {
        const auto created = ops::vaults::create(superUser, {.name = "ra_" + vh::test::uniqueTag('a'),
                                                             .type = vault::model::VaultType::Local});
        Vault v;
        v.engine = runtime::Deps::get().storageManager->getEngine(created->id);
        v.keyId = apiKey(provider);
        v.bucketName = "ra-" + vh::test::uniqueTag('a');
        v.bucket = newBucket(v.bucketName, mode);
        if (exported) markExported(created->id);
        return v;
    }

    static EnginePtr engineOf(const Vault& v) { return runtime::Deps::get().storageManager->getEngine(v.id()); }

    static std::shared_ptr<fs::model::File> write(const Vault& v, const std::string& path, const std::string& text) {
        const auto engine = engineOf(v);
        return fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                           .buffer = bytes(text), .engine = engine, .user = superUser,
                                           .overwrite = true});
    }

    static void remove(const Vault& v, const std::string& path) {
        fs::Filesystem::remove(engineOf(v)->vaultPathToFusePath(path), superUser->id);
    }

    static std::shared_ptr<fs::model::File> row(const Vault& v, const std::string& path) {
        return db::query::fs::File::getFileByPath(v.id(), path);
    }

    static std::string readLocal(const Vault& v, const std::string& path) {
        const auto reader = engineOf(v)->openPlaintextReader(row(v, path));
        return str(storage::readAll(*reader, 64 << 20));
    }

    static std::string keyOf(const Vault& v, const std::string& path) { return keys::contentKey(*row(v, path)->object_uid); }

    static sync::Controller& leases() {
        static sync::Controller controller;
        return controller;
    }

    static std::shared_ptr<storage::CloudEngine> cloudOf(const Vault& v) {
        return std::dynamic_pointer_cast<storage::CloudEngine>(engineOf(v));
    }

    static unsigned transfers(const std::vector<sync::model::Action>& plan) {
        unsigned n = 0;
        for (const auto& a : plan)
            if (a.type == sync::model::ActionType::Upload || a.type == sync::model::ActionType::Download ||
                a.type == sync::model::ActionType::DeleteRemote || a.type == sync::model::ActionType::DeleteLocal)
                ++n;
        return n;
    }

    // One regular sync pass of the attached vault, inline.
    static unsigned pass(const Vault& v) {
        const auto cloud = cloudOf(v);
        EXPECT_TRUE(cloud) << "the vault has a cloud engine";
        if (!cloud) return 0;
        return transfers(test_support::versioned::runSyncPass(cloud, {.purgeTrash = true, .remoteOnlyActions = true,
                                                                      .requireOk = true, .expectOk = true})
                             .plan);
    }

    static ra::RunDeps deps(const Vault& v) {
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
        d.firstPass = [v](const uint32_t, std::time_t) -> std::optional<json> {
            return json{{"status", "success"}, {"started_at", nullptr}, {"finished_at", nullptr}, {"error", nullptr},
                        {"transfers", pass(v)}};
        };
        return d;
    }

    static vr::Status start(const Vault& v) {
        return vr::attach(superUser, {.vault_id = v.id(), .api_key_id = v.keyId, .bucket = v.bucketName,
                                      .storage_tier = std::nullopt, .accept_unpriced = true});
    }

    static ra::RunResult attach(const Vault& v) {
        (void)start(v);
        return ra::run(v.id(), deps(v));
    }

    static ra::Row rowOf(const Vault& v) {
        const auto r = Q::get(v.id());
        EXPECT_TRUE(r);
        return r.value_or(ra::Row{});
    }

    static std::string typeOf(const Vault& v) {
        return db::Transactions::exec("RemoteAttachTest::typeOf", [&](pqxx::work& txn) {
            return txn.exec("SELECT type FROM vault WHERE id = $1", pqxx::params{v.id()}).one_field_ref().as<std::string>();
        });
    }

    static uint64_t count(const std::string& sql, const uint32_t id) {
        return db::Transactions::exec("RemoteAttachTest::count", [&](pqxx::work& txn) {
            return txn.exec(sql, pqxx::params{id}).one_field_ref().as<uint64_t>();
        });
    }

    // The bucket's current object of the file at path holds exactly the bytes of its local backing file.
    static void expectObjectIsLocalBytes(const Vault& v, const std::string& path) {
        const auto f = row(v, path);
        ASSERT_TRUE(f) << path;
        const auto current = v.bucket->current(keys::contentKey(*f->object_uid));
        ASSERT_TRUE(current) << path << ": no object";
        const auto backing = engineOf(v)->paths->absPath(f->backing_path, fs::model::PathType::BACKING_ROOT);
        std::ifstream in(f->backing_path.is_absolute() ? f->backing_path : backing, std::ios::binary);
        const std::vector<uint8_t> local((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        EXPECT_EQ(current->body, local) << path;
    }

    // What the ops layer answers: the refusal's code, "ok", or the error kind.
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

    static uint64_t auditEvents(const std::string& action, const uint32_t vaultId) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("RemoteAttachTest::auditEvents", [&](pqxx::work& txn) {
            return txn.exec("SELECT COUNT(*) FROM audit_event WHERE action = $1 AND vault_id = $2",
                            pqxx::params{action, vaultId}).one_field_ref().as<uint64_t>();
        });
    }

    // Every object key of the bucket is an opaque content key or a .vaulthalla/ metadata key.
    static void expectOnlyOpaqueKeys(const Vault& v) {
        for (const auto& k : v.bucket->keys())
            EXPECT_NE(keys::classify(k), keys::KeyClass::Foreign) << k;
    }
};

// The acceptance scenario: a local vault with folders, files and an empty file becomes an encrypting opaque_v1 S3
// vault in place. Same id and uid, every object the bytes of its backing file, the manifest readable from the bucket,
// the first pass uploads only what the attach left to it, and the pass after it has nothing to do.
TEST_F(RemoteAttachTest, RemoteAttachTurnsALocalVaultIntoAnS3VaultInPlace) {
    auto v = localVault();
    const auto uid = *v.engine->vault->uid;
    v.engine->mkdir("/docs", superUser);
    write(v, "/docs/a.txt", "alpha");
    write(v, "/docs/b.txt", std::string(200'000, 'b'));
    write(v, "/c.txt", "charlie");
    write(v, "/empty.txt", "");

    const auto started = start(v);
    EXPECT_EQ(started.remote, "attaching:preparing");
    EXPECT_EQ(typeOf(v), "local");
    EXPECT_EQ(ops::vaults::get(superUser, v.id()).remote, "attaching:preparing");
    EXPECT_EQ(rowOf(v).manifest_publish, std::optional<std::string>("conditional"));
    EXPECT_TRUE(v.bucket->keys().empty()) << "the probe deleted what it wrote; nothing else was written yet";

    const auto result = ra::run(v.id(), deps(v));
    EXPECT_EQ(result.state, ra::State::Done) << result.error.value_or("");
    const auto done = rowOf(v);
    EXPECT_EQ(done.state, ra::State::Done) << done.last_error.value_or("");
    ASSERT_TRUE(done.first_pass);
    EXPECT_EQ(done.first_pass->at("transfers"), 1) << "the empty file's object goes up with the first pass";

    // The same vault, now an S3 vault on the bucket.
    const auto vault = db::query::vault::Vault::getVault(v.id());
    const auto s3 = std::dynamic_pointer_cast<vault::model::S3Vault>(vault);
    ASSERT_TRUE(s3);
    EXPECT_EQ(*s3->uid, uid);
    EXPECT_EQ(s3->bucket, v.bucketName);
    EXPECT_EQ(s3->api_key_id, v.keyId);
    EXPECT_TRUE(s3->encrypt_upstream);
    EXPECT_EQ(s3->storage_layout, vault::model::StorageLayout::OpaqueV1);
    const auto cloud = cloudOf(v);
    ASSERT_TRUE(cloud);
    EXPECT_EQ(cloud->remote_policy()->strategy, sync::model::RemotePolicy::Strategy::Cache);
    EXPECT_EQ(cloud->remote_policy()->conflict_policy, sync::model::RemotePolicy::ConflictPolicy::Ask);
    EXPECT_EQ(count("SELECT count(*) FROM fsync f JOIN sync s ON s.id = f.sync_id WHERE s.vault_id = $1", v.id()), 0u);
    EXPECT_EQ(ops::vaults::get(superUser, v.id()).remote, "attached");

    // Every file reads, and its object is its backing file byte for byte.
    EXPECT_EQ(readLocal(v, "/docs/a.txt"), "alpha");
    EXPECT_EQ(readLocal(v, "/docs/b.txt"), std::string(200'000, 'b'));
    EXPECT_EQ(readLocal(v, "/c.txt"), "charlie");
    for (const auto* path : {"/docs/a.txt", "/docs/b.txt", "/c.txt"}) expectObjectIsLocalBytes(v, path);
    EXPECT_TRUE(v.bucket->current(keyOf(v, "/empty.txt")));
    expectOnlyOpaqueKeys(v);
    EXPECT_TRUE(v.bucket->opaqueLayout());

    // The bucket alone names every file.
    const auto manifest = cloud->loadManifestFromBucket();
    std::set<std::string> named;
    for (const auto& e : manifest.entries) named.insert(e.uid);
    for (const auto* path : {"/docs/a.txt", "/docs/b.txt", "/c.txt", "/empty.txt"})
        EXPECT_TRUE(named.contains(vl::keykit::toBase32(*row(v, path)->object_uid))) << path;

    EXPECT_EQ(pass(v), 0u) << "nothing left to transfer";
    EXPECT_EQ(auditEvents("vault.remote.attach", v.id()), 1u);
    EXPECT_EQ(auditEvents("vault.remote.cutover", v.id()), 1u);
    EXPECT_TRUE(Q::summary().failed.empty());
}

TEST_F(RemoteAttachTest, RemoteAttachEveryPreconditionRefusesWithNothingWritten) {
    const auto refused = [&](const Vault& v, const std::string& expected, const std::size_t keysBefore = 0) {
        EXPECT_EQ(code([&] { return start(v); }), expected);
        EXPECT_FALSE(Q::get(v.id())) << expected << ": no attach was recorded";
        EXPECT_EQ(typeOf(v), "local") << expected;
        EXPECT_EQ(v.bucket->keys().size(), keysBefore) << expected << ": nothing was written";
    };

    // No recovery material independent of this host.
    auto noMaterial = localVault(Versioning::Enabled, false);
    write(noMaterial, "/a.txt", "a");
    refused(noMaterial, "recovery_material_missing");

    // A bucket that holds anything at all, even only a delete marker.
    auto occupied = localVault();
    occupied.bucket->seed("someone-elses.txt", std::string("x"));
    refused(occupied, "bucket_not_empty", 1);
    auto marker = localVault();
    (void)marker.bucket->seedDeleteMarker("gone.txt");
    refused(marker, "bucket_not_empty", 1);

    // A bucket that can't arbitrate the manifest's root: no conditional writes, no versions.
    auto insufficient = localVault(Versioning::Unversioned);
    insufficient.bucket->conditionalPuts = VersionedBucket::ConditionalPuts::Reject501;
    refused(insufficient, "bucket_capability_insufficient");

    // Legacy content: the format conversion finishes first.
    auto legacy = localVault();
    write(legacy, "/old.txt", "legacy bytes");
    test_support::recovery_local::makeLegacyGcm(legacy.engine, "/old.txt", "legacy bytes");
    refused(legacy, "legacy_content");

    // A bucket another vault holds.
    auto taken = localVault();
    const auto other = test_support::versioned::makeCloudVault(superUser, "raother", Versioning::Enabled, true);
    taken.bucketName = std::static_pointer_cast<vault::model::S3Vault>(other.engine->vault)->bucket;
    taken.keyId = std::static_pointer_cast<vault::model::S3Vault>(other.engine->vault)->api_key_id;
    buckets[taken.bucketName] = other.bucket;
    EXPECT_EQ(code([&] { return start(taken); }), "conflict");
    EXPECT_FALSE(Q::get(taken.id()));

    // An S3 vault has a remote already; bad requests.
    EXPECT_EQ(code([&] {
                  return vr::attach(superUser, {.vault_id = other.id(), .api_key_id = taken.keyId, .bucket = "ra-any",
                                                .storage_tier = std::nullopt, .accept_unpriced = true});
              }),
              "conflict");
    auto plain = localVault();
    EXPECT_EQ(code([&] {
                  return vr::attach(superUser, {.vault_id = plain.id(), .api_key_id = plain.keyId, .bucket = "",
                                                .storage_tier = std::nullopt, .accept_unpriced = true});
              }),
              "invalid");
    EXPECT_EQ(code([&] {
                  return vr::attach(superUser, {.vault_id = plain.id(), .api_key_id = 999'999, .bucket = plain.bucketName,
                                                .storage_tier = std::nullopt, .accept_unpriced = true});
              }),
              "not_found");
    EXPECT_FALSE(Q::get(plain.id()));
}

// A crash after each named step leaves a state the next run continues from; the outcome is the same vault either way.
TEST_F(RemoteAttachTest, RemoteAttachResumesAfterACrashAtEveryStep) {
    for (const std::string step : {"prepared", "item:", "uploaded", "listed", "sampled", "published", "verified",
                                   "staged", "cutover", "swapped"}) {
        SCOPED_TRACE(step);
        auto v = localVault();
        v.engine->mkdir("/d", superUser);
        write(v, "/d/one.txt", "one");
        write(v, "/two.txt", std::string(70'000, '2'));
        write(v, "/three.txt", "three");
        (void)start(v);

        auto crashing = deps(v);
        bool crashed = false;
        crashing.afterStep = [&](const std::string_view at) {
            if (!crashed && at.starts_with(step)) {
                crashed = true;
                throw Crash{std::string(at)};
            }
        };
        EXPECT_THROW((void)ra::run(v.id(), crashing), Crash);
        ASSERT_TRUE(crashed);
        const bool cutOver = step == "cutover" || step == "swapped";   // "staged" is before the transaction
        EXPECT_EQ(typeOf(v), cutOver ? "s3" : "local");
        EXPECT_EQ(readLocal(v, "/two.txt"), std::string(70'000, '2')) << "the vault stays readable";

        const auto resumed = ra::run(v.id(), deps(v));
        EXPECT_EQ(resumed.state, ra::State::Done) << resumed.error.value_or("");
        EXPECT_EQ(rowOf(v).state, ra::State::Done);
        for (const auto* path : {"/d/one.txt", "/two.txt", "/three.txt"}) {
            expectObjectIsLocalBytes(v, path);
            EXPECT_EQ(v.bucket->history(keyOf(v, path)).size(), 1u) << path << ": one version, no stray";
        }
        EXPECT_EQ(pass(v), 0u);
    }
}

// A PUT that reached the bucket without being recorded (the process died in between) leaves a stray version at a key
// the attach recorded: the next run deletes it by version id and sends the file again.
TEST_F(RemoteAttachTest, RemoteAttachRemovesAStrayVersion) {
    auto v = localVault();
    write(v, "/a.txt", "alpha");
    write(v, "/b.txt", "bravo");
    (void)start(v);
    auto crashing = deps(v);
    crashing.afterStep = [&](const std::string_view at) {
        if (at == "prepared") throw Crash{std::string(at)};
    };
    EXPECT_THROW((void)ra::run(v.id(), crashing), Crash);
    const auto strayId = v.bucket->seed(keyOf(v, "/a.txt"), std::string("an interrupted PUT's bytes"));

    EXPECT_EQ(ra::run(v.id(), deps(v)).state, ra::State::Done);
    const auto history = v.bucket->history(keyOf(v, "/a.txt"));
    ASSERT_EQ(history.size(), 1u);
    EXPECT_NE(history.front().version_id, strayId);
    expectObjectIsLocalBytes(v, "/a.txt");
}

TEST_F(RemoteAttachTest, RemoteAttachWritesRenamesAndDeletesDuringTheUploadEndConsistent) {
    auto v = localVault();
    write(v, "/keep.txt", "keep");
    write(v, "/change.txt", "before");
    write(v, "/delete.txt", "going away");
    write(v, "/rename.txt", "renamed later");
    const auto deletedKey = keyOf(v, "/delete.txt");
    const auto renamedKey = keyOf(v, "/rename.txt");
    (void)start(v);

    auto d = deps(v);
    bool duringUpload = false, beforeCutover = false;
    d.afterStep = [&](const std::string_view at) {
        if (at == "uploaded" && !duringUpload) {
            duringUpload = true;
            write(v, "/change.txt", "after, while the attach uploaded");
            remove(v, "/delete.txt");
            write(v, "/new.txt", "created meanwhile");
            const auto engine = engineOf(v);
            EXPECT_EQ(fs::Filesystem::rename(engine->vaultPathToFusePath("/rename.txt"),
                                             engine->vaultPathToFusePath("/renamed.txt"), superUser, engine), 0);
        }
        if (at == "verified" && !beforeCutover) {
            beforeCutover = true;
            write(v, "/late.txt", "written between the verification and the cutover");
            write(v, "/keep.txt", "keep, changed at the last moment");
        }
    };
    const auto result = ra::run(v.id(), d);
    EXPECT_EQ(result.state, ra::State::Done) << result.error.value_or("");
    EXPECT_TRUE(duringUpload && beforeCutover);
    EXPECT_GE(rowOf(v).passes, 1u);
    EXPECT_EQ(rowOf(v).first_pass->at("transfers"), 2) << "the late file and the late change upload with the first pass";

    EXPECT_EQ(readLocal(v, "/change.txt"), "after, while the attach uploaded");
    EXPECT_EQ(readLocal(v, "/new.txt"), "created meanwhile");
    EXPECT_EQ(readLocal(v, "/renamed.txt"), "renamed later");
    EXPECT_EQ(readLocal(v, "/late.txt"), "written between the verification and the cutover");
    EXPECT_EQ(readLocal(v, "/keep.txt"), "keep, changed at the last moment");
    for (const auto* path : {"/change.txt", "/new.txt", "/renamed.txt", "/late.txt", "/keep.txt"})
        expectObjectIsLocalBytes(v, path);
    EXPECT_EQ(keyOf(v, "/renamed.txt"), renamedKey) << "a rename keeps the object";
    EXPECT_EQ(v.bucket->history(keyOf(v, "/change.txt")).size(), 1u) << "the earlier generation was deleted by version id";
    // The object the attach sent for the deleted file was removed by version id. (The first pass's trash purge then
    // sends its usual DELETE for the trashed file, which on a versioned bucket leaves a delete marker.)
    EXPECT_FALSE(v.bucket->current(deletedKey)) << "a deleted file's object is gone";
    for (const auto& version : v.bucket->history(deletedKey)) EXPECT_TRUE(version.delete_marker);
    EXPECT_EQ(pass(v), 0u);
}

TEST_F(RemoteAttachTest, RemoteAttachVerificationFailuresKeepTheVaultLocal) {
    // A foreign object appears in the bucket while the attach runs.
    {
        auto v = localVault();
        write(v, "/a.txt", "alpha");
        (void)start(v);
        auto d = deps(v);
        d.afterStep = [&](const std::string_view at) {
            if (at == "uploaded") v.bucket->seed("foreign.txt", std::string("not ours"));
        };
        const auto result = ra::run(v.id(), d);
        EXPECT_EQ(result.state, ra::State::Failed);
        EXPECT_NE(rowOf(v).last_error.value_or("").find("bucket_not_empty"), std::string::npos);
        EXPECT_EQ(typeOf(v), "local");
        EXPECT_EQ(ops::vaults::get(superUser, v.id()).remote, "attaching:failed");
        EXPECT_EQ(readLocal(v, "/a.txt"), "alpha");
        ASSERT_EQ(Q::summary().failed.size(), 1u);
        EXPECT_EQ(Q::summary().failed.front().vault_id, v.id());
        EXPECT_EQ(auditEvents("vault.remote.failed", v.id()), 1u);
        EXPECT_TRUE(v.bucket->current("foreign.txt")) << "nothing the attach did not write is touched";
        (void)vr::abort(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name});
        (void)ra::runAbort(v.id());
    }

    // An object is altered in the bucket after it was sent: the read-back does not authenticate.
    {
        auto v = localVault();
        write(v, "/a.txt", std::string(5'000, 'a'));
        (void)start(v);
        auto d = deps(v);
        bool tampered = false;
        d.afterStep = [&](const std::string_view at) {
            if (at == "uploaded" && !tampered) {
                tampered = true;
                const auto key = keyOf(v, "/a.txt");
                v.bucket->tamper(key, v.bucket->current(key)->version_id, 200);
            }
        };
        EXPECT_EQ(ra::run(v.id(), d).state, ra::State::Failed);
        EXPECT_NE(rowOf(v).last_error.value_or("").find("read-back"), std::string::npos) << rowOf(v).last_error.value_or("");
        EXPECT_EQ(typeOf(v), "local");

        // Started again: the failed item is sent again, and the attach completes.
        (void)start(v);
        EXPECT_EQ(rowOf(v).attempts, 1u);
        EXPECT_EQ(ra::run(v.id(), deps(v)).state, ra::State::Done);
        expectObjectIsLocalBytes(v, "/a.txt");
        EXPECT_EQ(v.bucket->history(keyOf(v, "/a.txt")).size(), 1u);
    }

    // The manifest's root is replaced after it was published: it does not load back as published.
    {
        auto v = localVault();
        write(v, "/a.txt", "alpha");
        (void)start(v);
        auto d = deps(v);
        d.afterStep = [&](const std::string_view at) {
            if (at == "published") v.bucket->seed(std::string(sync::manifest::kRootKey), std::string("not a root"));
        };
        EXPECT_EQ(ra::run(v.id(), d).state, ra::State::Failed);
        EXPECT_EQ(typeOf(v), "local");
        EXPECT_EQ(count("SELECT count(*) FROM remote_object_index WHERE vault_id = $1", v.id()), 0u);
        EXPECT_EQ(count("SELECT count(*) FROM s3 WHERE vault_id = $1", v.id()), 0u);
    }
}

// A provider whose ETags are not MD5s (SSE-KMS, some S3-compatible stores): no PUT is proven by its ETag, so every
// object is read back and authenticated.
TEST_F(RemoteAttachTest, RemoteAttachReadsEveryObjectBackWhenETagsAreNotMd5s) {
    auto v = localVault();
    v.bucket->md5Etags = false;
    write(v, "/a.txt", "alpha");
    write(v, "/b.txt", "bravo");
    write(v, "/c.txt", "charlie");
    (void)start(v);
    v.bucket->resetCounters();
    auto d = deps(v);
    d.sampleMinimum = 0;
    uint64_t bodyGets = 0;
    d.afterStep = [&](const std::string_view at) {
        if (at == "uploaded") bodyGets = v.bucket->counters().body_gets;
    };
    EXPECT_EQ(ra::run(v.id(), d).state, ra::State::Done);
    EXPECT_GE(bodyGets, 3u) << "each of the three objects was read back";
}

TEST_F(RemoteAttachTest, RemoteAttachAbortDeletesExactlyTheRecordedVersions) {
    auto v = localVault();
    write(v, "/a.txt", "alpha");
    write(v, "/b.txt", "bravo");
    (void)start(v);
    auto crashing = deps(v);
    crashing.afterStep = [&](const std::string_view at) {
        if (at == "published") throw Crash{std::string(at)};
    };
    EXPECT_THROW((void)ra::run(v.id(), crashing), Crash);
    EXPECT_GE(v.bucket->keys().size(), 4u) << "two objects, the layout hint, a segment and the root";
    v.bucket->seed("keep-me.txt", std::string("another application's object"));

    EXPECT_EQ(code([&] { return vr::abort(superUser, {.vault_id = v.id(), .confirm = "not the name"}); }), "invalid");
    EXPECT_FALSE(rowOf(v).abort_requested_at);
    (void)vr::abort(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name});
    EXPECT_TRUE(rowOf(v).abort_requested_at);
    EXPECT_EQ(ra::run(v.id(), deps(v)).state, rowOf(v).state) << "a run does nothing once an abort was asked for";

    // A provider that refuses the deletes: listed, never reported done.
    v.bucket->refuseDeletes = true;
    const auto blocked = ra::runAbort(v.id());
    EXPECT_EQ(blocked.state, ra::State::Failed);
    EXPECT_GT(blocked.remaining, 0u);
    EXPECT_EQ(rowOf(v).state, ra::State::Failed);
    EXPECT_NE(rowOf(v).last_error.value_or("").find("abort"), std::string::npos);

    v.bucket->refuseDeletes = false;
    const auto aborted = ra::runAbort(v.id());
    EXPECT_EQ(aborted.state, ra::State::Aborted);
    EXPECT_EQ(aborted.remaining, 0u);
    EXPECT_EQ(v.bucket->keys(), std::vector<std::string>{"keep-me.txt"}) << "only what the attach did not write is left";
    EXPECT_EQ(v.bucket->history("keep-me.txt").size(), 1u);
    EXPECT_EQ(typeOf(v), "local");
    EXPECT_EQ(readLocal(v, "/a.txt"), "alpha");
    EXPECT_EQ(ops::vaults::get(superUser, v.id()).remote, "none");
    EXPECT_EQ(auditEvents("vault.remote.abort", v.id()), 1u);
    EXPECT_EQ(code([&] { return vr::abort(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name}); }),
              "conflict");

    // The reservation is released: the vault attaches another bucket afterwards.
    v.bucketName = "ra-" + vh::test::uniqueTag('a');
    v.bucket = newBucket(v.bucketName, Versioning::Enabled);
    EXPECT_EQ(attach(v).state, ra::State::Done);
    EXPECT_EQ(typeOf(v), "s3");
    EXPECT_EQ(code([&] { return vr::abort(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name}); }),
              "conflict") << "not after the cutover";
}

// The cutover is one transaction: a failure inside it leaves the vault local, with nothing of the S3 side written.
TEST_F(RemoteAttachTest, RemoteAttachCutoverIsOneTransaction) {
    auto v = localVault();
    write(v, "/a.txt", "alpha");
    (void)start(v);
    auto d = deps(v);
    d.afterStep = [&](const std::string_view at) {
        if (at != "verified") return;
        // The transaction changes the vault's type first, then fails for want of the sync row.
        db::Transactions::exec("RemoteAttachTest::breakSync", [&](pqxx::work& txn) {
            txn.exec("ALTER TABLE sync RENAME TO sync_hidden");
        });
    };
    const auto result = ra::run(v.id(), d);
    db::Transactions::exec("RemoteAttachTest::restoreSync", [&](pqxx::work& txn) {
        txn.exec("ALTER TABLE sync_hidden RENAME TO sync");
    });
    EXPECT_EQ(result.state, ra::State::Failed);
    EXPECT_EQ(typeOf(v), "local");
    EXPECT_EQ(count("SELECT count(*) FROM s3 WHERE vault_id = $1", v.id()), 0u);
    EXPECT_EQ(count("SELECT count(*) FROM remote_object_index WHERE vault_id = $1", v.id()), 0u);
    EXPECT_EQ(count("SELECT count(*) FROM remote_manifest_state WHERE vault_id = $1", v.id()), 0u);
    EXPECT_EQ(count("SELECT count(*) FROM fsync f JOIN sync s ON s.id = f.sync_id WHERE s.vault_id = $1", v.id()), 1u);
    EXPECT_EQ(readLocal(v, "/a.txt"), "alpha");

    (void)start(v);
    EXPECT_EQ(ra::run(v.id(), deps(v)).state, ra::State::Done);
    EXPECT_EQ(typeOf(v), "s3");
}

// A local vault's recovery recipient: its envelopes are kept in the database, copied into the bucket byte for byte and
// inspected there, and the database's copy goes at the cutover. No export is needed then.
TEST_F(RemoteAttachTest, RemoteAttachCopiesALocalVaultsRecoveryEnvelopesIntoTheBucket) {
    auto v = localVault(Versioning::Enabled, false);
    write(v, "/a.txt", "alpha");
    const auto seed = vl::keykit::RecoverySeed::generate();
    const auto added = ops::recovery_recipients::add(
        superUser, {.vault_id = v.id(), .public_key = crypto::util::b64_encode(seed.x25519PublicKey()),
                    .label = std::string("Recovery kit")},
        ops::vault_keys::Channel::Cli);
    EXPECT_EQ(added.envelopes_written, 1u);
    const auto held = Q::envelopes(v.id());
    ASSERT_EQ(held.size(), 1u);
    ASSERT_FALSE(held[0].bytes.empty());

    EXPECT_EQ(attach(v).state, ra::State::Done);
    const auto object = v.bucket->current(vl::keykit::kev1::objectKey(held[0].kid));
    ASSERT_TRUE(object);
    EXPECT_EQ(object->body, held[0].bytes);
    const auto unwrapped = vl::keykit::kev1::unwrap(object->body, seed.x25519SecretKey().bytes(),
                                                    vl::keykit::kev1::Suite::X25519, *v.engine->vault->uid);
    EXPECT_EQ(unwrapped.key_version, held[0].key_version);
    const auto after = Q::envelopes(v.id());
    ASSERT_EQ(after.size(), 1u);
    EXPECT_TRUE(after[0].bytes.empty()) << "the bucket holds it now";
    EXPECT_EQ(vault::envelopes::material(v.id()).state, std::string(vault::envelopes::kMaterialRecipient));
}

// A recipient enrolled after the envelopes were staged and before the cutover: its envelope exists only in the
// database, so the cutover refuses instead of clearing it. The vault stays local with the bytes intact, the attach is
// not failed, and the next run stages, verifies and cuts over with the envelope in the bucket.
TEST_F(RemoteAttachTest, RemoteAttachNeverDropsAnEnvelopeEnrolledJustBeforeTheCutover) {
    auto v = localVault();
    write(v, "/a.txt", "alpha");
    (void)start(v);
    const auto seed = vl::keykit::RecoverySeed::generate();
    auto d = deps(v);
    bool enrolled = false;
    d.afterStep = [&](const std::string_view at) {
        if (at != "staged" || enrolled) return;
        enrolled = true;
        (void)ops::recovery_recipients::add(
            superUser, {.vault_id = v.id(), .public_key = crypto::util::b64_encode(seed.x25519PublicKey()),
                        .label = std::string("Late kit")},
            ops::vault_keys::Channel::Cli);
    };
    const auto first = ra::run(v.id(), d);
    ASSERT_TRUE(enrolled);
    EXPECT_EQ(first.state, ra::State::Preparing) << first.error.value_or("");
    EXPECT_EQ(rowOf(v).state, ra::State::Preparing) << "not failed: picked up by the next run";
    EXPECT_FALSE(rowOf(v).verified_at);
    EXPECT_EQ(typeOf(v), "local");
    const auto held = Q::envelopes(v.id());
    ASSERT_EQ(held.size(), 1u);
    ASSERT_FALSE(held[0].bytes.empty()) << "the only copy was not cleared";
    EXPECT_FALSE(v.bucket->current(vl::keykit::kev1::objectKey(held[0].kid)));

    EXPECT_EQ(ra::run(v.id(), deps(v)).state, ra::State::Done);
    const auto object = v.bucket->current(vl::keykit::kev1::objectKey(held[0].kid));
    ASSERT_TRUE(object);
    EXPECT_EQ(object->body, held[0].bytes);
    const auto after = Q::envelopes(v.id());
    ASSERT_EQ(after.size(), 1u);
    EXPECT_TRUE(after[0].bytes.empty());
    EXPECT_EQ(typeOf(v), "s3");
}

// A key rotation asked for while the attach runs is queued, never started: a new key version must not seal content
// before its envelopes reach the bucket.
TEST_F(RemoteAttachTest, RemoteAttachMakesAKeyRotationWait) {
    auto v = localVault();
    write(v, "/a.txt", "alpha");
    const auto before = v.engine->encryptionManager->get_key_version();
    (void)start(v);
    EXPECT_TRUE(ra::attachInProgress(v.id()));
    const auto [exitCode, out] = test::parity::cli(*router, "vault keys rotate " + std::to_string(v.id()), superUser);
    EXPECT_EQ(exitCode, 0) << out;
    EXPECT_NE(out.find("queued"), std::string::npos) << out;
    EXPECT_EQ(v.engine->encryptionManager->get_key_version(), before);
    EXPECT_FALSE(db::query::vault::Key::keyRotationInProgress(v.id()));
    EXPECT_TRUE(rowOf(v).rotation_queued_at);
    EXPECT_FALSE(Q::takeQueuedRotation(v.id())) << "not while the attach runs";

    EXPECT_EQ(ra::run(v.id(), deps(v)).state, ra::State::Done);
    EXPECT_FALSE(ra::attachInProgress(v.id()));
    EXPECT_TRUE(Q::takeQueuedRotation(v.id())) << "the service starts it now";
    EXPECT_FALSE(ra::queueRotation(v.id())) << "nothing to wait for any more";
}

// The service's pass: a requested abort is carried out, and the rotation that waited starts once the attach has ended.
TEST_F(RemoteAttachTest, RemoteAttachServiceAbortsAndThenStartsTheQueuedRotation) {
    auto v = localVault();
    write(v, "/a.txt", "alpha");
    (void)start(v);
    auto crashing = deps(v);
    crashing.afterStep = [&](const std::string_view at) {
        if (at == "uploaded") throw Crash{std::string(at)};
    };
    EXPECT_THROW((void)ra::run(v.id(), crashing), Crash);
    EXPECT_FALSE(v.bucket->keys().empty());
    const auto before = v.engine->encryptionManager->get_key_version();
    ASSERT_TRUE(ra::queueRotation(v.id()));
    (void)vr::abort(superUser, {.vault_id = v.id(), .confirm = v.engine->vault->name});

    // The service runs every attach row with the daemon's seams: none of another test's may still be running.
    for (const auto& other : Q::list())
        if (other.vault_id != v.id() && ra::running(other.state) && ra::beforeCutover(other.state))
            Q::setState(other.vault_id, ra::State::Failed, "left by another test");
    vault::RemoteAttachService service;
    service.runOnce();
    EXPECT_EQ(rowOf(v).state, ra::State::Aborted);
    EXPECT_TRUE(v.bucket->keys().empty());
    EXPECT_FALSE(rowOf(v).rotation_queued_at);
    EXPECT_EQ(v.engine->encryptionManager->get_key_version(), before + 1) << "the rotation that waited was started";
    EXPECT_EQ(typeOf(v), "local");
}

// Cloudflare R2: no object versions (ListObjectsV2, deletes by key), conditional writes.
TEST_F(RemoteAttachTest, RemoteAttachOnABucketWithoutVersions) {
    auto v = localVault(Versioning::Unversioned, true, vault::model::S3Provider::CloudflareR2);
    write(v, "/a.txt", "alpha");
    write(v, "/b.txt", "bravo");
    (void)start(v);
    EXPECT_EQ(rowOf(v).versioned, std::optional<bool>(false));
    auto d = deps(v);
    bool changed = false;
    d.afterStep = [&](const std::string_view at) {
        if (at == "uploaded" && !changed) {
            changed = true;
            write(v, "/a.txt", "alpha, changed");
            remove(v, "/b.txt");
        }
    };
    const auto bKey = keyOf(v, "/b.txt");
    EXPECT_EQ(ra::run(v.id(), d).state, ra::State::Done);
    expectObjectIsLocalBytes(v, "/a.txt");
    EXPECT_FALSE(v.bucket->current(bKey));
    EXPECT_EQ(pass(v), 0u);

    // And an abort there deletes by key.
    auto w = localVault(Versioning::Unversioned, true, vault::model::S3Provider::CloudflareR2);
    write(w, "/a.txt", "alpha");
    (void)start(w);
    auto crashing = deps(w);
    crashing.afterStep = [&](const std::string_view at) {
        if (at == "published") throw Crash{std::string(at)};
    };
    EXPECT_THROW((void)ra::run(w.id(), crashing), Crash);
    EXPECT_FALSE(w.bucket->keys().empty());
    (void)vr::abort(superUser, {.vault_id = w.id(), .confirm = w.engine->vault->name});
    EXPECT_EQ(ra::runAbort(w.id()).state, ra::State::Aborted);
    EXPECT_TRUE(w.bucket->keys().empty());
}

// A bucket without conditional writes that keeps versions (Backblaze B2): the manifest is published as versions of
// its root (spec 06 §5), and the cutover records the root's version.
TEST_F(RemoteAttachTest, RemoteAttachOnAVersionLogBucket) {
    auto v = localVault();
    v.bucket->conditionalPuts = VersionedBucket::ConditionalPuts::Reject501;
    write(v, "/a.txt", "alpha");
    write(v, "/b.txt", "bravo");
    (void)start(v);
    EXPECT_EQ(rowOf(v).manifest_publish, std::optional<std::string>("version_log"));
    const auto result = ra::run(v.id(), deps(v));
    EXPECT_EQ(result.state, ra::State::Done) << result.error.value_or("");
    const auto state = db::query::sync::Manifest::state(v.id());
    EXPECT_TRUE(state.epoch);
    EXPECT_TRUE(state.root_version_id) << "the settled root's provider version is recorded";
    EXPECT_EQ(state.own_epoch, state.epoch);
    EXPECT_EQ(pass(v), 0u);
}

// A gateway bucket on a local vault serves local files; on an S3 vault it is a remote_cache bucket.
TEST_F(RemoteAttachTest, RemoteAttachFlipsAGatewayBindingToRemoteCache) {
    auto v = localVault();
    write(v, "/a.txt", "alpha");
    db::Transactions::exec("RemoteAttachTest::gateway", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO s3_gateway_bucket (vault_id, bucket_name, mode) VALUES ($1, $2, 'local')",
                 pqxx::params{v.id(), "gw-" + vh::test::uniqueTag('a')});
    });
    EXPECT_EQ(attach(v).state, ra::State::Done);
    EXPECT_EQ(count("SELECT count(*) FROM s3_gateway_bucket WHERE vault_id = $1 AND mode = 'remote_cache'", v.id()), 1u);
}

// RemoteAttachCost: the estimate names what the upload then sends, and the status reports progress as it goes.
TEST_F(RemoteAttachTest, RemoteAttachCostAndProgress) {
    auto v = localVault();
    write(v, "/a.txt", std::string(10'000, 'a'));
    write(v, "/b.txt", std::string(30'000, 'b'));
    write(v, "/empty.txt", "");
    (void)start(v);
    auto d = deps(v);
    uint64_t objectBytes = 0, objectPuts = 0;
    std::optional<vr::Status> midway;
    d.afterStep = [&](const std::string_view at) {
        if (at != "uploaded") return;
        for (const auto& k : v.bucket->keys())
            if (keys::classify(k) == keys::KeyClass::Content) {
                objectBytes += v.bucket->current(k)->size();
                ++objectPuts;
            }
        midway = vr::status(superUser, v.id()).front();
    };
    EXPECT_EQ(ra::run(v.id(), d).state, ra::State::Done);
    const auto done = rowOf(v);
    ASSERT_TRUE(done.estimate);
    const auto estimate = ra::estimateFromJson(*done.estimate);
    EXPECT_EQ(estimate.files, 2u) << "the empty file has no object to send";
    EXPECT_EQ(estimate.put_requests, objectPuts);
    EXPECT_EQ(estimate.upload_bytes, objectBytes);
    EXPECT_FALSE(estimate.priced);
    ASSERT_TRUE(done.usage);
    EXPECT_GE(done.usage->at("put_requests").get<uint64_t>(), objectPuts);
    EXPECT_GE(done.usage->at("uploaded_bytes").get<uint64_t>(), objectBytes);

    ASSERT_TRUE(midway && midway->progress);
    EXPECT_EQ(midway->progress->phase, "uploading");
    EXPECT_EQ(midway->progress->files_total, 2u);
    EXPECT_EQ(midway->progress->files_done, 2u);
    EXPECT_EQ(midway->progress->bytes_done, objectBytes);
    EXPECT_EQ(midway->items.files_sent, 2u);
    const auto shown = vr::toJson(vr::status(superUser, v.id()).front());
    EXPECT_EQ(shown.at("remote"), "attached");
    EXPECT_EQ(shown.at("attach").at("state"), "done");
    EXPECT_EQ(shown.at("progress").at("phase"), "done");
}

// The bucket is reserved from the start: a second vault can't attach it, and a failed attach names its bucket.
TEST_F(RemoteAttachTest, RemoteAttachReservesTheBucket) {
    auto first = localVault();
    write(first, "/a.txt", "alpha");
    (void)start(first);
    auto second = localVault();
    second.bucketName = first.bucketName;
    second.keyId = first.keyId;
    EXPECT_EQ(code([&] { return start(second); }), "conflict");
    EXPECT_EQ(code([&] { return start(first); }), "conflict") << "it already runs";

    // Failed, then started again with another bucket: refused until it is aborted.
    auto d = deps(first);
    d.afterStep = [&](const std::string_view at) {
        if (at == "uploaded") first.bucket->seed("foreign.txt", std::string("x"));
    };
    EXPECT_EQ(ra::run(first.id(), d).state, ra::State::Failed);
    auto elsewhere = first;
    elsewhere.bucketName = "ra-" + vh::test::uniqueTag('a');
    elsewhere.bucket = newBucket(elsewhere.bucketName, Versioning::Enabled);
    EXPECT_EQ(code([&] { return start(elsewhere); }), "conflict");
    EXPECT_EQ(code([&] { return start(second); }), "conflict") << "a failed attach keeps its reservation";
}

}
