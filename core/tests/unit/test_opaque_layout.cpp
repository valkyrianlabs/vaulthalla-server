// The opaque_v1 data plane (#369, design/encryption/01-provider-blind-storage.md §4, §5, §8).
//
//   OpaqueObjectKeys.*       storage/ObjectKeys.hpp: o/<uid> and .vaulthalla/ keys, the allowlist, part sizes
//   OpaqueRequestPolicy.*    s3::Controller::enforceRequestPolicy refuses names, metadata and foreign keys before
//                            anything is sent or metered
//   OpaqueMultipart.*        a 60 GiB object (sparse; nothing allocated) in at most 10,000 parts
//   OpaqueLayoutTest.*       DB-backed: real sync passes, uploads, restores and the manifest over a versioned fake
//                            bucket that records every request (OpaqueRequestAudit, OpaqueObjectCount,
//                            OpaqueRenameCostsNothing, OpaqueRequestCounts, copies, foreign objects, orphans)

#include "../helpers/bytes.hpp"
#include "../helpers/db_suite.hpp"
#include "../helpers/versioned_bucket.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/seed.hpp>
#include "crypto/util/encrypt.hpp"
#include "crypto/vhf1/Format.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/recovery/ObjectVersion.hpp"
#include "db/query/recovery/Policy.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/sync/RemoteObjectIndex.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/model/File.hpp"
#include "fs/model/file/Trashed.hpp"
#include "ops/RecoveryRecipients.hpp"
#include "recovery/local/Backlog.hpp"
#include "recovery/local/Versions.hpp"
#include "recovery/provider/Restore.hpp"
#include "storage/ObjectKeys.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Planner.hpp"
#include "sync/manifest/Store.hpp"
#include "sync/rotation/Runtime.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/RecoveryEnvelopes.hpp"

#include <functional>
#include <set>

namespace vh::test_opaque_layout {

namespace keys = storage::object_keys;
namespace content = vault::content;
namespace sfs = std::filesystem;
using test_support::versioned::VersionedBucket;
using test_support::versioned::Versioning;
using Bytes = std::vector<uint8_t>;
using vh::test::bin::bytes;
using vh::test::bin::randomBytes;
using vh::test::bin::spit;
using vh::test::bin::str;
using RequestOp = storage::s3::RequestOp;
using Refused = storage::s3::OpaqueRequestRefused;

constexpr uint64_t kMiB = 1024ull * 1024;
constexpr uint64_t kGiB = 1024ull * kMiB;

std::string tag() { return test::uniqueTag('o'); }

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

// ---- OpaqueObjectKeys ---------------------------------------------------------------------------------------------

TEST(OpaqueObjectKeys, KeysAreBuiltParsedAndClassifiedInOnePlace) {
    const auto uid = crypto::id::newObjectUid();
    const auto key = keys::contentKey(uid);
    EXPECT_EQ(key, "o/" + crypto::id::toBase32(uid));
    EXPECT_EQ(keys::uidOfContentKey(key), uid);
    EXPECT_EQ(keys::uidOfContentKey("/" + key), uid) << "scope keys and index paths carry a leading slash";
    EXPECT_FALSE(keys::uidOfContentKey("o/" + lower(crypto::id::toBase32(uid)) + "x"));
    EXPECT_FALSE(keys::uidOfContentKey("o/OO"));

    EXPECT_EQ(keys::classify(key), keys::KeyClass::Content);
    for (const auto* k : {".vaulthalla/layout.json", ".vaulthalla/root"})
        EXPECT_EQ(keys::classify(k), keys::KeyClass::Metadata) << k;
    EXPECT_EQ(keys::classify(".vaulthalla/seg/" + crypto::id::toBase32(uid)), keys::KeyClass::Metadata);
    EXPECT_EQ(keys::classify(".vaulthalla/key/" + crypto::id::toBase32(uid)), keys::KeyClass::Metadata);
    const auto envelopeKey = vl::keykit::kev1::objectKey(vl::keykit::kev1::kid(bytes("any envelope bytes")));
    EXPECT_EQ(keys::classify(envelopeKey), keys::KeyClass::Metadata) << "KEV1 envelopes (#370) are allowlisted";
    EXPECT_EQ(keys::classify(".vaulthalla/probe/" + crypto::id::toBase32(uid)), keys::KeyClass::Metadata)
        << "the bucket capability probe's object (spec 06 §7)";
    for (const auto* k : {"Reports/Q3 board pack.pdf", ".vaulthalla/index-v1.json", ".vaulthalla/seg/nope", "o/",
                          "o/x/y", "/o/abc", ".vaulthalla/probe/Reports"})
        EXPECT_EQ(keys::classify(k), keys::KeyClass::Foreign) << k;

    for (const auto* p : {"", "o/", ".vaulthalla/", ".vaulthalla/seg/"}) EXPECT_TRUE(keys::isAllowedListPrefix(p)) << p;
    EXPECT_TRUE(keys::isAllowedListPrefix(key)) << "the versions of one object";
    for (const auto* p : {"Reports/", "docs", "o/ab"}) EXPECT_FALSE(keys::isAllowedListPrefix(p)) << p;
    EXPECT_EQ(keys::importedPathOf("notes/plain.txt"), "/Imported/notes/plain.txt");
}

TEST(OpaqueObjectKeys, PartSizeGrowsWithTheObjectAndNeverExceeds10000Parts) {
    EXPECT_EQ(keys::partSizeFor(0), 5 * kMiB);
    EXPECT_EQ(keys::partSizeFor(11 * kMiB), 5 * kMiB);
    EXPECT_EQ(keys::partSizeFor(48 * kGiB), 5 * kMiB) << "today's objects keep 5 MiB parts";
    EXPECT_EQ(keys::partSizeFor(60 * kGiB), 7 * kMiB) << "ceil(60 GiB / 10,000) rounded up to a whole MiB";
    for (const uint64_t size : {50 * kGiB, 60 * kGiB, 1024 * kGiB, 5 * 1024 * kGiB, 5 * 1024 * kGiB + 1}) {
        const auto part = keys::partSizeFor(size);
        EXPECT_EQ(part % kMiB, 0u);
        EXPECT_GE(part, 5 * kMiB);
        EXPECT_LE(keys::partCountFor(size, part), keys::kMaxParts) << size;
    }
    EXPECT_GT(keys::partCountFor(60 * kGiB, 5 * kMiB), keys::kMaxParts) << "the fixed 5 MiB part could not do it";
}

// ---- OpaqueRequestPolicy ------------------------------------------------------------------------------------------

TEST(OpaqueRequestPolicy, RefusesNamesMetadataAndForeignKeysBeforeAnythingIsSent) {
    VersionedBucket bucket(Versioning::Enabled);
    bucket.setOpaqueLayout(true);
    const auto object = keys::contentKey(crypto::id::newObjectUid());
    const auto body = bytes("sealed bytes");
    storage::s3::RequestOptions meta;
    meta.metadata = {{"vh-iv", "AAAA"}};
    storage::s3::RequestOptions textType;
    textType.system_headers = {{"Content-Type", "text/plain"}};
    storage::s3::RequestOptions disposition;
    disposition.system_headers = {{"Content-Disposition", "attachment; filename=\"Q3.pdf\""}};
    storage::s3::RequestOptions storageClass;
    storageClass.system_headers = {{"x-amz-storage-class", "STANDARD_IA"}};

    EXPECT_THROW(bucket.uploadBufferWithMetadata("Reports/Q3.pdf", body, storage::s3::RequestOptions{}), Refused);
    EXPECT_THROW(bucket.uploadBufferWithMetadata(object, body, meta), Refused);
    EXPECT_THROW(bucket.uploadBufferWithMetadata(object, body, textType), Refused);
    EXPECT_THROW(bucket.uploadBufferWithMetadata(object, body, disposition), Refused);
    EXPECT_THROW((void)bucket.listObjects("Reports/"), Refused);
    EXPECT_THROW((void)bucket.listObjectVersionsPage("Reports/"), Refused);
    EXPECT_THROW(bucket.setObjectContentHash(object, "abc", storage::s3::RequestOptions{}), Refused);
    EXPECT_THROW(bucket.setObjectEncryptionMetadata(object, "AAAA", 1, storage::s3::RequestOptions{}), Refused);
    EXPECT_THROW(bucket.deleteObject("Reports/Q3.pdf"), Refused);
    EXPECT_EQ(bucket.counters().put + bucket.counters().list + bucket.counters().del + bucket.counters().copy, 0u)
        << "refused before the bucket saw anything";
    EXPECT_TRUE(bucket.keys().empty());

    // What opaque_v1 does send.
    bucket.uploadBufferWithMetadata(object, body, storageClass);
    bucket.uploadBufferWithMetadata(".vaulthalla/root", body, storage::s3::RequestOptions{});
    (void)bucket.listObjects({});
    (void)bucket.listObjects("o/");
    (void)bucket.listObjectVersionsPage(object);
    EXPECT_TRUE(bucket.getHeadObject(object));
    const auto versionId = bucket.history(object).front().version_id;
    bucket.uploadBufferWithMetadata(object, bytes("newer"), storage::s3::RequestOptions{});
    EXPECT_THROW((void)bucket.copyObjectVersion(object, versionId, keys::contentKey(crypto::id::newObjectUid()),
                                                body.size(), storage::s3::RequestOptions{}),
                 Refused)
        << "a copy goes onto its own key only";
    EXPECT_NO_THROW((void)bucket.copyObjectVersion(object, versionId, object, body.size(), storage::s3::RequestOptions{}));

    // A foreign object is read only inside the explicit import scope, and never written.
    (void)bucket.seed("notes/plain.txt", "someone else's");
    Bytes out;
    EXPECT_THROW(bucket.downloadToBuffer("notes/plain.txt", out), Refused);
    {
        const storage::s3::ScopedForeignObjectRead foreign;
        bucket.downloadToBuffer("notes/plain.txt", out);
        EXPECT_EQ(str(out), "someone else's");
        EXPECT_THROW(bucket.uploadBufferWithMetadata("notes/plain.txt", body, storage::s3::RequestOptions{}), Refused);
    }
    EXPECT_THROW(bucket.downloadToBuffer("notes/plain.txt", out), Refused);

    // path_v0 / transparent controllers are untouched by the rules.
    VersionedBucket legacy(Versioning::Unversioned);
    EXPECT_NO_THROW(legacy.uploadBufferWithMetadata("Reports/Q3.pdf", body, meta));
}

// ---- OpaqueMultipart ----------------------------------------------------------------------------------------------

// Counts what a multipart upload sends and keeps none of it: a 60 GiB object without 60 GiB anywhere.
// Records the multipart plan CloudEngine asks for. The 60 GiB of holes are never streamed (that took ~27 s): the
// plan is the subject here, and the driver's split into parts is Controller's (S3DataPathWire, S3VersionedFake).
class PartCounter final : public storage::s3::Controller {
public:
    using Controller::initiateMultipartUpload;
    using Controller::uploadLargeObject;

    PartCounter() : Controller(test_support::versioned::versionedBucketKey(), "vh-part-counter") {}

    mutable std::atomic<uint64_t> initiated{0}, completed{0}, partSize{0}, sourceBytes{0};
    mutable std::string contentKey;

    std::string initiateMultipartUpload(const sfs::path& key, const storage::s3::RequestOptions& options) const override {
        enforceRequestPolicy(RequestOp::Put, key.string(), &options);
        contentKey = key.string();
        ++initiated;
        return "upload-1";
    }

    void uploadLargeObject(const sfs::path& key, const sfs::path& filePath, const uintmax_t part,
                           const storage::s3::RequestOptions& options) const override {
        const auto uploadId = initiateMultipartUpload(key, options);
        partSize = part;
        sourceBytes = sfs::file_size(filePath);
        std::vector<std::string> etags(keys::partCountFor(sourceBytes.load(), part));
        completeMultipartUpload(key, uploadId, etags);
    }

    void completeMultipartUpload(const sfs::path& key, const std::string&, const std::vector<std::string>& etags) const override {
        enforceRequestPolicy(RequestOp::Put, key.string());
        ++completed;
        recordPutOutcomeForTesting({.etag = "\"multi-" + std::to_string(etags.size()) + "\"", .version_id = std::nullopt});
    }
};

TEST(OpaqueMultipart, ASixtyGiBObjectUploadsInAtMost10000Parts) {
    ASSERT_GE(sodium_init(), 0);
    constexpr unsigned kVault = 77;
    constexpr unsigned kKeyVersion = 3;
    const auto key = randomBytes(32, 5);
    const auto em = std::make_shared<vault::EncryptionManager>(vault::EncryptionManager::ForTesting{}, kVault, key,
                                                               kKeyVersion);
    auto s3 = std::make_shared<vault::model::S3Vault>();
    s3->id = kVault;
    s3->encrypt_upstream = true;
    s3->storage_layout = vault::model::StorageLayout::OpaqueV1;
    const auto cloud = std::make_shared<storage::CloudEngine>();
    cloud->vault = s3;
    cloud->encryptionManager = em;
    const auto counter = std::make_shared<PartCounter>();
    cloud->setS3ControllerForTesting(counter);
    ASSERT_TRUE(counter->opaqueLayout());

    // A sparse backing file: a real VHF1 header for this file's uid, then holes up to 60 GiB.
    const auto dir = sfs::temp_directory_path() / ("vh_opaque_60g_" + std::to_string(::getpid()) + "_" + tag());
    sfs::create_directories(dir);
    auto f = std::make_shared<fs::model::File>();
    f->id = 1;
    f->vault_id = kVault;
    f->path = "/huge.bin";
    f->object_uid = crypto::id::newObjectUid();
    f->backing_path = dir / "huge";
    const auto sealed = em->encrypt({}, f);   // the header of a generation of this file
    spit(f->backing_path, Bytes(sealed.begin(), sealed.begin() + crypto::vhf1::kHeaderSize));
    constexpr uint64_t kSize = 60 * kGiB;
    sfs::resize_file(f->backing_path, kSize);
    f->size_bytes = kSize;   // never read: the upload sends the sealed bytes as they are
    f->content_hash = "not-read";

    cloud->upload(f);
    std::error_code ec;
    sfs::remove_all(dir, ec);

    EXPECT_EQ(counter->contentKey, keys::contentKey(*f->object_uid));
    EXPECT_EQ(counter->initiated.load(), 1u);
    EXPECT_EQ(counter->completed.load(), 1u);
    EXPECT_EQ(counter->sourceBytes.load(), kSize) << "the sealed file as it is, one object";
    EXPECT_EQ(counter->partSize.load(), 7 * kMiB) << "not the fixed 5 MiB part";
    EXPECT_LE(keys::partCountFor(kSize, counter->partSize.load()), keys::kMaxParts);
    EXPECT_EQ(f->remote_etag, "\"multi-" + std::to_string(keys::partCountFor(kSize, 7 * kMiB)) + "\"");
}

// ---- DB-backed --------------------------------------------------------------------------------------------------------

class OpaqueLayoutTest : public vh::test::db::Suite {
protected:
    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_opaque_layout", {.freshEngines = false})) return;
        recovery::local::invalidateAllPolicies();
    }
    static void TearDownTestSuite() { tearDownDbSuite(); }

    using Vault = test_support::versioned::CloudVault;

    // An encrypting cloud vault made opaque_v1 before it holds anything (opaque_v1 is internal: test mode only).
    static Vault opaqueVault(const bool localVersioning = false,
                             const sync::model::RemotePolicy::Strategy strategy = sync::model::RemotePolicy::Strategy::Sync) {
        auto v = test_support::versioned::makeCloudVault(superUser, "ol", Versioning::Enabled, true, strategy);
        v.engine->remote_policy()->conflict_policy = sync::model::RemotePolicy::ConflictPolicy::KeepLocal;
        db::Transactions::exec("OpaqueLayoutTest::bucketVersioning", [&](pqxx::work& txn) {
            txn.exec(R"SQL(
                INSERT INTO upstream_bucket (provider, account_ref, bucket, vault_id, versioning_status, versioning_settles_at)
                VALUES ('aws-s3', 'ol-test', $1, $2, 'enabled', now() - interval '1 minute')
                ON CONFLICT (provider, account_ref, bucket) DO UPDATE SET versioning_status = 'enabled'
            )SQL", pqxx::params{v.bucketName, v.id()});
        });
        if (localVersioning) {
            db::query::recovery::PolicyRow row;
            row.vault_id = v.id();
            row.local_versioning = {.enabled = true, .keep_last = std::nullopt, .max_age_days = std::nullopt,
                                    .quota_bytes = std::nullopt};
            db::query::recovery::Policy::upsert(row);
            recovery::local::invalidatePolicy(v.id());
        }
        EXPECT_TRUE(v.engine->opaqueLayout());
        EXPECT_TRUE(v.bucket->opaqueLayout()) << "the controller enforces the request rules";
        return v;
    }

    static std::shared_ptr<fs::model::File> write(const Vault& v, const std::string& path, const Bytes& content) {
        return fs::Filesystem::createFile({.path = path, .fuse_path = v.engine->vaultPathToFusePath(path),
                                           .buffer = content, .engine = v.engine, .user = superUser, .overwrite = true});
    }
    static std::shared_ptr<fs::model::File> write(const Vault& v, const std::string& path, const std::string& content) {
        return write(v, path, bytes(content));
    }

    static void mkdir(const Vault& v, const std::string& path) { v.engine->mkdir(path, superUser); }

    static void rename(const Vault& v, const std::string& from, const std::string& to) {
        ASSERT_EQ(fs::Filesystem::rename(v.engine->vaultPathToFusePath(from), v.engine->vaultPathToFusePath(to),
                                         superUser), 0);
    }

    static std::shared_ptr<fs::model::File> row(const Vault& v, const std::string& path) {
        return db::query::fs::File::getFileByPath(v.id(), path);
    }

    static std::string readLocal(const Vault& v, const std::string& path) {
        const auto reader = v.engine->openPlaintextReader(row(v, path));
        return str(storage::readAll(*reader, 64 << 20));
    }

    // One regular pass inline, as sync::Cloud runs it: the trash purge, the bins, the plan, the transfers, then the
    // index and the manifest. Returns the pass (its plan and tally).
    using Pass = test_support::versioned::SyncPass;
    static Pass pass(const Vault& v) {
        return test_support::versioned::runSyncPass(v.engine, {.purgeTrash = true, .requireOk = true, .expectOk = true});
    }

    static unsigned planned(const Pass& p, const sync::model::ActionType type) {
        return static_cast<unsigned>(std::ranges::count_if(p.plan, [&](const auto& a) { return a.type == type; }));
    }

    // Requests since the last clearRequests(), split by what they touched.
    struct Tally {
        uint64_t object{};        // o/<uid>: PUT (+ multipart parts), GET, HEAD, DELETE, COPY
        uint64_t objectPut{}, objectGet{}, objectHead{}, objectDelete{}, objectCopy{};
        uint64_t rootPut{}, rootHead{}, rootGet{}, segmentPut{}, list{}, other{};
    };
    static Tally tally(const Vault& v) {
        Tally t;
        using Op = VersionedBucket::Op;
        for (const auto& r : v.bucket->requests()) {
            if (r.op == Op::List) {
                ++t.list;
                continue;
            }
            const auto cls = keys::classify(r.key);
            if (cls == keys::KeyClass::Content) {
                ++t.object;
                if (r.op == Op::Put) ++t.objectPut;
                if (r.op == Op::Get) ++t.objectGet;
                if (r.op == Op::Head) ++t.objectHead;
                if (r.op == Op::Delete) ++t.objectDelete;
                if (r.op == Op::Copy) ++t.objectCopy;
            } else if (r.key == ".vaulthalla/root") {
                if (r.op == Op::Put) ++t.rootPut;
                if (r.op == Op::Head) ++t.rootHead;
                if (r.op == Op::Get) ++t.rootGet;
            } else if (r.key.starts_with(".vaulthalla/seg/") && r.op == Op::Put) {
                ++t.segmentPut;
            } else {
                ++t.other;
            }
        }
        return t;
    }

    static std::vector<std::string> contentKeys(const Vault& v) {
        std::vector<std::string> out;
        for (const auto& k : v.bucket->keys())
            if (v.bucket->current(k) && keys::classify(k) == keys::KeyClass::Content) out.push_back(k);
        return out;
    }

    // The object of a file, opened as a reader would: against this vault and the file's uid.
    static std::string remotePlaintext(const Vault& v, const std::shared_ptr<fs::model::File>& f) {
        const auto object = v.bucket->current(keys::contentKey(*f->object_uid));
        if (!object) throw std::runtime_error("no object for " + f->path.string());
        auto remote = std::make_shared<fs::model::File>(*f);
        remote->encryption_iv.clear();
        remote->encrypted_with_key_version = 0;
        return str(v.engine->decryptRemotePayload(f->path, object->body, remote));
    }

    // Whether an object's header authenticates as the object of this file uid.
    static bool headerNames(const Vault& v, const Bytes& object, const crypto::id::ObjectUid& uid) {
        try {
            (void)crypto::vhf1::openHeader(
                object, {.kind = crypto::vhf1::Kind::FileContent, .vaultUid = v.engine->encryptionManager->vaultUid(),
                         .objectUid = uid, .generation = std::nullopt},
                [&](const uint32_t version) { return v.engine->encryptionManager->historicalKeySnapshot(version); });
            return true;
        } catch (const crypto::vhf1::Error&) {
            return false;
        }
    }
};

// Spec 01 §8 OpaqueRequestAudit: create, overwrite, rename, move, copy, delete, rotate, backlog replay, provider
// restore and manifest publish; no request carries a path, a name, x-amz-meta-* or a plaintext-derived value, every
// key matches the allowlist, and no stored byte holds a name or the plaintext.
TEST_F(OpaqueLayoutTest, OpaqueRequestAudit) {
    const auto v = opaqueVault(/*localVersioning=*/true);
    // A recovery recipient (#370): its KEV1 envelopes go to the same bucket (.vaulthalla/key/<kid>), under the same
    // request rules, at enrollment and at every rotation.
    vault::envelopes::setStoreFactoryForTesting([bucket = v.bucket](uint32_t) -> std::shared_ptr<sync::manifest::ObjectStore> {
        return std::make_shared<sync::manifest::S3Store>(bucket);
    });
    struct ResetEnvelopeStore {
        ~ResetEnvelopeStore() { vault::envelopes::setStoreFactoryForTesting({}); }
    } resetEnvelopeStore;
    const auto seed = vl::keykit::RecoverySeed::generate();
    (void)ops::recovery_recipients::add(superUser, {.vault_id = v.id(),
                                                    .public_key = crypto::util::b64_encode(seed.x25519PublicKey()),
                                                    .label = std::string("Recovery kit")},
                                        ops::vault_keys::Channel::Cli);
    const std::string folder = "/Quarterly Secret Reports";
    const std::string pack = folder + "/Board Pack Quarterly.pdf";
    mkdir(v, folder);
    write(v, pack, "quarterly board pack v1");
    write(v, "/empty-quarterly-marker.txt", "");
    write(v, "/big-quarterly-archive.bin", randomBytes(6 * kMiB, 9));
    (void)pass(v);                                                    // create (and the first publish)

    write(v, pack, "quarterly board pack v2");                        // retains v1 (upstream already)
    write(v, pack, "quarterly board pack v3");                        // retains v2, pending upstream
    (void)pass(v);                                                    // backlog replay of v2, then v3
    write(v, pack, "quarterly board pack v4");
    (void)pass(v);                                                    // overwrite

    rename(v, pack, folder + "/Renamed Quarterly.pdf");               // rename
    (void)pass(v);
    mkdir(v, "/Archive Quarterly");
    rename(v, folder + "/Renamed Quarterly.pdf", "/Archive Quarterly/Renamed Quarterly.pdf");   // move
    (void)pass(v);
    ASSERT_EQ(fs::Filesystem::copy({.from = v.engine->vaultPathToFusePath("/Archive Quarterly/Renamed Quarterly.pdf"),
                                    .to = v.engine->vaultPathToFusePath("/Archive Quarterly/Copy Quarterly.pdf"),
                                    .userId = superUser->id, .engine = v.engine, .authorize = {}}), 0);   // copy
    (void)pass(v);

    // rotate: every file re-sealed under the next key and uploaded, as rotation does.
    v.engine->encryptionManager->prepare_key_rotation();
    const auto deps = sync::rotation::runtimeDeps(v.engine);
    for (const auto& f : db::query::fs::File::listFilesInDir(v.id())) (void)sync::rotation::rotateFile(f, deps);
    v.engine->encryptionManager->finish_key_rotation();
    (void)pass(v);

    // provider restore: an earlier version of the moved file, onto its own object.
    const auto moved = row(v, "/Archive Quarterly/Renamed Quarterly.pdf");
    const auto history = db::query::recovery::ObjectVersion::listForKey(v.id(), keys::contentKey(*moved->object_uid),
                                                                        false, 100);
    ASSERT_GE(history.size(), 4u) << "v1, v2 (replayed), v3, v4 and the rotation";
    const auto older = std::ranges::find_if(history, [](const auto& r) { return !r.is_latest && !r.is_delete_marker; });
    ASSERT_NE(older, history.end());
    const auto plan = recovery::provider::planOne(v.engine, static_cast<uint64_t>(older->id));
    ASSERT_EQ(plan.items.size(), 1u);
    EXPECT_EQ(plan.items[0].destination_path, "/Archive Quarterly/Renamed Quarterly.pdf");
    const auto restored = recovery::provider::restore(v.engine, plan.items[0], plan.items[0].destination_source_id);
    EXPECT_EQ(restored.outcome, "restored") << restored.error.value_or("");
    (void)pass(v);

    // delete: trashed, then purged by the next pass.
    fs::Filesystem::remove(v.engine->vaultPathToFusePath("/big-quarterly-archive.bin"), superUser->id);
    (void)pass(v);
    (void)pass(v);

    // Requests are short: any name fragment, any case. Stored bytes are mostly ciphertext: whole names, exact case
    // (a short pattern would turn up in megabytes of random bytes by chance).
    const std::vector<std::string> names{"quarterly", "secret reports", "board pack", "renamed", "archive", "copy q",
                                         "empty-", "big-", ".pdf", ".txt", ".bin"};
    const std::vector<std::string> wholeNames{"Quarterly Secret Reports", "Board Pack Quarterly", "Renamed Quarterly",
                                              "Archive Quarterly", "Copy Quarterly", "empty-quarterly-marker",
                                              "big-quarterly-archive"};
    const auto leaks = [&](const std::string& text) {
        const auto l = lower(text);
        for (const auto& n : names)
            if (l.find(n) != std::string::npos) return n;
        return std::string{};
    };
    const auto storedLeak = [&](const std::string& body) {
        for (const auto& n : wholeNames)
            if (body.find(n) != std::string::npos) return n;
        return std::string{};
    };
    const auto requests = v.bucket->requests();
    ASSERT_GT(requests.size(), 20u);
    std::set<std::string> headerNames;
    for (const auto& r : requests) {
        SCOPED_TRACE(r.key);
        if (r.op == VersionedBucket::Op::List) {
            EXPECT_TRUE(keys::isAllowedListPrefix(r.key));
        } else {
            EXPECT_TRUE(keys::isAllowedKey(r.key)) << "key outside the allowlist";
        }
        EXPECT_EQ(leaks(r.key), "");
        EXPECT_EQ(leaks(r.second), "");
        EXPECT_TRUE(r.metadata.empty()) << "x-amz-meta-*";
        for (const auto& [name, value] : r.headers) {
            headerNames.insert(lower(name));
            EXPECT_EQ(leaks(value), "") << name;
        }
    }
    for (const auto& h : headerNames)
        EXPECT_TRUE(h == "x-amz-storage-class" || h == "content-type" || h == "if-match" || h == "range") << h;

    // Nothing stored names a file or holds its plaintext; every object carries no metadata.
    for (const auto& k : v.bucket->keys()) {
        EXPECT_TRUE(keys::isAllowedKey(k)) << k;
        for (const auto& version : v.bucket->history(k)) {
            EXPECT_TRUE(version.meta.empty()) << k;
            if (k == ".vaulthalla/layout.json") continue;   // the cleartext hint: layout and vault uid only
            const std::string body(version.body.begin(), version.body.end());
            EXPECT_EQ(storedLeak(body), "") << k;
            EXPECT_EQ(body.find("board pack v"), std::string::npos) << k;
        }
    }
    EXPECT_FALSE(v.bucket->current(".vaulthalla/index-v1.json"));
    const auto envelopes = std::ranges::count_if(v.bucket->keys(), [](const auto& k) {
        return k.starts_with(vl::keykit::kev1::kObjectPrefix);
    });
    EXPECT_GE(envelopes, 2) << "the enrolled recipient's envelopes, for the first key and the rotated one";

    // And it all reads back: the restored generation, the copy, the rotation.
    EXPECT_EQ(readLocal(v, "/Archive Quarterly/Copy Quarterly.pdf"), "quarterly board pack v4");
    EXPECT_EQ(remotePlaintext(v, row(v, "/Archive Quarterly/Copy Quarterly.pdf")), "quarterly board pack v4");
    EXPECT_FALSE(row(v, "/big-quarterly-archive.bin"));
    EXPECT_EQ(recovery::local::backlog::summary(v.id()).pending_versions, 0u);
}

// Spec 01 §8 OpaqueObjectCount: one object per live file (0-byte, small, multipart), provider versions = content
// versions, bounded metadata, no object per AEAD chunk (renames add none: OpaqueRequestCountsMatchSpec01Section5).
TEST_F(OpaqueLayoutTest, OpaqueObjectCount) {
    const auto v = opaqueVault();
    write(v, "/zero.bin", "");
    write(v, "/small.bin", randomBytes(300 * 1024, 1));
    const auto big = randomBytes(11 * kMiB, 2);
    write(v, "/large.bin", big);
    (void)pass(v);
    write(v, "/small.bin", randomBytes(300 * 1024, 3));   // a second content version
    (void)pass(v);

    const auto objects = contentKeys(v);
    EXPECT_EQ(objects.size(), 3u) << "live files";
    uint64_t versions = 0;
    for (const auto& k : objects) versions += v.bucket->history(k).size();
    EXPECT_EQ(versions, 4u) << "3 files, the small one twice";
    const auto large = row(v, "/large.bin");
    const auto largeObject = v.bucket->current(keys::contentKey(*large->object_uid));
    ASSERT_TRUE(largeObject);
    EXPECT_EQ(largeObject->body.size(), content::newSealedSize(big.size())) << "one object, chunks inside it";
    EXPECT_EQ(largeObject->etag.find('-') != std::string::npos, true) << "uploaded in parts";
    EXPECT_EQ(v.bucket->current(keys::contentKey(*row(v, "/zero.bin")->object_uid))->body.size(),
              content::newSealedSize(0));

    // Metadata: the hint, the root, and segments (one per publish here, until the daily collection after 24 h).
    uint64_t segments = 0, other = 0;
    for (const auto& k : v.bucket->keys()) {
        if (!v.bucket->current(k)) continue;
        if (k.starts_with(".vaulthalla/seg/")) ++segments;
        else if (k != ".vaulthalla/root" && k != ".vaulthalla/layout.json" && keys::classify(k) != keys::KeyClass::Content)
            ++other;
    }
    EXPECT_EQ(other, 0u);
    EXPECT_GE(segments, 1u);
    EXPECT_LE(segments, 2u) << "a segment per publish that changed it";
    EXPECT_TRUE(v.bucket->current(".vaulthalla/root"));
    EXPECT_TRUE(v.bucket->current(".vaulthalla/layout.json"));
}

// Spec 01 §8 OpaqueRenameCostsNothing: a 1,000-file folder rename issues 0 object requests (a one-file rename:
// OpaqueRequestCountsMatchSpec01Section5).
TEST_F(OpaqueLayoutTest, OpaqueRenameCostsNothing) {
    const auto v = opaqueVault();
    mkdir(v, "/many");
    for (int i = 0; i < 1000; ++i) write(v, "/many/f" + std::to_string(i) + ".txt", "file " + std::to_string(i));
    const auto first = pass(v);
    EXPECT_EQ(planned(first, sync::model::ActionType::Upload), 1000u);
    (void)pass(v);   // settles (nothing to do)

    v.bucket->clearRequests();
    rename(v, "/many", "/many-renamed");
    const auto p = pass(v);
    EXPECT_TRUE(p.plan.empty());
    const auto t = tally(v);
    EXPECT_EQ(t.object, 0u) << "a 1,000-file folder rename sends no object request";
    EXPECT_EQ(t.rootPut, 1u);
    EXPECT_LE(t.segmentPut, 1u) << "the folder's entry changes one segment";
    EXPECT_EQ(t.list, 0u);
    EXPECT_EQ(readLocal(v, "/many-renamed/f999.txt"), "file 999");
}

// Spec 01 §5: the requests of each operation on opaque_v1 (a one-file rename: no object request, so no object or
// version added; a pass with nothing to do: one HEAD of the root).
TEST_F(OpaqueLayoutTest, OpaqueRequestCountsMatchSpec01Section5) {
    const auto v = opaqueVault();
    write(v, "/seed.txt", "seed");
    (void)pass(v);   // the first pass lists the empty bucket and publishes; collection runs once
    (void)pass(v);

    const auto step = [&](const std::function<void()>& fn) {
        v.bucket->clearRequests();
        fn();
        return tally(v);
    };

    // Upload of a new or changed file: 1 PUT + per pass: changed segment PUT + 1 root PUT (+ the pass's root HEAD).
    auto t = step([&] {
        write(v, "/new.txt", "new");
        (void)pass(v);
    });
    EXPECT_EQ(t.objectPut, 1u);
    EXPECT_EQ(t.object, 1u);
    EXPECT_EQ(t.segmentPut, 1u);
    EXPECT_EQ(t.rootPut, 1u);
    EXPECT_EQ(t.rootHead, 1u);
    EXPECT_EQ(t.rootGet + t.list + t.other, 0u);

    t = step([&] {
        write(v, "/new.txt", "changed");
        (void)pass(v);
    });
    EXPECT_EQ(t.objectPut, 1u);
    EXPECT_EQ(t.object, 1u);
    EXPECT_EQ(t.segmentPut + t.rootPut, 2u);

    // Rename / move of one file: 0 object requests; segment + root PUTs at the next publish.
    t = step([&] {
        rename(v, "/new.txt", "/moved.txt");
        (void)pass(v);
    });
    EXPECT_EQ(t.object, 0u);
    EXPECT_EQ(t.segmentPut + t.rootPut, 2u);

    // A sync pass that changes nothing: HEAD root.
    t = step([&] { (void)pass(v); });
    EXPECT_EQ(v.bucket->requests().size(), 1u);
    EXPECT_EQ(t.rootHead, 1u);

    // Read (hydrate): GET only; the header comes from the catalog (no metadata HEAD).
    const auto f = row(v, "/moved.txt");
    sfs::remove(f->backing_path);
    t = step([&] { EXPECT_EQ(readLocal(v, "/moved.txt"), "changed"); });
    EXPECT_EQ(t.objectGet, 1u);
    EXPECT_EQ(t.objectHead, 0u);
    EXPECT_EQ(v.bucket->requests().size(), 1u);

    // Delete: one DELETE of the object, then a publish.
    t = step([&] {
        fs::Filesystem::remove(v.engine->vaultPathToFusePath("/moved.txt"), superUser->id);
        (void)pass(v);
    });
    EXPECT_EQ(t.objectDelete, 1u);
    EXPECT_EQ(t.object, 1u);
    EXPECT_GE(t.rootPut, 1u);

    // The planner's estimate for an opaque_v1 download needs no HEAD.
    sync::model::Action download{sync::model::ActionType::Download, {}, nullptr, std::make_shared<fs::model::File>()};
    EXPECT_EQ(sync::Planner::estimateS3Cost({download}, true).head_requests, 0u);
    EXPECT_EQ(sync::Planner::estimateS3Cost({download}, false).head_requests, 2u) << "path_v0 unchanged";
}

// Spec 01 §8 OpaqueCopyReseals: a copy is a different object (ETag, header uid) with the same plaintext.
TEST_F(OpaqueLayoutTest, OpaqueCopyReseals) {
    const auto v = opaqueVault();
    write(v, "/orig.txt", "the same plaintext");
    (void)pass(v);
    ASSERT_EQ(fs::Filesystem::copy({.from = v.engine->vaultPathToFusePath("/orig.txt"),
                                    .to = v.engine->vaultPathToFusePath("/copy.txt"), .userId = superUser->id,
                                    .engine = v.engine, .authorize = {}}), 0);
    const auto orig = row(v, "/orig.txt");
    const auto copy = row(v, "/copy.txt");
    ASSERT_TRUE(orig && copy);
    EXPECT_NE(copy->object_uid, orig->object_uid);
    EXPECT_NE(copy->encryption_iv, orig->encryption_iv) << "a new generation";
    EXPECT_EQ(readLocal(v, "/copy.txt"), "the same plaintext");
    (void)pass(v);

    const auto a = v.bucket->current(keys::contentKey(*orig->object_uid));
    const auto b = v.bucket->current(keys::contentKey(*copy->object_uid));
    ASSERT_TRUE(a && b);
    EXPECT_NE(a->etag, b->etag);
    EXPECT_NE(a->body, b->body);
    EXPECT_TRUE(headerNames(v, a->body, *orig->object_uid));
    EXPECT_TRUE(headerNames(v, b->body, *copy->object_uid));
    EXPECT_FALSE(headerNames(v, b->body, *orig->object_uid)) << "the copy's header names the copy";
    EXPECT_EQ(remotePlaintext(v, copy), "the same plaintext");
}

// Reads are bound to the file's uid (mandatory under opaque_v1): another file's object never opens as this one's.
TEST_F(OpaqueLayoutTest, OpaqueReadsRequireTheFilesObjectUid) {
    const auto v = opaqueVault();
    write(v, "/a.txt", "file a");
    write(v, "/b.txt", "file b");
    (void)pass(v);
    const auto a = row(v, "/a.txt");
    const auto b = row(v, "/b.txt");
    const auto objectA = v.bucket->current(keys::contentKey(*a->object_uid));
    ASSERT_TRUE(objectA);
    EXPECT_EQ(remotePlaintext(v, a), "file a");
    // B's row (its uid) holding A's object: refused even without a generation to compare.
    auto asB = std::make_shared<fs::model::File>(*b);
    asB->encryption_iv.clear();
    asB->encrypted_with_key_version = 0;
    EXPECT_THROW((void)v.engine->decryptRemotePayload(b->path, objectA->body, asB), storage::IntegrityError);
    // The provider swapping B's object for A's: the hydrate of B fails authentication and keeps nothing.
    (void)v.bucket->seed(keys::contentKey(*b->object_uid), objectA->body);
    sfs::remove(b->backing_path);
    EXPECT_ANY_THROW((void)readLocal(v, "/b.txt"));
    EXPECT_FALSE(sfs::exists(b->backing_path));
}

// Spec 01 §4.4 foreign objects (default ignore; import once) and orphans.
TEST_F(OpaqueLayoutTest, OpaqueForeignObjectsAndOrphans) {
    const auto v = opaqueVault();
    write(v, "/mine.txt", "mine");
    (void)pass(v);

    // Someone else's object and an o/ object no file names.
    (void)v.bucket->seed("notes/plain.txt", "someone else's text");
    const auto orphanUid = crypto::id::newObjectUid();
    const auto current = v.engine->encryptionManager->currentKey();
    (void)v.bucket->seed(keys::contentKey(orphanUid),
                         content::sealBuffer(bytes("orphan"), *current.key, current.version,
                                             v.engine->encryptionManager->vaultUid(), orphanUid).bytes);
    db::query::sync::RemoteObjectIndex::replaceFromListObjects(v.id(), {});   // the next pass lists the bucket
    v.bucket->clearRequests();
    const auto p = pass(v);
    EXPECT_EQ(p.tally.foreign_ignored, 1u);
    EXPECT_EQ(p.tally.foreign_imported, 0u);
    EXPECT_EQ(p.tally.orphans, 1u);
    EXPECT_EQ(planned(p, sync::model::ActionType::Download) + planned(p, sync::model::ActionType::IndexRemoteOnly) +
                  planned(p, sync::model::ActionType::DeleteRemote),
              0u)
        << "neither downloaded nor deleted";
    for (const auto& r : v.bucket->requests()) EXPECT_NE(r.key, "notes/plain.txt") << "a foreign key is never requested";
    EXPECT_TRUE(v.bucket->current("notes/plain.txt"));
    EXPECT_TRUE(v.bucket->current(keys::contentKey(orphanUid)));
    EXPECT_FALSE(row(v, "/Imported/notes/plain.txt"));

    // import: read as plaintext once, sealed into a new file; the original is left alone.
    const auto imported = v.engine->importForeignObject("notes/plain.txt");
    ASSERT_TRUE(imported);
    EXPECT_EQ(readLocal(v, "/Imported/notes/plain.txt"), "someone else's text");
    EXPECT_FALSE(v.engine->importForeignObject("notes/plain.txt")) << "imported once";
    EXPECT_THROW((void)v.engine->importForeignObject(keys::contentKey(orphanUid)), std::invalid_argument);
    (void)pass(v);
    EXPECT_TRUE(v.bucket->current(keys::contentKey(*row(v, "/Imported/notes/plain.txt")->object_uid)));
    EXPECT_TRUE(v.bucket->current("notes/plain.txt"));
}

// The manifest's object references (#368 left them to the data plane): ETag, version id, sealed size, generation.
TEST_F(OpaqueLayoutTest, OpaqueManifestNamesTheObjectsItsFilesAreStoredIn) {
    const auto v = opaqueVault();
    write(v, "/doc.txt", "document");
    (void)pass(v);
    const auto f = row(v, "/doc.txt");
    const auto object = v.bucket->current(keys::contentKey(*f->object_uid));
    ASSERT_TRUE(object);
    const auto content = db::query::sync::Manifest::collect(v.id());
    const auto entry = std::ranges::find_if(content.entries, [&](const auto& e) {
        return e.uid == crypto::id::toBase32(*f->object_uid);
    });
    ASSERT_NE(entry, content.entries.end());
    ASSERT_TRUE(entry->object);
    EXPECT_EQ(entry->object->etag, object->etag);
    EXPECT_EQ(entry->object->version_id, object->version_id);
    EXPECT_EQ(entry->object->size, object->body.size());
    EXPECT_EQ(entry->format, 1u);
    ASSERT_TRUE(entry->generation);
    EXPECT_EQ(entry->generation->size(), 64u);
    ASSERT_EQ(entry->versions.size(), 1u);
    EXPECT_EQ(entry->versions[0].version_id, object->version_id);
}

// Key rotation's remote re-read of an index-only file (#369 open item, done in #371): the object at o/<uid> must be this
// file's (its header binds the object uid), not another file's sealed object of the same vault planted there.
TEST_F(OpaqueLayoutTest, RotationRereadBindsTheObjectUid) {
    const auto v = opaqueVault();
    const auto a = write(v, "/a.txt", "the file being rotated");
    const auto b = write(v, "/b.txt", "another file of the vault");
    (void)pass(v);
    const auto aKey = keys::contentKey(*row(v, "/a.txt")->object_uid);
    const auto bObject = v.bucket->current(keys::contentKey(*row(v, "/b.txt")->object_uid));
    ASSERT_TRUE(bObject);
    (void)v.bucket->seed(aKey, bObject->body);  // b's sealed bytes under a's key
    const auto aRow = row(v, "/a.txt");
    sfs::remove(aRow->backing_path);            // index-only: rotation re-reads the bucket
    v.engine->encryptionManager->prepare_key_rotation();
    const auto deps = sync::rotation::runtimeDeps(v.engine);
    EXPECT_ANY_THROW((void)sync::rotation::rotateFile(row(v, "/a.txt"), deps));
    EXPECT_EQ(row(v, "/a.txt")->encrypted_with_key_version, aRow->encrypted_with_key_version) << "nothing committed";
    (void)a;
    (void)b;
}

}
