// `vh vault recover` (#371, design/encryption/03-metadata-recovery.md §6, §7, §8).
//
//   VaultRecoverTrustAnchor.*  the D1 rule (vault::recover::prove), every row of §6.2 step 4's table: verified, no
//                              anchor, empty anchor, wrong node, wrong vault, another node's key, self-attested,
//                              key-check mismatch, and a version proven through its recorded origin. Pure.
//   VaultRecoverDb.*           DB-backed, over a versioned fake bucket: an opaque_v1 vault written on "node A",
//                              node A destroyed (its vault, its attestation key, its node id), then rebuilt on a node
//                              that never held it from the bucket plus the customer's kit and/or export: the tree,
//                              trash, provider versions and key provenance; no byte of content until a file is read;
//                              rotation and sync afterwards; a second restore of the same bucket on a third node;
//                              dry run; salvage; missing versions; rollback; wrong material; lost manifest objects.

#include "../helpers/bytes.hpp"
#include "../helpers/db_suite.hpp"
#include "../helpers/versioned_bucket.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/kit.hpp>
#include <vl/keykit/seed.hpp>
#include "cloud/Identity.hpp"
#include "cloud/Signing.hpp"
#include "config/Registry.hpp"
#include "crypto/SecretKey.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/secrets/KeyProvider.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/vault/BucketCapability.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/model/File.hpp"
#include "db/query/cloud/Link.hpp"
#include "ops/CloudRestore.hpp"

#include <vl/keykit/attestation.hpp>
#include "ops/Error.hpp"
#include "ops/RecoveryRecipients.hpp"
#include "ops/VaultKeys.hpp"
#include "ops/VaultRecover.hpp"
#include "storage/BucketCapability.hpp"
#include <vl/vaultfmt/ObjectKeys.hpp>
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Capability.hpp"
#include "storage/s3/ManifestStore.hpp"
#include "storage/s3/curl/Http.hpp"
#include <vl/vaultfmt/manifest/Objects.hpp>
#include <vl/vaultfmt/manifest/Store.hpp>
#include "sync/rotation/Runtime.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/Recover.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "config/Registry.hpp"
#include "db/query/device/Device.hpp"
#include "ops/VaultReplicas.hpp"
#include "sync/vault_manifest/Replicas.hpp"

#include <set>

namespace vh::test_vault_recover {

using json = nlohmann::json;
using Bytes = std::vector<uint8_t>;
using vh::test::bin::bytes;
using vh::test::bin::randomBytes;
using vh::test::bin::str;
namespace rec = vault::recover;
namespace mf = vl::vaultfmt::manifest;
namespace keys = ops::vault_keys;
using test_support::versioned::VersionedBucket;
using test_support::versioned::Versioning;

std::string tag() { return test::uniqueTag('v'); }

// ---- VaultRecoverTrustAnchor: the D1 rule ---------------------------------------------------------------------------

struct Node {
    std::string id;
    Bytes seed;
    Bytes pk;
    unsigned key_id;
};

Node node(const std::string& id, const uint8_t fill, const unsigned keyId) {
    Node n{id, Bytes(32, fill), {}, keyId};
    n.pk = vault::attestation::publicKeyFromSeed(n.seed);
    return n;
}

// The evidence a root (or an export) carries for `version` of `key`, attested by `signer` over (node, vaultId).
rec::Evidence evidenceBy(const Node& signer, const std::string& nodeId, const uint64_t vaultId, const uint32_t version,
                         const crypto::SecretKey& key, const std::string& source = "root") {
    const auto check = vault::keyCheck(key.bytes(), static_cast<unsigned>(vaultId), version);
    const auto sig = vault::attestation::signWithSeed(signer.seed, vault::attestation::message(nodeId, vaultId, version,
                                                                                               check));
    return {source, nodeId, vaultId, check, vault::attestation::Attestation{.key_id = signer.key_id, .signature = sig}};
}

rec::Pins kitPins(const std::vector<const Node*>& keys, std::optional<std::string> nodeId = std::nullopt,
                  std::optional<uint64_t> vaultId = std::nullopt) {
    rec::Pins p;
    p.supplied = true;
    for (const auto* k : keys) p.keys.push_back({k->key_id, k->pk, "kit"});
    p.node_id = std::move(nodeId);
    p.vault_id = vaultId;
    return p;
}

class VaultRecoverTrustAnchor : public ::testing::Test {
protected:
    void SetUp() override { ASSERT_GE(sodium_init(), 0); }
    const Node a = node("00000000-0000-4000-8000-00000000000a", 0x0a, 3);
    const Node b = node("00000000-0000-4000-8000-00000000000b", 0x0b, 1);
    const Node self = node("00000000-0000-4000-8000-0000000000ff", 0xff, 1);
    const crypto::SecretKeyPtr key = crypto::SecretKey::random();
    static constexpr uint32_t kVersion = 2;
    static constexpr uint64_t kVault = 42;
    [[nodiscard]] std::vector<Bytes> selfKeys() const { return {self.pk}; }
    [[nodiscard]] rec::Proof prove(const std::vector<rec::Evidence>& ev, const rec::Pins& pins) const {
        return rec::prove(kVersion, key->bytes(), ev, pins, selfKeys());
    }
};

TEST_F(VaultRecoverTrustAnchor, VerifiedWhenTheOriginalNodesAttestationVerifiesUnderAPinnedKey) {
    const auto p = prove({evidenceBy(a, a.id, kVault, kVersion, *key)}, kitPins({&a}, a.id, kVault));
    EXPECT_EQ(p.verdict, rec::Anchor::Verified) << p.detail;
    ASSERT_TRUE(p.anchor && p.evidence);
    EXPECT_EQ(p.anchor->key_id, 3u);
    EXPECT_EQ(p.evidence->node_id, a.id);
    EXPECT_TRUE(p.canonical());
    // Without the kit's origin pins the key alone anchors it too.
    EXPECT_TRUE(prove({evidenceBy(a, a.id, kVault, kVersion, *key)}, kitPins({&a})).canonical());
    // An export's pinned key is customer material like the kit's.
    auto exportPins = kitPins({});
    exportPins.keys.push_back({a.key_id, a.pk, "export"});
    EXPECT_TRUE(prove({evidenceBy(a, a.id, kVault, kVersion, *key, "export")}, exportPins).canonical());
}

// Spec 03 §6.5: a Mac signs the versions it creates as a server does, with vl-keykit (the code Desktop links): its
// installation id as the node id, the vault id derived from the uid. The restore proves it by the same rule, and
// nothing about a Mac origin is weaker: a missing, flipped or misdirected attestation is still not proof.
TEST_F(VaultRecoverTrustAnchor, AMacOriginIsProvenExactlyAsAServerOriginIs) {
    namespace pv = vl::keykit::provenance;
    const std::string mac = "90y0p85pezmbhweprb138hvynr";  // an installation id: 26 base32 symbols, never a UUID
    vl::keykit::Uid uid{};
    uid[0] = 0x56, uid[1] = 0x48, uid[2] = 0xf1, uid[3] = 0xa2;
    const uint64_t macVault = pv::macOriginVaultId(uid);
    ASSERT_EQ(macVault, 1447621027u);  // key_provenance.json's Mac vector
    const Bytes seed(32, 0x4d);
    const auto pk = pv::attestationPublicKey(seed);
    const auto check = pv::keyCheck(key->bytes(), macVault, kVersion);
    ASSERT_EQ(check, vault::keyCheck(key->bytes(), static_cast<unsigned>(macVault), kVersion));
    const auto sig = pv::attest(seed, mac, macVault, kVersion, check);
    const auto evidence = [&](Bytes signature, const uint64_t vaultId = 0) {
        return rec::Evidence{"export", mac, vaultId ? vaultId : macVault, check,
                             vault::attestation::Attestation{.key_id = 1, .signature = std::move(signature)}};
    };
    auto pins = kitPins({});
    pins.keys.push_back({1, Bytes(pk.begin(), pk.end()), "export"});

    const auto p = prove({evidence(Bytes(sig.begin(), sig.end()))}, pins);
    EXPECT_EQ(p.verdict, rec::Anchor::Verified) << p.detail;
    EXPECT_TRUE(p.canonical());

    Bytes flipped(sig.begin(), sig.end());
    flipped[0] ^= 1;
    EXPECT_EQ(prove({evidence(flipped)}, pins).verdict, rec::Anchor::Unverified);
    EXPECT_EQ(prove({rec::Evidence{"export", mac, macVault, check, std::nullopt}}, pins).verdict, rec::Anchor::Unattested);
    // Signed over another vault id (the Mac's other vault): the key check binds the claimed one, so it doesn't verify.
    const auto other = pv::attest(seed, mac, macVault + 1, kVersion, pv::keyCheck(key->bytes(), macVault + 1, kVersion));
    EXPECT_FALSE(prove({evidence(Bytes(other.begin(), other.end()))}, pins).canonical());
    // Unpinned: no customer material names the Mac's key.
    EXPECT_EQ(prove({evidence(Bytes(sig.begin(), sig.end()))}, rec::Pins{}).verdict, rec::Anchor::NoAnchor);
}

TEST_F(VaultRecoverTrustAnchor, MissingAnchorIsSalvageOnly) {
    const auto p = prove({evidenceBy(a, a.id, kVault, kVersion, *key)}, rec::Pins{});
    EXPECT_EQ(p.verdict, rec::Anchor::NoAnchor);
    EXPECT_FALSE(p.canonical());
    EXPECT_FALSE(p.refused()) << "salvage, not refusal";
}

TEST_F(VaultRecoverTrustAnchor, EmptyAnchorIsSalvageOnly) {
    const auto p = prove({evidenceBy(a, a.id, kVault, kVersion, *key)}, kitPins({}, a.id, kVault));
    EXPECT_EQ(p.verdict, rec::Anchor::EmptyAnchor);
    EXPECT_FALSE(p.canonical());
}

TEST_F(VaultRecoverTrustAnchor, WrongNodeIsSalvageOnlyAndTheReportNamesTheMismatch) {
    // The kit pins another node's key: nothing verifies.
    auto p = prove({evidenceBy(a, a.id, kVault, kVersion, *key)}, kitPins({&b}));
    EXPECT_EQ(p.verdict, rec::Anchor::Unverified);
    EXPECT_NE(p.detail.find("signing key 3"), std::string::npos) << p.detail;
    // The right key, but the kit's origin is another node.
    p = prove({evidenceBy(a, a.id, kVault, kVersion, *key)}, kitPins({&a}, b.id, kVault));
    EXPECT_EQ(p.verdict, rec::Anchor::WrongNode);
    EXPECT_NE(p.detail.find(b.id), std::string::npos) << p.detail;
    // An attestation over another node id than the one the root names doesn't verify.
    p = prove({evidenceBy(a, b.id, kVault, kVersion, *key)}, kitPins({&a}));
    auto forged = evidenceBy(a, b.id, kVault, kVersion, *key);
    forged.node_id = a.id;
    EXPECT_EQ(prove({forged}, kitPins({&a})).verdict, rec::Anchor::Unverified);
}

TEST_F(VaultRecoverTrustAnchor, WrongVaultIsSalvageOnly) {
    // Verifies, but over a vault the kit doesn't pin.
    auto p = prove({evidenceBy(a, a.id, 7, kVersion, *key)}, kitPins({&a}, a.id, kVault));
    EXPECT_EQ(p.verdict, rec::Anchor::WrongVault);
    EXPECT_NE(p.detail.find("vault 7"), std::string::npos) << p.detail;
    // An attestation over vault 7 presented as vault 42's: the key check over 42 matches (the root records it), but
    // the signature does not.
    auto other = evidenceBy(a, a.id, 7, kVersion, *key);
    other.vault_id = kVault;
    other.key_check = vault::keyCheck(key->bytes(), kVault, kVersion);
    EXPECT_EQ(prove({other}, kitPins({&a})).verdict, rec::Anchor::Unverified);
    // Another version's attestation.
    auto v1 = evidenceBy(a, a.id, kVault, kVersion - 1, *key);
    v1.key_check = vault::keyCheck(key->bytes(), kVault, kVersion);
    EXPECT_EQ(prove({v1}, kitPins({&a})).verdict, rec::Anchor::Unverified);
}

TEST_F(VaultRecoverTrustAnchor, SelfAttestedIsNeverProofOfOrigin) {
    // The restoring node re-signed the version and the "anchor" is its own key.
    const auto p = prove({evidenceBy(self, self.id, kVault, kVersion, *key)}, kitPins({&self}, self.id, kVault));
    EXPECT_EQ(p.verdict, rec::Anchor::SelfAttested);
    EXPECT_FALSE(p.canonical());
    // With the original's key pinned as well, only the original's attestation counts.
    EXPECT_EQ(prove({evidenceBy(self, self.id, kVault, kVersion, *key)}, kitPins({&self, &a})).verdict,
              rec::Anchor::SelfAttested);
    EXPECT_TRUE(prove({evidenceBy(self, self.id, kVault, kVersion, *key), evidenceBy(a, a.id, kVault, kVersion, *key)},
                      kitPins({&self, &a}))
                    .canonical());
}

TEST_F(VaultRecoverTrustAnchor, KeyCheckMismatchIsRefused) {
    // The root records another key's check for the version (a planted key, or a damaged one).
    const auto other = crypto::SecretKey::random();
    auto ev = evidenceBy(a, a.id, kVault, kVersion, *other);
    const auto p = prove({ev}, kitPins({&a}, a.id, kVault));
    EXPECT_EQ(p.verdict, rec::Anchor::KeyCheckMismatch);
    EXPECT_TRUE(p.refused());
    EXPECT_FALSE(p.canonical());
}

TEST_F(VaultRecoverTrustAnchor, UnattestedAndUnknownNodeAreSalvageOnly) {
    rec::Evidence bare{"root", a.id, kVault, vault::keyCheck(key->bytes(), kVault, kVersion), std::nullopt};
    EXPECT_EQ(prove({bare}, kitPins({&a})).verdict, rec::Anchor::Unattested);
    EXPECT_EQ(prove({}, kitPins({&a})).verdict, rec::Anchor::Unattested);
    auto noNode = evidenceBy(a, a.id, kVault, kVersion, *key, "export");
    noNode.node_id.clear();
    EXPECT_EQ(prove({noNode}, kitPins({&a})).verdict, rec::Anchor::Unverified);
}

TEST_F(VaultRecoverTrustAnchor, ARecordedOriginAnchorsAVersionAnEarlierRestoreReAttested) {
    // Node B restored the vault (vault 9 there) and re-attested the version; the root also carries A's original.
    auto byB = evidenceBy(b, b.id, 9, kVersion, *key);
    auto origin = evidenceBy(a, a.id, kVault, kVersion, *key, "origin");
    // The customer's old kit pins A only: proven through the origin.
    auto p = prove({byB, origin}, kitPins({&a}, a.id, kVault));
    ASSERT_TRUE(p.canonical()) << p.detail;
    EXPECT_EQ(p.evidence->source, "origin");
    // A kit refreshed from B (vh-recovery kit add-vault) pins B: proven through B's attestation.
    p = prove({byB, origin}, kitPins({&b}, b.id, 9));
    ASSERT_TRUE(p.canonical()) << p.detail;
    EXPECT_EQ(p.evidence->source, "root");
}

TEST_F(VaultRecoverTrustAnchor, PinsComeFromTheKitEntryAndExportsOfThisVault) {
    const auto uid = crypto::id::newObjectUid();
    rec::Material m;
    EXPECT_FALSE(rec::pinsFor(m, uid).supplied);
    m.kit.emplace(vl::keykit::Kit{vl::keykit::RecoverySeed::generate(), {}});
    EXPECT_FALSE(rec::pinsFor(m, uid).supplied) << "a kit that doesn't list the vault pins nothing";
    m.kit->vaults.push_back({uid, a.id, kVault, {}, std::nullopt});
    EXPECT_TRUE(rec::pinsFor(m, uid).supplied);
    EXPECT_TRUE(rec::pinsFor(m, uid).keys.empty()) << "an empty anchor";
    m.kit->vaults.front().attestation_public_keys.push_back({a.key_id, a.pk});
    EXPECT_EQ(rec::pinsFor(m, uid).keys.size(), 1u);
    EXPECT_EQ(rec::pinsFor(m, uid).node_id, a.id);
}

// ---- VaultRecoverDb -------------------------------------------------------------------------------------------------

class VaultRecoverDb : public vh::test::db::Suite {
protected:
    static void SetUpTestSuite() {
        if (!setUpDbSuite("test_vault_recover")) return;
        if (!runtime::Deps::get().fsCache) runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
    }

    static void TearDownTestSuite() { tearDownDbSuite(); }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        vault::attestation::resetForTesting();
    }

    void TearDown() override {
        if (skipTests) return;
        vault::envelopes::setStoreFactoryForTesting({});
        ops::vault_recover::setStoreFactoryForTesting({});
        ops::vault_recover::setEngineHookForTesting({});
        storage::bucket_capability::setControllerFactoryForTesting({});
    }

    // ---- node A: an opaque_v1 vault with history ------------------------------------------------------------------

    struct Origin {
        std::shared_ptr<storage::CloudEngine> engine;
        std::shared_ptr<VersionedBucket> bucket;
        std::string bucketName;
        uint32_t id{};
        std::string name;
        crypto::id::ObjectUid uid{};
        std::string seed = vl::keykit::RecoverySeed::generate().text();  // the kit's seed text
        std::map<std::string, std::string> files;  // path → plaintext (live files)
    };

    static unsigned apiKey() {
        auto key = std::make_shared<vault::model::APIKey>(superUser->id, "vr_key_" + tag(), vault::model::S3Provider::AWS,
                                                          "AKIATESTACCESSKEY000", "secret-value-0000000000000000000000000",
                                                          "us-east-1", "https://s3.example.com");
        return runtime::Deps::get().apiKeyManager->addAPIKey(key);
    }

    static void useBucket(const std::shared_ptr<VersionedBucket>& bucket,
                          const vl::vaultfmt::manifest::WriteCapability mode = vl::vaultfmt::manifest::WriteCapability::Unknown) {
        vault::envelopes::setStoreFactoryForTesting(
            [bucket, mode](uint32_t) { return std::make_shared<storage::s3::ManifestStore>(bucket, mode); });
        ops::vault_recover::setStoreFactoryForTesting(
            [bucket](unsigned, const std::string&) { return std::make_shared<storage::s3::ManifestStore>(bucket); });
        ops::vault_recover::setEngineHookForTesting([bucket](const std::shared_ptr<storage::Engine>& engine) {
            const auto cloud = std::static_pointer_cast<storage::CloudEngine>(engine);
            cloud->setS3ControllerForTesting(bucket);
            cloud->setRemoteFetchGate([](const storage::CloudEngine&, const storage::RemoteFetchRequest&) {
                return std::unique_ptr<storage::RemoteFetchReservation>{};
            });
        });
    }

    // A bucket that answers like Backblaze B2 (spec 06): conditional PUTs refused with 501, versions kept, MD5 ETags.
    // The vault's binding is probed (version_log), and so is the restored vault's (through the controller factory).
    static void likeBackblaze(const Origin& o) {
        o.bucket->conditionalPuts = VersionedBucket::ConditionalPuts::Reject501;
        o.bucket->md5Etags = true;
        db::query::vault::BucketCapability::record(o.id, storage::s3::probeBucket(*o.bucket));
        useBucket(o.bucket, vl::vaultfmt::manifest::WriteCapability::VersionLog);
        storage::bucket_capability::setControllerFactoryForTesting(
            [b = o.bucket](unsigned int, const std::string&) -> std::shared_ptr<storage::s3::Controller> { return b; });
    }

    static Origin origin(const Versioning versioning = Versioning::Enabled, const bool backblaze = false) {
        const auto v = test_support::versioned::makeCloudVault(superUser, "vr", versioning, true);
        Origin o;
        o.engine = v.engine;
        o.bucket = v.bucket;
        o.bucketName = v.bucketName;
        o.id = v.id();
        o.name = v.engine->vault->name;
        o.uid = *v.engine->vault->uid;
        useBucket(o.bucket);
        if (backblaze) likeBackblaze(o);
        return o;
    }

    static void write(Origin& o, const std::string& path, const Bytes& content) {
        (void)fs::Filesystem::createFile({.path = path, .fuse_path = o.engine->vaultPathToFusePath(path), .buffer = content,
                                          .engine = o.engine, .user = superUser, .overwrite = true});
        o.files[path] = str(content);
    }

    // One pass: trash purge, the plan, the uploads (each must succeed), the index and the manifest.
    static void pass(const std::shared_ptr<storage::CloudEngine>& engine) {
        (void)test_support::versioned::runSyncPass(engine, {.purgeTrash = true, .downloads = false, .expectOk = true});
    }

    static void rotate(Origin& o) {
        o.engine->encryptionManager->prepare_key_rotation();
        const auto deps = sync::rotation::runtimeDeps(o.engine);
        for (const auto& f : db::query::fs::File::listFilesInDir(o.id)) (void)sync::rotation::rotateFile(f, deps);
        o.engine->encryptionManager->finish_key_rotation();
        pass(o.engine);
    }

    static void enroll(const Origin& o) {
        (void)ops::recovery_recipients::add(
            superUser, {.vault_id = o.id, .public_key = crypto::util::b64_encode(vl::keykit::RecoverySeed::parse(o.seed).x25519PublicKey()),
                        .label = std::string("Recovery kit")},
            keys::Channel::Cli);
    }

    // A vault with folders, a rename, a trashed file, a purged one (a tombstone) and an empty file; a recipient
    // enrolled after the first rotation; two rotations.
    static Origin populated(const Versioning versioning = Versioning::Enabled, const bool backblaze = false) {
        auto o = origin(versioning, backblaze);
        o.engine->mkdir("/Reports", superUser);
        o.engine->mkdir("/Reports/2026", superUser);
        write(o, "/Reports/2026/q3.pdf", randomBytes(150'000, 1));
        write(o, "/Reports/notes.txt", bytes("board notes"));
        write(o, "/empty.txt", {});
        write(o, "/doomed.txt", bytes("purged soon"));
        write(o, "/trash-me.txt", bytes("in the trash"));
        pass(o.engine);
        rotate(o);
        enroll(o);
        EXPECT_EQ(fs::Filesystem::rename(o.engine->vaultPathToFusePath("/Reports/2026"),
                                         o.engine->vaultPathToFusePath("/Reports/FY26"), superUser),
                  0);
        o.files["/Reports/FY26/q3.pdf"] = o.files.at("/Reports/2026/q3.pdf");
        o.files.erase("/Reports/2026/q3.pdf");
        write(o, "/Reports/notes.txt", bytes("board notes, second draft"));
        fs::Filesystem::remove(o.engine->vaultPathToFusePath("/doomed.txt"), superUser->id);
        o.files.erase("/doomed.txt");
        pass(o.engine);  // purges /doomed.txt (provider versions keep it: a tombstone)
        rotate(o);
        fs::Filesystem::remove(o.engine->vaultPathToFusePath("/trash-me.txt"), superUser->id);
        o.files.erase("/trash-me.txt");
        o.engine->publishRemoteIndexManifest();  // the trash entry, without the pass that would purge it
        return o;
    }

    static json kitOf(const Origin& o, const bool pinKeys = true, const bool checkpoint = true) {
        const auto status = keys::status(superUser, o.id).front();
        vl::keykit::KitVault v;
        v.vault_uid = o.uid;
        v.origin_node_id = status.node_id;
        v.origin_vault_id = o.id;
        if (pinKeys)
            for (const auto& k : status.attestation_public_keys)
                v.attestation_public_keys.push_back({k.key_id, crypto::util::b64_decode(k.public_key)});
        if (checkpoint && status.checkpoint)
            v.checkpoint = vl::keykit::KitCheckpoint{status.checkpoint->epoch, status.checkpoint->root_sha256,
                                                           std::nullopt};
        return vl::keykit::toJson(vl::keykit::Kit{vl::keykit::RecoverySeed::parse(o.seed), {v}});
    }

    static json exportOf(const Origin& o) {
        return keys::toJson(keys::exportVault(superUser, o.id, keys::Channel::Cli), "admin");
    }

    // Destroys node A: its vault (rows, engine, backing store), its attestation keys and node id. What is left is the
    // bucket and what the test captured as customer material: this process is now another node.
    static void becomeAnotherNode(const std::optional<uint32_t> vaultId = std::nullopt) {
        if (vaultId) runtime::Deps::get().storageManager->removeVault(*vaultId);
        db::Transactions::exec("VaultRecoverDb::becomeAnotherNode", [](pqxx::work& txn) {
            for (const auto* t : {"vault_keys", "vault_keys_trashed", "vault_deletion_key"})
                txn.exec(std::string("UPDATE ") + t + " SET attestation_key_id = NULL, attestation = NULL");
            txn.exec("DELETE FROM key_attestation_keys");
            txn.exec("UPDATE device_node SET node_id = gen_random_uuid()::text");
        });
        crypto::secrets::KeyProvider provider(paths::testMode ? "test_key_attest" : "key_attest");
        const auto fresh = vl::keykit::SecretBytes::random(32);
        provider.updateMasterKey(fresh.bytes());
        vault::attestation::resetForTesting();
    }

    static ops::vault_recover::Result recover(const Origin& o, const json* kit, const json* exported,
                                              ops::vault_recover::Request extra = {}) {
        extra.api_key_id = apiKey();
        extra.bucket = o.bucketName;
        extra.kit = kit;
        extra.exported = exported;
        return ops::vault_recover::recover(superUser, extra, keys::Channel::Cli);
    }

    template <typename F>
    static std::string code(F&& f) {
        try {
            (void)f();
        } catch (const ops::Refused& e) {
            return e.code;
        } catch (const ops::NeedsConfirmation& e) {
            return e.code;
        } catch (const ops::Conflict&) {
            return "conflict";
        } catch (const ops::Invalid&) {
            return "invalid";
        } catch (const ops::Denied&) {
            return "denied";
        }
        return "ok";
    }

    static std::string readFile(const std::shared_ptr<storage::Engine>& engine, const std::string& path) {
        const auto f = db::query::fs::File::getFileByPath(engine->vault->id, path);
        if (!f) throw std::runtime_error("no file " + path);
        const auto reader = engine->openPlaintextReader(f);
        return str(storage::readAll(*reader, 64 << 20));
    }

    // The tree as the manifest says it, without what a restore may legitimately change (the producer, ctime, the key
    // records' node-specific provenance).
    static std::map<std::string, std::string> shape(const mf::Content& c) {
        std::map<std::string, std::string> out;
        std::map<std::string, const mf::Entry*> byUid;
        for (const auto& e : c.entries) byUid[e.uid] = &e;
        const auto pathOf = [&](const mf::Entry& e) {
            std::string p = e.name;
            auto parent = e.parent;
            while (parent) {
                const auto it = byUid.find(*parent);
                if (it == byUid.end() || !it->second->parent) break;
                p = it->second->name + "/" + p;
                parent = it->second->parent;
            }
            return "/" + p;
        };
        for (const auto& e : c.entries) {
            if (!e.parent && e.kind == mf::EntryKind::Dir) continue;  // the vault root
            json j{{"kind", std::string(mf::to_string(e.kind))}, {"uid", e.uid}};
            if (e.mode) j["mode"] = *e.mode;
            if (e.kind == mf::EntryKind::File) {
                j["size"] = e.size.value_or(0);
                j["generation"] = e.generation.value_or("");
                j["key_version"] = e.key_version.value_or(0);
                j["mtime"] = e.mtime.value_or("");
                if (e.object) j["object"] = {e.object->size, e.object->etag.value_or(""), e.object->version_id.value_or("")};
                if (e.trashed) j["trashed"] = e.trashed->path.value_or("");
            }
            json versions = json::array();
            for (const auto& v : e.versions) versions.push_back({v.version_id, v.key_version.value_or(0), v.delete_marker});
            j["versions"] = versions;
            if (e.target) j["target"] = *e.target;
            out[e.kind == mf::EntryKind::Tombstone ? "tombstone:" + e.uid : e.trashed ? "trash:" + e.uid : pathOf(e)] =
                j.dump();
        }
        return out;
    }
};

TEST_F(VaultRecoverDb, RestoresTheVaultOnANodeThatNeverHeldItFromTheKit) {
    auto o = populated();
    // Created long before the restore (found by the mirror drill: the restored row took the restore's time, so the two
    // writers' roots disagreed on it and each republished the other's root every pass).
    db::Transactions::exec("backdate", [&](pqxx::work& txn) {
        txn.exec("UPDATE vault SET created_at = '2025-03-04T05:06:07Z' WHERE id = $1", pqxx::params{o.id});
    });
    o.engine->publishRemoteIndexManifest();
    const auto kit = kitOf(o);
    const auto expected = db::query::sync::Manifest::collect(o.id);
    const auto epochBefore = db::query::sync::Manifest::state(o.id).epoch;
    ASSERT_TRUE(epochBefore);
    const auto keysBefore = keys::status(superUser, o.id).front();
    becomeAnotherNode(o.id);

    const auto fsRootFiles = [] {
        return db::Transactions::exec("fs root", [](pqxx::work& txn) {
            return txn.exec("SELECT d.file_count FROM directories d JOIN fs_entry e ON e.id = d.fs_entry_id "
                            "WHERE e.parent_id IS NULL AND e.vault_id IS NULL AND e.path = '/' AND e.name = '/'")
                .one_field_ref().as<int64_t>();
        });
    };
    const auto rootFilesBefore = fsRootFiles();
    o.bucket->clearRequests();
    const auto r = recover(o, &kit, nullptr);
    ASSERT_TRUE(r.written) << r.report.dump(2);
    // The filesystem root counts the restored files, as a written vault's (found by the mirror drill: it went below
    // zero on the restored node's first deletes).
    const auto vaultRootFiles = db::Transactions::exec("vault root", [&](pqxx::work& txn) {
        return txn.exec("SELECT d.file_count FROM directories d JOIN fs_entry e ON e.id = d.fs_entry_id "
                        "WHERE e.vault_id = $1 AND e.path = '/'", pqxx::params{*r.vault_id}).one_field_ref().as<int64_t>();
    });
    EXPECT_GT(vaultRootFiles, 0);
    EXPECT_EQ(fsRootFiles() - rootFilesBefore, vaultRootFiles);
    ASSERT_TRUE(r.vault_id);
    EXPECT_EQ(r.mode, "canonical");
    EXPECT_TRUE(r.key_available) << r.note.value_or("");
    EXPECT_EQ(r.vault_name, o.name);
    EXPECT_EQ(r.report.at("freshness"), "verified") << r.report.at("freshness_report");
    EXPECT_EQ(r.report.at("canonical_versions"), json({1, 2, 3}));
    for (const auto& v : r.report.at("key_versions")) EXPECT_EQ(v.at("verdict"), "verified") << v.dump();

    // Nothing beyond headers, the manifest and envelopes until a file is read (spec 03 §7).
    EXPECT_EQ(r.report.at("downloads").at("content_bytes"), 0);
    for (const auto& req : o.bucket->requests())
        if (req.op == VersionedBucket::Op::Get && vl::vaultfmt::keys::classify(req.key) ==
                                                      vl::vaultfmt::keys::KeyClass::Content)
            ADD_FAILURE() << "a content object was fetched during the restore: " << req.key;

    // The tree, trash, provider versions and tombstones are what node A's manifest said.
    const auto restored = db::query::sync::Manifest::collect(*r.vault_id);
    EXPECT_EQ(shape(restored), shape(expected));
    EXPECT_EQ(restored.vault->name, expected.vault->name);
    EXPECT_EQ(restored.vault->created_at, std::optional<std::string>("2025-03-04T05:06:07Z")) << "the vault's creation";
    ASSERT_TRUE(restored.recovery_policy);
    EXPECT_EQ(restored.recovery_policy->grants.size(), 1u) << "the recipient is enrolled again";

    // Key status: every version present, attested by this node now, its origin recorded.
    const auto status = keys::status(superUser, *r.vault_id).front();
    EXPECT_TRUE(status.key_available);
    EXPECT_EQ(status.version, keysBefore.version);
    EXPECT_TRUE(status.missing_versions.empty());
    for (const auto& n : status.needed_versions) {
        ASSERT_TRUE(n.origin) << "version " << n.version;
        EXPECT_EQ(n.origin->node_id, keysBefore.node_id);
        EXPECT_EQ(n.origin->vault_id, o.id);
        EXPECT_EQ(n.origin->anchor, "kit");
        ASSERT_TRUE(n.attestation);
    }
    EXPECT_NE(status.node_id, keysBefore.node_id);

    // The first publish chains on the loaded root.
    EXPECT_EQ(r.published_epoch, *epochBefore + 1);

    // Reading a file fetches it (once), and its bytes are node A's.
    const auto engine = runtime::Deps::get().storageManager->getEngine(*r.vault_id);
    for (const auto& [path, content] : o.files) EXPECT_EQ(readFile(engine, path), content) << path;

    // The vault rotates and syncs afterwards.
    const auto cloud = std::static_pointer_cast<storage::CloudEngine>(engine);
    cloud->remote_policy()->strategy = sync::model::RemotePolicy::Strategy::Sync;
    Origin b{.engine = cloud, .bucket = o.bucket, .bucketName = o.bucketName, .id = *r.vault_id, .name = o.name, .uid = o.uid, .seed = o.seed,
             .files = o.files};
    write(b, "/after-restore.txt", bytes("written on the new node"));
    rotate(b);
    EXPECT_EQ(keys::status(superUser, b.id).front().version, keysBefore.version + 1);
    for (const auto& [path, content] : b.files) EXPECT_EQ(readFile(engine, path), content) << path;

    // A second restore of the same bucket on a third node, with the customer's original kit (pinning node A only):
    // A's versions are proven through their recorded origin; the version the second node minted is not.
    const auto epochB = db::query::sync::Manifest::state(b.id).epoch;
    becomeAnotherNode(b.id);
    ops::vault_recover::Request dry;
    dry.dry_run = true;
    const auto again = recover(o, &kit, nullptr, dry);
    EXPECT_FALSE(again.written);
    EXPECT_EQ(again.report.at("epoch"), *epochB);
    EXPECT_EQ(again.report.at("canonical_versions"), json({1, 2, 3}));
    EXPECT_EQ(again.report.at("salvageable_versions"), json({4})) << "node B's version needs node B's key pinned";
}

// A snapshot record keeps its uid through a restore (migration 145): the restored recovery_snapshot row carries the
// manifest's uid, so the restored vault's next publish names the same snapshot and a replica merges it by uid.
TEST_F(VaultRecoverDb, ARestoreKeepsEachSnapshotsUid) {
    auto o = origin();
    write(o, "/kept.txt", bytes("in a snapshot"));
    pass(o.engine);
    enroll(o);
    db::Transactions::exec("snapshot", [&](pqxx::work& txn) {
        const auto fileId = txn.exec("SELECT id FROM fs_entry WHERE vault_id = $1 AND path = '/kept.txt'",
                                     pqxx::params{o.id}).one_field_ref().as<int64_t>();
        const auto snap = txn.exec("INSERT INTO recovery_snapshot (vault_id, name, root_path, root_type, state) "
                                   "VALUES ($1, 'before restore', '/', 'directory', 'ready') RETURNING id",
                                   pqxx::params{o.id}).one_field_ref().as<int64_t>();
        auto storage = crypto::id::toUuid(crypto::id::newObjectUid());
        std::erase(storage, '-');
        const auto blob = txn.exec("INSERT INTO recovery_blob (vault_id, storage_name, key_version, cipher_bytes, "
                                   "  plaintext_bytes) VALUES ($1, $2, 1, 30, 10) RETURNING id",
                                   pqxx::params{o.id, storage}).one_field_ref().as<int64_t>();
        txn.exec("INSERT INTO file_versions (vault_id, file_id, snapshot_id, blob_id, version_number, size_bytes, path, "
                 "  rel_path) VALUES ($1, $2, $3, $4, 1, 10, '/kept.txt', 'kept.txt')",
                 pqxx::params{o.id, fileId, snap, blob});
    });
    o.engine->publishRemoteIndexManifest();
    const auto before = db::query::sync::Manifest::collect(o.id);
    ASSERT_EQ(before.snapshots.size(), 1u);
    const auto snapshotUid = before.snapshots[0].uid;
    ASSERT_FALSE(snapshotUid.empty());
    const auto kit = kitOf(o);
    becomeAnotherNode(o.id);
    const auto r = recover(o, &kit, nullptr);
    ASSERT_TRUE(r.written) << r.report.dump(2);
    const auto restored = db::query::sync::Manifest::collect(*r.vault_id);
    ASSERT_EQ(restored.snapshots.size(), 1u);
    EXPECT_EQ(restored.snapshots[0].uid, snapshotUid);
    EXPECT_EQ(restored.snapshots[0].name, "before restore");
}

TEST_F(VaultRecoverDb, OnABackblazeLikeBucketTheRestoreTakesTheCanonicalHeadAndPublishesOnIt) {
    // Spec 06 §5: an opaque_v1 vault on a bucket without conditional writes publishes its root as versions; a restore
    // reads the canonical head by rule C1 although a losing sibling and a delete marker sit above it, and its first
    // publish (in version_log mode, after the restore's probe) chains on it and takes the vault over.
    auto o = populated(Versioning::Enabled, /*backblaze=*/true);
    ASSERT_EQ(db::query::vault::BucketCapability::get(o.id).capability, vl::vaultfmt::manifest::WriteCapability::VersionLog);
    const auto state = db::query::sync::Manifest::state(o.id);
    ASSERT_TRUE(state.epoch);
    ASSERT_TRUE(state.root_version_id) << "the origin published its roots as versions";
    EXPECT_EQ(o.bucket->current(std::string(mf::kRootKey))->version_id, *state.root_version_id);
    const auto kit = kitOf(o);
    const auto expected = db::query::sync::Manifest::collect(o.id);

    // A crashed writer's sibling of the head (same epoch and prev, later in the provider's order) and a marker.
    const auto lookup = [&](const uint32_t v) { return o.engine->encryptionManager->historicalKeySnapshot(v); };
    auto sibling = mf::openRoot(o.bucket->version(std::string(mf::kRootKey), *state.root_version_id)->body, o.uid, lookup);
    sibling.published_at = "2031-01-01T00:00:00Z";
    sibling.vault->name = "a sibling that lost";
    const auto k = o.engine->encryptionManager->currentKey();
    const auto siblingId = o.bucket->seed(std::string(mf::kRootKey), mf::sealRoot(sibling, o.uid, {k.version, k.key}));
    (void)o.bucket->seedDeleteMarker(std::string(mf::kRootKey));
    becomeAnotherNode(o.id);

    const auto r = recover(o, &kit, nullptr);
    ASSERT_TRUE(r.written) << r.report.dump(2);
    ASSERT_TRUE(r.vault_id);
    EXPECT_EQ(r.mode, "canonical");
    EXPECT_EQ(r.report.at("epoch"), *state.epoch) << "the canonical head, not the sibling above it";
    const auto restored = db::query::sync::Manifest::collect(*r.vault_id);
    EXPECT_EQ(shape(restored), shape(expected));
    EXPECT_EQ(restored.vault->name, expected.vault->name);
    EXPECT_EQ(db::query::vault::BucketCapability::get(*r.vault_id).capability, vl::vaultfmt::manifest::WriteCapability::VersionLog);

    // The first publish settles on the head, as this node alone (a restore takes the vault over).
    ASSERT_TRUE(r.published_epoch) << r.note.value_or("");
    EXPECT_EQ(*r.published_epoch, *state.epoch + 1);
    const auto after = db::query::sync::Manifest::state(*r.vault_id);
    ASSERT_TRUE(after.root_version_id);
    EXPECT_EQ(after.own_epoch, after.epoch);
    const auto current = o.bucket->current(std::string(mf::kRootKey));
    ASSERT_TRUE(current);
    EXPECT_EQ(current->version_id, *after.root_version_id) << "the new root is the current version again";
    const auto engine = runtime::Deps::get().storageManager->getEngine(*r.vault_id);
    const auto cloud = std::static_pointer_cast<storage::CloudEngine>(engine);
    const auto newRoot = mf::openRoot(current->body, o.uid, [&](const uint32_t v) {
        return cloud->encryptionManager->historicalKeySnapshot(v);
    });
    EXPECT_EQ(newRoot.publish, std::string(mf::kPublishVersionLog));
    ASSERT_TRUE(newRoot.writers);
    EXPECT_EQ(newRoot.writers->size(), 1u);
    EXPECT_NE(newRoot.writers->front(), sibling.producer.node_id) << "the old node is no longer a writer";
    EXPECT_FALSE(o.bucket->version(std::string(mf::kRootKey), siblingId))
        << "repaired: deleted by id after the restored node's first listing (spec 06 §5.4)";
    EXPECT_FALSE(o.bucket->history(std::string(mf::kRootKey)).front().delete_marker);

    // Files read back; the vault rotates, enrolls another recipient and syncs on the version_log bucket.
    for (const auto& [path, content] : o.files) EXPECT_EQ(readFile(engine, path), content) << path;
    cloud->remote_policy()->strategy = sync::model::RemotePolicy::Strategy::Sync;
    Origin b{.engine = cloud, .bucket = o.bucket, .bucketName = o.bucketName, .id = *r.vault_id, .name = o.name,
             .uid = o.uid, .seed = vl::keykit::RecoverySeed::generate().text(), .files = o.files};
    write(b, "/after-restore.txt", bytes("written on the new node"));
    const auto versionBefore = keys::status(superUser, b.id).front().version;
    rotate(b);
    enroll(b);
    pass(b.engine);
    EXPECT_EQ(keys::status(superUser, b.id).front().version, versionBefore + 1);
    const auto last = db::query::sync::Manifest::state(b.id);
    EXPECT_GT(*last.epoch, *after.epoch);
    EXPECT_EQ(o.bucket->current(std::string(mf::kRootKey))->version_id, *last.root_version_id);
    const auto final = db::query::sync::Manifest::collect(b.id);
    ASSERT_TRUE(final.recovery_policy);
    EXPECT_EQ(final.recovery_policy->grants.size(), 2u) << "the restored recipient and the new one";
    for (const auto& [path, content] : b.files) EXPECT_EQ(readFile(engine, path), content) << path;
}

// vh vault join (replicated vaults, experimental): the restore in join mode. The other server's node stays a writer and
// this one is added by the first publish; the flag, the channel, a second copy of the uid are refused.
TEST_F(VaultRecoverDb, AJoinIsARestoreThatAddsThisNodeToTheWritersAndKeepsTheOthers) {
    auto o = populated();
    const auto kit = kitOf(o);
    // An object no live entry names (here: a purged file's, put back as a shared purge keeps it for the orphan
    // collection): a restore places it under /Recovered, a join leaves it to the writers (the cloud drill found joined
    // servers uploading /Recovered/<uid> into the shared vault).
    write(o, "/purged.txt", bytes("purged on A, kept in the bucket"));
    pass(o.engine);
    const auto purged = db::query::fs::File::getFileByPath(o.id, "/purged.txt");
    ASSERT_TRUE(purged && purged->object_uid);
    const auto purgedKey = vl::vaultfmt::keys::contentKey(*purged->object_uid);
    const auto kept = o.bucket->current(purgedKey);
    ASSERT_TRUE(kept);
    fs::Filesystem::remove(o.engine->vaultPathToFusePath("/purged.txt"), superUser->id);
    o.files.erase("/purged.txt");
    pass(o.engine);
    (void)o.bucket->seed(purgedKey, kept->body);
    const auto nodeA = db::query::device::Devices::nodeId();
    becomeAnotherNode(o.id);
    const auto nodeB = db::query::device::Devices::nodeId();
    ASSERT_NE(nodeA, nodeB);
    ops::vault_recover::Request req;
    req.api_key_id = apiKey();
    req.bucket = o.bucketName;
    req.kit = &kit;
    EXPECT_EQ(code([&] { return ops::vault_replicas::join(superUser, req, keys::Channel::Cli); }), "replicas_experimental");
    struct Flag {
        Flag() { set(true); }
        ~Flag() { set(false); }
        static void set(const bool on) {
            auto cfg = config::Registry::get();
            cfg.sync.replicas.experimental = on;
            config::Registry::set(cfg);
        }
    } flag;
    EXPECT_EQ(code([&] { return ops::vault_replicas::join(superUser, req, keys::Channel::Agent); }), "denied");
    auto dry = req;
    dry.dry_run = true;
    EXPECT_EQ(code([&] { return ops::vault_replicas::join(superUser, dry, keys::Channel::Cli); }), "ok");
    EXPECT_TRUE(ops::vault_replicas::join(superUser, dry, keys::Channel::Cli).report.at("orphans").empty());
    EXPECT_FALSE(recover(o, &kit, nullptr, dry).report.at("orphans").empty()) << "a restore still recovers it";

    const auto r = ops::vault_replicas::join(superUser, req, keys::Channel::Cli);
    ASSERT_TRUE(r.written) << r.report.dump(2);
    ASSERT_TRUE(r.vault_id);
    const auto state = db::query::sync::Manifest::state(*r.vault_id);
    EXPECT_EQ(state.writers, (std::vector<std::string>{nodeA, nodeB})) << "the other writer kept, this one added";
    EXPECT_FALSE(state.writers_change) << "the join's root is recorded";
    EXPECT_EQ(r.published_epoch, state.epoch);
    EXPECT_TRUE(sync::replicas::replicated(*r.vault_id));
    const auto engine = runtime::Deps::get().storageManager->getEngine(*r.vault_id);
    for (const auto& [path, content] : o.files) EXPECT_EQ(readFile(engine, path), content) << path;
    EXPECT_TRUE(r.report.at("orphans").empty());
    EXPECT_TRUE(db::query::fs::File::listFilesInDir(*r.vault_id, "/Recovered").empty()) << "nothing placed";
    EXPECT_FALSE(db::query::fs::File::getFileByPath(*r.vault_id, "/purged.txt"));

    EXPECT_EQ(code([&] { return ops::vault_replicas::join(superUser, req, keys::Channel::Cli); }), "conflict")
        << "the bucket is held here with that key already";
    EXPECT_EQ(code([&] { return recover(o, &kit, nullptr); }), "vault_uid_exists") << "no second copy of the vault";
    // Through another key for the same bucket: the vault's uid is held here (no second copy).
    auto other = req;
    other.api_key_id = apiKey();
    EXPECT_EQ(code([&] { return ops::vault_replicas::join(superUser, other, keys::Channel::Cli); }), "vault_uid_exists");
    EXPECT_THROW(engine->encryptionManager->prepare_key_rotation(), ops::Refused) << "a replica doesn't rotate";
}

TEST_F(VaultRecoverDb, DryRunWritesNothing) {
    auto o = populated();
    const auto kit = kitOf(o);
    becomeAnotherNode(o.id);
    const auto vaultsBefore = db::query::vault::Vault::listVaults().size();
    const auto putsBefore = o.bucket->counters().put;
    ops::vault_recover::Request req;
    req.dry_run = true;
    const auto r = recover(o, &kit, nullptr, req);
    EXPECT_TRUE(r.dry_run);
    EXPECT_FALSE(r.written);
    EXPECT_FALSE(r.vault_id);
    EXPECT_EQ(r.mode, "canonical");
    EXPECT_GT(r.report.at("counts").at("files"), 0);
    EXPECT_EQ(db::query::vault::Vault::listVaults().size(), vaultsBefore);
    EXPECT_EQ(o.bucket->counters().put, putsBefore) << "a dry run writes nothing to the bucket either";
}

TEST_F(VaultRecoverDb, UnprovenVersionsStopTheRestoreAndSalvageReEncryptsWithoutStoringTheKey) {
    auto o = populated();
    const auto empty = kitOf(o, /*pinKeys=*/false);
    becomeAnotherNode(o.id);
    EXPECT_EQ(code([&] { return recover(o, &empty, nullptr); }), "salvage_required");
    ops::vault_recover::Request dry;
    dry.dry_run = true;
    const auto plan = recover(o, &empty, nullptr, dry);
    for (const auto& v : plan.report.at("key_versions")) EXPECT_EQ(v.at("verdict"), "empty_anchor") << v.dump();

    ops::vault_recover::Request salvage;
    salvage.salvage = true;
    EXPECT_EQ(code([&] { return recover(o, &empty, nullptr, salvage); }), ops::vault_recover::RECOVER_SALVAGE);
    salvage.confirm_name = o.name;
    const auto r = recover(o, &empty, nullptr, salvage);
    ASSERT_TRUE(r.written) << r.report.dump(2);
    EXPECT_EQ(r.mode, "salvage");
    ASSERT_TRUE(r.salvage) << r.note.value_or("");
    EXPECT_EQ(r.salvage->new_version, 4u) << "above every version the bucket names";
    EXPECT_EQ(r.salvage->unrecoverable, 0u);
    // Only the fresh key is stored: none of the supplied versions.
    const auto status = keys::status(superUser, *r.vault_id).front();
    EXPECT_EQ(status.version, 4u);
    EXPECT_TRUE(db::query::vault::Key::retiredKeyVersions(*r.vault_id).empty());
    const auto engine = runtime::Deps::get().storageManager->getEngine(*r.vault_id);
    for (const auto& [path, content] : o.files) EXPECT_EQ(readFile(engine, path), content) << path;
}

TEST_F(VaultRecoverDb, AnExportFromBeforeARotationReportsLaterVersionsMissing) {
    auto o = origin();
    write(o, "/a.txt", bytes("version one"));
    pass(o.engine);
    const auto exported = exportOf(o);  // version 1 only
    rotate(o);
    write(o, "/b.txt", bytes("sealed under version two"));
    pass(o.engine);
    becomeAnotherNode(o.id);

    ops::vault_recover::Request dry;
    dry.dry_run = true;
    const auto plan = recover(o, nullptr, &exported, dry);
    bool sawMissing = false;
    for (const auto& v : plan.report.at("key_versions"))
        if (v.at("version") == 2) {
            EXPECT_EQ(v.at("state"), "missing");
            sawMissing = true;
        } else {
            EXPECT_EQ(v.at("state"), "canonical") << v.dump() << " (the export pins its node's key)";
        }
    EXPECT_TRUE(sawMissing) << plan.report.dump(2);
    EXPECT_EQ(code([&] { return recover(o, nullptr, &exported); }), "salvage_required") << "never invented";
}

TEST_F(VaultRecoverDb, ARollbackIsRefusedAgainstTheKitsCheckpointUnlessAccepted) {
    auto o = origin();
    write(o, "/a.txt", bytes("one"));
    pass(o.engine);
    enroll(o);
    o.engine->publishRemoteIndexManifest();
    const auto older = o.bucket->current(std::string(mf::kRootKey));
    ASSERT_TRUE(older);
    write(o, "/b.txt", bytes("two"));
    pass(o.engine);
    const auto kit = kitOf(o);           // checkpoint: the newer root
    const auto noCheckpoint = kitOf(o, true, false);
    becomeAnotherNode(o.id);
    (void)o.bucket->seed(std::string(mf::kRootKey), older->body);  // the bucket presents the older root

    EXPECT_EQ(code([&] { return recover(o, &kit, nullptr); }), "rollback");
    ops::vault_recover::Request req;
    req.dry_run = true;
    req.accept_rollback = true;
    auto r = recover(o, &kit, nullptr, req);
    EXPECT_EQ(r.report.at("freshness"), "rollback_accepted");
    req.accept_rollback = false;
    r = recover(o, &noCheckpoint, nullptr, req);
    EXPECT_EQ(r.report.at("freshness"), "unverified");
    EXPECT_EQ(r.report.at("freshness_report"), std::string(mf::kFreshnessUnverified));
}

TEST_F(VaultRecoverDb, AWrongSeedOrAnotherVaultsKitIsRefused) {
    auto o = origin();
    write(o, "/a.txt", bytes("one"));
    pass(o.engine);
    enroll(o);
    auto kit = kitOf(o);
    becomeAnotherNode(o.id);
    // A kit for another vault.
    auto other = kit;
    other["vaults"][0]["vault_uid"] = vl::keykit::toBase32(crypto::id::newObjectUid());
    EXPECT_EQ(code([&] { return recover(o, &other, nullptr); }), "kit_vault_mismatch");
    // The right vault, another seed.
    auto wrongSeed = kit;
    wrongSeed["recovery_seed"] = vl::keykit::RecoverySeed::generate().text();
    EXPECT_EQ(code([&] { return recover(o, &wrongSeed, nullptr); }), "recovery_material_mismatch");
    EXPECT_EQ(code([&] { return recover(o, nullptr, nullptr); }), "invalid");
}

TEST_F(VaultRecoverDb, ADeletedRootFallsBackToItsProviderVersionOrABlindRebuild) {
    // Versioned: the newest authentic root among the provider's versions.
    {
        auto o = populated(Versioning::Enabled);
        const auto kit = kitOf(o, true, false);
        becomeAnotherNode(o.id);
        (void)o.bucket->seedDeleteMarker(std::string(mf::kRootKey));
        ops::vault_recover::Request dry;
        dry.dry_run = true;
        const auto r = recover(o, &kit, nullptr, dry);
        EXPECT_FALSE(r.report.at("blind"));
        EXPECT_EQ(r.mode, "canonical");
        const auto issues = r.report.at("issues").dump();
        EXPECT_NE(issues.find("provider version"), std::string::npos) << issues;
    }
    // Unversioned: blind. The kit's envelopes hold the keys, but with no root nothing carries the attestations: an
    // export (customer material that does) makes them canonical; content lands under /Recovered.
    {
        auto o = populated(Versioning::Unversioned);
        const auto kit = kitOf(o, true, false);
        const auto exported = exportOf(o);
        becomeAnotherNode(o.id);
        o.bucket->deleteObject(std::string(mf::kRootKey));
        EXPECT_EQ(code([&] { return recover(o, &kit, nullptr); }), "salvage_required");
        const auto r = recover(o, &kit, &exported);
        ASSERT_TRUE(r.written) << r.report.dump(2);
        EXPECT_TRUE(r.report.at("blind"));
        EXPECT_EQ(r.mode, "canonical");
        const auto engine = runtime::Deps::get().storageManager->getEngine(*r.vault_id);
        std::multiset<std::string> contents, expected;
        for (const auto& f : db::query::fs::File::listFilesInDir(*r.vault_id, "/Recovered")) {
            if (f->size_bytes == 0) continue;
            contents.insert(readFile(engine, f->path.string()));
        }
        for (const auto& [_, content] : o.files)
            if (!content.empty()) expected.insert(content);
        expected.insert("in the trash");  // its object is still in the bucket: content is never lost
        EXPECT_EQ(contents, expected);
    }
}

TEST_F(VaultRecoverDb, ACorruptSegmentLeavesItsFilesUnderRecovered) {
    auto o = populated(Versioning::Unversioned);
    const auto kit = kitOf(o, true, false);
    // The segment the current root pins (older roots' segments are still in the bucket until GC).
    const auto rootObject = o.bucket->current(std::string(mf::kRootKey));
    ASSERT_TRUE(rootObject);
    const auto root = mf::openRoot(rootObject->body, o.uid, [&](const uint32_t v) {
        return o.engine->encryptionManager->historicalKeySnapshot(v);
    });
    ASSERT_FALSE(root.segments.empty());
    const auto segment = mf::segmentKey(root.segments.front().sid);
    becomeAnotherNode(o.id);
    auto body = o.bucket->current(segment)->body;
    body[body.size() / 2] ^= 0x5a;
    (void)o.bucket->seed(segment, body);
    const auto r = recover(o, &kit, nullptr);
    ASSERT_TRUE(r.written) << r.report.dump(2);
    const auto issues = r.report.at("issues").dump();
    EXPECT_NE(issues.find("segment"), std::string::npos) << issues;
    EXPECT_FALSE(r.report.at("orphans").empty()) << "the range's objects are found by their headers";
    const auto engine = runtime::Deps::get().storageManager->getEngine(*r.vault_id);
    std::multiset<std::string> contents, expected;
    for (const auto& f : db::query::fs::File::listFilesInDir(*r.vault_id, "/Recovered"))
        if (f->size_bytes) contents.insert(readFile(engine, f->path.string()));
    for (const auto& [_, content] : o.files)
        if (!content.empty()) expected.insert(content);
    expected.insert("in the trash");
    EXPECT_EQ(contents, expected);
}

// ---- Restoring with keys relayed through Vaulthalla Cloud (`vh vault recover --from-cloud`, ops::cloud_restore) -------
//
// What the cloud holds for the vault is what `vh cloud recovery enroll` sent: the bucket's envelopes and the key
// status's provenance. The deliverer (Desktop in production) opens the envelopes with the recipient it holds (here the
// kit's seed) and re-wraps each key to the restoring server's temporary key. The restore then proves every version
// exactly as for an export: keys the cloud invented are refused and nothing is written.

class VaultRecoverFromCloud : public VaultRecoverDb {
protected:
    void SetUp() override {
        VaultRecoverDb::SetUp();
        if (IsSkipped()) return;
        auto cfg = config::Registry::get();
        previousEndpoint_ = cfg.cloud.endpoint;
        cfg.cloud.endpoint = "https://api.vaulthalla.test";
        config::Registry::set(cfg);
        storage::s3::curl::http::setTransportForTesting(
            [this](const storage::s3::curl::http::Request& r) { return cloud(r); });
        const auto seed = cloud::identity::create();
        db::query::cloud::LinkRow row{.endpoint = "https://api.vaulthalla.test", .status = "pending",
                                      .public_key = cloud::publicKeyOf(seed.bytes()), .name = "restorer",
                                      .request_id = std::string("0123456789abcdefghjkmnpqrs"), .request_expires_at = 0,
                                      .installation_id = std::nullopt, .account_id = std::nullopt,
                                      .requested_by = "admin", .requested_at = 0, .linked_at = std::nullopt};
        ASSERT_TRUE(db::query::cloud::Link::putPending(row));
        ASSERT_TRUE(db::query::cloud::Link::markLinked("0123456789abcdefghjkmnpqrs", "kceypk9vfn5tv6yx5c6qpfebdm", 7, std::nullopt, std::nullopt));
    }
    void TearDown() override {
        if (!skipTests) {
            storage::s3::curl::http::setTransportForTesting(std::nullopt);
            db::query::cloud::Link::clear();
            cloud::identity::destroy();
            auto cfg = config::Registry::get();
            cfg.cloud.endpoint = previousEndpoint_;
            config::Registry::set(cfg);
        }
        VaultRecoverDb::TearDown();
    }

    // The cloud's copy of the vault's records, as enrollment sent them (taken before node A is destroyed).
    void enrolled(const Origin& o) {
        const auto ks = keys::status(superUser, o.id).front();
        records_ = {{"origin", {{"node_id", ks.node_id}, {"vault_id", o.id}}}};
        records_["key_versions"] = versionsOf(ks, o.id);
        json anchors = json::array();
        for (const auto& k : ks.attestation_public_keys) anchors.push_back({{"key_id", k.key_id}, {"public_key", k.public_key}});
        records_["attestation_public_keys"] = anchors;
        // The checkpoint, as `vh cloud recovery enroll` sends it (ops::cloud_recovery).
        records_["checkpoint"] = ks.checkpoint ? json{{"epoch", ks.checkpoint->epoch},
                                                      {"root_sha256", ks.checkpoint->root_sha256}}
                                               : json(nullptr);
        // The deliverer's side: the vault keys, opened from the bucket's envelopes with the recipient's secret.
        const auto sk = vl::keykit::RecoverySeed::parse(o.seed).x25519SecretKey();
        storage::s3::ManifestStore store(o.bucket);
        for (const auto& obj : store.list(std::string(vl::keykit::kev1::kObjectPrefix))) {
            const auto got = store.get(obj.key, std::nullopt);
            try {
                auto u = vl::keykit::kev1::unwrap(got->bytes, sk.bytes(), vl::keykit::kev1::Suite::X25519, o.uid);
                keys_[u.key_version] = Bytes(u.key.bytes().begin(), u.key.bytes().end());
            } catch (const vl::keykit::kev1::Error&) {}
        }
        vaultUid_ = vl::keykit::toBase32(o.uid);
    }

    // Each version as the cloud records it: its check and attestation under the origin they were made under (this
    // node's id and vault id), the attestation with the public key of the key it names.
    static json versionsOf(const keys::KeyStatus& ks, const uint32_t vaultId) {
        json versions = json::array();
        for (const auto& v : ks.needed_versions) {
            json att = nullptr;
            if (v.attestation) {
                att = {{"key_id", v.attestation->key_id}, {"signature", v.attestation->signature}};
                for (const auto& k : ks.attestation_public_keys)
                    if (k.key_id == v.attestation->key_id) att["public_key"] = k.public_key;
            }
            versions.push_back({{"version", v.version}, {"key_check", *v.key_check}, {"attestation", att},
                                {"origin", {{"node_id", ks.node_id}, {"vault_id", vaultId}}}});
        }
        return versions;
    }
    // The deliverer's keys, opened from the bucket's envelopes with the kit's recipient.
    void openKeys(const Origin& o) {
        const auto sk = vl::keykit::RecoverySeed::parse(o.seed).x25519SecretKey();
        storage::s3::ManifestStore store(o.bucket);
        for (const auto& obj : store.list(std::string(vl::keykit::kev1::kObjectPrefix))) {
            const auto got = store.get(obj.key, std::nullopt);
            try {
                auto u = vl::keykit::kev1::unwrap(got->bytes, sk.bytes(), vl::keykit::kev1::Suite::X25519, o.uid);
                keys_[u.key_version] = Bytes(u.key.bytes().begin(), u.key.bytes().end());
            } catch (const vl::keykit::kev1::Error&) {}
        }
    }

    storage::s3::curl::http::Response cloud(const storage::s3::curl::http::Request& r) {
        storage::s3::curl::http::Response res;
        const std::string base = "https://api.vaulthalla.test";
        const auto path = r.url.substr(base.size());
        calls.push_back(r.method + " " + path);
        res.status = 200;
        if (r.method == "POST" && path == "/v1/recovery/restores") {
            const auto body = json::parse(r.body);
            temporaryKey_ = *vl::keykit::base64Decode(body.at("temporary_public_key").get<std::string>());
            EXPECT_EQ(body.at("vault_uid"), vaultUid_);
            // As the cloud's Restores::request (src/recovery/Restore.cpp): intent restore (default) or join; a
            // refusal is the error envelope {error: {code, message, reason, details?}}.
            intent_ = body.value("intent", std::string("restore"));
            if (intent_ != "restore" && intent_ != "join") {
                res.status = 400;
                res.body = json{{"error", {{"code", "invalid_argument"}, {"message", "`intent` is restore or join"},
                                           {"reason", "invalid_intent"}}}}.dump();
                return res;
            }
            if (!refuseWith_.empty()) {
                res.status = refuseWith_ == "not_enrolled" ? 404 : 409;
                json e{{"code", res.status == 404 ? "not_found" : "conflict"}, {"message", "refused"},
                       {"reason", refuseWith_}};
                if (refuseWith_ == "replica_limit") e["details"] = {{"limit", "3"}};
                res.body = json{{"error", e}}.dump();
                return res;
            }
            res.status = 201;
            res.body = json{{"id", "rst0123456789abcdefghjkmnp"}, {"status", "requested"}, {"intent", intent_},
                            {"restore_code", "abcd-ef01-2345-6789"}}.dump();
            return res;
        }
        if (r.method == "GET" && path == "/v1/recovery/restores/rst0123456789abcdefghjkmnp") {
            if (++polls_ < 2 || answer_ != "delivered") {
                res.body = json{{"status", polls_ < 2 ? "approved" : answer_}}.dump();
                return res;
            }
            json bundle = json::array();
            for (const auto& [version, key] : keys_) {
                const auto k = forged_ ? randomBytes(32, version) : key;
                bundle.push_back({{"key_version", version},
                                  {"envelope", vl::keykit::base64Encode(vl::keykit::kev1::wrap(
                                                   k, vl::keykit::kev1::Suite::X25519, version, *vl::keykit::fromBase32(vaultUid_),
                                                   temporaryKey_))}});
            }
            res.body = json{{"status", "delivered"}, {"bundle", bundle}, {"records", records_},
                            {"deliverer", {{"installation_id", "x"}, {"name", "MacBook"}}}}.dump();
            return res;
        }
        if (r.method == "POST" && path.ends_with("/complete")) return res;
        if (r.method == "POST" && path.ends_with("/cancel")) return res;
        res.status = 404;
        return res;
    }

    // What `vh vault recover --from-cloud` does, without the terminal.
    ops::vault_recover::Result restoreFromCloud(const Origin& o, ops::vault_recover::Request extra = {}) {
        const auto started = ops::cloud_restore::start(superUser, vaultUid_, keys::Channel::Cli);
        EXPECT_EQ(started.restore_code, "abcd-ef01-2345-6789");
        std::optional<ops::cloud_restore::Delivered> delivered;
        for (int i = 0; i < 5 && !delivered; ++i) delivered = ops::cloud_restore::poll(superUser, started.restore_id);
        if (!delivered) throw std::runtime_error("not delivered");
        extra.vault_uid = vaultUid_;
        extra.checkpoint = delivered->checkpoint;  // as recover.cpp passes it
        try {
            auto r = recover(o, nullptr, &delivered->exported, extra);
            ops::cloud_restore::complete(superUser, started.restore_id);
            return r;
        } catch (...) {
            ops::cloud_restore::cancel(superUser, started.restore_id);
            throw;
        }
    }

    json records_;
    std::map<uint32_t, Bytes> keys_;
    std::string vaultUid_;
    std::vector<uint8_t> temporaryKey_;
    std::string answer_ = "delivered";
    std::string intent_;
    std::string refuseWith_;   // a reason POST /v1/recovery/restores refuses with
    bool forged_ = false;
    int polls_ = 0;
    std::vector<std::string> calls;
    std::string previousEndpoint_;
};

TEST_F(VaultRecoverFromCloud, RestoresTheVaultWithKeysADeviceRelayedThroughTheCloud) {
    auto o = populated();
    enrolled(o);
    ASSERT_EQ(keys_.size(), 3u);
    becomeAnotherNode(o.id);

    const auto r = restoreFromCloud(o);
    ASSERT_TRUE(r.written) << r.report.dump(2);
    EXPECT_EQ(r.mode, "canonical");
    EXPECT_EQ(r.report.at("canonical_versions"), json({1, 2, 3}));
    for (const auto& v : r.report.at("key_versions")) EXPECT_EQ(v.at("verdict"), "verified") << v.dump();
    ASSERT_FALSE(records_.at("checkpoint").is_null());
    EXPECT_EQ(r.report.at("freshness"), "verified") << "the cloud's checkpoint bounds rollback";
    const auto engine = runtime::Deps::get().storageManager->getEngine(*r.vault_id);
    for (const auto& [path, content] : o.files) EXPECT_EQ(readFile(engine, path), content) << path;
    const auto restoredStatus = keys::status(superUser, *r.vault_id);
    for (const auto& n : restoredStatus.front().needed_versions) {
        ASSERT_TRUE(n.origin) << "version " << n.version;
        EXPECT_EQ(n.origin->anchor, "export");
    }
    EXPECT_EQ(calls.back(), "POST /v1/recovery/restores/rst0123456789abcdefghjkmnp/complete");
    // The temporary key is gone once the restore completed.
    EXPECT_THROW((void)ops::cloud_restore::poll(superUser, "rst0123456789abcdefghjkmnp"), ops::Refused);
}

// vh vault join --from-cloud on a vault with its own bucket (BYOS): the request says intent join, the delivered keys
// are proven as for a restore, and the join keeps the other writer. The cloud's refusals arrive with their reason.
TEST_F(VaultRecoverFromCloud, AJoinAsksForIntentJoinAndKeepsTheOtherWriter) {
    auto o = populated();
    enrolled(o);
    const auto nodeA = db::query::device::Devices::nodeId();
    becomeAnotherNode(o.id);
    auto cfg = config::Registry::get();
    cfg.sync.replicas.experimental = true;
    config::Registry::set(cfg);
    for (const auto* reason : {"replica_limit", "unplaced", "held_by_desktop", "not_enrolled", "already_held"}) {
        refuseWith_ = reason;
        EXPECT_EQ(code([&] { return ops::cloud_restore::start(superUser, vaultUid_, keys::Channel::Cli,
                                                              ops::cloud_restore::Intent::Join); }),
                  reason);
    }
    refuseWith_.clear();
    const auto started = ops::cloud_restore::start(superUser, vaultUid_, keys::Channel::Cli,
                                                   ops::cloud_restore::Intent::Join);
    EXPECT_EQ(intent_, "join");
    std::optional<ops::cloud_restore::Delivered> delivered;
    for (int i = 0; i < 5 && !delivered; ++i) delivered = ops::cloud_restore::poll(superUser, started.restore_id);
    ASSERT_TRUE(delivered);
    ops::vault_recover::Request req;
    req.api_key_id = apiKey();
    req.bucket = o.bucketName;
    req.exported = &delivered->exported;
    req.vault_uid = vaultUid_;
    req.checkpoint = delivered->checkpoint;
    const auto r = ops::vault_replicas::join(superUser, req, keys::Channel::Cli);
    ops::cloud_restore::complete(superUser, started.restore_id);
    ASSERT_TRUE(r.written) << r.report.dump(2);
    const auto writers = db::query::sync::Manifest::state(*r.vault_id).writers;
    EXPECT_EQ(writers, (std::vector<std::string>{nodeA, db::query::device::Devices::nodeId()}));
    cfg.sync.replicas.experimental = false;
    config::Registry::set(cfg);
}

// `vh vault join --from-cloud` checks these before its restore request (the drill found the request, the approval and a
// bucket key all happening before the flag's refusal): nothing reaches the cloud for a join this server refuses.
TEST_F(VaultRecoverFromCloud, AJoinIsRefusedBeforeAnythingIsAskedWithTheFlagOffOrForAnAgent) {
    auto cfg = config::Registry::get();
    cfg.sync.replicas.experimental = false;
    config::Registry::set(cfg);
    const auto before = calls.size();
    EXPECT_EQ(code([&] { ops::vault_replicas::requireJoinAllowed(superUser, keys::Channel::Cli); return 0; }),
              "replicas_experimental");
    cfg.sync.replicas.experimental = true;
    config::Registry::set(cfg);
    EXPECT_EQ(code([&] { ops::vault_replicas::requireJoinAllowed(superUser, keys::Channel::Agent); return 0; }), "denied");
    EXPECT_EQ(code([&] { ops::vault_replicas::requireJoinAllowed(superUser, keys::Channel::Cli); return 0; }), "ok");
    EXPECT_EQ(calls.size(), before) << "no call to the cloud";
    cfg.sync.replicas.experimental = false;
    config::Registry::set(cfg);
}

// A vault restored onto node B, rotated there and enrolled again: the cloud keeps A's records of the versions A made
// and B's of the version B made, each under its own origin, and a restore onto a third node proves every version
// under its own, with no salvage. A version whose origin is misstated proves nothing.
TEST_F(VaultRecoverFromCloud, VersionsOfTwoNodesRestoreCanonicallyEachUnderItsOwnOrigin) {
    auto o = populated();
    enrolled(o);
    becomeAnotherNode(o.id);
    auto r = restoreFromCloud(o);
    ASSERT_TRUE(r.written) << r.report.dump(2);
    const auto engine = std::static_pointer_cast<storage::CloudEngine>(runtime::Deps::get().storageManager->getEngine(*r.vault_id));
    engine->remote_policy()->strategy = sync::model::RemotePolicy::Strategy::Sync;
    Origin b{.engine = engine, .bucket = o.bucket, .bucketName = o.bucketName, .id = *r.vault_id, .name = o.name,
             .uid = o.uid, .seed = o.seed, .files = o.files};
    rotate(b);
    // B's enrollment, as the cloud records it: the versions A recorded stay A's; B's new version is B's.
    const auto ksB = keys::status(superUser, b.id).front();
    const auto bVersions = versionsOf(ksB, b.id);
    auto aVersions = records_.at("key_versions");
    const auto known = aVersions.size();
    for (const auto& v : bVersions)
        if (v.at("version").get<size_t>() > known) aVersions.push_back(v);
    ASSERT_EQ(aVersions.size(), known + 1);
    records_["key_versions"] = aVersions;
    for (const auto& k : ksB.attestation_public_keys)
        records_["attestation_public_keys"].push_back({{"key_id", k.key_id}, {"public_key", k.public_key}});
    keys_.clear();
    openKeys(b);
    ASSERT_EQ(keys_.size(), known + 1);
    const auto good = records_;

    // Node C restores it: every version canonical, A's under A's origin and B's under B's.
    becomeAnotherNode(b.id);
    polls_ = 0;
    auto c = restoreFromCloud(b);
    ASSERT_TRUE(c.written) << c.report.dump(2);
    EXPECT_EQ(c.mode, "canonical") << c.report.dump(2);
    EXPECT_EQ(c.report.at("canonical_versions").size(), known + 1);
    for (const auto& v : c.report.at("key_versions")) EXPECT_EQ(v.at("verdict"), "verified") << v.dump();
    for (const auto& [path, content] : o.files)
        EXPECT_EQ(readFile(runtime::Deps::get().storageManager->getEngine(*c.vault_id), path), content) << path;

    // Misstated origins, each restored onto a fresh node: B's version claimed under A's origin, and that origin swapped
    // with an A version's. B's version is then proven by nothing (its claim doesn't verify and its check doesn't
    // match), so nothing is written.
    const auto at = [](json& versions, const size_t version) -> json& {
        for (auto& v : versions)
            if (v.at("version").get<size_t>() == version) return v;
        throw std::runtime_error("no version " + std::to_string(version));
    };
    const auto aOrigin = good.at("origin");
    const auto bOrigin = json{{"node_id", ksB.node_id}, {"vault_id", b.id}};
    for (const bool swapped : {false, true}) {
        becomeAnotherNode(*c.vault_id);
        records_ = good;
        at(records_["key_versions"], known + 1)["origin"] = aOrigin;
        if (swapped) at(records_["key_versions"], 1)["origin"] = bOrigin;
        polls_ = 0;
        std::string outcome;
        try {
            const auto bad = restoreFromCloud(b);
            outcome = bad.written ? "written " + bad.mode : "not written";
            if (bad.written) runtime::Deps::get().storageManager->removeVault(*bad.vault_id);
        } catch (const ops::Refused& e) {
            outcome = e.code;
        }
        EXPECT_NE(outcome.substr(0, 7), "written") << (swapped ? "swapped origins: " : "misstated origin: ") << outcome;
        records_ = good;
    }
}

TEST_F(VaultRecoverFromCloud, ARollbackIsRefusedAgainstTheCloudsCheckpointUnlessAccepted) {
    auto o = populated();
    o.engine->publishRemoteIndexManifest();
    const auto older = o.bucket->current(std::string(mf::kRootKey));
    ASSERT_TRUE(older);
    write(o, "/after.txt", bytes("written after the older root"));
    pass(o.engine);
    enrolled(o);  // the cloud records the newer root's checkpoint
    becomeAnotherNode(o.id);
    (void)o.bucket->seed(std::string(mf::kRootKey), older->body);  // the bucket presents the older root

    const auto vaultsBefore = db::query::vault::Vault::listVaults().size();
    EXPECT_EQ(code([&] { return restoreFromCloud(o); }), "rollback");
    EXPECT_EQ(db::query::vault::Vault::listVaults().size(), vaultsBefore) << "nothing was written";
    EXPECT_EQ(calls.back(), "POST /v1/recovery/restores/rst0123456789abcdefghjkmnp/cancel");
    polls_ = 0;
    ops::vault_recover::Request req;
    req.dry_run = true;
    req.accept_rollback = true;
    EXPECT_EQ(restoreFromCloud(o, req).report.at("freshness"), "rollback_accepted");
}

TEST_F(VaultRecoverFromCloud, AMalformedCheckpointRefusesTheRestore) {
    auto o = populated();
    enrolled(o);
    becomeAnotherNode(o.id);
    records_["checkpoint"] = {{"epoch", 3}, {"root_sha256", "not hex"}};
    const auto started = ops::cloud_restore::start(superUser, vaultUid_, keys::Channel::Cli);
    EXPECT_FALSE(ops::cloud_restore::poll(superUser, started.restore_id).has_value());
    try {
        (void)ops::cloud_restore::poll(superUser, started.restore_id);
        FAIL() << "a malformed checkpoint never silently drops the rollback bound";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "cloud_restore_malformed");
    }
    ops::cloud_restore::cancel(superUser, started.restore_id);
}

TEST_F(VaultRecoverFromCloud, KeysTheCloudMadeUpAreRefusedAndNothingIsWritten) {
    auto o = populated();
    enrolled(o);
    becomeAnotherNode(o.id);
    forged_ = true;  // a cloud (or anyone) handing over keys of its own, with the real records
    const auto vaultsBefore = db::query::vault::Vault::listVaults().size();
    EXPECT_NE(code([&] { return restoreFromCloud(o); }), "ok");
    EXPECT_EQ(db::query::vault::Vault::listVaults().size(), vaultsBefore) << "no vault was created";
    EXPECT_EQ(calls.back(), "POST /v1/recovery/restores/rst0123456789abcdefghjkmnp/cancel");
}

TEST_F(VaultRecoverFromCloud, ADeniedRestoreAndAnAgentStopBeforeAnyKey) {
    auto o = populated();
    enrolled(o);
    EXPECT_THROW((void)ops::cloud_restore::start(superUser, vaultUid_, keys::Channel::Agent), ops::Denied);
    EXPECT_THROW((void)ops::cloud_restore::start(superUser, vaultUid_, keys::Channel::Console), ops::Refused);
    answer_ = "denied";
    const auto started = ops::cloud_restore::start(superUser, vaultUid_, keys::Channel::Cli);
    EXPECT_FALSE(ops::cloud_restore::poll(superUser, started.restore_id).has_value());  // approved, waiting
    try {
        (void)ops::cloud_restore::poll(superUser, started.restore_id);
        FAIL() << "a denied restore delivers nothing";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "cloud_restore_denied");
    }
}

}
