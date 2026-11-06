// vh-test-tier: db-only
// Recovery recipients and KEV1 envelopes (#370; design/encryption/03-metadata-recovery.md §5, §8): enrollment on the CLI
// or a paired device only, envelopes for every held and every future key version in the vault's bucket only (a
// rotation that can't write them never starts), revocation that stops new envelopes and asks for a rotation, the D2
// requirement in status and health, no silent custody, exports that name their signing key, and
// `vh vault keys import --recovery-kit` after the vault master is lost.

#include "auth/stepup/StepUp.hpp"
#include "audit/Trail.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/recovery/Kev1.hpp"
#include "crypto/recovery/Kit.hpp"
#include "crypto/recovery/Seed.hpp"
#include "crypto/util/encrypt.hpp"
#include "db/Transactions.hpp"
#include "db/encoding/bytea.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/sync/Manifest.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/RecoveryGrants.hpp"
#include "db/query/vault/Vault.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Audit.hpp"
#include "ops/Error.hpp"
#include "ops/RecoveryRecipients.hpp"
#include "ops/Users.hpp"
#include "ops/VaultKeys.hpp"
#include "ops/Vaults.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/vault/Keys.hpp"
#include "device/Peer.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "stats/model/SystemHealth.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/manifest/Store.hpp"
#include "vault/APIKeyManager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/RecoveryEnvelopes.hpp"
#include "vault/model/APIKey.hpp"
#include "vault/model/Key.hpp"
#include "vault/model/S3Vault.hpp"
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
#include <iostream>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

namespace vh::test_recovery_recipients {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using EnginePtr = std::shared_ptr<storage::Engine>;
namespace rr = ops::recovery_recipients;
namespace keys = ops::vault_keys;
namespace kev1 = crypto::kev1;
using Channel = keys::Channel;
using WsKeys = protocols::ws::handler::VaultKeys;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "r" + std::to_string(n.fetch_add(1));
}

std::string b64(const std::vector<uint8_t>& bytes) { return crypto::util::b64_encode(bytes); }

// A bucket in memory: what the envelope writer and the kit import see of a vault's bucket. Every request is recorded.
class CaptureStore final : public sync::manifest::ObjectStore {
public:
    std::optional<sync::manifest::StoredObject> get(const std::string& key,
                                                    const std::optional<std::string>&) override {
        std::scoped_lock lock(mutex_);
        const auto it = objects_.find(key);
        if (it == objects_.end()) return std::nullopt;
        return sync::manifest::StoredObject{.bytes = it->second, .etag = "\"e\"", .version_id = std::nullopt};
    }
    std::optional<std::vector<uint8_t>> getRange(const std::string&, uint64_t, uint64_t) override { return std::nullopt; }
    std::string putIfAbsent(const std::string& key, const std::vector<uint8_t>& bytes) override {
        std::scoped_lock lock(mutex_);
        if (failPuts) throw std::runtime_error("the bucket is unreachable (test)");
        if (objects_.contains(key)) throw sync::manifest::PreconditionFailed("exists");
        objects_[key] = bytes;
        puts.push_back(key);
        return "\"e\"";
    }
    std::string putIfMatch(const std::string& key, const std::vector<uint8_t>& bytes, const std::string&) override {
        std::scoped_lock lock(mutex_);
        objects_[key] = bytes;
        puts.push_back(key);
        return "\"e\"";
    }
    std::vector<sync::manifest::ListedObject> list(const std::string& prefix) override {
        std::scoped_lock lock(mutex_);
        std::vector<sync::manifest::ListedObject> out;
        for (const auto& [k, v] : objects_)
            if (k.starts_with(prefix)) out.push_back({.key = k, .size = v.size(), .last_modified = std::nullopt, .etag = std::nullopt});
        return out;
    }
    std::vector<sync::manifest::StoredVersion> versions(const std::string&) override { return {}; }
    void remove(const std::string& key) override {
        std::scoped_lock lock(mutex_);
        objects_.erase(key);
    }

    void plant(const std::string& key, std::vector<uint8_t> bytes) {
        std::scoped_lock lock(mutex_);
        objects_[key] = std::move(bytes);
    }
    std::map<std::string, std::vector<uint8_t>> objects() {
        std::scoped_lock lock(mutex_);
        return objects_;
    }

    std::atomic<bool> failPuts{false};
    std::vector<std::string> puts;

private:
    std::mutex mutex_;
    std::map<std::string, std::vector<uint8_t>> objects_;
};

class RecipientFixture : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr superUser;
    inline static std::filesystem::path root;
    inline static std::mutex storesMutex;
    inline static std::map<uint32_t, std::shared_ptr<CaptureStore>> stores;
    inline static std::vector<uint32_t> storeRequests;

    inline static bool initialized = false;

    // Once per binary: the suites below share one schema and one runtime.
    static void SetUpTestSuite() {
        if (initialized || skipTests) return;
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_recovery_recipients] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_recovery_recipients_" + tag());
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
        static const struct RemoveRoot {
            ~RemoveRoot() {
                std::error_code ec;
                std::filesystem::remove_all(root, ec);
            }
        } removeRoot{};
        initialized = true;
    }

    void TearDown() override {
        if (skipTests) return;
        vault::envelopes::setStoreFactoryForTesting({});  // later suites reach no bucket of ours
        (void)runtime::Deps::releaseSessions();          // nor the sessions the device()/console() principals cached
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        installStores();
    }

    static void installStores() {
        vault::envelopes::setStoreFactoryForTesting([](const uint32_t vaultId) -> std::shared_ptr<sync::manifest::ObjectStore> {
            std::scoped_lock lock(storesMutex);
            storeRequests.push_back(vaultId);
            auto& s = stores[vaultId];
            if (!s) s = std::make_shared<CaptureStore>();
            return s;
        });
    }

    static std::shared_ptr<CaptureStore> storeOf(const uint32_t vaultId) {
        std::scoped_lock lock(storesMutex);
        auto& s = stores[vaultId];
        if (!s) s = std::make_shared<CaptureStore>();
        return s;
    }

    static EnginePtr s3Vault(const std::string& prefix = "rr") {
        auto apiKey = std::make_shared<vault::model::APIKey>(superUser->id, prefix + "_key_" + tag(),
                                                             vault::model::S3Provider::AWS, "AKIATESTACCESSKEY000",
                                                             "secret-value-0000000000000000000000000", "us-east-1",
                                                             "https://s3.example.com");
        const auto keyId = runtime::Deps::get().apiKeyManager->addAPIKey(apiKey);
        const auto created = ops::vaults::create(superUser, {.name = prefix + "_" + tag(), .type = vault::model::VaultType::S3,
                                                             .s3 = ops::vaults::S3Spec{.api_key_id = keyId,
                                                                                       .bucket = "rr-" + tag()}});
        return runtime::Deps::get().storageManager->getEngine(created->id);
    }

    static EnginePtr localVault() {
        const auto v = ops::vaults::create(superUser, {.name = "rrlocal_" + tag(), .type = vault::model::VaultType::Local});
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

    static void rotate(const EnginePtr& engine) {
        engine->encryptionManager->prepare_key_rotation();
        engine->encryptionManager->finish_key_rotation();
    }

    static kev1::VaultUid uidOf(const EnginePtr& engine) { return *engine->vault->uid; }

    static rr::AddResult enroll(const EnginePtr& engine, const crypto::recovery::RecoverySeed& seed,
                                const std::optional<std::string>& label = std::string("Recovery kit")) {
        return rr::add(superUser, {.vault_id = engine->vault->id, .public_key = b64(seed.x25519PublicKey()),
                                   .label = label},
                       Channel::Cli);
    }

    // The key versions of the vault's envelopes in its bucket that `seed` unwraps, with the keys they hold.
    static std::map<uint32_t, crypto::SecretKeyPtr> unwrapAll(const EnginePtr& engine,
                                                              const crypto::recovery::RecoverySeed& seed) {
        std::map<uint32_t, crypto::SecretKeyPtr> out;
        const auto sk = seed.x25519SecretKey();
        for (const auto& [key, bytes] : storeOf(engine->vault->id)->objects()) {
            if (!key.starts_with(kev1::kObjectPrefix)) continue;
            try {
                auto u = kev1::unwrap(bytes, sk.bytes(), kev1::Suite::X25519, uidOf(engine));
                out[u.key_version] = u.key;
            } catch (const kev1::Error&) {}
        }
        return out;
    }

    static bool sameKey(const crypto::SecretKeyPtr& a, const crypto::SecretKeyPtr& b) {
        return a && b && sodium_memcmp(a->bytes().data(), b->bytes().data(), 32) == 0;
    }

    static std::shared_ptr<protocols::ws::Session> console(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    static std::shared_ptr<protocols::ws::Session> device(const UserPtr& user) {
        auto peer = std::make_shared<vh::device::Peer>();
        peer->spkiHex = std::string(64, 'b');
        peer->address = "127.0.0.1";
        peer->deviceRowId = 1;
        return protocols::ws::Session::devicePrincipal(peer, user, {});
    }

    template <class Fn>
    static std::string code(Fn&& fn) {
        try {
            (void)fn();
            return "";
        } catch (const ops::NeedsConfirmation& e) {
            return e.code;
        } catch (const ops::Refused& e) {
            return e.code;
        } catch (const ops::Denied&) {
            return "denied";
        } catch (const ops::NotFound&) {
            return "not_found";
        } catch (const ops::Invalid&) {
            return "invalid";
        } catch (const ops::Conflict&) {
            return "conflict";
        }
    }

    static keys::KeyStatus statusOf(const unsigned int vaultId) { return keys::status(superUser, vaultId).at(0); }

    static void corruptCurrentKey(const unsigned int vaultId) {
        std::vector<uint8_t> junk(48);
        randombytes_buf(junk.data(), junk.size());
        db::Transactions::exec("RecipientFixture::corrupt", [&](pqxx::work& txn) {
            txn.exec("UPDATE vault_keys SET encrypted_key = $2 WHERE vault_id = $1",
                     pqxx::params{vaultId, db::encoding::to_hex_bytea(junk)});
        });
    }

    static json kitFor(const crypto::recovery::RecoverySeed& seed, const std::vector<kev1::VaultUid>& vaults = {}) {
        json doc{{"type", "vh.recovery-kit"}, {"v", 1}, {"recovery_seed", seed.text()}, {"vaults", json::array()}};
        for (const auto& uid : vaults) doc["vaults"].push_back({{"vault_uid", crypto::id::toBase32(uid)}});
        return doc;
    }

    static keys::ImportResult importKit(const EnginePtr& engine, const json& kit, const bool confirm = true) {
        return keys::importKeys(superUser,
                                {.vault_id = engine->vault->id, .keys = nullptr,
                                 .confirm_name = confirm ? std::make_optional(engine->vault->name) : std::nullopt,
                                 .mode = keys::ImportMode::Recover, .recovery_kit = &kit},
                                Channel::Cli);
    }

    static std::string outcome(const keys::ImportResult& r, const unsigned int version) {
        for (const auto& v : r.versions)
            if (v.version == version) return keys::to_string(v.outcome);
        return "<absent>";
    }

    static int64_t count(const std::string& sql) {
        return db::Transactions::exec("RecipientFixture::count", [&](pqxx::work& txn) {
            return txn.exec(sql).one_field_ref().as<int64_t>();
        });
    }
};

// The suites of spec 03 §8, one fixture each over the shared setup.
class RecoveryRecipient : public RecipientFixture {};
class RecoveryRequirement : public RecipientFixture {};
class RecoveryNoSilentCustody : public RecipientFixture {};
class KeysImportFromKit : public RecipientFixture {};
class VaultKeyExportProvenance : public RecipientFixture {};

// ---- RecoveryRecipient* ------------------------------------------------------------------------------------------------

TEST_F(RecoveryRecipient, EnrollmentWrapsEveryHeldVersionAndEveryFutureOne) {
    const auto engine = s3Vault();
    write(engine, "/a.txt", "sealed under version 1");
    rotate(engine);  // v2, before any recipient: no envelope, no request
    EXPECT_TRUE(storeOf(engine->vault->id)->puts.empty());

    const auto seed = crypto::recovery::RecoverySeed::generate();
    const auto added = enroll(engine, seed);
    EXPECT_FALSE(added.note) << *added.note;
    EXPECT_EQ(added.envelopes_written, 2u);
    EXPECT_EQ(added.versions, (std::vector<unsigned int>{1, 2}));
    EXPECT_EQ(added.recipient.recipient_class, "customer");
    EXPECT_EQ(added.recipient.suite, 1u);
    EXPECT_EQ(added.recipient.public_key, b64(seed.x25519PublicKey()));

    auto unwrapped = unwrapAll(engine, seed);
    ASSERT_EQ(unwrapped.size(), 2u);
    for (const auto v : {1u, 2u})
        EXPECT_TRUE(sameKey(unwrapped[v], engine->encryptionManager->historicalKeySnapshot(v))) << v;

    // A rotation wraps the new version before it is used: the envelope is there once prepare_key_rotation returns.
    engine->encryptionManager->prepare_key_rotation();
    const auto [current, version] = engine->encryptionManager->currentKey();
    EXPECT_EQ(version, 3u);
    unwrapped = unwrapAll(engine, seed);
    ASSERT_TRUE(unwrapped.contains(3));
    EXPECT_TRUE(sameKey(unwrapped[3], current));
    engine->encryptionManager->finish_key_rotation();

    // The manifest root names the grant (class customer) and every version's envelopes.
    const auto content = db::query::sync::Manifest::collect(engine->vault->id);
    ASSERT_TRUE(content.recovery_policy);
    ASSERT_EQ(content.recovery_policy->grants.size(), 1u);
    EXPECT_EQ(content.recovery_policy->grants[0].recipient_class, "customer");
    EXPECT_EQ(content.recovery_policy->grants[0].grant_id, added.recipient.grant_id);
    EXPECT_TRUE(content.recovery_policy->grants[0].usableForDecryption());
    for (const auto& k : content.keys) {
        ASSERT_TRUE(k.envelopes) << "version " << k.version;
        EXPECT_EQ(k.envelopes->size(), 1u);
    }

    // Enrollment and the envelopes it wrote are in the audit trail.
    ASSERT_TRUE(audit::Trail::instance()->flushNow());
    const auto events = ops::audit::list(superUser, {.action_prefix = std::string("vault.recovery.recipient.")}, 20).events;
    EXPECT_TRUE(std::ranges::any_of(events, [&](const auto& e) {
        return e.action == "vault.recovery.recipient.add" && e.vault_id == engine->vault->id;
    }));
}

TEST_F(RecoveryRecipient, ARotationThatCantWriteItsEnvelopesNeverStarts) {
    const auto engine = s3Vault();
    write(engine, "/a.txt", "v1");
    const auto seed = crypto::recovery::RecoverySeed::generate();
    (void)enroll(engine, seed);
    const auto store = storeOf(engine->vault->id);
    store->failPuts = true;
    EXPECT_ANY_THROW(engine->encryptionManager->prepare_key_rotation());
    store->failPuts = false;
    EXPECT_EQ(engine->encryptionManager->currentKey().version, 1u);
    EXPECT_FALSE(db::query::vault::Key::keyRotationInProgress(engine->vault->id));
    EXPECT_EQ(db::query::vault::Key::getVaultKey(engine->vault->id)->version, 1u);
    // New writes still seal under the version that has envelopes.
    write(engine, "/b.txt", "still v1");
    EXPECT_EQ(db::query::fs::File::getFileByPath(engine->vault->id, "/b.txt")->encrypted_with_key_version, 1u);
    EXPECT_FALSE(unwrapAll(engine, seed).contains(2));
}

TEST_F(RecoveryRecipient, EnrollmentIsForTheCliAndPairedDevicesWithTheExportPermission) {
    const auto engine = s3Vault();
    const auto seed = crypto::recovery::RecoverySeed::generate();
    const auto pk = b64(seed.x25519PublicKey());
    const json payload{{"vault_id", engine->vault->id}, {"public_key", pk}};

    EXPECT_EQ(code([&] { return WsKeys::addRecipient(payload, console(superUser)); }), "recipient_requires_device");
    EXPECT_EQ(code([&] { return rr::add(superUser, {.vault_id = engine->vault->id, .public_key = pk}, Channel::Agent); }),
              "denied");
    const auto created = ops::users::create(superUser, {.name = "rr_plain_" + tag(), .role = "unprivileged",
                                                        .password = std::string("Recovery-Pass-123456")});
    const auto plain = identities::manager().user(created.user->id);
    EXPECT_EQ(code([&] { return rr::add(plain, {.vault_id = engine->vault->id, .public_key = pk}, Channel::Cli); }),
              "denied");
    EXPECT_EQ(code([&] { return rr::list(plain, engine->vault->id); }), "denied");

    // Step-up (#359): a paired device's request is refused until device approvals (#361) can answer it; the host CLI
    // is exempt by design.
    {
        const auto session = device(superUser);
        auth::stepup::Scope scope(session);
        EXPECT_EQ(code([&] { return WsKeys::addRecipient(payload, session); }), "step_up_required");
    }
    {
        auth::stepup::Scope scope(auth::stepup::Channel::Host);
        EXPECT_EQ(code([&] { return rr::add(superUser, {.vault_id = engine->vault->id, .public_key = pk}, Channel::Cli); }),
                  "");
    }
    EXPECT_EQ(code([&] { return rr::add(superUser, {.vault_id = engine->vault->id, .public_key = pk}, Channel::Cli); }),
              "conflict") << "the same key enrolled twice";

    // Malformed and degenerate keys, a vault without a bucket.
    EXPECT_EQ(code([&] { return rr::add(superUser, {.vault_id = engine->vault->id, .public_key = "AAAA"}, Channel::Cli); }),
              "invalid");
    EXPECT_EQ(code([&] {
                  return rr::add(superUser, {.vault_id = engine->vault->id, .public_key = std::string(64, '0')},
                                 Channel::Cli);
              }),
              "invalid");
    const auto local = localVault();
    EXPECT_EQ(code([&] { return rr::add(superUser, {.vault_id = local->vault->id, .public_key = pk}, Channel::Cli); }),
              "conflict");

    // Listing is public data: any session with the View permission, the console included.
    const auto listed = WsKeys::listRecipients({{"vault_id", engine->vault->id}}, console(superUser));
    ASSERT_EQ(listed.at("recipients").size(), 1u);
    EXPECT_EQ(listed.at("recipients").at(0).at("public_key"), pk);
    EXPECT_EQ(listed.at("vault_uid"), crypto::id::toBase32(uidOf(engine)));
}

TEST_F(RecoveryRecipient, RevocationStopsNewEnvelopesAndAsksForARotation) {
    const auto engine = s3Vault();
    const auto a = crypto::recovery::RecoverySeed::generate();
    const auto b = crypto::recovery::RecoverySeed::generate();
    const auto grantA = enroll(engine, a).recipient.grant_id;
    (void)enroll(engine, b);

    const auto revoked = rr::revoke(superUser, engine->vault->id, grantA, Channel::Cli);
    ASSERT_TRUE(revoked.recipient.revoked_at);
    EXPECT_TRUE(revoked.recovery.rotation_needed) << "A still holds the current version's envelope";
    EXPECT_TRUE(statusOf(engine->vault->id).recovery.rotation_needed);
    EXPECT_EQ(code([&] { return rr::revoke(superUser, engine->vault->id, grantA, Channel::Cli); }), "conflict");
    EXPECT_EQ(code([&] { return rr::revoke(superUser, engine->vault->id, "0000000000000000000000000", Channel::Cli); }),
              "not_found");

    rotate(engine);  // v2: wrapped to B only
    EXPECT_FALSE(unwrapAll(engine, a).contains(2));
    EXPECT_TRUE(unwrapAll(engine, b).contains(2));
    EXPECT_TRUE(unwrapAll(engine, a).contains(1)) << "an envelope already written can't be taken back";
    // No file is sealed under v1 any more: the rotation cut A off.
    EXPECT_FALSE(statusOf(engine->vault->id).recovery.rotation_needed);

    // The root keeps the revoked grant, marked.
    const auto content = db::query::sync::Manifest::collect(engine->vault->id);
    ASSERT_EQ(content.recovery_policy->grants.size(), 2u);
    const auto& g = content.recovery_policy->grants[0].grant_id == grantA ? content.recovery_policy->grants[0]
                                                                          : content.recovery_policy->grants[1];
    EXPECT_TRUE(g.revoked_at);
    EXPECT_FALSE(g.usableForDecryption());
}

// ---- RecoveryRequirement* (D2, spec 03 §5.5) ---------------------------------------------------------------------------

TEST_F(RecoveryRequirement, ByosWithoutRecipientOrCurrentExportIsReportedMissing) {
    const auto engine = s3Vault();
    write(engine, "/a.txt", "x");
    const auto s = statusOf(engine->vault->id);
    EXPECT_TRUE(s.recovery.required);
    EXPECT_EQ(s.recovery.state, "recovery_material_missing");
    ASSERT_TRUE(s.recovery.detail);
    EXPECT_EQ(keys::toJson(s).at("recovery").at("state"), "recovery_material_missing");

    const auto health = stats::model::SystemHealth::snapshot();
    EXPECT_TRUE(std::ranges::any_of(health.vaultsRecoveryMaterialMissing,
                                    [&](const auto& v) { return v.vaultId == engine->vault->id; }));
    EXPECT_FALSE(health.healthy());
    EXPECT_TRUE(json(health).at("vaults_recovery_material_missing").is_array());

    // Local vaults keep the export guidance.
    const auto local = localVault();
    EXPECT_EQ(statusOf(local->vault->id).recovery.state, "not_required");
    EXPECT_FALSE(std::ranges::any_of(stats::model::SystemHealth::snapshot().vaultsRecoveryMaterialMissing,
                                     [&](const auto& v) { return v.vaultId == local->vault->id; }));
}

TEST_F(RecoveryRequirement, ACurrentExportCoversTheVaultUntilARotation) {
    const auto engine = s3Vault();
    keys::recordExport(keys::exportVault(superUser, engine->vault->id, Channel::Cli));
    auto s = statusOf(engine->vault->id);
    EXPECT_EQ(s.recovery.state, "export");
    EXPECT_TRUE(s.recovery.export_current);
    rotate(engine);
    s = statusOf(engine->vault->id);
    EXPECT_EQ(s.recovery.state, "recovery_material_missing") << "a rotation makes the export stale";
    EXPECT_FALSE(s.recovery.export_current);
}

TEST_F(RecoveryRequirement, ARecipientCoversEveryNeededVersionOnlyWithItsEnvelopes) {
    const auto engine = s3Vault();
    write(engine, "/a.txt", "x");
    const auto seed = crypto::recovery::RecoverySeed::generate();
    (void)enroll(engine, seed);
    EXPECT_EQ(statusOf(engine->vault->id).recovery.state, "recipient");

    // The bucket was unreachable for the next rotation's catch-up: the version is uncovered until the sync pass.
    db::Transactions::exec("RecipientFixture::dropEnvelopes", [&](pqxx::work& txn) {
        txn.exec("DELETE FROM vault_key_envelope WHERE vault_id = $1", pqxx::params{engine->vault->id});
    });
    auto s = statusOf(engine->vault->id);
    EXPECT_EQ(s.recovery.state, "recovery_material_missing");
    EXPECT_EQ(s.recovery.uncovered_versions, (std::vector<unsigned int>{1}));
    const auto cloud = std::dynamic_pointer_cast<storage::CloudEngine>(engine);
    ASSERT_TRUE(cloud);
    EXPECT_EQ(cloud->ensureRecoveryEnvelopes(), 1u);  // what each sync pass runs first
    EXPECT_EQ(statusOf(engine->vault->id).recovery.state, "recipient");
}

// ---- RecoveryNoSilentCustody -------------------------------------------------------------------------------------------

TEST_F(RecoveryNoSilentCustody, NoFlowAddsANonCustomerGrantOrSendsKeyMaterialAnywhereButTheBucket) {
    {
        std::scoped_lock lock(storesMutex);
        storeRequests.clear();
    }
    const auto grantsBefore = count("SELECT COUNT(*) FROM vault_recovery_grant");
    // Creating vaults (local and S3, with files and a rotation) never enrolls a recipient or touches a bucket for one.
    const auto local = localVault();
    write(local, "/l.txt", "local");
    const auto engine = s3Vault("custody");
    write(engine, "/a.txt", "x");
    rotate(engine);
    EXPECT_EQ(count("SELECT COUNT(*) FROM vault_recovery_grant"), grantsBefore);
    const auto requestsFor = [](const uint32_t vaultId) {
        std::scoped_lock lock(storesMutex);
        return std::ranges::count(storeRequests, vaultId);
    };
    EXPECT_EQ(requestsFor(local->vault->id), 0) << "no recovery request without a recipient the customer enrolled";
    EXPECT_EQ(requestsFor(engine->vault->id), 0) << "no recovery request without a recipient the customer enrolled";

    // Enrolling a recipient writes envelopes to that vault's bucket and nowhere else: customer class, purpose 1, this
    // vault, this recipient.
    const auto seed = crypto::recovery::RecoverySeed::generate();
    (void)enroll(engine, seed);
    EXPECT_GE(requestsFor(engine->vault->id), 1);
    EXPECT_EQ(requestsFor(local->vault->id), 0);
    const auto rid = kev1::recipientId(seed.x25519PublicKey());
    const auto store = storeOf(engine->vault->id);
    ASSERT_FALSE(store->puts.empty());
    for (const auto& key : store->puts) {
        EXPECT_TRUE(key.starts_with(kev1::kObjectPrefix)) << key;
        const auto h = kev1::inspect(store->objects().at(key));
        EXPECT_EQ(h.recipient_class, kev1::kClassCustomer);
        EXPECT_EQ(h.purpose, kev1::kPurposeVaultKey);
        EXPECT_EQ(h.vault_uid, uidOf(engine));
        EXPECT_EQ(h.recipient_id, rid);
    }
    for (const auto& g : db::query::vault::RecoveryGrants::list(engine->vault->id))
        EXPECT_EQ(g.recipient_class, "customer");

    // No code path can record a non-customer grant: the database refuses it outright.
    EXPECT_ANY_THROW(db::Transactions::exec("RecipientFixture::custodian", [&](pqxx::work& txn) {
        txn.exec("INSERT INTO vault_recovery_grant (vault_id, grant_id, recipient_id, public_key, suite, class, "
                 "authorized_by) VALUES ($1, $2, $3, $4::bytea, 1, 'custodian', 'test')",
                 pqxx::params{engine->vault->id, crypto::id::toBase32(crypto::id::newObjectUid()), std::string(64, 'a'),
                              db::encoding::to_hex_bytea(seed.x25519PublicKey())});
    }));
}

// ---- KeysImportFromKit* (spec 03 §5.6) ---------------------------------------------------------------------------------

TEST_F(KeysImportFromKit, RestoresTheVaultAfterItsVaultMasterIsLost) {
    const auto engine = s3Vault();
    write(engine, "/a.txt", "readable again");
    const auto seed = crypto::recovery::RecoverySeed::generate();
    (void)enroll(engine, seed);
    const auto id = engine->vault->id;
    const auto name = engine->vault->name;

    // The vault master that wrapped the key is gone: the row no longer unseals and the vault doesn't run.
    corruptCurrentKey(id);
    runtime::Deps::get().storageManager->retireVault(id);
    EXPECT_FALSE(statusOf(id).key_available);

    const auto kit = kitFor(seed, {uidOf(engine)});
    EXPECT_EQ(code([&] { return importKit(engine, kit, false); }), "vault_key_import");
    const auto r = importKit(engine, kit);
    EXPECT_EQ(outcome(r, 1), "restored");
    EXPECT_TRUE(r.written);
    EXPECT_TRUE(r.key_available) << r.note.value_or("");
    ASSERT_TRUE(r.recovery_kit);
    EXPECT_EQ(r.recovery_kit->unwrapped, 1u);
    EXPECT_EQ(readFile(id, "/a.txt"), "readable again");
    EXPECT_TRUE(statusOf(id).key_available);
    EXPECT_EQ(keys::toJson(r).at("recovery_kit").at("unwrapped"), 1);

    ASSERT_TRUE(audit::Trail::instance()->flushNow());
    const auto events = ops::audit::list(superUser, {.action_prefix = std::string("vault.keys.import.")}, 20).events;
    EXPECT_TRUE(std::ranges::any_of(events, [&](const auto& e) { return e.vault_id == id; }));
    (void)name;
}

TEST_F(KeysImportFromKit, RefusesAnotherVaultsKitAWrongSeedAndSalvage) {
    const auto engine = s3Vault();
    const auto seed = crypto::recovery::RecoverySeed::generate();
    (void)enroll(engine, seed);
    corruptCurrentKey(engine->vault->id);
    runtime::Deps::get().storageManager->retireVault(engine->vault->id);

    EXPECT_EQ(code([&] { return importKit(engine, kitFor(seed, {crypto::id::newObjectUid()})); }), "invalid");
    EXPECT_EQ(code([&] { return importKit(engine, kitFor(crypto::recovery::RecoverySeed::generate())); }), "invalid");
    const auto kit = kitFor(seed);
    EXPECT_EQ(code([&] {
                  return keys::importKeys(superUser,
                                          {.vault_id = engine->vault->id, .keys = nullptr,
                                           .confirm_name = engine->vault->name, .mode = keys::ImportMode::Salvage,
                                           .recovery_kit = &kit},
                                          Channel::Cli);
              }),
              "invalid");
    EXPECT_EQ(code([&] {
                  return keys::importKeys(superUser,
                                          {.vault_id = engine->vault->id, .keys = nullptr,
                                           .confirm_name = engine->vault->name, .mode = keys::ImportMode::Recover,
                                           .recovery_kit = &kit},
                                          Channel::Console);
              }),
              "import_requires_device");
    EXPECT_FALSE(statusOf(engine->vault->id).key_available) << "nothing was written";
}

TEST_F(KeysImportFromKit, SkipsReservedEnvelopesIgnoresPlantedKeysAndNeverIntroducesAVersion) {
    const auto engine = s3Vault();
    write(engine, "/a.txt", "genuine");
    const auto seed = crypto::recovery::RecoverySeed::generate();
    (void)enroll(engine, seed);
    const auto id = engine->vault->id;
    const auto store = storeOf(id);
    const auto pk = seed.x25519PublicKey();

    // Anyone who can write to the bucket can wrap a key of their own to the recipient's public key.
    const auto planted = crypto::SecretKey::random();
    const auto fake1 = kev1::wrap(*planted, kev1::Suite::X25519, 1, uidOf(engine), pk);
    store->plant(kev1::objectKey(kev1::kid(fake1)), fake1);
    const auto fake9 = kev1::wrap(*planted, kev1::Suite::X25519, 9, uidOf(engine), pk);
    store->plant(kev1::objectKey(kev1::kid(fake9)), fake9);
    // A reserved recipient class (a future custodian) and a reserved purpose: skipped, never fatal.
    auto reservedClass = fake1;
    reservedClass[13] = 1;
    store->plant(kev1::objectKey(kev1::kid(reservedClass)), reservedClass);
    auto reservedPurpose = fake1;
    reservedPurpose[12] = 2;
    store->plant(kev1::objectKey(kev1::kid(reservedPurpose)), reservedPurpose);
    // Another recipient's envelope.
    const auto other = crypto::recovery::RecoverySeed::generate();
    const auto others = kev1::wrap(*planted, kev1::Suite::X25519, 1, uidOf(engine), other.x25519PublicKey());
    store->plant(kev1::objectKey(kev1::kid(others)), others);

    corruptCurrentKey(id);
    runtime::Deps::get().storageManager->retireVault(id);
    const auto r = importKit(engine, kitFor(seed));
    EXPECT_EQ(outcome(r, 1), "restored");
    EXPECT_EQ(outcome(r, 9), "refused") << "a kit never introduces a key version";
    ASSERT_TRUE(r.recovery_kit);
    EXPECT_EQ(r.recovery_kit->skipped, 3u);
    EXPECT_EQ(r.recovery_kit->ignored, 1u) << "the planted version-1 key isn't the one the records name";
    EXPECT_EQ(readFile(id, "/a.txt"), "genuine");
    EXPECT_EQ(db::query::vault::Key::getVaultKey(id)->version, 1u) << "the current version never moves";
}

// ---- exports name their signing key (spec 03 §5.4) --------------------------------------------------------------------

TEST_F(VaultKeyExportProvenance, ExportsCarryTheAttestationPublicKeyAndOldExportsStillImport) {
    const auto engine = s3Vault();
    write(engine, "/a.txt", "x");
    const auto exported = WsKeys::exportKeys({{"vault_id", engine->vault->id}}, device(superUser));
    const auto& att = exported.at("attestation");
    ASSERT_TRUE(att.contains("public_key")) << exported.dump();
    const auto own = db::query::vault::Key::attestationPublicKey(att.at("key_id").get<unsigned int>());
    ASSERT_TRUE(own);
    EXPECT_EQ(att.at("public_key"), b64(*own));
    const auto status = keys::toJson(statusOf(engine->vault->id));
    EXPECT_FALSE(status.at("attestation_public_keys").empty());
    EXPECT_FALSE(status.at("node_id").get<std::string>().empty());

    const auto id = engine->vault->id;
    corruptCurrentKey(id);
    runtime::Deps::get().storageManager->retireVault(id);

    // Another node's public key under this node's key id: not this node's attestation.
    auto foreign = exported;
    std::vector<uint8_t> otherKey(32, 7);
    foreign["attestation"]["public_key"] = b64(otherKey);
    foreign["key_info"]["attestation"]["public_key"] = b64(otherKey);
    auto r = WsKeys::importKeys({{"vault_id", id}, {"keys", foreign}, {"confirm_name", engine->vault->name}},
                                device(superUser));
    EXPECT_EQ(r.at("versions").at(0).at("outcome"), "needs_salvage") << r.dump();

    // An export from before #370 (no public_key) still imports on its own node.
    auto old = exported;
    old["attestation"].erase("public_key");
    old["key_info"]["attestation"].erase("public_key");
    r = WsKeys::importKeys({{"vault_id", id}, {"keys", old}, {"confirm_name", engine->vault->name}}, device(superUser));
    EXPECT_EQ(r.at("versions").at(0).at("outcome"), "restored") << r.dump();
    EXPECT_EQ(readFile(id, "/a.txt"), "x");
}

}
