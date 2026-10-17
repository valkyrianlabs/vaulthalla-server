// File recovery keeps generations sealed under the key that was current when they were written; live rotation never
// re-encrypts them. These tests pin historical key compatibility (.claude/context/recovery.md, Keys):
// historicalKeySnapshot() serves every version the vault still holds while keySnapshot() stays strict for live reads,
// re-sealing an old generation under the current key streams and commits only after the old tag verifies, nothing
// deletes a retired key that recoverable data references (trigger recovery_guard_retired_vault_key), and key export
// carries exactly the referenced retired versions. The first suite needs no TPM or database; the second drives the
// real EncryptionManager (test vault master) against the test DB.

#include "../helpers/identities.hpp"
#include "crypto/SecretKey.hpp"
#include "crypto/util/encrypt.hpp"
#include "crypto/util/reseal.hpp"
#include "db/Transactions.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Key.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "preview/cache/Store.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
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
#include <memory>
#include <span>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_recovery_keys {

namespace stdfs = std::filesystem;
namespace cu = crypto::util;
using Bytes = std::vector<uint8_t>;
using vault::EncryptionManager;
using vault::KeyVersionUnavailable;

std::string rkTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "k" + std::to_string(n.fetch_add(1));
}

Bytes randomBytes(const std::size_t n) {
    Bytes out(n);
    randombytes_buf(out.data(), out.size());
    return out;
}

Bytes slurp(const stdfs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void spit(const stdfs::path& path, const Bytes& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

Bytes bytesOf(const crypto::SecretKeyPtr& key) { return {key->bytes().begin(), key->bytes().end()}; }

// Seals plaintext under key the way every vault write does; returns the sealed bytes and the IV (base64).
std::pair<Bytes, std::string> seal(const Bytes& plaintext, const Bytes& key) {
    Bytes iv;
    auto sealed = cu::encrypt_aes256_gcm(plaintext, key, iv);
    return {std::move(sealed), cu::b64_encode(iv)};
}

class RecoveryKeysTest : public ::testing::Test {
protected:
    stdfs::path dir;
    Bytes k2 = randomBytes(32), k3 = randomBytes(32), k4 = randomBytes(32), k5 = randomBytes(32);

    void SetUp() override {
        dir = stdfs::temp_directory_path() / ("vh_recovery_keys_" + rkTag());
        stdfs::create_directories(dir);
    }

    void TearDown() override {
        std::error_code ec;
        stdfs::remove_all(dir, ec);
    }

    // Current version 5, rotation to it still in progress (4 is the old key), 2 and 3 retired.
    [[nodiscard]] std::unique_ptr<EncryptionManager> manager() const {
        auto em = std::make_unique<EncryptionManager>(EncryptionManager::ForTesting{}, 7, k5, 5, k4);
        em->addHistoricalKeyForTesting(2, k2);
        em->addHistoricalKeyForTesting(3, k3);
        return em;
    }
};

TEST_F(RecoveryKeysTest, HistoricalSnapshotServesEveryHeldVersionWhileKeySnapshotStaysStrict) {
    const auto em = manager();
    EXPECT_EQ(bytesOf(em->historicalKeySnapshot(5)), k5);
    EXPECT_EQ(bytesOf(em->historicalKeySnapshot(4)), k4);
    EXPECT_EQ(bytesOf(em->historicalKeySnapshot(3)), k3);
    EXPECT_EQ(bytesOf(em->historicalKeySnapshot(2)), k2);

    // Live reads keep their rules: current and the rotation's old key only.
    EXPECT_EQ(bytesOf(em->keySnapshot(5)), k5);
    EXPECT_EQ(bytesOf(em->keySnapshot(4)), k4);
    EXPECT_THROW((void)em->keySnapshot(3), std::runtime_error);
    EXPECT_THROW((void)em->keySnapshot(2), std::runtime_error);

    const auto [sealed, iv] = seal({'o', 'l', 'd'}, k2);
    EXPECT_THROW((void)em->decrypt(sealed, iv, 2), std::runtime_error);

    EXPECT_THROW((void)em->historicalKeySnapshot(1), KeyVersionUnavailable);
    EXPECT_THROW((void)em->historicalKeySnapshot(6), KeyVersionUnavailable);
    EXPECT_THROW((void)em->historicalKeySnapshot(0), KeyVersionUnavailable);
    try {
        (void)em->historicalKeySnapshot(9);
        FAIL() << "expected KeyVersionUnavailable";
    } catch (const KeyVersionUnavailable& e) {
        EXPECT_EQ(e.vaultId(), 7u);
        EXPECT_EQ(e.version(), 9u);
    }

    EXPECT_EQ(em->retainedKeyVersions(), (std::vector<unsigned int>{2, 3, 4, 5}));
    EXPECT_TRUE(em->hasKeyVersion(2));
    EXPECT_TRUE(em->hasKeyVersion(4));
    EXPECT_TRUE(em->hasKeyVersion(5));
    EXPECT_FALSE(em->hasKeyVersion(0));
    EXPECT_FALSE(em->hasKeyVersion(1));
    EXPECT_FALSE(em->hasKeyVersion(6));
}

TEST_F(RecoveryKeysTest, ResealFileMovesAnOldGenerationUnderTheCurrentKey) {
    const auto em = manager();
    // Several 64 KiB chunks plus a partial one.
    const auto plaintext = randomBytes(3 * 64 * 1024 + 4099);
    const auto [sealed, iv] = seal(plaintext, k2);
    spit(dir / "blob", sealed);

    auto f = std::make_shared<fs::model::File>();
    em->resealFileToCurrent(dir / "blob", iv, 2, dir / "sub" / "sidecar", f);

    EXPECT_EQ(f->encrypted_with_key_version, 5u);
    EXPECT_FALSE(f->encryption_iv.empty());
    EXPECT_NE(f->encryption_iv, iv);
    EXPECT_EQ(stdfs::file_size(dir / "sub" / "sidecar"), sealed.size());
    EXPECT_EQ(stdfs::status(dir / "sub" / "sidecar").permissions() & stdfs::perms::all,
              stdfs::perms::owner_read | stdfs::perms::owner_write);

    // The live read path accepts the result; the source blob is untouched.
    EXPECT_EQ(em->decrypt(slurp(dir / "sub" / "sidecar"), f->encryption_iv, f->encrypted_with_key_version), plaintext);
    EXPECT_EQ(slurp(dir / "blob"), sealed);

    // The util directly, back the other way.
    const crypto::SecretKey oldKey(k5), newKey(k3);
    const auto backIv = cu::resealFile(dir / "sub" / "sidecar", oldKey, f->encryption_iv, dir / "back", newKey);
    EXPECT_EQ(cu::decrypt_aes256_gcm(slurp(dir / "back"), k3, cu::b64_decode(backIv)), plaintext);
}

TEST_F(RecoveryKeysTest, ResealOfATamperedSourceThrowsIntegrityErrorAndLeavesNothing) {
    const auto em = manager();
    const auto plaintext = randomBytes(100 * 1024);
    const auto [sealed, iv] = seal(plaintext, k3);

    const auto attempt = [&](const Bytes& source) {
        spit(dir / "blob", source);
        spit(dir / "sidecar", {'s', 't', 'a', 'l', 'e'});  // a leftover sidecar is removed too
        auto f = std::make_shared<fs::model::File>();
        f->encryption_iv = "unchanged";
        f->encrypted_with_key_version = 42;
        EXPECT_THROW(em->resealFileToCurrent(dir / "blob", iv, 3, dir / "sidecar", f), storage::IntegrityError);
        EXPECT_FALSE(stdfs::exists(dir / "sidecar"));
        EXPECT_EQ(f->encryption_iv, "unchanged");
        EXPECT_EQ(f->encrypted_with_key_version, 42u);
    };

    auto body = sealed;
    body[70 * 1024] ^= 0x01;  // a body byte in the second chunk
    attempt(body);

    auto tag = sealed;
    tag.back() ^= 0x80;
    attempt(tag);

    attempt(Bytes(sealed.begin(), sealed.end() - 1));  // truncated
    attempt(Bytes(sealed.begin(), sealed.begin() + 10));  // shorter than a tag

    // The right bytes under the wrong key version do not authenticate either.
    spit(dir / "blob", sealed);
    auto f = std::make_shared<fs::model::File>();
    EXPECT_THROW(em->resealFileToCurrent(dir / "blob", iv, 2, dir / "sidecar", f), storage::IntegrityError);
    EXPECT_FALSE(stdfs::exists(dir / "sidecar"));

    // A version the vault doesn't hold is refused before anything is written.
    EXPECT_THROW(em->resealFileToCurrent(dir / "blob", iv, 1, dir / "sidecar", f), KeyVersionUnavailable);
    EXPECT_FALSE(stdfs::exists(dir / "sidecar"));
}

TEST_F(RecoveryKeysTest, EmptyGenerationsKeepTheirRepresentation) {
    const auto em = manager();

    // Every empty file is stored unencrypted: no IV, version 0, zero bytes. It stays that way.
    spit(dir / "empty", {});
    auto f = std::make_shared<fs::model::File>();
    f->encryption_iv = "x";
    f->encrypted_with_key_version = 3;
    em->resealFileToCurrent(dir / "empty", "", 0, dir / "empty.out", f);
    EXPECT_TRUE(stdfs::exists(dir / "empty.out"));
    EXPECT_EQ(stdfs::file_size(dir / "empty.out"), 0u);
    EXPECT_TRUE(f->encryption_iv.empty());
    EXPECT_EQ(f->encrypted_with_key_version, 0u);
    EXPECT_TRUE(em->resealToCurrent({}, "", 0, f).empty());

    // Unencrypted non-empty bytes are plaintext: a re-seal refuses them rather than sealing them silently.
    spit(dir / "plain", {'h', 'i'});
    EXPECT_THROW(em->resealFileToCurrent(dir / "plain", "", 0, dir / "plain.out", f), std::invalid_argument);
    EXPECT_FALSE(stdfs::exists(dir / "plain.out"));
    EXPECT_THROW((void)em->resealToCurrent({'h', 'i'}, "", 0, f), std::invalid_argument);

    // A sealed empty message (just a tag) re-seals to another sealed empty message.
    const auto [sealed, iv] = seal({}, k2);
    ASSERT_EQ(sealed.size(), cu::AES_TAG_SIZE);
    spit(dir / "tag-only", sealed);
    em->resealFileToCurrent(dir / "tag-only", iv, 2, dir / "tag-only.out", f);
    EXPECT_EQ(stdfs::file_size(dir / "tag-only.out"), cu::AES_TAG_SIZE);
    EXPECT_EQ(f->encrypted_with_key_version, 5u);
    EXPECT_TRUE(em->decrypt(slurp(dir / "tag-only.out"), f->encryption_iv, 5).empty());
}

TEST_F(RecoveryKeysTest, ResealInMemoryRoundTripsAndRefusesTampering) {
    const auto em = manager();
    const auto plaintext = randomBytes(5000);
    const auto [sealed, iv] = seal(plaintext, k3);

    auto f = std::make_shared<fs::model::File>();
    const auto out = em->resealToCurrent(sealed, iv, 3, f);
    EXPECT_EQ(f->encrypted_with_key_version, 5u);
    EXPECT_NE(f->encryption_iv, iv);
    EXPECT_EQ(em->decrypt(out, f->encryption_iv, 5), plaintext);

    auto tampered = sealed;
    tampered[17] ^= 0x04;
    auto g = std::make_shared<fs::model::File>();
    EXPECT_THROW((void)em->resealToCurrent(tampered, iv, 3, g), storage::IntegrityError);
    EXPECT_TRUE(g->encryption_iv.empty());
}

// The decrypted bytes (unauthenticated until the tag verifies) are wiped on success and on every failure, in memory
// and while streaming a file.
TEST_F(RecoveryKeysTest, ResealWipesThePlaintextOnEveryPath) {
    struct Seen {
        std::size_t calls{}, bytes{}, nonZero{};
    } seen;
    struct ObserverReset {
        ~ObserverReset() { cu::setPlaintextWipeObserverForTesting({}); }
    } const reset;
    cu::setPlaintextWipeObserverForTesting([&](const std::span<const uint8_t> b) {
        ++seen.calls;
        seen.bytes += b.size();
        seen.nonZero += static_cast<std::size_t>(std::ranges::count_if(b, [](const uint8_t c) { return c != 0; }));
    });
    const crypto::SecretKey oldKey(k3), newKey(k5);
    const auto plaintext = randomBytes(5000);
    const auto [sealed, ivB64] = seal(plaintext, k3);
    const auto iv = cu::b64_decode(ivB64);

    Bytes outIv;
    (void)cu::resealBuffer(sealed, oldKey, iv, newKey, outIv);
    EXPECT_EQ(seen.calls, 1u) << "success";
    EXPECT_EQ(seen.bytes, plaintext.size());

    auto tampered = sealed;
    tampered[17] ^= 0x04;   // the body decrypts to (wrong) plaintext before the tag fails
    EXPECT_THROW((void)cu::resealBuffer(tampered, oldKey, iv, newKey, outIv), storage::IntegrityError);
    EXPECT_EQ(seen.calls, 2u) << "failed authentication";
    auto wrongTag = sealed;
    wrongTag.back() ^= 0x01;
    EXPECT_THROW((void)cu::resealBuffer(wrongTag, crypto::SecretKey(k2), iv, newKey, outIv), storage::IntegrityError);
    EXPECT_EQ(seen.calls, 3u) << "wrong key";

    const auto big = randomBytes(2 * 64 * 1024 + 77);
    const auto [bigSealed, bigIv] = seal(big, k3);
    spit(dir / "blob", bigSealed);
    (void)cu::resealFile(dir / "blob", oldKey, bigIv, dir / "out", newKey);
    EXPECT_EQ(seen.calls, 4u) << "file, success";
    auto bigTampered = bigSealed;
    bigTampered[64 * 1024 + 5] ^= 0x10;
    spit(dir / "blob", bigTampered);
    EXPECT_THROW((void)cu::resealFile(dir / "blob", oldKey, bigIv, dir / "out", newKey), storage::IntegrityError);
    EXPECT_EQ(seen.calls, 5u) << "file, failed authentication";
    EXPECT_EQ(seen.nonZero, 0u) << "every plaintext buffer was zero when released";
}

// Unsealed retired keys leave memory once idle, on the service's timer, without another access to the cache.
TEST_F(RecoveryKeysTest, IdleHistoricalKeysAreEvictedWithoutAnotherAccess) {
    const auto em = manager();
    const auto now = std::chrono::steady_clock::now();
    em->cacheHistoricalKeyForTesting(11, randomBytes(32), now - EncryptionManager::kHistoricalCacheIdle - std::chrono::seconds(1));
    em->cacheHistoricalKeyForTesting(12, randomBytes(32), now);
    EXPECT_EQ(em->cachedHistoricalKeyCount(), 2u);
    EXPECT_TRUE(em->hasKeyVersion(11));

    EXPECT_EQ(em->evictIdleHistoricalKeys(now), 1u);
    EXPECT_EQ(em->cachedHistoricalKeyCount(), 1u);
    EXPECT_FALSE(em->hasKeyVersion(11)) << "gone from memory (a TPM-backed manager would unseal it again on demand)";
    EXPECT_EQ(em->evictIdleHistoricalKeys(now), 0u);
    EXPECT_EQ(em->evictIdleHistoricalKeys(now + EncryptionManager::kHistoricalCacheIdle + std::chrono::seconds(1)), 1u);
    EXPECT_EQ(em->cachedHistoricalKeyCount(), 0u);
    EXPECT_EQ(bytesOf(em->historicalKeySnapshot(3)), k3) << "test-held versions are unaffected";
}

// ---- against the test database, with the real (test vault master) EncryptionManager -------------------------------

class RecoveryKeysDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<identities::User> superUser;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_recovery_keys] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = stdfs::temp_directory_path() / ("vh_recovery_keys_db_" + rkTag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        stdfs::create_directories(paths::backingPath);
        stdfs::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);

        const auto user = vh::test::identities::createUser("rk_super_" + rkTag(),
                                                           db::query::rbac::role::Admin::get("super_admin"),
                                                           "rk@vaulthalla.test", "x", std::nullopt);
        superUser = vh::identities::manager().user(user->id);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    struct TestVault {
        unsigned int id{};
        std::shared_ptr<EncryptionManager> em;
    };

    static TestVault newVault() {
        const auto v = ops::vaults::create(superUser, {.name = "rk_" + rkTag(), .type = vault::model::VaultType::Local});
        return {v->id, runtime::Deps::get().storageManager->getEngine(v->id)->encryptionManager};
    }

    static void rotate(const TestVault& v) {
        v.em->prepare_key_rotation();
        v.em->finish_key_rotation();
    }

    static unsigned int count(const std::string& sql, const unsigned int vaultId) {
        return db::Transactions::exec("RecoveryKeysDbTest::count", [&](pqxx::work& txn) {
            return txn.exec(sql, pqxx::params{vaultId}).one_field_ref().as<unsigned int>();
        });
    }

    static unsigned int retiredRows(const unsigned int vaultId) {
        return count("SELECT COUNT(*) FROM vault_keys_trashed WHERE vault_id = $1", vaultId);
    }

    static void addBlob(const unsigned int vaultId, const unsigned int keyVersion) {
        const auto name = [] {
            static constexpr char alphabet[] = "abcdefghijklmnopqrstuvwxyz0123456789";
            std::string s(32, 'a');
            for (auto& c : s) c = alphabet[randombytes_uniform(sizeof(alphabet) - 1)];
            return s;
        }();
        db::Transactions::exec("RecoveryKeysDbTest::addBlob", [&](pqxx::work& txn) {
            txn.exec("INSERT INTO recovery_blob (vault_id, storage_name, encryption_iv, key_version, cipher_bytes, "
                     "plaintext_bytes) VALUES ($1, $2, $3, $4, 32, 16)",
                     pqxx::params{vaultId, name, cu::b64_encode(randomBytes(12)), keyVersion});
        });
    }

    static void addProviderVersion(const unsigned int vaultId, const unsigned int keyVersion, const std::string& id) {
        db::Transactions::exec("RecoveryKeysDbTest::addProviderVersion", [&](pqxx::work& txn) {
            txn.exec("INSERT INTO upstream_object_version (vault_id, object_key, version_id, origin, encrypted, "
                     "encryption_iv, key_version) VALUES ($1, 'docs/a.txt', $2, 'vaulthalla', TRUE, 'aXY=', $3)",
                     pqxx::params{vaultId, id, keyVersion});
        });
    }

    static void markProviderVersionGone(const unsigned int vaultId, const std::string& id) {
        db::Transactions::exec("RecoveryKeysDbTest::gone", [&](pqxx::work& txn) {
            txn.exec("UPDATE upstream_object_version SET gone_at = NOW() WHERE vault_id = $1 AND version_id = $2",
                     pqxx::params{vaultId, id});
        });
    }

    // Deletes one retired key row; false when the database refuses.
    static bool deleteRetiredKey(const unsigned int vaultId, const unsigned int version) {
        try {
            db::Transactions::exec("RecoveryKeysDbTest::deleteRetiredKey", [&](pqxx::work& txn) {
                txn.exec("DELETE FROM vault_keys_trashed WHERE vault_id = $1 AND version = $2",
                         pqxx::params{vaultId, version});
            });
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }
};

TEST_F(RecoveryKeysDbTest, FinishedRotationsKeepEveryRetainedVersionDecryptable) {
    const auto v = newVault();
    const auto first = v.em->get_key_version();

    const auto plain1 = randomBytes(70 * 1024);
    auto f1 = std::make_shared<fs::model::File>();
    const auto sealed1 = v.em->encrypt(plain1, f1);
    ASSERT_EQ(f1->encrypted_with_key_version, first);

    rotate(v);
    const auto plain2 = randomBytes(1000);
    auto f2 = std::make_shared<fs::model::File>();
    const auto sealed2 = v.em->encrypt(plain2, f2);
    rotate(v);
    const auto current = v.em->get_key_version();
    ASSERT_EQ(current, first + 2);
    ASSERT_FALSE(v.em->rotation_in_progress());

    // Live reads refuse retired versions; recovery reads find them.
    EXPECT_THROW((void)v.em->decrypt(sealed1, f1->encryption_iv, first), std::runtime_error);
    EXPECT_EQ(cu::decrypt_aes256_gcm(sealed1, bytesOf(v.em->historicalKeySnapshot(first)),
                                     cu::b64_decode(f1->encryption_iv)), plain1);
    EXPECT_EQ(cu::decrypt_aes256_gcm(sealed2, bytesOf(v.em->historicalKeySnapshot(first + 1)),
                                     cu::b64_decode(f2->encryption_iv)), plain2);
    // Cached: the same unsealed key object comes back while it is in use.
    EXPECT_EQ(v.em->historicalKeySnapshot(first), v.em->historicalKeySnapshot(first));

    EXPECT_EQ(v.em->retainedKeyVersions(), (std::vector<unsigned int>{first, first + 1, current}));
    EXPECT_TRUE(v.em->hasKeyVersion(first));
    EXPECT_FALSE(v.em->hasKeyVersion(current + 1));
    EXPECT_THROW((void)v.em->historicalKeySnapshot(current + 1), KeyVersionUnavailable);

    // A manager loaded fresh from the database (a restart) unseals them too.
    const EncryptionManager fresh(v.id);
    EXPECT_EQ(bytesOf(fresh.historicalKeySnapshot(first)), bytesOf(v.em->historicalKeySnapshot(first)));
    EXPECT_EQ(fresh.retainedKeyVersions(), v.em->retainedKeyVersions());

    // Re-seal the oldest generation under the current key: the live read path takes it.
    const auto dir = stdfs::temp_directory_path() / ("vh_recovery_keys_reseal_" + rkTag());
    stdfs::create_directories(dir);
    spit(dir / "blob", sealed1);
    auto restored = std::make_shared<fs::model::File>();
    v.em->resealFileToCurrent(dir / "blob", f1->encryption_iv, first, dir / "sidecar", restored);
    EXPECT_EQ(restored->encrypted_with_key_version, current);
    EXPECT_EQ(v.em->decrypt(slurp(dir / "sidecar"), restored->encryption_iv, current), plain1);
    stdfs::remove_all(dir);
}

TEST_F(RecoveryKeysDbTest, AnInterruptedRotationServesBothVersionsAndSurvivesARestart) {
    const auto v = newVault();
    const auto first = v.em->get_key_version();
    const auto plain = randomBytes(2048);
    auto f = std::make_shared<fs::model::File>();
    const auto sealed = v.em->encrypt(plain, f);

    v.em->prepare_key_rotation();
    ASSERT_TRUE(v.em->rotation_in_progress());
    const auto next = v.em->get_key_version();
    ASSERT_EQ(next, first + 1);

    EXPECT_EQ(bytesOf(v.em->historicalKeySnapshot(first)), bytesOf(v.em->keySnapshot(first)));
    EXPECT_EQ(bytesOf(v.em->historicalKeySnapshot(next)), bytesOf(v.em->keySnapshot(next)));
    EXPECT_THROW((void)v.em->keySnapshot(next + 1), std::runtime_error);
    EXPECT_THROW((void)v.em->historicalKeySnapshot(next + 1), KeyVersionUnavailable);
    EXPECT_EQ(v.em->retainedKeyVersions(), (std::vector<unsigned int>{first, next}));

    // A restart mid-rotation loads the old key from vault_keys_trashed (it used to fail on a missing updated_at).
    const EncryptionManager fresh(v.id);
    EXPECT_TRUE(fresh.rotation_in_progress());
    EXPECT_EQ(fresh.decrypt(sealed, f->encryption_iv, first), plain);
    EXPECT_EQ(bytesOf(fresh.historicalKeySnapshot(first)), bytesOf(v.em->keySnapshot(first)));

    v.em->finish_key_rotation();
    EXPECT_THROW((void)v.em->keySnapshot(first), std::runtime_error);
    EXPECT_EQ(cu::decrypt_aes256_gcm(sealed, bytesOf(v.em->historicalKeySnapshot(first)),
                                     cu::b64_decode(f->encryption_iv)), plain);
}

TEST_F(RecoveryKeysDbTest, HistoricalSnapshotsStayValidWhileRotationFinishes) {
    const auto v = newVault();
    const auto first = v.em->get_key_version();
    const auto plain = randomBytes(4096);
    auto f = std::make_shared<fs::model::File>();
    const auto sealed = v.em->encrypt(plain, f);
    v.em->prepare_key_rotation();

    std::atomic<bool> stop{false};
    std::atomic<unsigned> failures{0}, reads{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 6; ++t)
        threads.emplace_back([&] {
            while (!stop.load()) {
                try {
                    const auto key = v.em->historicalKeySnapshot(first);
                    if (cu::decrypt_aes256_gcm(sealed, bytesOf(key), cu::b64_decode(f->encryption_iv)) != plain)
                        failures.fetch_add(1);
                } catch (const std::exception&) {
                    failures.fetch_add(1);
                }
                reads.fetch_add(1);
            }
        });

    while (reads.load() < 50) std::this_thread::yield();
    v.em->finish_key_rotation();
    const auto after = reads.load();
    while (reads.load() < after + 50) std::this_thread::yield();
    stop.store(true);
    for (auto& t : threads) t.join();

    EXPECT_EQ(failures.load(), 0u);
    EXPECT_FALSE(v.em->rotation_in_progress());
}

TEST_F(RecoveryKeysDbTest, NothingDeletesRetiredKeys) {
    const auto v = newVault();
    rotate(v);
    rotate(v);
    ASSERT_EQ(retiredRows(v.id), 2u);

    // Finishing again (nothing pending), the preview cache's retired-key purge and the deleted-vault key expiry all
    // leave a live vault's retired keys alone.
    v.em->finish_key_rotation();
    (void)preview::cache::Store::purgeRetiredKeys(runtime::Deps::get().storageManager->getEngine(v.id));
    (void)db::query::vault::Deletion::expireKeys(std::chrono::system_clock::now() + std::chrono::hours(24 * 3650));
    EXPECT_EQ(retiredRows(v.id), 2u);
}

TEST_F(RecoveryKeysDbTest, TheGuardTriggerKeepsReferencedRetiredKeysAndVaultDeletionStillCascades) {
    const auto v = newVault();
    const auto first = v.em->get_key_version();
    rotate(v);
    rotate(v);
    rotate(v);  // retired: first, first+1, first+2

    addBlob(v.id, first);
    addProviderVersion(v.id, first + 1, "pv-live");

    EXPECT_FALSE(deleteRetiredKey(v.id, first)) << "a recovery blob references it";
    EXPECT_FALSE(deleteRetiredKey(v.id, first + 1)) << "a live provider version references it";
    EXPECT_EQ(retiredRows(v.id), 3u);

    EXPECT_TRUE(deleteRetiredKey(v.id, first + 2)) << "nothing references it";
    markProviderVersionGone(v.id, "pv-live");
    EXPECT_TRUE(deleteRetiredKey(v.id, first + 1)) << "the provider no longer lists that version";
    EXPECT_EQ(retiredRows(v.id), 1u);

    // Deleting the vault itself cascades through the guard (rolled back so the engine keeps a consistent vault).
    const auto [keysLeft, blobsLeft] = db::Transactions::exec("RecoveryKeysDbTest::cascade", [&](pqxx::work& txn) {
        pqxx::subtransaction sub(txn, "cascade");
        sub.exec("DELETE FROM vault WHERE id = $1", pqxx::params{v.id});
        const auto keys = sub.exec("SELECT COUNT(*) FROM vault_keys_trashed WHERE vault_id = $1", pqxx::params{v.id})
                              .one_field_ref().as<unsigned int>();
        const auto blobs = sub.exec("SELECT COUNT(*) FROM recovery_blob WHERE vault_id = $1", pqxx::params{v.id})
                               .one_field_ref().as<unsigned int>();
        sub.abort();
        return std::pair{keys, blobs};
    });
    EXPECT_EQ(keysLeft, 0u);
    EXPECT_EQ(blobsLeft, 0u);
    EXPECT_EQ(retiredRows(v.id), 1u);
}

TEST_F(RecoveryKeysDbTest, ExportCarriesRetiredKeysOnlyWhileRecoverableDataReferencesThem) {
    const auto v = newVault();
    const auto first = v.em->get_key_version();
    rotate(v);
    rotate(v);
    const auto current = v.em->get_key_version();

    // No recovery data: nothing extra to export.
    auto exported = v.em->referencedHistoricalKeys();
    EXPECT_TRUE(exported.keys.empty());
    EXPECT_TRUE(exported.missing.empty());

    addBlob(v.id, first);
    addBlob(v.id, current);  // the current key is exported anyway
    addBlob(v.id, 0);        // unencrypted
    exported = v.em->referencedHistoricalKeys();
    ASSERT_EQ(exported.keys.size(), 1u);
    EXPECT_EQ(exported.keys[0].version, first);
    EXPECT_EQ(bytesOf(exported.keys[0].key), bytesOf(v.em->historicalKeySnapshot(first)));
    EXPECT_GT(exported.keys[0].retired_at, 0);

    addProviderVersion(v.id, first + 1, "pv-a");
    exported = v.em->referencedHistoricalKeys();
    ASSERT_EQ(exported.keys.size(), 2u);
    EXPECT_EQ(exported.keys[1].version, first + 1);

    markProviderVersionGone(v.id, "pv-a");
    exported = v.em->referencedHistoricalKeys();
    ASSERT_EQ(exported.keys.size(), 1u);
    EXPECT_EQ(exported.keys[0].version, first);

    // A referenced version the vault doesn't hold is reported, never invented.
    addBlob(v.id, current + 40);
    exported = v.em->referencedHistoricalKeys();
    EXPECT_EQ(exported.keys.size(), 1u);
    EXPECT_EQ(exported.missing, (std::vector<unsigned int>{current + 40}));
}

}
