#include "crypto/IntegrityRegistry.hpp"
#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "protocols/http/Range.hpp"
#include "storage/Engine.hpp"
#include "storage/GcmFileReader.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <thread>
#include <vector>

namespace vh::crypto::test_gcm_range {

using namespace std::chrono_literals;

namespace {

std::vector<uint8_t> randomBytes(const std::size_t n, const uint32_t seed) {
    std::vector<uint8_t> out(n);
    std::mt19937 rng(seed);
    for (auto& b : out) b = static_cast<uint8_t>(rng());
    return out;
}

std::vector<uint8_t> randomKey() {
    std::vector<uint8_t> key(util::AES_KEY_SIZE);
    randombytes_buf(key.data(), key.size());
    return key;
}

void writeBytes(const std::filesystem::path& path, const std::vector<uint8_t>& bytes) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

struct Sealed {
    std::vector<uint8_t> key, iv, ciphertext, plaintext;
};

Sealed seal(const std::size_t size, const uint32_t seed) {
    Sealed s;
    s.key = randomKey();
    s.plaintext = randomBytes(size, seed);
    s.ciphertext = util::encrypt_aes256_gcm(s.plaintext, s.key, s.iv);
    return s;
}

}

class TempDir {
public:
    TempDir() {
        path_ = std::filesystem::temp_directory_path() / ("vh_gcm_range_" + std::to_string(::getpid()) + "_" +
                                                          std::to_string(counter_++));
        std::filesystem::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        std::filesystem::remove_all(path_, ec);
    }
    [[nodiscard]] const std::filesystem::path& path() const { return path_; }

private:
    std::filesystem::path path_;
    static inline std::atomic<int> counter_{0};
};

namespace {

storage::GcmFileReader::Params paramsFor(const std::filesystem::path& path, const Sealed& s, const bool strict,
                                         const std::string& domain) {
    storage::GcmFileReader::Params p;
    p.path = path;
    p.plaintextSize = s.plaintext.size();
    p.key = std::make_shared<const SecretKey>(s.key);
    std::copy(s.iv.begin(), s.iv.end(), p.iv.begin());
    p.generation.iv_b64 = util::b64_encode(s.iv);
    p.generation.size = s.plaintext.size();
    p.integrityDomain = domain;
    p.strict = strict;
    return p;
}

}

TEST(GcmCtrDecryptAt, MatchesAuthenticatedDecryptionAtEveryBoundary) {
    const auto s = seal(4096 + 7, 1);
    const util::GcmKey key(s.key.data(), util::AES_KEY_SIZE);
    const util::GcmIv iv(s.iv.data(), util::AES_IV_SIZE);
    const auto n = s.plaintext.size();

    for (const uint64_t offset : std::vector<uint64_t>{0, 1, 15, 16, 17, 31, 32, 4095, 4096, n - 1}) {
        for (const std::size_t len : {std::size_t{1}, std::size_t{2}, std::size_t{15}, std::size_t{16},
                                      std::size_t{17}, std::size_t{100}}) {
            if (offset + len > n) continue;
            std::vector<uint8_t> out(len);
            util::gcmCtrDecryptAt(key, iv, offset, {s.ciphertext.data() + offset, len}, out);
            ASSERT_TRUE(std::equal(out.begin(), out.end(), s.plaintext.begin() + static_cast<std::ptrdiff_t>(offset)))
                << "offset " << offset << " len " << len;
        }
    }
}

TEST(GcmCtrDecryptAt, RandomRangesMatchAndDecryptInPlace) {
    const auto s = seal(1 << 20, 2);
    const util::GcmKey key(s.key.data(), util::AES_KEY_SIZE);
    const util::GcmIv iv(s.iv.data(), util::AES_IV_SIZE);
    std::mt19937_64 rng(7);
    for (int i = 0; i < 500; ++i) {
        const auto offset = rng() % s.plaintext.size();
        const auto len = 1 + rng() % std::min<uint64_t>(70000, s.plaintext.size() - offset);
        std::vector<uint8_t> buf(s.ciphertext.begin() + static_cast<std::ptrdiff_t>(offset),
                                 s.ciphertext.begin() + static_cast<std::ptrdiff_t>(offset + len));
        util::gcmCtrDecryptAt(key, iv, offset, buf, buf);  // in place
        ASSERT_TRUE(std::equal(buf.begin(), buf.end(), s.plaintext.begin() + static_cast<std::ptrdiff_t>(offset)));
    }
}

TEST(GcmOneShot, ShortCiphertextIsRejectedNotUnderflowed) {
    const auto key = randomKey();
    std::vector<uint8_t> iv(util::AES_IV_SIZE, 1);
    EXPECT_THROW((void)util::decrypt_aes256_gcm(std::vector<uint8_t>(5, 0), key, iv), std::runtime_error);
    EXPECT_THROW((void)util::decrypt_aes256_gcm({}, key, iv), std::runtime_error);
}

TEST(GcmOneShot, OpenSslAndLibsodiumFormatsInteroperate) {
    const auto key = randomKey();
    const auto plaintext = randomBytes(100'003, 3);
    std::vector<uint8_t> iv;
    const auto sealed = util::encrypt_aes256_gcm(plaintext, key, iv);
    std::vector<uint8_t> viaSodium(plaintext.size());
    unsigned long long len = 0;
    ASSERT_EQ(crypto_aead_aes256gcm_decrypt(viaSodium.data(), &len, nullptr, sealed.data(), sealed.size(), nullptr, 0,
                                            iv.data(), key.data()), 0);
    EXPECT_EQ(viaSodium, plaintext);
    EXPECT_EQ(util::decrypt_aes256_gcm(sealed, key, iv), plaintext);

    auto tampered = sealed;
    tampered[10] ^= 0x01;
    EXPECT_THROW((void)util::decrypt_aes256_gcm(tampered, key, iv), std::runtime_error);
}

TEST(GcmStreamVerifier, AuthenticatesWithAndWithoutAad) {
    const auto key = randomKey();
    std::array<uint8_t, 12> iv{};
    randombytes_buf(iv.data(), iv.size());
    const auto plaintext = randomBytes(5000, 4);
    const std::vector<uint8_t> aad{'h', 'd', 'r'};

    util::GcmStreamEncryptor enc(util::GcmKey(key.data(), 32), iv, aad);
    std::vector<uint8_t> body(plaintext.size());
    enc.update(plaintext, body);
    const auto tag = enc.finish();

    util::GcmStreamVerifier ok(util::GcmKey(key.data(), 32), iv, aad);
    ok.update(body);
    EXPECT_TRUE(ok.finish(tag));

    util::GcmStreamVerifier wrongAad(util::GcmKey(key.data(), 32), iv, std::vector<uint8_t>{'x'});
    wrongAad.update(body);
    EXPECT_FALSE(wrongAad.finish(tag));
}

class GcmFileReaderTest : public ::testing::Test {
protected:
    void SetUp() override { IntegrityRegistry::instance().clearForTesting(); }
    TempDir dir;
};

TEST_F(GcmFileReaderTest, ServesArbitraryRangesOfASealedFile) {
    const auto s = seal(3 * 1024 * 1024 + 11, 5);
    const auto path = dir.path() / "f.bin";
    writeBytes(path, s.ciphertext);
    storage::GcmFileReader reader(paramsFor(path, s, false, "test:ranges"));
    EXPECT_EQ(reader.size(), s.plaintext.size());

    std::mt19937_64 rng(11);
    for (int i = 0; i < 300; ++i) {
        const auto offset = rng() % s.plaintext.size();
        std::vector<uint8_t> out(1 + rng() % 300000);
        const auto got = reader.read(offset, out);
        ASSERT_EQ(got, std::min<uint64_t>(out.size(), s.plaintext.size() - offset));
        ASSERT_TRUE(std::equal(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(got),
                               s.plaintext.begin() + static_cast<std::ptrdiff_t>(offset)));
    }
    std::vector<uint8_t> past(10);
    EXPECT_EQ(reader.read(s.plaintext.size(), past), 0u);
    EXPECT_EQ(reader.read(s.plaintext.size() + 100, past), 0u);
    EXPECT_EQ(reader.integrityState() == IntegrityState::Failed, false);
}

TEST_F(GcmFileReaderTest, OptimisticReaderAbortsOnceBackgroundVerificationFails) {
    auto s = seal(2 * 1024 * 1024, 6);
    auto tampered = s.ciphertext;
    tampered[tampered.size() - 1] ^= 0xff;  // corrupt the tag
    const auto path = dir.path() / "bad.bin";
    writeBytes(path, tampered);

    storage::GcmFileReader reader(paramsFor(path, s, false, "test:optimistic-bad"));
    std::vector<uint8_t> out(4096);
    // The first read schedules verification and may be served before the verdict (optimistic), or refused when the
    // background verification already failed (a busy machine runs the reader late): both are correct.
    try {
        (void)reader.read(0, out);
    } catch (const storage::IntegrityError&) {
    }
    const auto deadline = std::chrono::steady_clock::now() + 10s;
    while (reader.integrityState() != IntegrityState::Failed && std::chrono::steady_clock::now() < deadline)
        std::this_thread::sleep_for(5ms);
    ASSERT_EQ(reader.integrityState(), IntegrityState::Failed);
    EXPECT_THROW((void)reader.read(0, out), storage::IntegrityError);

    // A new reader of the same exact bytes fails fast from the shared verdict.
    storage::GcmFileReader again(paramsFor(path, s, false, "test:optimistic-bad"));
    EXPECT_THROW((void)again.read(100, out), storage::IntegrityError);
}

TEST_F(GcmFileReaderTest, CorruptedCiphertextBodyIsDetected) {
    auto s = seal(300'000, 7);
    auto tampered = s.ciphertext;
    tampered[150'000] ^= 0x40;
    const auto path = dir.path() / "body.bin";
    writeBytes(path, tampered);
    EXPECT_THROW(storage::GcmFileReader(paramsFor(path, s, true, "test:body")), storage::IntegrityError);
}

TEST_F(GcmFileReaderTest, StrictReaderVerifiesBeforeReleasingAnyByte) {
    const auto s = seal(1'000'000, 8);
    const auto good = dir.path() / "good.bin";
    writeBytes(good, s.ciphertext);
    storage::GcmFileReader reader(paramsFor(good, s, true, "test:strict-good"));
    EXPECT_EQ(reader.integrityState(), IntegrityState::Verified);

    auto tampered = s.ciphertext;
    tampered[0] ^= 1;
    const auto bad = dir.path() / "strict-bad.bin";
    writeBytes(bad, tampered);
    EXPECT_THROW(storage::GcmFileReader(paramsFor(bad, s, true, "test:strict-bad")), storage::IntegrityError);
}

TEST_F(GcmFileReaderTest, SizeMismatchIsRefused) {
    const auto s = seal(1000, 9);
    const auto path = dir.path() / "short.bin";
    writeBytes(path, std::vector<uint8_t>(s.ciphertext.begin(), s.ciphertext.end() - 3));
    EXPECT_THROW(storage::GcmFileReader(paramsFor(path, s, false, "test:short")), storage::IntegrityError);
}

TEST_F(GcmFileReaderTest, ReplacementDuringVerificationIsSupersededNotCorruption) {
    const auto s = seal(500'000, 10);
    auto tampered = s.ciphertext;
    tampered[42] ^= 1;
    const auto path = dir.path() / "replaced.bin";
    writeBytes(path, tampered);
    auto p = paramsFor(path, s, true, "test:superseded");
    p.stillCurrent = [] { return false; };  // the file got a new IV meanwhile
    try {
        storage::GcmFileReader reader(std::move(p));
        FAIL() << "expected IntegrityError";
    } catch (const storage::IntegrityError& e) {
        EXPECT_NE(std::string(e.what()).find("changed"), std::string::npos);
    }
    EXPECT_EQ(IntegrityRegistry::instance().stats().failed, 0u);
}

TEST_F(GcmFileReaderTest, ReadAllAuthenticatedIsOnePassAndRecordsTheVerdict) {
    const auto s = seal(70'000, 12);
    const auto path = dir.path() / "all.bin";
    writeBytes(path, s.ciphertext);
    storage::GcmFileReader reader(paramsFor(path, s, false, "test:all"));
    EXPECT_EQ(storage::readAll(reader, 1 << 20), s.plaintext);
    EXPECT_THROW((void)storage::readAll(reader, 10), std::length_error);
    EXPECT_EQ(IntegrityRegistry::instance().stats().scheduled, 0u);  // no separate verification pass
}

TEST_F(GcmFileReaderTest, ConcurrentReadersShareOneVerification) {
    const auto s = seal(4 * 1024 * 1024, 13);
    const auto path = dir.path() / "concurrent.bin";
    writeBytes(path, s.ciphertext);

    std::atomic<int> mismatches{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t) {
        threads.emplace_back([&, t] {
            storage::GcmFileReader reader(paramsFor(path, s, false, "test:concurrent"));
            std::mt19937_64 rng(100 + t);
            std::vector<uint8_t> out(65536);
            for (int i = 0; i < 200; ++i) {
                const auto offset = rng() % s.plaintext.size();
                const auto got = reader.read(offset, out);
                if (!std::equal(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(got),
                                s.plaintext.begin() + static_cast<std::ptrdiff_t>(offset)))
                    ++mismatches;
            }
        });
    }
    for (auto& th : threads) th.join();
    EXPECT_EQ(mismatches.load(), 0);
    EXPECT_EQ(IntegrityRegistry::instance().stats().scheduled, 1u);
}

TEST(EngineReader, OpensEncryptedVaultFilesThroughTheEncryptionManager) {
    TempDir dir;
    IntegrityRegistry::instance().clearForTesting();
    const auto key = randomKey();
    auto engine = std::make_shared<storage::Engine>();
    engine->vault = std::make_shared<vault::model::Vault>();
    engine->vault->id = 77;
    engine->encryptionManager =
        std::make_shared<vault::EncryptionManager>(vault::EncryptionManager::ForTesting{}, 77, key, 3);

    const auto plaintext = randomBytes(123'457, 14);
    auto file = std::make_shared<fs::model::File>();
    file->id = 5;
    file->path = "/clip.bin";
    file->backing_path = dir.path() / "ALIAS";
    file->size_bytes = plaintext.size();
    writeBytes(file->backing_path, engine->encryptionManager->encrypt(plaintext, file));
    EXPECT_EQ(file->encrypted_with_key_version, 3u);

    const auto reader = engine->openPlaintextReader(file, {.integrity = storage::IntegrityPolicy::Strict});
    std::vector<uint8_t> out(1000);
    ASSERT_EQ(reader->read(50'000, out), out.size());
    EXPECT_TRUE(std::equal(out.begin(), out.end(), plaintext.begin() + 50'000));
    EXPECT_EQ(reader->generation().vault_id, 77u);
    EXPECT_EQ(reader->generation().sourceId(), file->encryption_iv);
    EXPECT_EQ(reader->generation().etag().front(), '"');

    // Empty files need no key and no backing bytes.
    auto empty = std::make_shared<fs::model::File>();
    empty->id = 6;
    empty->size_bytes = 0;
    EXPECT_EQ(engine->openPlaintextReader(empty)->size(), 0u);

    // A different key version is not resolvable outside rotation.
    file->encrypted_with_key_version = 2;
    EXPECT_THROW((void)engine->openPlaintextReader(file), std::runtime_error);
}

TEST(EncryptionManagerKeys, SnapshotsSurviveRotationAndOldVersionsResolveOnlyDuringIt) {
    const auto oldKey = randomKey();
    const auto newKey = randomKey();
    vault::EncryptionManager rotating(vault::EncryptionManager::ForTesting{}, 1, newKey, 5, oldKey);
    EXPECT_TRUE(rotating.rotation_in_progress());
    const auto snapOld = rotating.keySnapshot(4);
    EXPECT_TRUE(std::equal(oldKey.begin(), oldKey.end(), snapOld->bytes().begin()));
    EXPECT_TRUE(std::equal(newKey.begin(), newKey.end(), rotating.keySnapshot(5)->bytes().begin()));
    EXPECT_THROW((void)rotating.keySnapshot(3), std::runtime_error);

    vault::EncryptionManager settled(vault::EncryptionManager::ForTesting{}, 1, newKey, 5);
    EXPECT_THROW((void)settled.keySnapshot(4), std::runtime_error);
    EXPECT_EQ(settled.currentKey().version, 5u);
}

TEST(EncryptionManagerKeys, ConcurrentEncryptReadsNeverSeeTornKeyState) {
    const auto key = randomKey();
    vault::EncryptionManager em(vault::EncryptionManager::ForTesting{}, 1, key, 9);
    std::atomic<int> errors{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
        threads.emplace_back([&] {
            for (int i = 0; i < 200; ++i) {
                auto f = std::make_shared<fs::model::File>();
                const std::vector<uint8_t> pt(64, static_cast<uint8_t>(i));
                const auto ct = em.encrypt(pt, f);
                if (f->encrypted_with_key_version != 9 || em.decrypt(ct, f->encryption_iv, 9) != pt) ++errors;
            }
        });
    for (auto& th : threads) th.join();
    EXPECT_EQ(errors.load(), 0);
}

TEST(HttpRange, ParsesRfc9110SingleRanges) {
    using protocols::http::range::parse;
    auto p = parse("bytes=0-499");
    ASSERT_TRUE(p.spec);
    EXPECT_EQ(*p.spec->first, 0u);
    EXPECT_EQ(*p.spec->last, 499u);
    p = parse("Bytes = 500-");
    EXPECT_TRUE(p.malformed);  // no whitespace allowed around '=' per grammar
    p = parse("BYTES=500-");
    ASSERT_TRUE(p.spec);
    EXPECT_FALSE(p.spec->last);
    p = parse("bytes=-200");
    ASSERT_TRUE(p.spec);
    EXPECT_FALSE(p.spec->first);
    EXPECT_EQ(*p.spec->last, 200u);
    EXPECT_TRUE(parse("bytes=0-1,5-6").multi);
    EXPECT_TRUE(parse("bytes=5-1").malformed);
    EXPECT_TRUE(parse("bytes=").malformed);
    EXPECT_TRUE(parse("items=0-1").malformed);
    EXPECT_TRUE(parse("bytes=a-b").malformed);
    EXPECT_TRUE(parse("bytes=99999999999999999999999-").malformed);  // overflow
    EXPECT_TRUE(parse("bytes=0-1, ").spec.has_value());               // empty list element allowed
}

TEST(HttpRange, ResolvesAgainstTheRepresentationSize) {
    using namespace protocols::http::range;
    auto r = resolve({.first = 0, .last = 499}, 1000);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->length(), 500u);
    r = resolve({.first = 900, .last = 5000}, 1000);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->last, 999u);
    r = resolve({.first = std::nullopt, .last = 100}, 1000);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->first, 900u);
    r = resolve({.first = std::nullopt, .last = 5000}, 1000);
    ASSERT_TRUE(r);
    EXPECT_EQ(r->first, 0u);
    EXPECT_FALSE(resolve({.first = 1000, .last = std::nullopt}, 1000));
    EXPECT_FALSE(resolve({.first = std::nullopt, .last = 0}, 1000));
    EXPECT_FALSE(resolve({.first = 0, .last = 0}, 0));
    EXPECT_EQ(contentRange({.first = 0, .last = 9}, 10), "bytes 0-9/10");
    EXPECT_EQ(unsatisfiedContentRange(10), "bytes */10");
}

}
