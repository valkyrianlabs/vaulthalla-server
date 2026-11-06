// VHF1 at rest for new writes (#367, WS2-b; design/encryption/02-authenticated-file-format.md §3.7, §3.8, §4, §7).
//
//   Vhf1AtRest*        every EncryptionManager write is a VHF1 generation bound to the vault, the object and the key
//                      version; legacy GCM keeps reading.
//   Vhf1Streaming*     the streaming writer (encryptToFile) for 0 bytes, exact chunk multiples and odd sizes.
//   Vhf1RangeReader*   the local chunk reader: never a byte of a failed chunk, the size from the catalog, sticky.
//   IntegrityContract  no VHF1 read path reaches the GCM CTR keystream (gcmCtrDecryptAt).
//   Vhf1Resumable*     the resumable sealing cursor (vault::content::PrefixSealer).
//   Vhf1Sidecar*       the rotation sidecar protocol with VHF1 sidecars.
//   Vhf1Upload*        one object per file version on a fake S3 (0 bytes, small, multipart), part failure, a lost
//                      Complete response, retries.

#include "../helpers/versioned_bucket.hpp"

#include "crypto/IntegrityRegistry.hpp"
#include "crypto/util/Gcm.hpp"
#include "crypto/util/encrypt.hpp"
#include "crypto/util/hash.hpp"
#include "crypto/vhf1/Format.hpp"
#include "fs/PlaintextSource.hpp"
#include "fs/model/File.hpp"
#include "storage/CloudEngine.hpp"
#include "storage/Engine.hpp"
#include "storage/PlaintextReader.hpp"
#include "storage/s3/Controller.hpp"
#include "sync/rotation/Rotation.hpp"
#include "sync/rotation/Runtime.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/PrefixSealer.hpp"
#include "vault/model/S3Vault.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <random>
#include <unistd.h>
#include <vector>

namespace vh::test_vhf1_at_rest {

namespace stdfs = std::filesystem;
namespace content = vault::content;
using Bytes = std::vector<uint8_t>;
using FileSP = std::shared_ptr<fs::model::File>;

constexpr unsigned int kVault = 31;
constexpr unsigned int kKeyVersion = 4;
constexpr uint64_t kChunk = 64 * 1024;
constexpr uint64_t kSealedChunk = kChunk + 16;

Bytes randomBytes(const std::size_t n, const unsigned seed) {
    std::mt19937 rng(seed);
    Bytes out(n);
    for (auto& b : out) b = static_cast<uint8_t>(rng());
    return out;
}

Bytes slurp(const stdfs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void spit(const stdfs::path& p, const Bytes& bytes) {
    stdfs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary | std::ios::trunc);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

// XORs one byte in place (a write of a fixed value would leave the file unchanged 1 time in 256).
void flipByte(const stdfs::path& p, const uint64_t offset) {
    auto bytes = slurp(p);
    bytes.at(static_cast<std::size_t>(offset)) ^= 0x5a;
    spit(p, bytes);
}

class TempDir {
public:
    TempDir() : path_(stdfs::temp_directory_path() / ("vh_vhf1_at_rest_" + std::to_string(::getpid()) + "_" +
                                                       std::to_string(counter_++))) {
        stdfs::remove_all(path_);
        stdfs::create_directories(path_);
    }
    ~TempDir() {
        std::error_code ec;
        stdfs::remove_all(path_, ec);
    }
    [[nodiscard]] const stdfs::path& path() const { return path_; }

private:
    stdfs::path path_;
    static inline std::atomic<int> counter_{0};
};

struct Fd {
    explicit Fd(const int f) : fd(f) {}
    ~Fd() { if (fd >= 0) ::close(fd); }
    Fd(const Fd&) = delete;
    Fd& operator=(const Fd&) = delete;
    int fd;
};

class Vhf1AtRestTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        key_ = randomBytes(32, 7);
        em_ = std::make_shared<vault::EncryptionManager>(vault::EncryptionManager::ForTesting{}, kVault, key_, kKeyVersion);
        engine_ = std::make_shared<storage::Engine>();
        engine_->vault = std::make_shared<vault::model::Vault>();
        engine_->vault->id = kVault;
        engine_->encryptionManager = em_;
        crypto::IntegrityRegistry::instance().clearForTesting();
    }

    // A vault file whose backing bytes are VHF1, sealed as a write would seal them.
    FileSP sealedFile(const Bytes& plaintext, const std::string& name = "file.bin") {
        auto f = std::make_shared<fs::model::File>();
        f->id = ++ids_;
        f->vault_id = kVault;
        f->path = "/" + name;
        f->backing_path = dir_.path() / ("ALIAS" + std::to_string(f->id));
        f->size_bytes = plaintext.size();
        spit(f->backing_path, em_->encrypt(plaintext, f));
        return f;
    }

    [[nodiscard]] content::Binding bindingOf(const fs::model::File& f) const {
        return {.vaultUid = em_->vaultUid(), .generation = f.encryption_iv, .keyVersion = f.encrypted_with_key_version};
    }

    TempDir dir_;
    Bytes key_;
    std::shared_ptr<vault::EncryptionManager> em_;
    std::shared_ptr<storage::Engine> engine_;
    unsigned int ids_{0};
};

// ---- Vhf1AtRest --------------------------------------------------------------------------------------------------

TEST_F(Vhf1AtRestTest, EveryWriteIsAVhf1GenerationBoundToVaultObjectAndKeyVersion) {
    const auto plaintext = randomBytes(150'000, 1);
    auto f = std::make_shared<fs::model::File>();
    const auto sealed = em_->encrypt(plaintext, f);

    ASSERT_TRUE(content::isVhf1(f->encryption_iv));
    EXPECT_EQ(content::formatOf(f->encryption_iv), content::Format::Vhf1);
    EXPECT_EQ(f->encrypted_with_key_version, kKeyVersion);
    ASSERT_TRUE(f->object_uid) << "a new file draws its object uid when sealed";
    EXPECT_EQ(sealed.size(), content::newSealedSize(plaintext.size()));
    EXPECT_TRUE(std::equal(crypto::vhf1::kMagic.begin(), crypto::vhf1::kMagic.end(), sealed.begin()));

    // The header names this vault, this object, this key version, and the generation is its salt.
    const auto header = content::openHeader(sealed, {.vaultUid = em_->vaultUid(), .generation = f->encryption_iv,
                                                      .keyVersion = kKeyVersion, .objectUid = f->object_uid},
                                            em_->keySnapshot(kKeyVersion));
    EXPECT_EQ(header.params().vaultUid, vault::EncryptionManager::testVaultUid(kVault));
    EXPECT_EQ(header.params().objectUid, *f->object_uid);
    EXPECT_EQ(content::generationOf(header.params().salt), f->encryption_iv);
    EXPECT_EQ(em_->decrypt(sealed, f->encryption_iv, kKeyVersion), plaintext);

    // An existing file keeps its object uid; every write is a new salt.
    const auto uid = *f->object_uid;
    const auto first = f->encryption_iv;
    (void)em_->encrypt(plaintext, f);
    EXPECT_EQ(*f->object_uid, uid);
    EXPECT_NE(f->encryption_iv, first);
}

TEST_F(Vhf1AtRestTest, ReadsAreBoundToTheVaultTheGenerationAndTheKeyVersion) {
    const auto plaintext = randomBytes(10'000, 2);
    auto f = std::make_shared<fs::model::File>();
    const auto sealed = em_->encrypt(plaintext, f);

    // Another sealing of the same file (a stale or rolled-back object) is not this generation.
    auto again = std::make_shared<fs::model::File>(*f);
    (void)em_->encrypt(plaintext, again);
    EXPECT_THROW((void)em_->decrypt(sealed, again->encryption_iv, kKeyVersion), storage::IntegrityError);

    // Another vault's manager (another vault uid) refuses it even with the same key.
    vault::EncryptionManager other(vault::EncryptionManager::ForTesting{}, kVault + 1, key_, kKeyVersion);
    EXPECT_THROW((void)other.decrypt(sealed, f->encryption_iv, kKeyVersion), storage::IntegrityError);

    // A flipped byte anywhere fails closed.
    auto bad = sealed;
    bad[bad.size() / 2] ^= 0x01;
    EXPECT_THROW((void)em_->decrypt(bad, f->encryption_iv, kKeyVersion), storage::IntegrityError);
}

TEST_F(Vhf1AtRestTest, LegacyGcmGenerationsKeepReadingAndAreNotRewritten) {
    const auto plaintext = randomBytes(90'000, 3);
    Bytes iv;
    const auto legacy = crypto::util::encrypt_aes256_gcm(plaintext, key_, iv);
    auto f = std::make_shared<fs::model::File>();
    f->id = 900;
    f->path = "/legacy.bin";
    f->backing_path = dir_.path() / "LEGACY";
    f->size_bytes = plaintext.size();
    f->encryption_iv = crypto::util::b64_encode(iv);
    f->encrypted_with_key_version = kKeyVersion;
    spit(f->backing_path, legacy);
    EXPECT_EQ(content::formatOf(f->encryption_iv), content::Format::Gcm0);

    EXPECT_EQ(em_->decrypt(legacy, f->encryption_iv, kKeyVersion), plaintext);
    Bytes streamed;
    em_->decryptFileTo(f->backing_path, [&](const std::span<const uint8_t> b) { streamed.insert(streamed.end(), b.begin(), b.end()); },
                       f->encryption_iv, kKeyVersion);
    EXPECT_EQ(streamed, plaintext);
    const auto reader = engine_->openPlaintextReader(f, {.integrity = storage::IntegrityPolicy::Strict});
    EXPECT_EQ(storage::readAll(*reader, plaintext.size()), plaintext);
    EXPECT_TRUE(em_->verifyFile(f->backing_path, plaintext.size(), f->encryption_iv, kKeyVersion));
    EXPECT_EQ(slurp(f->backing_path), legacy) << "reading never rewrites a legacy file";

    // A re-seal (restore under an older key, key rotation) turns it into a new VHF1 generation.
    auto resealed = std::make_shared<fs::model::File>(*f);
    em_->resealFileToCurrent(f->backing_path, f->encryption_iv, kKeyVersion, dir_.path() / "RESEALED", resealed);
    EXPECT_TRUE(content::isVhf1(resealed->encryption_iv));
    EXPECT_EQ(em_->decrypt(slurp(dir_.path() / "RESEALED"), resealed->encryption_iv, kKeyVersion), plaintext);
}

TEST_F(Vhf1AtRestTest, SizeMathTellsTheFormatsApart) {
    EXPECT_EQ(content::sealedSize(0, content::Format::Vhf1), 136u);
    EXPECT_EQ(content::sealedSize(1000, content::Format::Gcm0), 1016u);
    EXPECT_EQ(content::sealedSize(1000, content::Format::Plain), 1000u);
    EXPECT_EQ(content::sealedSize(5 * 1024 * 1024, content::Format::Vhf1), 5'244'280u);
    EXPECT_EQ(content::plaintextSizeOf(5'244'280, content::Format::Vhf1), 5u * 1024 * 1024);
    EXPECT_EQ(content::plaintextSizeOf(1016, content::Format::Gcm0), 1000u);
    EXPECT_FALSE(content::plaintextSizeOf(120 + kSealedChunk + 16, content::Format::Vhf1));  // an empty chunk after a full one
    EXPECT_FALSE(content::plaintextSizeOf(10, content::Format::Gcm0));
    EXPECT_FALSE(content::isVhf1("not base64 at all"));
    EXPECT_THROW((void)content::formatOf("AAAA"), std::invalid_argument);  // 3 bytes: neither an IV nor a salt
}

// ---- Vhf1Streaming -----------------------------------------------------------------------------------------------

TEST_F(Vhf1AtRestTest, Vhf1StreamingWriterHandlesEmptyExactMultiplesAndOddSizes) {
    for (const uint64_t size : {uint64_t{0}, uint64_t{1}, kChunk - 1, kChunk, kChunk + 1, 3 * kChunk, 3 * kChunk + 77}) {
        SCOPED_TRACE(size);
        const auto plaintext = randomBytes(static_cast<std::size_t>(size), static_cast<unsigned>(size + 1));
        // A source that hands out odd-sized pieces, as staged uploads and working copies do.
        const fs::PlaintextSource source{
            .size = size,
            .read = [&](const uint64_t offset, const std::span<uint8_t> out) -> std::size_t {
                const auto n = std::min<uint64_t>({out.size(), size - offset, 4097});
                std::copy_n(plaintext.begin() + static_cast<std::ptrdiff_t>(offset), n, out.begin());
                return static_cast<std::size_t>(n);
            }};
        auto f = std::make_shared<fs::model::File>();
        const auto path = dir_.path() / ("stream-" + std::to_string(size));
        em_->encryptToFile(source, path, f);
        ASSERT_TRUE(content::isVhf1(f->encryption_iv));
        EXPECT_EQ(stdfs::file_size(path), crypto::vhf1::objectSizeFor(size, 16));

        Bytes chunks;
        em_->decryptFileTo(path, [&](const std::span<const uint8_t> b) { chunks.insert(chunks.end(), b.begin(), b.end()); },
                           f->encryption_iv, kKeyVersion);
        EXPECT_EQ(chunks, plaintext);
        EXPECT_EQ(em_->decrypt(slurp(path), f->encryption_iv, kKeyVersion), plaintext);
        EXPECT_TRUE(em_->verifyFile(path, size, f->encryption_iv, kKeyVersion));
        EXPECT_FALSE(em_->verifyFile(path, size + 1, f->encryption_iv, kKeyVersion));
    }
}

TEST_F(Vhf1AtRestTest, Vhf1StreamingOpenerReleasesOnlyAuthenticatedChunks) {
    const auto plaintext = randomBytes(5 * kChunk, 5);
    auto f = std::make_shared<fs::model::File>();
    auto sealed = em_->encrypt(plaintext, f);
    sealed[120 + 3 * kSealedChunk + 9] ^= 0x10;  // chunk 3
    content::StreamOpener opener(bindingOf(*f), em_->keySnapshot(kKeyVersion), sealed.size());
    Bytes out;
    const content::Sink sink = [&](const std::span<const uint8_t> b) { out.insert(out.end(), b.begin(), b.end()); };
    EXPECT_THROW(
        {
            for (std::size_t pos = 0; pos < sealed.size(); pos += 10'000)
                opener.update(std::span<const uint8_t>(sealed).subspan(pos, std::min<std::size_t>(10'000, sealed.size() - pos)),
                              sink);
            opener.finish(sink);
        },
        storage::IntegrityError);
    EXPECT_EQ(out.size(), 3 * kChunk) << "chunks 0..2 authenticated; nothing of chunk 3 was released";
    EXPECT_TRUE(std::equal(out.begin(), out.end(), plaintext.begin()));
}

// ---- Vhf1RangeReader (local) -------------------------------------------------------------------------------------

TEST_F(Vhf1AtRestTest, Vhf1RangeReaderServesEveryRangeOfTheGeneration) {
    const auto plaintext = randomBytes(4 * kChunk + 1234, 6);
    const auto f = sealedFile(plaintext);
    const auto reader = engine_->openPlaintextReader(f);
    EXPECT_EQ(reader->size(), plaintext.size());
    EXPECT_EQ(reader->generation().sourceId(), f->encryption_iv);
    for (const auto& [offset, length] : std::vector<std::pair<uint64_t, uint64_t>>{
             {0, 1}, {0, kChunk}, {kChunk - 3, 10}, {100, 3 * kChunk}, {4 * kChunk, 1234}, {4 * kChunk + 1000, 5000}}) {
        Bytes out(static_cast<std::size_t>(length));
        const auto got = reader->read(offset, out);
        ASSERT_EQ(got, std::min<uint64_t>(length, plaintext.size() - offset));
        EXPECT_TRUE(std::equal(out.begin(), out.begin() + static_cast<std::ptrdiff_t>(got),
                               plaintext.begin() + static_cast<std::ptrdiff_t>(offset)));
    }
    EXPECT_EQ(reader->readAllAuthenticated(plaintext.size()), plaintext);
    EXPECT_NO_THROW(reader->requireAuthenticated());
}

TEST_F(Vhf1AtRestTest, Vhf1RangeReaderNeverReturnsBytesOfAFailedChunkAndTheFailureIsSticky) {
    const auto plaintext = randomBytes(4 * kChunk, 7);
    const auto f = sealedFile(plaintext);
    flipByte(f->backing_path, 120 + 2 * kSealedChunk + 100);
    const auto reader = engine_->openPlaintextReader(f);
    Bytes good(100);
    ASSERT_EQ(reader->read(10, good), good.size());  // chunk 0 authenticates
    EXPECT_TRUE(std::equal(good.begin(), good.end(), plaintext.begin() + 10));

    Bytes bad(200, 0xEE);
    EXPECT_THROW((void)reader->read(2 * kChunk - 100, bad), storage::IntegrityError);  // spans chunks 1 and 2
    EXPECT_TRUE(std::ranges::all_of(bad, [](const uint8_t b) { return b == 0; }))
        << "a failed read leaves nothing in the caller's buffer";
    EXPECT_THROW((void)reader->read(10, good), storage::IntegrityError) << "sticky for this reader";
    EXPECT_THROW((void)engine_->openPlaintextReader(f), storage::IntegrityError) << "and for the generation";
}

TEST_F(Vhf1AtRestTest, Vhf1RangeReaderRequiresTheCatalogsSizeAndGeneration) {
    const auto plaintext = randomBytes(2 * kChunk + 5, 8);
    const auto f = sealedFile(plaintext);

    // A truncated object (cut at a chunk boundary) can't pass for a shorter file: the size comes from the catalog.
    auto shorter = std::make_shared<fs::model::File>(*f);
    shorter->size_bytes = 2 * kChunk;
    EXPECT_THROW((void)engine_->openPlaintextReader(shorter), storage::IntegrityError);
    {
        auto bytes = slurp(f->backing_path);
        bytes.resize(120 + 2 * kSealedChunk);
        spit(dir_.path() / "TRUNC", bytes);
    }
    auto truncated = std::make_shared<fs::model::File>(*shorter);
    truncated->backing_path = dir_.path() / "TRUNC";
    const auto cut = engine_->openPlaintextReader(truncated);
    EXPECT_THROW((void)cut->readAllAuthenticated(2 * kChunk), storage::IntegrityError)
        << "chunk 1 was sealed non-final: a cut object never authenticates as a shorter complete one";

    // Another sealing of the file under this row (a stale copy, a rollback) is another generation.
    auto stale = std::make_shared<fs::model::File>(*f);
    auto other = std::make_shared<fs::model::File>(*f);
    (void)em_->encrypt(plaintext, other);
    stale->encryption_iv = other->encryption_iv;
    EXPECT_THROW((void)engine_->openPlaintextReader(stale), storage::IntegrityError);
}

TEST_F(Vhf1AtRestTest, Vhf1RangeReaderRequireAuthenticatedChecksChunksNotReadYet) {
    const auto plaintext = randomBytes(3 * kChunk, 9);
    const auto f = sealedFile(plaintext);
    flipByte(f->backing_path, stdfs::file_size(f->backing_path) - 5);  // the last chunk's tag
    const auto reader = engine_->openPlaintextReader(f);
    Bytes head(kChunk);
    ASSERT_EQ(reader->read(0, head), head.size());
    EXPECT_THROW(reader->requireAuthenticated(), storage::IntegrityError);
}

// ---- IntegrityContract -------------------------------------------------------------------------------------------

TEST_F(Vhf1AtRestTest, IntegrityContractNoVhf1ReadReachesTheGcmCtrKeystream) {
    const auto plaintext = randomBytes(3 * kChunk + 999, 10);
    const auto f = sealedFile(plaintext);
    const auto before = crypto::util::gcmCtrDecryptAtCallsForTesting();

    for (const auto policy : {storage::IntegrityPolicy::Optimistic, storage::IntegrityPolicy::Strict}) {
        const auto reader = engine_->openPlaintextReader(f, {.integrity = policy});
        Bytes out(4096);
        for (uint64_t at = 0; at < plaintext.size(); at += 50'000) (void)reader->read(at, out);
        (void)reader->readAllAuthenticated(plaintext.size());
        reader->requireAuthenticated();
    }
    em_->decryptFileTo(f->backing_path, [](std::span<const uint8_t>) {}, f->encryption_iv, kKeyVersion);
    (void)em_->decrypt(slurp(f->backing_path), f->encryption_iv, kKeyVersion);
    EXPECT_TRUE(em_->verifyFile(f->backing_path, plaintext.size(), f->encryption_iv, kKeyVersion));
    EXPECT_EQ(crypto::util::gcmCtrDecryptAtCallsForTesting(), before);

    // The counter is live: a legacy positioned read does go through the keystream.
    Bytes iv;
    const auto legacy = crypto::util::encrypt_aes256_gcm(plaintext, key_, iv);
    auto old = std::make_shared<fs::model::File>(*f);
    old->id = 777;
    old->backing_path = dir_.path() / "OLD";
    old->encryption_iv = crypto::util::b64_encode(iv);
    spit(old->backing_path, legacy);
    Bytes out(100);
    (void)engine_->openPlaintextReader(old, {.integrity = storage::IntegrityPolicy::Strict})->read(0, out);
    EXPECT_GT(crypto::util::gcmCtrDecryptAtCallsForTesting(), before);
}

// ---- Vhf1Resumable (the sealing cursor) --------------------------------------------------------------------------

class Vhf1ResumableTest : public Vhf1AtRestTest {
protected:
    content::PrefixSealer::Params params(const int fd, const uint64_t size, const std::string& generation) const {
        return {.fd = fd,
                .binding = {.vaultUid = em_->vaultUid(), .generation = generation, .keyVersion = kKeyVersion,
                            .objectUid = objectUid_},
                .key = em_->keySnapshot(kKeyVersion),
                .plaintextSize = size};
    }
    [[nodiscard]] static std::string freshGeneration() { return content::generationOf(crypto::vhf1::freshSalt()); }

    crypto::id::ObjectUid objectUid_ = crypto::id::newObjectUid();

    // What a reader of the finished object gets.
    Bytes open(const stdfs::path& p, const std::string& generation) const {
        return em_->decrypt(slurp(p), generation, kKeyVersion);
    }
};

TEST_F(Vhf1ResumableTest, Vhf1ResumableSealsWholeChunksOnlyAndTheLastOneFinal) {
    const auto plaintext = randomBytes(3 * kChunk + 500, 11);
    const auto path = dir_.path() / "spool";
    Fd fd(::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600));
    const auto generation = freshGeneration();
    auto sealer = content::PrefixSealer::begin(params(fd.fd, plaintext.size(), generation));
    EXPECT_EQ(stdfs::file_size(path), 120u) << "the header is written first";

    ASSERT_EQ(sealer->feed(0, std::span(plaintext).first(100'000)), content::PrefixSealer::Fed::Ok);
    EXPECT_EQ(sealer->fed(), 100'000u);
    EXPECT_EQ(sealer->sealed(), kChunk) << "the partial chunk is held back in memory";
    EXPECT_EQ(stdfs::file_size(path), 120 + kSealedChunk);

    ASSERT_EQ(sealer->feed(100'000, std::span(plaintext).subspan(100'000, 3 * kChunk - 100'000)),
              content::PrefixSealer::Fed::Ok);
    EXPECT_EQ(sealer->sealed(), 3 * kChunk) << "chunk 2 is complete but not final: more follows";
    EXPECT_FALSE(sealer->complete());
    ASSERT_EQ(sealer->feed(3 * kChunk, std::span(plaintext).subspan(3 * kChunk)), content::PrefixSealer::Fed::Ok);
    ASSERT_TRUE(sealer->complete());
    EXPECT_EQ(stdfs::file_size(path), content::newSealedSize(plaintext.size()));
    EXPECT_EQ(open(path, generation), plaintext);
    EXPECT_EQ(sealer->contentHash(), crypto::hash::blake2b(path));
}

TEST_F(Vhf1ResumableTest, Vhf1ResumableRestartRebuildsByAuthenticationWithoutReencrypting) {
    const auto plaintext = randomBytes(4 * kChunk + 3, 12);
    const auto path = dir_.path() / "spool";
    const auto generation = freshGeneration();
    Bytes prefixBytes;
    {
        Fd fd(::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600));
        auto sealer = content::PrefixSealer::begin(params(fd.fd, plaintext.size(), generation));
        ASSERT_EQ(sealer->feed(0, std::span(plaintext).first(2 * kChunk + 10)), content::PrefixSealer::Fed::Ok);
        ASSERT_EQ(sealer->sealed(), 2 * kChunk);
        prefixBytes = slurp(path);
    }  // "restart": the held-back 10 bytes are gone, the durable prefix is 2 chunks

    Fd fd(::open(path.c_str(), O_RDWR));
    auto resumed = content::PrefixSealer::resume(params(fd.fd, plaintext.size(), generation), 2 * kChunk);
    EXPECT_FALSE(resumed->tail());
    EXPECT_EQ(resumed->fed(), 2 * kChunk);
    EXPECT_EQ(slurp(path), prefixBytes) << "rebuilding only reads";
    // The part holding the boundary is fed again from its start: the bytes below fed() are compared, not re-sealed.
    ASSERT_EQ(resumed->feed(kChunk, std::span(plaintext).subspan(kChunk)), content::PrefixSealer::Fed::Ok);
    ASSERT_TRUE(resumed->complete());
    const auto finished = slurp(path);
    EXPECT_TRUE(std::equal(prefixBytes.begin(), prefixBytes.end(), finished.begin()));
    EXPECT_EQ(open(path, generation), plaintext);
    EXPECT_EQ(resumed->contentHash(), crypto::hash::blake2b(path));

    // A durable prefix that doesn't authenticate is refused (the file fails; nothing is guessed).
    auto damaged = slurp(path);
    damaged[120 + 5] ^= 0x01;
    spit(dir_.path() / "damaged", damaged);
    Fd bad(::open((dir_.path() / "damaged").c_str(), O_RDWR));
    EXPECT_THROW((void)content::PrefixSealer::resume(params(bad.fd, plaintext.size(), generation), 2 * kChunk),
                 storage::IntegrityError);
    // Under another generation (salt) it isn't this sealing either.
    EXPECT_THROW((void)content::PrefixSealer::resume(params(fd.fd, plaintext.size(), freshGeneration()), 2 * kChunk),
                 storage::IntegrityError);
}

TEST_F(Vhf1ResumableTest, Vhf1ResumableBytesPastTheRecordContinueUnderANewSalt) {
    const auto plaintext = randomBytes(3 * kChunk + 7, 13);
    const auto path = dir_.path() / "spool";
    const auto generation = freshGeneration();
    {
        Fd fd(::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600));
        auto sealer = content::PrefixSealer::begin(params(fd.fd, plaintext.size(), generation));
        ASSERT_EQ(sealer->feed(0, std::span(plaintext).first(2 * kChunk + 1)), content::PrefixSealer::Fed::Ok);
    }  // a crash: chunks 0 and 1 are on disk, only chunk 0 was recorded as durable
    Fd fd(::open(path.c_str(), O_RDWR));
    auto resumed = content::PrefixSealer::resume(params(fd.fd, plaintext.size(), generation), kChunk);
    ASSERT_TRUE(resumed->tail()) << "chunk 1 was sealed under this salt without a record";
    EXPECT_THROW((void)resumed->feed(kChunk, std::span(plaintext).subspan(kChunk, 10)), std::logic_error)
        << "no index past the record is sealed again under the old salt";

    const auto fresh = dir_.path() / "spool.resalt";
    Fd nfd(::open(fresh.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600));
    auto next = resumed->resealed(nfd.fd, kChunk);
    EXPECT_NE(next->generation(), generation);
    EXPECT_EQ(next->fed(), kChunk);
    ASSERT_EQ(next->feed(kChunk, std::span(plaintext).subspan(kChunk)), content::PrefixSealer::Fed::Ok);
    ASSERT_TRUE(next->complete());
    EXPECT_EQ(open(fresh, next->generation()), plaintext);
    EXPECT_THROW((void)open(fresh, generation), storage::IntegrityError);
}

TEST_F(Vhf1ResumableTest, Vhf1ResumableDivergentBytesRestartWithANewSalt) {
    const auto plaintext = randomBytes(3 * kChunk, 14);
    auto changed = plaintext;
    changed[kChunk + 40] ^= 0xFF;  // the stored bytes of an already sealed index changed
    const auto path = dir_.path() / "spool";
    Fd fd(::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600));
    const auto generation = freshGeneration();
    auto sealer = content::PrefixSealer::begin(params(fd.fd, plaintext.size(), generation));
    ASSERT_EQ(sealer->feed(0, std::span(plaintext).first(2 * kChunk + 100)), content::PrefixSealer::Fed::Ok);
    const auto before = slurp(path);

    // Re-fed from a part start below fed(): the same bytes are accepted, different ones are Diverged (no change).
    EXPECT_EQ(sealer->feed(kChunk, std::span(plaintext).subspan(kChunk, 1000)), content::PrefixSealer::Fed::Ok);
    EXPECT_EQ(sealer->feed(kChunk, std::span(changed).subspan(kChunk, kChunk + 200)),
              content::PrefixSealer::Fed::Diverged);
    EXPECT_EQ(sealer->feed(2 * kChunk + 50, std::span(changed).subspan(2 * kChunk + 50, 50)),
              content::PrefixSealer::Fed::Ok) << "held-back bytes are compared too (and these match)";
    auto pendingChanged = plaintext;
    pendingChanged[2 * kChunk + 60] ^= 0x01;
    EXPECT_EQ(sealer->feed(2 * kChunk + 50, std::span(pendingChanged).subspan(2 * kChunk + 50, 50)),
              content::PrefixSealer::Fed::Diverged);
    EXPECT_EQ(slurp(path), before) << "a divergence changes nothing";
    EXPECT_EQ(sealer->fed(), 2 * kChunk + 100);

    // The sealing continues under a new salt from the divergent part's start.
    const auto fresh = dir_.path() / "spool.resalt";
    Fd nfd(::open(fresh.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600));
    auto next = sealer->resealed(nfd.fd, kChunk);
    EXPECT_NE(next->generation(), generation);
    ASSERT_EQ(next->feed(kChunk, std::span(changed).subspan(kChunk)), content::PrefixSealer::Fed::Ok);
    ASSERT_TRUE(next->complete());
    EXPECT_EQ(open(fresh, next->generation()), changed);
}

TEST_F(Vhf1ResumableTest, Vhf1ResumableAnEmptySpoolStartsFreshAndAnUnrecordedOneMovesToANewSalt) {
    const auto plaintext = randomBytes(kChunk + 1, 15);
    const auto path = dir_.path() / "spool";
    const auto generation = freshGeneration();
    {
        Fd fd(::open(path.c_str(), O_RDWR | O_CREAT | O_TRUNC, 0600));
        auto fresh = content::PrefixSealer::resume(params(fd.fd, plaintext.size(), generation), 0);
        EXPECT_FALSE(fresh->tail());
        ASSERT_EQ(fresh->feed(0, std::span(plaintext).first(kChunk)), content::PrefixSealer::Fed::Ok);
    }
    Fd fd(::open(path.c_str(), O_RDWR));
    auto resumed = content::PrefixSealer::resume(params(fd.fd, plaintext.size(), generation), 0);
    EXPECT_TRUE(resumed->tail()) << "something sealed under the salt was never recorded";
}

// ---- Vhf1Sidecar (rotation crash recovery) ----------------------------------------------------------------------

TEST_F(Vhf1AtRestTest, Vhf1SidecarTornIsDiscardedCompleteIsPromoted) {
    const auto crypto = sync::rotation::runtimeDeps(engine_).crypto;
    const auto plaintext = randomBytes(3 * kChunk + 11, 16);

    const auto check = [&](const bool torn, const bool rowMovedOn, const sync::rotation::Resolution expected) {
        const auto f = sealedFile(plaintext);
        const auto old = sync::rotation::stateOf(*f);
        const auto oldBytes = slurp(f->backing_path);
        auto next = std::make_shared<fs::model::File>(*f);
        auto sidecarBytes = em_->encrypt(plaintext, next);
        if (torn) sidecarBytes.resize(120 + 2 * kSealedChunk);  // cut at a chunk boundary: no final chunk
        spit(sync::rotation::sidecarPathFor(f->backing_path), sidecarBytes);
        const auto state = rowMovedOn ? sync::rotation::stateOf(*next) : old;
        EXPECT_EQ(sync::rotation::resolveSidecar(f->backing_path, state, crypto), expected);
        EXPECT_FALSE(stdfs::exists(sync::rotation::sidecarPathFor(f->backing_path)) &&
                     expected != sync::rotation::Resolution::Unresolved);
        if (expected == sync::rotation::Resolution::Promoted) {
            EXPECT_EQ(slurp(f->backing_path), sidecarBytes);
        }
        if (expected == sync::rotation::Resolution::Discarded) {
            EXPECT_EQ(slurp(f->backing_path), oldBytes);
        }
    };
    check(/*torn=*/false, /*rowMovedOn=*/true, sync::rotation::Resolution::Promoted);
    check(/*torn=*/true, /*rowMovedOn=*/false, sync::rotation::Resolution::Discarded);
    check(/*torn=*/false, /*rowMovedOn=*/false, sync::rotation::Resolution::Discarded);

    // A sidecar cut at a chunk boundary never authenticates as its own generation (the final flag is missing).
    auto f = sealedFile(plaintext);
    auto next = std::make_shared<fs::model::File>(*f);
    auto bytes = em_->encrypt(plaintext, next);
    bytes.resize(120 + 2 * kSealedChunk);
    spit(dir_.path() / "cut", bytes);
    EXPECT_FALSE(crypto.fileAuthenticates(dir_.path() / "cut", sync::rotation::stateOf(*next)));
}

// ---- Vhf1Upload (fake S3) ----------------------------------------------------------------------------------------

using test_support::versioned::VersionedBucket;
using test_support::versioned::Versioning;

class Vhf1UploadTest : public Vhf1AtRestTest {
protected:
    void SetUp() override {
        Vhf1AtRestTest::SetUp();
        s3vault_ = std::make_shared<vault::model::S3Vault>();
        s3vault_->id = kVault;
        s3vault_->encrypt_upstream = true;
        cloud_ = std::make_shared<storage::CloudEngine>();
        cloud_->vault = s3vault_;
        cloud_->encryptionManager = em_;
        cloud_->setS3ControllerForTesting(bucket_);
    }

    FileSP localFile(const Bytes& plaintext, const std::string& path) {
        auto f = std::make_shared<fs::model::File>();
        f->id = ++ids_;
        f->vault_id = kVault;
        f->path = path;
        f->backing_path = dir_.path() / ("UP" + std::to_string(f->id));
        f->size_bytes = plaintext.size();
        if (plaintext.empty()) {
            spit(f->backing_path, {});  // every empty file is stored as nothing
        } else {
            spit(f->backing_path, em_->encrypt(plaintext, f));
        }
        f->content_hash = crypto::hash::blake2b(f->backing_path);
        return f;
    }

    // The object's own header names this file's generation (what a reconciling pass checks, spec 01 §6.2).
    [[nodiscard]] std::string headerGeneration(const Bytes& object, const std::string& generation) const {
        const auto opened = content::openHeader(object, {.vaultUid = em_->vaultUid(), .generation = generation,
                                                          .keyVersion = kKeyVersion},
                                                em_->keySnapshot(kKeyVersion));
        return content::generationOf(opened.params().salt);
    }

    std::shared_ptr<VersionedBucket> bucket_ = std::make_shared<VersionedBucket>(Versioning::Unversioned);
    std::shared_ptr<vault::model::S3Vault> s3vault_;
    std::shared_ptr<storage::CloudEngine> cloud_;
};

TEST_F(Vhf1UploadTest, Vhf1UploadEmptySmallAndMultipartFilesAreOneObjectEach) {
    struct Case {
        std::string path;
        std::size_t size;
        uint64_t puts;  // requests: 1 PUT, or initiate + parts + complete
    };
    const std::vector<Case> cases{
        {"/zero.bin", 0, 1},
        {"/small.bin", 300 * 1024, 1},
        {"/large.bin", 11 * 1024 * 1024, 1 + 3 + 1},  // 11 MiB + overhead in 5 MiB parts: 3 parts
    };
    for (const auto& c : cases) {
        SCOPED_TRACE(c.path);
        bucket_->resetCounters();
        const auto plaintext = randomBytes(c.size, static_cast<unsigned>(c.size + 3));
        const auto f = localFile(plaintext, c.path);
        cloud_->upload(f);

        const auto key = c.path.substr(1);
        const auto object = bucket_->current(key);
        ASSERT_TRUE(object);
        EXPECT_EQ(bucket_->history(key).size(), 1u);
        EXPECT_EQ(bucket_->counters().put, c.puts);
        EXPECT_EQ(bucket_->openUploads(), 0u);
        // One object of the VHF1 size, never one per chunk; the same bytes as the local backing file.
        EXPECT_EQ(object->body.size(), content::newSealedSize(c.size));
        if (c.size > 0) {
            EXPECT_EQ(object->body, slurp(f->backing_path));
        }
        EXPECT_TRUE(content::isVhf1(f->encryption_iv));
        EXPECT_EQ(headerGeneration(object->body, f->encryption_iv), f->encryption_iv);
        EXPECT_EQ(em_->decrypt(object->body, f->encryption_iv, kKeyVersion), plaintext);
    }
    const auto keys = bucket_->keys();
    EXPECT_EQ(keys.size(), cases.size()) << "no per-chunk keys";
}

TEST_F(Vhf1UploadTest, Vhf1UploadAPartFailureAbortsAndStoresNothing) {
    const auto plaintext = randomBytes(11 * 1024 * 1024, 21);
    const auto f = localFile(plaintext, "/part-fail.bin");
    bucket_->failAfter(VersionedBucket::Op::Put, VersionedBucket::Failure::Transport, 2);  // initiate, part 1, then fail
    EXPECT_ANY_THROW(cloud_->upload(f));
    EXPECT_FALSE(bucket_->current("part-fail.bin"));
    EXPECT_TRUE(bucket_->history("part-fail.bin").empty());
    EXPECT_EQ(bucket_->openUploads(), 0u) << "the multipart upload was aborted";
    EXPECT_GE(bucket_->counters().del, 1u);

    // The retry sends the sealed file again, byte for byte (no re-encryption).
    bucket_->clearFailures();
    cloud_->upload(f);
    ASSERT_TRUE(bucket_->current("part-fail.bin"));
    EXPECT_EQ(bucket_->current("part-fail.bin")->body, slurp(f->backing_path));
}

TEST_F(Vhf1UploadTest, Vhf1UploadALostCompleteResponseIsReconciledAndARetryResendsIdenticalBytes) {
    for (const auto mode : {Versioning::Unversioned, Versioning::Enabled}) {
        SCOPED_TRACE(mode == Versioning::Enabled ? "versioned" : "unversioned");
        bucket_->setVersioning(mode);
        const auto key = std::string(mode == Versioning::Enabled ? "lost-v.bin" : "lost-u.bin");
        const auto plaintext = randomBytes(6 * 1024 * 1024, mode == Versioning::Enabled ? 22 : 23);
        const auto f = localFile(plaintext, "/" + key);
        bucket_->loseResponses = 1;
        EXPECT_ANY_THROW(cloud_->upload(f)) << "the Complete took effect, its response was lost";

        // The object exists and says which generation it is: size, metadata and its own header agree with the row,
        // so the next pass can record it instead of guessing.
        const auto object = bucket_->current(key);
        ASSERT_TRUE(object);
        EXPECT_EQ(object->body, slurp(f->backing_path));
        const auto head = cloud_->headRemoteObject("/" + key);
        ASSERT_TRUE(head);
        EXPECT_TRUE(head->encrypted);
        EXPECT_EQ(head->iv_b64, f->encryption_iv);
        EXPECT_EQ(head->key_version, kKeyVersion);
        EXPECT_EQ(head->content_length.value_or(0), content::newSealedSize(plaintext.size()));
        EXPECT_EQ(headerGeneration(object->body, head->iv_b64), f->encryption_iv);

        // A retry re-sends identical bytes: the same object (ETag) again, one more identical version when versioned.
        const auto etag = object->etag;
        cloud_->upload(f);
        const auto after = bucket_->current(key);
        ASSERT_TRUE(after);
        EXPECT_EQ(after->etag, etag);
        EXPECT_EQ(after->body, object->body);
        const auto history = bucket_->history(key);
        EXPECT_EQ(history.size(), mode == Versioning::Enabled ? 2u : 1u);
        for (const auto& v : history) EXPECT_EQ(v.body, object->body);
    }
}

}
