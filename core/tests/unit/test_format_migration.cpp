// Local format conversion of legacy (gcm0) content to VHF1 (#372, WS2-c; design/encryption/02-authenticated-file-format.md
// §6.1, §6.2, §7 FormatMigration*). The protocol (vault/FormatConversion.hpp) runs with real crypto (an in-memory
// EncryptionManager, legacy files sealed with the legacy AES-256-GCM writer) against a files table and a recovery_blob
// table kept in maps with compare-and-set semantics, and the real rotation sidecar recovery. No TPM, database or S3.
//
//   FormatMigrationTest.*  per-item verification and digests, the key version kept, crash at every step then restart
//                          (idempotent), hard-linked blobs converted once with their file, no plaintext on disk, refusals
//                          (tampering, a drifted size, rotation/salvage running, open files, changed rows), pacing.

#include "crypto/util/encrypt.hpp"
#include "fs/model/File.hpp"
#include "recovery/Store.hpp"
#include "storage/Engine.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/rotation/Rotation.hpp"
#include "sync/rotation/Runtime.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/FormatConversion.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

namespace vh::test_format_migration {

namespace stdfs = std::filesystem;
namespace content = vault::content;
namespace conv = vault::conversion;
namespace rotation = sync::rotation;
using Bytes = std::vector<uint8_t>;
using FileSP = std::shared_ptr<fs::model::File>;

constexpr unsigned int kVault = 37;
constexpr unsigned int kRetired = 2;
constexpr unsigned int kCurrent = 3;
constexpr uint64_t kChunk = 64 * 1024;

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

ino_t inodeOf(const stdfs::path& p) {
    struct stat st{};
    return ::stat(p.c_str(), &st) == 0 ? st.st_ino : 0;
}

conv::Digest blake2b(const Bytes& bytes) {
    conv::Digest d{};
    crypto_generichash(d.data(), d.size(), bytes.data(), bytes.size(), nullptr, 0);
    return d;
}

class TempDir {
public:
    TempDir() : path_(stdfs::temp_directory_path() / ("vh_format_migration_" + std::to_string(::getpid()) + "_" +
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

class FormatMigrationTest : public ::testing::Test {
protected:
    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        key_ = randomBytes(32, 11);
        retiredKey_ = randomBytes(32, 12);
        em_ = std::make_shared<vault::EncryptionManager>(vault::EncryptionManager::ForTesting{}, kVault, key_, kCurrent);
        em_->addHistoricalKeyForTesting(kRetired, retiredKey_);
        engine_ = std::make_shared<storage::Engine>();
        engine_->vault = std::make_shared<vault::model::Vault>();
        engine_->vault->id = kVault;
        engine_->encryptionManager = em_;
        backingRoot_ = dir_.path() / "backing";
        storeRoot_ = dir_.path() / "store";
        stdfs::create_directories(backingRoot_);
        stdfs::create_directories(storeRoot_);
    }

    // ---- the catalog --------------------------------------------------------------------------------------------

    struct Live {
        FileSP file;
        Bytes plaintext;
    };

    // A live file whose backing bytes are legacy GCM under the current key, as builds before #367 wrote them.
    FileSP legacyFile(const Bytes& plaintext, const std::string& name) {
        auto f = std::make_shared<fs::model::File>();
        f->id = ++ids_;
        f->vault_id = kVault;
        f->path = "/" + name;
        f->backing_path = backingRoot_ / ("B" + std::to_string(f->id));
        f->size_bytes = plaintext.size();
        f->object_uid = crypto::id::newObjectUid();
        Bytes iv;
        spit(f->backing_path, crypto::util::encrypt_aes256_gcm(plaintext, key_, iv));
        ::chmod(f->backing_path.c_str(), 0640);
        f->encryption_iv = crypto::util::b64_encode(iv);
        f->encrypted_with_key_version = kCurrent;
        rows_[f->path.string()] = rotation::stateOf(*f);
        live_[f->path.string()] = {f, plaintext};
        return f;
    }

    stdfs::path storePath(const std::string& name) const { return storeRoot_ / name.substr(0, 2) / name; }

    // A recovery blob: a hard link of a live file's backing file (its generation), or its own legacy bytes.
    conv::Blob linkedBlob(const FileSP& f) {
        conv::Blob b{.id = ++blobIds_, .storageName = recovery::store::newStorageName(), .generation = f->encryption_iv,
                     .keyVersion = f->encrypted_with_key_version, .cipherBytes = stdfs::file_size(f->backing_path),
                     .plaintextBytes = f->size_bytes, .objectUid = f->object_uid};
        stdfs::create_directories(storePath(b.storageName).parent_path());
        EXPECT_EQ(::link(f->backing_path.c_str(), storePath(b.storageName).c_str()), 0);
        blobs_[b.id] = b;
        blobPlain_[b.id] = live_.at(f->path.string()).plaintext;
        return b;
    }

    conv::Blob legacyBlob(const Bytes& plaintext, const unsigned int version) {
        Bytes iv;
        const auto& k = version == kCurrent ? key_ : retiredKey_;
        const auto sealed = crypto::util::encrypt_aes256_gcm(plaintext, k, iv);
        conv::Blob b{.id = ++blobIds_, .storageName = recovery::store::newStorageName(),
                     .generation = crypto::util::b64_encode(iv), .keyVersion = version, .cipherBytes = sealed.size(),
                     .plaintextBytes = plaintext.size()};
        spit(storePath(b.storageName), sealed);
        blobs_[b.id] = b;
        blobPlain_[b.id] = plaintext;
        return b;
    }

    // ---- the protocol's seams over the maps -----------------------------------------------------------------------

    conv::PassDeps passDeps() {
        conv::PassDeps pass;
        auto& d = pass.item;
        d.rotation.crypto = rotation::runtimeDeps(engine_).crypto;  // sidecar authentication, as the daemon's
        d.rotation.catalog.lock = [this](const FileSP&) { return std::unique_lock(mutex_); };
        d.rotation.catalog.current = [this](const FileSP& f) -> std::optional<rotation::EncryptionState> {
            const auto it = rows_.find(f->path.string());
            if (it == rows_.end()) return std::nullopt;
            return it->second;
        };
        d.rotation.catalog.busy = [this](const FileSP& f) { return busy_.contains(f->id); };
        d.rotation.catalog.committed = [this](const FileSP&) { ++refreshed_; };
        d.vaultUid = em_->vaultUid();
        d.liveKey = [this](const unsigned int v) -> crypto::SecretKeyPtr {
            const auto c = em_->currentKey();
            return c.version == v ? c.key : nullptr;
        };
        d.historicalKey = [this](const unsigned int v) { return em_->historicalKeySnapshot(v); };
        d.blocked = [this]() -> std::optional<std::string> { return blocked_; };
        d.sharedBlob = [this](const std::string& gen, const unsigned int v) -> std::optional<conv::Blob> {
            for (const auto& [id, b] : blobs_)
                if (b.generation == gen && b.keyVersion == v) return b;
            return std::nullopt;
        };
        d.commitFile = [this](const fs::model::File& f, const rotation::EncryptionState& expected,
                              const std::optional<conv::BlobSwap>& swap) {
            ++commits_;
            if (failCommit_) throw std::runtime_error("database unavailable");
            conv::FileCommit out;
            auto& row = rows_.at(f.path.string());
            if (!(row == expected)) return out;
            row = rotation::stateOf(f);
            out.file = true;
            if (swap) out.blob = swapBlob(*swap);
            return out;
        };
        d.commitBlob = [this](const conv::BlobSwap& swap) {
            ++commits_;
            return swapBlob(swap);
        };
        d.blobPath = [this](const std::string& name) { return storePath(name); };
        d.newStorageName = [] { return recovery::store::newStorageName(); };
        d.prepareBlobDir = [](const stdfs::path& p) { stdfs::create_directories(p); };
        d.plaintextUpstream = plaintextUpstream_;
        d.afterStep = [this](const conv::Step step, std::string_view) {
            ++stepsReached_[step];
            if (crashAt_ && *crashAt_ == step) {
                crashAt_.reset();
                throw conv::SimulatedCrash{step};
            }
        };

        pass.liveFiles = [this](const uint32_t after, const std::size_t limit) {
            std::vector<FileSP> out;
            for (const auto& [path, l] : live_) {
                const auto& row = rows_.at(path);
                if (l.file->id > after && content::formatOf(row.iv_b64) == content::Format::Gcm0 &&
                    row.key_version == kCurrent) {
                    auto f = std::make_shared<fs::model::File>(*l.file);  // a fresh row, as a query returns it
                    f->encryption_iv = row.iv_b64;
                    f->encrypted_with_key_version = row.key_version;
                    out.push_back(f);
                }
            }
            std::ranges::sort(out, {}, [](const FileSP& f) { return f->id; });
            if (out.size() > limit) out.resize(limit);
            return out;
        };
        pass.blobs = [this](const int64_t after, const std::size_t limit) {
            std::vector<conv::Blob> out;
            for (const auto& [id, b] : blobs_) {
                if (id <= after || content::formatOf(b.generation) != content::Format::Gcm0) continue;
                // As the query: blobs of a live legacy file's generation convert with it.
                const bool live = std::ranges::any_of(rows_, [&](const auto& r) {
                    return r.second.iv_b64 == b.generation && r.second.key_version == b.keyVersion &&
                           b.keyVersion == kCurrent;
                });
                if (!live) out.push_back(b);
            }
            if (out.size() > limit) out.resize(limit);
            return out;
        };
        pass.pause = [this](const std::chrono::nanoseconds d) { pauses_.push_back(d); };
        return pass;
    }

    bool swapBlob(const conv::BlobSwap& s) {
        const auto it = blobs_.find(s.id);
        if (it == blobs_.end()) return false;
        auto& b = it->second;
        if (b.generation != s.fromGeneration || b.storageName != s.fromStorageName || b.keyVersion != s.keyVersion)
            return false;
        b.generation = s.toGeneration;
        b.storageName = s.toStorageName;
        b.cipherBytes = s.cipherBytes;
        return true;
    }

    // ---- restart: what the daemon does after a crash --------------------------------------------------------------

    // Startup sidecar recovery (sync::rotation::recoverSidecars against the files table) and the store sweep (files no
    // row references; recovery/Store.hpp), then a fresh pass.
    void restart() {
        rotation::Deps deps;
        deps.crypto = rotation::runtimeDeps(engine_).crypto;
        const auto report = rotation::recoverSidecars(
            backingRoot_,
            [this](const stdfs::path& backing) -> FileSP {
                for (const auto& [path, l] : live_)
                    if (l.file->backing_path == backing) {
                        auto f = std::make_shared<fs::model::File>(*l.file);
                        f->encryption_iv = rows_.at(path).iv_b64;
                        f->encrypted_with_key_version = rows_.at(path).key_version;
                        return f;
                    }
                return nullptr;
            },
            deps);
        EXPECT_EQ(report.unresolved, 0u);
        std::set<std::string> referenced;
        for (const auto& [id, b] : blobs_) referenced.insert(b.storageName);
        for (const auto& e : stdfs::recursive_directory_iterator(storeRoot_))
            if (e.is_regular_file() && !referenced.contains(e.path().filename().string())) stdfs::remove(e.path());
    }

    // ---- what must hold after any pass ----------------------------------------------------------------------------

    [[nodiscard]] Bytes openLive(const std::string& path) const {
        const auto& l = live_.at(path);
        const auto& row = rows_.at(path);
        Bytes out;
        content::openFileTo(l.file->backing_path,
                            {.vaultUid = em_->vaultUid(), .generation = row.iv_b64, .keyVersion = row.key_version,
                             .objectUid = content::isVhf1(row.iv_b64) ? l.file->object_uid : std::nullopt},
                            *em_->historicalKeySnapshot(row.key_version),
                            [&](const std::span<const uint8_t> p) { out.insert(out.end(), p.begin(), p.end()); });
        return out;
    }

    [[nodiscard]] Bytes openBlob(const conv::Blob& b) const {
        Bytes out;
        content::openFileTo(storePath(b.storageName),
                            {.vaultUid = em_->vaultUid(), .generation = b.generation, .keyVersion = b.keyVersion},
                            *em_->historicalKeySnapshot(b.keyVersion),
                            [&](const std::span<const uint8_t> p) { out.insert(out.end(), p.begin(), p.end()); });
        return out;
    }

    // Every row readable with its recorded generation and key version, the plaintext unchanged.
    void expectEverythingReadable() const {
        for (const auto& [path, l] : live_) EXPECT_EQ(openLive(path), l.plaintext) << path;
        for (const auto& [id, b] : blobs_) EXPECT_EQ(openBlob(b), blobPlain_.at(id)) << "blob " << id;
    }

    void expectAllVhf1() const {
        for (const auto& [path, row] : rows_) {
            EXPECT_TRUE(content::isVhf1(row.iv_b64)) << path;
            EXPECT_EQ(row.key_version, kCurrent) << path << ": the key version never changes";
        }
        for (const auto& [id, b] : blobs_) EXPECT_TRUE(content::isVhf1(b.generation)) << "blob " << id;
    }

    // Exactly the files the catalog names: no sidecars, temp files or orphans.
    void expectOnlyCatalogFiles() const {
        std::set<stdfs::path> expected;
        for (const auto& [path, l] : live_) expected.insert(l.file->backing_path);
        for (const auto& [id, b] : blobs_) expected.insert(storePath(b.storageName));
        std::set<stdfs::path> found;
        for (const auto& e : stdfs::recursive_directory_iterator(dir_.path()))
            if (!e.is_directory()) found.insert(e.path());
        EXPECT_EQ(found, expected);
    }

    // No file under the test directory holds any 64-byte window of any plaintext.
    void expectNoPlaintextOnDisk() const {
        std::vector<Bytes> needles;
        for (const auto& [path, l] : live_)
            for (std::size_t at = 0; at + 64 <= l.plaintext.size(); at += kChunk / 2)
                needles.emplace_back(l.plaintext.begin() + static_cast<std::ptrdiff_t>(at),
                                     l.plaintext.begin() + static_cast<std::ptrdiff_t>(at + 64));
        for (const auto& [id, p] : blobPlain_)
            if (p.size() >= 64) needles.emplace_back(p.begin(), p.begin() + 64);
        for (const auto& e : stdfs::recursive_directory_iterator(dir_.path())) {
            if (!e.is_regular_file()) continue;
            const auto bytes = slurp(e.path());
            for (const auto& n : needles)
                EXPECT_EQ(std::search(bytes.begin(), bytes.end(), n.begin(), n.end()), bytes.end())
                    << e.path() << " holds plaintext";
        }
    }

    TempDir dir_;
    Bytes key_, retiredKey_;
    std::shared_ptr<vault::EncryptionManager> em_;
    std::shared_ptr<storage::Engine> engine_;
    stdfs::path backingRoot_, storeRoot_;
    std::mutex mutex_;
    uint32_t ids_{0};
    int64_t blobIds_{0};

    std::map<std::string, rotation::EncryptionState> rows_;
    std::map<std::string, Live> live_;
    std::map<int64_t, conv::Blob> blobs_;
    std::map<int64_t, Bytes> blobPlain_;

    std::set<uint32_t> busy_;
    std::optional<std::string> blocked_;
    bool failCommit_{false};
    bool plaintextUpstream_{false};
    std::optional<conv::Step> crashAt_;
    std::map<conv::Step, int> stepsReached_;
    int commits_{0}, refreshed_{0};
    std::vector<std::chrono::nanoseconds> pauses_;
};

TEST_F(FormatMigrationTest, FormatMigrationConvertFileVerifiesTheTagAndComparesPlaintextDigests) {
    for (const std::size_t size : {std::size_t{1}, std::size_t{kChunk}, std::size_t{3 * kChunk + 17}}) {
        const auto plaintext = randomBytes(size, static_cast<unsigned>(size));
        const auto f = legacyFile(plaintext, "d" + std::to_string(size));
        const auto out = dir_.path() / ("out" + std::to_string(size));
        const content::Binding from{.vaultUid = em_->vaultUid(), .generation = f->encryption_iv, .keyVersion = kCurrent};
        const auto converted = conv::convertFile(f->backing_path, from, *em_->keySnapshot(kCurrent), out, 0600,
                                                 *f->object_uid);
        EXPECT_EQ(converted.digest, blake2b(plaintext)) << "the digest of the legacy plaintext, streamed";
        EXPECT_EQ(converted.plaintextBytes, size);
        EXPECT_EQ(converted.sealedBytes, content::sealedSize(size, content::Format::Vhf1));
        EXPECT_EQ(stdfs::file_size(out), converted.sealedBytes);
        EXPECT_TRUE(content::isVhf1(converted.generation));
        // Bound to this vault, this object and the same key version.
        const auto header = slurp(out);
        const auto opened = content::openHeader({header.data(), crypto::vhf1::kHeaderSize},
                                                {.vaultUid = em_->vaultUid(), .generation = converted.generation,
                                                 .keyVersion = kCurrent, .objectUid = f->object_uid},
                                                em_->keySnapshot(kCurrent));
        EXPECT_EQ(content::generationOf(opened.params().salt), converted.generation);
        stdfs::remove(out);
    }

    // A tag that doesn't verify: nothing is left at dst.
    const auto f = legacyFile(randomBytes(2 * kChunk, 5), "tampered");
    auto bytes = slurp(f->backing_path);
    bytes[bytes.size() / 2] ^= 0x5a;
    spit(f->backing_path, bytes);
    const auto out = dir_.path() / "out-tampered";
    EXPECT_THROW((void)conv::convertFile(f->backing_path,
                                         {.vaultUid = em_->vaultUid(), .generation = f->encryption_iv,
                                          .keyVersion = kCurrent},
                                         *em_->keySnapshot(kCurrent), out, 0600, *f->object_uid),
                 storage::IntegrityError);
    EXPECT_FALSE(stdfs::exists(out));

    // Only legacy generations convert.
    EXPECT_THROW((void)conv::convertFile(f->backing_path, {.vaultUid = em_->vaultUid(), .generation = "",
                                                           .keyVersion = kCurrent},
                                         *em_->keySnapshot(kCurrent), out, 0600, *f->object_uid),
                 std::invalid_argument);
}

TEST_F(FormatMigrationTest, FormatMigrationConvertsLiveFilesSnapshotsVersionsAndRetiredKeyBlobsUnderTheSameKeyVersion) {
    const auto a = legacyFile(randomBytes(3 * kChunk + 5, 1), "a.bin");
    const auto b = legacyFile(randomBytes(100, 2), "b.txt");
    const auto shared = linkedBlob(a);                        // a snapshot of a's current generation
    const auto old = legacyBlob(randomBytes(kChunk + 1, 3), kCurrent);   // a local version of an earlier content
    const auto retired = legacyBlob(randomBytes(777, 4), kRetired);     // retained across a finished rotation
    const auto mode = stdfs::status(a->backing_path).permissions();

    const auto result = conv::runPass(passDeps());
    EXPECT_EQ(result.files, 2u);
    EXPECT_EQ(result.blobs, 3u);
    EXPECT_EQ(result.failed, 0u) << (result.failures.empty() ? "" : result.failures.front().reason);
    EXPECT_FALSE(result.blocked);
    expectAllVhf1();
    expectEverythingReadable();
    expectOnlyCatalogFiles();
    EXPECT_EQ(blobs_.at(retired.id).keyVersion, kRetired) << "a retired-key generation stays under its key version";
    EXPECT_EQ(blobs_.at(old.id).keyVersion, kCurrent);
    EXPECT_EQ(stdfs::status(a->backing_path).permissions(), mode) << "the backing file keeps its permission bits";
    EXPECT_EQ(refreshed_, 2) << "the cached rows learn the new generation";
    (void)b;
    (void)shared;

    // Idempotent: nothing is left to do, nothing is rewritten.
    const auto before = rows_;
    const auto again = conv::runPass(passDeps());
    EXPECT_EQ(again.files + again.blobs + again.failed + again.skipped, 0u);
    EXPECT_EQ(rows_, before);
}

TEST_F(FormatMigrationTest, FormatMigrationConvertsAHardLinkedBlobOnceTogetherWithItsLiveFile) {
    const auto f = legacyFile(randomBytes(2 * kChunk + 3, 7), "linked.bin");
    const auto blob = linkedBlob(f);
    ASSERT_EQ(inodeOf(f->backing_path), inodeOf(storePath(blob.storageName)));

    const auto result = conv::runPass(passDeps());
    EXPECT_EQ(result.files, 1u);
    EXPECT_EQ(result.blobs, 1u);
    EXPECT_EQ(stepsReached_[conv::Step::Staged], 1) << "one re-seal for the file and its blob";
    EXPECT_EQ(stepsReached_[conv::Step::Linked], 1);
    EXPECT_EQ(commits_, 1) << "one transaction moves both rows";

    const auto& b = blobs_.at(blob.id);
    EXPECT_EQ(b.generation, rows_.at("/linked.bin").iv_b64) << "the blob is the live generation again";
    EXPECT_EQ(inodeOf(f->backing_path), inodeOf(storePath(b.storageName))) << "and still a hard link of it";
    EXPECT_EQ(b.cipherBytes, stdfs::file_size(f->backing_path));
    expectEverythingReadable();
    expectOnlyCatalogFiles();
}

TEST_F(FormatMigrationTest, FormatMigrationIsIdempotentAfterACrashAtEachStep) {
    for (const auto step : {conv::Step::Staged, conv::Step::Linked, conv::Step::Committed, conv::Step::Replaced}) {
        SCOPED_TRACE(std::string(conv::to_string(step)));
        rows_.clear();
        live_.clear();
        blobs_.clear();
        blobPlain_.clear();
        stepsReached_.clear();
        stdfs::remove_all(backingRoot_);
        stdfs::remove_all(storeRoot_);
        stdfs::create_directories(backingRoot_);
        stdfs::create_directories(storeRoot_);

        const auto f = legacyFile(randomBytes(3 * kChunk + 9, 21), "crash.bin");
        (void)linkedBlob(f);
        (void)legacyBlob(randomBytes(kChunk + 2, 22), kRetired);

        // The first item (the live file with its blob) crashes at `step`; Linked only exists for it.
        crashAt_ = step;
        EXPECT_THROW((void)conv::runPass(passDeps()), conv::SimulatedCrash);

        // Whatever the crash left, every row still reads back.
        restart();
        expectEverythingReadable();
        expectNoPlaintextOnDisk();

        // The next pass finishes the job; one more finds nothing.
        const auto resumed = conv::runPass(passDeps());
        EXPECT_EQ(resumed.failed, 0u) << (resumed.failures.empty() ? "" : resumed.failures.front().reason);
        restart();
        expectAllVhf1();
        expectEverythingReadable();
        expectOnlyCatalogFiles();
        expectNoPlaintextOnDisk();
        const auto& b = *std::ranges::find_if(blobs_, [](const auto& e) { return e.second.keyVersion == kCurrent; });
        EXPECT_EQ(inodeOf(f->backing_path), inodeOf(storePath(b.second.storageName)))
            << "the blob converted with the file, even across the crash";
        const auto idle = conv::runPass(passDeps());
        EXPECT_EQ(idle.files + idle.blobs + idle.failed, 0u);
    }

    // The standalone blob crashing at each of its own steps.
    for (const auto step : {conv::Step::Staged, conv::Step::Committed, conv::Step::Replaced}) {
        SCOPED_TRACE("blob " + std::string(conv::to_string(step)));
        rows_.clear();
        live_.clear();
        blobs_.clear();
        blobPlain_.clear();
        stdfs::remove_all(backingRoot_);
        stdfs::remove_all(storeRoot_);
        stdfs::create_directories(backingRoot_);
        stdfs::create_directories(storeRoot_);
        (void)legacyBlob(randomBytes(kChunk * 2, 31), kRetired);
        crashAt_ = step;
        EXPECT_THROW((void)conv::runPass(passDeps()), conv::SimulatedCrash);
        restart();
        expectEverythingReadable();
        (void)conv::runPass(passDeps());
        restart();
        expectAllVhf1();
        expectEverythingReadable();
        expectOnlyCatalogFiles();
    }
}

TEST_F(FormatMigrationTest, FormatMigrationWritesNoPlaintextTempFiles) {
    (void)legacyFile(randomBytes(4 * kChunk + 1, 41), "p1.bin");
    const auto f = legacyFile(randomBytes(kChunk, 42), "p2.bin");
    (void)linkedBlob(f);
    (void)legacyBlob(randomBytes(3 * kChunk, 43), kCurrent);

    // Look while each item is in flight, and after. Files that existed before the pass are legacy ciphertext (the old
    // forms, removed once their item commits); anything new must be VHF1.
    std::set<stdfs::path> initial;
    for (const auto& e : stdfs::recursive_directory_iterator(dir_.path()))
        if (e.is_regular_file()) initial.insert(e.path());
    std::size_t looked = 0;
    auto deps = passDeps();
    const auto inner = deps.item.afterStep;
    deps.item.afterStep = [&](const conv::Step step, const std::string_view what) {
        inner(step, what);
        expectNoPlaintextOnDisk();
        // In flight, the only files besides the catalog's are VHF1 (a sidecar, a new blob or its link).
        for (const auto& e : stdfs::recursive_directory_iterator(dir_.path())) {
            if (!e.is_regular_file()) continue;
            const auto bytes = slurp(e.path());
            const bool vhf1 = bytes.size() >= 8 && std::equal(bytes.begin(), bytes.begin() + 8,
                                                              crypto::vhf1::kMagic.begin());
            bool catalog = false;
            for (const auto& [p, l] : live_) catalog = catalog || e.path() == l.file->backing_path;
            for (const auto& [id, b] : blobs_) catalog = catalog || e.path() == storePath(b.storageName);
            EXPECT_TRUE(vhf1 || catalog || initial.contains(e.path())) << e.path() << " is a new file but not VHF1";
        }
        ++looked;
    };
    const auto result = conv::runPass(deps);
    EXPECT_EQ(result.failed, 0u);
    EXPECT_GT(looked, 0u);
    expectNoPlaintextOnDisk();
    expectOnlyCatalogFiles();
}

TEST_F(FormatMigrationTest, FormatMigrationLeavesWhatDoesNotVerifyAsItWas) {
    // A tampered live file, a blob whose file is gone, a row whose size drifted from its bytes.
    const auto bad = legacyFile(randomBytes(2 * kChunk, 51), "bad.bin");
    auto bytes = slurp(bad->backing_path);
    bytes[10] ^= 0x01;
    spit(bad->backing_path, bytes);
    const auto drifted = legacyFile(randomBytes(500, 52), "drifted.bin");
    live_.at("/drifted.bin").file->size_bytes = 501;
    const auto gone = legacyBlob(randomBytes(300, 53), kCurrent);
    stdfs::remove(storePath(gone.storageName));
    const auto good = legacyFile(randomBytes(900, 54), "good.bin");
    const auto badRow = rows_.at("/bad.bin");
    const auto driftedRow = rows_.at("/drifted.bin");

    const auto result = conv::runPass(passDeps());
    EXPECT_EQ(result.failed, 3u);
    EXPECT_EQ(result.files, 1u) << "one failure never stops the others";
    EXPECT_EQ(rows_.at("/bad.bin"), badRow);
    EXPECT_EQ(slurp(bad->backing_path), bytes) << "the legacy bytes are kept";
    EXPECT_EQ(rows_.at("/drifted.bin"), driftedRow);
    EXPECT_FALSE(stdfs::exists(rotation::sidecarPathFor(bad->backing_path)));
    EXPECT_FALSE(content::isVhf1(blobs_.at(gone.id).generation));
    EXPECT_TRUE(content::isVhf1(rows_.at("/good.bin").iv_b64));
    (void)drifted;
    (void)good;

    // A commit whose outcome is unknown keeps both copies; recovery settles by authentication.
    rows_.clear();
    live_.clear();
    blobs_.clear();
    blobPlain_.clear();
    const auto f = legacyFile(randomBytes(kChunk + 3, 55), "unknown.bin");
    failCommit_ = true;
    const auto failed = conv::runPass(passDeps());
    EXPECT_EQ(failed.failed, 1u);
    EXPECT_TRUE(stdfs::exists(rotation::sidecarPathFor(f->backing_path)));
    failCommit_ = false;
    restart();
    EXPECT_FALSE(stdfs::exists(rotation::sidecarPathFor(f->backing_path))) << "the row didn't move: discarded";
    expectEverythingReadable();
}

TEST_F(FormatMigrationTest, FormatMigrationNeverRunsDuringARotationOrSalvage) {
    (void)legacyFile(randomBytes(1000, 61), "r1.bin");
    (void)legacyFile(randomBytes(1000, 62), "r2.bin");
    (void)legacyBlob(randomBytes(1000, 63), kRetired);
    const auto before = rows_;

    blocked_ = "a key salvage of the vault is running";
    const auto refused = conv::runPass(passDeps());
    EXPECT_EQ(refused.blocked, blocked_);
    EXPECT_EQ(refused.files + refused.blobs, 0u);
    EXPECT_EQ(rows_, before);
    EXPECT_EQ(commits_, 0);

    // A rotation that starts mid-pass stops it before the next item; the item already converted stays converted.
    blocked_.reset();
    auto deps = passDeps();
    const auto inner = deps.item.afterStep;
    deps.item.afterStep = [&](const conv::Step step, const std::string_view what) {
        inner(step, what);
        if (step == conv::Step::Replaced) blocked_ = "a key rotation of the vault is in progress";
    };
    const auto stopped = conv::runPass(deps);
    EXPECT_TRUE(stopped.blocked);
    EXPECT_EQ(stopped.files, 1u);
    EXPECT_EQ(stopped.blobs, 0u);
    blocked_.reset();
    const auto done = conv::runPass(passDeps());
    EXPECT_EQ(done.files, 1u);
    EXPECT_EQ(done.blobs, 1u);
    for (const auto& [path, row] : rows_) EXPECT_EQ(row.key_version, kCurrent) << "no key is ever rotated";
}

TEST_F(FormatMigrationTest, FormatMigrationDefersOpenFilesAndBacksOutOfRowsThatChanged) {
    const auto open = legacyFile(randomBytes(1000, 71), "open.bin");
    busy_.insert(open->id);
    const auto deferred = conv::runPass(passDeps());
    EXPECT_EQ(deferred.deferred, 1u);
    EXPECT_FALSE(content::isVhf1(rows_.at("/open.bin").iv_b64));
    EXPECT_FALSE(stdfs::exists(rotation::sidecarPathFor(open->backing_path)));
    busy_.clear();

    // The row moves on (a write) between the listing and the commit: the conversion backs out.
    auto deps = passDeps();
    const auto list = deps.liveFiles;
    deps.liveFiles = [&](const uint32_t after, const std::size_t limit) {
        auto page = list(after, limit);
        if (!page.empty()) rows_["/open.bin"] = {.iv_b64 = crypto::util::b64_encode(randomBytes(12, 72)), .key_version = kCurrent};
        return page;
    };
    const auto conflict = conv::runPass(deps);
    EXPECT_EQ(conflict.conflicts, 1u);
    EXPECT_FALSE(stdfs::exists(rotation::sidecarPathFor(open->backing_path)));
}

TEST_F(FormatMigrationTest, FormatMigrationClearsAStaleGenerationOfAPlaintextUpstreamFileWithoutLocalBytes) {
    const auto f = legacyFile(randomBytes(400, 81), "evicted.bin");
    stdfs::remove(f->backing_path);

    // A local vault: a missing backing file is a failure, never "nothing to convert".
    const auto missing = conv::runPass(passDeps());
    EXPECT_EQ(missing.failed, 1u);
    EXPECT_FALSE(rows_.at("/evicted.bin").iv_b64.empty());

    plaintextUpstream_ = true;
    const auto result = conv::runPass(passDeps());
    EXPECT_EQ(result.cleared, 1u);
    EXPECT_TRUE(rows_.at("/evicted.bin").iv_b64.empty());
    EXPECT_EQ(rows_.at("/evicted.bin").key_version, 0u);
}

TEST_F(FormatMigrationTest, FormatMigrationPacesThroughputAndCpu) {
    using namespace std::chrono_literals;
    // Unlimited: no pause.
    EXPECT_EQ(conv::pauseAfter({.maxBytesPerSecond = 0, .maxCpuPercent = 100}, 1 << 30, 1s), 0ns);
    // 1 MiB/s: 4 MiB that took 1 s wait 3 s more.
    EXPECT_EQ(conv::pauseAfter({.maxBytesPerSecond = 1 << 20, .maxCpuPercent = 100}, 4 << 20, 1s), 3s);
    // Faster than the limit already: nothing.
    EXPECT_EQ(conv::pauseAfter({.maxBytesPerSecond = 1 << 20, .maxCpuPercent = 100}, 1 << 20, 2s), 0ns);
    // 25 % CPU: 1 s busy, 3 s idle.
    EXPECT_EQ(conv::pauseAfter({.maxBytesPerSecond = 0, .maxCpuPercent = 25}, 1, 1s), 3s);
    // Both: the longer one wins.
    EXPECT_EQ(conv::pauseAfter({.maxBytesPerSecond = 1 << 20, .maxCpuPercent = 50}, 8 << 20, 1s), 7s);
    // Out-of-range CPU is clamped (0 behaves as 1 %).
    EXPECT_EQ(conv::pauseAfter({.maxBytesPerSecond = 0, .maxCpuPercent = 0}, 1, 1ms), 99ms);

    // The pass pauses after each item by what the clock and the limits say.
    (void)legacyFile(randomBytes(1 << 20, 91), "t1.bin");
    (void)legacyFile(randomBytes(1 << 20, 92), "t2.bin");
    auto deps = passDeps();
    deps.limits = {.maxBytesPerSecond = 1 << 20, .maxCpuPercent = 100};
    auto clock = std::chrono::steady_clock::time_point{};
    deps.now = [&] { return clock; };  // items take no time on this clock
    const auto result = conv::runPass(deps);
    EXPECT_EQ(result.files, 2u);
    ASSERT_EQ(pauses_.size(), 2u);
    // (1 MiB + the 16-byte tag) at 1 MiB/s.
    for (const auto p : pauses_)
        EXPECT_NEAR(static_cast<double>(p.count()), 1e9 * static_cast<double>((1 << 20) + 16) / (1 << 20), 2.0);
}

}
