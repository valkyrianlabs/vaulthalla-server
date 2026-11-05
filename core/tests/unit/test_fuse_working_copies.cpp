// #173: the FUSE mount is the decrypting view of vault bytes that are always ciphertext on disk. These tests drive
// fuse::WorkingCopies (one working copy per open inode, sealed back on flush/fsync/last release) with a reversible
// stand-in vault cipher, and crypto::util::decrypt_aes256_gcm_file with real AES-256-GCM. #328: the working copy
// itself is a crypto::ScratchFile (never plaintext on disk), and a copy that fails to seal stays recoverable for the
// life of the process.

#include "crypto/ScratchFile.hpp"
#include "crypto/util/encrypt.hpp"
#include "fs/PlaintextSource.hpp"
#include "fs/model/File.hpp"
#include "fuse/WorkingCopies.hpp"

#include "fs/ops/file.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace vh::test_fuse_working_copies {

namespace stdfs = std::filesystem;

std::string slurp(const stdfs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

void spit(const stdfs::path& path, const std::string& bytes) {
    std::ofstream(path, std::ios::binary | std::ios::trunc) << bytes;
}

std::string readSource(const fs::PlaintextSource& source) {
    std::string out;
    fs::forEachChunk(source, [&](const std::span<const uint8_t> chunk) { out.append(chunk.begin(), chunk.end()); });
    return out;
}

void appendTo(crypto::ScratchFile& to, const std::string& bytes) {
    to.append({reinterpret_cast<const uint8_t*>(bytes.data()), bytes.size()});
}

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

// Stand-in cipher: every byte flipped, then a 16-byte trailer, like the real tag.
const std::string kTrailer = "0123456789ABCDEF";
std::string fakeSeal(const std::string& plain) {
    std::string out = plain;
    for (auto& c : out) c = static_cast<char>(c ^ 0x5A);
    return out + kTrailer;
}
std::string fakeOpen(const std::string& sealed) {
    std::string out = sealed.substr(0, sealed.size() - kTrailer.size());
    for (auto& c : out) c = static_cast<char>(c ^ 0x5A);
    return out;
}

class WorkingCopiesTest : public ::testing::Test {
protected:
    stdfs::path dir;
    std::shared_ptr<fs::model::File> file;
    bool deleted = false;
    bool failSeal = false;
    int saves = 0;
    unsigned int seals = 0;
    std::unique_ptr<fuse::WorkingCopies> copies;
    int materializations = 0;
    std::vector<std::string> recovered;  // what the recover hook stored
    bool failRecover = false;

    void SetUp() override {
        dir = stdfs::temp_directory_path() / ("vh_wc_" + std::to_string(::getpid()) + "_" +
                                              ::testing::UnitTest::GetInstance()->current_test_info()->name());
        stdfs::remove_all(dir);
        stdfs::create_directories(dir / "backing");

        file = std::make_shared<fs::model::File>();
        file->id = 7;
        file->inode = 42;
        file->vault_id = 1;
        file->path = "/notes/todo.txt";
        file->backing_path = dir / "backing" / "ALIAS";

        copies = std::make_unique<fuse::WorkingCopies>(dir / "working", fuse::WorkingCopyHooks{
            .materialize = [this](const fs::model::File& f, crypto::ScratchFile& to) {
                ++materializations;
                if (!stdfs::exists(f.backing_path) || stdfs::file_size(f.backing_path) == 0) return;
                const auto bytes = slurp(f.backing_path);
                appendTo(to, f.encryption_iv.empty() ? bytes : fakeOpen(bytes));
            },
            .seal = [this](const fs::PlaintextSource& from, const stdfs::path& to,
                           const std::shared_ptr<fs::model::File>& staged) {
                if (failSeal) throw std::runtime_error("seal failed");
                spit(to, fakeSeal(readSource(from)));
                staged->encryption_iv = "iv-" + std::to_string(++seals);
                staged->encrypted_with_key_version = 3;
            },
            .current = [this](uint64_t) { return deleted ? nullptr : file; },
            .commit = {},
            .saved = [this](const std::shared_ptr<fs::model::File>&) { ++saves; },
            .lock = {},
            .recover = [this](const fs::model::File& last, const fs::PlaintextSource& content, std::optional<int32_t>) {
                if (failRecover) throw std::runtime_error("vault unavailable");
                EXPECT_EQ(last.path, file->path) << "restored where the deleted file was";
                recovered.push_back(readSource(content));
            },
        });
    }

    void TearDown() override { stdfs::remove_all(dir); }

    // A file already at rest: sealed bytes on disk, IV recorded.
    void storeSealed(const std::string& plain) {
        spit(file->backing_path, fakeSeal(plain));
        file->encryption_iv = "iv-0";
        file->size_bytes = plain.size();
    }

    std::string readAll(const fuse::WorkingCopies::Handle& h) const {
        std::string out(4096, '\0');
        const auto n = copies->read(h, out.data(), out.size(), 0);
        out.resize(static_cast<size_t>(n));
        return out;
    }

    // Every byte the working-copy directory holds on disk (what a crash would leave behind).
    std::string bytesOnDisk() const {
        std::string all;
        if (!stdfs::exists(dir / "working")) return all;
        for (const auto& e : stdfs::recursive_directory_iterator(dir / "working"))
            if (e.is_regular_file()) all += slurp(e.path());
        return all;
    }

    size_t plainFilesUnder(const stdfs::path& root) const {
        size_t n = 0;
        if (!stdfs::exists(root)) return 0;
        for (const auto& e : stdfs::directory_iterator(root)) n += e.is_regular_file() ? 1 : 0;
        return n;
    }
};

TEST_F(WorkingCopiesTest, ReadsDecryptAndAReadOnlyCloseWritesNothing) {
    storeSealed("hello\n");
    const auto sealedBefore = slurp(file->backing_path);

    auto h = copies->open(42, file, O_RDONLY);
    EXPECT_EQ(readAll(h), "hello\n");

    struct stat st{};
    const auto copyPath = h.copy->file->path();
    ASSERT_EQ(::stat(copyPath.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u) << "daemon-only";
    EXPECT_TRUE(copyPath.string().starts_with((dir / "working").string())) << "never inside the mount";
    EXPECT_FALSE(contains(bytesOnDisk(), "hello")) << "the working copy is ciphertext on disk";

    copies->release(h);
    EXPECT_EQ(saves, 0);
    EXPECT_EQ(slurp(file->backing_path), sealedBefore);
    EXPECT_EQ(plainFilesUnder(dir / "working"), 0u) << "the last release deletes the copy";
}

TEST_F(WorkingCopiesTest, WritesAreSealedBackWithANewIvAndThePlaintextSize) {
    storeSealed("hello\n");

    auto h = copies->open(42, file, O_RDWR);
    const std::string more = "hello, world\n";
    ASSERT_EQ(copies->write(h, more.data(), more.size(), 0, 5), static_cast<ssize_t>(more.size()));
    EXPECT_EQ(copies->openSize(42), more.size()) << "getattr sees the plaintext size while the file is open";
    copies->release(h);

    EXPECT_EQ(saves, 1);
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), more) << "ciphertext on disk";
    EXPECT_EQ(file->encryption_iv, "iv-1");
    EXPECT_EQ(file->encrypted_with_key_version, 3u);
    EXPECT_EQ(file->size_bytes, more.size()) << "size_bytes is the plaintext size, not the ciphertext's";
    EXPECT_EQ(file->last_modified_by, 5);
    EXPECT_FALSE(copies->openSize(42));
    EXPECT_EQ(plainFilesUnder(file->backing_path.parent_path()), 1u) << "no sealing leftovers next to the file";
}

TEST_F(WorkingCopiesTest, HandlesOnOneInodeShareACopyAndFlushSealsOnlyWhatChanged) {
    storeSealed("abc");

    auto writer = copies->open(42, file, O_WRONLY);
    auto reader = copies->open(42, file, O_RDONLY);
    EXPECT_EQ(writer.copy, reader.copy);

    ASSERT_EQ(copies->write(writer, "XY", 2, 1, std::nullopt), 2);
    EXPECT_EQ(readAll(reader), "aXY");

    copies->persist(writer);  // flush: close(2) returns with the change on disk
    EXPECT_EQ(saves, 1);
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), "aXY");
    copies->persist(writer);
    EXPECT_EQ(saves, 1) << "an unchanged copy is not sealed again";

    copies->release(writer);
    EXPECT_EQ(readAll(reader), "aXY") << "the copy lives until the last handle";
    copies->release(reader);
    EXPECT_EQ(saves, 1);
}

TEST_F(WorkingCopiesTest, OTruncEmptiesWritableOpensOnly) {
    storeSealed("keep me");

    auto ro = copies->open(42, file, O_RDONLY | O_TRUNC);
    EXPECT_EQ(readAll(ro), "keep me");
    copies->release(ro);
    EXPECT_EQ(saves, 0);

    auto wo = copies->open(42, file, O_WRONLY | O_TRUNC);
    ASSERT_EQ(copies->write(wo, "new", 3, 0, std::nullopt), 3);
    copies->release(wo);
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), "new") << "no stale tail from the longer old content";
}

TEST_F(WorkingCopiesTest, ATruncatingOpenNeverMaterializesTheOldContentButStillPersistsTheTruncation) {
    // For a remote-only cloud file materializing means downloading it; O_TRUNC discards it anyway.
    storeSealed("old content that would have been fetched");
    auto wo = copies->open(42, file, O_WRONLY | O_TRUNC);
    EXPECT_EQ(materializations, 0);
    copies->release(wo);
    EXPECT_EQ(saves, 1) << "an O_TRUNC open with no writes still empties the file";
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), "");
}

TEST_F(WorkingCopiesTest, TheRowIsCommittedBeforeTheSealedBytesReplaceTheBackingFile) {
    storeSealed("old");
    const auto before = slurp(file->backing_path);
    bool committed = false;
    copies = std::make_unique<fuse::WorkingCopies>(dir / "working", fuse::WorkingCopyHooks{
        .materialize = [](const fs::model::File& f, crypto::ScratchFile& to) { appendTo(to, fakeOpen(slurp(f.backing_path))); },
        .seal = [](const fs::PlaintextSource& from, const stdfs::path& to, const std::shared_ptr<fs::model::File>& staged) {
            spit(to, fakeSeal(readSource(from)));
            staged->encryption_iv = "iv-new";
        },
        .current = [this](uint64_t) { return file; },
        .commit = [&](const fuse::WorkingCopyHooks::Commit& c) {
            committed = true;
            EXPECT_EQ(c.staged->encryption_iv, "iv-new");
            EXPECT_EQ(c.prior.encryption_iv, "iv-0") << "the generation being replaced, for local versioning";
            EXPECT_EQ(c.prior.backing_path, file->backing_path);
            EXPECT_TRUE(c.truncated) << "opened with O_TRUNC";
            EXPECT_EQ(slurp(file->backing_path), before) << "the old bytes are still in place when the row is written";
            EXPECT_TRUE(stdfs::exists(fs::ops::contentSidecarPath(file->backing_path)));
        },
        .saved = [](const std::shared_ptr<fs::model::File>&) {},
        .lock = {},
        .recover = {},
    });
    auto h = copies->open(42, file, O_WRONLY | O_TRUNC);
    ASSERT_EQ(copies->write(h, "new", 3, 0, std::nullopt), 3);
    copies->release(h);
    EXPECT_TRUE(committed);
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), "new");
    EXPECT_FALSE(stdfs::exists(fs::ops::contentSidecarPath(file->backing_path)));
}

TEST_F(WorkingCopiesTest, AFailedRowCommitKeepsTheOldBytesAndNoSidecar) {
    storeSealed("old");
    const auto before = slurp(file->backing_path);
    copies = std::make_unique<fuse::WorkingCopies>(dir / "working", fuse::WorkingCopyHooks{
        .materialize = [](const fs::model::File& f, crypto::ScratchFile& to) { appendTo(to, fakeOpen(slurp(f.backing_path))); },
        .seal = [](const fs::PlaintextSource& from, const stdfs::path& to, const std::shared_ptr<fs::model::File>&) {
            spit(to, fakeSeal(readSource(from)));
        },
        .current = [this](uint64_t) { return file; },
        .commit = [](const fuse::WorkingCopyHooks::Commit&) { throw std::runtime_error("database unavailable"); },
        .saved = [](const std::shared_ptr<fs::model::File>&) {},
        .lock = {},
        .recover = {},
    });
    auto h = copies->open(42, file, O_WRONLY | O_TRUNC);
    ASSERT_EQ(copies->write(h, "new", 3, 0, std::nullopt), 3);
    EXPECT_THROW(copies->release(h), std::runtime_error);
    EXPECT_EQ(slurp(file->backing_path), before);
    EXPECT_FALSE(stdfs::exists(fs::ops::contentSidecarPath(file->backing_path)));
}

TEST_F(WorkingCopiesTest, TruncateShrinksAndGrowsThePlaintext) {
    storeSealed("0123456789");

    auto h = copies->open(42, file, O_RDWR);
    copies->truncate(h, 4, std::nullopt);
    EXPECT_EQ(readAll(h), "0123");
    copies->truncate(h, 6, std::nullopt);
    EXPECT_EQ(copies->openSize(42), 6u);
    copies->release(h);
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), std::string("0123\0\0", 6));
    EXPECT_EQ(file->size_bytes, 6u);
}

TEST_F(WorkingCopiesTest, EmptyingAFileStoresAnEmptyFileWithoutAnIv) {
    storeSealed("gone soon");

    auto h = copies->open(42, file, O_WRONLY | O_TRUNC);
    copies->release(h);

    EXPECT_EQ(saves, 1);
    EXPECT_EQ(stdfs::file_size(file->backing_path), 0u);
    EXPECT_TRUE(file->encryption_iv.empty());
    EXPECT_EQ(file->size_bytes, 0u);
}

TEST_F(WorkingCopiesTest, PlaintextLeftByOlderBuildsReadsCorrectlyAndIsSealedOnClose) {
    spit(file->backing_path, "written by 1.8.0\n");  // no IV: stored in plaintext
    file->encryption_iv.clear();
    file->size_bytes = 0;

    auto h = copies->open(42, file, O_RDONLY);
    EXPECT_EQ(readAll(h), "written by 1.8.0\n");
    copies->release(h);

    EXPECT_EQ(saves, 1) << "the plaintext file is encrypted on its first close";
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), "written by 1.8.0\n");
    EXPECT_FALSE(file->encryption_iv.empty());
    EXPECT_EQ(file->size_bytes, 17u);
}

TEST_F(WorkingCopiesTest, AFileDeletedWhileOpenIsNotWrittenBack) {
    storeSealed("abc");
    auto h = copies->open(42, file, O_RDWR);
    ASSERT_EQ(copies->write(h, "z", 1, 0, std::nullopt), 1);
    deleted = true;
    const auto sealedBefore = slurp(file->backing_path);

    EXPECT_NO_THROW(copies->release(h));
    EXPECT_EQ(saves, 0);
    EXPECT_EQ(slurp(file->backing_path), sealedBefore);
    EXPECT_EQ(plainFilesUnder(dir / "working"), 0u);
}

TEST_F(WorkingCopiesTest, WritesNeverReachTheDiskAsPlaintext) {
    const std::string marker = "PLAINTEXT-MARKER-THAT-MUST-NOT-REACH-THE-DISK|";
    std::string big;
    while (big.size() < 300 * 1024) big += marker;

    auto h = copies->open(42, file, O_RDWR);
    ASSERT_EQ(copies->write(h, big.data(), big.size(), 0, std::nullopt), static_cast<ssize_t>(big.size()));
    h.copy->file->flush();  // every block on disk, none left in memory
    const auto onDisk = bytesOnDisk();
    EXPECT_GT(onDisk.size(), big.size()) << "all of it is on disk (plus a nonce and tag per block)";
    EXPECT_FALSE(contains(onDisk, "PLAINTEXT-MARKER")) << "only ciphertext is ever written";
    EXPECT_EQ(readAll(h), big.substr(0, 4096));
    copies->release(h);
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), big);
}

TEST_F(WorkingCopiesTest, AFailedSealKeepsTheChangesEncryptedAndRetriesUntilTheyAreWrittenBack) {
    storeSealed("original");
    const auto sealedBefore = slurp(file->backing_path);

    auto h = copies->open(42, file, O_RDWR);
    ASSERT_EQ(copies->write(h, "CHANGED!", 8, 0, 9), 8);
    failSeal = true;

    EXPECT_THROW(copies->release(h), std::runtime_error);
    EXPECT_EQ(slurp(file->backing_path), sealedBefore) << "the old ciphertext stays intact";
    EXPECT_EQ(file->encryption_iv, "iv-0") << "metadata is only updated after the sealed file is in place";
    EXPECT_EQ(plainFilesUnder(file->backing_path.parent_path()), 1u);
    ASSERT_EQ(plainFilesUnder(dir / "working" / "unsaved"), 1u) << "kept in unsaved/";
    EXPECT_FALSE(contains(bytesOnDisk(), "CHANGED!")) << "and never as plaintext";
    EXPECT_FALSE(contains(bytesOnDisk(), "original"));
    EXPECT_TRUE(copies->isOpen(42)) << "an unsaved copy still holds the file against conditional writers";
    EXPECT_EQ(copies->unsavedCount(), 1u);
    EXPECT_EQ(copies->openSize(42), 8u);

    EXPECT_EQ(copies->retryUnsaved(), 1u) << "still failing: still kept";
    EXPECT_EQ(copies->unsavedCount(), 1u);

    failSeal = false;
    EXPECT_EQ(copies->retryUnsaved(), 0u);
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), "CHANGED!") << "the retry wrote the changes back";
    EXPECT_EQ(file->last_modified_by, 9) << "attributed to who made them";
    EXPECT_FALSE(copies->isOpen(42));
    EXPECT_EQ(copies->unsavedCount(), 0u);
    EXPECT_EQ(plainFilesUnder(dir / "working" / "unsaved"), 0u);
    EXPECT_EQ(plainFilesUnder(dir / "working"), 0u);
}

TEST_F(WorkingCopiesTest, ReopeningAnUnsavedFileShowsItsChangesAndTheNextCloseSavesThem) {
    storeSealed("original");
    auto h = copies->open(42, file, O_RDWR);
    ASSERT_EQ(copies->write(h, "CHANGED!", 8, 0, std::nullopt), 8);
    failSeal = true;
    EXPECT_THROW(copies->release(h), std::runtime_error);

    failSeal = false;
    auto again = copies->open(42, file, O_RDONLY);
    EXPECT_EQ(readAll(again), "CHANGED!") << "the same copy, not the stale backing file";
    EXPECT_EQ(materializations, 1) << "not decrypted again over the unsaved changes";
    copies->release(again);
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), "CHANGED!");
    EXPECT_FALSE(copies->isOpen(42));
    EXPECT_EQ(plainFilesUnder(dir / "working"), 0u);
    EXPECT_EQ(plainFilesUnder(dir / "working" / "unsaved"), 0u);
}

TEST_F(WorkingCopiesTest, AnUnsavedFileDeletedMeanwhileIsRestoredAsANewFile) {
    storeSealed("original");
    auto h = copies->open(42, file, O_RDWR);
    ASSERT_EQ(copies->write(h, "CHANGED!", 8, 0, std::nullopt), 8);
    failSeal = true;
    EXPECT_THROW(copies->release(h), std::runtime_error);

    deleted = true;
    failRecover = true;
    EXPECT_EQ(copies->retryUnsaved(), 1u) << "the vault can't take it yet: kept";
    EXPECT_TRUE(recovered.empty());

    failRecover = false;
    EXPECT_EQ(copies->retryUnsaved(), 0u);
    ASSERT_EQ(recovered.size(), 1u);
    EXPECT_EQ(recovered.front(), "CHANGED!");
    EXPECT_FALSE(copies->isOpen(42));
    EXPECT_EQ(plainFilesUnder(dir / "working" / "unsaved"), 0u);
}

TEST_F(WorkingCopiesTest, ShutdownTriesOnceMoreThenReportsAndDeletesWhatIsStillUnsaved) {
    storeSealed("original");
    auto h = copies->open(42, file, O_RDWR);
    ASSERT_EQ(copies->write(h, "CHANGED!", 8, 0, std::nullopt), 8);
    failSeal = true;
    EXPECT_THROW(copies->release(h), std::runtime_error);

    EXPECT_EQ(copies->shutdown(), 1u) << "lost: its key ends with the process";
    EXPECT_FALSE(copies->isOpen(42));
    EXPECT_EQ(plainFilesUnder(dir / "working" / "unsaved"), 0u);

    // A failure that clears before shutdown loses nothing.
    auto again = copies->open(42, file, O_RDWR);
    ASSERT_EQ(copies->write(again, "SAVED!!!", 8, 0, std::nullopt), 8);
    EXPECT_THROW(copies->release(again), std::runtime_error);
    failSeal = false;
    EXPECT_EQ(copies->shutdown(), 0u);
    EXPECT_EQ(fakeOpen(slurp(file->backing_path)), "SAVED!!!");
}

TEST_F(WorkingCopiesTest, TheRetryThreadStopsWithoutWaitingOutItsInterval) {
    storeSealed("original");
    auto h = copies->open(42, file, O_RDWR);
    ASSERT_EQ(copies->write(h, "CHANGED!", 8, 0, std::nullopt), 8);
    failSeal = true;
    EXPECT_THROW(copies->release(h), std::runtime_error);
    copies->startRetrying();
    copies->stopRetrying();  // never waits out the interval
    EXPECT_EQ(copies->unsavedCount(), 1u);
}

TEST_F(WorkingCopiesTest, ClearStaleDeletesWhatACrashLeftAndCountsTheLostUnsavedChanges) {
    // A previous run's copies, under that run's key (any other key than this process's).
    stdfs::create_directories(dir / "working" / "unsaved");
    {
        const auto otherRunKey = crypto::SecretKey::random();
        crypto::ScratchFile left(dir / "working" / "x.scratch", otherRunKey);
        crypto::ScratchFile kept(dir / "working" / "unsaved" / "y.scratch", otherRunKey);
        appendTo(left, "secret");
        appendTo(kept, "unsaved work");
        left.flush();
        kept.flush();
        // A crash: the files outlive the objects (and the key).
        stdfs::copy_file(left.path(), dir / "working" / "9-left.scratch");
        stdfs::copy_file(kept.path(), dir / "working" / "unsaved" / "9-kept.scratch");
    }
    // Versions before #328 kept plaintext next to it.
    const auto legacy = dir / std::string(fuse::WorkingCopies::kLegacyDirName);
    stdfs::create_directories(legacy / "unsaved");
    spit(legacy / "7-stale.plain", "stale plaintext");
    spit(legacy / "unsaved" / "7-kept.plain", "the operator needs this");

    const auto sweep = copies->clearStale();
    EXPECT_EQ(sweep.removed, 2u);
    EXPECT_EQ(sweep.unsavedLost, 1u);
    EXPECT_EQ(sweep.legacyPlaintextKept, 1u);
    EXPECT_FALSE(stdfs::exists(dir / "working" / "9-left.scratch"));
    EXPECT_FALSE(stdfs::exists(dir / "working" / "unsaved" / "9-kept.scratch"));
    EXPECT_FALSE(stdfs::exists(legacy / "7-stale.plain"));
    EXPECT_TRUE(stdfs::exists(legacy / "unsaved" / "7-kept.plain")) << "never deleted: it is the operator's data";

    stdfs::remove(legacy / "unsaved" / "7-kept.plain");
    EXPECT_EQ(copies->clearStale().legacyPlaintextKept, 0u);
    EXPECT_FALSE(stdfs::exists(legacy)) << "an empty legacy directory goes";
}

// --- streaming AES-256-GCM decryption -------------------------------------------------------------------------

class GcmFileTest : public ::testing::Test {
protected:
    stdfs::path dir;
    std::vector<uint8_t> key = std::vector<uint8_t>(crypto::util::AES_KEY_SIZE);

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        randombytes_buf(key.data(), key.size());
        dir = stdfs::temp_directory_path() / ("vh_gcm_" + std::to_string(::getpid()) + "_" +
                                              ::testing::UnitTest::GetInstance()->current_test_info()->name());
        stdfs::remove_all(dir);
        stdfs::create_directories(dir);
    }
    void TearDown() override { stdfs::remove_all(dir); }

    static std::function<void(std::span<const uint8_t>)> sinkInto(std::vector<uint8_t>& out) {
        return [&out](const std::span<const uint8_t> chunk) { out.insert(out.end(), chunk.begin(), chunk.end()); };
    }

    // Writes plaintext sealed the way vault files are (body || tag, IV kept separately); returns the IV.
    std::vector<uint8_t> seal(const std::vector<uint8_t>& plain, const stdfs::path& to) const {
        std::vector<uint8_t> iv;
        const auto ct = crypto::util::encrypt_aes256_gcm(plain, key, iv);
        std::ofstream(to, std::ios::binary).write(reinterpret_cast<const char*>(ct.data()), static_cast<std::streamsize>(ct.size()));
        return iv;
    }
};

TEST_F(GcmFileTest, StreamsLargeFilesBackToTheirPlaintext) {
    std::vector<uint8_t> plain(300 * 1024 + 17);  // several 64 KiB chunks plus a ragged end
    randombytes_buf(plain.data(), plain.size());
    const auto iv = seal(plain, dir / "c");

    std::vector<uint8_t> got;
    crypto::util::decrypt_aes256_gcm_file(dir / "c", sinkInto(got), key, iv);
    EXPECT_EQ(got, plain);
}

TEST_F(GcmFileTest, ATamperedFileFailsAndLeavesNoPlaintext) {
    const auto iv = seal({'s', 'e', 'c', 'r', 'e', 't'}, dir / "c");
    auto bytes = slurp(dir / "c");
    bytes[2] = static_cast<char>(bytes[2] ^ 1);
    spit(dir / "c", bytes);

    std::vector<uint8_t> got;
    EXPECT_THROW(crypto::util::decrypt_aes256_gcm_file(dir / "c", sinkInto(got), key, iv), std::runtime_error);
    EXPECT_EQ(std::distance(stdfs::directory_iterator(dir), stdfs::directory_iterator()), 1) << "nothing written to disk";
}

TEST_F(GcmFileTest, TheWrongKeyOrATruncatedFileFails) {
    const auto iv = seal({'a', 'b', 'c'}, dir / "c");
    auto other = key;
    other[0] ^= 1;
    std::vector<uint8_t> got;
    EXPECT_THROW(crypto::util::decrypt_aes256_gcm_file(dir / "c", sinkInto(got), other, iv), std::runtime_error);

    spit(dir / "short", "tooshort");
    EXPECT_THROW(crypto::util::decrypt_aes256_gcm_file(dir / "short", sinkInto(got), key, iv), std::runtime_error);
}

}
