// #173: the FUSE mount is the decrypting view of vault bytes that are always ciphertext on disk. These tests drive
// fuse::WorkingCopies (one decrypted working copy per open inode, sealed back on flush/fsync/last release) with a
// reversible stand-in cipher, and crypto::util::decrypt_aes256_gcm_file with real AES-256-GCM.

#include "crypto/util/encrypt.hpp"
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

        copies = std::make_unique<fuse::WorkingCopies>(dir / "plain", fuse::WorkingCopyHooks{
            .materialize = [this](const fs::model::File& f, const stdfs::path& to) {
                ++materializations;
                if (!stdfs::exists(f.backing_path) || stdfs::file_size(f.backing_path) == 0) return;
                const auto bytes = slurp(f.backing_path);
                spit(to, f.encryption_iv.empty() ? bytes : fakeOpen(bytes));
            },
            .seal = [this](const stdfs::path& from, const stdfs::path& to, const std::shared_ptr<fs::model::File>& staged) {
                if (failSeal) throw std::runtime_error("seal failed");
                spit(to, fakeSeal(slurp(from)));
                staged->encryption_iv = "iv-" + std::to_string(++seals);
                staged->encrypted_with_key_version = 3;
            },
            .current = [this](uint64_t) { return deleted ? nullptr : file; },
            .commit = {},
            .saved = [this](const std::shared_ptr<fs::model::File>&) { ++saves; },
            .lock = {},
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
    ASSERT_EQ(::stat(h.copy->path.c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600u) << "the working copy is plaintext: daemon-only";
    EXPECT_TRUE(h.copy->path.string().starts_with((dir / "plain").string())) << "never inside the mount";

    copies->release(h);
    EXPECT_EQ(saves, 0);
    EXPECT_EQ(slurp(file->backing_path), sealedBefore);
    EXPECT_EQ(plainFilesUnder(dir / "plain"), 0u) << "the last release deletes the plaintext copy";
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
    copies = std::make_unique<fuse::WorkingCopies>(dir / "plain", fuse::WorkingCopyHooks{
        .materialize = [](const fs::model::File& f, const stdfs::path& to) { spit(to, fakeOpen(slurp(f.backing_path))); },
        .seal = [](const stdfs::path& from, const stdfs::path& to, const std::shared_ptr<fs::model::File>& staged) {
            spit(to, fakeSeal(slurp(from)));
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
    copies = std::make_unique<fuse::WorkingCopies>(dir / "plain", fuse::WorkingCopyHooks{
        .materialize = [](const fs::model::File& f, const stdfs::path& to) { spit(to, fakeOpen(slurp(f.backing_path))); },
        .seal = [](const stdfs::path& from, const stdfs::path& to, const std::shared_ptr<fs::model::File>&) {
            spit(to, fakeSeal(slurp(from)));
        },
        .current = [this](uint64_t) { return file; },
        .commit = [](const fuse::WorkingCopyHooks::Commit&) { throw std::runtime_error("database unavailable"); },
        .saved = [](const std::shared_ptr<fs::model::File>&) {},
        .lock = {},
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
    EXPECT_EQ(plainFilesUnder(dir / "plain"), 0u);
}

TEST_F(WorkingCopiesTest, AFailedSealKeepsTheBackingFileAndTheChangesForTheOperator) {
    storeSealed("original");
    const auto sealedBefore = slurp(file->backing_path);

    auto h = copies->open(42, file, O_RDWR);
    ASSERT_EQ(copies->write(h, "CHANGED!", 8, 0, std::nullopt), 8);
    failSeal = true;

    EXPECT_THROW(copies->release(h), std::runtime_error);
    EXPECT_EQ(slurp(file->backing_path), sealedBefore) << "the old ciphertext stays intact";
    EXPECT_EQ(file->encryption_iv, "iv-0") << "metadata is only updated after the sealed file is in place";
    ASSERT_EQ(plainFilesUnder(dir / "plain" / "unsaved"), 1u);
    EXPECT_EQ(slurp(stdfs::directory_iterator(dir / "plain" / "unsaved")->path()), "CHANGED!");
    EXPECT_EQ(plainFilesUnder(file->backing_path.parent_path()), 1u);
}

TEST_F(WorkingCopiesTest, ClearStaleRemovesLeftoverPlaintextButKeepsUnsaved) {
    stdfs::create_directories(dir / "plain" / "unsaved");
    spit(dir / "plain" / "9-left.plain", "secret");
    spit(dir / "plain" / "unsaved" / "9-kept.plain", "operator needs this");

    copies->clearStale();
    EXPECT_FALSE(stdfs::exists(dir / "plain" / "9-left.plain"));
    EXPECT_TRUE(stdfs::exists(dir / "plain" / "unsaved" / "9-kept.plain"));
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

    crypto::util::decrypt_aes256_gcm_file(dir / "c", dir / "p", key, iv);
    const auto got = slurp(dir / "p");
    EXPECT_EQ(std::vector<uint8_t>(got.begin(), got.end()), plain);
}

TEST_F(GcmFileTest, ATamperedFileFailsAndLeavesNoPlaintext) {
    const auto iv = seal({'s', 'e', 'c', 'r', 'e', 't'}, dir / "c");
    auto bytes = slurp(dir / "c");
    bytes[2] = static_cast<char>(bytes[2] ^ 1);
    spit(dir / "c", bytes);

    EXPECT_THROW(crypto::util::decrypt_aes256_gcm_file(dir / "c", dir / "p", key, iv), std::runtime_error);
    EXPECT_FALSE(stdfs::exists(dir / "p"));
}

TEST_F(GcmFileTest, TheWrongKeyOrATruncatedFileFails) {
    const auto iv = seal({'a', 'b', 'c'}, dir / "c");
    auto other = key;
    other[0] ^= 1;
    EXPECT_THROW(crypto::util::decrypt_aes256_gcm_file(dir / "c", dir / "p", other, iv), std::runtime_error);
    EXPECT_FALSE(stdfs::exists(dir / "p"));

    spit(dir / "short", "tooshort");
    EXPECT_THROW(crypto::util::decrypt_aes256_gcm_file(dir / "short", dir / "p", key, iv), std::runtime_error);
}

}
