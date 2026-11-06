// #328: crypto::ScratchFile keeps in-use plaintext (FUSE working copies, upload and `vh fs put` staging) on disk only
// as block-wise XChaCha20-Poly1305 under a key held in this process's memory. These tests pin the properties the
// design depends on: random access matches a plain byte array, nothing readable reaches the disk, a rewritten block
// never reuses a nonce, tampering fails closed, and what a crash leaves is unreadable under any other key.

#include "crypto/ScratchFile.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <random>
#include <string>
#include <thread>
#include <vector>

namespace vh::test_scratch_file {

namespace stdfs = std::filesystem;
using crypto::ScratchFile;

std::string slurp(const stdfs::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

std::span<const uint8_t> bytesOf(const std::string& s) { return {reinterpret_cast<const uint8_t*>(s.data()), s.size()}; }

std::string readRange(const ScratchFile& f, const uint64_t offset, const std::size_t n) {
    std::string out(n, '\0');
    const auto got = f.read(offset, {reinterpret_cast<uint8_t*>(out.data()), out.size()});
    out.resize(got);
    return out;
}

std::string readAll(const ScratchFile& f) { return readRange(f, 0, static_cast<std::size_t>(f.size())); }

// Raw record access, as an attacker with the disk would have it.
std::string rawRecord(const stdfs::path& path, const uint64_t index, const std::size_t length) {
    const auto all = slurp(path);
    return all.substr(index * ScratchFile::kRecordSize, length);
}

void overwriteRaw(const stdfs::path& path, const uint64_t offset, const std::string& bytes) {
    const int fd = ::open(path.c_str(), O_WRONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::pwrite(fd, bytes.data(), bytes.size(), static_cast<off_t>(offset)), static_cast<ssize_t>(bytes.size()));
    ::close(fd);
}

std::string marker(const std::size_t n) {
    static const std::string unit = "VAULTHALLA-PLAINTEXT-MARKER|";
    std::string out;
    while (out.size() < n) out += unit;
    out.resize(n);
    return out;
}

class ScratchFileTest : public ::testing::Test {
protected:
    stdfs::path dir;

    void SetUp() override {
        ASSERT_GE(sodium_init(), 0);
        dir = stdfs::temp_directory_path() / ("vh_scratch_" + std::to_string(::getpid()) + "_" +
                                              ::testing::UnitTest::GetInstance()->current_test_info()->name());
        stdfs::remove_all(dir);
        stdfs::create_directories(dir);
    }
    void TearDown() override { stdfs::remove_all(dir); }
};

TEST_F(ScratchFileTest, IsPrivateExclusiveAndGoesWithItsObject) {
    const auto path = dir / "a.scratch";
    {
        ScratchFile f(path);
        struct stat st{};
        ASSERT_EQ(::stat(path.c_str(), &st), 0);
        EXPECT_EQ(st.st_mode & 0777, 0600u);
        EXPECT_THROW(ScratchFile again(path), std::system_error) << "never opens something already there";
    }
    EXPECT_FALSE(stdfs::exists(path)) << "nothing else could ever read it";
}

TEST_F(ScratchFileTest, RandomOffsetWritesReadsAndSizeChangesMatchAPlainByteArray) {
    ScratchFile f(dir / "a.scratch");
    std::string model;
    std::mt19937_64 rng(328);
    const auto pick = [&](const uint64_t lo, const uint64_t hi) { return std::uniform_int_distribution<uint64_t>(lo, hi)(rng); };

    for (int step = 0; step < 3000; ++step) {
        const auto op = pick(0, 99);
        if (op < 55) {
            // Writes anywhere, including past the end (a sparse gap reads as zeros) and across block boundaries.
            const auto offset = pick(0, std::max<uint64_t>(model.size() + 70000, 1));
            const auto length = static_cast<std::size_t>(pick(1, op < 10 ? 3 * ScratchFile::kBlockSize : 9000));
            std::string data(length, '\0');
            for (auto& c : data) c = static_cast<char>(pick(0, 255));
            f.write(offset, bytesOf(data));
            if (model.size() < offset + length) model.resize(offset + length, '\0');
            model.replace(offset, length, data);
        } else if (op < 62) {
            const auto size = pick(0, model.size() + 2 * ScratchFile::kBlockSize);
            f.truncate(size);
            model.resize(size, '\0');
        } else if (op < 65) {
            f.flush();
        } else {
            const auto offset = pick(0, model.size() + 10);
            const auto length = static_cast<std::size_t>(pick(0, 2 * ScratchFile::kBlockSize + 5));
            const auto expect = offset >= model.size() ? std::string{} : model.substr(offset, length);
            ASSERT_EQ(readRange(f, offset, length), expect) << "step " << step << " offset " << offset;
        }
        ASSERT_EQ(f.size(), model.size()) << "step " << step;
        if (model.size() > 4 * 1024 * 1024) {
            f.truncate(0);
            model.clear();
        }
    }
    ASSERT_EQ(readAll(f), model);
    f.flush();
    ASSERT_EQ(readAll(f), model) << "the same from disk alone";
}

TEST_F(ScratchFileTest, SparseGapsAndExtensionsReadAsZerosAndShrinkingKeepsTheHead) {
    ScratchFile f(dir / "a.scratch");
    f.write(200 * 1024, bytesOf("tail"));
    EXPECT_EQ(f.size(), 200u * 1024 + 4);
    EXPECT_EQ(readRange(f, 0, 200 * 1024), std::string(200 * 1024, '\0'));
    EXPECT_EQ(readRange(f, 200 * 1024, 10), "tail");

    f.truncate(1024 * 1024 + 3);
    EXPECT_EQ(readRange(f, 200 * 1024 + 4, 1024 * 1024), std::string(1024 * 1024 + 3 - 200 * 1024 - 4, '\0'));
    f.truncate(200 * 1024 + 2);
    EXPECT_EQ(readRange(f, 200 * 1024 - 1, 10), std::string("\0ta", 3));
    f.flush();
    EXPECT_EQ(stdfs::file_size(f.path()), 3 * ScratchFile::kRecordSize + ScratchFile::kRecordOverhead + 8 * 1024 + 2)
        << "a shrink releases the space the cut blocks used";
    f.truncate(0);
    EXPECT_EQ(f.size(), 0u);
    EXPECT_EQ(stdfs::file_size(f.path()), 0u);
}

TEST_F(ScratchFileTest, NothingReadableEverReachesTheDisk) {
    const auto plain = marker(5 * ScratchFile::kBlockSize + 1234);
    ScratchFile f(dir / "a.scratch");
    for (std::size_t off = 0; off < plain.size(); off += 4000)  // small appends, as an HTTP body arrives
        f.append(bytesOf(plain.substr(off, 4000)));
    f.flush();

    const auto raw = slurp(f.path());
    EXPECT_EQ(raw.size(), 5 * ScratchFile::kRecordSize + ScratchFile::kRecordOverhead + 1234);
    EXPECT_EQ(raw.find("PLAINTEXT-MARKER"), std::string::npos);
    EXPECT_EQ(raw.find("VAULTHALLA"), std::string::npos);
    EXPECT_EQ(readAll(f), plain);
}

TEST_F(ScratchFileTest, RewritingABlockNeverReusesItsNonce) {
    ScratchFile f(dir / "a.scratch");
    const auto block = marker(ScratchFile::kBlockSize);
    f.write(0, bytesOf(block));
    f.flush();
    const auto first = f.nonceOf(0);
    const auto firstRecord = rawRecord(f.path(), 0, ScratchFile::kRecordSize);
    ASSERT_TRUE(first);

    f.write(0, bytesOf(block));  // the same bytes again
    f.flush();
    const auto second = f.nonceOf(0);
    ASSERT_TRUE(second);
    EXPECT_NE(*first, *second) << "a fresh random nonce on every write of a block";
    EXPECT_NE(rawRecord(f.path(), 0, ScratchFile::kRecordSize), firstRecord);

    f.write(10, bytesOf("x"));  // a partial rewrite too
    f.flush();
    EXPECT_NE(*f.nonceOf(0), *second);
    EXPECT_EQ(rawRecord(f.path(), 0, ScratchFile::kNonceSize),
              std::string(reinterpret_cast<const char*>(f.nonceOf(0)->data()), ScratchFile::kNonceSize))
        << "the nonce is stored beside the block";
}

TEST_F(ScratchFileTest, AFlippedByteFailsClosed) {
    ScratchFile f(dir / "a.scratch");
    f.write(0, bytesOf(marker(2 * ScratchFile::kBlockSize)));
    f.flush();
    const auto path = f.path();

    const auto original = rawRecord(path, 1, ScratchFile::kRecordSize);
    for (const std::size_t at : {std::size_t{0}, ScratchFile::kNonceSize + 100, ScratchFile::kRecordSize - 1}) {
        auto flipped = original;
        flipped[at] = static_cast<char>(flipped[at] ^ 0x01);
        overwriteRaw(path, ScratchFile::kRecordSize, flipped);
        std::array<uint8_t, 16> out{};
        EXPECT_THROW((void)f.read(ScratchFile::kBlockSize + 5, out), ScratchFile::Tampered) << "byte " << at;
        overwriteRaw(path, ScratchFile::kRecordSize, original);
    }
    EXPECT_EQ(readRange(f, ScratchFile::kBlockSize, 10), marker(2 * ScratchFile::kBlockSize).substr(ScratchFile::kBlockSize, 10));
}

TEST_F(ScratchFileTest, SwappedMovedOrReplayedBlocksFailClosed) {
    ScratchFile f(dir / "a.scratch");
    std::string plain = std::string(ScratchFile::kBlockSize, 'A') + std::string(ScratchFile::kBlockSize, 'B');
    f.write(0, bytesOf(plain));
    f.flush();
    const auto path = f.path();
    const auto r0 = rawRecord(path, 0, ScratchFile::kRecordSize);
    const auto r1 = rawRecord(path, 1, ScratchFile::kRecordSize);
    std::array<uint8_t, 8> out{};

    // Swapped within the file.
    overwriteRaw(path, 0, r1);
    overwriteRaw(path, ScratchFile::kRecordSize, r0);
    EXPECT_THROW((void)f.read(0, out), ScratchFile::Tampered);
    EXPECT_THROW((void)f.read(ScratchFile::kBlockSize, out), ScratchFile::Tampered);
    overwriteRaw(path, 0, r0);
    overwriteRaw(path, ScratchFile::kRecordSize, r1);

    // A replayed older version of the same block.
    f.write(0, bytesOf(std::string(ScratchFile::kBlockSize, 'C')));
    f.flush();
    overwriteRaw(path, 0, r0);
    EXPECT_THROW((void)f.read(0, out), ScratchFile::Tampered);

    // A block from another file under the same key, at the same index, with its nonce made to match: the AAD binds
    // every block to its own file.
    ScratchFile other(dir / "b.scratch");
    other.write(0, bytesOf(std::string(ScratchFile::kBlockSize, 'C')));
    other.flush();
    auto foreign = rawRecord(other.path(), 0, ScratchFile::kRecordSize);
    const auto mine = f.nonceOf(0);
    std::copy(mine->begin(), mine->end(), foreign.begin());
    overwriteRaw(path, 0, foreign);
    EXPECT_THROW((void)f.read(0, out), ScratchFile::Tampered);
}

TEST_F(ScratchFileTest, ACutOffFileFailsClosed) {
    ScratchFile f(dir / "a.scratch");
    f.write(0, bytesOf(marker(3 * ScratchFile::kBlockSize)));
    f.flush();
    ASSERT_EQ(::truncate(f.path().c_str(), static_cast<off_t>(2 * ScratchFile::kRecordSize + 10)), 0);
    std::array<uint8_t, 8> out{};
    EXPECT_THROW((void)f.read(2 * ScratchFile::kBlockSize, out), ScratchFile::Tampered);
    EXPECT_NO_THROW((void)f.read(0, out));
}

// What a crash leaves: records that open only under the key that died with the process (the positive control shows
// the layout is what the test thinks), never under the next process's key.
TEST_F(ScratchFileTest, LeftoversCanOnlyBeReadUnderTheKeyThatDiedWithTheirProcess) {
    const auto deadKey = crypto::SecretKey::random();
    const auto plain = marker(1000);
    std::string leftover;
    std::array<uint8_t, ScratchFile::kIdSize> id{};
    {
        ScratchFile f(dir / "a.scratch", deadKey);
        f.write(0, bytesOf(plain));
        f.flush();
        leftover = slurp(f.path());
        id = f.fileId();
    }
    ASSERT_EQ(leftover.size(), ScratchFile::kRecordOverhead + plain.size());

    std::array<uint8_t, ScratchFile::kIdSize + 8> aad{};
    std::copy(id.begin(), id.end(), aad.begin());  // block 0: BE64(0)
    const auto* rec = reinterpret_cast<const uint8_t*>(leftover.data());
    const auto open = [&](const crypto::SecretKeyPtr& key) {
        std::vector<uint8_t> out(plain.size());
        unsigned long long n = 0;
        const bool ok = crypto_aead_xchacha20poly1305_ietf_decrypt(
                            out.data(), &n, nullptr, rec + ScratchFile::kNonceSize,
                            leftover.size() - ScratchFile::kNonceSize, aad.data(), aad.size(), rec,
                            key->bytes().data()) == 0;
        return ok ? std::string(out.begin(), out.end()) : std::string{};
    };
    EXPECT_EQ(open(deadKey), plain) << "positive control";
    EXPECT_EQ(open(crypto::SecretKey::random()), "") << "any other key, such as the next run's";
    EXPECT_EQ(open(ScratchFile::processKey()), "");
    EXPECT_EQ(leftover.find("PLAINTEXT-MARKER"), std::string::npos);
}

TEST_F(ScratchFileTest, ConcurrentReadersNeverSeeATornBlock) {
    ScratchFile f(dir / "a.scratch");
    const std::string a(ScratchFile::kBlockSize, 'a'), b(ScratchFile::kBlockSize, 'b');
    f.write(0, bytesOf(a));
    f.write(ScratchFile::kBlockSize, bytesOf(a));  // two blocks, so writes move the cache and hit the disk
    std::atomic<bool> stop{false};
    std::atomic<int> torn{0};
    std::vector<std::thread> readers;
    for (int r = 0; r < 4; ++r)
        readers.emplace_back([&] {
            std::string buf(ScratchFile::kBlockSize, '\0');
            while (!stop.load()) {
                for (const uint64_t at : {uint64_t{0}, uint64_t{ScratchFile::kBlockSize}}) {
                    (void)f.read(at, {reinterpret_cast<uint8_t*>(buf.data()), buf.size()});
                    if (buf != a && buf != b) ++torn;
                }
            }
        });
    for (int i = 0; i < 126; ++i) {  // three cycles of the (i % 2, i % 3, i % 7) pattern
        f.write((i % 2) * ScratchFile::kBlockSize, bytesOf(i % 3 ? a : b));
        if (i % 7 == 0) f.flush();
    }
    stop = true;
    for (auto& t : readers) t.join();
    EXPECT_EQ(torn.load(), 0);
}

// Sequential throughput of a large working copy, plain file vs scratch file. Not part of the suite (timing); run with
// --gtest_also_run_disabled_tests --gtest_filter='*Throughput*'. Numbers go in the PR, not in assertions.
TEST_F(ScratchFileTest, DISABLED_SequentialThroughput) {
    constexpr std::size_t kTotal = 1ull << 30, kChunk = 128 * 1024;  // FUSE's usual write size
    std::vector<uint8_t> chunk(kChunk);
    randombytes_buf(chunk.data(), chunk.size());
    const auto mbps = [&](const auto& body) {
        const auto start = std::chrono::steady_clock::now();
        body();
        const std::chrono::duration<double> s = std::chrono::steady_clock::now() - start;
        return static_cast<double>(kTotal) / (1024.0 * 1024.0) / s.count();
    };
    {
        const auto path = dir / "plain.bin";
        const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        ASSERT_GE(fd, 0);
        const auto w = mbps([&] {
            for (std::size_t off = 0; off < kTotal; off += kChunk)
                ASSERT_EQ(::pwrite(fd, chunk.data(), kChunk, static_cast<off_t>(off)), static_cast<ssize_t>(kChunk));
        });
        const auto r = mbps([&] {
            for (std::size_t off = 0; off < kTotal; off += kChunk)
                ASSERT_EQ(::pread(fd, chunk.data(), kChunk, static_cast<off_t>(off)), static_cast<ssize_t>(kChunk));
        });
        ::close(fd);
        std::printf("plain pwrite/pread: write %.0f MiB/s, read %.0f MiB/s\n", w, r);
    }
    for (const std::size_t size : {kChunk, std::size_t{4096}}) {
        ScratchFile f(dir / ("scratch-" + std::to_string(size)));
        const auto w = mbps([&] {
            for (std::size_t off = 0; off < kTotal; off += size) f.write(off, {chunk.data(), size});
            f.flush();
        });
        const auto r = mbps([&] {
            for (std::size_t off = 0; off < kTotal; off += size) (void)f.read(off, {chunk.data(), size});
        });
        std::printf("scratch file, %zu-byte ops: write %.0f MiB/s, read %.0f MiB/s\n", size, w, r);
    }
}

}
