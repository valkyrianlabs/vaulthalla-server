// S3 gateway staging at rest (#345), without a database: the multipart part format (protocols/s3/PartCipher.hpp) and
// the request-body scratch files. The DB-backed end to end tests are S3GatewayDbTest.*Sealed*/*Legacy*/*Staged*.

#include "crypto/ScratchFile.hpp"
#include "crypto/util/digest.hpp"
#include "fs/PlaintextSource.hpp"
#include "protocols/s3/PartCipher.hpp"
#include "protocols/s3/RequestBody.hpp"
#include "protocols/s3/Router.hpp"
#include "vault/EncryptionManager.hpp"

#include <gtest/gtest.h>
#include <sodium.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <unistd.h>
#include <vector>

namespace {

namespace pc = vh::protocols::s3::part_cipher;

constexpr std::string_view kStagingNeedle = "VH-S3-STAGING-PLAINTEXT-NEEDLE";

std::vector<uint8_t> stagingPlaintext(const std::size_t size, const char salt) {
    std::vector<uint8_t> out;
    out.reserve(size);
    while (out.size() < size) {
        out.insert(out.end(), kStagingNeedle.begin(), kStagingNeedle.end());
        out.push_back(static_cast<uint8_t>(salt));
    }
    out.resize(size);
    return out;
}

std::string stagingFileBytes(const std::filesystem::path& path) {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

bool stagingHoldsNeedle(const std::filesystem::path& path) {
    return stagingFileBytes(path).find(kStagingNeedle) != std::string::npos;
}

vh::fs::PlaintextSource stagingMemory(const std::vector<uint8_t>& bytes) {
    return {.size = bytes.size(), .read = [&bytes](const uint64_t offset, const std::span<uint8_t> out) -> std::size_t {
        if (offset >= bytes.size()) return 0;
        const auto n = std::min<std::size_t>(out.size(), bytes.size() - offset);
        std::memcpy(out.data(), bytes.data() + offset, n);
        return n;
    }};
}

std::vector<uint8_t> stagingReadAll(const vh::fs::PlaintextSource& source) {
    std::vector<uint8_t> out;
    vh::fs::forEachChunk(source, [&](const std::span<const uint8_t> chunk) { out.insert(out.end(), chunk.begin(), chunk.end()); });
    return out;
}

std::vector<uint8_t> stagingMd5(const std::vector<uint8_t>& bytes) {
    const auto d = vh::crypto::util::EvpDigest::of(EVP_md5(), bytes.data(), bytes.size());
    return {d.begin(), d.end()};
}

std::array<uint8_t, 32> stagingKey(const uint8_t fill) {
    std::array<uint8_t, 32> key{};
    key.fill(fill);
    return key;
}

}

class S3GatewayPartCipher : public ::testing::Test {
protected:
    void SetUp() override {
        dir_ = std::filesystem::temp_directory_path() /
               ("vh-s3-parts-" + std::to_string(::getpid()) + "-" +
                std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
        std::filesystem::create_directories(dir_);
    }
    void TearDown() override { std::filesystem::remove_all(dir_); }

    // The vault's key as the daemon unseals it at every start: the same bytes, a new manager.
    [[nodiscard]] std::unique_ptr<vh::vault::EncryptionManager> manager(const uint8_t fill = 0x42,
                                                                        const unsigned version = 3) const {
        const auto key = stagingKey(fill);
        return std::make_unique<vh::vault::EncryptionManager>(vh::vault::EncryptionManager::ForTesting{}, kVault, key,
                                                              version);
    }

    struct Written {
        pc::Stored stored;
        std::vector<uint8_t> plain;
    };

    Written write(const vh::vault::EncryptionManager& keys, const uint32_t part, std::vector<uint8_t> plain,
                  const std::string& upload = "upload-a") {
        const pc::Binding binding{.vault_id = kVault, .upload_id = upload, .part_number = part};
        const auto path = dir_ / (upload + "-" + std::to_string(part) + "-" + std::to_string(counter_++));
        const auto sealed = pc::seal(keys, binding, stagingMemory(plain), path);
        EXPECT_EQ(sealed.size_bytes, plain.size());
        EXPECT_EQ(sealed.md5, stagingMd5(plain));
        return {.stored = {.binding = binding, .path = path, .encryption_iv = sealed.encryption_iv,
                           .key_version = sealed.key_version, .size_bytes = sealed.size_bytes},
                .plain = std::move(plain)};
    }

    static constexpr uint32_t kVault = 17;
    std::filesystem::path dir_;
    int counter_{};
};

// A sealed part holds no plaintext, is exactly body + tag, and reads back in a new process that has only the vault's
// key (no process scratch key, no memory of the write): an upload survives a daemon restart.
TEST_F(S3GatewayPartCipher, SealedPartsHoldNoPlaintextAndReadBackAfterARestart) {
    std::vector<pc::Stored> parts;
    std::vector<uint8_t> whole;
    {
        const auto before = manager();
        for (uint32_t n = 1; n <= 3; ++n) {
            auto w = write(*before, n, stagingPlaintext(n == 3 ? 1234 : 200 * 1024 + n, static_cast<char>('a' + n)));
            EXPECT_FALSE(stagingHoldsNeedle(w.stored.path));
            EXPECT_EQ(std::filesystem::file_size(w.stored.path), w.plain.size() + 16);
            EXPECT_EQ(w.stored.key_version, 3u);
            EXPECT_EQ(std::filesystem::status(w.stored.path).permissions() & std::filesystem::perms::all,
                      std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
            whole.insert(whole.end(), w.plain.begin(), w.plain.end());
            parts.push_back(w.stored);
        }
    }
    const auto after = manager();  // the restart
    const auto source = pc::open(*after, parts);
    EXPECT_EQ(source.size, whole.size());
    EXPECT_EQ(stagingReadAll(source), whole);
}

// Every way a part file can differ from what its row says fails closed, before anything is read from it.
TEST_F(S3GatewayPartCipher, TamperedSwappedReplayedOrForeignPartsFailClosed) {
    const auto keys = manager();
    const auto one = write(*keys, 1, stagingPlaintext(70000, 'x'));
    const auto two = write(*keys, 2, stagingPlaintext(70000, 'y'));
    ASSERT_NO_THROW((void)pc::open(*keys, {one.stored, two.stored}));

    const auto expectTampered = [&](std::vector<pc::Stored> parts, const std::string& what,
                                    const vh::vault::EncryptionManager* with = nullptr) {
        EXPECT_THROW((void)pc::open(with ? *with : *keys, parts), pc::Tampered) << what;
    };

    // A flipped byte.
    {
        const auto copy = dir_ / "flipped";
        std::filesystem::copy_file(one.stored.path, copy);
        std::fstream f(copy, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(5000);
        f.put('\x7f');
        f.close();
        auto flipped = one.stored;
        flipped.path = copy;
        expectTampered({flipped, two.stored}, "flipped byte");
    }
    // Part files swapped between part numbers (same size).
    {
        auto a = one.stored, b = two.stored;
        std::swap(a.path, b.path);
        std::swap(a.encryption_iv, b.encryption_iv);
        expectTampered({a, b}, "swapped");
    }
    // An older copy of part 1 under the row of its re-upload (new IV), and the re-upload's file under the old row.
    {
        const auto again = write(*keys, 1, stagingPlaintext(70000, 'z'));
        auto replay = again.stored;
        replay.path = one.stored.path;
        expectTampered({replay, two.stored}, "replayed older part");
        auto oldRow = one.stored;
        oldRow.path = again.stored.path;
        expectTampered({oldRow, two.stored}, "new file under the old IV");
    }
    // Moved to another upload or vault.
    {
        auto foreign = one.stored;
        foreign.binding.upload_id = "upload-b";
        expectTampered({foreign}, "other upload");
        foreign = one.stored;
        foreign.binding.vault_id = kVault + 1;
        expectTampered({foreign}, "other vault");
    }
    // Cut off, extended, missing.
    {
        const auto cut = dir_ / "cut";
        std::filesystem::copy_file(one.stored.path, cut);
        std::filesystem::resize_file(cut, std::filesystem::file_size(cut) - 1);
        auto c = one.stored;
        c.path = cut;
        expectTampered({c}, "cut off");
        auto shorter = one.stored;
        shorter.size_bytes -= 1;  // a row claiming a shorter part
        expectTampered({shorter}, "row size");
        auto missing = one.stored;
        missing.path = dir_ / "nope";
        expectTampered({missing}, "missing");
    }
    // Another vault key (or none of this vault's).
    {
        const auto other = manager(0x24, 3);
        expectTampered({one.stored}, "other key", other.get());
    }
}

// A part changed after it was opened (authenticated) fails the read that finishes it: nothing that read it in order
// can treat the whole as good.
TEST_F(S3GatewayPartCipher, PartChangedWhileReadingFailsTheReadThatFinishesIt) {
    const auto keys = manager();
    const auto one = write(*keys, 1, stagingPlaintext(150000, 'p'));
    const auto two = write(*keys, 2, stagingPlaintext(150000, 'q'));
    const auto source = pc::open(*keys, {one.stored, two.stored});

    std::fstream f(two.stored.path, std::ios::in | std::ios::out | std::ios::binary);
    f.seekp(100);
    f.put('\x01');
    f.close();

    EXPECT_THROW((void)stagingReadAll(source), pc::Tampered);
}

// Reads out of order (a MIME sniff of the head, then the in-order pass that seals the object) and empty parts.
TEST_F(S3GatewayPartCipher, OutOfOrderReadsAndEmptyPartsReturnTheConcatenation) {
    const auto keys = manager();
    const auto a = write(*keys, 1, stagingPlaintext(100000, 'a'));
    const auto empty = write(*keys, 2, {});
    const auto c = write(*keys, 3, stagingPlaintext(5000, 'c'));
    std::vector<uint8_t> whole = a.plain;
    whole.insert(whole.end(), c.plain.begin(), c.plain.end());

    const auto source = pc::open(*keys, {a.stored, empty.stored, c.stored});
    ASSERT_EQ(source.size, whole.size());

    std::vector<uint8_t> head(300);
    ASSERT_EQ(source.read(0, head), head.size());
    EXPECT_TRUE(std::equal(head.begin(), head.end(), whole.begin()));
    std::vector<uint8_t> middle(64);
    ASSERT_EQ(source.read(100000 + 17, middle), middle.size());
    EXPECT_TRUE(std::equal(middle.begin(), middle.end(), whole.begin() + 100000 + 17));
    EXPECT_EQ(stagingReadAll(source), whole);

    const auto onlyEmpty = pc::open(*keys, {empty.stored});
    EXPECT_EQ(onlyEmpty.size, 0u);
}

// A part is bound by its AAD to the domain label, vault, upload, part number and size.
TEST(S3GatewayPartCipherFormat, AadBindsDomainVaultUploadPartAndSize) {
    const pc::Binding b{.vault_id = 0x01020304, .upload_id = "up", .part_number = 7};
    const auto aad = pc::aad(b, 0x10);
    const std::string domain = "vaulthalla/s3-multipart-part/v1";
    std::vector<uint8_t> expected(domain.begin(), domain.end());
    expected.push_back(0);
    for (const uint8_t x : {0x01, 0x02, 0x03, 0x04, 0x00, 0x00, 0x00, 0x02}) expected.push_back(x);
    expected.push_back('u');
    expected.push_back('p');
    for (const uint8_t x : {0, 0, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0x10}) expected.push_back(x);
    EXPECT_EQ(aad, expected);
}

// An aws-chunked body is decoded into a scratch file: ciphertext under the process key on disk, gone with the payload.
TEST(S3GatewayRequestBodyStaging, DecodedAwsChunkedBodyIsCiphertextAndGoesWithThePayload) {
    const auto plain = stagingPlaintext(150000, 'k');
    std::string encoded;
    for (std::size_t at = 0; at < plain.size(); at += 65536) {
        const auto n = std::min<std::size_t>(65536, plain.size() - at);
        char size[32];
        std::snprintf(size, sizeof size, "%zx\r\n", n);
        encoded += size;
        encoded.append(reinterpret_cast<const char*>(plain.data() + at), n);
        encoded += "\r\n";
    }
    encoded += "0\r\n\r\n";
    const std::vector<uint8_t> raw(encoded.begin(), encoded.end());

    vh::protocols::s3::Router::Request request{boost::beast::http::verb::put, "/b/k", 11};
    request.set("Content-Encoding", "aws-chunked");
    request.set("x-amz-decoded-content-length", std::to_string(plain.size()));

    const auto path = std::filesystem::temp_directory_path() /
                      ("vh-s3-decoded-" + std::to_string(::getpid()) + "-" +
                       std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()));
    auto payload = vh::protocols::s3::decodeAwsChunkedBody(stagingMemory(raw), path, request, std::nullopt);
    ASSERT_TRUE(payload.file);
    EXPECT_EQ(payload.size, plain.size());
    EXPECT_TRUE(std::filesystem::exists(path));
    EXPECT_FALSE(stagingHoldsNeedle(path));
    EXPECT_EQ(stagingReadAll(vh::fs::sourceOf(*payload.file)), plain);
    payload.file.reset();
    EXPECT_FALSE(std::filesystem::exists(path));
}
