// Streamed folder-download ZIPs (#143): the writer validated by independent readers (Python zipfile, Info-ZIP
// unzip), UTF-8 and dot names, empty files and directories, ZIP64 (members over 4 GiB, offsets past 4 GiB, more
// than 65535 entries), bounded memory (one member open at a time), integrity failures truncating instead of
// vouching, zip-slip-safe names, and the HTTP session streaming it with an exact Content-Length, HEAD and disconnects.
#include "protocols/http/Router.hpp"
#include "protocols/http/Session.hpp"
#include "protocols/http/handler/Archive.hpp"
#include "storage/PlaintextReader.hpp"

#include "../helpers/zip_check.hpp"

#include <boost/asio.hpp>
#include <gtest/gtest.h>
#include <zlib.h>

#include <array>
#include <atomic>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <filesystem>
#include <future>
#include <map>
#include <thread>
#include <unistd.h>

namespace vh::protocols::http::test_archive {

using namespace std::chrono_literals;
namespace archive = handler::archive;
namespace asio = boost::asio;
using tcp = asio::ip::tcp;

namespace {

std::atomic<int> liveReaders{0};
std::atomic<int> peakReaders{0};

// Deterministic bytes per (seed, offset), or zeros. Counts how many readers are alive at once.
class FakeReader final : public storage::PlaintextReader {
public:
    FakeReader(const uint64_t size, const uint32_t seed, const bool zeros = false)
        : size_(size), seed_(seed), zeros_(zeros) {
        generation_.size = size;
        const auto now = ++liveReaders;
        int peak = peakReaders.load();
        while (now > peak && !peakReaders.compare_exchange_weak(peak, now)) {}
    }
    ~FakeReader() override { --liveReaders; }

    [[nodiscard]] uint64_t size() const override { return size_; }
    [[nodiscard]] const storage::Generation& generation() const override { return generation_; }
    std::size_t read(const uint64_t offset, const std::span<uint8_t> out) override {
        if (offset >= size_) return 0;
        const auto n = static_cast<std::size_t>(std::min<uint64_t>(out.size(), size_ - offset));
        if (zeros_) std::memset(out.data(), 0, n);
        else
            for (std::size_t i = 0; i < n; ++i) out[i] = byteAt(seed_, offset + i);
        reads.fetch_add(1);
        return n;
    }
    void requireAuthenticated() override {
        if (failVerification) throw storage::IntegrityError("Content failed integrity verification");
    }

    static uint8_t byteAt(const uint32_t seed, const uint64_t offset) {
        return static_cast<uint8_t>((offset * 131u + seed * 7u + (offset >> 9u)) & 0xffu);
    }

    std::atomic<uint64_t> reads{0};
    bool failVerification{false};

private:
    uint64_t size_;
    uint32_t seed_;
    bool zeros_;
    storage::Generation generation_;
};

archive::Member fileMember(const std::string& name, const uint64_t size) {
    return {.name = name, .size = size, .mtime = 1'700'000'000, .directory = false, .file = nullptr};
}

archive::Member dirMember(const std::string& name) {
    return {.name = name, .size = 0, .mtime = 1'700'000'000, .directory = true, .file = nullptr};
}

uint32_t seedOf(const std::string& name) { return static_cast<uint32_t>(std::hash<std::string>{}(name)); }

uint32_t expectedCrc(const archive::Member& m) {
    uLong crc = crc32_z(0L, nullptr, 0);
    std::vector<uint8_t> chunk(1 << 16);
    for (uint64_t off = 0; off < m.size; off += chunk.size()) {
        const auto n = static_cast<std::size_t>(std::min<uint64_t>(chunk.size(), m.size - off));
        for (std::size_t i = 0; i < n; ++i) chunk[i] = FakeReader::byteAt(seedOf(m.name), off + i);
        crc = crc32_z(crc, chunk.data(), n);
    }
    return static_cast<uint32_t>(crc);
}

archive::Opener patternOpener() {
    return [](const archive::Member& m) { return std::make_shared<FakeReader>(m.size, seedOf(m.name)); };
}

// Drains the archive into a file, leaving all-zero chunks as holes so multi-GiB cases cost no disk.
uint64_t drainTo(storage::PlaintextReader& zip, const std::filesystem::path& path) {
    const int fd = ::open(path.c_str(), O_CREAT | O_TRUNC | O_WRONLY | O_CLOEXEC, 0600);
    if (fd < 0) throw std::runtime_error("open " + path.string());
    static const std::vector<uint8_t> zeros(256 * 1024, 0);
    std::vector<uint8_t> chunk(256 * 1024);
    uint64_t offset = 0;
    while (offset < zip.size()) {
        const auto want = static_cast<std::size_t>(std::min<uint64_t>(chunk.size(), zip.size() - offset));
        const auto n = zip.read(offset, std::span<uint8_t>(chunk.data(), want));
        if (n == 0) break;
        if (std::memcmp(chunk.data(), zeros.data(), n) != 0) {
            if (::pwrite(fd, chunk.data(), n, static_cast<off_t>(offset)) != static_cast<ssize_t>(n)) {
                ::close(fd);
                throw std::runtime_error("pwrite");
            }
        }
        offset += n;
    }
    if (::ftruncate(fd, static_cast<off_t>(offset)) != 0) {
        ::close(fd);
        throw std::runtime_error("ftruncate");
    }
    ::close(fd);
    return offset;
}

class ScratchDir {
public:
    ScratchDir() {
        path = std::filesystem::temp_directory_path() /
               ("vh_http_archive_" + std::to_string(::getpid()) + "_" + std::to_string(counter++));
        std::filesystem::create_directories(path);
    }
    ~ScratchDir() {
        std::error_code ec;
        std::filesystem::remove_all(path, ec);
    }
    std::filesystem::path path;

private:
    inline static std::atomic<int> counter{0};
};

std::map<std::string, vh::test::zip::Item> byName(const vh::test::zip::Listing& listing) {
    std::map<std::string, vh::test::zip::Item> out;
    for (const auto& item : listing.items) out[item.name] = item;
    return out;
}

}

TEST(HttpArchiveZip, SafeNamesNeverEscapeTheArchiveRoot) {
    EXPECT_EQ(archive::safeName("a/b.txt", false), "a/b.txt");
    EXPECT_EQ(archive::safeName("/abs/x", false), "abs/x");
    EXPECT_EQ(archive::safeName("a//b/", true), "a/b/");
    EXPECT_EQ(archive::safeName(".env", false), ".env");
    EXPECT_EQ(archive::safeName("na\xC3\xAFve \xE6\x97\xA5\xE6\x9C\xAC.pdf", false), "na\xC3\xAFve \xE6\x97\xA5\xE6\x9C\xAC.pdf");
    // A Linux name with backslashes would be a path (and a traversal) to Windows extractors.
    EXPECT_EQ(archive::safeName("..\\..\\evil.bat", false), ".._.._evil.bat");
    EXPECT_EQ(archive::safeName("bad\xFF\xC0\xAFname\n", false), "bad___name_");  // invalid UTF-8, overlong '/', LF
    EXPECT_EQ(archive::safeName("\xED\xA0\x80x", false), "___x");               // UTF-16 surrogate
    EXPECT_THROW((void)archive::safeName("..", false), std::invalid_argument);
    EXPECT_THROW((void)archive::safeName("a/../b", false), std::invalid_argument);
    EXPECT_THROW((void)archive::safeName("./", true), std::invalid_argument);
    EXPECT_THROW((void)archive::safeName("//", true), std::invalid_argument);
}

TEST(HttpArchiveZip, StreamsAValidArchiveWithExactLengthUtf8NamesEmptyFilesAndDirectories) {
    const std::vector<archive::Member> members = {
        fileMember(".env", 12),
        fileMember("empty.txt", 0),
        dirMember("nested/"),
        dirMember("nested/deeper/"),                                    // an empty directory
        fileMember("nested/big.bin", archive::kSmallMemberBytes + 4097), // streamed + CRC'd chunk by chunk
        fileMember("nested/small.txt", 1000),
        fileMember("na\xC3\xAFve \xE6\x97\xA5\xE6\x9C\xAC.pdf", 3 * 1024 * 1024 + 5),
    };
    const auto expectedSize = archive::archiveSize(members);
    peakReaders = 0;
    auto zip = archive::stream(members, patternOpener());
    ASSERT_EQ(zip->size(), expectedSize);

    ScratchDir dir;
    const auto path = dir.path / "out.zip";
    ASSERT_EQ(drainTo(*zip, path), expectedSize);
    EXPECT_EQ(std::filesystem::file_size(path), expectedSize);
    EXPECT_EQ(peakReaders.load(), 1);  // never more than one member open: bounded memory
    EXPECT_EQ(liveReaders.load(), 0);

    const auto listing = vh::test::zip::pythonCheck(path);
    if (!listing) GTEST_SKIP() << "python3 unavailable";
    EXPECT_EQ(listing->badMember, "");
    ASSERT_EQ(listing->items.size(), members.size());
    const auto items = byName(*listing);
    for (const auto& m : members) {
        ASSERT_TRUE(items.contains(m.name)) << m.name;
        const auto& item = items.at(m.name);
        EXPECT_EQ(item.size, m.size) << m.name;
        EXPECT_EQ(item.directory, m.directory) << m.name;
        EXPECT_EQ(item.crc, m.directory ? 0u : expectedCrc(m)) << m.name;
        EXPECT_TRUE(item.flags & 0x0800u) << m.name;  // UTF-8 names
        EXPECT_EQ(static_cast<bool>(item.flags & 0x0008u), m.size > 0) << m.name;  // descriptors only after data
    }
    const auto unzip = vh::test::zip::unzipTest(path);
    if (unzip >= 0) {
        EXPECT_EQ(unzip, 0);
    }
}

TEST(HttpArchiveZip, AnEmptyFolderIsAnEmptyArchive) {
    auto zip = archive::stream({}, patternOpener());
    ASSERT_EQ(zip->size(), 22u);
    ScratchDir dir;
    ASSERT_EQ(drainTo(*zip, dir.path / "empty.zip"), 22u);
    const auto listing = vh::test::zip::pythonCheck(dir.path / "empty.zip");
    if (!listing) GTEST_SKIP() << "python3 unavailable";
    EXPECT_TRUE(listing->items.empty());
}

TEST(HttpArchiveZip, TheValidatorsCatchACorruptedMember) {
    // Guards the guards: a flipped data byte must fail both independent readers.
    auto zip = archive::stream({fileMember("a.txt", 64)}, patternOpener());
    ScratchDir dir;
    const auto path = dir.path / "bad.zip";
    ASSERT_GT(drainTo(*zip, path), 0u);
    {
        FILE* f = std::fopen(path.c_str(), "r+b");
        ASSERT_NE(f, nullptr);
        std::fseek(f, 30 + 5 + 9 + 10, SEEK_SET);  // local header + name + time extra, then into the data
        const int c = std::fgetc(f);
        std::fseek(f, 30 + 5 + 9 + 10, SEEK_SET);
        std::fputc(c ^ 0xff, f);
        std::fclose(f);
    }
    const auto listing = vh::test::zip::pythonCheck(path);
    if (!listing) GTEST_SKIP() << "python3 unavailable";
    EXPECT_EQ(listing->badMember, "a.txt");
    EXPECT_NE(vh::test::zip::unzipTest(path), 0);
}

TEST(HttpArchiveZip, ReadsMustBeSequential) {
    auto zip = archive::stream({fileMember("a.txt", 10)}, patternOpener());
    std::array<uint8_t, 8> buf{};
    EXPECT_THROW((void)zip->read(5, buf), std::logic_error);
    EXPECT_EQ(zip->read(0, buf), buf.size());
    EXPECT_THROW((void)zip->read(0, buf), std::logic_error);
}

TEST(HttpArchiveZip, AMemberThatFailsVerificationTruncatesBeforeItsCrcIsWritten) {
    const auto big = archive::kSmallMemberBytes * 2;
    std::shared_ptr<FakeReader> opened;
    auto zip = archive::stream({fileMember("a.bin", big), fileMember("b.txt", 5)}, [&](const archive::Member& m) {
        opened = std::make_shared<FakeReader>(m.size, 1);
        opened->failVerification = true;
        return opened;
    });
    std::vector<uint8_t> buf(256 * 1024);
    uint64_t offset = 0;
    EXPECT_THROW({
        for (;;) {
            const auto n = zip->read(offset, buf);
            if (n == 0) break;
            offset += n;
        }
    }, storage::IntegrityError);
    // Everything up to the end of a.bin's data went out; its data descriptor (the CRC) never did.
    EXPECT_LE(offset, 30 + 5 + 9 + big);
}

TEST(HttpArchiveZip, AMemberWhoseSizeChangedSinceThePlanAborts) {
    auto zip = archive::stream({fileMember("a.bin", 100)}, [](const archive::Member&) {
        return std::make_shared<FakeReader>(101, 1);
    });
    std::vector<uint8_t> buf(4096);
    EXPECT_THROW((void)zip->read(0, buf), storage::IntegrityError);
}

TEST(HttpArchiveZip, Zip64CoversMembersOver4GiBLaterOffsetsAndTheirDescriptors) {
    const uint64_t big = (4ull << 30) + 4099;  // > 0xFFFFFFFF: sizes in ZIP64 extras and an 8-byte descriptor
    const std::vector<archive::Member> members = {
        fileMember("big.bin", big),
        fileMember("after.txt", 777),  // local header beyond 4 GiB: ZIP64 offset in the central directory
        dirMember("later/"),
    };
    auto zip = archive::stream(members, [](const archive::Member& m) {
        return std::make_shared<FakeReader>(m.size, seedOf(m.name), m.name == "big.bin");
    });
    ScratchDir dir;
    const auto path = dir.path / "zip64.zip";
    ASSERT_EQ(drainTo(*zip, path), archive::archiveSize(members));

    // big.bin's 4 GiB aren't read back (two independent readers took ~22 s): its recorded CRC and descriptor are
    // checked against the CRC of its zeros, computed with crc32_combine. unzip -t covers ZIP64 in the 65535+ case.
    const auto listing = vh::test::zip::pythonCheck(path, "big.bin");
    if (!listing) GTEST_SKIP() << "python3 unavailable";
    EXPECT_EQ(listing->badMember, "");
    const auto items = byName(*listing);
    ASSERT_EQ(items.size(), 3u);
    EXPECT_EQ(items.at("big.bin").size, big);
    EXPECT_EQ(items.at("after.txt").crc, expectedCrc(members[1]));
    const std::vector<uint8_t> mib(1 << 20, 0);
    const auto mibCrc = crc32_z(0L, mib.data(), mib.size());
    uLong zerosCrc = crc32_z(0L, mib.data(), big % mib.size());
    for (uint64_t i = 0; i < big / mib.size(); ++i) zerosCrc = crc32_combine(zerosCrc, mibCrc, 1 << 20);
    EXPECT_EQ(items.at("big.bin").crc, static_cast<uint32_t>(zerosCrc));
    ASSERT_TRUE(listing->unreadDescriptor);
    EXPECT_EQ(listing->unreadDescriptor->signature, 0x08074b50u);
    EXPECT_EQ(listing->unreadDescriptor->crc, static_cast<uint32_t>(zerosCrc));
    EXPECT_EQ(listing->unreadDescriptor->compressedSize, big);
    EXPECT_EQ(listing->unreadDescriptor->size, big);
}

TEST(HttpArchiveZip, Zip64EndRecordsCoverMoreThan65535Entries) {
    std::vector<archive::Member> members;
    for (int i = 0; i < 70'000; ++i) {
        char name[32];
        std::snprintf(name, sizeof(name), "d%02d/f%05d", i % 50, i);
        members.push_back(fileMember(name, i % 1000 == 0 ? 3 : 0));
    }
    auto zip = archive::stream(members, patternOpener());
    ScratchDir dir;
    const auto path = dir.path / "many.zip";
    ASSERT_EQ(drainTo(*zip, path), archive::archiveSize(members));
    const auto listing = vh::test::zip::pythonCheck(path);
    if (!listing) GTEST_SKIP() << "python3 unavailable";
    EXPECT_EQ(listing->badMember, "");
    EXPECT_EQ(listing->items.size(), members.size());
    const auto unzip = vh::test::zip::unzipTest(path);
    if (unzip >= 0) {
        EXPECT_EQ(unzip, 0);
    }
}

// --- Through the HTTP session ---------------------------------------------------------------------------------

namespace {

struct Harness {
    asio::io_context ioc;
    tcp::acceptor acceptor{ioc, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)};
    tcp::socket client{ioc};
    std::thread serverThread;

    void start() {
        client.connect(acceptor.local_endpoint());
        tcp::socket server(ioc);
        acceptor.accept(server);
        auto session = Session::open(std::move(server));
        serverThread = std::thread([session] { session->run(); });
    }
    ~Harness() {
        boost::system::error_code ec;
        client.close(ec);
        if (serverThread.joinable()) serverThread.join();
    }
    void send(const std::string& raw) { asio::write(client, asio::buffer(raw)); }
    std::string readAll() {
        std::string all;
        boost::system::error_code ec;
        std::array<char, 65536> buf{};
        while (true) {
            const auto n = client.read_some(asio::buffer(buf), ec);
            if (ec) break;
            all.append(buf.data(), n);
        }
        return all;
    }
};

// What directory() in handler/Content.cpp builds: STORE ZIP, exact Content-Length, HEAD without a reader.
model::preview::StreamResponse zipResponse(const request& req, std::vector<archive::Member> members,
                                           archive::Opener open,
                                           std::promise<std::pair<uint64_t, bool>>* finished = nullptr) {
    model::preview::StreamResponse res;
    res.version(req.version());
    res.keep_alive(req.keep_alive());
    res.result(boost::beast::http::status::ok);
    res.set(boost::beast::http::field::content_type, "application/zip");
    res.length = archive::archiveSize(members);
    if (req.method() == boost::beast::http::verb::head) {
        res.headOnly = true;
        return res;
    }
    res.reader = archive::stream(std::move(members), std::move(open));
    if (finished)
        res.onFinish = [finished](const uint64_t sent, const bool complete) { finished->set_value({sent, complete}); };
    return res;
}

}

class HttpArchiveSessionTest : public ::testing::Test {
protected:
    void TearDown() override {
        Router::setRouteOverrideForTesting({});
        Session::setTimeoutsForTesting(20s, 60s);
    }
};

TEST_F(HttpArchiveSessionTest, HeadAnswersTheExactLengthAndGetStreamsAValidArchive) {
    const std::vector<archive::Member> members = {
        dirMember("photos/"), fileMember("photos/a.jpg", 5 * 1024 * 1024 + 3), fileMember(".env", 40)};
    const auto length = archive::archiveSize(members);
    std::atomic<int> opens{0};
    Router::setRouteOverrideForTesting([&](request&& req) -> model::preview::Response {
        return zipResponse(req, members, [&](const archive::Member& m) {
            ++opens;
            return std::make_shared<FakeReader>(m.size, seedOf(m.name));
        });
    });
    Harness h;
    h.start();
    h.send("HEAD /download HTTP/1.1\r\nHost: t\r\n\r\nGET /download HTTP/1.1\r\nHost: t\r\nConnection: close\r\n\r\n");
    const auto wire = h.readAll();
    const auto headEnd = wire.find("\r\n\r\n");
    ASSERT_NE(headEnd, std::string::npos);
    const auto head = wire.substr(0, headEnd);
    EXPECT_NE(head.find("Content-Length: " + std::to_string(length)), std::string::npos);
    // The HEAD carried no body: the next bytes are the GET's status line.
    const auto rest = wire.substr(headEnd + 4);
    ASSERT_EQ(rest.rfind("HTTP/1.1 200", 0), 0u);
    EXPECT_NE(rest.find("Content-Length: " + std::to_string(length)), std::string::npos);
    const auto body = rest.substr(rest.find("\r\n\r\n") + 4);
    ASSERT_EQ(body.size(), length);
    EXPECT_EQ(opens.load(), 2);  // only the GET opened members (the two files)

    ScratchDir dir;
    const auto path = dir.path / "wire.zip";
    {
        FILE* f = std::fopen(path.c_str(), "wb");
        ASSERT_NE(f, nullptr);
        std::fwrite(body.data(), 1, body.size(), f);
        std::fclose(f);
    }
    const auto listing = vh::test::zip::pythonCheck(path);
    if (!listing) GTEST_SKIP() << "python3 unavailable";
    EXPECT_EQ(listing->badMember, "");
    EXPECT_EQ(listing->items.size(), 3u);
}

TEST_F(HttpArchiveSessionTest, ClientDisconnectStopsReadingMembers) {
    std::shared_ptr<FakeReader> reader;
    std::promise<std::pair<uint64_t, bool>> finished;
    Router::setRouteOverrideForTesting([&](request&& req) -> model::preview::Response {
        return zipResponse(req, {fileMember("huge.bin", 1ull << 34), fileMember("never.bin", 10)},
                           [&](const archive::Member& m) {
                               reader = std::make_shared<FakeReader>(m.size, 3);
                               return reader;
                           }, &finished);
    });
    auto h = std::make_unique<Harness>();
    h->start();
    h->send("GET /download HTTP/1.1\r\nHost: t\r\n\r\n");
    std::array<char, 1 << 20> buf{};
    boost::system::error_code ec;
    (void)asio::read(h->client, asio::buffer(buf), ec);
    h->client.close(ec);

    auto fut = finished.get_future();
    ASSERT_EQ(fut.wait_for(10s), std::future_status::ready);
    const auto [sent, complete] = fut.get();
    EXPECT_FALSE(complete);
    EXPECT_LT(sent, 1ull << 30);
    ASSERT_TRUE(reader);
    const auto readsAtFinish = reader->reads.load();
    std::this_thread::sleep_for(200ms);
    EXPECT_EQ(reader->reads.load(), readsAtFinish);
}

TEST_F(HttpArchiveSessionTest, StalledClientIsDroppedAfterTheWriteDeadline) {
    Session::setTimeoutsForTesting(5s, 300ms);
    std::promise<std::pair<uint64_t, bool>> finished;
    Router::setRouteOverrideForTesting([&](request&& req) -> model::preview::Response {
        return zipResponse(req, {fileMember("huge.bin", 1ull << 34)}, patternOpener(), &finished);
    });
    Harness h;
    h.start();
    h.send("GET /download HTTP/1.1\r\nHost: t\r\n\r\n");
    auto fut = finished.get_future();
    ASSERT_EQ(fut.wait_for(15s), std::future_status::ready);
    EXPECT_FALSE(fut.get().second);
}

}
