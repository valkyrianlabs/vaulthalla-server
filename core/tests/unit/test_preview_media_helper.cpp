// vaulthalla-preview-media: the pure browser direct-play classifier, and the built helper binary driven over the
// real derive-seam protocol (fd 3 range-pull socketpair served from memory, fd 1 artifact, fd 4 result line).
//
// Helper tests skip when the helper was not built (meson feature `preview_media` off / libav* dev packages absent)
// or when the `ffmpeg` CLI used to synthesize fixtures is missing. Override the helper path with
// VH_PREVIEW_MEDIA_HELPER.

#include "../../tools/preview-media/Browser.hpp"
#include "platform/Fd.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <array>
#include <cerrno>
#include <chrono>
#include <csignal>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <spawn.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>


namespace vh::test_preview_media {

namespace browser = vh::media::browser;
namespace stdfs = std::filesystem;

// ── pure classifier ──────────────────────────────────────────────────────────────────────────────────────

browser::Traits traits(std::string container, std::optional<std::string> video, std::optional<std::string> audio,
                       std::string pixFmt = "yuv420p", std::string tag = "") {
    browser::Traits t;
    t.container = std::move(container);
    t.video = std::move(video);
    t.audio = std::move(audio);
    t.videoPixFmt = std::move(pixFmt);
    t.videoCodecTag = std::move(tag);
    return t;
}

TEST(PreviewMediaBrowser, Mp4H264AacDirectPlaysEverywhere) {
    const auto j = browser::evaluate(traits("mp4", "h264", "aac", "yuv420p", "avc1"));
    EXPECT_EQ(j["action"], "none");
    EXPECT_EQ(j["direct_play"].size(), 3u);
    for (const char* b : {"chrome", "firefox", "safari"}) {
        EXPECT_EQ(j[b]["verdict"], "direct_play") << b;
        EXPECT_EQ(j[b]["confidence"], "high") << b;
    }
}

TEST(PreviewMediaBrowser, MatroskaNeedsRemuxWhenCodecsArePlayable) {
    const auto j = browser::evaluate(traits("matroska", "h264", "aac"));
    EXPECT_EQ(j["action"], "remux");
    EXPECT_TRUE(j["direct_play"].empty());
    for (const char* b : {"chrome", "firefox", "safari"}) EXPECT_EQ(j[b]["verdict"], "container_remux_needed") << b;
}

TEST(PreviewMediaBrowser, HevcIsSafariOnly) {
    const auto j = browser::evaluate(traits("mp4", "hevc", "aac", "yuv420p", "hvc1"));
    EXPECT_EQ(j["safari"]["verdict"], "direct_play");
    EXPECT_EQ(j["safari"]["confidence"], "high");
    EXPECT_EQ(j["chrome"]["verdict"], "video_transcode_needed");
    EXPECT_EQ(j["firefox"]["verdict"], "video_transcode_needed");
    EXPECT_EQ(j["action"], "transcode");

    const auto hev1 = browser::classify(browser::Browser::Safari, traits("mov", "hevc", "aac", "yuv420p", "hev1"));
    EXPECT_TRUE(hev1.directPlay);
    EXPECT_EQ(hev1.confidence, browser::Support::Medium);
}

TEST(PreviewMediaBrowser, WebmVp9OpusIsMediumOnSafari) {
    const auto j = browser::evaluate(traits("webm", "vp9", "opus"));
    EXPECT_EQ(j["chrome"]["confidence"], "high");
    EXPECT_EQ(j["firefox"]["confidence"], "high");
    EXPECT_EQ(j["safari"]["confidence"], "medium");
    EXPECT_EQ(j["action"], "none");
}

TEST(PreviewMediaBrowser, CodecMismatchedWithContainerNeedsRemux) {
    const auto v = browser::classify(browser::Browser::Chrome, traits("webm", "vp9", "aac"));
    EXPECT_EQ(v.verdict, "container_remux_needed");
    EXPECT_NE(std::ranges::find(v.reasons, "codec_not_allowed_in_container"), v.reasons.end());
}

TEST(PreviewMediaBrowser, HighBitDepthH264NeedsTranscodeOutsideSafari) {
    const auto t = traits("mp4", "h264", "aac", "yuv420p10le");
    EXPECT_EQ(browser::classify(browser::Browser::Chrome, t).verdict, "video_transcode_needed");
    const auto safari = browser::classify(browser::Browser::Safari, t);
    EXPECT_TRUE(safari.directPlay);
    EXPECT_EQ(safari.confidence, browser::Support::Low);
}

TEST(PreviewMediaBrowser, AudioAndVideoTranscodeVerdicts) {
    EXPECT_EQ(browser::classify(browser::Browser::Chrome, traits("mp4", "h264", "ac3")).verdict, "audio_transcode_needed");
    EXPECT_TRUE(browser::classify(browser::Browser::Safari, traits("mp4", "h264", "ac3")).directPlay);
    EXPECT_EQ(browser::classify(browser::Browser::Firefox, traits("avi", "mpeg4", "mp3")).verdict, "video_transcode_needed");
    EXPECT_EQ(browser::classify(browser::Browser::Firefox, traits("avi", "mpeg4", "wmav2")).verdict, "transcode_needed");
    const auto none = browser::evaluate(traits("mp4", std::nullopt, std::nullopt));
    EXPECT_EQ(none["action"], "unsupported");
    EXPECT_EQ(none["chrome"]["verdict"], "unsupported");
}

TEST(PreviewMediaBrowser, AudioOnlyContainers) {
    EXPECT_EQ(browser::evaluate(traits("mp3", std::nullopt, "mp3"))["action"], "none");
    EXPECT_EQ(browser::classify(browser::Browser::Safari, traits("ogg", std::nullopt, "vorbis")).confidence,
              browser::Support::Low);
    EXPECT_EQ(browser::classify(browser::Browser::Chrome, traits("wav", std::nullopt, "pcm_s16le")).verdict, "direct_play");
}

TEST(PreviewMediaBrowser, NormalizesContainers) {
    EXPECT_EQ(browser::normalizeContainer("mov,mp4,m4a,3gp,3g2,mj2", "qt  ", ""), "mov");
    EXPECT_EQ(browser::normalizeContainer("mov,mp4,m4a,3gp,3g2,mj2", "isom", ""), "mp4");
    EXPECT_EQ(browser::normalizeContainer("matroska,webm", "", "webm"), "webm");
    EXPECT_EQ(browser::normalizeContainer("matroska,webm", "", "matroska"), "matroska");
    EXPECT_EQ(browser::normalizeContainer("aac", "", ""), "adts");
    EXPECT_EQ(browser::normalizeContainer("ogg", "", ""), "ogg");
    EXPECT_EQ(browser::normalizeContainer("mpegts", "", ""), "mpegts");
}

TEST(PreviewMediaBrowser, ReadsMatroskaDocType) {
    const std::vector<uint8_t> head = {0x1A, 0x45, 0xDF, 0xA3, 0x9F, 0x42, 0x86, 0x81, 0x01, 0x42, 0xF7, 0x81,
                                       0x01, 0x42, 0x82, 0x84, 'w',  'e',  'b',  'm',  0x42, 0x87, 0x81, 0x04};
    EXPECT_EQ(browser::matroskaDocType(head), "webm");
    EXPECT_EQ(browser::matroskaDocType(std::vector<uint8_t>{0x00, 0x01}), "");
}

// ── helper process harness ───────────────────────────────────────────────────────────────────────────────

stdfs::path helperPath() {
    if (const char* env = std::getenv("VH_PREVIEW_MEDIA_HELPER"); env && *env) return env;
    std::error_code ec;
    const auto self = stdfs::read_symlink("/proc/self/exe", ec);
    if (ec) return {};
    return self.parent_path() / "tools" / "preview-media" / "vaulthalla-preview-media";
}

bool onPath(const std::string& program) {
    const char* path = std::getenv("PATH");
    if (!path) return false;
    std::string_view rest(path);
    while (!rest.empty()) {
        const auto colon = rest.find(':');
        const stdfs::path dir(std::string(rest.substr(0, colon)));
        if (!dir.empty() && ::access((dir / program).c_str(), X_OK) == 0) return true;
        if (colon == std::string_view::npos) break;
        rest.remove_prefix(colon + 1);
    }
    return false;
}

struct Run {
    int exitCode = -1;
    int signal = 0;
    std::vector<uint8_t> out;
    std::string err;
    nlohmann::json result;
    uint64_t bytesServed = 0;
    uint64_t requests = 0;
};

void readAll(const int fd, std::vector<uint8_t>& into) {
    std::array<uint8_t, 65536> buf{};
    for (;;) {
        const ssize_t n = ::read(fd, buf.data(), buf.size());
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        into.insert(into.end(), buf.data(), buf.data() + n);
    }
    ::close(fd);
}

bool recvExact(const int fd, uint8_t* p, std::size_t len) {
    while (len > 0) {
        const ssize_t n = ::recv(fd, p, len, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += n;
        len -= static_cast<std::size_t>(n);
    }
    return true;
}

bool sendAll(const int fd, const uint8_t* p, std::size_t len) {
    while (len > 0) {
        const ssize_t n = ::send(fd, p, len, MSG_NOSIGNAL);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        p += n;
        len -= static_cast<std::size_t>(n);
    }
    return true;
}

// The daemon side of the range-pull protocol, served from an in-memory buffer.
void serveRanges(const int fd, const std::vector<uint8_t>& input, Run& run) {
    std::array<uint8_t, 16> req{};
    while (recvExact(fd, req.data(), req.size())) {
        uint64_t offset = 0;
        uint32_t length = 0;
        for (int i = 0; i < 8; ++i) offset |= static_cast<uint64_t>(req[i]) << (8 * i);
        for (int i = 0; i < 4; ++i) length |= static_cast<uint32_t>(req[8 + i]) << (8 * i);
        const uint64_t avail = offset < input.size() ? input.size() - offset : 0;
        const auto n = static_cast<uint32_t>(std::min<uint64_t>(length, avail));
        const std::array<uint8_t, 4> hdr = {static_cast<uint8_t>(n), static_cast<uint8_t>(n >> 8),
                                            static_cast<uint8_t>(n >> 16), static_cast<uint8_t>(n >> 24)};
        if (!sendAll(fd, hdr.data(), hdr.size())) break;
        if (n > 0 && !sendAll(fd, input.data() + offset, n)) break;
        ++run.requests;
        run.bytesServed += n;
    }
    ::close(fd);
}

int highFd(const int fd) {
    const int dup = ::fcntl(fd, F_DUPFD_CLOEXEC, 64);
    ::close(fd);
    return dup;
}

Run runHelper(const std::vector<uint8_t>& input, const std::string& command, const std::vector<std::string>& options,
              const std::chrono::seconds timeout = std::chrono::seconds(180)) {
    Run run;
    int sv[2], outPipe[2], resPipe[2], errPipe[2];
    if (vh::platform::fd::socketpair(AF_UNIX, SOCK_STREAM, 0, sv) != 0 || !vh::platform::fd::pipe(outPipe) ||
        !vh::platform::fd::pipe(resPipe) || !vh::platform::fd::pipe(errPipe))
        throw std::runtime_error("pipe setup failed");
    const int childRange = highFd(sv[1]), childOut = highFd(outPipe[1]), childRes = highFd(resPipe[1]),
              childErr = highFd(errPipe[1]);

    posix_spawn_file_actions_t fa;
    posix_spawn_file_actions_init(&fa);
    posix_spawn_file_actions_addopen(&fa, 0, "/dev/null", O_RDONLY, 0);
    posix_spawn_file_actions_adddup2(&fa, childOut, 1);
    posix_spawn_file_actions_adddup2(&fa, childErr, 2);
    posix_spawn_file_actions_adddup2(&fa, childRange, 3);
    posix_spawn_file_actions_adddup2(&fa, childRes, 4);

    const std::string path = helperPath().string();
    std::vector<std::string> argvStore = {path, command, "--input-size", std::to_string(input.size())};
    argvStore.insert(argvStore.end(), options.begin(), options.end());
    std::vector<char*> argv;
    for (auto& a : argvStore) argv.push_back(a.data());
    argv.push_back(nullptr);
    std::string lang = "LANG=C.UTF-8";
    std::array<char*, 2> envp = {lang.data(), nullptr};

    pid_t pid = 0;
    const int rc = ::posix_spawn(&pid, path.c_str(), &fa, nullptr, argv.data(), envp.data());
    posix_spawn_file_actions_destroy(&fa);
    for (const int fd : {childRange, childOut, childRes, childErr}) ::close(fd);
    if (rc != 0) {
        for (const int fd : {sv[0], outPipe[0], resPipe[0], errPipe[0]}) ::close(fd);
        throw std::runtime_error(std::string("posix_spawn: ") + std::strerror(rc));
    }

    std::vector<uint8_t> resultBytes, errBytes;
    std::thread server(serveRanges, sv[0], std::cref(input), std::ref(run));
    std::thread outReader(readAll, outPipe[0], std::ref(run.out));
    std::thread resReader(readAll, resPipe[0], std::ref(resultBytes));
    std::thread errReader(readAll, errPipe[0], std::ref(errBytes));

    int status = 0;
    const auto until = std::chrono::steady_clock::now() + timeout;
    for (;;) {
        const pid_t w = ::waitpid(pid, &status, WNOHANG);
        if (w == pid) break;
        if (std::chrono::steady_clock::now() > until) {
            ::kill(pid, SIGKILL);
            ::waitpid(pid, &status, 0);
            break;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    server.join();
    outReader.join();
    resReader.join();
    errReader.join();

    if (WIFEXITED(status)) run.exitCode = WEXITSTATUS(status);
    if (WIFSIGNALED(status)) run.signal = WTERMSIG(status);
    run.err.assign(errBytes.begin(), errBytes.end());
    const std::string line(resultBytes.begin(), resultBytes.end());
    run.result = nlohmann::json::parse(line, nullptr, false);
    return run;
}

std::vector<uint8_t> readFile(const stdfs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
}

struct Box {
    std::string type;
    uint64_t size;
};

// Top-level ISO BMFF boxes; empty when the buffer does not tile exactly into boxes.
std::vector<Box> topLevelBoxes(const std::vector<uint8_t>& d) {
    std::vector<Box> boxes;
    uint64_t o = 0;
    while (o + 8 <= d.size()) {
        uint64_t size = (uint64_t{d[o]} << 24) | (uint64_t{d[o + 1]} << 16) | (uint64_t{d[o + 2]} << 8) | d[o + 3];
        const std::string type(reinterpret_cast<const char*>(&d[o + 4]), 4);
        if (size == 1 && o + 16 <= d.size()) {
            size = 0;
            for (int i = 0; i < 8; ++i) size = (size << 8) | d[o + 8 + i];
        } else if (size == 0) {
            size = d.size() - o;
        }
        if (size < 8 || o + size > d.size()) return {};
        boxes.push_back({type, size});
        o += size;
    }
    return o == d.size() ? boxes : std::vector<Box>{};
}

bool hasBox(const std::vector<Box>& boxes, const std::string& type) {
    return std::ranges::any_of(boxes, [&](const Box& b) { return b.type == type; });
}

// Returns {width, height} from the first SOFn marker of a JPEG, or {0,0}.
std::pair<int, int> jpegSize(const std::vector<uint8_t>& d) {
    if (d.size() < 4 || d[0] != 0xFF || d[1] != 0xD8) return {0, 0};
    std::size_t o = 2;
    while (o + 9 < d.size()) {
        if (d[o] != 0xFF) return {0, 0};
        const uint8_t marker = d[o + 1];
        const std::size_t len = (std::size_t{d[o + 2]} << 8) | d[o + 3];
        if (marker >= 0xC0 && marker <= 0xC3)
            return {(d[o + 7] << 8) | d[o + 8], (d[o + 5] << 8) | d[o + 6]};
        o += 2 + len;
    }
    return {0, 0};
}

std::map<std::string, std::vector<uint8_t>> unframe(const std::vector<uint8_t>& d, std::vector<std::string>& order,
                                                    bool& terminated) {
    std::map<std::string, std::vector<uint8_t>> files;
    terminated = false;
    std::size_t o = 0;
    auto le = [&](const std::size_t at, const int bytes) {
        uint64_t v = 0;
        for (int i = 0; i < bytes; ++i) v |= static_cast<uint64_t>(d[at + i]) << (8 * i);
        return v;
    };
    while (o + 4 <= d.size()) {
        const auto nameLen = le(o, 4);
        o += 4;
        if (nameLen == 0) {
            terminated = o == d.size();
            break;
        }
        if (o + nameLen + 8 > d.size()) break;
        std::string name(reinterpret_cast<const char*>(&d[o]), nameLen);
        o += nameLen;
        const auto dataLen = le(o, 8);
        o += 8;
        if (o + dataLen > d.size()) break;
        files[name].assign(d.begin() + static_cast<std::ptrdiff_t>(o), d.begin() + static_cast<std::ptrdiff_t>(o + dataLen));
        order.push_back(name);
        o += dataLen;
    }
    return files;
}

class PreviewMediaHelper : public ::testing::Test {
protected:
    static inline stdfs::path dir_;
    static inline std::map<std::string, std::vector<uint8_t>> media_;
    static inline bool ready_ = false;
    static inline std::string skipReason_;

    static void SetUpTestSuite() {
        if (!stdfs::exists(helperPath())) {
            skipReason_ = "vaulthalla-preview-media not built (" + helperPath().string() + ")";
            return;
        }
        if (!onPath("ffmpeg")) {
            skipReason_ = "ffmpeg CLI not available to synthesize fixtures";
            return;
        }
        std::string tmpl = (stdfs::temp_directory_path() / "vh-preview-media-XXXXXX").string();
        if (!::mkdtemp(tmpl.data())) {
            skipReason_ = "mkdtemp failed";
            return;
        }
        dir_ = tmpl;
        const std::string ff = "ffmpeg -nostdin -hide_banner -loglevel error -y ";
        const std::string d = dir_.string() + "/";
        const std::map<std::string, std::string> recipes = {
            {"moov_end.mp4", ff + "-f lavfi -i testsrc2=size=320x240:rate=25:duration=3 -f lavfi -i "
                             "sine=frequency=440:sample_rate=44100:duration=3 -c:v libx264 -preset ultrafast -crf 38 "
                             "-pix_fmt yuv420p -g 25 -c:a aac -b:a 48k -shortest " + d + "moov_end.mp4"},
            {"vp9.webm", ff + "-f lavfi -i testsrc2=size=256x144:rate=25:duration=2 -f lavfi -i sine=frequency=330:duration=2 "
                         "-c:v libvpx-vp9 -b:v 100k -deadline realtime -cpu-used 8 -c:a libopus -b:a 32k -shortest " +
                         d + "vp9.webm"},
            {"audio.mp3", ff + "-f lavfi -i sine=frequency=500:duration=3 -c:a libmp3lame -b:a 48k " + d + "audio.mp3"},
            {"audio.ogg", ff + "-f lavfi -i sine=frequency=500:duration=3 -c:a libvorbis " + d + "audio.ogg"},
            {"huge.mkv", ff + "-f lavfi -i color=size=17000x16:rate=1:duration=1 -frames:v 1 -c:v mjpeg " + d + "huge.mkv"},
        };
        for (const auto& [name, cmd] : recipes)
            if (std::system(cmd.c_str()) == 0) media_[name] = readFile(dir_ / name);
        if (!media_.contains("moov_end.mp4")) {
            skipReason_ = "ffmpeg could not synthesize the H.264/AAC fixture (libx264 missing?)";
            return;
        }
        const std::string src = d + "moov_end.mp4";
        if (std::system((ff + "-i " + src + " -c copy -movflags +faststart " + d + "faststart.mp4").c_str()) == 0)
            media_["faststart.mp4"] = readFile(dir_ / "faststart.mp4");
        if (std::system((ff + "-i " + src + " -c copy " + d + "clip.mkv").c_str()) == 0)
            media_["clip.mkv"] = readFile(dir_ / "clip.mkv");
        ready_ = true;
    }

    static void TearDownTestSuite() {
        if (!dir_.empty()) {
            std::error_code ec;
            stdfs::remove_all(dir_, ec);
        }
    }

    void SetUp() override {
        if (!ready_) GTEST_SKIP() << skipReason_;
    }

    static const std::vector<uint8_t>& media(const char* name) { return media_.at(name); }
    static bool has(const char* name) { return media_.contains(name); }
};

TEST_F(PreviewMediaHelper, ProbeReadsMoovAtEndInPlace) {
    const auto& input = media("moov_end.mp4");
    // Sanity: the fixture really has its moov after mdat.
    const auto boxes = topLevelBoxes(input);
    ASSERT_FALSE(boxes.empty());
    std::vector<std::string> types;
    for (const auto& b : boxes) types.push_back(b.type);
    ASSERT_LT(std::ranges::find(types, "mdat"), std::ranges::find(types, "moov"));

    const auto run = runHelper(input, "probe", {});
    ASSERT_EQ(run.exitCode, 0) << run.err << run.result.dump();
    const auto& r = run.result;
    EXPECT_EQ(r["ok"], true);
    EXPECT_EQ(r["container"], "mp4");
    EXPECT_NEAR(r["duration_seconds"].get<double>(), 3.0, 0.2);
    EXPECT_EQ(r["size"], input.size());
    ASSERT_TRUE(r["video_stream"].is_number());
    ASSERT_TRUE(r["audio_stream"].is_number());
    const auto& v = r["streams"][r["video_stream"].get<int>()];
    EXPECT_EQ(v["type"], "video");
    EXPECT_EQ(v["codec_name"], "h264");
    EXPECT_EQ(v["width"], 320);
    EXPECT_EQ(v["height"], 240);
    EXPECT_EQ(v["pix_fmt"], "yuv420p");
    EXPECT_NEAR(v["fps"].get<double>(), 25.0, 0.01);
    EXPECT_TRUE(v["profile"].is_string());
    const auto& a = r["streams"][r["audio_stream"].get<int>()];
    EXPECT_EQ(a["codec_name"], "aac");
    EXPECT_EQ(a["sample_rate"], 44100);
    EXPECT_EQ(a["channels"], 1);
    EXPECT_EQ(r["browser"]["action"], "none");
    EXPECT_EQ(r["browser"]["direct_play"].size(), 3u);
    EXPECT_GT(run.requests, 0u);

    // fd 1 carries the same document (minus the envelope fields).
    const auto stdoutDoc = nlohmann::json::parse(run.out.begin(), run.out.end(), nullptr, false);
    ASSERT_TRUE(stdoutDoc.is_object());
    EXPECT_EQ(stdoutDoc["streams"], r["streams"]);
    EXPECT_FALSE(stdoutDoc.contains("ok"));
}

TEST_F(PreviewMediaHelper, ProbeClassifiesContainers) {
    if (has("faststart.mp4")) {
        const auto run = runHelper(media("faststart.mp4"), "probe", {});
        ASSERT_EQ(run.exitCode, 0) << run.err;
        EXPECT_EQ(run.result["container"], "mp4");
    }
    if (has("clip.mkv")) {
        const auto run = runHelper(media("clip.mkv"), "probe", {});
        ASSERT_EQ(run.exitCode, 0) << run.err;
        EXPECT_EQ(run.result["container"], "matroska");
        EXPECT_EQ(run.result["browser"]["action"], "remux");
    }
    if (has("vp9.webm")) {
        const auto run = runHelper(media("vp9.webm"), "probe", {});
        ASSERT_EQ(run.exitCode, 0) << run.err;
        EXPECT_EQ(run.result["container"], "webm");
        EXPECT_EQ(run.result["browser"]["chrome"]["verdict"], "direct_play");
        EXPECT_EQ(run.result["browser"]["safari"]["confidence"], "medium");
    }
    if (has("audio.mp3")) {
        const auto run = runHelper(media("audio.mp3"), "probe", {});
        ASSERT_EQ(run.exitCode, 0) << run.err;
        EXPECT_EQ(run.result["container"], "mp3");
        EXPECT_TRUE(run.result["video_stream"].is_null());
        EXPECT_EQ(run.result["has_poster_source"], false);
    }
}

TEST_F(PreviewMediaHelper, PosterIsJpegOfRequestedMaxWidth) {
    const auto run = runHelper(media("moov_end.mp4"), "poster", {"--max-width", "160", "--at", "auto"});
    ASSERT_EQ(run.exitCode, 0) << run.err << run.result.dump();
    ASSERT_GE(run.out.size(), 4u);
    EXPECT_EQ(run.out[run.out.size() - 2], 0xFF);
    EXPECT_EQ(run.out[run.out.size() - 1], 0xD9);
    const auto [w, h] = jpegSize(run.out);
    EXPECT_EQ(w, 160);
    EXPECT_EQ(h, 120);
    EXPECT_EQ(run.result["width"], 160);
    EXPECT_EQ(run.result["height"], 120);
    EXPECT_EQ(run.result["format"], "jpeg");
    EXPECT_EQ(run.result["source"], "video");
    EXPECT_NEAR(run.result["at_seconds"].get<double>(), 0.3, 0.05);  // 10% of 3 s

    // Never upscales.
    const auto big = runHelper(media("moov_end.mp4"), "poster", {"--max-width", "1280", "--at", "1.5"});
    ASSERT_EQ(big.exitCode, 0) << big.err;
    EXPECT_EQ(jpegSize(big.out).first, 320);
}

TEST_F(PreviewMediaHelper, PosterOfAudioOnlyIsUnsupported) {
    if (!has("audio.mp3")) GTEST_SKIP() << "no mp3 fixture";
    const auto run = runHelper(media("audio.mp3"), "poster", {});
    EXPECT_EQ(run.exitCode, 4);
    EXPECT_EQ(run.result["error"], "unsupported");
    EXPECT_TRUE(run.out.empty());
}

TEST_F(PreviewMediaHelper, TranscodesMoovAtEndToFragmentedMp4) {
    const auto run = runHelper(media("moov_end.mp4"), "transcode",
                               {"--profile", "h264-480", "--hwaccel", "software", "--max-output-bytes", "50000000"});
    ASSERT_EQ(run.exitCode, 0) << run.err << run.result.dump();
    const auto boxes = topLevelBoxes(run.out);
    ASSERT_FALSE(boxes.empty()) << "output does not tile into ISO BMFF boxes";
    EXPECT_EQ(boxes.front().type, "ftyp");
    EXPECT_TRUE(hasBox(boxes, "moov"));
    EXPECT_TRUE(hasBox(boxes, "moof"));
    EXPECT_TRUE(hasBox(boxes, "mdat"));
    EXPECT_EQ(run.result["encoder"], "software");
    EXPECT_EQ(run.result["video_encoder"], "libx264");
    EXPECT_EQ(run.result["fragmented"], true);
    EXPECT_EQ(run.result["video"]["width"], 320);  // never upscales into the 480p box
    EXPECT_EQ(run.result["video"]["frames"], 75);
    EXPECT_EQ(run.result["audio"]["codec"], "aac");
    EXPECT_EQ(run.result["audio"]["channels"], 2);
    EXPECT_EQ(run.result["output_bytes"], run.out.size());
}

TEST_F(PreviewMediaHelper, TranscodesAudioOnlyToAacMp4) {
    for (const char* name : {"audio.mp3", "audio.ogg"}) {
        if (!has(name)) continue;
        const auto run = runHelper(media(name), "transcode", {"--hwaccel", "software"});
        ASSERT_EQ(run.exitCode, 0) << name << run.err;
        const auto boxes = topLevelBoxes(run.out);
        ASSERT_FALSE(boxes.empty()) << name;
        EXPECT_TRUE(hasBox(boxes, "moof")) << name;
        EXPECT_TRUE(run.result["video"].is_null()) << name;
        EXPECT_EQ(run.result["audio"]["codec"], "aac") << name;
    }
}

TEST_F(PreviewMediaHelper, HlsEmitsFramedSegmentsWithPlaylistLast) {
    const auto run = runHelper(media("moov_end.mp4"), "hls",
                               {"--profile", "h264-480", "--hwaccel", "software", "--segment-seconds", "1"});
    ASSERT_EQ(run.exitCode, 0) << run.err << run.result.dump();
    std::vector<std::string> order;
    bool terminated = false;
    const auto files = unframe(run.out, order, terminated);
    EXPECT_TRUE(terminated);
    ASSERT_FALSE(order.empty());
    EXPECT_EQ(order.back(), "index.m3u8");
    ASSERT_TRUE(files.contains("init.mp4"));
    ASSERT_TRUE(files.contains("seg-00000.m4s"));
    EXPECT_GE(run.result["segments"].size(), 3u);
    const std::string playlist(files.at("index.m3u8").begin(), files.at("index.m3u8").end());
    EXPECT_NE(playlist.find("#EXT-X-PLAYLIST-TYPE:VOD"), std::string::npos);
    EXPECT_NE(playlist.find("#EXT-X-MAP:URI=\"init.mp4\""), std::string::npos);
    EXPECT_NE(playlist.find("#EXT-X-ENDLIST"), std::string::npos);
    for (const auto& seg : run.result["segments"]) {
        const auto name = seg["name"].get<std::string>();
        EXPECT_NE(playlist.find(name), std::string::npos) << name;
        ASSERT_TRUE(files.contains(name));
        EXPECT_TRUE(hasBox(topLevelBoxes(files.at(name)), "moof")) << name;
    }
    EXPECT_TRUE(hasBox(topLevelBoxes(files.at("init.mp4")), "moov"));
}

TEST_F(PreviewMediaHelper, CorruptTruncatedAndEmptyInputsAreInvalid) {
    std::vector<uint8_t> garbage(256 * 1024);
    std::mt19937 rng(1234);
    for (auto& b : garbage) b = static_cast<uint8_t>(rng());
    const auto& full = media("moov_end.mp4");
    const std::vector<uint8_t> truncated(full.begin(), full.begin() + static_cast<std::ptrdiff_t>(full.size() / 2));
    const std::vector<uint8_t> empty;

    for (const std::vector<uint8_t>* input : std::array<const std::vector<uint8_t>*, 3>{&garbage, &truncated, &empty}) {
        for (const char* command : {"probe", "poster", "transcode"}) {
            const auto run = runHelper(*input, command, {"--hwaccel", "software"});
            EXPECT_EQ(run.signal, 0) << command << " crashed";
            EXPECT_EQ(run.exitCode, 2) << command << " size=" << input->size() << " " << run.result.dump();
            EXPECT_EQ(run.result["ok"], false);
            EXPECT_EQ(run.result["error"], "invalid_input");
        }
    }
}

TEST_F(PreviewMediaHelper, OutputCapIsLimitExceeded) {
    const auto run = runHelper(media("moov_end.mp4"), "transcode",
                               {"--hwaccel", "software", "--max-output-bytes", "20000"});
    EXPECT_EQ(run.exitCode, 3) << run.result.dump();
    EXPECT_EQ(run.result["error"], "limit_exceeded");
    EXPECT_LE(run.out.size(), 20000u);
}

TEST_F(PreviewMediaHelper, AbsurdDimensionsAreRefused) {
    if (!has("huge.mkv")) GTEST_SKIP() << "ffmpeg could not synthesize the oversized fixture";
    const auto run = runHelper(media("huge.mkv"), "probe", {});
    EXPECT_EQ(run.exitCode, 3) << run.result.dump();
    EXPECT_EQ(run.result["error"], "limit_exceeded");
}

// This VM has no render node: an explicit VAAPI request must fall back to software (or, on a host with a working
// VAAPI stack, actually use it). Hardware encoding itself is not validated here.
TEST_F(PreviewMediaHelper, VaapiRequestFallsBackToSoftware) {
    const auto run = runHelper(media("moov_end.mp4"), "transcode", {"--profile", "h264-480", "--hwaccel", "vaapi"});
    if (run.exitCode == 4) {
        EXPECT_EQ(run.result["error"], "unsupported");
        return;
    }
    ASSERT_EQ(run.exitCode, 0) << run.err << run.result.dump();
    const auto encoder = run.result["encoder"].get<std::string>();
    ASSERT_TRUE(encoder == "software" || encoder == "vaapi") << encoder;
    if (encoder == "software") {
        ASSERT_FALSE(run.result["hwaccel_fallbacks"].empty());
        EXPECT_EQ(run.result["hwaccel_fallbacks"][0]["accel"], "vaapi");
        EXPECT_TRUE(run.result["hwaccel_fallbacks"][0]["reason"].is_string());
    }
    EXPECT_TRUE(hasBox(topLevelBoxes(run.out), "moof"));
}

TEST_F(PreviewMediaHelper, CapabilitiesReportsEncodersAndHardware) {
    const auto run = runHelper({}, "capabilities", {});
    ASSERT_EQ(run.exitCode, 0) << run.err;
    EXPECT_EQ(run.requests, 0u);
    EXPECT_TRUE(run.result["encoders"].contains("libx264"));
    EXPECT_TRUE(run.result["encoders"].contains("mjpeg"));
    for (const char* hw : {"vaapi", "qsv", "nvenc"}) {
        ASSERT_TRUE(run.result["hardware"].contains(hw)) << hw;
        EXPECT_TRUE(run.result["hardware"][hw]["device_available"].is_boolean()) << hw;
    }
    EXPECT_EQ(run.result["hardware_validated"], false);
}

// Hardware devices are opened inside the sandbox (driver threads must not escape Landlock): capabilities, which
// probes every accelerator, runs confined with the GPU allowance (render nodes opened read-write via Landlock).
TEST_F(PreviewMediaHelper, CapabilitiesProbesHardwareInsideTheSandbox) {
    const auto run = runHelper({}, "capabilities", {});
    ASSERT_EQ(run.exitCode, 0) << run.err;
    const auto& sandbox = run.result["sandbox"];
    EXPECT_TRUE(sandbox["landlock"].get<bool>()) << sandbox.dump();
    EXPECT_TRUE(sandbox["seccomp"].get<bool>()) << sandbox.dump();
    EXPECT_FALSE(sandbox["open_write_denied"].get<bool>()) << sandbox.dump();   // GPU allowance, left to Landlock
    EXPECT_FALSE(sandbox["threads_denied"].get<bool>()) << sandbox.dump();

    // Software transcodes get no device allowance at all.
    const auto sw = runHelper(media("moov_end.mp4"), "transcode", {"--profile", "h264-480", "--hwaccel", "software"});
    ASSERT_EQ(sw.exitCode, 0) << sw.err << sw.result.dump();
    EXPECT_TRUE(sw.result["sandbox"]["open_write_denied"].get<bool>()) << sw.result["sandbox"].dump();
}

TEST_F(PreviewMediaHelper, RefusesToRunWithoutLandlock) {
    const auto run = runHelper(media("moov_end.mp4"), "probe", {"--sandbox-test-no-landlock", "1"});
    EXPECT_EQ(run.exitCode, 5) << run.err;
    EXPECT_EQ(run.result["error"], "sandbox_unavailable");
    EXPECT_FALSE(run.result["sandbox"]["landlock"].get<bool>());
    EXPECT_EQ(run.requests, 0u);
    EXPECT_TRUE(run.out.empty());
}

TEST_F(PreviewMediaHelper, UnknownCommandIsUnsupported) {
    const auto run = runHelper(media("moov_end.mp4"), "frobnicate", {});
    EXPECT_EQ(run.exitCode, 4);
    EXPECT_EQ(run.result["error"], "unsupported");
}

}
