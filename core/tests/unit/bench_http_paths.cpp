// Disabled-by-default benchmarks for the HTTP byte, folder-ZIP and preview paths. Run with a release build and the test DB env:
//   ./vh_unit_tests --gtest_also_run_disabled_tests --gtest_filter='DISABLED_HttpBench*'
// The same file compiles against the pre-rich-preview tree with -DVH_BENCH_LEGACY (whole-buffer responses, the old
// thumbnail functions), so the numbers in the PR come from identical scenarios.
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Vaults.hpp"
#include "preview/render/Raster.hpp"
#include "protocols/http/Router.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#ifndef VH_BENCH_LEGACY
#include "preview/render/Service.hpp"
#include "protocols/http/Access.hpp"
#include "storage/PlaintextReader.hpp"
#else
#include "preview/thumbnail/ops.hpp"
#endif

#include <gtest/gtest.h>
#include <paths.h>
#include <turbojpeg.h>

#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <optional>
#include <thread>

namespace vh::protocols::http::bench {

using Clock = std::chrono::steady_clock;
using Response = model::preview::Response;

namespace {

double ms(const Clock::time_point a, const Clock::time_point b = Clock::now()) {
    return std::chrono::duration<double, std::milli>(b - a).count();
}

void resetPeakRss() {
    std::ofstream("/proc/self/clear_refs") << "5";
}

long peakRssMiB() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line))
        if (line.starts_with("VmHWM:")) return std::stol(line.substr(6)) / 1024;
    return -1;
}

long currentRssMiB() {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line))
        if (line.starts_with("VmRSS:")) return std::stol(line.substr(6)) / 1024;
    return -1;
}

std::vector<uint8_t> photo(const int w, const int h) {
    std::vector<uint8_t> rgb(static_cast<std::size_t>(w) * h * 3);
    unsigned s = 1;
    for (int y = 0; y < h; ++y)
        for (int x = 0; x < w; ++x) {
            s = s * 1103515245u + 12345u;
            const int n = (s >> 16) & 15;
            auto* p = &rgb[(static_cast<std::size_t>(y) * w + x) * 3];
            p[0] = static_cast<uint8_t>(128 + 100 * std::sin(x / 97.0) + n);
            p[1] = static_cast<uint8_t>(128 + 100 * std::cos(y / 71.0) + n);
            p[2] = static_cast<uint8_t>((x + y) / 30 + n);
        }
    tjhandle tj = tjInitCompress();
    unsigned char* buf = nullptr;
    unsigned long size = 0;
    tjCompress2(tj, rgb.data(), w, 0, h, TJPF_RGB, &buf, &size, TJSAMP_420, 90, 0);
    std::vector<uint8_t> out(buf, buf + size);
    tjFree(buf);
    tjDestroy(tj);
    return out;
}

struct Drained {
    double firstByteMs{};
    double totalMs{};
    uint64_t bytes{};
};

// Drains a response the way the session would: the first chunk marks time-to-first-byte.
Drained drain(Response&& response, const Clock::time_point started) {
    Drained d;
    if (const auto* v = std::get_if<vector_response>(&response)) {
        d.firstByteMs = ms(started);
        d.bytes = v->body().size();
        d.totalMs = ms(started);
        return d;
    }
#ifndef VH_BENCH_LEGACY
    if (auto* s = std::get_if<model::preview::StreamResponse>(&response); s && s->reader) {
        std::vector<uint8_t> chunk(256 * 1024);
        uint64_t sent = 0;
        while (sent < s->length) {
            const auto n = s->reader->read(s->offset + sent, std::span<uint8_t>(chunk.data(), std::min<uint64_t>(chunk.size(), s->length - sent)));
            if (n == 0) break;
            if (sent == 0) d.firstByteMs = ms(started);
            sent += n;
        }
        d.bytes = sent;
        d.totalMs = ms(started);
        return d;
    }
#endif
    d.firstByteMs = d.totalMs = ms(started);
    return d;
}

request get(const std::string& target, const verb method = verb::get) {
    request req{method, target, 11};
    req.keep_alive(true);
    return req;
}

}

class DISABLED_HttpBench : public ::testing::Test {
protected:
    inline static bool skip = false;
    inline static std::filesystem::path root;
    inline static std::optional<vh::preview::render::PdfiumLibrary> pdfium;

    static void TearDownTestSuite() {
        std::error_code ec;
        if (!root.empty()) std::filesystem::remove_all(root, ec);  // test vault backing (encrypted files up to 300 MiB)
        pdfium.reset();
    }
    inline static std::shared_ptr<identities::User> admin;
    inline static std::shared_ptr<storage::Engine> engine;

    static void SetUpTestSuite() {
        if (!std::getenv("VH_TEST_DB_NAME")) {
            skip = true;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_bench_" + std::to_string(::getpid()));
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);
        pdfium.emplace();
        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        admin = vh::identities::manager().userByName("admin");
        const auto vault = ops::vaults::create(admin, {.name = "bench_" + std::to_string(::getpid()), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);

        auto session = std::make_shared<ws::Session>(std::make_shared<ws::Router>());
        session->user = admin;
        Router::setPreviewSessionResolverForTesting([session](const request&) { return session; });

        // 256 MiB: the old download cap, so both trees can serve it.
        const auto source = root / "big.src";
        {
            std::ofstream out(source, std::ios::binary);
            std::vector<char> mib(1 << 20);
            for (int i = 0; i < 256; ++i) {
                std::fill(mib.begin(), mib.end(), static_cast<char>(i));
                out.write(mib.data(), static_cast<std::streamsize>(mib.size()));
            }
        }
        (void)fs::Filesystem::createFile({.path = "/big.bin", .fuse_path = engine->vaultPathToFusePath("/big.bin"),
                                          .source_path = source, .engine = engine, .user = admin, .overwrite = true});
        std::filesystem::remove(source);
        // A folder under the old archive caps (4 × 48 MiB), so both trees can zip it.
        (void)fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath("/folder"), .engine = engine, .user = admin});
        for (int f = 0; f < 4; ++f) {
            {
                std::ofstream out(source, std::ios::binary);
                std::vector<char> mib(1 << 20);
                for (int i = 0; i < 48; ++i) {
                    std::fill(mib.begin(), mib.end(), static_cast<char>(i + f));
                    out.write(mib.data(), static_cast<std::streamsize>(mib.size()));
                }
            }
            const auto path = "/folder/part" + std::to_string(f) + ".bin";
            (void)fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                              .source_path = source, .engine = engine, .user = admin, .overwrite = true});
            std::filesystem::remove(source);
        }
        (void)fs::Filesystem::createFile({.path = "/photo.jpg", .fuse_path = engine->vaultPathToFusePath("/photo.jpg"),
                                          .buffer = photo(4000, 3000), .engine = engine, .user = admin, .overwrite = true});
        std::this_thread::sleep_for(std::chrono::seconds(3));  // let upload-time thumbnail generation finish
    }

    void SetUp() override {
        if (skip) GTEST_SKIP();
    }

    [[nodiscard]] static std::string url(const std::string& route, const std::string& path, const std::string& extra = {}) {
        return route + "?vault_id=" + std::to_string(engine->vault->id) + "&path=" + path + extra;
    }
};

TEST_F(DISABLED_HttpBench, Download256MiB) {
    for (int run = 0; run < 3; ++run) {
        resetPeakRss();
        const auto base = currentRssMiB();
        const auto t0 = Clock::now();
        const auto d = drain(Router::route(get(url("/download", "%2Fbig.bin"))), t0);
        std::printf("[bench] download 256MiB: first byte %.1f ms, total %.1f ms (%.0f MB/s), peak RSS +%ld MiB\n",
                    d.firstByteMs, d.totalMs, d.bytes / 1e6 / (d.totalMs / 1000.0), peakRssMiB() - base);
    }
}

TEST_F(DISABLED_HttpBench, FourConcurrentDownloadsPeakRss) {
    resetPeakRss();
    const auto base = currentRssMiB();
    const auto t0 = Clock::now();
    std::vector<std::thread> threads;
    for (int i = 0; i < 4; ++i)
        threads.emplace_back([&] { (void)drain(Router::route(get(url("/download", "%2Fbig.bin"))), Clock::now()); });
    for (auto& t : threads) t.join();
    std::printf("[bench] 4 concurrent 256MiB downloads: %.1f ms, peak RSS +%ld MiB\n", ms(t0), peakRssMiB() - base);
}

// Folder ZIP of 192 MiB: streamed (exact Content-Length, one member open at a time) vs the old in-memory build.
TEST_F(DISABLED_HttpBench, FolderZip192MiB) {
    for (int run = 0; run < 3; ++run) {
        resetPeakRss();
        const auto base = currentRssMiB();
        const auto h0 = Clock::now();
        (void)Router::route(get(url("/download", "%2Ffolder"), verb::head));
        const auto headMs = ms(h0);
        const auto t0 = Clock::now();
        const auto d = drain(Router::route(get(url("/download", "%2Ffolder"))), t0);
        std::printf("[bench] folder zip 192MiB: HEAD %.2f ms, first byte %.1f ms, total %.1f ms (%.0f MB/s), peak RSS +%ld MiB\n",
                    headMs, d.firstByteMs, d.totalMs, d.bytes / 1e6 / (d.totalMs / 1000.0), peakRssMiB() - base);
    }
}

TEST_F(DISABLED_HttpBench, RangeRead1MiBAt200MiB) {
    for (int run = 0; run < 5; ++run) {
        auto req = get(url("/download/content", "%2Fbig.bin"));
        req.set(field::range, "bytes=209715200-210763775");
        const auto t0 = Clock::now();
        const auto d = drain(Router::route(std::move(req)), t0);
        std::printf("[bench] range 1MiB @200MiB: first byte %.2f ms, total %.2f ms, %llu bytes\n", d.firstByteMs, d.totalMs,
                    static_cast<unsigned long long>(d.bytes));
    }
}

TEST_F(DISABLED_HttpBench, HeadVersusGetPreflight) {
    const auto t0 = Clock::now();
    auto head = Router::route(get(url("/download", "%2Fbig.bin"), verb::head));
    std::printf("[bench] HEAD /download 256MiB: %.2f ms (status %d)\n", ms(t0),
                static_cast<int>(std::visit([](const auto& r) { return r.result_int(); }, head)));
    const auto t1 = Clock::now();
    const auto d = drain(Router::route(get(url("/download", "%2Fbig.bin"))), t1);
    std::printf("[bench] GET preflight (old console behaviour, full body produced): %.1f ms for %llu bytes\n", d.totalMs,
                static_cast<unsigned long long>(d.bytes));
}

TEST_F(DISABLED_HttpBench, PreviewColdAndWarm1024) {
    for (int run = 0; run < 4; ++run) {
        const auto t0 = Clock::now();
        const auto d = drain(Router::route(get(url("/preview", "%2Fphoto.jpg", "&size=1024"))), t0);
        std::printf("[bench] preview 12MP @1024 run %d: %.1f ms (%llu bytes)\n", run, d.totalMs,
                    static_cast<unsigned long long>(d.bytes));
    }
}

TEST_F(DISABLED_HttpBench, ThumbnailGenerationAllSizes) {
    const auto file = std::dynamic_pointer_cast<fs::model::File>(
        runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath("/photo.jpg")));
    for (int run = 0; run < 3; ++run) {
        const auto t0 = Clock::now();
#ifndef VH_BENCH_LEGACY
        // A fresh source generation each run, so nothing is served from cache.
        const auto reader = engine->openPlaintextReader(file);
        const auto plaintext = storage::readAll(*reader, 1ull << 30);
        auto fresh = std::make_shared<fs::model::File>(*file);
        fresh->encryption_iv = "bench-run-" + std::to_string(run) + std::to_string(Clock::now().time_since_epoch().count());
        preview::render::generateThumbnails(engine, fresh, plaintext);
#else
        const auto plaintext = engine->decrypt(file);
        for (const auto size : {128u, 256u, 512u})
            preview::thumbnail::generateAndStore(plaintext, std::filesystem::temp_directory_path() / ("bench_" + std::to_string(size) + ".jpg"),
                                                 "image/jpeg", size);
#endif
        std::printf("[bench] thumbnails 128/256/512 of a 12MP JPEG: %.1f ms\n", ms(t0));
    }
}

}
