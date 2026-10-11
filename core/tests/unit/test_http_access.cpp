// DB-backed HTTP lane tests over real vaults, users, RBAC and encrypted files: the human preview authorization
// matrix (audit D1), original-bytes vs preview semantics (D9), Range/HEAD/conditional serving, large files,
// text editing with optimistic concurrency, PDF paging, hostile parameters and plaintext temp-file hygiene.
#include "db/Transactions.hpp"
#include "db/query/identities/User.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fs/model/Path.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "preview/render/Raster.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/Router.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "vault/model/Vault.hpp"

#include "../helpers/zip_check.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <turbojpeg.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <random>
#include <thread>

namespace vh::protocols::http::test_access {

using Response = model::preview::Response;
using StreamResponse = model::preview::StreamResponse;
using UserPtr = std::shared_ptr<identities::User>;

namespace {

std::string tag() {
    return std::to_string(::getpid()) + "_" +
           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 1'000'000'000);
}

std::vector<uint8_t> jpegOf(const int w, const int h) {
    std::vector<uint8_t> rgb(static_cast<std::size_t>(w) * h * 3);
    for (int y = 0; y < h; ++y)
        for (int x = 0; x < w; ++x) {
            auto* p = &rgb[(static_cast<std::size_t>(y) * w + x) * 3];
            p[0] = static_cast<uint8_t>(x);
            p[1] = static_cast<uint8_t>(y);
            p[2] = 128;
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

// A minimal valid two-page PDF (xref offsets computed).
std::vector<uint8_t> twoPagePdf() {
    std::vector<std::string> objects = {
        "<< /Type /Catalog /Pages 2 0 R >>",
        "<< /Type /Pages /Kids [3 0 R 4 0 R] /Count 2 >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] >>",
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 200] >>",
    };
    std::string pdf = "%PDF-1.4\n";
    std::vector<std::size_t> offsets;
    for (std::size_t i = 0; i < objects.size(); ++i) {
        offsets.push_back(pdf.size());
        pdf += std::to_string(i + 1) + " 0 obj\n" + objects[i] + "\nendobj\n";
    }
    const auto xref = pdf.size();
    pdf += "xref\n0 " + std::to_string(objects.size() + 1) + "\n0000000000 65535 f \n";
    for (const auto off : offsets) {
        char line[32];
        std::snprintf(line, sizeof(line), "%010zu 00000 n \n", off);
        pdf += line;
    }
    pdf += "trailer\n<< /Size " + std::to_string(objects.size() + 1) + " /Root 1 0 R >>\nstartxref\n" +
           std::to_string(xref) + "\n%%EOF\n";
    return {pdf.begin(), pdf.end()};
}

request get(const std::string& target, const verb method = verb::get) {
    request req{method, target, 11};
    req.keep_alive(true);
    return req;
}

status statusOf(const Response& r) {
    return std::visit([](const auto& res) { return res.result(); }, r);
}

std::string header(const Response& r, const std::string& name) {
    return std::visit([&](const auto& res) -> std::string {
        const auto it = res.find(name);
        return it == res.end() ? std::string{} : std::string(it->value());
    }, r);
}

std::vector<uint8_t> bodyOf(const Response& r) {
    if (const auto* v = std::get_if<vector_response>(&r)) return v->body();
    if (const auto* s = std::get_if<string_response>(&r)) return {s->body().begin(), s->body().end()};
    if (const auto* st = std::get_if<StreamResponse>(&r)) {
        if (!st->reader || st->headOnly) return {};
        std::vector<uint8_t> out(static_cast<std::size_t>(st->length));
        std::size_t done = 0;
        while (done < out.size()) {
            const auto n = st->reader->read(st->offset + done, std::span<uint8_t>(out.data() + done, out.size() - done));
            if (n == 0) break;
            done += n;
        }
        out.resize(done);
        return out;
    }
    return {};
}

bool isJpeg(const std::vector<uint8_t>& b) { return b.size() > 3 && b[0] == 0xFF && b[1] == 0xD8 && b[2] == 0xFF; }

std::size_t plaintextTempFiles() {
    std::size_t n = 0;
    std::error_code ec;
    for (const auto& e : std::filesystem::directory_iterator(std::filesystem::temp_directory_path(), ec))
        if (e.path().filename().string().starts_with("vaulthalla_dec_")) ++n;
    return n;
}

}

class HttpAccessDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::filesystem::path root;
    inline static std::optional<vh::preview::render::PdfiumLibrary> pdfium;

    static void TearDownTestSuite() {
        std::error_code ec;
        if (!root.empty()) std::filesystem::remove_all(root, ec);  // test vault backing (encrypted files up to 300 MiB)
        pdfium.reset();
    }
    inline static UserPtr admin, reader, plain;
    inline static std::shared_ptr<storage::Engine> vaultA, vaultB;
    inline static std::vector<uint8_t> big;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_http_access_" + tag());
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

        const auto a = ops::vaults::create(admin, {.name = "ha_" + tag(), .type = vault::model::VaultType::Local});
        const auto b = ops::vaults::create(admin, {.name = "hb_" + tag(), .type = vault::model::VaultType::Local});
        vaultA = runtime::Deps::get().storageManager->getEngine(a->id);
        vaultB = runtime::Deps::get().storageManager->getEngine(b->id);

        const auto makeUser = [](const std::string& prefix) {
            const auto created = ops::users::create(admin, {.name = prefix + "_" + tag(), .role = "unprivileged",
                                                            .password = std::string("Http-Access-Pass-123")});
            return vh::identities::manager().user(created.user->id);
        };
        reader = makeUser("reader");
        plain = makeUser("plain");
        (void)ops::roles::assignVaultRole(admin, {.target = {.vault_id = a->id, .subject = {.type = "user", .id = reader->id}},
                                                  .role = std::string("reader")});
        reader = vh::identities::manager().user(reader->id);

        write(vaultA, "/pic.jpg", jpegOf(1600, 1200));
        write(vaultA, "/doc.pdf", twoPagePdf());
        const std::string svg = R"(<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>)";
        write(vaultA, "/vec.svg", {svg.begin(), svg.end()});
        const std::string text = "hello vault\n";
        write(vaultA, "/note.txt", {text.begin(), text.end()});
        write(vaultB, "/other.jpg", jpegOf(64, 64));

        big.resize(3 * 1024 * 1024 + 123);
        std::mt19937 rng(9);
        for (auto& v : big) v = static_cast<uint8_t>(rng());
        write(vaultA, "/blob.bin", big);
    }

    static std::shared_ptr<fs::model::File> write(const std::shared_ptr<storage::Engine>& engine, const std::string& path,
                                                  const std::vector<uint8_t>& bytes) {
        return fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                           .buffer = bytes, .engine = engine, .user = admin, .overwrite = true});
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        access::clearCachesForTesting();
    }

    void TearDown() override {
        if (!skipTests) Router::resetPreviewSessionResolverForTesting();
    }

    static void as(const UserPtr& user) {
        auto session = std::make_shared<ws::Session>(std::make_shared<ws::Router>());
        session->user = user;
        Router::setPreviewSessionResolverForTesting([session](const request&) { return session; });
    }

    [[nodiscard]] static std::string inA(const std::string& route, const std::string& path, const std::string& extra = {}) {
        return route + "?vault_id=" + std::to_string(vaultA->vault->id) + "&path=" + path + extra;
    }
};

TEST_F(HttpAccessDbTest, HumanPreviewEnforcesFilesystemRbacBeforeAnyWork) {
    const auto target = inA("/preview", "%2Fpic.jpg", "&size=256");

    as(admin);
    auto ok = Router::route(get(target));
    ASSERT_EQ(statusOf(ok), status::ok);
    EXPECT_TRUE(isJpeg(bodyOf(ok)));

    as(reader);
    EXPECT_EQ(statusOf(Router::route(get(target))), status::ok);
    EXPECT_EQ(statusOf(Router::route(get(target, verb::head))), status::ok);

    // Unprivileged user: denied, also for the now-cached size and for HEAD (D1).
    as(plain);
    EXPECT_EQ(statusOf(Router::route(get(target))), status::forbidden);
    EXPECT_EQ(statusOf(Router::route(get(target, verb::head))), status::forbidden);
    EXPECT_EQ(statusOf(Router::route(get(inA("/preview", "%2Fpic.jpg", "&size=128")))), status::forbidden);

    // Guessing another vault id: the reader holds no role there.
    as(reader);
    const auto other = "/preview?vault_id=" + std::to_string(vaultB->vault->id) + "&path=%2Fother.jpg&size=128";
    EXPECT_EQ(statusOf(Router::route(get(other))), status::forbidden);
    // No existence oracle: a missing path in a vault the caller can't read is also 403, not 404.
    const auto missingOther = "/preview?vault_id=" + std::to_string(vaultB->vault->id) + "&path=%2Fnope.jpg";
    EXPECT_EQ(statusOf(Router::route(get(missingOther))), status::forbidden);
    EXPECT_EQ(statusOf(Router::route(get("/preview?vault_id=999999&path=%2Fpic.jpg"))), status::not_found);
    EXPECT_EQ(statusOf(Router::route(get(inA("/preview", "%2Fmissing.jpg")))), status::not_found);
    EXPECT_EQ(statusOf(Router::route(get(inA("/preview", "%2F..%2F..%2Fetc%2Fpasswd")))), status::bad_request);

    // Batch applies the same rule per item.
    as(plain);
    request batch{verb::post, "/preview/batch", 11};
    batch.body() = nlohmann::json{{"vault_id", vaultA->vault->id}, {"size", 128},
                                  {"items", {{{"path", "/pic.jpg"}, {"key", "a"}}}}}.dump();
    batch.prepare_payload();
    const auto items = nlohmann::json::parse(bodyOf(Router::route(std::move(batch)))).at("items");
    EXPECT_EQ(items.at(0).at("status"), "unsupported");
    EXPECT_FALSE(items.at(0).contains("url"));
}

TEST_F(HttpAccessDbTest, PreviewNeverServesOriginalBytesAndContentNeedsRead) {
    as(reader);
    EXPECT_EQ(statusOf(Router::route(get(inA("/preview", "%2Fvec.svg")))), status::unsupported_media_type);
    EXPECT_EQ(statusOf(Router::route(get(inA("/preview", "%2Fnote.txt")))), status::unsupported_media_type);

    auto svg = Router::route(get(inA("/download/content", "%2Fvec.svg")));
    ASSERT_EQ(statusOf(svg), status::ok);
    EXPECT_NE(header(svg, "Content-Security-Policy").find("sandbox"), std::string::npos);
    EXPECT_EQ(header(svg, "X-Content-Type-Options"), "nosniff");

    // Non-media originals are never labelled with a renderable document type inline.
    auto text = Router::route(get(inA("/download/content", "%2Fnote.txt")));
    EXPECT_EQ(header(text, "Content-Type"), "application/octet-stream");

    as(plain);
    EXPECT_EQ(statusOf(Router::route(get(inA("/download/content", "%2Fvec.svg")))), status::forbidden);
    EXPECT_EQ(statusOf(Router::route(get(inA("/download/content", "%2Fvec.svg"), verb::head))), status::forbidden);
}

TEST_F(HttpAccessDbTest, ContentServesRangesConditionalsAndHead) {
    as(admin);
    const auto url = inA("/download/content", "%2Fblob.bin");
    auto full = Router::route(get(url));
    ASSERT_EQ(statusOf(full), status::ok);
    const auto etag = header(full, "ETag");
    ASSERT_FALSE(etag.empty());
    EXPECT_EQ(header(full, "Accept-Ranges"), "bytes");
    EXPECT_EQ(header(full, "X-Accel-Buffering"), "no");
    EXPECT_EQ(bodyOf(full), big);

    auto req = get(url);
    req.set(field::range, "bytes=1000-1999");
    auto part = Router::route(std::move(req));
    ASSERT_EQ(statusOf(part), status::partial_content);
    EXPECT_EQ(header(part, "Content-Range"), "bytes 1000-1999/" + std::to_string(big.size()));
    EXPECT_EQ(bodyOf(part), std::vector<uint8_t>(big.begin() + 1000, big.begin() + 2000));

    req = get(url);
    req.set(field::range, "bytes=-17");
    auto suffix = Router::route(std::move(req));
    ASSERT_EQ(statusOf(suffix), status::partial_content);
    EXPECT_EQ(bodyOf(suffix), std::vector<uint8_t>(big.end() - 17, big.end()));

    req = get(url);
    req.set(field::range, "bytes=" + std::to_string(big.size()) + "-");
    auto unsat = Router::route(std::move(req));
    EXPECT_EQ(statusOf(unsat), status::range_not_satisfiable);
    EXPECT_EQ(header(unsat, "Content-Range"), "bytes */" + std::to_string(big.size()));

    req = get(url);
    req.set(field::range, "bytes=0-1,5-6");
    EXPECT_EQ(statusOf(Router::route(std::move(req))), status::ok);  // multi-range: full representation

    req = get(url);
    req.set(field::range, "bytes=10-19");
    req.set(field::if_range, "\"stale\"");
    EXPECT_EQ(statusOf(Router::route(std::move(req))), status::ok);

    req = get(url);
    req.set(field::range, "bytes=10-19");
    req.set(field::if_range, etag);
    EXPECT_EQ(statusOf(Router::route(std::move(req))), status::partial_content);

    req = get(url);
    req.set(field::if_none_match, etag);
    EXPECT_EQ(statusOf(Router::route(std::move(req))), status::not_modified);

    auto head = Router::route(get(url, verb::head));
    ASSERT_EQ(statusOf(head), status::ok);
    const auto* stream = std::get_if<StreamResponse>(&head);
    ASSERT_NE(stream, nullptr);
    EXPECT_TRUE(stream->headOnly);
    EXPECT_FALSE(stream->reader);  // HEAD never opens (or fetches) the content
    EXPECT_EQ(stream->length, big.size());

    // Inline open-ended ranges are bounded so one response can't pin a connection for a whole movie.
    req = get(url);
    req.set(field::range, "bytes=0-");
    auto open = Router::route(std::move(req));
    EXPECT_EQ(statusOf(open), status::partial_content);
}

TEST_F(HttpAccessDbTest, DownloadsLargerThanTheOldInMemoryCapStream) {
    // Encrypt a 300 MiB file from a source path (streaming), then serve it without buffering.
    const auto source = std::filesystem::temp_directory_path() / ("vh_big_src_" + tag());
    {
        std::ofstream out(source, std::ios::binary);
        std::vector<char> chunk(1 << 20);
        for (int i = 0; i < 300; ++i) {
            std::fill(chunk.begin(), chunk.end(), static_cast<char>(i));
            out.write(chunk.data(), static_cast<std::streamsize>(chunk.size()));
        }
    }
    const auto file = fs::Filesystem::createFile({.path = "/huge.bin", .fuse_path = vaultA->vaultPathToFusePath("/huge.bin"),
                                                  .source_path = source, .engine = vaultA, .user = admin, .overwrite = true});
    std::filesystem::remove(source);
    ASSERT_EQ(file->size_bytes, 300ull << 20);

    as(admin);
    auto res = Router::route(get(inA("/download", "%2Fhuge.bin")));
    ASSERT_EQ(statusOf(res), status::ok);
    auto* stream = std::get_if<StreamResponse>(&res);
    ASSERT_NE(stream, nullptr);
    EXPECT_EQ(stream->length, 300ull << 20);
    EXPECT_NE(header(res, "Content-Disposition").find("attachment"), std::string::npos);
    std::vector<uint8_t> tail(4096);
    ASSERT_EQ(stream->reader->read((300ull << 20) - tail.size(), tail), tail.size());
    EXPECT_TRUE(std::ranges::all_of(tail, [](const uint8_t b) { return b == 43; }));  // 299 % 256
}

TEST_F(HttpAccessDbTest, FolderDownloadsStreamAValidZipOfDecryptedBytes) {
    const std::string utf8Name = "na\xC3\xAFve \xE6\x97\xA5\xE6\x9C\xAC.pdf";
    const auto pdf = twoPagePdf();
    const std::string env = "KEY=value\n";
    for (const auto* dir : {"/zipdir", "/zipdir/sub", "/zipdir/sub/nothing"})
        ASSERT_EQ(fs::Filesystem::mkdir({.path = vaultA->vaultPathToFusePath(dir), .engine = vaultA, .user = admin}), 0);
    write(vaultA, "/zipdir/" + utf8Name, pdf);
    write(vaultA, "/zipdir/.env", {env.begin(), env.end()});
    write(vaultA, "/zipdir/empty.txt", {});
    write(vaultA, "/zipdir/sub/blob.bin", big);  // > 1 MiB: streamed member, authenticated before its descriptor

    const auto url = inA("/download", "%2Fzipdir");
    as(plain);
    EXPECT_EQ(statusOf(Router::route(get(url))), status::forbidden);
    EXPECT_EQ(statusOf(Router::route(get(url, verb::head))), status::forbidden);

    as(reader);
    auto head = Router::route(get(url, verb::head));
    ASSERT_EQ(statusOf(head), status::ok);
    const auto* headStream = std::get_if<StreamResponse>(&head);
    ASSERT_NE(headStream, nullptr);
    EXPECT_TRUE(headStream->headOnly);
    EXPECT_FALSE(headStream->reader);  // HEAD never opens a member

    auto res = Router::route(get(url));
    ASSERT_EQ(statusOf(res), status::ok);
    EXPECT_EQ(header(res, "Content-Type"), "application/zip");
    EXPECT_EQ(header(res, "Content-Disposition"), "attachment; filename=\"zipdir.zip\"; filename*=UTF-8''zipdir.zip");
    const auto body = bodyOf(res);
    EXPECT_EQ(std::get<StreamResponse>(res).length, body.size());
    EXPECT_EQ(headStream->length, body.size());

    const auto path = root / "zipdir.zip";
    std::ofstream(path, std::ios::binary).write(reinterpret_cast<const char*>(body.data()),
                                                static_cast<std::streamsize>(body.size()));
    const auto listing = vh::test::zip::pythonCheck(path);
    if (!listing) GTEST_SKIP() << "python3 unavailable";
    EXPECT_EQ(listing->badMember, "");
    std::map<std::string, uint64_t> sizes;
    for (const auto& item : listing->items) sizes[item.name] = item.size;
    EXPECT_EQ(sizes, (std::map<std::string, uint64_t>{{".env", env.size()}, {"empty.txt", 0}, {utf8Name, pdf.size()},
                                                      {"sub/", 0}, {"sub/blob.bin", big.size()}, {"sub/nothing/", 0}}));
    // Plaintext, not ciphertext: the stored member bytes are the original file.
    const std::string bodyText(body.begin(), body.end());
    EXPECT_NE(bodyText.find(std::string(big.begin(), big.begin() + 4096)), std::string::npos);
    EXPECT_NE(bodyText.find(env), std::string::npos);
    const auto unzip = vh::test::zip::unzipTest(path);
    if (unzip >= 0) {
        EXPECT_EQ(unzip, 0);
    }
}

TEST_F(HttpAccessDbTest, FolderDownloadOfTamperedCiphertextTruncatesInsteadOfVouching) {
    std::vector<uint8_t> payload(2 * 1024 * 1024 + 77);
    std::mt19937 rng(17);
    for (auto& v : payload) v = static_cast<uint8_t>(rng());
    ASSERT_EQ(fs::Filesystem::mkdir({.path = vaultA->vaultPathToFusePath("/ziptamper"), .engine = vaultA, .user = admin}), 0);
    const auto file = write(vaultA, "/ziptamper/data.bin", payload);
    {
        std::fstream f(file->backing_path, std::ios::in | std::ios::out | std::ios::binary);
        f.seekp(1000);
        f.put('\x5a');
    }
    as(admin);
    auto res = Router::route(get(inA("/download", "%2Fziptamper")));
    ASSERT_EQ(statusOf(res), status::ok);  // the walk reads no bytes
    // Draining throws before data.bin's descriptor (its CRC) is produced: the HTTP session turns this into a
    // truncated body and a closed connection, which every client reports as a failed download.
    EXPECT_THROW((void)bodyOf(res), storage::IntegrityError);
}

TEST_F(HttpAccessDbTest, TextSaveIsConditionalEncryptedAndAuthorized) {
    as(admin);
    auto opened = Router::route(get(inA("/download/content", "%2Fnote.txt")));
    const auto etag = header(opened, "ETag");
    const auto before = vaultA->paths;  // keep paths alive
    (void)before;

    const auto save = [&](const std::string& body, const std::optional<std::string>& ifMatch) {
        request req{verb::put, inA("/upload/text", "%2Fnote.txt"), 11};
        req.body() = body;
        if (ifMatch) req.set(field::if_match, *ifMatch);
        req.prepare_payload();
        return Router::route(std::move(req));
    };

    EXPECT_EQ(statusOf(save("no precondition", std::nullopt)), status::precondition_required);
    auto saved = save("SECRET-EDIT-MARKER updated text\n", etag);
    ASSERT_EQ(statusOf(saved), status::ok);
    const auto newEtag = header(saved, "ETag");
    EXPECT_NE(newEtag, etag);

    // The stale ETag now conflicts and the response carries the current one.
    auto conflict = save("lost update", etag);
    EXPECT_EQ(statusOf(conflict), status::precondition_failed);
    EXPECT_EQ(header(conflict, "ETag"), newEtag);

    auto reread = Router::route(get(inA("/download/content", "%2Fnote.txt")));
    const auto bytes = bodyOf(reread);
    EXPECT_EQ(std::string(bytes.begin(), bytes.end()), "SECRET-EDIT-MARKER updated text\n");

    // Re-sealed with the vault key: the marker never reaches the backing file.
    const auto entry = std::dynamic_pointer_cast<fs::model::File>(
        runtime::Deps::get().fsCache->getEntry(vaultA->vaultPathToFusePath("/note.txt")));
    std::ifstream in(entry->backing_path, std::ios::binary);
    const std::string onDisk((std::istreambuf_iterator<char>(in)), {});
    EXPECT_EQ(onDisk.find("SECRET-EDIT-MARKER"), std::string::npos);
    EXPECT_FALSE(entry->encryption_iv.empty());

    EXPECT_EQ(statusOf(save(std::string("bin\0ary", 7), newEtag)), status::unprocessable_entity);
    EXPECT_EQ(statusOf(save(std::string(3 * 1024 * 1024, 'x'), newEtag)), status::payload_too_large);

    // Not text: refused even with Overwrite.
    request pic{verb::put, inA("/upload/text", "%2Fpic.jpg"), 11};
    pic.body() = "x";
    pic.set(field::if_match, "\"whatever\"");
    pic.prepare_payload();
    EXPECT_EQ(statusOf(Router::route(std::move(pic))), status::unsupported_media_type);

    // A reader may view but not overwrite.
    as(reader);
    EXPECT_EQ(statusOf(save("reader edit", newEtag)), status::forbidden);
}

TEST_F(HttpAccessDbTest, PdfPagesRenderWithPageCountAndHostileParametersAreBounded) {
    as(reader);
    auto p0 = Router::route(get(inA("/preview", "%2Fdoc.pdf", "&size=512")));
    ASSERT_EQ(statusOf(p0), status::ok);
    EXPECT_EQ(header(p0, "X-Vaulthalla-Page-Count"), "2");
    auto p1 = Router::route(get(inA("/preview", "%2Fdoc.pdf", "&size=512&page=1")));
    ASSERT_EQ(statusOf(p1), status::ok);
    EXPECT_NE(bodyOf(p0), bodyOf(p1));
    EXPECT_EQ(statusOf(Router::route(get(inA("/preview", "%2Fdoc.pdf", "&page=7")))), status::unprocessable_entity);
    EXPECT_EQ(statusOf(Router::route(get(inA("/preview", "%2Fpic.jpg", "&page=1")))), status::unprocessable_entity);

    // Absurd sizes clamp (2048 max) instead of allocating; legacy `scale` is ignored.
    auto huge = Router::route(get(inA("/preview", "%2Fpic.jpg", "&size=100000&scale=50")));
    ASSERT_EQ(statusOf(huge), status::ok);
    const auto jpeg = bodyOf(huge);
    tjhandle tj = tjInitDecompress();
    int w = 0, h = 0, ss = 0, cs = 0;
    ASSERT_EQ(tjDecompressHeader3(tj, jpeg.data(), jpeg.size(), &w, &h, &ss, &cs), 0);
    tjDestroy(tj);
    EXPECT_LE(std::max(w, h), 2048);
    EXPECT_LE(std::max(w, h), 1600);  // never upscaled past the source
    EXPECT_EQ(statusOf(Router::route(get(inA("/preview", "%2Fpic.jpg", "&size=abc")))), status::bad_request);
}

TEST_F(HttpAccessDbTest, ConcurrentPdfAndImageRendersAreSafeAndLeaveNoPlaintextTempFiles) {
    const auto tempsBefore = plaintextTempFiles();
    as(admin);
    std::atomic<int> failures{0};
    std::vector<std::thread> threads;
    for (int t = 0; t < 8; ++t)
        threads.emplace_back([&, t] {
            for (int i = 0; i < 6; ++i) {
                const auto size = 64 + 16 * ((t * 7 + i) % 20);  // distinct sizes: cache misses render
                const auto path = (t % 2) ? std::string("%2Fdoc.pdf") : std::string("%2Fpic.jpg");
                if (statusOf(Router::route(get(inA("/preview", path, "&size=" + std::to_string(size))))) != status::ok)
                    ++failures;
            }
        });
    for (auto& th : threads) th.join();
    EXPECT_EQ(failures.load(), 0);
    EXPECT_EQ(plaintextTempFiles(), tempsBefore);
}

}
