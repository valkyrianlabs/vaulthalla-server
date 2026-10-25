// PUT /upload/content (#258, vaulthalla/desktop#1): conditional create (If-None-Match: *) and replace
// (If-Match: <content_version>) of one file, committed through Filesystem::createFile's streaming seal and
// compare-and-swap; and the /upload/session hygiene that came with it (commit from the staged file instead of a
// whole-file buffer, a failed per-file PUT sent again). Real vaults, users, RBAC and encrypted files; the large-file
// cases stream through a real HTTP session over a socket and sample the process's resident memory while they run.

#include "db/Transactions.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "fuse/WorkingCopies.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/Router.hpp"
#include "protocols/http/Session.hpp"
#include "protocols/http/upload/Content.hpp"
#include "protocols/http/upload/Coordinator.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Controller.hpp"
#include "vault/model/Vault.hpp"

#include <boost/asio.hpp>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#endif
#include <fcntl.h>
#include <unistd.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace vh::protocols::http::test_upload_content {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using Response = model::preview::Response;

namespace {

std::string ucTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "u" + std::to_string(n.fetch_add(1));
}

status statusOf(const Response& r) {
    return std::visit([](const auto& res) { return res.result(); }, r);
}

std::string headerOf(const Response& r, const field name) {
    return std::visit([&](const auto& res) -> std::string {
        const auto it = res.find(name);
        return it == res.end() ? std::string{} : std::string(it->value());
    }, r);
}

json jsonOf(const Response& r) {
    const auto* s = std::get_if<string_response>(&r);
    return s && !s->body().empty() ? json::parse(s->body()) : json{};
}

std::string encodePath(const std::string& path) {
    std::string out;
    for (const char c : path) out += c == '/' ? std::string("%2F") : std::string(1, c);
    return out;
}

// Deterministic content, generated a chunk at a time so no test holds a large file in memory.
uint8_t patternByte(const uint64_t offset) { return static_cast<uint8_t>((offset * 131u + (offset >> 13)) & 0xff); }

void fillPattern(std::vector<char>& chunk, const uint64_t offset) {
    for (std::size_t i = 0; i < chunk.size(); ++i) chunk[i] = static_cast<char>(patternByte(offset + i));
}

// The process's resident set now (not a high-water mark: earlier suites in this binary may have peaked higher).
uint64_t residentBytes() {
#if defined(__APPLE__)
    mach_task_basic_info info{};
    mach_msg_type_number_t count = MACH_TASK_BASIC_INFO_COUNT;
    if (task_info(mach_task_self(), MACH_TASK_BASIC_INFO, reinterpret_cast<task_info_t>(&info), &count) != KERN_SUCCESS)
        return 0;
    return info.resident_size;
#else
    std::ifstream statm("/proc/self/statm");
    uint64_t size = 0, resident = 0;
    statm >> size >> resident;
    return resident * static_cast<uint64_t>(::sysconf(_SC_PAGESIZE));
#endif
}

// Samples the resident set every few milliseconds while it lives; peakGrowth() is the most it rose above the value
// at construction.
class RssSampler {
public:
    RssSampler() : base_(residentBytes()), peak_(base_) {
        thread_ = std::thread([this] {
            while (!stop_.load()) {
                const auto now = residentBytes();
                if (now > peak_.load()) peak_.store(now);
                std::this_thread::sleep_for(std::chrono::milliseconds(2));
            }
        });
    }
    ~RssSampler() { finish(); }
    uint64_t finish() {
        if (thread_.joinable()) {
            stop_.store(true);
            thread_.join();
        }
        const auto now = residentBytes();
        if (now > peak_.load()) peak_.store(now);
        return peak_.load() > base_ ? peak_.load() - base_ : 0;
    }

private:
    uint64_t base_;
    std::atomic<uint64_t> peak_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

// The plaintext of a stored file compared with the pattern, read a window at a time.
bool matchesPattern(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<fs::model::File>& file,
                    const uint64_t size) {
    auto reader = engine->openPlaintextReader(file);
    if (reader->size() != size) return false;
    std::vector<uint8_t> window(1 << 20);
    for (uint64_t off = 0; off < size;) {
        const auto n = reader->read(off, std::span<uint8_t>(window.data(), window.size()));
        if (n == 0) return false;
        for (std::size_t i = 0; i < n; ++i)
            if (window[i] != patternByte(off + i)) return false;
        off += n;
    }
    return true;
}

}

class HttpUploadContentDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr admin;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    std::shared_ptr<storage::Engine> engine;
    std::shared_ptr<ws::Session> session;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_http_upload_content] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_upload_content_" + ucTag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        fs::Filesystem::init(runtime::Deps::get().storageManager);
        runtime::Deps::get().fsCache = std::make_shared<fs::cache::Registry>();
        runtime::Deps::get().storageManager->initStorageEngines();
        admin = vh::identities::manager().userByName("admin");

        previousController = runtime::Deps::get().syncController;
        runtime::Deps::setSyncController(std::make_shared<sync::Controller>());
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        runtime::Deps::setSyncController(previousController);
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        access::clearCachesForTesting();
        const auto vault = ops::vaults::create(admin, {.name = "uc_" + ucTag(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);
        as(admin);
    }

    void TearDown() override {
        if (skipTests) return;
        Router::resetPreviewSessionResolverForTesting();
        upload::Coordinator::resetSessionResolverForTesting();
        upload::Coordinator::clearForTesting();
    }

    void as(const UserPtr& user) {
        session = std::make_shared<ws::Session>(std::make_shared<ws::Router>());
        session->user = user;
        auto s = session;
        Router::setPreviewSessionResolverForTesting([s](const request&) { return s; });
        upload::Coordinator::setSessionResolverForTesting([s](const request&) { return s; });
    }

    [[nodiscard]] UserPtr userWithVaultRole(const std::string& role) const {
        const auto created = ops::users::create(admin, {.name = "uc_user_" + ucTag(), .role = "unprivileged",
                                                        .password = std::string("Upload-Content-Pass-123")});
        (void)ops::roles::assignVaultRole(admin, {.target = {.vault_id = engine->vault->id,
                                                             .subject = {.type = "user", .id = created.user->id}},
                                                  .role = role});
        return vh::identities::manager().user(created.user->id);
    }

    void deny(const UserPtr& user, const std::string& permission, const std::string& pattern) const {
        ops::roles::PermissionEdit edit;
        edit.changes.emplace_back(permission, false);
        (void)ops::roles::addVaultRoleOverrides(admin, {
            .target = {.vault_id = engine->vault->id, .subject = {.type = "user", .id = user->id}},
            .permissions = edit,
            .pattern = pattern});
    }

    [[nodiscard]] std::string target(const std::string& path) const {
        return "/upload/content?vault_id=" + std::to_string(engine->vault->id) + "&path=" + encodePath(path);
    }

    struct Precondition {
        std::optional<std::string> ifMatch{};
        std::optional<std::string> ifNoneMatch{};
    };

    [[nodiscard]] Response put(const std::string& path, const std::string& body, const Precondition& pre,
                               const bool withLength = true) const {
        request req{verb::put, target(path), 11};
        req.body() = body;
        if (pre.ifMatch) req.set(field::if_match, *pre.ifMatch);
        if (pre.ifNoneMatch) req.set(field::if_none_match, *pre.ifNoneMatch);
        if (withLength) req.prepare_payload();
        return Router::route(std::move(req));
    }

    [[nodiscard]] Response create(const std::string& path, const std::string& body) const {
        return put(path, body, {.ifNoneMatch = "*"});
    }

    [[nodiscard]] Response replace(const std::string& path, const std::string& body, const std::string& version) const {
        return put(path, body, {.ifMatch = version});
    }

    [[nodiscard]] std::shared_ptr<fs::model::File> file(const std::string& path) const {
        return std::dynamic_pointer_cast<fs::model::File>(
            runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path)));
    }

    // GET /download/content: status, ETag and body.
    struct Downloaded {
        status code{};
        std::string etag;
        std::string body;
    };

    [[nodiscard]] Downloaded download(const std::string& path) const {
        request req{verb::get, "/download/content?vault_id=" + std::to_string(engine->vault->id) + "&path=" +
                                   encodePath(path), 11};
        auto res = Router::route(std::move(req));
        Downloaded out{.code = statusOf(res), .etag = headerOf(res, field::etag), .body = {}};
        if (const auto* st = std::get_if<model::preview::StreamResponse>(&res); st && st->reader) {
            std::vector<uint8_t> buf(static_cast<std::size_t>(st->length));
            std::size_t done = 0;
            while (done < buf.size()) {
                const auto n = st->reader->read(st->offset + done, std::span(buf.data() + done, buf.size() - done));
                if (n == 0) break;
                done += n;
            }
            out.body.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(done));
        }
        return out;
    }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine, .user = admin, .overwrite = true}));
    }

    [[nodiscard]] std::size_t stagingFiles() const {
        std::size_t n = 0;
        std::error_code ec;
        for (auto it = std::filesystem::recursive_directory_iterator(root, ec);
             !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
            if (it->path().filename().string().starts_with(".upload-http-")) ++n;
        return n;
    }
};

TEST_F(HttpUploadContentDbTest, CreateWithIfNoneMatchStoresTheFileAndAnswersItsEntry) {
    auto res = create("/notes/new.txt", "hello, vault\n");
    ASSERT_EQ(statusOf(res), status::created) << jsonOf(res).dump();
    const auto body = jsonOf(res);
    EXPECT_TRUE(body.at("created").get<bool>());
    const auto& entry = body.at("entry");
    EXPECT_EQ(entry.at("type"), "file");
    EXPECT_EQ(entry.at("path"), "/notes/new.txt");
    EXPECT_EQ(entry.at("size_bytes"), 13);
    EXPECT_TRUE(entry.at("metadata_version").is_string());

    // The response's version is the stored file's, and the one /download/content serves.
    const auto etag = headerOf(res, field::etag);
    EXPECT_EQ(entry.at("content_version"), etag);
    const auto got = download("/notes/new.txt");
    EXPECT_EQ(got.code, status::ok);
    EXPECT_EQ(got.etag, etag);
    EXPECT_EQ(got.body, "hello, vault\n");
    EXPECT_EQ(entry.at("id"), file("/notes/new.txt")->id);
    EXPECT_FALSE(file("/notes/new.txt")->encryption_iv.empty()) << "sealed with the vault key";

    // Create-only: the second create is refused with the current version, and nothing changes.
    auto again = create("/notes/new.txt", "lost update\n");
    EXPECT_EQ(statusOf(again), status::precondition_failed);
    EXPECT_EQ(headerOf(again, field::etag), etag);
    EXPECT_EQ(jsonOf(again).at("content_version"), etag);
    EXPECT_EQ(download("/notes/new.txt").body, "hello, vault\n");

    // An empty file is a file too.
    auto empty = create("/notes/empty.txt", "");
    ASSERT_EQ(statusOf(empty), status::created);
    EXPECT_EQ(file("/notes/empty.txt")->size_bytes, 0u);
    EXPECT_EQ(jsonOf(empty).at("entry").at("content_version"), download("/notes/empty.txt").etag);

    // A folder in the way is a conflict, not a precondition.
    engine->mkdir("/folder", admin);
    EXPECT_EQ(statusOf(create("/folder", "x")), status::conflict);
    EXPECT_EQ(stagingFiles(), 0u) << "staging is removed after every outcome";
}

TEST_F(HttpUploadContentDbTest, ReplaceWithIfMatchIsACompareAndSwapOnTheContentVersion) {
    write("/doc.txt", "version one\n");
    const auto v1 = download("/doc.txt").etag;
    const auto id = file("/doc.txt")->id;

    auto res = replace("/doc.txt", "version two, longer\n", v1);
    ASSERT_EQ(statusOf(res), status::ok) << jsonOf(res).dump();
    const auto body = jsonOf(res);
    EXPECT_FALSE(body.at("created").get<bool>());
    const auto v2 = headerOf(res, field::etag);
    EXPECT_NE(v2, v1);
    EXPECT_EQ(body.at("entry").at("content_version"), v2);
    EXPECT_EQ(body.at("entry").at("id"), id) << "a replacement keeps the entry id";
    EXPECT_EQ(download("/doc.txt").body, "version two, longer\n");
    EXPECT_EQ(download("/doc.txt").etag, v2);

    // The version the client read is stale now: 412 with the current one, and the content stays.
    auto stale = replace("/doc.txt", "lost update\n", v1);
    EXPECT_EQ(statusOf(stale), status::precondition_failed);
    EXPECT_EQ(headerOf(stale, field::etag), v2);
    EXPECT_EQ(jsonOf(stale).at("content_version"), v2);
    EXPECT_EQ(jsonOf(stale).at("code"), "conflict");
    EXPECT_EQ(download("/doc.txt").body, "version two, longer\n");

    // Replacing with nothing is allowed (an empty file).
    ASSERT_EQ(statusOf(replace("/doc.txt", "", v2)), status::ok);
    EXPECT_EQ(file("/doc.txt")->size_bytes, 0u);
    EXPECT_EQ(stagingFiles(), 0u);
}

TEST_F(HttpUploadContentDbTest, AWriteBetweenAcceptAndCommitIsAConflictNotALostUpdate) {
    write("/race.txt", "base\n");
    const auto base = download("/race.txt").etag;

    request req{verb::put, target("/race.txt"), 11};
    req.set(field::if_match, base);
    auto begun = upload::content::begin(req, 7);
    ASSERT_FALSE(begun.refusal);
    begun.upload.write("client\n", 7);

    write("/race.txt", "someone else\n");  // lands while the body is still arriving
    const auto current = download("/race.txt").etag;

    auto res = begun.upload.commit(req);
    EXPECT_EQ(statusOf(res), status::precondition_failed);
    EXPECT_EQ(headerOf(res, field::etag), current);
    EXPECT_EQ(download("/race.txt").body, "someone else\n");
}

TEST_F(HttpUploadContentDbTest, AnOpenFuseWorkingCopyRefusesTheReplacement) {
    write("/open.txt", "opened in an editor\n");
    const auto version = download("/open.txt").etag;
    const auto f = file("/open.txt");
    ASSERT_TRUE(f->inode);

    auto& copies = fuse::WorkingCopies::instance();
    // The daemon's registry keeps the root it was first made with (an earlier suite's backing path, maybe gone).
    std::filesystem::create_directories(copies.root());
    auto handle = copies.open(*f->inode, f, O_RDONLY);
    auto res = replace("/open.txt", "from the lane\n", version);
    EXPECT_EQ(statusOf(res), status::precondition_failed);
    EXPECT_EQ(headerOf(res, field::etag), version);

    // Also when the copy opens after the request was accepted (createFile checks again under the content lock).
    copies.release(handle);
    request req{verb::put, target("/open.txt"), 11};
    req.set(field::if_match, version);
    auto begun = upload::content::begin(req, 4);
    ASSERT_FALSE(begun.refusal);
    begun.upload.write("late", 4);
    auto late = copies.open(*f->inode, f, O_RDONLY);
    EXPECT_EQ(statusOf(begun.upload.commit(req)), status::precondition_failed);
    copies.release(late);

    EXPECT_EQ(download("/open.txt").body, "opened in an editor\n");
    ASSERT_EQ(statusOf(replace("/open.txt", "now it may\n", version)), status::ok);
    EXPECT_EQ(download("/open.txt").body, "now it may\n");
}

TEST_F(HttpUploadContentDbTest, RequestsWithoutAUsablePreconditionOrLengthAreRefusedBeforeTheBody) {
    write("/x.txt", "x");
    const auto version = download("/x.txt").etag;

    EXPECT_EQ(statusOf(put("/x.txt", "y", {})), status::precondition_required);
    EXPECT_EQ(statusOf(put("/x.txt", "y", {.ifMatch = version, .ifNoneMatch = "*"})), status::precondition_required);
    EXPECT_EQ(statusOf(put("/x.txt", "y", {.ifMatch = "*"})), status::precondition_required);
    EXPECT_EQ(statusOf(put("/x.txt", "y", {.ifNoneMatch = version})), status::precondition_required);
    EXPECT_EQ(statusOf(put("/x.txt", "y", {.ifMatch = version}, false)), status::length_required);
    EXPECT_EQ(statusOf(replace("/missing.txt", "y", version)), status::not_found);
    engine->mkdir("/dir", admin);
    EXPECT_EQ(statusOf(replace("/dir", "y", version)), status::bad_request);
    EXPECT_EQ(statusOf(create("/", "y")), status::bad_request);
    EXPECT_EQ(statusOf(create("/../escape.txt", "y")), status::bad_request);

    request get{verb::get, target("/x.txt"), 11};
    EXPECT_EQ(statusOf(upload::content::handle(std::move(get))), status::method_not_allowed);

    // Over the per-file ceiling (as /upload/session), answered from the header alone.
    request huge{verb::put, target("/huge.bin"), 11};
    huge.set(field::if_none_match, "*");
    auto begun = upload::content::begin(huge, 9ull << 30);
    ASSERT_TRUE(begun.refusal);
    EXPECT_EQ(statusOf(*begun.refusal), status::payload_too_large);
    EXPECT_EQ(download("/x.txt").body, "x");
    EXPECT_EQ(stagingFiles(), 0u);
}

TEST_F(HttpUploadContentDbTest, RbacDecidesThroughTheAccessLayer) {
    engine->mkdir("/shared", admin);
    write("/shared/doc.txt", "original\n");
    const auto version = download("/shared/doc.txt").etag;

    // A reader may download but neither create nor replace.
    as(userWithVaultRole("reader"));
    EXPECT_EQ(download("/shared/doc.txt").code, status::ok);
    EXPECT_EQ(statusOf(replace("/shared/doc.txt", "reader edit\n", version)), status::forbidden);
    EXPECT_EQ(statusOf(create("/shared/new.txt", "reader file\n")), status::forbidden);

    // Write without Overwrite: new files yes, replacing an existing one no.
    const auto editor = userWithVaultRole("editor");
    deny(editor, "vault.fs.files.overwrite", "/shared/doc.txt");
    as(vh::identities::manager().user(editor->id));
    EXPECT_EQ(statusOf(replace("/shared/doc.txt", "editor edit\n", version)), status::forbidden);
    EXPECT_EQ(statusOf(create("/shared/editor.txt", "editor file\n")), status::created);

    // No session, a share session on the human lane.
    Router::setPreviewSessionResolverForTesting([](const request&) -> std::shared_ptr<ws::Session> {
        throw std::runtime_error("Refresh token not set");
    });
    EXPECT_EQ(statusOf(create("/shared/anon.txt", "x")), status::unauthorized);
    as(admin);
    request share{verb::put, target("/shared/s.txt") + "&share=1", 11};
    share.set(field::if_none_match, "*");
    share.body() = "x";
    share.prepare_payload();
    const auto shareStatus = statusOf(Router::route(std::move(share)));
    EXPECT_TRUE(shareStatus == status::unauthorized || shareStatus == status::forbidden);

    EXPECT_EQ(download("/shared/doc.txt").body, "original\n");
    EXPECT_FALSE(file("/shared/new.txt"));
    EXPECT_FALSE(file("/shared/anon.txt"));
    EXPECT_FALSE(file("/shared/s.txt"));
}

TEST_F(HttpUploadContentDbTest, AccessIsCheckedAgainAtCommit) {
    const auto editor = userWithVaultRole("editor");
    as(editor);
    request req{verb::put, target("/late/revoked.txt"), 11};
    req.set(field::if_none_match, "*");
    auto begun = upload::content::begin(req, 5);
    ASSERT_FALSE(begun.refusal);
    begun.upload.write("bytes", 5);

    (void)ops::roles::unassignVaultRole(admin, {.vault_id = engine->vault->id,
                                                .subject = {.type = "user", .id = editor->id}});
    as(vh::identities::manager().user(editor->id));
    EXPECT_EQ(statusOf(begun.upload.commit(req)), status::forbidden);
    EXPECT_FALSE(file("/late/revoked.txt"));
}

TEST_F(HttpUploadContentDbTest, ConcurrentCreatesOfOnePathStoreExactlyOne) {
    constexpr int kWriters = 6;
    std::vector<request> reqs;
    std::vector<upload::content::Begun> begun;
    for (int i = 0; i < kWriters; ++i) {
        reqs.emplace_back(verb::put, target("/one.txt"), 11);
        reqs.back().set(field::if_none_match, "*");
        begun.push_back(upload::content::begin(reqs.back(), 8));
        ASSERT_FALSE(begun.back().refusal);
        const auto text = "writer " + std::to_string(i);
        begun.back().upload.write(text.data(), text.size());
    }
    std::atomic<int> created{0}, refused{0};
    std::vector<std::thread> threads;
    for (int i = 0; i < kWriters; ++i)
        threads.emplace_back([&, i] {
            const auto code = statusOf(begun[static_cast<std::size_t>(i)].upload.commit(reqs[static_cast<std::size_t>(i)]));
            if (code == status::created) ++created;
            else if (code == status::precondition_failed) ++refused;
        });
    for (auto& t : threads) t.join();
    EXPECT_EQ(created.load(), 1);
    EXPECT_EQ(refused.load(), kWriters - 1);
    EXPECT_TRUE(download("/one.txt").body.starts_with("writer "));
}

// A body far larger than any buffer streams through a real HTTP session into staging and is sealed from the staged
// file: resident memory stays flat (it would grow by the file size if either step buffered the whole body).
TEST_F(HttpUploadContentDbTest, ALargeBodyStreamsAndCommitsInBoundedMemory) {
    constexpr uint64_t kSize = 256ull << 20;
    namespace asio = boost::asio;
    using tcp = asio::ip::tcp;
    asio::io_context ioc;
    tcp::acceptor acceptor{ioc, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)};
    tcp::socket client{ioc};
    client.connect(acceptor.local_endpoint());
    tcp::socket server(ioc);
    acceptor.accept(server);
    auto httpSession = Session::open(std::move(server));
    std::thread serverThread([httpSession] { httpSession->run(); });

    RssSampler sampler;
    const auto head = "PUT " + target("/big/blob.bin") + " HTTP/1.1\r\nHost: test\r\nIf-None-Match: *\r\n"
                      "Content-Length: " + std::to_string(kSize) + "\r\nConnection: close\r\n\r\n";
    asio::write(client, asio::buffer(head));
    std::vector<char> chunk(1 << 20);
    for (uint64_t off = 0; off < kSize; off += chunk.size()) {
        fillPattern(chunk, off);
        asio::write(client, asio::buffer(chunk.data(), static_cast<std::size_t>(std::min<uint64_t>(chunk.size(), kSize - off))));
    }
    asio::streambuf response;
    boost::system::error_code ec;
    asio::read(client, response, ec);  // Connection: close → until EOF
    const auto growth = sampler.finish();
    client.close(ec);
    serverThread.join();

    const std::string raw{asio::buffers_begin(response.data()), asio::buffers_end(response.data())};
    ASSERT_TRUE(raw.starts_with("HTTP/1.1 201")) << raw.substr(0, 400);
    const auto stored = file("/big/blob.bin");
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->size_bytes, kSize);
    EXPECT_NE(raw.find(storage::generationOf(*stored).etag()), std::string::npos) << "the answer carries the new ETag";
    EXPECT_TRUE(matchesPattern(engine, stored, kSize));
    EXPECT_LT(growth, 64ull << 20) << "resident memory grew by " << (growth >> 20) << " MiB for a "
                                   << (kSize >> 20) << " MiB upload";
    EXPECT_EQ(stagingFiles(), 0u);
}

// /upload/session commits from the staged file now (it used to read the whole file into memory first).
TEST_F(HttpUploadContentDbTest, AnUploadSessionCommitsALargeFileInBoundedMemory) {
    constexpr uint64_t kSize = 256ull << 20;
    request createReq{verb::post, "/upload/session", 11};
    const auto created = upload::Coordinator::instance().createSession(createReq, {
        {"vault_id", engine->vault->id},
        {"files", json::array({{{"file_id", "big"}, {"path", "/session/big.bin"}, {"size", kSize}}})}});
    const auto uploadId = created.at("upload_id").get<std::string>();

    request putReq{verb::put, "/upload/" + uploadId + "/files/big", 11};
    {
        auto stream = upload::Coordinator::instance().beginFile(putReq, kSize);
        std::vector<char> chunk(1 << 20);
        for (uint64_t off = 0; off < kSize; off += chunk.size()) {
            fillPattern(chunk, off);
            stream.write(chunk.data(), chunk.size());
        }
        (void)stream.finish();
    }

    RssSampler sampler;
    request finishReq{verb::post, "/upload/" + uploadId + "/finish", 11};
    const auto finished = upload::Coordinator::instance().finishSession(finishReq, uploadId);
    const auto growth = sampler.finish();

    EXPECT_TRUE(finished.at("complete").get<bool>());
    const auto stored = file("/session/big.bin");
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->size_bytes, kSize);
    EXPECT_TRUE(matchesPattern(engine, stored, kSize));
    EXPECT_LT(growth, 64ull << 20) << "the commit grew resident memory by " << (growth >> 20) << " MiB for a "
                                   << (kSize >> 20) << " MiB file";
}

TEST_F(HttpUploadContentDbTest, AFailedUploadSessionPutCanBeSentAgain) {
    request createReq{verb::post, "/upload/session", 11};
    const auto created = upload::Coordinator::instance().createSession(createReq, {
        {"vault_id", engine->vault->id},
        {"files", json::array({{{"file_id", "f1"}, {"path", "/retry/a.txt"}, {"size", 12}}})}});
    const auto uploadId = created.at("upload_id").get<std::string>();
    request putReq{verb::put, "/upload/" + uploadId + "/files/f1", 11};

    {
        // The connection drops after five bytes: the stream fails (abandoned) and the file is Failed.
        auto stream = upload::Coordinator::instance().beginFile(putReq, 12);
        stream.write("hello", 5);
    }
    {
        // A short body fails it too.
        auto stream = upload::Coordinator::instance().beginFile(putReq, 12);
        stream.write("hel", 3);
        EXPECT_THROW((void)stream.finish(), std::runtime_error);
    }

    // Sent again from the start, it completes, and the session commits exactly those bytes.
    {
        auto stream = upload::Coordinator::instance().beginFile(putReq, 12);
        stream.write("hello again!", 12);
        const auto done = stream.finish();
        EXPECT_TRUE(done.at("complete").get<bool>());
    }
    // A completed file is not reopened.
    EXPECT_THROW((void)upload::Coordinator::instance().beginFile(putReq, 12), std::runtime_error);

    request finishReq{verb::post, "/upload/" + uploadId + "/finish", 11};
    (void)upload::Coordinator::instance().finishSession(finishReq, uploadId);
    EXPECT_EQ(download("/retry/a.txt").body, "hello again!");
}

TEST_F(HttpUploadContentDbTest, AnEmptyUploadSessionFileStillTakesItsMimeTypeFromItsName) {
    request createReq{verb::post, "/upload/session", 11};
    const auto created = upload::Coordinator::instance().createSession(createReq, {
        {"vault_id", engine->vault->id},
        {"files", json::array({{{"file_id", "e"}, {"path", "/empty/notes.txt"}, {"size", 0}},
                               {{"file_id", "t"}, {"path", "/empty/data.json"}, {"size", 13}}})}});
    const auto uploadId = created.at("upload_id").get<std::string>();
    request putReq{verb::put, "/upload/" + uploadId + "/files/t", 11};
    {
        auto stream = upload::Coordinator::instance().beginFile(putReq, 13);
        stream.write("{\"a\": [1, 2]}", 13);
        (void)stream.finish();
    }
    request finishReq{verb::post, "/upload/" + uploadId + "/finish", 11};
    (void)upload::Coordinator::instance().finishSession(finishReq, uploadId);

    const auto empty = file("/empty/notes.txt");
    ASSERT_TRUE(empty);
    EXPECT_EQ(empty->size_bytes, 0u);
    EXPECT_EQ(empty->mime_type.value_or(""), "text/plain");
    const auto data = file("/empty/data.json");
    ASSERT_TRUE(data);
    EXPECT_EQ(download("/empty/data.json").body, "{\"a\": [1, 2]}");
    EXPECT_TRUE(data->mime_type && !data->mime_type->empty());
}

}
