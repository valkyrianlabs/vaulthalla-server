// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Resumable uploads (/upload/sessions, capability http.upload.resumable, docs/reference/transfer-protocol.md §3):
// create/status/part/finish/cancel against real vaults, users, RBAC, share links and encrypted files; parts out of
// order and in parallel; idempotent duplicates and conflicts; Content-Digest; a daemon "restart" (the in-memory state
// dropped and rebuilt from the rows and the spool) during receiving and during finalization; expiry; quota; key
// rotation; preconditions (reject, create-only, if_match) including a target that appears before the commit; bounded
// memory for a large streamed part; and the committed bytes read back through the normal reader. The DISABLED_
// benchmarks at the end measure part throughput and finalize latency against the legacy /upload/session lane.

#include "crypto/util/digest.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/upload/Resumable.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/Router.hpp"
#include "protocols/http/Session.hpp"
#include "protocols/http/upload/Coordinator.hpp"
#include "protocols/http/upload/Resumable.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "config/Registry.hpp"
#include "rbac/Actor.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "share/Link.hpp"
#include "share/Manager.hpp"
#include "share/Principal.hpp"
#include "share/Token.hpp"
#include "share/Types.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "sync/Controller.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <boost/asio.hpp>
#include <fmt/format.h>
#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>
#include <sodium.h>

#if defined(__APPLE__)
#include <mach/mach.h>
#endif
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

namespace vh::protocols::http::test_upload_resumable {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using Response = model::preview::Response;
using Service = upload::resumable::Service;

namespace {

std::string rsTag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "r" + std::to_string(n.fetch_add(1));
}

status statusOf(const Response& r) {
    return std::visit([](const auto& res) { return res.result(); }, r);
}

std::string headerOf(const Response& r, const std::string& name) {
    return std::visit([&](const auto& res) -> std::string {
        const auto it = res.find(name);
        return it == res.end() ? std::string{} : std::string(it->value());
    }, r);
}

json jsonOf(const Response& r) {
    const auto* s = std::get_if<string_response>(&r);
    return s && !s->body().empty() ? json::parse(s->body()) : json{};
}

std::string codeOf(const Response& r) {
    const auto j = jsonOf(r);
    return j.contains("error") && j.at("error").is_object() ? j.at("error").value("code", "") : "";
}

uint8_t patternByte(const uint64_t offset, const uint8_t seed = 0) {
    return static_cast<uint8_t>(((offset * 131u + (offset >> 13)) + seed) & 0xff);
}

std::string pattern(const uint64_t offset, const uint64_t n, const uint8_t seed = 0) {
    std::string out(static_cast<std::size_t>(n), '\0');
    for (uint64_t i = 0; i < n; ++i) out[static_cast<std::size_t>(i)] = static_cast<char>(patternByte(offset + i, seed));
    return out;
}

std::string digestHeader(const std::string& body) {
    const auto d = crypto::util::EvpDigest::of(EVP_sha256(), body.data(), body.size());
    std::string b64(sodium_base64_ENCODED_LEN(d.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(b64.data(), b64.size(), d.data(), d.size(), sodium_base64_VARIANT_ORIGINAL);
    b64.resize(std::strlen(b64.c_str()));
    return "sha-256=:" + b64 + ":";
}

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
        return peak_.load() > base_ ? peak_.load() - base_ : 0;
    }

private:
    uint64_t base_;
    std::atomic<uint64_t> peak_;
    std::atomic<bool> stop_{false};
    std::thread thread_;
};

bool matchesPattern(const std::shared_ptr<storage::Engine>& engine, const std::shared_ptr<fs::model::File>& file,
                    const uint64_t size, const uint8_t seed = 0) {
    auto reader = engine->openPlaintextReader(file);
    if (reader->size() != size) return false;
    std::vector<uint8_t> window(1 << 20);
    for (uint64_t off = 0; off < size;) {
        const auto n = reader->read(off, std::span<uint8_t>(window.data(), window.size()));
        if (n == 0) return false;
        for (std::size_t i = 0; i < n; ++i)
            if (window[i] != patternByte(off + i, seed)) return false;
        off += n;
    }
    reader->requireAuthenticated();
    return true;
}

std::size_t countFiles(const std::filesystem::path& dir) {
    std::size_t n = 0;
    std::error_code ec;
    for (auto it = std::filesystem::recursive_directory_iterator(dir, ec);
         !ec && it != std::filesystem::recursive_directory_iterator(); it.increment(ec))
        if (it->is_regular_file()) ++n;
    return n;
}

}

class ResumableUploadDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static UserPtr admin;
    inline static std::shared_ptr<sync::Controller> previousController;
    inline static std::filesystem::path root;

    std::shared_ptr<storage::Engine> engine;
    std::shared_ptr<ws::Session> session;
    config::Config savedConfig;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_http_upload_resumable] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_upload_resumable_" + rsTag());
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
        share::Token::setPepperForTesting(std::vector<uint8_t>(32, 0x52));
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        share::Token::clearPepperForTesting();
        runtime::Deps::setSyncController(previousController);
        std::error_code ec;
        std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        savedConfig = config::Registry::get();
        // Small parts so the tests run fast; the defaults (1 MiB minimum) are exercised by the large cases.
        transfer([](config::TransferConfig& t) {
            t.part_min_bytes = 1024;
            t.part_default_bytes = 64 * 1024;
        });
        access::clearCachesForTesting();
        const auto vault = ops::vaults::create(admin, {.name = "rs_" + rsTag(), .type = vault::model::VaultType::Local});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        ASSERT_TRUE(engine);
        as(admin);
    }

    void TearDown() override {
        if (skipTests) return;
        Service::holdCommitsForTesting(false);
        Service::forgetForTesting();
        Service::resetClockForTesting();
        Service::setFinishWaitForTesting(std::chrono::milliseconds(5000));
        Router::resetPreviewSessionResolverForTesting();
        config::Registry::set(savedConfig);
        db::Transactions::exec("test: clear upload sessions", [](pqxx::work& txn) { txn.exec("DELETE FROM upload_session"); });
        std::error_code ec;
        std::filesystem::remove_all(Service::spoolRoot(), ec);
    }

    static void transfer(const std::function<void(config::TransferConfig&)>& edit) {
        auto next = config::Registry::get();
        edit(next.transfer);
        config::Registry::set(next);
    }

    void as(const UserPtr& user) {
        session = std::make_shared<ws::Session>(std::make_shared<ws::Router>());
        session->user = user;
        auto s = session;
        Router::setPreviewSessionResolverForTesting([s](const request&) { return s; });
    }

    void asSession(const std::shared_ptr<ws::Session>& s) {
        session = s;
        Router::setPreviewSessionResolverForTesting([s](const request&) { return s; });
    }

    [[nodiscard]] UserPtr userWithVaultRole(const std::string& role) const {
        const auto created = ops::users::create(admin, {.name = "rs_user_" + rsTag(), .role = "unprivileged",
                                                        .password = std::string("Resumable-Upload-Pass-123")});
        (void)ops::roles::assignVaultRole(admin, {.target = {.vault_id = engine->vault->id,
                                                             .subject = {.type = "user", .id = created.user->id}},
                                                  .role = role});
        return vh::identities::manager().user(created.user->id);
    }

    static Response send(const verb method, const std::string& target, const std::string& body = {},
                         const std::vector<std::pair<std::string, std::string>>& headers = {}) {
        request req{method, target, 11};
        for (const auto& [k, v] : headers) req.set(k, v);
        req.body() = body;
        if (method == verb::put || method == verb::post) req.prepare_payload();
        return Router::route(std::move(req));
    }

    [[nodiscard]] Response createSession(json files, const std::string& query = "") const {
        json body = {{"files", std::move(files)}};
        if (query.empty()) body["vault_id"] = engine->vault->id;
        return send(verb::post, "/upload/sessions" + query, body.dump());
    }

    [[nodiscard]] std::string createOk(json files) const {
        const auto res = createSession(std::move(files));
        EXPECT_EQ(statusOf(res), status::created) << jsonOf(res).dump();
        return jsonOf(res).value("upload_id", "");
    }

    static Response part(const std::string& id, const std::string& fileId, const uint64_t offset, const std::string& bytes,
                         const std::vector<std::pair<std::string, std::string>>& headers = {},
                         const std::string& query = "") {
        return send(verb::put, "/upload/sessions/" + id + "/files/" + fileId + "?offset=" + std::to_string(offset) +
                                   query, bytes, headers);
    }

    static json status(const std::string& id, const std::string& query = "") {
        return jsonOf(send(verb::get, "/upload/sessions/" + id + query));
    }

    static Response finish(const std::string& id, const std::string& query = "") {
        return send(verb::post, "/upload/sessions/" + id + "/finish" + query);
    }

    // Finish until it is no longer 202 (commits run on the workers).
    static Response finishDone(const std::string& id, const std::string& query = "") {
        for (int i = 0; i < 120; ++i) {
            auto res = finish(id, query);
            if (statusOf(res) != status::accepted) return res;
        }
        return finish(id, query);
    }

    static json fileStatus(const json& st, const std::string& fileId) {
        for (const auto& f : st.at("files"))
            if (f.at("file_id") == fileId) return f;
        return {};
    }

    // Polls status until the file reaches `state` (or 30 s pass).
    static json waitFileState(const std::string& id, const std::string& fileId, const std::string& state,
                              const std::string& query = "") {
        json f;
        for (int i = 0; i < 3000; ++i) {
            f = fileStatus(status(id, query), fileId);
            if (f.value("state", "") == state) return f;
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
        }
        return f;
    }

    [[nodiscard]] std::shared_ptr<fs::model::File> file(const std::string& path) const {
        return std::dynamic_pointer_cast<fs::model::File>(
            runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path)));
    }

    void write(const std::string& path, const std::string& content) const {
        ASSERT_TRUE(fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                                .buffer = std::vector<uint8_t>(content.begin(), content.end()),
                                                .engine = engine, .user = admin, .overwrite = true}));
    }

    [[nodiscard]] std::string etagOf(const std::string& path) const {
        const auto f = file(path);
        return f ? storage::generationOf(*f).etag() : std::string{};
    }

    // Uploads `size` pattern bytes in parts of `partBytes`, in order.
    static void uploadAll(const std::string& id, const std::string& fileId, const uint64_t size, const uint64_t partBytes,
                          const uint8_t seed = 0) {
        for (uint64_t off = 0; off < size; off += partBytes) {
            const auto n = std::min(partBytes, size - off);
            const auto res = part(id, fileId, off, pattern(off, n, seed));
            ASSERT_EQ(statusOf(res), status::ok) << jsonOf(res).dump();
        }
    }

    // A share link on `rootPath` (upload allowed) and a ready share ws session on it.
    [[nodiscard]] std::shared_ptr<ws::Session> shareSession(const std::string& rootPath,
                                                            const std::optional<uint64_t> maxUpload = std::nullopt) const {
        const auto dir = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(rootPath));
        EXPECT_TRUE(dir);
        share::Manager manager;
        share::Link link;
        link.vault_id = engine->vault->id;
        link.root_entry_id = dir->id;
        link.root_path = rootPath;
        link.target_type = share::TargetType::Directory;
        link.link_type = share::LinkType::Access;
        link.access_mode = share::AccessMode::Public;
        link.allowed_ops = share::bit(share::Operation::Upload) | share::bit(share::Operation::List);
        link.expires_at = std::time(nullptr) + 3600;
        link.max_upload_size_bytes = maxUpload.value_or(64ull << 20);
        link.duplicate_policy = share::DuplicatePolicy::Reject;
        const auto created = manager.createLink(rbac::Actor::human(admin), {
            .link = link,
            .public_role = share::RoleAssignmentRequest{.vault_role_name = rbac::role::Vault::Contributor().name}});
        const auto opened = manager.openPublicSession(created.public_token, std::string("127.0.0.1"), std::string("rs-test"));
        auto principal = manager.resolvePrincipal(opened.session_token, std::string("127.0.0.1"), std::string("rs-test"));
        auto s = std::make_shared<ws::Session>(std::make_shared<ws::Router>());
        s->ipAddress = "127.0.0.1";
        s->userAgent = "rs-test";
        s->setSharePrincipal(std::move(principal), opened.session_token);
        return s;
    }
};

TEST_F(ResumableUploadDbTest, CreateStatusPartsFinishCommitTheExactBytes) {
    const uint64_t big = 300 * 1024 + 17;  // not a multiple of the part size or of the AES block
    auto created = createSession(json::array({
        {{"file_id", "big"}, {"path", "/in/big.bin"}, {"size", big}, {"mime_type", "application/octet-stream"}},
        {{"file_id", "small"}, {"path", "/in/small.txt"}, {"size", 5}, {"if_none_match", "*"}},
        {{"file_id", "empty"}, {"path", "/in/empty.txt"}, {"size", 0}}}));
    ASSERT_EQ(statusOf(created), status::created) << jsonOf(created).dump();
    const auto body = jsonOf(created);
    EXPECT_TRUE(body.at("resumable").get<bool>());
    EXPECT_GT(body.at("expires_at").get<int64_t>(), std::time(nullptr));
    EXPECT_EQ(body.at("part").at("min_bytes"), 1024);
    EXPECT_EQ(body.at("part").at("max_bytes"), 64ull << 20) << "web listener: min(max_part_bytes, http.max_part_bytes)";
    EXPECT_EQ(body.at("part").at("max_in_flight"), 4);
    const auto id = body.at("upload_id").get<std::string>();
    EXPECT_EQ(fileStatus(body, "big").at("state"), "receiving");
    EXPECT_EQ(fileStatus(body, "big").at("ranges"), json::array());

    // Not complete yet: finish says which bytes are missing.
    auto early = finish(id);
    EXPECT_EQ(statusOf(early), status::conflict);
    EXPECT_EQ(codeOf(early), "incomplete");
    EXPECT_EQ(jsonOf(early).at("upload_id"), id);

    const uint64_t partBytes = 64 * 1024;
    for (uint64_t off = 0; off < big; off += partBytes) {
        const auto n = std::min(partBytes, big - off);
        const auto chunk = pattern(off, n);
        const auto res = part(id, "big", off, chunk, {{"Content-Digest", digestHeader(chunk)}});
        ASSERT_EQ(statusOf(res), status::ok) << jsonOf(res).dump();
        const auto ack = jsonOf(res);
        EXPECT_EQ(ack.at("offset"), off);
        EXPECT_EQ(ack.at("length"), n);
        const auto d = crypto::util::EvpDigest::of(EVP_sha256(), chunk.data(), chunk.size());
        std::string hexDigest;
        for (const auto b : d) hexDigest += fmt::format("{:02x}", b);
        EXPECT_EQ(ack.at("sha256"), hexDigest) << "the plaintext digest, as the client computes it";
        EXPECT_NE(headerOf(res, "Server-Timing").find("sync;dur="), std::string::npos);
    }
    ASSERT_EQ(statusOf(part(id, "small", 0, "hello")), status::ok);

    const auto done = finishDone(id);
    ASSERT_EQ(statusOf(done), status::ok) << jsonOf(done).dump();
    const auto st = jsonOf(done);
    EXPECT_EQ(st.at("state"), "complete");
    for (const auto& f : st.at("files")) {
        EXPECT_EQ(f.at("state"), "committed") << f.dump();
        EXPECT_TRUE(f.at("entry").is_object());
    }
    EXPECT_EQ(fileStatus(st, "big").at("received_bytes"), big);
    EXPECT_EQ(fileStatus(st, "big").at("ranges"), json::array({json::array({0, big})}));

    // The committed file decrypts (through the normal positioned reader, and authenticates) to exactly the bytes sent.
    const auto stored = file("/in/big.bin");
    ASSERT_TRUE(stored);
    EXPECT_EQ(stored->size_bytes, big);
    EXPECT_FALSE(stored->encryption_iv.empty());
    EXPECT_TRUE(matchesPattern(engine, stored, big));
    EXPECT_EQ(fileStatus(st, "big").at("entry").at("content_version"), storage::generationOf(*stored).etag());
    // The content hash recorded at commit is the BLAKE2b of the backing file (computed by the sealing cursor).
    EXPECT_EQ(stored->content_hash.value_or(""), crypto::hash::blake2b(stored->backing_path));
    EXPECT_EQ(file("/in/small.txt")->size_bytes, 5u);
    EXPECT_EQ(file("/in/empty.txt")->size_bytes, 0u);

    // Finish is idempotent; nothing is left in the spool.
    EXPECT_EQ(statusOf(finish(id)), status::ok);
    EXPECT_EQ(countFiles(Service::spoolRoot()), 0u);
}

TEST_F(ResumableUploadDbTest, PartsOutOfOrderAndInParallelSealInOrder) {
    const uint64_t partBytes = 32 * 1024, parts = 12, size = partBytes * parts - 100;
    const auto id = createOk(json::array({{{"file_id", "f"}, {"path", "/p/out-of-order.bin"}, {"size", size}}}));
    // The last part first, then the even ones from four threads, then the odd ones in reverse.
    const auto send1 = [&](const uint64_t i) {
        const auto off = i * partBytes;
        const auto res = part(id, "f", off, pattern(off, std::min(partBytes, size - off), 7));
        EXPECT_EQ(statusOf(res), status::ok) << jsonOf(res).dump();
    };
    send1(parts - 1);
    std::vector<std::thread> threads;
    for (uint64_t t = 0; t < 4; ++t)
        threads.emplace_back([&, t] {
            for (uint64_t i = t * 2; i < parts - 1; i += 8) send1(i);
        });
    for (auto& t : threads) t.join();
    const auto mid = fileStatus(status(id), "f");
    EXPECT_EQ(mid.at("state"), "receiving");
    EXPECT_GT(mid.at("ranges").size(), 1u) << "gaps are reported as separate ranges";
    for (uint64_t i = parts - 1; i-- > 0;)
        if (i % 2 == 1) send1(i);
    ASSERT_EQ(statusOf(finishDone(id)), status::ok);
    EXPECT_TRUE(matchesPattern(engine, file("/p/out-of-order.bin"), size, 7));
}

TEST_F(ResumableUploadDbTest, DuplicatePartsAreIdempotentAndConflictsAreRefused) {
    const uint64_t size = 10 * 1024;
    const auto id = createOk(json::array({{{"file_id", "d"}, {"path", "/dup.bin"}, {"size", size}}}));
    const auto first = pattern(0, 4096);
    const auto ack = part(id, "d", 0, first);
    ASSERT_EQ(statusOf(ack), status::ok);

    // The acknowledgement was lost: the client sends the same part again. 200, same digest, nothing changes.
    const auto again = part(id, "d", 0, first);
    EXPECT_EQ(statusOf(again), status::ok) << jsonOf(again).dump();
    EXPECT_EQ(jsonOf(again).at("sha256"), jsonOf(ack).at("sha256"));
    EXPECT_EQ(jsonOf(again).at("received_bytes"), 4096);

    // Same range, different bytes: 409 part_conflict, nothing changes.
    auto other = first;
    other[100] ^= 0x5a;
    const auto conflict = part(id, "d", 0, other);
    EXPECT_EQ(statusOf(conflict), status::conflict);
    EXPECT_EQ(codeOf(conflict), "part_conflict");

    // Partial overlaps (and a different length at the same offset) are 409 part_overlap.
    EXPECT_EQ(codeOf(part(id, "d", 2048, pattern(2048, 4096))), "part_overlap");
    EXPECT_EQ(codeOf(part(id, "d", 0, pattern(0, 2048))), "part_overlap");

    // Rules answered from the header.
    EXPECT_EQ(statusOf(part(id, "d", 9000, pattern(9000, 2000))), status::bad_request) << "past the end";
    EXPECT_EQ(statusOf(part(id, "d", 4096, pattern(4096, 100))), status::bad_request) << "under min_bytes, not last";
    EXPECT_EQ(statusOf(part(id, "d", 4096, "")), status::bad_request) << "empty";
    EXPECT_EQ(statusOf(part(id, "nope", 0, first)), status::not_found);
    EXPECT_EQ(statusOf(send(verb::put, "/upload/sessions/" + id + "/files/d", first)), status::bad_request) << "no offset";
    {
        request noLength{verb::put, "/upload/sessions/" + id + "/files/d?offset=4096", 11};
        auto begun = upload::resumable::beginPart(noLength, std::nullopt);
        ASSERT_TRUE(begun.refusal);
        EXPECT_EQ(statusOf(*begun.refusal), status::length_required);
    }
    transfer([](config::TransferConfig& t) { t.http.max_part_bytes = 2048; });
    EXPECT_EQ(codeOf(part(id, "d", 4096, pattern(4096, 4096))), "part_too_large");
    transfer([](config::TransferConfig& t) { t.http.max_part_bytes = 64ull << 20; });

    // Finish the file; a part resent after sealing compares against the sealed bytes (its part file is gone).
    ASSERT_EQ(statusOf(part(id, "d", 4096, pattern(4096, size - 4096))), status::ok);
    ASSERT_EQ(statusOf(finishDone(id)), status::ok);
    EXPECT_EQ(codeOf(part(id, "d", 0, first)), "file_state") << "a committed file takes no parts";
    EXPECT_TRUE(matchesPattern(engine, file("/dup.bin"), size));
}

TEST_F(ResumableUploadDbTest, ADuplicateOfASealedPartIsComparedWithTheSealedBytes) {
    const uint64_t size = 8192;
    const auto id = createOk(json::array({{{"file_id", "s"}, {"path", "/sealed-dup.bin"}, {"size", size}}}));
    ASSERT_EQ(statusOf(part(id, "s", 0, pattern(0, 4096))), status::ok);
    // Let the cursor seal the first part (its part file is removed once the prefix is durable).
    ASSERT_TRUE(Service::waitIdleForTesting(std::chrono::seconds(30)));
    EXPECT_EQ(statusOf(part(id, "s", 0, pattern(0, 4096))), status::ok);
    auto wrong = pattern(0, 4096);
    wrong[4095] ^= 1;
    EXPECT_EQ(codeOf(part(id, "s", 0, wrong)), "part_conflict");
    ASSERT_EQ(statusOf(part(id, "s", 4096, pattern(4096, 4096))), status::ok);
    ASSERT_EQ(statusOf(finishDone(id)), status::ok);
    EXPECT_TRUE(matchesPattern(engine, file("/sealed-dup.bin"), size));
}

TEST_F(ResumableUploadDbTest, AContentDigestMismatchIsRefusedAndNotRecorded) {
    const auto id = createOk(json::array({{{"file_id", "c"}, {"path", "/digest.bin"}, {"size", 4096}}}));
    const auto bytes = pattern(0, 4096);
    const auto bad = part(id, "c", 0, bytes, {{"Content-Digest", digestHeader("something else")}});
    EXPECT_EQ(statusOf(bad), status::bad_request);
    EXPECT_EQ(codeOf(bad), "digest_mismatch");
    EXPECT_EQ(fileStatus(status(id), "c").at("received_bytes"), 0) << "nothing recorded";
    EXPECT_EQ(statusOf(part(id, "c", 0, bytes, {{"Content-Digest", "sha-256=:notbase64!:"}})), status::bad_request);
    // Other algorithms are ignored; the sha-256 member is checked.
    const auto ok = part(id, "c", 0, bytes, {{"Content-Digest", "sha-512=:AAAA:, " + digestHeader(bytes)}});
    EXPECT_EQ(statusOf(ok), status::ok) << jsonOf(ok).dump();
    ASSERT_EQ(statusOf(finishDone(id)), status::ok);
    EXPECT_TRUE(matchesPattern(engine, file("/digest.bin"), 4096));
}

TEST_F(ResumableUploadDbTest, ARestartResumesReceivingFromTheRowsAndTheSpool) {
    const uint64_t partBytes = 16 * 1024, size = partBytes * 6;
    const auto id = createOk(json::array({{{"file_id", "r"}, {"path", "/restart/r.bin"}, {"size", size}}}));
    for (const uint64_t i : {0, 1, 4})
        ASSERT_EQ(statusOf(part(id, "r", i * partBytes, pattern(i * partBytes, partBytes, 3))), status::ok);
    ASSERT_TRUE(Service::waitIdleForTesting(std::chrono::seconds(30)));
    const auto before = fileStatus(status(id), "r");

    // The daemon "restarts": every in-memory session, cursor and worker is gone; rows and spool stay. A stray
    // unfinished attempt and an orphan session directory are swept by the recovery.
    Service::forgetForTesting();
    { std::ofstream(Service::spoolRoot() / id / "0.999.deadbeef.tmp") << "x"; }
    std::filesystem::create_directories(Service::spoolRoot() / "00000000-0000-4000-8000-000000000000");
    Service::recover();
    EXPECT_FALSE(std::filesystem::exists(Service::spoolRoot() / id / "0.999.deadbeef.tmp"));
    EXPECT_FALSE(std::filesystem::exists(Service::spoolRoot() / "00000000-0000-4000-8000-000000000000"));

    const auto after = fileStatus(status(id), "r");
    EXPECT_EQ(after.at("ranges"), before.at("ranges"));
    EXPECT_EQ(after.at("received_bytes"), 3 * partBytes);
    // A part that was stored before the restart is still idempotent.
    EXPECT_EQ(statusOf(part(id, "r", 4 * partBytes, pattern(4 * partBytes, partBytes, 3))), status::ok);
    for (const uint64_t i : {2, 3, 5})
        ASSERT_EQ(statusOf(part(id, "r", i * partBytes, pattern(i * partBytes, partBytes, 3))), status::ok);
    ASSERT_EQ(statusOf(finishDone(id)), status::ok);
    EXPECT_TRUE(matchesPattern(engine, file("/restart/r.bin"), size, 3));
}

TEST_F(ResumableUploadDbTest, AnInterruptedFinalizationResumesAfterARestart) {
    const uint64_t size = 40 * 1024;
    const auto id = createOk(json::array({{{"file_id", "i"}, {"path", "/restart/final.bin"}, {"size", size}}}));
    Service::holdCommitsForTesting(true);
    uploadAll(id, "i", size, 8192, 9);
    EXPECT_EQ(waitFileState(id, "i", "committing").at("state"), "committing");

    // Finish never holds the request for the commit: 202 + Retry-After while it is pending.
    Service::setFinishWaitForTesting(std::chrono::milliseconds(0));
    const auto pending = finish(id);
    EXPECT_EQ(statusOf(pending), status::accepted);
    EXPECT_EQ(headerOf(pending, "Retry-After"), "1");
    EXPECT_EQ(jsonOf(pending).at("state"), "finalizing");

    Service::forgetForTesting();  // the commit had not run: the sealed file and the "committing" row remain
    EXPECT_FALSE(file("/restart/final.bin"));
    Service::holdCommitsForTesting(false);
    Service::setFinishWaitForTesting(std::chrono::milliseconds(5000));
    Service::recover();
    const auto done = finishDone(id);
    ASSERT_EQ(statusOf(done), status::ok) << jsonOf(done).dump();
    EXPECT_EQ(jsonOf(done).at("state"), "complete");
    EXPECT_TRUE(matchesPattern(engine, file("/restart/final.bin"), size, 9));
}

TEST_F(ResumableUploadDbTest, ExpiredSessionsLoseTheirRowsAndSpool) {
    const auto id = createOk(json::array({{{"file_id", "e"}, {"path", "/expire.bin"}, {"size", 8192}}}));
    ASSERT_EQ(statusOf(part(id, "e", 0, pattern(0, 4096))), status::ok);
    ASSERT_TRUE(Service::waitIdleForTesting(std::chrono::seconds(30)));
    ASSERT_TRUE(std::filesystem::exists(Service::spoolRoot() / id));
    std::filesystem::create_directories(Service::spoolRoot() / "11111111-1111-4111-8111-111111111111");

    const auto later = std::time(nullptr) + 25 * 3600;  // past the 24 h idle TTL
    Service::setClockForTesting([later] { return later; });
    EXPECT_EQ(statusOf(send(verb::get, "/upload/sessions/" + id)), status::not_found) << "expired is gone";
    EXPECT_GE(Service::sweepExpired(), 1u);
    EXPECT_FALSE(db::query::upload::Resumable::exists(id));
    EXPECT_FALSE(std::filesystem::exists(Service::spoolRoot() / id));
    EXPECT_FALSE(std::filesystem::exists(Service::spoolRoot() / "11111111-1111-4111-8111-111111111111"));
}

TEST_F(ResumableUploadDbTest, CancelRemovesTheSessionAndKeepsCommittedFiles) {
    const auto id = createOk(json::array({{{"file_id", "a"}, {"path", "/cancel/a.txt"}, {"size", 3}},
                                          {{"file_id", "b"}, {"path", "/cancel/b.bin"}, {"size", 8192}}}));
    ASSERT_EQ(statusOf(part(id, "a", 0, "abc")), status::ok);
    EXPECT_EQ(waitFileState(id, "a", "committed").at("state"), "committed");
    ASSERT_EQ(statusOf(part(id, "b", 0, pattern(0, 4096))), status::ok);
    const auto res = send(verb::delete_, "/upload/sessions/" + id);
    EXPECT_EQ(statusOf(res), status::no_content);
    EXPECT_EQ(statusOf(send(verb::get, "/upload/sessions/" + id)), status::not_found);
    EXPECT_EQ(statusOf(send(verb::delete_, "/upload/sessions/" + id)), status::not_found);
    EXPECT_FALSE(db::query::upload::Resumable::exists(id));
    EXPECT_FALSE(std::filesystem::exists(Service::spoolRoot() / id));
    EXPECT_TRUE(file("/cancel/a.txt")) << "a file that committed stays";
    EXPECT_FALSE(file("/cancel/b.bin"));
}

TEST_F(ResumableUploadDbTest, QuotaAndSizeLimitsAreCheckedAtCreate) {
    // The legacy lanes stop at 8 GiB; here only the AES-GCM format limit (2^36 - 32) and the vault's space apply.
    // No byte is written: the sizes are declared, and a part far past 8 GiB lands at its offset (a sparse spool).
    constexpr uint64_t kFormatMax = (uint64_t{1} << 36) - 32;
    auto tooBig = createSession(json::array({{{"file_id", "x"}, {"path", "/huge.bin"}, {"size", kFormatMax + 1}}}));
    EXPECT_EQ(statusOf(tooBig), status::payload_too_large);
    EXPECT_EQ(codeOf(tooBig), "file_too_large");

    engine->vault->quota = 1ull << 40;  // 1 TiB, so the space check passes for these declared sizes
    const uint64_t twelveGiB = 12ull << 30;
    const auto id = createOk(json::array({{{"file_id", "g"}, {"path", "/big/12g.bin"}, {"size", twelveGiB}},
                                          {{"file_id", "m"}, {"path", "/big/max.bin"}, {"size", kFormatMax}}}));
    const uint64_t at = 9ull << 30;
    const auto res = part(id, "g", at, pattern(at, 4096));
    ASSERT_EQ(statusOf(res), status::ok) << jsonOf(res).dump();
    EXPECT_EQ(jsonOf(res).at("ranges"), json::array({json::array({at, at + 4096})}));
    const auto last = part(id, "m", kFormatMax - 10, pattern(0, 10));
    EXPECT_EQ(statusOf(last), status::ok) << "the last part of a file may be short";
    EXPECT_EQ(statusOf(send(verb::delete_, "/upload/sessions/" + id)), status::no_content);

    // Over the vault's space: 507, and promised bytes of open sessions count.
    const auto used = (1ull << 40) - engine->freeSpace();  // what the vault holds plus the reserve
    engine->vault->quota = used + (8ull << 20);
    auto over = createSession(json::array({{{"file_id", "q"}, {"path", "/q.bin"}, {"size", 64ull << 20}}}));
    EXPECT_EQ(statusOf(over), status::insufficient_storage);
    EXPECT_EQ(codeOf(over), "insufficient_storage");
    const auto free = engine->freeSpace();
    ASSERT_GT(free, 4096u);
    const auto half = createOk(json::array({{{"file_id", "h"}, {"path", "/h1.bin"}, {"size", free - 1024}}}));
    auto second = createSession(json::array({{{"file_id", "h"}, {"path", "/h2.bin"}, {"size", 2048}}}));
    EXPECT_EQ(statusOf(second), status::insufficient_storage) << "the first session's bytes are reserved";
    EXPECT_FALSE(half.empty());
    engine->vault->quota = 0;

    transfer([](config::TransferConfig& t) { t.max_file_bytes = 1000; });
    EXPECT_EQ(codeOf(createSession(json::array({{{"path", "/l.bin"}, {"size", 1001}}}))), "file_too_large");
}

TEST_F(ResumableUploadDbTest, AKeyRotationBeforeTheCommitFailsTheFileWithKeyRotated) {
    const auto id = createOk(json::array({{{"file_id", "k"}, {"path", "/rot/k.bin"}, {"size", 8192}},
                                          {{"file_id", "j"}, {"path", "/rot/j.bin"}, {"size", 8192}}}));
    Service::holdCommitsForTesting(true);
    uploadAll(id, "k", 8192, 4096);
    EXPECT_EQ(waitFileState(id, "k", "committing").at("state"), "committing");
    ASSERT_EQ(statusOf(part(id, "j", 0, pattern(0, 4096))), status::ok);

    engine->encryptionManager->prepare_key_rotation();
    engine->encryptionManager->finish_key_rotation();

    // A part for a file created under the old key is refused, and the file fails.
    const auto refused = part(id, "j", 4096, pattern(4096, 4096));
    EXPECT_EQ(statusOf(refused), status::conflict);
    EXPECT_EQ(codeOf(refused), "file_state");
    Service::holdCommitsForTesting(false);
    const auto done = finishDone(id);
    ASSERT_EQ(statusOf(done), status::ok);
    const auto st = jsonOf(done);
    EXPECT_EQ(st.at("state"), "failed");
    for (const auto* f : {"k", "j"}) {
        EXPECT_EQ(fileStatus(st, f).at("state"), "failed");
        EXPECT_EQ(fileStatus(st, f).at("error").at("code"), "key_rotated");
    }
    EXPECT_FALSE(file("/rot/k.bin"));
}

TEST_F(ResumableUploadDbTest, AnotherUsersSessionIsNotFound) {
    const auto id = createOk(json::array({{{"file_id", "o"}, {"path", "/own.bin"}, {"size", 4096}}}));
    as(userWithVaultRole("editor"));
    EXPECT_EQ(statusOf(send(verb::get, "/upload/sessions/" + id)), status::not_found);
    EXPECT_EQ(statusOf(part(id, "o", 0, pattern(0, 4096))), status::not_found);
    EXPECT_EQ(statusOf(finish(id)), status::not_found);
    EXPECT_EQ(statusOf(send(verb::delete_, "/upload/sessions/" + id)), status::not_found);
    EXPECT_EQ(statusOf(send(verb::get, "/upload/sessions/not-a-session")), status::not_found);

    // A reader may not create; no session at all is 401.
    as(userWithVaultRole("reader"));
    EXPECT_EQ(statusOf(createSession(json::array({{{"path", "/r.bin"}, {"size", 1}}}))), status::forbidden);
    Router::setPreviewSessionResolverForTesting([](const request&) -> std::shared_ptr<ws::Session> {
        throw std::runtime_error("Refresh token not set");
    });
    EXPECT_EQ(statusOf(createSession(json::array({{{"path", "/r.bin"}, {"size", 1}}}))), status::unauthorized);
    EXPECT_EQ(statusOf(send(verb::get, "/upload/sessions/" + id)), status::unauthorized);
    as(admin);
    EXPECT_EQ(fileStatus(status(id), "o").at("state"), "receiving") << "untouched";
}

TEST_F(ResumableUploadDbTest, PreconditionsRejectCreateOnlyAndIfMatch) {
    engine->mkdir("/pre", admin);
    write("/pre/existing.txt", "old\n");
    const auto v1 = etagOf("/pre/existing.txt");
    engine->mkdir("/pre/dir", admin);

    // At create: reject → 409 already_exists, create-only → 412 + ETag, a folder → 409 conflict, stale if_match → 412.
    auto rejected = createSession(json::array({{{"file_id", "x"}, {"path", "/pre/existing.txt"}, {"size", 1}}}));
    EXPECT_EQ(statusOf(rejected), status::conflict);
    EXPECT_EQ(codeOf(rejected), "already_exists");
    auto createOnly = createSession(json::array({{{"path", "/pre/existing.txt"}, {"size", 1}, {"if_none_match", "*"}}}));
    EXPECT_EQ(statusOf(createOnly), status::precondition_failed);
    EXPECT_EQ(headerOf(createOnly, "ETag"), v1);
    EXPECT_EQ(codeOf(createSession(json::array({{{"path", "/pre/dir"}, {"size", 1}}}))), "conflict");
    auto stale = createSession(json::array({{{"path", "/pre/existing.txt"}, {"size", 1}, {"if_match", "\"g1-0000\""}}}));
    EXPECT_EQ(statusOf(stale), status::precondition_failed);
    EXPECT_EQ(headerOf(stale, "ETag"), v1);
    EXPECT_EQ(statusOf(createSession(json::array({{{"path", "/x"}, {"size", 1}, {"if_none_match", "*"},
                                                   {"if_match", v1}}}))), status::bad_request);
    EXPECT_EQ(statusOf(createSession(json::array({{{"path", "/x"}, {"size", 1}, {"duplicate_policy", "rename"}}}))),
              status::bad_request);

    // if_match replaces with a compare-and-swap; the entry keeps its id.
    const auto entryId = file("/pre/existing.txt")->id;
    const auto replace = createOk(json::array({{{"file_id", "r"}, {"path", "/pre/existing.txt"}, {"size", 4},
                                                {"if_match", v1}}}));
    ASSERT_EQ(statusOf(part(replace, "r", 0, "new\n")), status::ok);
    const auto replaced = finishDone(replace);
    ASSERT_EQ(statusOf(replaced), status::ok) << jsonOf(replaced).dump();
    EXPECT_EQ(fileStatus(jsonOf(replaced), "r").at("state"), "committed");
    EXPECT_EQ(file("/pre/existing.txt")->id, entryId);
    EXPECT_NE(etagOf("/pre/existing.txt"), v1);

    // A target that appears (or changes) between create and commit fails that file, never silently.
    Service::holdCommitsForTesting(true);
    const auto v2 = etagOf("/pre/existing.txt");
    const auto race = createOk(json::array({
        {{"file_id", "rej"}, {"path", "/pre/later-a.txt"}, {"size", 2}},
        {{"file_id", "cre"}, {"path", "/pre/later-b.txt"}, {"size", 2}, {"if_none_match", "*"}},
        {{"file_id", "cas"}, {"path", "/pre/existing.txt"}, {"size", 2}, {"if_match", v2}},
        {{"file_id", "ok"}, {"path", "/pre/fine.txt"}, {"size", 2}}}));
    for (const auto* f : {"rej", "cre", "cas", "ok"}) ASSERT_EQ(statusOf(part(race, f, 0, "zz")), status::ok);
    for (const auto* f : {"rej", "cre", "cas", "ok"}) EXPECT_EQ(waitFileState(race, f, "committing").at("state"), "committing");
    write("/pre/later-a.txt", "someone else\n");
    write("/pre/later-b.txt", "someone else\n");
    write("/pre/existing.txt", "changed meanwhile\n");
    Service::holdCommitsForTesting(false);
    const auto raced = jsonOf(finishDone(race));
    EXPECT_EQ(raced.at("state"), "failed");
    EXPECT_EQ(fileStatus(raced, "rej").at("error").at("code"), "already_exists");
    EXPECT_EQ(fileStatus(raced, "cre").at("error").at("code"), "precondition_failed");
    EXPECT_EQ(fileStatus(raced, "cre").at("error").at("etag"), etagOf("/pre/later-b.txt"));
    EXPECT_EQ(fileStatus(raced, "cas").at("error").at("code"), "precondition_failed");
    EXPECT_EQ(fileStatus(raced, "ok").at("state"), "committed");
    // Nothing of theirs was overwritten.
    auto reader = engine->openPlaintextReader(file("/pre/later-a.txt"));
    EXPECT_EQ(reader->size(), std::string("someone else\n").size());
}

TEST_F(ResumableUploadDbTest, AccessIsCheckedAgainAtCommit) {
    const auto editor = userWithVaultRole("editor");
    as(editor);
    Service::holdCommitsForTesting(true);
    const auto id = createOk(json::array({{{"file_id", "v"}, {"path", "/revoked.bin"}, {"size", 4}}}));
    ASSERT_EQ(statusOf(part(id, "v", 0, "abcd")), status::ok);
    EXPECT_EQ(waitFileState(id, "v", "committing").at("state"), "committing");
    (void)ops::roles::unassignVaultRole(admin, {.vault_id = engine->vault->id,
                                                .subject = {.type = "user", .id = editor->id}});
    Service::holdCommitsForTesting(false);
    as(vh::identities::manager().user(editor->id));
    const auto st = jsonOf(finishDone(id));
    EXPECT_EQ(fileStatus(st, "v").at("error").at("code"), "forbidden");
    EXPECT_FALSE(file("/revoked.bin"));
}

TEST_F(ResumableUploadDbTest, ShareSessionsAreScopedToTheirShareAndItsLimits) {
    engine->mkdir("/drop", admin);
    engine->mkdir("/drop/sub", admin);
    const auto share = shareSession("/drop", 16 * 1024);
    asSession(share);
    const std::string q = "?share=1";

    // Share-relative paths; the link's max_upload_size_bytes caps each file.
    auto tooBig = createSession(json::array({{{"file_id", "t"}, {"path", "/big.bin"}, {"size", 16 * 1024 + 1}}}), q);
    EXPECT_EQ(statusOf(tooBig), status::forbidden) << jsonOf(tooBig).dump();
    auto replace = createSession(json::array({{{"path", "/x.txt"}, {"size", 1}, {"if_match", "\"g1-x\""}}}), q);
    EXPECT_EQ(statusOf(replace), status::forbidden);

    auto created = createSession(json::array({{{"file_id", "s"}, {"path", "/sub/from-share.bin"}, {"size", 8192}}}), q);
    ASSERT_EQ(statusOf(created), status::created) << jsonOf(created).dump();
    const auto id = jsonOf(created).at("upload_id").get<std::string>();
    EXPECT_EQ(fileStatus(jsonOf(created), "s").at("path"), "/sub/from-share.bin");
    EXPECT_FALSE(fileStatus(jsonOf(created), "s").at("transfer_id").get<std::string>().empty());

    // Without ?share=1, as a human, or as another share session: 404 (or 401 for the missing lane).
    EXPECT_NE(statusOf(send(verb::get, "/upload/sessions/" + id)), status::ok);
    as(admin);
    EXPECT_EQ(statusOf(send(verb::get, "/upload/sessions/" + id)), status::not_found);
    asSession(shareSession("/drop"));
    EXPECT_EQ(statusOf(send(verb::get, "/upload/sessions/" + id + q)), status::not_found);
    EXPECT_EQ(statusOf(part(id, "s", 0, pattern(0, 4096), {}, "&share=1")), status::not_found);

    asSession(share);
    ASSERT_EQ(statusOf(part(id, "s", 0, pattern(0, 4096), {}, "&share=1")), status::ok);
    ASSERT_EQ(statusOf(part(id, "s", 4096, pattern(4096, 4096), {}, "&share=1")), status::ok);
    const auto done = finishDone(id, q);
    ASSERT_EQ(statusOf(done), status::ok) << jsonOf(done).dump();
    const auto f = fileStatus(jsonOf(done), "s");
    EXPECT_EQ(f.at("state"), "committed") << f.dump();
    EXPECT_EQ(f.at("entry").at("path"), "/sub/from-share.bin") << "share callers see share-relative paths only";
    const auto stored = file("/drop/sub/from-share.bin");
    ASSERT_TRUE(stored);
    EXPECT_TRUE(matchesPattern(engine, stored, 8192));
    EXPECT_EQ(stored->created_by, admin->id) << "committed as the link's creator";

    // An existing target is refused at create (the link's duplicate policy is reject).
    auto dup = createSession(json::array({{{"path", "/sub/from-share.bin"}, {"size", 1}}}), q);
    EXPECT_EQ(codeOf(dup), "already_exists");
}

TEST_F(ResumableUploadDbTest, AParallelPartBeyondTheLimitIs429) {
    const auto id = createOk(json::array({{{"file_id", "f"}, {"path", "/inflight.bin"}, {"size", 64 * 1024}}}));
    transfer([](config::TransferConfig& t) { t.max_parts_in_flight = 1; });
    request first{verb::put, "/upload/sessions/" + id + "/files/f?offset=0", 11};
    auto begun = upload::resumable::beginPart(first, 4096);
    ASSERT_FALSE(begun.refusal);
    const auto busy = part(id, "f", 8192, pattern(8192, 4096));
    EXPECT_EQ(statusOf(busy), status::too_many_requests);
    EXPECT_EQ(codeOf(busy), "too_many_parts_in_flight");
    EXPECT_EQ(headerOf(busy, "Retry-After"), "1");
    EXPECT_EQ(codeOf(part(id, "f", 0, pattern(0, 4096))), "part_overlap") << "the range itself is being received";
    // An abandoned part (the connection dropped) frees its range and slot, and records nothing.
    begun.part.write(pattern(0, 100).data(), 100);
    begun = {};
    EXPECT_EQ(statusOf(part(id, "f", 0, pattern(0, 4096))), status::ok);
}

// A file well past 100 MB in many parts (the default 1 MiB minimum), and one 256 MiB part streamed through a real
// HTTP session: resident memory stays flat (it would grow by the part size if anything buffered the body).
TEST_F(ResumableUploadDbTest, LargeFilesInManyPartsAndALargePartInBoundedMemory) {
    transfer([](config::TransferConfig& t) {
        t = config::TransferConfig{};
        t.http.max_part_bytes = 512ull << 20;
    });
    constexpr uint64_t kSize = 112ull << 20, kPart = 8ull << 20;
    const auto id = createOk(json::array({{{"file_id", "many"}, {"path", "/large/many.bin"}, {"size", kSize}}}));
    uploadAll(id, "many", kSize, kPart, 5);
    ASSERT_EQ(statusOf(finishDone(id)), status::ok);
    EXPECT_TRUE(matchesPattern(engine, file("/large/many.bin"), kSize, 5));

    constexpr uint64_t kBig = 256ull << 20;
    const auto big = createOk(json::array({{{"file_id", "one"}, {"path", "/large/one-part.bin"}, {"size", kBig}}}));
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
    const auto head = "PUT /upload/sessions/" + big + "/files/one?offset=0 HTTP/1.1\r\nHost: test\r\n"
                      "Cookie: refresh=test\r\nContent-Length: " + std::to_string(kBig) + "\r\nConnection: close\r\n\r\n";
    asio::write(client, asio::buffer(head));
    for (uint64_t off = 0; off < kBig; off += 1 << 20) {
        const auto chunk = pattern(off, 1 << 20, 6);
        asio::write(client, asio::buffer(chunk));
    }
    asio::streambuf response;
    boost::system::error_code ec;
    asio::read(client, response, ec);
    const auto growth = sampler.finish();
    client.close(ec);
    serverThread.join();
    const std::string raw{asio::buffers_begin(response.data()), asio::buffers_end(response.data())};
    ASSERT_TRUE(raw.starts_with("HTTP/1.1 200")) << raw.substr(0, 400);
    EXPECT_NE(raw.find("Server-Timing"), std::string::npos);
    EXPECT_LT(growth, 64ull << 20) << "resident memory grew by " << (growth >> 20) << " MiB for a 256 MiB part";

    RssSampler sealSampler;
    ASSERT_EQ(statusOf(finishDone(big)), status::ok);
    const auto sealGrowth = sealSampler.finish();
    EXPECT_LT(sealGrowth, 64ull << 20) << "sealing and commit grew resident memory by " << (sealGrowth >> 20) << " MiB";
    EXPECT_TRUE(matchesPattern(engine, file("/large/one-part.bin"), kBig, 6));
}

// ---- benchmarks (DISABLED_: run with --gtest_also_run_disabled_tests --gtest_filter='*DISABLED_ResumableBench*') --

namespace {

struct BenchResult {
    double partsSeconds{};
    double finalizeSeconds{};
};

}

class DISABLED_ResumableBench : public ResumableUploadDbTest {
protected:
    BenchResult runResumable(const std::string& path, const uint64_t size, const uint64_t partBytes) {
        transfer([](config::TransferConfig& t) {
            t = config::TransferConfig{};
            t.max_part_bytes = 512ull << 20;
            t.http.max_part_bytes = 512ull << 20;
        });
        const auto id = createOk(json::array({{{"file_id", "b"}, {"path", path}, {"size", size}}}));
        const auto chunk = pattern(0, partBytes, 1);
        const auto t0 = std::chrono::steady_clock::now();
        for (uint64_t off = 0; off < size; off += partBytes) {
            request req{verb::put, "/upload/sessions/" + id + "/files/b?offset=" + std::to_string(off), 11};
            auto begun = upload::resumable::beginPart(req, std::min(partBytes, size - off));
            EXPECT_FALSE(begun.refusal);
            for (uint64_t p = 0; p < std::min(partBytes, size - off); p += 1 << 20)
                begun.part.write(chunk.data() + p, static_cast<std::size_t>(std::min<uint64_t>(1 << 20, partBytes - p)));
            EXPECT_EQ(statusOf(begun.part.finish(req, {})), status::ok);
        }
        const auto t1 = std::chrono::steady_clock::now();
        Service::setFinishWaitForTesting(std::chrono::milliseconds(60'000));
        EXPECT_EQ(statusOf(finishDone(id)), status::ok);
        const auto t2 = std::chrono::steady_clock::now();
        return {std::chrono::duration<double>(t1 - t0).count(), std::chrono::duration<double>(t2 - t1).count()};
    }

    BenchResult runLegacy(const std::string& path, const uint64_t size) {
        request createReq{verb::post, "/upload/session", 11};
        upload::Coordinator::setSessionResolverForTesting([s = session](const request&) { return s; });
        const auto created = upload::Coordinator::instance().createSession(createReq, {
            {"vault_id", engine->vault->id}, {"files", json::array({{{"file_id", "l"}, {"path", path}, {"size", size}}})}});
        const auto uploadId = created.at("upload_id").get<std::string>();
        const auto chunk = pattern(0, 1 << 20, 1);
        const auto t0 = std::chrono::steady_clock::now();
        {
            request putReq{verb::put, "/upload/" + uploadId + "/files/l", 11};
            auto stream = upload::Coordinator::instance().beginFile(putReq, size);
            for (uint64_t off = 0; off < size; off += 1 << 20) stream.write(chunk.data(), chunk.size());
            (void)stream.finish();
        }
        const auto t1 = std::chrono::steady_clock::now();
        request finishReq{verb::post, "/upload/" + uploadId + "/finish", 11};
        (void)upload::Coordinator::instance().finishSession(finishReq, uploadId);
        const auto t2 = std::chrono::steady_clock::now();
        upload::Coordinator::resetSessionResolverForTesting();
        return {std::chrono::duration<double>(t1 - t0).count(), std::chrono::duration<double>(t2 - t1).count()};
    }
};

TEST_F(DISABLED_ResumableBench, OneGiBInPartsVersusTheLegacyLane) {
    const uint64_t size = std::getenv("VH_BENCH_BYTES") ? std::stoull(std::getenv("VH_BENCH_BYTES")) : (1ull << 30);
    const auto mib = static_cast<double>(size) / (1 << 20);
    const auto report = [&](const char* name, const BenchResult& r) {
        std::cout << "[bench] " << name << ": parts " << r.partsSeconds << " s (" << mib / r.partsSeconds
                  << " MiB/s), finalize " << r.finalizeSeconds * 1000 << " ms, end-to-end "
                  << mib / (r.partsSeconds + r.finalizeSeconds) << " MiB/s" << std::endl;
    };
    report("resumable 64 MiB parts", runResumable("/bench/r64.bin", size, 64ull << 20));
    report("resumable 256 MiB parts", runResumable("/bench/r256.bin", size, 256ull << 20));
    report("legacy /upload/session", runLegacy("/bench/legacy.bin", size));
}

}
