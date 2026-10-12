// `vh fs ls|get|put` (#229): the transfer protocol's bounds and codec, the client's local plan, and the daemon handlers
// over a real socketpair against real vaults, users and RBAC: allow/deny parity with the HTTP lanes (no existence
// oracle), overwrite policy, malformed/cancelled/oversized transfers, revocation mid-stream, and staging hygiene.
#include "db/Transactions.hpp"
#include "fs/Filesystem.hpp"
#include "fs/cache/Registry.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Roles.hpp"
#include "ops/Users.hpp"
#include "ops/Vaults.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/SocketIO.hpp"
#include "protocols/shell/Transfer.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/shell/commands/fs.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "storage/PlaintextReader.hpp"
#include "UsageManager.hpp"
#include "vault/model/Vault.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <random>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <unistd.h>

namespace vh::protocols::shell::test_cli_fs {

namespace tx = transfer;
using UserPtr = std::shared_ptr<identities::User>;

std::vector<uint8_t> randomBytes(const std::size_t n, const unsigned seed) {
    std::vector<uint8_t> out(n);
    std::mt19937 rng(seed);
    for (auto& b : out) b = static_cast<uint8_t>(rng());
    return out;
}

// ------------------------------------------------------------------------------------------- protocol, no DB ----

TEST(CliTransferProtocol, Base64RoundTripsEverySizeUpToAChunk) {
    for (const std::size_t n : {std::size_t{0}, std::size_t{1}, std::size_t{2}, std::size_t{3}, std::size_t{4},
                                std::size_t{255}, std::size_t{1000}, tx::kChunkBytes - 1, tx::kChunkBytes}) {
        const auto bytes = randomBytes(n, static_cast<unsigned>(n));
        const auto encoded = tx::encode(bytes);
        EXPECT_LE(encoded.size(), tx::kMaxChunkEncoded);
        const auto decoded = tx::decodeChunk(encoded);
        ASSERT_TRUE(decoded.has_value()) << n;
        EXPECT_EQ(*decoded, bytes) << n;
    }
    EXPECT_EQ(tx::encode(std::vector<uint8_t>{'f', 'o', 'o', 'b'}), "Zm9vYg==");
}

TEST(CliTransferProtocol, DecodeIsStrictAndBoundedBeforeAllocating) {
    EXPECT_FALSE(tx::decodeChunk("Zm9vY"));        // not a multiple of 4
    EXPECT_FALSE(tx::decodeChunk("Zm9v\nYg=="));   // whitespace
    EXPECT_FALSE(tx::decodeChunk("Zm=vYg=="));     // padding in the middle
    EXPECT_FALSE(tx::decodeChunk("Zm9vY=g="));     // "x=y=" in the last quartet
    EXPECT_FALSE(tx::decodeChunk("Zm9vYh=="));     // non-zero trailing bits (non-canonical)
    EXPECT_FALSE(tx::decodeChunk("Zm9v*g=="));     // outside the alphabet
    // One quartet past the largest chunk: refused on its length, without decoding.
    EXPECT_FALSE(tx::decodeChunk(std::string(tx::kMaxChunkEncoded + 4, 'A')));
    // The largest encoded size is accepted only while it decodes to at most a chunk.
    EXPECT_TRUE(tx::decodeChunk(tx::encode(randomBytes(tx::kChunkBytes, 1))));
}

TEST(CliTransferProtocol, AnOversizedFrameIsRefusedFromItsLengthAlone) {
    int fds[2];
    ASSERT_EQ(::socketpair(AF_UNIX, SOCK_STREAM, 0, fds), 0);
    // Announce a frame one byte over the transfer limit and send nothing else: the reader must refuse at once instead
    // of allocating the body or waiting for it.
    const uint32_t len = htonl(tx::kMaxTransferFrameBytes + 1);
    ASSERT_EQ(::send(fds[1], &len, 4, 0), 4);
    const auto started = std::chrono::steady_clock::now();
    EXPECT_THROW((void)SocketIO::recv_json(fds[0], tx::kMaxTransferFrameBytes), std::runtime_error);
    EXPECT_LT(std::chrono::steady_clock::now() - started, std::chrono::seconds(1));
    ::close(fds[0]);
    ::close(fds[1]);
}

TEST(CliTransferProtocol, TheClientPlansTheLocalSideLikeTheDaemonParses) {
    using Kind = tx::LocalPlan::Kind;
    auto plan = tx::planLocal({"fs", "get", "42", "/a/b.bin", "-o", "b.bin"});
    EXPECT_EQ(plan.kind, Kind::Get);
    EXPECT_EQ(plan.local, "b.bin");
    EXPECT_TRUE(plan.error.empty());

    plan = tx::planLocal({"fs", "download", "photos", "/x", "--owner", "alice", "--output", "-"});
    EXPECT_EQ(plan.kind, Kind::Get);
    EXPECT_TRUE(plan.local.empty());
    EXPECT_TRUE(plan.explicitStdout);

    plan = tx::planLocal({"fs", "get", "42", "/x"});
    EXPECT_TRUE(plan.local.empty());
    EXPECT_FALSE(plan.explicitStdout);

    plan = tx::planLocal({"fs", "put", "42", "-", "/logs/today.log"});
    EXPECT_EQ(plan.kind, Kind::Put);
    EXPECT_EQ(plan.local, "-");

    plan = tx::planLocal({"fs", "upload", "42", "./q3.pdf", "/q3.pdf", "--overwrite"});
    EXPECT_EQ(plan.local, "./q3.pdf");

    // The daemon's parser gives a flag the next word as its value; the client must agree, so this is a usage error
    // on both sides rather than the client reading a different local file than the daemon expects.
    plan = tx::planLocal({"fs", "put", "--overwrite", "42", "a.bin", "/a.bin"});
    EXPECT_FALSE(plan.error.empty());
    // "--" ends the options.
    plan = tx::planLocal({"fs", "put", "42", "--", "-weird-name", "/w"});
    EXPECT_EQ(plan.local, "-weird-name");

    EXPECT_FALSE(tx::planLocal({"fs", "get", "42"}).error.empty());
    EXPECT_FALSE(tx::planLocal({"fs", "get", "42", "/x", "-o"}).error.empty());
    EXPECT_FALSE(tx::planLocal({"fs", "put", "42", "a", "/a", "-o", "x"}).error.empty());
    EXPECT_EQ(tx::planLocal({"fs", "ls", "42", "/"}).kind, Kind::None);
    EXPECT_EQ(tx::planLocal({"vault", "get", "42"}).kind, Kind::None);
}

// ---------------------------------------------------------------------------------------- handlers, DB-backed ----

std::string tag() {
    return std::to_string(::getpid()) + "_" +
           std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 1'000'000'000);
}

struct SocketPair {
    int daemon{-1}, client{-1};
    SocketPair() {
        int fds[2];
        if (::socketpair(AF_UNIX, SOCK_STREAM, 0, fds) != 0) throw std::runtime_error("socketpair");
        daemon = fds[0];
        client = fds[1];
        // The CLI server's bounds (protocols/shell/Server.hpp): the tests never hang on a broken handler.
        const timeval rcv{.tv_sec = 10, .tv_usec = 0}, snd{.tv_sec = 30, .tv_usec = 0};
        ::setsockopt(daemon, SOL_SOCKET, SO_RCVTIMEO, &rcv, sizeof rcv);
        ::setsockopt(daemon, SOL_SOCKET, SO_SNDTIMEO, &snd, sizeof snd);
        ::setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, &snd, sizeof snd);
    }
    ~SocketPair() {
        if (daemon >= 0) ::close(daemon);
        if (client >= 0) ::close(client);
    }
};

struct Outcome {
    int exit{-1};
    std::string out, err;
    bool sawTransfer{false};
    std::vector<uint8_t> bytes;
    uint64_t chunks{0};
};

class CliFsDbTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::filesystem::path root;
    inline static UserPtr admin, reader, plain, writer;
    inline static std::shared_ptr<storage::Engine> vaultA, vaultB;
    inline static std::shared_ptr<Router> router;
    inline static std::vector<uint8_t> big;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            return;
        }
        paths::enableTestMode();
        root = std::filesystem::temp_directory_path() / ("vh_cli_fs_" + tag());
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
        if (!runtime::Deps::get().shellUsageManager)
            runtime::Deps::get().shellUsageManager = std::make_shared<UsageManager>();
        router = std::make_shared<Router>();
        commands::registerAllCommands(router);

        admin = identities::manager().userByName("admin");
        const auto a = ops::vaults::create(admin, {.name = "fa_" + tag(), .type = vault::model::VaultType::Local});
        const auto b = ops::vaults::create(admin, {.name = "fb_" + tag(), .type = vault::model::VaultType::Local});
        vaultA = runtime::Deps::get().storageManager->getEngine(a->id);
        vaultB = runtime::Deps::get().storageManager->getEngine(b->id);

        reader = makeUser("reader");
        plain = makeUser("plain");
        writer = makeUser("writer");
        grant(reader, a->id, "reader");
        grant(writer, a->id, "editor");

        big = randomBytes(9 * 1024 * 1024 + 77, 7);  // 37 chunks: past the 32-chunk re-authorization point
        write(vaultA, "/big.bin", big);
        const std::string note = "hello from the vault\n";
        write(vaultA, "/docs/note.txt", {note.begin(), note.end()});
        write(vaultB, "/other.bin", randomBytes(1000, 3));
    }

    static void TearDownTestSuite() {
        std::error_code ec;
        if (!root.empty()) std::filesystem::remove_all(root, ec);
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
    }

    static UserPtr makeUser(const std::string& prefix) {
        const auto created = ops::users::create(admin, {.name = prefix + "_" + tag(), .role = "unprivileged",
                                                        .password = std::string("Cli-Fs-Pass-123")});
        return identities::manager().user(created.user->id);
    }

    static void grant(UserPtr& user, const uint32_t vaultId, const std::string& role) {
        (void)ops::roles::assignVaultRole(admin, {.target = {.vault_id = vaultId, .subject = {.type = "user", .id = user->id}},
                                                  .role = role});
        user = identities::manager().user(user->id);
    }

    static void revoke(const UserPtr& user, const uint32_t vaultId) {
        (void)ops::roles::unassignVaultRole(admin, {.vault_id = vaultId, .subject = {.type = "user", .id = user->id}});
    }

    static void write(const std::shared_ptr<storage::Engine>& engine, const std::string& path,
                      const std::vector<uint8_t>& bytes) {
        (void)fs::Filesystem::mkdir({.path = engine->vaultPathToFusePath(std::filesystem::path(path).parent_path()),
                                     .engine = engine, .user = admin});
        (void)fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path),
                                          .buffer = bytes, .engine = engine, .user = admin, .overwrite = true});
    }

    static std::optional<std::vector<uint8_t>> stored(const std::shared_ptr<storage::Engine>& engine,
                                                      const std::string& path) {
        const auto entry = runtime::Deps::get().fsCache->getEntry(engine->vaultPathToFusePath(path));
        const auto file = std::dynamic_pointer_cast<fs::model::File>(entry);
        if (!file) return std::nullopt;
        auto reader = engine->openPlaintextReader(file);
        return storage::readAll(*reader, 64ull << 20);
    }

    static std::size_t stagingLeftovers() {
        std::size_t n = 0;
        std::error_code ec;
        for (const auto& e : std::filesystem::directory_iterator(paths::getBackingPath() / ".cli-staging", ec))
            if (e.path().extension() == ".part") ++n;
        return n;
    }

    static std::string a(const std::string& rest) { return std::to_string(vaultA->vault->id) + " " + rest; }
    static std::string b(const std::string& rest) { return std::to_string(vaultB->vault->id) + " " + rest; }

    // Runs `line` as `user` the way the CLI server does (handler on its own thread, the client on this one).
    // onChunk sees each received data frame's index; the handler's result is returned whatever the transfer did.
    static Outcome get(const UserPtr& user, const std::string& line, const bool withTransfer = true,
                       const std::function<void(uint64_t)>& onChunk = {}) {
        SocketPair pair;
        auto handler = std::async(std::launch::async, [&] {
            CommandResult r;
            try {
                r = router->executeLine(line, user, nullptr,
                                        withTransfer ? std::make_optional(TransferPeer{.fd = pair.daemon, .putSize = std::nullopt}) : std::nullopt);
            } catch (const std::exception& e) {
                r = {-1, "", e.what()};
            }
            ::shutdown(pair.daemon, SHUT_WR);
            return r;
        });
        Outcome out;
        try {
            for (;;) {
                const auto frame = SocketIO::recv_json(pair.client, tx::kMaxTransferFrameBytes);
                if (frame.value("type", "") == "transfer") out.sawTransfer = true;
                if (frame.value("type", "") == "data") {
                    const auto bytes = tx::decodeChunk(frame["b64"].get<std::string>());
                    EXPECT_TRUE(bytes.has_value());
                    EXPECT_EQ(frame["seq"].get<uint64_t>(), out.chunks);
                    out.bytes.insert(out.bytes.end(), bytes->begin(), bytes->end());
                    if (onChunk) onChunk(out.chunks);
                    ++out.chunks;
                }
            }
        } catch (const std::exception&) {}  // EOF once the handler is done
        const auto r = handler.get();
        out.exit = r.exit_code;
        out.out = r.stdout_text;
        out.err = r.stderr_text;
        return out;
    }

    enum class Send { Normal, BadSeq, Abort, HangUp, Extra, Oversized, Short };

    static Outcome put(const UserPtr& user, const std::string& line, const std::vector<uint8_t>& bytes,
                       const Send how = Send::Normal, const std::function<void()>& onReady = {}) {
        SocketPair pair;
        auto handler = std::async(std::launch::async, [&] {
            CommandResult r;
            try {
                r = router->executeLine(line, user, nullptr,
                                        TransferPeer{.fd = pair.daemon, .putSize = bytes.size()});
            } catch (const std::exception& e) {
                r = {-1, "", e.what()};
            }
            ::shutdown(pair.daemon, SHUT_RDWR);
            return r;
        });
        Outcome out;
        try {
            const auto ready = SocketIO::recv_json(pair.client, tx::kMaxTransferFrameBytes);
            out.sawTransfer = ready.value("type", "") == "transfer-ready";
        } catch (const std::exception&) {}
        if (out.sawTransfer) {
            if (onReady) onReady();
            std::size_t off = 0;
            uint64_t seq = 0;
            const auto data = [&](const std::size_t from, const std::size_t n, const uint64_t s) {
                return SocketIO::send_json(pair.client, {{"type", "data"}, {"seq", s},
                    {"b64", tx::encode(std::span(bytes.data() + from, n))}});
            };
            bool ok = true;
            while (ok && off < bytes.size()) {
                const auto n = std::min(tx::kChunkBytes, bytes.size() - off);
                if (how == Send::BadSeq && seq == 1) { ok = data(off, n, seq + 5); break; }
                if (how == Send::HangUp && seq == 1) { ::shutdown(pair.client, SHUT_RDWR); ok = false; break; }
                if (how == Send::Abort && seq == 1) { ok = SocketIO::send_json(pair.client, {{"type", "transfer-abort"}}); break; }
                if (how == Send::Short && off + n >= bytes.size()) break;
                ok = data(off, n, seq++);
                off += n;
            }
            if (how == Send::Extra) ok = ok && data(0, 1, seq++);
            if (how == Send::Oversized) {
                const uint32_t len = htonl(tx::kMaxTransferFrameBytes + 1);
                (void)::send(pair.client, &len, 4, MSG_NOSIGNAL);
            }
            if (ok && (how == Send::Normal || how == Send::Short || how == Send::Extra))
                (void)SocketIO::send_json(pair.client, {{"type", "transfer-end"}, {"bytes", bytes.size()}});
        }
        const auto r = handler.get();
        out.exit = r.exit_code;
        out.out = r.stdout_text;
        out.err = r.stderr_text;
        return out;
    }
};

TEST_F(CliFsDbTest, GetStreamsTheExactBytesInBoundedChunks) {
    const auto out = get(admin, "fs get " + a("/big.bin"));
    EXPECT_EQ(out.exit, 0) << out.err;
    EXPECT_TRUE(out.sawTransfer);
    EXPECT_EQ(out.bytes, big);
    EXPECT_EQ(out.chunks, (big.size() + tx::kChunkBytes - 1) / tx::kChunkBytes);

    const auto byReader = get(reader, "fs download " + a("/docs/note.txt"));
    EXPECT_EQ(byReader.exit, 0) << byReader.err;
    EXPECT_EQ(std::string(byReader.bytes.begin(), byReader.bytes.end()), "hello from the vault\n");
}

TEST_F(CliFsDbTest, GetDeniesLikeTheHttpLaneWithoutAnExistenceOracle) {
    // No role on the vault: denied, and nothing about the file is sent.
    auto out = get(plain, "fs get " + a("/big.bin"));
    EXPECT_EQ(out.exit, tx::exitcode::kNoPerm);
    EXPECT_FALSE(out.sawTransfer);
    EXPECT_TRUE(out.bytes.empty());
    // A missing path in a vault the caller can't read is "permission denied", not "not found".
    EXPECT_EQ(get(plain, "fs get " + a("/nope.bin")).exit, tx::exitcode::kNoPerm);
    EXPECT_EQ(get(reader, "fs get " + b("/nope.bin")).exit, tx::exitcode::kNoPerm);
    EXPECT_EQ(get(reader, "fs get " + b("/other.bin")).exit, tx::exitcode::kNoPerm);
    // Where the caller can read, a missing path is reported as such.
    EXPECT_EQ(get(reader, "fs get " + a("/nope.bin")).exit, tx::exitcode::kNoInput);
    // Paths are normalized and can't leave the vault.
    EXPECT_EQ(get(admin, "fs get " + a("/../../etc/passwd")).exit, tx::exitcode::kUsage);
    EXPECT_EQ(get(admin, "fs get " + a("/docs/../big.bin")).bytes, big);
    // A directory is not a file.
    EXPECT_EQ(get(admin, "fs get " + a("/docs")).exit, tx::exitcode::kUsage);
    // A client that doesn't speak the transfer frames gets a usage error, never a stream it can't read.
    out = get(admin, "fs get " + a("/big.bin"), /*withTransfer=*/false);
    EXPECT_EQ(out.exit, tx::exitcode::kUsage);
    EXPECT_FALSE(out.sawTransfer);
}

TEST_F(CliFsDbTest, RevokingReadStopsALongDownload) {
    auto victim = makeUser("revoked_reader");
    grant(victim, vaultA->vault->id, "reader");
    const auto out = get(victim, "fs get " + a("/big.bin"), true, [&](const uint64_t chunk) {
        if (chunk == 0) revoke(victim, vaultA->vault->id);
    });
    EXPECT_EQ(out.exit, tx::exitcode::kNoPerm) << out.err;
    EXPECT_LT(out.bytes.size(), big.size());
    EXPECT_LE(out.chunks, 32u);
}

TEST_F(CliFsDbTest, PutStoresAnEncryptedFileAndLeavesNothingStaged) {
    const auto bytes = randomBytes(3 * tx::kChunkBytes + 5, 11);
    const auto out = put(writer, "fs put " + a("ignored-local-name /in/new/upload.bin"), bytes);
    EXPECT_EQ(out.exit, 0) << out.err;
    EXPECT_EQ(stored(vaultA, "/in/new/upload.bin"), bytes);
    EXPECT_EQ(stagingLeftovers(), 0u);
    // What the vault holds on disk is ciphertext: no backing file equals the plaintext.
    const auto entry = runtime::Deps::get().fsCache->getEntry(vaultA->vaultPathToFusePath("/in/new/upload.bin"));
    ASSERT_TRUE(entry);
    std::ifstream backing(entry->backing_path, std::ios::binary);
    const std::vector<uint8_t> raw{std::istreambuf_iterator<char>(backing), {}};
    EXPECT_NE(raw, bytes);

    // Empty files are files too.
    EXPECT_EQ(put(writer, "fs put " + a("x /in/empty.bin"), {}).exit, 0);
    EXPECT_EQ(stored(vaultA, "/in/empty.bin"), std::vector<uint8_t>{});
}

TEST_F(CliFsDbTest, PutOverwritePolicy) {
    const auto first = randomBytes(1000, 21), second = randomBytes(2000, 22);
    ASSERT_EQ(put(writer, "fs put " + a("x /ow.bin"), first).exit, 0);
    // Exists, no --overwrite: refused before any byte moves.
    auto out = put(writer, "fs put " + a("x /ow.bin"), second);
    EXPECT_EQ(out.exit, tx::exitcode::kCantCreat);
    EXPECT_FALSE(out.sawTransfer);
    EXPECT_EQ(stored(vaultA, "/ow.bin"), first);
    // A reader can't replace it, and learns nothing from trying.
    out = put(reader, "fs put " + a("x /ow.bin --overwrite"), second);
    EXPECT_EQ(out.exit, tx::exitcode::kNoPerm);
    EXPECT_EQ(stored(vaultA, "/ow.bin"), first);
    // With --overwrite and the permission: replaced.
    EXPECT_EQ(put(writer, "fs put " + a("x /ow.bin --overwrite"), second).exit, 0);
    EXPECT_EQ(stored(vaultA, "/ow.bin"), second);
    // A directory can't be replaced by a file.
    EXPECT_EQ(put(admin, "fs put " + a("x /docs --overwrite"), first).exit, tx::exitcode::kUsage);
    EXPECT_EQ(put(admin, "fs put " + a("x /"), first).exit, tx::exitcode::kUsage);
    EXPECT_EQ(put(admin, "fs put " + a("x /../escape.bin"), first).exit, tx::exitcode::kUsage);
}

TEST_F(CliFsDbTest, PutDeniedWithoutWrite) {
    auto out = put(reader, "fs put " + a("x /reader.bin"), randomBytes(10, 1));
    EXPECT_EQ(out.exit, tx::exitcode::kNoPerm);
    EXPECT_FALSE(out.sawTransfer);
    out = put(plain, "fs put " + b("x /plain.bin"), randomBytes(10, 1));
    EXPECT_EQ(out.exit, tx::exitcode::kNoPerm);
    EXPECT_FALSE(stored(vaultA, "/reader.bin").has_value());
    EXPECT_FALSE(stored(vaultB, "/plain.bin").has_value());
}

TEST_F(CliFsDbTest, BrokenTransfersStoreNothingAndCleanUp) {
    const auto bytes = randomBytes(3 * tx::kChunkBytes, 31);
    const std::vector<std::pair<Send, std::string>> cases{
        {Send::BadSeq, "/broken-seq.bin"}, {Send::Abort, "/broken-abort.bin"}, {Send::HangUp, "/broken-hangup.bin"},
        {Send::Extra, "/broken-extra.bin"}, {Send::Oversized, "/broken-oversized.bin"}, {Send::Short, "/broken-short.bin"}};
    for (const auto& [how, path] : cases) {
        const auto out = put(writer, "fs put " + a("x " + path), bytes, how);
        EXPECT_NE(out.exit, 0) << path;
        EXPECT_FALSE(stored(vaultA, path).has_value()) << path;
        EXPECT_EQ(stagingLeftovers(), 0u) << path;
    }
    EXPECT_EQ(put(writer, "fs put " + a("x /broken-seq.bin"), bytes, Send::BadSeq).exit, tx::exitcode::kDataErr);
    EXPECT_EQ(put(writer, "fs put " + a("x /broken-extra.bin"), bytes, Send::Extra).exit, tx::exitcode::kDataErr);
    EXPECT_EQ(put(writer, "fs put " + a("x /broken-short.bin"), bytes, Send::Short).exit, tx::exitcode::kDataErr);
}

TEST_F(CliFsDbTest, RevokingWriteDuringAnUploadCommitsNothing) {
    auto victim = makeUser("revoked_writer");
    grant(victim, vaultA->vault->id, "editor");
    const auto out = put(victim, "fs put " + a("x /revoked.bin"), randomBytes(2 * tx::kChunkBytes, 41), Send::Normal,
                         [&] { revoke(victim, vaultA->vault->id); });
    EXPECT_EQ(out.exit, tx::exitcode::kNoPerm) << out.err;
    EXPECT_FALSE(stored(vaultA, "/revoked.bin").has_value());
    EXPECT_EQ(stagingLeftovers(), 0u);
}

TEST_F(CliFsDbTest, LsListsWithTheListPermission) {
    auto out = get(admin, "fs ls " + a("/"), false);
    EXPECT_EQ(out.exit, 0) << out.err;
    EXPECT_NE(out.out.find("big.bin"), std::string::npos);
    EXPECT_NE(out.out.find("docs/"), std::string::npos);
    EXPECT_EQ(get(reader, "fs ls " + a("/docs"), false).exit, 0);
    EXPECT_EQ(get(plain, "fs ls " + a("/"), false).exit, tx::exitcode::kNoPerm);
    EXPECT_EQ(get(reader, "fs ls " + b("/"), false).exit, tx::exitcode::kNoPerm);
    EXPECT_EQ(get(reader, "fs ls " + a("/missing"), false).exit, tx::exitcode::kNoInput);
}

TEST_F(CliFsDbTest, StartupSweepsLeftoverStagingFiles) {
    const auto dir = paths::getBackingPath() / ".cli-staging";
    std::filesystem::create_directories(dir);
    std::ofstream(dir / "put-leftover.part") << "plaintext from a crashed upload";
    std::ofstream(dir / "unrelated.txt") << "not ours";
    commands::sweepFsStaging();
    EXPECT_FALSE(std::filesystem::exists(dir / "put-leftover.part"));
    EXPECT_TRUE(std::filesystem::exists(dir / "unrelated.txt"));
    std::filesystem::remove(dir / "unrelated.txt");
}

}
