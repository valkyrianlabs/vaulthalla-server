// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The sealed lane (design/peers/mirror.md "Contents"; protocols::device::peer_object, peer::object) through the real
// device listener over TLS 1.3: this process holds a vault it is the core of, mirrored with a linked server that the
// test client plays with its own key. One test per refusal: not a peer session (a device, an unknown key), a peer that
// is not the vault's linked server, a revoked peer (on an open connection, and its connections closed by unlinking),
// the switch off, a generation that is not current, a non-VHF1 file (gcm0, plain with bytes), bytes not on disk; and
// the happy path: the sealed bytes exactly as on disk, HEAD, a range that resumes mid-file, and the real fetching client
// (pinned, resuming after a broken-off transfer) against this listener. The two-daemon half is the Tier B drill
// (`vhh drill peers`, step 6).

#include "../helpers/db_suite.hpp"
#include "../helpers/device_client.hpp"
#include "config/Registry.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/util/hash.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/fs/File.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/peer/Peer.hpp"
#include "device/Crypto.hpp"
#include "device/ServerIdentity.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "mirror/submit/Contents.hpp"
#include "ops/Roles.hpp"
#include "ops/Vaults.hpp"
#include "peer/Links.hpp"
#include "peer/ObjectClient.hpp"
#include "protocols/device/Listener.hpp"
#include "protocols/device/PeerObject.hpp"
#include "protocols/device/Service.hpp"
#include "protocols/http/Session.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/Content.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/model/Vault.hpp"

#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>
#include <pqxx/pqxx>
#include <sodium.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <thread>

namespace vh::test_peer_object_lane {

using json = nlohmann::json;
using vh::test::device::ClientIdentity;
using vh::test::device::HttpClient;
namespace bhttp = boost::beast::http;
namespace object = vh::peer::object;
using namespace std::chrono_literals;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "s" + std::to_string(n.fetch_add(1));
}

std::vector<uint8_t> readAll(const std::filesystem::path& p) {
    std::ifstream in(p, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), {}};
}

std::string codeOf(const std::optional<HttpClient::Response>& r) {
    if (!r) return "<no answer>";
    try {
        return json::parse(r->body()).value("code", "");
    } catch (const std::exception&) {
        return "<not json>";
    }
}

class PeerObjectLaneDbTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<boost::asio::io_context> ioc;
    inline static std::vector<std::thread> threads;
    inline static std::shared_ptr<protocols::device::Listener> listener;
    inline static std::shared_ptr<const vh::device::ServerIdentity> server;
    inline static uint16_t port = 0;
    inline static std::shared_ptr<storage::Engine> engine;
    inline static config::Config savedConfig;
    inline static std::unique_ptr<ClientIdentity> linkedKey;   // the vault's linked server
    inline static vh::peer::Record linked;
    inline static std::vector<uint8_t> plaintext;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("peer_object_lane")) return;
        savedConfig = config::Registry::get();
        setExperimental(true);
        server = vh::device::ServerIdentity::generate();
        vh::device::setCurrentServerIdentity(server);
        ioc = std::make_shared<boost::asio::io_context>();
        auto router = std::make_shared<protocols::ws::Router>();
        protocols::ws::Handler::registerAllHandlers(router);
        listener = std::make_shared<protocols::device::Listener>(*ioc, protocols::device::makeServerContext(*server),
                                                                 router, 64);
        listener->listen({boost::asio::ip::make_address("127.0.0.1"), 0});
        port = listener->localEndpoint().port();
        auto guard = std::make_shared<boost::asio::executor_work_guard<boost::asio::io_context::executor_type>>(
            boost::asio::make_work_guard(*ioc));
        for (int i = 0; i < 2; ++i) threads.emplace_back([guard] { ioc->run(); });

        const auto vault = ops::vaults::create(superUser, {.name = "sl_" + tag(), .type = vault::model::VaultType::Local,
                                                           .owner_id = superUser->id});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        plaintext.resize(3 * 64 * 1024 + 4321);  // four chunks, the last partial
        std::mt19937 rng(11);
        for (auto& b : plaintext) b = static_cast<uint8_t>(rng());
        write("/blob.bin", plaintext);

        linkedKey = std::make_unique<ClientIdentity>();
        linked = addPeer(*linkedKey, "core-of-nothing");
        (void)db::query::mirror::MirrorVaults::startCore(vault->id, linked.id);
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        listener->close();
        protocols::device::closeAllDeviceListenerSessions();
        (void)protocols::device::peer_object::closeAllConnections();
        EXPECT_TRUE(protocols::http::Session::waitUntilNoDeviceSessionsAlive(5s));
        ioc->stop();
        for (auto& t : threads) t.join();
        threads.clear();
        listener.reset();
        (void)runtime::Deps::releaseSessions();
        ioc.reset();
        engine.reset();
        config::Registry::set(savedConfig);
        vh::device::setCurrentServerIdentity(nullptr);
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        setExperimental(true);
    }

    static void setExperimental(const bool on) {
        auto cfg = config::Registry::get();
        cfg.peers.experimental = on;
        config::Registry::set(cfg);
    }

    static vh::peer::Record addPeer(const ClientIdentity& key, const std::string& name) {
        db::query::peer::NewPeer p;
        p.node_id = "node-" + tag();
        p.name = name;
        p.spki_sha256 = key.deviceId();
        vh::peer::Key32 k{};
        k.fill(0x41);
        p.attest_public_keys = {k};
        k.fill(0x42);
        p.wrap_public_key = k;
        p.product_version = "1.27.0";
        return db::query::peer::Peers::insert(p);
    }

    static std::shared_ptr<fs::model::File> write(const std::string& path, const std::vector<uint8_t>& bytes) {
        (void)fs::Filesystem::createFile({.path = path, .fuse_path = engine->vaultPathToFusePath(path), .buffer = bytes,
                                          .engine = engine, .user = superUser, .overwrite = true});
        return db::query::fs::File::getFileByPath(engine->vault->id, path);
    }

    static std::string targetOf(const fs::model::File& f, const std::optional<std::string>& generation = std::nullopt) {
        return object::target({.vault = engine->encryptionManager->vaultUid(), .object = *f.object_uid,
                               .generation = generation.value_or(f.encryption_iv)});
    }

    static std::optional<HttpClient::Response> get(const ClientIdentity& key, const std::string& target,
                                                   const std::vector<std::pair<std::string, std::string>>& headers = {},
                                                   const bhttp::verb verb = bhttp::verb::get) {
        HttpClient http(port, key);
        if (!http.connect()) return std::nullopt;
        return http.request(verb, target, {}, headers);
    }

    // The fetching side's view of this server: its key and where it listens.
    static vh::peer::Record thisServerAsSeen() {
        vh::peer::Record r;
        r.id = 0;
        r.name = "the core";
        r.spki_sha256 = server->spkiHex();
        r.endpoints = {{.host = "127.0.0.1", .port = port, .kind = "loopback"}};
        return r;
    }
};

TEST_F(PeerObjectLaneDbTest, TheLinkedServerGetsTheSealedBytesAsTheyAreWithRangesThatResume) {
    const auto f = db::query::fs::File::getFileByPath(engine->vault->id, "/blob.bin");
    ASSERT_TRUE(f && f->object_uid);
    ASSERT_TRUE(vh::vault::content::isVhf1(f->encryption_iv));
    const auto onDisk = readAll(f->backing_path);
    ASSERT_EQ(onDisk.size(), vh::vault::content::sealedSizeOf(f->size_bytes, f->encryption_iv));

    const auto full = get(*linkedKey, targetOf(*f));
    ASSERT_TRUE(full);
    ASSERT_EQ(full->result_int(), 200) << full->body();
    EXPECT_EQ(std::vector<uint8_t>(full->body().begin(), full->body().end()), onDisk) << "byte for byte, sealed";
    EXPECT_EQ((*full)[bhttp::field::etag], object::etagOf(f->encryption_iv));
    EXPECT_EQ((*full)[bhttp::field::content_type], "application/octet-stream");
    EXPECT_EQ((*full)[bhttp::field::cache_control], "no-store");
    EXPECT_EQ((*full)[bhttp::field::accept_ranges], "bytes");
    // No plaintext anywhere in the answer.
    const std::string body = full->body();
    EXPECT_EQ(body.find(std::string(plaintext.begin(), plaintext.begin() + 64)), std::string::npos);

    // A transfer that broke off at 100,000 bytes resumes there, on the generation it started with.
    const uint64_t at = 100'000;
    const auto rest = get(*linkedKey, targetOf(*f),
                          {{"Range", "bytes=" + std::to_string(at) + "-"}, {"If-Range", object::etagOf(f->encryption_iv)}});
    ASSERT_TRUE(rest);
    ASSERT_EQ(rest->result_int(), 206);
    EXPECT_EQ((*rest)[bhttp::field::content_range],
              "bytes " + std::to_string(at) + "-" + std::to_string(onDisk.size() - 1) + "/" + std::to_string(onDisk.size()));
    EXPECT_EQ(std::vector<uint8_t>(rest->body().begin(), rest->body().end()),
              std::vector<uint8_t>(onDisk.begin() + static_cast<std::ptrdiff_t>(at), onDisk.end()));

    const auto head = get(*linkedKey, targetOf(*f), {}, bhttp::verb::head);
    ASSERT_TRUE(head);
    EXPECT_EQ(head->result_int(), 200);
    EXPECT_EQ((*head)[bhttp::field::content_length], std::to_string(onDisk.size()));

    // The real fetching client: pinned to this server's key, broken off after 70,000 bytes, then resumed by range.
    const auto tls = protocols::device::makeClientContext(*linkedKey->id);
    std::vector<uint8_t> got;
    bool stop = false;
    object::FetchOptions options;
    options.tls = tls;
    options.expectedSize = onDisk.size();
    options.deadline = std::chrono::steady_clock::now() + 30s;
    options.cancelled = [&] { return stop; };
    const object::Sink sink = [&](const std::span<const uint8_t> bytes) {
        got.insert(got.end(), bytes.begin(), bytes.end());
        if (got.size() >= 70'000) stop = true;
    };
    const object::Address what{.vault = engine->encryptionManager->vaultUid(), .object = *f->object_uid,
                               .generation = f->encryption_iv};
    const auto first = object::fetch(thisServerAsSeen(), what, options, sink);
    EXPECT_EQ(first.status, object::FetchStatus::Cancelled) << first.error;
    ASSERT_GE(got.size(), 70'000u);
    ASSERT_LT(got.size(), onDisk.size());
    stop = false;
    options.offset = got.size();
    const auto second = object::fetch(thisServerAsSeen(), what, options,
                                      [&](const std::span<const uint8_t> b) { got.insert(got.end(), b.begin(), b.end()); });
    ASSERT_EQ(second.status, object::FetchStatus::Complete) << second.error;
    EXPECT_EQ(second.http_status, 206u);
    EXPECT_EQ(second.total, onDisk.size());
    EXPECT_EQ(got, onDisk);
    EXPECT_EQ(crypto::hash::blake2b(f->backing_path), f->content_hash) << "the log's content hash names these bytes";

    // The client refuses a server whose key is not the pin, before it sends a request.
    auto wrongPin = thisServerAsSeen();
    wrongPin.spki_sha256 = std::string(64, '0');
    options.offset = 0;
    const auto refused = object::fetch(wrongPin, what, options, [](std::span<const uint8_t>) { FAIL(); });
    EXPECT_EQ(refused.status, object::FetchStatus::Unreachable);
    EXPECT_NE(refused.error.find("TLS handshake failed"), std::string::npos) << refused.error;
}

TEST_F(PeerObjectLaneDbTest, NotAPeerSessionFindsNoLane) {
    const auto f = db::query::fs::File::getFileByPath(engine->vault->id, "/blob.bin");
    // A paired device (of the vault's owner, a super admin): the lane does not exist for it.
    const ClientIdentity device;
    (void)db::query::device::Devices::insert({.user_id = superUser->id, .approved_by = superUser->id, .name = "Mac",
                                              .platform = "macOS", .app_version = "1.0",
                                              .spki_sha256 = device.deviceId(), .last_ip = "127.0.0.1"});
    const auto asDevice = get(device, targetOf(*f));
    ASSERT_TRUE(asDevice);
    EXPECT_EQ(asDevice->result_int(), 404);
    // An unknown key (pairing-only).
    const ClientIdentity stranger;
    const auto asStranger = get(stranger, targetOf(*f));
    ASSERT_TRUE(asStranger);
    EXPECT_EQ(asStranger->result_int(), 404);
    // And the linked server gets nothing but the lane: the device lanes refuse it.
    const auto download = get(*linkedKey, "/download/content?vault_id=" + std::to_string(engine->vault->id) +
                                              "&path=/blob.bin");
    ASSERT_TRUE(download);
    EXPECT_EQ(download->result_int(), 403);
}

TEST_F(PeerObjectLaneDbTest, APeerThatIsNotTheVaultsLinkedServerIsRefused) {
    const auto f = db::query::fs::File::getFileByPath(engine->vault->id, "/blob.bin");
    const ClientIdentity other;
    const auto row = addPeer(other, "another-server");
    const auto res = get(other, targetOf(*f));
    ASSERT_TRUE(res);
    EXPECT_EQ(res->result_int(), 404) << res->body();
    EXPECT_EQ(codeOf(res), "not_found") << "no existence oracle: the same answer as no such vault";
    (void)db::query::peer::Peers::revoke(row.id);
}

TEST_F(PeerObjectLaneDbTest, ARevokedPeerIsRefusedAndUnlinkingClosesItsLaneConnections) {
    const auto f = db::query::fs::File::getFileByPath(engine->vault->id, "/blob.bin");
    const ClientIdentity key;
    const auto row = addPeer(key, "soon-unlinked");
    // The vault is mirrored with this one for the test (a vault has one linked server).
    db::Transactions::exec("repoint", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_vault SET peer_id = $1 WHERE vault_id = $2", pqxx::params{row.id, engine->vault->id});
    });
    HttpClient http(port, key);
    ASSERT_TRUE(http.connect());
    const auto before = http.request(bhttp::verb::get, targetOf(*f));
    ASSERT_TRUE(before);
    EXPECT_EQ(before->result_int(), 200);
    // Revoked after the handshake: the next request on the same connection is refused.
    (void)db::query::peer::Peers::revoke(row.id);
    const auto after = http.request(bhttp::verb::get, targetOf(*f));
    ASSERT_TRUE(after);
    EXPECT_EQ(after->result_int(), 403);
    EXPECT_EQ(codeOf(after), "peer_revoked");
    // A new connection with the revoked key is pairing-only: no lane.
    const auto fresh = get(key, targetOf(*f));
    ASSERT_TRUE(fresh);
    EXPECT_EQ(fresh->result_int(), 404);
    db::Transactions::exec("repoint back", [&](pqxx::work& txn) {
        txn.exec("UPDATE mirror_vault SET peer_id = $1 WHERE vault_id = $2", pqxx::params{linked.id, engine->vault->id});
    });

    // Unlinking closes the lane connections the peer has open (link.md invariant 7), not only its websocket.
    HttpClient open(port, *linkedKey);
    ASSERT_TRUE(open.connect());
    ASSERT_EQ(open.request(bhttp::verb::get, targetOf(*f))->result_int(), 200);
    EXPECT_GE(vh::peer::linkService()->disconnect(linked.id, false), 0u);
    EXPECT_FALSE(open.request(bhttp::verb::get, targetOf(*f))) << "the connection was closed";
}

TEST_F(PeerObjectLaneDbTest, WithTheSwitchOffTheLaneDoesNotExist) {
    const auto f = db::query::fs::File::getFileByPath(engine->vault->id, "/blob.bin");
    HttpClient http(port, *linkedKey);
    ASSERT_TRUE(http.connect());  // linked at the handshake
    setExperimental(false);
    const auto open = http.request(bhttp::verb::get, targetOf(*f));
    ASSERT_TRUE(open);
    EXPECT_EQ(open->result_int(), 404) << "per request: an open connection too";
    const auto fresh = get(*linkedKey, targetOf(*f));
    ASSERT_TRUE(fresh);
    EXPECT_EQ(fresh->result_int(), 404);
    setExperimental(true);
}

TEST_F(PeerObjectLaneDbTest, AGenerationThatIsNotCurrentIsGone) {
    const auto f = db::query::fs::File::getFileByPath(engine->vault->id, "/blob.bin");
    std::array<uint8_t, 32> salt{};
    randombytes_buf(salt.data(), salt.size());
    const auto other = vh::device::crypto::toBase64(salt);
    const auto res = get(*linkedKey, targetOf(*f, other));
    ASSERT_TRUE(res);
    EXPECT_EQ(res->result_int(), 410);
    EXPECT_EQ(codeOf(res), "generation_not_current");
    // An older generation of a file written again.
    const auto v1 = write("/again.bin", std::vector<uint8_t>(5000, 0x11));
    const auto v2 = write("/again.bin", std::vector<uint8_t>(5000, 0x22));
    ASSERT_NE(v1->encryption_iv, v2->encryption_iv);
    EXPECT_EQ(get(*linkedKey, targetOf(*v2, v1->encryption_iv))->result_int(), 410);
    EXPECT_EQ(get(*linkedKey, targetOf(*v2))->result_int(), 200);
    // A malformed address.
    EXPECT_EQ(get(*linkedKey, std::string(object::kPrefix) + "nope/nope/nope")->result_int(), 400);
}

TEST_F(PeerObjectLaneDbTest, AFileThatIsNotVhf1IsNeverSent) {
    const auto gcm = write("/legacy.bin", std::vector<uint8_t>(3000, 0x33));
    const auto plain = write("/plain.bin", std::vector<uint8_t>(3000, 0x44));
    // As an older build left them: a 12-byte GCM IV, and plaintext with no generation at all.
    std::array<uint8_t, 12> iv{};
    randombytes_buf(iv.data(), iv.size());
    const auto ivB64 = vh::device::crypto::toBase64(iv);
    db::Transactions::exec("legacy formats", [&](pqxx::work& txn) {
        txn.exec("UPDATE files SET encryption_iv = $1 WHERE fs_entry_id = $2", pqxx::params{ivB64, gcm->id});
        txn.exec("UPDATE files SET encryption_iv = '' WHERE fs_entry_id = $1", pqxx::params{plain->id});
    });
    const auto g = get(*linkedKey, targetOf(*gcm, ivB64));
    ASSERT_TRUE(g);
    EXPECT_EQ(g->result_int(), 422);
    EXPECT_EQ(codeOf(g), "format_not_portable");
    const auto p = get(*linkedKey, targetOf(*plain, std::string()));
    ASSERT_TRUE(p);
    EXPECT_EQ(p->result_int(), 422);
    EXPECT_EQ(codeOf(p), "format_not_portable");
}

TEST_F(PeerObjectLaneDbTest, BytesThatAreNotOnThisServersDiskAreNotHeldHere) {
    const auto f = write("/gone.bin", std::vector<uint8_t>(9000, 0x55));
    const auto aside = f->backing_path.string() + ".aside";
    std::filesystem::rename(f->backing_path, aside);
    const auto res = get(*linkedKey, targetOf(*f));
    ASSERT_TRUE(res);
    EXPECT_EQ(res->result_int(), 404);
    EXPECT_EQ(codeOf(res), "not_held");
    // Bytes of the wrong length are not that generation's either.
    std::filesystem::copy_file(aside, f->backing_path);
    std::filesystem::resize_file(f->backing_path, 100);
    EXPECT_EQ(codeOf(get(*linkedKey, targetOf(*f))), "not_held");
    std::filesystem::remove(f->backing_path);
    std::filesystem::rename(aside, f->backing_path);
    EXPECT_EQ(get(*linkedKey, targetOf(*f))->result_int(), 200);
}

TEST_F(PeerObjectLaneDbTest, BytesAreTakenOnlyFromAMirrorWhoseRoleWritesFilesAndOnlyAsManyAsTheVaultHasRoomFor) {
    // The linked server's PUT of a write's sealed bytes (mirror::submit; design/peers/mirror.md "As built: a change
    // made on the mirror"): this vault's own sealed bytes under a new object uid, which verify here.
    const auto f = db::query::fs::File::getFileByPath(engine->vault->id, "/blob.bin");
    ASSERT_TRUE(f && f->object_uid);
    const auto sealed = readAll(f->backing_path);
    const auto uid = vh::crypto::id::newObjectUid();
    const auto target = object::target({.vault = engine->encryptionManager->vaultUid(), .object = uid,
                                        .generation = f->encryption_iv});
    const std::vector<std::pair<std::string, std::string>> facts{
        {std::string(object::kSizeHeader), std::to_string(f->size_bytes)},
        {std::string(object::kContentHashHeader), f->content_hash.value_or("")},
        {std::string(object::kKeyVersionHeader), std::to_string(f->encrypted_with_key_version)}};
    const auto put = [&] {
        HttpClient http(port, *linkedKey);
        EXPECT_TRUE(http.connect());
        return http.request(bhttp::verb::put, target, std::string(sealed.begin(), sealed.end()), facts);
    };
    const vh::ops::roles::VaultSubject subject{.vault_id = engine->vault->id, .subject = {.type = "peer", .id = linked.id}};

    // No role that creates or replaces a file (none here at all, then a reader's): refused before a byte is kept.
    auto res = put();
    ASSERT_TRUE(res);
    EXPECT_EQ(res->result_int(), 403) << res->body();
    EXPECT_EQ(codeOf(res), "denied");
    (void)ops::roles::assignVaultRole(superUser, {.target = subject, .role = "reader"});
    res = put();
    ASSERT_TRUE(res);
    EXPECT_EQ(res->result_int(), 403) << res->body();
    (void)ops::roles::unassignVaultRole(superUser, subject);

    // A role that writes: staged.
    (void)ops::roles::assignVaultRole(superUser, {.target = subject, .role = "power_user"});
    res = put();
    ASSERT_TRUE(res);
    EXPECT_EQ(res->result_int(), 201) << res->body();

    // A vault whose quota has no room: refused with what to tell the person.
    const auto quota = engine->vault->quota;
    engine->vault->quota = 1;
    res = put();
    engine->vault->quota = quota;
    ASSERT_TRUE(res);
    EXPECT_EQ(res->result_int(), 413) << res->body();
    EXPECT_EQ(codeOf(res), "over_quota");

    (void)ops::roles::unassignVaultRole(superUser, subject);
    if (const auto kept = vh::mirror::submit::contents::staged(engine->vault->id, vh::crypto::id::toUuid(uid),
                                                                 f->encryption_iv))
        vh::mirror::submit::contents::dropStaged(*kept);
}

}
