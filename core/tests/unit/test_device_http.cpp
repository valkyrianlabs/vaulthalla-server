// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// The device listener's HTTP lanes and remote MCP over real TLS 1.3 (S1b): downloads with Range, an upload session,
// RBAC as the device's user (never a cookie), no share lanes, pairing-only refused, revocation ending a keep-alive
// connection; /mcp as Streamable HTTP (initialize, tools/list, tools/call through executeLine), its Origin and
// MCP-Protocol-Version checks, the exclusions (D4: key export unreachable), the destructive gate and the per-call
// deadline.

#include "../helpers/device_client.hpp"
#include "../helpers/identities.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Pairing.hpp"
#include "device/ServerIdentity.hpp"
#include "fs/Filesystem.hpp"
#include "fs/model/File.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Devices.hpp"
#include "ops/Roles.hpp"
#include "ops/Error.hpp"
#include "ops/Vaults.hpp"
#include "protocols/device/Listener.hpp"
#include "protocols/device/Mcp.hpp"
#include "protocols/device/Service.hpp"
#include "protocols/http/Access.hpp"
#include "protocols/http/Session.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/vault/Keys.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/model/Vault.hpp"

#include <boost/asio/io_context.hpp>
#include <gtest/gtest.h>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <random>
#include <thread>

namespace vh::test_device_http {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using vh::test::device::Client;
using vh::test::device::ClientIdentity;
using vh::test::device::HttpClient;
namespace bhttp = boost::beast::http;
using namespace std::chrono_literals;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

class DeviceHttpTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<boost::asio::io_context> ioc;
    inline static std::vector<std::thread> threads;
    inline static std::shared_ptr<protocols::device::Listener> listener;
    inline static uint16_t port = 0;
    inline static UserPtr admin, owner, stranger;
    inline static std::shared_ptr<storage::Engine> engine;
    inline static std::vector<uint8_t> blob;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_device_http] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_device_http_" + tag());
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
        admin = identities::manager().userByName("admin");

        owner = seedUser("dh_owner");
        stranger = seedUser("dh_stranger");
        const auto vault = ops::vaults::create(admin, {.name = "dh_" + tag(), .type = vault::model::VaultType::Local,
                                                       .owner_id = owner->id});
        engine = runtime::Deps::get().storageManager->getEngine(vault->id);
        (void)ops::roles::assignVaultRole(admin, {.target = {.vault_id = vault->id,
                                                             .subject = {.type = "user", .id = owner->id}},
                                                  .role = std::string("contributor")});
        owner = identities::manager().user(owner->id);
        blob.resize(1024 * 1024 + 77);
        std::mt19937 rng(7);
        for (auto& b : blob) b = static_cast<uint8_t>(rng());
        (void)fs::Filesystem::createFile({.path = "/blob.bin", .fuse_path = engine->vaultPathToFusePath("/blob.bin"),
                                          .buffer = blob, .engine = engine, .user = owner, .overwrite = true});

        const auto server = vh::device::ServerIdentity::generate();
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
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        listener->close();
        protocols::device::closeAllDeviceListenerSessions();
        (void)protocols::http::Session::waitUntilNoDeviceSessionsAlive(5s);
        ioc->stop();
        for (auto& t : threads) t.join();
        threads.clear();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        protocols::http::access::clearCachesForTesting();
        protocols::device::mcp::setCallDeadlineForTesting(protocols::device::mcp::kCallDeadline);
    }

    static UserPtr seedUser(const std::string& prefix, const std::string& role = "unprivileged") {
        const auto name = prefix + "_" + tag();
        return test::identities::createUser(name, db::query::rbac::role::Admin::get(role), name + "@vaulthalla.test");
    }

    // A device paired to `user` (the row the approval would write).
    static vh::device::Device paired(const ClientIdentity& device, const UserPtr& user) {
        return db::query::device::Devices::insert({.user_id = user->id, .approved_by = user->id, .name = "Mac",
                                                   .platform = "macOS", .app_version = "1.0",
                                                   .spki_sha256 = device.deviceId(), .last_ip = "127.0.0.1"});
    }

    static std::string blobUrl() {
        return "/download/content?vault_id=" + std::to_string(engine->vault->id) + "&path=/blob.bin";
    }

    static json toolText(const std::optional<json>& reply) {
        if (!reply || !reply->contains("result")) return json();
        const auto& content = reply->at("result").at("content");
        return content.empty() ? json() : content.at(0).at("text");
    }
};

TEST_F(DeviceHttpTest, DownloadsWithRangeAsTheDevicesUser) {
    const ClientIdentity device;
    (void)paired(device, owner);
    HttpClient http(port, device);
    ASSERT_TRUE(http.connect());

    const auto full = http.request(bhttp::verb::get, blobUrl());
    ASSERT_TRUE(full);
    EXPECT_EQ(full->result_int(), 200) << full->body();
    EXPECT_EQ(std::vector<uint8_t>(full->body().begin(), full->body().end()), blob);

    // Same keep-alive connection: a byte range, then HEAD.
    const auto range = http.request(bhttp::verb::get, blobUrl(), {}, {{"Range", "bytes=100-4195"}});
    ASSERT_TRUE(range);
    EXPECT_EQ(range->result_int(), 206);
    EXPECT_EQ(range->body().size(), 4096u);
    EXPECT_EQ(std::vector<uint8_t>(range->body().begin(), range->body().end()),
              std::vector<uint8_t>(blob.begin() + 100, blob.begin() + 4196));
    const auto head = http.request(bhttp::verb::head, blobUrl());
    ASSERT_TRUE(head);
    EXPECT_EQ(head->result_int(), 200);
    EXPECT_EQ((*head)[bhttp::field::content_length], std::to_string(blob.size()));
    EXPECT_FALSE(db::query::device::Devices::byCurrentSpki(device.deviceId())->last_seen_at == std::nullopt);
}

TEST_F(DeviceHttpTest, RbacShareLanesAndPairingOnly) {
    // Another user's device: the vault is not theirs (no existence oracle: 403).
    const ClientIdentity theirs;
    (void)paired(theirs, stranger);
    HttpClient other(port, theirs);
    ASSERT_TRUE(other.connect());
    const auto denied = other.request(bhttp::verb::get, blobUrl());
    ASSERT_TRUE(denied);
    EXPECT_EQ(denied->result_int(), 403);

    // The share lanes are not offered on the listener, whatever the cookies say.
    const ClientIdentity mine;
    (void)paired(mine, owner);
    HttpClient http(port, mine);
    ASSERT_TRUE(http.connect());
    const auto share = http.request(bhttp::verb::get, blobUrl() + "&share=1", {}, {{"Cookie", "share_refresh=x"}});
    ASSERT_TRUE(share);
    EXPECT_EQ(share->result_int(), 403);
    // Only the device lanes: the console's session endpoint is not one.
    HttpClient again(port, mine);
    ASSERT_TRUE(again.connect());
    const auto session = again.request(bhttp::verb::get, "/auth/session");
    ASSERT_TRUE(session);
    EXPECT_EQ(session->result_int(), 404);

    // An unpaired key: no HTTP lane, no MCP.
    const ClientIdentity unknown;
    for (const auto* target : {"/download/content?vault_id=1&path=/blob.bin", "/mcp"}) {
        HttpClient anon(port, unknown);
        ASSERT_TRUE(anon.connect());
        const auto res = anon.request(bhttp::verb::get, target);
        ASSERT_TRUE(res) << target;
        EXPECT_EQ(res->result_int(), 403) << target;
    }
}

TEST_F(DeviceHttpTest, UploadSessionOverTls) {
    const ClientIdentity device;
    (void)paired(device, owner);
    HttpClient http(port, device);
    ASSERT_TRUE(http.connect());

    const std::string content = "uploaded from a paired Mac\n";
    const auto created = http.request(
        bhttp::verb::post, "/upload/session",
        json{{"vault_id", engine->vault->id},
             {"files", {{{"file_id", "f1"}, {"path", "/from-mac.txt"}, {"size", content.size()}}}}}.dump(),
        {{"Content-Type", "application/json"}});
    ASSERT_TRUE(created);
    ASSERT_EQ(created->result_int(), 200) << created->body();
    const auto uploadId = json::parse(created->body()).at("upload_id").get<std::string>();

    const auto put = http.request(bhttp::verb::put, "/upload/" + uploadId + "/files/f1", content,
                                  {{"Content-Type", "application/octet-stream"}});
    ASSERT_TRUE(put);
    ASSERT_EQ(put->result_int(), 200) << put->body();
    const auto finished = http.request(bhttp::verb::post, "/upload/" + uploadId + "/finish");
    ASSERT_TRUE(finished);
    ASSERT_EQ(finished->result_int(), 200) << finished->body();

    HttpClient check(port, device);
    ASSERT_TRUE(check.connect());
    const auto back = check.request(bhttp::verb::get, "/download/content?vault_id=" + std::to_string(engine->vault->id) +
                                                          "&path=/from-mac.txt");
    ASSERT_TRUE(back);
    EXPECT_EQ(back->result_int(), 200);
    EXPECT_EQ(back->body(), content);

    // A device without Write on the vault is refused before any byte is staged.
    const ClientIdentity theirs;
    (void)paired(theirs, stranger);
    HttpClient other(port, theirs);
    ASSERT_TRUE(other.connect());
    const auto refused = other.request(
        bhttp::verb::post, "/upload/session",
        json{{"vault_id", engine->vault->id}, {"files", {{{"file_id", "f2"}, {"path", "/x.txt"}, {"size", 1}}}}}.dump(),
        {{"Content-Type", "application/json"}});
    ASSERT_TRUE(refused);
    EXPECT_GE(refused->result_int(), 400);
}

TEST_F(DeviceHttpTest, RevocationEndsAKeepAliveConnection) {
    const ClientIdentity device;
    const auto row = paired(device, owner);
    HttpClient http(port, device);
    ASSERT_TRUE(http.connect());
    ASSERT_EQ(http.request(bhttp::verb::get, blobUrl())->result_int(), 200);
    (void)ops::devices::revoke(owner, row.spki_sha256);
    const auto after = http.request(bhttp::verb::get, blobUrl());
    EXPECT_TRUE(!after || after->result_int() >= 400) << "the revoked device's connection is over";
    HttpClient again(port, device);
    ASSERT_TRUE(again.connect());
    EXPECT_EQ(again.request(bhttp::verb::get, blobUrl())->result_int(), 403);
}

TEST_F(DeviceHttpTest, McpOverStreamableHttp) {
    const ClientIdentity device;
    const auto row = paired(device, owner);
    HttpClient http(port, device);
    ASSERT_TRUE(http.connect());

    const auto init = http.mcp({{"jsonrpc", "2.0"}, {"id", 1}, {"method", "initialize"},
                                {"params", {{"protocolVersion", "2025-11-25"}, {"capabilities", json::object()},
                                            {"clientInfo", {{"name", "test"}, {"version", "1"}}}}}});
    ASSERT_TRUE(init);
    EXPECT_EQ(init->at("result").at("protocolVersion"), "2025-11-25");
    const std::vector<std::pair<std::string, std::string>> v{{"MCP-Protocol-Version", "2025-11-25"}};

    // A notification gets 202 and no body.
    const auto note = http.request(bhttp::verb::post, "/mcp",
                                   json{{"jsonrpc", "2.0"}, {"method", "notifications/initialized"}}.dump(),
                                   {{"Content-Type", "application/json"}, {"MCP-Protocol-Version", "2025-11-25"}});
    ASSERT_TRUE(note);
    EXPECT_EQ(note->result_int(), 202);

    const auto tools = http.mcp({{"jsonrpc", "2.0"}, {"id", 2}, {"method", "tools/list"}}, v);
    ASSERT_TRUE(tools);
    const auto dump = tools->dump();
    EXPECT_NE(dump.find("vh_read"), std::string::npos);
    EXPECT_EQ(dump.find("vault key export"), std::string::npos);

    // A read runs as the device's user through the CLI router.
    const auto list = http.mcp({{"jsonrpc", "2.0"}, {"id", 3}, {"method", "tools/call"},
                                {"params", {{"name", "vh_read"}, {"arguments", {{"command", "device list --json"}}}}}}, v);
    ASSERT_TRUE(list);
    EXPECT_FALSE(list->at("result").value("isError", false)) << list->dump();
    EXPECT_NE(toolText(list).get<std::string>().find(row.spki_sha256), std::string::npos);

    // D4: key and secret export are unreachable, however they are spelled; pairing and exposure stay human.
    for (const auto* command : {"vault keys export 1", "vault keys import 1 --file keys.json", "secrets export jwt-secret", "device approve abc --code 123456",
                                "device remote enable"}) {
        const auto refused = http.mcp({{"jsonrpc", "2.0"}, {"id", 4}, {"method", "tools/call"},
                                       {"params", {{"name", "vh_run"}, {"arguments", {{"command", command}}}}}}, v);
        ASSERT_TRUE(refused) << command;
        EXPECT_NE(toolText(refused).get<std::string>().find("not available to agents"), std::string::npos) << command;
    }

    // The destructive gate: revoking another device needs the explicit acknowledgement.
    const ClientIdentity second;
    const auto other = paired(second, owner);
    const auto gated = http.mcp({{"jsonrpc", "2.0"}, {"id", 5}, {"method", "tools/call"},
                                 {"params", {{"name", "vh_run"},
                                             {"arguments", {{"command", "device revoke " + std::to_string(other.id)}}}}}},
                                v);
    ASSERT_TRUE(gated);
    EXPECT_NE(gated->dump().find("needs_confirmation"), std::string::npos) << gated->dump();
    EXPECT_FALSE(db::query::device::Devices::byId(other.id)->revoked());
    const auto confirmed = http.mcp(
        {{"jsonrpc", "2.0"}, {"id", 6}, {"method", "tools/call"},
         {"params", {{"name", "vh_run"}, {"arguments", {{"command", "device revoke " + std::to_string(other.id)},
                                                        {"confirm", {{"destructive", true}}}}}}}},
        v);
    ASSERT_TRUE(confirmed);
    EXPECT_FALSE(confirmed->at("result").value("isError", false)) << confirmed->dump();
    EXPECT_TRUE(db::query::device::Devices::byId(other.id)->revoked());

    // A call past its deadline is abandoned with a clear error.
    protocols::device::mcp::setCallDeadlineForTesting(0ms);
    const auto late = http.mcp({{"jsonrpc", "2.0"}, {"id", 7}, {"method", "tools/call"},
                                {"params", {{"name", "vh_read"}, {"arguments", {{"command", "device list"}}}}}}, v);
    ASSERT_TRUE(late);
    EXPECT_TRUE(late->at("result").value("isError", false));
    EXPECT_NE(late->dump().find("did not finish"), std::string::npos);
}

// D4 over the real listener: a paired device exports a vault key and confirms it; a browser session gets
// export_requires_device for the same command; a device acts with its user's permission; and /mcp reads key status
// (key checks only) but reaches no export.
TEST_F(DeviceHttpTest, VaultKeyExportOnlyOnAPairedDevice) {
    const auto vaultId = engine->vault->id;
    const auto [key, version] = engine->encryptionManager->currentKey();
    const auto check = vault::keyCheck(key->bytes(), vaultId, version);

    const ClientIdentity device;
    (void)paired(device, admin);
    Client client(port, device);
    ASSERT_TRUE(client.connect());
    const auto exported = client.call("vault.keys.export", {{"vault_id", vaultId}});
    ASSERT_TRUE(exported && exported->value("status", "") == "OK") << (exported ? exported->dump() : "no reply");
    EXPECT_EQ(exported->at("data").at("key_check"), check);
    EXPECT_EQ(exported->at("data").at("key_info").at("key_version"), version);
    const auto confirmed = client.call("vault.keys.export.confirm",
                                       {{"vault_id", vaultId}, {"version", version}, {"key_check", check}});
    ASSERT_TRUE(confirmed && confirmed->value("status", "") == "OK") << (confirmed ? confirmed->dump() : "no reply");
    const auto status = client.call("vault.keys.status", {{"vault_id", vaultId}});
    ASSERT_TRUE(status && status->value("status", "") == "OK");
    EXPECT_EQ(status->at("data").at("vaults").at(0).at("exported_version"), version);

    // The same command from a browser session.
    auto console = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    console->user = admin;
    try {
        (void)protocols::ws::handler::VaultKeys::exportKeys({{"vault_id", vaultId}}, console);
        ADD_FAILURE() << "a browser session got key material";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "export_requires_device");
    }

    // A device is its user: without the Export permission it is denied.
    const ClientIdentity theirs;
    (void)paired(theirs, stranger);
    Client other(port, theirs);
    ASSERT_TRUE(other.connect());
    const auto denied = other.call("vault.keys.export", {{"vault_id", vaultId}});
    ASSERT_TRUE(denied);
    EXPECT_EQ(denied->value("status", ""), "ERROR");
    EXPECT_EQ(denied->at("data").value("code", ""), "denied");

    // /mcp: status is readable (key checks, never keys); no spelling of export or import runs.
    HttpClient http(port, device);
    ASSERT_TRUE(http.connect());
    ASSERT_TRUE(http.mcp({{"jsonrpc", "2.0"}, {"id", 1}, {"method", "initialize"},
                          {"params", {{"protocolVersion", "2025-11-25"}, {"capabilities", json::object()},
                                      {"clientInfo", {{"name", "test"}, {"version", "1"}}}}}}));
    const std::vector<std::pair<std::string, std::string>> v{{"MCP-Protocol-Version", "2025-11-25"}};
    const auto read = http.mcp({{"jsonrpc", "2.0"}, {"id", 2}, {"method", "tools/call"},
                                {"params", {{"name", "vh_read"},
                                            {"arguments", {{"command", "vault keys status " + std::to_string(vaultId) +
                                                                           " --json"}}}}}}, v);
    ASSERT_TRUE(read);
    EXPECT_FALSE(read->at("result").value("isError", false)) << read->dump();
    const auto text = toolText(read).get<std::string>();
    EXPECT_NE(text.find(check), std::string::npos);
    EXPECT_EQ(text.find("\"key\""), std::string::npos);
    for (const auto& command : {"vault keys export " + std::to_string(vaultId), std::string("vault k export all"),
                                "vault keys import " + std::to_string(vaultId) + " --file keys.json --confirm-name x",
                                "VAULT KEYS EXPORT " + std::to_string(vaultId)}) {
        const auto refused = http.mcp({{"jsonrpc", "2.0"}, {"id", 3}, {"method", "tools/call"},
                                       {"params", {{"name", "vh_run"}, {"arguments", {{"command", command}}}}}}, v);
        ASSERT_TRUE(refused) << command;
        EXPECT_NE(toolText(refused).get<std::string>().find("not available to agents"), std::string::npos) << command;
        EXPECT_EQ(refused->dump().find(exported->at("data").at("key").get<std::string>()), std::string::npos);
    }
}

TEST_F(DeviceHttpTest, McpTransportChecks) {
    const ClientIdentity device;
    (void)paired(device, owner);
    const auto call = [&](const bhttp::verb method, const std::string& body,
                          const std::vector<std::pair<std::string, std::string>>& headers) {
        HttpClient http(port, device);
        EXPECT_TRUE(http.connect());
        const auto res = http.request(method, "/mcp", body, headers);
        return res ? res->result_int() : 0u;
    };
    const auto ping = json{{"jsonrpc", "2.0"}, {"id", 1}, {"method", "ping"}}.dump();
    const std::pair<std::string, std::string> ct{"Content-Type", "application/json"};
    EXPECT_EQ(call(bhttp::verb::post, ping, {ct}), 200u);
    EXPECT_EQ(call(bhttp::verb::post, ping, {ct, {"Origin", "https://evil.example"}}), 403u);
    EXPECT_EQ(call(bhttp::verb::post, ping, {ct, {"MCP-Protocol-Version", "1999-01-01"}}), 400u);
    EXPECT_EQ(call(bhttp::verb::post, ping, {{"Content-Type", "text/plain"}}), 415u);
    EXPECT_EQ(call(bhttp::verb::post, "not json", {ct}), 400u);
    EXPECT_EQ(call(bhttp::verb::post, "[" + ping + "]", {ct}), 400u);
    EXPECT_EQ(call(bhttp::verb::get, {}, {}), 405u);
}

}
