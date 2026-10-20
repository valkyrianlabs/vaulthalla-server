// Paired devices through both surfaces: `vh device ...` and ws device.* run the same ops::devices, so for every caller
// they reach the same verdict and leave the same state. D3: any user pairs, lists, renames and revokes their own
// devices; only super admins see every user's devices and switch remote connections. The device's side of pairing is
// driven with a connection identity (Peer) directly; test_device_listener.cpp runs it over real TLS.

#include "../helpers/identities.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Crypto.hpp"
#include "device/Pairing.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "identities/User.hpp"
#include "ops/Devices.hpp"
#include "ops/Error.hpp"
#include "protocols/shell/Router.hpp"
#include "protocols/shell/commands/all.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Devices.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "UsageManager.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>
#include <paths.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <functional>
#include <iostream>

namespace vh::test_ops_parity_devices {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
namespace crypto = vh::device::crypto;
namespace handler = protocols::ws::handler;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

class DeviceParityTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<protocols::shell::Router> router;
    inline static UserPtr superUser;
    inline static std::filesystem::path configCopy;
    inline static std::filesystem::path previousConfig;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_ops_parity_devices] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_device_parity_" + tag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);
        // Settings writes (device.remote.*) go to a private copy, never the tree's config.yaml.
        previousConfig = paths::configPath;
        configCopy = root / "config.yaml";
        std::filesystem::copy_file(previousConfig, configCopy);
        paths::configPath = configCopy;

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();
        vh::device::setCurrentServerIdentity(vh::device::ServerIdentity::generate());

        router = std::make_shared<protocols::shell::Router>();
        protocols::shell::commands::registerDeviceCommands(router);
        superUser = seedUser("dp_super", "super_admin");
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        paths::configPath = previousConfig;
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        vh::device::Pairing::instance().resetForTesting();
    }

    static UserPtr seedUser(const std::string& prefix, const std::string& role = "unprivileged") {
        const auto name = prefix + "_" + tag();
        return test::identities::createUser(name, db::query::rbac::role::Admin::get(role), name + "@vaulthalla.test");
    }

    static std::pair<int, std::string> cli(const std::string& line, const UserPtr& user) {
        try {
            const auto res = router->executeLine(line, user, nullptr);
            return {res.exit_code, res.stdout_text + res.stderr_text};
        } catch (const std::exception& e) {
            return {1, e.what()};
        }
    }

    static std::shared_ptr<protocols::ws::Session> ws(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    static bool wsOk(const std::function<void()>& fn) {
        try {
            fn();
            return true;
        } catch (const std::exception&) {
            return false;
        }
    }

    static vh::device::Peer devicePeer() {
        const auto spki = crypto::randomNonce();
        return vh::device::Peer{.spki = spki, .spkiHex = crypto::toHex(spki), .address = "192.0.2.44"};
    }

    // A confirmed request from a new device key, waiting in `owner`'s window: {request id, its code, the key}.
    struct Waiting {
        std::string id{};
        std::string code{};
        std::string deviceId{};
        std::array<std::string, 3> choices{};
    };
    static Waiting waiting(const UserPtr& owner, const std::string& name = "Mac") {
        (void)ops::devices::openWindow(owner);
        const auto peer = devicePeer();
        const auto nonce = crypto::randomNonce();
        const auto receipt = ops::devices::pairRequest(peer, {.name = name, .platform = "macOS", .app_version = "1.0",
                                                              .commitment = crypto::toHex(crypto::commitment(peer.spki, nonce))});
        (void)ops::devices::pairConfirm(peer, receipt.request_id, crypto::toHex(nonce));
        const auto pending = ops::devices::pending(owner);
        const auto it = std::ranges::find(pending.requests, receipt.request_id, &vh::device::PendingRequest::request_id);
        return {receipt.request_id, *vh::device::Pairing::instance().codeForTesting(receipt.request_id), peer.spkiHex,
                it->code_choices};
    }

    static std::string decoy(const Waiting& w) {
        return *std::ranges::find_if(w.choices, [&](const auto& c) { return c != w.code; });
    }

    static vh::device::Device paired(const UserPtr& owner, const std::string& name = "Mac") {
        const auto w = waiting(owner, name);
        auto d = ops::devices::approve(owner, w.id, w.code);
        (void)ops::devices::closeWindow(owner);
        return d;
    }
};

TEST_F(DeviceParityTest, PairingWindowsOnBothSurfaces) {
    const auto alice = seedUser("dp_alice");
    const auto bob = seedUser("dp_bob");

    const auto [code, out] = cli("device pair", alice);  // not interactive: opens the window and says how to approve
    EXPECT_EQ(code, 0) << out;
    EXPECT_TRUE(ops::devices::pending(alice).window);
    // One window per node: another user is refused on both surfaces until it closes.
    EXPECT_NE(cli("device pair", bob).first, 0);
    EXPECT_FALSE(wsOk([&] { (void)handler::Devices::pairingOpen(ws(bob)); }));
    EXPECT_FALSE(handler::Devices::pairingClose(ws(bob)).at("closed").get<bool>()) << "not bob's window";

    EXPECT_EQ(cli("device pair --close", alice).first, 0);
    EXPECT_FALSE(ops::devices::pending(alice).window);
    EXPECT_TRUE(wsOk([&] { (void)handler::Devices::pairingOpen(ws(bob)); }));
    EXPECT_TRUE(ops::devices::pending(bob).window);
    // A super admin may close anyone's window.
    EXPECT_TRUE(handler::Devices::pairingClose(ws(superUser)).at("closed").get<bool>());
}

TEST_F(DeviceParityTest, NumberMatchingOnBothSurfaces) {
    const auto alice = seedUser("dp_nm");

    // A wrong code denies, through either surface; nothing is created.
    auto w = waiting(alice);
    EXPECT_NE(cli("device approve " + w.id + " --code " + decoy(w), alice).first, 0);
    EXPECT_EQ(vh::device::Pairing::instance().codeForTesting(w.id), std::nullopt) << "denied requests are gone";
    w = waiting(alice);
    EXPECT_FALSE(wsOk([&] { (void)handler::Devices::pairingApprove({{"request_id", w.id}, {"code", decoy(w)}}, ws(alice)); }));
    EXPECT_FALSE(db::query::device::Devices::byCurrentSpki(w.deviceId));

    // Non-interactive approval needs the code.
    w = waiting(alice);
    EXPECT_NE(cli("device approve " + w.id, alice).first, 0);

    // The right code pairs, through either surface, for the window's owner.
    const auto [code, out] = cli("device approve " + w.id + " --code \"" + crypto::displayCode(w.code) + "\"", alice);
    EXPECT_EQ(code, 0) << out;
    auto row = db::query::device::Devices::byCurrentSpki(w.deviceId);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->user_id, alice->id);
    EXPECT_EQ(row->approved_by, alice->id);
    EXPECT_EQ(row->last_ip, "192.0.2.44");

    w = waiting(alice);
    EXPECT_TRUE(wsOk([&] { (void)handler::Devices::pairingApprove({{"request_id", w.id}, {"code", w.code}}, ws(alice)); }));
    row = db::query::device::Devices::byCurrentSpki(w.deviceId);
    ASSERT_TRUE(row);
    EXPECT_EQ(row->user_id, alice->id);

    // Deny on both surfaces.
    w = waiting(alice);
    EXPECT_EQ(cli("device deny " + w.id, alice).first, 0);
    w = waiting(alice);
    EXPECT_TRUE(wsOk([&] { (void)handler::Devices::pairingDeny({{"request_id", w.id}}, ws(alice)); }));
    EXPECT_TRUE(ops::devices::pending(alice).requests.empty());
}

TEST_F(DeviceParityTest, DevicesAreTheirUsersOnBothSurfaces) {
    const auto alice = seedUser("dp_own");
    const auto mallory = seedUser("dp_mal");
    const auto d = paired(alice, "Alice's Mac");

    // Listing: own devices for everyone; every device only for super admins.
    const auto [listCode, listOut] = cli("device list --json", alice);
    ASSERT_EQ(listCode, 0) << listOut;
    const auto cliList = json::parse(listOut);
    const auto wsList = handler::Devices::list(json::object(), ws(alice)).at("devices");
    EXPECT_EQ(cliList, wsList);
    ASSERT_EQ(wsList.size(), 1u);
    EXPECT_EQ(wsList.at(0).at("device_id"), d.spki_sha256);
    EXPECT_TRUE(handler::Devices::list(json::object(), ws(mallory)).at("devices").empty());
    EXPECT_NE(cli("device list --all", alice).first, 0);
    EXPECT_FALSE(wsOk([&] { (void)handler::Devices::list({{"all", true}}, ws(alice)); }));
    EXPECT_EQ(cli("device list --all", superUser).first, 0);
    EXPECT_TRUE(wsOk([&] { (void)handler::Devices::list({{"all", true}}, ws(superUser)); }));

    // Rename and revoke: another user can't (and can't tell it exists); the owner and a super admin can.
    EXPECT_NE(cli("device rename " + std::to_string(d.id) + " Stolen", mallory).first, 0);
    EXPECT_FALSE(wsOk([&] { (void)handler::Devices::rename({{"device_id", d.spki_sha256}, {"name", "Stolen"}}, ws(mallory)); }));
    EXPECT_EQ(db::query::device::Devices::byId(d.id)->name, "Alice's Mac");
    EXPECT_EQ(cli("device rename " + d.spki_sha256.substr(0, 12) + " \"Work Mac\"", alice).first, 0);
    EXPECT_EQ(db::query::device::Devices::byId(d.id)->name, "Work Mac");
    EXPECT_TRUE(wsOk([&] { (void)handler::Devices::rename({{"device_id", d.spki_sha256}, {"name", "Home Mac"}}, ws(superUser)); }));
    EXPECT_EQ(db::query::device::Devices::byId(d.id)->name, "Home Mac");
    EXPECT_NE(cli("device rename " + std::to_string(d.id) + " \"\"", alice).first, 0) << "names are 1-64 characters";

    EXPECT_NE(cli("device revoke " + std::to_string(d.id), mallory).first, 0);
    EXPECT_FALSE(wsOk([&] { (void)handler::Devices::revoke({{"device_id", d.spki_sha256}}, ws(mallory)); }));
    EXPECT_FALSE(db::query::device::Devices::byId(d.id)->revoked());
    EXPECT_EQ(cli("device revoke " + std::to_string(d.id), alice).first, 0);
    EXPECT_TRUE(db::query::device::Devices::byId(d.id)->revoked());
    const auto d2 = paired(alice);
    EXPECT_TRUE(wsOk([&] { (void)handler::Devices::revoke({{"device_id", d2.spki_sha256}}, ws(superUser)); }));
    EXPECT_TRUE(db::query::device::Devices::byId(d2.id)->revoked());
}

// The listener's exposure is a daemon setting: for every seeded admin role, allowed exactly for super admins, on
// both surfaces, and persisted to config.yaml.
TEST_F(DeviceParityTest, RemoteSwitchOnlyForSuperAdmins) {
    for (const auto& role : db::query::rbac::role::Admin::list()) {
        if (role->name.starts_with("dp_")) continue;
        const auto caller = seedUser("dp_remote", role->name);
        const bool allowed = caller->isSuperAdmin();

        const auto statusCli = cli("device remote status", caller).first == 0;
        const auto statusWs = wsOk([&] { (void)handler::Devices::remoteStatus(ws(caller)); });
        EXPECT_EQ(statusCli, allowed) << role->name;
        EXPECT_EQ(statusWs, allowed) << role->name;

        const auto enableCli = cli("device remote enable", caller).first == 0;
        EXPECT_EQ(enableCli, allowed) << role->name;
        EXPECT_EQ(config::Registry::get().device_server.remote, allowed) << role->name;
        EXPECT_EQ(config::loadConfig(paths::getConfigPath().string()).device_server.remote, allowed) << role->name;

        const auto disableWs = wsOk([&] { (void)handler::Devices::remoteDisable(ws(caller)); });
        EXPECT_EQ(disableWs, allowed) << role->name;
        if (allowed) {
            EXPECT_FALSE(config::Registry::get().device_server.remote) << role->name;
            EXPECT_TRUE(wsOk([&] { (void)handler::Devices::remoteEnable(ws(caller)); }));
            EXPECT_TRUE(config::Registry::get().device_server.remote);
            EXPECT_EQ(cli("device remote disable", caller).first, 0);
        }
        EXPECT_FALSE(config::Registry::get().device_server.remote) << role->name;
    }
}

}
