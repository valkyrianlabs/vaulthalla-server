// The device listener end to end over real TLS 1.3 (docs/pairing.md): the handshake profile, authorization by the
// client key at handshake time (pairing-only vs Device session, revoked -> pairing-only with device_unknown), the
// whole pairing flow through the ws Router (request -> confirm -> number matching -> approve -> reconnect as a
// device), key rotation (idempotent retry, replays refused), RBAC on live device sessions (role changes and
// deactivation seen at once; revokeSessions and revocation close them), the sweeper, and the listener rebinding when
// remote connections are turned on and off.

#include "../helpers/device_client.hpp"
#include "../helpers/identities.hpp"
#include "auth/Manager.hpp"
#include "auth/session/Manager.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Crypto.hpp"
#include "device/Pairing.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "identities/Manager.hpp"
#include "identities/User.hpp"
#include "ops/Devices.hpp"
#include "protocols/device/Listener.hpp"
#include "protocols/device/Service.hpp"
#include "protocols/ws/ConnectionLifecycleManager.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/handler/Devices.hpp"
#include "rbac/role/Admin.hpp"
#include "runtime/Deps.hpp"
#include "seed/include/init_db_tables.hpp"
#include "seed/include/seed_db.hpp"
#include "Contract.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <paths.h>

#include <atomic>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <thread>

namespace vh::test_device_listener {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using vh::test::device::Client;
using vh::test::device::ClientIdentity;
namespace crypto = vh::device::crypto;
namespace handler = protocols::ws::handler;
using Decision = protocols::ws::Router::CommandAuthDecision;
using namespace std::chrono_literals;

std::string tag() {
    static std::atomic<unsigned> n{0};
    static const auto run = std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000);
    return run + "x" + std::to_string(n.fetch_add(1));
}

std::string code(const std::optional<json>& reply) {
    if (!reply || !reply->contains("data") || !reply->at("data").is_object()) return "";
    return reply->at("data").value("code", "");
}

bool ok(const std::optional<json>& reply) { return reply && reply->value("status", "") == "OK"; }

class DeviceListenerTest : public ::testing::Test {
protected:
    inline static bool skipTests = false;
    inline static std::shared_ptr<boost::asio::io_context> ioc;
    inline static std::vector<std::thread> threads;
    inline static std::shared_ptr<protocols::device::Listener> listener;
    inline static std::shared_ptr<const vh::device::ServerIdentity> server;
    inline static uint16_t port = 0;
    inline static UserPtr super;

    static void SetUpTestSuite() {
        if (!(std::getenv("VH_TEST_DB_USER") && std::getenv("VH_TEST_DB_PASS") && std::getenv("VH_TEST_DB_HOST") &&
              std::getenv("VH_TEST_DB_PORT") && std::getenv("VH_TEST_DB_NAME"))) {
            skipTests = true;
            std::cout << "[test_device_listener] Skipping db tests due to missing environment variables." << std::endl;
            return;
        }
        paths::enableTestMode();
        const auto root = std::filesystem::temp_directory_path() / ("vh_device_" + tag());
        paths::backingPath = root / "backing";
        paths::mountPath = root / "mount";
        std::filesystem::create_directories(paths::backingPath);
        std::filesystem::create_directories(paths::mountPath);

        db::Transactions::init();
        db::seed::nuke_and_recreate_schema_public();
        db::Transactions::dbPool_->initPreparedStatements();
        seed::seed_database();
        runtime::Deps::init();

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

        super = seedUser("dl_super", "super_admin");
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        listener->close();
        protocols::device::closeAllDeviceListenerSessions();
        std::this_thread::sleep_for(100ms);
        ioc->stop();
        for (auto& t : threads) t.join();
        threads.clear();
    }

    void SetUp() override {
        if (skipTests) GTEST_SKIP() << "Skipping db tests due to missing environment variables.";
        vh::device::Pairing::instance().resetForTesting();
    }

    static UserPtr seedUser(const std::string& prefix, const std::string& role = "unprivileged") {
        const auto name = prefix + "_" + tag();
        return test::identities::createUser(name, db::query::rbac::role::Admin::get(role), name + "@vaulthalla.test");
    }

    // A console session for `user` (the owner's side runs through the same handlers the web calls).
    static std::shared_ptr<protocols::ws::Session> console(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    // The daemon's side of a client's connection.
    static std::shared_ptr<protocols::ws::Session> serverSession(const ClientIdentity& device) {
        for (int i = 0; i < 50; ++i) {
            for (const auto& [_, s] : runtime::Deps::get().sessionManager->getActive())
                if (s && s->devicePeer() && s->devicePeer()->spkiHex == device.deviceId() && !s->closing()) return s;
            std::this_thread::sleep_for(20ms);
        }
        return nullptr;
    }

    // Pairs `device` to `owner` through the real listener and returns the devices row.
    static vh::device::Device pair(const ClientIdentity& device, const UserPtr& owner, const std::string& name = "Mac") {
        (void)handler::Devices::pairingOpen(console(owner));
        Client client(port, device);
        EXPECT_TRUE(client.connect());
        const auto nonceDevice = crypto::randomNonce();
        const auto request = client.call("device.pair.request",
                                          {{"name", name}, {"platform", "macOS"}, {"app_version", "1.0.0"},
                                           {"commitment", crypto::toHex(crypto::commitment(device.publicKey().spkiSha256, nonceDevice))}});
        EXPECT_TRUE(ok(request)) << (request ? request->dump() : "no reply");
        const auto requestId = request->at("data").at("request_id").get<std::string>();
        const auto nonceServer = *crypto::hashFromHex(request->at("data").at("nonce_server").get<std::string>());
        EXPECT_TRUE(ok(client.call("device.pair.confirm", {{"request_id", requestId}, {"nonce_device", crypto::toHex(nonceDevice)}})));
        const auto sas = crypto::sasCode(crypto::sasDigest(client.serverKey()->spkiSha256, device.publicKey().spkiSha256,
                                                           nonceDevice, nonceServer));
        const auto approved = handler::Devices::pairingApprove({{"request_id", requestId}, {"code", sas}}, console(owner));
        (void)handler::Devices::pairingClose(console(owner));
        return *db::query::device::Devices::byId(approved.at("device").at("id").get<uint32_t>());
    }
};

// ---- the TLS profile and authorization at handshake ---------------------------------------------------------------

TEST_F(DeviceListenerTest, TlsProfileIsMutualTls13WithAP256ClientKey) {
    const ClientIdentity device;
    {
        Client client(port, device);
        ASSERT_TRUE(client.connect());
        ASSERT_TRUE(client.serverKey());
        EXPECT_EQ(client.serverKey()->spkiSha256, server->spkiSha256()) << "the pin is the server key's SPKI hash";
    }
    {
        Client::Options tls12;
        tls12.maxTlsVersion = TLS1_2_VERSION;
        Client client(port, device, tls12);
        EXPECT_FALSE(client.connect()) << "TLS 1.2 is refused";
    }
    {
        Client::Options noCert;
        noCert.presentCertificate = false;
        Client client(port, device, noCert);
        EXPECT_FALSE(client.connect()) << "a client certificate is required";
    }
    {
        // An EC key on another curve: not a device key.
        EVP_PKEY* p384 = EVP_PKEY_Q_keygen(nullptr, nullptr, "EC", "P-384");
        X509* cert = X509_new();
        X509_set_version(cert, X509_VERSION_3);
        ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);
        X509_gmtime_adj(X509_getm_notBefore(cert), -60);
        X509_gmtime_adj(X509_getm_notAfter(cert), 3600);
        X509_NAME_add_entry_by_txt(X509_get_subject_name(cert), "CN", MBSTRING_ASC,
                                   reinterpret_cast<const unsigned char*>("p384"), -1, -1, 0);
        X509_set_issuer_name(cert, X509_get_subject_name(cert));
        X509_set_pubkey(cert, p384);
        X509_sign(cert, p384, EVP_sha384());
        Client::Options other;
        other.overrideKey = p384;
        other.overrideCert = cert;
        Client client(port, device, other);
        EXPECT_FALSE(client.connect()) << "only ECDSA P-256 device keys";
        X509_free(cert);
        EVP_PKEY_free(p384);
    }
    {
        Client client(port, device);
        ASSERT_TRUE(client.connect("/nothing-here") == false) << "only /ws upgrades today (HTTP lanes are S1b)";
    }
}

TEST_F(DeviceListenerTest, AnUnknownKeyOnlyPairs) {
    const ClientIdentity device;
    Client client(port, device);
    ASSERT_TRUE(client.connect());
    for (const auto* command : {"fs.list", "auth.login", "device.list", "device.server.identity", "settings.get",
                                "share.session.open", "storage.vault.list"}) {
        const auto reply = client.call(command, {{"vault_id", 1}, {"path", "/"}});
        ASSERT_TRUE(reply) << command;
        EXPECT_EQ(reply->value("status", ""), "ERROR") << command;
        EXPECT_EQ(code(reply), "device_unknown") << command;
    }
    EXPECT_TRUE(ok(client.call("meta.contract.get")));
    EXPECT_EQ(code(client.call("device.pair.request", {{"name", "Mac"}, {"platform", "macOS"},
                                                        {"commitment", std::string(64, '0')}})),
              "no_pairing_window");

    const auto session = serverSession(device);
    ASSERT_TRUE(session);
    EXPECT_TRUE(session->isDevicePairing());
    EXPECT_FALSE(session->user);
    EXPECT_EQ(session->ipAddress, "127.0.0.1");
}

// ---- the whole pairing flow through the router -------------------------------------------------------------------

TEST_F(DeviceListenerTest, PairingFlowEndToEnd) {
    const auto owner = seedUser("dl_owner");
    const ClientIdentity device;
    Client client(port, device);
    ASSERT_TRUE(client.connect());

    (void)handler::Devices::pairingOpen(console(owner));

    const auto requestAndConfirm = [&](crypto::Hash& nonceServerOut) {
        const auto nonceDevice = crypto::randomNonce();
        const auto request = client.call("device.pair.request",
                                          {{"name", "Studio Mac"}, {"platform", "macOS"}, {"app_version", "1.2.0"},
                                           {"commitment", crypto::toHex(crypto::commitment(device.publicKey().spkiSha256, nonceDevice))}});
        EXPECT_TRUE(ok(request)) << (request ? request->dump() : "");
        const auto id = request->at("data").at("request_id").get<std::string>();
        nonceServerOut = *crypto::hashFromHex(request->at("data").at("nonce_server").get<std::string>());
        // Not shown to the owner before the device reveals its nonce.
        EXPECT_TRUE(handler::Devices::pairingPending(console(owner)).at("requests").empty());
        const auto confirm = client.call("device.pair.confirm", {{"request_id", id}, {"nonce_device", crypto::toHex(nonceDevice)}});
        EXPECT_TRUE(ok(confirm));
        EXPECT_EQ(confirm->at("data").at("state"), "pending");
        EXPECT_EQ(client.call("device.pair.status", {{"request_id", id}})->at("data").at("state"), "pending");
        // Desktop's own view of the code: the server key it saw in the handshake, its own key, both nonces.
        const auto sas = crypto::sasCode(crypto::sasDigest(client.serverKey()->spkiSha256, device.publicKey().spkiSha256,
                                                           nonceDevice, nonceServerOut));
        return std::pair{id, sas};
    };

    // 1. A wrong pick among the three choices denies the request.
    crypto::Hash nonceServer{};
    auto [firstId, firstCode] = requestAndConfirm(nonceServer);
    auto pending = handler::Devices::pairingPending(console(owner));
    ASSERT_EQ(pending.at("requests").size(), 1u);
    const auto& entry = pending.at("requests").at(0);
    EXPECT_EQ(entry.at("device_id"), device.deviceId());
    EXPECT_EQ(entry.at("source_ip"), "127.0.0.1");
    const auto choices = entry.at("code_choices").get<std::vector<std::string>>();
    ASSERT_EQ(choices.size(), 3u);
    EXPECT_EQ(std::ranges::count(choices, firstCode), 1) << "the code the Mac shows is one of the three";
    const auto decoy = *std::ranges::find_if(choices, [&](const auto& c) { return c != firstCode; });
    EXPECT_THROW((void)handler::Devices::pairingApprove({{"request_id", firstId}, {"code", decoy}}, console(owner)),
                 ops::Invalid);
    EXPECT_EQ(client.call("device.pair.status", {{"request_id", firstId}})->at("data").at("state"), "denied");
    EXPECT_FALSE(db::query::device::Devices::byCurrentSpki(device.deviceId()));

    // 2. Starting over with fresh nonces; the right code creates the device for the owner.
    auto [secondId, secondCode] = requestAndConfirm(nonceServer);
    const auto other = seedUser("dl_other");
    EXPECT_THROW((void)handler::Devices::pairingApprove({{"request_id", secondId}, {"code", secondCode}}, console(other)),
                 ops::NotFound) << "only the window's owner approves";
    const auto approved = handler::Devices::pairingApprove({{"request_id", secondId}, {"code", secondCode}}, console(owner));
    const auto row = db::query::device::Devices::byCurrentSpki(device.deviceId());
    ASSERT_TRUE(row);
    EXPECT_EQ(row->user_id, owner->id);
    EXPECT_EQ(row->approved_by, owner->id);
    EXPECT_EQ(row->name, "Studio Mac");
    EXPECT_EQ(row->platform, "macOS");
    EXPECT_EQ(row->app_version, "1.2.0");
    EXPECT_EQ(row->last_ip, "127.0.0.1");
    EXPECT_EQ(approved.at("device").at("device_id"), device.deviceId());

    const auto status = client.call("device.pair.status", {{"request_id", secondId}});
    ASSERT_TRUE(ok(status));
    EXPECT_EQ(status->at("data").at("state"), "approved");
    EXPECT_EQ(status->at("data").at("device_id"), device.deviceId());
    EXPECT_FALSE(status->at("data").at("node_id").get<std::string>().empty());
    EXPECT_EQ(status->at("data").at("node_id"), db::query::device::Devices::nodeId()) << "stable";
    EXPECT_FALSE(status->at("data").at("node_name").get<std::string>().empty());

    // The pairing connection stays pairing-only (authorization happens at the handshake)...
    EXPECT_EQ(code(client.call("device.list")), "device_unknown");

    // 3. ...and the reconnect is a Device session acting as the owner.
    Client paired(port, device);
    ASSERT_TRUE(paired.connect());
    const auto identity = paired.call("device.server.identity");
    ASSERT_TRUE(ok(identity));
    EXPECT_EQ(identity->at("data").at("spki_sha256"), server->spkiHex());
    const auto list = paired.call("device.list");
    ASSERT_TRUE(ok(list));
    ASSERT_EQ(list->at("data").at("devices").size(), 1u);
    EXPECT_EQ(list->at("data").at("devices").at(0).at("user_id"), owner->id);
    EXPECT_EQ(paired.call("auth.login", {{"name", owner->name()}, {"password", "x"}})->value("status", ""), "UNAUTHORIZED");
    EXPECT_EQ(paired.call("auth.refresh")->value("status", ""), "UNAUTHORIZED");
    EXPECT_EQ(code(paired.call("device.pair.request", {{"name", "Mac"}, {"platform", "macOS"},
                                                       {"commitment", std::string(64, '0')}})),
              "conflict") << "a paired key never pairs again";
    const auto session = serverSession(device);
    ASSERT_TRUE(session);
    EXPECT_TRUE(session->isDeviceSession());
    EXPECT_EQ(session->user.get(), identities::manager().user(owner->id).get()) << "the canonical user object";
    EXPECT_TRUE(session->rbacActor().isHuman()) << "a device acts as its user: the human actor";
    EXPECT_EQ(session->rbacActor().user().get(), owner.get());
}

// ---- revocation ---------------------------------------------------------------------------------------------------

TEST_F(DeviceListenerTest, RevocationClosesLiveSessionsAndTheKeyOnlyPairsAgain) {
    const auto owner = seedUser("dl_rev");
    const ClientIdentity device;
    const auto row = pair(device, owner);
    Client live(port, device);
    ASSERT_TRUE(live.connect());
    ASSERT_TRUE(ok(live.call("device.list")));

    // Another user can't see it; the owner revokes it and the live session closes at once.
    const auto stranger = seedUser("dl_stranger");
    EXPECT_THROW((void)ops::devices::revoke(stranger, row.spki_sha256), ops::NotFound);
    (void)ops::devices::revoke(owner, row.spki_sha256);
    EXPECT_TRUE(live.closedByServer());

    Client again(port, device);
    ASSERT_TRUE(again.connect());
    EXPECT_EQ(code(again.call("device.list")), "device_unknown") << "revoked looks exactly like unknown";
    (void)handler::Devices::pairingOpen(console(owner));
    EXPECT_EQ(code(again.call("device.pair.request", {{"name", "Mac"}, {"platform", "macOS"},
                                                      {"commitment", std::string(64, '0')}})),
              "conflict") << "a revoked key can never be approved again";
    (void)handler::Devices::pairingClose(console(owner));

    // The device itself can unpair ("Unpair this Mac"); a super admin can revoke anyone's.
    const ClientIdentity second;
    const auto secondRow = pair(second, owner);
    Client self(port, second);
    ASSERT_TRUE(self.connect());
    EXPECT_TRUE(ok(self.call("device.revoke", {{"device_id", second.deviceId()}})));
    EXPECT_TRUE(self.closedByServer());
    const ClientIdentity third;
    const auto thirdRow = pair(third, owner);
    EXPECT_NO_THROW((void)ops::devices::revoke(super, std::to_string(thirdRow.id)));
    EXPECT_TRUE(db::query::device::Devices::byId(thirdRow.id)->revoked());
}

// ---- key rotation (spec §4) ---------------------------------------------------------------------------------------

TEST_F(DeviceListenerTest, KeyRotation) {
    const auto owner = seedUser("dl_rot");
    const ClientIdentity oldKey;
    const auto row = pair(oldKey, owner);
    Client oldSession(port, oldKey);
    ASSERT_TRUE(oldSession.connect());

    const auto proof = [&](const ClientIdentity& signer, const ClientIdentity& next, const int64_t ts,
                           const crypto::Hash& serverSpki) {
        const auto message = crypto::rotationMessage(next.publicKey().spkiSha256, serverSpki, static_cast<uint64_t>(ts));
        return json{{"certificate", crypto::toBase64(next.certificateDer())}, {"timestamp", ts},
                    {"signature", crypto::toBase64(signer.sign(message))}};
    };
    const auto now = static_cast<int64_t>(std::time(nullptr));
    const ClientIdentity newKey;

    // Replays and forgeries are refused before anything changes.
    EXPECT_EQ(code(oldSession.call("device.identity.rotate", proof(oldKey, newKey, now - 301, server->spkiSha256()))),
              "invalid") << "older than 300 s";
    EXPECT_EQ(code(oldSession.call("device.identity.rotate", proof(oldKey, newKey, now, crypto::randomNonce()))),
              "invalid") << "minted for another node";
    EXPECT_EQ(code(oldSession.call("device.identity.rotate", proof(newKey, newKey, now, server->spkiSha256()))),
              "invalid") << "not signed by the connection's key";
    const ClientIdentity taken;
    (void)pair(taken, owner);
    EXPECT_EQ(code(oldSession.call("device.identity.rotate", proof(oldKey, taken, now, server->spkiSha256()))),
              "conflict") << "a key another device has";
    EXPECT_EQ(db::query::device::Devices::byId(row.id)->spki_sha256, oldKey.deviceId());

    // The rotation itself.
    const auto rotated = oldSession.call("device.identity.rotate", proof(oldKey, newKey, now, server->spkiSha256()));
    ASSERT_TRUE(ok(rotated)) << (rotated ? rotated->dump() : "");
    EXPECT_EQ(rotated->at("data").at("device_id"), newKey.deviceId());
    auto after = db::query::device::Devices::byId(row.id);
    EXPECT_EQ(after->spki_sha256, newKey.deviceId());
    EXPECT_EQ(after->previous_spki_sha256, oldKey.deviceId());

    // The reply was "lost": a retry from the old key naming the same new key succeeds again (a fresh proof)...
    const auto retry = oldSession.call("device.identity.rotate", proof(oldKey, newKey, now + 1, server->spkiSha256()));
    ASSERT_TRUE(ok(retry));
    EXPECT_EQ(retry->at("data").at("device_id"), newKey.deviceId());
    // ...naming another key is a conflict.
    const ClientIdentity another;
    EXPECT_EQ(code(oldSession.call("device.identity.rotate", proof(oldKey, another, now, server->spkiSha256()))),
              "conflict");

    // The old key keeps authenticating until the first handshake with the new one.
    Client graceful(port, oldKey);
    ASSERT_TRUE(graceful.connect());
    EXPECT_TRUE(ok(graceful.call("device.list")));
    Client renewed(port, newKey);
    ASSERT_TRUE(renewed.connect());
    EXPECT_TRUE(ok(renewed.call("device.server.identity")));
    after = db::query::device::Devices::byId(row.id);
    EXPECT_FALSE(after->previous_spki_sha256) << "the first handshake with the new key ends the grace";
    Client stale(port, oldKey);
    ASSERT_TRUE(stale.connect());
    EXPECT_EQ(code(stale.call("device.list")), "device_unknown");
}

// ---- RBAC on live device sessions (D3) ---------------------------------------------------------------------------

TEST_F(DeviceListenerTest, LiveDeviceSessionsFollowTheirUser) {
    const auto owner = seedUser("dl_rbac");
    const ClientIdentity device;
    (void)pair(device, owner);
    Client client(port, device);
    ASSERT_TRUE(client.connect());

    EXPECT_EQ(code(client.call("device.remote.status")), "denied") << "super admins only";
    EXPECT_EQ(code(client.call("device.list", {{"all", true}})), "denied");

    // A role change reaches the open session through the canonical user object.
    (void)identities::manager().updateUser(owner->id, [](identities::UserState& s) {
        s.roles.admin = db::query::rbac::role::Admin::get("super_admin");
    });
    EXPECT_TRUE(ok(client.call("device.remote.status")));
    EXPECT_TRUE(ok(client.call("device.list", {{"all", true}})));

    // Deactivation: the next command is refused.
    (void)identities::manager().updateUser(owner->id, [](identities::UserState& s) { s.meta.is_active = false; });
    EXPECT_EQ(client.call("device.list")->value("status", ""), "UNAUTHORIZED");
    const auto session = serverSession(device);
    ASSERT_TRUE(session);
    EXPECT_EQ(protocols::ws::ConnectionLifecycleManager::verdict(*session, std::chrono::system_clock::now(), 60s),
              protocols::ws::ConnectionLifecycleManager::SweepVerdict::DeviceEnded);
    (void)identities::manager().updateUser(owner->id, [](identities::UserState& s) { s.meta.is_active = true; });
    EXPECT_TRUE(ok(client.call("device.list")));
    EXPECT_EQ(protocols::ws::ConnectionLifecycleManager::verdict(*session, std::chrono::system_clock::now() + 24h, 60s),
              protocols::ws::ConnectionLifecycleManager::SweepVerdict::Keep)
        << "a device session has no refresh token to expire";

    // revokeSessions (password reset, role change, deletion) closes it.
    runtime::Deps::get().authManager->revokeSessions(owner->id);
    EXPECT_TRUE(client.closedByServer());
    Client back(port, device);
    ASSERT_TRUE(back.connect());
    EXPECT_TRUE(ok(back.call("device.list"))) << "the device is still paired: it just reconnects";

    // Deleting the account deletes its devices (ON DELETE CASCADE): the key is unknown again.
    identities::manager().deleteUser(owner->id);
    EXPECT_FALSE(db::query::device::Devices::byCurrentSpki(device.deviceId()));
    runtime::Deps::get().authManager->revokeSessions(owner->id);
    EXPECT_TRUE(back.closedByServer());
    Client gone(port, device);
    ASSERT_TRUE(gone.connect());
    EXPECT_EQ(code(gone.call("device.list")), "device_unknown");
}

// The sweeper times out pairing-only connections that outlive any window; the book's auth levels are what the router
// enforces on each kind of device-listener session.
TEST_F(DeviceListenerTest, SweeperAndContractAuthLevelsMatchTheRouter) {
    const auto owner = seedUser("dl_book");
    const ClientIdentity unpaired, paired;
    (void)pair(paired, owner);
    Client a(port, unpaired), b(port, paired);
    ASSERT_TRUE(a.connect());
    ASSERT_TRUE(b.connect());
    const auto pairingSession = serverSession(unpaired);
    const auto deviceSession = serverSession(paired);
    ASSERT_TRUE(pairingSession && deviceSession);
    const auto human = console(owner);

    using Verdict = protocols::ws::ConnectionLifecycleManager::SweepVerdict;
    const auto now = std::chrono::system_clock::now();
    EXPECT_EQ(protocols::ws::ConnectionLifecycleManager::verdict(*pairingSession, now, 60s), Verdict::Keep);
    EXPECT_EQ(protocols::ws::ConnectionLifecycleManager::verdict(*pairingSession, now + 16min, 60s), Verdict::DeviceEnded);

    for (const auto& cmd : contract::ws::commands()) {
        const auto& c = cmd.command;
        if (cmd.auth == "pairing") {
            EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *pairingSession), Decision::Allow) << c;
            EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *deviceSession), Decision::Allow) << c;
            EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *human), Decision::Deny) << c;
        } else if (cmd.auth == "device") {
            EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *deviceSession), Decision::Allow) << c;
            EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *pairingSession), Decision::DenyDeviceUnknown) << c;
            EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *human), Decision::Deny) << c;
        } else if (cmd.auth == "human") {
            const bool deviceMayRun = c != "auth.register";
            EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *deviceSession),
                      deviceMayRun ? Decision::Allow : Decision::Deny) << c;
            EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *pairingSession), Decision::DenyDeviceUnknown) << c;
        } else if (cmd.auth == "session") {
            const bool deviceMayRun = c == "auth.isAuthenticated" || c == "meta.contract.get";
            EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *deviceSession),
                      deviceMayRun ? Decision::Allow : Decision::Deny) << c;
        }
    }
}

// ---- the listener's exposure (D1) ---------------------------------------------------------------------------------

TEST_F(DeviceListenerTest, RemoteConnectionsRebindTheListenerLive) {
    const auto before = config::Registry::get();
    auto cfg = before;
    cfg.device_server.enabled = true;
    cfg.device_server.port = 0;  // never the real 36972 (a packaged daemon may run on this host)
    cfg.device_server.remote = false;
    config::Registry::set(cfg);

    protocols::device::Service service;
    service.setIdentityForTesting(server);
    service.start();
    protocols::device::ListenerStatus status;
    for (int i = 0; i < 100 && !(status = service.listenerStatus()).listening; ++i) std::this_thread::sleep_for(20ms);
    ASSERT_TRUE(status.listening) << status.error.value_or("");
    EXPECT_TRUE(status.address.starts_with("127.0.0.1:")) << status.address;
    EXPECT_FALSE(status.remote);
    EXPECT_EQ(status.server_spki_sha256, server->spkiHex());

    cfg.device_server.remote = true;
    config::Registry::set(cfg);
    status = service.applyConfig();
    EXPECT_TRUE(status.listening);
    EXPECT_TRUE(status.address.starts_with("0.0.0.0:")) << status.address;
    const auto remotePort = static_cast<uint16_t>(std::stoi(status.address.substr(status.address.rfind(':') + 1)));
    const ClientIdentity device;
    {
        Client client(remotePort, device);
        EXPECT_TRUE(client.connect()) << "reachable after the rebind, without a restart";
    }

    cfg.device_server.remote = false;
    config::Registry::set(cfg);
    status = service.applyConfig();
    EXPECT_TRUE(status.address.starts_with("127.0.0.1:")) << status.address;

    service.stop();
    config::Registry::set(before);
}

// `vh device remote enable` / device.remote.enable: super admins only, saved to config.yaml (kept across restarts and
// upgrades, which never rewrite it).
TEST_F(DeviceListenerTest, RemoteSwitchIsASuperAdminSetting) {
    const auto before = config::Registry::get();
    const auto previousConfigPath = paths::configPath;
    const auto tmp = std::filesystem::temp_directory_path() / ("vh_device_config_" + tag() + ".yaml");
    std::filesystem::copy_file(previousConfigPath, tmp);
    paths::configPath = tmp;

    const auto plain = seedUser("dl_plain");
    EXPECT_THROW((void)ops::devices::setRemote(plain, true), ops::Denied);
    EXPECT_THROW((void)ops::devices::remoteStatus(plain), ops::Denied);
    EXPECT_FALSE(config::Registry::get().device_server.remote);

    const auto status = ops::devices::setRemote(super, true);
    EXPECT_TRUE(status.remote);
    EXPECT_TRUE(config::Registry::get().device_server.remote);
    EXPECT_TRUE(config::loadConfig(tmp.string()).device_server.remote) << "persisted";
    (void)ops::devices::setRemote(super, false);
    EXPECT_FALSE(config::loadConfig(tmp.string()).device_server.remote);

    paths::configPath = previousConfigPath;
    std::filesystem::remove(tmp);
    config::Registry::set(before);
}

}
