// vh-test-tier: db-only
// Every test here needs VH_TEST_DB_*, so -Ddb_tests=false builds (CI) leave this file out.
// Linked servers (design/peers/link.md) through the real device listener over TLS 1.3: this process is server B (the
// window's side, the accepting end); the test client is server A, speaking the peer wire with its own key. Covers the
// pairing transcript end to end (window, request, confirm, number matching, the brokered expect_spki check), the Peer
// session a linked key gets and what it may run (invariant 1), keys that are a device's or a server's and never both
// (invariant 2), the dialling end's pin (invariant 5, the link service against this listener), nothing dialled and
// no peer key accepted without rows (invariant 6), unlinking closing the link and refusing the key (invariant 7),
// a rotation announcement and the announced key taking over, and the switch turned off. The two-daemon half (A's own
// side, reconnecting after a restart) is the Tier B drill `vhh drill peers` (tools/harness/vhh/drill_peers.py).

#include "../helpers/db_suite.hpp"
#include "../helpers/device_client.hpp"
#include "../helpers/identities.hpp"
#include "audit/Trail.hpp"
#include "auth/model/RefreshToken.hpp"
#include "auth/model/TokenPair.hpp"
#include "auth/session/Manager.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Registry.hpp"
#include "db/Transactions.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/rbac/role/Admin.hpp"
#include "device/Crypto.hpp"
#include "device/Pairing.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Peers.hpp"
#include "peer/Crypto.hpp"
#include "peer/Keys.hpp"
#include "peer/Links.hpp"
#include "peer/Pairing.hpp"
#include "protocols/device/Listener.hpp"
#include "protocols/device/Service.hpp"
#include "protocols/ws/Client.hpp"
#include "protocols/ws/ConnectionLifecycleManager.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/TlsTransport.hpp"
#include "protocols/ws/handler/Devices.hpp"
#include "protocols/ws/handler/Peers.hpp"
#include "runtime/Deps.hpp"
#include "runtime/Manager.hpp"

#include <boost/asio/io_context.hpp>
#include <boost/asio/ssl/context.hpp>
#include <gtest/gtest.h>
#include <openssl/x509.h>

#include <atomic>
#include <chrono>
#include <future>
#include <optional>
#include <thread>

namespace vh::test_peer_link_db {

using json = nlohmann::json;
using UserPtr = std::shared_ptr<identities::User>;
using vh::test::device::Client;
using vh::test::device::ClientIdentity;
namespace dc = vh::device::crypto;
namespace pc = vh::peer::crypto;
namespace handler = protocols::ws::handler;
using namespace std::chrono_literals;

std::string replyCode(const std::optional<json>& reply) {
    if (!reply || !reply->contains("data") || !reply->at("data").is_object()) return "";
    return reply->at("data").value("code", "");
}

bool isOk(const std::optional<json>& reply) { return reply && reply->value("status", "") == "OK"; }

std::string tag() {
    static std::atomic<unsigned> n{0};
    return std::to_string(std::chrono::steady_clock::now().time_since_epoch().count() % 100000) + "p" +
           std::to_string(n.fetch_add(1));
}

// Server A's card as the test client presents it.
vh::peer::Card cardOf(const std::string& nodeId) {
    vh::peer::Card c;
    c.node_id = nodeId;
    c.name = "server-a";
    vh::peer::Key32 k{};
    k.fill(0x5a);
    c.attest_public_keys = {k};
    k.fill(0x5b);
    c.wrap_public_key = k;
    c.product_version = "1.27.0";
    return c;
}

class PeerLinkDbTest : public vh::test::db::Suite {
protected:
    inline static std::shared_ptr<boost::asio::io_context> ioc;
    inline static std::vector<std::thread> threads;
    inline static std::shared_ptr<protocols::device::Listener> listener;
    inline static std::shared_ptr<const vh::device::ServerIdentity> server;
    inline static uint16_t port = 0;
    inline static UserPtr super;
    inline static config::Config savedConfig;

    static void SetUpTestSuite() {
        if (!setUpDbSuite("peer_link")) return;
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
        super = test::identities::createUser("pl_super_" + tag(), db::query::rbac::role::Admin::get("super_admin"),
                                             "pl_super_" + tag() + "@vaulthalla.test");
        protocols::device::endpoints::clearNodeIdForTesting();
        savedConfig = config::Registry::get();
        setExperimental(true);
    }

    static void TearDownTestSuite() {
        if (skipTests) return;
        if (const auto links = vh::peer::linkService()) (void)links->disconnectAll();
        listener->close();
        protocols::device::closeAllDeviceListenerSessions();
        std::this_thread::sleep_for(200ms);
        ioc->stop();
        for (auto& t : threads) t.join();
        threads.clear();
        listener.reset();
        (void)runtime::Deps::releaseSessions();
        ioc.reset();
        config::Registry::set(savedConfig);
        vh::device::setCurrentServerIdentity(nullptr);
        tearDownDbSuite();
    }

    void SetUp() override {
        Suite::SetUp();
        if (IsSkipped()) return;
        vh::device::Pairing::instance().resetForTesting();
        vh::peer::Pairing::instance().resetForTesting();
        setExperimental(true);
    }

    static void setExperimental(const bool on) {
        auto cfg = config::Registry::get();
        cfg.peers.experimental = on;
        config::Registry::set(cfg);
    }

    static std::shared_ptr<protocols::ws::Session> console(const UserPtr& user) {
        auto s = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
        s->user = user;
        return s;
    }

    // The daemon's side of the client's connection with key `key`: a Peer session (peer) or another mode.
    static std::shared_ptr<protocols::ws::Session> serverSession(const ClientIdentity& key, const bool peer) {
        for (int i = 0; i < 100; ++i) {
            for (const auto& [_, s] : runtime::Deps::get().sessionManager->getActive()) {
                if (!s || s->closing()) continue;
                if (peer && s->isPeerSession() && s->peerPrincipal() && s->peerPrincipal()->spki_hex == key.deviceId())
                    return s;
                if (!peer && s->devicePeer() && s->devicePeer()->spkiHex == key.deviceId()) return s;
            }
            std::this_thread::sleep_for(20ms);
        }
        return nullptr;
    }

    struct Linked {
        vh::peer::Record row;
        std::string nodeA;
    };

    // A full-access device session of the super admin's, connected directly (Vaulthalla Desktop), or relayed.
    static std::shared_ptr<protocols::ws::Session> desktopSession(const bool relayed = false) {
        auto p = std::make_shared<vh::device::Peer>();
        p->spki.fill(relayed ? 0x31 : 0x32);
        p->spkiHex = dc::toHex(p->spki);
        p->address = "10.0.0.7";
        p->deviceRowId = 9;
        p->relayed = relayed;
        return protocols::ws::Session::devicePrincipal(std::move(p), super, [] {});
    }

    // The peer.link audit event's details for the row `peerId` wrote here.
    static json linkAudit(const uint32_t peerId) {
        EXPECT_TRUE(audit::Trail::instance()->flushNow());
        return db::Transactions::exec("peer link audit", [&](pqxx::work& txn) {
            for (const auto& r : txn.exec("SELECT details FROM audit_event WHERE action = 'peer.link' ORDER BY seq DESC")) {
                auto d = json::parse(r[0].as<std::string>());
                if (d.value("peer", 0u) == peerId) return d;
            }
            return json();
        });
    }

    // Server A (the client, key `a`) links with this server through the listener; `expect` is the brokered check, and
    // `via` the session that approves (the console's by default; a device session is Desktop's channel).
    static Linked link(const ClientIdentity& a, const std::optional<std::string>& expect = std::nullopt,
                       const std::shared_ptr<protocols::ws::Session>& via = nullptr) {
        const auto opened = handler::Peers::pairingOpen(console(super));
        EXPECT_EQ(opened.at("spki_sha256"), server->spkiHex());
        Client client(port, a);
        EXPECT_TRUE(client.connect());
        const auto nodeA = "node-a-" + tag();
        const auto cardA = cardOf(nodeA);
        const auto nonceA = dc::randomNonce();
        const auto request = client.call("peer.pair.request",
                                         {{"card", vh::peer::toJson(cardA)},
                                          {"commitment", dc::toHex(pc::commitment(a.publicKey().spkiSha256, nonceA))}});
        EXPECT_TRUE(isOk(request)) << (request ? request->dump() : "no reply");
        const auto receipt = request->at("data");
        const auto cardB = vh::peer::cardFromJson(receipt.at("card"));
        EXPECT_EQ(cardB.node_id, db::query::device::Devices::nodeId());
        EXPECT_EQ(cardB.wrap_public_key, vh::peer::keys::wrapPublicKey()) << "the wrap key the window created";
        const auto requestId = receipt.at("request_id").get<std::string>();
        EXPECT_TRUE(isOk(client.call("peer.pair.confirm",
                                     {{"request_id", requestId}, {"nonce_a", dc::toHex(nonceA)}})));
        // A's code, computed as A does: B's key from the handshake, both nonces, both cards.
        const auto code = pc::sasCode(pc::sasDigest(client.serverKey()->spkiSha256, a.publicKey().spkiSha256, nonceA,
                                                    *dc::hashFromHex(receipt.at("nonce_b").get<std::string>()),
                                                    pc::cardHash(cardA), pc::cardHash(cardB)));
        const auto pending = handler::Peers::pairingPending(console(super));
        EXPECT_EQ(pending.at("requests").size(), 1u);
        const auto& choices = pending.at("requests").at(0).at("code_choices");
        EXPECT_EQ(std::ranges::count(choices, json(code)), 1);
        json payload{{"request_id", requestId}, {"code", code}};
        if (expect) payload["expect_spki"] = *expect;
        std::optional<auth::stepup::Scope> scope;
        if (via) scope.emplace(via);
        const auto approved = handler::Peers::pairingApprove(payload, via ? via : console(super));
        scope.reset();
        const auto status = client.call("peer.pair.status", {{"request_id", requestId}});
        EXPECT_EQ(status->at("data").value("state", ""), "approved");
        return {*db::query::peer::Peers::byId(approved.at("peer").at("id").get<uint32_t>()), nodeA};
    }

    static json helloFrom(const std::string& nodeA) {
        return {{"node_id", nodeA}, {"name", "server-a"}, {"peer_protocol", 1}, {"product_version", "1.27.0"}};
    }
};

// Invariant 6: no rows, nothing dials and no key is a peer's.
TEST_F(PeerLinkDbTest, WithoutLinkedServersNothingDialsAndNoKeyIsAPeer) {
    db::Transactions::exec("peer.reset", [](pqxx::work& txn) { txn.exec("DELETE FROM peer"); });
    const auto links = vh::peer::linkService();
    ASSERT_TRUE(links);
    const auto before = links->dialsStarted();
    links->wake();
    links->tickForTesting();
    links->tickForTesting();
    EXPECT_EQ(links->dialsStarted(), before) << "no peer rows: nothing dials";
    const ClientIdentity stranger;
    const auto auth = vh::device::authorize(stranger.publicKey(), "127.0.0.1");
    EXPECT_FALSE(auth.linked);
    EXPECT_FALSE(auth.user);
    Client client(port, stranger);
    ASSERT_TRUE(client.connect());
    EXPECT_EQ(replyCode(client.call("peer.ping")), "device_unknown") << "a pairing-only connection";
}

TEST_F(PeerLinkDbTest, TwoServersPairByNumberMatchingAndTheLinkedKeyGetsAPeerSession) {
    const ClientIdentity a;
    const auto linked = link(a);
    EXPECT_EQ(linked.row.spki_sha256, a.deviceId());
    EXPECT_EQ(linked.row.compared_by, "person");
    const auto audited = linkAudit(linked.row.id);
    EXPECT_EQ(audited.value("compared_by", ""), "person");
    EXPECT_EQ(audited.value("pinned", true), false) << audited.dump();
    EXPECT_EQ(linked.row.sharing, "identities");
    EXPECT_EQ(linked.row.approved_by, super->id);
    EXPECT_FALSE(vh::device::Pairing::instance().window(vh::device::PairingClock::now())) << "the window closed";

    Client client(port, a);
    ASSERT_TRUE(client.connect());
    const auto hello = client.call("peer.hello", helloFrom(linked.nodeA));
    ASSERT_TRUE(isOk(hello)) << (hello ? hello->dump() : "no reply");
    EXPECT_EQ(hello->at("data").at("node_id"), db::query::device::Devices::nodeId());
    const auto session = serverSession(a, true);
    ASSERT_TRUE(session);
    EXPECT_TRUE(session->isPeerSession());
    EXPECT_EQ(session->user, nullptr);
    EXPECT_TRUE(session->peerPrincipal()->inbound);
    // Invariant 1, end to end: the wire set answers, anything else is refused whatever it is.
    EXPECT_TRUE(isOk(client.call("peer.ping")));
    EXPECT_TRUE(isOk(client.call("meta.contract.get")));
    for (const auto* refused : {"device.list", "storage.vault.list", "fs.dir.list", "peer.list", "auth.users.list",
                                "vault.keys.export", "peer.pairing.open", "settings.get"}) {
        const auto r = client.call(refused, json::object());
        ASSERT_TRUE(r) << refused;
        EXPECT_EQ(r->value("status", ""), "UNAUTHORIZED") << refused;
    }
    const auto health = vh::peer::linkService()->health(linked.row.id);
    EXPECT_TRUE(health.connected);
    EXPECT_EQ(health.dialed_by, "peer");
    EXPECT_EQ(health.peer_version, "1.27.0");
    EXPECT_EQ(health.protocol_compatible, true);
    // A hello naming another node is refused.
    EXPECT_EQ(replyCode(client.call("peer.hello", helloFrom("someone-else"))), "invalid");
    // The sweeper leaves a link alone: the link service owns its liveness.
    EXPECT_EQ(protocols::ws::ConnectionLifecycleManager::verdict(*session, std::chrono::system_clock::now() + 1h, 60s),
              protocols::ws::ConnectionLifecycleManager::SweepVerdict::Keep);
    // peer.endpoints: stored as advertised, answered with this server's.
    json advertised = json::object();
    advertised["host"] = "10.9.9.9";
    advertised["port"] = 4443;
    const auto ep = client.call("peer.endpoints", {{"endpoints", json::array({advertised})}});
    ASSERT_TRUE(isOk(ep));
    EXPECT_TRUE(ep->at("data").at("endpoints").is_array());
    const auto row = db::query::peer::Peers::byId(linked.row.id);
    ASSERT_EQ(row->endpoints.size(), 1u);
    EXPECT_EQ(row->endpoints.front().host, "10.9.9.9");
    (void)ops::peers::unlink(super, std::to_string(linked.row.id));
}

TEST_F(PeerLinkDbTest, TheBrokeredPathRefusesAnyOtherRequestingKey) {
    const ClientIdentity a, other;
    // Desktop's pin for A is `other`: A's request is denied, and no row is written.
    (void)handler::Peers::pairingOpen(console(super));
    Client client(port, a);
    ASSERT_TRUE(client.connect());
    const auto nonceA = dc::randomNonce();
    const auto request = client.call("peer.pair.request",
                                     {{"card", vh::peer::toJson(cardOf("node-b-" + tag()))},
                                      {"commitment", dc::toHex(pc::commitment(a.publicKey().spkiSha256, nonceA))}});
    ASSERT_TRUE(isOk(request));
    const auto requestId = request->at("data").at("request_id").get<std::string>();
    ASSERT_TRUE(isOk(client.call("peer.pair.confirm", {{"request_id", requestId}, {"nonce_a", dc::toHex(nonceA)}})));
    const auto code = *vh::peer::Pairing::instance().codeForTesting(requestId);
    EXPECT_THROW((void)handler::Peers::pairingApprove(
                     {{"request_id", requestId}, {"code", code}, {"expect_spki", other.deviceId()}}, console(super)),
                 ops::Invalid);
    EXPECT_EQ(client.call("peer.pair.status", {{"request_id", requestId}})->at("data").value("state", ""), "denied");
    EXPECT_FALSE(db::query::peer::Peers::liveBySpki(a.deviceId()));
    // With the right pin, approved over Desktop's device session, it links, compared by Desktop.
    const ClientIdentity b;
    const auto desktop = desktopSession();
    const auto linked = link(b, b.deviceId(), desktop);
    EXPECT_EQ(linked.row.compared_by, "desktop");
    auto audited = linkAudit(linked.row.id);
    EXPECT_EQ(audited.value("compared_by", ""), "desktop");
    EXPECT_EQ(audited.value("pinned", false), true) << audited.dump();
    (void)ops::peers::unlink(super, std::to_string(linked.row.id));
    desktop->close();
    // A person who pins the key (the host socket, or the console) is recorded as a person; the pin is in the audit.
    const ClientIdentity c;
    {
        const auth::stepup::Scope host(auth::stepup::Channel::Host);
        const auto pinned = link(c, c.deviceId());
        EXPECT_EQ(pinned.row.compared_by, "person") << "who compared, not whether a key was pinned";
        audited = linkAudit(pinned.row.id);
        EXPECT_EQ(audited.value("compared_by", ""), "person");
        EXPECT_EQ(audited.value("pinned", false), true) << audited.dump();
        (void)ops::peers::unlink(super, std::to_string(pinned.row.id));
    }
}

// Invariant 2: a key in `peer` is never accepted as a device, and a key in `devices` never as a peer.
TEST_F(PeerLinkDbTest, AKeyIsADevicesOrAServersNeverBoth) {
    const ClientIdentity serverKey;
    const auto linked = link(serverKey);
    // The linked server's key asking to pair as a device: refused.
    (void)handler::Devices::pairingOpen(console(super));
    {
        Client client(port, serverKey);
        ASSERT_TRUE(client.connect());
        const auto r = client.call("device.pair.request", {{"name", "Mac"}, {"platform", "macOS"},
                                                           {"commitment", dc::toHex(dc::randomNonce())}});
        ASSERT_TRUE(r);
        EXPECT_EQ(r->value("status", ""), "UNAUTHORIZED") << "a linked key's connection is a Peer session: device.* is refused";
    }
    (void)handler::Devices::pairingClose(json::object(), console(super));
    const auto asPeer = vh::device::authorize(serverKey.publicKey(), "127.0.0.1");
    EXPECT_TRUE(asPeer.linked);
    EXPECT_FALSE(asPeer.user) << "a linked server never acts as a user";

    // A device's key (live or revoked) asking to link: refused, and never authorized as a peer.
    const ClientIdentity deviceKey;
    const auto device = db::query::device::Devices::insert({.user_id = super->id, .approved_by = super->id,
                                                            .name = "Mac", .platform = "macOS", .app_version = "1",
                                                            .spki_sha256 = deviceKey.deviceId(), .last_ip = "127.0.0.1"});
    (void)handler::Peers::pairingOpen(console(super));
    {
        // Its connection is a Device session, which never runs the dialling server's side of pairing.
        Client client(port, deviceKey);
        ASSERT_TRUE(client.connect());
        const auto r = client.call("peer.pair.request", {{"card", vh::peer::toJson(cardOf("node-d-" + tag()))},
                                                         {"commitment", dc::toHex(dc::randomNonce())}});
        EXPECT_EQ(r->value("status", ""), "UNAUTHORIZED");
    }
    (void)db::query::device::Devices::revoke(device.id);
    {
        // Revoked: a pairing-only connection now, and the key is still a device's.
        Client client(port, deviceKey);
        ASSERT_TRUE(client.connect());
        const auto r = client.call("peer.pair.request", {{"card", vh::peer::toJson(cardOf("node-d-" + tag()))},
                                                         {"commitment", dc::toHex(dc::randomNonce())}});
        EXPECT_EQ(replyCode(r), "conflict");
    }
    // Even a row written behind the service's back for a device key is never a peer: devices are looked up first.
    (void)db::query::peer::Peers::insert({.node_id = "node-x-" + tag(), .name = "x", .spki_sha256 = deviceKey.deviceId()});
    const auto deviceAuth = vh::device::authorize(deviceKey.publicKey(), "127.0.0.1");
    EXPECT_FALSE(deviceAuth.linked);
    (void)vh::device::Pairing::instance().close(super->id, true, vh::device::PairingClock::now(),
                                                vh::device::WindowKind::Peer);
    (void)ops::peers::unlink(super, std::to_string(linked.row.id));
}

// Invariant 7: a revoked peer is refused at the handshake, and its open connections are closed in the unlinking's wake.
TEST_F(PeerLinkDbTest, UnlinkingClosesTheLinkAndTheKeyIsRefusedFromThen) {
    const ClientIdentity a;
    const auto linked = link(a);
    Client client(port, a);
    ASSERT_TRUE(client.connect());
    ASSERT_TRUE(isOk(client.call("peer.hello", helloFrom(linked.nodeA))));
    const auto unlinked = ops::peers::unlink(super, std::to_string(linked.row.id));
    EXPECT_TRUE(unlinked.revoked());
    EXPECT_TRUE(client.closedByServer()) << "closed at once (after the peer.unlinked notice)";
    Client again(port, a);
    ASSERT_TRUE(again.connect());
    EXPECT_EQ(replyCode(again.call("peer.ping")), "device_unknown") << "the revoked key is a stranger's now";
    EXPECT_FALSE(vh::device::authorize(a.publicKey(), "127.0.0.1").linked);
    EXPECT_THROW((void)ops::peers::unlink(super, std::to_string(linked.row.id)), ops::Conflict);
    // Linking the same server again writes a new row; the revoked one stays for the audit trail.
    const auto relinked = link(a);
    EXPECT_NE(relinked.row.id, linked.row.id);
    EXPECT_TRUE(db::query::peer::Peers::byId(linked.row.id)->revoked());
    // The peer unlinking this server (peer.unlinked) revokes the row here too.
    Client live(port, a);
    ASSERT_TRUE(live.connect());
    ASSERT_TRUE(isOk(live.call("peer.hello", helloFrom(relinked.nodeA))));
    EXPECT_TRUE(isOk(live.call("peer.unlinked")));
    EXPECT_TRUE(db::query::peer::Peers::byId(relinked.row.id)->revoked());
    EXPECT_TRUE(live.closedByServer());
}

// Invariant 5: the dialling side never completes a handshake with a key other than its pin (or expect_spki).
TEST_F(PeerLinkDbTest, TheDiallingEndCompletesOnlyWithItsPin) {
    const auto tls = protocols::device::makeClientContext(*vh::device::ServerIdentity::generate());
    const auto dialWith = [&](const std::string& pin) {
        std::promise<protocols::ws::client::DialResult> done;
        auto future = done.get_future();
        protocols::ws::client::dial(*ioc,
                                    {.host = "127.0.0.1", .port = port, .target = "/ws", .tls = tls,
                                     .acceptCertificate = [pin](X509* leaf) {
                                         const auto key = dc::p256KeyOf(leaf);
                                         return key && dc::toHex(key->spkiSha256) == pin;
                                     },
                                     .timeout = 5s, .userAgent = "test"},
                                    [&done](protocols::ws::client::DialResult r) { done.set_value(std::move(r)); });
        return future.get();
    };
    const auto good = dialWith(server->spkiHex());
    EXPECT_TRUE(good.transport) << good.error;
    if (good.transport) {
        boost::system::error_code ignored;
        boost::beast::get_lowest_layer(good.transport->ws).close(ignored);
    }
    const auto bad = dialWith(std::string(64, 'a'));
    EXPECT_FALSE(bad.transport);
    EXPECT_NE(bad.error.find("TLS"), std::string::npos) << bad.error;

    // The link service with a row whose pin is not this listener's key: it dials and never connects.
    const auto links = vh::peer::linkService();
    auto row = db::query::peer::Peers::insert({.node_id = "node-pin-" + tag(), .name = "pinned",
                                               .spki_sha256 = std::string(64, 'b'),
                                               .endpoints = {{.host = "127.0.0.1", .port = port, .kind = "loopback"}}});
    const auto before = links->dialsStarted();
    links->wake();
    links->tickForTesting();
    EXPECT_GE(links->dialsStarted(), before + 1);
    vh::peer::Health h;
    for (int i = 0; i < 100 && !h.last_error; ++i) {
        std::this_thread::sleep_for(50ms);
        h = links->health(row.id);
    }
    EXPECT_FALSE(h.connected);
    ASSERT_TRUE(h.last_error);
    EXPECT_NE(h.last_error->find("TLS handshake failed"), std::string::npos) << *h.last_error;
    (void)db::query::peer::Peers::revoke(row.id);

    // Pairing's dialling side: expect_spki other than the listener's key never gets as far as a request.
    (void)handler::Peers::pairingOpen(console(super));
    const auto attempt = ops::peers::linkStart(super, {{.host = "127.0.0.1", .port = port, .kind = "manual"}},
                                               std::string(64, 'c'));
    vh::peer::LinkAttempt a = attempt;
    for (int i = 0; i < 200 && !a.finished(); ++i) {
        std::this_thread::sleep_for(50ms);
        a = ops::peers::linkStatus(super, attempt.id);
    }
    EXPECT_EQ(a.state, "failed");
    EXPECT_NE(a.error.find("not the expected"), std::string::npos) << a.error;
    EXPECT_EQ(a.compared_by, "person") << "a pinned start by a person stays a person's";
    // Started over Desktop's device session, the attempt (and the row it would write) is Desktop's.
    {
        const auto desktop = desktopSession();
        const auth::stepup::Scope scope(desktop);
        const auto viaDesktop = ops::peers::linkStart(super, {{.host = "127.0.0.1", .port = port, .kind = "manual"}},
                                                      std::string(64, 'd'));
        EXPECT_EQ(viaDesktop.compared_by, "desktop");
        vh::peer::LinkAttempt d = viaDesktop;
        for (int i = 0; i < 200 && !d.finished(); ++i) {
            std::this_thread::sleep_for(50ms);
            d = ops::peers::linkStatus(super, viaDesktop.id);
        }
        EXPECT_EQ(d.state, "failed");
        desktop->close();
    }
    EXPECT_TRUE(vh::peer::Pairing::instance().pending(super->id, vh::device::PairingClock::now()).empty());
    // Trust on first use never accepts this server's own key (an address that loops back here).
    const auto self = ops::peers::linkStart(super, {{.host = "127.0.0.1", .port = port, .kind = "manual"}}, std::nullopt);
    a = self;
    for (int i = 0; i < 200 && !a.finished(); ++i) {
        std::this_thread::sleep_for(50ms);
        a = ops::peers::linkStatus(super, self.id);
    }
    EXPECT_EQ(a.state, "failed");
    EXPECT_NE(a.error.find("this server"), std::string::npos) << a.error;
    (void)handler::Peers::pairingClose(console(super));
}

TEST_F(PeerLinkDbTest, ARotationAnnouncementIsVerifiedAndTheAnnouncedKeyTakesOver) {
    const ClientIdentity a, next, stranger;
    const auto linked = link(a);
    Client client(port, a);
    ASSERT_TRUE(client.connect());
    ASSERT_TRUE(isOk(client.call("peer.hello", helloFrom(linked.nodeA))));
    const auto announce = [&](const ClientIdentity& signer, const uint64_t counter) {
        const auto msg = pc::rotationMessage(next.publicKey().spkiSha256, server->spkiSha256(), linked.nodeA, counter);
        return client.call("peer.identity.rotate", {{"next_spki_sha256", next.deviceId()}, {"counter", counter},
                                                    {"signature", dc::toBase64(signer.sign(msg))}});
    };
    EXPECT_EQ(replyCode(announce(stranger, 2)), "invalid") << "signed by another key";
    ASSERT_TRUE(isOk(announce(a, 2)));
    EXPECT_EQ(db::query::peer::Peers::byId(linked.row.id)->next_spki_sha256, next.deviceId());
    EXPECT_EQ(replyCode(announce(a, 2)), "conflict") << "a replay";
    EXPECT_EQ(replyCode(announce(a, 1)), "conflict") << "an older one";

    // The new key in use: a Peer session, and it is the pin from then on.
    Client rotated(port, next);
    ASSERT_TRUE(rotated.connect());
    EXPECT_TRUE(isOk(rotated.call("peer.ping")));
    const auto row = db::query::peer::Peers::byId(linked.row.id);
    EXPECT_EQ(row->spki_sha256, next.deviceId());
    EXPECT_FALSE(row->next_spki_sha256);
    Client old(port, a);
    ASSERT_TRUE(old.connect());
    EXPECT_EQ(replyCode(old.call("peer.ping")), "device_unknown") << "the old key is dropped once the new one is seen";
    (void)ops::peers::unlink(super, std::to_string(linked.row.id));
}

TEST_F(PeerLinkDbTest, WithTheSwitchOffALinkedKeyIsNoPeerAndNothingAnswers) {
    const ClientIdentity a;
    const auto linked = link(a);
    setExperimental(false);
    EXPECT_FALSE(vh::device::authorize(a.publicKey(), "127.0.0.1").linked);
    Client client(port, a);
    ASSERT_TRUE(client.connect());
    EXPECT_EQ(replyCode(client.call("peer.ping")), "device_unknown");
    EXPECT_EQ(replyCode(client.call("peer.pair.request", {{"card", vh::peer::toJson(cardOf("n"))},
                                                          {"commitment", dc::toHex(dc::randomNonce())}})),
              "peers_experimental");
    try {
        (void)ops::peers::list(super);
        ADD_FAILURE() << "listed with the switch off";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "peers_experimental");
    }
    const auto links = vh::peer::linkService();
    const auto before = links->dialsStarted();
    links->tickForTesting();
    EXPECT_EQ(links->dialsStarted(), before) << "the switch off: nothing dials";
    setExperimental(true);
    (void)ops::peers::unlink(super, std::to_string(linked.row.id));
}

// peer.status reports the switch, on or off, without the peers_experimental refusal every other command answers, so
// the console can leave linked servers out; it is still a super admin's (and a person's) question.
TEST_F(PeerLinkDbTest, TheStatusAnswersTheSwitchEitherWayToTheSameCallers) {
    EXPECT_EQ(handler::Peers::status(console(super)), json({{"enabled", true}}));
    setExperimental(false);
    EXPECT_EQ(handler::Peers::status(console(super)), json({{"enabled", false}})) << "answered, not refused";
    EXPECT_THROW((void)handler::Peers::pairingPending(console(super)), ops::Refused) << "the rest still refuse";

    const auto name = "pl_user_" + tag();
    const auto plain = test::identities::createUser(name, db::query::rbac::role::Admin::get("unprivileged"),
                                                    name + "@vaulthalla.test");
    EXPECT_THROW((void)handler::Peers::status(console(plain)), ops::Denied) << "only super admins";
    {
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        try {
            (void)ops::peers::enabled(super);
            ADD_FAILURE() << "an agent read the switch";
        } catch (const ops::Refused& e) {
            EXPECT_EQ(e.code, "peer_forbidden");
        }
    }
    setExperimental(true);
    EXPECT_TRUE(ops::peers::enabled(super));
}


// Who may make a link: the console steps up (device.trust, bound to the target), a full-access Desktop connected
// directly does not (RBAC alone, decision 2), nor does the host; a device reached through the relay never gets there.
TEST_F(PeerLinkDbTest, MakingALinkStepsUpInTheConsoleButNotOnADirectFullAccessDesktopOrTheHost) {
    namespace stepup = auth::stepup;
    auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = super;
    web->tokens->refreshToken = std::make_shared<auth::model::RefreshToken>();
    web->tokens->refreshToken->jti = "peer-link-jti-" + tag();
    web->tokens->refreshToken->aal = 1;
    web->tokens->refreshToken->amr = {"pwd"};
    web->tokens->refreshToken->authTime = std::chrono::system_clock::now() - 1h;
    const std::string target = "peer.link.start:tofu:127.0.0.1:1";
    {
        const stepup::Scope scope(web);
        try {
            (void)ops::peers::linkStart(super, {{.host = "127.0.0.1", .port = 1, .kind = "manual"}}, std::nullopt);
            ADD_FAILURE() << "the console linked without a step-up";
        } catch (const ops::StepUpRequired& e) {
            EXPECT_EQ(e.family, "device.trust");
            EXPECT_EQ(e.target, target);
        }
        web->stepUp().addGrant({.user_id = super->id, .refresh_jti = web->tokens->refreshToken->jti,
                                .family = stepup::Family::DeviceTrust, .target = target, .method = "test",
                                .expires_at = std::chrono::system_clock::now() + 5min});
        EXPECT_NO_THROW(stepup::requireForServerLink(target)) << "the grant for exactly this target";
    }
    const auto deviceWith = [&](const bool relayed) {
        auto p = std::make_shared<vh::device::Peer>();
        p->spki.fill(relayed ? 0x31 : 0x32);
        p->spkiHex = dc::toHex(p->spki);
        p->address = "10.0.0.7";
        p->deviceRowId = 9;
        p->relayed = relayed;
        return protocols::ws::Session::devicePrincipal(std::move(p), super, [] {});
    };
    const auto desktop = deviceWith(false);
    {
        const stepup::Scope scope(desktop);
        EXPECT_NO_THROW(stepup::requireForServerLink("peer.link.start:tofu:somewhere:1")) << "RBAC alone";
    }
    const auto relayed = deviceWith(true);
    {
        const stepup::Scope scope(relayed);
        EXPECT_THROW(stepup::requireForServerLink("peer.link.start:tofu:somewhere:1"), ops::StepUpRequired);
        try {
            (void)ops::peers::list(super);
            ADD_FAILURE() << "a relayed device listed linked servers";
        } catch (const ops::Refused& e) {
            EXPECT_EQ(e.code, "peer_forbidden");
        }
    }
    {
        const stepup::Scope host(stepup::Channel::Host);
        EXPECT_NO_THROW(stepup::requireForServerLink("peer.link.start:tofu:somewhere:1"));
    }
    desktop->close();
    relayed->close();
}

}
