// Linked servers (design/peers/link.md), DB-free: the pairing vector shared with Vaulthalla Desktop
// (core/test-assets/peer/pairing-vectors.json, computed independently by tools/dev/peer_pairing_vectors.py), the
// domain separation from device pairing (invariant 3), every card field bound into the code (invariant 4), cards and
// endpoints as they travel, the in-memory link requests, the router's peer branch (invariants 1 and 8, with the MCP
// catalog and ops' own refusal) and the experimental switch. The DB-backed half is test_peer_link_db.cpp.

#include "Contract.hpp"
#include "Mcp.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Config.hpp"
#include "config/Registry.hpp"
#include "device/Crypto.hpp"
#include "device/Pairing.hpp"
#include "device/Peer.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "ops/Peers.hpp"
#include "peer/Crypto.hpp"
#include "peer/Pairing.hpp"
#include "peer/Peer.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "rbac/role/Admin.hpp"

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <unistd.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <memory>
#include <set>
#include <string>
#include <vector>

namespace vh::test_peer_crypto {

using json = nlohmann::json;
namespace dc = vh::device::crypto;
namespace pc = vh::peer::crypto;
using Decision = protocols::ws::Router::CommandAuthDecision;
using vh::peer::Card;

json vectors() {
    std::ifstream in(std::filesystem::path(VH_TEST_ASSETS_DIR) / "peer" / "pairing-vectors.json");
    if (!in) throw std::runtime_error("peer/pairing-vectors.json is missing");
    return json::parse(in);
}

dc::Hash hash(const json& v) { return *dc::hashFromHex(v.get<std::string>()); }

std::string hex(const std::vector<uint8_t>& b) { return dc::toHex(b); }

Card sampleCard(const uint8_t fill) {
    Card c;
    c.node_id = "00000000-0000-4000-8000-0000000000" + std::to_string(10 + fill % 80);
    c.name = "server " + std::to_string(fill);
    vh::peer::Key32 k{};
    k.fill(fill);
    c.attest_public_keys = {k};
    k.fill(static_cast<uint8_t>(fill + 1));
    c.wrap_public_key = k;
    c.product_version = "1.27.0";
    return c;
}

// ---- the vector ---------------------------------------------------------------------------------------------------

TEST(PeerCryptoVectors, TheSharedVectorHolds) {
    const auto doc = vectors();
    const auto& in = doc.at("inputs");
    const auto& want = doc.at("expected");
    const auto cardA = vh::peer::cardFromJson(in.at("card_a"));
    const auto cardB = vh::peer::cardFromJson(in.at("card_b"));
    EXPECT_EQ(hex(pc::cardBytes(cardA)), want.at("card_a_bytes").get<std::string>());
    EXPECT_EQ(dc::toHex(pc::cardHash(cardA)), want.at("card_a_sha256").get<std::string>());
    EXPECT_EQ(dc::toHex(pc::cardHash(cardB)), want.at("card_b_sha256").get<std::string>());
    EXPECT_EQ(dc::toHex(pc::commitment(hash(in.at("spki_a")), hash(in.at("nonce_a")))),
              want.at("commitment_a").get<std::string>());
    const auto digest = pc::sasDigest(hash(in.at("spki_b")), hash(in.at("spki_a")), hash(in.at("nonce_a")),
                                      hash(in.at("nonce_b")), pc::cardHash(cardA), pc::cardHash(cardB));
    EXPECT_EQ(dc::toHex(digest), want.at("sas_digest").get<std::string>());
    EXPECT_EQ(pc::sasCode(digest), want.at("code").get<std::string>());
    EXPECT_EQ(pc::sasCode(digest), "227515") << "the code Desktop's brokered check is written against";
    const auto& rot = in.at("rotation");
    EXPECT_EQ(hex(pc::rotationMessage(hash(rot.at("next_spki")), hash(rot.at("peer_spki")),
                                      rot.at("node_id").get<std::string>(), rot.at("counter").get<uint64_t>())),
              want.at("rotation_message").get<std::string>());
    // The card round-trips through its wire form unchanged.
    EXPECT_EQ(vh::peer::toJson(cardA), in.at("card_a"));
}

// Invariant 3: a code computed for a device pairing is never valid for a peer pairing, and the reverse.
TEST(PeerCrypto, DevicePairingAndServerLinkingNeverShareACode) {
    dc::Hash a{}, b{}, na{}, nb{};
    a.fill(1);
    b.fill(2);
    na.fill(3);
    nb.fill(4);
    const auto cardA = pc::cardHash(sampleCard(5)), cardB = pc::cardHash(sampleCard(6));
    EXPECT_NE(pc::sasDigest(b, a, na, nb, cardA, cardB), dc::sasDigest(b, a, na, nb)) << "the SAS domains differ";
    EXPECT_NE(pc::commitment(a, na), dc::commitment(a, na)) << "the commitment domains differ";
    // The same inputs over many nonces: no pair of codes is equal more often than chance (1 in 10^6).
    int equal = 0;
    for (int i = 0; i < 200; ++i) {
        na[0] = static_cast<uint8_t>(i);
        equal += pc::sasCode(pc::sasDigest(b, a, na, nb, cardA, cardB)) == dc::sasCode(dc::sasDigest(b, a, na, nb));
    }
    EXPECT_EQ(equal, 0);
}

// Invariant 4: changing any field of either card after the request changes the code.
TEST(PeerCrypto, EveryFieldOfEitherCardIsBoundIntoTheCode) {
    dc::Hash a{}, b{}, na{}, nb{};
    a.fill(0x11);
    b.fill(0x22);
    na.fill(0x33);
    nb.fill(0x44);
    const auto base = sampleCard(7);
    auto other = sampleCard(9);
    vh::peer::Key32 second{};
    second.fill(0x77);
    other.attest_public_keys.push_back(second);
    const auto digestOf = [&](const Card& ca, const Card& cb) {
        return pc::sasDigest(b, a, na, nb, pc::cardHash(ca), pc::cardHash(cb));
    };
    const auto original = digestOf(base, other);
    std::vector<std::pair<std::string, std::function<void(Card&)>>> changes{
        {"node_id", [](Card& c) { c.node_id += "x"; }},
        {"name", [](Card& c) { c.name = "elsewhere"; }},
        {"an attestation key", [](Card& c) { c.attest_public_keys.front()[0] ^= 1; }},
        {"an attestation key added", [](Card& c) {
             vh::peer::Key32 k{};
             k.fill(0x99);
             c.attest_public_keys.push_back(k);
         }},
        {"the attestation keys' order", [](Card& c) {
             if (c.attest_public_keys.size() > 1) std::ranges::reverse(c.attest_public_keys);
             else c.attest_public_keys.clear();
         }},
        {"wrap_public_key", [](Card& c) { c.wrap_public_key[31] ^= 1; }},
        {"peer_protocol", [](Card& c) { c.peer_protocol = 2; }},
        {"product_version", [](Card& c) { c.product_version = "1.27.1"; }},
        // Length-prefixed: moving a byte between two text fields is a different card.
        {"name/version boundary", [](Card& c) {
             c.name += c.product_version.substr(0, 1);
             c.product_version = c.product_version.substr(1);
         }},
    };
    for (const auto& [what, change] : changes) {
        auto ca = base, cb = other;
        change(ca);
        EXPECT_NE(digestOf(ca, other), original) << "card A: " << what;
        change(cb);
        EXPECT_NE(digestOf(base, cb), original) << "card B: " << what;
    }
    // Swapping the cards (who dialled whom) is a different code too.
    EXPECT_NE(digestOf(other, base), original);
}

// ---- cards and endpoints on the wire --------------------------------------------------------------------------------

TEST(PeerCards, MalformedCardsAreRefusedByField) {
    const auto good = vh::peer::toJson(sampleCard(3));
    EXPECT_NO_THROW((void)vh::peer::cardFromJson(good));
    const auto refused = [&](const std::function<void(json&)>& change) {
        auto j = good;
        change(j);
        EXPECT_THROW((void)vh::peer::cardFromJson(j), ops::Invalid) << j.dump();
    };
    refused([](json& j) { j.erase("node_id"); });
    refused([](json& j) { j["node_id"] = ""; });
    refused([](json& j) { j["node_id"] = std::string(65, 'a'); });
    refused([](json& j) { j["name"] = "bad\nname"; });
    refused([](json& j) { j["name"] = std::string(65, 'n'); });
    refused([](json& j) { j["wrap_public_key"] = dc::toBase64(std::vector<uint8_t>(31, 1)); });
    refused([](json& j) { j["attest_public_keys"] = json::array({"not base64!"}); });
    refused([](json& j) { j["attest_public_keys"].push_back(j["attest_public_keys"][0]); });
    refused([](json& j) {
        j["attest_public_keys"] = json::array();
        for (int i = 0; i < 65; ++i) {
            std::vector<uint8_t> k(32, static_cast<uint8_t>(i));
            j["attest_public_keys"].push_back(dc::toBase64(k));
        }
    });
    refused([](json& j) { j["peer_protocol"] = 0; });
    refused([](json& j) { j["peer_protocol"] = "1"; });
    refused([](json& j) { j["product_version"] = std::string(65, '1'); });
    // A name is trimmed, as device names are.
    auto j = good;
    j["name"] = "  vps  ";
    EXPECT_EQ(vh::peer::cardFromJson(j).name, "vps");
}

TEST(PeerEndpoints, AddressesAndAdvertisementsParseStrictly) {
    const auto e = vh::peer::parseAddress("vps.example.net", 36972);
    ASSERT_TRUE(e);
    EXPECT_EQ(e->host, "vps.example.net");
    EXPECT_EQ(e->port, 36972);
    EXPECT_EQ(vh::peer::parseAddress("10.0.0.5:4443", 36972)->port, 4443);
    EXPECT_EQ(vh::peer::parseAddress("[fd00::5]:4443", 36972)->host, "fd00::5");
    EXPECT_EQ(vh::peer::parseAddress("fd00::5", 36972)->port, 36972) << "a bare IPv6 literal takes the default port";
    EXPECT_EQ(vh::peer::toString(*vh::peer::parseAddress("[fd00::5]:1", 2)), "[fd00::5]:1");
    for (const auto* bad : {"", "host:", "host:0", "host:65536", "host:12a", "[fd00::5", "[nope]:1", "a/b:1", "u@h:1"})
        EXPECT_FALSE(vh::peer::parseAddress(bad, 36972)) << bad;

    const auto endpoint = [](const std::string& host, const int port, const std::optional<std::string>& kind = std::nullopt) {
        json e = json::object();
        e["host"] = host;
        e["port"] = port;
        if (kind) e["kind"] = *kind;
        return e;
    };
    const auto list = vh::peer::endpointsFromJson(json::array({endpoint("a", 1, "lan"), endpoint("A", 1), endpoint("b", 2)}));
    ASSERT_EQ(list.size(), 2u) << "duplicates (host case-insensitive, port) are dropped";
    EXPECT_EQ(list[1].kind, "manual");
    EXPECT_THROW((void)vh::peer::endpointsFromJson(json::array({endpoint("a", 0)})), ops::Invalid);
    EXPECT_THROW((void)vh::peer::endpointsFromJson(json::array({endpoint("a b", 1)})), ops::Invalid);
    EXPECT_THROW((void)vh::peer::endpointsFromJson(json::array({endpoint("a", 1, "x")})), ops::Invalid);
    json many = json::array();
    for (int i = 0; i < 33; ++i) many.push_back(endpoint("h" + std::to_string(i), 1));
    EXPECT_THROW((void)vh::peer::endpointsFromJson(many), ops::Invalid);
}

// ---- link requests (in memory) --------------------------------------------------------------------------------------

class PeerPairingState : public ::testing::Test {
protected:
    void SetUp() override {
        vh::device::Pairing::instance().resetForTesting();
        vh::peer::Pairing::instance().resetForTesting();
    }
    void TearDown() override { SetUp(); }

    // A pairing-only connection's key (device::Peer holds an atomic: kept behind a pointer).
    static std::shared_ptr<const vh::device::Peer> connection(const uint8_t fill, const std::string& address = "10.0.0.9") {
        auto p = std::make_shared<vh::device::Peer>();
        p->spki.fill(fill);
        p->spkiHex = dc::toHex(p->spki);
        p->address = address;
        return p;
    }

    // request + confirm; returns the request id and the code the dialling side computes.
    static std::pair<std::string, std::string> requestAndConfirm(const vh::device::Peer& a, const dc::Hash& serverSpki,
                                                                 const Card& cardA, const Card& cardB) {
        auto& pairing = vh::peer::Pairing::instance();
        const auto now = vh::peer::PairingClock::now();
        const auto nonceA = dc::randomNonce();
        const auto receipt = pairing.request(a, {.card = cardA, .commitment = pc::commitment(a.spki, nonceA)}, cardB, now);
        EXPECT_EQ(receipt.card.node_id, cardB.node_id) << "the answer carries this server's card";
        (void)pairing.confirm(a, receipt.request_id, nonceA, serverSpki, now);
        const auto code = pc::sasCode(pc::sasDigest(serverSpki, a.spki, nonceA, receipt.nonce_b, pc::cardHash(cardA),
                                                    pc::cardHash(cardB)));
        return {receipt.request_id, code};
    }
};

TEST_F(PeerPairingState, AServerWindowAndADeviceWindowExcludeEachOther) {
    auto& windows = vh::device::Pairing::instance();
    const auto now = vh::peer::PairingClock::now();
    const auto aConn = connection(0x51);
    const auto& a = *aConn;
    // No window at all.
    try {
        (void)vh::peer::Pairing::instance().request(a, {.card = sampleCard(1), .commitment = {}}, sampleCard(2), now);
        ADD_FAILURE() << "a request without a window";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "no_pairing_window");
    }
    // A device window is no window for a server, and the reverse.
    (void)windows.open(7, now, vh::device::WindowKind::Device);
    EXPECT_THROW((void)vh::peer::Pairing::instance().request(a, {.card = sampleCard(1), .commitment = {}}, sampleCard(2), now),
                 ops::Refused);
    EXPECT_THROW((void)windows.open(7, now, vh::device::WindowKind::Peer), ops::Conflict) << "one window at a time";
    EXPECT_THROW((void)windows.open(8, now, vh::device::WindowKind::Peer), ops::Conflict);
    EXPECT_FALSE(windows.close(7, false, now, vh::device::WindowKind::Peer)) << "closing a server window closes no device one";
    EXPECT_TRUE(windows.close(7, false, now, vh::device::WindowKind::Device));
    (void)windows.open(7, now, vh::device::WindowKind::Peer);
    vh::device::PairRequestInput deviceRequest{.name = "Mac", .platform = "macOS", .app_version = "1",
                                               .commitment = dc::commitment(a.spki, dc::randomNonce())};
    try {
        (void)windows.request(a, deviceRequest, now);
        ADD_FAILURE() << "a device request in a server window";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "no_pairing_window");
    }
    EXPECT_THROW((void)windows.open(7, now, vh::device::WindowKind::Device), ops::Conflict);
}

TEST_F(PeerPairingState, NumberMatchingWithItsDecoysAndTheBrokeredKeyCheck) {
    const auto now = vh::peer::PairingClock::now();
    (void)vh::device::Pairing::instance().open(7, now, vh::device::WindowKind::Peer);
    dc::Hash serverSpki{};
    serverSpki.fill(0xee);
    auto& pairing = vh::peer::Pairing::instance();

    // The right code, with the right expected key.
    const auto aConn = connection(0x61);
    const auto& a = *aConn;
    const auto [id, code] = requestAndConfirm(a, serverSpki, sampleCard(1), sampleCard(2));
    EXPECT_EQ(pairing.codeForTesting(id), code);
    const auto pending = pairing.pending(7, now);
    ASSERT_EQ(pending.size(), 1u);
    EXPECT_EQ(std::ranges::count(pending.front().code_choices, code), 1) << "one of the three is the code";
    EXPECT_EQ(std::set<std::string>(pending.front().code_choices.begin(), pending.front().code_choices.end()).size(), 3u);
    EXPECT_TRUE(pairing.pending(8, now).empty()) << "another user's window is not this one";
    EXPECT_THROW((void)pairing.check(8, id, code, std::nullopt, now), ops::NotFound);
    const auto claim = pairing.begin(7, id, code, a.spkiHex, now);
    EXPECT_EQ(claim.spki_sha256, a.spkiHex);
    pairing.finish(id, 42, now);
    const auto status = pairing.status(a, id, now);
    EXPECT_EQ(status.state, vh::device::RequestState::Approved);
    EXPECT_EQ(status.peer_row_id, 42u);
    EXPECT_THROW((void)pairing.status(*connection(0x62), id, now), ops::NotFound) << "another key learns nothing";

    // A wrong code denies.
    const auto bConn = connection(0x63, "10.0.0.10");
    const auto& b = *bConn;
    const auto [id2, code2] = requestAndConfirm(b, serverSpki, sampleCard(3), sampleCard(2));
    const auto wrong = code2 == "000000" ? std::string("000001") : std::string("000000");
    EXPECT_THROW((void)pairing.check(7, id2, wrong, std::nullopt, now), ops::Invalid);
    EXPECT_EQ(pairing.status(b, id2, now).state, vh::device::RequestState::Denied);

    // The brokered path: another key than the broker pinned denies, whatever the code.
    const auto cConn = connection(0x64, "10.0.0.11");
    const auto& c = *cConn;
    const auto [id3, code3] = requestAndConfirm(c, serverSpki, sampleCard(4), sampleCard(2));
    EXPECT_THROW((void)pairing.check(7, id3, code3, connection(0x65)->spkiHex, now), ops::Invalid);
    EXPECT_EQ(pairing.status(c, id3, now).state, vh::device::RequestState::Denied);

    // A device approval never approves a link request (invariant 3), and the reverse.
    const auto dConn = connection(0x66, "10.0.0.12");
    const auto& d = *dConn;
    const auto [id4, code4] = requestAndConfirm(d, serverSpki, sampleCard(5), sampleCard(2));
    EXPECT_THROW((void)vh::device::Pairing::instance().checkApproval(7, id4, code4, now), ops::NotFound);
    EXPECT_EQ(pairing.status(d, id4, now).state, vh::device::RequestState::Pending) << "and that denied nothing";
}

TEST_F(PeerPairingState, ACommitmentThatDoesNotMatchDeletesTheRequest) {
    const auto now = vh::peer::PairingClock::now();
    (void)vh::device::Pairing::instance().open(7, now, vh::device::WindowKind::Peer);
    auto& pairing = vh::peer::Pairing::instance();
    const auto aConn = connection(0x71);
    const auto& a = *aConn;
    const auto receipt =
        pairing.request(a, {.card = sampleCard(1), .commitment = pc::commitment(a.spki, dc::randomNonce())}, sampleCard(2), now);
    EXPECT_THROW((void)pairing.confirm(a, receipt.request_id, dc::randomNonce(), {}, now), ops::Invalid);
    EXPECT_THROW((void)pairing.status(a, receipt.request_id, now), ops::NotFound);
    // A device commitment (the other domain) never confirms a link request either.
    const auto nonce = dc::randomNonce();
    const auto again = pairing.request(a, {.card = sampleCard(1), .commitment = dc::commitment(a.spki, nonce)}, sampleCard(2), now);
    EXPECT_THROW((void)pairing.confirm(a, again.request_id, nonce, {}, now), ops::Invalid);
}

TEST_F(PeerPairingState, TheLimitsAreDevicePairings) {
    const auto now = vh::peer::PairingClock::now();
    (void)vh::device::Pairing::instance().open(7, now, vh::device::WindowKind::Peer);
    auto& pairing = vh::peer::Pairing::instance();
    for (std::size_t i = 0; i < vh::device::kMaxRequestsPerWindow; ++i)
        (void)pairing.request(*connection(static_cast<uint8_t>(0x80 + i), "10.1.0." + std::to_string(i)),
                              {.card = sampleCard(1), .commitment = {}}, sampleCard(2), now);
    try {
        (void)pairing.request(*connection(0x90, "10.1.1.1"), {.card = sampleCard(1), .commitment = {}}, sampleCard(2), now);
        ADD_FAILURE() << "past the window's limit";
    } catch (const ops::Refused& e) {
        EXPECT_EQ(e.code, "rate_limited");
    }
    // Closing the window drops every request in it.
    EXPECT_TRUE(vh::device::Pairing::instance().close(7, false, now, vh::device::WindowKind::Peer));
    EXPECT_TRUE(pairing.pending(7, now).empty());
}

// ---- the router and who may link ------------------------------------------------------------------------------------

std::shared_ptr<identities::User> detachedSuperAdmin(const uint32_t id) {
    identities::UserState state;
    state.name = "peer-admin-" + std::to_string(id);
    state.roles.admin = std::make_shared<rbac::role::Admin>(rbac::role::Admin::SuperAdmin());
    return identities::User::detached(id, std::move(state));
}

std::shared_ptr<protocols::ws::Session> deviceSession(const std::string& scope, const bool relayed) {
    auto peer = std::make_shared<vh::device::Peer>();
    peer->spki.fill(0x42);
    peer->spkiHex = dc::toHex(peer->spki);
    peer->address = "10.0.0.2";
    peer->deviceRowId = 3;
    peer->scope = scope;
    peer->relayed = relayed;
    return protocols::ws::Session::devicePrincipal(std::move(peer), detachedSuperAdmin(5301), [] {});
}

std::shared_ptr<protocols::ws::Session> peerSession(const bool pairing) {
    auto p = std::make_shared<vh::peer::Principal>();
    p->peer_id = pairing ? 0 : 4;
    p->node_id = "00000000-0000-4000-8000-0000000000bb";
    p->spki.fill(0x43);
    p->spki_hex = dc::toHex(p->spki);
    p->address = "10.0.0.3";
    p->inbound = true;
    p->pairing = pairing;
    return protocols::ws::Session::peerForTesting(std::move(p));
}

std::vector<std::string> peerWireSet() {
    return {"peer.hello",        "peer.ping",          "peer.endpoints",   "peer.identity.rotate", "peer.unlinked",
            // starting a mirror (mirror phase 2 wave 3, piece A)
            "peer.mirror.offer", "peer.mirror.answer", "peer.mirror.keys", "peer.mirror.begin",    "peer.mirror.grant",
            "peer.mirror.cancel",
            // following the core (piece B)
            "peer.mirror.tree",  "peer.mirror.log",    "peer.mirror.ack",  "peer.mirror.notify",
            // a change made on the mirror (wave 4 piece B)
            "peer.mirror.submit",
            // resync (wave 5 piece B)
            "peer.mirror.resync",
            // the planned switch (wave 5 piece B)
            "peer.mirror.switch.request", "peer.mirror.switch.prepare", "peer.mirror.switch.commit",
            // take over: the old core learns (wave 5 piece B)
            "peer.mirror.promoted"};
}

// Invariant 1: a peer session can call no command outside the peer set, whatever its vault roles are.
TEST(PeerRouting, ALinkedServerRunsThePeerWireSetAndNothingElse) {
    const auto session = peerSession(false);
    ASSERT_TRUE(session->isPeerSession());
    EXPECT_FALSE(session->onDeviceListener()) << "never a device listener mode";
    EXPECT_EQ(session->user, nullptr) << "a peer never acts as a user";
    const auto wire = peerWireSet();
    std::set<std::string> allowed(wire.begin(), wire.end());
    allowed.insert("meta.hello");
    allowed.insert("meta.contract.get");
    auto everything = contract::ws::commands();
    std::vector<std::string> names;
    for (const auto& c : everything) names.push_back(c.command);
    // Commands no book names (a later one, a typo, the pairing commands' look-alikes) are refused too: fail closed.
    for (const auto* invented : {"peer.mirror.submit", "peer.identity.list", "peer.pings", "fs.dir.list.all", "x"})
        names.emplace_back(invented);
    for (const auto& c : names)
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *session),
                  allowed.contains(c) ? Decision::Allow : Decision::Deny)
            << c;
    // A pairing connection this server dialled runs nothing it is sent.
    const auto pairing = peerSession(true);
    for (const auto& c : names) EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *pairing), Decision::Deny) << c;
    // The step-up channel of a peer session is the one that never steps up.
    const auth::stepup::Scope scope(session);
    EXPECT_EQ(scope.channel(), auth::stepup::Channel::Agent);
}

TEST(PeerRouting, TheWireSetRunsOnALinkedServersSessionOnly) {
    const auto device = deviceSession("destructive", false);
    const auto web = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    web->user = detachedSuperAdmin(5302);
    for (const auto& c : peerWireSet()) {
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *device), Decision::Deny) << c;
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *web), Decision::Deny) << c;
    }
    for (const auto* c : {"peer.pair.request", "peer.pair.confirm", "peer.pair.status"}) {
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *device), Decision::Deny) << c;
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *web), Decision::Deny) << c;
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *peerSession(false)), Decision::Deny) << c;
    }
    device->close();
}

// Invariant 8: no scoped device, relayed session, share session or MCP caller can reach a peer.* management command.
TEST(PeerRouting, ScopedRelayedShareAndAgentCallersNeverManageLinks) {
    std::vector<std::string> management;
    for (const auto& c : contract::ws::commands())
        if (c.command.starts_with("peer.") && c.auth == "human") management.push_back(c.command);
    ASSERT_EQ(management.size(), 15u) << "the twelve of the design, peer.status and peer.policy.get|set";
    EXPECT_NE(std::ranges::find(management, std::string("peer.status")), management.end());
    // Device principals are registered with the session manager: each is closed at the end.
    const auto full = deviceSession("destructive", false);
    const auto readOnly = deviceSession("read", false);
    const auto writeOnly = deviceSession("write", false);
    const auto relayed = deviceSession("destructive", true);
    const auto share = std::make_shared<protocols::ws::Session>(std::make_shared<protocols::ws::Router>());
    share->setPendingShareSession("share-session", "share-token");
    for (const auto& c : management) {
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *full), Decision::Allow) << c << ": a full-access device";
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *readOnly), Decision::DenyScope) << c;
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *writeOnly), Decision::DenyScope) << c;
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *relayed), Decision::DenyReadOnly) << c << ": through the relay";
        EXPECT_EQ(protocols::ws::Router::classifyCommand(c, *share), Decision::Deny) << c;
    }
    // MCP: the catalog leaves `vh peer` out, so no tool or command line reaches it.
    const vh::mcp::Catalog catalog;
    bool sawPeer = false;
    for (const auto& leaf : catalog.leaves())
        if (leaf.command.starts_with("peer")) {
            sawPeer = true;
            EXPECT_TRUE(leaf.excluded) << leaf.command;
        }
    EXPECT_TRUE(sawPeer);
    EXPECT_EQ(catalog.tools(protocols::shell::CommandEffect::Destructive).dump().find("\"peer_"), std::string::npos);
    EXPECT_FALSE(catalog.hasTool("peer_list"));

    // ops refuses them too (the router is not the only gate): an agent, a scoped device, a relayed one.
    auto cfg = config::Registry::get();
    const auto saved = cfg;
    cfg.peers.experimental = true;
    config::Registry::set(cfg);
    const auto admin = detachedSuperAdmin(5303);
    const auto refusedAs = [&](const std::function<void()>& call) {
        try {
            call();
            ADD_FAILURE() << "not refused";
        } catch (const ops::Refused& e) {
            EXPECT_EQ(e.code, "peer_forbidden");
        }
    };
    {
        const auth::stepup::Scope agent(auth::stepup::Channel::Agent);
        refusedAs([&] { (void)ops::peers::list(admin); });
        refusedAs([&] { (void)ops::peers::openWindow(admin); });
        refusedAs([&] { (void)ops::peers::linkStart(admin, {{.host = "h", .port = 1, .kind = "manual"}}, std::nullopt); });
        refusedAs([&] { (void)ops::peers::enabled(admin); });
    }
    for (const auto& session : {readOnly, relayed}) {
        const auth::stepup::Scope device(session);
        refusedAs([&] { (void)ops::peers::unlink(admin, "1"); });
    }
    config::Registry::set(saved);
    for (const auto& session : {full, readOnly, writeOnly, relayed}) session->close();
}

// ---- the switch ------------------------------------------------------------------------------------------------------

TEST(PeerSwitch, OffByDefaultAndEveryOperationSaysSo) {
    EXPECT_FALSE(config::Config{}.peers.experimental);
    // This tree's deploy/config/config.yaml ships it off.
    const auto shipped = config::loadConfig(
        (std::filesystem::path(VH_TEST_ASSETS_DIR).parent_path().parent_path() / "deploy" / "config" / "config.yaml").string());
    EXPECT_FALSE(shipped.peers.experimental);
    const auto path = std::filesystem::temp_directory_path() / ("vh-peer-switch-" + std::to_string(::getpid()) + ".yaml");
    std::ofstream(path) << "peers:\n  experimental: true\n";
    EXPECT_TRUE(config::loadConfig(path.string()).peers.experimental);
    std::filesystem::remove(path);

    auto cfg = config::Registry::get();
    const auto saved = cfg;
    cfg.peers.experimental = false;
    config::Registry::set(cfg);
    const auto admin = detachedSuperAdmin(5304);
    const auto off = [&](const std::function<void()>& call) {
        try {
            call();
            ADD_FAILURE() << "not refused";
        } catch (const ops::Refused& e) {
            EXPECT_EQ(e.code, "peers_experimental");
        }
    };
    off([&] { (void)ops::peers::openWindow(admin); });
    off([&] { (void)ops::peers::list(admin); });
    off([&] { (void)ops::peers::linkStart(admin, {{.host = "h", .port = 1, .kind = "manual"}}, std::nullopt); });
    off([&] { (void)ops::peers::unlink(admin, "1"); });
    off([&] { (void)ops::peers::pairRequest(vh::device::Peer{}, json::object()); });
    EXPECT_FALSE(ops::peers::enabled(admin)) << "peer.status answers the switch instead of refusing";
    config::Registry::set(saved);
}

}
