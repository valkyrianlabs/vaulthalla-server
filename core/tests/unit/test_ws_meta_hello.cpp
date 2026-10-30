// meta.hello, the ws protocol handshake (core/usage WsProtocol.hpp, docs/reference/ws-protocol.md): the answer's wire
// shape, negotiation and its edges (no client range, overlap, no overlap -> protocol_unsupported with the server's
// range), what the session remembers (and its default without a hello), the auth decision on every session type, and
// the typed unknown-command answer per session type. DB-free; the device listener's end-to-end half (pairing-only
// and paired sessions over TLS, app_version refresh) is in test_device_listener.cpp.

#include "Contract.hpp"
#include "WsProtocol.hpp"
#include "device/Peer.hpp"
#include "identities/User.hpp"
#include "ops/Error.hpp"
#include "protocols/ws/Handler.hpp"
#include "protocols/ws/Router.hpp"
#include "protocols/ws/Session.hpp"
#include "protocols/ws/core/handler_templates.hpp"
#include "protocols/ws/handler/Meta.hpp"
#include "protocols/ws/model/Response.hpp"
#include "rbac/role/Admin.hpp"

#include <version.h>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <memory>
#include <string>
#include <vector>

namespace vh::test_ws_meta_hello {

using json = nlohmann::json;
using protocols::ws::Router;
using protocols::ws::Session;
using Decision = Router::CommandAuthDecision;
namespace handler = protocols::ws::handler;

std::shared_ptr<Router> daemonRouter() {
    auto router = std::make_shared<Router>();
    protocols::ws::Handler::registerAllHandlers(router);
    return router;
}

std::shared_ptr<identities::User> admin(const uint32_t id, const std::string& name) {
    identities::UserState state;
    state.name = name;
    state.roles.admin = std::make_shared<rbac::role::Admin>();
    return identities::User::detached(id, std::move(state));
}

// A paired device's session without a listener (the HTTP-lane principal: same mode, same router rules).
std::shared_ptr<Session> deviceSession() {
    auto peer = std::make_shared<vh::device::Peer>();
    peer->spkiHex = std::string(64, 'a');
    peer->address = "127.0.0.1";
    peer->deviceRowId = 1;
    return Session::devicePrincipal(std::move(peer), admin(4301, "hello_device_owner"), [] {});
}

// What the client sees for the refusal the handler throws.
json refusalData(const json& payload) {
    try {
        (void)handler::Meta::hello(payload, std::make_shared<Session>(std::make_shared<Router>()), {});
    } catch (...) {
        return protocols::ws::core::describeCurrentError().data;
    }
    return nullptr;
}

TEST(WsMetaHello, AnswersTheWireShape) {
    const auto router = daemonRouter();
    const auto session = std::make_shared<Session>(router);
    const auto reply = handler::Meta::hello(json::object(), session, router->commands());

    std::vector<std::string> keys;
    for (const auto& [key, _] : reply.items()) keys.push_back(key);
    EXPECT_EQ(keys, (std::vector<std::string>{"capabilities", "commands", "contract", "protocol", "server"}));
    EXPECT_EQ(reply.at("server"), (json{{"name", "vaulthalla"}, {"version", VH_VERSION}}));
    EXPECT_EQ(reply.at("protocol"), (json{{"version", contract::kProtocolMin},
                                          {"min", contract::kProtocolMin},
                                          {"max", contract::kProtocolVersion}}));
    EXPECT_EQ(reply.at("capabilities").get<std::vector<std::string>>(), contract::capabilityNames());
    EXPECT_EQ(reply.at("contract"), handler::Meta::contract());

    const auto commands = reply.at("commands").get<std::vector<std::string>>();
    EXPECT_EQ(commands, router->commands());
    EXPECT_TRUE(std::ranges::is_sorted(commands));
    for (const auto* name : {"meta.hello", "meta.contract.get", "device.server.identity", "fs.dir.list"})
        EXPECT_NE(std::ranges::find(commands, name), commands.end()) << name;
}

TEST(WsMetaHello, ASessionWithoutHelloSpeaksTheServerMinimum) {
    const auto session = std::make_shared<Session>(std::make_shared<Router>());
    EXPECT_EQ(session->protocolVersion(), contract::kProtocolMin);
    EXPECT_TRUE(session->clientInfo().name.empty());
    EXPECT_TRUE(session->clientInfo().version.empty());
}

TEST(WsMetaHello, NegotiatesTheNewestCommonVersionAndTheSessionKeepsIt) {
    const auto session = std::make_shared<Session>(std::make_shared<Router>());
    const auto reply = handler::Meta::hello(
        {{"client", {{"name", "Vaulthalla Desktop"}, {"version", "0.9.1"}}},
         {"protocol", {{"min", 1}, {"max", contract::kProtocolVersion + 3}}}},
        session, {});
    EXPECT_EQ(reply.at("protocol").at("version"), contract::kProtocolVersion) << "min(server max, client max)";
    EXPECT_EQ(session->protocolVersion(), contract::kProtocolVersion);
    EXPECT_EQ(session->clientInfo().name, "Vaulthalla Desktop");
    EXPECT_EQ(session->clientInfo().version, "0.9.1");

    // No client range: the server's minimum (what a session that never says hello speaks); null members read as
    // missing.
    const auto plain = std::make_shared<Session>(std::make_shared<Router>());
    EXPECT_EQ(handler::Meta::hello({{"client", nullptr}, {"protocol", json::object()}}, plain, {})
                  .at("protocol").at("version"),
              contract::kProtocolMin);
    EXPECT_EQ(plain->protocolVersion(), contract::kProtocolMin);
}

TEST(WsMetaHello, NegotiationEdges) {
    using contract::kProtocolMin;
    using contract::kProtocolVersion;
    using contract::negotiateProtocol;
    EXPECT_EQ(negotiateProtocol(std::nullopt, std::nullopt), kProtocolMin);
    EXPECT_EQ(negotiateProtocol(kProtocolMin, kProtocolVersion), kProtocolVersion);
    EXPECT_EQ(negotiateProtocol(std::nullopt, kProtocolVersion + 10), kProtocolVersion) << "a missing min is ours";
    EXPECT_EQ(negotiateProtocol(kProtocolMin, std::nullopt), kProtocolVersion) << "a missing max is ours";
    EXPECT_EQ(negotiateProtocol(kProtocolVersion, kProtocolVersion), kProtocolVersion) << "a one-version overlap";
    EXPECT_EQ(negotiateProtocol(kProtocolVersion + 1, kProtocolVersion + 4), std::nullopt) << "a newer client only";
    EXPECT_EQ(negotiateProtocol(0, kProtocolMin - 1), std::nullopt) << "an older client only";
    EXPECT_EQ(negotiateProtocol(kProtocolVersion, kProtocolMin - 1), std::nullopt) << "an inverted client range";

    // The rule itself, over a window around the server's range.
    for (int lo = 0; lo <= kProtocolVersion + 2; ++lo)
        for (int hi = 0; hi <= kProtocolVersion + 2; ++hi) {
            const int v = std::min(kProtocolVersion, hi);
            const auto expected = v < std::max(kProtocolMin, lo) ? std::nullopt : std::optional<int>(v);
            EXPECT_EQ(negotiateProtocol(lo, hi), expected) << lo << ".." << hi;
        }
}

TEST(WsMetaHello, NoOverlapRefusesWithProtocolUnsupportedAndTheServersRange) {
    const auto session = std::make_shared<Session>(std::make_shared<Router>());
    const json tooNew{{"client", {{"name", "Future Desktop"}}},
                      {"protocol", {{"min", contract::kProtocolVersion + 1}, {"max", contract::kProtocolVersion + 2}}}};
    EXPECT_THROW((void)handler::Meta::hello(tooNew, session, {}), ops::Refused);
    EXPECT_EQ(session->protocolVersion(), contract::kProtocolMin) << "a refused hello changes nothing";
    EXPECT_TRUE(session->clientInfo().name.empty());

    EXPECT_EQ(refusalData(tooNew), (json{{"code", "protocol_unsupported"},
                                         {"server_min", contract::kProtocolMin},
                                         {"server_max", contract::kProtocolVersion},
                                         {"server_version", VH_VERSION}}));
    EXPECT_EQ(refusalData({{"protocol", {{"max", contract::kProtocolMin - 1}}}}).value("code", ""),
              "protocol_unsupported");
}

TEST(WsMetaHello, MalformedMembersAreInvalid) {
    for (const auto& payload : {json{{"client", "Desktop"}},
                                json{{"protocol", 1}},
                                json{{"protocol", {{"max", "1"}}}},
                                json{{"protocol", {{"min", -1}}}},
                                json{{"protocol", {{"max", 1.5}}}},
                                json{{"client", {{"name", 7}}}},
                                json{{"client", {{"name", std::string(65, 'x')}}}},
                                json{{"client", {{"version", "1.0\n"}}}}})
        EXPECT_EQ(refusalData(payload), (json{{"code", "invalid"}})) << payload.dump();
}

TEST(WsMetaHello, EverySessionTypeMaySayHello) {
    const auto unauthenticated = std::make_shared<Session>(std::make_shared<Router>());
    const auto human = std::make_shared<Session>(std::make_shared<Router>());
    human->user = admin(4302, "hello_human");
    const auto share = std::make_shared<Session>(std::make_shared<Router>());
    share->setPendingShareSession("share-session", "share-token");
    const auto device = deviceSession();
    ASSERT_TRUE(device->isDeviceSession());

    for (const auto& s : {unauthenticated, human, share, device})
        EXPECT_EQ(Router::classifyCommand("meta.hello", *s), Decision::Allow) << static_cast<int>(s->mode());
    // meta.contract.get stays behind sign-in on the web side (bc342115); pairing-only sessions are covered over TLS.
    EXPECT_EQ(Router::classifyCommand("meta.contract.get", *unauthenticated), Decision::Deny);

    // Through the daemon's router: an unauthenticated socket's hello reaches the handler and the session keeps it
    // (the answer goes nowhere: the session is closed).
    const auto router = daemonRouter();
    const auto routed = std::make_shared<Session>(router);
    routed->close();
    router->routeMessage({{"command", "meta.hello"},
                          {"payload", {{"client", {{"name", "probe"}}}, {"protocol", {{"max", 99}}}}}},
                         routed);
    EXPECT_EQ(routed->protocolVersion(), contract::kProtocolVersion);
    EXPECT_EQ(routed->clientInfo().name, "probe");
}

TEST(WsMetaHello, UnknownCommandsAreTypedOnWebAndDeviceSessions) {
    const auto frame = Router::unknownCommand("frobnicate", json{{"requestId", "r-9"}}).frame();
    EXPECT_EQ(frame.at("command"), "frobnicate.response");
    EXPECT_EQ(frame.at("status"), "ERROR");
    EXPECT_EQ(frame.at("requestId"), "r-9");
    EXPECT_EQ(frame.at("data"), (json{{"code", "unknown_command"}}));
    EXPECT_EQ(frame.at("error"), "Unknown command") << "the text old clients match stays";

    // Who reaches that answer: a signed-in web session (after its token checks out) and a paired device. An
    // unauthenticated socket is still refused first (UNAUTHORIZED, no command oracle); pairing-only connections get
    // device_unknown (test_device_listener.cpp).
    const auto unauthenticated = std::make_shared<Session>(std::make_shared<Router>());
    const auto human = std::make_shared<Session>(std::make_shared<Router>());
    human->user = admin(4303, "unknown_human");
    EXPECT_EQ(Router::classifyCommand("frobnicate", *unauthenticated), Decision::Deny);
    EXPECT_EQ(Router::classifyCommand("frobnicate", *human), Decision::RequireHumanAuth);
    EXPECT_EQ(Router::classifyCommand("frobnicate", *deviceSession()), Decision::Allow);
}

}
