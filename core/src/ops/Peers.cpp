#include "ops/Peers.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "config/Registry.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/peer/Peer.hpp"
#include "device/Crypto.hpp"
#include "device/Device.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "peer/Crypto.hpp"
#include "peer/Keys.hpp"
#include "protocols/ws/Session.hpp"

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <thread>

namespace vh::ops::peers {

namespace {

using vh::peer::Record;
using Peers = db::query::peer::Peers;
using json = nlohmann::json;
namespace dc = vh::device::crypto;

std::string lowerText(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool hexOnly(const std::string& s) {
    return !s.empty() && std::ranges::all_of(s, [](const unsigned char c) { return std::isxdigit(c) != 0; });
}

bool digitsOnly(const std::string& s) {
    return !s.empty() && s.size() <= 9 && std::ranges::all_of(s, [](const unsigned char c) { return std::isdigit(c) != 0; });
}

// A key a caller names (expect_spki): 64 hex digits, spaces or colons between them allowed; lower case.
std::optional<std::string> normalizedSpki(const std::optional<std::string>& text) {
    if (!text) return std::nullopt;
    std::string hex;
    for (const char c : *text)
        if (c != ':' && c != ' ') hex.push_back(c);
    hex = lowerText(hex);
    if (hex.size() != 64 || !hexOnly(hex)) throw Invalid("a server key is its SPKI SHA-256: 64 hex digits");
    return hex;
}

// Who may: a super admin who can sign in, on the host socket, the web console or a full-access, directly connected
// device; never an agent, a scoped device, a relayed device or a linked server (design/peers/link.md).
void requireLinkerRights(const Actor& actor, const std::string& what) {
    requireActor(actor);
    if (actor->systemOnly() || !actor->authorizing()) throw Denied("this account cannot " + what);
    if (!actor->isSuperAdmin()) throw Denied("only super admins may " + what);
    const auto* scope = auth::stepup::Scope::current();
    if (!scope) return;  // the daemon's own callers and tests (ops/Actor.hpp)
    switch (scope->channel()) {
        case auth::stepup::Channel::Host:
        case auth::stepup::Channel::Web: return;
        case auth::stepup::Channel::Agent:
            throw Refused("peer_forbidden", "which servers this one is linked with is decided by a person: an agent or "
                                            "a device with limited access can't " + what);
        case auth::stepup::Channel::Device: {
            const auto& session = scope->session();
            const auto& device = session ? session->devicePeer() : nullptr;
            if (!device || device->scoped() || device->readOnly())
                throw Refused("peer_forbidden", "only a person, or a fully trusted device connected directly, may " + what);
            return;
        }
    }
}

// Who compared the code: Vaulthalla Desktop when the call came over a device session (requireLinkerRights already
// refused scoped and relayed ones, so it is a full-access, directly connected device: the brokered path), else a person
// (the web console, the host socket). Never inferred from whether a key was pinned: a person may pin one too.
std::string comparedByCaller() {
    const auto* scope = auth::stepup::Scope::current();
    return scope && scope->channel() == auth::stepup::Channel::Device ? "desktop" : "person";
}

// Every management operation but status(): the switch first, then who.
void requireLinker(const Actor& actor, const std::string& what) {
    requireExperimental();
    requireLinkerRights(actor, what);
}

std::string serverSpkiOrThrow() {
    const auto identity = vh::device::currentServerIdentity();
    if (!identity) throw std::runtime_error("the device listener has no server identity yet");
    return identity->spkiHex();
}

Linked withHealth(Record r) {
    Linked out{.record = std::move(r), .health = {}};
    if (!out.record.revoked())
        if (const auto links = vh::peer::linkService()) out.health = links->health(out.record.id);
    return out;
}

Record resolve(const std::string& ref) {
    const auto text = lowerText(ref);
    const auto all = Peers::listAll();
    std::vector<Record> matches;
    const auto pick = [&](const auto& pred) {
        matches.clear();
        for (const auto& r : all)
            if (pred(r)) matches.push_back(r);
        // A live row wins over revoked ones with the same name, node or key (a server linked again).
        if (matches.size() > 1) {
            std::vector<Record> live;
            for (const auto& r : matches)
                if (!r.revoked()) live.push_back(r);
            if (live.size() == 1) matches = live;
        }
    };
    if (digitsOnly(text)) {
        if (const auto row = Peers::byId(static_cast<uint32_t>(std::strtoul(text.c_str(), nullptr, 10)))) return *row;
        throw NotFound("no linked server '" + ref + "'");
    }
    pick([&](const Record& r) { return r.node_id == ref; });
    if (matches.empty() && text.size() == 64 && hexOnly(text)) pick([&](const Record& r) { return r.spki_sha256 == text; });
    if (matches.empty() && text.size() >= 8 && text.size() < 64 && hexOnly(text))
        pick([&](const Record& r) { return r.spki_sha256.starts_with(text); });
    if (matches.empty()) pick([&](const Record& r) { return lowerText(r.name) == text; });
    if (matches.empty()) throw NotFound("no linked server '" + ref + "'");
    if (matches.size() > 1) throw Invalid("'" + ref + "' matches more than one linked server; name it by its number");
    return matches.front();
}

std::string codeDigest(const std::string& code) {
    const auto chosen = dc::normalizeCode(code).value_or("");
    const auto d = dc::sha256(std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(chosen.data()), chosen.size()));
    return dc::toHex(d).substr(0, 16);
}

std::shared_ptr<vh::peer::LinkService> links() {
    auto service = vh::peer::linkService();
    if (!service) throw std::runtime_error("the link service is not available");
    return service;
}

}

void requireExperimental() {
    if (!vh::config::Registry::get().peers.experimental)
        throw Refused("peers_experimental", "linked servers are experimental and off on this server: set "
                                            "peers.experimental: true in config.yaml and restart the daemon");
}

bool enabled(const Actor& actor) {
    requireLinkerRights(actor, "see whether servers can be linked");
    return vh::config::Registry::get().peers.experimental;
}

// ---- pairing, the side that opens a window

OpenWindow openWindow(const Actor& actor) {
    requireLinker(actor, "link servers");
    const auto now = vh::device::PairingClock::now();
    OpenWindow out;
    out.window = vh::device::Pairing::instance().open(actor->id, now, vh::device::WindowKind::Peer);
    (void)vh::peer::keys::wrapPublicKey();  // the first link: the sealed wrap key is made now
    out.node_id = db::query::device::Devices::nodeId();
    out.spki_sha256 = serverSpkiOrThrow();
    out.endpoints = protocols::device::endpoints::current();
    out.name = vh::peer::keys::serverName();
    audit::record({.action = "peer.pairing.open", .actor_id = actor->id, .actor = actor->name(),
                   .details = {{"expires_at", static_cast<int64_t>(out.window.expires_at)}}},
                  "[peer] " + actor->name() + " opened a window for linking a server");
    return out;
}

bool closeWindow(const Actor& actor) {
    requireLinker(actor, "link servers");
    return vh::device::Pairing::instance().close(actor->id, false, vh::device::PairingClock::now(),
                                                 vh::device::WindowKind::Peer);
}

PendingLinks pending(const Actor& actor) {
    requireLinker(actor, "link servers");
    const auto now = vh::device::PairingClock::now();
    PendingLinks out;
    if (const auto w = vh::device::Pairing::instance().window(now);
        w && w->kind == vh::device::WindowKind::Peer && w->owner_id == actor->id)
        out.window = w;
    out.requests = vh::peer::Pairing::instance().pending(actor->id, now);
    return out;
}

Record approve(const Actor& actor, const std::string& requestId, const std::string& code,
               const std::optional<std::string>& expectSpki) {
    requireLinker(actor, "link servers");
    const auto expect = normalizedSpki(expectSpki);
    auto& pairing = vh::peer::Pairing::instance();
    // A wrong code (or key) denies the request before anything is asked of the person.
    const auto checked = pairing.check(actor->id, requestId, code, expect, vh::device::PairingClock::now());
    auth::stepup::requireForServerLink("peer.pairing.approve:" + requestId + ":" + checked.spki_sha256 + ":" +
                                       codeDigest(code));
    const auto claim = pairing.begin(actor->id, requestId, code, expect, vh::device::PairingClock::now());
    Record row;
    try {
        if (db::query::device::Devices::spkiKnown(claim.spki_sha256))
            throw Conflict("this server's key is a device's on this server: it can't be linked");
        row = Peers::insert({.node_id = claim.card.node_id, .name = claim.card.name, .spki_sha256 = claim.spki_sha256,
                             .attest_public_keys = claim.card.attest_public_keys,
                             .wrap_public_key = claim.card.wrap_public_key, .endpoints = {}, .approved_by = actor->id,
                             .compared_by = comparedByCaller(), .peer_protocol = claim.card.peer_protocol,
                             .product_version = claim.card.product_version});
    } catch (...) {
        pairing.abort(requestId, vh::device::PairingClock::now());
        throw;
    }
    pairing.finish(requestId, row.id, vh::device::PairingClock::now());
    (void)vh::device::Pairing::instance().close(actor->id, false, vh::device::PairingClock::now(),
                                                vh::device::WindowKind::Peer);
    audit::record({.action = "peer.link", .actor_id = actor->id, .actor = actor->name(),
                   .details = {{"peer", row.id}, {"node_id", row.node_id}, {"key", row.shortId()},
                               {"compared_by", row.compared_by}, {"pinned", expect.has_value()},
                               {"source_ip", claim.source_ip}, {"side", "accepting"}}},
                  fmt::format("[peer] {} linked server {} ('{}', key {}) from {}; the code was compared by {}",
                              actor->name(), row.node_id, row.name, row.shortId(), claim.source_ip,
                              row.compared_by == "desktop" ? "Desktop" : "a person"));
    if (const auto service = vh::peer::linkService()) service->wake();
    return row;
}

void deny(const Actor& actor, const std::string& requestId) {
    requireLinker(actor, "link servers");
    vh::peer::Pairing::instance().deny(actor->id, requestId, vh::device::PairingClock::now());
    audit::record({.action = "peer.link.denied", .outcome = audit::Outcome::Denied, .actor_id = actor->id,
                   .actor = actor->name(), .details = {{"request", requestId}, {"side", "accepting"}}},
                  "[peer] " + actor->name() + " declined link request " + requestId);
}

// ---- pairing, the dialling side

vh::peer::LinkAttempt linkStart(const Actor& actor, const std::vector<vh::peer::Endpoint>& endpoints,
                                const std::optional<std::string>& expectSpki) {
    requireLinker(actor, "link servers");
    if (endpoints.empty()) throw Invalid("name where the other server is: at least one endpoint {host, port}");
    if (endpoints.size() > vh::peer::kMaxEndpoints) throw Invalid("at most 32 endpoints");
    const auto expect = normalizedSpki(expectSpki);
    if (expect && *expect == serverSpkiOrThrow()) throw Invalid("that key is this server's own");
    auth::stepup::requireForServerLink("peer.link.start:" + expect.value_or("tofu") + ":" +
                                       vh::peer::toString(endpoints.front()));
    const auto service = links();
    const auto id = service->startLink(actor->id, endpoints, expect, comparedByCaller());
    return service->attempt(id).value_or(vh::peer::LinkAttempt{.id = id, .owner_id = actor->id});
}

vh::peer::LinkAttempt linkStatus(const Actor& actor, const std::string& linkId) {
    requireLinker(actor, "link servers");
    auto a = links()->attempt(linkId);
    if (!a) throw NotFound("no link attempt '" + linkId + "' (finished ones are kept 15 minutes)");
    return *a;
}

vh::peer::LinkAttempt linkCancel(const Actor& actor, const std::string& linkId) {
    requireLinker(actor, "link servers");
    const auto service = links();
    if (!service->attempt(linkId)) throw NotFound("no link attempt '" + linkId + "'");
    (void)service->cancelLink(linkId);
    for (int i = 0; i < 50; ++i) {
        if (const auto a = service->attempt(linkId); a && a->finished()) return *a;
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    return *service->attempt(linkId);
}

// ---- linked servers

std::vector<Linked> list(const Actor& actor, const bool all) {
    requireLinker(actor, "see linked servers");
    std::vector<Linked> out;
    for (auto& r : all ? Peers::listAll() : Peers::listLive()) out.push_back(withHealth(std::move(r)));
    return out;
}

Linked get(const Actor& actor, const std::string& ref) {
    requireLinker(actor, "see linked servers");
    return withHealth(resolve(ref));
}

Record rename(const Actor& actor, const std::string& ref, const std::string& name) {
    requireLinker(actor, "rename linked servers");
    const auto row = resolve(ref);
    const auto next = vh::device::normalizeDeviceName(name);
    if (!next) throw Invalid("a server's name is 1-64 characters without control characters");
    auto renamed = Peers::rename(row.id, *next);
    if (!renamed) throw NotFound("no linked server '" + ref + "'");
    log::Registry::audit()->info("[ops::peers] {} renamed linked server {} '{}' -> '{}'", actor->name(), row.node_id,
                                 row.name, *next);
    return *renamed;
}

Record unlink(const Actor& actor, const std::string& ref) {
    requireLinker(actor, "unlink servers");
    const auto row = resolve(ref);
    if (row.revoked()) throw Conflict("that server is already unlinked");
    auto revoked = Peers::revoke(row.id);
    if (!revoked) throw NotFound("no linked server '" + ref + "'");
    // In the unlinking's wake: its key is refused at the next handshake; its connections end now, told first.
    std::size_t closed = 0;
    if (const auto service = vh::peer::linkService()) closed = service->disconnect(row.id, true);
    audit::record({.action = "peer.unlink", .actor_id = actor->id, .actor = actor->name(),
                   .details = {{"peer", row.id}, {"node_id", row.node_id}, {"key", row.shortId()}, {"by", "this_server"},
                               {"connections_closed", static_cast<int64_t>(closed)}}},
                  fmt::format("[peer] {} unlinked server {} ('{}', key {}); {} connection(s) closed", actor->name(),
                              row.node_id, row.name, row.shortId(), closed));
    return *revoked;
}

// ---- the wire

vh::peer::LinkRequestReceipt pairRequest(const vh::device::Peer& connection, const json& payload) {
    requireExperimental();
    if (connection.relayed) throw Refused("peer_forbidden", "a server can't be linked through the Vaulthalla Cloud relay");
    if (!payload.is_object() || !payload.contains("card")) throw Invalid("card is required");
    auto card = vh::peer::cardFromJson(payload.at("card"));
    if (!payload.contains("commitment") || !payload.at("commitment").is_string()) throw Invalid("commitment is required");
    const auto commitment = dc::hashFromHex(payload.at("commitment").get<std::string>());
    if (!commitment) throw Invalid("commitment must be 64 hex digits");
    // A key is a device's or a server's, never both (invariant 2), and a linked server links once.
    if (db::query::device::Devices::spkiKnown(connection.spkiHex))
        throw Conflict("this key is known here as a device's: a server links with its own identity key");
    if (Peers::liveBySpki(connection.spkiHex)) throw Conflict("this server is already linked here");
    if (card.node_id == db::query::device::Devices::nodeId()) throw Invalid("that card is this server's own");
    if (Peers::liveByNodeId(card.node_id))
        throw Conflict("a server with this node id is already linked here (unlink it first to link it again)");
    const auto own = vh::peer::keys::localCard();
    auto receipt = vh::peer::Pairing::instance().request(connection, {.card = std::move(card), .commitment = *commitment},
                                                         own, vh::device::PairingClock::now());
    audit::record({.action = "peer.link.request", .outcome = audit::Outcome::Info,
                   .details = {{"node_id", payload.at("card").value("node_id", "")}, {"key", connection.shortId()},
                               {"source_ip", connection.address}, {"side", "accepting"}}},
                  fmt::format("[peer] server {} asks to link from {} (key {})", payload.at("card").value("node_id", ""),
                              connection.address, connection.shortId()));
    return receipt;
}

std::time_t pairConfirm(const vh::device::Peer& connection, const std::string& requestId, const std::string& nonceA) {
    requireExperimental();
    const auto nonce = dc::hashFromHex(nonceA);
    if (!nonce) throw Invalid("nonce_a must be 64 hex digits");
    const auto identity = vh::device::currentServerIdentity();
    if (!identity) throw std::runtime_error("the device listener has no server identity yet");
    return vh::peer::Pairing::instance().confirm(connection, requestId, *nonce, identity->spkiSha256(),
                                                 vh::device::PairingClock::now());
}

vh::peer::LinkRequestStatus pairStatus(const vh::device::Peer& connection, const std::string& requestId) {
    requireExperimental();
    return vh::peer::Pairing::instance().status(connection, requestId, vh::device::PairingClock::now());
}

namespace {

const vh::peer::Principal& linkedOf(const std::shared_ptr<protocols::ws::Session>& session) {
    if (!session || !session->isPeerSession() || !session->peerPrincipal() || session->peerPrincipal()->pairing ||
        session->peerPrincipal()->peer_id == 0)
        throw Denied("not a linked server's session");
    return *session->peerPrincipal();
}

}

void identityRotateReceived(const std::shared_ptr<protocols::ws::Session>& session, const json& payload) {
    requireExperimental();
    const auto& principal = linkedOf(session);
    const auto row = Peers::byId(principal.peer_id);
    if (!row || row->revoked()) throw Denied("this server is not linked here");
    if (!payload.is_object()) throw Invalid("payload must be an object");
    const auto next = dc::hashFromHex(lowerText(payload.value("next_spki_sha256", "")));
    if (!next) throw Invalid("next_spki_sha256 must be 64 hex digits");
    const auto& c = payload.contains("counter") ? payload.at("counter") : json();
    if (!(c.is_number_unsigned() || (c.is_number_integer() && c.get<int64_t>() >= 1)) || c.get<uint64_t>() < 1)
        throw Invalid("counter must be a positive integer");
    const auto counter = payload.at("counter").get<uint64_t>();
    const auto signature = dc::fromBase64(payload.value("signature", ""));
    if (!signature || signature->empty()) throw Invalid("signature must be standard base64");
    const auto identity = vh::device::currentServerIdentity();
    if (!identity) throw std::runtime_error("the device listener has no server identity yet");
    // Signed by the key this connection was authenticated with, for this server's key and the peer's node id.
    const auto message = vh::peer::crypto::rotationMessage(*next, identity->spkiSha256(), row->node_id, counter);
    if (!dc::verifyEcdsaP256Sha256(principal.spki_der, message, *signature))
        throw Invalid("the announcement's signature does not verify under this link's key");
    const auto nextHex = dc::toHex(*next);
    if (nextHex == row->spki_sha256) throw Invalid("the announced key is the one in use");
    if (db::query::device::Devices::spkiKnown(nextHex)) throw Conflict("the announced key is a device's here");
    if (const auto other = Peers::liveBySpki(nextHex); other && other->id != row->id)
        throw Conflict("the announced key is another linked server's");
    if (!Peers::announceNext(row->id, nextHex, counter))
        throw Conflict("an announcement with this counter or a later one was already accepted");
    audit::record({.action = "peer.identity.rotate", .outcome = audit::Outcome::Info,
                   .details = {{"peer", row->id}, {"node_id", row->node_id}, {"key", row->shortId()},
                               {"next_key", nextHex.substr(0, 16)}, {"counter", static_cast<int64_t>(counter)},
                               {"side", "received"}}},
                  fmt::format("[peer] linked server {} announced its next key {} (counter {})", row->node_id,
                              nextHex.substr(0, 16), counter));
}

void unlinkedReceived(const std::shared_ptr<protocols::ws::Session>& session) {
    requireExperimental();
    const auto& principal = linkedOf(session);
    const auto row = Peers::byId(principal.peer_id);
    if (!row || row->revoked()) return;
    (void)Peers::revoke(row->id);
    std::size_t closed = 0;
    if (const auto service = vh::peer::linkService()) closed = service->disconnect(row->id, false, session.get());
    audit::record({.action = "peer.unlink", .outcome = audit::Outcome::Info,
                   .details = {{"peer", row->id}, {"node_id", row->node_id}, {"key", row->shortId()}, {"by", "peer"},
                               {"connections_closed", static_cast<int64_t>(closed)}}},
                  fmt::format("[peer] linked server {} ('{}') unlinked this server; the link is revoked here too",
                              row->node_id, row->name));
}

}
