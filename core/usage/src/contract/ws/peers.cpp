// ws book: peer.* (core/src/protocols/ws/handler/Peers.cpp; design/peers/link.md). Linked servers.
//
// Auth levels: the management commands are "human" (a signed-in super admin, or a full-access paired device's session:
// never a scoped device, a relayed one, an agent or a share session; ops answers peer_forbidden, the router and the
// MCP catalog refuse first). "peer_pairing": the dialling server, on a pairing-only connection of the device listener
// (its key is no live device's or linked server's). "peer": only on a linked server's own Peer session, which runs
// nothing else but meta.hello and meta.contract.get.

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField pcHex64(std::string name) { return str(std::move(name)).desc("64 lowercase hex digits (a SHA-256 value)."); }

std::vector<std::string> pcPeerRefusals() {
    auto out = opsRefusals();
    out.emplace_back("peer_forbidden");
    return out;
}

std::vector<std::string> pcWireRefusals() { return {"denied", "invalid", "not_found", "conflict", "unauthorized"}; }

WsField pcWindowObject() {
    return object("window", "", {uinteger("owner_id"), uinteger("opened_at"), uinteger("expires_at")})
        .desc("The window (node-wide, shared with device pairing): its owner and Unix times.");
}

std::vector<WsField> pcEndpointFields() {
    return {str("host").desc("Host name or IP literal (IPv6 unbracketed)."), uinteger("port").max(65535),
            str("kind").oneOf({"loopback", "lan", "vpn", "wan", "passthrough", "manual"})};
}

std::vector<WsField> pcCardFields() {
    return {str("node_id").desc("The server's node id (1-64 printable ASCII)."),
            str("name").desc("1-64 characters."),
            strArray("attest_public_keys").desc("Its Ed25519 key-attestation public keys, current and retired (32 "
                                                "bytes each, standard base64); at most 64."),
            str("wrap_public_key").desc("Its X25519 peer wrap key (32 bytes, standard base64)."),
            uinteger("peer_protocol").min(1).max(65535), str("product_version").desc("At most 64 printable ASCII.")};
}

WsField pcCardObject(std::string name) {
    return object(std::move(name), "", pcCardFields())
        .desc("A peer card (design/peers/link.md): bound into the pairing code, field by field.");
}

std::vector<WsField> pcHealthFields() {
    return {boolean("connected").desc("Only after peer.hello answered, and only until the socket ends."),
            integer("since").nullable(), str("dialed_by").oneOf({"this_server", "peer"}).nullable(),
            str("address").nullable(), integer("rtt_ms").nullable().desc("The last peer.ping's round trip."),
            integer("peer_protocol").nullable(), str("peer_version").nullable(),
            boolean("protocol_compatible").nullable().desc("false: another major peer protocol (upgrade one)."),
            str("last_error").nullable(), integer("last_error_at").nullable(), integer("next_attempt_at").nullable()};
}

std::vector<WsField> pcPeerFields(const bool withHealth) {
    std::vector<WsField> f{uinteger("id"), str("node_id"), str("name"), pcHex64("spki_sha256").desc("The pin."),
                           pcHex64("next_spki_sha256").nullable().desc("A key it announced and isn't using yet."),
                           strArray("attest_public_keys"), str("wrap_public_key"),
                           objectArray("endpoints", "", pcEndpointFields()).desc("Last good first."),
                           str("sharing").oneOf({"identities", "full"}), integer("approved_by").nullable(),
                           str("compared_by").oneOf({"person", "desktop"}), uinteger("peer_protocol"),
                           str("product_version"), uinteger("linked_at"), integer("last_seen_at").nullable(),
                           integer("revoked_at").nullable(), boolean("revoked")};
    if (withHealth) f.push_back(object("health", "", pcHealthFields()));
    return f;
}

WsField pcPeerObject(const bool withHealth) { return object("peer", "", pcPeerFields(withHealth)); }

WsField pcLinkObject() {
    return object("link", "",
                  {str("link_id"),
                   str("state").oneOf({"connecting", "awaiting_approval", "linked", "denied", "expired", "failed",
                                       "cancelled"}),
                   str("code").nullable().desc("Six digits, once both nonces are known: what this side shows."),
                   object("peer", "", {str("node_id"), str("name"), str("product_version"), pcHex64("spki_sha256")})
                       .nullable(),
                   integer("peer_id").nullable().desc("linked: the row written here."), str("expect_spki").nullable(),
                   str("address").nullable(), str("error").nullable(), uinteger("created_at"), uinteger("updated_at")})
        .desc("One peer.link.start attempt (kept 15 minutes after it ends).");
}

WsField pcPeerRef() {
    return str("peer").gen(gen::ref("peer", {"id"})).desc(
        "Its row id, node id, name, key (64 hex) or 8+ hex digits of its key.");
}

WsField pcRequestIdField() {
    return str("request_id").gen(gen::ref("peer.pairing_request", {"request_id"})).desc("From peer.pair.request.");
}

std::vector<WsField> pcHelloFields() {
    return {str("node_id"), str("name"), uinteger("peer_protocol").min(1).max(65535), str("product_version")};
}

}

std::vector<WsCommandUsage> peerCommands() {
    std::vector<WsCommandUsage> out;

    // ---- the window's side (B)

    out.push_back({
        .command = "peer.pairing.open",
        .description = "Open (or extend) a 10-minute window for linking another server; one window per node, shared "
                       "with device pairing (conflict while another is open). Answers what the other side needs: this "
                       "server's node id, name, key (its expect_spki on the brokered path) and endpoints. Creates the "
                       "peer wrap key on first use.",
        .input = "none",
        .response = {pcWindowObject(), uinteger("server_time"), str("node_id"), str("name"), pcHex64("spki_sha256"),
                     object("endpoints", "",
                            {uinteger("port").max(65535), boolean("remote"), boolean("listening"),
                             uinteger("generated_at"), objectArray("candidates", "", pcEndpointFields())})},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.pairing.close",
        .description = "Close the caller's window for linking a server; its requests expire.",
        .input = "none",
        .response = {boolean("closed")},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.pairing.pending",
        .description = "The caller's window and its confirmed link requests, each with three code_choices (random "
                       "order; one is the code the dialling server shows).",
        .input = "none",
        .response = {pcWindowObject().nullable(),
                     objectArray("requests", "",
                                 {str("request_id"), str("node_id"), str("name"), str("product_version"),
                                  uinteger("peer_protocol"), pcHex64("spki_sha256"), str("source_ip"),
                                  strArray("code_choices"), uinteger("created_at"), uinteger("expires_at")}),
                     uinteger("server_time")},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.pairing.approve",
        .description = "Approve a link request with the code the dialling server shows (number matching); any other "
                       "code denies it. expect_spki (the brokered path: Desktop's pin for the dialling server) also "
                       "requires the requesting key to be that one, or the request is denied. Writes the peer row and "
                       "closes the window. A device.trust step-up in the console; none on a full-access device's "
                       "session or `vh`.",
        .payload = {pcRequestIdField(), str("code").gen(gen::ref("peer.pairing_request", {"code"})).desc("Six digits."),
                    pcHex64("expect_spki").opt().nullable()},
        .response = {pcPeerObject(false)},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.pairing.deny",
        .description = "Decline a link request.",
        .payload = {pcRequestIdField()},
        .response = {boolean("denied")},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- the dialling side (A)

    out.push_back({
        .command = "peer.link.start",
        .description = "Dial another server whose window is open (endpoints: what its peer.pairing.open answered, or "
                       "an address) and ask to link. With expect_spki only that key completes the TLS handshake; "
                       "without it the key is trusted on first use, guarded by the code. Answers at once "
                       "(connecting); peer.link.status shows the code to compare, then the outcome. A device.trust "
                       "step-up in the console; none on a full-access device's session or `vh`.",
        .payload = {objectArray("endpoints", "", {str("host"), uinteger("port").max(65535),
                                                  str("kind").opt().nullable()})
                        .gen(gen::ref("peer.endpoint", {"endpoints"}))
                        .desc("1-32 of {host, port}, tried in order."),
                    pcHex64("expect_spki").opt().nullable()},
        .response = {pcLinkObject()},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.link.status",
        .description = "How a peer.link.start attempt stands: connecting, awaiting_approval (with the code), linked, "
                       "denied, expired, failed (with the error) or cancelled. Ask again in 1-2 s while it runs.",
        .payload = {str("link_id").gen(gen::ref("peer.link", {"link_id"}))},
        .response = {pcLinkObject()},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.link.cancel",
        .description = "Stop a peer.link.start attempt that has not finished.",
        .payload = {str("link_id").gen(gen::ref("peer.link", {"link_id"}))},
        .response = {pcLinkObject()},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- linked servers

    out.push_back({
        .command = "peer.list",
        .description = "The linked servers with each link's health (connected, since, who dialled, round trip, the "
                       "peer's version); all: unlinked ones too.",
        .payload = {boolean("all").opt().gen(gen::boolean())},
        .response = {objectArray("peers", "", pcPeerFields(true))},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.get",
        .description = "One linked server with its link's health.",
        .payload = {pcPeerRef()},
        .response = {pcPeerObject(true)},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.rename",
        .description = "Rename a linked server here (1-64 characters).",
        .payload = {pcPeerRef(), str("name").gen(gen::pattern("vps-{a}{a}{a}"))},
        .response = {pcPeerObject(false)},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.unlink",
        .description = "Unlink a server: the row is revoked (kept for the audit trail), its connections close at once, "
                       "and it is told (peer.unlinked) if it is connected. Linking it again needs a new pairing.",
        .payload = {pcPeerRef()},
        .response = {pcPeerObject(false)},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- a linked server's vault role on this server (migration 162; ops/PeerPolicy.hpp)

    const auto policyObject = [] {
        return object("policy", "",
                      {object("peer", "", {uinteger("id"), str("node_id"), str("name"), boolean("revoked")}),
                       object("role", "VaultRole").nullable().desc(
                           "The default vault role, with its permissions; null: none (the link grants nothing on a "
                           "vault without its own assignment)."),
                       integer("set_by").nullable(), str("set_by_name").nullable(),
                       integer("set_at").nullable().desc("Unix seconds; null: never set.")})
            .desc("A linked server's default vault role here: it holds it on every vault mirrored over the link, "
                  "unless the vault assigns it another (role.vault.assign, subject_type peer; implicit_deny is no "
                  "access). The ceiling on what that server may submit; nothing transmits or enforces it yet.");
    };

    out.push_back({
        .command = "peer.policy.get",
        .description = "A linked server's default vault role on this server. Needs vault.roles.view on every vault "
                       "(super admins hold it).",
        .payload = {pcPeerRef()},
        .response = {policyObject()},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.policy.set",
        .description = "Set (role: a vault role's id or name) or clear (role: null) a linked server's default vault "
                       "role here. It reaches every vault mirrored over the link, whoever owns it: needs "
                       "vault.roles.assign on every vault (super admins hold it). implicit_deny is refused (no "
                       "access is a per-vault override). Audited peer.policy.set with the server's node id.",
        .payload = {pcPeerRef(),
                    anyOf("role", {"integer", "string", "null"})
                        .alternatives({alt({"integer"}).desc("A vault role's id."),
                                       alt({"string"}).desc("A vault role's name.")})
                        .gen(gen::ref("role.vault", {"id"}))
                        .desc("A vault role's id or name; null: no default.")},
        .response = {policyObject()},
        .refusal_codes = pcPeerRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- the dialling server, on a pairing-only connection of this server's listener

    out.push_back({
        .command = "peer.pair.request",
        .description = "Ask to link while a window is open: the dialling server's card and its commitment "
                       "SHA-256(\"vh/peer/commit/v1\" ‖ spki_A ‖ nonce_A). Answers this server's card and nonce_b. "
                       "no_pairing_window when none is open, rate_limited past 10 per minute per address or 5 per "
                       "window, conflict for a key or node already linked or a device's key.",
        .auth = "peer_pairing",
        .payload = {pcCardObject("card").gen(gen::ref("peer.card", {"card"})),
                    pcHex64("commitment").gen(gen::ref("peer.pairing_request", {"commitment"}))},
        .response = {str("request_id"), pcHex64("nonce_b"), pcCardObject("card"), uinteger("expires_at")},
        .refusal_codes = [] {
            auto r = pcWireRefusals();
            for (const auto* c : {"no_pairing_window", "rate_limited", "device_unknown", "peer_forbidden"}) r.emplace_back(c);
            return r;
        }(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.pair.confirm",
        .description = "Reveal nonce_a; it must match the commitment (else the request is deleted: invalid). The "
                       "request is then shown to the window's owner with three codes; the code is "
                       "UInt64BE(digest[0..8]) mod 10^6 of SHA-256(\"vh/peer/sas/v1\" ‖ spki_B ‖ spki_A ‖ nonce_A ‖ "
                       "nonce_B ‖ SHA-256(card_A) ‖ SHA-256(card_B)). The code is never sent.",
        .auth = "peer_pairing",
        .payload = {pcRequestIdField(), pcHex64("nonce_a").gen(gen::ref("peer.pairing_request", {"nonce_a"}))},
        .response = {str("state").oneOf({"pending"}), uinteger("expires_at")},
        .refusal_codes = [] {
            auto r = pcWireRefusals();
            r.emplace_back("device_unknown");
            return r;
        }(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.pair.status",
        .description = "How the link request stands; ask again in 2 s while pending. approved: this server wrote its "
                       "peer row, and the dialling server writes its own.",
        .auth = "peer_pairing",
        .payload = {pcRequestIdField()},
        .response = {str("state").oneOf({"pending", "approved", "denied", "expired"})},
        .refusal_codes = [] {
            auto r = pcWireRefusals();
            r.emplace_back("device_unknown");
            return r;
        }(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- a linked server's own session (either end of the link)

    out.push_back({
        .command = "peer.hello",
        .description = "The first request on a link: who the sender is and the peer protocol and version it speaks. "
                       "The node id must be the linked one. When both servers dialled at once, the connection the "
                       "lower node id dialled is kept and the other answers conflict and closes.",
        .auth = "peer",
        .payload = [] {
            auto f = pcHelloFields();
            for (auto& field : f) field = field.gen(gen::ref("peer.hello", {field.name}));
            return f;
        }(),
        .response = pcHelloFields(),
        .refusal_codes = pcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.ping",
        .description = "Liveness, every 30 s from each end; three missed answers end the connection.",
        .auth = "peer",
        .input = "none",
        .response = {integer("time").desc("The answering server's clock (Unix seconds).")},
        .refusal_codes = pcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.endpoints",
        .description = "Where the sender can be reached (its device listener's advertisement); answers the "
                       "receiver's. Each side stores what it is told.",
        .auth = "peer",
        .payload = {objectArray("endpoints", "", pcEndpointFields()).gen(gen::ref("peer.endpoint", {"endpoints"}))},
        .response = {objectArray("endpoints", "", pcEndpointFields())},
        .refusal_codes = pcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.identity.rotate",
        .description = "The sender's next identity key, announced before it is used: signature is ECDSA P-256 / "
                       "SHA-256 (DER, base64) by its current key over \"vh/peer/rotate/v1\" ‖ next_spki ‖ "
                       "receiver_spki ‖ UInt32BE(len) ‖ node_id ‖ UInt64BE(counter). Stored as next_spki_sha256; "
                       "either key is accepted until the new one is seen. counter must exceed the last one.",
        .auth = "peer",
        .payload = {pcHex64("next_spki_sha256").gen(gen::ref("peer.rotation", {"next_spki_sha256"})),
                    uinteger("counter").min(1).gen(gen::ref("peer.rotation", {"counter"})),
                    str("signature").gen(gen::ref("peer.rotation", {"signature"}))},
        .response = {boolean("stored")},
        .refusal_codes = pcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "peer.unlinked",
        .description = "The sender unlinked the receiver: the receiver revokes its row too and the connection ends "
                       "after the answer. A courtesy: a revoked key is refused at the handshake anyway.",
        .auth = "peer",
        .input = "none",
        .response = {boolean("revoked")},
        .refusal_codes = pcWireRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
