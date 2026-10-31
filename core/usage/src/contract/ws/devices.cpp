// ws book: device.* (core/src/protocols/ws/handler/Devices.cpp; protocol: docs/pairing.md in valkyrianlabs/vaulthalla-desktop).
//
// Auth levels on the device listener: "pairing" commands run on a pairing-only connection (a client key that is not a
// live device; everything else there is refused with data.code "device_unknown") and on a paired device's session;
// "device" commands only on a paired device's session. "human" commands run on a signed-in console session and on a
// paired device's session alike (a device acts as its user).

#include "fields.hpp"

namespace vh::contract::ws::detail {

namespace {

WsField hex64(std::string name) { return str(std::move(name)).desc("64 lowercase hex digits (a SHA-256 value)."); }

WsField deviceObject() { return object("device", "Device"); }

WsField deviceIdField() {
    return hex64("device_id")
        .gen(gen::ref("device", {"device_id"}))
        .desc("The device id: the SHA-256 of its certificate's SubjectPublicKeyInfo (64 lowercase hex digits).");
}

WsField requestIdField() {
    return str("request_id").gen(gen::ref("device.pairing_request", {"request_id"})).desc("From device.pair.request.");
}

WsField windowObject() {
    return object("window", "", {uinteger("owner_id"), uinteger("opened_at"), uinteger("expires_at")})
        .desc("The pairing window: its owner and Unix times. Requests go to its owner.");
}

WsField listenerStatus() {
    return object("status", "",
                  {boolean("enabled"), boolean("remote").desc("Every interface; else loopback only."),
                   uinteger("port").desc("The configured port (36972 by default)."), boolean("listening"),
                   str("address").nullable().desc("Where it listens, host:port; null when it does not."),
                   str("error").nullable().desc("Why it does not listen where configured (e.g. the port is taken)."),
                   hex64("server_spki_sha256").nullable().desc("The server key's SPKI hash (the pin Desktop records)."),
                   uinteger("connections").desc("Open device-listener connections.")})
        .desc("The device listener as configured and as it is.");
}

// One advertised endpoint (docs/reference/transfer-protocol.md §1.1).
std::vector<WsField> candidateFields() {
    return {str("host").desc("Host name or IP literal (IPv6 unbracketed)."), uinteger("port").max(65535),
            str("kind").oneOf({"loopback", "lan", "vpn", "wan", "passthrough"})
                .desc("Address class: loopback, RFC 1918 / ULA (lan), 100.64/10 or a VPN interface (vpn), other "
                      "global unicast (wan), a TLS passthrough (passthrough)."),
            str("source").oneOf({"interface", "mdns", "config"}),
            str("interface").opt().desc("The interface it was read from (source interface only).")};
}

WsField candidates() {
    return objectArray("candidates", "", candidateFields())
        .desc("Ordered loopback, lan, vpn, wan, passthrough; de-duplicated by (host, port); at most 32. Only loopback "
              "interface addresses while remote is off; configured names always.");
}

// The §1.1 object (device.endpoints adds node_id).
std::vector<WsField> endpointFields() {
    return {uinteger("port").max(65535).desc("The listener's port."),
            boolean("remote").desc("Remote connections on; else loopback only."),
            boolean("listening").desc("The listener is bound right now."),
            uinteger("generated_at").desc("Unix seconds: the list is computed on every call."), candidates()};
}

// The device's side answers ops::Refused codes of its own besides the generic kinds: no_pairing_window and
// rate_limited (pairing), device_unknown (the command reached a session without a device identity, or the key is not
// a live device). The router refuses device.pair.* and the device-only commands on console sessions (unauthorized).

}

std::vector<WsCommandUsage> deviceCommands() {
    std::vector<WsCommandUsage> out;

    // ---- the device's side of pairing (pairing-only connections)

    out.push_back({
        .command = "device.pair.request",
        .description = "Ask to pair this connection's key while a pairing window is open, committing to nonce_device "
                       "(SHA-256(\"vh-pair-commit-v1\" ‖ device_spki_sha256 ‖ nonce_device)). Refused with "
                       "no_pairing_window when none is open, rate_limited past 10 per minute per address or 5 per "
                       "window, conflict for a key this node knows. One live request per key: a new one replaces it.",
        .auth = "pairing",
        .payload = {str("name").gen(gen::pattern("Mac {a}{a}{a}")).desc("1-64 characters."),
                    str("platform").gen(gen::constant("macOS")).desc("\"macOS\"."),
                    str("app_version").opt().gen(gen::pattern("1.{9}.{9}")),
                    hex64("commitment").gen(gen::ref("device.pairing_request", {"commitment"}))},
        .response = {str("request_id"), hex64("nonce_server"), uinteger("expires_at")},
        .refusal_codes = {"invalid", "conflict", "no_pairing_window", "rate_limited", "device_unknown", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.pair.confirm",
        .description = "Reveal nonce_device. It must match the request's commitment (else the request is deleted: "
                       "invalid); then the request is shown to the window's owner with its code. The daemon never "
                       "sends the code to the device. Same key as the request only.",
        .auth = "pairing",
        .payload = {requestIdField(), hex64("nonce_device").gen(gen::ref("device.pairing_request", {"nonce_device"}))},
        .response = {str("state").oneOf({"pending"}), uinteger("expires_at")},
        .refusal_codes = {"invalid", "not_found", "conflict", "device_unknown", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.pair.status",
        .description = "How the request stands. Answered at once (no long poll): after pending, ask again in 2 s. "
                       "Approved carries the node's id and name and the device id; the device then pins the server "
                       "key and reconnects, which makes a Device session. Same key as the request only.",
        .auth = "pairing",
        .payload = {requestIdField()},
        .response = {str("state").oneOf({"pending", "approved", "denied", "expired"}),
                     str("node_id").opt(), str("node_name").opt(), hex64("device_id").opt()},
        .refusal_codes = {"invalid", "not_found", "device_unknown", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    // ---- a paired device's own session

    out.push_back({
        .command = "device.identity.rotate",
        .description = "Replace this device's key: certificate is the new self-signed P-256 certificate (base64 DER), "
                       "signature the old key's ECDSA-P256-SHA256 (base64 DER) over \"vh-device-rotate-v1\" ‖ "
                       "new_spki_sha256 ‖ server_spki_sha256 ‖ UInt64BE(timestamp). The old key keeps working until "
                       "the first connection with the new one. A retry from the old key naming the same new key "
                       "succeeds again; another key is conflict.",
        .auth = "device",
        .payload = {str("certificate").gen(gen::ref("device.identity", {"certificate"})),
                    anyOf("timestamp", {"integer"}).gen(gen::ref("device.identity", {"timestamp"}))
                        .desc("Unix seconds, within 300 s of the node's clock."),
                    str("signature").gen(gen::ref("device.identity", {"signature"}))},
        .response = {hex64("device_id").desc("The new device id.")},
        .refusal_codes = {"invalid", "conflict", "device_unknown", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.server.identity",
        .description = "The server key's SPKI hash (the pin). A next key is never announced: a new server key means "
                       "pairing again.",
        .auth = "device",
        .input = "none",
        .response = {hex64("spki_sha256")},
        .refusal_codes = {"device_unknown", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.endpoints",
        .description = "Where this node's device listener can be reached (docs/reference/transfer-protocol.md §1.1): "
                       "interface addresses classified by range, <hostname>.local where an mDNS responder runs, and "
                       "device_server.advertise's configured names. Computed per call; never answered before a device "
                       "is paired.",
        .auth = "device",
        .input = "none",
        .response = [] {
            auto fields = endpointFields();
            fields.insert(fields.begin(), str("node_id").desc("The node id, as device.pair.status reports it."));
            return fields;
        }(),
        .refusal_codes = {"device_unknown", "unauthorized"},
        .client_timeout = kDefaultTimeout,
    });

    // ---- the owner's side of pairing (any signed-in user, for their own account)

    out.push_back({
        .command = "device.pairing.open",
        .description = "Open a 10-minute pairing window owned by the caller (reopening extends it). One window per "
                       "node: conflict while another user's is open. Also says what to type into Desktop: the "
                       "listener's port and whether devices on other hosts can reach it (remote), and what the "
                       "vaulthalla://pair link carries (node_id, server_spki_sha256, endpoints; "
                       "transfer-protocol.md §1.2).",
        .input = "none",
        .response = {windowObject(), uinteger("server_time").desc("The node's clock (Unix seconds), to count down by."),
                     uinteger("port").desc("The device listener's port."),
                     boolean("remote").desc("Remote connections on; else only a Desktop on the node itself can pair."),
                     str("node_id").desc("The node id (the pairing link's node=)."),
                     hex64("server_spki_sha256").nullable()
                         .desc("The server key's SPKI hash (the pairing link's spki=); null until the listener has "
                               "loaded its identity."),
                     object("endpoints", "", endpointFields())
                         .desc("device.endpoints' answer without node_id: what the pairing link's endpoints= lists.")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.pairing.close",
        .description = "Close the caller's own pairing window; its requests expire. any: whoever's window is open "
                       "(super admins only).",
        .payload = {boolean("any").opt().gen(gen::boolean())},
        .response = {boolean("closed").desc("False when no such window was open.")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.pairing.pending",
        .description = "The caller's open window and its confirmed requests. Each offers three code_choices (random "
                       "order): one is the code the device shows, two are decoys fixed for the request. The real code "
                       "is never returned on its own.",
        .input = "none",
        .response = {windowObject().nullable(),
                     objectArray("requests", "",
                                 {str("request_id"), str("name"), str("platform"), str("app_version"),
                                  str("source_ip"), hex64("device_id"), strArray("code_choices"),
                                  uinteger("created_at"), uinteger("expires_at")}),
                     uinteger("server_time").desc("The node's clock (Unix seconds), to count down by.")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.pairing.approve",
        .description = "Approve a request with the code the device shows (number matching). Any other code denies "
                       "the request (invalid). Creates the device for the caller's account.",
        .payload = {requestIdField(),
                    str("code").gen(gen::ref("device.pairing_request", {"code"})).desc("Six digits (spaces allowed).")},
        .response = {deviceObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.pairing.deny",
        .description = "Deny a pending request; the device is told it was declined.",
        .payload = {requestIdField()},
        .response = {boolean("denied")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- devices

    out.push_back({
        .command = "device.list",
        .description = "The caller's devices, revoked ones included; with all, every user's (super admins only).",
        .payload = {boolean("all").opt().gen(gen::boolean())},
        .response = {objectArray("devices", "Device")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.rename",
        .description = "Rename a device (its user, or a super admin).",
        .payload = {deviceIdField(), str("name").gen(gen::pattern("Mac {a}{a}{a}")).desc("1-64 characters.")},
        .response = {deviceObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.revoke",
        .description = "Unpair a device (its user, a super admin, or the device itself). Final: its live sessions "
                       "close at once and its key only ever gets pairing-only connections again.",
        .payload = {deviceIdField()},
        .response = {deviceObject()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    // ---- the listener's exposure (super admins)

    out.push_back({
        .command = "device.remote.status",
        .description = "The device listener: loopback only or every interface, and whether it listens; diagnostics "
                       "say where it is bound, what devices are told, what the host firewall looks like (read-only, "
                       "null when unknown) and when a device last connected from a public address.",
        .input = "none",
        .response = {listenerStatus(),
                     object("diagnostics", "",
                            {strArray("bind").desc("Every address it listens on (\"[::]:36972\", \"127.0.0.1:36972\")."),
                             boolean("ipv6").desc("An IPv6 socket is among them."), candidates(),
                             object("firewall", "",
                                    {str("detected").oneOf({"ufw", "firewalld", "nftables", "pf", "alf", "none",
                                                            "unknown"}),
                                     boolean("active").nullable().desc("Null when it can't be told without root."),
                                     str("hint").nullable().desc("What to run so the port gets through, if known.")}),
                             uinteger("last_remote_device_at").nullable()
                                 .desc("Unix seconds of the latest Device handshake from a public (non-loopback, "
                                       "non-private) address since the daemon started; null when none."),
                             str("last_remote_device_ip").nullable()})
                         .desc("transfer-protocol.md §1.3.")},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.remote.enable",
        .description = "Let devices on other hosts connect: the listener rebinds to every interface now, and stays "
                       "that way across restarts and upgrades (device_server.remote in config.yaml).",
        .input = "none",
        .response = {listenerStatus()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    out.push_back({
        .command = "device.remote.disable",
        .description = "Back to loopback only: the listener rebinds now and device sessions from other hosts close.",
        .input = "none",
        .response = {listenerStatus()},
        .refusal_codes = opsRefusals(),
        .client_timeout = kDefaultTimeout,
    });

    return out;
}

}
