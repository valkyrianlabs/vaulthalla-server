#include "ops/Devices.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "db/query/device/ApprovalKey.hpp"
#include "db/query/device/BackupGrant.hpp"
#include "ops/BackupGrants.hpp"

#include "config/Registry.hpp"
#include "db/query/device/Device.hpp"
#include "device/Crypto.hpp"
#include "device/Peer.hpp"
#include "device/ServerIdentity.hpp"
#include "identities/User.hpp"
#include "log/Registry.hpp"
#include "ops/Config.hpp"
#include "protocols/device/Service.hpp"
#include "runtime/Manager.hpp"

#include <unistd.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdlib>

namespace vh::ops::devices {

namespace {

using vh::device::Pairing;
using vh::device::PairingClock;
using Devices = db::query::device::Devices;

constexpr int64_t kRotationClockSkewSeconds = 300;

Pairing& pairing() { return Pairing::instance(); }

// A person signed in: any account that may sign in can pair devices to itself (D3).
void requireUser(const Actor& actor) {
    requireActor(actor);
    if (actor->systemOnly() || !actor->authorizing()) throw Denied("this account cannot pair devices");
}

void requireSuperAdmin(const Actor& actor, const std::string& what) {
    requireActor(actor);
    if (!actor->isSuperAdmin()) throw Denied("only super admins may " + what);
}

std::string lower(std::string s) {
    std::ranges::transform(s, s.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return s;
}

bool allHex(const std::string& s) {
    return !s.empty() && std::ranges::all_of(s, [](const unsigned char c) { return std::isxdigit(c) != 0; });
}

bool allDigits(const std::string& s) {
    return !s.empty() && s.size() <= 9 && std::ranges::all_of(s, [](const unsigned char c) { return std::isdigit(c) != 0; });
}

std::string nodeName() {
    std::array<char, 256> host{};
    if (::gethostname(host.data(), host.size() - 1) != 0) return "vaulthalla";
    return host.data();
}

std::string shortId(const std::string& deviceId) { return deviceId.substr(0, 16); }

// The row a caller names, visible to them: their own devices, or any for a super admin. Anything else is
// "not found" (no oracle for other users' devices).
Device resolve(const Actor& actor, const Ref& ref) {
    const auto text = lower(ref);
    std::optional<Device> row;
    if (text.size() == 64 && allHex(text)) row = Devices::byCurrentSpki(text);
    else if (allDigits(text)) row = Devices::byId(static_cast<uint32_t>(std::strtoul(text.c_str(), nullptr, 10)));
    else if (text.size() >= 8 && text.size() < 64 && allHex(text)) {
        const auto candidates = actor->isSuperAdmin() ? Devices::listAll() : Devices::listForUser(actor->id);
        for (const auto& d : candidates) {
            if (!d.spki_sha256.starts_with(text)) continue;
            if (row) throw Invalid("'" + ref + "' matches more than one device; give more of its id");
            row = d;
        }
    } else {
        throw Invalid("name a device by its id (64 hex digits, or at least the first 8) or its number");
    }
    if (!row || (row->user_id != actor->id && !actor->isSuperAdmin()))
        throw NotFound("no device '" + ref + "'");
    return *row;
}

std::string validPlatform(const std::string& platform) {
    const bool ok = !platform.empty() && platform.size() <= 32 &&
                    std::ranges::all_of(platform, [](const unsigned char c) {
                        return std::isalnum(c) != 0 || c == ' ' || c == '.' || c == '_' || c == '-';
                    });
    if (!ok) throw Invalid("platform must be 1-32 letters, digits, spaces, dots, dashes or underscores");
    return platform;
}

std::string validAppVersion(const std::string& version) {
    const bool ok = version.size() <= 64 &&
                    std::ranges::all_of(version, [](const unsigned char c) { return c >= 0x20 && c < 0x7f; });
    if (!ok) throw Invalid("app_version must be at most 64 printable ASCII characters");
    return version;
}

std::string validName(const std::string& name) {
    const auto normalized = vh::device::normalizeDeviceName(name);
    if (!normalized) throw Invalid("a device name is 1-64 characters without control characters");
    return *normalized;
}

// An approval key as a device sends it (base64 SPKI DER): a P-256 key that isn't the connection's own key and that no
// device here has or had (as its key or approval key).
vh::device::crypto::PublicKey validApprovalKey(const std::vector<uint8_t>& der, const vh::device::Peer& peer) {
    auto key = vh::device::crypto::p256KeyFromSpki(der);
    if (!key)
        throw Invalid("approval_key must be a P-256 SubjectPublicKeyInfo (91 bytes of DER, an uncompressed point), "
                      "in standard base64");
    if (key->spkiSha256 == peer.spki) throw Invalid("the approval key must be a second key, not the connection's");
    if (db::query::device::ApprovalKeys::known(vh::device::crypto::toHex(key->spkiSha256)))
        throw Conflict("this approval key is already known to this node; use a new key");
    return *key;
}

std::shared_ptr<const vh::device::ServerIdentity> serverIdentityOrThrow() {
    auto identity = vh::device::currentServerIdentity();
    if (!identity) throw std::runtime_error("the device listener has no server identity yet");
    return identity;
}

}

// ---- pairing, owner side

vh::device::PairingWindow openWindow(const Actor& actor) {
    requireUser(actor);
    const auto window = pairing().open(actor->id, PairingClock::now());
    log::Registry::audit()->info("[ops::devices] {} opened a pairing window (until {})", actor->name(), window.expires_at);
    return window;
}

bool closeWindow(const Actor& actor, const bool any) {
    requireUser(actor);
    if (any) requireSuperAdmin(actor, "close another user's pairing window");
    const bool closed = pairing().close(actor->id, any, PairingClock::now());
    if (closed) log::Registry::audit()->info("[ops::devices] {} closed the pairing window", actor->name());
    return closed;
}

PendingList pending(const Actor& actor) {
    requireUser(actor);
    const auto now = PairingClock::now();
    PendingList out;
    if (const auto window = pairing().window(now); window && window->owner_id == actor->id) out.window = window;
    out.requests = pairing().pending(actor->id, now);
    return out;
}

Device approve(const Actor& actor, const std::string& requestId, const std::string& code) {
    requireUser(actor);
    // #359: device.trust, bound to this request, the key it pairs and the code the person chose (digested: the audit
    // trail never holds codes). Checked (a wrong code still denies) before the request is held for the approval.
    const auto spki = pairing().checkApproval(actor->id, requestId, code, PairingClock::now());
    const auto chosen = vh::device::crypto::normalizeCode(code).value_or("");
    const auto codeDigest = vh::device::crypto::sha256(
        std::span<const uint8_t>(reinterpret_cast<const uint8_t*>(chosen.data()), chosen.size()));
    auth::stepup::require(auth::stepup::Family::DeviceTrust,
                          "device.pairing.approve:" + requestId + ":" + spki + ":" +
                              vh::device::crypto::toHex(codeDigest).substr(0, 16));
    const auto claim = pairing().beginApproval(actor->id, requestId, code, PairingClock::now());
    Device device;
    try {
        db::query::device::NewDevice row{.user_id = claim.owner_id, .approved_by = actor->id, .name = claim.name,
                                         .platform = claim.platform, .app_version = claim.app_version,
                                         .spki_sha256 = claim.device_id, .last_ip = claim.source_ip};
        if (claim.approval_key) {
            row.approval_key_spki = claim.approval_key->spkiDer;
            row.approval_key_sha256 = vh::device::crypto::toHex(claim.approval_key->spkiSha256);
        }
        device = Devices::insert(row);
    } catch (...) {
        pairing().abortApproval(requestId, PairingClock::now());
        throw;
    }
    pairing().finishApproval(requestId, device.id, PairingClock::now());
    log::Registry::audit()->info("[ops::devices] {} approved device {} ('{}', {}) from {}", actor->name(),
                                 shortId(device.spki_sha256), device.name, device.platform, claim.source_ip);
    if (claim.approval_key)
        vh::audit::record({.action = "device.approval.key.register", .actor_id = actor->id, .actor = actor->name(),
                       .details = {{"device", device.id}, {"via", "pairing"},
                                   {"key", vh::device::crypto::toHex(claim.approval_key->spkiSha256).substr(0, 16)}}},
                      "[ops::devices] device " + shortId(device.spki_sha256) +
                          " was paired with an approval key");
    return device;
}

void deny(const Actor& actor, const std::string& requestId) {
    requireUser(actor);
    pairing().deny(actor->id, requestId, PairingClock::now());
    log::Registry::audit()->info("[ops::devices] {} denied pairing request {}", actor->name(), requestId);
}

// ---- pairing, device side

vh::device::PairRequestReceipt pairRequest(const vh::device::Peer& peer, const PairRequest& req) {
    const auto commitment = vh::device::crypto::hashFromHex(req.commitment);
    if (!commitment) throw Invalid("commitment must be 64 hex digits");
    vh::device::PairRequestInput input{.name = validName(req.name), .platform = validPlatform(req.platform),
                                       .app_version = validAppVersion(req.app_version), .commitment = *commitment};
    if (req.approval_key) {
        const auto der = vh::device::crypto::fromBase64(*req.approval_key);
        if (!der || der->empty()) throw Invalid("approval_key must be standard base64 (with padding)");
        input.approval_key = validApprovalKey(*der, peer);
    }
    // A key that is (or was) a device here never pairs again: pairing always uses a fresh key (spec §6).
    if (Devices::spkiKnown(peer.spkiHex))
        throw Conflict("this device key is already known to this node; pair with a new key");
    return pairing().request(peer, input, PairingClock::now());
}

std::time_t pairConfirm(const vh::device::Peer& peer, const std::string& requestId, const std::string& nonceDevice) {
    const auto nonce = vh::device::crypto::hashFromHex(nonceDevice);
    if (!nonce) throw Invalid("nonce_device must be 64 hex digits");
    return pairing().confirm(peer, requestId, *nonce, serverIdentityOrThrow()->spkiSha256(), PairingClock::now());
}

PairStatus pairStatus(const vh::device::Peer& peer, const std::string& requestId) {
    const auto status = pairing().status(peer, requestId, PairingClock::now());
    PairStatus out{.state = status.state};
    if (status.state == vh::device::RequestState::Approved) {
        out.node_id = Devices::nodeId();
        out.node_name = nodeName();
        out.device_id = status.device_id;
    }
    return out;
}

// ---- devices

std::vector<Device> list(const Actor& actor, const bool all) {
    requireUser(actor);
    if (all) {
        requireSuperAdmin(actor, "list every user's devices");
        return Devices::listAll();
    }
    return Devices::listForUser(actor->id);
}

Device get(const Actor& actor, const Ref& device) {
    requireUser(actor);
    return resolve(actor, device);
}

Device rename(const Actor& actor, const Ref& device, const std::string& name) {
    requireUser(actor);
    const auto row = resolve(actor, device);
    const auto next = validName(name);
    auto renamed = Devices::rename(row.id, next);
    if (!renamed) throw NotFound("no device '" + device + "'");
    log::Registry::audit()->info("[ops::devices] {} renamed device {} '{}' -> '{}'", actor->name(),
                                 shortId(row.spki_sha256), row.name, next);
    return *renamed;
}

Device revoke(const Actor& actor, const Ref& device, const vh::device::Peer* self) {
    // The device itself ("Unpair this Mac") acts as its user, so the visibility rule in resolve() already admits it.
    requireUser(actor);
    const auto row = resolve(actor, device);
    // #362: the device's key-backup grant ends with it, in the revocation's transaction; audited here.
    const auto grant = db::query::device::BackupGrants::liveForDevice(row.id);
    auto revoked = Devices::revoke(row.id);
    if (!revoked) throw NotFound("no device '" + device + "'");
    if (grant)
        if (const auto ended = db::query::device::BackupGrants::byId(grant->id); ended && !ended->live())
            backup_grants::auditRevoked({*ended}, backup_grants::Revocation::DeviceRevoked, actor->id);
    // The device revoking itself keeps its own connection until its reply is out (the ws handler closes it then).
    const auto closed = protocols::device::closeDeviceSessions(row.id, self);
    log::Registry::audit()->info("[ops::devices] {} revoked device {} ('{}', user {}){}; closed {} live session(s)",
                                 actor->name(), shortId(row.spki_sha256), row.name, row.user_name,
                                 self && self->deviceRowId == row.id ? " from the device itself" : "", closed);
    return *revoked;
}

std::string rotateIdentity(const Actor& actor, const vh::device::Peer& peer, const std::vector<uint8_t>& certificate,
                           const int64_t timestamp, const std::vector<uint8_t>& signature) {
    requireActor(actor);
    if (!peer.deviceRowId) throw Refused("device_unknown", "this device is not paired with this node");
    const auto row = Devices::byId(*peer.deviceRowId);
    if (!row || row->revoked() || row->user_id != actor->id)
        throw Refused("device_unknown", "this device is not paired with this node");

    const auto newKey = vh::device::crypto::p256KeyOfCertificate(certificate);
    const auto verifyProof = [&](const vh::device::crypto::Hash& newSpki) {
        const auto now = static_cast<int64_t>(PairingClock::to_time_t(PairingClock::now()));
        if (timestamp < now - kRotationClockSkewSeconds || timestamp > now + kRotationClockSkewSeconds)
            throw Invalid("the rotation timestamp is more than 5 minutes from this node's clock");
        const auto message = vh::device::crypto::rotationMessage(newSpki, serverIdentityOrThrow()->spkiSha256(),
                                                                  static_cast<uint64_t>(timestamp));
        if (!vh::device::crypto::verifyEcdsaP256Sha256(peer.spkiDer, message, signature))
            throw Invalid("the rotation signature does not verify under this connection's key");
    };

    // 1. The connection's key must be the row's current key. A connection still on the previous key may only
    //    retry the rotation that already happened (the reply was lost): same new key succeeds, another conflicts.
    if (peer.spkiHex != row->spki_sha256) {
        if (row->previous_spki_sha256 == peer.spkiHex && newKey &&
            vh::device::crypto::toHex(newKey->spkiSha256) == row->spki_sha256) {
            verifyProof(newKey->spkiSha256);
            return row->spki_sha256;
        }
        throw Conflict("this device's key was already rotated to another key");
    }
    // 2. The certificate carries a P-256 key.
    if (!newKey) throw Invalid("certificate must be a DER X.509 certificate with an ECDSA P-256 key");
    const auto newHex = vh::device::crypto::toHex(newKey->spkiSha256);
    // 3. A key no device has ever had (current or previous, revoked included).
    if (Devices::spkiKnown(newHex)) throw Conflict("the new key is already known to this node");
    // 4 + 5. Fresh, and endorsed by the old key for this node.
    verifyProof(newKey->spkiSha256);

    if (!Devices::rotate(row->id, peer.spkiHex, newHex))
        throw Conflict("this device's key changed meanwhile; reconnect and try again");
    log::Registry::audit()->info("[ops::devices] device {} ('{}', user {}) rotated its key to {}", shortId(row->spki_sha256),
                                 row->name, row->user_name, shortId(newHex));
    return newHex;
}

void registerApprovalKey(const Actor& actor, const vh::device::Peer& peer, const std::vector<uint8_t>& spkiDer) {
    requireUser(actor);
    if (!peer.deviceRowId) throw Refused("device_unknown", "this device is not paired with this node");
    const auto row = Devices::byId(*peer.deviceRowId);
    if (!row || row->revoked() || row->user_id != actor->id)
        throw Refused("device_unknown", "this device is not paired with this node");
    const auto key = validApprovalKey(spkiDer, peer);
    if (db::query::device::ApprovalKeys::forDevice(row->id))
        throw Conflict("this device already has an approval key (a device registers one once)");
    const auto keyHex = vh::device::crypto::toHex(key.spkiSha256);
    // A person approves it in the web console (design 6.2): a device.trust grant for exactly this device and key.
    auth::stepup::require(auth::stepup::Family::DeviceTrust,
                          "device.approval.key.register:" + std::to_string(row->id) + ":" + keyHex);
    (void)db::query::device::ApprovalKeys::registerKey(row->id, key.spkiDer, keyHex, "console_approval");
    vh::audit::record({.action = "device.approval.key.register", .actor_id = actor->id, .actor = actor->name(),
                   .details = {{"device", row->id}, {"via", "console_approval"}, {"key", keyHex.substr(0, 16)}}},
                  "[ops::devices] device " + shortId(row->spki_sha256) + " registered an approval key");
}

ServerIdentityInfo serverIdentity(const vh::device::Peer& peer) {
    if (!peer.deviceRowId) throw Refused("device_unknown", "this device is not paired with this node");
    return {.spki_sha256 = serverIdentityOrThrow()->spkiHex()};
}

// ---- endpoint advertisement

Endpoints endpoints(const vh::device::Peer& peer) {
    if (!peer.deviceRowId) throw Refused("device_unknown", "this device is not paired with this node");
    return {.node_id = protocols::device::endpoints::nodeId(), .advertisement = protocols::device::endpoints::current()};
}

PairingBootstrap pairingBootstrap(const Actor& actor) {
    requireUser(actor);
    PairingBootstrap out{.node_id = protocols::device::endpoints::nodeId(),
                         .endpoints = protocols::device::endpoints::current()};
    if (const auto identity = vh::device::currentServerIdentity()) out.server_spki_sha256 = identity->spkiHex();
    return out;
}

// ---- the listener's exposure

protocols::device::ListenerStatus remoteStatus(const Actor& actor) {
    requireSuperAdmin(actor, "see the device listener's settings");
    if (const auto service = runtime::Manager::instance().getDeviceServer(); service && service->isRunning())
        return service->listenerStatus();
    const auto cfg = vh::config::Registry::get().device_server;
    protocols::device::ListenerStatus out{.enabled = cfg.enabled, .remote = cfg.remote, .port = cfg.port};
    if (const auto identity = vh::device::currentServerIdentity()) out.server_spki_sha256 = identity->spkiHex();
    return out;
}

RemoteDiagnostics remoteDiagnostics(const Actor& actor) {
    const auto status = remoteStatus(actor);  // super admins only
    auto advertisement = protocols::device::endpoints::current();
    return {.bind = status.bind,
            .ipv6 = status.ipv6,
            .candidates = std::move(advertisement.candidates),
            .firewall = platform::network::detectFirewall(advertisement.port),
            .last_remote_device = protocols::device::endpoints::lastRemoteDevice()};
}

protocols::device::ListenerStatus setRemote(const Actor& actor, const bool enabled) {
    (void)ops::config::setDeviceRemote(actor, enabled);
    return remoteStatus(actor);
}

}
