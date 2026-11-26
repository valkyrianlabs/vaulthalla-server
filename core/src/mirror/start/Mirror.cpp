#include "mirror/start/Start.hpp"

#include "audit/Trail.hpp"
#include "crypto/SecretKey.hpp"
#include "crypto/id/Generator.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/Vault.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "peer/Keys.hpp"
#include "runtime/Deps.hpp"
#include "storage/Manager.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/KeyCheck.hpp"
#include "vault/Master.hpp"
#include "vault/Recover.hpp"
#include "vault/model/Vault.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/uid.hpp>

#include <fmt/format.h>
#include <paths.h>
#include <sodium.h>

#include <sys/statvfs.h>

#include <algorithm>
#include <filesystem>
#include <set>

namespace vh::mirror::start {

namespace start_mirror_detail {

using Q = vh::db::query::mirror::MirrorStart;
using vh::db::query::mirror::MirrorVaults;

// ---- reading what the other server sent (every field checked; nothing is trusted for what this server decides)

const json& field(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key)) throw ops::Invalid(std::string(key) + " is required");
    return payload.at(key);
}

std::string text(const json& payload, const char* key, const std::size_t min, const std::size_t max) {
    const auto& v = field(payload, key);
    if (!v.is_string()) throw ops::Invalid(std::string(key) + " must be a string");
    auto s = v.get<std::string>();
    if (s.size() < min || s.size() > max)
        throw ops::Invalid(fmt::format("{} must be {} to {} bytes", key, min, max));
    if (std::ranges::any_of(s, [](const unsigned char c) { return c < 0x20 || c == 0x7f; }))
        throw ops::Invalid(std::string(key) + " must not hold control characters");
    return s;
}

uint64_t number(const json& payload, const char* key, const uint64_t min, const uint64_t max) {
    const auto& v = field(payload, key);
    if (!v.is_number_unsigned() && !(v.is_number_integer() && v.get<int64_t>() >= 0))
        throw ops::Invalid(std::string(key) + " must be a non-negative integer");
    const auto n = v.get<uint64_t>();
    if (n < min || n > max) throw ops::Invalid(fmt::format("{} must be {} to {}", key, min, max));
    return n;
}

vh::crypto::id::ObjectUid uidOf(const json& payload, const char* key) {
    const auto s = text(payload, key, 26, 26);
    const auto uid = vl::keykit::fromBase32(s);
    if (!uid) throw ops::Invalid(std::string(key) + " is not a uid (26 base32 symbols)");
    return *uid;
}

std::string offerUidOf(const json& payload) {
    const auto s = text(payload, "offer_uid", 36, 36);
    try {
        return vh::crypto::id::toUuid(vh::crypto::id::fromUuid(s));
    } catch (const std::exception&) {
        throw ops::Invalid("offer_uid is not a UUID");
    }
}

std::vector<uint8_t> base64(const json& payload, const char* key, const std::size_t maxBytes) {
    const auto s = text(payload, key, 1, maxBytes * 2);
    std::vector<uint8_t> out(s.size());
    std::size_t len = 0;
    if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0 || len > maxBytes)
        throw ops::Invalid(std::string(key) + " is not standard base64 of at most " + std::to_string(maxBytes) +
                           " bytes");
    out.resize(len);
    return out;
}

std::optional<vh::db::query::mirror::OfferedRole> roleOf(const json& j) {
    if (j.is_null()) return std::nullopt;
    if (!j.is_object()) throw ops::Invalid("a role is an object or null");
    return vh::db::query::mirror::OfferedRole{.name = text(j, "role_name", 1, 50),
                                              .files = number(j, "files", 0, 0xffffffffu),
                                              .directories = number(j, "directories", 0, 0xffffffffu),
                                              .sync = number(j, "sync", 0, 0xffffffffu),
                                              .roles = number(j, "roles", 0, 0xffffu)};
}

// The offer as this server stores it, from the core's payload.
Offer offerFrom(const vh::peer::Record& from, const json& p) {
    Offer o;
    o.offer_uid = offerUidOf(p);
    o.side = "mirror";
    o.peer_id = from.id;
    o.vault_uid = uidOf(p, "vault_uid");
    o.core_vault_id = number(p, "core_vault_id", 1, 2147483647);
    o.root_uid = uidOf(p, "root_uid");
    o.term = number(p, "term", 1, uint64_t{1} << 62);
    o.name = text(p, "name", 1, 255);
    o.description = p.contains("description") && p.at("description").is_string() ? text(p, "description", 0, 4096) : "";
    o.quota = number(p, "quota", 0, uint64_t{1} << 62);
    o.size_bytes = number(p, "size_bytes", 0, uint64_t{1} << 62);
    o.file_count = number(p, "file_count", 0, uint64_t{1} << 62);
    const auto& history = field(p, "history");
    if (!history.is_boolean()) throw ops::Invalid("history must be a boolean");
    o.history = history.get<bool>();
    const auto& owner = field(p, "owner");
    if (!owner.is_object()) throw ops::Invalid("owner must be an object");
    o.owner = {.node = text(owner, "node", 1, 64), .id = static_cast<uint32_t>(number(owner, "id", 1, 2147483647)),
               .name = owner.contains("name") && owner.at("name").is_string() ? text(owner, "name", 0, 80) : ""};
    o.role = roleOf(p.contains("role") ? p.at("role") : json(nullptr));
    // This server's own lifetime, never the other server's clock.
    o.expires_at = std::time(nullptr) + std::chrono::duration_cast<std::chrono::seconds>(kOfferLifetime).count();
    return o;
}

const Offer& requireFrom(const Offer& o, const vh::peer::Record& from) {
    if (o.peer_id != from.id) throw ops::NotFound("no such offer");
    return o;
}

vh::db::query::mirror::Grant grantFrom(const vh::db::query::mirror::OfferedRole& r, const vh::peer::Record& from) {
    return {.role_name = r.name, .files = r.files, .directories = r.directories, .sync = r.sync, .roles = r.roles,
            // The server that sent it, from its pinned session: never a field of the payload.
            .granted_by_node = from.node_id, .granted_at = 0};
}

void applyGrant(const uint32_t vaultId, const std::optional<vh::db::query::mirror::OfferedRole>& role,
                const vh::peer::Record& from) {
    if (role) (void)MirrorVaults::recordGrant(vaultId, grantFrom(*role, from));
    else (void)MirrorVaults::clearGrant(vaultId);
}

// The vault this server holds as `from`'s copy, by its uid: role mirror (or orphaned) for that very server.
std::optional<uint32_t> heldFrom(const vh::crypto::id::ObjectUid& vaultUid, const vh::peer::Record& from) {
    const auto vaultId = Q::vaultWithUid(vaultUid);
    if (!vaultId) return std::nullopt;
    const auto row = MirrorVaults::get(*vaultId);
    if (!row || row->role == "core" || row->peer_id != from.id) return std::nullopt;
    return vaultId;
}

}

// ---- what this server would take -------------------------------------------------------------------------------------

std::optional<std::pair<std::string, std::string>> mirrorRefusal(const Offer& o, const std::optional<uint32_t> ownVault) {
    using namespace start_mirror_detail;
    if (o.history)
        return std::make_pair(std::string("history_not_supported"),
                              std::string("the offer includes the vault's history, which this server can't mirror yet"));
    if (const auto v = Q::vaultWithUid(o.vault_uid); v && v != ownVault)
        return std::make_pair(std::string("mirror_vault_exists"),
                              "a vault on this server already has that vault's uid (vault " + std::to_string(*v) + ")");
    // A name clash is refused, not renamed (design decision): a second vault of that name here would be one a person
    // could mistake for the other, in the mount and in every list. Rename or remove this server's vault, then accept.
    if (const auto v = Q::vaultNamed(o.name); v && v != ownVault)
        return std::make_pair(std::string("mirror_name_taken"),
                              "a vault named '" + o.name + "' exists on this server already (vault " + std::to_string(*v) +
                                  "): rename it, then accept the offer");
    struct statvfs st{};
    const auto where = vh::paths::getBackingPath();
    if (::statvfs(where.c_str(), &st) == 0) {
        const auto free = static_cast<uint64_t>(st.f_bavail) * static_cast<uint64_t>(st.f_frsize);
        const auto need = o.size_bytes + std::max<uint64_t>(kSpaceMarginFloor, o.size_bytes / 10);
        if (free < need)
            return std::make_pair(std::string("mirror_no_space"),
                                  fmt::format("the vault needs about {} bytes (its {} bytes and a margin) and the volume "
                                              "this server keeps vaults on has {} free", need, o.size_bytes, free));
    }
    return std::nullopt;
}

// ---- a person here ------------------------------------------------------------------------------------------------------

Offer accept(const Offer& offer, const std::optional<uint32_t> actorId, const std::string& actorName) {
    if (offer.side != "mirror" || offer.state != "pending")
        throw ops::Refused("mirror_offer_not_pending", "that offer is " + offer.state + ", not waiting for an answer");
    if (const auto refusal = mirrorRefusal(offer)) throw ops::Refused(refusal->first, refusal->second);
    const auto moved = start_mirror_detail::Q::transition(offer.id, {"pending"},
                                                          {.to = "accepted", .notify = true, .decided_by = actorId});
    if (!moved) throw ops::Conflict("the offer moved on meanwhile");
    audit::record({.action = "mirror.accept", .actor_id = actorId, .actor = actorName,
                   .details = {{"peer", offer.peer_id}, {"core_vault_id", offer.core_vault_id}, {"automatic", !actorId}}},
                  fmt::format("[mirror] {} accepted linked server {}'s offer of its vault {}",
                              actorName.empty() ? std::string("this server (every vault from it is accepted)") : actorName,
                              offer.peer_id, offer.core_vault_id));
    Service::instance()->wake();
    return *moved;
}

Offer decline(const Offer& offer, const std::optional<uint32_t> actorId, const std::string& actorName,
              const std::string& reason) {
    if (offer.side != "mirror" || (offer.state != "pending" && offer.state != "accepted"))
        throw ops::Refused("mirror_offer_not_pending", "that offer is " + offer.state + ": it can't be declined now");
    const auto moved = start_mirror_detail::Q::transition(
        offer.id, {"pending", "accepted"}, {.to = "declined", .notify = true, .reason = reason, .decided_by = actorId});
    if (!moved) throw ops::Conflict("the offer moved on meanwhile");
    audit::record({.action = "mirror.decline", .actor_id = actorId, .actor = actorName,
                   .details = {{"peer", offer.peer_id}, {"core_vault_id", offer.core_vault_id}, {"reason", reason}}},
                  fmt::format("[mirror] {} declined linked server {}'s offer of its vault {} ({})",
                              actorName.empty() ? std::string("this server") : actorName, offer.peer_id,
                              offer.core_vault_id, reason));
    Service::instance()->wake();
    return *moved;
}

void removeCopy(const uint32_t vaultId) {
    std::optional<uint32_t> owner;
    if (const auto v = vh::db::query::vault::Vault::getVault(vaultId)) owner = v->owner_id;
    if (const auto& manager = runtime::Deps::get().storageManager) manager->removeVault(vaultId);
    else vh::db::query::vault::Vault::removeVault(vaultId);
    // The rows cascaded with the vault (keys, origins, pending contents, the mirror row); this republishes who may.
    (void)vh::db::query::mirror::MirrorVaults::remove(vaultId);
    if (owner) start_mirror_detail::Q::dropOrphanedOwner(*owner);
}

Offer cancelOnMirror(const Offer& offer, const std::optional<uint32_t> actorId, const std::string& actorName) {
    using namespace start_mirror_detail;
    if (offer.side != "mirror") throw ops::Invalid("not an offer this server received");
    if (offer.state == "started")
        throw ops::Refused("mirror_detach_required",
                           "this server holds the vault as a completed mirror: removing it here would destroy a copy of "
                           "its data, so it is refused; ending a mirror from this side is the detach (a later version), "
                           "or the core cancels it (vh mirror cancel on the core)");
    if (offer.finished()) throw ops::Refused("mirror_offer_finished", "that offer is " + offer.state + " already");
    std::optional<Offer> moved;
    {
        std::scoped_lock lock(stepMutex());
        const auto now = Q::offer(offer.id);
        if (!now || now->finished()) throw ops::Conflict("the offer moved on meanwhile");
        if (now->state == "installed" && now->vault_id) removeCopy(*now->vault_id);
        moved = Q::transition(offer.id, {"pending", "accepted", "installed"},
                              {.to = "cancelled", .notify = true, .reason = "cancelled_by_mirror", .decided_by = actorId});
    }
    if (!moved) throw ops::Conflict("the offer moved on meanwhile");
    audit::record({.action = "mirror.cancel", .actor_id = actorId, .actor = actorName, .vault_id = offer.vault_id,
                   .details = {{"peer", offer.peer_id}, {"side", "mirror"}, {"reason", "cancelled_by_mirror"},
                               {"by", "this_server"}}},
                  fmt::format("[mirror] {} cancelled the start of linked server {}'s vault {} on this server",
                              actorName, offer.peer_id, offer.core_vault_id),
                  spdlog::level::warn);
    Service::instance()->wake();
    return *moved;
}

// ---- the wire, on the mirror --------------------------------------------------------------------------------------------

json offerReceived(const vh::peer::Record& from, const json& payload) {
    using namespace start_mirror_detail;
    auto o = offerFrom(from, payload);
    if (const auto existing = Q::offerByUid(o.offer_uid, "mirror"))
        return {{"offer_uid", requireFrom(*existing, from).offer_uid}, {"state", existing->state}};

    // An earlier start of the same vault from the same server that never got its keys gives way to this one.
    if (const auto earlier = Q::activeOffer(o.vault_uid, "mirror")) {
        if (earlier->peer_id == from.id && (earlier->state == "pending" || earlier->state == "accepted"))
            (void)Q::transition(earlier->id, {"pending", "accepted"},
                                {.to = "cancelled", .notify = false, .reason = "superseded"});
        else
            o.state = "declined";
    }
    if (o.state == "declined") {
        o.reason = "mirror_vault_exists";
        o.detail = "this server is starting a mirror of that vault already";
    } else if (const auto refusal = mirrorRefusal(o)) {
        o.state = "declined";
        o.reason = refusal->first;
        o.detail = refusal->second;
    } else {
        o.state = Q::acceptVaults(from.id).enabled ? "accepted" : "pending";
    }
    o.notify = o.state != "pending";
    const auto stored = Q::insertOffer(o);
    audit::record({.action = "mirror.offer", .outcome = audit::Outcome::Info,
                   .details = {{"peer", from.id}, {"node_id", from.node_id}, {"side", "mirror"},
                               {"core_vault_id", stored.core_vault_id}, {"files", stored.file_count},
                               {"bytes", stored.size_bytes}, {"state", stored.state},
                               {"reason", stored.reason ? json(*stored.reason) : json(nullptr)}}},
                  fmt::format("[mirror] linked server {} ('{}') offered its vault {} to this server: {}", from.node_id,
                              from.name, stored.core_vault_id,
                              stored.state == "accepted" ? std::string("accepted (every vault from it is accepted)")
                              : stored.state == "pending" ? std::string("waiting for a super admin here")
                                                          : "declined (" + stored.reason.value_or("") + ")"));
    if (stored.state == "accepted")
        audit::record({.action = "mirror.accept", .details = {{"peer", from.id}, {"core_vault_id", stored.core_vault_id},
                                                              {"automatic", true}}},
                      fmt::format("[mirror] this server accepted linked server {}'s offer of its vault {} (the link "
                                  "accepts every vault from it)", from.node_id, stored.core_vault_id));
    Service::instance()->wake();
    return {{"offer_uid", stored.offer_uid}, {"state", stored.state}};
}

json keysReceived(const vh::peer::Record& from, const json& payload) {
    using namespace start_mirror_detail;
    const auto offerUid = offerUidOf(payload);
    const auto found = Q::offerByUid(offerUid, "mirror");
    if (!found) throw ops::NotFound("no such offer");
    const auto& offer = requireFrom(*found, from);
    if ((offer.state == "installed" || offer.state == "started") && offer.vault_id)
        return {{"vault_uid", vl::keykit::toBase32(offer.vault_uid)}, {"installed", true}};
    if (offer.state != "accepted")
        throw ops::Refused("mirror_offer_not_accepted", "this server has not accepted that offer (it is " + offer.state + ")");
    if (uidOf(payload, "vault_uid") != offer.vault_uid || number(payload, "core_vault_id", 1, 2147483647) != offer.core_vault_id)
        throw ops::Invalid("the keys are for another vault than the offer");
    const auto& list = field(payload, "versions");
    if (!list.is_array() || list.empty() || list.size() > kMaxKeyVersions)
        throw ops::Invalid(fmt::format("versions must be 1 to {} key versions", kMaxKeyVersions));

    // The anchors: the attestation keys this server pinned when it paired with `from` (the card bound into the code),
    // over `from`'s node id and the vault's id there. This server's own keys prove nothing about where a key came from.
    vh::vault::recover::Pins pins{.supplied = true, .keys = {}, .node_id = from.node_id, .vault_id = offer.core_vault_id};
    for (std::size_t i = 0; i < from.attest_public_keys.size(); ++i)
        pins.keys.push_back({.key_id = static_cast<unsigned>(i + 1),
                             .public_key = {from.attest_public_keys[i].begin(), from.attest_public_keys[i].end()},
                             .source = "pairing"});
    std::vector<std::vector<uint8_t>> selfKeys;
    for (const auto& k : vh::db::query::vault::Key::attestationKeys()) selfKeys.push_back(k.public_key);

    struct Proven {
        uint32_t version{};
        bool current{false};
        crypto::SecretKeyPtr key;
        std::string key_check;
        unsigned int attestation_key_id{};
        std::vector<uint8_t> attestation, anchor;
    };
    std::vector<Proven> proven;
    std::set<uint32_t> seen;
    unsigned currents = 0;
    std::optional<std::string> failure;
    for (const auto& item : list) {
        if (!item.is_object()) throw ops::Invalid("each key version is an object");
        const auto version = static_cast<uint32_t>(number(item, "version", 1, 0x7fffffff));
        if (!seen.insert(version).second) throw ops::Invalid(fmt::format("key version {} is listed twice", version));
        const auto& cur = field(item, "current");
        if (!cur.is_boolean()) throw ops::Invalid("current must be a boolean");
        currents += cur.get<bool>() ? 1 : 0;
        const auto envelope = base64(item, "envelope", 4096);
        const auto keyCheck = text(item, "key_check", 32, 32);
        const auto& att = field(item, "attestation");
        if (!att.is_object()) throw ops::Invalid("attestation must be an object");
        const auto keyId = static_cast<unsigned>(number(att, "key_id", vh::vault::attestation::kMinKeyId,
                                                        vh::vault::attestation::kMaxKeyId));
        const auto signature = base64(att, "signature", vh::vault::attestation::kSignatureSize);
        if (signature.size() != vh::vault::attestation::kSignatureSize) throw ops::Invalid("a signature is 64 bytes");

        vl::keykit::kev1::Unwrapped unwrapped;
        try {
            unwrapped = vh::peer::keys::unwrapVaultKey(envelope, offer.vault_uid);
        } catch (const vl::keykit::kev1::Error& e) {
            failure = fmt::format("key version {}: its envelope does not open here ({})", version,
                                  std::string(vl::keykit::kev1::errorCodeName(e.code())));
            break;
        }
        if (unwrapped.key_version != version) {
            failure = fmt::format("key version {}: its envelope holds version {}", version, unwrapped.key_version);
            break;
        }
        auto key = std::make_shared<const crypto::SecretKey>(unwrapped.key.bytes());
        const vh::vault::recover::Evidence evidence{
            .source = "peer", .node_id = from.node_id, .vault_id = offer.core_vault_id, .key_check = keyCheck,
            .attestation = vh::vault::attestation::Attestation{.key_id = keyId, .signature = signature}};
        const auto proof = vh::vault::recover::prove(version, key->bytes(), {evidence}, pins, selfKeys);
        if (!proof.canonical()) {
            failure = fmt::format("key version {}: {} ({})", version, proof.detail,
                                  std::string(vh::vault::recover::to_string(proof.verdict)));
            break;
        }
        proven.push_back({.version = version, .current = cur.get<bool>(), .key = std::move(key), .key_check = keyCheck,
                          .attestation_key_id = keyId, .attestation = signature,
                          .anchor = proof.anchor->public_key});
    }
    if (!failure && currents != 1) failure = "exactly one key version must be the current one";
    if (failure) {
        // One unprovable version refuses the whole start: nothing of the vault is written.
        (void)Q::transition(offer.id, {"accepted"},
                            {.to = "failed", .notify = false, .reason = "mirror_keys_unproven", .detail = *failure});
        audit::record({.action = "mirror.keys", .outcome = audit::Outcome::Failure,
                       .details = {{"peer", from.id}, {"core_vault_id", offer.core_vault_id}, {"proven", false}}},
                      fmt::format("[mirror] refused the keys linked server {} sent for its vault {}: {}", from.node_id,
                                  offer.core_vault_id, *failure),
                      spdlog::level::warn);
        throw ops::Refused("mirror_keys_refused", "the start is refused: " + *failure);
    }
    if (const auto refusal = mirrorRefusal(offer)) {
        (void)Q::transition(offer.id, {"accepted"},
                            {.to = "declined", .notify = false, .reason = refusal->first, .detail = refusal->second});
        throw ops::Refused(refusal->first, refusal->second);
    }

    // Sealed here, provenance over the new vault id, origin from the core.
    std::scoped_lock lock(stepMutex());
    const auto vaultId = Q::reserveVaultId();
    vh::db::query::mirror::NewMirrorVault in;
    in.vault_id = vaultId;
    in.offer_id = offer.id;
    in.peer_id = from.id;
    in.term = offer.term;
    in.vault_uid = offer.vault_uid;
    in.root_uid = offer.root_uid;
    in.name = offer.name;
    in.description = offer.description;
    in.quota = offer.quota;
    in.owner = offer.owner;
    in.mount_point = vh::crypto::id::Generator({.namespace_token = offer.name}).generate();
    const vh::vault::master::Writer writer(true);
    std::vector<uint32_t> versions;
    for (const auto& p : proven) {
        vh::db::query::mirror::MirrorKeyRow row;
        row.version = p.version;
        row.current = p.current;
        const auto wrapped = writer.wrap(p.key->bytes());
        row.encrypted_key = wrapped.encrypted_key;
        row.iv = wrapped.iv;
        row.master_version = wrapped.master_version;
        row.provenance = vh::vault::attestation::provenanceOf(vaultId, p.version, p.key->bytes());
        row.origin_node_id = from.node_id;
        row.origin_vault_id = offer.core_vault_id;
        row.origin_key_check = p.key_check;
        row.attestation_key_id = p.attestation_key_id;
        row.attestation_public_key = p.anchor;
        row.attestation = p.attestation;
        in.keys.push_back(std::move(row));
        versions.push_back(p.version);
    }
    // The backing directory first (an empty directory is all a failed transaction leaves).
    const auto backing = vh::paths::getBackingPath() / in.mount_point;
    std::error_code ec;
    std::filesystem::create_directories(backing, ec);
    try {
        (void)Q::createMirrorVault(in);
    } catch (...) {
        std::filesystem::remove(backing, ec);
        throw;
    }
    std::string versionList;
    for (const auto v : versions) versionList += (versionList.empty() ? "" : ",") + std::to_string(v);
    audit::record({.action = "mirror.keys", .vault_id = vaultId,
                   .details = {{"peer", from.id}, {"node_id", from.node_id}, {"core_vault_id", offer.core_vault_id},
                               {"versions", versionList}, {"proven", true}}},
                  fmt::format("[mirror] installed key version(s) {} of linked server {}'s vault {} as vault {} (each "
                              "proven against the attestation key pinned at pairing, sealed under this server's vault "
                              "master)", versionList, from.node_id, offer.core_vault_id, vaultId));
    try {
        if (const auto& manager = runtime::Deps::get().storageManager) (void)manager->reinstateVault(vaultId);
    } catch (const std::exception& e) {
        log::Registry::storage()->error("[mirror] vault {} was created for linked server {} but does not start yet: {}",
                                        vaultId, from.node_id, e.what());
    }
    return {{"vault_uid", vl::keykit::toBase32(offer.vault_uid)}, {"installed", true}};
}

json beginReceived(const vh::peer::Record& from, const json& payload) {
    using namespace start_mirror_detail;
    const auto found = Q::offerByUid(offerUidOf(payload), "mirror");
    if (!found) throw ops::NotFound("no such offer");
    const auto& offer = requireFrom(*found, from);
    if (uidOf(payload, "vault_uid") != offer.vault_uid) throw ops::Invalid("the begin is for another vault than the offer");
    if (number(payload, "term", 1, uint64_t{1} << 62) != offer.term) throw ops::Invalid("the begin names another term");
    if (offer.state != "installed" && offer.state != "started")
        throw ops::Refused("mirror_offer_not_installed", "this server holds no keys for that offer (it is " + offer.state + ")");
    const auto vaultId = offer.vault_id ? heldFrom(offer.vault_uid, from) : std::nullopt;
    if (!vaultId) throw ops::NotFound("this server holds no such vault for that server");
    applyGrant(*vaultId, roleOf(payload.contains("grant") ? payload.at("grant") : json(nullptr)), from);
    if (offer.state == "installed") {
        (void)Q::transition(offer.id, {"installed"}, {.to = "started", .notify = false});
        audit::record({.action = "mirror.start", .vault_id = *vaultId,
                       .details = {{"peer", from.id}, {"node_id", from.node_id}, {"side", "mirror"},
                                   {"term", offer.term}}},
                      fmt::format("[mirror] vault {} now mirrors linked server {}'s vault {} (term {})", *vaultId,
                                  from.node_id, offer.core_vault_id, offer.term));
    }
    return {{"started", true}};
}

json grantReceived(const vh::peer::Record& from, const json& payload) {
    using namespace start_mirror_detail;
    const auto vaultId = heldFrom(uidOf(payload, "vault_uid"), from);
    // The grant of a vault that is not that server's (another core, none, this server's own): never kept.
    if (!vaultId) throw ops::NotFound("this server holds no such vault for that server");
    applyGrant(*vaultId, roleOf(payload.contains("grant") ? payload.at("grant") : json(nullptr)), from);
    return {{"recorded", true}};
}

json cancelReceived(const vh::peer::Record& from, const json& payload) {
    using namespace start_mirror_detail;
    const auto vaultUid = uidOf(payload, "vault_uid");
    std::optional<std::string> offerUid;
    if (payload.contains("offer_uid") && !payload.at("offer_uid").is_null()) offerUid = offerUidOf(payload);
    const auto why = payload.contains("reason") && payload.at("reason").is_string() ? text(payload, "reason", 0, 48)
                                                                                     : std::string("cancelled");

    // This server is the core: the mirror cancelled (or never took the vault).
    if (const auto vaultId = Q::vaultWithUid(vaultUid)) {
        const auto row = MirrorVaults::get(*vaultId);
        const auto coreOffer = Q::activeOffer(vaultUid, "core");
        if ((row && row->role == "core" && row->peer_id == from.id) || (coreOffer && coreOffer->peer_id == from.id))
            return {{"cancelled", cancelOnCore(*vaultId, "peer_" + why, false, std::nullopt, "")}};
    }

    // This server is the mirror: the core cancelled the start, or ended a completed one.
    std::optional<Offer> offer;
    if (offerUid) offer = Q::offerByUid(*offerUid, "mirror");
    if (!offer) offer = Q::activeOffer(vaultUid, "mirror");
    if (!offer) offer = Q::latestOffer(vaultUid, "mirror");
    if (offer && offer->peer_id != from.id) offer.reset();
    const auto held = heldFrom(vaultUid, from);
    if (!offer && !held) return {{"cancelled", false}};
    {
        std::scoped_lock lock(stepMutex());
        if (held) removeCopy(*held);
        if (offer)
            (void)Q::transition(offer->id, {"pending", "accepted", "installed", "started"},
                                {.to = "cancelled", .notify = false, .reason = "core_" + why});
    }
    audit::record({.action = "mirror.cancel", .outcome = audit::Outcome::Info, .vault_id = held,
                   .details = {{"peer", from.id}, {"node_id", from.node_id}, {"side", "mirror"}, {"reason", why},
                               {"removed", held.has_value()}, {"by", "peer"}}},
                  fmt::format("[mirror] linked server {} cancelled the mirror of its vault{}{}", from.node_id,
                              offer ? " " + std::to_string(offer->core_vault_id) : std::string(),
                              held ? fmt::format(": vault {} and its keys were removed here", *held) : std::string()),
                  spdlog::level::warn);
    Service::instance()->wake();
    return {{"cancelled", true}};
}

json answerReceived(const vh::peer::Record& from, const json& payload) {
    using namespace start_mirror_detail;
    const auto found = Q::offerByUid(offerUidOf(payload), "core");
    if (!found) throw ops::NotFound("no such offer");
    const auto& offer = requireFrom(*found, from);
    const auto decision = text(payload, "decision", 1, 16);
    if (decision == "accepted") {
        if (offer.state == "offered")
            if (const auto moved = Q::transition(offer.id, {"offered"}, {.to = "accepted", .notify = false})) {
                audit::record({.action = "mirror.accept", .outcome = audit::Outcome::Info, .vault_id = offer.vault_id,
                               .details = {{"peer", from.id}, {"node_id", from.node_id}, {"side", "core"}}},
                              fmt::format("[mirror] linked server {} accepted the offer of vault {}", from.node_id,
                                          offer.vault_id.value_or(0)));
                Service::instance()->wake();
                return {{"state", moved->state}};
            }
        return {{"state", Q::offer(offer.id)->state}};
    }
    if (decision != "declined") throw ops::Invalid("decision is accepted or declined");
    const auto reason = payload.contains("reason") && payload.at("reason").is_string() ? text(payload, "reason", 0, 48)
                                                                                         : std::string("declined");
    const auto detail = payload.contains("detail") && payload.at("detail").is_string() ? text(payload, "detail", 0, 500)
                                                                                         : std::string();
    if (const auto moved = Q::transition(offer.id, {"offered", "accepted"},
                                         {.to = "declined", .notify = false, .reason = reason,
                                          .detail = detail.empty() ? std::nullopt : std::optional<std::string>(detail)})) {
        audit::record({.action = "mirror.decline", .outcome = audit::Outcome::Info, .vault_id = offer.vault_id,
                       .details = {{"peer", from.id}, {"node_id", from.node_id}, {"side", "core"}, {"reason", reason}}},
                      fmt::format("[mirror] linked server {} declined the offer of vault {} ({})", from.node_id,
                                  offer.vault_id.value_or(0), reason));
        return {{"state", moved->state}};
    }
    return {{"state", Q::offer(offer.id)->state}};
}

}
