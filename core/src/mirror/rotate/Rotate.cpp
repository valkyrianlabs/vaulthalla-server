#include "mirror/rotate/Rotate.hpp"

#include "audit/Trail.hpp"
#include "crypto/SecretKey.hpp"
#include "db/query/mirror/Keys.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Start.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/vault/Key.hpp"
#include "log/Registry.hpp"
#include "mirror/start/Guard.hpp"
#include "mirror/start/Start.hpp"
#include "ops/Error.hpp"
#include "peer/Keys.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/Master.hpp"
#include "vault/Recover.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/uid.hpp>

#include <fmt/format.h>
#include <sodium.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace vh::mirror::rotate {

namespace mirror_rotate_detail {

using Q = vh::db::query::mirror::MirrorStart;
using vh::db::query::mirror::MirrorVaults;

std::string base64Of(const std::span<const uint8_t> bytes) {
    if (bytes.empty()) return {};
    std::string out(sodium_base64_encoded_len(bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}

const json& field(const json& payload, const char* key) {
    if (!payload.is_object() || !payload.contains(key)) throw ops::Invalid(std::string(key) + " is required");
    return payload.at(key);
}

std::string text(const json& payload, const char* key, const std::size_t min, const std::size_t max) {
    const auto& v = field(payload, key);
    if (!v.is_string()) throw ops::Invalid(std::string(key) + " must be a string");
    auto s = v.get<std::string>();
    if (s.size() < min || s.size() > max) throw ops::Invalid(fmt::format("{} must be {} to {} bytes", key, min, max));
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

std::vector<uint8_t> base64(const json& payload, const char* key, const std::size_t maxBytes) {
    const auto s = text(payload, key, 1, maxBytes * 2);
    std::vector<uint8_t> out(s.size());
    std::size_t len = 0;
    if (sodium_base642bin(out.data(), out.size(), s.data(), s.size(), nullptr, &len, nullptr,
                          sodium_base64_VARIANT_ORIGINAL) != 0 ||
        len > maxBytes)
        throw ops::Invalid(std::string(key) + " is not standard base64 of at most " + std::to_string(maxBytes) +
                           " bytes");
    out.resize(len);
    return out;
}

bool ok(const std::optional<json>& answer) { return answer && answer->value("status", "") == "OK"; }

std::string errorOf(const std::optional<json>& answer) {
    if (!answer) return "no answer from the linked server";
    if (const auto e = answer->find("error"); e != answer->end() && e->is_string()) return e->get<std::string>();
    if (const auto d = answer->find("data"); d != answer->end() && d->is_object() && d->contains("code") &&
                                             d->at("code").is_string())
        return d->at("code").get<std::string>();
    return "refused";
}

std::string endHint(const uint32_t vaultId) {
    return fmt::format("rotate when it is, or end the mirror first (vh mirror cancel {})", vaultId);
}

}

void deliverBeforeRotation(const uint32_t vaultId, const uint32_t version, const std::span<const uint8_t> key,
                           const db::query::vault::Key::Provenance& provenance) {
    using namespace mirror_rotate_detail;
    const auto row = MirrorVaults::get(vaultId);
    // A copy of another server's vault never mints a key version here: its keys are its core's.
    if (row && row->role != "core") vh::mirror::start::refuseIfMirrored(vaultId, "a key rotation");
    if (vh::mirror::start::rotationAllowedForTesting()) return;
    if (!row) {
        if (vh::mirror::start::mirroredOrStarting(vaultId))
            throw ops::Refused("mirror_start_running",
                               fmt::format("a mirror of vault {} is starting: rotate its key once the start has "
                                           "finished, or cancel it (vh mirror cancel {})", vaultId, vaultId));
        return;
    }
    if (row->state != "live")
        throw ops::Refused("mirror_not_live",
                           fmt::format("vault {} is mirrored and its mirror is {}: a rotation's new key version must "
                                       "reach the mirror before anything is re-sealed, so it waits until the mirror is "
                                       "live; {}", vaultId, row->state, endHint(vaultId)));
    const auto peer = db::query::peer::Peers::byId(row->peer_id);
    if (!peer || peer->revoked())
        throw ops::Refused("mirror_link_down", fmt::format("vault {}'s mirror server is unlinked; {}", vaultId,
                                                           endHint(vaultId)));
    const auto t = vh::mirror::start::transport();
    if (!t.request || !t.upSince || !t.upSince(peer->id))
        throw ops::Refused("mirror_link_down",
                           fmt::format("the link to server '{}', which mirrors vault {}, is down: a rotation's new key "
                                       "version must reach the mirror before anything is re-sealed; rotate when the "
                                       "link is up, or end the mirror first (vh mirror cancel {})",
                                       peer->name, vaultId, vaultId));
    const auto facts = Q::facts(vaultId);
    if (!facts) throw ops::NotFound("no vault with ID " + std::to_string(vaultId));
    if (!provenance.attestation_key_id || provenance.attestation.empty())
        throw ops::Refused("key_version_unattested",
                           fmt::format("the new key version {} of vault {} could not be attested by this server, so its "
                                       "mirror could not prove where it came from; try again", version, vaultId));

    const auto envelope = vl::keykit::kev1::wrap(key, vl::keykit::kev1::Suite::X25519, version, facts->vault_uid,
                                                 std::span<const uint8_t>(peer->wrap_public_key));
    json attestation = {{"key_id", *provenance.attestation_key_id}, {"signature", base64Of(provenance.attestation)}};
    if (const auto pub = vh::db::query::vault::Key::attestationPublicKey(*provenance.attestation_key_id))
        attestation["public_key"] = base64Of(*pub);
    const json payload = {{"vault_uid", vl::keykit::toBase32(facts->vault_uid)}, {"core_vault_id", vaultId},
                          {"version", version}, {"envelope", base64Of(envelope)},
                          {"key_check", provenance.key_check}, {"attestation", std::move(attestation)}};
    const auto answer = t.request(peer->id, "peer.mirror.key", payload,
                                  std::chrono::duration_cast<std::chrono::milliseconds>(kDeliverTimeout));
    if (!ok(answer)) {
        audit::record({.action = "mirror.key", .outcome = audit::Outcome::Failure, .vault_id = vaultId,
                       .details = {{"peer", peer->id}, {"node_id", peer->node_id}, {"side", "core"},
                                   {"version", version}, {"delivered", false}}},
                      fmt::format("[mirror] the rotation of vault {} is refused: linked server {} did not take key "
                                  "version {} ({})", vaultId, peer->node_id, version, errorOf(answer)),
                      spdlog::level::warn);
        if (!answer)
            throw ops::Refused("mirror_link_down",
                               fmt::format("server '{}', which mirrors vault {}, did not answer: a rotation's new key "
                                           "version must reach the mirror before anything is re-sealed; rotate when the "
                                           "link is up, or end the mirror first (vh mirror cancel {})",
                                           peer->name, vaultId, vaultId));
        throw ops::Refused("mirror_key_refused",
                           fmt::format("server '{}', which mirrors vault {}, refused the new key version ({}); nothing "
                                       "was rotated; {}", peer->name, vaultId, errorOf(answer), endHint(vaultId)));
    }
    audit::record({.action = "mirror.key", .vault_id = vaultId,
                   .details = {{"peer", peer->id}, {"node_id", peer->node_id}, {"side", "core"}, {"version", version},
                               {"delivered", true}}},
                  fmt::format("[mirror] linked server {} proved and holds key version {} of vault {} before its "
                              "rotation", peer->node_id, version, vaultId));
}

json keyReceived(const vh::peer::Record& from, const json& payload) {
    using namespace mirror_rotate_detail;
    const auto uidText = text(payload, "vault_uid", 26, 26);
    const auto vaultUid = vl::keykit::fromBase32(uidText);
    if (!vaultUid) throw ops::Invalid("vault_uid is not a uid (26 base32 symbols)");
    const auto vaultId = Q::vaultWithUid(*vaultUid);
    const auto row = vaultId ? MirrorVaults::get(*vaultId) : std::nullopt;
    // Only the vault this server holds as that very server's mirror (never an orphaned copy, never its own).
    if (!row || row->role != "mirror" || row->peer_id != from.id)
        throw ops::NotFound("this server holds no such vault as that server's mirror");
    const auto coreVaultId = number(payload, "core_vault_id", 1, 2147483647);
    if (const auto origin = vh::db::query::mirror::MirrorKeys::originVaultOf(*vaultId, from.node_id);
        origin && *origin != coreVaultId)
        throw ops::Invalid("the key is for another vault than the one this server mirrors");
    const auto version = static_cast<uint32_t>(number(payload, "version", 1, 0x7fffffff));
    const auto envelope = base64(payload, "envelope", 4096);
    const auto keyCheck = text(payload, "key_check", 32, 32);
    const auto& att = field(payload, "attestation");
    if (!att.is_object()) throw ops::Invalid("attestation must be an object");
    const auto keyId = static_cast<unsigned>(
        number(att, "key_id", vh::vault::attestation::kMinKeyId, vh::vault::attestation::kMaxKeyId));
    const auto signature = base64(att, "signature", vh::vault::attestation::kSignatureSize);
    if (signature.size() != vh::vault::attestation::kSignatureSize) throw ops::Invalid("a signature is 64 bytes");

    const auto refuse = [&](const std::string& why) {
        audit::record({.action = "mirror.key", .outcome = audit::Outcome::Failure, .vault_id = *vaultId,
                       .details = {{"peer", from.id}, {"node_id", from.node_id}, {"side", "mirror"},
                                   {"version", version}, {"proven", false}}},
                      fmt::format("[mirror] refused key version {} linked server {} sent for vault {}: {}", version,
                                  from.node_id, *vaultId, why),
                      spdlog::level::warn);
        throw ops::Refused("mirror_key_refused", "the key version is refused: " + why);
    };

    vl::keykit::kev1::Unwrapped unwrapped;
    try {
        unwrapped = vh::peer::keys::unwrapVaultKey(envelope, *vaultUid);
    } catch (const vl::keykit::kev1::Error& e) {
        refuse(fmt::format("its envelope does not open here ({})", std::string(vl::keykit::kev1::errorCodeName(e.code()))));
    }
    if (unwrapped.key_version != version) refuse(fmt::format("its envelope holds version {}", unwrapped.key_version));
    const auto key = std::make_shared<const crypto::SecretKey>(unwrapped.key.bytes());

    // The anchors: the attestation keys pinned when this server paired with `from`, over its node id and the vault's id
    // there. This server's own keys prove nothing about where a key came from.
    vh::vault::recover::Pins pins{.supplied = true, .keys = {}, .node_id = from.node_id, .vault_id = coreVaultId};
    for (std::size_t i = 0; i < from.attest_public_keys.size(); ++i)
        pins.keys.push_back({.key_id = static_cast<unsigned>(i + 1),
                             .public_key = {from.attest_public_keys[i].begin(), from.attest_public_keys[i].end()},
                             .source = "pairing"});
    std::vector<std::vector<uint8_t>> selfKeys;
    for (const auto& k : vh::db::query::vault::Key::attestationKeys()) selfKeys.push_back(k.public_key);
    const vh::vault::recover::Evidence evidence{
        .source = "peer", .node_id = from.node_id, .vault_id = coreVaultId, .key_check = keyCheck,
        .attestation = vh::vault::attestation::Attestation{.key_id = keyId, .signature = signature}};
    const auto proof = vh::vault::recover::prove(version, key->bytes(), {evidence}, pins, selfKeys);
    if (!proof.canonical())
        refuse(fmt::format("{} ({})", proof.detail, std::string(vh::vault::recover::to_string(proof.verdict))));

    vh::db::query::mirror::MirrorKeyRow k;
    k.version = version;
    const vh::vault::master::Writer writer(true);
    const auto wrapped = writer.wrap(key->bytes());
    k.encrypted_key = wrapped.encrypted_key;
    k.iv = wrapped.iv;
    k.master_version = wrapped.master_version;
    k.provenance = vh::vault::attestation::provenanceOf(*vaultId, version, key->bytes());
    k.origin_node_id = from.node_id;
    k.origin_vault_id = coreVaultId;
    k.origin_key_check = keyCheck;
    k.attestation_key_id = keyId;
    k.attestation_public_key = proof.anchor->public_key;
    k.attestation = signature;
    const auto outcome = vh::db::query::mirror::MirrorKeys::install(*vaultId, k);
    if (outcome == vh::db::query::mirror::KeyInstall::Conflict)
        refuse(fmt::format("this server holds version {} of the vault with another key", version));
    if (outcome == vh::db::query::mirror::KeyInstall::Installed)
        audit::record({.action = "mirror.key", .vault_id = *vaultId,
                       .details = {{"peer", from.id}, {"node_id", from.node_id}, {"side", "mirror"},
                                   {"core_vault_id", coreVaultId}, {"version", version}, {"proven", true}}},
                      fmt::format("[mirror] holds key version {} of linked server {}'s vault {} (vault {} here) for its "
                                  "rotation: proven against the attestation key pinned at pairing, sealed under this "
                                  "server's vault master; current once the core's log names it",
                                  version, from.node_id, coreVaultId, *vaultId));
    return {{"vault_uid", uidText}, {"version", version}, {"installed", true}};
}

}
