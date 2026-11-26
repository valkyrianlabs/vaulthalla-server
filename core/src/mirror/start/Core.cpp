#include "mirror/start/Start.hpp"

#include "audit/Trail.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "crypto/SecretKey.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/vault/Key.hpp"
#include "db/query/vault/LayoutMigration.hpp"
#include "db/query/vault/RemoteAttach.hpp"
#include "db/query/vault/RemoteDetach.hpp"
#include "log/Registry.hpp"
#include "ops/Error.hpp"
#include "rbac/resolver/PeerVault.hpp"
#include "rbac/role/Vault.hpp"
#include "runtime/Deps.hpp"
#include "storage/Engine.hpp"
#include "storage/Manager.hpp"
#include "sync/vault_manifest/Replicas.hpp"
#include "vault/EncryptionManager.hpp"
#include "vault/KeyAttestation.hpp"
#include "vault/LayoutMigration.hpp"
#include "vault/RemoteAttach.hpp"
#include "vault/RemoteDetach.hpp"
#include "vault/model/Vault.hpp"

#include <vl/keykit/kev1.hpp>
#include <vl/keykit/uid.hpp>

#include <fmt/format.h>
#include <sodium.h>

#include <algorithm>
#include <atomic>
#include <cstring>
#include <set>

namespace vh::mirror::start {

namespace start_core_detail {

using Q = vh::db::query::mirror::MirrorStart;
using vh::db::query::mirror::MirrorVaults;

std::string versionText(const std::vector<uint32_t>& versions) {
    std::string out;
    for (const auto v : versions) out += (out.empty() ? "" : ", ") + std::to_string(v);
    return out;
}

std::string base64Of(const std::span<const uint8_t> bytes) {
    if (bytes.empty()) return {};
    std::string out(sodium_base64_encoded_len(bytes.size(), sodium_base64_VARIANT_ORIGINAL), '\0');
    sodium_bin2base64(out.data(), out.size(), bytes.data(), bytes.size(), sodium_base64_VARIANT_ORIGINAL);
    out.resize(std::strlen(out.c_str()));
    return out;
}

json roleJson(const std::optional<vh::db::query::mirror::OfferedRole>& r) {
    if (!r) return nullptr;
    return {{"role_name", r->name}, {"files", r->files}, {"directories", r->directories}, {"sync", r->sync},
            {"roles", r->roles}};
}

std::optional<vh::db::query::mirror::OfferedRole> offeredRole(const uint32_t peerId, const uint32_t vaultId) {
    const auto r = rbac::resolver::PeerVault::role(peerId, vaultId);
    if (!r.grantsAnything()) return std::nullopt;
    return vh::db::query::mirror::OfferedRole{.name = r.role->name,
                                              .files = r.role->fs.files.toMask(),
                                              .directories = r.role->fs.directories.toMask(),
                                              .sync = r.role->sync.toMask(),
                                              .roles = r.role->roles.toMask()};
}

}

// ---- preconditions --------------------------------------------------------------------------------------------------

Prepared checkVault(const uint32_t vaultId) {
    using namespace start_core_detail;
    const auto facts = Q::facts(vaultId);
    if (!facts) throw ops::NotFound("no vault with ID " + std::to_string(vaultId));
    const auto& f = *facts;
    const auto name = "vault '" + f.name + "'";
    if (f.deleted)
        throw ops::Refused("vault_pending_deletion", name + " is scheduled for deletion: restore it before mirroring it");
    if (const auto m = MirrorVaults::get(vaultId))
        throw ops::Refused("mirror_already", m->role == "core"
                                                 ? name + " is mirrored already: one mirror per vault"
                                                 : name + " is another server's vault, held here as its copy: only its "
                                                          "core can mirror it");
    if (Q::activeOffer(f.vault_uid, "core"))
        throw ops::Refused("mirror_start_running", "a start of " + name + " is in progress already (vh mirror info " +
                                                       std::to_string(vaultId) + "); cancel it to start another");
    if (vh::sync::replicas::replicated(vaultId))
        throw ops::Refused("vault_replicated", name + " is replicated through its bucket (vh vault join): a vault is "
                                               "mirrored or bucket-replicated, never both");
    if (const auto a = vh::db::query::vault::RemoteAttach::get(vaultId);
        a && a->state != vh::vault::remote::State::Done && a->state != vh::vault::remote::State::Aborted)
        throw ops::Refused("vault_attach_running", "a remote is being attached to " + name +
                                                       "; mirror it once the attach has finished or been aborted (vh "
                                                       "vault remote status " + std::to_string(vaultId) + ")");
    if (const auto d = vh::db::query::vault::RemoteDetach::get(vaultId);
        d && d->state != vh::vault::remote::detach::State::Done && d->state != vh::vault::remote::detach::State::Aborted)
        throw ops::Refused("vault_detach_running", "the remote of " + name + " is being detached; mirror it once the "
                                                                              "detach has finished or been aborted");
    if (const auto l = vh::db::query::vault::LayoutMigration::get(vaultId);
        l && l->state != vh::vault::layout::State::Complete)
        throw ops::Refused("layout_migration_running", "the storage layout of " + name + " is being migrated; mirror "
                                                                                          "it once that has finished");
    if (vh::db::query::vault::Key::keyRotationInProgress(vaultId))
        throw ops::Refused("key_rotation_running", "a key rotation of " + name + " is in progress; mirror it once it "
                                                                                  "has finished");
    if (vh::db::query::vault::Key::runningSalvage(vaultId))
        throw ops::Refused("key_salvage_running", "a key salvage of " + name + " is running; mirror it once it has "
                                                                                "finished");
    if (f.gcm0_files || f.plain_files)
        throw ops::Refused("legacy_content",
                           fmt::format("{} still holds {} file(s) in the legacy gcm0 format and {} unencrypted file(s): "
                                       "their bytes bind nothing and are never sent; convert them first (vh vault "
                                       "format status {})", name, f.gcm0_files, f.plain_files, vaultId));
    if (f.trashed_without_uid)
        throw ops::Refused("trashed_without_uid",
                           fmt::format("{} has {} trashed file(s) from before permanent ids, which a mirror's log can't "
                                       "name: restore or purge them from the trash first", name, f.trashed_without_uid));
    if (!f.root_uid) throw ops::Refused("vault_unavailable", name + " has no root folder here");

    const auto versions = neededVersions(vaultId);
    if (const auto missing = Q::firstFileNotHeld(vaultId))
        throw ops::Refused("contents_not_held",
                           name + " has files whose bytes are only in its bucket (" + *missing +
                               " is one): a mirror gets what this server holds, so download them here first (open "
                               "them, or set the vault's sync strategy to keep everything on disk)");

    Prepared out{.facts = f, .versions = versions};
    if (out.facts.owner.node.empty()) out.facts.owner.node = vh::db::query::device::Devices::nodeId();
    return out;
}

std::vector<uint32_t> neededVersions(const uint32_t vaultId) {
    using namespace start_core_detail;
    const auto engine = runtime::Deps::get().storageManager ? runtime::Deps::get().storageManager->getEngine(vaultId)
                                                            : nullptr;
    if (!engine || !engine->encryptionManager || !engine->vault)
        throw ops::Refused("vault_unavailable", "vault " + std::to_string(vaultId) +
                                                   " is not loaded on this server (its key can't be read here)");
    const auto em = engine->encryptionManager;
    const auto name = "vault '" + engine->vault->name + "'";
    std::set<uint32_t> needed;
    for (const auto v : vh::db::query::vault::Key::dataKeyVersions(vaultId)) needed.insert(v);
    // Trashed files don't record their key version: every retired version this server still holds goes too.
    for (const auto v : vh::db::query::vault::Key::retiredKeyVersions(vaultId)) needed.insert(v);
    needed.insert(em->get_key_version());
    needed.erase(0);
    std::vector<uint32_t> notHeld, notAttested;
    const auto unattested = vh::db::query::vault::RemoteAttach::unattestedKeyVersions(vaultId);
    for (const auto v : needed) {
        if (!em->hasKeyVersion(v)) notHeld.push_back(v);
        else if (std::ranges::find(unattested, v) != unattested.end()) notAttested.push_back(v);
    }
    if (!notHeld.empty())
        throw ops::Refused("key_version_missing", fmt::format("{}'s contents are sealed under key version(s) {}, which "
                                                              "this server doesn't hold; import them (vh vault keys "
                                                              "import) first", name, versionText(notHeld)));
    if (!notAttested.empty())
        throw ops::Refused("key_version_unattested",
                           fmt::format("key version(s) {} of {} carry no attestation by this server, so the mirror "
                                       "couldn't prove where they came from; open the vault once (its keys are attested "
                                       "as they unseal) and try again", versionText(notAttested), name));
    if (needed.size() > kMaxKeyVersions)
        throw ops::Refused("key_version_missing", fmt::format("{} uses {} key versions; a mirror takes at most {}", name,
                                                              needed.size(), kMaxKeyVersions));
    return {needed.begin(), needed.end()};
}

bool mirroredOrStarting(const uint32_t vaultId) {
    if (vh::db::query::mirror::MirrorVaults::get(vaultId)) return true;
    const auto facts = start_core_detail::Q::facts(vaultId);
    return facts && start_core_detail::Q::activeOffer(facts->vault_uid, "core").has_value();
}

namespace start_core_detail {
std::atomic<bool>& rotationAllowedForTesting() {
    static std::atomic<bool> allowed{false};
    return allowed;
}
}

void allowRotationOnMirroredForTesting(const bool allow) { start_core_detail::rotationAllowedForTesting().store(allow); }

void refuseIfMirrored(const uint32_t vaultId, const std::string& what) {
    if (start_core_detail::rotationAllowedForTesting().load()) return;
    if (!mirroredOrStarting(vaultId)) return;
    throw ops::Refused("vault_mirrored", fmt::format("vault {} is mirrored with a linked server (or a mirror of it is "
                                                     "starting): {} is refused until rotation over the link is built; "
                                                     "cancel the mirror first (vh mirror cancel {})",
                                                     vaultId, what, vaultId));
}

void refuseDeletionIfMirrored(const uint32_t vaultId) {
    const auto row = vh::db::query::mirror::MirrorVaults::get(vaultId);
    if (row && row->role == "orphaned")
        throw ops::Refused("vault_orphaned_copy",
                           fmt::format("vault {} is an orphaned copy of another server's vault: remove it with vh mirror "
                                       "cancel {}", vaultId, vaultId));
    if (row && row->role == "mirror")
        throw ops::Refused("vault_mirrored", fmt::format("vault {} is another server's vault, held here as its mirror: "
                                                         "only that server (its core) ends the mirror", vaultId));
    if (mirroredOrStarting(vaultId))
        throw ops::Refused("vault_mirrored", fmt::format("vault {} is mirrored with a linked server (or a mirror of it is "
                                                         "starting): end the mirror first: vh mirror cancel {} "
                                                         "[--remove-copy]", vaultId, vaultId));
}

void checkLink(const vh::peer::Record& peer) {
    if (peer.revoked()) throw ops::Refused("peer_not_linked", "server '" + peer.name + "' is unlinked: link it again first");
    const auto t = transport();
    const auto up = t.upSince ? t.upSince(peer.id) : std::nullopt;
    if (!up)
        throw ops::Refused("peer_link_down", "the link to server '" + peer.name + "' is down; mirror once it is up "
                                             "again (vh peer info " + std::to_string(peer.id) + ")");
}

json grantFor(const uint32_t peerId, const uint32_t vaultId) {
    return start_core_detail::roleJson(start_core_detail::offeredRole(peerId, vaultId));
}

Offer offerVault(const uint32_t vaultId, const vh::peer::Record& peer, const std::optional<uint32_t> actorId,
                 const std::string& actorName) {
    using namespace start_core_detail;
    checkLink(peer);
    const auto prepared = checkVault(vaultId);
    const auto& f = prepared.facts;
    Offer o;
    o.offer_uid = vh::crypto::id::toUuid(vh::crypto::id::newObjectUid());
    o.side = "core";
    o.peer_id = peer.id;
    o.vault_uid = f.vault_uid;
    o.vault_id = vaultId;
    o.core_vault_id = vaultId;
    o.root_uid = *f.root_uid;
    o.term = 1;
    o.name = f.name;
    o.description = f.description;
    o.quota = f.quota;
    o.size_bytes = f.live_bytes + f.trashed_bytes;
    o.file_count = f.live_files + f.trashed_files;
    o.history = false;
    o.owner = f.owner;
    o.role = offeredRole(peer.id, vaultId);
    o.state = "offered";
    o.notify = true;
    o.started_by = actorId;
    o.expires_at = std::time(nullptr) + std::chrono::duration_cast<std::chrono::seconds>(kOfferLifetime).count();
    auto offer = Q::insertOffer(o);
    audit::record({.action = "mirror.offer", .actor_id = actorId, .actor = actorName, .vault_id = vaultId,
                   .details = {{"peer", peer.id}, {"node_id", peer.node_id}, {"side", "core"},
                               {"files", offer.file_count}, {"bytes", offer.size_bytes},
                               {"role", offer.role ? json(offer.role->name) : json(nullptr)}}},
                  fmt::format("[mirror] {} offered vault {} to linked server {} ('{}')",
                              actorName.empty() ? std::string("the server") : actorName, vaultId, peer.node_id, peer.name));
    Service::instance()->wake();
    return offer;
}

// ---- what the core sends ----------------------------------------------------------------------------------------------

json offerPayload(const Offer& o) {
    using namespace start_core_detail;
    return {{"offer_uid", o.offer_uid},
            {"vault_uid", vl::keykit::toBase32(o.vault_uid)},
            {"core_vault_id", o.core_vault_id},
            {"root_uid", vl::keykit::toBase32(o.root_uid)},
            {"term", o.term},
            {"name", o.name},
            {"description", o.description},
            {"quota", o.quota},
            {"size_bytes", o.size_bytes},
            {"file_count", o.file_count},
            {"history", o.history},
            {"owner", {{"node", o.owner.node}, {"id", o.owner.id}, {"name", o.owner.name}}},
            {"role", roleJson(o.role)},
            {"expires_at", static_cast<int64_t>(o.expires_at)}};
}

json keysPayload(const Offer& o, const vh::peer::Record& peer) {
    using namespace start_core_detail;
    if (!o.vault_id) throw ops::Conflict("the offer names no vault");
    const auto vaultId = *o.vault_id;
    // The versions as they are now (a rotation is refused while the start runs, so they are the offer's).
    const auto prepared = neededVersions(vaultId);
    const auto engine = runtime::Deps::get().storageManager->getEngine(vaultId);
    if (!engine || !engine->encryptionManager) throw ops::Refused("vault_unavailable", "the vault is not loaded here");
    const auto em = engine->encryptionManager;
    const auto current = em->get_key_version();
    json versions = json::array();
    for (const auto v : prepared) {
        const auto key = em->historicalKeySnapshot(v);
        if (!key) throw ops::Refused("key_version_missing", fmt::format("key version {} can't be read here", v));
        const auto bytes = key->bytes();
        const auto envelope = vl::keykit::kev1::wrap(bytes, vl::keykit::kev1::Suite::X25519, v, o.vault_uid,
                                                     std::span<const uint8_t>(peer.wrap_public_key));
        const auto provenance = vh::vault::attestation::provenanceOf(vaultId, v, bytes);
        if (!provenance.attestation_key_id || provenance.attestation.empty())
            throw ops::Refused("key_version_unattested",
                               fmt::format("key version {} could not be attested by this server now", v));
        json item = {{"version", v},
                     {"current", v == current},
                     {"envelope", base64Of(envelope)},
                     {"key_check", provenance.key_check},
                     {"attestation", {{"key_id", *provenance.attestation_key_id},
                                      {"signature", base64Of(provenance.attestation)}}}};
        if (const auto pub = vh::db::query::vault::Key::attestationPublicKey(*provenance.attestation_key_id))
            item["attestation"]["public_key"] = base64Of(*pub);
        versions.push_back(std::move(item));
    }
    return {{"offer_uid", o.offer_uid}, {"vault_uid", vl::keykit::toBase32(o.vault_uid)},
            {"core_vault_id", o.core_vault_id}, {"versions", std::move(versions)}};
}

json beginPayload(const Offer& o) {
    return {{"offer_uid", o.offer_uid}, {"vault_uid", vl::keykit::toBase32(o.vault_uid)}, {"term", o.term},
            {"grant", o.vault_id ? grantFor(o.peer_id, *o.vault_id) : json(nullptr)}};
}

// ---- cancelling on the core -------------------------------------------------------------------------------------------

bool cancelOnCore(const uint32_t vaultId, const std::string& reason, const bool tell, const bool removeCopy,
                  const std::optional<uint32_t> actorId, const std::string& by) {
    using namespace start_core_detail;
    std::scoped_lock lock(stepMutex());
    const auto facts = Q::facts(vaultId);
    if (!facts) return false;
    const auto row = MirrorVaults::get(vaultId);
    if (row && row->role != "core") return false;
    auto offer = Q::activeOffer(facts->vault_uid, "core");
    if (!offer) {
        const auto latest = Q::latestOffer(facts->vault_uid, "core");
        if (latest && latest->state == "started" && row) offer = latest;
    }
    if (!offer && !row) return false;
    const auto peerId = row ? row->peer_id : offer->peer_id;
    if (row) (void)MirrorVaults::remove(vaultId);
    if (offer)
        (void)Q::transition(offer->id, {"offered", "accepted", "keys_acked", "started"},
                            {.to = "cancelled", .notify = tell, .reason = reason, .remove_copy = removeCopy});
    audit::record({.action = "mirror.cancel", .actor_id = actorId, .actor = by, .vault_id = vaultId,
                   .details = {{"peer", peerId}, {"side", "core"}, {"reason", reason},
                               {"started", row.has_value()}, {"remove_copy", removeCopy},
                               {"by", actorId ? "this_server" : "peer"}}},
                  fmt::format("[mirror] the mirror of vault {} with linked server {} was cancelled on this server, the "
                              "core ({}; {})", vaultId, peerId, reason, by.empty() ? "the linked server" : by),
                  spdlog::level::warn);
    Service::instance()->wake();
    return true;
}

}
