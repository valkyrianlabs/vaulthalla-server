#include "ops/Mirrors.hpp"

#include "audit/Trail.hpp"
#include "auth/stepup/StepUp.hpp"
#include "crypto/id/ObjectUid.hpp"
#include "db/query/mirror/Detach.hpp"
#include "db/query/mirror/Pending.hpp"
#include "db/query/mirror/Rejoin.hpp"
#include "db/query/mirror/Switch.hpp"
#include "db/query/mirror/Takeover.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/vault/Deletion.hpp"
#include "db/query/vault/Vault.hpp"
#include "identities/User.hpp"
#include "mirror/access/Access.hpp"
#include "mirror/follow/Follower.hpp"
#include "mirror/leave/Leave.hpp"
#include "mirror/resync/Resync.hpp"
#include "mirror/start/Start.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/submit/Local.hpp"
#include "mirror/switching/Switch.hpp"
#include "mirror/takeover/Takeover.hpp"
#include "ops/PeerPolicy.hpp"
#include "ops/Peers.hpp"
#include "rbac/permission/admin/Mirror.hpp"
#include "rbac/permission/admin/Vaults.hpp"
#include "rbac/permission/vault/Roles.hpp"
#include "rbac/resolver/admin/all.hpp"
#include "rbac/resolver/vault/all.hpp"
#include "vault/model/Vault.hpp"

#include <vl/keykit/uid.hpp>

#include <fmt/format.h>
#include <nlohmann/json.hpp>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <map>
#include <set>

namespace vh::ops::mirrors {

namespace ops_mirrors_detail {

using Q = db::query::mirror::MirrorStart;
using db::query::mirror::MirrorVaults;
using VaultPerm = rbac::permission::admin::VaultPermissions;
using RolePerm = rbac::permission::vault::RolePermissions;

// The switch, then a person (never an agent, a scoped or relayed device, a linked server): ops::peer_policy's gate.
void requireMirrorPerson(const Actor& actor, const std::string& what) { peer_policy::requirePerson(actor, what); }

void requireSuperAdmin(const Actor& actor, const std::string& what) {
    requireMirrorPerson(actor, what);
    if (!actor->isSuperAdmin()) throw Denied("only super admins of this server may " + what);
}

std::shared_ptr<vault::model::Vault> liveVault(const uint32_t vaultId) {
    if (vaultId == 0) throw Invalid("vault ID must be a positive integer");
    auto vault = db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw NotFound("no vault with ID " + std::to_string(vaultId));
    return vault;
}

// A super admin, or a person whose roles let them manage the vault and decide who holds it (Mirrors.hpp).
void requireManager(const Actor& actor, const std::shared_ptr<vault::model::Vault>& vault, const std::string& what) {
    requireMirrorPerson(actor, what);
    if (actor->isSuperAdmin()) return;
    if (!rbac::resolver::Admin::has<VaultPerm>({.user = actor, .permission = VaultPerm::Edit, .vault = vault}) ||
        !rbac::resolver::Vault::has<RolePerm>({.user = actor, .permission = RolePerm::Assign, .vault_id = vault->id}))
        throw Denied("mirroring vault '" + vault->name + "' takes a super admin, or the vault's edit permission and the "
                     "right to assign its vault roles");
}

bool digitsOnly(const std::string& s) {
    return !s.empty() && s.size() <= 9 && std::ranges::all_of(s, [](const unsigned char c) { return std::isdigit(c) != 0; });
}

Offer offerByRef(const std::string& ref) {
    std::optional<Offer> found;
    if (digitsOnly(ref)) found = Q::offer(static_cast<uint32_t>(std::strtoul(ref.c_str(), nullptr, 10)));
    else if (ref.size() == 36) {
        found = Q::offerByUid(ref, "mirror");
        if (!found) found = Q::offerByUid(ref, "core");
    }
    if (!found) throw NotFound("no mirror offer '" + ref + "' (vh mirror pending lists them)");
    return *found;
}

std::string actorName(const Actor& actor) { return actor ? actor->name() : std::string(); }

}

Offer add(const Actor& actor, const AddRequest& request) {
    using namespace ops_mirrors_detail;
    requireActor(actor);
    const auto vault = liveVault(request.vault_id);
    requireManager(actor, vault, "mirror a vault to a linked server");
    if (request.peer.empty()) throw Invalid("a linked server is required (--to <server>)");
    const auto peer = peers::resolveRef(request.peer);
    if (peer.revoked()) throw Refused("peer_not_linked", "server '" + peer.name + "' is unlinked: link it again first");
    // Detached between these two servers and not re-keyed since: the same uid and keys on both (wave 5).
    if (vault->uid)
        if (const auto refusal = vh::mirror::leave::offerRefusal(vh::crypto::id::toUuid(*vault->uid), peer.id))
            throw Refused(refusal->first, refusal->second);
    // Preconditions before the step-up: a refusal is said without asking for anything.
    vh::mirror::start::checkLink(peer);
    (void)vh::mirror::start::checkVault(vault->id);
    auth::stepup::require(auth::stepup::Family::Keys, "mirror.add:" + std::to_string(vault->id));
    return vh::mirror::start::offerVault(vault->id, peer, actor->id, actor->name());
}

std::vector<Offer> pending(const Actor& actor) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "see the vaults linked servers offer this one");
    std::vector<Offer> out;
    for (auto& o : Q::offers("mirror", true))
        if (o.state == "pending") out.push_back(std::move(o));
    return out;
}

Offer accept(const Actor& actor, const std::string& ref) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "accept a vault from a linked server");
    const auto offer = offerByRef(ref);
    if (offer.side != "mirror") throw Invalid("that offer is one this server made, not one it received");
    return vh::mirror::start::accept(offer, actor->id, actor->name());
}

Offer decline(const Actor& actor, const std::string& ref) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "decline a vault from a linked server");
    const auto offer = offerByRef(ref);
    if (offer.side != "mirror") throw Invalid("that offer is one this server made, not one it received");
    return vh::mirror::start::decline(offer, actor->id, actor->name());
}

Cancelled cancel(const Actor& actor, const CancelRequest& request) {
    using namespace ops_mirrors_detail;
    requireActor(actor);
    if (!request.vault_id && !request.offer) throw Invalid("name the vault (or the offer) to cancel");
    std::optional<Offer> offer;
    if (request.offer) offer = offerByRef(*request.offer);
    std::optional<uint32_t> vaultId = request.vault_id;
    if (!vaultId && offer) vaultId = offer->vault_id;

    const auto row = vaultId ? MirrorVaults::get(*vaultId) : std::nullopt;
    const bool coreSide = (row && row->role == "core") || (offer && offer->side == "core") ||
                          (!row && !offer && vaultId);
    if (coreSide) {
        if (!vaultId) throw NotFound("that offer names no vault here");
        const auto vault = liveVault(*vaultId);
        requireManager(actor, vault, "cancel a vault's mirror");
        // Removing a copy the mirror holds of a mirror that has begun destroys data there: the data-destroy step-up.
        const auto latest = vault->uid ? Q::latestOffer(*vault->uid, "core") : std::nullopt;
        if (request.remove_copy && (row || (latest && latest->state == "keys_acked")))
            auth::stepup::require(auth::stepup::Family::DataDestroy, "mirror.cancel:" + std::to_string(*vaultId));
        if (!vh::mirror::start::cancelOnCore(*vaultId, "cancelled_by_core", true, request.remove_copy, actor->id,
                                             actor->name()))
            throw NotFound("vault '" + vault->name + "' is not mirrored and no start of it is running");
        Cancelled out{.side = "core", .vault_id = vaultId, .offer = Q::latestOffer(*vault->uid, "core"),
                      .remove_copy = request.remove_copy};
        return out;
    }

    requireSuperAdmin(actor, "cancel the mirror of another server's vault");
    // An orphaned copy (its core ended the mirror and it was kept): a super admin here removes it.
    if (row && row->role == "orphaned") {
        auth::stepup::require(auth::stepup::Family::DataDestroy, "mirror.cancel:" + std::to_string(*vaultId));
        vh::mirror::start::removeOrphaned(*vaultId, actor->id, actor->name());
        return {.side = "mirror", .vault_id = vaultId, .removed = true};
    }
    if (!offer && vaultId)
        if (const auto v = db::query::vault::Vault::getVault(*vaultId); v && v->uid) {
            offer = Q::activeOffer(*v->uid, "mirror");
            if (!offer) offer = Q::latestOffer(*v->uid, "mirror");
        }
    if (!offer) {
        if (row && row->role != "core")
            throw Refused("mirror_detach_required",
                          "this server holds the vault as another server's mirror: removing it here would destroy a copy "
                          "of its data, so it is refused; leave with it as this server's vault (vh mirror detach), or "
                          "the core ends the mirror");
        throw NotFound("no mirror or start of that vault here");
    }
    const bool hadVault = offer->state == "installed";
    const auto moved = vh::mirror::start::cancelOnMirror(*offer, actor->id, actor->name());
    return {.side = "mirror", .vault_id = hadVault ? offer->vault_id : std::nullopt, .offer = moved, .removed = hadVault};
}

std::vector<Mirrored> list(const Actor& actor) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "list mirrored vaults");
    std::vector<Mirrored> out;
    std::map<uint32_t, std::size_t> byVault;
    for (const auto& row : MirrorVaults::list()) {
        Mirrored m{.vault_id = row.vault_id, .role = row.role, .row = row};
        auto v = db::query::vault::Vault::getVault(row.vault_id);
        if (!v) v = db::query::vault::Deletion::getDeletedVault(row.vault_id);   // being deleted: its mirror stays
        if (v) {
            m.vault_name = v->name;
            if (v->uid) m.start = Q::latestOffer(*v->uid, row.role == "core" ? "core" : "mirror");
        }
        m.peer = db::query::peer::Peers::byId(row.peer_id);
        byVault[row.vault_id] = out.size();
        out.push_back(std::move(m));
    }
    // Vaults detached here (wave 5): standalone now, sharing the original's uid and keys until the re-key pass.
    for (const auto& d : db::query::mirror::MirrorDetach::list()) {
        if (d.side != "mirror" || d.rekeyed_at || byVault.contains(d.vault_id)) continue;
        const auto v = db::query::vault::Vault::getVault(d.vault_id);
        if (!v) continue;
        Mirrored m{.vault_id = d.vault_id, .vault_name = v->name, .role = "detached", .detached = d};
        m.peer = db::query::peer::Peers::byId(d.peer_id);
        byVault[d.vault_id] = out.size();
        out.push_back(std::move(m));
    }
    // Starts that have no mirror row yet (an offer on either side).
    for (const auto& o : Q::offers("", true)) {
        if (o.vault_id && byVault.contains(*o.vault_id)) continue;
        Mirrored m{.vault_id = o.vault_id.value_or(0), .vault_name = o.name, .role = "starting", .start = o};
        m.peer = db::query::peer::Peers::byId(o.peer_id);
        out.push_back(std::move(m));
    }
    return out;
}

Mirrored get(const Actor& actor, const uint32_t vaultId) {
    using namespace ops_mirrors_detail;
    requireMirrorPerson(actor, "see a vault's mirror");
    // A vault this server is deleting (its retention window) keeps its mirror until the purge: still shown.
    auto vault = vaultId ? db::query::vault::Deletion::getDeletedVault(vaultId) : nullptr;
    if (!vault) vault = liveVault(vaultId);
    const auto row = MirrorVaults::get(vaultId);
    const auto side = row && row->role != "core" ? "mirror" : "core";
    if (!actor->isSuperAdmin()) {
        if (std::string(side) == "mirror" ||
            !rbac::resolver::Admin::has<VaultPerm>({.user = actor, .permission = VaultPerm::View, .vault = vault}))
            throw Denied("you do not have permission to view vault " + vault->name);
    }
    Mirrored m{.vault_id = vaultId, .vault_name = vault->name, .role = row ? row->role : "none", .row = row};
    if (vault->uid) m.start = Q::latestOffer(*vault->uid, side);
    if (m.start && !row && !m.start->finished()) m.role = "starting";
    if (row) m.peer = db::query::peer::Peers::byId(row->peer_id);
    else if (m.start) m.peer = db::query::peer::Peers::byId(m.start->peer_id);
    m.detached = db::query::mirror::MirrorDetach::forVault(vaultId);
    if (m.detached && !row && m.detached->side == "mirror") {
        m.role = "detached";
        m.peer = db::query::peer::Peers::byId(m.detached->peer_id);
        // The vault's own offer on this side was the mirror's (it ended detached).
        if (vault->uid) m.start = Q::latestOffer(*vault->uid, "mirror");
    }
    return m;
}

std::vector<Offer> offers(const Actor& actor) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "list mirror offers");
    return Q::offers("", false);
}

db::query::mirror::AcceptVaults acceptAll(const Actor& actor, const std::string& peerRef) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "see which linked servers' vaults this server accepts");
    return Q::acceptVaults(peers::resolveRef(peerRef).id);
}

db::query::mirror::AcceptVaults setAcceptAll(const Actor& actor, const std::string& peerRef, const bool enabled) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "decide which linked servers' vaults this server accepts");
    const auto peer = peers::resolveRef(peerRef);
    if (peer.revoked()) throw Conflict("that server is unlinked: link it again first");
    const auto before = Q::acceptVaults(peer.id);
    Q::setAcceptVaults(peer.id, enabled, actor->id);
    audit::record({.action = "mirror.accept_all.set", .actor_id = actor->id, .actor = actor->name(),
                   .details = {{"peer", peer.id}, {"node_id", peer.node_id}, {"enabled", enabled},
                               {"was", before.enabled}}},
                  fmt::format("[mirror] {} {} accepting every vault linked server {} ('{}') offers", actor->name(),
                              enabled ? "turned on" : "turned off", peer.node_id, peer.name));
    return Q::acceptVaults(peer.id);
}

db::query::mirror::AcceptVaults keepRemoved(const Actor& actor, const std::string& peerRef) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "see which linked servers' removed vaults this server keeps");
    return Q::keepVaults(peers::resolveRef(peerRef).id);
}

db::query::mirror::AcceptVaults setKeepRemoved(const Actor& actor, const std::string& peerRef, const bool enabled) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "decide whether this server keeps the vaults a linked server removes");
    const auto peer = peers::resolveRef(peerRef);
    if (peer.revoked()) throw Conflict("that server is unlinked: link it again first");
    const auto before = Q::keepVaults(peer.id);
    Q::setKeepVaults(peer.id, enabled, actor->id);
    audit::record({.action = "mirror.keep_removed.set", .actor_id = actor->id, .actor = actor->name(),
                   .details = {{"peer", peer.id}, {"node_id", peer.node_id}, {"enabled", enabled},
                               {"was", before.enabled}}},
                  fmt::format("[mirror] {} turned {} keeping the vaults linked server {} ('{}') removes", actor->name(),
                              enabled ? "on" : "off", peer.node_id, peer.name));
    return Q::keepVaults(peer.id);
}

db::query::mirror::AcceptVaults mirrorAll(const Actor& actor, const std::string& peerRef) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "see which linked servers this server mirrors every vault to");
    return Q::mirrorVaults(peers::resolveRef(peerRef).id);
}

db::query::mirror::AcceptVaults setMirrorAll(const Actor& actor, const std::string& peerRef, const bool enabled) {
    using namespace ops_mirrors_detail;
    requireSuperAdmin(actor, "decide whether this server mirrors every vault to a linked server");
    const auto peer = peers::resolveRef(peerRef);
    if (peer.revoked()) throw Refused("peer_not_linked", "server '" + peer.name + "' is unlinked: link it again first");
    const auto before = Q::mirrorVaults(peer.id);
    // Every vault's keys go to that server from now on: the keys step-up, bound to the server (none to turn it off).
    if (enabled && !before.enabled)
        auth::stepup::require(auth::stepup::Family::Keys, "mirror.mirror_all:" + std::to_string(peer.id));
    Q::setMirrorVaults(peer.id, enabled, actor->id);
    audit::record({.action = "mirror.mirror_all.set", .actor_id = actor->id, .actor = actor->name(),
                   .details = {{"peer", peer.id}, {"node_id", peer.node_id}, {"enabled", enabled},
                               {"was", before.enabled}}},
                  fmt::format("[mirror] {} {} mirroring every vault of this server to linked server {} ('{}')",
                              actor->name(), enabled ? "turned on" : "turned off", peer.node_id, peer.name));
    vh::mirror::start::Service::instance()->wake();
    return Q::mirrorVaults(peer.id);
}

// ---- json ---------------------------------------------------------------------------------------------------------

namespace ops_mirrors_detail {

nlohmann::json optTime(const std::optional<std::time_t>& t) {
    return t ? nlohmann::json(static_cast<int64_t>(*t)) : nlohmann::json(nullptr);
}

template <class T>
nlohmann::json opt(const std::optional<T>& v) {
    return v ? nlohmann::json(*v) : nlohmann::json(nullptr);
}

// What step a start is at, in words a person reads.
std::string stepOf(const Offer& o) {
    if (o.side == "core") {
        if (o.state == "offered") return o.notify ? "offering" : "waiting_for_answer";
        if (o.state == "accepted") return "delivering_keys";
        if (o.state == "keys_acked") return "beginning";
    } else {
        if (o.state == "pending") return "waiting_for_a_super_admin";
        if (o.state == "accepted") return o.notify ? "answering" : "waiting_for_keys";
        if (o.state == "installed") return "waiting_for_begin";
    }
    return o.state;
}

}

nlohmann::json toJson(const Offer& o) {
    using namespace ops_mirrors_detail;
    nlohmann::json role = nullptr;
    if (o.role)
        role = {{"role_name", o.role->name}, {"files", o.role->files}, {"directories", o.role->directories},
                {"sync", o.role->sync}, {"roles", o.role->roles}};
    return {{"id", o.id}, {"offer_uid", o.offer_uid}, {"side", o.side}, {"peer_id", o.peer_id},
            {"vault_uid", vl::keykit::toBase32(o.vault_uid)}, {"vault_id", opt(o.vault_id)},
            {"core_vault_id", o.core_vault_id}, {"term", o.term}, {"name", o.name}, {"description", o.description},
            {"quota", o.quota}, {"size_bytes", o.size_bytes}, {"file_count", o.file_count}, {"history", o.history},
            {"owner", {{"node", o.owner.node}, {"id", o.owner.id}, {"name", o.owner.name}}}, {"role", std::move(role)},
            {"state", o.state}, {"step", stepOf(o)}, {"told", !o.notify}, {"remove_copy", o.remove_copy},
            {"copy", opt(o.copy_outcome)}, {"reason", opt(o.reason)},
            {"detail", opt(o.detail)}, {"attempts", o.attempts}, {"last_error", opt(o.last_error)},
            {"created_at", static_cast<int64_t>(o.created_at)}, {"updated_at", static_cast<int64_t>(o.updated_at)},
            {"expires_at", static_cast<int64_t>(o.expires_at)}, {"finished_at", optTime(o.finished_at)}};
}

nlohmann::json toJson(const Mirrored& m) {
    using namespace ops_mirrors_detail;
    nlohmann::json j = {{"vault_id", m.vault_id}, {"vault_name", m.vault_name}, {"role", m.role}};
    if (m.peer)
        j["peer"] = {{"id", m.peer->id}, {"node_id", m.peer->node_id}, {"name", m.peer->name},
                     {"revoked", m.peer->revoked()}};
    else
        j["peer"] = nullptr;
    if (m.row) {
        const auto& r = *m.row;
        nlohmann::json grant = nullptr;
        if (r.grant)
            grant = {{"role_name", r.grant->role_name}, {"files", r.grant->files}, {"directories", r.grant->directories},
                     {"sync", r.grant->sync}, {"roles", r.grant->roles}, {"granted_by_node", r.grant->granted_by_node},
                     {"granted_at", static_cast<int64_t>(r.grant->granted_at)}};
        j["term"] = r.term;
        j["last_seq"] = r.last_seq;
        j["state"] = r.state;
        j["grant"] = std::move(grant);
        j["acked"] = r.acked ? nlohmann::json{{"term", r.acked->term}, {"seq", r.acked->seq}} : nlohmann::json(nullptr);
        j["created_at"] = static_cast<int64_t>(r.created_at);
    } else {
        j["term"] = nullptr;
        j["last_seq"] = nullptr;
        j["state"] = nullptr;
        j["grant"] = nullptr;
        j["acked"] = nullptr;
        j["created_at"] = nullptr;
    }
    j["start"] = m.start ? toJson(*m.start) : nlohmann::json(nullptr);
    // Moving the core (wave 5 piece B): the vault's latest planned switch here, a take over still waiting for its old
    // core, and what a person does next when the vault waits on the other server.
    j["switch"] = nullptr;
    j["takeover"] = nullptr;
    j["advice"] = nullptr;
    if (m.row) {
        const auto sw = vh::db::query::mirror::Switches::latestOf(m.vault_id);
        if (sw)
            j["switch"] = {{"switch_id", sw->switch_id}, {"side", sw->side}, {"phase", sw->phase}, {"term", sw->term},
                           {"reason", opt(sw->reason)}, {"created_at", static_cast<int64_t>(sw->created_at)},
                           {"ended_at", optTime(sw->ended_at)}};
        const auto tk = vh::db::query::mirror::Takeovers::openOf(m.vault_id);
        if (tk)
            j["takeover"] = {{"term", tk->term}, {"fork", {{"term", tk->from_term}, {"seq", tk->fork_seq}}},
                             {"peer_id", tk->peer_id}, {"contents_missing", tk->contents_missing},
                             {"created_at", static_cast<int64_t>(tk->created_at)}};
        const auto& r = *m.row;
        if (r.role == "mirror" && r.state == "switching" && sw && sw->side == "mirror" && sw->open())
            j["advice"] = fmt::format(
                "This server is preparing to take the core role and waits for its core's decision. If the core never "
                "comes back, take over as the core here (vh mirror takeover {} --confirm '{}'), or detach the copy "
                "(vh mirror detach {}).",
                m.vault_id, m.vault_name, m.vault_id);
        else if (r.role == "mirror" && r.state == "switching")
            j["advice"] = "This server handed the core role to the other server and waits for it to confirm; it is "
                          "read-only until then.";
        else if (r.role == "core" && r.state == "rejoining") {
            const auto rj = vh::db::query::mirror::Rejoins::openOf(m.vault_id);
            j["advice"] = fmt::format(
                "Linked server {} took over as this vault's core in term {} while this server was cut off, and this "
                "server holds {} change(s) it never received; the vault is read-only here until they are merged (the "
                "merge is the next step). Meanwhile: start this copy over from it (vh mirror resync {}: your changes kept "
                "as held changes), or detach it (vh mirror detach {}).",
                r.peer_id, rj ? rj->new_term : r.term + 1, rj ? rj->changes : 0u, m.vault_id, m.vault_id);
        } else if (r.role == "core" && r.state == "forked")
            j["advice"] = fmt::format(
                "Both servers took over as this vault's core while they were cut off; it is read-only on both. Pick the "
                "server whose vault stays, and on the other run vh mirror resync <its vault> (what it holds that the "
                "kept one does not is kept as held changes) or detach it.");
        else if (r.role == "core" && tk && tk->old_core_outcome == std::optional<std::string>("rejoining"))
            j["advice"] = fmt::format("The old core, linked server {}, holds {} change(s) this server never received; it "
                                      "waits read-only for the merge (the next step) or a resync there.",
                                      tk->peer_id, tk->old_core_changes.value_or(0));
        else if (r.role == "core" && tk)
            j["advice"] = fmt::format("This server took over as the core in term {} (fork point ({}, {})); the old core, "
                                      "linked server {}, may hold changes this server never received: they are merged "
                                      "when it returns.",
                                      tk->term, tk->from_term, tk->fork_seq, tk->peer_id);
    }
    j["detached"] = m.detached ? vh::mirror::leave::toJson(*m.detached) : nlohmann::json(nullptr);
    j["rekey_recommended"] = m.detached && m.detached->side == "mirror" && !m.detached->rekeyed_at;
    // Wave 5: the vault's pending deletion (core: from its deletion; mirror: what the core said): the date its purge
    // is due and what it does to the copy, or null.
    j["deleting"] = m.row ? vh::mirror::leave::deletionOf(m.vault_id) : nlohmann::json(nullptr);
    j["stop_reason"] = m.row && m.row->stop_reason ? nlohmann::json(*m.row->stop_reason) : nlohmann::json(nullptr);
    return j;
}

nlohmann::json toJson(const Cancelled& c) {
    using namespace ops_mirrors_detail;
    return {{"side", c.side}, {"vault_id", opt(c.vault_id)}, {"removed", c.removed}, {"remove_copy", c.remove_copy},
            {"offer", c.offer ? toJson(*c.offer) : nlohmann::json(nullptr)}};
}

nlohmann::json toJson(const db::query::mirror::AcceptVaults& a, const vh::peer::Record& peer) {
    using namespace ops_mirrors_detail;
    return {{"peer", {{"id", peer.id}, {"node_id", peer.node_id}, {"name", peer.name}}},
            {"enabled", a.enabled},
            {"set_by", opt(a.set_by)},
            {"set_at", optTime(a.set_at)}};
}

// ---- resync (wave 5 piece B) -----------------------------------------------------------------------------------------

nlohmann::json resync(const Actor& actor, const uint32_t vaultId) {
    ops_mirrors_detail::requireSuperAdmin(actor, "start a mirrored vault's copy over");
    (void)ops_mirrors_detail::liveVault(vaultId);
    return vh::mirror::resync::start(vaultId, actor->id, actor->name(), *vh::mirror::follow::linkTransport());
}

// ---- the planned switch (wave 5 piece B) ----------------------------------------------------------------------------

nlohmann::json switchRole(const Actor& actor, const uint32_t vaultId, const bool acceptNoAccess) {
    ops_mirrors_detail::requireSuperAdmin(actor, "switch a mirrored vault's core");
    (void)ops_mirrors_detail::liveVault(vaultId);
    return vh::mirror::switching::request(vaultId, actor->id, actor->name(), *vh::mirror::follow::linkTransport(),
                                          vh::mirror::switching::timeout() + std::chrono::seconds(10), acceptNoAccess);
}

// ---- take over (wave 5 piece B) ----------------------------------------------------------------------------------------

void requireTakeover(const Actor& actor, const std::string& what) {
    ops_mirrors_detail::requireMirrorPerson(actor, what);
    if (actor->isSuperAdmin() || actor->mirrorPerms().canTakeover()) return;
    throw Denied("only super admins of this server, or people its admin roles let take over as core "
                 "(admin.mirror.takeover), may " + what);
}

nlohmann::json takeover(const Actor& actor, const uint32_t vaultId, const std::string& confirmName) {
    requireTakeover(actor, "take over as a mirrored vault's core");
    (void)ops_mirrors_detail::liveVault(vaultId);
    auth::stepup::require(auth::stepup::Family::DataDestroy, "mirror.takeover:" + std::to_string(vaultId));
    return vh::mirror::takeover::take(vaultId, confirmName, actor->id, actor->name(),
                                      *vh::mirror::follow::linkTransport());
}

// ---- held changes ------------------------------------------------------------------------------------------------------

std::vector<db::query::mirror::HeldChange> held(const Actor& actor, const std::optional<uint32_t> vaultId,
                                                const bool all) {
    ops_mirrors_detail::requireSuperAdmin(actor, "list held changes");
    std::vector<db::query::mirror::HeldChange> out;
    std::set<uint32_t> vaults;
    // Every row: a core holds the changes it held while it was the mirror (a planned switch since).
    for (const auto& m : db::query::mirror::MirrorVaults::list()) vaults.insert(m.vault_id);
    // A detached vault's held changes stay listed until discarded (wave 5).
    for (const auto& d : db::query::mirror::MirrorDetach::list())
        if (d.side == "mirror") vaults.insert(d.vault_id);
    for (const auto v : vaults) {
        if (vaultId && v != *vaultId) continue;
        for (auto& h : db::query::mirror::Pending::heldChanges(v, all)) out.push_back(std::move(h));
    }
    return out;
}

db::query::mirror::HeldChange discardHeld(const Actor& actor, const uint64_t id) {
    ops_mirrors_detail::requireSuperAdmin(actor, "discard a held change");
    const auto h = db::query::mirror::Pending::heldChange(id);
    if (!h) throw NotFound("no held change " + std::to_string(id));
    if (!db::query::mirror::Pending::resolveHeld(id, "discarded", actor->id))
        throw Conflict("held change " + std::to_string(id) + " is " + h->state + " already");
    // The person's sealed bytes go with it (the person's own act).
    vh::mirror::submit::contents::dropBlob(vh::mirror::submit::contents::heldBlob(h->vault_id, id));
    audit::record({.action = "mirror.held.discard", .actor_id = actor->id, .actor = actor->name(), .vault_id = h->vault_id,
                   .details = {{"held", id}, {"kind", h->kind}, {"op", h->op}, {"reason_code", h->reason_code}}},
                  fmt::format("[mirror] {} discarded held change {} ({}) of vault {}", actor->name(), id, h->op,
                              h->vault_id));
    return *db::query::mirror::Pending::heldChange(id);
}

db::query::mirror::HeldChange retryHeld(const Actor& actor, const uint64_t id) {
    ops_mirrors_detail::requireSuperAdmin(actor, "retry a held change");
    const auto h = db::query::mirror::Pending::heldChange(id);
    if (!h) throw NotFound("no held change " + std::to_string(id));
    if (h->kind != "held") throw Invalid("a conflict copy is in the vault already; there is nothing to retry");
    if (h->state != "open") throw Conflict("held change " + std::to_string(id) + " is " + h->state + " already");
    if (!h->entry_uid) throw Invalid("held change " + std::to_string(id) + " names no entry");
    if (vh::mirror::access::state(h->vault_id) == vh::mirror::access::State::NotMirrored)
        throw Refused("mirror_read_only", "this server is not the vault's mirror now (its core since a planned switch, "
                                          "or no longer mirrored): a held change is retried from a mirror; make the "
                                          "change again here, or discard it");
    if (vh::mirror::access::state(h->vault_id) != vh::mirror::access::State::Live)
        throw Refused("mirror_read_only", "the vault is read-only on this server now: " +
                                              vh::mirror::access::reason(h->vault_id));
    {
        std::scoped_lock local(vh::mirror::submit::vaultMutex(h->vault_id));
        if (!db::query::mirror::Pending::resolveHeld(id, "retried", actor->id))
            throw Conflict("held change " + std::to_string(id) + " is not open any more");
        db::query::mirror::NewPending change;
        change.vault_id = h->vault_id;
        change.request_id = vh::mirror::submit::newRequestId();
        change.entry_uid = *h->entry_uid;
        change.op = h->op;
        change.args = h->args;
        change.actor = h->actor;
        // Submitted only: nothing of it is applied here first, and it holds no entry dirty.
        const auto row = db::query::mirror::Pending::open(change, {}, {});
        // A write's sealed bytes go with it to the new change (and back to a held change if it is refused again).
        vh::mirror::submit::contents::moveBlob(vh::mirror::submit::contents::heldBlob(h->vault_id, id),
                                               vh::mirror::submit::contents::pendingBlob(h->vault_id, row.id));
        db::query::mirror::Pending::ready(row.id);
    }
    vh::mirror::follow::Follower::instance()->wake(h->vault_id);
    audit::record({.action = "mirror.held.retry", .actor_id = actor->id, .actor = actor->name(), .vault_id = h->vault_id,
                   .details = {{"held", id}, {"op", h->op}, {"reason_code", h->reason_code}}},
                  fmt::format("[mirror] {} retried held change {} ({}) of vault {}", actor->name(), id, h->op,
                              h->vault_id));
    return *db::query::mirror::Pending::heldChange(id);
}

nlohmann::json toJson(const db::query::mirror::HeldChange& h) {
    nlohmann::json out{{"id", h.id},
                       {"vault_id", h.vault_id},
                       {"kind", h.kind},
                       {"op", h.op},
                       {"entry_uid", h.entry_uid ? nlohmann::json(*h.entry_uid) : nlohmann::json(nullptr)},
                       {"path", h.path ? nlohmann::json(*h.path) : nlohmann::json(nullptr)},
                       {"name", h.args.value("name", std::string{})},
                       {"copy_name", h.copy_name ? nlohmann::json(*h.copy_name) : nlohmann::json(nullptr)},
                       {"person", {{"node", h.actor.node}, {"id", h.actor.id}}},
                       {"reason_code", h.reason_code},
                       {"reason", h.reason},
                       {"state", h.state},
                       {"created_at", h.created_at},
                       {"resolved_at", h.resolved_at ? nlohmann::json(*h.resolved_at) : nlohmann::json(nullptr)}};
    return out;
}

}
