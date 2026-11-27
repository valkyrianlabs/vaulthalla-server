#include "mirror/takeover/Takeover.hpp"

#include "audit/Trail.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Switch.hpp"
#include "db/query/vault/Vault.hpp"
#include "log/Registry.hpp"
#include "mirror/start/Start.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/submit/Local.hpp"
#include "ops/Error.hpp"
#include "vault/model/Vault.hpp"

#include <fmt/format.h>

#include <mutex>

namespace vh::mirror::takeover {

namespace mq = vh::db::query::mirror;
using json = nlohmann::json;

json take(const uint32_t vaultId, const std::string& confirmName, const uint32_t actorId, const std::string& actorName,
          vh::mirror::follow::Transport& transport) {
    const auto mv = mq::MirrorVaults::get(vaultId);
    if (!mv) throw vh::ops::NotFound("vault " + std::to_string(vaultId) + " is not mirrored");
    if (mv->role == "core") throw vh::ops::Refused("mirror_not_mirror", "this server is the vault's core already");
    if (mv->role == "orphaned")
        throw vh::ops::Refused("mirror_orphaned", "the core ended this mirror: this copy has no core to take over from; "
                                                  "detach it to keep it as a vault of this server");
    const auto vault = vh::db::query::vault::Vault::getVault(vaultId);
    if (!vault) throw vh::ops::NotFound("no such vault");
    // The vault's name typed: the act is the person's, on this vault and no other.
    if (confirmName != vault->name)
        throw vh::ops::Refused("mirror_name_mismatch", "type the vault's name exactly to take over as its core");

    // The core answers: the role moves by agreement (the planned switch), never by force.
    if (transport.connected(mv->peer_id))
        if (const auto uid = mq::MirrorVaults::vaultUidOf(vaultId)) {
            const auto a = transport.request(mv->peer_id, "peer.mirror.log",
                                             {{"vault_uid", *uid}, {"term", mv->term}, {"seq", mv->last_seq}});
            if (a && a->ok)
                throw vh::ops::Refused("mirror_core_reachable",
                                       "the vault's core answers: move the core by agreement (vh mirror switch); take "
                                       "over is for a core that is gone or cannot be reached");
        }

    const auto missing = mq::Switches::obstacles(vaultId).contents;
    mq::Takeovers::Taken taken;
    {
        // No change made here is half recorded, and no group from the core is half applied, while it is promoted.
        std::scoped_lock local(vh::mirror::submit::vaultMutex(vaultId));
        taken = mq::Takeovers::take(vaultId, actorId, actorName, static_cast<uint32_t>(missing));
    }
    // The pending changes' sealed bytes: the files hold them now (ordinary local changes).
    for (const auto id : taken.pending_ids)
        vh::mirror::submit::contents::dropBlob(vh::mirror::submit::contents::pendingBlob(vaultId, id));
    const auto& t = taken.takeover;
    const std::string warning =
        "linked server " + std::to_string(t.peer_id) + ", the old core, may hold changes this server never received "
        "(after the fork point); they are merged when it returns";
    audit::record({.action = "mirror.takeover", .outcome = audit::Outcome::Info, .actor_id = actorId, .actor = actorName,
                   .vault_id = vaultId,
                   .details = {{"peer", t.peer_id}, {"from_term", t.from_term}, {"term", t.term},
                               {"fork_seq", t.fork_seq}, {"fork_digest", t.fork_digest.hex()},
                               {"pending_made_local", t.pending_made_local}, {"held", t.held},
                               {"contents_missing", t.contents_missing}, {"fork_base_matches", taken.fork_base_matches},
                               {"was", mv->state}}},
                  fmt::format("[mirror] {} took over as the core of vault {} in term {} (its core was linked server {}; "
                              "fork point ({}, {})): {}",
                              actorName.empty() ? std::string("someone") : actorName, vaultId, t.term, t.peer_id,
                              t.from_term, t.fork_seq, warning),
                  spdlog::level::warn);
    if (!taken.fork_base_matches)
        vh::log::Registry::sync()->warn("[MirrorTakeover] Vault {}: the fork base's digest is not the fork point's "
                                        "(recorded in the take over's detail)",
                                        vaultId);
    vh::mirror::start::Service::instance()->wake();
    auto out = toJson(t);
    out["warning"] = warning;
    out["fork_base_matches"] = taken.fork_base_matches;
    return out;
}

bool settledBySwitch(const uint32_t vaultId, const uint64_t switchTerm, const uint64_t switchSeq,
                     const vh::mirror::Digest& switchDigest) {
    const auto t = mq::Takeovers::latestOf(vaultId);
    if (!t) return false;
    if (t->fork() != mq::Position{switchTerm, switchSeq} || t->fork_digest != switchDigest || t->term != switchTerm + 1 ||
        t->pending_made_local != 0)
        return false;
    // Told again (the answer was lost): the same answer.
    if (!t->open()) return t->settled_how.value_or("") == "switched";
    if (!mq::Takeovers::settle(t->id, "switched", {{"why", "the old core had decided the switch this server took over "
                                                           "from: nothing to merge"}}))
        return false;
    audit::record({.action = "mirror.takeover.settled", .outcome = audit::Outcome::Info, .vault_id = vaultId,
                   .details = {{"peer", t->peer_id}, {"term", t->term}, {"how", "switched"}}},
                  fmt::format("[mirror] vault {}: linked server {}, the old core, had decided the switch this server took "
                              "over from; it follows this server now, nothing to merge",
                              vaultId, t->peer_id));
    return true;
}

json toJson(const mq::Takeover& t) {
    return {{"id", t.id},
            {"vault_id", t.vault_id},
            {"peer_id", t.peer_id},
            {"from_term", t.from_term},
            {"term", t.term},
            {"fork", {{"term", t.from_term}, {"seq", t.fork_seq}, {"digest", t.fork_digest.hex()},
                      {"entries", t.fork_digest.entries}}},
            {"fork_rows", t.fork_rows},
            {"pending_made_local", t.pending_made_local},
            {"held", t.held},
            {"contents_missing", t.contents_missing},
            {"by", {{"id", t.by_id ? json(*t.by_id) : json(nullptr)}, {"name", t.by_name}}},
            {"created_at", static_cast<int64_t>(t.created_at)},
            {"settled_at", t.settled_at ? json(static_cast<int64_t>(*t.settled_at)) : json(nullptr)},
            {"settled_how", t.settled_how ? json(*t.settled_how) : json(nullptr)},
            {"detail", t.detail}};
}

}
