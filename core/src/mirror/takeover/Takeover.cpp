#include "mirror/takeover/Takeover.hpp"

#include "audit/Trail.hpp"
#include "db/query/device/Device.hpp"
#include "db/query/mirror/Log.hpp"
#include "db/query/mirror/MirrorVault.hpp"
#include "db/query/mirror/Rejoin.hpp"
#include "db/query/peer/Peer.hpp"
#include "db/query/mirror/Switch.hpp"
#include "db/query/vault/Vault.hpp"
#include "log/Registry.hpp"
#include "mirror/follow/Follower.hpp"
#include "mirror/leave/Leave.hpp"
#include "mirror/start/Start.hpp"
#include "mirror/submit/Contents.hpp"
#include "mirror/submit/Local.hpp"
#include "mirror/versions/Versions.hpp"
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

    // Paused because the core scheduled the vault's deletion (mirror_core_deleting): allowed. The vault is this
    // server's from here on and its purge there no longer reaches it; audited as such.
    const bool coreDeleting = mv->state == "paused" && mv->stop_reason &&
                              *mv->stop_reason == vh::mirror::leave::kCoreDeletingReason;
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
    vh::mirror::versions::invalidate();   // the versions setting follows the role: this server's own policy now
    const auto& t = taken.takeover;
    std::string warning =
        "linked server " + std::to_string(t.peer_id) + ", the old core, may hold changes this server never received "
        "(after the fork point); they are merged when it returns";
    if (coreDeleting)
        warning += "; the old core was deleting the vault: it stays this server's vault, and that deletion no longer "
                   "reaches it";
    audit::record({.action = "mirror.takeover", .outcome = audit::Outcome::Info, .actor_id = actorId, .actor = actorName,
                   .vault_id = vaultId,
                   .details = {{"peer", t.peer_id}, {"from_term", t.from_term}, {"term", t.term},
                               {"fork_seq", t.fork_seq}, {"fork_digest", t.fork_digest.hex()},
                               {"pending_made_local", t.pending_made_local}, {"held", t.held},
                               {"contents_missing", t.contents_missing}, {"fork_base_matches", taken.fork_base_matches},
                               {"was", mv->state}, {"core_deleting", coreDeleting},
                               {"core_deletion", coreDeleting && mv->stop_detail.is_object() ? mv->stop_detail
                                                                                              : json(nullptr)}}},
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

// ---- the old core learns ------------------------------------------------------------------------------------------------

namespace {

json takeoverDigestJson(const vh::mirror::Digest& d) { return {{"digest", d.hex()}, {"entries", d.entries}}; }

vh::mirror::Digest takeoverDigestFrom(const json& j) {
    if (!j.is_object() || !j.contains("digest") || !j["digest"].is_string())
        throw vh::ops::Invalid("a digest is {digest, entries}");
    try {
        return vh::mirror::Digest::fromBytes(vh::mirror::hashFromHex(j["digest"].get<std::string>()),
                                             j.value("entries", int64_t{0}));
    } catch (const std::invalid_argument&) {
        throw vh::ops::Invalid("a digest is 64 hex digits");
    }
}

json takeoverAnswerOf(const mq::Rejoin& r) {
    json out{{"outcome", r.phase == "draining" ? std::string("pending")
                         : r.phase == "forked"  ? std::string("forced")
                                                : r.phase}};
    if (r.phase == "rejoining") out["changes"] = r.changes;
    return out;
}

// The new core: tells the old core it took over, until answered.
bool takeoverTell(const mq::Takeover& t, vh::mirror::follow::Transport& transport) {
    const auto peer = vh::db::query::peer::Peers::byId(t.peer_id);
    if (!peer || peer->revoked()) return false;   // unlinked: the trust ended, nothing more is told
    if (!transport.connected(t.peer_id)) return false;
    const auto mv = mq::MirrorVaults::get(t.vault_id);
    const auto uid = mq::MirrorVaults::vaultUidOf(t.vault_id);
    if (!mv || mv->role != "core" || !uid) return false;
    json payload{{"vault_uid", *uid},
                 {"term", t.term},
                 {"fork", {{"term", t.from_term}, {"seq", t.fork_seq}, {"digest", t.fork_digest.hex()},
                           {"entries", t.fork_digest.entries}}}};
    if (mv->baseline_digest) payload["baseline"] = takeoverDigestJson(*mv->baseline_digest);
    const auto a = transport.request(t.peer_id, "peer.mirror.promoted", payload);
    if (!a || !a->ok) return false;
    const auto outcome = a->data.value("outcome", std::string{});
    if (outcome != "following" && outcome != "rejoining" && outcome != "forced") return false;   // pending: next pass
    std::optional<uint32_t> changes;
    if (a->data.contains("changes") && a->data["changes"].is_number_unsigned()) changes = a->data["changes"].get<uint32_t>();
    mq::Takeovers::recordOutcome(t.id, outcome, changes);
    audit::record({.action = "mirror.takeover.old_core", .outcome = audit::Outcome::Info, .vault_id = t.vault_id,
                   .details = {{"peer", t.peer_id}, {"term", t.term}, {"old_core", outcome},
                               {"changes", changes ? json(*changes) : json(nullptr)}}},
                  fmt::format("[mirror] vault {}: linked server {}, the old core, learned this server took over: {}",
                              t.vault_id, t.peer_id,
                              outcome == "following" ? std::string("it follows this server, nothing to merge")
                              : outcome == "rejoining"
                                  ? fmt::format("it holds {} change(s) this server never received, kept read-only "
                                                "there until the merge",
                                                changes.value_or(0))
                                  : std::string("it had taken over too: both are read-only until an operator picks one")),
                  outcome == "following" ? spdlog::level::info : spdlog::level::warn);
    return true;
}

// The old core: once the writers it saw are gone and numbered, following or rejoining.
bool takeoverDecide(const mq::Rejoin& r) {
    if (mq::Switches::anyRunning(r.writers)) return false;
    (void)vh::db::query::mirror::Log::sequence(r.vault_id);
    const auto vault = vh::db::query::vault::Vault::getVault(r.vault_id);
    const auto d = mq::Rejoins::decide(r.id, vault ? vault->owner_id : 0u);
    if (!d.waits.empty()) return false;
    audit::record({.action = "mirror.rejoin", .outcome = audit::Outcome::Info, .vault_id = r.vault_id,
                   .details = {{"peer", r.peer_id}, {"term", r.new_term}, {"phase", d.phase}, {"changes", d.changes}}},
                  d.phase == "following"
                      ? fmt::format("[mirror] vault {}: linked server {} took over as its core in term {}; this server "
                                    "committed nothing since and is its mirror now",
                                    r.vault_id, r.peer_id, r.new_term)
                      : fmt::format("[mirror] vault {}: linked server {} took over as its core in term {}; this server "
                                    "holds {} change(s) it never received and stays read-only until they are merged "
                                    "(or vh mirror resync)",
                                    r.vault_id, r.peer_id, r.new_term, d.changes),
                  d.phase == "following" ? spdlog::level::info : spdlog::level::warn);
    vh::mirror::follow::Follower::instance()->wake(r.vault_id);
    return true;
}

}

json servePromoted(const uint32_t callerPeerId, const json& payload) {
    if (!payload.is_object() || !payload.contains("vault_uid") || !payload["vault_uid"].is_string())
        throw vh::ops::Invalid("vault_uid is required");
    const auto mv = mq::MirrorVaults::byVaultUid(payload["vault_uid"].get<std::string>());
    if (!mv || mv->peer_id != callerPeerId) throw vh::ops::NotFound("Not found");
    if (!payload.contains("term") || !payload["term"].is_number_integer() || payload["term"].get<int64_t>() < 1)
        throw vh::ops::Invalid("term is required");
    const auto term = payload["term"].get<uint64_t>();
    const auto forkJson = payload.contains("fork") ? payload["fork"] : json(nullptr);
    if (!forkJson.is_object() || !forkJson.contains("term") || !forkJson.contains("seq"))
        throw vh::ops::Invalid("fork is {term, seq, digest, entries}");
    const mq::Position fork{forkJson.value("term", uint64_t{0}), forkJson.value("seq", uint64_t{0})};
    const auto forkDigest = takeoverDigestFrom(forkJson);
    std::optional<vh::mirror::Digest> baseline;
    if (payload.contains("baseline") && payload["baseline"].is_object()) baseline = takeoverDigestFrom(payload["baseline"]);

    // Told again after it decided: the same answer.
    if (const auto r = mq::Rejoins::latestOf(mv->vault_id); r && r->peer_id == callerPeerId && r->new_term == term &&
                                                            r->phase != "resynced")
        return takeoverAnswerOf(*r);
    if (mv->role == "mirror" && mv->term == term) return {{"outcome", "following"}};
    if (mv->role != "core") throw vh::ops::Refused("mirror_term_stale", "this server is not the vault's core");
    // Both servers took over (each its own forced promotion, the other's term above the one this server took over from):
    // neither follows the other, both read-only.
    if (const auto own = mq::Takeovers::openOf(mv->vault_id); own && term > own->from_term) {
        const auto r = mq::Rejoins::forked(mv->vault_id, callerPeerId, term, fork, forkDigest);
        audit::record({.action = "mirror.rejoin", .outcome = audit::Outcome::Failure, .vault_id = mv->vault_id,
                       .details = {{"peer", callerPeerId}, {"term", term}, {"phase", "forked"}}},
                      fmt::format("[mirror] vault {}: linked server {} took over it too (term {}), as this server did: "
                                  "both are read-only; pick the server whose tree stays and resync or detach the other",
                                  mv->vault_id, callerPeerId, term),
                      spdlog::level::warn);
        return takeoverAnswerOf(r);
    }
    const auto r = mq::Rejoins::begin(mv->vault_id, callerPeerId, term, fork, forkDigest, baseline);
    if (r.writers.empty() && r.phase == "draining") mq::Rejoins::recordWriters(r.id, mq::Switches::writersNow());
    vh::log::Registry::sync()->warn("[MirrorRejoin] Vault {}: linked server {} took over as its core in term {}; this "
                                    "server stopped taking changes for it",
                                    mv->vault_id, callerPeerId, term);
    vh::mirror::follow::Follower::instance()->wake(mv->vault_id);
    return takeoverAnswerOf(r);
}

std::size_t tick(vh::mirror::follow::Transport& transport) {
    std::size_t n = 0;
    for (const auto& t : mq::Takeovers::untold()) {
        try {
            if (takeoverTell(t, transport)) ++n;
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[MirrorTakeover] Vault {}: telling the old core failed: {}", t.vault_id,
                                            e.what());
        }
    }
    for (const auto& r : mq::Rejoins::draining()) {
        try {
            if (takeoverDecide(r)) ++n;
        } catch (const std::exception& e) {
            vh::log::Registry::sync()->warn("[MirrorRejoin] Vault {}: the decision failed: {}", r.vault_id, e.what());
        }
    }
    return n;
}

}
